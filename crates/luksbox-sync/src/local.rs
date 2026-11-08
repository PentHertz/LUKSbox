// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Penthertz <https://penthertz.com> (https://x.com/PentHertz)

//! Per-device storage outside the synced folder.
//!
//! Holds, for one bundle on one device: the sealed device state (ids,
//! what this device has seen, its anchor), the staged-commit record and
//! the outbox of sealed objects not yet published. Everything here is
//! either sealed or ciphertext; the folder is 0700 and every write is
//! atomic (`atomic_secure_write`: 0600 temp file, fsync, rename, fsync of
//! the folder). Two implementations: `FsLocal` and `MemLocal`.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use luksbox_core::aead;
use zeroize::Zeroizing;

use crate::error::{Result, SyncError};
use crate::keys::BundleKeys;
use crate::names::fill_random;

pub trait LocalStore: Send {
    fn get(&mut self, name: &str) -> Result<Option<Vec<u8>>>;
    /// Durable, atomic replace.
    fn put(&mut self, name: &str, bytes: &[u8]) -> Result<()>;
    fn remove(&mut self, name: &str) -> Result<()>;
    fn list(&mut self) -> Result<Vec<String>>;
}

/// Local names: lowercase letters, digits, `-` and `.`, at most 100
/// characters, no leading dot. Anything else is a bug, refused.
fn check_name(name: &str) -> Result<()> {
    let ok = !name.is_empty()
        && name.len() <= 100
        && !name.starts_with('.')
        && name
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-' || b == b'.');
    if ok {
        Ok(())
    } else {
        Err(SyncError::Refused {
            what: name.to_string(),
            why: "invalid local state name",
        })
    }
}

/// Local folder of one bundle: `<root>/<bundle id>/`.
///
/// Every `put` is atomic (temporary file, then rename). Durability: on
/// Apple platforms `fsync` does not reach the disk's own cache and the
/// full flush (`F_FULLFSYNC`) costs about 4 ms per MiB, which made every
/// outbox page of a save pay it. There, an outbox object (`p-...`) is
/// fsync'd and renamed into place without that flush; every other record
/// (the staged record that names outbox objects, the device state, the
/// manifest being published...) first puts an ordering barrier behind
/// everything written before it (`F_BARRIERFSYNC`: those objects reach
/// the disk before the record's name does), then flushes the disk's
/// cache once, so it is durable when `put` returns. A save is therefore
/// still all or nothing: after a power cut the old record names the old
/// objects, or the new record names new objects that are all there. An
/// outbox object no record names yet is only a leftover, removed at the
/// next writable open. Elsewhere every `put` is `atomic_secure_write`
/// (fsync, rename, fsync of the folder), as before.
pub struct FsLocal {
    dir: PathBuf,
    _lock: std::fs::File,
    /// Apple platforms: outbox objects written since the last record,
    /// whose renames are not flushed yet.
    #[cfg(target_vendor = "apple")]
    unflushed: bool,
}

/// Names of outbox objects (sealed pages not published yet).
#[cfg(target_vendor = "apple")]
const OUTBOX_PREFIX: &str = "p-";

impl FsLocal {
    /// Open (creating 0700) the folder and take its exclusive lock, so
    /// only one process on this device works on the bundle at a time.
    pub fn open(dir: &Path) -> Result<Self> {
        create_dir_all_private(dir)?;
        let lock_path = dir.join("lock");
        let mut o = std::fs::OpenOptions::new();
        o.create(true).truncate(false).write(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            o.mode(0o600);
        }
        let lock = o.open(&lock_path)?;
        use fs2::FileExt;
        lock.try_lock_exclusive().map_err(|_| {
            SyncError::Io(std::io::Error::new(
                std::io::ErrorKind::WouldBlock,
                "the bundle is open in another LuksBox process on this device",
            ))
        })?;
        Ok(Self {
            dir: dir.to_path_buf(),
            _lock: lock,
            #[cfg(target_vendor = "apple")]
            unflushed: false,
        })
    }

    fn path(&self, name: &str) -> Result<PathBuf> {
        check_name(name)?;
        Ok(self.dir.join(name))
    }

    /// `put` on Apple platforms (see the type's docs).
    #[cfg(target_vendor = "apple")]
    fn put_ordered(&mut self, name: &str, path: &Path, bytes: &[u8]) -> Result<()> {
        use std::io::Write;
        use std::os::fd::AsRawFd;
        fn fsync(fd: std::os::fd::RawFd) -> std::io::Result<()> {
            // SAFETY: live fd.
            if unsafe { libc::fsync(fd) } == 0 {
                Ok(())
            } else {
                Err(std::io::Error::last_os_error())
            }
        }
        /// `fcntl(cmd)`, or the full flush where the file system has no
        /// such command.
        fn flush(f: &std::fs::File, cmd: libc::c_int) -> std::io::Result<()> {
            // SAFETY: live fd.
            if unsafe { libc::fcntl(f.as_raw_fd(), cmd) } == 0 {
                return Ok(());
            }
            f.sync_all()
        }
        let outbox = name.starts_with(OUTBOX_PREFIX);
        let mut rnd = [0u8; 8];
        fill_random(&mut rnd)?;
        let tmp = self
            .dir
            .join(format!("{name}.tmp.{}", crate::names::to_hex(&rnd)));
        let mut f = luksbox_core::file_util::secure_create_new(&tmp)?;
        let written = f.write_all(bytes).and_then(|()| {
            if outbox {
                fsync(f.as_raw_fd())
            } else {
                // The renames of the outbox objects written since the
                // last record, then a barrier behind them and this
                // record's data.
                if self.unflushed {
                    fsync(std::fs::File::open(&self.dir)?.as_raw_fd())?;
                }
                flush(&f, libc::F_BARRIERFSYNC)
            }
        });
        drop(f);
        if let Err(e) = written.and_then(|()| std::fs::rename(&tmp, path)) {
            let _ = std::fs::remove_file(&tmp);
            return Err(e.into());
        }
        if outbox {
            self.unflushed = true;
            return Ok(());
        }
        flush(&std::fs::File::open(&self.dir)?, libc::F_FULLFSYNC)?;
        self.unflushed = false;
        Ok(())
    }
}

impl LocalStore for FsLocal {
    fn get(&mut self, name: &str) -> Result<Option<Vec<u8>>> {
        let p = self.path(name)?;
        match open_no_follow(&p) {
            Ok(mut f) => {
                use std::io::Read;
                let mut v = Vec::new();
                f.read_to_end(&mut v)?;
                Ok(Some(v))
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(e.into()),
        }
    }

    fn put(&mut self, name: &str, bytes: &[u8]) -> Result<()> {
        let p = self.path(name)?;
        #[cfg(target_vendor = "apple")]
        {
            self.put_ordered(name, &p, bytes)
        }
        #[cfg(not(target_vendor = "apple"))]
        {
            luksbox_core::file_util::atomic_secure_write(&p, bytes)?;
            Ok(())
        }
    }

    fn remove(&mut self, name: &str) -> Result<()> {
        let p = self.path(name)?;
        match std::fs::remove_file(&p) {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(e.into()),
        }
    }

    fn list(&mut self) -> Result<Vec<String>> {
        let mut out = Vec::new();
        for e in std::fs::read_dir(&self.dir)? {
            let e = e?;
            if let Some(n) = e.file_name().to_str()
                && check_name(n).is_ok()
                && n != "lock"
            {
                out.push(n.to_string());
            }
        }
        out.sort();
        Ok(out)
    }
}

/// `create_dir_all`, with every folder it creates private (0700), the
/// existing ones left as they are. R16-09: the per-device state lives
/// under `<data dir>/luksbox/sync/`; with a plain `create_dir_all` the
/// intermediate folders took the umask (0755 as a rule), so another
/// account on the machine could list which bundles this one uses.
pub fn create_dir_all_private(dir: &Path) -> std::io::Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::{DirBuilderExt, PermissionsExt};
        std::fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(dir)?;
        std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700))?;
    }
    #[cfg(not(unix))]
    {
        std::fs::create_dir_all(dir)?;
    }
    Ok(())
}

/// Open for reading without following a link at the final component
/// (the folder is ours and 0700; this is belt and braces).
fn open_no_follow(p: &Path) -> std::io::Result<std::fs::File> {
    let mut o = std::fs::OpenOptions::new();
    o.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        o.custom_flags(libc::O_NOFOLLOW);
    }
    o.open(p)
}

/// In-memory local store. Clones share the same map, so a test can drop
/// a session ("crash") and open a new one on the same device state.
#[derive(Clone, Default)]
pub struct MemLocal(pub Arc<Mutex<BTreeMap<String, Vec<u8>>>>);

impl LocalStore for MemLocal {
    fn get(&mut self, name: &str) -> Result<Option<Vec<u8>>> {
        check_name(name)?;
        Ok(self.0.lock().unwrap().get(name).cloned())
    }
    fn put(&mut self, name: &str, bytes: &[u8]) -> Result<()> {
        check_name(name)?;
        self.0
            .lock()
            .unwrap()
            .insert(name.to_string(), bytes.to_vec());
        Ok(())
    }
    fn remove(&mut self, name: &str) -> Result<()> {
        self.0.lock().unwrap().remove(name);
        Ok(())
    }
    fn list(&mut self) -> Result<Vec<String>> {
        Ok(self.0.lock().unwrap().keys().cloned().collect())
    }
}

const LOCAL_AAD: &[u8] = b"lbx:sync/local-record/v1";

/// Seal a local record under the bundle's local key. Random nonce: the
/// local key seals few records, and the default suite (AES-256-GCM-SIV)
/// keeps even a repeated nonce from breaking confidentiality beyond
/// equality.
pub fn seal_local(keys: &BundleKeys, kind: &str, plaintext: &[u8]) -> Result<Vec<u8>> {
    let mut nonce = [0u8; 12];
    fill_random(&mut nonce)?;
    let ct = aead::seal(
        keys.suite(),
        keys.local_key(),
        &nonce,
        &local_aad(keys, kind),
        plaintext,
    )?;
    let mut out = Vec::with_capacity(12 + ct.len());
    out.extend_from_slice(&nonce);
    out.extend_from_slice(&ct);
    Ok(out)
}

pub fn open_local(keys: &BundleKeys, kind: &str, sealed: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
    let fail = || SyncError::ObjectAuth {
        name: format!("local {kind}"),
    };
    if sealed.len() < 12 + 16 {
        return Err(fail());
    }
    let nonce: [u8; 12] = sealed[..12].try_into().expect("12 bytes");
    aead::open(
        keys.suite(),
        keys.local_key(),
        &nonce,
        &local_aad(keys, kind),
        &sealed[12..],
    )
    .map(Zeroizing::new)
    .map_err(|_| fail())
}

fn local_aad(keys: &BundleKeys, kind: &str) -> Vec<u8> {
    let mut a = Vec::with_capacity(LOCAL_AAD.len() + 16 + kind.len());
    a.extend_from_slice(LOCAL_AAD);
    a.extend_from_slice(&keys.bundle().0);
    a.extend_from_slice(kind.as_bytes());
    a
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keys::tests::fixed_keys;
    use luksbox_core::CipherSuite;

    #[test]
    fn fs_local_round_trip_and_lock() {
        let d = tempfile::tempdir().unwrap();
        let dir = d.path().join("b");
        let mut l = FsLocal::open(&dir).unwrap();
        l.put("state", b"abc").unwrap();
        assert_eq!(l.get("state").unwrap().unwrap(), b"abc");
        assert_eq!(l.list().unwrap(), vec!["state".to_string()]);
        assert!(l.put("../x", b"").is_err());
        assert!(l.put("UP", b"").is_err());
        // A second process (second lock holder) is refused.
        assert!(FsLocal::open(&dir).is_err());
        drop(l);
        assert!(FsLocal::open(&dir).is_ok());
    }

    /// Outbox objects and records (written differently on Apple
    /// platforms: see `FsLocal`) replace atomically and leave no
    /// temporary file behind.
    #[test]
    fn outbox_objects_and_records_leave_no_temporary_files() {
        let d = tempfile::tempdir().unwrap();
        let mut l = FsLocal::open(&d.path().join("b")).unwrap();
        l.put("p-0a", b"page").unwrap();
        l.put("staged", b"record").unwrap();
        l.put("p-0a", b"page again").unwrap();
        l.put("staged", b"record 2").unwrap();
        assert_eq!(
            l.list().unwrap(),
            vec!["p-0a".to_string(), "staged".to_string()]
        );
        assert_eq!(l.get("p-0a").unwrap().unwrap(), b"page again");
        assert_eq!(l.get("staged").unwrap().unwrap(), b"record 2");
    }

    #[test]
    fn local_records_are_bound_to_kind_and_bundle() {
        let k = fixed_keys(CipherSuite::Aes256GcmSiv, [1; 16]);
        let k2 = fixed_keys(CipherSuite::Aes256GcmSiv, [2; 16]);
        let s = seal_local(&k, "state", b"hello").unwrap();
        assert_eq!(&open_local(&k, "state", &s).unwrap()[..], b"hello");
        assert!(open_local(&k, "staged", &s).is_err());
        assert!(open_local(&k2, "state", &s).is_err());
    }
}
