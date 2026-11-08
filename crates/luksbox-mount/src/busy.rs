// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Penthertz <https://penthertz.com> (https://x.com/PentHertz)

//! "The mount is still saving": shared by the FUSE and FUSE-T adapters.
//!
//! While a mount serves a vault, its process holds a shared `flock` until
//! it exits, after the final save at unmount; `unmount` takes it
//! exclusively once the kernel (or FUSE-T's NFS client) has let go of the
//! mountpoint, so it returns only when the vault is saved and released.
//! Without it, `luksbox umount mnt && luksbox ls vault.lbx /` failed with
//! "vault locked by another process", and a computer switched off right
//! after `umount` could lose the last 30 s of changes. Nothing is written
//! to disk but an empty lock file; on a file system without `flock` this
//! is skipped.
//!
//! Two locks: one on a file only this user can open (the per-user
//! temporary folder of macOS, `$XDG_RUNTIME_DIR` on Linux, named after the
//! mountpoint), which `unmount` waits on when it is there, and one on the
//! mountpoint directory itself (opened before the mount covers it), the
//! fallback when there is no such folder or the mount was started by an
//! older version. Any local process that can read the mountpoint
//! directory can take a shared lock on it too and make `unmount` wait its
//! full [`UNMOUNT_SAVE_WAIT`]; nobody else can open the private file.

use std::os::fd::AsRawFd;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

/// Held only for its locks, released when dropped (or when the process
/// exits, which is what the daemonized mounts rely on).
pub(crate) struct MountBusy {
    _dir: Option<std::fs::File>,
    _private: Option<std::fs::File>,
}

impl MountBusy {
    /// Lock the directory `mountpoint` names, which must still be the
    /// one `harden_mountpoint` probed (`expected` = its `(dev, ino)`):
    /// opened with `O_DIRECTORY | O_NOFOLLOW`, so a directory swapped in
    /// since the probe is refused rather than locked in its place. Also
    /// the private lock file, when there is a private folder for it.
    pub(crate) fn hold(mountpoint: &Path, expected: (u64, u64)) -> std::io::Result<Self> {
        use std::os::unix::fs::{MetadataExt as _, OpenOptionsExt as _};
        let dir = std::fs::OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW)
            .open(mountpoint)?;
        let m = dir.metadata()?;
        if (m.dev(), m.ino()) != expected {
            return Err(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                format!(
                    "mountpoint {} was swapped between probe and mount; refusing",
                    mountpoint.display()
                ),
            ));
        }
        let private = private_lock_path(mountpoint).and_then(|p| {
            let f = std::fs::OpenOptions::new()
                .read(true)
                .write(true)
                .create(true)
                .truncate(false)
                .mode(0o600)
                .custom_flags(libc::O_NOFOLLOW)
                .open(p)
                .ok()?;
            shared_lock(&f).then_some(f)
        });
        let dir = shared_lock(&dir).then_some(dir);
        Ok(Self {
            _dir: dir,
            _private: private,
        })
    }
}

fn shared_lock(f: &std::fs::File) -> bool {
    // SAFETY: a valid fd we own.
    unsafe { libc::flock(f.as_raw_fd(), libc::LOCK_SH | libc::LOCK_NB) == 0 }
}

/// This user's private folder for lock files: owned by us and closed to
/// everyone else (mode `0700`), else `None`.
fn private_dir() -> Option<PathBuf> {
    use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};
    #[cfg(target_os = "macos")]
    let dir = {
        // The per-user temporary folder (`/var/folders/.../T/`), the same
        // for every process of the user whatever `$TMPDIR` says.
        let mut buf = vec![0u8; 1024];
        // SAFETY: `buf` is writable for its length.
        let n = unsafe {
            libc::confstr(
                libc::_CS_DARWIN_USER_TEMP_DIR,
                buf.as_mut_ptr().cast(),
                buf.len(),
            )
        };
        if n == 0 || n > buf.len() {
            return None;
        }
        buf.truncate(n - 1);
        PathBuf::from(String::from_utf8(buf).ok()?)
    };
    #[cfg(not(target_os = "macos"))]
    let dir = PathBuf::from(std::env::var_os("XDG_RUNTIME_DIR")?);
    if !dir.is_absolute() {
        return None;
    }
    let m = std::fs::symlink_metadata(&dir).ok()?;
    // SAFETY: getuid has no preconditions.
    let uid = unsafe { libc::getuid() };
    (m.is_dir() && m.uid() == uid && m.permissions().mode() & 0o077 == 0).then_some(dir)
}

/// `<private folder>/luksbox-mount-<hash of the canonical mountpoint>.lock`.
fn private_lock_path(mountpoint: &Path) -> Option<PathBuf> {
    use std::os::unix::ffi::OsStrExt as _;
    let canonical = mountpoint.canonicalize().ok()?;
    // FNV-1a: the same in every build, so a newer `umount` finds the
    // file an older mount made.
    let mut h: u64 = 0xcbf2_9ce4_8422_2325;
    for b in canonical.as_os_str().as_bytes() {
        h ^= u64::from(*b);
        h = h.wrapping_mul(0x0100_0000_01b3);
    }
    Some(private_dir()?.join(format!("luksbox-mount-{h:016x}.lock")))
}

/// How long `unmount` waits for the mount to save and release the vault.
pub(crate) const UNMOUNT_SAVE_WAIT: Duration = Duration::from_secs(120);

/// After the unmount itself: wait until the mount process has saved and
/// released the vault (it holds [`MountBusy`] until it exits).
pub(crate) fn wait_for_mount_to_finish(mountpoint: &Path) -> std::io::Result<()> {
    use std::os::unix::fs::{MetadataExt as _, OpenOptionsExt as _};
    // The private lock file, when the mount made one: nobody else can
    // hold it. Else the mountpoint directory.
    // SAFETY: getuid has no preconditions.
    let uid = unsafe { libc::getuid() };
    let private = private_lock_path(mountpoint).and_then(|p| {
        let f = std::fs::OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW)
            .open(&p)
            .ok()?;
        let m = f.metadata().ok()?;
        (m.is_file() && m.uid() == uid).then_some((f, p))
    });
    let (lock, private_path) = match private {
        Some((f, p)) => (f, Some(p)),
        None => {
            let Ok(dir) = std::fs::File::open(mountpoint) else {
                return Ok(());
            };
            (dir, None)
        }
    };
    let start = Instant::now();
    let mut said = false;
    loop {
        // SAFETY: a valid fd we own.
        if unsafe { libc::flock(lock.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } == 0 {
            // Free: the mount saved and exited. The lock file is no longer
            // needed (a new mount of the same folder makes it again).
            if let Some(p) = private_path {
                let _ = std::fs::remove_file(p);
            }
            // SAFETY: as above.
            unsafe { libc::flock(lock.as_raw_fd(), libc::LOCK_UN) };
            return Ok(());
        }
        let e = std::io::Error::last_os_error();
        if e.raw_os_error() != Some(libc::EWOULDBLOCK) {
            // No flock here (ENOLCK, ...): nothing to wait on.
            return Ok(());
        }
        if start.elapsed() >= UNMOUNT_SAVE_WAIT {
            return Err(std::io::Error::other(format!(
                "unmounted, but the vault was still being saved after {} s; wait before \
                 opening it or switching the computer off",
                UNMOUNT_SAVE_WAIT.as_secs()
            )));
        }
        if !said && start.elapsed() >= Duration::from_secs(1) {
            eprintln!("waiting for the vault to be saved...");
            said = true;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The private lock file is in a folder only this user can open and
    /// is named after the canonical mountpoint (the same from any path to
    /// it); a shared lock someone else takes on the mountpoint directory
    /// no longer makes `wait_for_mount_to_finish` wait.
    #[test]
    fn unmount_waits_on_the_private_lock_not_the_shared_directory() {
        let Some(dir) = private_dir() else {
            eprintln!("[skip] no private folder for lock files here");
            return;
        };
        let tmp = tempfile::tempdir().unwrap();
        let mnt = tmp.path().join("mnt");
        std::fs::create_dir(&mnt).unwrap();
        std::os::unix::fs::symlink(&mnt, tmp.path().join("alias")).unwrap();
        let p = private_lock_path(&mnt).unwrap();
        assert!(p.starts_with(&dir));
        assert_eq!(
            private_lock_path(&tmp.path().join("alias")),
            Some(p.clone())
        );

        use std::os::unix::fs::MetadataExt as _;
        let m = std::fs::metadata(&mnt).unwrap();
        let busy = MountBusy::hold(&mnt, (m.dev(), m.ino())).unwrap();
        // Someone else holds a shared lock on the directory, for good.
        let other = std::fs::File::open(&mnt).unwrap();
        assert!(shared_lock(&other));
        // While the mount holds its locks, unmount waits ...
        let waiter = {
            let mnt = mnt.clone();
            std::thread::spawn(move || {
                let t = Instant::now();
                wait_for_mount_to_finish(&mnt).unwrap();
                t.elapsed()
            })
        };
        std::thread::sleep(Duration::from_millis(300));
        assert!(
            !waiter.is_finished(),
            "returned while the mount held its lock"
        );
        // ... and returns once the mount let go, although the directory
        // is still locked by the other process.
        drop(busy);
        let waited = waiter.join().unwrap();
        assert!(waited < Duration::from_secs(5), "waited {waited:?}");
        assert!(!p.exists(), "the lock file was left behind");
        drop(other);
    }
}
