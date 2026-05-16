// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Penthertz <https://penthertz.com> (https://x.com/PentHertz)

use std::fs::{File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

use fs2::FileExt;
use luksbox_core::file_util::{secure_create_new, sync_parent_dir};
use luksbox_core::{
    Argon2idParams, CipherSuite, HEADER_SIZE, Header, KdfId, Keyslot, MAX_KEYSLOTS,
    MasterVolumeKey, SlotKind, SubKey,
};

/// Capture the (device, inode) tuple of an open file. This is the
/// kernel-level identifier of the underlying inode, immune to path
/// or symlink renaming after the fd was opened.
///
/// We use this for TOCTOU-detection: if two `open(path)` calls in
/// the same logical operation resolve to different inodes, the
/// path was substituted between opens, refuse to proceed.
///
/// POSIX uses (st_dev, st_ino). Windows uses
/// (volume_serial_number, file_index) from
/// GetFileInformationByHandle, which std exposes via
/// MetadataExt on a File handle (both stable since Rust 1.63).
#[cfg(unix)]
fn inode_of(f: &File) -> std::io::Result<(u64, u64)> {
    use std::os::unix::fs::MetadataExt;
    let m = f.metadata()?;
    Ok((m.dev(), m.ino()))
}

#[cfg(windows)]
fn inode_of(f: &File) -> std::io::Result<(u64, u64)> {
    // The std-lib equivalents (`MetadataExt::volume_serial_number` /
    // `file_index`) are still nightly-only behind `windows_by_handle`
    // (rust-lang/rust#63010), so we call kernel32 directly. Same data,
    // same syscall the std method would have invoked.
    use std::os::windows::io::AsRawHandle;

    #[repr(C)]
    struct Filetime {
        low: u32,
        high: u32,
    }
    #[repr(C)]
    struct ByHandleFileInformation {
        attrs: u32,
        creation: Filetime,
        last_access: Filetime,
        last_write: Filetime,
        volume_serial: u32,
        size_high: u32,
        size_low: u32,
        num_links: u32,
        index_high: u32,
        index_low: u32,
    }
    #[link(name = "kernel32")]
    unsafe extern "system" {
        fn GetFileInformationByHandle(
            handle: *mut core::ffi::c_void,
            info: *mut ByHandleFileInformation,
        ) -> i32;
    }

    let handle = f.as_raw_handle() as *mut core::ffi::c_void;
    let mut info = std::mem::MaybeUninit::<ByHandleFileInformation>::uninit();
    let ok = unsafe { GetFileInformationByHandle(handle, info.as_mut_ptr()) };
    if ok == 0 {
        return Err(std::io::Error::last_os_error());
    }
    let info = unsafe { info.assume_init() };
    let vol = u64::from(info.volume_serial);
    let idx = (u64::from(info.index_high) << 32) | u64::from(info.index_low);
    Ok((vol, idx))
}

/// Detect whether `path` is a symlink WITHOUT following it. Used by
/// the `LUKSBOX_NO_FOLLOW_SYMLINKS=1` opt-in mode to refuse
/// symlinked vault files entirely.
fn is_symlink(path: &Path) -> bool {
    std::fs::symlink_metadata(path)
        .map(|m| m.file_type().is_symlink())
        .unwrap_or(false)
}

/// Open a path read+write while also enforcing optional TOCTOU-detection:
/// if `expected_inode` is `Some`, verify the freshly-opened fd resolves
/// to the same (device, inode) that a previous open captured. New open
/// paths should prefer locking this returned handle before reading mutable
/// security state; the expected-inode hook remains for operations that must
/// intentionally re-open a path.
///
/// If `LUKSBOX_NO_FOLLOW_SYMLINKS=1` is set in the env and `path`
/// is a symlink, refuse with `Error::SymlinkRefused` BEFORE
/// open(), this is the "paranoid mode" that breaks legit symlink
/// users in exchange for stronger guarantees on shared filesystems.
fn open_rw_checked(
    path: &Path,
    expected_inode: Option<(u64, u64)>,
) -> Result<(File, (u64, u64)), Error> {
    if std::env::var_os("LUKSBOX_NO_FOLLOW_SYMLINKS").is_some() && is_symlink(path) {
        return Err(Error::SymlinkRefused {
            path: path.display().to_string(),
        });
    }
    let f = OpenOptions::new()
        .read(true)
        .write(true)
        .open(path)
        .map_err(|e| map_io_err_to_vault_locked(e, path))?;
    let actual = inode_of(&f).map_err(|e| map_io_err_to_vault_locked(e, path))?;
    if let Some(expected) = expected_inode {
        if actual != expected {
            return Err(Error::PathSubstituted {
                path: path.display().to_string(),
            });
        }
    }
    Ok((f, actual))
}

/// After we have opened a file and taken its lock, confirm that the path the
/// caller asked for still resolves to the inode we hold. Catches the narrow
/// race where an attacker renamed a different file over `path` between
/// `open_rw_checked` and `lock_handles`. Performed via a fresh read-only
/// open + `inode_of` because stable `std::fs::metadata` does not expose
/// volume serial / file index on Windows; this matches the FFI path
/// `inode_of` already uses on a handle.
fn verify_path_inode(path: &Path, expected: (u64, u64)) -> Result<(), Error> {
    let probe = OpenOptions::new()
        .read(true)
        .open(path)
        .map_err(|e| map_io_err_to_vault_locked(e, path))?;
    let actual = inode_of(&probe).map_err(|e| map_io_err_to_vault_locked(e, path))?;
    if actual != expected {
        return Err(Error::PathSubstituted {
            path: path.display().to_string(),
        });
    }
    Ok(())
}

/// Remap an `io::Error` from a read against a vault file to a
/// structured `Error::VaultLocked { path }` if the OS reported a
/// region-lock conflict, otherwise wrap as `Error::Io`.
///
/// On Windows, `fs2::FileExt::try_lock_exclusive` uses `LockFileEx`
/// over the entire file. A peer process holding that lock does NOT
/// prevent us from `open()`ing the file - `LockFileEx` is byte-range,
/// not share-mode - but it DOES make any read against the locked
/// range fail with `ERROR_LOCK_VIOLATION` (os error 33). The
/// upstream `lock_handles` remap only catches the case where WE try
/// to take the lock and conflict; if the peer's lock is already held
/// when we hit a read first, the raw `io::Error` would bubble up
/// untranslated and the user sees a cryptic "os error 33" instead of
/// "vault locked by another process".
///
/// On POSIX, advisory `flock` doesn't block reads from other
/// processes (`man flock`: "advisory record locks..."), so this remap
/// is a no-op there - the conflict always surfaces inside
/// `lock_handles`. Kept conditional via `cfg(windows)` so non-Windows
/// builds don't carry the dead branch in the optimized binary.
fn map_io_err_to_vault_locked(err: std::io::Error, path: &Path) -> Error {
    #[cfg(windows)]
    {
        // ERROR_LOCK_VIOLATION = 33 (winerror.h). Hardcoded because
        // we don't otherwise depend on the `windows` crate, and a
        // single integer literal isn't worth a build-system entry.
        if err.raw_os_error() == Some(33) {
            return Error::VaultLocked {
                path: path.display().to_string(),
            };
        }
    }
    let _ = path; // silence unused-on-POSIX warning
    Error::from(err)
}

/// Take an exclusive advisory lock on each provided ALREADY-OPEN
/// file handle. Skipped entirely if `LUKSBOX_NO_LOCK` is set in the
/// env (escape hatch for read-only inspection from scripts that
/// knowingly race a live writer, DANGEROUS in any other context).
///
/// The lock is held by the file handle, dropping the handle releases
/// the lock. Callers that want lifetime-of-Container locking should
/// pass the same handle they store in the Container struct.
///
/// Why this takes existing handles instead of opening fresh ones:
/// on Windows, `LockFileEx` fails with `ERROR_LOCK_VIOLATION` if
/// another handle in the same process has the file open with write
/// access, even with `FILE_SHARE_*` flags set. Opening a separate
/// handle for the lock then trying to lock it raced the I/O handle
/// in our previous design. Linux's `flock` is per-inode and didn't
/// have this conflict, but locking the same handle that does I/O is
/// the correct cross-platform pattern. Path-substitution attack
/// detection on creation is now redundant (`create_new(true)`
/// atomically allocated the inode, no inter-open gap), and on open
/// it's covered by locking the I/O handle itself before reading mutable
/// security state.
///
/// `handles_and_paths`: each tuple's path is purely for error-
/// reporting (`Error::VaultLocked { path }`).
///
/// Errors:
///   - `Error::VaultLocked` if another process holds an overlapping
///     lock on any of the supplied handles
fn lock_handles(handles_and_paths: &[(&File, &Path)]) -> Result<(), Error> {
    if std::env::var_os("LUKSBOX_NO_LOCK").is_some() {
        return Ok(());
    }
    for (file, path) in handles_and_paths {
        if file.try_lock_exclusive().is_err() {
            return Err(Error::VaultLocked {
                path: path.display().to_string(),
            });
        }
    }
    Ok(())
}

/// Where the 8 KB container header lives.
///
/// - `Inline`: header occupies bytes 0..8192 of the vault file (current default).
/// - `Detached(file, path)`: header lives in a separate sidecar file; the
///   vault file starts at offset 0 with the metadata region. Without the
///   header file, the vault is indistinguishable from random, no magic
///   bytes, no keyslots, nothing to attack.
enum HeaderStorage {
    Inline,
    Detached(File, PathBuf),
}

use crate::error::Error;
use crate::metadata::{self, DEFAULT_METADATA_REGION_SIZE, METADATA_OVERHEAD};

pub enum UnlockMaterial<'a> {
    Passphrase(&'a [u8]),
    Fido2 {
        passphrase: Option<&'a [u8]>,
        cred_id: &'a [u8],
        hmac_secret: &'a [u8; 32],
    },
    /// Hybrid passphrase + ML-KEM-768. Caller has already pulled the
    /// kyber pubkey + ciphertext from the `.hybrid` sidecar, decrypted
    /// the seed from the `.kyber` file, and decapsulated to produce
    /// `pq_shared`. Only `HybridPqKemPassphrase` slots are tried.
    HybridPqPassphrase {
        passphrase: &'a [u8],
        pq_shared: &'a [u8; 32],
    },
    /// Hybrid FIDO2 + ML-KEM-768. Caller has already done the YubiKey
    /// touch (to get `hmac_secret`) AND the Kyber decapsulation (over
    /// the sidecar ciphertext using the seed from the `.kyber` file).
    /// Only `HybridPqKemFido2` slots whose `cred_id` matches are tried.
    HybridPqFido2 {
        passphrase: Option<&'a [u8]>,
        cred_id: &'a [u8],
        hmac_secret: &'a [u8; 32],
        pq_shared: &'a [u8; 32],
    },
    /// TPM 2.0-sealed slot. The closure is invoked once per
    /// `Tpm2Sealed` keyslot in the header with that slot's
    /// `SealedBlob` bytes; it must return the original 32-byte KEK
    /// that was sealed at enroll time. The first slot whose KEK
    /// successfully unwraps the MVK wins.
    ///
    /// Caller (CLI / GUI) is responsible for opening a TPM context
    /// once via `luksbox_tpm::Tpm2Sealer::new()` and passing a
    /// closure that parses the blob via `SealedBlob::from_bytes`,
    /// calls `Tpm2Sealer::unseal`, and returns the bytes. This
    /// inversion keeps `luksbox-format` itself TPM-agnostic - no
    /// `tss-esapi` / `libtss2-*` dep.
    ///
    /// Closure errors (TPM busy, missing chip, lockout) are
    /// reported per-slot but iteration continues so a vault with
    /// e.g. one TPM slot from a different machine and one local
    /// TPM slot can still unlock via the matching slot.
    Tpm2 {
        unseal: &'a mut dyn FnMut(&[u8]) -> Result<[u8; 32], String>,
    },
    /// Fused TPM 2.0 + FIDO2 slot. Unlock requires BOTH the local
    /// TPM (via the `unseal` closure, same shape as `Tpm2` above)
    /// AND a connected FIDO2 authenticator's hmac-secret output
    /// (`hmac_secret`, pre-computed by the caller via touch + PIN).
    ///
    /// `cred_id` selects which Tpm2Fido2 slot to attempt, only
    /// slots whose stored cred_id matches are tried. Caller must
    /// have already used the slot's `tpm2_fido2_cred_id()` to
    /// drive the FIDO2 authenticator's hmac_secret call with the
    /// matching slot's `fido2_hmac_salt`; that's why the cred_id
    /// match here selects an exact slot rather than iterating.
    ///
    /// Same closure-error tolerance as `Tpm2` (per-slot failure
    /// continues iteration).
    Tpm2Fido2 {
        unseal: &'a mut dyn FnMut(&[u8]) -> Result<[u8; 32], String>,
        cred_id: &'a [u8],
        hmac_secret: &'a [u8; 32],
    },
    /// Hybrid TPM 2.0 + ML-KEM-768 slot. Same closure pattern as
    /// `Tpm2`; `pq_shared` is the Kyber-decapsulated 32-byte
    /// shared secret the caller has already obtained from the
    /// `.lbx.hybrid` sidecar entry + the user's `.kyber` seed file.
    HybridPqTpm2 {
        unseal: &'a mut dyn FnMut(&[u8]) -> Result<[u8; 32], String>,
        pq_shared: &'a [u8; 32],
    },
    /// Maximum-paranoia hybrid TPM 2.0 + FIDO2 + ML-KEM-768 slot.
    /// Three independent factors required.
    HybridPqTpm2Fido2 {
        unseal: &'a mut dyn FnMut(&[u8]) -> Result<[u8; 32], String>,
        cred_id: &'a [u8],
        hmac_secret: &'a [u8; 32],
        pq_shared: &'a [u8; 32],
    },
}

/// Open `.lbx` container backed by a file on disk.
///
/// Creation reserves a fixed metadata region right after the header; the data
/// area starts at `header.data_offset` and grows as `luksbox-vfs` writes
/// chunks.  Closing the container persists the header back to disk if it has
/// been mutated (keyslot enroll/revoke).
pub struct Container {
    file: File,
    path: PathBuf,
    header_storage: HeaderStorage,
    pub header: Header,
    mvk: MasterVolumeKey,
    header_dirty: bool,
    /// If set, every metadata-blob write also writes an updated
    /// anchor file at this path. See `crate::anchor` for the format
    /// and threat model.
    anchor_path: Option<PathBuf>,
    /// Set while a crash-safe MVK rotation is in flight. Tracks the
    /// real (committed) paths so `commit_atomic_rotation` can rename
    /// the `.rotating` files into place, or `abort_atomic_rotation`
    /// can clean them up.
    rotation: Option<RotationState>,
    // Locks are held intrinsically by `file` (and by the `File`
    // inside `header_storage` when detached). When the Container is
    // dropped, those handles are dropped, which releases their
    // OS-level locks. No separate Vec needed since we no longer
    // open second handles just to hold the lock.
    //
    // Bypass mechanism: if `LUKSBOX_NO_LOCK=1` is set in the env,
    // `lock_handles` returns Ok without taking any locks. Documented
    // as DANGEROUS in the env-var guard for cases where the user
    // knows what they're doing (e.g. read-only inspection from a
    // backup script that races a live writer they don't care to
    // coordinate with, accepts the risk).
}

/// In-flight crash-safe rotation. While set, `self.file` is open on
/// `tmp_data_path`; reads/writes go to the temp file. The original
/// vault at `committed_data_path` is untouched until `commit_*` runs.
struct RotationState {
    tmp_data_path: PathBuf,
    committed_data_path: PathBuf,
}

impl Container {
    /// Create a new container on disk with a single passphrase keyslot.
    /// If `header_path` is `Some`, the 8 KB header is written to a separate
    /// sidecar file ("detached header" mode); the vault file at `path`
    /// starts at offset 0 with the metadata region.
    pub fn create_with_passphrase(
        path: &Path,
        header_path: Option<&Path>,
        cipher: CipherSuite,
        kdf_params: Argon2idParams,
        passphrase: &[u8],
    ) -> Result<Self, Error> {
        Self::create_with_passphrase_flags(path, header_path, cipher, kdf_params, 0, passphrase)
    }

    /// Variant of `create_with_passphrase` that also takes a `flags` u32
    /// (see `luksbox_core::FLAG_PAD_FILES_POW2` etc.).
    pub fn create_with_passphrase_flags(
        path: &Path,
        header_path: Option<&Path>,
        cipher: CipherSuite,
        kdf_params: Argon2idParams,
        flags: u32,
        passphrase: &[u8],
    ) -> Result<Self, Error> {
        Self::create_internal(path, header_path, cipher, flags, |mvk, header| {
            Keyslot::new_passphrase(cipher, mvk, passphrase, kdf_params, &header.header_salt)
        })
    }

    /// Create a new container with a single hybrid passphrase + ML-KEM
    /// keyslot. Caller has already generated a Kyber keypair and called
    /// `encapsulate(pk)` to obtain `pq_shared`. The matching ciphertext
    /// must be stored separately in the `<vault>.hybrid` sidecar and
    /// the seed in the user's `.kyber` file (this constructor does NOT
    /// touch those files, it just builds the keyslot).
    pub fn create_with_hybrid_pq_passphrase(
        path: &Path,
        header_path: Option<&Path>,
        cipher: CipherSuite,
        kdf_params: Argon2idParams,
        flags: u32,
        passphrase: &[u8],
        pq_shared: &[u8; 32],
    ) -> Result<Self, Error> {
        Self::create_internal(path, header_path, cipher, flags, |mvk, header| {
            Keyslot::new_hybrid_pq_passphrase(
                cipher,
                mvk,
                passphrase,
                pq_shared,
                kdf_params,
                &header.header_salt,
            )
        })
    }

    /// ML-KEM-1024 variant of `create_with_hybrid_pq_passphrase`.
    /// The on-disk slot bytes differ only in the kind byte (= 6).
    pub fn create_with_hybrid_pq_1024_passphrase(
        path: &Path,
        header_path: Option<&Path>,
        cipher: CipherSuite,
        kdf_params: Argon2idParams,
        flags: u32,
        passphrase: &[u8],
        pq_shared: &[u8; 32],
    ) -> Result<Self, Error> {
        Self::create_internal(path, header_path, cipher, flags, |mvk, header| {
            Keyslot::new_hybrid_pq_1024_passphrase(
                cipher,
                mvk,
                passphrase,
                pq_shared,
                kdf_params,
                &header.header_salt,
            )
        })
    }

    /// Create a new container with a single hybrid FIDO2 + ML-KEM keyslot.
    /// Caller has already (a) done the FIDO2 enroll to obtain `cred_id`
    /// and `hmac_secret`, and (b) generated a Kyber keypair + encapsulated
    /// to obtain `pq_shared`. The matching Kyber ciphertext goes in the
    /// `.hybrid` sidecar; the seed goes in the user's `.kyber` file.
    pub fn create_with_hybrid_pq_fido2(
        path: &Path,
        header_path: Option<&Path>,
        cipher: CipherSuite,
        kdf_params: Argon2idParams,
        flags: u32,
        passphrase: Option<&[u8]>,
        hmac_secret: &[u8; 32],
        pq_shared: &[u8; 32],
        cred_id: &[u8],
        hmac_salt: [u8; 32],
    ) -> Result<Self, Error> {
        Self::create_internal(path, header_path, cipher, flags, |mvk, header| {
            Keyslot::new_hybrid_pq_fido2(
                cipher,
                mvk,
                passphrase,
                hmac_secret,
                pq_shared,
                cred_id,
                hmac_salt,
                kdf_params,
                &header.header_salt,
            )
        })
    }

    /// ML-KEM-1024 variant of `create_with_hybrid_pq_fido2`.
    pub fn create_with_hybrid_pq_1024_fido2(
        path: &Path,
        header_path: Option<&Path>,
        cipher: CipherSuite,
        kdf_params: Argon2idParams,
        flags: u32,
        passphrase: Option<&[u8]>,
        hmac_secret: &[u8; 32],
        pq_shared: &[u8; 32],
        cred_id: &[u8],
        hmac_salt: [u8; 32],
    ) -> Result<Self, Error> {
        Self::create_internal(path, header_path, cipher, flags, |mvk, header| {
            Keyslot::new_hybrid_pq_1024_fido2(
                cipher,
                mvk,
                passphrase,
                hmac_secret,
                pq_shared,
                cred_id,
                hmac_salt,
                kdf_params,
                &header.header_salt,
            )
        })
    }

    /// Create a new container with a single derived-MVK FIDO2 keyslot.
    /// The MVK is derived from the YubiKey's hmac-secret output rather than
    /// generated randomly, there's no wrapped MVK in the vault. This is
    /// the strongest "vault is meaningless without the YubiKey" mode but
    /// has no MVK-layer backup: lose the YubiKey, lose the data.
    pub fn create_with_fido2_derived_mvk(
        path: &Path,
        header_path: Option<&Path>,
        cipher: CipherSuite,
        cred_id: &[u8],
        hmac_secret: &[u8; 32],
        hmac_salt: [u8; 32],
    ) -> Result<Self, Error> {
        let metadata_region_size = DEFAULT_METADATA_REGION_SIZE;
        let metadata_offset = if header_path.is_some() {
            0
        } else {
            HEADER_SIZE as u64
        };
        let data_offset = metadata_offset + metadata_region_size;

        // MVK is FORCED to the HKDF output. Subsequent keyslots (if added
        // later via `enroll`) will wrap this same MVK under their own KEKs.
        let mvk = luksbox_core::keyslot::derive_mvk_from_fido2(&hmac_salt, hmac_secret);

        let mut header = Header::try_new(cipher, KdfId::Argon2id, 4096, data_offset)?;
        header.metadata_offset = metadata_offset;
        header.metadata_size = metadata_region_size;

        let slot = Keyslot::new_fido2_derived_mvk(cred_id, hmac_salt)?;
        header.install_slot(0, slot)?;

        let mut file = secure_create_new(path)?;

        let header_bytes = header.to_bytes(&mvk);
        let header_storage = match header_path {
            None => {
                file.write_all(&header_bytes)?;
                HeaderStorage::Inline
            }
            Some(hp) => {
                let mut hf = secure_create_new(hp)?;
                hf.write_all(&header_bytes)?;
                hf.flush()?;
                HeaderStorage::Detached(hf, hp.to_path_buf())
            }
        };

        let mut region = vec![0u8; metadata_region_size as usize];
        metadata::write_metadata(cipher, &mvk, &header.header_salt, b"", &mut region)?;
        file.write_all(&region)?;
        file.flush()?;

        // Lock the just-created handles in place (see lock_handles
        // doc for why we reuse the I/O handles instead of opening
        // fresh ones).
        match (&header_storage, header_path) {
            (HeaderStorage::Inline, _) => {
                lock_handles(&[(&file, path)])?;
            }
            (HeaderStorage::Detached(hf, _), Some(hp)) => {
                lock_handles(&[(&file, path), (hf, hp)])?;
            }
            (HeaderStorage::Detached(_, _), None) => {
                unreachable!("Detached header storage requires a header_path, this is a bug")
            }
        }

        Ok(Self {
            file,
            path: path.to_path_buf(),
            header_storage,
            header,
            mvk,
            header_dirty: false,
            anchor_path: None,
            rotation: None,
        })
    }

    /// Create a new container on disk with a single FIDO2 keyslot.
    pub fn create_with_fido2(
        path: &Path,
        header_path: Option<&Path>,
        cipher: CipherSuite,
        kdf_params: Argon2idParams,
        passphrase: Option<&[u8]>,
        hmac_secret: &[u8; 32],
        cred_id: &[u8],
        hmac_salt: [u8; 32],
    ) -> Result<Self, Error> {
        Self::create_with_fido2_flags(
            path,
            header_path,
            cipher,
            kdf_params,
            0,
            passphrase,
            hmac_secret,
            cred_id,
            hmac_salt,
        )
    }

    /// Variant of `create_with_fido2` taking an extra `flags` u32.
    pub fn create_with_fido2_flags(
        path: &Path,
        header_path: Option<&Path>,
        cipher: CipherSuite,
        kdf_params: Argon2idParams,
        flags: u32,
        passphrase: Option<&[u8]>,
        hmac_secret: &[u8; 32],
        cred_id: &[u8],
        hmac_salt: [u8; 32],
    ) -> Result<Self, Error> {
        Self::create_internal(path, header_path, cipher, flags, |mvk, header| {
            Keyslot::new_fido2(
                cipher,
                mvk,
                passphrase,
                hmac_secret,
                cred_id,
                hmac_salt,
                kdf_params,
                &header.header_salt,
            )
        })
    }

    fn create_internal<F>(
        path: &Path,
        header_path: Option<&Path>,
        cipher: CipherSuite,
        flags: u32,
        build_slot: F,
    ) -> Result<Self, Error>
    where
        F: FnOnce(&MasterVolumeKey, &Header) -> Result<Keyslot, luksbox_core::Error>,
    {
        let metadata_region_size = DEFAULT_METADATA_REGION_SIZE;
        // Detached: vault file starts directly with the metadata region.
        // Inline: vault file has the 8 KB header at offset 0.
        let metadata_offset = if header_path.is_some() {
            0
        } else {
            HEADER_SIZE as u64
        };
        let data_offset = metadata_offset + metadata_region_size;

        let mvk = MasterVolumeKey::try_random()
            .map_err(|e| Error::Crypto(luksbox_core::Error::OsRng(e.to_string())))?;
        let mut header = Header::try_new(cipher, KdfId::Argon2id, 4096, data_offset)?;
        header.flags = flags;
        header.metadata_offset = metadata_offset;
        header.metadata_size = metadata_region_size;

        let slot = build_slot(&mvk, &header)?;
        header.install_slot(0, slot)?;

        let mut file = secure_create_new(path)?;

        let header_bytes = header.to_bytes(&mvk);
        let header_storage = match header_path {
            None => {
                file.write_all(&header_bytes)?;
                HeaderStorage::Inline
            }
            Some(hp) => {
                let mut hf = secure_create_new(hp)?;
                hf.write_all(&header_bytes)?;
                hf.flush()?;
                HeaderStorage::Detached(hf, hp.to_path_buf())
            }
        };

        let mut region = vec![0u8; metadata_region_size as usize];
        metadata::write_metadata(cipher, &mvk, &header.header_salt, b"", &mut region)?;
        file.write_all(&region)?;
        file.flush()?;

        // Lock the handles we already have open. Inline mode locks
        // just `file`; detached mode also locks the header sidecar.
        // We don't need a path-substitution check here, the .lbx and
        // (if applicable) the header sidecar were just allocated via
        // `create_new(true)`, so there is no inter-open gap an
        // attacker could race.
        match (&header_storage, header_path) {
            (HeaderStorage::Inline, _) => {
                lock_handles(&[(&file, path)])?;
            }
            (HeaderStorage::Detached(hf, _), Some(hp)) => {
                lock_handles(&[(&file, path), (hf, hp)])?;
            }
            (HeaderStorage::Detached(_, _), None) => {
                unreachable!("Detached header storage requires a header_path, this is a bug")
            }
        }

        Ok(Self {
            file,
            path: path.to_path_buf(),
            header_storage,
            header,
            mvk,
            header_dirty: false,
            anchor_path: None,
            rotation: None,
        })
    }

    /// Open an existing container, recover the MVK by trying the supplied
    /// material against matching keyslots, and verify the header HMAC.
    /// If `header_path` is `Some`, the header is read from that sidecar file
    /// instead of the vault file's offset-0 prefix.
    pub fn open(
        path: &Path,
        header_path: Option<&Path>,
        mut material: UnlockMaterial<'_>,
    ) -> Result<Self, Error> {
        let (file, header_storage, header_bytes, header) =
            Self::load_locked_header(path, header_path)?;
        let mvk = try_unlock(&header, &mut material)?;
        header.verify_hmac(&header_bytes, &mvk)?;
        Ok(Self {
            file,
            path: path.to_path_buf(),
            header_storage,
            header,
            mvk,
            header_dirty: false,
            anchor_path: None,
            rotation: None,
        })
    }

    /// Open a Container with a pre-derived Master Volume Key.
    ///
    /// Used by the FUSE-T mount-helper subprocess: the parent (GUI)
    /// process unlocks the vault normally via `Container::open`,
    /// extracts the MVK with [`Container::mvk_clone`], spawns this
    /// process, and pipes the 32-byte MVK over its stdin. The child
    /// then constructs the Container directly from the MVK without
    /// re-running the unlock derivation. This is what makes FUSE-T
    /// subprocess isolation viable without forcing the user to
    /// re-authenticate on every mount.
    ///
    /// Security:
    /// - The header HMAC is verified against the supplied MVK, so a
    ///   wrong MVK fails fast with `Error::Crypto(HeaderAuthFailed)`
    ///   instead of producing garbled metadata reads downstream.
    /// - The file is opened, locked, and TOCTOU-verified using the
    ///   same machinery as [`Container::open`]; nothing about the
    ///   on-disk integrity story is weakened by skipping the unlock
    ///   derivation.
    /// - The provided MVK is moved into the returned Container, no
    ///   copies are made beyond the field assignment. The caller's
    ///   `MasterVolumeKey` is consumed.
    pub fn open_with_mvk(
        path: &Path,
        header_path: Option<&Path>,
        mvk: MasterVolumeKey,
    ) -> Result<Self, Error> {
        let (file, header_storage, header_bytes, header) =
            Self::load_locked_header(path, header_path)?;
        // Verify HMAC FIRST. If the supplied MVK is wrong, surface a
        // clean error instead of going on to read garbled metadata.
        header.verify_hmac(&header_bytes, &mvk)?;
        Ok(Self {
            file,
            path: path.to_path_buf(),
            header_storage,
            header,
            mvk,
            header_dirty: false,
            anchor_path: None,
            rotation: None,
        })
    }

    /// Shared file-open + lock + TOCTOU re-verification + header read +
    /// header parse path used by both `open` and `open_with_mvk`. Stops
    /// just before the MVK source is needed (HMAC verification).
    ///
    /// Returns `(file, header_storage, header_bytes, header)` so the
    /// caller can run HMAC verification with whatever MVK they have
    /// (derived or supplied).
    fn load_locked_header(
        path: &Path,
        header_path: Option<&Path>,
    ) -> Result<(File, HeaderStorage, [u8; HEADER_SIZE], Header), Error> {
        // Open the actual handles that will back the Container, lock them,
        // and only then read or authenticate the header. This serializes
        // header read/modify/write sequences so a second opener cannot keep
        // a stale pre-lock header in memory and later overwrite keyslot
        // changes made by the first opener.
        let (mut file, file_inode) = open_rw_checked(path, None)?;
        let (mut header_storage, header_inode) = match header_path {
            None => (HeaderStorage::Inline, None),
            Some(hp) => {
                let (hf, hf_inode) = open_rw_checked(hp, None)?;
                (
                    HeaderStorage::Detached(hf, hp.to_path_buf()),
                    Some(hf_inode),
                )
            }
        };

        match (&header_storage, header_path) {
            (HeaderStorage::Inline, _) => {
                lock_handles(&[(&file, path)])?;
            }
            (HeaderStorage::Detached(hf, _), Some(hp)) => {
                lock_handles(&[(&file, path), (hf, hp)])?;
            }
            (HeaderStorage::Detached(_, _), None) => {
                unreachable!("Detached header storage requires a header_path, this is a bug")
            }
        }

        // Post-lock TOCTOU re-verification: the open above and the lock just
        // taken aren't atomic, so an attacker who can write to the parent
        // directory could rename a different file over `path` (or
        // `header_path`) in the gap. Our handles still point at the
        // originally-opened inodes, locked, consistent, but the path now
        // resolves to a different file. The user requested the path; if
        // we proceeded we'd hold the lock on an orphaned inode and any
        // subsequent write would silently land in the wrong file. Reject
        // with `PathSubstituted` so the user can investigate. Once verified,
        // the lock guarantees inode A stays our backing store regardless of
        // any further rename of the path.
        verify_path_inode(path, file_inode)?;
        if let (Some(hp), Some(expected)) = (header_path, header_inode) {
            verify_path_inode(hp, expected)?;
        }

        let mut header_bytes = [0u8; HEADER_SIZE];
        match (&mut header_storage, header_path) {
            (HeaderStorage::Inline, _) => {
                file.seek(SeekFrom::Start(0))
                    .map_err(|e| map_io_err_to_vault_locked(e, path))?;
                file.read_exact(&mut header_bytes)
                    .map_err(|e| map_io_err_to_vault_locked(e, path))?;
            }
            (HeaderStorage::Detached(hf, _), Some(hp)) => {
                hf.seek(SeekFrom::Start(0))
                    .map_err(|e| map_io_err_to_vault_locked(e, hp))?;
                hf.read_exact(&mut header_bytes)
                    .map_err(|e| map_io_err_to_vault_locked(e, hp))?;
            }
            (HeaderStorage::Detached(_, _), None) => {
                unreachable!("Detached header storage requires a header_path, this is a bug")
            }
        }
        let header = Header::from_bytes(&header_bytes)?;
        Ok((file, header_storage, header_bytes, header))
    }

    /// Read and decrypt the metadata blob. Returned plaintext is
    /// `Zeroizing`, wiped from memory when the caller drops it.
    pub fn read_metadata(&mut self) -> Result<zeroize::Zeroizing<Vec<u8>>, Error> {
        let region_size = self.header.metadata_size as usize;
        let mut region = vec![0u8; region_size];
        self.file
            .seek(SeekFrom::Start(self.header.metadata_offset))?;
        self.file.read_exact(&mut region)?;
        metadata::read_metadata(
            self.header.cipher_suite,
            &self.mvk,
            &self.header.header_salt,
            &region,
        )
    }

    /// Encrypt and write the metadata blob.
    pub fn write_metadata(&mut self, plaintext: &[u8]) -> Result<(), Error> {
        let region_size = self.header.metadata_size as usize;
        if plaintext.len() + METADATA_OVERHEAD > region_size {
            return Err(Error::MetadataTooLarge);
        }
        let mut region = vec![0u8; region_size];
        metadata::write_metadata(
            self.header.cipher_suite,
            &self.mvk,
            &self.header.header_salt,
            plaintext,
            &mut region,
        )?;
        self.file
            .seek(SeekFrom::Start(self.header.metadata_offset))?;
        self.file.write_all(&region)?;
        self.file.flush()?;
        Ok(())
    }

    pub fn enroll_passphrase(
        &mut self,
        passphrase: &[u8],
        kdf_params: Argon2idParams,
    ) -> Result<usize, Error> {
        let idx = self.header.first_free_slot()?;
        let slot = Keyslot::new_passphrase(
            self.header.cipher_suite,
            &self.mvk,
            passphrase,
            kdf_params,
            &self.header.header_salt,
        )?;
        self.header.install_slot(idx, slot)?;
        self.header_dirty = true;
        Ok(idx)
    }

    pub fn enroll_fido2(
        &mut self,
        passphrase: Option<&[u8]>,
        hmac_secret: &[u8; 32],
        cred_id: &[u8],
        hmac_salt: [u8; 32],
        kdf_params: Argon2idParams,
    ) -> Result<usize, Error> {
        let idx = self.header.first_free_slot()?;
        let slot = Keyslot::new_fido2(
            self.header.cipher_suite,
            &self.mvk,
            passphrase,
            hmac_secret,
            cred_id,
            hmac_salt,
            kdf_params,
            &self.header.header_salt,
        )?;
        self.header.install_slot(idx, slot)?;
        self.header_dirty = true;
        Ok(idx)
    }

    /// Add a TPM 2.0-sealed keyslot wrapping the MVK under
    /// `kek_from_tpm` (a 32-byte random KEK the caller has already
    /// sealed via `luksbox_tpm::Tpm2Sealer::seal`, whose resulting
    /// blob bytes are passed in `sealed_blob`).
    ///
    /// This crate stays TPM-agnostic - the caller (CLI / GUI in
    /// Day 4 / 5) does the actual TPM I/O. From `luksbox-format`'s
    /// point of view the KEK is just a 32-byte secret, and the
    /// sealed blob is opaque bytes that get stored in the slot's
    /// variable-length region.
    ///
    /// `kek_from_tpm` should be wiped from the caller's memory
    /// after this call returns (the passed reference is borrowed,
    /// not consumed; consider wrapping in `Zeroizing` upstream).
    pub fn enroll_tpm2(
        &mut self,
        kek_from_tpm: &[u8; 32],
        sealed_blob: &[u8],
    ) -> Result<usize, Error> {
        let idx = self.header.first_free_slot()?;
        let slot = Keyslot::new_tpm2(
            self.header.cipher_suite,
            &self.mvk,
            kek_from_tpm,
            sealed_blob,
            &self.header.header_salt,
        )?;
        self.header.install_slot(idx, slot)?;
        self.header_dirty = true;
        Ok(idx)
    }

    /// Add a PIN-protected TPM 2.0 keyslot. Same wire-shape as
    /// `enroll_tpm2`; the difference is purely (a) the slot's
    /// `kind` byte (Tpm2SealedPin) and (b) the SealedBlob itself
    /// was sealed via `Tpm2Sealer::seal_with_pin` so the chip
    /// refuses to unseal without the matching PIN. The PIN is NOT
    /// stored anywhere by LUKSbox - it lives in the user's head
    /// and in the TPM's userAuth slot.
    pub fn enroll_tpm2_pin(
        &mut self,
        kek_from_tpm: &[u8; 32],
        sealed_blob: &[u8],
    ) -> Result<usize, Error> {
        let idx = self.header.first_free_slot()?;
        let slot = Keyslot::new_tpm2_pin(
            self.header.cipher_suite,
            &self.mvk,
            kek_from_tpm,
            sealed_blob,
            &self.header.header_salt,
        )?;
        self.header.install_slot(idx, slot)?;
        self.header_dirty = true;
        Ok(idx)
    }

    /// Add a hybrid TPM 2.0 + ML-KEM-768 keyslot. Caller has
    /// generated a Kyber keypair, encapsulated against it to get
    /// `pq_shared`, and is responsible for storing the matching
    /// ciphertext + pubkey in the `.lbx.hybrid` sidecar (this
    /// crate doesn't see the sidecar). KEK = HKDF(salt,
    /// kek_from_tpm || pq_shared).
    pub fn enroll_hybrid_pq_tpm2(
        &mut self,
        kek_from_tpm: &[u8; 32],
        pq_shared: &[u8; 32],
        sealed_blob: &[u8],
    ) -> Result<usize, Error> {
        let idx = self.header.first_free_slot()?;
        let slot = Keyslot::new_hybrid_pq_tpm2(
            self.header.cipher_suite,
            &self.mvk,
            kek_from_tpm,
            pq_shared,
            sealed_blob,
            &self.header.header_salt,
        )?;
        self.header.install_slot(idx, slot)?;
        self.header_dirty = true;
        Ok(idx)
    }

    /// ML-KEM-1024 variant of `enroll_hybrid_pq_tpm2`. Identical
    /// shape; caller is responsible for using ML-KEM-1024 in the
    /// Kyber operations + storing `level = Ml1024` in the .hybrid
    /// sidecar entry.
    pub fn enroll_hybrid_pq_1024_tpm2(
        &mut self,
        kek_from_tpm: &[u8; 32],
        pq_shared: &[u8; 32],
        sealed_blob: &[u8],
    ) -> Result<usize, Error> {
        let idx = self.header.first_free_slot()?;
        let slot = Keyslot::new_hybrid_pq_1024_tpm2(
            self.header.cipher_suite,
            &self.mvk,
            kek_from_tpm,
            pq_shared,
            sealed_blob,
            &self.header.header_salt,
        )?;
        self.header.install_slot(idx, slot)?;
        self.header_dirty = true;
        Ok(idx)
    }

    /// ML-KEM-1024 variant of `enroll_hybrid_pq_tpm2_fido2`.
    pub fn enroll_hybrid_pq_1024_tpm2_fido2(
        &mut self,
        tpm_unsealed: &[u8; 32],
        hmac_secret: &[u8; 32],
        pq_shared: &[u8; 32],
        sealed_blob: &[u8],
        cred_id: &[u8],
        hmac_salt: [u8; 32],
    ) -> Result<usize, Error> {
        let idx = self.header.first_free_slot()?;
        let slot = Keyslot::new_hybrid_pq_1024_tpm2_fido2(
            self.header.cipher_suite,
            &self.mvk,
            tpm_unsealed,
            hmac_secret,
            pq_shared,
            sealed_blob,
            cred_id,
            hmac_salt,
            &self.header.header_salt,
        )?;
        self.header.install_slot(idx, slot)?;
        self.header_dirty = true;
        Ok(idx)
    }

    /// Add the maximum-paranoia hybrid TPM 2.0 + FIDO2 + ML-KEM-768
    /// keyslot. Three independent factors required at every unlock.
    pub fn enroll_hybrid_pq_tpm2_fido2(
        &mut self,
        tpm_unsealed: &[u8; 32],
        hmac_secret: &[u8; 32],
        pq_shared: &[u8; 32],
        sealed_blob: &[u8],
        cred_id: &[u8],
        hmac_salt: [u8; 32],
    ) -> Result<usize, Error> {
        let idx = self.header.first_free_slot()?;
        let slot = Keyslot::new_hybrid_pq_tpm2_fido2(
            self.header.cipher_suite,
            &self.mvk,
            tpm_unsealed,
            hmac_secret,
            pq_shared,
            sealed_blob,
            cred_id,
            hmac_salt,
            &self.header.header_salt,
        )?;
        self.header.install_slot(idx, slot)?;
        self.header_dirty = true;
        Ok(idx)
    }

    /// Replace slot `idx` (regardless of its current state) with a
    /// freshly-built TPM-sealed keyslot wrapping the same MVK.
    /// Parallels `update_passphrase_at` / `update_fido2_at`. Used
    /// by `luksbox update --tpm2` once that ships in Day 4.
    pub fn update_tpm2_at(
        &mut self,
        idx: usize,
        kek_from_tpm: &[u8; 32],
        sealed_blob: &[u8],
    ) -> Result<(), Error> {
        let slot = Keyslot::new_tpm2(
            self.header.cipher_suite,
            &self.mvk,
            kek_from_tpm,
            sealed_blob,
            &self.header.header_salt,
        )?;
        self.header.install_slot(idx, slot)?;
        self.header_dirty = true;
        Ok(())
    }

    /// Add a fused TPM 2.0 + FIDO2 keyslot wrapping the MVK under
    /// a KEK derived from BOTH `tpm_unsealed` and `hmac_secret`.
    /// Caller (CLI / GUI) does the prep: open TPM context, generate
    /// random `tpm_unsealed`, seal it (returns `sealed_blob`); then
    /// register a FIDO2 credential, get its `cred_id`, choose
    /// `hmac_salt`, get `hmac_secret` from the authenticator. Both
    /// halves are required at every subsequent unlock.
    ///
    /// Constraint: `2 + sealed_blob.len() + cred_id.len()` must fit
    /// in the slot's variable-length region (352 B). Typical
    /// YubiKey + sealed-data-object combos fit comfortably; Google
    /// Titan-class authenticators (cred_id about 288 B) overflow and
    /// the call returns `Crypto(Fido2CredIdTooLong)`. Such users
    /// should enroll independent `Tpm2Sealed` + `Fido2HmacSecret`
    /// slots instead.
    pub fn enroll_tpm2_fido2(
        &mut self,
        tpm_unsealed: &[u8; 32],
        hmac_secret: &[u8; 32],
        sealed_blob: &[u8],
        cred_id: &[u8],
        hmac_salt: [u8; 32],
    ) -> Result<usize, Error> {
        let idx = self.header.first_free_slot()?;
        let slot = Keyslot::new_tpm2_fido2(
            self.header.cipher_suite,
            &self.mvk,
            tpm_unsealed,
            hmac_secret,
            sealed_blob,
            cred_id,
            hmac_salt,
            &self.header.header_salt,
        )?;
        self.header.install_slot(idx, slot)?;
        self.header_dirty = true;
        Ok(idx)
    }

    pub fn revoke_slot(&mut self, idx: usize) -> Result<(), Error> {
        self.header.revoke_slot(idx)?;
        self.header_dirty = true;
        Ok(())
    }

    /// Swap two keyslots in the header. The per-slot AAD does NOT
    /// include the slot's index, so a swap leaves both slots' wrapped
    /// MVKs valid; only their position in the slot table changes.
    /// Caller is responsible for updating any out-of-band metadata that
    /// references slot indices (e.g. the `<vault>.lbx.hybrid` sidecar's
    /// `slot_idx` field) and for calling `persist_header()` afterwards.
    pub fn swap_slots(&mut self, a: usize, b: usize) -> Result<(), Error> {
        let max = self.header.keyslots.len();
        if a >= max || b >= max {
            return Err(Error::Io(std::io::Error::other(format!(
                "swap_slots: index out of range (a={a}, b={b}, max={max})"
            ))));
        }
        if a != b {
            self.header.keyslots.swap(a, b);
            self.header_dirty = true;
        }
        Ok(())
    }

    /// Replace slot `idx` (regardless of its current state) with a freshly-built
    /// passphrase keyslot wrapping the same MVK. Used by `luksbox update`.
    pub fn update_passphrase_at(
        &mut self,
        idx: usize,
        passphrase: &[u8],
        kdf_params: Argon2idParams,
    ) -> Result<(), Error> {
        let slot = Keyslot::new_passphrase(
            self.header.cipher_suite,
            &self.mvk,
            passphrase,
            kdf_params,
            &self.header.header_salt,
        )?;
        self.header.install_slot(idx, slot)?;
        self.header_dirty = true;
        Ok(())
    }

    /// Replace slot `idx` with a freshly-built FIDO2 keyslot.
    pub fn update_fido2_at(
        &mut self,
        idx: usize,
        passphrase: Option<&[u8]>,
        hmac_secret: &[u8; 32],
        cred_id: &[u8],
        hmac_salt: [u8; 32],
        kdf_params: Argon2idParams,
    ) -> Result<(), Error> {
        let slot = Keyslot::new_fido2(
            self.header.cipher_suite,
            &self.mvk,
            passphrase,
            hmac_secret,
            cred_id,
            hmac_salt,
            kdf_params,
            &self.header.header_salt,
        )?;
        self.header.install_slot(idx, slot)?;
        self.header_dirty = true;
        Ok(())
    }

    /// Number of populated (non-empty) keyslots.
    pub fn populated_slot_count(&self) -> usize {
        self.header
            .keyslots
            .iter()
            .filter(|s| s.kind != SlotKind::Empty)
            .count()
    }

    /// Find the index of the single populated keyslot. Returns `None` if
    /// zero or more than one slot is populated.
    pub fn unique_populated_slot(&self) -> Option<usize> {
        let mut idx = None;
        for (i, s) in self.header.keyslots.iter().enumerate() {
            if s.kind != SlotKind::Empty {
                if idx.is_some() {
                    return None;
                }
                idx = Some(i);
            }
        }
        idx
    }

    /// Re-encrypt one chunk slot at `slot_offset` with the new file_key.
    /// Helper for MVK rotation; uses raw read_at/write_at on the data area.
    /// `aad` must be the original chunk AAD (file_id || chunk_idx || generation).
    pub fn rekey_chunk_at(
        &mut self,
        chunk_id: u64,
        old_file_key: &[u8; 32],
        new_file_key: &[u8; 32],
        aad: &[u8],
    ) -> Result<(), Error> {
        const NONCE_LEN: usize = 12;
        const PT_LEN: usize = 4096;
        const TAG_LEN: usize = 16;
        let slot_size = NONCE_LEN as u64 + PT_LEN as u64 + TAG_LEN as u64;
        let off = chunk_id
            .checked_mul(slot_size)
            .and_then(|relative| self.header.data_offset.checked_add(relative))
            .ok_or(Error::OffsetOverflow)?;

        let mut buf = vec![0u8; NONCE_LEN + PT_LEN + TAG_LEN];
        self.read_at(off, &mut buf)?;
        let mut old_nonce = [0u8; NONCE_LEN];
        old_nonce.copy_from_slice(&buf[..NONCE_LEN]);
        let pt = luksbox_core::aead::open(
            self.header.cipher_suite,
            old_file_key,
            &old_nonce,
            aad,
            &buf[NONCE_LEN..],
        )?;
        debug_assert_eq!(pt.len(), PT_LEN);

        let mut new_nonce = [0u8; NONCE_LEN];
        rand_core::RngCore::try_fill_bytes(&mut rand_core::OsRng, &mut new_nonce)
            .map_err(|e| Error::Crypto(luksbox_core::Error::OsRng(e.to_string())))?;
        let new_ct =
            luksbox_core::aead::seal(self.header.cipher_suite, new_file_key, &new_nonce, aad, &pt)?;
        let mut on_disk = Vec::with_capacity(NONCE_LEN + new_ct.len());
        on_disk.extend_from_slice(&new_nonce);
        on_disk.extend_from_slice(&new_ct);
        self.write_at(off, &on_disk)?;
        Ok(())
    }

    /// Re-encrypt the metadata blob with a new MVK. Used by MVK rotation
    /// after all chunks have been re-encrypted.
    pub fn rekey_metadata(&mut self, new_mvk: &MasterVolumeKey) -> Result<(), Error> {
        let plaintext = self.read_metadata()?;
        // Temporarily swap MVK so write_metadata uses the new key.
        let old = std::mem::replace(&mut self.mvk, new_mvk.clone());
        let r = self.write_metadata(&plaintext);
        if r.is_err() {
            // Roll back so the container stays usable.
            self.mvk = old;
        }
        r
    }

    /// Final step of MVK rotation: install the new MVK + a fresh single
    /// passphrase keyslot wrapping it. Called AFTER all chunks have been
    /// re-encrypted with `new_mvk`-derived file_keys and the metadata blob
    /// has been re-encrypted with the new `metadata_key`. The new keyslot
    /// uses the same `passphrase` (the user's existing one) but with fresh
    /// random `kdf_salt` and `aead_nonce` for forward security.
    pub fn install_rotated_mvk_passphrase(
        &mut self,
        slot_idx: usize,
        new_mvk: MasterVolumeKey,
        passphrase: &[u8],
        kdf_params: Argon2idParams,
    ) -> Result<(), Error> {
        if slot_idx >= MAX_KEYSLOTS {
            return Err(Error::Crypto(luksbox_core::Error::InvalidKeyslotIndex(
                slot_idx,
            )));
        }
        // Generate a fresh keyslot (random uuid/salt/nonce) wrapping new_mvk.
        let new_slot = Keyslot::new_passphrase(
            self.header.cipher_suite,
            &new_mvk,
            passphrase,
            kdf_params,
            &self.header.header_salt,
        )?;
        // Empty all other slots so a stale wrap can't be unlocked.
        for i in 0..MAX_KEYSLOTS {
            if i != slot_idx {
                self.header.revoke_slot(i)?;
            }
        }
        self.header.install_slot(slot_idx, new_slot)?;
        self.mvk = new_mvk;
        self.header_dirty = true;
        Ok(())
    }

    /// Multi-slot variant: install a fresh keyslot at each `(slot_idx, keyslot)`
    /// pair, and empty every other slot. Caller is responsible for building
    /// each Keyslot under the new MVK. Atomic-ish: header is modified in
    /// memory then persisted in one write.
    pub fn install_rotated_mvk_multi(
        &mut self,
        new_mvk: MasterVolumeKey,
        new_slots: Vec<(usize, Keyslot)>,
    ) -> Result<(), Error> {
        // Validate indices first.
        for (idx, _) in &new_slots {
            if *idx >= MAX_KEYSLOTS {
                return Err(Error::Crypto(luksbox_core::Error::InvalidKeyslotIndex(
                    *idx,
                )));
            }
        }
        let installed: std::collections::BTreeSet<usize> =
            new_slots.iter().map(|(i, _)| *i).collect();
        // Empty slots not being replaced.
        for i in 0..MAX_KEYSLOTS {
            if !installed.contains(&i) {
                self.header.revoke_slot(i)?;
            }
        }
        // Install replacements.
        for (idx, slot) in new_slots {
            self.header.install_slot(idx, slot)?;
        }
        self.mvk = new_mvk;
        self.header_dirty = true;
        Ok(())
    }

    /// Expose a clone of the current MVK for MVK rotation. Caller is
    /// responsible for using it briefly and dropping (it's `ZeroizeOnDrop`
    /// inside via `MasterVolumeKey`'s SecretBox storage).
    pub fn mvk_clone(&self) -> MasterVolumeKey {
        self.mvk.clone()
    }

    /// Persist the header back to disk if it has been mutated. Writes to the
    /// sidecar file in detached mode; otherwise to offset 0 of the vault file.
    pub fn persist_header(&mut self) -> Result<(), Error> {
        if !self.header_dirty {
            return Ok(());
        }
        let bytes = self.header.to_bytes(&self.mvk);
        match &mut self.header_storage {
            HeaderStorage::Inline => {
                self.file.seek(SeekFrom::Start(0))?;
                self.file.write_all(&bytes)?;
                self.file.flush()?;
            }
            HeaderStorage::Detached(hf, _) => {
                hf.seek(SeekFrom::Start(0))?;
                hf.write_all(&bytes)?;
                hf.flush()?;
            }
        }
        self.header_dirty = false;
        Ok(())
    }

    /// Inspect keyslots without exposing the MVK.
    pub fn slot_kinds(&self) -> [SlotKind; MAX_KEYSLOTS] {
        core::array::from_fn(|i| self.header.keyslots[i].kind)
    }

    pub fn data_offset(&self) -> u64 {
        self.header.data_offset
    }

    pub fn cipher_suite(&self) -> CipherSuite {
        self.header.cipher_suite
    }

    pub fn header_salt(&self) -> &[u8; 32] {
        &self.header.header_salt
    }

    /// Derive a 32-byte subkey from the MVK without exposing the MVK itself.
    /// `info` is a domain-separation tag (e.g. `b"lbx:file/v1:" || file_id_le`).
    /// Returned key is `Zeroizing`, it's memset-to-zero when dropped.
    pub fn derive_subkey(&self, info: &[u8]) -> SubKey {
        self.mvk.derive_subkey(&self.header.header_salt, info)
    }

    /// Read raw bytes at `offset` (caller is responsible for ensuring `offset`
    /// is within the data region, `offset >= self.data_offset()`).
    pub fn read_at(&mut self, offset: u64, buf: &mut [u8]) -> Result<(), Error> {
        self.file.seek(SeekFrom::Start(offset))?;
        self.file.read_exact(buf)?;
        Ok(())
    }

    /// Write raw bytes at `offset`. Same contract as `read_at`.
    pub fn write_at(&mut self, offset: u64, buf: &[u8]) -> Result<(), Error> {
        self.file.seek(SeekFrom::Start(offset))?;
        self.file.write_all(buf)?;
        Ok(())
    }

    pub fn flush(&mut self) -> Result<(), Error> {
        self.file.flush().map_err(Into::into)
    }

    /// Set or clear the anchor sidecar path. With `Some`, reads and
    /// verifies the anchor file's HMAC under the MVK-derived anchor key,
    /// returning the trusted generation counter for the caller to compare
    /// against the metadata blob's `next_chunk_gen`. The container will
    /// then auto-update the anchor on every metadata write. `None`
    /// detaches without touching disk.
    pub fn set_anchor(&mut self, anchor_path: Option<PathBuf>) -> Result<Option<u64>, Error> {
        match anchor_path {
            None => {
                self.anchor_path = None;
                Ok(None)
            }
            Some(p) => {
                let a = crate::anchor::read_and_verify(&p, &self.mvk, &self.header.header_salt)?;
                self.anchor_path = Some(p);
                Ok(Some(a.generation))
            }
        }
    }

    /// Initialize an anchor file at the given path with the supplied
    /// generation. Used right after `create_*` to bootstrap a vault
    /// with anchor protection from the start.
    pub fn init_anchor(&mut self, anchor_path: PathBuf, generation: u64) -> Result<(), Error> {
        crate::anchor::write(
            &anchor_path,
            generation,
            &self.mvk,
            &self.header.header_salt,
        )?;
        self.anchor_path = Some(anchor_path);
        Ok(())
    }

    /// Update the anchor file (if one is set) to the given generation.
    /// Called by `Vfs::flush` after every metadata-blob write.
    pub fn write_anchor(&self, generation: u64) -> Result<(), Error> {
        if let Some(p) = &self.anchor_path {
            crate::anchor::write(p, generation, &self.mvk, &self.header.header_salt)?;
        }
        Ok(())
    }

    pub fn anchor_path(&self) -> Option<&Path> {
        self.anchor_path.as_deref()
    }

    /// Path of the underlying vault file (the `.lbx`).
    pub fn vault_path(&self) -> &Path {
        &self.path
    }

    /// Path where the 8 KB header lives. Returns the vault path itself
    /// for inline-header vaults (header occupies the first 8 KB), or the
    /// detached sidecar path for detached-header vaults.
    pub fn header_storage_path(&self) -> &Path {
        match &self.header_storage {
            HeaderStorage::Inline => &self.path,
            HeaderStorage::Detached(_, p) => p,
        }
    }

    /// Whether `begin_atomic_rotation` is supported in the current mode.
    /// Currently only inline-header vaults can be rotated atomically: a
    /// single atomic `rename()` over the vault file commits ALL changes
    /// (header + metadata + data) in one filesystem op. For detached-header
    /// mode we'd need a 2-file commit protocol with a sentinel; not yet
    /// implemented.
    pub fn supports_atomic_rotation(&self) -> bool {
        matches!(self.header_storage, HeaderStorage::Inline)
    }

    /// Begin a crash-safe MVK rotation. Copies the vault file to
    /// `<path>.rotating`, swaps the open file handle to the temp file,
    /// and remembers the original path. All subsequent reads/writes go
    /// to the temp file; the original is untouched until commit.
    ///
    /// Inline mode only. Caller must check `supports_atomic_rotation()`
    /// and fall back to in-place rotation otherwise.
    pub fn begin_atomic_rotation(&mut self) -> Result<(), Error> {
        if !self.supports_atomic_rotation() {
            return Err(Error::Crypto(luksbox_core::Error::InvalidField));
        }
        if self.rotation.is_some() {
            return Err(Error::Crypto(luksbox_core::Error::InvalidField));
        }
        let original = self.path.clone();
        let mut tmp_os = original.as_os_str().to_owned();
        tmp_os.push(".rotating");
        let tmp = PathBuf::from(tmp_os);

        // If a stale .rotating exists from a prior crash, refuse, caller
        // must clean up explicitly so we don't silently overwrite their
        // recovery state.
        if tmp.exists() {
            return Err(Error::Io(std::io::Error::new(
                std::io::ErrorKind::AlreadyExists,
                format!(
                    "rotation tmp file {} already exists; remove it manually \
                     to confirm no in-progress rotation is being recovered",
                    tmp.display()
                ),
            )));
        }

        // Flush any pending writes on the original before we copy.
        self.file.flush()?;

        // Full byte-for-byte copy. std::fs::copy uses platform fast paths
        // (copy_file_range on Linux, clonefile on APFS where supported).
        // std::fs::copy preserves the source's permissions, so on a vault
        // created post-Round-9E (mode 0600) the tmp inherits 0600 too.
        // For LEGACY pre-9E vaults that may exist on disk with mode
        // 0644, force-narrow the tmp to 0600 anyway so the rotation
        // doesn't carry the legacy looseness forward.
        std::fs::copy(&original, &tmp)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o600))?;
        }

        // Open the tmp for read+write and swap the file handle. The old
        // handle drops here (closing the original file).
        let tmp_file = OpenOptions::new().read(true).write(true).open(&tmp)?;
        self.file = tmp_file;
        self.path = tmp.clone();
        self.rotation = Some(RotationState {
            tmp_data_path: tmp,
            committed_data_path: original,
        });
        Ok(())
    }

    /// Commit an in-progress rotation: fsync the temp file to durable
    /// storage, then atomically `rename()` it over the original vault.
    /// After this returns, the rotation is durably committed: a crash
    /// after this point leaves the new vault in place.
    pub fn commit_atomic_rotation(&mut self) -> Result<(), Error> {
        let state = self
            .rotation
            .take()
            .ok_or(Error::Crypto(luksbox_core::Error::InvalidField))?;

        // Make sure all writes (header at offset 0, metadata, all rekeyed
        // chunks) are durable on disk BEFORE the rename. Without this,
        // the rename can succeed while the data blocks are still in
        // page cache; a power loss leaves a renamed-but-empty file.
        self.file.flush()?;
        self.file.sync_all()?;

        // Atomic on POSIX (and on Windows when the target is on the same
        // volume, std::fs::rename uses MoveFileExW with REPLACE_EXISTING).
        std::fs::rename(&state.tmp_data_path, &state.committed_data_path)?;
        sync_parent_dir(&state.committed_data_path)?;

        // Our open handle now points at the renamed file (same inode as
        // the new vault on POSIX). Update path so future operations refer
        // to the canonical path.
        self.path = state.committed_data_path;
        Ok(())
    }

    /// Discard an in-progress rotation. Drops the swapped file handle,
    /// removes the temp file, and reopens the original. Best-effort,
    /// errors during cleanup are logged but not propagated; the original
    /// vault is intact regardless (we never touched it).
    pub fn abort_atomic_rotation(&mut self) -> Result<(), Error> {
        let state = match self.rotation.take() {
            Some(s) => s,
            None => return Ok(()),
        };

        // Reopen original BEFORE dropping the temp handle so we never
        // leave self.file in a half-valid state.
        let original_file = OpenOptions::new()
            .read(true)
            .write(true)
            .open(&state.committed_data_path)?;
        self.file = original_file;
        self.path = state.committed_data_path;

        // Best-effort cleanup of the temp file.
        let _ = std::fs::remove_file(&state.tmp_data_path);

        // Mark header as dirty so any in-memory changes get rewritten on
        // top of the original (in case caller wants to retry rotation).
        // Actually, we shouldn't trust self.header here either; on abort,
        // the safest thing is to reload from disk. But that's caller-side:
        // they should drop the Vfs and reopen.
        Ok(())
    }
}

impl Drop for Container {
    fn drop(&mut self) {
        let _ = self.persist_header();
    }
}

fn try_unlock(
    header: &Header,
    material: &mut UnlockMaterial<'_>,
) -> Result<MasterVolumeKey, Error> {
    let suite = header.cipher_suite;
    match material {
        UnlockMaterial::Passphrase(pw) => {
            // Constant-time-ish iteration: try EVERY passphrase keyslot,
            // even after a match. Without this, an observer who can time
            // unlock attempts learns which keyslot's KDF parameters
            // matched (and therefore which slot the user holds). The cost
            // is N x Argon2id stretching per unlock attempt regardless of
            // success, annoying for large keyslot counts but the right
            // default for a security-focused tool.
            //
            // The kind-check (`SlotKind::Passphrase`) is structural, it
            // doesn't reveal anything secret since slot kinds are public
            // metadata in the header.
            let mut found: Option<MasterVolumeKey> = None;
            for slot in &header.keyslots {
                if slot.kind != SlotKind::Passphrase {
                    continue;
                }
                if let Ok(mvk) = slot.unlock_passphrase(suite, pw, &header.header_salt) {
                    if found.is_none() {
                        found = Some(mvk);
                    }
                    // Don't break, keep iterating to maintain
                    // constant time across the whole keyslot table.
                }
            }
            found.ok_or(Error::UnlockFailed)
        }
        UnlockMaterial::Fido2 {
            passphrase,
            cred_id,
            hmac_secret,
        } => {
            for slot in &header.keyslots {
                if slot.fido2_cred_id != *cred_id {
                    continue;
                }
                match slot.kind {
                    SlotKind::Fido2HmacSecret => {
                        return slot
                            .unlock_fido2(suite, *passphrase, hmac_secret, &header.header_salt)
                            .map_err(Into::into);
                    }
                    SlotKind::Fido2DerivedMvk => {
                        return slot
                            .unlock_fido2_derived_mvk(hmac_secret)
                            .map_err(Into::into);
                    }
                    _ => continue,
                }
            }
            Err(Error::Fido2CredNotFound)
        }
        UnlockMaterial::HybridPqPassphrase {
            passphrase,
            pq_shared,
        } => {
            // Same constant-time-ish iteration as the passphrase arm.
            let mut found: Option<MasterVolumeKey> = None;
            for slot in &header.keyslots {
                if !slot.kind.is_hybrid_pq_passphrase() {
                    continue;
                }
                if let Ok(mvk) = slot.unlock_hybrid_pq_passphrase(
                    suite,
                    passphrase,
                    pq_shared,
                    &header.header_salt,
                ) {
                    if found.is_none() {
                        found = Some(mvk);
                    }
                }
            }
            found.ok_or(Error::UnlockFailed)
        }
        UnlockMaterial::HybridPqFido2 {
            passphrase,
            cred_id,
            hmac_secret,
            pq_shared,
        } => {
            for slot in &header.keyslots {
                if !slot.kind.is_hybrid_pq_fido2() {
                    continue;
                }
                if slot.fido2_cred_id != *cred_id {
                    continue;
                }
                return slot
                    .unlock_hybrid_pq_fido2(
                        suite,
                        *passphrase,
                        hmac_secret,
                        pq_shared,
                        &header.header_salt,
                    )
                    .map_err(Into::into);
            }
            Err(Error::Fido2CredNotFound)
        }
        UnlockMaterial::Tpm2Fido2 {
            unseal,
            cred_id,
            hmac_secret,
        } => {
            // Iterate Tpm2Fido2 slots whose stored cred_id matches.
            // For each match: parse the sub-format to extract the
            // TPM blob, ask the closure to unseal, derive the
            // fused KEK from (tpm_unsealed || hmac_secret), try
            // unwrap. First success wins. Closure errors continue
            // to next slot (multi-machine / multi-key configs).
            for slot in &header.keyslots {
                if slot.kind != SlotKind::Tpm2Fido2 {
                    continue;
                }
                let stored_cred = slot
                    .tpm2_fido2_cred_id()
                    .expect("kind == Tpm2Fido2 implies tpm2_fido2_cred_id() is Some");
                if stored_cred != *cred_id {
                    continue;
                }
                let tpm_blob = slot
                    .tpm2_fido2_sealed_blob()
                    .expect("kind == Tpm2Fido2 implies tpm2_fido2_sealed_blob() is Some");
                let tpm_unsealed = match unseal(tpm_blob) {
                    Ok(k) => k,
                    Err(_) => continue,
                };
                if let Ok(mvk) =
                    slot.unlock_tpm2_fido2(suite, &tpm_unsealed, hmac_secret, &header.header_salt)
                {
                    return Ok(mvk);
                }
            }
            Err(Error::UnlockFailed)
        }
        UnlockMaterial::HybridPqTpm2 { unseal, pq_shared } => {
            // Iterate both 768 and 1024 hybrid TPM slots; per
            // slot, ask the closure to unseal then derive the
            // fused KEK from (tpm_unsealed || pq_shared). KEK
            // derivation is identical between 768 and 1024.
            for slot in &header.keyslots {
                if !matches!(
                    slot.kind,
                    SlotKind::HybridPqKemTpm2 | SlotKind::HybridPqKem1024Tpm2
                ) {
                    continue;
                }
                let blob = slot
                    .tpm2_sealed_blob()
                    .expect("hybrid-pq TPM kind implies tpm2_sealed_blob() is Some");
                let tpm_kek = match unseal(blob) {
                    Ok(k) => k,
                    Err(_) => continue,
                };
                if let Ok(mvk) =
                    slot.unlock_hybrid_pq_tpm2(suite, &tpm_kek, pq_shared, &header.header_salt)
                {
                    return Ok(mvk);
                }
            }
            Err(Error::UnlockFailed)
        }
        UnlockMaterial::HybridPqTpm2Fido2 {
            unseal,
            cred_id,
            hmac_secret,
            pq_shared,
        } => {
            for slot in &header.keyslots {
                if !matches!(
                    slot.kind,
                    SlotKind::HybridPqKemTpm2Fido2 | SlotKind::HybridPqKem1024Tpm2Fido2
                ) {
                    continue;
                }
                let stored_cred = slot
                    .tpm2_fido2_cred_id()
                    .expect("hybrid-pq fused TPM+FIDO2 implies tpm2_fido2_cred_id() is Some");
                if stored_cred != *cred_id {
                    continue;
                }
                let tpm_blob = slot
                    .tpm2_fido2_sealed_blob()
                    .expect("hybrid-pq fused TPM+FIDO2 implies tpm2_fido2_sealed_blob() is Some");
                let tpm_unsealed = match unseal(tpm_blob) {
                    Ok(k) => k,
                    Err(_) => continue,
                };
                if let Ok(mvk) = slot.unlock_hybrid_pq_tpm2_fido2(
                    suite,
                    &tpm_unsealed,
                    hmac_secret,
                    pq_shared,
                    &header.header_salt,
                ) {
                    return Ok(mvk);
                }
            }
            Err(Error::UnlockFailed)
        }
        UnlockMaterial::Tpm2 { unseal } => {
            // Iterate Tpm2Sealed slots, ask the caller's closure to
            // unseal each blob, and try to unwrap the MVK with the
            // returned KEK. First success wins.
            //
            // Unlike the Passphrase / HybridPqPassphrase arms we
            // do NOT iterate to constant time after the first
            // match, because each TPM unseal is an actual hardware
            // call and may be slow / interactive (even though the
            // current `Tpm2Sealed` design has no userAuth, future
            // userAuth-protected slots would prompt the user). The
            // attacker-side timing channel is "which slot index
            // unsealed first" - already public information since
            // slot kinds and metadata are unencrypted in the
            // header. Acceptable trade-off vs. forcing N TPM ops
            // per unlock.
            //
            // Closure errors per slot are tolerated and cause the
            // loop to continue: a vault enrolled on one machine
            // might have multiple TPM slots from different machines,
            // and only the local TPM will succeed.
            for slot in &header.keyslots {
                // Iterate both plain Tpm2Sealed AND Tpm2SealedPin
                // slots - the closure handles whichever PIN logic
                // it has captured. Hybrid-PQ-TPM slots have their
                // own dispatcher arm (UnlockMaterial::HybridPqTpm2)
                // and aren't tried here.
                if !matches!(slot.kind, SlotKind::Tpm2Sealed | SlotKind::Tpm2SealedPin) {
                    continue;
                }
                let blob = slot.tpm2_sealed_blob().expect(
                    "kind in {Tpm2Sealed, Tpm2SealedPin} implies tpm2_sealed_blob() is Some",
                );
                let kek = match unseal(blob) {
                    Ok(k) => k,
                    Err(_) => continue,
                };
                if let Ok(mvk) = slot.unlock_tpm2(suite, &kek, &header.header_salt) {
                    return Ok(mvk);
                }
                // Wrong KEK for this slot, but the closure ran
                // successfully. This is the "vault has multiple
                // TPM slots, the chip unsealed something but it
                // doesn't unwrap THIS slot" case. Continue.
            }
            Err(Error::UnlockFailed)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use luksbox_core::Argon2idParams;
    use tempfile::tempdir;

    fn test_params() -> Argon2idParams {
        // Tiny params, never use in real containers.
        Argon2idParams {
            m_cost_kib: 8,
            t_cost: 1,
            p_cost: 1,
        }
    }

    #[test]
    fn create_and_reopen_with_passphrase() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("test.lbx");

        {
            let mut c = Container::create_with_passphrase(
                &path,
                None,
                CipherSuite::Aes256Gcm,
                test_params(),
                b"correct horse",
            )
            .unwrap();
            c.write_metadata(b"hello world").unwrap();
        }

        let mut c =
            Container::open(&path, None, UnlockMaterial::Passphrase(b"correct horse")).unwrap();
        let blob = c.read_metadata().unwrap();
        assert_eq!(&**blob, b"hello world");
    }

    #[test]
    fn wrong_passphrase_rejected() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("test.lbx");
        Container::create_with_passphrase(
            &path,
            None,
            CipherSuite::Aes256Gcm,
            test_params(),
            b"right",
        )
        .unwrap();

        let r = Container::open(&path, None, UnlockMaterial::Passphrase(b"wrong"));
        assert!(matches!(r, Err(Error::UnlockFailed)));
    }

    /// Validates the FUSE-T mount-helper subprocess unlock path:
    /// parent opens with passphrase, extracts MVK, child opens with
    /// MVK directly, both see identical metadata. If this test ever
    /// regresses, the subprocess-isolated FUSE-T mount on macOS
    /// breaks (the child can't open the vault the parent unlocked).
    #[test]
    fn open_with_mvk_round_trip_matches_passphrase_unlock() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("test.lbx");

        // Parent process: create + write metadata via passphrase.
        {
            let mut c = Container::create_with_passphrase(
                &path,
                None,
                CipherSuite::Aes256Gcm,
                test_params(),
                b"correct horse",
            )
            .unwrap();
            c.write_metadata(b"shared between parent and helper")
                .unwrap();
        }

        // Parent re-opens, extracts MVK (this is what the GUI does
        // before spawning the mount-helper subprocess), drops the
        // Container so the file lock is released.
        let mvk = {
            let c =
                Container::open(&path, None, UnlockMaterial::Passphrase(b"correct horse")).unwrap();
            c.mvk_clone()
        };

        // Child process: opens with the MVK directly (no passphrase
        // derivation), should read identical metadata.
        let mut c = Container::open_with_mvk(&path, None, mvk).unwrap();
        let blob = c.read_metadata().unwrap();
        assert_eq!(&**blob, b"shared between parent and helper");
    }

    /// A wrong MVK must produce a clean Crypto(HeaderAuthFailed)
    /// instead of proceeding to read garbled metadata. This is the
    /// safety guarantee that lets us trust open_with_mvk's downstream
    /// callers; without it a corrupted MVK pipe transfer would
    /// silently produce a Container that fails later at metadata-
    /// decrypt with an opaque AEAD error.
    #[test]
    fn open_with_mvk_rejects_wrong_mvk() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("test.lbx");
        Container::create_with_passphrase(
            &path,
            None,
            CipherSuite::Aes256Gcm,
            test_params(),
            b"right",
        )
        .unwrap();

        // Construct a fixed MVK that is NOT the one derived from the
        // real passphrase. Any constant 32 bytes is fine, the
        // probability of a random salt deriving exactly this is
        // 2^-256.
        let wrong_mvk = MasterVolumeKey::from_bytes([0u8; 32]);
        let r = Container::open_with_mvk(&path, None, wrong_mvk);
        let is_header_auth_failed = matches!(
            &r,
            Err(Error::Crypto(luksbox_core::Error::HeaderAuthFailed))
        );
        assert!(
            is_header_auth_failed,
            "expected Crypto(HeaderAuthFailed), got {}",
            match &r {
                Ok(_) => "Ok(...)".to_string(),
                Err(e) => format!("{e:?}"),
            }
        );
    }

    #[test]
    fn enroll_and_unlock_with_second_passphrase() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("test.lbx");

        {
            let mut c = Container::create_with_passphrase(
                &path,
                None,
                CipherSuite::Aes256Gcm,
                test_params(),
                b"first",
            )
            .unwrap();
            let idx = c.enroll_passphrase(b"second", test_params()).unwrap();
            assert_eq!(idx, 1);
            c.persist_header().unwrap();
        }

        let _ = Container::open(&path, None, UnlockMaterial::Passphrase(b"first")).unwrap();
        let _ = Container::open(&path, None, UnlockMaterial::Passphrase(b"second")).unwrap();
    }

    #[test]
    fn revoke_slot_locks_out() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("test.lbx");

        {
            let mut c = Container::create_with_passphrase(
                &path,
                None,
                CipherSuite::Aes256Gcm,
                test_params(),
                b"first",
            )
            .unwrap();
            c.enroll_passphrase(b"second", test_params()).unwrap();
            c.revoke_slot(0).unwrap();
            c.persist_header().unwrap();
        }

        assert!(matches!(
            Container::open(&path, None, UnlockMaterial::Passphrase(b"first")),
            Err(Error::UnlockFailed)
        ));
        let _ = Container::open(&path, None, UnlockMaterial::Passphrase(b"second")).unwrap();
    }

    #[test]
    fn enroll_and_unlock_with_fido2() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("test.lbx");
        let cred_id = b"my-credential-id-bytes";
        let hmac_salt = [0xbeu8; 32];
        let hmac_secret = [0xefu8; 32];

        {
            let mut c = Container::create_with_passphrase(
                &path,
                None,
                CipherSuite::Aes256Gcm,
                test_params(),
                b"recovery-only",
            )
            .unwrap();
            c.enroll_fido2(None, &hmac_secret, cred_id, hmac_salt, test_params())
                .unwrap();
            c.write_metadata(b"yubikey-protected").unwrap();
            c.persist_header().unwrap();
        }

        let mut c = Container::open(
            &path,
            None,
            UnlockMaterial::Fido2 {
                passphrase: None,
                cred_id,
                hmac_secret: &hmac_secret,
            },
        )
        .unwrap();
        assert_eq!(&**c.read_metadata().unwrap(), b"yubikey-protected");
    }

    #[test]
    fn header_tamper_detected_at_open() {
        use std::io::Write as _;
        let dir = tempdir().unwrap();
        let path = dir.path().join("test.lbx");

        Container::create_with_passphrase(
            &path,
            None,
            CipherSuite::Aes256Gcm,
            test_params(),
            b"pw",
        )
        .unwrap();

        let mut f = OpenOptions::new()
            .read(true)
            .write(true)
            .open(&path)
            .unwrap();
        f.seek(SeekFrom::Start(20)).unwrap();
        f.write_all(&[0xff]).unwrap();
        drop(f);

        let r = Container::open(&path, None, UnlockMaterial::Passphrase(b"pw"));
        assert!(matches!(
            r,
            Err(Error::Crypto(luksbox_core::Error::HeaderAuthFailed))
        ));
    }

    /// End-to-end hybrid keyslot round-trip:
    ///   - synthesise a 32-byte "shared secret" (any random bytes here
    ///     play the role of a real ML-KEM decap output);
    ///   - create a container with a hybrid slot wrapping the MVK under
    ///     `(passphrase, shared)`;
    ///   - close, reopen with `HybridPqPassphrase { passphrase, shared }`
    ///     and confirm the metadata round-trips;
    ///   - confirm `Passphrase(passphrase)` alone REJECTS the slot.
    #[test]
    fn hybrid_pq_passphrase_round_trip_and_rejects_classical_only_open() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("hybrid.lbx");

        let mut shared = [0u8; 32];
        // Deterministic for the test; in real use this is from
        // `luksbox_pq::decapsulate`.
        for (i, b) in shared.iter_mut().enumerate() {
            *b = (i as u8).wrapping_mul(17).wrapping_add(3);
        }

        {
            let mut c = Container::create_with_hybrid_pq_passphrase(
                &path,
                None,
                CipherSuite::Aes256Gcm,
                test_params(),
                0,
                b"hunter2",
                &shared,
            )
            .unwrap();
            c.write_metadata(b"top secret").unwrap();
        }

        // Reopen with hybrid material, must succeed.
        let mut c = Container::open(
            &path,
            None,
            UnlockMaterial::HybridPqPassphrase {
                passphrase: b"hunter2",
                pq_shared: &shared,
            },
        )
        .unwrap();
        let blob = c.read_metadata().unwrap();
        assert_eq!(&**blob, b"top secret");
        drop(c);

        // Plain passphrase open, must FAIL (no Passphrase slot exists).
        let r = Container::open(&path, None, UnlockMaterial::Passphrase(b"hunter2"));
        assert!(matches!(r, Err(Error::UnlockFailed)));

        // Wrong shared secret, must FAIL.
        let mut wrong = shared;
        wrong[0] ^= 0xff;
        let r = Container::open(
            &path,
            None,
            UnlockMaterial::HybridPqPassphrase {
                passphrase: b"hunter2",
                pq_shared: &wrong,
            },
        );
        assert!(matches!(r, Err(Error::UnlockFailed)));

        // Wrong passphrase, must FAIL.
        let r = Container::open(
            &path,
            None,
            UnlockMaterial::HybridPqPassphrase {
                passphrase: b"WRONGpw",
                pq_shared: &shared,
            },
        );
        assert!(matches!(r, Err(Error::UnlockFailed)));
    }

    /// End-to-end TPM2 enroll + open with a mocked unseal closure.
    /// The "TPM" is just a HashMap mapping `sealed_blob -> KEK`; the
    /// real `Tpm2Sealer` from `luksbox-tpm` lives one layer up in
    /// the CLI / GUI (Day 4 / 5). This test verifies that
    /// `Container::enroll_tpm2` + `UnlockMaterial::Tpm2` round-trip
    /// the MVK correctly, that wrong-KEK unsealing fails cleanly,
    /// and that the closure-iteration ignores closure errors so
    /// multi-machine TPM-slot configurations can still find the
    /// matching slot.
    #[test]
    fn tpm2_enroll_open_roundtrip_mocked() {
        use std::collections::HashMap;
        let dir = tempdir().unwrap();
        let path = dir.path().join("v.lbx");

        // Bootstrap with a passphrase slot we can use to enroll
        // the TPM slot. (Container needs an unlocked MVK to add
        // any new slot kind.)
        let mut cont = Container::create_with_passphrase(
            &path,
            None,
            CipherSuite::Aes256GcmSiv,
            test_params(),
            b"bootstrap",
        )
        .unwrap();

        // Mock TPM: pretend "seal" gave us back this fake blob for
        // this random KEK.
        let kek = [0x37u8; 32];
        let fake_sealed_blob = vec![0xA5u8; 280];
        let mut mock_tpm: HashMap<Vec<u8>, [u8; 32]> = HashMap::new();
        mock_tpm.insert(fake_sealed_blob.clone(), kek);

        let slot_idx = cont.enroll_tpm2(&kek, &fake_sealed_blob).unwrap();
        cont.persist_header().unwrap();
        // Drop to flush + force a clean re-open from disk.
        drop(cont);

        // Re-open via UnlockMaterial::Tpm2 with a closure that
        // looks up the blob in our mock TPM.
        let mut unseal = |blob: &[u8]| -> Result<[u8; 32], String> {
            mock_tpm
                .get(blob)
                .copied()
                .ok_or_else(|| "blob not found in mock TPM".to_string())
        };
        let cont = Container::open(
            &path,
            None,
            UnlockMaterial::Tpm2 {
                unseal: &mut unseal,
            },
        )
        .unwrap();
        // If we got here, the MVK was recovered + the metadata
        // blob decrypted, which proves the unwrap worked.
        assert_eq!(cont.header.keyslots[slot_idx].kind, SlotKind::Tpm2Sealed);
    }

    #[test]
    fn tpm2_open_rejects_wrong_kek_from_unseal() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("v.lbx");
        let mut cont = Container::create_with_passphrase(
            &path,
            None,
            CipherSuite::Aes256GcmSiv,
            test_params(),
            b"bootstrap",
        )
        .unwrap();
        let kek = [0x11u8; 32];
        let blob = vec![0xCDu8; 200];
        cont.enroll_tpm2(&kek, &blob).unwrap();
        cont.persist_header().unwrap();
        drop(cont);

        // Closure returns a WRONG KEK - simulates the "another
        // machine's TPM unsealed but the value doesn't match this
        // slot" case. Open must fail with UnlockFailed (NOT panic,
        // NOT silently succeed).
        let mut wrong_unseal = |_blob: &[u8]| -> Result<[u8; 32], String> { Ok([0x99u8; 32]) };
        let r = Container::open(
            &path,
            None,
            UnlockMaterial::Tpm2 {
                unseal: &mut wrong_unseal,
            },
        );
        assert!(matches!(r, Err(Error::UnlockFailed)));
    }

    #[test]
    fn tpm2_fido2_enroll_open_roundtrip_mocked() {
        // End-to-end fused enroll + open with mocked TPM and
        // mocked FIDO2 hmac_secret.
        let dir = tempdir().unwrap();
        let path = dir.path().join("v.lbx");
        let mut cont = Container::create_with_passphrase(
            &path,
            None,
            CipherSuite::Aes256GcmSiv,
            test_params(),
            b"bootstrap",
        )
        .unwrap();

        let tpm_unsealed = [0xA5u8; 32];
        let hmac_secret = [0xB6u8; 32];
        let fake_blob = vec![0xCDu8; 220];
        let cred_id = vec![0xEFu8; 64];
        let hmac_salt = [0x42u8; 32];

        cont.enroll_tpm2_fido2(&tpm_unsealed, &hmac_secret, &fake_blob, &cred_id, hmac_salt)
            .unwrap();
        cont.persist_header().unwrap();
        drop(cont);

        // Reopen via UnlockMaterial::Tpm2Fido2 with both halves
        // correct. The closure returns the matching tpm_unsealed
        // value when given our fake blob.
        let mut unseal = |blob: &[u8]| -> Result<[u8; 32], String> {
            assert_eq!(
                blob,
                fake_blob.as_slice(),
                "closure should see the same blob"
            );
            Ok(tpm_unsealed)
        };
        let cont = Container::open(
            &path,
            None,
            UnlockMaterial::Tpm2Fido2 {
                unseal: &mut unseal,
                cred_id: &cred_id,
                hmac_secret: &hmac_secret,
            },
        )
        .unwrap();
        assert!(
            cont.header
                .keyslots
                .iter()
                .any(|s| s.kind == SlotKind::Tpm2Fido2)
        );
    }

    #[test]
    fn tpm2_fido2_open_rejects_wrong_factor() {
        // Multi-factor: wrong TPM unsealed value OR wrong
        // hmac_secret OR wrong cred_id all fail with UnlockFailed
        // (the AEAD check fails for the first two, the cred_id
        // mismatch causes the slot to be skipped entirely).
        let dir = tempdir().unwrap();
        let path = dir.path().join("v.lbx");
        let mut cont = Container::create_with_passphrase(
            &path,
            None,
            CipherSuite::Aes256GcmSiv,
            test_params(),
            b"bootstrap",
        )
        .unwrap();
        let tpm = [0x10u8; 32];
        let hs = [0x20u8; 32];
        let blob = vec![0xCDu8; 200];
        let cred = vec![0xEFu8; 60];
        cont.enroll_tpm2_fido2(&tpm, &hs, &blob, &cred, [0u8; 32])
            .unwrap();
        cont.persist_header().unwrap();
        drop(cont);

        // Wrong TPM half: closure returns a different value.
        let mut wrong_tpm_unseal = |_: &[u8]| -> Result<[u8; 32], String> { Ok([0x99u8; 32]) };
        let r = Container::open(
            &path,
            None,
            UnlockMaterial::Tpm2Fido2 {
                unseal: &mut wrong_tpm_unseal,
                cred_id: &cred,
                hmac_secret: &hs,
            },
        );
        assert!(matches!(r, Err(Error::UnlockFailed)));

        // Wrong FIDO2 half: tpm correct but hmac_secret wrong.
        let mut good_unseal = |_: &[u8]| -> Result<[u8; 32], String> { Ok(tpm) };
        let wrong_hs = [0x88u8; 32];
        let r = Container::open(
            &path,
            None,
            UnlockMaterial::Tpm2Fido2 {
                unseal: &mut good_unseal,
                cred_id: &cred,
                hmac_secret: &wrong_hs,
            },
        );
        assert!(matches!(r, Err(Error::UnlockFailed)));

        // Wrong cred_id: no slot matches, closure never invoked.
        let wrong_cred = vec![0u8; 60];
        let mut should_not_be_called = |_: &[u8]| -> Result<[u8; 32], String> {
            panic!("must not be called for unmatched cred_id")
        };
        let r = Container::open(
            &path,
            None,
            UnlockMaterial::Tpm2Fido2 {
                unseal: &mut should_not_be_called,
                cred_id: &wrong_cred,
                hmac_secret: &hs,
            },
        );
        assert!(matches!(r, Err(Error::UnlockFailed)));
    }

    #[test]
    fn tpm2_open_tolerates_unseal_errors() {
        // Multi-slot vault: one passphrase slot we never try, one
        // TPM slot whose closure errors. Open via Tpm2 must
        // surface UnlockFailed rather than propagating the closure
        // error - the caller's "no TPM available right now" case
        // shouldn't crash.
        let dir = tempdir().unwrap();
        let path = dir.path().join("v.lbx");
        let mut cont = Container::create_with_passphrase(
            &path,
            None,
            CipherSuite::Aes256GcmSiv,
            test_params(),
            b"bootstrap",
        )
        .unwrap();
        cont.enroll_tpm2(&[0u8; 32], &[0u8; 100]).unwrap();
        cont.persist_header().unwrap();
        drop(cont);

        let mut failing_unseal = |_blob: &[u8]| -> Result<[u8; 32], String> {
            Err("TPM device not available".to_string())
        };
        let r = Container::open(
            &path,
            None,
            UnlockMaterial::Tpm2 {
                unseal: &mut failing_unseal,
            },
        );
        assert!(matches!(r, Err(Error::UnlockFailed)));
    }

    /// `verify_path_inode` is the post-lock TOCTOU check inside
    /// `Container::open`. Construct two real vault files with different
    /// inodes; opening file A and checking that the path resolves to file B
    /// must reject with `PathSubstituted`. We exercise the helper directly
    /// because the actual race window inside `Container::open` is between
    /// open and lock and impossible to reproduce deterministically from a
    /// synchronous test.
    #[test]
    #[cfg(unix)]
    fn verify_path_inode_rejects_substituted_path() {
        let dir = tempdir().unwrap();
        let a = dir.path().join("a.lbx");
        let b = dir.path().join("b.lbx");
        Container::create_with_passphrase(&a, None, CipherSuite::Aes256Gcm, test_params(), b"pwA")
            .unwrap();
        Container::create_with_passphrase(&b, None, CipherSuite::Aes256Gcm, test_params(), b"pwB")
            .unwrap();

        let (a_handle, a_inode) = open_rw_checked(&a, None).unwrap();
        // Path `a` matches the handle's inode, must succeed.
        verify_path_inode(&a, a_inode).expect("identical path resolves to same inode");
        // Path `b` is a different file, must reject as substituted.
        let err = verify_path_inode(&b, a_inode).unwrap_err();
        assert!(
            matches!(err, Error::PathSubstituted { .. }),
            "expected PathSubstituted, got {err:?}"
        );
        drop(a_handle);
    }
}
