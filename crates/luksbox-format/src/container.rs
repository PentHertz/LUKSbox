// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Penthertz <https://penthertz.com> (https://x.com/PentHertz)

use std::fs::{File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

use fs2::FileExt;
use luksbox_core::file_util::{atomic_secure_write, secure_create_new, sync_parent_dir};
use luksbox_core::{
    Argon2idParams, CipherSuite, FLAG_HAS_HEADER_MIRROR, FLAG_HAS_METADATA_MIRROR, HEADER_SIZE,
    Header, KdfId, Keyslot, MAX_KEYSLOTS, MasterVolumeKey, SlotKind, SubKey,
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
/// Append `".{ext}"` to a path's filename without replacing the
/// existing extension. `Path::with_extension` would replace, which
/// turns `vault.lbx` into `vault.meta-bak`; we want
/// `vault.lbx.meta-bak`. Uses `OsString::push` so it works on Linux
/// (raw bytes), macOS (UTF-8), and Windows (WTF-16 code units)
/// without lossy conversion.
fn append_extension(path: &Path, ext: &str) -> PathBuf {
    let mut s = path.as_os_str().to_owned();
    s.push(".");
    s.push(ext);
    PathBuf::from(s)
}

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

/// Operation kinds recorded in the per-thread flush op log. Used by
/// the v0.2.2 regression test to verify that `Container::sync_data_area`
/// runs BEFORE `Container::write_metadata` during `Vfs::flush`, which
/// is the load-bearing ordering for the mirror-protocol durability
/// fence. Only present (and only recorded) when the `test-injection`
/// feature is on; production / release builds compile this out.
#[cfg(feature = "test-injection")]
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum FlushOp {
    SyncDataArea,
    WriteMetadata,
}

/// Abstraction over the backing storage for the `.lbx` file. Real
/// production code uses `std::fs::File`; the crash-impact test suite
/// uses `SimFile` which models page-cache writes vs durable bytes and
/// supports a `crash()` operation that reverts un-fsync'd writes.
///
/// Composes `std::io::{Read, Write, Seek}` and adds `sync_all` which is
/// the durability primitive Container relies on (and which is NOT on
/// the std I/O traits -- it's an inherent on `std::fs::File`).
pub trait LbxFile: std::io::Read + std::io::Write + std::io::Seek + Send {
    fn sync_all(&mut self) -> std::io::Result<()>;
}

impl LbxFile for std::fs::File {
    fn sync_all(&mut self) -> std::io::Result<()> {
        std::fs::File::sync_all(self)
    }
}

#[cfg(feature = "test-injection")]
std::thread_local! {
    static FLUSH_OP_LOG: std::cell::RefCell<Vec<FlushOp>> =
        const { std::cell::RefCell::new(Vec::new()) };
}

#[cfg(feature = "test-injection")]
fn record_flush_op(op: FlushOp) {
    FLUSH_OP_LOG.with(|log| log.borrow_mut().push(op));
}

/// Clear the per-thread flush op log. Tests call this immediately
/// before the operation under test so prior unrelated flushes don't
/// pollute the assertion.
#[cfg(feature = "test-injection")]
pub fn reset_flush_op_log() {
    FLUSH_OP_LOG.with(|log| log.borrow_mut().clear());
}

/// Snapshot the per-thread flush op log. Tests inspect the returned
/// vec to assert ordering of `sync_data_area` vs `write_metadata`.
#[cfg(feature = "test-injection")]
pub fn flush_op_log_snapshot() -> Vec<FlushOp> {
    FLUSH_OP_LOG.with(|log| log.borrow().clone())
}

#[cfg(feature = "test-injection")]
std::thread_local! {
    /// Thread-local crash-injection point used by the SimFile-backed
    /// durability impact test. When set, `Container::write_metadata`
    /// returns an `Error::Io` AFTER the sidecar mirror has been
    /// committed via `write_metadata_mirror` but BEFORE the live
    /// metadata region is overwritten and `self.file.sync_all()`
    /// is called. This models a real-world crash in the precise
    /// fault window the v0.2.2 durability fence closes: mirror is
    /// durably committed to the NEW state, but un-fsync'd writes
    /// to the `.lbx` file (chunk-list blocks from the spill stage,
    /// plus the live region overwrite still to come) are about to
    /// be lost.
    static CRASH_AFTER_MIRROR_TLS: std::cell::Cell<bool> =
        const { std::cell::Cell::new(false) };
}

/// RAII guard for the crash-after-mirror injection. Restores the
/// previous value on drop. Test-only.
#[cfg(feature = "test-injection")]
pub struct CrashAfterMirrorGuard {
    previous: bool,
}

#[cfg(feature = "test-injection")]
impl Drop for CrashAfterMirrorGuard {
    fn drop(&mut self) {
        CRASH_AFTER_MIRROR_TLS.with(|c| c.set(self.previous));
    }
}

/// Test-only: enable / disable the crash-after-mirror-commit
/// injection on the current thread. Returns a guard that restores
/// the previous value on drop. Set by the durability-impact test
/// to verify the v0.2.2 fence saves chunk-list-block writes; never
/// touched in production.
#[cfg(feature = "test-injection")]
pub fn set_crash_after_mirror_for_test(v: bool) -> CrashAfterMirrorGuard {
    let previous = CRASH_AFTER_MIRROR_TLS.with(|c| c.replace(v));
    CrashAfterMirrorGuard { previous }
}

#[cfg(feature = "test-injection")]
fn crash_after_mirror_for_test() -> bool {
    CRASH_AFTER_MIRROR_TLS.with(|c| c.get())
}

#[cfg(not(feature = "test-injection"))]
#[inline(always)]
fn crash_after_mirror_for_test() -> bool {
    false
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
) -> Result<(File, (u64, u64), PathBuf), Error> {
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
    if let Some(expected) = expected_inode
        && actual != expected
    {
        return Err(Error::PathSubstituted {
            path: path.display().to_string(),
        });
    }
    // Round 12 fix R12-11: capture the canonical (symlink-resolved)
    // path right after the successful open so the later
    // `verify_path_inode` can re-open with `O_NOFOLLOW` and still
    // resolve to the same backing inode. Falls back to the caller's
    // original path if canonicalize fails (e.g. permission denied on
    // an intermediate dir for the canonicalize syscall; the caller's
    // open already succeeded so the regression is just R12-pre-fix
    // behaviour, not worse).
    let canonical = path.canonicalize().unwrap_or_else(|_| path.to_path_buf());
    Ok((f, actual, canonical))
}

/// After we have opened a file and taken its lock, confirm that the path the
/// caller asked for still resolves to the inode we hold. Catches the narrow
/// race where an attacker renamed a different file over `path` between
/// `open_rw_checked` and `lock_handles`. Performed via a fresh read-only
/// open + `inode_of` because stable `std::fs::metadata` does not expose
/// volume serial / file index on Windows; this matches the FFI path
/// `inode_of` already uses on a handle.
///
/// Round 12 fix R12-11: opens the CANONICAL path captured at the
/// original open with `O_NOFOLLOW`. Canonical paths have no symlink
/// components by construction so the open never legitimately needs to
/// follow a link; an attacker-staged symlink over the canonical path
/// is refused with `ELOOP` AND surfaces as `PathSubstituted` here.
/// Legitimate `~/vault.lbx -> /mnt/usb/vault.lbx` users still work
/// because the initial `open_rw_checked` follows the symlink ONCE
/// and the canonical `/mnt/usb/vault.lbx` is then re-opened directly.
fn verify_path_inode(canonical_path: &Path, expected: (u64, u64)) -> Result<(), Error> {
    let mut opts = OpenOptions::new();
    opts.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        opts.custom_flags(libc::O_NOFOLLOW);
    }
    let probe = opts
        .open(canonical_path)
        .map_err(|e| map_io_err_to_vault_locked(e, canonical_path))?;
    let actual = inode_of(&probe).map_err(|e| map_io_err_to_vault_locked(e, canonical_path))?;
    if actual != expected {
        return Err(Error::PathSubstituted {
            path: canonical_path.display().to_string(),
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
use crate::metadata::{self, METADATA_OVERHEAD};

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
    file: Box<dyn LbxFile>,
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
    /// Set when this Container was created in / opened from
    /// deniable-header mode. Carries the cached 8 KiB header bytes
    /// (which `persist_header` writes back wholesale instead of
    /// re-serialising the `Header` struct), the per-vault salt (for
    /// metadata-region AEAD), and a copy of the parsed inner-header
    /// fields. `None` means standard mode and the existing
    /// `header.to_bytes(&mvk)` path applies.
    deniable: Option<DeniableState>,
    /// Set to true when `read_metadata` falls back to the
    /// `<vault>.lbx.meta-bak` sidecar after the live region failed
    /// AEAD verification. `Vfs::flush` uses this to force a metadata
    /// rewrite even when the in-memory tree is otherwise clean,
    /// re-establishing the live region from the recovered bytes so
    /// the next crash has a current live + previous mirror again.
    metadata_recovered_from_mirror: bool,
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

/// Companion state attached to a Container when the vault uses a
/// deniable header (every on-disk byte is indistinguishable from
/// uniform random output). See `docs/DENIABLE_HEADER.md` for the
/// threat model and the five normative security invariants.
///
/// `bytes` is the cached 8 KiB on-disk header buffer; mutations to
/// slot occupancy happen at the byte level (via
/// `deniable_header::install_slot` / `clear_slot`) so we can write
/// it back wholesale during `persist_header` instead of re-running
/// the deniable-create pipeline. `salt` mirrors `bytes[..32]` for
/// fast access (it's used as the metadata-region KDF salt). `inner`
/// caches the parsed inner-header fields so `Container.header` can
/// expose the standard accessors without re-parsing.
/// Intermediate handle returned by phase 1 of v2 deniable open
/// (`Container::try_open_envelope_v2_deniable`). Holds the
/// authenticator material the caller needs to drive secondary
/// factors plus the locked file handle, header buffer, and envelope
/// KEK that phase 2 will use to finish the open. Hand it back to
/// `Container::complete_open_v2_deniable` with a fully-populated
/// `DeniableCredential`.
pub struct DeniableV2EnvelopeHandle {
    file: File,
    path: PathBuf,
    header_buf: Vec<u8>,
    pub opened: crate::deniable_header::OpenedDeniableEnvelope,
    cipher: CipherSuite,
}

impl DeniableV2EnvelopeHandle {
    /// Recovered slot payload: `kind`, `cred_id`, `hmac_salt`,
    /// `tpm_blob`. Caller reads these to know what secondaries to
    /// drive (FIDO2 `get_assertion`, TPM `Unseal`, ML-KEM `decap`).
    pub fn payload(&self) -> &luksbox_core::deniable::slot_payload::SlotPayload {
        &self.opened.payload
    }
}

struct DeniableState {
    bytes: Box<[u8; luksbox_core::deniable::DENIABLE_HEADER_SIZE]>,
    salt: [u8; luksbox_core::deniable::DENIABLE_SALT_SIZE],
    inner: crate::deniable_header::DeniableInnerHeader,
    /// Slot index that the unlock credential matched (or 0 for the
    /// freshly-created vault, which always writes to slot 0). Used
    /// to surface "your credential is in slot N" in the UI and to
    /// catch the footgun where the admin tries to overwrite their
    /// own slot when adding a new user. Set at create / open time;
    /// updated when ops complete.
    unlocked_slot_idx: usize,
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
    #[allow(clippy::too_many_arguments)]
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
    #[allow(clippy::too_many_arguments)]
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
        let metadata_region_size = crate::metadata::resolved_create_metadata_region_size();
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
            file: Box::new(file),
            path: path.to_path_buf(),
            header_storage,
            header,
            mvk,
            header_dirty: false,
            anchor_path: None,
            rotation: None,
            deniable: None,
            metadata_recovered_from_mirror: false,
        })
    }

    /// Create a new container on disk with a single FIDO2 keyslot.
    #[allow(clippy::too_many_arguments)]
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
    #[allow(clippy::too_many_arguments)]
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

    /// Create a vault whose ONLY keyslot is TPM 2.0. No passphrase
    /// slot, no other recovery path. If the TPM chip dies (BIOS
    /// reset, motherboard replacement, OS reinstall) the vault is
    /// permanently unrecoverable.
    ///
    /// Caller has already sealed the unwrap secret via
    /// `Tpm2Sealer::seal` and supplies (a) the 32-byte unsealed key
    /// for the in-process wrap and (b) the sealed blob to store on
    /// disk. The MVK is generated fresh inside `create_internal`.
    pub fn create_with_tpm2(
        path: &Path,
        header_path: Option<&Path>,
        cipher: CipherSuite,
        flags: u32,
        kek_from_tpm: &[u8; 32],
        sealed_blob: &[u8],
    ) -> Result<Self, Error> {
        Self::create_internal(path, header_path, cipher, flags, |mvk, header| {
            Keyslot::new_tpm2(cipher, mvk, kek_from_tpm, sealed_blob, &header.header_salt)
        })
    }

    /// PIN-bound variant of `create_with_tpm2`. Same single-slot,
    /// no-recovery story; the sealed blob must have been produced by
    /// `Tpm2Sealer::seal_with_pin`.
    pub fn create_with_tpm2_pin(
        path: &Path,
        header_path: Option<&Path>,
        cipher: CipherSuite,
        flags: u32,
        kek_from_tpm: &[u8; 32],
        sealed_blob: &[u8],
    ) -> Result<Self, Error> {
        Self::create_internal(path, header_path, cipher, flags, |mvk, header| {
            Keyslot::new_tpm2_pin(cipher, mvk, kek_from_tpm, sealed_blob, &header.header_salt)
        })
    }

    /// Create a vault whose ONLY keyslot is a fused TPM + FIDO2.
    /// Both factors required at every unlock. Loss of either
    /// permanently destroys the vault by design - users picked this
    /// combo because they want AND-semantics.
    #[allow(clippy::too_many_arguments)]
    pub fn create_with_tpm2_fido2(
        path: &Path,
        header_path: Option<&Path>,
        cipher: CipherSuite,
        flags: u32,
        tpm_unsealed: &[u8; 32],
        hmac_secret: &[u8; 32],
        sealed_blob: &[u8],
        cred_id: &[u8],
        hmac_salt: [u8; 32],
    ) -> Result<Self, Error> {
        Self::create_internal(path, header_path, cipher, flags, |mvk, header| {
            Keyslot::new_tpm2_fido2(
                cipher,
                mvk,
                tpm_unsealed,
                hmac_secret,
                sealed_blob,
                cred_id,
                hmac_salt,
                &header.header_salt,
            )
        })
    }

    /// Create a vault whose ONLY keyslot is hybrid TPM + ML-KEM-768.
    /// Both factors required at every unlock; caller stores the
    /// .hybrid sidecar separately.
    pub fn create_with_hybrid_pq_tpm2(
        path: &Path,
        header_path: Option<&Path>,
        cipher: CipherSuite,
        flags: u32,
        kek_from_tpm: &[u8; 32],
        pq_shared: &[u8; 32],
        sealed_blob: &[u8],
    ) -> Result<Self, Error> {
        Self::create_internal(path, header_path, cipher, flags, |mvk, header| {
            Keyslot::new_hybrid_pq_tpm2(
                cipher,
                mvk,
                kek_from_tpm,
                pq_shared,
                sealed_blob,
                &header.header_salt,
            )
        })
    }

    /// ML-KEM-1024 variant of `create_with_hybrid_pq_tpm2`.
    pub fn create_with_hybrid_pq_1024_tpm2(
        path: &Path,
        header_path: Option<&Path>,
        cipher: CipherSuite,
        flags: u32,
        kek_from_tpm: &[u8; 32],
        pq_shared: &[u8; 32],
        sealed_blob: &[u8],
    ) -> Result<Self, Error> {
        Self::create_internal(path, header_path, cipher, flags, |mvk, header| {
            Keyslot::new_hybrid_pq_1024_tpm2(
                cipher,
                mvk,
                kek_from_tpm,
                pq_shared,
                sealed_blob,
                &header.header_salt,
            )
        })
    }

    /// Create a vault whose ONLY keyslot is 3-factor
    /// hybrid TPM + FIDO2 + ML-KEM-768. All three required at every
    /// unlock.
    #[allow(clippy::too_many_arguments)]
    pub fn create_with_hybrid_pq_tpm2_fido2(
        path: &Path,
        header_path: Option<&Path>,
        cipher: CipherSuite,
        flags: u32,
        tpm_unsealed: &[u8; 32],
        hmac_secret: &[u8; 32],
        pq_shared: &[u8; 32],
        sealed_blob: &[u8],
        cred_id: &[u8],
        hmac_salt: [u8; 32],
    ) -> Result<Self, Error> {
        Self::create_internal(path, header_path, cipher, flags, |mvk, header| {
            Keyslot::new_hybrid_pq_tpm2_fido2(
                cipher,
                mvk,
                tpm_unsealed,
                hmac_secret,
                pq_shared,
                sealed_blob,
                cred_id,
                hmac_salt,
                &header.header_salt,
            )
        })
    }

    /// ML-KEM-1024 variant of `create_with_hybrid_pq_tpm2_fido2`.
    #[allow(clippy::too_many_arguments)]
    pub fn create_with_hybrid_pq_1024_tpm2_fido2(
        path: &Path,
        header_path: Option<&Path>,
        cipher: CipherSuite,
        flags: u32,
        tpm_unsealed: &[u8; 32],
        hmac_secret: &[u8; 32],
        pq_shared: &[u8; 32],
        sealed_blob: &[u8],
        cred_id: &[u8],
        hmac_salt: [u8; 32],
    ) -> Result<Self, Error> {
        Self::create_internal(path, header_path, cipher, flags, |mvk, header| {
            Keyslot::new_hybrid_pq_1024_tpm2_fido2(
                cipher,
                mvk,
                tpm_unsealed,
                hmac_secret,
                pq_shared,
                sealed_blob,
                cred_id,
                hmac_salt,
                &header.header_salt,
            )
        })
    }

    // ============================================================
    // Deniable-header mode: integration with the standard Container
    // ============================================================
    //
    // create_with_passphrase_deniable / open_with_passphrase_deniable
    // are siblings of `create_internal` / `open`. They produce a
    // Container whose `deniable` field is `Some` and whose synthetic
    // `header` is populated from the parsed `DeniableInnerHeader`.
    // The rest of Container's machinery (metadata region, data area,
    // chunk AEAD, file locking) is identical between the two modes -
    // only the header serialisation differs.
    //
    // v1 limitations enforced by `guard_no_deniable_slot_mutation`:
    // - Only a single passphrase slot is supported (slot 0 occupied,
    //   slots 1..8 random filler).
    // - Slot enroll / revoke / rotate operations return a clear
    //   "not yet supported in deniable mode" error. Multi-user
    //   deniable is tracked as a follow-up.
    // - FIDO2 / TPM / hybrid-PQ slot kinds are not supported in
    //   deniable mode at all in v1 (they each carry per-slot
    //   metadata that the deniable slot format hides; wiring them
    //   in needs sidecar handling per the design doc).

    /// Create a new deniable-mode container. The resulting vault
    /// file's first 8 KiB is a deniable header (every byte
    /// indistinguishable from uniform random); the metadata region
    /// and data area below follow the standard layout but are
    /// AEAD-keyed via the MVK recovered from the deniable header.
    ///
    /// The user MUST remember `cipher`, `kdf_params`, and the
    /// passphrase to reopen this vault. There is no fail-fast magic
    /// check.
    pub fn create_with_passphrase_deniable(
        path: &Path,
        header_path: Option<&Path>,
        cipher: CipherSuite,
        kdf_params: Argon2idParams,
        flags: u32,
        passphrase: &[u8],
    ) -> Result<Self, Error> {
        // v2 delegate: wrap the passphrase into a
        // `DeniableCredential::Passphrase` and route through the v2
        // create path so the on-disk layout matches everything else
        // produced by the v2-only user paths (CLI / TUI / GUI).
        let cred = luksbox_core::deniable::DeniableCredential::Passphrase {
            passphrase,
            argon2: kdf_params,
        };
        Self::create_with_credential_v2_deniable(
            path,
            header_path,
            cipher,
            flags,
            0,
            &cred,
            &crate::deniable_header::DeniableMaterial::passphrase_only(),
        )
    }

    // v1 `create_with_credential_deniable`, `open_with_credential_deniable`,
    // and `enroll_credential_deniable` were removed in v2. All
    // callers (CLI, TUI wizard, GUI, container tests) now use the v2
    // two-phase API: `create_with_credential_v2_deniable`,
    // `try_open_envelope_v2_deniable` + `complete_open_v2_deniable`,
    // and `enroll_credential_v2_deniable`.

    /// Open an existing deniable-mode container. Caller must supply
    /// the cipher + Argon2 params + passphrase that was used at
    /// create time. All failure modes (wrong cipher, wrong params,
    /// wrong passphrase, truncated file) collapse to
    /// `Error::OpaqueUnlockFailed`.
    pub fn open_with_passphrase_deniable(
        path: &Path,
        header_path: Option<&Path>,
        passphrase: &[u8],
        kdf_params: Argon2idParams,
        cipher: CipherSuite,
    ) -> Result<Self, Error> {
        // v2 delegate: wrap the passphrase into a
        // `DeniableCredential::Passphrase` and route through the v2
        // two-phase open (envelope discovery + complete unlock).
        let cred = luksbox_core::deniable::DeniableCredential::Passphrase {
            passphrase,
            argon2: kdf_params,
        };
        // This wrapper is dedicated to passphrase deniable slots, so
        // hint discovery at Passphrase. Without the hint, a vault
        // that has both a Passphrase and a higher-variant slot under
        // the same envelope passphrase could non-deterministically
        // dispatch into the higher slot (which then fails phase 2
        // for missing FIDO2 / TPM / ML-KEM secondaries) instead of
        // unlocking the passphrase slot the user explicitly chose.
        let envelope = Self::try_open_envelope_v2_deniable(
            path,
            header_path,
            &cred,
            cipher,
            Some(luksbox_core::deniable::DeniableKindTag::Passphrase),
        )?;
        Self::complete_open_v2_deniable(envelope, &cred)
    }

    /// Slot index whose credential opened this Container, or 0 if
    /// the vault was just created. Only meaningful for deniable-mode
    /// containers; `None` for standard mode (which uses
    /// `header.keyslots[idx].kind` instead).
    pub fn deniable_unlocked_slot(&self) -> Option<usize> {
        self.deniable.as_ref().map(|d| d.unlocked_slot_idx)
    }

    // ============================================================
    // v2 deniable container API: embedded material, no sidecar
    // ============================================================

    /// v2 deniable create. Same role as
    /// `create_with_credential_deniable` but embeds `cred_id`,
    /// `hmac_salt`, and the TPM sealed blob inside the slot envelope
    /// instead of demanding a `.tpm-blob` sidecar / external `cred_id`
    /// storage.
    ///
    /// Caller must have already enrolled the relevant device (FIDO2
    /// `MakeCredential`, TPM `TPM2_Create`+`Load`+`PolicyAuthorize`,
    /// ML-KEM encap) and supplies both the resulting secondaries (in
    /// `credential`) and the on-disk material (in `material`).
    ///
    /// Hard requirements:
    /// - `credential` must be a v2 `*Passphrase` variant. Passing a
    ///   v1 passphraseless variant returns `Error::InvalidField`.
    /// - `material` must match the variant: FIDO2 variants need
    ///   non-empty `cred_id` + `Some(hmac_salt)`, TPM variants need
    ///   non-empty `tpm_blob`, Passphrase needs nothing.
    /// - `header_path` must be `None` (deniable v2 mode keeps the
    ///   header inline; sidecar headers are a separate feature).
    pub fn create_with_credential_v2_deniable(
        path: &Path,
        header_path: Option<&Path>,
        cipher: CipherSuite,
        flags: u32,
        slot_idx: usize,
        credential: &luksbox_core::deniable::DeniableCredential,
        material: &crate::deniable_header::DeniableMaterial,
    ) -> Result<Self, Error> {
        use crate::deniable_header::{DeniableInnerHeader, create_with_credential_v2};
        use luksbox_core::deniable::DENIABLE_HEADER_SIZE;

        let metadata_region_size = crate::metadata::resolved_create_metadata_region_size();
        if header_path.is_some() {
            return Err(Error::Crypto(luksbox_core::Error::InvalidField));
        }
        let metadata_offset = DENIABLE_HEADER_SIZE as u64;
        let data_offset = metadata_offset + metadata_region_size;

        let inner = DeniableInnerHeader {
            format_version_minor: 0,
            cipher_suite: cipher,
            kdf_id: KdfId::Argon2id,
            flags,
            metadata_offset,
            metadata_size: metadata_region_size,
            data_offset,
            chunk_size: 4096,
        };

        let (header_bytes, mvk) =
            create_with_credential_v2(credential, material, slot_idx, cipher, inner)?;
        debug_assert_eq!(header_bytes.len(), DENIABLE_HEADER_SIZE);

        let mut salt = [0u8; 32];
        salt.copy_from_slice(&header_bytes[..32]);

        let mut synth_header = Header::try_new(cipher, KdfId::Argon2id, 4096, data_offset)?;
        synth_header.flags = flags;
        synth_header.metadata_offset = metadata_offset;
        synth_header.metadata_size = metadata_region_size;
        synth_header.header_salt = salt;

        let mut file = secure_create_new(path)?;
        file.write_all(&header_bytes)?;
        let mut region = vec![0u8; metadata_region_size as usize];
        metadata::write_metadata(cipher, &mvk, &salt, b"", &mut region)?;
        file.write_all(&region)?;
        file.flush()?;

        lock_handles(&[(&file, path)])?;

        let mut header_bytes_arr = Box::new([0u8; DENIABLE_HEADER_SIZE]);
        header_bytes_arr.copy_from_slice(&header_bytes);

        Ok(Self {
            file: Box::new(file),
            path: path.to_path_buf(),
            header_storage: HeaderStorage::Inline,
            header: synth_header,
            mvk,
            header_dirty: false,
            anchor_path: None,
            rotation: None,
            deniable: Some(DeniableState {
                bytes: header_bytes_arr,
                salt,
                inner,
                unlocked_slot_idx: slot_idx,
            }),
            metadata_recovered_from_mirror: false,
        })
    }

    /// v2 deniable open, phase 1. Returns the matched slot's payload
    /// (kind tag + `cred_id` + `hmac_salt` + `tpm_blob`) plus the
    /// envelope KEK that the caller needs to pass back into
    /// `complete_open_v2_deniable` once it has driven the secondary
    /// factors.
    ///
    /// `credential` only needs the passphrase + Argon2 params; any
    /// secondaries on it are ignored at this phase. In practice the
    /// caller passes `DeniableCredential::Passphrase { passphrase,
    /// argon2 }` here, learns the kind tag from the returned payload,
    /// drives the device, then constructs the full credential for
    /// phase 2.
    pub fn try_open_envelope_v2_deniable(
        path: &Path,
        header_path: Option<&Path>,
        credential: &luksbox_core::deniable::DeniableCredential,
        cipher: CipherSuite,
        want_kind: Option<luksbox_core::deniable::DeniableKindTag>,
    ) -> Result<DeniableV2EnvelopeHandle, Error> {
        use crate::deniable_header::try_open_envelope_v2;
        use luksbox_core::deniable::DENIABLE_HEADER_SIZE;

        if header_path.is_some() {
            return Err(Error::Crypto(luksbox_core::Error::InvalidField));
        }

        // Route through `open_rw_checked` so this path honors
        // `LUKSBOX_NO_FOLLOW_SYMLINKS=1` (refuses if `path` is a
        // symlink) and captures the canonical path + inode for the
        // post-lock TOCTOU re-verification, matching the standard
        // (non-deniable) open. A direct `OpenOptions::open` would
        // silently follow a symlink and skip the path-substitution
        // check.
        let (mut file, file_inode, canonical_path) = open_rw_checked(path, None)?;
        lock_handles(&[(&file, path)])?;
        // Post-lock TOCTOU re-verification: between the open above
        // and the lock just taken, an attacker who can write to the
        // parent directory could have renamed a different file over
        // `path`. Our handle still points at the originally-opened
        // inode, locked, but the path now resolves to a different
        // file. Refuse with `PathSubstituted` so the user can
        // investigate. Mirrors the same check in `load_locked_header`.
        verify_path_inode(&canonical_path, file_inode)?;

        let mut header_buf = vec![0u8; DENIABLE_HEADER_SIZE];
        file.read_exact(&mut header_buf)
            .map_err(|_| Error::OpaqueUnlockFailed)?;

        let opened = try_open_envelope_v2(&header_buf, credential, cipher, want_kind)?;

        Ok(DeniableV2EnvelopeHandle {
            file,
            path: path.to_path_buf(),
            header_buf,
            opened,
            cipher,
        })
    }

    /// v2 deniable open, phase 2. Caller has driven the secondary
    /// factors based on the payload exposed by phase 1 and now
    /// supplies a fully-populated `DeniableCredential` (one whose
    /// `kind_tag()` matches the envelope's payload kind).
    pub fn complete_open_v2_deniable(
        envelope: DeniableV2EnvelopeHandle,
        credential: &luksbox_core::deniable::DeniableCredential,
    ) -> Result<Self, Error> {
        Self::complete_open_v2_deniable_reusable(envelope, credential).map_err(|(_, e)| e)
    }

    /// Same as `complete_open_v2_deniable` but hands the envelope
    /// handle back on failure so the caller can retry with a
    /// different secondary-factor output without re-running the
    /// Argon2id discovery phase or dropping the vault file lock.
    ///
    /// Exists for the v0.2.x -> v0.3.0 FIDO2 hmac-secret
    /// salt-convention probe: v2 deniable envelopes embed no
    /// convention marker (unlike keyslots, which carry
    /// `aad_version`), so the front-ends try the V4 prehashed
    /// convention first and on `OpaqueUnlockFailed` drive the
    /// authenticator again with the raw-salt convention that
    /// v0.2.1/v0.2.2 envelopes recorded.
    pub fn complete_open_v2_deniable_reusable(
        envelope: DeniableV2EnvelopeHandle,
        credential: &luksbox_core::deniable::DeniableCredential,
    ) -> Result<Self, (DeniableV2EnvelopeHandle, Error)> {
        use crate::deniable_header::complete_open_v2;
        use luksbox_core::deniable::DENIABLE_HEADER_SIZE;

        let result = match complete_open_v2(&envelope.opened, credential, envelope.cipher) {
            Ok(r) => r,
            Err(e) => return Err((envelope, e)),
        };

        // Build the synthetic header before destructuring so a
        // structural failure can still hand the envelope back.
        let mut synth_header = match Header::try_new(
            result.inner.cipher_suite,
            result.inner.kdf_id,
            result.inner.chunk_size,
            result.inner.data_offset,
        ) {
            Ok(h) => h,
            Err(e) => return Err((envelope, Error::Crypto(e))),
        };

        let DeniableV2EnvelopeHandle {
            file,
            path,
            header_buf,
            opened: _,
            cipher: _,
        } = envelope;
        synth_header.flags = result.inner.flags;
        synth_header.metadata_offset = result.inner.metadata_offset;
        synth_header.metadata_size = result.inner.metadata_size;
        synth_header.header_salt = result.per_vault_salt;

        let mut header_bytes_arr = Box::new([0u8; DENIABLE_HEADER_SIZE]);
        header_bytes_arr.copy_from_slice(&header_buf);

        Ok(Self {
            file: Box::new(file),
            path,
            header_storage: HeaderStorage::Inline,
            header: synth_header,
            mvk: result.mvk,
            header_dirty: false,
            anchor_path: None,
            rotation: None,
            deniable: Some(DeniableState {
                bytes: header_bytes_arr,
                salt: result.per_vault_salt,
                inner: result.inner,
                unlocked_slot_idx: result.matched_slot_idx,
            }),
            metadata_recovered_from_mirror: false,
        })
    }

    /// **Envelope-only** deniable MVK rotation. Generates a fresh
    /// per-vault salt and MVK, re-installs each kept slot under the
    /// new salt as a v2 two-layer envelope. Slots not in
    /// `keep_slots` get fresh `OsRng` bytes so a before/after diff
    /// of the on-disk header reveals nothing about which slots were
    /// occupied (security invariant #4).
    ///
    /// **SAFETY**: this entry point ONLY rewraps the slot envelope.
    /// It does NOT re-encrypt chunks, chunk-list blocks (v3), or the
    /// metadata blob under the new MVK. Calling this on a vault that
    /// already has user content leaves those bytes encrypted under
    /// the OLD MVK's file_keys, and the vault becomes unreadable on
    /// next open. The guard at the top of this function rejects such
    /// calls with `Error::DeniableRotationRequiresEmptyVault`.
    ///
    /// **For non-empty deniable vaults use
    /// [`luksbox_vfs::Vfs::rotate_mvk_deniable`] instead** -- it pairs
    /// the envelope rewrap with a full chunk + chunk-list-block +
    /// metadata re-encryption.
    ///
    /// Legitimate use cases for this direct entry point are narrow:
    ///   - immediately after `create_with_credential_v2_deniable` to
    ///     re-randomize the slot envelope before any data is written
    ///     (e.g., for deterministic-test setup);
    ///   - low-level format tests that drive rotation without going
    ///     through the Vfs.
    ///
    /// `keep_slots = [(slot_idx, credential, material)]`. Caller is
    /// responsible for re-supplying every credential's secondary
    /// outputs (e.g. re-running FIDO2 assertion to get
    /// `hmac_secret_output`, re-running `TPM2_Unseal` to get
    /// `unsealed`, re-running ML-KEM decap to get `mlkem_shared`).
    /// `material` is re-embedded byte-for-byte; rotation re-keys the
    /// envelope, not the underlying authenticator material.
    ///
    /// On success, mutates the Container's MVK + salt + cached
    /// deniable header bytes to match the new state and marks
    /// `header_dirty`. Call `persist_header` to commit to disk.
    ///
    /// On error the Container is left untouched.
    pub fn rotate_mvk_v2_deniable(
        &mut self,
        keep_slots: &[(
            usize,
            &luksbox_core::deniable::DeniableCredential,
            &crate::deniable_header::DeniableMaterial,
        )],
    ) -> Result<MasterVolumeKey, Error> {
        // Footgun guard: refuse if the vault has any user content.
        // The metadata blob is empty exactly when no Vfs::flush has
        // ever happened -- i.e. no files have been written. Any
        // non-empty blob means there are chunks on disk that this
        // envelope-only rotation would NOT re-encrypt under the new
        // MVK, leaving the vault unreadable on next open.
        //
        // The check is cheap (one AEAD decrypt of the metadata
        // region) and runs BEFORE any state mutation, so the
        // refusal is fully atomic -- caller sees a typed error and
        // the container is unchanged.
        //
        // Read uses the CURRENT MVK + salt (the rotation hasn't
        // started yet); the plaintext is dropped immediately, only
        // its length matters here.
        let pt_len = self.read_metadata()?.len();
        if pt_len > 0 {
            return Err(Error::DeniableRotationRequiresEmptyVault);
        }
        // Empty-vault path: delegate to the unguarded primitive.
        self.rotate_mvk_v2_deniable_envelope_only(keep_slots)
    }

    /// Envelope-only rotation primitive **without** the
    /// empty-vault guard. Used by
    /// [`luksbox_vfs::Vfs::rotate_mvk_deniable`], which couples this
    /// call with a chunk + chunk-list-block + metadata
    /// re-encryption pass under the new MVK to deliver a full
    /// rotation. The Vfs wrapper has its own atomicity envelope
    /// (`begin_atomic_rotation` / `commit_atomic_rotation`) so a
    /// crash between this call and the chunk-rekey loop leaves the
    /// original vault intact.
    ///
    /// **DO NOT CALL THIS DIRECTLY** unless you have a chunk-rekey
    /// loop ready to follow. Calling this and then opening the
    /// vault will fail because the chunks are still encrypted under
    /// the OLD MVK. The guarded public entry point
    /// `rotate_mvk_v2_deniable` is the one external code should
    /// reach for; this is `pub` only because cross-crate access from
    /// `luksbox-vfs` is needed.
    pub fn rotate_mvk_v2_deniable_envelope_only(
        &mut self,
        keep_slots: &[(
            usize,
            &luksbox_core::deniable::DeniableCredential,
            &crate::deniable_header::DeniableMaterial,
        )],
    ) -> Result<MasterVolumeKey, Error> {
        use crate::deniable_header::rotate_mvk_v2;
        use luksbox_core::deniable::{self, DENIABLE_SALT_SIZE};

        let den = self
            .deniable
            .as_mut()
            .ok_or(Error::Crypto(luksbox_core::Error::InvalidField))?;

        let mut new_salt = [0u8; DENIABLE_SALT_SIZE];
        deniable::fill_random(&mut new_salt).map_err(Error::Crypto)?;

        // rotate_mvk_v2 takes a temp copy and only commits on
        // success, so a mid-rotation failure leaves the cached
        // header bytes untouched. We mirror that at this layer by
        // running rotation against a clone and only swapping into
        // `den.bytes` on success.
        let mut work = den.bytes.clone();
        let new_mvk = rotate_mvk_v2(
            &mut work,
            den.inner,
            self.header.cipher_suite,
            new_salt,
            keep_slots,
        )?;

        // Commit the new state.
        *den.bytes = *work;
        den.salt = new_salt;
        self.mvk = new_mvk.clone();
        // Sync the synthetic Header's salt so any downstream
        // metadata-region code derives subkeys against the new
        // per-vault salt.
        self.header.header_salt = new_salt;
        self.header_dirty = true;
        Ok(new_mvk)
    }

    /// v2 deniable enroll: install a new credential at `slot_idx`
    /// using the v2 two-layer envelope + embedded material flow.
    /// Same footgun guard as the v1 enroll (refuses
    /// `slot_idx == unlocked_slot_idx`).
    pub fn enroll_credential_v2_deniable(
        &mut self,
        slot_idx: usize,
        credential: &luksbox_core::deniable::DeniableCredential,
        material: &crate::deniable_header::DeniableMaterial,
    ) -> Result<usize, Error> {
        use luksbox_core::deniable::DENIABLE_SLOT_COUNT;
        let den = self
            .deniable
            .as_mut()
            .ok_or(Error::Crypto(luksbox_core::Error::InvalidField))?;
        if slot_idx >= DENIABLE_SLOT_COUNT {
            return Err(Error::Crypto(luksbox_core::Error::InvalidKeyslotIndex(
                slot_idx,
            )));
        }
        if slot_idx == den.unlocked_slot_idx {
            return Err(Error::Crypto(luksbox_core::Error::InvalidField));
        }
        crate::deniable_header::install_slot_v2(
            &mut den.bytes,
            slot_idx,
            credential,
            material,
            &self.mvk,
            self.header.cipher_suite,
            &den.salt,
        )?;
        self.header_dirty = true;
        Ok(slot_idx)
    }

    /// Enroll an additional passphrase credential at a specific
    /// `slot_idx` (0..7). Deniable-mode equivalent of
    /// `enroll_passphrase` - the latter would silently break the
    /// vault by mutating only the synthetic `Header.keyslots`
    /// while `persist_header` writes the cached deniable buffer
    /// without the new wrap.
    ///
    /// `slot_idx` is the target slot. The caller is responsible
    /// for picking an index that doesn't overwrite an existing
    /// credential the admin wants to keep. The current unlock
    /// slot (visible via `deniable_unlocked_slot`) is rejected
    /// here as a footgun guard - admins should not overwrite their
    /// own credential. To rotate the admin's own credential, use
    /// `rotate_mvk_deniable` (forthcoming).
    pub fn enroll_passphrase_deniable(
        &mut self,
        slot_idx: usize,
        passphrase: &[u8],
        kdf_params: Argon2idParams,
    ) -> Result<usize, Error> {
        // v2 delegate: wrap the passphrase into a
        // `DeniableCredential::Passphrase` and route through the v2
        // enroll path so the new slot uses the same two-layer
        // envelope encoding as everything else.
        let cred = luksbox_core::deniable::DeniableCredential::Passphrase {
            passphrase,
            argon2: kdf_params,
        };
        self.enroll_credential_v2_deniable(
            slot_idx,
            &cred,
            &crate::deniable_header::DeniableMaterial::passphrase_only(),
        )
    }

    /// Overwrite a slot with fresh random bytes so the credential
    /// previously stored there can no longer unlock the vault.
    /// Refuses to clear the admin's own unlock slot - that's a
    /// footgun, and the admin would lock themselves out
    /// permanently. To clear ALL slots and re-enroll with a fresh
    /// MVK, use `rotate_mvk_deniable` (forthcoming).
    pub fn clear_deniable_slot(&mut self, slot_idx: usize) -> Result<(), Error> {
        use luksbox_core::deniable::DENIABLE_SLOT_COUNT;
        let den = self
            .deniable
            .as_mut()
            .ok_or(Error::Crypto(luksbox_core::Error::InvalidField))?;
        if slot_idx >= DENIABLE_SLOT_COUNT {
            return Err(Error::Crypto(luksbox_core::Error::InvalidKeyslotIndex(
                slot_idx,
            )));
        }
        if slot_idx == den.unlocked_slot_idx {
            return Err(Error::Crypto(luksbox_core::Error::InvalidField));
        }
        crate::deniable_header::clear_slot(&mut den.bytes, slot_idx)?;
        self.header_dirty = true;
        Ok(())
    }

    /// Returns true if this Container was opened from a deniable-mode
    /// vault. Used by slot-mutation guards and by `persist_header`.
    pub fn is_deniable(&self) -> bool {
        self.deniable.is_some()
    }

    /// Gate slot enroll / revoke / rotate operations. v1 deniable
    /// mode is single-slot; the multi-slot management story lives
    /// at the `deniable_header::install_slot` / `clear_slot` /
    /// `rotate_mvk` layer but plumbing it through the Container's
    /// slot-table abstraction needs more design (the synthetic
    /// `header.keyslots` array doesn't reflect occupancy in
    /// deniable mode). Until then we refuse the operation with a
    /// clear error rather than silently writing to the wrong place.
    fn guard_no_deniable_slot_mutation(&self) -> Result<(), Error> {
        if self.is_deniable() {
            return Err(Error::Crypto(luksbox_core::Error::InvalidField));
        }
        Ok(())
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
        let metadata_region_size = crate::metadata::resolved_create_metadata_region_size();
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
            file: Box::new(file),
            path: path.to_path_buf(),
            header_storage,
            header,
            mvk,
            header_dirty: false,
            anchor_path: None,
            rotation: None,
            deniable: None,
            metadata_recovered_from_mirror: false,
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
        let (file, header_storage, _header_bytes, header, mvk, recovered) =
            Self::open_locked_with_header_recovery(path, header_path, |h, b| {
                let mvk = try_unlock(h, &mut material)?;
                h.verify_hmac(b, &mvk)?;
                Ok(mvk)
            })?;
        Ok(Self {
            file: Box::new(file),
            path: path.to_path_buf(),
            header_storage,
            header,
            mvk,
            // If the header was recovered from a sidecar mirror, force
            // a header flush on next clean shutdown so the live region
            // is re-established. Avoids the next crash leaving the
            // vault with no live header AND no recovered mirror.
            header_dirty: recovered,
            anchor_path: None,
            rotation: None,
            deniable: None,
            metadata_recovered_from_mirror: false,
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
        // The unlock+verify closure here is HMAC-only because the
        // caller already has the MVK; we don't need to walk keyslots.
        // We return a clone of the input MVK on success so the helper
        // signature stays uniform with the keyslot-bearing path.
        let mvk_for_closure = mvk.clone();
        let (file, header_storage, _header_bytes, header, recovered_mvk, recovered) =
            Self::open_locked_with_header_recovery(path, header_path, move |h, b| {
                h.verify_hmac(b, &mvk_for_closure)?;
                Ok(mvk_for_closure.clone())
            })?;
        // Drop the unused clone returned by the helper; we already
        // hold the caller-supplied MVK and prefer that exact instance.
        let _ = recovered_mvk;
        Ok(Self {
            file: Box::new(file),
            path: path.to_path_buf(),
            header_storage,
            header,
            mvk,
            header_dirty: recovered,
            anchor_path: None,
            rotation: None,
            deniable: None,
            metadata_recovered_from_mirror: false,
        })
    }

    /// Open a **deniable-format** vault using a pre-supplied MVK and
    /// the already-decrypted deniable state.
    ///
    /// Companion to `open_with_mvk` for the deniable container format,
    /// used by the macOS FUSE-T mount helper subprocess. Standard
    /// `open_with_mvk` cannot work on deniable vaults because:
    ///   - there is no plaintext magic at offset 0 (the whole file
    ///     looks uniformly random by design),
    ///   - there is no plain HMAC header to verify the MVK against
    ///     (each slot is independently AEAD-wrapped),
    ///   - the inner header (cipher_suite, offsets, chunk_size) is
    ///     AEAD-encrypted with a key derived from the user's
    ///     **credential**, not from the MVK, so a holder of just the
    ///     MVK cannot recover the layout fields needed to read chunks.
    ///
    /// The parent process that already unlocked the vault must
    /// therefore hand the helper:
    ///   - `mvk` -- the recovered MVK,
    ///   - `per_vault_salt` -- first 32 B of the on-disk file (public,
    ///     but needed to derive any secondary keys),
    ///   - `inner` -- the already-decrypted public layout fields,
    ///   - `unlocked_slot_idx` -- which slot's envelope the parent
    ///     opened (used for downstream enroll/rotate refusals).
    ///
    /// On disk: re-opens `path` with `O_RDWR`, takes the exclusive
    /// flock, and reads the 36864-byte deniable header into the
    /// returned Container's `DeniableState.bytes` so that rotation /
    /// enroll operations have the same authoritative byte image the
    /// parent had.
    ///
    /// `header_path` is rejected with `InvalidField`: deniable vaults
    /// store the header inline by definition (every byte must look
    /// uniformly random -- a detached header file would be a
    /// distinguishability beacon).
    pub fn open_with_mvk_deniable(
        path: &Path,
        header_path: Option<&Path>,
        mvk: MasterVolumeKey,
        per_vault_salt: [u8; luksbox_core::deniable::DENIABLE_SALT_SIZE],
        inner: crate::deniable_header::DeniableInnerHeader,
        unlocked_slot_idx: usize,
    ) -> Result<Self, Error> {
        use luksbox_core::deniable::{DENIABLE_HEADER_SIZE, DENIABLE_SLOT_COUNT};

        if header_path.is_some() {
            return Err(Error::Crypto(luksbox_core::Error::InvalidField));
        }
        if unlocked_slot_idx >= DENIABLE_SLOT_COUNT {
            return Err(Error::Crypto(luksbox_core::Error::InvalidField));
        }

        // Same hardening as `try_open_envelope_v2_deniable` and the
        // standard `open_with_mvk` -- go through `open_rw_checked` so
        // `LUKSBOX_NO_FOLLOW_SYMLINKS` and the post-lock inode
        // re-verification apply to this deniable open path too.
        let (mut file, file_inode, canonical_path) = open_rw_checked(path, None)?;
        lock_handles(&[(&file, path)])?;
        verify_path_inode(&canonical_path, file_inode)?;

        let mut header_buf = Box::new([0u8; DENIABLE_HEADER_SIZE]);
        file.read_exact(header_buf.as_mut_slice())
            .map_err(|_| Error::OpaqueUnlockFailed)?;

        // Belt-and-suspenders: the first 32 bytes of the on-disk file
        // ARE the per_vault_salt. If the parent passed a salt that
        // doesn't match what we read from disk, the parent's
        // deniable-state cache has drifted from what's on disk and the
        // helper would proceed to mount with a stale layout. Refuse
        // rather than silently mount the wrong vault image. Constant-
        // time compare so an attacker cannot side-channel the
        // mismatch position (defense-in-depth; we're inside the trust
        // boundary, but cheap).
        use subtle::ConstantTimeEq;
        if header_buf[..per_vault_salt.len()]
            .ct_eq(&per_vault_salt)
            .unwrap_u8()
            == 0
        {
            return Err(Error::OpaqueUnlockFailed);
        }

        // Synthesize the standard Header struct the same way
        // `complete_open_v2_deniable` does, so downstream code that
        // reads `self.header.*` sees consistent values for the
        // cipher_suite / metadata offsets / chunk size.
        let mut synth_header = Header::try_new(
            inner.cipher_suite,
            inner.kdf_id,
            inner.chunk_size,
            inner.data_offset,
        )?;
        synth_header.flags = inner.flags;
        synth_header.metadata_offset = inner.metadata_offset;
        synth_header.metadata_size = inner.metadata_size;
        synth_header.header_salt = per_vault_salt;

        Ok(Self {
            file: Box::new(file),
            path: path.to_path_buf(),
            header_storage: HeaderStorage::Inline,
            header: synth_header,
            mvk,
            header_dirty: false,
            anchor_path: None,
            rotation: None,
            deniable: Some(DeniableState {
                bytes: header_buf,
                salt: per_vault_salt,
                inner,
                unlocked_slot_idx,
            }),
            metadata_recovered_from_mirror: false,
        })
    }

    /// Snapshot of the open-deniable state needed to hand off to a
    /// mount-helper subprocess. Returns `None` for standard (non-
    /// deniable) containers. The MVK is NOT included -- the caller
    /// already has it via `mvk_clone()`. The salt, inner header, and
    /// slot index together are the minimum a helper needs to re-open
    /// the same vault image without re-running envelope discovery.
    pub fn deniable_handoff_state(
        &self,
    ) -> Option<(
        [u8; luksbox_core::deniable::DENIABLE_SALT_SIZE],
        crate::deniable_header::DeniableInnerHeader,
        usize,
    )> {
        self.deniable
            .as_ref()
            .map(|d| (d.salt, d.inner, d.unlocked_slot_idx))
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
        let (mut file, file_inode, canonical_path) = open_rw_checked(path, None)?;
        let (mut header_storage, header_inode, canonical_header) = match header_path {
            None => (HeaderStorage::Inline, None, None),
            Some(hp) => {
                let (hf, hf_inode, canon_hp) = open_rw_checked(hp, None)?;
                (
                    HeaderStorage::Detached(hf, hp.to_path_buf()),
                    Some(hf_inode),
                    Some(canon_hp),
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
        // Round 12 fix R12-11: re-verify using the CANONICAL path
        // captured at open time (symlinks resolved once), and the
        // updated `verify_path_inode` opens with `O_NOFOLLOW` so an
        // attacker-staged symlink swap is refused.
        verify_path_inode(&canonical_path, file_inode)?;
        if let (Some(canon_hp), Some(expected)) = (canonical_header.as_ref(), header_inode) {
            verify_path_inode(canon_hp, expected)?;
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

    /// Open + lock the vault, then attempt the caller-supplied unlock
    /// step against the live header. If the live header fails (parse,
    /// unlock, or HMAC verify), look for `<storage_path>.header-bak`
    /// and retry the same unlock step against it. On mirror success,
    /// returns the mirror-recovered (bytes, header, mvk) tuple with
    /// `recovered = true`. On mirror failure or absence, returns the
    /// LIVE error so the user sees the actual cause.
    ///
    /// Threat model:
    /// - Mirror is AEAD-authenticated under the same MVK as live, so
    ///   a forged mirror does not verify and gets rejected here.
    /// - A stale-but-valid mirror would lose at most the most recent
    ///   header rewrite, which is the same posture as recovering an
    ///   older anchor counter (also a "previous good" semantics).
    /// - The anchor-counter check downstream still runs against the
    ///   recovered header so a malicious rollback past the anchor
    ///   high-water mark still gets rejected.
    fn open_locked_with_header_recovery<F>(
        path: &Path,
        header_path: Option<&Path>,
        mut try_unlock_and_verify: F,
    ) -> Result<
        (
            File,
            HeaderStorage,
            [u8; HEADER_SIZE],
            Header,
            MasterVolumeKey,
            bool,
        ),
        Error,
    >
    where
        F: FnMut(&Header, &[u8; HEADER_SIZE]) -> Result<MasterVolumeKey, Error>,
    {
        // **CRITICAL SECURITY BOUNDARY**: mirror recovery is gated
        // strictly on the live header failing to PARSE. We do NOT
        // recover from the mirror when the live header parses fine
        // but the unlock step rejects the credential. The mirror
        // holds the PREVIOUS-good keyslot table, which still
        // contains slots the user may have REVOKED in the current
        // live header. Falling back on unlock-failure would let a
        // revoked credential succeed against the previous-good
        // mirror, silently undoing every revocation the user has
        // performed. The reviewer flagged this as a one-line
        // auth-bypass; this gating is the fix.
        //
        // User-visible trade-off: the v0.2.0 "no keyslot accepted"
        // scenario where keyslot AEAD bytes get partially overwritten
        // by a crashed write is auto-recovered only when the
        // corruption surfaces as a structural parse failure
        // (e.g. a slot whose kind byte is garbage gets rejected by
        // Keyslot::from_bytes, which propagates as a Header parse
        // failure). For the narrow case where keyslot bytes are
        // corrupted but Header::from_bytes still passes, the user
        // runs `luksbox header-restore <vault> <vault>.lbx.header-bak
        // --no-verify` manually. Manual is correct: it makes the
        // implicit "I accept whatever credentials the mirror has"
        // choice explicit and auditable, instead of papering over
        // a revocation silently.
        match Self::load_locked_header(path, header_path) {
            Ok((file, storage, live_bytes, live_header)) => {
                // Live header parsed cleanly. Surface unlock outcome
                // directly. NO mirror fallback here -- that would be
                // the revoke-bypass.
                let mvk = try_unlock_and_verify(&live_header, &live_bytes)?;
                Ok((file, storage, live_bytes, live_header, mvk, false))
            }
            Err(live_parse_err) => {
                // Live header is structurally broken (the crashed-
                // write signature). Open + lock the vault file fresh
                // so we can return a useful handle, then try the
                // mirror.
                let (file, storage) = open_lock_no_header(path, header_path)?;
                let mirror_path = header_mirror_path_for(path, &storage);
                match try_unlock_via_mirror(&mirror_path, &mut try_unlock_and_verify) {
                    Some(Ok((m_bytes, m_header, mvk))) => {
                        eprintln!(
                            "luksbox: live header failed to parse; \
                             recovered from sidecar mirror at {}",
                            mirror_path.display()
                        );
                        Ok((file, storage, m_bytes, m_header, mvk, true))
                    }
                    _ => Err(live_parse_err),
                }
            }
        }
    }

    /// Read and decrypt the metadata blob. Returned plaintext is
    /// `Zeroizing`, wiped from memory when the caller drops it.
    pub fn read_metadata(&mut self) -> Result<zeroize::Zeroizing<Vec<u8>>, Error> {
        let region_size = self.header.metadata_size as usize;
        let mut region = vec![0u8; region_size];
        self.file
            .seek(SeekFrom::Start(self.header.metadata_offset))?;
        self.file.read_exact(&mut region)?;
        match metadata::read_metadata(
            self.header.cipher_suite,
            &self.mvk,
            &self.header.header_salt,
            &region,
        ) {
            Ok(pt) => Ok(pt),
            Err(live_err) => {
                // Live region failed to AEAD-verify or parse. Try the
                // sidecar mirror at `<vault>.lbx.meta-bak`. The mirror
                // is AEAD-bound to the same MVK and header_salt, so a
                // forged or attacker-substituted mirror fails the same
                // way live did and we surface the live error.
                let mirror_path = self.metadata_mirror_path();
                if !mirror_path.exists() {
                    return Err(live_err);
                }
                // Stat-first bounded read: refuse anything that isn't
                // exactly the expected region size. Defends against an
                // attacker-planted symlink at the mirror path pointing
                // at /dev/zero or a multi-GB file. We never allocate
                // more than `region_size` bytes regardless of what's
                // at the mirror path.
                let mirror_stat = match std::fs::metadata(&mirror_path) {
                    Ok(s) => s,
                    Err(_) => return Err(live_err),
                };
                if mirror_stat.len() != region_size as u64 {
                    return Err(live_err);
                }
                let mut mirror_bytes = vec![0u8; region_size];
                match std::fs::File::open(&mirror_path)
                    .and_then(|mut f| f.read_exact(&mut mirror_bytes))
                {
                    Ok(()) => {}
                    Err(_) => return Err(live_err),
                }
                match metadata::read_metadata(
                    self.header.cipher_suite,
                    &self.mvk,
                    &self.header.header_salt,
                    &mirror_bytes,
                ) {
                    Ok(pt) => {
                        eprintln!(
                            "luksbox: live metadata failed to AEAD-verify; \
                             recovered from sidecar mirror at {}",
                            mirror_path.display()
                        );
                        // Mark for re-establishment on next flush so
                        // we don't keep relying on the mirror.
                        self.metadata_recovered_from_mirror = true;
                        Ok(pt)
                    }
                    Err(_mirror_err) => Err(live_err),
                }
            }
        }
    }

    /// Whether the most recent `read_metadata` fell back to the
    /// sidecar mirror. `Vfs::flush` reads this to know whether to force
    /// a metadata rewrite even when the tree is otherwise clean.
    pub fn metadata_was_recovered_from_mirror(&self) -> bool {
        self.metadata_recovered_from_mirror
    }

    /// Clear the metadata-recovered flag. Called by `Vfs::flush` after
    /// it successfully re-establishes the live region so subsequent
    /// clean flushes take the fast path.
    pub fn clear_metadata_recovered_flag(&mut self) {
        self.metadata_recovered_from_mirror = false;
    }

    /// Mark the header dirty so the next `persist_header` (e.g. via
    /// `Drop` or an explicit call) writes the in-memory header back to
    /// disk. Used by `Vfs::flush` to commit the v0.2.1 LUKSBOX1 ->
    /// LUKSBOX2 auto-upgrade.
    pub fn mark_header_dirty(&mut self) {
        self.header_dirty = true;
    }

    /// Encrypt and write the metadata blob.
    ///
    /// v0.2.1 crash-safety protocol: before overwriting the live region,
    /// rotate a previous-good copy into the `<vault>.lbx.meta-bak`
    /// sidecar via temp+rename. On the first call for a v2 vault this
    /// also sets `FLAG_HAS_METADATA_MIRROR` so the next `persist_header`
    /// records the mirror's presence on disk. A crash mid-write to the
    /// live region leaves the previously-good bytes intact in the
    /// mirror, which `read_metadata`'s recovery path will use on next
    /// open.
    ///
    /// Skipped for v1 vaults (LUKSBOX1 magic), which preserve the
    /// v0.2.0 in-place rewrite behavior until the auto-upgrade trigger
    /// in `Vfs::flush` bumps them to v2.
    pub fn write_metadata(&mut self, plaintext: &[u8]) -> Result<(), Error> {
        #[cfg(feature = "test-injection")]
        record_flush_op(FlushOp::WriteMetadata);
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
        // v2 vaults: **intended-state mirror protocol**. Commit the
        // mirror to the NEW bytes BEFORE overwriting live. This is
        // the load-bearing security property of v0.2.1+:
        //
        //   - The mirror NEVER holds bytes that the user does not
        //     currently want as the authoritative state. It is not a
        //     "previous-good" snapshot; it is a "what live should
        //     become" buffer.
        //   - Consequence: a revoked credential cannot be resurrected
        //     by forcing the recovery path. The mirror reflects the
        //     post-revoke keyslot table, same as live.
        //   - Crash mid-mirror-commit: atomic_secure_write uses
        //     temp+rename, so the mirror is either old-committed or
        //     new-committed; never partial. Live is untouched.
        //     Reopen reads live (still old, valid). Lost: the
        //     in-progress write's content (which never made it to
        //     either copy). No bypass.
        //   - Crash mid-live-overwrite (after mirror commit): live
        //     partial, mirror = new bytes. Recovery: mirror unlocks
        //     under the new keyslot table; revoked credentials stay
        //     revoked.
        //
        // The earlier "rotate-before-overwrite" design (kept a
        // previous-good copy) was reviewed and found to permit an
        // auth-bypass: an attacker who corrupted the live header
        // could force the recovery path and the mirror's stale
        // keyslot table would accept a previously-revoked
        // credential. Regression-tested by
        // `v2_corrupted_live_after_revoke_does_not_unlock_via_mirror`.
        if self.is_v2_format() {
            self.write_metadata_mirror(&region)?;
        }
        // Test-only crash injection at the exact fault window the
        // v0.2.2 durability fence closes: mirror is durably committed
        // (above) but the live region overwrite + `sync_all()` below
        // haven't run yet. SimFile-backed tests use this to simulate
        // power loss here and verify the fence saved chunk-list-block
        // writes by fsync'ing the `.lbx` file before this call (in
        // `Vfs::flush::container.sync_data_area()`).
        if crash_after_mirror_for_test() {
            return Err(Error::Io(std::io::Error::other(
                "crash_after_mirror_for_test: simulated crash after mirror commit",
            )));
        }
        self.file
            .seek(SeekFrom::Start(self.header.metadata_offset))?;
        self.file.write_all(&region)?;
        self.file.sync_all()?;
        sync_parent_dir(&self.path)?;
        Ok(())
    }

    /// True iff the in-memory header is v0.2.1+ format (LUKSBOX2 magic)
    /// AND the container is NOT a deniable vault. Deniable vaults
    /// explicitly opt out of the sidecar-mirror protocol because:
    ///
    ///   - **Entropy invariant**: deniability targets the property
    ///     that the on-disk artefact set has Shannon entropy
    ///     indistinguishable from uniform random (each byte close to
    ///     8 bits, in practice >= 7.99 bits per byte across the
    ///     vault file). The deniable header (DENIABLE_HEADER_SIZE =
    ///     36864 B) is constructed so its bytes pass this test
    ///     (verified by `dieharder` / NIST STS in the test suite).
    ///     A visible `<vault>.lbx.{header,meta}-bak` sidecar at a
    ///     predictable name and length next to the vault drops
    ///     observed entropy of the artefact set well below that
    ///     threshold (predictable filename, predictable 8 KiB /
    ///     metadata_size length, predictable existence pattern
    ///     after every flush). An observer counting sidecar files
    ///     in a directory immediately identifies the vault as a
    ///     LUKSbox deniable container -- defeating the property
    ///     the deniable header pays a 36 KiB cost to establish.
    ///
    ///   - The deniable header format already has internal
    ///     redundancy. The 36 KiB header (DENIABLE_HEADER_SIZE) carries
    ///     each AEAD-wrapped slot at a deterministic offset; a partial
    ///     overwrite that destroys some slot bytes is detectable
    ///     and rejectable, and the persist path writes the cached
    ///     36 KiB buffer wholesale rather than field-by-field.
    ///
    ///   - The crash-safety class the mirror protocol defends against
    ///     (in-place overwrite of a critical region) is less acute
    ///     for deniable vaults because the inner-header offsets are
    ///     fixed and the persist is a single contiguous write.
    ///
    /// v1 (LUKSBOX1) vaults preserve the v0.2.0 in-place rewrite
    /// behavior to avoid touching disk in any new way until the
    /// auto-upgrade trigger fires in `Vfs::flush`.
    fn is_v2_format(&self) -> bool {
        self.header.version_major == luksbox_core::VERSION_MAJOR_V2 && self.deniable.is_none()
    }

    /// Write the metadata mirror to the **intended new bytes** (NOT
    /// the previous-good ones) via temp+rename, fsync parent dir. On
    /// first call also marks the in-memory header flag so the next
    /// `persist_header` records the mirror's presence on disk.
    ///
    /// Caller commits this BEFORE overwriting live. If a crash
    /// happens after this returns but before live is fully overwritten,
    /// the mirror is the recovery source and decrypts to the intended
    /// state -- including any in-progress credential revocations.
    fn write_metadata_mirror(&mut self, new_region_bytes: &[u8]) -> Result<(), Error> {
        let mirror_path = self.metadata_mirror_path();
        // atomic_secure_write: 0600 temp neighbour, fsync, rename,
        // fsync parent. If a stale `.tmp.<hex>` is left from a prior
        // crashed write it will be cleaned up by the helper.
        atomic_secure_write(&mirror_path, new_region_bytes)?;
        if !self.header.has_metadata_mirror() {
            self.header.flags |= FLAG_HAS_METADATA_MIRROR;
            self.header_dirty = true;
        }
        Ok(())
    }

    /// Conventional path of the metadata mirror sidecar.
    fn metadata_mirror_path(&self) -> PathBuf {
        append_extension(&self.path, "meta-bak")
    }

    /// Conventional path of the header mirror sidecar. For inline-header
    /// vaults this sits next to the .lbx file. For detached-header
    /// vaults it sits next to the sidecar.
    fn header_mirror_path(&self) -> PathBuf {
        let base = self.header_storage_path().to_path_buf();
        append_extension(&base, "header-bak")
    }

    pub fn enroll_passphrase(
        &mut self,
        passphrase: &[u8],
        kdf_params: Argon2idParams,
    ) -> Result<usize, Error> {
        self.guard_no_deniable_slot_mutation()?;
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
        self.guard_no_deniable_slot_mutation()?;
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
        self.guard_no_deniable_slot_mutation()?;
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
        self.guard_no_deniable_slot_mutation()?;
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
        self.guard_no_deniable_slot_mutation()?;
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
        self.guard_no_deniable_slot_mutation()?;
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
        self.guard_no_deniable_slot_mutation()?;
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

    /// Append a passphrase + ML-KEM-768 hybrid keyslot. Mirrors the
    /// CREATE-time `create_with_hybrid_pq_passphrase` but operates on
    /// an already-open Container. The caller has already (a) generated
    /// a fresh ML-KEM-768 keypair, (b) called `encapsulate` against it
    /// to obtain `pq_shared`, and is responsible for (c) writing the
    /// matching ciphertext + pubkey into the `.hybrid` sidecar and the
    /// seed into the user's `.kyber` file. This function does NOT
    /// touch either of those files; the GUI / CLI wrapper performs
    /// the atomic-enroll dance (install-in-memory, write sidecars,
    /// persist header, roll back on any failure) to keep the on-disk
    /// vault consistent.
    pub fn enroll_hybrid_pq_passphrase(
        &mut self,
        passphrase: &[u8],
        pq_shared: &[u8; 32],
        kdf_params: Argon2idParams,
    ) -> Result<usize, Error> {
        self.guard_no_deniable_slot_mutation()?;
        let idx = self.header.first_free_slot()?;
        let slot = Keyslot::new_hybrid_pq_passphrase(
            self.header.cipher_suite,
            &self.mvk,
            passphrase,
            pq_shared,
            kdf_params,
            &self.header.header_salt,
        )?;
        self.header.install_slot(idx, slot)?;
        self.header_dirty = true;
        Ok(idx)
    }

    /// ML-KEM-1024 variant of `enroll_hybrid_pq_passphrase`. Same
    /// shape; only the slot's kind byte and the sidecar entry's level
    /// byte differ on disk.
    pub fn enroll_hybrid_pq_1024_passphrase(
        &mut self,
        passphrase: &[u8],
        pq_shared: &[u8; 32],
        kdf_params: Argon2idParams,
    ) -> Result<usize, Error> {
        self.guard_no_deniable_slot_mutation()?;
        let idx = self.header.first_free_slot()?;
        let slot = Keyslot::new_hybrid_pq_1024_passphrase(
            self.header.cipher_suite,
            &self.mvk,
            passphrase,
            pq_shared,
            kdf_params,
            &self.header.header_salt,
        )?;
        self.header.install_slot(idx, slot)?;
        self.header_dirty = true;
        Ok(idx)
    }

    /// Append a FIDO2 + ML-KEM-768 hybrid keyslot. Caller has already
    /// (a) enrolled the FIDO2 credential to obtain `cred_id` +
    /// `hmac_secret`, (b) generated an ML-KEM-768 keypair, (c) called
    /// `encapsulate` to obtain `pq_shared`. The optional `passphrase`
    /// folds into the KEK alongside the hmac_secret + pq_shared (it
    /// is independent of the FIDO2 PIN; it protects the slot if the
    /// FIDO2 token is stolen but the seed file is leaked). Pass
    /// `None` for a pure FIDO2 + ML-KEM slot.
    pub fn enroll_hybrid_pq_fido2(
        &mut self,
        passphrase: Option<&[u8]>,
        hmac_secret: &[u8; 32],
        pq_shared: &[u8; 32],
        cred_id: &[u8],
        hmac_salt: [u8; 32],
        kdf_params: Argon2idParams,
    ) -> Result<usize, Error> {
        self.guard_no_deniable_slot_mutation()?;
        let idx = self.header.first_free_slot()?;
        let slot = Keyslot::new_hybrid_pq_fido2(
            self.header.cipher_suite,
            &self.mvk,
            passphrase,
            hmac_secret,
            pq_shared,
            cred_id,
            hmac_salt,
            kdf_params,
            &self.header.header_salt,
        )?;
        self.header.install_slot(idx, slot)?;
        self.header_dirty = true;
        Ok(idx)
    }

    /// ML-KEM-1024 variant of `enroll_hybrid_pq_fido2`.
    pub fn enroll_hybrid_pq_1024_fido2(
        &mut self,
        passphrase: Option<&[u8]>,
        hmac_secret: &[u8; 32],
        pq_shared: &[u8; 32],
        cred_id: &[u8],
        hmac_salt: [u8; 32],
        kdf_params: Argon2idParams,
    ) -> Result<usize, Error> {
        self.guard_no_deniable_slot_mutation()?;
        let idx = self.header.first_free_slot()?;
        let slot = Keyslot::new_hybrid_pq_1024_fido2(
            self.header.cipher_suite,
            &self.mvk,
            passphrase,
            hmac_secret,
            pq_shared,
            cred_id,
            hmac_salt,
            kdf_params,
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
        self.guard_no_deniable_slot_mutation()?;
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
        self.guard_no_deniable_slot_mutation()?;
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
        self.guard_no_deniable_slot_mutation()?;
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
        self.guard_no_deniable_slot_mutation()?;
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
    /// For deniable-mode containers writes the cached 8 KiB buffer instead
    /// of re-serialising `self.header`, because the wrapped-MVK ciphertext
    /// lives inside the opaque slot bytes (not in `self.header.keyslots`).
    ///
    /// Round 13 fix R13-04: durability + atomicity.
    ///   - Inline (and deniable): we use `sync_all()` instead of `flush()`
    ///     so the kernel commits the rewritten header bytes to the disk's
    ///     stable storage before we return. Without this, a power loss
    ///     between `flush()` and the next vault open could leave the
    ///     keyslot table half-updated (e.g. a revoke whose ciphertext is
    ///     gone from page cache but whose on-disk bytes still contain the
    ///     old wrap), reintroducing the revoked credential.
    ///   - Detached: we go through `atomic_secure_write`, which writes a
    ///     `.tmp.<16hex>` neighbour at mode 0600, fsyncs it, atomically
    ///     renames over the sidecar, then fsyncs the parent directory.
    ///     This replaces the prior in-place rewrite path, which could
    ///     leave the sidecar half-overwritten on crash.
    pub fn persist_header(&mut self) -> Result<(), Error> {
        if !self.header_dirty {
            return Ok(());
        }
        if let Some(deniable) = &self.deniable {
            // Deniable-mode persist: write the cached 36 KiB header
            // buffer wholesale. Detached headers are not yet
            // supported in deniable mode (constructors reject
            // header_path), so we always write to offset 0 of
            // `self.file`. Deniable mode opts out of the v2 sidecar
            // mirror protocol entirely: a visible mirror file would
            // defeat the deniability property that the vault contains
            // no observable LUKSbox-shaped artifacts. The deniable
            // header itself is duplicated at multiple offsets within
            // the 36 KiB region for its own redundancy.
            self.file.seek(SeekFrom::Start(0))?;
            self.file.write_all(&deniable.bytes[..])?;
            self.file.sync_all()?;
            self.header_dirty = false;
            return Ok(());
        }
        // v2 vaults: **intended-state mirror protocol**. Commit the
        // mirror to the NEW header bytes BEFORE we overwrite live.
        // See the long-form comment in `write_metadata` for the
        // rationale; the short version: a "previous-good" mirror is
        // an auth-bypass surface for revoked credentials, so the
        // mirror MUST reflect the post-write keyslot table.
        //
        // Ordering subtlety: we need the FLAG_HAS_HEADER_MIRROR bit
        // set in the serialized bytes BEFORE we write them to the
        // mirror, otherwise the mirror's header would advertise "no
        // mirror exists" which is the opposite of reality. Flip the
        // flag in-memory first, then serialize, then write mirror,
        // then overwrite live.
        if self.is_v2_format() && !self.header.has_header_mirror() {
            self.header.flags |= FLAG_HAS_HEADER_MIRROR;
        }
        let bytes = self.header.to_bytes(&self.mvk);
        if self.is_v2_format() {
            self.write_header_mirror(&bytes)?;
        }
        match &mut self.header_storage {
            HeaderStorage::Inline => {
                self.file.seek(SeekFrom::Start(0))?;
                self.file.write_all(&bytes)?;
                self.file.sync_all()?;
                sync_parent_dir(&self.path)?;
            }
            HeaderStorage::Detached(_, hp) => {
                // Replace the sidecar atomically. The existing
                // `HeaderStorage::Detached` handle is held only so we
                // keep an OS-level lock on the path while the
                // container is live; the actual write goes through
                // the temp+fsync+rename helper so a crash mid-write
                // never leaves the sidecar truncated.
                let hp = hp.clone();
                atomic_secure_write(&hp, &bytes)?;
                // Re-open the handle so it points at the new inode
                // (the old handle still refers to the unlinked
                // pre-rename inode on POSIX). Without this the
                // existing lock is on the wrong file going forward.
                let new_hf = OpenOptions::new().read(true).write(true).open(&hp)?;
                // Re-lock the new inode before swapping in the handle.
                // `atomic_secure_write` renamed a fresh file over the
                // sidecar, so the old handle's advisory lock sits on the
                // now-unlinked pre-rename inode; without re-locking here,
                // the sidecar lock invariant is silently lost for the
                // rest of the container's life. The old handle (and its
                // stale lock) is released when it is overwritten just
                // below. `lock_handles` honors `LUKSBOX_NO_LOCK`.
                lock_handles(&[(&new_hf, hp.as_path())])?;
                if let HeaderStorage::Detached(hf, _) = &mut self.header_storage {
                    *hf = new_hf;
                }
            }
        }
        self.header_dirty = false;
        Ok(())
    }

    /// Write the header mirror to the **intended new bytes** via
    /// temp+rename. Same intended-state protocol as the metadata
    /// mirror: the mirror reflects what live SHOULD become, not what
    /// live WAS. Prevents the revoke-then-corrupt-then-recover
    /// auth-bypass class.
    ///
    /// Caller commits this BEFORE overwriting live. If a crash
    /// happens after this returns but before live is fully
    /// overwritten, the mirror is the recovery source and decrypts
    /// with the post-write keyslot table.
    fn write_header_mirror(&mut self, new_bytes: &[u8; HEADER_SIZE]) -> Result<(), Error> {
        let mirror_path = self.header_mirror_path();
        atomic_secure_write(&mirror_path, new_bytes)?;
        Ok(())
    }

    /// Round 13 fix R13-02: install a 8 KiB header backup safely.
    ///
    /// The CLI's `luksbox header restore` previously opened the vault
    /// path with `OpenOptions::open(path)` after verifying the new
    /// header's HMAC against the currently-open container. That second
    /// open re-traversed the path with no `O_NOFOLLOW` and no inode
    /// check, so an attacker who could race the path between the verify
    /// and the write was able to redirect the first 8 KiB of the
    /// rewrite into another file the caller had write access to.
    ///
    /// This method reuses the container's already-verified `self.file`
    /// handle (opened with `O_NOFOLLOW` + canonical-path-bound + inode
    /// check at `open_rw_checked`) for the inline path, and routes the
    /// detached path through `atomic_secure_write` so the sidecar swap
    /// happens via temp+fsync+rename rather than in-place truncation.
    ///
    /// Caller is responsible for having ALREADY verified the backup
    /// bytes against the vault's current MVK (or having opted out via
    /// `--no-verify`); this method is byte-for-byte and does not
    /// re-parse. After it returns, the in-memory `self.header` is
    /// stale relative to disk; the caller should drop the container
    /// rather than continue using it.
    pub fn restore_header_bytes(&mut self, bytes: &[u8; HEADER_SIZE]) -> Result<(), Error> {
        match &mut self.header_storage {
            HeaderStorage::Inline => {
                self.file.seek(SeekFrom::Start(0))?;
                self.file.write_all(bytes)?;
                self.file.sync_all()?;
            }
            HeaderStorage::Detached(_, hp) => {
                let hp = hp.clone();
                atomic_secure_write(&hp, bytes)?;
                let new_hf = OpenOptions::new().read(true).write(true).open(&hp)?;
                // Re-lock the new inode before swapping in the handle.
                // `atomic_secure_write` renamed a fresh file over the
                // sidecar, so the old handle's advisory lock sits on the
                // now-unlinked pre-rename inode; without re-locking here,
                // the sidecar lock invariant is silently lost for the
                // rest of the container's life. The old handle (and its
                // stale lock) is released when it is overwritten just
                // below. `lock_handles` honors `LUKSBOX_NO_LOCK`.
                lock_handles(&[(&new_hf, hp.as_path())])?;
                if let HeaderStorage::Detached(hf, _) = &mut self.header_storage {
                    *hf = new_hf;
                }
            }
        }
        // The in-memory header is now out of sync with disk. Mark it
        // clean so the `Drop` impl's `persist_header()` doesn't write
        // the stale in-memory copy back on top of the restored bytes.
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

    /// Test-only: replace the backing `.lbx` file handle with a
    /// different `LbxFile` implementation (typically a `SimFile` for
    /// crash-impact tests). The replacement file MUST hold byte-
    /// identical content to the file being replaced at every offset
    /// the Container will read from -- the easiest way is to read
    /// the original file into a Vec before swapping, then pass
    /// `Box::new(SimFile::from_bytes(bytes))`. Returns the original
    /// file so the caller can drop it (or stash it for a later
    /// re-swap).
    ///
    /// Gated behind the `test-injection` cargo feature; release builds
    /// of downstream crates do NOT compile this method in, so the
    /// surface is unreachable from a production binary.
    #[cfg(feature = "test-injection")]
    pub fn swap_lbx_file_for_test(&mut self, new_file: Box<dyn LbxFile>) -> Box<dyn LbxFile> {
        std::mem::replace(&mut self.file, new_file)
    }

    /// Fsync the .lbx file so any writes queued via `write_at`
    /// (chunk data, chunk-list blocks) are durable on disk. Used as
    /// a fence by the VFS flush path: chunk-list block writes MUST
    /// be durable BEFORE the sidecar mirror (`.lbx.meta-bak`) commits
    /// new chunks_external pointers. Without that fence a crash
    /// between mirror-commit and the live-region fsync can leave
    /// the mirror durable while chunk-list-block writes are still
    /// in the page cache, producing a vault whose mirror says
    /// "chunk-list block at slot X under generation G" while slot X
    /// on disk still holds the pre-flush bytes. The reader's AEAD
    /// then fails on every such block. Affects v0.2.1 vaults.
    pub fn sync_data_area(&mut self) -> Result<(), Error> {
        #[cfg(feature = "test-injection")]
        record_flush_op(FlushOp::SyncDataArea);
        self.file.sync_all().map_err(Into::into)
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
                // Deniable vaults use the AEAD-encrypted anchor
                // format (every byte indistinguishable from random
                // output) instead of the standard plaintext-magic
                // anchor. Selection is automatic based on
                // `self.is_deniable()`.
                let a = if self.is_deniable() {
                    let den = self.deniable.as_ref().expect("is_deniable() implies Some");
                    crate::anchor::deniable_read_and_verify(
                        &p,
                        &self.mvk,
                        &den.salt,
                        self.header.cipher_suite,
                    )?
                } else {
                    crate::anchor::read_and_verify(&p, &self.mvk, &self.header.header_salt)?
                };
                self.anchor_path = Some(p);
                Ok(Some(a.generation))
            }
        }
    }

    /// Initialize an anchor file at the given path with the supplied
    /// generation. Used right after `create_*` to bootstrap a vault
    /// with anchor protection from the start.
    pub fn init_anchor(&mut self, anchor_path: PathBuf, generation: u64) -> Result<(), Error> {
        // Use the no-clobber variants: `init_anchor` is only called at
        // vault-creation time on a path the user just supplied.
        // `write_initial` / `deniable_write_initial` commit via POSIX
        // `link(2)` / Windows `MoveFileExW(0)`, which refuse to follow
        // a symlink an attacker may have planted between the CLI-level
        // `path.exists()` pre-check and this call. Subsequent updates
        // (`write_anchor`, called on every vfs flush) use the rename-
        // replace path, which is safe because the path was validated
        // at unlock time and `self.anchor_path` is bound to it.
        if self.is_deniable() {
            let den = self.deniable.as_ref().expect("is_deniable() implies Some");
            crate::anchor::deniable_write_initial(
                &anchor_path,
                generation,
                &self.mvk,
                &den.salt,
                self.header.cipher_suite,
            )?;
        } else {
            crate::anchor::write_initial(
                &anchor_path,
                generation,
                &self.mvk,
                &self.header.header_salt,
            )?;
        }
        self.anchor_path = Some(anchor_path);
        Ok(())
    }

    /// Update the anchor file (if one is set) to the given generation.
    /// Called by `Vfs::flush` after every metadata-blob write.
    pub fn write_anchor(&self, generation: u64) -> Result<(), Error> {
        if let Some(p) = &self.anchor_path {
            if self.is_deniable() {
                let den = self.deniable.as_ref().expect("is_deniable() implies Some");
                crate::anchor::deniable_write(
                    p,
                    generation,
                    &self.mvk,
                    &den.salt,
                    self.header.cipher_suite,
                )?;
            } else {
                crate::anchor::write(p, generation, &self.mvk, &self.header.header_salt)?;
            }
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

        // Round 12 fix R12-10: create the rotation tmp atomically with
        // `O_CREAT|O_EXCL|O_NOFOLLOW` at mode 0600 BEFORE copying
        // content into it. The previous flow did `std::fs::copy` (which
        // preserves source mode, briefly exposing legacy 0644 to other
        // users) and then `set_permissions(0600)` non-atomically, and
        // would happily follow a pre-existing `<vault>.rotating`
        // symlink. The new sequence is:
        //   1. open(tmp, O_CREAT|O_EXCL|O_NOFOLLOW, 0600)  -> tmp_file
        //   2. read source -> write into tmp_file
        //   3. (existing) fsync + rename on commit
        //
        // Windows: there is no portable `O_NOFOLLOW`/`O_EXCL` combo for
        // refusing reparse points. Keep the previous `std::fs::copy`
        // path (tracked under R12-15) and rely on the parent directory
        // ACL for protection.
        #[cfg(unix)]
        let mut tmp_file: File = {
            use std::os::unix::fs::OpenOptionsExt as _;
            OpenOptions::new()
                .read(true)
                .write(true)
                .create_new(true)
                .mode(0o600)
                .custom_flags(libc::O_NOFOLLOW)
                .open(&tmp)?
        };
        #[cfg(unix)]
        {
            use std::io::{Read, Seek, SeekFrom, Write};
            // Reset the source's read position before slurping.
            self.file.seek(SeekFrom::Start(0))?;
            // 1 MiB chunks: low memory pressure, fits typical L2 cache.
            let mut buf = vec![0u8; 1 << 20];
            loop {
                let n = self.file.read(&mut buf)?;
                if n == 0 {
                    break;
                }
                tmp_file.write_all(&buf[..n])?;
            }
            tmp_file.flush()?;
        }
        // Windows fallback: legacy copy + chmod-equivalent.
        #[cfg(not(unix))]
        {
            std::fs::copy(&original, &tmp)?;
        }
        #[cfg(not(unix))]
        let tmp_file = OpenOptions::new().read(true).write(true).open(&tmp)?;
        self.file = Box::new(tmp_file);
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

        // **CRITICAL**: drop the OLD sidecar mirrors that were
        // written under the PRE-rotation MVK + keyslot envelopes.
        // If we left them, a later crash mid-write on the post-
        // rotation live region would let mirror recovery present
        // a header whose keyslots still unwrap the OLD MVK -- which
        // is the rolled-away credential the user just removed.
        // Mirror cleanup at the committed path; the v2 write path
        // will write fresh mirrors on the next live overwrite.
        // Best-effort: the rotation itself succeeded; failure to
        // delete a stale mirror is logged but not propagated, since
        // the in-place-renamed live region is still authoritative.
        let stale_meta_mirror = append_extension(&state.committed_data_path, "meta-bak");
        let stale_header_mirror = match &self.header_storage {
            HeaderStorage::Inline => append_extension(&state.committed_data_path, "header-bak"),
            HeaderStorage::Detached(_, hp) => append_extension(hp, "header-bak"),
        };
        for stale in [&stale_meta_mirror, &stale_header_mirror] {
            if stale.exists()
                && let Err(e) = std::fs::remove_file(stale)
            {
                eprintln!(
                    "luksbox: warn: failed to remove stale post-rotation mirror at {}: {}",
                    stale.display(),
                    e
                );
            }
        }
        // Also clear the FLAG_HAS_*_MIRROR bits in the in-memory
        // header so the next persist_header / write_metadata
        // treat this as a "first-time mirror init" and re-establish
        // mirrors with the NEW-MVK-encrypted bytes.
        self.header.flags &= !(FLAG_HAS_HEADER_MIRROR | FLAG_HAS_METADATA_MIRROR);
        self.header_dirty = true;

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
        self.file = Box::new(original_file);
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

/// Conventional path of the header mirror sidecar for the given vault
/// path + storage shape. Inline vaults put it next to the .lbx file;
/// detached vaults put it next to the header sidecar (so the mirror
/// rides along with whichever file is the source of truth for the
/// header bytes).
fn header_mirror_path_for(vault: &Path, storage: &HeaderStorage) -> PathBuf {
    let base = match storage {
        HeaderStorage::Inline => vault.to_path_buf(),
        HeaderStorage::Detached(_, hp) => hp.clone(),
    };
    append_extension(&base, "header-bak")
}

/// Try to read the header mirror at `mirror_path` and run the caller's
/// unlock+verify closure against it. Returns:
///   - `None` if the mirror file doesn't exist (no recovery possible).
///   - `Some(Err(_))` if the mirror exists but is invalid or fails the
///     unlock/verify step (forged, stale-with-wrong-MVK, corrupted).
///   - `Some(Ok((bytes, header, mvk)))` on successful recovery.
///
/// On any I/O error reading the mirror (permission, etc.), returns
/// `Some(Err(_))` so the caller can decide whether to fall back to
/// the live error.
fn try_unlock_via_mirror<F>(
    mirror_path: &Path,
    try_unlock_and_verify: &mut F,
) -> Option<Result<([u8; HEADER_SIZE], Header, MasterVolumeKey), Error>>
where
    F: FnMut(&Header, &[u8; HEADER_SIZE]) -> Result<MasterVolumeKey, Error>,
{
    if !mirror_path.exists() {
        return None;
    }
    // Defense against attacker who can write to the vault directory:
    // a symlink at `<vault>.lbx.header-bak` to `/dev/zero` (Linux)
    // or a multi-GB attacker-staged file would OOM us on
    // `fs::read`. Stat first and refuse anything that isn't exactly
    // HEADER_SIZE so we never allocate more than 8 KiB regardless
    // of what's at the path. `metadata()` follows symlinks; we want
    // that here so a symlink to /dev/zero (which reports size 0)
    // would also be rejected by the != HEADER_SIZE branch.
    let stat = match std::fs::metadata(mirror_path) {
        Ok(s) => s,
        Err(e) => return Some(Err(Error::Io(e))),
    };
    if stat.len() != HEADER_SIZE as u64 {
        return Some(Err(Error::Crypto(luksbox_core::Error::HeaderAuthFailed)));
    }
    // Bounded read: open the file and pull exactly HEADER_SIZE
    // bytes. `read_exact` against an 8 KiB buffer caps the
    // allocation. Use OpenOptions then read_exact rather than
    // fs::read so we don't touch attacker-controlled length fields.
    let mut buf = [0u8; HEADER_SIZE];
    {
        let mut f = match std::fs::File::open(mirror_path) {
            Ok(f) => f,
            Err(e) => return Some(Err(Error::Io(e))),
        };
        if let Err(e) = f.read_exact(&mut buf) {
            return Some(Err(Error::Io(e)));
        }
    }
    let header = match Header::from_bytes(&buf) {
        Ok(h) => h,
        Err(e) => return Some(Err(Error::Crypto(e))),
    };
    let mvk = match try_unlock_and_verify(&header, &buf) {
        Ok(m) => m,
        Err(e) => return Some(Err(e)),
    };
    Some(Ok((buf, header, mvk)))
}

/// Open + lock the vault file and (optionally) the detached header
/// sidecar, but do NOT read or parse the header. Used by the recovery
/// path when the live header parse failed: we still need the file
/// handle for the rotate-back step, but we can't trust the live header
/// to even be there.
///
/// Errors propagate from the same `open_rw_checked` / `lock_handles`
/// paths as `load_locked_header`; this is the prefix of that function
/// up to (but not including) the live read.
fn open_lock_no_header(
    path: &Path,
    header_path: Option<&Path>,
) -> Result<(File, HeaderStorage), Error> {
    let (file, file_inode, canonical_path) = open_rw_checked(path, None)?;
    let (header_storage, header_inode, canonical_header) = match header_path {
        None => (HeaderStorage::Inline, None, None),
        Some(hp) => {
            let (hf, hf_inode, canon_hp) = open_rw_checked(hp, None)?;
            (
                HeaderStorage::Detached(hf, hp.to_path_buf()),
                Some(hf_inode),
                Some(canon_hp),
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
            unreachable!("Detached header storage requires a header_path")
        }
    }
    verify_path_inode(&canonical_path, file_inode)?;
    if let (Some(canon_hp), Some(expected)) = (canonical_header.as_ref(), header_inode) {
        verify_path_inode(canon_hp, expected)?;
    }
    Ok((file, header_storage))
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
                if let Ok(mvk) = slot.unlock_passphrase(suite, pw, &header.header_salt)
                    && found.is_none()
                {
                    found = Some(mvk);
                }
                // Don't break, keep iterating to maintain
                // constant time across the whole keyslot table.
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
                ) && found.is_none()
                {
                    found = Some(mvk);
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
    fn tpm2_only_create_no_passphrase_slot_round_trip() {
        // create_with_tpm2 produces a single-slot vault: slot 0 is
        // TPM, no passphrase, no recovery. Round-trip: open via
        // UnlockMaterial::Tpm2 succeeds; opening with any passphrase
        // fails because there's no passphrase slot to match.
        use std::collections::HashMap;
        let dir = tempdir().unwrap();
        let path = dir.path().join("v.lbx");
        let kek = [0x42u8; 32];
        let fake_blob = vec![0x73u8; 256];

        let cont = Container::create_with_tpm2(
            &path,
            None,
            CipherSuite::Aes256GcmSiv,
            0,
            &kek,
            &fake_blob,
        )
        .unwrap();
        // Slot 0 must be TPM and only one slot must be occupied.
        assert_eq!(cont.header.keyslots[0].kind, SlotKind::Tpm2Sealed);
        for i in 1..cont.header.keyslots.len() {
            assert_eq!(cont.header.keyslots[i].kind, SlotKind::Empty);
        }
        drop(cont);

        // Round-trip open via TPM closure that returns the right KEK.
        let mut mock_tpm: HashMap<Vec<u8>, [u8; 32]> = HashMap::new();
        mock_tpm.insert(fake_blob.clone(), kek);
        let mut unseal = |b: &[u8]| -> Result<[u8; 32], String> {
            mock_tpm
                .get(b)
                .copied()
                .ok_or_else(|| "blob not found".to_string())
        };
        Container::open(
            &path,
            None,
            UnlockMaterial::Tpm2 {
                unseal: &mut unseal,
            },
        )
        .unwrap();

        // No passphrase slot exists: any passphrase must fail.
        let r = Container::open(&path, None, UnlockMaterial::Passphrase(b"anything"));
        assert!(matches!(r, Err(Error::UnlockFailed)));
    }

    #[test]
    fn tpm2_fido2_only_create_no_passphrase_slot() {
        // create_with_tpm2_fido2 must yield a single-slot vault: slot
        // 0 = Tpm2Fido2, no passphrase fallback. The full open round-
        // trip goes through enroll_tpm2_fido2's open path which needs
        // FIDO2 hardware; we just verify the shape here.
        let dir = tempdir().unwrap();
        let path = dir.path().join("v.lbx");
        let tpm_unsealed = [0xA1u8; 32];
        let hmac_secret = [0xB2u8; 32];
        let blob = vec![0xC3u8; 240];
        let cred_id = vec![0xD4u8; 64];
        let hmac_salt = [0xE5u8; 32];

        let cont = Container::create_with_tpm2_fido2(
            &path,
            None,
            CipherSuite::Aes256GcmSiv,
            0,
            &tpm_unsealed,
            &hmac_secret,
            &blob,
            &cred_id,
            hmac_salt,
        )
        .unwrap();
        assert_eq!(cont.header.keyslots[0].kind, SlotKind::Tpm2Fido2);
        for i in 1..cont.header.keyslots.len() {
            assert_eq!(cont.header.keyslots[i].kind, SlotKind::Empty);
        }
        drop(cont);
        let r = Container::open(&path, None, UnlockMaterial::Passphrase(b"anything"));
        assert!(matches!(r, Err(Error::UnlockFailed)));
    }

    #[test]
    fn hybrid_pq_tpm2_only_create_no_passphrase_slot() {
        // Same shape check for hybrid TPM + ML-KEM-768 single-slot.
        let dir = tempdir().unwrap();
        let path = dir.path().join("v.lbx");
        let kek = [0x11u8; 32];
        let pq_shared = [0x22u8; 32];
        let blob = vec![0x33u8; 240];

        let cont = Container::create_with_hybrid_pq_tpm2(
            &path,
            None,
            CipherSuite::Aes256GcmSiv,
            0,
            &kek,
            &pq_shared,
            &blob,
        )
        .unwrap();
        assert_eq!(cont.header.keyslots[0].kind, SlotKind::HybridPqKemTpm2);
        drop(cont);
        let r = Container::open(&path, None, UnlockMaterial::Passphrase(b"anything"));
        assert!(matches!(r, Err(Error::UnlockFailed)));
    }

    #[test]
    fn tpm2_pin_only_create_no_passphrase_slot_round_trip() {
        // Same round-trip as the plain tpm2 case, just verifies the
        // PIN-bound variant lands as Tpm2SealedPin (the chip would
        // refuse to unseal without the PIN; the mock closure just
        // returns the KEK so we're testing slot-kind plumbing only).
        let dir = tempdir().unwrap();
        let path = dir.path().join("v.lbx");
        let kek = [0xA1u8; 32];
        let fake_blob = vec![0x9Eu8; 280];

        let cont = Container::create_with_tpm2_pin(
            &path,
            None,
            CipherSuite::Aes256GcmSiv,
            0,
            &kek,
            &fake_blob,
        )
        .unwrap();
        assert_eq!(cont.header.keyslots[0].kind, SlotKind::Tpm2SealedPin);
        drop(cont);

        let r = Container::open(&path, None, UnlockMaterial::Passphrase(b"anything"));
        assert!(matches!(r, Err(Error::UnlockFailed)));
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

        let (a_handle, a_inode, a_canonical) = open_rw_checked(&a, None).unwrap();
        // Path `a` matches the handle's inode, must succeed.
        verify_path_inode(&a_canonical, a_inode).expect("identical path resolves to same inode");
        // Path `b` is a different file, must reject as substituted.
        let b_canonical = b.canonicalize().unwrap();
        let err = verify_path_inode(&b_canonical, a_inode).unwrap_err();
        assert!(
            matches!(err, Error::PathSubstituted { .. }),
            "expected PathSubstituted, got {err:?}"
        );
        drop(a_handle);
    }

    // ============================================================
    // Deniable mode Container-level tests
    // ============================================================

    fn cheap_argon2() -> Argon2idParams {
        Argon2idParams {
            m_cost_kib: 8,
            t_cost: 1,
            p_cost: 1,
        }
    }

    #[test]
    fn deniable_container_create_open_round_trip() {
        // Create a deniable container, drop it, reopen with the
        // same credentials, confirm the MVK comes back identical.
        // Validates that the Container's metadata write + the
        // deniable header write + the open path all agree on the
        // per-vault salt and cipher.
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("vault.lbx");
        let c = Container::create_with_passphrase_deniable(
            &path,
            None,
            CipherSuite::Aes256GcmSiv,
            cheap_argon2(),
            0,
            b"hunter2",
        )
        .unwrap();
        let mvk_before = c.mvk_clone();
        drop(c);

        let c = Container::open_with_passphrase_deniable(
            &path,
            None,
            b"hunter2",
            cheap_argon2(),
            CipherSuite::Aes256GcmSiv,
        )
        .unwrap();
        assert_eq!(c.mvk_clone().as_bytes(), mvk_before.as_bytes());
        assert!(c.is_deniable());
    }

    #[test]
    fn deniable_container_open_with_mvk_handoff_round_trip() {
        // Models the macOS GUI -> mount-helper handoff for deniable
        // vaults. The parent opens the vault via the credential, then
        // hands (MVK, salt, inner header, slot_idx) over a pipe; the
        // helper re-opens via open_with_mvk_deniable WITHOUT the
        // credential and must produce a Container with the same MVK
        // and the same observable deniable state. Anything less and
        // the FUSE event loop in the helper would mount a vault that
        // disagrees with the parent on layout / cipher.
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("vault.lbx");
        let c_parent = Container::create_with_passphrase_deniable(
            &path,
            None,
            CipherSuite::Aes256GcmSiv,
            cheap_argon2(),
            0,
            b"hunter2",
        )
        .unwrap();
        let mvk_before = c_parent.mvk_clone();
        let (salt, inner, slot_idx) = c_parent
            .deniable_handoff_state()
            .expect("deniable container must expose handoff state");
        // Drop the parent's Container so its flock is released; the
        // helper-side open will acquire its own.
        drop(c_parent);

        // Simulate the wire transit: serialize + parse inner header.
        let inner_wire = inner.serialise_for_handoff();
        let inner_parsed =
            crate::deniable_header::DeniableInnerHeader::parse_from_handoff(&inner_wire).unwrap();
        assert_eq!(inner, inner_parsed);

        let c_helper = Container::open_with_mvk_deniable(
            &path,
            None,
            mvk_before.clone(),
            salt,
            inner_parsed,
            slot_idx,
        )
        .unwrap();
        assert_eq!(c_helper.mvk_clone().as_bytes(), mvk_before.as_bytes());
        assert!(c_helper.is_deniable());
        assert_eq!(c_helper.deniable_unlocked_slot(), Some(slot_idx));
        // And the helper-side handoff state must match what the parent
        // exported, so a future re-handoff (e.g. unmount-then-remount)
        // sees the same image.
        assert_eq!(
            c_helper.deniable_handoff_state(),
            Some((salt, inner, slot_idx))
        );
    }

    #[test]
    fn deniable_open_with_mvk_refuses_salt_mismatch() {
        // Defense-in-depth: if the parent's cached salt has drifted
        // from what's on disk (e.g. a rotation happened in between),
        // mounting with the stale salt would silently bind to the
        // wrong vault image. The helper-side check refuses rather
        // than mount inconsistently.
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("vault.lbx");
        let c = Container::create_with_passphrase_deniable(
            &path,
            None,
            CipherSuite::Aes256GcmSiv,
            cheap_argon2(),
            0,
            b"hunter2",
        )
        .unwrap();
        let mvk = c.mvk_clone();
        let (_real_salt, inner, slot_idx) = c.deniable_handoff_state().unwrap();
        drop(c);

        let wrong_salt = [0xABu8; luksbox_core::deniable::DENIABLE_SALT_SIZE];
        let err = Container::open_with_mvk_deniable(&path, None, mvk, wrong_salt, inner, slot_idx)
            .err()
            .expect("must refuse wrong salt");
        assert!(matches!(err, Error::OpaqueUnlockFailed), "got {err:?}");
    }

    #[test]
    fn deniable_open_with_mvk_refuses_out_of_range_slot() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("vault.lbx");
        let c = Container::create_with_passphrase_deniable(
            &path,
            None,
            CipherSuite::Aes256GcmSiv,
            cheap_argon2(),
            0,
            b"hunter2",
        )
        .unwrap();
        let mvk = c.mvk_clone();
        let (salt, inner, _slot_idx) = c.deniable_handoff_state().unwrap();
        drop(c);

        let err = Container::open_with_mvk_deniable(
            &path, None, mvk, salt, inner, 999, // > DENIABLE_SLOT_COUNT
        )
        .err()
        .expect("must refuse out-of-range slot");
        assert!(matches!(err, Error::Crypto(_)), "got {err:?}");
    }

    #[test]
    fn deniable_open_with_mvk_refuses_detached_header() {
        // Deniable vaults are always inline-header (a detached header
        // would be a structural fingerprint defeating the indistin-
        // guishability goal). The handoff path enforces this.
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("vault.lbx");
        let header_p = tmp.path().join("vault.hdr"); // not actually used
        let c = Container::create_with_passphrase_deniable(
            &path,
            None,
            CipherSuite::Aes256GcmSiv,
            cheap_argon2(),
            0,
            b"hunter2",
        )
        .unwrap();
        let mvk = c.mvk_clone();
        let (salt, inner, slot_idx) = c.deniable_handoff_state().unwrap();
        drop(c);

        let err =
            Container::open_with_mvk_deniable(&path, Some(&header_p), mvk, salt, inner, slot_idx)
                .err()
                .expect("must refuse detached header path for deniable");
        assert!(matches!(err, Error::Crypto(_)), "got {err:?}");
    }

    #[test]
    fn deniable_handoff_state_returns_none_for_standard_container() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("vault.lbx");
        let c = Container::create_with_passphrase(
            &path,
            None,
            CipherSuite::Aes256GcmSiv,
            cheap_argon2(),
            b"hunter2",
        )
        .unwrap();
        assert_eq!(c.deniable_handoff_state(), None);
    }

    #[test]
    fn deniable_container_wrong_passphrase_returns_opaque_error() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("vault.lbx");
        Container::create_with_passphrase_deniable(
            &path,
            None,
            CipherSuite::Aes256GcmSiv,
            cheap_argon2(),
            0,
            b"hunter2",
        )
        .unwrap();
        let err = Container::open_with_passphrase_deniable(
            &path,
            None,
            b"wrong",
            cheap_argon2(),
            CipherSuite::Aes256GcmSiv,
        )
        .err()
        .unwrap();
        assert!(matches!(err, Error::OpaqueUnlockFailed));
    }

    #[test]
    fn deniable_container_wrong_cipher_returns_opaque_error() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("vault.lbx");
        Container::create_with_passphrase_deniable(
            &path,
            None,
            CipherSuite::Aes256GcmSiv,
            cheap_argon2(),
            0,
            b"hunter2",
        )
        .unwrap();
        let err = Container::open_with_passphrase_deniable(
            &path,
            None,
            b"hunter2",
            cheap_argon2(),
            CipherSuite::ChaCha20Poly1305,
        )
        .err()
        .unwrap();
        assert!(matches!(err, Error::OpaqueUnlockFailed));
    }

    #[test]
    fn deniable_container_rejects_detached_header() {
        // v1 limitation surfaced as a clear error; symmetric for
        // create and open. The future detached-deniable extension
        // would write the 8 KiB to a sidecar and put the metadata
        // region at offset 0 of the .lbx.
        let tmp = tempfile::tempdir().unwrap();
        let vault = tmp.path().join("vault.lbx");
        let header = tmp.path().join("vault.hdr");
        let err = Container::create_with_passphrase_deniable(
            &vault,
            Some(&header),
            CipherSuite::Aes256GcmSiv,
            cheap_argon2(),
            0,
            b"hunter2",
        )
        .err()
        .unwrap();
        assert!(matches!(err, Error::Crypto(_)));
    }

    #[test]
    fn deniable_container_persist_header_writes_cached_bytes() {
        // After mutating `header_dirty` we expect persist_header
        // to write the cached 8 KiB buffer back to offset 0 - NOT
        // re-serialise `self.header`, which would produce a
        // standard-format header and corrupt the deniable vault.
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("vault.lbx");
        let mut c = Container::create_with_passphrase_deniable(
            &path,
            None,
            CipherSuite::Aes256GcmSiv,
            cheap_argon2(),
            0,
            b"hunter2",
        )
        .unwrap();
        // Force persist by flipping the dirty flag directly. Real
        // code paths only flip this via slot mutations which are
        // currently gated for deniable mode; this test exercises
        // the persist path in isolation.
        c.header_dirty = true;
        c.persist_header().unwrap();

        // Reopen and confirm the vault still unlocks - i.e., the
        // persist did NOT clobber the deniable header with a
        // standard one.
        drop(c);
        assert!(
            Container::open_with_passphrase_deniable(
                &path,
                None,
                b"hunter2",
                cheap_argon2(),
                CipherSuite::Aes256GcmSiv,
            )
            .is_ok(),
            "persist_header in deniable mode wrote the wrong bytes",
        );
    }

    #[test]
    fn deniable_container_enroll_second_passphrase_persists() {
        // The bug this guards: in v1 the standard enroll_passphrase
        // was used in deniable mode too, which silently mutated the
        // synthetic Header.keyslots while persist_header wrote the
        // cached deniable bytes - the new slot never landed on disk.
        // With enroll_passphrase_deniable + the persist_header
        // branch the second user CAN open the vault after reopen.
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("vault.lbx");
        let mut c = Container::create_with_passphrase_deniable(
            &path,
            None,
            CipherSuite::Aes256GcmSiv,
            cheap_argon2(),
            0,
            b"admin",
        )
        .unwrap();
        let admin_mvk = c.mvk_clone();
        assert_eq!(c.deniable_unlocked_slot(), Some(0));

        // Enroll a second passphrase at slot 3 (not the admin's
        // slot 0).
        let new_idx = c
            .enroll_passphrase_deniable(3, b"bob-password", cheap_argon2())
            .unwrap();
        assert_eq!(new_idx, 3);
        c.persist_header().unwrap();
        drop(c);

        // Bob opens with his passphrase - should land in slot 3.
        let c_bob = Container::open_with_passphrase_deniable(
            &path,
            None,
            b"bob-password",
            cheap_argon2(),
            CipherSuite::Aes256GcmSiv,
        )
        .unwrap();
        assert_eq!(c_bob.mvk_clone().as_bytes(), admin_mvk.as_bytes());
        assert_eq!(c_bob.deniable_unlocked_slot(), Some(3));
        // Drop Bob's handle so the OS lock releases before the
        // admin reopens (Container holds an exclusive lock; two
        // concurrent opens would error with VaultLocked).
        drop(c_bob);

        // Admin can still open with the original passphrase - slot 0.
        let c_admin = Container::open_with_passphrase_deniable(
            &path,
            None,
            b"admin",
            cheap_argon2(),
            CipherSuite::Aes256GcmSiv,
        )
        .unwrap();
        assert_eq!(c_admin.mvk_clone().as_bytes(), admin_mvk.as_bytes());
        assert_eq!(c_admin.deniable_unlocked_slot(), Some(0));
    }

    #[test]
    fn deniable_container_enroll_refuses_admin_own_slot() {
        // Footgun guard: the admin must not be able to overwrite the
        // slot whose credential opened the vault. The error is what
        // the GUI catches to prompt the user to pick a different
        // index.
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("vault.lbx");
        let mut c = Container::create_with_passphrase_deniable(
            &path,
            None,
            CipherSuite::Aes256GcmSiv,
            cheap_argon2(),
            0,
            b"admin",
        )
        .unwrap();
        let err = c
            .enroll_passphrase_deniable(0, b"would-overwrite-me", cheap_argon2())
            .err()
            .unwrap();
        assert!(matches!(err, Error::Crypto(_)));
    }

    #[test]
    fn deniable_container_standard_enroll_rejected() {
        // The standard enroll_passphrase used to silently mis-save in
        // deniable mode. With the guard it errors out so callers know
        // to use enroll_passphrase_deniable instead.
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("vault.lbx");
        let mut c = Container::create_with_passphrase_deniable(
            &path,
            None,
            CipherSuite::Aes256GcmSiv,
            cheap_argon2(),
            0,
            b"admin",
        )
        .unwrap();
        let err = c.enroll_passphrase(b"bob", cheap_argon2()).err().unwrap();
        assert!(matches!(err, Error::Crypto(_)));
    }

    #[test]
    fn deniable_container_clear_slot_removes_credential() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("vault.lbx");
        let mut c = Container::create_with_passphrase_deniable(
            &path,
            None,
            CipherSuite::Aes256GcmSiv,
            cheap_argon2(),
            0,
            b"admin",
        )
        .unwrap();
        c.enroll_passphrase_deniable(5, b"bob", cheap_argon2())
            .unwrap();
        c.clear_deniable_slot(5).unwrap();
        c.persist_header().unwrap();
        drop(c);

        // Bob can no longer open; admin still can.
        assert!(matches!(
            Container::open_with_passphrase_deniable(
                &path,
                None,
                b"bob",
                cheap_argon2(),
                CipherSuite::Aes256GcmSiv,
            ),
            Err(Error::OpaqueUnlockFailed),
        ));
        assert!(
            Container::open_with_passphrase_deniable(
                &path,
                None,
                b"admin",
                cheap_argon2(),
                CipherSuite::Aes256GcmSiv,
            )
            .is_ok(),
        );
    }

    /// Regression: vault created with a non-default cipher, second
    /// passphrase slot enrolled, then re-opened with second slot's
    /// passphrase under the same cipher MUST succeed. Pins the
    /// container-level cipher-threading so the wizard / GUI cipher
    /// dropdown not being the default is never enough on its own to
    /// break later enroll / unlock.
    #[test]
    fn second_passphrase_slot_unlocks_under_aes_gcm() {
        const NON_DEFAULT: CipherSuite = CipherSuite::Aes256Gcm;

        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("vault.lbx");
        let mut c = Container::create_with_passphrase_deniable(
            &path,
            None,
            NON_DEFAULT,
            cheap_argon2(),
            0,
            b"admin-pp",
        )
        .unwrap();
        c.enroll_passphrase_deniable(2, b"second-pp", cheap_argon2())
            .unwrap();
        c.persist_header().unwrap();
        drop(c);

        // Admin still opens under the non-default cipher.
        Container::open_with_passphrase_deniable(
            &path,
            None,
            b"admin-pp",
            cheap_argon2(),
            NON_DEFAULT,
        )
        .expect("admin slot 0 must reopen under create-time cipher");

        // Second passphrase opens under the same cipher.
        Container::open_with_passphrase_deniable(
            &path,
            None,
            b"second-pp",
            cheap_argon2(),
            NON_DEFAULT,
        )
        .expect("freshly-enrolled second passphrase must open under create-time cipher");

        // Cross-check: opening either slot under the wrong cipher
        // fails cleanly (no slot-specific oracle).
        for pw in [b"admin-pp" as &[u8], b"second-pp"] {
            assert!(matches!(
                Container::open_with_passphrase_deniable(
                    &path,
                    None,
                    pw,
                    cheap_argon2(),
                    CipherSuite::Aes256GcmSiv,
                ),
                Err(Error::OpaqueUnlockFailed)
            ));
        }
    }

    #[test]
    fn deniable_container_fido2_round_trip() {
        // v2: FIDO2 deniable slot must be FIDO2 + envelope passphrase
        // (Fido2Passphrase). cred_id + hmac_salt are embedded in the
        // slot envelope; passphrase opens the envelope, hmac_secret
        // unwraps the inner MVK.
        use crate::deniable_header::DeniableMaterial;
        use luksbox_core::deniable::DeniableCredential;
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("vault.lbx");
        let hmac = [0xaau8; 32];
        let cred = DeniableCredential::Fido2Passphrase {
            passphrase: b"hunter2",
            argon2: cheap_argon2(),
            hmac_secret_output: &hmac,
        };
        let material = DeniableMaterial {
            cred_id: vec![0xcd; 64],
            hmac_salt: Some([0xef; 32]),
            tpm_blob: Vec::new(),
        };
        let c = Container::create_with_credential_v2_deniable(
            &path,
            None,
            CipherSuite::Aes256GcmSiv,
            0,
            2,
            &cred,
            &material,
        )
        .unwrap();
        let mvk_before = c.mvk_clone();
        assert_eq!(c.deniable_unlocked_slot(), Some(2));
        drop(c);

        // v2 open: two-phase. The matched slot index is recovered
        // from the envelope payload, not supplied by the caller.
        let env = Container::try_open_envelope_v2_deniable(
            &path,
            None,
            &cred,
            CipherSuite::Aes256GcmSiv,
            None,
        )
        .unwrap();
        assert_eq!(env.opened.matched_slot_idx, 2);
        // Material round-trips through the envelope.
        assert_eq!(env.payload().cred_id, material.cred_id);
        assert_eq!(env.payload().hmac_salt, material.hmac_salt);
        let c_open = Container::complete_open_v2_deniable(env, &cred).unwrap();
        assert_eq!(c_open.mvk_clone().as_bytes(), mvk_before.as_bytes());
        assert_eq!(c_open.deniable_unlocked_slot(), Some(2));
    }

    #[test]
    fn deniable_container_tpm_round_trip() {
        // v2: TPM + envelope passphrase. The TPM sealed blob is
        // embedded in the slot envelope (no .tpm-blob sidecar).
        use crate::deniable_header::DeniableMaterial;
        use luksbox_core::deniable::DeniableCredential;
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("vault.lbx");
        let unsealed = [0xbcu8; 32];
        let cred = DeniableCredential::TpmPassphrase {
            passphrase: b"vault-pass",
            argon2: cheap_argon2(),
            unsealed: &unsealed,
        };
        // Realistic ~1.8 KiB TPM blob.
        let blob = vec![0x77; 1800];
        let material = DeniableMaterial {
            cred_id: Vec::new(),
            hmac_salt: None,
            tpm_blob: blob.clone(),
        };
        let c = Container::create_with_credential_v2_deniable(
            &path,
            None,
            CipherSuite::Aes256GcmSiv,
            0,
            5,
            &cred,
            &material,
        )
        .unwrap();
        let mvk_before = c.mvk_clone();
        drop(c);

        let env = Container::try_open_envelope_v2_deniable(
            &path,
            None,
            &cred,
            CipherSuite::Aes256GcmSiv,
            None,
        )
        .unwrap();
        assert_eq!(env.payload().tpm_blob, blob);
        let c = Container::complete_open_v2_deniable(env, &cred).unwrap();
        assert_eq!(c.mvk_clone().as_bytes(), mvk_before.as_bytes());
    }

    #[test]
    fn deniable_container_hybrid_pq_tpm_fido2_round_trip() {
        // v2: 4-factor hybrid-PQ + TPM + FIDO2 + passphrase.
        use crate::deniable_header::DeniableMaterial;
        use luksbox_core::deniable::DeniableCredential;
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("vault.lbx");
        let mlkem = [0x01u8; 32];
        let unsealed = [0x02u8; 32];
        let hmac = [0x03u8; 32];
        let cred = DeniableCredential::HybridPqTpmFido2Passphrase {
            passphrase: b"vault-pass",
            argon2: cheap_argon2(),
            mlkem_shared: &mlkem,
            unsealed: &unsealed,
            hmac_secret_output: &hmac,
        };
        let material = DeniableMaterial {
            cred_id: vec![0x10; 80],
            hmac_salt: Some([0x20; 32]),
            tpm_blob: vec![0x30; 1500],
        };
        let c = Container::create_with_credential_v2_deniable(
            &path,
            None,
            CipherSuite::Aes256GcmSiv,
            0,
            7,
            &cred,
            &material,
        )
        .unwrap();
        let mvk_before = c.mvk_clone();
        drop(c);

        let env = Container::try_open_envelope_v2_deniable(
            &path,
            None,
            &cred,
            CipherSuite::Aes256GcmSiv,
            None,
        )
        .unwrap();
        let c = Container::complete_open_v2_deniable(env, &cred).unwrap();
        assert_eq!(c.mvk_clone().as_bytes(), mvk_before.as_bytes());
    }

    #[test]
    fn deniable_container_enroll_mixed_credentials() {
        // v2 real-world flow: admin creates with a passphrase slot,
        // enrolls a Fido2Passphrase slot at index 4, both can unlock
        // the same MVK independently.
        use crate::deniable_header::DeniableMaterial;
        use luksbox_core::deniable::DeniableCredential;
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("vault.lbx");
        let admin_cred = DeniableCredential::Passphrase {
            passphrase: b"admin",
            argon2: cheap_argon2(),
        };
        let mut c = Container::create_with_credential_v2_deniable(
            &path,
            None,
            CipherSuite::Aes256GcmSiv,
            0,
            0,
            &admin_cred,
            &DeniableMaterial::passphrase_only(),
        )
        .unwrap();
        let mvk_admin = c.mvk_clone();

        let hmac = [0x42u8; 32];
        let fido2_cred = DeniableCredential::Fido2Passphrase {
            passphrase: b"bob",
            argon2: cheap_argon2(),
            hmac_secret_output: &hmac,
        };
        let fido2_material = DeniableMaterial {
            cred_id: vec![0x99; 64],
            hmac_salt: Some([0x88; 32]),
            tpm_blob: Vec::new(),
        };
        c.enroll_credential_v2_deniable(4, &fido2_cred, &fido2_material)
            .unwrap();
        c.persist_header().unwrap();
        drop(c);

        // Open with FIDO2+passphrase cred -> lands at slot 4.
        let env = Container::try_open_envelope_v2_deniable(
            &path,
            None,
            &fido2_cred,
            CipherSuite::Aes256GcmSiv,
            None,
        )
        .unwrap();
        assert_eq!(env.opened.matched_slot_idx, 4);
        let c_fido = Container::complete_open_v2_deniable(env, &fido2_cred).unwrap();
        assert_eq!(c_fido.mvk_clone().as_bytes(), mvk_admin.as_bytes());
        drop(c_fido);

        // Admin still works at slot 0.
        let env_admin = Container::try_open_envelope_v2_deniable(
            &path,
            None,
            &admin_cred,
            CipherSuite::Aes256GcmSiv,
            None,
        )
        .unwrap();
        assert_eq!(env_admin.opened.matched_slot_idx, 0);
        let c_admin = Container::complete_open_v2_deniable(env_admin, &admin_cred).unwrap();
        assert_eq!(c_admin.mvk_clone().as_bytes(), mvk_admin.as_bytes());
    }

    #[test]
    fn deniable_container_anchor_round_trip() {
        // End-to-end: create deniable vault, init anchor, drop,
        // reopen, attach anchor via set_anchor, verify generation
        // matches.
        use crate::deniable_header::DeniableMaterial;
        use luksbox_core::deniable::DeniableCredential;
        let tmp = tempfile::tempdir().unwrap();
        let vault = tmp.path().join("vault.lbx");
        let anchor = tmp.path().join("vault.anchor");
        let cred = DeniableCredential::Passphrase {
            passphrase: b"admin",
            argon2: cheap_argon2(),
        };
        let mut c = Container::create_with_credential_v2_deniable(
            &vault,
            None,
            CipherSuite::Aes256GcmSiv,
            0,
            0,
            &cred,
            &DeniableMaterial::passphrase_only(),
        )
        .unwrap();
        c.init_anchor(anchor.clone(), 42).unwrap();
        drop(c);

        // Anchor file must be the fixed 256-byte deniable size, not
        // the 48-byte standard anchor size.
        let sz = std::fs::metadata(&anchor).unwrap().len();
        assert_eq!(sz, crate::anchor::DENIABLE_ANCHOR_SIZE as u64);

        let env = Container::try_open_envelope_v2_deniable(
            &vault,
            None,
            &cred,
            CipherSuite::Aes256GcmSiv,
            None,
        )
        .unwrap();
        let mut c = Container::complete_open_v2_deniable(env, &cred).unwrap();
        let gen_from_anchor = c.set_anchor(Some(anchor.clone())).unwrap();
        assert_eq!(gen_from_anchor, Some(42));
    }

    #[test]
    fn deniable_container_anchor_wrong_vault_rejected() {
        // Attach an anchor from vault A to vault B. The deniable
        // anchor's AAD binds to per_vault_salt, so the read fails
        // with OpaqueUnlockFailed.
        use crate::deniable_header::DeniableMaterial;
        use luksbox_core::deniable::DeniableCredential;
        let tmp = tempfile::tempdir().unwrap();
        let vault_a = tmp.path().join("a.lbx");
        let vault_b = tmp.path().join("b.lbx");
        let anchor_a = tmp.path().join("a.anchor");

        let cred = DeniableCredential::Passphrase {
            passphrase: b"shared",
            argon2: cheap_argon2(),
        };
        let mut ca = Container::create_with_credential_v2_deniable(
            &vault_a,
            None,
            CipherSuite::Aes256GcmSiv,
            0,
            0,
            &cred,
            &DeniableMaterial::passphrase_only(),
        )
        .unwrap();
        ca.init_anchor(anchor_a.clone(), 5).unwrap();
        drop(ca);

        let _cb = Container::create_with_credential_v2_deniable(
            &vault_b,
            None,
            CipherSuite::Aes256GcmSiv,
            0,
            0,
            &cred,
            &DeniableMaterial::passphrase_only(),
        )
        .unwrap();
        drop(_cb);

        // Open vault B, try to attach anchor_a -> must fail
        // because the per_vault_salt differs (random per create).
        let env_b = Container::try_open_envelope_v2_deniable(
            &vault_b,
            None,
            &cred,
            CipherSuite::Aes256GcmSiv,
            None,
        )
        .unwrap();
        let mut cb = Container::complete_open_v2_deniable(env_b, &cred).unwrap();
        let err = cb.set_anchor(Some(anchor_a)).err().unwrap();
        assert!(matches!(err, Error::OpaqueUnlockFailed));
    }

    #[test]
    fn deniable_container_wrong_credential_type_returns_opaque() {
        // v2: Creator used Fido2Passphrase, opener tries
        // TpmPassphrase with the same passphrase + same secret. The
        // envelope opens (same passphrase) but the kind-tag mismatch
        // at complete_open_v2 surfaces OpaqueUnlockFailed.
        use crate::deniable_header::DeniableMaterial;
        use luksbox_core::deniable::DeniableCredential;
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("vault.lbx");
        let secret = [0x5au8; 32];

        let create_cred = DeniableCredential::Fido2Passphrase {
            passphrase: b"pp",
            argon2: cheap_argon2(),
            hmac_secret_output: &secret,
        };
        Container::create_with_credential_v2_deniable(
            &path,
            None,
            CipherSuite::Aes256GcmSiv,
            0,
            3,
            &create_cred,
            &DeniableMaterial {
                cred_id: vec![0xaa; 32],
                hmac_salt: Some([0xbb; 32]),
                tpm_blob: Vec::new(),
            },
        )
        .unwrap();

        // Try to open with the wrong variant - envelope opens (same
        // passphrase) but the kind-tag check in complete_open_v2
        // rejects the mismatch.
        let wrong_cred = DeniableCredential::TpmPassphrase {
            passphrase: b"pp",
            argon2: cheap_argon2(),
            unsealed: &secret,
        };
        let env = Container::try_open_envelope_v2_deniable(
            &path,
            None,
            &wrong_cred,
            CipherSuite::Aes256GcmSiv,
            None,
        )
        .unwrap();
        let err = Container::complete_open_v2_deniable(env, &wrong_cred)
            .err()
            .unwrap();
        assert!(matches!(err, Error::OpaqueUnlockFailed));
    }

    #[test]
    fn deniable_container_rotate_mvk_v2_round_trip() {
        // Create a v2 deniable vault with two slots, rotate keeping
        // both, confirm both still open and yield the new MVK,
        // confirm persist_header writes the rotated bytes back.
        use crate::deniable_header::DeniableMaterial;
        use luksbox_core::deniable::DeniableCredential;
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("vault.lbx");
        let admin = DeniableCredential::Passphrase {
            passphrase: b"admin",
            argon2: cheap_argon2(),
        };
        let bob = DeniableCredential::Passphrase {
            passphrase: b"bob",
            argon2: cheap_argon2(),
        };
        let mut c = Container::create_with_credential_v2_deniable(
            &path,
            None,
            CipherSuite::Aes256GcmSiv,
            0,
            0,
            &admin,
            &DeniableMaterial::passphrase_only(),
        )
        .unwrap();
        c.enroll_credential_v2_deniable(3, &bob, &DeniableMaterial::passphrase_only())
            .unwrap();
        c.persist_header().unwrap();
        let mvk_before = c.mvk_clone();

        // Rotate keeping both slots.
        let new_mvk = c
            .rotate_mvk_v2_deniable(&[
                (0, &admin, &DeniableMaterial::passphrase_only()),
                (3, &bob, &DeniableMaterial::passphrase_only()),
            ])
            .unwrap();
        assert_ne!(new_mvk.as_bytes(), mvk_before.as_bytes());
        c.persist_header().unwrap();
        drop(c);

        // Both credentials open the rotated vault and yield new_mvk.
        let env_admin = Container::try_open_envelope_v2_deniable(
            &path,
            None,
            &admin,
            CipherSuite::Aes256GcmSiv,
            None,
        )
        .unwrap();
        assert_eq!(env_admin.opened.matched_slot_idx, 0);
        let c_admin = Container::complete_open_v2_deniable(env_admin, &admin).unwrap();
        assert_eq!(c_admin.mvk_clone().as_bytes(), new_mvk.as_bytes());
        drop(c_admin);

        let env_bob = Container::try_open_envelope_v2_deniable(
            &path,
            None,
            &bob,
            CipherSuite::Aes256GcmSiv,
            None,
        )
        .unwrap();
        assert_eq!(env_bob.opened.matched_slot_idx, 3);
        let c_bob = Container::complete_open_v2_deniable(env_bob, &bob).unwrap();
        assert_eq!(c_bob.mvk_clone().as_bytes(), new_mvk.as_bytes());
    }

    #[test]
    fn deniable_container_rotate_mvk_v2_drops_credential() {
        // Rotate keeping only one of two slots - the dropped one
        // must no longer open the vault.
        use crate::deniable_header::DeniableMaterial;
        use luksbox_core::deniable::DeniableCredential;
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("vault.lbx");
        let admin = DeniableCredential::Passphrase {
            passphrase: b"admin",
            argon2: cheap_argon2(),
        };
        let bob = DeniableCredential::Passphrase {
            passphrase: b"bob",
            argon2: cheap_argon2(),
        };
        let mut c = Container::create_with_credential_v2_deniable(
            &path,
            None,
            CipherSuite::Aes256GcmSiv,
            0,
            0,
            &admin,
            &DeniableMaterial::passphrase_only(),
        )
        .unwrap();
        c.enroll_credential_v2_deniable(2, &bob, &DeniableMaterial::passphrase_only())
            .unwrap();
        c.persist_header().unwrap();

        c.rotate_mvk_v2_deniable(&[(0, &admin, &DeniableMaterial::passphrase_only())])
            .unwrap();
        c.persist_header().unwrap();
        drop(c);

        // Bob's slot is now random noise; opening with Bob's
        // credential fails opaquely.
        let err = Container::try_open_envelope_v2_deniable(
            &path,
            None,
            &bob,
            CipherSuite::Aes256GcmSiv,
            None,
        )
        .err()
        .unwrap();
        assert!(matches!(err, Error::OpaqueUnlockFailed));
    }

    #[test]
    fn deniable_rotate_mvk_v2_refuses_non_empty_vault() {
        // Footgun guard: rotate_mvk_v2_deniable does an envelope-only
        // rewrap. Calling it on a vault that has chunks would silently
        // corrupt the vault (chunks stay encrypted under the OLD MVK).
        // The guard must refuse with DeniableRotationRequiresEmptyVault
        // before any state mutation, pointing the caller at
        // Vfs::rotate_mvk_deniable which does the full re-encryption.
        use crate::deniable_header::DeniableMaterial;
        use crate::metadata;
        use luksbox_core::deniable::DeniableCredential;
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("nonempty.lbx");
        let cred = DeniableCredential::Passphrase {
            passphrase: b"pw",
            argon2: cheap_argon2(),
        };
        let mut c = Container::create_with_passphrase_deniable(
            &path,
            None,
            CipherSuite::Aes256GcmSiv,
            cheap_argon2(),
            0,
            b"pw",
        )
        .unwrap();
        // Simulate a flush by writing a non-empty metadata blob.
        // The real Vfs::flush would write the postcard-encoded tree
        // here; any non-empty plaintext triggers the guard.
        c.write_metadata(b"LBM\x02fake-tree-bytes").unwrap();
        let mvk_before = c.mvk_clone();
        let salt_before = c.header.header_salt;

        let err = c
            .rotate_mvk_v2_deniable(&[(0, &cred, &DeniableMaterial::passphrase_only())])
            .err()
            .expect("guard must refuse rotation on non-empty deniable vault");
        assert!(
            matches!(err, Error::DeniableRotationRequiresEmptyVault),
            "expected DeniableRotationRequiresEmptyVault, got {err:?}"
        );
        // Container state must be untouched.
        assert_eq!(c.mvk_clone().as_bytes(), mvk_before.as_bytes());
        assert_eq!(c.header.header_salt, salt_before);
        // And we can still read the (fake) metadata back -- proving
        // the guard didn't touch on-disk state either.
        let _ = metadata::read_metadata(
            c.header.cipher_suite,
            &c.mvk_clone(),
            &c.header.header_salt,
            // Just call read_metadata to confirm the AEAD still verifies:
            &{
                let mut region = vec![0u8; c.header.metadata_size as usize];
                use std::io::{Read, Seek, SeekFrom};
                c.file
                    .seek(SeekFrom::Start(c.header.metadata_offset))
                    .unwrap();
                c.file.read_exact(&mut region).unwrap();
                region
            },
        )
        .unwrap();
    }

    #[test]
    fn deniable_rotate_mvk_v2_envelope_only_skips_guard() {
        // The unguarded primitive used by Vfs::rotate_mvk_deniable
        // must still work on non-empty vaults -- it's the building
        // block of the full rotation path. This test pins that
        // the rename + split didn't accidentally re-add the guard.
        use crate::deniable_header::DeniableMaterial;
        use luksbox_core::deniable::DeniableCredential;
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("nonempty2.lbx");
        let cred = DeniableCredential::Passphrase {
            passphrase: b"pw",
            argon2: cheap_argon2(),
        };
        let mut c = Container::create_with_passphrase_deniable(
            &path,
            None,
            CipherSuite::Aes256GcmSiv,
            cheap_argon2(),
            0,
            b"pw",
        )
        .unwrap();
        c.write_metadata(b"non-empty-fake").unwrap();
        let mvk_before = c.mvk_clone();
        // Should succeed (no guard on this primitive). The caller
        // is responsible for re-encrypting chunks afterward; this
        // test only validates the entry point.
        let new_mvk = c
            .rotate_mvk_v2_deniable_envelope_only(&[(
                0,
                &cred,
                &DeniableMaterial::passphrase_only(),
            )])
            .expect("envelope-only primitive must succeed on non-empty vault");
        assert_ne!(new_mvk.as_bytes(), mvk_before.as_bytes());
    }

    #[test]
    fn deniable_container_metadata_region_round_trips() {
        // Container creates a 1 MiB metadata region encrypted with
        // the MVK. After reopen we should be able to read it back
        // intact via the existing metadata::read_metadata path.
        // This validates that the synthetic Header struct carries
        // the right header_salt and cipher_suite for downstream
        // metadata code.
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("vault.lbx");
        Container::create_with_passphrase_deniable(
            &path,
            None,
            CipherSuite::Aes256GcmSiv,
            cheap_argon2(),
            0,
            b"hunter2",
        )
        .unwrap();
        let c = Container::open_with_passphrase_deniable(
            &path,
            None,
            b"hunter2",
            cheap_argon2(),
            CipherSuite::Aes256GcmSiv,
        )
        .unwrap();
        // Read the metadata region back. An empty vault stores an
        // empty payload, so `read_metadata` should return Vec::new().
        // The synthetic header gives the offset and salt.
        let mut metadata = vec![0u8; c.header.metadata_size as usize];
        let mut f = std::fs::File::open(&path).unwrap();
        use std::io::{Read, Seek, SeekFrom};
        f.seek(SeekFrom::Start(c.header.metadata_offset)).unwrap();
        f.read_exact(&mut metadata).unwrap();
        let pt = metadata::read_metadata(
            c.header.cipher_suite,
            &c.mvk,
            &c.header.header_salt,
            &metadata,
        )
        .expect("metadata roundtrip failed; synthetic header carries wrong salt or cipher");
        assert!(
            pt.is_empty(),
            "empty vault should have empty metadata payload"
        );
    }

    #[test]
    fn v2_vault_write_creates_header_and_metadata_mirrors() {
        // When the in-memory header is marked v2, both `write_metadata`
        // and `persist_header` must rotate previous-good copies into
        // sidecar files before overwriting the live regions, and must
        // set the corresponding FLAG_HAS_*_MIRROR bits so subsequent
        // opens advertise the mirrors as present.
        let dir = tempdir().unwrap();
        let path = dir.path().join("v2.lbx");
        {
            let mut c = Container::create_with_passphrase(
                &path,
                None,
                CipherSuite::Aes256Gcm,
                test_params(),
                b"v2-roundtrip",
            )
            .unwrap();
            // Promote the in-memory header to v2 so the next write
            // exercises the mirror-rotate path. Auto-upgrade (commit 5)
            // will do this automatically from `Vfs::flush`; here we
            // simulate it directly to isolate the write-path test.
            c.header.version_major = luksbox_core::VERSION_MAJOR_V2;
            c.header_dirty = true;
            c.write_metadata(b"first payload").unwrap();
            c.persist_header().unwrap();
        }
        let mirror_meta = path.with_file_name(format!(
            "{}.meta-bak",
            path.file_name().unwrap().to_string_lossy()
        ));
        let mirror_header = path.with_file_name(format!(
            "{}.header-bak",
            path.file_name().unwrap().to_string_lossy()
        ));
        assert!(
            mirror_meta.exists(),
            "metadata mirror should exist after a v2 write_metadata: {}",
            mirror_meta.display()
        );
        assert!(
            mirror_header.exists(),
            "header mirror should exist after a v2 persist_header: {}",
            mirror_header.display()
        );
        // Reopen and confirm the flag bits made it to disk and the
        // recovered tree is readable from the live region.
        let mut c =
            Container::open(&path, None, UnlockMaterial::Passphrase(b"v2-roundtrip")).unwrap();
        assert_eq!(c.header.version_major, luksbox_core::VERSION_MAJOR_V2);
        assert!(c.header.has_header_mirror());
        assert!(c.header.has_metadata_mirror());
        let blob = c.read_metadata().unwrap();
        assert_eq!(&**blob, b"first payload");
    }

    #[test]
    fn v1_vault_writes_do_not_create_mirrors() {
        // v0.2.0-format vaults preserve the in-place rewrite behavior
        // until an explicit upgrade trigger fires. No mirror files
        // should appear on disk.
        let dir = tempdir().unwrap();
        let path = dir.path().join("v1.lbx");
        let mut c = Container::create_with_passphrase(
            &path,
            None,
            CipherSuite::Aes256Gcm,
            test_params(),
            b"v1-only",
        )
        .unwrap();
        // Default `try_new` builds a v1 header; explicitly assert
        // before testing the negative.
        assert_eq!(c.header.version_major, luksbox_core::VERSION_MAJOR_V1);
        c.write_metadata(b"v1 payload").unwrap();
        c.persist_header().unwrap();
        for ext in ["meta-bak", "header-bak"] {
            let sidecar = path.with_file_name(format!(
                "{}.{ext}",
                path.file_name().unwrap().to_string_lossy()
            ));
            assert!(
                !sidecar.exists(),
                "v1 vault must not create sidecar at {}",
                sidecar.display()
            );
        }
    }

    #[test]
    fn v2_recovers_metadata_after_corrupting_live_region() {
        // Simulates the user's "blob deserialization failed" scenario:
        // a crash corrupted the live metadata bytes; the mirror holds
        // the intended new bytes (v0.2.1 intended-state protocol:
        // mirror is written with the INTENDED-NEW payload before live
        // overwrite, so the mirror reflects what live should hold).
        // Open should fall back to the mirror and surface the LATEST
        // payload (not a stale previous-good).
        let dir = tempdir().unwrap();
        let path = dir.path().join("recover.lbx");
        // Phase 1: create v2 vault, write known payload.
        {
            let mut c = Container::create_with_passphrase(
                &path,
                None,
                CipherSuite::Aes256Gcm,
                test_params(),
                b"recover",
            )
            .unwrap();
            c.header.version_major = luksbox_core::VERSION_MAJOR_V2;
            c.header_dirty = true;
            c.write_metadata(b"alpha").unwrap();
            c.persist_header().unwrap();
            // Second write: mirror is now written with "beta" first
            // (atomic temp+rename), then live is overwritten with
            // "beta". Both copies equal "beta" on success.
            c.write_metadata(b"beta").unwrap();
            c.persist_header().unwrap();
        }
        // Phase 2: simulate a crash mid-write to the LIVE metadata
        // region by overwriting AEAD bytes. The live region now fails
        // AEAD verification; the mirror still holds the encrypted
        // "beta" blob (intended-state).
        {
            let mut f = OpenOptions::new()
                .read(true)
                .write(true)
                .open(&path)
                .unwrap();
            let header = {
                let mut hb = [0u8; HEADER_SIZE];
                f.seek(SeekFrom::Start(0)).unwrap();
                f.read_exact(&mut hb).unwrap();
                Header::from_bytes(&hb).unwrap()
            };
            f.seek(SeekFrom::Start(header.metadata_offset)).unwrap();
            f.write_all(&[0xAA; 64]).unwrap();
            f.sync_all().unwrap();
        }
        // Phase 3: reopen and confirm recovery returns "beta" (the
        // LATEST committed payload from the mirror), not the live
        // garbage and not a stale "alpha". The intended-state
        // protocol means the mirror tracks live forward, never
        // backward.
        let mut c = Container::open(&path, None, UnlockMaterial::Passphrase(b"recover")).unwrap();
        let blob = c.read_metadata().unwrap();
        assert_eq!(
            &**blob, b"beta",
            "must recover latest committed payload, not stale"
        );
        assert!(c.metadata_was_recovered_from_mirror());
    }

    #[test]
    fn v2_recovers_header_after_corrupting_live_header() {
        // Simulates the user's "no keyslot accepted the provided unlock
        // material" scenario: a crash partially overwrote the live
        // 8 KiB header, breaking keyslot AEAD or header HMAC. The
        // header-bak sidecar still holds the previous-good header.
        let dir = tempdir().unwrap();
        let path = dir.path().join("hdr.lbx");
        // Phase 1: create v2 vault, two persist_headers so the mirror
        // is established.
        {
            let mut c = Container::create_with_passphrase(
                &path,
                None,
                CipherSuite::Aes256Gcm,
                test_params(),
                b"hdr-recover",
            )
            .unwrap();
            c.header.version_major = luksbox_core::VERSION_MAJOR_V2;
            c.header_dirty = true;
            c.persist_header().unwrap();
            // Touch the header (re-enroll same passphrase or just
            // re-set dirty) to trigger a second persist that rotates
            // the previous-good copy into the mirror.
            c.header_dirty = true;
            c.persist_header().unwrap();
            // Write a small metadata payload so we have something to
            // verify reads still work after recovery.
            c.write_metadata(b"header-recovery-payload").unwrap();
        }
        // Phase 2: simulate a crash mid-write to the LIVE header by
        // scribbling over the first 4 KiB. This destroys the magic,
        // version, AND the first 4 keyslots; unlock fails completely.
        {
            let mut f = OpenOptions::new()
                .read(true)
                .write(true)
                .open(&path)
                .unwrap();
            f.seek(SeekFrom::Start(0)).unwrap();
            f.write_all(&[0xCC; 4096]).unwrap();
            f.sync_all().unwrap();
        }
        // Phase 3: reopen should succeed via the header mirror.
        let mut c = Container::open(&path, None, UnlockMaterial::Passphrase(b"hdr-recover"))
            .expect("must recover header from sidecar mirror");
        let blob = c.read_metadata().unwrap();
        assert_eq!(&**blob, b"header-recovery-payload");
    }

    /// **CRITICAL REGRESSION TEST**: a revoked credential must NOT
    /// succeed against the `<vault>.lbx.header-bak` mirror that was
    /// written before the revoke. Mirror recovery is gated strictly
    /// on Header::from_bytes parse failure; unlock-failure on an
    /// otherwise-parseable header must NOT fall back to the mirror,
    /// because the mirror still carries the revoked slot.
    ///
    /// First reviewer-found auth-bypass in the v0.2.1 durability
    /// fix. This test pins the gating so a future regression is
    /// caught immediately.
    /// **Deniability invariant**: a deniable vault must NEVER create
    /// sidecar mirror files, even if its in-memory header gets
    /// forced into the v2 magic by a stray code path or test setup.
    /// Mirror sidecars at predictable names + lengths drop the
    /// observed entropy of the on-disk artefact set below the
    /// >=7.99 bits/byte target the deniable header pays 36 KiB to
    /// > establish, defeating the property entirely.
    #[test]
    fn deniable_vault_never_creates_sidecar_mirrors() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("denvault.lbx");
        let mut c = Container::create_with_passphrase_deniable(
            &path,
            None,
            CipherSuite::Aes256GcmSiv,
            cheap_argon2(),
            0,
            b"deniable-test",
        )
        .unwrap();
        // Force the in-memory header to claim v2; this is what a
        // confused code path might do. The is_v2_format guard must
        // still refuse the mirror write because is_deniable() is
        // true.
        c.header.version_major = luksbox_core::VERSION_MAJOR_V2;
        c.mark_header_dirty();
        // Persist + write some metadata. Neither should produce a
        // mirror file.
        c.persist_header().unwrap();
        c.write_metadata(b"deniable payload should not leak mirror")
            .unwrap();
        let mirror_header = path.with_file_name(format!(
            "{}.header-bak",
            path.file_name().unwrap().to_string_lossy()
        ));
        let mirror_meta = path.with_file_name(format!(
            "{}.meta-bak",
            path.file_name().unwrap().to_string_lossy()
        ));
        assert!(
            !mirror_header.exists(),
            "deniable vault must NEVER create a header sidecar mirror at {}: \
             would drop entropy of on-disk artefact set below ~7.99 bits/byte \
             and defeat deniability",
            mirror_header.display()
        );
        assert!(
            !mirror_meta.exists(),
            "deniable vault must NEVER create a metadata sidecar mirror at {}: \
             would drop entropy of on-disk artefact set below ~7.99 bits/byte \
             and defeat deniability",
            mirror_meta.display()
        );
    }

    /// **CRITICAL REGRESSION TEST** (revoke + crash + mirror
    /// recovery): an attacker who corrupts the live header MUST NOT
    /// resurrect a revoked credential by forcing the recovery path.
    /// The v0.2.1 intended-state mirror protocol commits the mirror
    /// to NEW bytes BEFORE overwriting live, so the mirror always
    /// reflects the post-write keyslot table. Even a successful
    /// mirror recovery cannot accept a revoked credential.
    ///
    /// This is the deeper bypass: parse-fail-only gating prevents
    /// the recovery path from firing on a healthy live header, but
    /// if the attacker corrupts live, recovery WILL fire, and the
    /// protocol must be safe at that point too.
    #[test]
    fn v2_corrupted_live_after_revoke_does_not_unlock_via_mirror() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("revoke-crash.lbx");
        // Phase 1: create v2 vault, enroll second slot, persist
        // (mirror is committed to the current keyslot table).
        {
            let mut c = Container::create_with_passphrase(
                &path,
                None,
                CipherSuite::Aes256Gcm,
                test_params(),
                b"pass-A",
            )
            .unwrap();
            c.header.version_major = luksbox_core::VERSION_MAJOR_V2;
            c.header_dirty = true;
            c.enroll_passphrase(b"pass-B", test_params()).unwrap();
            c.persist_header().unwrap();
        }
        // Phase 2: revoke A. Mirror must be rewritten to the
        // post-revoke header bytes.
        {
            let mut c =
                Container::open(&path, None, UnlockMaterial::Passphrase(b"pass-A")).unwrap();
            c.header.revoke_slot(0).unwrap();
            c.header_dirty = true;
            c.persist_header().unwrap();
        }
        // Phase 3: attacker corrupts live header to force recovery.
        {
            let mut f = OpenOptions::new()
                .read(true)
                .write(true)
                .open(&path)
                .unwrap();
            f.seek(SeekFrom::Start(0)).unwrap();
            f.write_all(&[0xCC; 4096]).unwrap();
            f.sync_all().unwrap();
        }
        // Phase 4: revoked pass-A must NOT unlock, even though the
        // recovery path fires and reads the mirror.
        let result = Container::open(&path, None, UnlockMaterial::Passphrase(b"pass-A"));
        // The exact error variant depends on whether the recovery
        // path bubbled the live parse failure (when mirror also
        // rejects the credential) or the mirror unlock failure
        // directly. Both are "user is locked out" outcomes; what
        // matters for the security property is `Ok(_)` MUST NOT
        // fire.
        if result.is_ok() {
            panic!(
                "AUTH BYPASS: revoked pass-A unlocked via mirror after live corruption. \
                 Intended-state mirror protocol regressed; mirror is holding pre-revoke \
                 keyslots instead of the current post-revoke state."
            )
        }
        // Phase 5: pass-B must still work via mirror recovery
        // (sanity: recovery path itself is functional).
        let _ = Container::open(&path, None, UnlockMaterial::Passphrase(b"pass-B"))
            .expect("pass-B must still unlock via mirror recovery after live corruption");
    }

    #[test]
    fn v2_revoked_credential_does_not_unlock_via_mirror() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("revoke.lbx");
        // Phase 1: create v2 vault with passphrase A in slot 0,
        // enroll passphrase B in slot 1, persist (rotates mirror).
        // Then revoke slot 0 and persist again (rotates again).
        // After this, live header has B only; mirror has A and B.
        {
            let mut c = Container::create_with_passphrase(
                &path,
                None,
                CipherSuite::Aes256Gcm,
                test_params(),
                b"pass-A",
            )
            .unwrap();
            c.header.version_major = luksbox_core::VERSION_MAJOR_V2;
            c.header_dirty = true;
            c.enroll_passphrase(b"pass-B", test_params()).unwrap();
            c.persist_header().unwrap();
            // Sanity: both passphrases work right now.
            drop(c);
            let _ = Container::open(&path, None, UnlockMaterial::Passphrase(b"pass-A")).unwrap();
            let _ = Container::open(&path, None, UnlockMaterial::Passphrase(b"pass-B")).unwrap();

            let mut c =
                Container::open(&path, None, UnlockMaterial::Passphrase(b"pass-A")).unwrap();
            // Slot 0 is pass-A, slot 1 is pass-B. Revoke slot 0.
            c.header.revoke_slot(0).unwrap();
            c.header_dirty = true;
            c.persist_header().unwrap();
        }
        // Phase 2: a header-bak mirror exists and (because of the
        // rotate-before-overwrite protocol) holds the state from
        // the previous persist, which still had pass-A in slot 0.
        // The mirror MUST NOT allow pass-A to unlock.
        let mirror = path.with_file_name(format!(
            "{}.header-bak",
            path.file_name().unwrap().to_string_lossy()
        ));
        assert!(mirror.exists(), "phase 2: header mirror should exist");
        let result = Container::open(&path, None, UnlockMaterial::Passphrase(b"pass-A"));
        match result {
            Ok(_) => panic!("pass-A was revoked; mirror-recovery auth-bypass regressed"),
            Err(Error::UnlockFailed) => {}
            Err(other) => panic!("expected UnlockFailed for revoked credential, got {other:?}"),
        }
        // pass-B still works against live (sanity).
        let _ = Container::open(&path, None, UnlockMaterial::Passphrase(b"pass-B")).unwrap();
    }

    /// **CRITICAL REGRESSION TEST**: an attacker who plants a
    /// symlink at `<vault>.lbx.header-bak` pointing at `/dev/zero`
    /// (or any oversize file) must not OOM us via the recovery
    /// path. We stat-then-bounded-read so the allocation is capped
    /// at HEADER_SIZE regardless of what's at the path.
    #[test]
    #[cfg(unix)]
    fn v2_recovery_refuses_oversize_mirror_file() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("oversize.lbx");
        {
            let mut c = Container::create_with_passphrase(
                &path,
                None,
                CipherSuite::Aes256Gcm,
                test_params(),
                b"oversize",
            )
            .unwrap();
            c.header.version_major = luksbox_core::VERSION_MAJOR_V2;
            c.header_dirty = true;
            c.persist_header().unwrap();
            c.header_dirty = true;
            c.persist_header().unwrap();
        }
        // Corrupt live (force the recovery path to look at the
        // mirror) and replace the mirror with a 1 MB file (way
        // larger than HEADER_SIZE = 8 KiB).
        {
            let mut f = OpenOptions::new()
                .read(true)
                .write(true)
                .open(&path)
                .unwrap();
            f.seek(SeekFrom::Start(0)).unwrap();
            f.write_all(&[0u8; 4096]).unwrap();
            f.sync_all().unwrap();
        }
        let mirror = path.with_file_name(format!(
            "{}.header-bak",
            path.file_name().unwrap().to_string_lossy()
        ));
        std::fs::write(&mirror, vec![0u8; 1024 * 1024]).unwrap();
        // Open must fail (the oversize mirror is rejected without
        // OOM-allocating a 1 MB buffer for it).
        assert!(
            Container::open(&path, None, UnlockMaterial::Passphrase(b"oversize")).is_err(),
            "oversize mirror must be rejected"
        );
    }

    #[test]
    fn v2_detached_header_vault_mirror_sits_next_to_sidecar() {
        // Detached-header vaults keep the 8 KiB header in a separate
        // sidecar file (referenced via `header_path`). The mirror
        // protocol must rotate `<header_sidecar>.header-bak`, not
        // `<vault>.lbx.header-bak`. Verify the path placement and
        // that recovery works from there.
        let dir = tempdir().unwrap();
        let vault = dir.path().join("d.lbx");
        let header_sidecar = dir.path().join("d.hdr");
        {
            let mut c = Container::create_with_passphrase(
                &vault,
                Some(&header_sidecar),
                CipherSuite::Aes256Gcm,
                test_params(),
                b"detached",
            )
            .unwrap();
            c.header.version_major = luksbox_core::VERSION_MAJOR_V2;
            c.header_dirty = true;
            c.persist_header().unwrap();
            // Second persist so the mirror has previous-good.
            c.header_dirty = true;
            c.persist_header().unwrap();
        }
        // Mirror lives next to the detached header, not the vault.
        let mirror_next_to_sidecar = header_sidecar.with_file_name(format!(
            "{}.header-bak",
            header_sidecar.file_name().unwrap().to_string_lossy()
        ));
        let mirror_next_to_vault = vault.with_file_name(format!(
            "{}.header-bak",
            vault.file_name().unwrap().to_string_lossy()
        ));
        assert!(
            mirror_next_to_sidecar.exists(),
            "header mirror should sit next to the detached sidecar at {}",
            mirror_next_to_sidecar.display()
        );
        assert!(
            !mirror_next_to_vault.exists(),
            "header mirror should NOT sit next to the .lbx for detached vaults"
        );
        // Corrupt the live sidecar and confirm recovery works.
        {
            let mut f = OpenOptions::new()
                .read(true)
                .write(true)
                .open(&header_sidecar)
                .unwrap();
            f.write_all(&[0xCC; 4096]).unwrap();
            f.sync_all().unwrap();
        }
        let _c = Container::open(
            &vault,
            Some(&header_sidecar),
            UnlockMaterial::Passphrase(b"detached"),
        )
        .expect("must recover detached header from sidecar mirror");
    }

    #[test]
    fn v2_recovery_refuses_truncated_mirror() {
        // A mirror file shorter than HEADER_SIZE is corrupt; the
        // recovery path must refuse it and surface the live error
        // rather than silently zero-padding.
        let dir = tempdir().unwrap();
        let path = dir.path().join("trunc.lbx");
        {
            let mut c = Container::create_with_passphrase(
                &path,
                None,
                CipherSuite::Aes256Gcm,
                test_params(),
                b"trunc",
            )
            .unwrap();
            c.header.version_major = luksbox_core::VERSION_MAJOR_V2;
            c.header_dirty = true;
            c.persist_header().unwrap();
            c.header_dirty = true;
            c.persist_header().unwrap();
        }
        // Corrupt live AND truncate mirror.
        {
            let mut f = OpenOptions::new()
                .read(true)
                .write(true)
                .open(&path)
                .unwrap();
            f.seek(SeekFrom::Start(0)).unwrap();
            f.write_all(&[0u8; 4096]).unwrap();
            f.sync_all().unwrap();
        }
        let mirror = path.with_file_name(format!(
            "{}.header-bak",
            path.file_name().unwrap().to_string_lossy()
        ));
        std::fs::write(&mirror, b"short").unwrap();
        assert!(
            Container::open(&path, None, UnlockMaterial::Passphrase(b"trunc")).is_err(),
            "truncated mirror must not be accepted"
        );
    }

    #[test]
    fn v2_repeated_writes_keep_mirror_at_intended_new_state() {
        // After two successful write_metadata calls on a v2 vault,
        // the mirror MUST hold the LATEST committed payload, not a
        // historical previous-good copy. This is the v0.2.1
        // intended-state mirror protocol: a previous-good mirror
        // would be an auth-bypass surface for revoked credentials
        // (a corrupt-live attacker could force recovery from the
        // mirror's pre-revoke keyslots). The mirror always tracks
        // live forward.
        let dir = tempdir().unwrap();
        let path = dir.path().join("v2-rotate.lbx");
        let mut c = Container::create_with_passphrase(
            &path,
            None,
            CipherSuite::Aes256Gcm,
            test_params(),
            b"rotate",
        )
        .unwrap();
        c.header.version_major = luksbox_core::VERSION_MAJOR_V2;
        c.header_dirty = true;
        c.write_metadata(b"first").unwrap();
        c.persist_header().unwrap();
        // Second write: BOTH live and mirror MUST commit to "second"
        // (intended-state protocol). The mirror does NOT retain
        // "first".
        c.write_metadata(b"second").unwrap();
        let mirror_path = path.with_file_name(format!(
            "{}.meta-bak",
            path.file_name().unwrap().to_string_lossy()
        ));
        let mirror_bytes = std::fs::read(&mirror_path).unwrap();
        let pt = metadata::read_metadata(
            c.header.cipher_suite,
            &c.mvk,
            &c.header.header_salt,
            &mirror_bytes,
        )
        .expect("mirror must AEAD-decrypt under the live MVK");
        assert_eq!(
            &**pt, b"second",
            "intended-state protocol: mirror must hold the LATEST committed bytes, \
             not a historical previous-good"
        );
        // Live also has "second" (the intended state).
        let live = c.read_metadata().unwrap();
        assert_eq!(&**live, b"second");
    }
}
