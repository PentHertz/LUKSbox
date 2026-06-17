// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Penthertz <https://penthertz.com> (https://x.com/PentHertz)

//! `luksbox-fuse-t`: a thin, safe Rust wrapper around FUSE-T's
//! libfuse-t.dylib. Used by `luksbox-mount` on macOS when the
//! `fuse-t` Cargo feature is enabled, as a kext-free alternative to
//! macFUSE.
//!
//! # Why a separate crate
//!
//! `fuser` (the Rust crate that backs the macFUSE / libfuse2 path on
//! macOS today) hard-codes a pkg-config probe for `fuse.pc` and links
//! libfuse2. FUSE-T installs `fuse-t.pc` and ships `libfuse-t.dylib`,
//! a parallel implementation. They cannot be linked into the same
//! binary cleanly. So FUSE-T support lives in its own crate that
//! `luksbox-mount` chooses at link-time via a feature flag, NOT at
//! runtime via dlopen. (A user wanting both backends would build two
//! binaries; the common case is one or the other.)
//!
//! # API shape
//!
//! [`Filesystem`] is a sync trait modelled on libfuse 2.x's high-level
//! `struct fuse_operations`, every method is path-based (the kernel
//! resolves dentries to paths before calling us; FUSE-T preserves
//! that contract). All methods return [`Result<T, Errno>`] where
//! `Errno` is a small wrapper over `libc::c_int` so the C trampoline
//! can pass `-EIO` etc. straight through.
//!
//! [`mount`] takes a [`Filesystem`] impl, a mountpoint, and an
//! options bag, mounts the volume, and blocks until it's unmounted.
//! [`unmount`] wraps FUSE-T's mount-helper invocation.
//!
//! # Status
//!
//! Phase 1: binding compiles, mount path is wired end-to-end, the
//! lifecycle (mount, run, unmount) is exercised by luksbox-mount's
//! integration tests on a macOS+FUSE-T host. Phase 2 will harden
//! signal handling, concurrency, and edge cases (xattr, fsync,
//! statfs detail) once we have telemetry from real users.
//!
//! See `docs/MACOS_FUSE_T.md` for the full implementation roadmap
//! and the unmerged issues against this crate.

#![cfg_attr(not(target_os = "macos"), allow(dead_code))]

use std::path::Path;
use thiserror::Error;

#[cfg(target_os = "macos")]
mod ops;
#[cfg(target_os = "macos")]
mod sys;

/// Errors surfaced by the FUSE-T binding. Users of the binding only
/// see [`MountError`], [`Errno`] is for callbacks back from the
/// kernel into the [`Filesystem`] trait.
#[derive(Debug, Error)]
pub enum MountError {
    /// `mountpoint` doesn't exist or isn't a directory.
    #[error("invalid mountpoint {path}: {reason}")]
    InvalidMountpoint { path: String, reason: String },

    /// FUSE-T's `fuse_mount()` returned an error. The inner string is
    /// FUSE-T's own diagnostic, captured from stderr where possible.
    #[error("FUSE-T mount failed: {0}")]
    Mount(String),

    /// FUSE-T isn't installed (or libfuse-t.dylib failed to load).
    /// On macOS this means `brew install --cask fuse-t` first.
    #[error(
        "FUSE-T not available at runtime. Install with: \
         `brew install --cask fuse-t`. (libfuse-t.dylib must be on \
         the dynamic loader's search path.)"
    )]
    NotInstalled,

    /// The crate was built for a non-macOS target. FUSE-T is macOS-only.
    #[error("FUSE-T is macOS-only; this binary was built for a different OS")]
    Unsupported,

    /// Generic I/O error (e.g. mountpoint stat failed).
    #[error("io: {0}")]
    Io(#[from] std::io::Error),

    /// A `MountOptions` field contained a character that would
    /// inject additional libfuse `-o` options when the option list
    /// is comma-joined. Specifically `,`, `=`, `\0`, or any ASCII
    /// control byte. Surfaced from `mount()` BEFORE we hand the
    /// strings to libfuse, so a buggy or attacker-influenced caller
    /// can't smuggle options like `nosuid` -> `nosuid,allow_other`
    /// through `volname` injection.
    #[error(
        "invalid mount option {field}: contains forbidden character (one of `,`, `=`, `\\0`, or a control byte)"
    )]
    InvalidOption { field: &'static str },
}

/// Validate one user-supplied mount-option string. Reject characters
/// that would change the meaning of the comma-joined `-o` argument:
///
/// - `,` would split this option from a synthetic next one
///   (`fsname=foo,allow_other`).
/// - `=` would turn a value into another `key=value` if combined
///   with `,` (`volname=foo,bar=baz`).
/// - `\0` would prematurely terminate the C string libfuse parses.
/// - ASCII control bytes have no legitimate use in any of these
///   fields and are easiest to refuse than to characterize.
///
/// Internal callers pass hard-coded strings, this guard exists so a
/// future API extension that takes user input doesn't accidentally
/// re-open an injection vector.
fn validate_option(field: &'static str, value: &str) -> Result<(), MountError> {
    if value
        .bytes()
        .any(|b| b == b',' || b == b'=' || b == 0 || b.is_ascii_control())
    {
        return Err(MountError::InvalidOption { field });
    }
    Ok(())
}

/// Per-callback errno wrapper. Always negative-or-zero in the wire
/// representation libfuse expects (`-EIO`, `-ENOENT`, ...). Construct
/// via [`Errno::from_raw`] or the typed constants below.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Errno(pub libc::c_int);

#[allow(non_upper_case_globals)]
impl Errno {
    pub const ENOENT: Errno = Errno(libc::ENOENT);
    pub const EEXIST: Errno = Errno(libc::EEXIST);
    pub const ENOTDIR: Errno = Errno(libc::ENOTDIR);
    pub const EISDIR: Errno = Errno(libc::EISDIR);
    pub const ENOTEMPTY: Errno = Errno(libc::ENOTEMPTY);
    pub const EINVAL: Errno = Errno(libc::EINVAL);
    pub const EIO: Errno = Errno(libc::EIO);
    pub const EACCES: Errno = Errno(libc::EACCES);
    pub const ENOSYS: Errno = Errno(libc::ENOSYS);
    /// "No space left on device". `luksbox-mount` returns this from
    /// write/truncate when the v2 metadata budget would be exceeded
    /// by the in-flight write (`Vfs::Error::MetadataBudgetExhausted`).
    /// userspace sees the right errno mid-copy instead of a silent
    /// "vault is corrupt next time you open it".
    pub const ENOSPC: Errno = Errno(libc::ENOSPC);
    /// "File too large". Returned when a write/truncate would push a
    /// single file past `luksbox_vfs::MAX_FILE_SIZE`.
    pub const EFBIG: Errno = Errno(libc::EFBIG);

    pub const fn from_raw(e: libc::c_int) -> Errno {
        Errno(e)
    }
}

/// File-attribute snapshot returned by [`Filesystem::getattr`].
/// Mirrors the subset of `struct stat` we actually populate. Fields
/// not listed (rdev, blocks, ...) are filled in by the C trampoline
/// with sensible defaults.
#[derive(Debug, Clone, Copy)]
pub struct FileAttr {
    /// `S_IFDIR | 0o700` for directories, `S_IFREG | 0o600` for files.
    /// The trampoline does NOT set the type bits for you, callers must
    /// OR them in. `S_IFREG` and `S_IFDIR` are exposed as `u32`
    /// constants below (we don't `pub use` libc's because libc gives
    /// them as `mode_t`, which is `u16` on macOS).
    pub mode: u32,
    pub size: u64,
    pub uid: u32,
    pub gid: u32,
    /// Modification time as nanoseconds since the Unix epoch. Used for
    /// atime, mtime, and ctime, FUSE-T doesn't differentiate today.
    pub mtime_ns: u128,
    /// `nlink` value to report. 1 for files, 2 for empty directories
    /// (per POSIX convention).
    pub nlink: u32,
}

// File-type bits exposed as u32 constants. We can't `pub use libc::{
// S_IFDIR, S_IFREG }` because libc gives them as `mode_t`, and
// `mode_t` is `u16` on macOS but `u32` on Linux - a caller who
// composes `S_IFDIR | 0o700u32` would get a type-mismatch on macOS
// only. Re-exposing as u32 (the type used by `FileAttr::mode`)
// keeps the math consistent across platforms.
// `as u32` cast is mandatory: `libc::S_IFDIR` etc. are typed as
// `mode_t`, which is `u16` on macOS / FUSE-T (a `as u32` widening
// cast) and `u32` on Linux (a no-op cast). Without the cast the
// macOS build fails with E0308 mismatched types; without `u32` on
// the lhs the Linux build's caller-side arithmetic (e.g.
// `S_IFDIR | 0o700u32`) would force callers to platform-cast.
// The `as u32` is a no-op on Linux (where clippy runs) but required on
// macOS where `S_IF*` are u16; allow the resulting false-positive lint.
#[allow(clippy::unnecessary_cast)]
pub const S_IFDIR: u32 = libc::S_IFDIR as u32;
#[allow(clippy::unnecessary_cast)]
pub const S_IFREG: u32 = libc::S_IFREG as u32;
#[allow(clippy::unnecessary_cast)]
pub const S_IFLNK: u32 = libc::S_IFLNK as u32;

/// One entry as fed into the readdir callback's filler function.
#[derive(Debug)]
pub struct DirEntry {
    pub name: String,
    /// `Some` if the FS knows the inode and wants the kernel to
    /// remember it; `None` if the kernel should call lookup() to find
    /// out (slower but always safe).
    pub ino: Option<u64>,
    /// `S_IFDIR` or `S_IFREG`, matching [`FileAttr::mode`] type bits.
    pub mode: u32,
}

/// Trait implemented by the user. Each method maps 1:1 to a
/// `struct fuse_operations` callback in libfuse 2.x. All methods
/// take `&self` so the impl can use interior mutability (a Mutex
/// is fine, FUSE-T serializes callbacks per request anyway).
///
/// Default implementations return `Err(Errno::ENOSYS)`, which
/// libfuse interprets as "this operation is not supported", an
/// adapter only needs to override the methods relevant to it.
#[allow(unused_variables)]
pub trait Filesystem: Send + Sync {
    fn getattr(&self, path: &Path) -> Result<FileAttr, Errno> {
        Err(Errno::ENOSYS)
    }

    fn readdir(&self, path: &Path) -> Result<Vec<DirEntry>, Errno> {
        Err(Errno::ENOSYS)
    }

    fn open(&self, path: &Path, flags: i32) -> Result<(), Errno> {
        // libfuse 2.x default: open is OK if no error is returned. We
        // don't track per-open file handles, so a simple permission
        // check is enough. Override to enforce O_TRUNC etc.
        Ok(())
    }

    fn read(&self, path: &Path, buf: &mut [u8], offset: u64) -> Result<usize, Errno> {
        Err(Errno::ENOSYS)
    }

    fn write(&self, path: &Path, data: &[u8], offset: u64) -> Result<usize, Errno> {
        Err(Errno::ENOSYS)
    }

    fn create(&self, path: &Path, mode: u32) -> Result<(), Errno> {
        Err(Errno::ENOSYS)
    }

    fn mkdir(&self, path: &Path, mode: u32) -> Result<(), Errno> {
        Err(Errno::ENOSYS)
    }

    fn unlink(&self, path: &Path) -> Result<(), Errno> {
        Err(Errno::ENOSYS)
    }

    fn rmdir(&self, path: &Path) -> Result<(), Errno> {
        Err(Errno::ENOSYS)
    }

    fn rename(&self, from: &Path, to: &Path) -> Result<(), Errno> {
        Err(Errno::ENOSYS)
    }

    fn truncate(&self, path: &Path, size: u64) -> Result<(), Errno> {
        Err(Errno::ENOSYS)
    }

    /// POSIX `chmod(2)`. The full mode word (including file-type
    /// bits like `S_IFREG`) is passed; adapters should mask to
    /// `0o7777` before storing if they only persist permission bits.
    /// Default ENOSYS keeps backward compat for adapters that
    /// haven't opted in (libfuse maps ENOSYS to "operation not
    /// supported" and most callers like git fall back gracefully).
    fn chmod(&self, path: &Path, mode: u32) -> Result<(), Errno> {
        Err(Errno::ENOSYS)
    }

    /// POSIX `link(2)`. Create a new directory entry at `to`
    /// pointing at the inode currently named by `from`. Both paths
    /// are vault-internal POSIX paths. Default ENOSYS so adapters
    /// without hardlink support keep their pre-existing behavior;
    /// callers that get ENOSYS typically fall back to copy.
    fn link(&self, from: &Path, to: &Path) -> Result<(), Errno> {
        Err(Errno::ENOSYS)
    }

    /// POSIX `symlink(2)`. Create a symlink at `linkpath` whose
    /// stored target is `target`. **Adapters MUST sanitize `target`**
    /// before storing -- an unvalidated absolute target (e.g.
    /// `/etc/shadow`) or a relative target that escapes the vault
    /// (e.g. `../../../etc/shadow`) creates a supply-chain CVE
    /// (CVE-2018-1002200 class). LUKSbox's adapter resolves symlinks
    /// inside the vault namespace only; see `crates/luksbox-vfs/
    /// src/vfs.rs::Vfs::symlink` for the validation rules.
    fn symlink(&self, target: &Path, linkpath: &Path) -> Result<(), Errno> {
        Err(Errno::ENOSYS)
    }

    /// POSIX `readlink(2)`. Returns the bytes of the symlink target
    /// stored at `path`. `buf` is the kernel-provided destination;
    /// the impl must copy at most `buf.len()` bytes and return the
    /// number copied (the kernel uses this as the symlink length).
    fn readlink(&self, path: &Path, buf: &mut [u8]) -> Result<usize, Errno> {
        Err(Errno::ENOSYS)
    }

    fn flush(&self, path: &Path) -> Result<(), Errno> {
        Ok(())
    }

    fn fsync(&self, path: &Path, datasync: bool) -> Result<(), Errno> {
        Ok(())
    }

    fn release(&self, path: &Path) -> Result<(), Errno> {
        Ok(())
    }

    fn statfs(&self, path: &Path) -> Result<StatVfs, Errno> {
        Ok(StatVfs::default())
    }

    fn access(&self, path: &Path, mask: i32) -> Result<(), Errno> {
        // DefaultPermissions is on, so the kernel does the access check
        // from getattr-returned modes. Anything that reaches here is
        // an explicit-confirmation case, accept it.
        Ok(())
    }

    /// Called once when the FUSE session is being torn down (after the
    /// kernel has unmounted us). Use this to flush any in-memory state
    /// to disk.
    fn destroy(&self) {}
}

/// Result of [`Filesystem::statfs`]. All fields default to 0. Note
/// that returning zeros on macOS FUSE-T is NOT safe: the kernel NFS
/// client gates `WRITE3` on the server's reported `f_bavail` and
/// returns ENOSPC (visible as "not enough space" in Finder, blocking
/// every file copy) if it's zero. Adapters MUST override the default
/// and surface real numbers, typically by calling `statvfs(2)` on the
/// directory that backs the volume. See `crates/luksbox-mount/src/
/// fuse_t.rs` for the LUKSbox reference impl.
#[derive(Debug, Default, Clone, Copy)]
pub struct StatVfs {
    pub blocks: u64,
    pub bfree: u64,
    pub bavail: u64,
    pub files: u64,
    pub ffree: u64,
    pub bsize: u32,
    pub frsize: u32,
    pub namemax: u32,
}

/// Mount options. We expose only the options luksbox actually needs.
/// Adding more is straightforward, append to the args vector in the
/// macOS impl of `mount()`.
#[derive(Debug, Clone)]
pub struct MountOptions {
    /// `-o fsname=<name>`. Shows up in `mount` / `df` output.
    pub fsname: String,
    /// `-o subtype=<type>`. Shows up in `mount` / `df` output.
    pub subtype: String,
    /// `-o default_permissions`. Kernel does the permission check
    /// using the `mode` from getattr.
    pub default_permissions: bool,
    /// `-o nosuid`. Don't honor setuid bits inside the FS.
    pub nosuid: bool,
    /// `-o nodev`. Don't allow device nodes inside the FS.
    pub nodev: bool,
    /// `-o noatime`. Don't update atimes on read. We don't track
    /// atime separately anyway, but this hint tells the kernel not
    /// to bother trying.
    pub noatime: bool,
    /// `-o volname=<name>`. macOS-specific, sets the volume name in
    /// Finder.
    pub volname: Option<String>,
}

impl Default for MountOptions {
    fn default() -> Self {
        Self {
            fsname: "luksbox".to_string(),
            subtype: "luksbox".to_string(),
            default_permissions: true,
            nosuid: true,
            nodev: true,
            noatime: false,
            volname: None,
        }
    }
}

/// Mount the filesystem at `mountpoint` and run the FUSE event loop
/// until the kernel unmounts us. Blocking; spawn a thread (or
/// daemonize at the binary level) before calling if you need
/// foreground control.
///
/// On non-macOS targets this returns [`MountError::Unsupported`].
#[cfg(target_os = "macos")]
pub fn mount<F: Filesystem + 'static>(
    fs: F,
    mountpoint: &Path,
    options: &MountOptions,
) -> Result<(), MountError> {
    // Pre-flight: surface mountpoint errors here, where the caller's
    // stderr is still attached, instead of inside FUSE-T's setup
    // where they'd be eaten.
    let meta = std::fs::metadata(mountpoint)?;
    if !meta.is_dir() {
        return Err(MountError::InvalidMountpoint {
            path: mountpoint.display().to_string(),
            reason: "not a directory".into(),
        });
    }
    // Validate every option string BEFORE we format the comma-joined
    // -o list. `validate_option` rejects bytes that would let a
    // string smuggle additional `-o` options (defense in depth, the
    // built-in defaults are safe but a future API extension might
    // take user input).
    validate_option("fsname", &options.fsname)?;
    validate_option("subtype", &options.subtype)?;
    if let Some(volname) = &options.volname {
        validate_option("volname", volname)?;
    }
    ops::run_mount(fs, mountpoint, options)
}

#[cfg(not(target_os = "macos"))]
pub fn mount<F: Filesystem + 'static>(
    _fs: F,
    _mountpoint: &Path,
    _options: &MountOptions,
) -> Result<(), MountError> {
    Err(MountError::Unsupported)
}

/// Unmount a FUSE-T volume. Wraps `umount` (FUSE-T's volumes show up
/// as NFS mounts, so the system `umount` is the right tool, no
/// equivalent of `fusermount3 -u` is needed).
#[cfg(target_os = "macos")]
pub fn unmount(mountpoint: &Path) -> Result<(), MountError> {
    let status = std::process::Command::new("/sbin/umount")
        .arg(mountpoint)
        .status()
        .map_err(MountError::Io)?;
    if !status.success() {
        return Err(MountError::Mount(format!(
            "/sbin/umount {} returned {}",
            mountpoint.display(),
            status
        )));
    }
    Ok(())
}

#[cfg(not(target_os = "macos"))]
pub fn unmount(_mountpoint: &Path) -> Result<(), MountError> {
    Err(MountError::Unsupported)
}
