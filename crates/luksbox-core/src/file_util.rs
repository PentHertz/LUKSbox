// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Penthertz <https://penthertz.com> (https://x.com/PentHertz)

//! Filesystem helpers for creating files that hold encrypted material.
//!
//! Round 9E (audit follow-up) introduced these helpers to enforce a
//! single permission contract for every file LUKSbox writes:
//!
//!   **Owner-only (mode 0600 on POSIX) regardless of user umask.**
//!
//! Why: the user's `umask` on most Linux distros defaults to `022`,
//! which yields world-readable files. The `.lbx` / `.hdr` / `.kyber`
//! / `.hybrid` / `.anchor` files all hold material an offline
//! attacker could use:
//!
//! - `.lbx` / `.hdr`: wrapped MVK ciphertext, KDF salt, AEAD nonce.
//!   A reader can offline-brute-force the passphrase keyslot, rate-
//!   limited by Argon2id (about 2 g/s on commodity CPUs at our
//!   defaults). Even though it's encrypted, restricting access to
//!   the owner removes the offline-attack surface entirely from
//!   non-owner users on multi-user systems.
//! - `.kyber`: passphrase-encrypted ML-KEM seed. Same rationale.
//! - `.hybrid`: ML-KEM public key + ciphertext. Doesn't leak the
//!   private side, but no reason to make it world-readable either.
//! - `.anchor`: HMAC tag under an MVK-derived key. Reading it
//!   doesn't break the vault (forging requires the MVK), but
//!   tightening the permission costs nothing.
//!
//! Without these helpers, `OpenOptions::new().create_new(true).open()`
//! produces a file with mode `(0666 & ~umask)`, which is `0644` on
//! a default `022`-umask system - world-readable.
//!
//! Windows: file mode bits don't apply; files inherit the parent
//! directory's NTFS ACL. The user-home default ACL is owner-only,
//! so the practical outcome matches POSIX. We don't override the
//! ACL explicitly (would require windows-acl crate dependency); if
//! a user creates a vault under a directory with permissive ACLs,
//! they're explicitly opting into that exposure.

use std::fs::{File, OpenOptions};
use std::io;
use std::path::{Path, PathBuf};
use std::time::SystemTime;

#[cfg(unix)]
use std::os::unix::fs::OpenOptionsExt;

/// File mode for newly-created LUKSbox files (POSIX). `rw-------`.
#[cfg(unix)]
pub const SECURE_FILE_MODE: u32 = 0o600;

/// Directory mode for LUKSbox-created directories that hold decrypted
/// plaintext (extraction targets). `rwx------`. Unix only; Windows uses
/// inherited ACLs from the parent.
#[cfg(unix)]
pub const SECURE_DIR_MODE: u32 = 0o700;

/// Create a new file with the LUKSbox secure permission contract.
///
/// On Unix: equivalent to `open(path, O_RDWR | O_CREAT | O_EXCL, 0600)`.
/// The `0600` mode is set BEFORE any data is written, so even a
/// concurrent reader can't observe the file in a wider-permission
/// state.
///
/// On Windows: `OpenOptions::new().read(true).write(true).create_new(true)`.
/// File ACL is inherited from the parent directory.
///
/// `create_new(true)` makes this fail if the path already exists -
/// matches LUKSbox's anti-clobber policy across the codebase.
pub fn secure_create_new(path: &Path) -> io::Result<File> {
    let mut o = OpenOptions::new();
    o.read(true).write(true).create_new(true);
    #[cfg(unix)]
    o.mode(SECURE_FILE_MODE);
    o.open(path)
}

/// Open an EXISTING file with read-only access, refusing to follow
/// a symlink at the final path component **when
/// `LUKSBOX_NO_FOLLOW_SYMLINKS=1` is set in the environment**.
///
/// Use this for the kind-dispatch / unlock-prescan header peek paths
/// (CLI `open_container`, GUI ops's hybrid/TPM unlock pre-flights)
/// where the same `LUKSBOX_NO_FOLLOW_SYMLINKS` opt-in that
/// `open_rw_checked` honors needs to apply BEFORE the full container
/// open does its own check. Without this preflight, a symlink in the
/// vault path could be silently followed by the prescan even though
/// the final open would later reject it -- and the prescan can trigger
/// FIDO2 / TPM prompts on attacker-controlled header data in the
/// interim, which is the nuisance the policy gate is meant to prevent.
///
/// Default behaviour (env var unset) is to follow symlinks, matching
/// `File::open`: legitimate users who symlink their vault path don't
/// pay any cost.
pub fn open_existing_read_no_follow_policy(path: &Path) -> io::Result<File> {
    if std::env::var_os("LUKSBOX_NO_FOLLOW_SYMLINKS").is_some() {
        // Stat without following so the check sees the symlink
        // itself, not its target.
        match std::fs::symlink_metadata(path) {
            Ok(m) if m.file_type().is_symlink() => {
                return Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    format!(
                        "path {} is a symlink and LUKSBOX_NO_FOLLOW_SYMLINKS=1 is set",
                        path.display()
                    ),
                ));
            }
            _ => {}
        }
    }
    File::open(path)
}

/// Open an EXISTING file with read+write access, refusing to follow
/// a symlink (or reparse point, on Windows) at the final path
/// component AND refusing anything that isn't a regular file.
///
/// Use this for destructive operations on a user-named path (panic
/// destroy, in-place overwrite, etc.) where the TOCTOU between a
/// `path.is_file()` check and a subsequent `OpenOptions::open(path)`
/// would otherwise let an attacker with write access to the parent
/// directory swap in a symlink -- and have our random-bytes
/// overwrite land in /etc/shadow or some other attacker-chosen
/// target.
///
/// On Unix: `O_NOFOLLOW` makes `open(2)` fail with `ELOOP` if the
/// final path component is a symlink. The metadata check after open
/// catches non-regular files (FIFOs, sockets, block devices) that
/// `O_NOFOLLOW` doesn't reject -- those would silently swallow the
/// write or worse.
///
/// On Windows: `FILE_FLAG_OPEN_REPARSE_POINT` (0x00200000) opens
/// the reparse point itself rather than following it; the
/// `FILE_ATTRIBUTE_REPARSE_POINT` (0x00000400) attribute check
/// then refuses if the opened thing is a reparse point.
/// `FILE_ATTRIBUTE_DIRECTORY` (0x00000010) check refuses
/// directories.
///
/// Compare against `secure_create_or_truncate` which is for write
/// paths that CREATE (or replace) a file -- this helper is for
/// destructive writes to a file the caller knows already exists.
pub fn secure_open_existing_no_follow(path: &Path) -> io::Result<File> {
    #[cfg(unix)]
    {
        let f = OpenOptions::new()
            .read(true)
            .write(true)
            .custom_flags(libc::O_NOFOLLOW)
            .open(path)?;
        let meta = f.metadata()?;
        if !meta.is_file() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "refusing to operate on non-regular file (directory / FIFO / socket / device)",
            ));
        }
        Ok(f)
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::{MetadataExt, OpenOptionsExt};
        // FILE_FLAG_OPEN_REPARSE_POINT = 0x00200000.
        let f = OpenOptions::new()
            .read(true)
            .write(true)
            .custom_flags(0x0020_0000)
            .open(path)?;
        let attrs = f.metadata()?.file_attributes();
        // FILE_ATTRIBUTE_REPARSE_POINT
        if attrs & 0x0000_0400 != 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "refusing to operate on a reparse point (symlink / junction)",
            ));
        }
        // FILE_ATTRIBUTE_DIRECTORY
        if attrs & 0x0000_0010 != 0 {
            return Err(io::Error::new(
                io::ErrorKind::IsADirectory,
                "refusing to operate on a directory",
            ));
        }
        Ok(f)
    }
    #[cfg(not(any(unix, windows)))]
    {
        let _ = path;
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "secure_open_existing_no_follow: platform not supported",
        ))
    }
}

/// Like `secure_create_new` but allows opening an existing file
/// (truncate-then-write semantics). Used for sidecar updates AND for
/// extracting plaintext from a vault to a host path (`luksbox get`,
/// wizard extract, GUI extract). `0600` is re-applied via explicit
/// chmod after open to handle the case where the file existed with a
/// wider mode (e.g. user manually chmod'd it).
///
/// On Unix, `O_NOFOLLOW` is added so that if the destination path
/// already exists as a symlink, `open` fails with `ELOOP` instead of
/// following the link and writing the vault contents into the link
/// target. Without this guard, an attacker who can pre-create a
/// symlink at the destination (e.g. `/tmp/output.txt` -> `/etc/passwd`)
/// would have arbitrary file overwrite if `luksbox get` runs as a user
/// with write permission to the target, a privilege-escalation
/// primitive when invoked as root, an integrity-tampering primitive
/// otherwise. Users who genuinely want to extract through a symlink
/// can resolve it manually first (`readlink -f`) or remove the link.
/// `O_NOFOLLOW` only refuses the FINAL path component; intermediate
/// directory symlinks are still followed (refusing those would break
/// legitimate setups like `~/extracted -> /mnt/usb/extracted`).
/// Deny-list helper for `secure_create_or_truncate` (Round 12
/// R12-09). Returns true if the canonical path is, or sits under, a
/// system directory we never want plaintext written into via a
/// root-privileged extract. Mirrors the spirit of
/// `cmd_mount`'s `validate_mountpoint_safety` in the CLI.
#[cfg(unix)]
fn is_denied_extract_root(canonical_parent: &Path) -> bool {
    const DENIED_PREFIXES: &[&str] = &[
        "/etc",
        "/usr",
        "/bin",
        "/sbin",
        "/boot",
        "/sys",
        "/proc",
        "/dev",
        "/System",                                  // macOS
        "/Library/System",                          // macOS
        "/Library/Preferences/SystemConfiguration", // macOS
    ];
    let s = canonical_parent.to_string_lossy();
    DENIED_PREFIXES
        .iter()
        .any(|p| s == *p || s.starts_with(&format!("{p}/")))
}

pub fn secure_create_or_truncate(path: &Path) -> io::Result<File> {
    // Round 13 fix R13-01: on Unix, perform the create+truncate through
    // an `openat(parent_dir_fd, basename, ...)` call so an attacker who
    // can swap an INTERMEDIATE directory along the path cannot redirect
    // the extraction. The legacy Round 12 path canonicalized the parent
    // and then re-opened by path with `O_NOFOLLOW` -- which only checks
    // the final component for symlinks. An attacker controlling, e.g.,
    // `/tmp/extract/` could replace it with a symlink to `/etc/` after
    // canonicalize-time but before the final open, redirecting the
    // 0600 write into `/etc/<basename>`.
    //
    // New flow on Unix:
    //   1. Decompose path into (parent_dir, basename).
    //   2. Canonicalize parent_dir (resolves all intermediate
    //      symlinks once, with the kernel handling races at each
    //      step). On the resolved path there are no symlinks left.
    //   3. Re-run the system-directory deny-list against the
    //      canonical parent.
    //   4. Open the canonical parent as a `O_DIRECTORY` fd. If an
    //      attacker swapped a directory on the path between
    //      canonicalize and open, this open fails (directory missing)
    //      or returns an fd that doesn't point at the original
    //      directory; the basename openat will then fail loudly.
    //   5. `openat(parent_fd, basename, O_RDWR|O_CREAT|O_TRUNC|O_NOFOLLOW, 0600)`.
    //      `O_NOFOLLOW` on the final component refuses a symlinked
    //      basename. The parent_fd binding means the basename is
    //      resolved against the directory we already inspected,
    //      not against the path we got from the caller.
    //
    // Residual race: between (2) canonicalize and (4) parent_fd
    // open, an attacker who can write to one of canon_parent's
    // ancestors can swap canon_parent itself. Closing this fully
    // requires `openat2()` with `RESOLVE_NO_SYMLINKS|RESOLVE_BENEATH`
    // (Linux >= 5.6) and is left as a future enhancement. The
    // realistic attacker who could win that race already has write
    // access to a system-controlled ancestor, which is a much
    // bigger privilege than redirecting one extraction.
    //
    // Windows: keep the existing `FILE_FLAG_OPEN_REPARSE_POINT` +
    // `FILE_ATTRIBUTE_REPARSE_POINT` rejection. The intermediate-
    // junction problem on Windows is tracked separately under R12-15.
    #[cfg(unix)]
    {
        use std::ffi::CString;
        use std::os::unix::ffi::OsStrExt;
        use std::os::unix::io::FromRawFd;

        let parent = path
            .parent()
            .filter(|p| !p.as_os_str().is_empty())
            .unwrap_or_else(|| Path::new("."));
        let basename = path.file_name().ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "extraction path has no file name",
            )
        })?;

        let canon = parent.canonicalize().map_err(|e| {
            io::Error::new(
                e.kind(),
                format!("canonicalizing extraction parent {}: {e}", parent.display()),
            )
        })?;
        if is_denied_extract_root(&canon) {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                format!(
                    "refusing to write under a system directory: {} \
                     (parent symlink may have redirected the extraction; \
                     resolve the path manually with readlink -f)",
                    canon.display()
                ),
            ));
        }

        // Open the canonical parent. `O_DIRECTORY` rejects non-dir
        // targets (TOCTOU defense: the canon was a dir at
        // canonicalize time; if it isn't now, the open fails).
        let parent_cstr = CString::new(canon.as_os_str().as_bytes()).map_err(|_| {
            io::Error::new(io::ErrorKind::InvalidInput, "parent path contains NUL byte")
        })?;
        // SAFETY: parent_cstr is a valid NUL-terminated C string and
        // outlives the open() call.
        let parent_fd =
            unsafe { libc::open(parent_cstr.as_ptr(), libc::O_RDONLY | libc::O_DIRECTORY) };
        if parent_fd < 0 {
            return Err(io::Error::last_os_error());
        }
        // Make sure parent_fd is closed on every return path.
        // SAFETY: parent_fd is a valid fd we just opened; the wrapper
        // takes ownership.
        let parent_owned = unsafe { ParentDirFd::from_raw(parent_fd) };

        let bn_cstr = CString::new(basename.as_bytes()).map_err(|_| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "extraction basename contains NUL",
            )
        })?;
        // openat(2): O_NOFOLLOW refuses a symlinked basename.
        // SAFETY: parent_owned.raw() is a valid open fd; bn_cstr is
        // a valid NUL-terminated C string outliving the call.
        let fd = unsafe {
            libc::openat(
                parent_owned.raw(),
                bn_cstr.as_ptr(),
                libc::O_RDWR | libc::O_CREAT | libc::O_TRUNC | libc::O_NOFOLLOW | libc::O_CLOEXEC,
                SECURE_FILE_MODE as libc::c_uint,
            )
        };
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: openat returned a fresh fd; File takes ownership.
        let f = unsafe { File::from_raw_fd(fd) };

        // If the file pre-existed with a wider mode, openat's `mode`
        // arg only applies on creation. Force-narrow via fchmod
        // (operates on the open fd, no path traversal, so no TOCTOU
        // window vs. the original `std::fs::set_permissions(path)`).
        // SAFETY: fd is owned by `f`; AsRawFd reads it safely.
        use std::os::unix::io::AsRawFd as _;
        let rc = unsafe { libc::fchmod(f.as_raw_fd(), SECURE_FILE_MODE as libc::mode_t) };
        if rc != 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(f)
    }

    // Non-Unix path: preserve the prior Windows-only flow.
    #[cfg(not(unix))]
    {
        let mut o = OpenOptions::new();
        o.read(true).write(true).create(true).truncate(true);
        #[cfg(windows)]
        {
            use std::os::windows::fs::OpenOptionsExt;
            // FILE_FLAG_OPEN_REPARSE_POINT = 0x00200000.
            o.custom_flags(0x0020_0000);
        }
        let f = o.open(path)?;
        #[cfg(windows)]
        {
            use std::os::windows::fs::MetadataExt as _;
            // FILE_ATTRIBUTE_REPARSE_POINT = 0x00000400
            let attrs = f.metadata()?.file_attributes();
            if attrs & 0x0000_0400 != 0 {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "extraction destination is a reparse point (symlink / junction); refused",
                ));
            }
        }
        Ok(f)
    }
}

/// Owned wrapper around a raw parent-directory file descriptor for the
/// `secure_create_or_truncate` Unix path. Closes the fd on drop; the
/// only operation we ever do with it is `openat()`, which doesn't move
/// ownership.
#[cfg(unix)]
struct ParentDirFd(libc::c_int);

#[cfg(unix)]
impl ParentDirFd {
    /// SAFETY: caller must pass a freshly-opened, non-negative fd.
    /// Ownership transfers to the wrapper.
    unsafe fn from_raw(fd: libc::c_int) -> Self {
        Self(fd)
    }
    fn raw(&self) -> libc::c_int {
        self.0
    }
}

#[cfg(unix)]
impl Drop for ParentDirFd {
    fn drop(&mut self) {
        // SAFETY: `from_raw` invariant: we own the fd.
        unsafe {
            libc::close(self.0);
        }
    }
}

/// Recursive directory creation with the LUKSbox secure permission
/// contract. Behaves like `fs::create_dir_all` but every directory
/// component this call newly creates is mode 0700 on Unix
/// (`SECURE_DIR_MODE`), regardless of the process umask.
///
/// Pre-existing directories on the path are left untouched (we don't
/// chmod the user's `$HOME` to 0700 because they passed
/// `~/extract/foo` as an extraction target). Only the components this
/// call creates are narrowed.
///
/// On Windows, falls back to plain `fs::create_dir_all`; ACL hygiene
/// is inherited from the parent.
pub fn secure_create_dir_all(path: &Path) -> io::Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        let mut b = std::fs::DirBuilder::new();
        b.recursive(true).mode(SECURE_DIR_MODE);
        b.create(path)
    }
    #[cfg(not(unix))]
    {
        std::fs::create_dir_all(path)
    }
}

/// Make the directory entry for `path` durable after a create, remove, or
/// rename. POSIX requires syncing the parent directory separately from the
/// file itself; syncing only the file does not guarantee the renamed entry
/// survives power loss.
///
/// On Windows the same guarantee is delivered by opening a handle to the
/// parent directory with `FILE_FLAG_BACKUP_SEMANTICS` (CreateFile rejects
/// directory paths without it) and calling `FlushFileBuffers` via
/// `sync_all()`. Other non-Unix targets (none built today) fall through to
/// a no-op rather than silently breaking the rename.
#[cfg(windows)]
fn is_windows_dir_sync_skippable(e: &io::Error) -> bool {
    // ERROR_ACCESS_DENIED (5), ERROR_INVALID_FUNCTION (1),
    // ERROR_INVALID_HANDLE (6), ERROR_NOT_SUPPORTED (50): all observed
    // when FlushFileBuffers is called on a directory handle without
    // SeManageVolumePrivilege, or on filesystems (FAT/exFAT, network
    // shares) that don't support the operation. Treat them as
    // "Windows can't do the equivalent of fsync(dirfd) here", not as
    // a real failure of the write itself.
    matches!(
        e.kind(),
        io::ErrorKind::PermissionDenied | io::ErrorKind::InvalidInput | io::ErrorKind::Unsupported
    ) || matches!(e.raw_os_error(), Some(1) | Some(5) | Some(6) | Some(50))
}

pub fn sync_parent_dir(path: &Path) -> io::Result<()> {
    fn parent_for(path: &Path) -> &Path {
        path.parent()
            .filter(|p| !p.as_os_str().is_empty())
            .unwrap_or_else(|| Path::new("."))
    }
    #[cfg(unix)]
    {
        let dir = File::open(parent_for(path))?;
        dir.sync_all()
    }
    #[cfg(windows)]
    {
        use std::fs::OpenOptions;
        use std::os::windows::fs::OpenOptionsExt;
        // FILE_FLAG_BACKUP_SEMANTICS (winnt.h: 0x02000000) is the documented
        // flag that lets `CreateFileW` open a directory handle. Without it,
        // open() on a directory path returns ERROR_ACCESS_DENIED.
        //
        // `FlushFileBuffers` (what Rust's `sync_all` calls) requires
        // `GENERIC_WRITE` on the handle, AND for *directory* handles
        // additionally requires `SeManageVolumePrivilege` on many
        // configurations -- which non-admin users do not have. That
        // means the original `read(true)`-only handle would always
        // fail with `ERROR_ACCESS_DENIED`, and even `read(true).write(true)`
        // fails for a standard user on most NTFS volumes.
        //
        // Make it best-effort on Windows: open with write access if we
        // can, try to flush, and swallow `PermissionDenied` /
        // `InvalidInput` / "not supported" errors. The rename has
        // already been committed to the NTFS journal via `MoveFileExW`,
        // which is what an interactive Windows tool can realistically
        // promise without elevating. The Unix branch keeps its strict
        // fsync-the-directory contract.
        const FILE_FLAG_BACKUP_SEMANTICS: u32 = 0x0200_0000;
        let opened = OpenOptions::new()
            .read(true)
            .write(true)
            .custom_flags(FILE_FLAG_BACKUP_SEMANTICS)
            .open(parent_for(path))
            .or_else(|_| {
                OpenOptions::new()
                    .read(true)
                    .custom_flags(FILE_FLAG_BACKUP_SEMANTICS)
                    .open(parent_for(path))
            });
        let dir = match opened {
            Ok(d) => d,
            Err(e) if is_windows_dir_sync_skippable(&e) => return Ok(()),
            Err(e) => return Err(e),
        };
        match dir.sync_all() {
            Ok(()) => Ok(()),
            Err(e) if is_windows_dir_sync_skippable(&e) => Ok(()),
            Err(e) => Err(e),
        }
    }
    #[cfg(not(any(unix, windows)))]
    {
        let _ = path;
        Ok(())
    }
}

/// Build a `<path>.tmp.<16hex>` neighbour path, write `bytes` to it
/// with `secure_create_new` (mode 0600 on POSIX), fsync the file, and
/// return the temp path. The caller is responsible for commit
/// (rename or hard-link) and cleanup on failure.
fn write_secure_tmp_for(path: &Path, bytes: &[u8]) -> io::Result<PathBuf> {
    use std::io::Write as _;

    let mut rand_bytes = [0u8; 8];
    use rand_core::{OsRng, RngCore};
    OsRng
        .try_fill_bytes(&mut rand_bytes)
        .map_err(|e| io::Error::other(format!("rng: {e}")))?;
    let suffix: String = rand_bytes.iter().map(|b| format!("{b:02x}")).collect();

    let mut tmp_path = path.to_path_buf();
    let new_name = match path.file_name() {
        Some(n) => format!("{}.tmp.{}", n.to_string_lossy(), suffix),
        None => format!("luksbox.tmp.{suffix}"),
    };
    tmp_path.set_file_name(new_name);

    let mut f = secure_create_new(&tmp_path)?;
    f.write_all(bytes)?;
    f.flush()?;
    f.sync_all()?;
    drop(f);
    Ok(tmp_path)
}

/// Atomic, owner-only file replacement: write `bytes` to a unique
/// `<path>.tmp.<rand>` neighbour with mode 0600, fsync it, then
/// `rename(2)` over `path`, then fsync the parent directory. Replaces
/// the unsafe pattern of
/// `fs::write(tmp); fs::rename(tmp, path)` which produces tmp
/// files with `0644` permissions during the window before rename.
///
/// Replace semantics: if `path` exists it will be overwritten. For
/// no-clobber semantics (refuses to overwrite, and refuses to follow
/// a pre-existing symlink at `path`), use `atomic_secure_create_new`.
pub fn atomic_secure_write(path: &Path, bytes: &[u8]) -> io::Result<()> {
    let tmp_path = write_secure_tmp_for(path, bytes)?;
    // POSIX rename is atomic on the same filesystem. Windows uses
    // MoveFileExW with MOVEFILE_REPLACE_EXISTING.
    if let Err(e) = std::fs::rename(&tmp_path, path) {
        let _ = std::fs::remove_file(&tmp_path);
        return Err(e);
    }
    sync_parent_dir(path)
}

/// Atomic, owner-only file creation that **refuses to overwrite**.
///
/// Why a separate API: `atomic_secure_write` uses `rename(2)` /
/// `MoveFileExW(REPLACE_EXISTING)` which silently overwrites the
/// target -- and on both platforms follows a symlink at the target,
/// writing through to whatever the symlink resolves to. For
/// create-only callers (Kyber seed file, initial anchor) that's a
/// TOCTOU privilege-escalation primitive: an attacker who can plant
/// a symlink at the target path between a `path.exists()` pre-check
/// and the rename redirects the write into an attacker-chosen file.
///
/// Commit step:
/// - POSIX: `link(tmp, path)` -- `link(2)` fails with `EEXIST` if
///   `path` exists for any reason (regular file, symlink, anything),
///   and `link` itself never follows a symlink at the destination.
///   On success we `unlink(tmp)` so only `path` remains.
/// - Windows: `MoveFileExW(tmp, path, 0)` -- without
///   `MOVEFILE_REPLACE_EXISTING` this fails with `ERROR_ALREADY_EXISTS`
///   if `path` exists, including when `path` is a reparse point /
///   symlink.
///
/// On any failure after the temp file is written, the temp is
/// best-effort cleaned up so a retry doesn't trip its own
/// `create_new(true)` guard.
pub fn atomic_secure_create_new(path: &Path, bytes: &[u8]) -> io::Result<()> {
    let tmp_path = write_secure_tmp_for(path, bytes)?;
    match commit_create_new(&tmp_path, path) {
        Ok(()) => {
            // POSIX `link(2)` leaves tmp_path pointing at the same
            // inode; unlink so only `path` survives. On Windows,
            // `MoveFileExW` already moved the entry; tmp_path is gone.
            #[cfg(unix)]
            {
                let _ = std::fs::remove_file(&tmp_path);
            }
            sync_parent_dir(path)
        }
        Err(e) => {
            let _ = std::fs::remove_file(&tmp_path);
            Err(e)
        }
    }
}

#[cfg(unix)]
fn commit_create_new(tmp: &Path, dst: &Path) -> io::Result<()> {
    // `std::fs::hard_link` is `link(2)` on POSIX. `link` fails with
    // EEXIST if `dst` exists (any file type, including symlinks), and
    // never follows a symlink at `dst`. tmp and dst sit in the same
    // directory so they're guaranteed on the same filesystem.
    std::fs::hard_link(tmp, dst)
}

#[cfg(windows)]
fn commit_create_new(tmp: &Path, dst: &Path) -> io::Result<()> {
    // `MoveFileExW` without `MOVEFILE_REPLACE_EXISTING` (flags=0)
    // fails with `ERROR_ALREADY_EXISTS` if `dst` exists for any
    // reason -- including when `dst` is a reparse point / symlink to
    // somewhere else. Same direct-extern pattern as
    // `secret_box::VirtualLock`, no extra crate dep.
    use std::os::windows::ffi::OsStrExt;
    fn to_wide(p: &Path) -> Vec<u16> {
        p.as_os_str()
            .encode_wide()
            .chain(std::iter::once(0))
            .collect()
    }
    let src = to_wide(tmp);
    let dst_w = to_wide(dst);
    unsafe extern "system" {
        fn MoveFileExW(src: *const u16, dst: *const u16, flags: u32) -> i32;
    }
    let rc = unsafe { MoveFileExW(src.as_ptr(), dst_w.as_ptr(), 0) };
    if rc == 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}

#[cfg(not(any(unix, windows)))]
fn commit_create_new(tmp: &Path, dst: &Path) -> io::Result<()> {
    let _ = (tmp, dst);
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "atomic_secure_create_new: platform not supported",
    ))
}

// ----------------------------------------------------------------------
// Orphan tempfile cleanup (Round 10, follow-up to 9E)
// ----------------------------------------------------------------------
//
// LUKSbox writes sidecars (anchor, hybrid, header) atomically:
//
//   1. write `<base>.tmp.<16hex>` with mode 0600
//   2. fsync
//   3. rename(tmp, base)
//
// MVK rotation in inline mode writes to `<base>.rotating` and renames at
// commit. If the process crashes (or the host loses power) between
// steps 1 and 3, the temp file is left behind:
//
//   - `.tmp.<16hex>` orphans: contain a partial / fully-written but un-
//     renamed copy of a sidecar. Safe to delete (the rename never landed
//     so the canonical file is either the previous version or absent).
//   - `.rotating` orphans: the in-progress rotation's working copy. May
//     be the ONLY surviving copy if the rotation crashed AFTER the
//     vault was substantially re-encrypted; never auto-delete. Surface
//     to the user instead.
//
// `find_orphan_tempfiles` enumerates both kinds for a given vault path
// without touching disk state. Callers (CLI `cleanup-orphans` subcommand,
// GUI startup hook in future) decide what to do with the result.

/// Why a tempfile is considered an orphan.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OrphanKind {
    /// `<base>.tmp.<16hex>` - leftover from a crashed `atomic_secure_write`.
    /// Safe to delete; contents are an aborted partial sidecar.
    AtomicWriteTmp,
    /// `<base>.rotating` - leftover from a crashed `begin_atomic_rotation`.
    /// May be the only surviving copy of an in-progress MVK rotation;
    /// **never auto-delete**. Surface to the user with strong wording.
    RotationTmp,
}

/// One orphan tempfile found next to a vault.
#[derive(Debug, Clone)]
pub struct OrphanTempfile {
    pub path: PathBuf,
    pub kind: OrphanKind,
    pub size: u64,
    pub modified: Option<SystemTime>,
}

/// Scan the parent directory of `vault_path` for tempfiles that match
/// the conventions used by `atomic_secure_write` and the inline-mode
/// rotation flow.
///
/// Returns an empty vec if the parent directory doesn't exist (e.g.
/// the vault path itself doesn't exist). Returns an `io::Error` only
/// if `read_dir` fails for a reason other than NotFound (permission
/// denied, etc.).
///
/// Matching rules:
///
/// - `<vault_filename>.tmp.<exactly-16-lowercase-hex>` -> AtomicWriteTmp
/// - `<vault_filename>.rotating` (exact suffix) -> RotationTmp
/// - Also matches sidecar tempfiles where the `<vault_filename>` is
///   replaced by any of the conventional sidecar basenames:
///     * `<vault_filename>.hdr.tmp.<16hex>`
///     * `<vault_filename>.anchor.tmp.<16hex>`
///     * `<vault_filename>.hybrid.tmp.<16hex>`
///     * `<vault_filename>.kyber.tmp.<16hex>`
///
///   We don't enforce the sidecar substring strictly; the
///   `<vault_filename>` prefix + `.tmp.<16hex>` suffix is sufficient.
pub fn find_orphan_tempfiles(vault_path: &Path) -> io::Result<Vec<OrphanTempfile>> {
    let dir = match vault_path.parent() {
        Some(d) if !d.as_os_str().is_empty() => d.to_path_buf(),
        _ => PathBuf::from("."),
    };
    let vault_name = match vault_path.file_name().and_then(|n| n.to_str()) {
        Some(n) => n.to_owned(),
        // Non-UTF8 vault names: skip orphan scan (no false-positive
        // matches possible without a comparable string form).
        None => return Ok(Vec::new()),
    };

    let read = match std::fs::read_dir(&dir) {
        Ok(it) => it,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(e) => return Err(e),
    };

    let mut out = Vec::new();
    for entry in read.flatten() {
        let name = match entry.file_name().into_string() {
            Ok(s) => s,
            Err(_) => continue, // non-UTF8 names can't match our prefix
        };
        // Don't include the vault file itself (hits when callers pass a
        // vault path whose name happens to overlap a tmp suffix).
        if name == vault_name {
            continue;
        }
        let kind = if let Some(stripped) = name.strip_prefix(&vault_name) {
            classify_tempfile_suffix(stripped)
        } else {
            None
        };
        let Some(kind) = kind else { continue };
        let path = entry.path();
        let meta = entry.metadata().ok();
        let size = meta.as_ref().map(|m| m.len()).unwrap_or(0);
        let modified = meta.as_ref().and_then(|m| m.modified().ok());
        out.push(OrphanTempfile {
            path,
            kind,
            size,
            modified,
        });
    }
    // Stable order so test output + CLI listing are deterministic.
    out.sort_by(|a, b| a.path.cmp(&b.path));
    Ok(out)
}

/// Inspect the suffix that follows the vault filename. Returns the
/// orphan kind if recognized, `None` otherwise. Pulled out as a free
/// fn so it's unit-testable independently of the disk.
fn classify_tempfile_suffix(suffix: &str) -> Option<OrphanKind> {
    // `.rotating` exact suffix match - used for both the vault itself
    // and (theoretically) any sidecar; either way it's a rotation tmp.
    if suffix == ".rotating" {
        return Some(OrphanKind::RotationTmp);
    }
    // `.tmp.<16hex>` - `atomic_secure_write` random suffix is exactly
    // 8 random bytes formatted as `{:02x}` -> 16 lowercase hex chars.
    // Allow an optional sidecar segment between the vault name and
    // `.tmp` (e.g. `.hdr`, `.anchor`, `.hybrid`, `.kyber`).
    let after_sidecar = match suffix.find(".tmp.") {
        Some(idx) => &suffix[idx + ".tmp.".len()..],
        None => return None,
    };
    if after_sidecar.len() == 16
        && after_sidecar
            .bytes()
            .all(|b| b.is_ascii_hexdigit() && (b.is_ascii_digit() || b.is_ascii_lowercase()))
    {
        return Some(OrphanKind::AtomicWriteTmp);
    }
    None
}

/// Delete the given `AtomicWriteTmp` orphans. Skips `RotationTmp`
/// entries silently - caller must surface those to the user
/// separately and never auto-delete them.
///
/// Returns `(deleted_paths, errors)` so callers can show a per-file
/// report. Deletion of one orphan failing does not prevent the next
/// from being attempted.
pub fn delete_atomic_write_orphans(
    orphans: &[OrphanTempfile],
) -> (Vec<PathBuf>, Vec<(PathBuf, io::Error)>) {
    let mut deleted = Vec::new();
    let mut errors = Vec::new();
    for o in orphans {
        if o.kind != OrphanKind::AtomicWriteTmp {
            continue;
        }
        match std::fs::remove_file(&o.path) {
            Ok(_) => deleted.push(o.path.clone()),
            Err(e) => errors.push((o.path.clone(), e)),
        }
    }
    (deleted, errors)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[cfg(unix)]
    fn mode_of(path: &Path) -> u32 {
        use std::os::unix::fs::PermissionsExt;
        std::fs::metadata(path).unwrap().permissions().mode() & 0o7777
    }

    #[cfg(unix)]
    #[test]
    fn secure_create_new_yields_0600_under_022_umask() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("vault.lbx");

        // Force a permissive umask so a non-secure helper would
        // produce 0644. If our helper doesn't override, this test
        // fails.
        unsafe {
            libc::umask(0o022);
        }

        let _f = secure_create_new(&path).unwrap();
        assert_eq!(
            mode_of(&path),
            0o600,
            "secure_create_new must produce mode 0600 even under umask 022"
        );
    }

    #[cfg(unix)]
    #[test]
    fn secure_create_or_truncate_narrows_existing_wide_file() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("preexisting.lbx");

        // Create a pre-existing file with mode 0644 (the broken case).
        std::fs::write(&path, b"old contents").unwrap();
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
        assert_eq!(mode_of(&path), 0o644);

        // Re-open via the helper. Mode must narrow to 0600.
        let _f = secure_create_or_truncate(&path).unwrap();
        assert_eq!(
            mode_of(&path),
            0o600,
            "secure_create_or_truncate must narrow pre-existing 0644 -> 0600"
        );
    }

    /// Symlink-target overwrite guard for plaintext extraction. If the
    /// destination path already exists as a symlink (e.g. attacker pre-
    /// created `/tmp/output` -> `/etc/passwd`), `secure_create_or_truncate`
    /// must fail with `ELOOP` rather than truncate the symlink target
    /// and write vault contents into it. The legitimate "symlink in an
    /// intermediate dir" case (e.g. `~/extracted -> /mnt/usb/extracted`,
    /// then a regular file under it) is unaffected, only the FINAL
    /// component is checked.
    #[cfg(unix)]
    #[test]
    fn secure_create_or_truncate_refuses_symlink_destination() {
        let dir = tempdir().unwrap();
        let target_real = dir.path().join("victim.txt");
        std::fs::write(&target_real, b"sensitive contents").unwrap();
        let link = dir.path().join("attacker.symlink");
        std::os::unix::fs::symlink(&target_real, &link).unwrap();

        let err = secure_create_or_truncate(&link)
            .expect_err("opening a symlink for write+truncate must fail");
        assert_eq!(
            err.raw_os_error(),
            Some(libc::ELOOP),
            "expected ELOOP for symlink dst, got {err:?}"
        );

        // Sanity: the original sensitive contents weren't touched.
        let still = std::fs::read(&target_real).unwrap();
        assert_eq!(still, b"sensitive contents");
    }

    #[cfg(unix)]
    #[test]
    fn secure_create_dir_all_yields_0700_under_022_umask() {
        let dir = tempdir().unwrap();
        let target = dir.path().join("a/b/c");

        unsafe {
            libc::umask(0o022);
        }
        secure_create_dir_all(&target).unwrap();

        // Every component this call newly creates must be 0700.
        for p in [
            &target,
            &target.parent().unwrap().to_path_buf(),
            &target.parent().unwrap().parent().unwrap().to_path_buf(),
        ] {
            assert_eq!(
                mode_of(p),
                0o700,
                "secure_create_dir_all must produce mode 0700 at {} even under umask 022",
                p.display(),
            );
        }
    }

    #[cfg(unix)]
    #[test]
    fn secure_create_dir_all_does_not_chmod_preexisting_components() {
        // Pre-existing parent dirs (e.g. the user's $HOME) must NOT be
        // chmod'd to 0700 by a recursive create. Only newly-created
        // components are narrowed.
        let dir = tempdir().unwrap();
        let parent = dir.path().join("preexisting_parent");
        std::fs::create_dir(&parent).unwrap();
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&parent, std::fs::Permissions::from_mode(0o755)).unwrap();
        assert_eq!(mode_of(&parent), 0o755);

        let leaf = parent.join("new_child");
        secure_create_dir_all(&leaf).unwrap();

        assert_eq!(
            mode_of(&parent),
            0o755,
            "pre-existing parent must be untouched"
        );
        assert_eq!(mode_of(&leaf), 0o700, "newly created leaf must be 0700");
    }

    #[cfg(unix)]
    #[test]
    fn atomic_secure_write_yields_0600() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("anchor.dat");
        unsafe {
            libc::umask(0o022);
        }
        atomic_secure_write(&path, b"anchor bytes").unwrap();
        assert_eq!(mode_of(&path), 0o600);
        assert_eq!(std::fs::read(&path).unwrap(), b"anchor bytes");
    }

    #[cfg(unix)]
    #[test]
    fn atomic_secure_write_leaves_no_tempfile_on_success() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("vault.hdr");
        atomic_secure_write(&path, &vec![0xAA; 1024]).unwrap();

        // The directory should contain only the final file, no
        // .tmp.* leftovers.
        let entries: Vec<_> = std::fs::read_dir(dir.path())
            .unwrap()
            .filter_map(Result::ok)
            .map(|e| e.file_name().into_string().unwrap())
            .collect();
        assert_eq!(entries, vec!["vault.hdr".to_string()]);
    }

    #[test]
    fn atomic_secure_create_new_writes_to_fresh_path() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("seed.kyber");
        atomic_secure_create_new(&path, b"seed contents").unwrap();
        assert_eq!(std::fs::read(&path).unwrap(), b"seed contents");
    }

    #[cfg(unix)]
    #[test]
    fn open_existing_read_no_follow_policy_follows_symlink_by_default() {
        // Without LUKSBOX_NO_FOLLOW_SYMLINKS, the prescan helper
        // MUST follow symlinks -- otherwise legit users who symlink
        // their vault path get broken at every command.
        let dir = tempdir().unwrap();
        let real = dir.path().join("vault.lbx");
        std::fs::write(&real, b"contents").unwrap();
        let link = dir.path().join("link.lbx");
        std::os::unix::fs::symlink(&real, &link).unwrap();
        // Ensure env var is NOT set for this test.
        // SAFETY: tests using this env var serialize via the
        // symlink_env_lock pattern (see security_invariants.rs).
        unsafe {
            std::env::remove_var("LUKSBOX_NO_FOLLOW_SYMLINKS");
        }
        let _f = open_existing_read_no_follow_policy(&link)
            .expect("default behaviour: must follow symlinks");
    }

    #[cfg(unix)]
    #[test]
    fn open_existing_read_no_follow_policy_refuses_symlink_when_env_set() {
        let dir = tempdir().unwrap();
        let real = dir.path().join("vault.lbx");
        std::fs::write(&real, b"contents").unwrap();
        let link = dir.path().join("link.lbx");
        std::os::unix::fs::symlink(&real, &link).unwrap();
        // SAFETY: serialized via env var pattern; this test runs
        // single-threaded within itself but env is process-wide.
        // Use a unique guard to minimize cross-test races.
        unsafe {
            std::env::set_var("LUKSBOX_NO_FOLLOW_SYMLINKS", "1");
        }
        let r = open_existing_read_no_follow_policy(&link);
        unsafe {
            std::env::remove_var("LUKSBOX_NO_FOLLOW_SYMLINKS");
        }
        let err = r.expect_err("must refuse symlink under no-follow env");
        assert_eq!(err.kind(), io::ErrorKind::PermissionDenied);
        // Real path still opens.
        let _f = open_existing_read_no_follow_policy(&real)
            .expect("non-symlink path still opens under no-follow");
    }

    #[cfg(unix)]
    #[test]
    fn secure_open_existing_no_follow_refuses_symlink_to_regular_file() {
        // The TOCTOU-driven panic-destroy attack: between the user
        // confirming "yes, wipe my vault" and the open(), an
        // attacker who controls the parent dir swaps the vault
        // path for a symlink to /etc/shadow (or any other file
        // the caller's process has write access to). With the
        // hardened helper, the open MUST fail with ELOOP-style
        // error before any write happens.
        let dir = tempdir().unwrap();
        let victim = dir.path().join("victim_file");
        std::fs::write(&victim, b"do not overwrite this").unwrap();
        let link = dir.path().join("attacker_planted_symlink");
        std::os::unix::fs::symlink(&victim, &link).unwrap();

        let err = secure_open_existing_no_follow(&link)
            .expect_err("must refuse to follow a symlink at the open target");
        // ELOOP on Linux for O_NOFOLLOW + symlink.
        assert_eq!(err.raw_os_error(), Some(libc::ELOOP));

        // The victim must NOT have been touched (we didn't even
        // get to a write call, but pin the invariant).
        assert_eq!(std::fs::read(&victim).unwrap(), b"do not overwrite this");
    }

    #[cfg(unix)]
    #[test]
    fn secure_open_existing_no_follow_refuses_directory() {
        let dir = tempdir().unwrap();
        let subdir = dir.path().join("subdir");
        std::fs::create_dir(&subdir).unwrap();
        let err = secure_open_existing_no_follow(&subdir)
            .expect_err("must refuse to operate on a directory");
        // O_NOFOLLOW doesn't reject directories; the metadata
        // check after open does. Either an EISDIR from open
        // (some kernels) or an InvalidInput from the metadata
        // check is acceptable.
        let ok = err.raw_os_error() == Some(libc::EISDIR)
            || matches!(err.kind(), std::io::ErrorKind::InvalidInput);
        assert!(ok, "expected EISDIR or InvalidInput, got {err:?}");
    }

    #[cfg(unix)]
    #[test]
    fn secure_open_existing_no_follow_succeeds_for_regular_file() {
        // Sanity: the happy path still works.
        let dir = tempdir().unwrap();
        let path = dir.path().join("ordinary_file");
        std::fs::write(&path, b"contents").unwrap();
        let _f =
            secure_open_existing_no_follow(&path).expect("regular file must open under no-follow");
    }

    #[cfg(unix)]
    #[test]
    fn secure_open_existing_no_follow_refuses_fifo() {
        // FIFOs / sockets aren't symlinks, but they aren't
        // regular files either. A write to a FIFO would block
        // forever waiting for a reader; a write to a device
        // file could have arbitrary side effects. The
        // is_file() post-open check refuses both.
        use std::ffi::CString;
        let dir = tempdir().unwrap();
        let fifo_path = dir.path().join("attacker_fifo");
        let c = CString::new(fifo_path.to_str().unwrap()).unwrap();
        let rc = unsafe { libc::mkfifo(c.as_ptr(), 0o600) };
        assert_eq!(rc, 0, "mkfifo setup failed");
        let err = secure_open_existing_no_follow(&fifo_path).expect_err("must refuse FIFO");
        assert!(
            matches!(err.kind(), std::io::ErrorKind::InvalidInput),
            "expected InvalidInput, got {err:?}"
        );
    }

    #[cfg(unix)]
    #[test]
    fn atomic_secure_create_new_yields_0600() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("seed.kyber");
        unsafe {
            libc::umask(0o022);
        }
        atomic_secure_create_new(&path, b"seed").unwrap();
        assert_eq!(mode_of(&path), 0o600);
    }

    #[test]
    fn atomic_secure_create_new_refuses_to_overwrite_regular_file() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("existing.kyber");
        std::fs::write(&path, b"original").unwrap();

        let err = atomic_secure_create_new(&path, b"replacement")
            .expect_err("must refuse to overwrite an existing regular file");
        assert_eq!(err.kind(), io::ErrorKind::AlreadyExists);

        // Original contents must be intact.
        assert_eq!(std::fs::read(&path).unwrap(), b"original");
    }

    #[test]
    fn atomic_secure_create_new_cleans_up_tempfile_on_eexist() {
        // A failed commit must not leave the temp file behind: otherwise
        // a retry would either trip its own create_new(true) guard or
        // accumulate stale .tmp.<hex> orphans next to user files.
        let dir = tempdir().unwrap();
        let path = dir.path().join("existing.kyber");
        std::fs::write(&path, b"original").unwrap();

        let _ = atomic_secure_create_new(&path, b"replacement");

        let leftovers: Vec<_> = std::fs::read_dir(dir.path())
            .unwrap()
            .filter_map(Result::ok)
            .map(|e| e.file_name().into_string().unwrap())
            .filter(|n| n.contains(".tmp."))
            .collect();
        assert!(
            leftovers.is_empty(),
            "atomic_secure_create_new must clean up the temp file on \
             commit failure; found leftovers: {leftovers:?}"
        );
    }

    #[cfg(unix)]
    #[test]
    fn atomic_secure_create_new_refuses_to_follow_symlink_target() {
        // The TOCTOU-driven attack: between the caller's `path.exists()`
        // pre-check and the commit, an attacker swaps `path` for a
        // symlink to an attacker-chosen file (e.g. `/etc/sudoers` if
        // luksbox is running as root via sudo). With the old
        // rename-replace commit, the write would follow the symlink and
        // clobber the target. With `link(2)`-based no-clobber commit,
        // the symlink itself counts as an existing destination and the
        // write fails.
        let dir = tempdir().unwrap();
        let victim = dir.path().join("victim");
        std::fs::write(&victim, b"do not touch").unwrap();

        let attack_path = dir.path().join("attacker_planted_symlink.kyber");
        std::os::unix::fs::symlink(&victim, &attack_path).unwrap();

        let err = atomic_secure_create_new(&attack_path, b"vault secret material")
            .expect_err("must refuse to follow a symlink at the destination");
        assert_eq!(err.kind(), io::ErrorKind::AlreadyExists);

        // The victim file must NOT have been touched.
        assert_eq!(std::fs::read(&victim).unwrap(), b"do not touch");
        // The symlink itself must still be there, untouched.
        assert!(
            attack_path
                .symlink_metadata()
                .unwrap()
                .file_type()
                .is_symlink()
        );
        // And no stale tempfile should have leaked into the directory.
        let leftovers: Vec<_> = std::fs::read_dir(dir.path())
            .unwrap()
            .filter_map(Result::ok)
            .map(|e| e.file_name().into_string().unwrap())
            .filter(|n| n.contains(".tmp."))
            .collect();
        assert!(leftovers.is_empty(), "leftover tempfiles: {leftovers:?}");
    }

    // ------------------------------------------------------------------
    // Orphan-tempfile cleanup tests
    // ------------------------------------------------------------------

    #[test]
    fn classify_tempfile_suffix_recognizes_atomic_write_tmp() {
        assert_eq!(
            classify_tempfile_suffix(".tmp.0123456789abcdef"),
            Some(OrphanKind::AtomicWriteTmp)
        );
        assert_eq!(
            classify_tempfile_suffix(".hdr.tmp.deadbeef00112233"),
            Some(OrphanKind::AtomicWriteTmp)
        );
        assert_eq!(
            classify_tempfile_suffix(".anchor.tmp.aaaaaaaaaaaaaaaa"),
            Some(OrphanKind::AtomicWriteTmp)
        );
    }

    #[test]
    fn classify_tempfile_suffix_recognizes_rotation_tmp() {
        assert_eq!(
            classify_tempfile_suffix(".rotating"),
            Some(OrphanKind::RotationTmp)
        );
    }

    #[test]
    fn classify_tempfile_suffix_rejects_unrelated() {
        // Wrong suffix length (15 chars).
        assert_eq!(classify_tempfile_suffix(".tmp.0123456789abcde"), None);
        // Uppercase hex (we emit lowercase).
        assert_eq!(classify_tempfile_suffix(".tmp.DEADBEEF00112233"), None);
        // Non-hex chars.
        assert_eq!(classify_tempfile_suffix(".tmp.zzzzzzzzzzzzzzzz"), None);
        // Random unrelated suffix.
        assert_eq!(classify_tempfile_suffix(".bak"), None);
        // Empty.
        assert_eq!(classify_tempfile_suffix(""), None);
        // Final extension only (the vault file itself).
        assert_eq!(classify_tempfile_suffix(".lbx"), None);
    }

    #[test]
    fn find_orphan_tempfiles_empty_dir_returns_empty() {
        let dir = tempdir().unwrap();
        let vault = dir.path().join("vault.lbx");
        let orphans = find_orphan_tempfiles(&vault).unwrap();
        assert!(orphans.is_empty());
    }

    #[test]
    fn find_orphan_tempfiles_finds_atomic_write_orphan() {
        let dir = tempdir().unwrap();
        let vault = dir.path().join("vault.lbx");
        // Drop the vault itself + a tmp orphan + an unrelated file.
        std::fs::write(&vault, b"vault contents").unwrap();
        std::fs::write(
            dir.path().join("vault.lbx.anchor.tmp.deadbeef00112233"),
            b"partial anchor",
        )
        .unwrap();
        std::fs::write(dir.path().join("unrelated.txt"), b"hello").unwrap();

        let orphans = find_orphan_tempfiles(&vault).unwrap();
        assert_eq!(orphans.len(), 1, "should find exactly one orphan");
        assert_eq!(orphans[0].kind, OrphanKind::AtomicWriteTmp);
        assert_eq!(
            orphans[0].path.file_name().unwrap(),
            "vault.lbx.anchor.tmp.deadbeef00112233"
        );
    }

    #[test]
    fn find_orphan_tempfiles_finds_rotation_orphan() {
        let dir = tempdir().unwrap();
        let vault = dir.path().join("vault.lbx");
        std::fs::write(&vault, b"vault").unwrap();
        std::fs::write(dir.path().join("vault.lbx.rotating"), b"in-flight rotation").unwrap();

        let orphans = find_orphan_tempfiles(&vault).unwrap();
        assert_eq!(orphans.len(), 1);
        assert_eq!(orphans[0].kind, OrphanKind::RotationTmp);
    }

    #[test]
    fn find_orphan_tempfiles_does_not_match_other_vaults() {
        // Two vaults in the same dir; ensure we only get tempfiles for
        // the one we asked about.
        let dir = tempdir().unwrap();
        let vault_a = dir.path().join("vault-a.lbx");
        let vault_b = dir.path().join("vault-b.lbx");
        std::fs::write(&vault_a, b"a").unwrap();
        std::fs::write(&vault_b, b"b").unwrap();
        std::fs::write(
            dir.path().join("vault-a.lbx.tmp.0000000011112222"),
            b"a tmp",
        )
        .unwrap();
        std::fs::write(
            dir.path().join("vault-b.lbx.tmp.3333333344445555"),
            b"b tmp",
        )
        .unwrap();

        let orphans_a = find_orphan_tempfiles(&vault_a).unwrap();
        assert_eq!(orphans_a.len(), 1);
        assert_eq!(
            orphans_a[0].path.file_name().unwrap(),
            "vault-a.lbx.tmp.0000000011112222"
        );

        let orphans_b = find_orphan_tempfiles(&vault_b).unwrap();
        assert_eq!(orphans_b.len(), 1);
        assert_eq!(
            orphans_b[0].path.file_name().unwrap(),
            "vault-b.lbx.tmp.3333333344445555"
        );
    }

    #[test]
    fn delete_atomic_write_orphans_removes_only_atomic_kind() {
        let dir = tempdir().unwrap();
        let vault = dir.path().join("vault.lbx");
        let atomic_orphan = dir.path().join("vault.lbx.tmp.aabbccddeeff0011");
        let rotation_orphan = dir.path().join("vault.lbx.rotating");
        std::fs::write(&vault, b"v").unwrap();
        std::fs::write(&atomic_orphan, b"x").unwrap();
        std::fs::write(&rotation_orphan, b"y").unwrap();

        let orphans = find_orphan_tempfiles(&vault).unwrap();
        assert_eq!(orphans.len(), 2);

        let (deleted, errors) = delete_atomic_write_orphans(&orphans);
        assert_eq!(deleted.len(), 1);
        assert_eq!(
            deleted[0].file_name().unwrap(),
            "vault.lbx.tmp.aabbccddeeff0011"
        );
        assert!(errors.is_empty());

        // Atomic gone, rotation preserved (must surface to user, not
        // auto-delete).
        assert!(!atomic_orphan.exists());
        assert!(rotation_orphan.exists());

        // Re-scan: only the rotation orphan remains.
        let after = find_orphan_tempfiles(&vault).unwrap();
        assert_eq!(after.len(), 1);
        assert_eq!(after[0].kind, OrphanKind::RotationTmp);
    }

    #[test]
    fn find_orphan_tempfiles_nonexistent_vault_returns_empty() {
        // Pointing at a vault under a directory that doesn't exist
        // should be Ok(empty), not Err. Lets callers run cleanup
        // unconditionally without pre-checking existence.
        let dir = tempdir().unwrap();
        let nonexistent_subdir = dir.path().join("does-not-exist");
        let vault = nonexistent_subdir.join("vault.lbx");
        let orphans = find_orphan_tempfiles(&vault).unwrap();
        assert!(orphans.is_empty());
    }
}
