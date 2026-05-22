// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Penthertz <https://penthertz.com> (https://x.com/PentHertz)

//! WinFsp adapter, the Windows counterpart to `fuse.rs`.
//!
//! WinFsp is the Windows usermode-filesystem driver
//! (<https://winfsp.dev>); the kernel driver itself is Microsoft-signed
//! and shipped as a separate installer. The user must have it installed
//! before luksbox can mount on their machine, just like FUSE on Linux.
//!
//! Architecture mirrors the FUSE adapter:
//!   * one `Mutex<Vfs>` shared across WinFsp's worker-thread dispatch;
//!   * one `Arc<FileContext>` per open handle, which carries the
//!     `FileId` we look up in the Vfs;
//!   * Win32 path translation (`\foo\bar` -> `/foo/bar`) at every entry
//!     point, since luksbox-vfs uses POSIX-style separators internally.
//!
//! Implemented operations (sufficient for browse / read / write):
//!   get_security_by_name, open, create, overwrite, cleanup, close,
//!   read, write, flush, get_file_info, set_basic_info, set_file_size,
//!   can_delete, rename, read_directory, get_volume_info.
//!
//! Not implemented (returns NTSTATUS_NOT_IMPLEMENTED): reparse points,
//! extended attributes, alternate streams, security descriptors beyond
//! a fixed all-access ACL.
//!
//! ## Gotchas this file has learned the hard way
//!
//! These are the non-obvious correctness traps the WinFsp + Rust
//! binding combo has on Windows 11 / WinFsp 2.x. If something breaks
//! while you're refactoring this file, start here.
//!
//! ### 1. WinFsp requires Open AND Create AND Overwrite to be defined
//!
//! `FspFileSystemOpCreate` does an up-front null-check at the top of
//! the function - if any of `(Create | CreateEx)`, `Open`, or
//! `(Overwrite | OverwriteEx)` is null, EVERY IRP_MJ_CREATE returns
//! `STATUS_INVALID_DEVICE_REQUEST` (0xC0000010), including the volume
//! probe Windows issues right after `FspFileSystemSetMountPoint`. The
//! drive letter ends up registered with `Mount Manager`, but Win32
//! reports it as "no recognized file system" (Error 1005) and our
//! callback handlers never run. A unit test on the Rust side would
//! NOT catch this; only an actual mount + `fsutil volume diskfree`
//! does. See `tests/winfsp_mount.rs::mount_makes_drive_visible_to_win32`.
//!
//! ### 2. Volume creation time of 0 = malformed volume
//!
//! `FILETIME=0` (1601-01-01 00:00:00) is a perfectly fine value for
//! per-FILE timestamps but Windows treats it as "this volume has no
//! valid creation time" and refuses to bind it. Always
//! `set_volume_creation_time(filetime_now())`, never 0.
//!
//! ### 3. Drive letter mountpoint must NOT carry a trailing separator
//!
//! WinFsp accepts `Y:` but rejects `Y:\` with
//! `STATUS_OBJECT_NAME_INVALID` (0xC0000033). `Path` and `PathBuf`
//! happily round-trip the separator-bearing form, so `mount()`
//! normalizes via `normalize_mountpoint()` before handing the string
//! to WinFsp. Directory mountpoints (`C:\some\dir`) keep their
//! separators since they're real paths.
//!
//! ### 4. `OperationGuardStrategy::Fine` + `Mutex<Vfs>` = pure overhead
//!
//! Fine tells WinFsp it can dispatch reads/writes concurrently across
//! its worker threads. With our single `Mutex<Vfs>` they all bottle-
//! neck on the same lock anyway. Coarse (the default) lets WinFsp
//! serialize upstream and matches our adapter's actual concurrency.
//! Don't switch to Fine without first making the VFS layer truly
//! parallel.
//!
//! ### 5. Set the metadata timeouts or Explorer makes us look slow
//!
//! Without `set_file_info_timeout`, `set_volume_info_timeout`,
//! `set_dir_info_timeout`, and `set_security_timeout` set non-zero,
//! WinFsp re-dispatches every metadata query for every Explorer
//! redraw - under heavy enumeration that round-trips through our
//! `Mutex<Vfs>` often enough to look like a hang ("drive opens but
//! folder takes 30 s to populate"). 1 s matches the memfs reference
//! and NTFS-equivalent staleness expectations.
//!
//! ### 6. WinFsp 2.x can run without the persistent `winfsp` service
//!
//! In modern installs the user-mode launcher attaches the kernel
//! driver on demand. Probing `Get-Service winfsp` returns false even
//! on a working install - use the registry key
//! `HKLM\SOFTWARE\WOW6432Node\WinFsp\InstallDir` plus presence of
//! `<install-dir>\bin\winfsp-x64.sys` instead. The integration test
//! does this in `winfsp_available()`.
//!
//! ### 7. Cross-process unmount is not a thing on WinFsp
//!
//! There is no `fusermount -u` equivalent. The only ways to release
//! a kernel mount are (a) calling `FileSystem::stop()` from within
//! the owning process, or (b) terminating the owning process. The
//! `unmount(mountpoint)` helper handles case (a) via a process-wide
//! mount registry; case (b) is on the user. Cross-process callers
//! get a clear error rather than a fake `Ok(())`.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::mpsc::Sender;
use std::sync::{Arc, Mutex, OnceLock};

use winfsp_wrs::U16Str;
use winfsp_wrs::{
    CleanupFlags, CreateFileInfo, CreateOptions, DirInfo, FileAccessRights, FileAttributes,
    FileInfo, FileSystem, FileSystemInterface, NTSTATUS, PSecurityDescriptor, Params,
    STATUS_ACCESS_DENIED, STATUS_DIRECTORY_NOT_EMPTY, STATUS_END_OF_FILE, STATUS_INVALID_PARAMETER,
    STATUS_NOT_A_DIRECTORY, STATUS_OBJECT_NAME_COLLISION, STATUS_OBJECT_NAME_NOT_FOUND,
    STATUS_OBJECT_PATH_NOT_FOUND, SecurityDescriptor, U16CStr, U16CString, VolumeInfo, WriteMode,
    filetime_now,
};

use luksbox_vfs::{FileId, InodeKind, Vfs};

use crate::MountError;
use crate::winfsp_path::{
    PathParseError, from_win_path_str, normalize_mountpoint_str,
    split_parent_name as split_parent_name_inner,
};

const VOLUME_LABEL: &str = "luksbox";

/// Turn `winfsp_wrs::InitError` into a user-facing message. The
/// upstream `Debug` impl prints bare identifiers like
/// `WinFSPNotFound`, which we used to forward verbatim -- users
/// then saw "winfsp init failed: WinFSPNotFound" with no hint
/// about what to install or why. The binding resolves the DLL
/// strictly via `HKLM\SOFTWARE\WOW6432Node\WinFsp\InstallDir`, so
/// placing `winfsp-x64.dll` next to luksbox.exe is NOT a fallback;
/// the only real fix is "install WinFsp 2.x". Surface that.
fn map_init_error(e: winfsp_wrs::InitError) -> MountError {
    let msg = match e {
        winfsp_wrs::InitError::WinFSPNotFound => {
            "WinFsp 2.x is not installed on this machine, so LUKSbox \
             cannot create a Windows volume. Install WinFsp from \
             https://winfsp.dev/rel/, reboot if prompted, then try \
             again. (Detection looks for HKLM\\SOFTWARE\\\
             WOW6432Node\\WinFsp\\InstallDir; if you installed WinFsp \
             but still see this, reinstall using the official MSI so \
             the registry entry is created.)"
                .to_string()
        }
        winfsp_wrs::InitError::CannotLoadDLL { dll_path } => format!(
            "WinFsp's registry entry points at {} but the DLL could \
             not be loaded. Common causes: WinFsp install corrupted, \
             64-bit / ARM64 mismatch, or a broken upgrade. Reinstall \
             WinFsp from https://winfsp.dev/rel/.",
            dll_path.to_string_lossy()
        ),
    };
    MountError::Io(std::io::Error::other(msg))
}

/// Returns `Ok(())` if WinFsp 2.x is installed and the DLL loads.
/// Used by the GUI to pre-flight the mount button so it can show
/// the install-WinFsp hint without first spinning up the FUSE
/// dispatch and friends. Idempotent; calling it before
/// `mount()` is fine because `winfsp_wrs::init` itself is.
pub fn winfsp_preflight() -> Result<(), MountError> {
    winfsp_wrs::init().map_err(map_init_error)
}

/// Map a `winfsp_path::PathParseError` to the closest NTSTATUS we can
/// return from a WinFsp callback. Centralized so every helper that
/// calls into the parser uses the same mapping - keeps Explorer error
/// messages consistent across operations.
fn path_err_to_nt(e: PathParseError) -> NTSTATUS {
    match e {
        // Empty / NUL / oversized -> "object name invalid" maps cleanly
        // to STATUS_OBJECT_NAME_INVALID, but Win32 doesn't expose that
        // constant via winfsp_wrs. STATUS_INVALID_PARAMETER is the
        // closest broadly-recognized fallback that Explorer surfaces
        // as "invalid path".
        PathParseError::EmptyPath
        | PathParseError::EmptyName
        | PathParseError::ContainsNul
        | PathParseError::TooLong => STATUS_INVALID_PARAMETER,
    }
}

/// Translate a Windows path (`\` separator, U16) to a luksbox-vfs path
/// (`/` separator, UTF-8). The root `\\?\C:\` form never reaches us, by
/// the time WinFsp dispatches to our callbacks the path is relative to
/// the mount, e.g. `\foo\bar`. An empty / `\` path means root.
fn from_win_path(p: &U16CStr) -> Result<String, NTSTATUS> {
    let s = p.to_string().map_err(|_| STATUS_INVALID_PARAMETER)?;
    from_win_path_str(&s).map_err(path_err_to_nt)
}

fn split_parent_name(path: &str) -> Result<(&str, &str), NTSTATUS> {
    split_parent_name_inner(path).map_err(path_err_to_nt)
}

// Two NTSTATUSes not re-exported by winfsp_wrs but needed for the
// metadata-budget and per-file-cap errors. Standard Win32 codes:
//   STATUS_DISK_FULL       = 0xC000007F  (-> "There is not enough space on the disk.")
//   STATUS_FILE_TOO_LARGE  = 0xC0000904  (-> "The file size exceeds the limit allowed and cannot be saved.")
// `winfsp_wrs::NTSTATUS` is a type alias for `LONG` (i32), so build via cast.
const STATUS_DISK_FULL: NTSTATUS = 0xC000_007Fu32 as NTSTATUS;
const STATUS_FILE_TOO_LARGE: NTSTATUS = 0xC000_0904u32 as NTSTATUS;

fn vfs_err_to_nt(e: &luksbox_vfs::Error) -> NTSTATUS {
    use luksbox_vfs::Error as E;
    match e {
        E::NotFound => STATUS_OBJECT_NAME_NOT_FOUND,
        E::AlreadyExists => STATUS_OBJECT_NAME_COLLISION,
        E::NotEmpty => STATUS_DIRECTORY_NOT_EMPTY,
        E::NotADirectory => STATUS_NOT_A_DIRECTORY,
        E::InvalidPath(_) => STATUS_OBJECT_PATH_NOT_FOUND,
        // POSIX: rename(2) into own descendant -> EINVAL.
        E::RenameCycle => STATUS_INVALID_PARAMETER,
        E::MetadataBudgetExhausted => STATUS_DISK_FULL,
        E::FileSizeExceedsCap => STATUS_FILE_TOO_LARGE,
        _ => STATUS_ACCESS_DENIED,
    }
}

/// Fill in a `FileInfo` for a luksbox file/dir. Timestamps are always
/// zero, luksbox doesn't track per-file mtime/ctime/atime; Windows
/// callers see "epoch" everywhere. Attributes carry the dir bit and
/// nothing else (no read-only / hidden / system).
/// Cheap process-wide debug toggle: if `LUKSBOX_WINFSP_DEBUG` is set
/// in the env, every traced WinFsp callback prints its name + key
/// inputs + result NTSTATUS to stderr. Cached on first call so the
/// per-callback overhead is one atomic load when disabled. Output
/// is intentionally line-oriented so users can `2> winfsp.log` and
/// share it for diagnosis.
fn winfsp_debug() -> bool {
    use std::sync::atomic::{AtomicU8, Ordering};
    static CACHED: AtomicU8 = AtomicU8::new(0); // 0=unknown, 1=off, 2=on
    let v = CACHED.load(Ordering::Relaxed);
    if v != 0 {
        return v == 2;
    }
    let on = std::env::var_os("LUKSBOX_WINFSP_DEBUG").is_some();
    CACHED.store(if on { 2 } else { 1 }, Ordering::Relaxed);
    on
}

/// Call inside a callback to log a one-line trace. The `result`
/// closure is invoked AFTER the body to format the outcome - pass
/// `Ok(...)` or `Err(STATUS_..)` as a string.
macro_rules! winfsp_trace {
    ($cb:expr, $args:expr) => {
        if $crate::winfsp::winfsp_debug() {
            eprintln!("[winfsp] {} {}", $cb, $args);
        }
    };
    ($cb:expr, $args:expr, $result:expr) => {
        if $crate::winfsp::winfsp_debug() {
            eprintln!("[winfsp] {} {} -> {}", $cb, $args, $result);
        }
    };
}

fn fmt_status(rc: NTSTATUS) -> String {
    format!("NTSTATUS=0x{:08X}", rc as u32)
}

fn make_file_info(vfs: &mut Vfs, file_id: FileId) -> Result<FileInfo, NTSTATUS> {
    let st = vfs.stat(file_id).map_err(|e| vfs_err_to_nt(&e))?;
    let attrs = if st.kind == InodeKind::Directory {
        FileAttributes::DIRECTORY
    } else {
        // ARCHIVE rather than NORMAL: NTFS sets ARCHIVE on every
        // newly-created file and Windows backup tools rely on it. A
        // FILE_ATTRIBUTE_NORMAL (0x80) entry MUST be the only flag set
        // per Win32 docs, which we can't guarantee long-term as we
        // grow new attribute bits. ARCHIVE composes safely with
        // anything else and matches what Explorer expects to see for
        // a "regular file" on a typical Windows volume.
        FileAttributes::ARCHIVE
    };
    let mut info = FileInfo::default();
    // Convert UNIX nanoseconds (luksbox-vfs's mtime_ns) to FILETIME
    // (100-ns ticks since 1601-01-01-00:00:00 UTC). The 1601->1970
    // offset in 100-ns ticks is 116_444_736_000_000_000. Without
    // this conversion, timestamps default to 0 which Windows
    // displays as 1601-01-01 and some shell paths reject as invalid.
    const FILETIME_UNIX_EPOCH: u64 = 116_444_736_000_000_000;
    let filetime = (st.mtime_ns / 100).saturating_add(FILETIME_UNIX_EPOCH);
    info.set_file_attributes(attrs)
        .set_file_size(st.size)
        .set_allocation_size(st.size)
        .set_index_number(file_id)
        // We don't separately track ctime/atime, set every timestamp
        // to mtime. set_time is winfsp_wrs's "set them all at once"
        // helper. Better than zero for Explorer's "Date modified"
        // column AND for any code that validates non-zero timestamps.
        .set_time(filetime);
    Ok(info)
}

/// Per-open handle. Cloned (refcount-bumped) on every callback by
/// `winfsp_wrs`'s `FileContextKind for Arc<T>`.
pub struct OpenContext {
    pub file_id: FileId,
    pub is_dir: bool,
}

pub struct LuksboxFs {
    inner: Mutex<Vfs>,
    /// Default security descriptor returned for every inode in the
    /// volume. With `PersistentAcls=false` (we don't store ACLs in
    /// the vault), every `get_security_by_name` call MUST return a
    /// non-null security descriptor, otherwise WinFsp hands the
    /// file off with a null SD and Windows refuses access ("Z:\ is
    /// unavailable" in Explorer, even from the user that mounted
    /// the FS - empirically observed). The previous code returned
    /// `PSecurityDescriptor::default()` (a null pointer) hoping
    /// WinFsp would substitute a default; it does not.
    ///
    /// SDDL grants Full Access to BUILTIN\Administrators, NT
    /// AUTHORITY\SYSTEM, and the **current user** (the SID of the
    /// process that mounted the volume, resolved at construction
    /// via `current_user_sid`). Owner/Group set to the same user.
    /// Earlier versions granted Full Access to Everyone (`WD`)
    /// which let any local logon session read decrypted contents
    /// while the volume was mounted - that ACE has been removed.
    /// The .lbx file itself still gates initial access (you need
    /// read access to the .lbx to mount in the first place), and
    /// the per-volume ACL now enforces single-user isolation on
    /// the mountpoint side too.
    ///
    /// Boxed because `Vec<u8>` (which `SecurityDescriptor` wraps)
    /// can reallocate; the pointer we hand to WinFsp must stay
    /// valid for the FS lifetime, so we pin it via `Box`.
    default_security: Box<SecurityDescriptor>,
    /// Directory containing the .lbx vault file, cached at construction
    /// time so `get_volume_info` can probe the host disk for real
    /// total/free numbers (via `GetDiskFreeSpaceExW`) instead of lying.
    /// Mirrors the same pattern used on Linux/macOS in `fuse.rs` so all
    /// three platforms surface honest space numbers to file managers.
    vault_parent: Option<PathBuf>,
}

impl LuksboxFs {
    pub fn new(vfs: Vfs) -> Self {
        // Build the default SD from SDDL. Owner/Group/extra-DACL-entry
        // = the current process's user SID, resolved at runtime via
        // `current_user_sid` so volume-internal ACLs match the user
        // who actually mounted the volume. Falls back to a strict
        // "Administrators + SYSTEM only" SDDL if SID resolution fails
        // (e.g. token query rejected in some sandboxed contexts) -
        // strictly tighter than the previous Everyone (`WD`) default.
        let sddl_string = match current_user_sid() {
            Some(sid) => format!("O:{sid}G:{sid}D:P(A;;FA;;;BA)(A;;FA;;;SY)(A;;FA;;;{sid})"),
            None => String::from("O:BAG:SYD:P(A;;FA;;;BA)(A;;FA;;;SY)"),
        };
        let sddl_str =
            U16CString::from_str(&sddl_string).expect("constructed SDDL is ASCII, no NUL");
        let sd = SecurityDescriptor::from_wstr(&sddl_str).expect("constructed SDDL must parse");
        let vault_parent = vfs
            .container()
            .vault_path()
            .parent()
            .map(|p| p.to_path_buf());
        Self {
            inner: Mutex::new(vfs),
            default_security: Box::new(sd),
            vault_parent,
        }
    }

    fn lookup_kind(&self, path: &str) -> Result<(FileId, InodeKind), NTSTATUS> {
        let mut vfs = self.inner.lock().unwrap();
        let id = vfs.lookup_path(path).map_err(|e| vfs_err_to_nt(&e))?;
        let st = vfs.stat(id).map_err(|e| vfs_err_to_nt(&e))?;
        Ok((id, st.kind))
    }
}

impl Drop for LuksboxFs {
    /// Final flush on filesystem teardown. `FileSystem::stop()` drops
    /// the owned `LuksboxFs`, which lands here. Belt-and-suspenders
    /// behind the per-handle `cleanup` flush: if Windows ever skips a
    /// cleanup (e.g. process forced-killed mid-copy, kernel-mode
    /// abandonment) the dirty metadata still gets persisted before the
    /// underlying `Container` is dropped. `Vfs::flush()` is a no-op
    /// when nothing is dirty, so this is free in the happy path.
    fn drop(&mut self) {
        if let Ok(mut vfs) = self.inner.lock() {
            let _ = vfs.flush();
        }
    }
}

impl FileSystemInterface for LuksboxFs {
    type FileContext = Arc<OpenContext>;

    const GET_VOLUME_INFO_DEFINED: bool = true;
    const GET_SECURITY_BY_NAME_DEFINED: bool = true;
    const CREATE_DEFINED: bool = true;
    const OPEN_DEFINED: bool = true;
    // OVERWRITE_DEFINED is NOT optional: WinFsp's `FspFileSystemOpCreate`
    // up-front checks that all of (Create | CreateEx), Open, and
    // (Overwrite | OverwriteEx) are non-null before dispatching ANY
    // Create IRP. With Overwrite null, every IRP_MJ_CREATE - including
    // the volume-probe open of `\` that Windows issues right after
    // mount - is rejected with STATUS_INVALID_DEVICE_REQUEST (0xC0000010)
    // and Win32 reports the volume as "not a recognized file system".
    // The implementation only needs to handle FILE_SUPERSEDE /
    // FILE_OVERWRITE / FILE_OVERWRITE_IF dispositions, which for
    // luksbox-vfs maps to truncating the existing inode to the
    // requested allocation size.
    const OVERWRITE_DEFINED: bool = true;
    const CLEANUP_DEFINED: bool = true;
    const CLOSE_DEFINED: bool = true;
    const READ_DEFINED: bool = true;
    const WRITE_DEFINED: bool = true;
    const FLUSH_DEFINED: bool = true;
    const GET_FILE_INFO_DEFINED: bool = true;
    const SET_FILE_SIZE_DEFINED: bool = true;
    const CAN_DELETE_DEFINED: bool = true;
    const RENAME_DEFINED: bool = true;
    const READ_DIRECTORY_DEFINED: bool = true;
    // Required for Windows to update timestamps / attributes on
    // touched files. Without it, every NtSetInformationFile call
    // for FILE_BASIC_INFORMATION returns STATUS_INVALID_DEVICE_REQUEST,
    // which Explorer can surface as "Z:\ is not accessible" depending
    // on the code path. Implementation below is intentionally a no-op
    // (we don't persist timestamps / attribute bits in the vault yet)
    // - but Windows just needs the call to succeed.
    const SET_BASIC_INFO_DEFINED: bool = true;

    fn get_volume_info(&self) -> Result<VolumeInfo, NTSTATUS> {
        winfsp_trace!("get_volume_info", "");
        // Query the host disk for real total/free numbers when possible.
        // Without this, Windows Explorer cannot warn the user before
        // they drop a file bigger than the underlying disk can hold
        // (the write would then fail mid-copy when the host .lbx file
        // can't grow). Falls back to a roomy 1 TiB nominal when the
        // query fails, matching the historical behaviour and the
        // Linux/macOS fallback in `fuse.rs`.
        let (total, free) = self
            .vault_parent
            .as_deref()
            .and_then(host_disk_space)
            .unwrap_or((1 << 40, 1 << 39));
        // VolumeInfo::new takes &U16Str (no NUL terminator), not &U16CStr.
        let label_owned: Vec<u16> = VOLUME_LABEL.encode_utf16().collect();
        let label = U16Str::from_slice(&label_owned);
        VolumeInfo::new(total, free, label).map_err(|_| STATUS_INVALID_PARAMETER)
    }

    fn get_security_by_name(
        &self,
        file_name: &U16CStr,
        _find_reparse_point: impl Fn() -> Option<FileAttributes>,
    ) -> Result<(FileAttributes, PSecurityDescriptor, bool), NTSTATUS> {
        let path = from_win_path(file_name)?;
        let res = self.lookup_kind(&path);
        match &res {
            Ok((id, kind)) => {
                winfsp_trace!(
                    "get_security_by_name",
                    format!("path={path:?} -> id={id} kind={kind:?}")
                );
            }
            Err(rc) => {
                winfsp_trace!(
                    "get_security_by_name",
                    format!("path={path:?}"),
                    fmt_status(*rc)
                );
            }
        }
        let (_id, kind) = res?;
        let attrs = if kind == InodeKind::Directory {
            FileAttributes::DIRECTORY
        } else {
            FileAttributes::NORMAL
        };
        // Return the precomputed permissive SD, see the field doc on
        // `LuksboxFs::default_security` for the threat model. Returning
        // `PSecurityDescriptor::default()` (null) here was the cause
        // of "Z:\ is unavailable" errors in Explorer.
        Ok((attrs, self.default_security.as_ptr(), false))
    }

    fn create(
        &self,
        file_name: &U16CStr,
        create_file_info: CreateFileInfo,
        _security_descriptor: SecurityDescriptor,
    ) -> Result<(Self::FileContext, FileInfo), NTSTATUS> {
        let path = from_win_path(file_name)?;
        let (parent_str, name) = split_parent_name(&path)?;
        let mut vfs = self.inner.lock().unwrap();
        let parent_id = vfs.lookup_path(parent_str).map_err(|e| vfs_err_to_nt(&e))?;
        let is_dir = create_file_info
            .file_attributes
            .is(FileAttributes::DIRECTORY);
        let new_id = if is_dir {
            vfs.mkdir(parent_id, name).map_err(|e| vfs_err_to_nt(&e))?
        } else {
            vfs.create(parent_id, name).map_err(|e| vfs_err_to_nt(&e))?
        };
        let info = make_file_info(&mut vfs, new_id)?;
        let ctx = Arc::new(OpenContext {
            file_id: new_id,
            is_dir,
        });
        Ok((ctx, info))
    }

    fn open(
        &self,
        file_name: &U16CStr,
        _create_options: CreateOptions,
        _granted_access: FileAccessRights,
    ) -> Result<(Self::FileContext, FileInfo), NTSTATUS> {
        let path = from_win_path(file_name)?;
        let res = self.lookup_kind(&path);
        match &res {
            Ok((id, kind)) => {
                winfsp_trace!("open", format!("path={path:?} -> id={id} kind={kind:?}"));
            }
            Err(rc) => {
                winfsp_trace!("open", format!("path={path:?}"), fmt_status(*rc));
            }
        }
        let (id, kind) = res?;
        let mut vfs = self.inner.lock().unwrap();
        let info = make_file_info(&mut vfs, id)?;
        let ctx = Arc::new(OpenContext {
            file_id: id,
            is_dir: kind == InodeKind::Directory,
        });
        Ok((ctx, info))
    }

    fn cleanup(&self, ctx: Self::FileContext, file_name: Option<&U16CStr>, flags: CleanupFlags) {
        // WinFsp `Cleanup` is the analogue of FUSE `release`: it fires
        // when the user-mode handle closes (CloseHandle). With
        // `set_post_cleanup_when_modified_only(true)` set in `mount()`,
        // it is dispatched only when the file was modified or marked for
        // delete - exactly the cases where we MUST persist the in-memory
        // metadata + chunk index onto the underlying .lbx, otherwise the
        // newly-written chunks have no inode entry pointing at them and
        // get reaped as garbage on the next mount. Symptom: "I copied a
        // file into the mounted volume in Explorer, unmounted, and on
        // remount the file is gone."
        //
        // Flush is unconditional within cleanup because the gating
        // (modified-or-delete) is done by WinFsp itself before we get
        // here. It's also cheap for non-mutating cases: Vfs::flush() is
        // a no-op when `dirty == false`.
        if flags.is(CleanupFlags::DELETE) {
            // Triggered after can_delete + actual delete decision.
            let Some(name) = file_name else { return };
            let Ok(path) = from_win_path(name) else {
                return;
            };
            let Ok((parent, leaf)) = split_parent_name(&path) else {
                return;
            };
            let mut vfs = self.inner.lock().unwrap();
            let Ok(parent_id) = vfs.lookup_path(parent) else {
                return;
            };
            let _ = if ctx.is_dir {
                vfs.rmdir(parent_id, leaf)
            } else {
                vfs.unlink(parent_id, leaf)
            };
            let _ = vfs.flush();
        } else {
            // Non-delete cleanup: a write/truncate/set-size happened on
            // this handle; persist it now so an unmount or process exit
            // immediately afterwards doesn't lose the data.
            if let Ok(mut vfs) = self.inner.lock() {
                let _ = vfs.flush();
            }
        }
    }

    fn close(&self, _ctx: Self::FileContext) {
        // Arc drops naturally; nothing to do.
    }

    fn read(
        &self,
        ctx: Self::FileContext,
        buffer: &mut [u8],
        offset: u64,
    ) -> Result<usize, NTSTATUS> {
        if ctx.is_dir {
            return Err(STATUS_INVALID_PARAMETER);
        }
        let mut vfs = self.inner.lock().unwrap();
        let n = vfs
            .read(ctx.file_id, offset, buffer)
            .map_err(|e| vfs_err_to_nt(&e))?;
        if n == 0 {
            // WinFsp expects STATUS_END_OF_FILE rather than n==0 to signal EOF.
            return Err(STATUS_END_OF_FILE);
        }
        Ok(n)
    }

    fn write(
        &self,
        ctx: Self::FileContext,
        buffer: &[u8],
        mode: WriteMode,
    ) -> Result<(usize, FileInfo), NTSTATUS> {
        if ctx.is_dir {
            return Err(STATUS_INVALID_PARAMETER);
        }
        let mut vfs = self.inner.lock().unwrap();
        // WinFsp gives us either an explicit offset or a "write at end" hint
        // (constrained_io / write_to_end). For luksbox-vfs we need a
        // concrete offset every time, so resolve "write to end" by stat-ing.
        let offset = match mode {
            WriteMode::Normal { offset } => offset,
            WriteMode::ConstrainedIO { offset } => offset,
            WriteMode::WriteToEOF => vfs.stat(ctx.file_id).map_err(|e| vfs_err_to_nt(&e))?.size,
        };
        vfs.write(ctx.file_id, offset, buffer)
            .map_err(|e| vfs_err_to_nt(&e))?;
        let info = make_file_info(&mut vfs, ctx.file_id)?;
        Ok((buffer.len(), info))
    }

    /// Overwrite (truncate + reset) an existing file. WinFsp dispatches
    /// here for FILE_SUPERSEDE / FILE_OVERWRITE / FILE_OVERWRITE_IF
    /// dispositions on `Open`. The handler MUST exist (even as a stub)
    /// or `FspFileSystemOpCreate` rejects every Create IRP up front,
    /// see the comment on `OVERWRITE_DEFINED` above for the bind-time
    /// check.
    ///
    /// Semantics: drop existing content down to `allocation_size` and
    /// - if the caller asked for it - replace the file attributes
    /// (read-only / hidden / etc.). luksbox-vfs doesn't persist
    /// FAT-style attribute bits so the `replace_file_attributes`
    /// argument is consumed for protocol compliance and otherwise
    /// ignored, mirroring the approach in `set_basic_info`.
    fn overwrite(
        &self,
        ctx: Self::FileContext,
        _file_attributes: FileAttributes,
        _replace_file_attributes: bool,
        allocation_size: u64,
    ) -> Result<FileInfo, NTSTATUS> {
        if ctx.is_dir {
            return Err(STATUS_INVALID_PARAMETER);
        }
        let mut vfs = self.inner.lock().unwrap();
        vfs.truncate(ctx.file_id, allocation_size)
            .map_err(|e| vfs_err_to_nt(&e))?;
        make_file_info(&mut vfs, ctx.file_id)
    }

    fn flush(&self, ctx: Self::FileContext) -> Result<FileInfo, NTSTATUS> {
        let mut vfs = self.inner.lock().unwrap();
        vfs.flush().map_err(|e| vfs_err_to_nt(&e))?;
        make_file_info(&mut vfs, ctx.file_id)
    }

    fn get_file_info(&self, ctx: Self::FileContext) -> Result<FileInfo, NTSTATUS> {
        winfsp_trace!("get_file_info", format!("file_id={}", ctx.file_id));
        let mut vfs = self.inner.lock().unwrap();
        make_file_info(&mut vfs, ctx.file_id)
    }

    /// Accept timestamp / attribute updates as a no-op success.
    ///
    /// luksbox-vfs doesn't persist Windows-style timestamps or the
    /// archive/hidden/readonly attribute bits - its model is
    /// content-addressed encrypted chunks, not POSIX or NTFS metadata.
    /// We could store these in the inode metadata blob in a future
    /// version; for now, returning success on every call lets Windows
    /// proceed (Explorer routinely calls this on file open / save /
    /// rename, and a STATUS_INVALID_DEVICE_REQUEST refusal cascades
    /// into "Z:\ is not accessible" UI errors on some paths).
    fn set_basic_info(
        &self,
        ctx: Self::FileContext,
        attrs: FileAttributes,
        ctime: u64,
        atime: u64,
        mtime: u64,
        change_time: u64,
    ) -> Result<FileInfo, NTSTATUS> {
        winfsp_trace!(
            "set_basic_info",
            format!(
                "file_id={} attrs={:?} ctime={} atime={} mtime={} change_time={}",
                ctx.file_id, attrs, ctime, atime, mtime, change_time
            )
        );
        let mut vfs = self.inner.lock().unwrap();
        make_file_info(&mut vfs, ctx.file_id)
    }

    fn set_file_size(
        &self,
        ctx: Self::FileContext,
        new_size: u64,
        _set_allocation_size: bool,
    ) -> Result<FileInfo, NTSTATUS> {
        if ctx.is_dir {
            return Err(STATUS_INVALID_PARAMETER);
        }
        let mut vfs = self.inner.lock().unwrap();
        vfs.truncate(ctx.file_id, new_size)
            .map_err(|e| vfs_err_to_nt(&e))?;
        make_file_info(&mut vfs, ctx.file_id)
    }

    fn can_delete(&self, _ctx: Self::FileContext, _file_name: &U16CStr) -> Result<(), NTSTATUS> {
        // Always permit; rmdir's NotEmpty check happens in cleanup. A more
        // strict implementation would pre-check directory emptiness here.
        Ok(())
    }

    fn rename(
        &self,
        _ctx: Self::FileContext,
        old_name: &U16CStr,
        new_name: &U16CStr,
        replace_if_exists: bool,
    ) -> Result<(), NTSTATUS> {
        let old = from_win_path(old_name)?;
        let new = from_win_path(new_name)?;
        let (op, ol) = split_parent_name(&old)?;
        let (np, nl) = split_parent_name(&new)?;
        let mut vfs = self.inner.lock().unwrap();
        let from_parent = vfs.lookup_path(op).map_err(|e| vfs_err_to_nt(&e))?;
        // Reuse the same id when both paths share a parent so the VFS
        // takes its single-get_mut fast path; otherwise resolve the
        // distinct destination directory.
        let to_parent = if op == np {
            from_parent
        } else {
            vfs.lookup_path(np).map_err(|e| vfs_err_to_nt(&e))?
        };
        // Honor the Win32 `MoveFileEx` semantics: if the caller did NOT
        // pass MOVEFILE_REPLACE_EXISTING and the target already exists,
        // surface STATUS_OBJECT_NAME_COLLISION instead of silently
        // overwriting. The VFS layer's POSIX behavior is replace-on-
        // conflict, so we enforce the no-replace contract here.
        if !replace_if_exists && vfs.lookup(to_parent, nl).is_ok() {
            return Err(STATUS_OBJECT_NAME_COLLISION);
        }
        vfs.rename(from_parent, ol, to_parent, nl)
            .map_err(|e| vfs_err_to_nt(&e))?;
        let _ = vfs.flush();
        Ok(())
    }

    fn read_directory(
        &self,
        ctx: Self::FileContext,
        marker: Option<&U16CStr>,
        mut add_dir_info: impl FnMut(DirInfo) -> bool,
    ) -> Result<(), NTSTATUS> {
        winfsp_trace!(
            "read_directory",
            format!(
                "file_id={} is_dir={} marker={:?}",
                ctx.file_id,
                ctx.is_dir,
                marker.map(|m| m.to_string().unwrap_or_default())
            )
        );
        if !ctx.is_dir {
            return Err(STATUS_NOT_A_DIRECTORY);
        }
        let mut vfs = self.inner.lock().unwrap();
        let mut entries = vfs.readdir(ctx.file_id).map_err(|e| vfs_err_to_nt(&e))?;
        entries.sort_by(|a, b| a.name.cmp(&b.name));

        // Windows requires every directory listing to begin with `.`
        // (current dir) and `..` (parent dir) entries - NTFS, FAT,
        // exFAT, and every Windows-aware filesystem does this. Without
        // them, Explorer reports the directory as inaccessible
        // ("drive is unavailable, Incorrect function" when the
        // missing entries are at the root). The luksbox-vfs `readdir`
        // returns only the real children (POSIX-style); we synthesize
        // the dot entries here so Explorer sees a proper listing.
        //
        // For the root ("/"), `..` points to itself per POSIX
        // convention. For subdirectories, `..` resolves to the
        // parent inode; luksbox-vfs's `parent_of` gives us that.
        let parent_id = vfs.parent_of(ctx.file_id).unwrap_or(ctx.file_id);
        let dot_entries: [(&str, FileId); 2] = [(".", ctx.file_id), ("..", parent_id)];

        // Marker is the last name returned in the previous batch, skip
        // until we're past it (WinFsp's continuation protocol).
        let marker_str = marker.map(|m| m.to_string().unwrap_or_default());

        // Emit dot entries first (they sort before any real name in
        // ASCII order, matching the order Windows expects).
        for (name_str, id) in &dot_entries {
            if let Some(mk) = &marker_str {
                if (*name_str) <= mk.as_str() {
                    continue;
                }
            }
            let info = make_file_info(&mut vfs, *id)?;
            let name = U16CString::from_str(*name_str).map_err(|_| STATUS_INVALID_PARAMETER)?;
            let dir_info = DirInfo::new(info, &name);
            if !add_dir_info(dir_info) {
                return Ok(());
            }
        }

        for ent in entries {
            if let Some(mk) = &marker_str {
                if ent.name.as_str() <= mk.as_str() {
                    continue;
                }
            }
            let info = make_file_info(&mut vfs, ent.id)?;
            let name = U16CString::from_str(&ent.name).map_err(|_| STATUS_INVALID_PARAMETER)?;
            let dir_info = DirInfo::new(info, &name);
            if !add_dir_info(dir_info) {
                break;
            }
        }
        Ok(())
    }
}

/// Mount the given Vfs at `mountpoint` (a drive letter like `R:` or a
/// directory path on an existing NTFS volume). Blocks the calling
/// thread until Ctrl-C, then calls `FileSystem::stop()` to tear the
/// mount down cleanly. WinFsp doesn't have a `fusermount -u`-style
/// out-of-band unmount API; the only ways to release the kernel
/// mount are the in-process `stop()` (handled here) or letting the
/// process exit, which the kernel driver detects and unwinds.
pub fn mount(vfs: Vfs, mountpoint: &Path) -> Result<(), MountError> {
    winfsp_wrs::init().map_err(map_init_error)?;

    // Default OperationGuardStrategy (Coarse) matches our `Mutex<Vfs>`:
    // WinFsp serializes dispatch under a single internal lock, which is
    // what we'd produce anyway by funnelling through the mutex. The
    // previous `Fine` setting let WinFsp dispatch reads/writes
    // concurrently across its worker threads, all of which then
    // contended on our single Mutex - pure overhead, plus it deviates
    // from the locking contract the C API documents for single-mutex
    // adapters and was correlated with mount-time hangs.
    let mut params = Params::default();
    // FILETIME=0 means 1601-01-01, which Windows accepts on a per-file
    // basis but rejects on the volume itself (a volume with no creation
    // time is treated as malformed and Explorer surfaces the drive as
    // "not accessible"). Use the real current time, same fix the file
    // metadata path documents in `make_file_info`.
    let _ = params
        .volume_params
        .set_volume_creation_time(filetime_now());
    let _ = params.volume_params.set_volume_serial_number(0xC0FFEE_u32);
    let fs_name = U16CString::from_str("luksbox").unwrap();
    let prefix = U16CString::from_str("").unwrap();
    let _ = params.volume_params.set_file_system_name(&fs_name);
    let _ = params.volume_params.set_prefix(&prefix);
    let _ = params.volume_params.set_sector_size(512);
    let _ = params.volume_params.set_sectors_per_allocation_unit(8);
    let _ = params.volume_params.set_max_component_length(255);
    // 1 second metadata cache. Without a non-zero file_info_timeout,
    // WinFsp re-dispatches `get_file_info` / `get_security_by_name`
    // for every Explorer redraw; under heavy enumeration that round-
    // trips through our Mutex<Vfs> often enough to look like a hang
    // ("drive opens but folder takes 30s to populate"). 1000 ms is the
    // memfs example default and matches NTFS-equivalent behaviour for
    // local-volume metadata staleness.
    let _ = params.volume_params.set_file_info_timeout(1000);
    let _ = params.volume_params.set_volume_info_timeout(1000);
    let _ = params.volume_params.set_dir_info_timeout(1000);
    let _ = params.volume_params.set_security_timeout(1000);
    // Skip the post-cleanup callback for files that weren't modified,
    // and the post-disposition callback when the disposition (delete-
    // on-close bit) wasn't actually set. Both are recommended by the
    // canonical memfs sample as default optimizations.
    let _ = params
        .volume_params
        .set_post_cleanup_when_modified_only(true);
    let _ = params
        .volume_params
        .set_post_disposition_only_when_necessary(true);
    // Pass the QueryDirectoryFile filename (search pattern) through to
    // our `read_directory` handler. We currently ignore the pattern
    // (matching is done client-side by the caller) but enabling this
    // flag mirrors the memfs sample and avoids WinFsp's fallback path
    // that double-buffers entries through a kernel allocation.
    let _ = params.volume_params.set_pass_query_directory_filename(true);
    // Allow opens originating in kernel mode (some Windows components,
    // notably Mount Manager probes and the volume-arrival pipeline,
    // enumerate the volume from kernel context immediately after the
    // FS comes up). Without this, those probes silently fail and the
    // drive letter ends up registered but Win32 reports it as an
    // empty / inaccessible drive - DeviceID present, FileSystem blank.
    let _ = params.volume_params.set_allow_open_in_kernel_mode(true);
    // Surface as a real disk volume to consumers that look for WSL /
    // device-control behaviours (Explorer's "this PC" enumerator,
    // backup tools, etc.). Both flags are no-cost on the data path
    // and bring our params in line with the memfs reference.
    let _ = params.volume_params.set_wsl_features(true);
    let _ = params.volume_params.set_device_control(true);
    // Match NTFS semantics: case-preserving but case-insensitive
    // lookups. case_sensitive_search(true) here was breaking some
    // Explorer / Windows-app paths that re-look up names with
    // different casing than how they were stored, which contributed
    // to the "drive unavailable" symptom.
    let _ = params.volume_params.set_case_sensitive_search(false);
    let _ = params.volume_params.set_case_preserved_names(true);
    let _ = params.volume_params.set_unicode_on_disk(true);
    // We hand WinFsp a permissive default SD per file via
    // get_security_by_name (see LuksboxFs::default_security),
    // there's nothing for the volume to persist beyond that.
    let _ = params.volume_params.set_persistent_acls(false);

    let mp_norm = normalize_mountpoint(mountpoint)?;
    let mp = U16CString::from_str(&mp_norm)
        .map_err(|_| MountError::Io(std::io::Error::other("mountpoint contains NUL")))?;

    if winfsp_debug() {
        eprintln!(
            "[winfsp] mount start mountpoint={mp_norm:?} vol_serial=0x{:08X}",
            0xC0FFEE_u32
        );
    }
    let fs = LuksboxFs::new(vfs);
    let running = FileSystem::start(params, Some(&mp), fs).map_err(|e| {
        if winfsp_debug() {
            eprintln!("[winfsp] FileSystem::start FAILED NTSTATUS=0x{:08X}", e);
        }
        MountError::Io(std::io::Error::other(format!(
            "WinFsp start failed: NTSTATUS=0x{e:08X}"
        )))
    })?;
    if winfsp_debug() {
        eprintln!("[winfsp] FileSystem::start OK, dispatcher running");
    }

    // WinFsp's dispatcher runs on its own threads inside the kernel
    // driver; this thread just has to keep `running` (the FileSystem
    // handle) alive. We wait on a channel that gets a signal from
    // either:
    //
    //   1. Ctrl-C in the foreground process (CLI / wizard) - handled
    //      by a process-wide ctrlc handler, installed once via
    //      `install_ctrlc_handler_once()`, that broadcasts to every
    //      mount currently in the registry.
    //
    //   2. A call to `unmount(mountpoint)` from another thread (GUI
    //      "Unmount" button) - looks the mountpoint up in the
    //      registry and sends to its sender.
    //
    // Either way, on wake-up we deregister and call
    // `FileSystem::stop()` to tear the kernel mount down cleanly.
    // Killing the process without `stop()` works in the happy path
    // but has been observed to leave the drive letter half-attached
    // on some Windows builds until the user reboots.
    let (tx, rx) = std::sync::mpsc::channel::<()>();
    let key = PathBuf::from(&mp_norm);
    register_mount(&key, tx);
    install_ctrlc_handler_once();

    let _ = rx.recv();
    deregister_mount(&key);
    if winfsp_debug() {
        eprintln!("[winfsp] received shutdown signal, stopping FS");
    }
    running.stop();
    Ok(())
}

/// Trim a trailing separator from drive-letter mountpoints and return
/// the canonical string form. Drive-letter form must NOT carry a
/// trailing `\` or `/` (`Y:\` is rejected by WinFsp with
/// STATUS_OBJECT_NAME_INVALID, 0xC0000033). Directory-path mounts
/// keep their separators because they're real filesystem paths.
///
/// Pure-string logic lives in `winfsp_path::normalize_mountpoint_str`
/// (testable + fuzzable cross-platform); this wrapper just adapts the
/// `&Path` API and maps errors to `MountError`.
fn normalize_mountpoint(mountpoint: &Path) -> Result<String, MountError> {
    let mp_str = mountpoint
        .to_str()
        .ok_or_else(|| MountError::Io(std::io::Error::other("non-UTF-8 mountpoint")))?;
    normalize_mountpoint_str(mp_str)
        .map_err(|e| MountError::Io(std::io::Error::other(format!("invalid mountpoint: {e:?}"))))
}

/// Process-wide registry of currently-mounted luksbox volumes. Maps the
/// normalized mountpoint to a one-shot sender that wakes the mount
/// thread blocked in `mount()`. Used by `unmount()` to tear down a
/// specific mount without touching the others, and by the Ctrl-C
/// handler to tear down all of them at once.
///
/// Return `(total_bytes, free_bytes_available_to_caller)` for the host
/// drive that holds `path`. Returns `None` on any failure so the caller
/// can fall back to a roomy nominal value. Used by `get_volume_info`
/// to surface honest disk space to Windows Explorer instead of a
/// hardcoded 1 TiB lie. Counterpart to `host_fs_statvfs` on Linux/macOS.
/// Return the string-form SID (`S-1-5-21-...`) of the current
/// process's primary token user. Used to build the volume's default
/// security descriptor so it grants Full Access to the user that
/// mounted the volume rather than to Everyone.
///
/// Returns `None` on any Win32-API failure; the caller falls back to
/// an Administrators+SYSTEM-only ACL in that case (strictly tighter
/// than the previous Everyone default, so a failure-mode never
/// regresses security).
fn current_user_sid() -> Option<String> {
    use std::ffi::c_void;
    use std::ptr;

    use windows_sys::Win32::Foundation::{CloseHandle, HANDLE, LocalFree};
    use windows_sys::Win32::Security::Authorization::ConvertSidToStringSidW;
    use windows_sys::Win32::Security::{GetTokenInformation, TOKEN_QUERY, TOKEN_USER, TokenUser};
    use windows_sys::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

    unsafe {
        // 1. Open the current process's primary token for TOKEN_QUERY.
        let mut token: HANDLE = ptr::null_mut();
        if OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) == 0 {
            return None;
        }

        // 2. Two-call pattern: first call returns the required buffer
        //    size in `len`; second call fills the buffer with a
        //    TOKEN_USER struct.
        let mut len: u32 = 0;
        let _ = GetTokenInformation(token, TokenUser, ptr::null_mut(), 0, &mut len);
        if len == 0 {
            CloseHandle(token);
            return None;
        }
        let mut buf = vec![0u8; len as usize];
        if GetTokenInformation(
            token,
            TokenUser,
            buf.as_mut_ptr() as *mut c_void,
            len,
            &mut len,
        ) == 0
        {
            CloseHandle(token);
            return None;
        }
        CloseHandle(token);

        // 3. Convert the binary SID to the canonical "S-1-..." string
        //    form. ConvertSidToStringSidW allocates the result via
        //    LocalAlloc; we must LocalFree it after copying.
        let user = &*(buf.as_ptr() as *const TOKEN_USER);
        let mut sid_ptr: *mut u16 = ptr::null_mut();
        if ConvertSidToStringSidW(user.User.Sid, &mut sid_ptr) == 0 || sid_ptr.is_null() {
            return None;
        }

        // Find the NUL terminator (max 184 chars per Microsoft docs for
        // ConvertSidToStringSid; the bound caps a runaway scan if the
        // returned buffer is somehow not NUL-terminated).
        let mut count = 0usize;
        while count < 256 && *sid_ptr.add(count) != 0 {
            count += 1;
        }
        let slice = std::slice::from_raw_parts(sid_ptr, count);
        let sid_string = String::from_utf16_lossy(slice);
        LocalFree(sid_ptr as *mut c_void);

        Some(sid_string)
    }
}

fn host_disk_space(path: &Path) -> Option<(u64, u64)> {
    use std::os::windows::ffi::OsStrExt;
    // GetDiskFreeSpaceExW takes a wide-string path; convert and NUL-terminate.
    let mut wpath: Vec<u16> = path.as_os_str().encode_wide().collect();
    wpath.push(0);

    // Direct extern decl avoids pulling in windows-sys / winapi just for
    // one syscall. The signature is stable since Windows 2000.
    #[link(name = "kernel32")]
    unsafe extern "system" {
        fn GetDiskFreeSpaceExW(
            lp_directory_name: *const u16,
            lp_free_bytes_available_to_caller: *mut u64,
            lp_total_number_of_bytes: *mut u64,
            lp_total_number_of_free_bytes: *mut u64,
        ) -> i32;
    }

    let mut free_avail: u64 = 0;
    let mut total: u64 = 0;
    let mut total_free: u64 = 0;
    // SAFETY: wpath is a valid NUL-terminated UTF-16 string; the three
    // output pointers are valid for writes of u64. Win32 BOOL is 0 on
    // failure, nonzero on success.
    let ok = unsafe {
        GetDiskFreeSpaceExW(wpath.as_ptr(), &mut free_avail, &mut total, &mut total_free)
    };
    if ok == 0 {
        None
    } else {
        Some((total, free_avail))
    }
}

/// Stored as a global because mount and unmount are called from
/// independent threads (and on the GUI side, from completely
/// independent egui worker threads): the sender HAS to outlive the
/// stack frame that created it, so the registry owns it.
fn mount_registry() -> &'static Mutex<HashMap<PathBuf, Sender<()>>> {
    static REG: OnceLock<Mutex<HashMap<PathBuf, Sender<()>>>> = OnceLock::new();
    REG.get_or_init(|| Mutex::new(HashMap::new()))
}

fn register_mount(key: &Path, tx: Sender<()>) {
    mount_registry()
        .lock()
        .unwrap()
        .insert(key.to_path_buf(), tx);
}

fn deregister_mount(key: &Path) {
    let _ = mount_registry().lock().unwrap().remove(key);
}

/// Install a process-wide Ctrl-C handler exactly once. The handler
/// broadcasts a stop signal to every mount currently registered. We
/// can't install per-mount handlers because `ctrlc::set_handler`
/// rejects the second call with `MultipleHandlers`, so the first
/// mount's handler would otherwise be the only one that ever fires.
///
/// Unmount-via-channel from `unmount()` keeps working independently
/// regardless of whether this handler installation succeeded - we
/// don't depend on Ctrl-C for the GUI flow.
fn install_ctrlc_handler_once() {
    static INSTALLED: OnceLock<()> = OnceLock::new();
    INSTALLED.get_or_init(|| {
        if let Err(e) = ctrlc::set_handler(|| {
            // Snapshot the senders under the lock and drop the guard
            // before sending - sending on an mpsc is not blocking
            // here (unbounded channel) but we still don't want to
            // hold the registry lock across user-visible work.
            let snapshot: Vec<Sender<()>> = mount_registry()
                .lock()
                .map(|g| g.values().cloned().collect())
                .unwrap_or_default();
            for tx in snapshot {
                let _ = tx.send(());
            }
        }) {
            // Non-fatal: the GUI can still unmount via `unmount()`,
            // and the CLI user can still terminate the process.
            if winfsp_debug() {
                eprintln!("[winfsp] ctrlc::set_handler failed: {e:?}");
            }
        }
    });
}

/// Unmount a luksbox volume that's mounted IN THIS PROCESS. Looks the
/// mountpoint up in the registry, sends the wake-up signal to the
/// owning mount thread, which then calls `FileSystem::stop()` and
/// returns. WinFsp has no out-of-band unmount API equivalent to
/// `fusermount -u`, so cross-process unmount isn't possible - kill
/// the process holding the mount instead.
pub fn unmount(mountpoint: &Path) -> Result<(), MountError> {
    let mp_norm = normalize_mountpoint(mountpoint)?;
    let key = PathBuf::from(&mp_norm);
    let tx = match mount_registry().lock().unwrap().remove(&key) {
        Some(tx) => tx,
        None => {
            return Err(MountError::Io(std::io::Error::other(format!(
                "no luksbox mount at {} found in this process. \
                 Mounts owned by another process can only be released \
                 by terminating that process (Ctrl-C in the foreground \
                 process, or taskkill /pid <pid>); WinFsp does not \
                 expose a cross-process unmount API.",
                mountpoint.display()
            ))));
        }
    };
    // Errors here mean the receiver was already dropped - the mount
    // thread is exiting on its own. Either way, we're done.
    let _ = tx.send(());
    Ok(())
}
