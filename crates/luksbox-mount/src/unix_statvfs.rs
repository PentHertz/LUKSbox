// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Penthertz <https://penthertz.com> (https://x.com/PentHertz)

//! Shared helper for querying the host filesystem's free-space numbers
//! via `statvfs(2)`, used by both the libfuse (`fuse.rs`) and FUSE-T
//! (`fuse_t.rs`) mount adapters.
//!
//! Why this matters: macOS's FUSE-T bridges through the kernel NFS
//! client, which refuses `WRITE3` operations when the server reports
//! `f_bavail == 0` (returns ENOSPC, and Finder shows a "not enough
//! space" warning that blocks drag-and-drop into the volume). Reporting
//! zeros worked on macFUSE / Linux libfuse because their kernels don't
//! gate writes on the statfs reply, but FUSE-T takes it literally.
//!
//! The adapter caches the parent directory of the `.lbx` vault file at
//! construction time, then calls `host_fs_statvfs(parent)` from its
//! `statfs` callback. The reply mirrors host-disk numbers so growth
//! is bounded by actual disk space and file managers report honestly.

use std::path::Path;

pub struct HostFsInfo {
    pub blocks: u64,
    pub bfree: u64,
    pub bavail: u64,
    pub files: u64,
    pub ffree: u64,
    pub bsize: u32,
    pub frsize: u32,
}

/// Query `statvfs(2)` on `path` and return a copy of the relevant
/// fields, or `None` if the syscall failed (the caller falls back to a
/// roomy nominal value so writes are not rejected).
pub fn host_fs_statvfs(path: &Path) -> Option<HostFsInfo> {
    use std::ffi::CString;
    use std::os::unix::ffi::OsStrExt;
    let c_path = CString::new(path.as_os_str().as_bytes()).ok()?;
    // SAFETY: statvfs is signal-safe and the pointer is valid for the
    // call; the buffer is fully written by the syscall on success.
    let mut buf: libc::statvfs = unsafe { std::mem::zeroed() };
    let rc = unsafe { libc::statvfs(c_path.as_ptr(), &mut buf) };
    if rc != 0 {
        return None;
    }
    // statvfs field widths differ across platforms (u64 on Linux,
    // varies on macOS); cast through u64 then clamp the block-size
    // fields to u32 for fuser's ReplyStatfs. The block counts are
    // reported as u64 to fuser and can address the full host disk;
    // the FUSE-T shim further clamps to u32 on macOS (POSIX
    // fsblkcnt_t) which still allows up to ~16 TiB at 4 KiB blocks.
    Some(HostFsInfo {
        blocks: buf.f_blocks as u64,
        bfree: buf.f_bfree as u64,
        bavail: buf.f_bavail as u64,
        files: buf.f_files as u64,
        ffree: buf.f_ffree as u64,
        bsize: u32::try_from(buf.f_bsize as u64).unwrap_or(4096),
        frsize: u32::try_from(buf.f_frsize as u64).unwrap_or(4096),
    })
}
