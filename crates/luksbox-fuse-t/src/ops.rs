// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Penthertz <https://penthertz.com> (https://x.com/PentHertz)

//! Safe wrapper around the libfuse 2.x high-level callbacks.
//!
//! The strategy is the standard libfuse pattern: build a `struct
//! fuse_operations` of `extern "C"` trampolines, hand it to
//! `fuse_main_real` together with a `user_data` pointer to a boxed
//! `dyn Filesystem`, then let libfuse drive the kernel↔userspace
//! event loop. Each trampoline does:
//!
//! 1. `fuse_get_context()->private_data` -> &dyn Filesystem
//! 2. translate C args (path C string -> &Path, raw buffers -> slices)
//! 3. call the trait method, catching panics so a buggy impl can't
//!    take down the FUSE thread mid-syscall (FUSE-T runs callbacks
//!    on its own NFS-server worker threads; a panic there leaves the
//!    NFS connection wedged)
//! 4. map `Result<T, Errno>` back to libfuse's negative-errno
//!    convention.
//!
//! Threading: libfuse's default is multi-threaded. We force `-s`
//! (single-threaded) for v1 because our Vfs is `Mutex<...>`-wrapped
//! and the per-callback lock contention is fine for a personal
//! encrypted-container workload, but doesn't justify the extra
//! audit cost of running concurrently. Phase 2 may revisit if
//! benchmarks show single-thread mode bottlenecking on large reads.

use std::ffi::{CStr, CString};
use std::fs::OpenOptions;
use std::io::Write;
use std::os::raw::{c_char, c_int, c_void};
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::path::{Path, PathBuf};
use std::ptr::{self, NonNull};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use crate::sys;
use crate::{Errno, FileAttr, Filesystem, MountError, MountOptions, S_IFDIR};

/// Bridge between FUSE's `user_data` slot and our typed Filesystem.
///
/// Ownership model: an `Arc<FsHolder>` is constructed in `run_mount`
/// and lives on its stack frame for the duration of the FUSE session.
/// We hand libfuse a raw pointer derived from `Arc::as_ptr` - libfuse
/// does NOT own the allocation. When `run_mount` returns (after
/// `fuse_main_real` exits), the Arc is dropped, FsHolder is dropped,
/// the user's Filesystem impl is dropped.
///
/// The `destroyed` flag is a CAS-guarded sentinel so `op_destroy` is
/// idempotent: a second call (libfuse buggy or runtime quirk) sees
/// `destroyed = true` and fast-returns instead of re-running
/// `Filesystem::destroy()`. Trampolines also check it on entry; once
/// flipped, every callback returns -EIO. This is the explicit
/// "post-destroy / post-panic" mode that replaces the implicit
/// Mutex-poisoning DoS we used to lean on.
struct FsHolder {
    fs: Box<dyn Filesystem>,
    destroyed: AtomicBool,
}

/// Convert a libfuse callback's `const char *path` to a `PathBuf`.
/// Returns `None` if the path is null or non-UTF-8 (we treat that as
/// EINVAL upstream).
fn cstr_to_path(p: *const c_char) -> Option<PathBuf> {
    if p.is_null() {
        return None;
    }
    // SAFETY: libfuse guarantees `path` is a NUL-terminated C string
    // valid for the duration of the callback.
    let cs = unsafe { CStr::from_ptr(p) };
    let s = cs.to_str().ok()?;
    Some(PathBuf::from(s))
}

/// Fetch the current FsHolder via libfuse's per-request context.
/// Returns `None` if libfuse hasn't initialized yet OR if the holder
/// has already been destroyed (post-destroy callbacks fast-fail).
///
/// Lifetime: the returned reference is bound to the call site, NOT
/// `'static`. The pointee actually lives until `run_mount` returns;
/// each trampoline takes the reference, uses it within the same call,
/// and drops it before returning to libfuse. The borrow is sound for
/// that scope because `run_mount` blocks until libfuse stops calling
/// us, and we forced single-threaded mode (`-s`) so callbacks don't
/// race with destroy.
///
/// SAFETY: the caller must invoke this from inside a libfuse callback
/// (i.e. from the FUSE event loop), where `fuse_get_context()` is
/// well-defined and the `private_data` pointer points at the
/// `FsHolder` `run_mount` registered. Outside of that context, `ctx`
/// is undefined.
unsafe fn current_fs<'a>() -> Option<&'a FsHolder> {
    let ctx = unsafe { sys::fuse_get_context() };
    if ctx.is_null() {
        return None;
    }
    let pd = unsafe { (*ctx).private_data };
    let holder_ptr = NonNull::new(pd as *mut FsHolder)?;
    // SAFETY: holder_ptr was set in run_mount via Arc::as_ptr and the
    // owning Arc on run_mount's stack outlives every callback. The
    // `'a` lifetime is the call's lifetime, not 'static.
    let holder: &'a FsHolder = unsafe { holder_ptr.as_ref() };
    if holder.destroyed.load(Ordering::Acquire) {
        return None;
    }
    Some(holder)
}

/// Standard trampoline preamble: resolve the FsHolder, run `body`
/// against it, catch panics, and on panic flip the holder's
/// `destroyed` flag so every subsequent callback fast-fails with
/// -EIO. This is the explicit "post-panic mode" that replaces the
/// implicit Mutex-poisoning DoS we used to lean on, the user gets
/// a deterministic dead mount instead of a slow trickle of ambiguous
/// EIOs from a poisoned lock.
///
/// Returns -EIO if the holder is missing (libfuse not initialized,
/// or destroyed). The body itself returns the raw libfuse return
/// value (positive = bytes, 0 = success, negative = -errno).
fn with_fs<F>(body: F) -> c_int
where
    F: FnOnce(&FsHolder) -> c_int,
{
    // Resolve the holder OUTSIDE the panic-catching scope so that a
    // post-destroy callback short-circuits without touching `body`.
    // SAFETY: callers are libfuse trampolines, see current_fs.
    let Some(holder) = (unsafe { current_fs() }) else {
        return -libc::EIO;
    };
    // Stash a NonNull so we can flip `destroyed` from the panic arm
    // without reborrowing through `holder` (which moved into `body`).
    let holder_ptr: NonNull<FsHolder> = NonNull::from(holder);
    match catch_unwind(AssertUnwindSafe(|| body(holder))) {
        Ok(rc) => rc,
        Err(_) => {
            // SAFETY: holder_ptr is the same address `current_fs`
            // returned moments ago; the owning Arc on run_mount's
            // stack is still alive. Setting destroyed makes every
            // subsequent callback (including the next attempt at
            // this same operation) fast-fail with -EIO via
            // current_fs's destroyed-check.
            unsafe { holder_ptr.as_ref() }
                .destroyed
                .store(true, Ordering::Release);
            -libc::EIO
        }
    }
}

fn to_errno(r: Result<(), Errno>) -> c_int {
    match r {
        Ok(()) => 0,
        Err(e) => -e.0,
    }
}

/// Convert a kernel-supplied `off_t` to a `u64`, rejecting negatives.
/// libfuse SHOULD never pass a negative offset (it's a bug if it
/// does), but `as u64` would silently wrap to a huge value, the FS
/// would read/write at that address, and the kernel would see "EOF"
/// or "succeeded with 0 bytes" with no diagnostic. Better to refuse
/// up front.
fn off_to_u64(off: libc::off_t) -> Result<u64, c_int> {
    if off < 0 {
        Err(-libc::EINVAL)
    } else {
        Ok(off as u64)
    }
}

/// Convert a Rust-side byte count back to libfuse's positive-int
/// return value. Truncation is silent corruption (kernel thinks
/// fewer bytes were read/written than actually were), `try_into`
/// catches it and we return -EOVERFLOW. libfuse caps single
/// read/write at FUSE_MAX_WRITE (~4 MiB) so this is defense in
/// depth, not currently reachable.
fn n_to_c_int(n: usize) -> c_int {
    match c_int::try_from(n) {
        Ok(v) => v,
        Err(_) => -libc::EOVERFLOW,
    }
}

// ---------------------------------------------------------------
// Trampolines
// ---------------------------------------------------------------

// libfuse 2.x callbacks take `struct stat *` / `struct statvfs *`
// from the system headers. bindgen generates Rust mirrors of those
// structs (`sys::stat`, `sys::statvfs`) and uses them in the
// `fuse_operations` function pointer signatures. They have the same
// memory layout as `libc::stat` / `libc::statvfs` on macOS but are
// distinct Rust types, so the trampolines below MUST use the
// bindgen-generated names or the `Some(op_getattr)` assignment in
// `build_operations` won't type-check (E0308: fn pointer mismatch).
unsafe extern "C" fn op_getattr(path: *const c_char, stbuf: *mut sys::stat) -> c_int {
    with_fs(|holder| {
        let Some(p) = cstr_to_path(path) else {
            return -libc::EINVAL;
        };
        match holder.fs.getattr(&p) {
            Ok(attr) => {
                if stbuf.is_null() {
                    return -libc::EINVAL;
                }
                // SAFETY: stbuf is a libfuse-provided out-param,
                // valid for the call duration.
                unsafe { ptr::write_bytes(stbuf, 0, 1) };
                let s = unsafe { &mut *stbuf };
                fill_stat(s, &attr);
                0
            }
            Err(e) => -e.0,
        }
    })
}

fn fill_stat(s: &mut sys::stat, a: &FileAttr) {
    // Field types come from bindgen's view of `<sys/stat.h>`, which
    // are NOT the same as libc's convenience-flattened equivalents
    // (libc collapses st_atimespec etc. into separate st_atime /
    // st_atime_nsec fields; bindgen preserves the nested timespec
    // shape that the C header actually uses on macOS).
    //
    // Cast everything through `as` to whichever unsigned/signed
    // integer the bindgen output requires; `try_from` for the
    // potentially-overflowing conversions (u64 -> i64 etc.) so a
    // corrupt FileAttr clamps instead of wrapping silently.
    s.st_mode = a.mode as _;
    s.st_size = i64::try_from(a.size).unwrap_or(i64::MAX) as _;
    s.st_uid = a.uid as _;
    s.st_gid = a.gid as _;
    s.st_nlink = a.nlink as _;
    s.st_blksize = 4096;
    s.st_blocks = i64::try_from(a.size.div_ceil(512)).unwrap_or(i64::MAX) as _;
    let secs_u = a.mtime_ns / 1_000_000_000;
    let secs = i64::try_from(secs_u).unwrap_or(i64::MAX);
    let nsec = (a.mtime_ns % 1_000_000_000) as i64; // <1e9, always fits
    // macOS struct stat uses nested timespec sub-structs:
    //   struct timespec st_atimespec, st_mtimespec, st_ctimespec, st_birthtimespec;
    // Write through the nested form. bindgen's timespec has
    // `tv_sec` and `tv_nsec` fields; cast through `as _` to absorb
    // platform-typedef differences (e.g. __darwin_time_t).
    s.st_atimespec.tv_sec = secs as _;
    s.st_atimespec.tv_nsec = nsec as _;
    s.st_mtimespec.tv_sec = secs as _;
    s.st_mtimespec.tv_nsec = nsec as _;
    s.st_ctimespec.tv_sec = secs as _;
    s.st_ctimespec.tv_nsec = nsec as _;
    // st_birthtimespec is intentionally left at the memset-zero
    // initialised value (epoch). bindgen only emits the field when
    // the FUSE-T headers were compiled with `_DARWIN_USE_64_BIT_INODE`
    // visible to clang; the FUSE wrapper.h doesn't force that macro,
    // so the field's presence depends on the SDK headers picked up at
    // bindgen time. Skipping the assignment keeps the binding portable
    // across macOS SDK versions; Finder shows the file's birth time as
    // 1970-01-01 instead of mtime, which is harmless for a vault.
}

unsafe extern "C" fn op_readdir(
    path: *const c_char,
    buf: *mut c_void,
    filler: sys::fuse_fill_dir_t,
    _offset: libc::off_t,
    _fi: *mut sys::fuse_file_info,
) -> c_int {
    with_fs(|holder| {
        let Some(p) = cstr_to_path(path) else {
            return -libc::EINVAL;
        };
        let entries = match holder.fs.readdir(&p) {
            Ok(e) => e,
            Err(e) => return -e.0,
        };
        let Some(filler) = filler else {
            return -libc::EIO;
        };
        // libfuse convention: emit "." and ".." first.
        let dot = c".";
        let ddot = c"..";
        unsafe {
            let _ = filler(buf, dot.as_ptr(), ptr::null(), 0);
            let _ = filler(buf, ddot.as_ptr(), ptr::null(), 0);
        }
        for entry in entries {
            let Ok(name) = CString::new(entry.name.as_bytes()) else {
                continue;
            };
            // We don't fill in stat for each entry (would require
            // an extra getattr per file), let the kernel issue a
            // separate lookup. libfuse accepts a NULL stat ptr.
            unsafe {
                if filler(buf, name.as_ptr(), ptr::null(), 0) != 0 {
                    // Buffer full; libfuse will call us again with a
                    // higher offset (we ignore offset, which is
                    // legal in "no offset" mode).
                    break;
                }
            }
        }
        0
    })
}

unsafe extern "C" fn op_open(path: *const c_char, fi: *mut sys::fuse_file_info) -> c_int {
    with_fs(|holder| {
        let Some(p) = cstr_to_path(path) else {
            return -libc::EINVAL;
        };
        let flags = if fi.is_null() {
            0
        } else {
            unsafe { (*fi).flags }
        };
        to_errno(holder.fs.open(&p, flags))
    })
}

unsafe extern "C" fn op_read(
    path: *const c_char,
    buf: *mut c_char,
    size: usize,
    offset: libc::off_t,
    _fi: *mut sys::fuse_file_info,
) -> c_int {
    with_fs(|holder| {
        let Some(p) = cstr_to_path(path) else {
            return -libc::EINVAL;
        };
        if buf.is_null() {
            return -libc::EINVAL;
        }
        let off = match off_to_u64(offset) {
            Ok(v) => v,
            Err(rc) => return rc,
        };
        // SAFETY: libfuse guarantees `buf` is writable for `size` bytes
        // and lives for the duration of this call.
        let slice = unsafe { std::slice::from_raw_parts_mut(buf as *mut u8, size) };
        match holder.fs.read(&p, slice, off) {
            Ok(n) => n_to_c_int(n),
            Err(e) => -e.0,
        }
    })
}

unsafe extern "C" fn op_write(
    path: *const c_char,
    buf: *const c_char,
    size: usize,
    offset: libc::off_t,
    _fi: *mut sys::fuse_file_info,
) -> c_int {
    with_fs(|holder| {
        let Some(p) = cstr_to_path(path) else {
            return -libc::EINVAL;
        };
        if buf.is_null() {
            return -libc::EINVAL;
        }
        let off = match off_to_u64(offset) {
            Ok(v) => v,
            Err(rc) => return rc,
        };
        // SAFETY: libfuse guarantees `buf` is readable for `size`
        // bytes and lives for the duration of this call.
        let slice = unsafe { std::slice::from_raw_parts(buf as *const u8, size) };
        match holder.fs.write(&p, slice, off) {
            Ok(n) => n_to_c_int(n),
            Err(e) => -e.0,
        }
    })
}

unsafe extern "C" fn op_create(
    path: *const c_char,
    mode: libc::mode_t,
    fi: *mut sys::fuse_file_info,
) -> c_int {
    with_fs(|holder| {
        let Some(p) = cstr_to_path(path) else {
            return -libc::EINVAL;
        };
        // libfuse convention: after create, the file is "open" and
        // subsequent read/write goes through the same fi without a
        // separate open() call. We don't track per-open state, so the
        // `fi` mutation is just to clear flags libfuse might check.
        if !fi.is_null() {
            unsafe { (*fi).fh = 0 };
        }
        to_errno(holder.fs.create(&p, mode as u32))
    })
}

unsafe extern "C" fn op_mkdir(path: *const c_char, mode: libc::mode_t) -> c_int {
    with_fs(|holder| {
        let Some(p) = cstr_to_path(path) else {
            return -libc::EINVAL;
        };
        to_errno(holder.fs.mkdir(&p, mode as u32))
    })
}

unsafe extern "C" fn op_unlink(path: *const c_char) -> c_int {
    with_fs(|holder| {
        let Some(p) = cstr_to_path(path) else {
            return -libc::EINVAL;
        };
        to_errno(holder.fs.unlink(&p))
    })
}

unsafe extern "C" fn op_rmdir(path: *const c_char) -> c_int {
    with_fs(|holder| {
        let Some(p) = cstr_to_path(path) else {
            return -libc::EINVAL;
        };
        to_errno(holder.fs.rmdir(&p))
    })
}

unsafe extern "C" fn op_rename(from: *const c_char, to: *const c_char) -> c_int {
    with_fs(|holder| {
        let Some(f) = cstr_to_path(from) else {
            return -libc::EINVAL;
        };
        let Some(t) = cstr_to_path(to) else {
            return -libc::EINVAL;
        };
        to_errno(holder.fs.rename(&f, &t))
    })
}

unsafe extern "C" fn op_truncate(path: *const c_char, size: libc::off_t) -> c_int {
    with_fs(|holder| {
        let Some(p) = cstr_to_path(path) else {
            return -libc::EINVAL;
        };
        let new_size = match off_to_u64(size) {
            Ok(v) => v,
            Err(rc) => return rc,
        };
        to_errno(holder.fs.truncate(&p, new_size))
    })
}

unsafe extern "C" fn op_flush(path: *const c_char, _fi: *mut sys::fuse_file_info) -> c_int {
    with_fs(|holder| {
        let Some(p) = cstr_to_path(path) else {
            return -libc::EINVAL;
        };
        to_errno(holder.fs.flush(&p))
    })
}

unsafe extern "C" fn op_fsync(
    path: *const c_char,
    datasync: c_int,
    _fi: *mut sys::fuse_file_info,
) -> c_int {
    with_fs(|holder| {
        let Some(p) = cstr_to_path(path) else {
            return -libc::EINVAL;
        };
        to_errno(holder.fs.fsync(&p, datasync != 0))
    })
}

unsafe extern "C" fn op_release(path: *const c_char, _fi: *mut sys::fuse_file_info) -> c_int {
    with_fs(|holder| {
        let Some(p) = cstr_to_path(path) else {
            return -libc::EINVAL;
        };
        to_errno(holder.fs.release(&p))
    })
}

unsafe extern "C" fn op_statfs(path: *const c_char, sv: *mut sys::statvfs) -> c_int {
    with_fs(|holder| {
        let Some(p) = cstr_to_path(path) else {
            return -libc::EINVAL;
        };
        match holder.fs.statfs(&p) {
            Ok(s) => {
                if sv.is_null() {
                    return -libc::EINVAL;
                }
                unsafe { ptr::write_bytes(sv, 0, 1) };
                let out = unsafe { &mut *sv };
                // macOS's `fsblkcnt_t` / `fsfilcnt_t` are `unsigned int`
                // (u32) for POSIX legacy reasons - Linux uses u64. Our
                // `StatVfs` uses u64 to match the wider Linux shape;
                // clamp to the destination width via try_from so a
                // spuriously huge value reports "u32::MAX blocks free"
                // rather than wrapping to a small/zero number.
                // `as _` defers the bindgen-generated typedef name
                // (might be `__darwin_fsblkcnt_t` etc.).
                out.f_blocks = u32::try_from(s.blocks).unwrap_or(u32::MAX) as _;
                out.f_bfree = u32::try_from(s.bfree).unwrap_or(u32::MAX) as _;
                out.f_bavail = u32::try_from(s.bavail).unwrap_or(u32::MAX) as _;
                out.f_files = u32::try_from(s.files).unwrap_or(u32::MAX) as _;
                out.f_ffree = u32::try_from(s.ffree).unwrap_or(u32::MAX) as _;
                out.f_bsize = s.bsize as _;
                out.f_frsize = s.frsize as _;
                out.f_namemax = s.namemax as _;
                0
            }
            Err(e) => -e.0,
        }
    })
}

unsafe extern "C" fn op_access(path: *const c_char, mask: c_int) -> c_int {
    with_fs(|holder| {
        let Some(p) = cstr_to_path(path) else {
            return -libc::EINVAL;
        };
        to_errno(holder.fs.access(&p, mask))
    })
}

unsafe extern "C" fn op_destroy(_priv: *mut c_void) {
    // Idempotent: CAS-flip the `destroyed` flag, only the winner
    // calls Filesystem::destroy(). A second invocation (libfuse bug,
    // runtime quirk) sees `destroyed = true` and fast-returns without
    // touching the user's destroy logic again. We do NOT free the
    // FsHolder here, the owning Arc lives on `run_mount`'s stack and
    // is dropped when fuse_main_real returns.
    trace("op_destroy entered (libfuse is tearing down the session)");
    let Some(holder_ptr) = NonNull::new(_priv as *mut FsHolder) else {
        trace("op_destroy: NULL private_data, returning");
        return;
    };
    // SAFETY: holder_ptr came from Arc::as_ptr in run_mount; the Arc
    // on run_mount's stack outlives this call.
    let holder = unsafe { holder_ptr.as_ref() };
    if holder.destroyed.swap(true, Ordering::AcqRel) {
        trace("op_destroy: already destroyed flag was set; this is a repeat call");
        return;
    }
    // Catch panics so a buggy Filesystem::destroy can't take down
    // libfuse's teardown thread; we still mark destroyed above so
    // subsequent callbacks fast-fail.
    let _ = catch_unwind(AssertUnwindSafe(|| holder.fs.destroy()));
    trace("op_destroy: Filesystem::destroy completed");
}

// ---------------------------------------------------------------
// fuse_operations construction
// ---------------------------------------------------------------

// Layout pin: every `Option<unsafe extern "C" fn(...)>` in
// `fuse_operations` is niche-optimized so that all-zero == None.
// `build_operations` relies on this when it zero-initializes the
// struct and selectively writes the callbacks we implement. If a
// future libfuse-t adds a non-Option field (e.g. a raw pointer with
// no `None` niche, or a non-zero-valid enum), zero-init becomes UB
// and we need to switch to per-field initialization. The compile-
// time check below pins the layout assumption; if it ever fires,
// re-audit `build_operations` before silencing.
const _ASSERT_OPTION_FN_PTR_NICHE: () = {
    assert!(
        core::mem::size_of::<Option<unsafe extern "C" fn()>>() == core::mem::size_of::<*const ()>(),
        "Option<unsafe extern \"C\" fn()> must be niche-optimized to a pointer; \
         build_operations's zero-init relies on this. If this fails, switch to \
         explicit per-field initialization in build_operations."
    );
};

/// Build the `fuse_operations` table for our session.
///
/// SAFETY: relies on `Option<fn>` being niche-optimized so that an
/// all-zero `fuse_operations` is the equivalent of `Default::default()`
/// - every callback slot is `None`, every flag bit is 0. The
/// `_ASSERT_OPTION_FN_PTR_NICHE` const above pins the relevant half
/// of that assumption at compile time. The other half (no field of
/// `fuse_operations` requires a non-zero value to be valid) is
/// audited against the current libfuse-t header (libfuse 2.9 shape):
/// every field is either `Option<...>`, a `c_uint` bitfield (zero
/// means "flag off"), or a `c_int` (zero is a valid value). When
/// regenerating bindings against a newer libfuse-t, re-confirm by
/// reading the bindgen output before this file goes through CI.
fn build_operations() -> sys::fuse_operations {
    // SAFETY: see the module comment above.
    let mut ops: sys::fuse_operations = unsafe { core::mem::zeroed() };
    ops.getattr = Some(op_getattr);
    ops.readdir = Some(op_readdir);
    ops.open = Some(op_open);
    ops.read = Some(op_read);
    ops.write = Some(op_write);
    ops.create = Some(op_create);
    ops.mkdir = Some(op_mkdir);
    ops.unlink = Some(op_unlink);
    ops.rmdir = Some(op_rmdir);
    ops.rename = Some(op_rename);
    ops.truncate = Some(op_truncate);
    ops.flush = Some(op_flush);
    ops.fsync = Some(op_fsync);
    ops.release = Some(op_release);
    ops.statfs = Some(op_statfs);
    ops.access = Some(op_access);
    ops.destroy = Some(op_destroy);
    ops
}

/// Diagnostic log target for FUSE-T mount lifecycle events.
///
/// Writes to BOTH stderr (visible if launched from Terminal) AND
/// `~/Library/Logs/LUKSbox/fuse-t.log` (visible regardless of launch
/// method, so a Finder-double-click of LUKSbox.app produces a
/// readable trace of the mount session). The file is opened in
/// append mode and timestamped per-line so a user reporting a bug
/// can include the most recent session.
///
/// Falls back to stderr-only on any I/O error so the diagnostic
/// path never causes its own failures.
fn trace(msg: &str) {
    let line = format!("{}: luksbox-fuse-t: {}", chrono_like_now(), msg);
    eprintln!("{line}");
    if let Some(path) = trace_log_path() {
        if let Some(parent) = path.parent() {
            let _ = std::fs::create_dir_all(parent);
        }
        if let Ok(mut f) = OpenOptions::new().create(true).append(true).open(&path) {
            let _ = writeln!(f, "{line}");
        }
    }
}

/// `~/Library/Logs/LUKSbox/fuse-t.log` on macOS, `None` elsewhere
/// (the binding is macOS-only at the runtime level, the file path
/// follows Apple's per-user log directory convention).
fn trace_log_path() -> Option<PathBuf> {
    let home = std::env::var_os("HOME")?;
    let mut p = PathBuf::from(home);
    p.push("Library");
    p.push("Logs");
    p.push("LUKSbox");
    p.push("fuse-t.log");
    Some(p)
}

/// Return a timestamp string for the trace log. We avoid pulling in
/// the `chrono` crate just for this; SystemTime + a hand-formatter
/// is enough for log-correlation purposes.
fn chrono_like_now() -> String {
    let dur = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default();
    let secs = dur.as_secs();
    let millis = dur.subsec_millis();
    // ISO-ish but Unix-time-based; good enough to correlate with
    // `Console.app`'s timestamps when needed.
    format!("[t={secs}.{millis:03}]")
}

// ---------------------------------------------------------------
// Mount entry point
// ---------------------------------------------------------------

/// Minimum libfuse ABI we accept at runtime. Compiled against
/// libfuse 2.9 (FUSE_USE_VERSION=29 in wrapper.h); a runtime libfuse
/// reporting < 29 means our `fuse_operations` layout doesn't match
/// what the dylib expects -> wild dereferences inside libfuse-t. Fail
/// fast with a clear error instead.
const MIN_FUSE_ABI: i32 = 29;

pub(crate) fn run_mount<F: Filesystem + 'static>(
    fs: F,
    mountpoint: &Path,
    options: &MountOptions,
) -> Result<(), MountError> {
    // Runtime ABI check: the libfuse-t.dylib we're about to call
    // might have been built against a different libfuse header
    // version than our bindings. fuse_version() reports MAJOR*10+MINOR
    // - refuse to mount if it's lower than what we built against.
    // SAFETY: fuse_version takes no args and has no preconditions.
    let runtime_abi = unsafe { sys::fuse_version() };
    if runtime_abi < MIN_FUSE_ABI {
        return Err(MountError::Mount(format!(
            "libfuse-t.dylib reports ABI {runtime_abi}, need >= {MIN_FUSE_ABI}. \
             Reinstall FUSE-T (brew reinstall --cask fuse-t)."
        )));
    }
    let ops = build_operations();

    // Construct the holder as an Arc owned by THIS stack frame.
    // libfuse gets a raw pointer derived from `Arc::as_ptr` (no
    // ownership transfer), so `op_destroy` doesn't have to reclaim
    // memory and can't double-free if libfuse calls it twice. The
    // Arc is dropped when this function returns (after fuse_main_real
    // exits), which is the natural end of the FUSE session.
    let holder: Arc<FsHolder> = Arc::new(FsHolder {
        fs: Box::new(fs),
        destroyed: AtomicBool::new(false),
    });
    let user_data = Arc::as_ptr(&holder) as *mut c_void;

    // Build argv. libfuse's high-level entry point parses these like
    // a command line: argv[0] = program name, then `-o opt=val`
    // options, then the mountpoint. We force `-f` (foreground, since
    // our caller daemonizes if it needs to) and `-s` (single-threaded;
    // see module docstring for why). Capacity rough-sized; CString
    // allocations live in `_owned` until the function returns so
    // libfuse can read them via the *mut c_char pointers in `argv`.
    let mut owned: Vec<CString> = Vec::with_capacity(16);
    owned.push(CString::new("luksbox-fuse-t").unwrap());
    owned.push(CString::new("-f").unwrap());
    owned.push(CString::new("-s").unwrap());

    let mut o_parts: Vec<String> = Vec::new();
    o_parts.push(format!("fsname={}", options.fsname));
    o_parts.push(format!("subtype={}", options.subtype));
    if options.default_permissions {
        o_parts.push("default_permissions".into());
    }
    if options.nosuid {
        o_parts.push("nosuid".into());
    }
    if options.nodev {
        o_parts.push("nodev".into());
    }
    if options.noatime {
        o_parts.push("noatime".into());
    }
    if let Some(volname) = &options.volname {
        o_parts.push(format!("volname={volname}"));
    }
    if !o_parts.is_empty() {
        owned.push(CString::new("-o").unwrap());
        owned.push(CString::new(o_parts.join(",")).unwrap());
    }

    let mp_c = CString::new(mountpoint.as_os_str().as_encoded_bytes()).map_err(|e| {
        MountError::InvalidMountpoint {
            path: mountpoint.display().to_string(),
            reason: format!("contains NUL byte: {e}"),
        }
    })?;
    owned.push(mp_c);

    // Build argv as a Vec of *mut c_char (libfuse expects mutable
    // since it parses + reorders in place). We borrow into the
    // CStrings; they outlive `argv` because `owned` is on this
    // function's stack and we don't return until fuse_main_real does.
    let mut argv: Vec<*mut c_char> = owned.iter().map(|cs| cs.as_ptr() as *mut c_char).collect();
    let argc = argv.len() as c_int;

    // Save the current process-wide signal dispositions for the
    // signals libfuse 2.x's high-level API installs handlers for
    // (SIGTERM, SIGINT, SIGHUP, SIGPIPE). `fuse_main_real` calls
    // `fuse_set_signal_handlers` internally, which writes new
    // sigaction entries; `fuse_teardown` calls
    // `fuse_remove_signal_handlers` to restore them. In practice
    // (observed on FUSE-T 1.x with the GUI host process) the
    // restore path is unreliable: handlers can be left in a state
    // where a SIGTERM from the FUSE-T helper-process exit kills the
    // GUI process the next time anything triggers it. We
    // belt-and-suspenders this by saving + restoring ourselves
    // around the call. Same approach used by other host apps that
    // embed libfuse (sshfs's macOS GUI fork etc.).
    //
    // SIGCHLD is NOT in the list: libfuse doesn't install a handler
    // for it, but FUSE-T's go-nfsv4 helper IS a child of our
    // process and exits at unmount time. Default SIGCHLD action is
    // SIG_DFL = ignore; leaving it alone is correct.
    const SAVED_SIGS: &[i32] = &[libc::SIGTERM, libc::SIGINT, libc::SIGHUP, libc::SIGPIPE];
    let mut saved: Vec<libc::sigaction> = Vec::with_capacity(SAVED_SIGS.len());
    for &sig in SAVED_SIGS {
        // SAFETY: zeroed sigaction is a valid initial value;
        // sigaction with a NULL new-action and a non-NULL oldact
        // queries the current handler without modifying it.
        let mut old: libc::sigaction = unsafe { std::mem::zeroed() };
        let r = unsafe { libc::sigaction(sig, std::ptr::null(), &mut old) };
        if r != 0 {
            // Don't fail the mount over this - just log and continue
            // without restore for that specific signal. Safer to mount
            // than to bail out for a diagnostic-grade defense.
            trace(&format!(
                "warning: sigaction({sig}, query) failed; \
                 won't be able to restore the original handler after unmount"
            ));
        }
        saved.push(old);
    }

    trace(&format!(
        "entering fuse_main_real (mountpoint={}, abi={runtime_abi})",
        mountpoint.display()
    ));

    // SAFETY: argv and ops are valid for the call. user_data is a
    // raw pointer derived from Arc::as_ptr; the owning Arc on this
    // stack frame outlives the call. The `&ops` borrow is alive for
    // the call. fuse_main_real blocks until unmount.
    let rc = unsafe {
        sys::fuse_main_real(
            argc,
            argv.as_mut_ptr(),
            &ops as *const sys::fuse_operations,
            std::mem::size_of::<sys::fuse_operations>(),
            user_data,
        )
    };

    trace(&format!(
        "fuse_main_real returned (rc={rc}); restoring signal handlers"
    ));

    // Restore the saved signal dispositions. Use SA_RESTART /
    // SA_NOCLDSTOP flags as set in `saved`.
    for (sig, old) in SAVED_SIGS.iter().zip(saved.iter()) {
        // SAFETY: `old` was populated by the query above; its layout
        // is a valid sigaction struct.
        let r = unsafe { libc::sigaction(*sig, old as *const _, std::ptr::null_mut()) };
        if r != 0 {
            trace(&format!(
                "warning: sigaction({sig}, restore) failed; \
                 default handler will be used for this signal"
            ));
        }
    }

    trace("signal handlers restored, mount session ended cleanly");

    // Belt-and-suspenders: mark destroyed even if libfuse never
    // called op_destroy (early failure paths). Any stray callback
    // that fires after we return here will load `destroyed = true`
    // via current_fs and fast-fail with -EIO. The Arc itself is
    // dropped at the end of this function so the underlying
    // FsHolder + Filesystem are freed normally.
    holder.destroyed.store(true, Ordering::Release);

    // Suppress unused-must-use on owned, the CStrings hold the backing
    // storage for argv pointers and must live until here.
    drop(owned);

    if rc != 0 {
        return Err(MountError::Mount(format!("fuse_main_real returned {rc}")));
    }
    Ok(())
}

// Suppress unused warnings for the imports kept around for future
// expansion (truncate via SystemTime conversion, etc.).
#[allow(dead_code)]
fn _unused_imports() {
    let _ = (S_IFDIR, SystemTime::now(), UNIX_EPOCH);
}
