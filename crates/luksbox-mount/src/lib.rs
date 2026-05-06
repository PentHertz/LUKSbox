// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Penthertz <https://penthertz.com> (https://x.com/PentHertz)

//! luksbox-mount, userspace-filesystem adapter wiring `luksbox-vfs::Vfs`
//! into the host OS as a real mount point.
//!
//! - Linux/macOS: `fuser` (FUSE3 / macFUSE).
//! - Windows: `winfsp_wrs` (requires the WinFsp 2.x kernel driver
//!   installed at runtime, https://winfsp.dev/rel/).

use std::path::Path;

use thiserror::Error;

#[cfg(all(any(target_os = "linux", target_os = "macos"), feature = "fuse"))]
mod fuse;

#[cfg(all(target_os = "windows", feature = "winfsp"))]
mod winfsp;

// Pure-string parsing helpers used by the WinFsp adapter. Compiled on
// every platform so unit tests + fuzz harnesses can exercise them
// without the WinFsp SDK / kernel driver. See `winfsp_path.rs` for
// the full rationale.
pub mod winfsp_path;

#[derive(Debug, Error)]
pub enum MountError {
    #[error("io: {0}")]
    Io(#[from] std::io::Error),

    /// The mount entry point is the no-op stub, the binary was built
    /// without the per-platform `fuse` / `winfsp` feature. The
    /// platform itself is fine; what's missing is build-time config.
    /// We keep the message specific so users don't waste time trying
    /// to install macFUSE/FUSE-T/WinFsp at runtime when the actual
    /// fix is to rebuild.
    #[error(
        "mount support was not compiled into this binary. \
         To enable: install a FUSE provider for your platform \
         (macOS: `brew install --cask fuse-t`; \
         Linux: `apt install libfuse3-dev`; \
         Windows: WinFsp from https://winfsp.dev/), \
         then rebuild luksbox-mount with the `fuse` (Linux/macOS) or \
         `winfsp` (Windows) feature, e.g. \
         `cargo clean -p luksbox-mount && cargo build --release -p luksbox-cli`. \
         The default workspace features include both, so a plain \
         `cargo build --release` picks them up automatically when the \
         provider is detectable."
    )]
    Unsupported,
}

/// Mount the given Vfs at `mountpoint`.
///
/// - Linux/macOS: `daemonize = true` forks after the FUSE fd is open;
///   parent prints success and exits, child runs the session detached.
///   `daemonize = false` blocks the current process. SIGINT/SIGTERM
///   triggers a clean unmount via the installed signal handler.
/// - Windows: `daemonize` is ignored, WinFsp's mount lifetime is tied to
///   the process holding the FileSystem handle. The function blocks
///   until the process is killed (Ctrl-C, taskkill, or quit from GUI).
#[cfg(all(any(target_os = "linux", target_os = "macos"), feature = "fuse"))]
pub fn mount<P: AsRef<Path>>(
    vfs: luksbox_vfs::Vfs,
    mountpoint: P,
    daemonize: bool,
) -> Result<(), MountError> {
    fuse::mount(vfs, mountpoint.as_ref(), daemonize)?;
    Ok(())
}

#[cfg(all(target_os = "windows", feature = "winfsp"))]
pub fn mount<P: AsRef<Path>>(
    vfs: luksbox_vfs::Vfs,
    mountpoint: P,
    _daemonize: bool,
) -> Result<(), MountError> {
    winfsp::mount(vfs, mountpoint.as_ref())
}

#[cfg(any(
    not(any(target_os = "linux", target_os = "macos", target_os = "windows")),
    all(any(target_os = "linux", target_os = "macos"), not(feature = "fuse")),
    all(target_os = "windows", not(feature = "winfsp")),
))]
pub fn mount<P: AsRef<Path>>(
    _vfs: luksbox_vfs::Vfs,
    _mountpoint: P,
    _daemonize: bool,
) -> Result<(), MountError> {
    Err(MountError::Unsupported)
}

/// Unmount a luksbox mountpoint.
///
/// - Linux: wraps `fusermount3 -u`.
/// - macOS: wraps `umount`.
/// - Windows: returns an error explaining there is no separate unmount
///   API; user must terminate the mount-holding process.
#[cfg(all(any(target_os = "linux", target_os = "macos"), feature = "fuse"))]
pub fn unmount<P: AsRef<Path>>(mountpoint: P) -> Result<(), MountError> {
    fuse::unmount(mountpoint.as_ref())?;
    Ok(())
}

#[cfg(all(target_os = "windows", feature = "winfsp"))]
pub fn unmount<P: AsRef<Path>>(mountpoint: P) -> Result<(), MountError> {
    winfsp::unmount(mountpoint.as_ref())
}

#[cfg(any(
    not(any(target_os = "linux", target_os = "macos", target_os = "windows")),
    all(any(target_os = "linux", target_os = "macos"), not(feature = "fuse")),
    all(target_os = "windows", not(feature = "winfsp")),
))]
pub fn unmount<P: AsRef<Path>>(_mountpoint: P) -> Result<(), MountError> {
    Err(MountError::Unsupported)
}
