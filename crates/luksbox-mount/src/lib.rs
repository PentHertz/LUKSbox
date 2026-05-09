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

// FUSE-T adapter, macOS-only. Built when the `fuse-t` feature is
// enabled. On macOS the dispatch in `mount()` / `unmount()` below
// prefers FUSE-T over macFUSE when both features are somehow on (the
// `fuse-t` feature opts the user out of macFUSE), so a mixed build
// is well-defined even if not recommended.
#[cfg(all(target_os = "macos", feature = "fuse-t"))]
mod fuse_t;

#[cfg(all(target_os = "windows", feature = "winfsp"))]
mod winfsp;

// Pure-string parsing helpers used by the WinFsp adapter. Compiled on
// every platform so unit tests + fuzz harnesses can exercise them
// without the WinFsp SDK / kernel driver. See `winfsp_path.rs` for
// the full rationale.
pub mod winfsp_path;

/// Compile-time identifier of the FUSE backend wired into this build.
///
/// Resolved by the same `cfg` precedence as `mount()` / `unmount()`:
///
/// - macOS + `fuse-t` feature: `"fuse-t"`
/// - macOS + `fuse` feature (no `fuse-t`): `"macfuse"`
/// - Linux + `fuse` feature: `"libfuse3"`
/// - Windows + `winfsp` feature: `"winfsp"`
/// - none of the above: `"none"` (mount returns `MountError::Unsupported`)
///
/// Used by `luksbox --version` so a user who downloads a release
/// artifact can immediately tell which FUSE provider their binary
/// expects on the host (and which provider to install if they're
/// missing it). Also surfaced in the GUI's "About" if/when one
/// gets added.
pub const FUSE_BACKEND: &str = {
    #[cfg(all(target_os = "macos", feature = "fuse-t"))]
    {
        "fuse-t"
    }
    #[cfg(all(target_os = "macos", feature = "fuse", not(feature = "fuse-t"),))]
    {
        "macfuse"
    }
    #[cfg(all(target_os = "linux", feature = "fuse"))]
    {
        "libfuse3"
    }
    #[cfg(all(target_os = "windows", feature = "winfsp"))]
    {
        "winfsp"
    }
    #[cfg(any(
        not(any(target_os = "linux", target_os = "macos", target_os = "windows")),
        all(target_os = "linux", not(feature = "fuse")),
        all(target_os = "macos", not(feature = "fuse"), not(feature = "fuse-t")),
        all(target_os = "windows", not(feature = "winfsp")),
    ))]
    {
        "none"
    }
};

#[derive(Debug, Error)]
pub enum MountError {
    #[error("io: {0}")]
    Io(#[from] std::io::Error),

    /// The mount entry point is the no-op stub, the binary was built
    /// without the per-platform `fuse` / `fuse-t` / `winfsp` feature.
    /// The platform itself is fine; what's missing is build-time
    /// config. We keep the message specific so users don't waste time
    /// trying to install a FUSE provider at runtime when the actual
    /// fix is to rebuild.
    #[error(
        "mount support was not compiled into this binary. \
         To enable: install a FUSE provider for your platform and \
         rebuild luksbox-mount with the matching feature flag.\n\
         - Linux: `apt install libfuse3-dev` and the `fuse` feature.\n\
         - macOS (kext-free): `brew tap macos-fuse-t/homebrew-cask && \
           brew install --cask fuse-t` and the `fuse-t` feature.\n\
         - macOS (legacy): `brew install --cask macfuse` and the \
           `fuse` feature.\n\
         - Windows: WinFsp from https://winfsp.dev/ and the `winfsp` \
           feature.\n\
         Then: `cargo clean -p luksbox-mount && cargo build --release \
         -p luksbox-cli`. The default workspace features include `fuse` \
         and `winfsp`; pass `--features fuse-t` (and drop `--features \
         fuse` on macOS) to opt into FUSE-T."
    )]
    Unsupported,
}

/// Mount the given Vfs at `mountpoint`.
///
/// - Linux: `daemonize = true` forks after the FUSE fd is open;
///   parent prints success and exits, child runs the session detached.
///   `daemonize = false` blocks the current process. SIGINT/SIGTERM
///   triggers a clean unmount via the installed signal handler.
/// - macOS: same fork semantics with macFUSE (`fuse` feature); with
///   FUSE-T (`fuse-t` feature) the function always blocks because
///   FUSE-T's high-level API installs its own signal handlers and
///   the foreground/daemonize split is the caller's responsibility.
/// - Windows: `daemonize` is ignored, WinFsp's mount lifetime is tied to
///   the process holding the FileSystem handle. The function blocks
///   until the process is killed (Ctrl-C, taskkill, or quit from GUI).
///
/// Backend selection on macOS when both `fuse` and `fuse-t` are
/// enabled: FUSE-T wins. This is intentional, the only realistic
/// reason to enable both is "downstream picked the union of features",
/// and FUSE-T is the kext-free option which is the better default
/// when the user has installed it.
#[cfg(all(target_os = "macos", feature = "fuse-t"))]
pub fn mount<P: AsRef<Path>>(
    vfs: luksbox_vfs::Vfs,
    mountpoint: P,
    daemonize: bool,
) -> Result<(), MountError> {
    fuse_t::mount(vfs, mountpoint.as_ref(), daemonize)?;
    Ok(())
}

#[cfg(all(
    any(target_os = "linux", target_os = "macos"),
    feature = "fuse",
    not(all(target_os = "macos", feature = "fuse-t")),
))]
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
    all(target_os = "linux", not(feature = "fuse"),),
    all(target_os = "macos", not(feature = "fuse"), not(feature = "fuse-t"),),
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
/// - macOS (macFUSE / FUSE-T): wraps `umount`. Both providers
///   surface as a normal kernel mount that the system `umount`
///   can detach.
/// - Windows: returns an error explaining there is no separate unmount
///   API; user must terminate the mount-holding process.
#[cfg(all(target_os = "macos", feature = "fuse-t"))]
pub fn unmount<P: AsRef<Path>>(mountpoint: P) -> Result<(), MountError> {
    fuse_t::unmount(mountpoint.as_ref())?;
    Ok(())
}

#[cfg(all(
    any(target_os = "linux", target_os = "macos"),
    feature = "fuse",
    not(all(target_os = "macos", feature = "fuse-t")),
))]
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
    all(target_os = "linux", not(feature = "fuse"),),
    all(target_os = "macos", not(feature = "fuse"), not(feature = "fuse-t"),),
    all(target_os = "windows", not(feature = "winfsp")),
))]
pub fn unmount<P: AsRef<Path>>(_mountpoint: P) -> Result<(), MountError> {
    Err(MountError::Unsupported)
}
