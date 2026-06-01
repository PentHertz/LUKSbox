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

// Shared `statvfs(2)` helper used by both Unix mount adapters above
// to report honest host-disk free space to the FUSE/FUSE-T layer.
// Gated on whichever Unix adapter is active so non-Unix targets and
// adapter-less builds don't pull libc::statvfs into the link.
#[cfg(any(
    all(any(target_os = "linux", target_os = "macos"), feature = "fuse"),
    all(target_os = "macos", feature = "fuse-t"),
))]
mod unix_statvfs;

#[cfg(all(target_os = "windows", feature = "winfsp"))]
mod winfsp;

/// Re-export of `winfsp::winfsp_preflight` so the GUI can fail the
/// "Mount" button early with an actionable WinFsp-missing message
/// instead of waiting for the dispatcher set-up to surface the
/// upstream `WinFSPNotFound` debug string verbatim.
#[cfg(all(target_os = "windows", feature = "winfsp"))]
pub use winfsp::winfsp_preflight;

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

/// macOS-only: derive a per-user mountpoint under
/// `~/Library/LUKSbox/Mounts/<sanitized-vault-name>`, creating the
/// directory tree (with mode 0700 on every component owned by us) if
/// missing. Returns an absolute path the caller can pass straight to
/// `mount()`.
///
/// Why this exists: on macOS the default mountpoint is `/Volumes/<name>`,
/// which sits inside a world-readable directory. With FUSE-T the
/// on-disk mode bits (0700 root, 0600 files) keep data confidential -
/// other users get EACCES on every op - but the mount's NAME is still
/// visible to anyone running `ls /Volumes`. Some users running a
/// shared Mac want the name hidden too. Mounting under `~/Library`
/// (mode 0700 by default) makes the mountpoint path itself
/// unreachable from another account.
///
/// Errors:
/// - `$HOME` is unset (rare on macOS, but inherits from the OS).
/// - The target dir exists and is not empty (a previous mount may
///   not have been cleaned up). We refuse to overlay user data; the
///   caller should display the error and let the user unmount /
///   delete the stale dir manually.
///
/// Note: the helper does NOT lock the dir against concurrent mounts.
/// The flock on the .lbx vault file (acquired by `Container::open`)
/// already prevents two concurrent mounts of the same vault, so a
/// non-empty mountpoint here means a previous session left state
/// behind, not a live conflict.
#[cfg(target_os = "macos")]
pub fn private_mountpoint_for(vault_name: &str) -> std::io::Result<std::path::PathBuf> {
    use std::fs;
    use std::os::unix::fs::PermissionsExt as _;
    let home = std::env::var_os("HOME").ok_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::NotFound,
            "HOME environment variable is not set",
        )
    })?;
    let safe = sanitize_vault_name_for_mount(vault_name);
    let base = std::path::PathBuf::from(home).join("Library/LUKSbox/Mounts");
    fs::create_dir_all(&base)?;
    // create_dir_all honors umask (typically 022 -> 0755). Tighten to
    // 0700 explicitly so the parent doesn't leak the names of other
    // mountpoints to anyone with shell access on a multi-user Mac.
    fs::set_permissions(&base, fs::Permissions::from_mode(0o700))?;
    let dir = base.join(&safe);
    if dir.exists() {
        let mut it = fs::read_dir(&dir)?;
        if it.next().is_some() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::AlreadyExists,
                format!(
                    "private mountpoint {} exists and is not empty - a previous \
                     mount may not have been torn down. Unmount it or delete the \
                     directory manually before retrying.",
                    dir.display()
                ),
            ));
        }
    } else {
        fs::create_dir(&dir)?;
        fs::set_permissions(&dir, fs::Permissions::from_mode(0o700))?;
    }
    Ok(dir)
}

/// Filter a vault name into a path component that's safe to append
/// to the private-mount base directory. Strips control chars and
/// path separators; collapses to "vault" if the result is empty.
/// Unicode letters/digits pass through (egui shows them fine, and
/// macOS HFS+/APFS handles UTF-8 paths natively).
#[cfg(target_os = "macos")]
fn sanitize_vault_name_for_mount(s: &str) -> String {
    // Round 12 fix R12-16:
    //  - Reject ':' as well as '/' '\\' '\0'. ':' was the path separator
    //    on classic Mac (Carbon HFS+ APIs) and a few macOS framework
    //    callsites still treat it as a delimiter. Refusing it here
    //    avoids ambiguity at no real-world UX cost (no Mac user names
    //    vaults with ':').
    //  - Cap by BYTE length (255 = APFS/HFS+ filename limit), not by
    //    char count. A 128-grapheme name in a complex script can
    //    serialise to ~500 bytes and would otherwise produce
    //    `ENAMETOOLONG` when the mountpoint is created.
    const MAX_BYTES: usize = 200; // leave headroom for parent path
    let mut out = String::with_capacity(MAX_BYTES);
    for c in s.chars() {
        if c.is_control() || matches!(c, '/' | '\\' | '\0' | ':') {
            continue;
        }
        let needed = c.len_utf8();
        if out.len() + needed > MAX_BYTES {
            break;
        }
        out.push(c);
    }
    let trimmed = out.trim();
    // Reject exact "." and ".." (the only character sequences that
    // would cause path-traversal when appended to the base dir).
    // Embedded ".." inside a longer name is harmless: "foo..bar" is
    // just a regular directory name to the filesystem.
    if trimmed.is_empty() || trimmed == "." || trimmed == ".." {
        "vault".to_string()
    } else {
        trimmed.to_string()
    }
}

#[cfg(all(test, target_os = "macos"))]
mod private_mount_tests {
    use super::sanitize_vault_name_for_mount as sanitize;

    #[test]
    fn rejects_path_separators() {
        assert_eq!(sanitize("../etc/passwd"), "..etcpasswd");
        assert_eq!(sanitize("a/b\\c"), "abc");
    }
    #[test]
    fn strips_control_chars_and_nul() {
        assert_eq!(sanitize("hi\0there\n"), "hithere");
    }
    #[test]
    fn collapses_traversal_components_to_vault() {
        assert_eq!(sanitize(""), "vault");
        assert_eq!(sanitize("   "), "vault");
        assert_eq!(sanitize("."), "vault");
        assert_eq!(sanitize(".."), "vault");
        assert_eq!(sanitize("  ..  "), "vault");
    }
    #[test]
    fn preserves_leading_dot_names() {
        // Legit "hidden" naming convention - do NOT silently rewrite.
        assert_eq!(sanitize(".hidden_vault"), ".hidden_vault");
        assert_eq!(sanitize("...overkill..."), "...overkill...");
    }
    #[test]
    fn preserves_unicode() {
        assert_eq!(sanitize("café-2026"), "café-2026");
    }
    #[test]
    fn caps_length() {
        let s = "a".repeat(300);
        assert_eq!(sanitize(&s).len(), 128);
    }
}

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
    sync_mode: bool,
) -> Result<(), MountError> {
    // FUSE-T's mount() does not yet plumb sync_mode through the C
    // trampoline; v0.2.2 deferred-flush optimisation lives in the
    // libfuse3 (Linux) handler. macOS users opt in by mounting via
    // macFUSE instead (which goes through the cfg branch below).
    let _ = sync_mode;
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
    sync_mode: bool,
) -> Result<(), MountError> {
    fuse::mount(vfs, mountpoint.as_ref(), daemonize, sync_mode)?;
    Ok(())
}

#[cfg(all(target_os = "windows", feature = "winfsp"))]
pub fn mount<P: AsRef<Path>>(
    vfs: luksbox_vfs::Vfs,
    mountpoint: P,
    _daemonize: bool,
    sync_mode: bool,
) -> Result<(), MountError> {
    // WinFsp's session API doesn't yet take the sync_mode hint; the
    // deferred-flush change is libfuse3-only for v0.2.2. The flag is
    // accepted at the API surface for forward compat.
    let _ = sync_mode;
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
    _sync_mode: bool,
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
