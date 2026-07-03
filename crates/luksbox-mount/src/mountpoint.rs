//! Shared mountpoint hardening for the Unix FUSE backends.
//!
//! Historically this lived inline inside the CLI's `cmd_mount`, and was
//! hand-copied to other CLI entry points one at a time. Every mount
//! call site that was NOT `cmd_mount` reached `luksbox_mount::mount`
//! with some or all of the protections missing: the TUI wizard mounts
//! and the GUI's in-process mount had no `O_NOFOLLOW` probe, no inode
//! re-probe, and no deny-list at all (audit by Garry Jean-Baptiste,
//! 2026-06-19). Putting the guard here, one layer below every frontend,
//! means the CLI subcommands, the TUI wizard, AND the GUI (a separate
//! crate that cannot call a `luksbox-cli`-local helper) all inherit it
//! with no per-frontend code.
//!
//! The two protections:
//!
//! 1. **`O_DIRECTORY | O_NOFOLLOW` probe** — the kernel refuses
//!    (`ELOOP`) if the final mountpoint component is a symlink, closing
//!    the "swap the mountpoint for a symlink to a sensitive path"
//!    vector. The probed `(dev, ino)` is captured.
//! 2. **`reverify_mountpoint` re-probe immediately before the mount
//!    syscall** (R12-08) — refuses if the inode changed since the
//!    initial probe, closing the narrow window between probe and mount.
//!    For the daemonized FUSE path this runs inside the forked child,
//!    right before `fuser::mount2`, which is tighter than the CLI's old
//!    parent-side re-probe (the syscall happens post-fork).
//!
//! Plus the deny-list (`validate_mountpoint_safety`) that refuses
//! mounting the decrypted volume over a system directory, bounding the
//! blast radius of any residual race to user-writable paths.
//!
//! Windows/WinFsp is intentionally out of scope here: a WinFsp
//! mountpoint must NOT pre-exist (an existing path yields
//! `STATUS_OBJECT_NAME_COLLISION`), so the symlink-swap-over-a-real-dir
//! shape does not apply and there is nothing to `O_NOFOLLOW`-probe. The
//! helpers below are `#[cfg(unix)]`; the WinFsp backend keeps its own
//! path handling.

#[cfg(unix)]
use std::path::Path;

/// System directories the decrypted volume must never be mounted over
/// (mounting there would let vault contents shadow system-critical
/// files). Mirrors the CLI's historical `DENIED_MOUNTPOINT_ROOTS` list
/// exactly so behavior is identical whichever frontend initiates the
/// mount; keep the two in sync.
#[cfg(unix)]
const DENIED_MOUNTPOINT_ROOTS: &[&str] = &[
    "/etc",
    "/usr",
    "/bin",
    "/sbin",
    "/lib",
    "/lib32",
    "/lib64",
    "/boot",
    "/sys",
    "/proc",
    "/dev",
    #[cfg(target_os = "macos")]
    "/System",
    #[cfg(target_os = "macos")]
    "/Library",
];

/// Refuse mounting over a deny-listed system directory. `canonical`
/// must be the fully-resolved mountpoint (so a `..`/symlink dance can't
/// smuggle the path past the prefix check).
#[cfg(unix)]
fn validate_mountpoint_safety(user_supplied: &Path, canonical: &Path) -> std::io::Result<()> {
    for denied in DENIED_MOUNTPOINT_ROOTS {
        let denied_path = Path::new(denied);
        if canonical == denied_path || canonical.starts_with(denied_path) {
            return Err(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                format!(
                    "mountpoint {} (resolves to {}) is inside the system \
                     directory {}, which is on LUKSbox's deny-list because \
                     mounting there would let vault contents shadow \
                     system-critical files. Choose a mountpoint outside \
                     {{/etc, /usr, /bin, /sbin, /lib*, /boot, /sys, /proc, /dev{}}}.",
                    user_supplied.display(),
                    canonical.display(),
                    denied_path.display(),
                    if cfg!(target_os = "macos") {
                        ", /System, /Library"
                    } else {
                        ""
                    },
                ),
            ));
        }
    }
    Ok(())
}

/// Probe the mountpoint with `O_DIRECTORY | O_NOFOLLOW` (refusing a
/// symlinked final component and a non-directory in one syscall),
/// capture its `(dev, ino)`, canonicalize, and run the deny-list.
/// Returns the captured inode pair; pass it to `reverify_mountpoint`
/// immediately before the mount syscall to close the symlink-swap
/// TOCTOU.
#[cfg(unix)]
pub(crate) fn harden_mountpoint(mountpoint: &Path) -> std::io::Result<(u64, u64)> {
    use std::os::unix::fs::{MetadataExt as _, OpenOptionsExt as _};
    let probe = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW)
        .open(mountpoint)
        .map_err(|e| {
            let kind = if e.raw_os_error() == Some(libc::ELOOP) {
                "is a symbolic link (refused: open the underlying directory directly)"
            } else if e.raw_os_error() == Some(libc::ENOTDIR) {
                "is not a directory"
            } else {
                "could not be opened"
            };
            std::io::Error::new(
                e.kind(),
                format!("mountpoint {} {kind}: {e}", mountpoint.display()),
            )
        })?;
    let meta = probe.metadata().map_err(|e| {
        std::io::Error::new(
            e.kind(),
            format!("cannot stat mountpoint {}: {e}", mountpoint.display()),
        )
    })?;
    let inode = (meta.dev(), meta.ino());
    drop(probe);
    let canonical = mountpoint.canonicalize().map_err(|e| {
        std::io::Error::new(
            e.kind(),
            format!("cannot resolve {}: {e}", mountpoint.display()),
        )
    })?;
    validate_mountpoint_safety(mountpoint, &canonical)?;
    Ok(inode)
}

/// Re-probe the mountpoint inode immediately before the mount syscall
/// and refuse if it changed since `harden_mountpoint` captured it
/// (R12-08). Call this as close to the syscall as possible — for the
/// daemonized FUSE path that means inside the forked child.
#[cfg(unix)]
pub(crate) fn reverify_mountpoint(mountpoint: &Path, expected: (u64, u64)) -> std::io::Result<()> {
    use std::os::unix::fs::{MetadataExt as _, OpenOptionsExt as _};
    let final_probe = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW)
        .open(mountpoint)
        .map_err(|e| {
            std::io::Error::new(
                e.kind(),
                format!(
                    "mountpoint {} could not be re-verified before mount: {e}",
                    mountpoint.display()
                ),
            )
        })?;
    let m = final_probe.metadata().map_err(|e| {
        std::io::Error::new(
            e.kind(),
            format!(
                "cannot stat mountpoint {} for re-verify: {e}",
                mountpoint.display()
            ),
        )
    })?;
    if (m.dev(), m.ino()) != expected {
        return Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            format!(
                "mountpoint {} was swapped between probe and mount; refusing",
                mountpoint.display()
            ),
        ));
    }
    drop(final_probe);
    Ok(())
}

#[cfg(all(test, unix))]
mod tests {
    //! Fix-validation for the GUI/wizard mount TOCTOU + deny-list
    //! bypass: the shared `harden_mountpoint` / `reverify_mountpoint`
    //! now run for every frontend reaching `luksbox_mount::mount`.
    use super::{harden_mountpoint, reverify_mountpoint};
    use std::path::Path;

    #[test]
    fn refuses_symlinked_mountpoint_and_accepts_real_dir() {
        let base = std::env::temp_dir().join(format!("lbx-mp-sym-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&base);
        std::fs::create_dir_all(&base).unwrap();
        let target = base.join("real_dir");
        std::fs::create_dir_all(&target).unwrap();
        let link = base.join("mp_symlink");
        std::os::unix::fs::symlink(&target, &link).unwrap();
        // O_NOFOLLOW refuses the symlinked mountpoint (the wizard/GUI TOCTOU).
        assert!(
            harden_mountpoint(&link).is_err(),
            "symlinked mountpoint must be refused"
        );
        // A real directory is accepted (legitimate mounts still work).
        assert!(
            harden_mountpoint(&target).is_ok(),
            "a real directory must be accepted"
        );
        let _ = std::fs::remove_dir_all(&base);
    }

    #[test]
    fn refuses_deny_listed_system_dir() {
        // /etc is on the deny-list (the validate_mountpoint_safety the
        // GUI and TUI wizard skipped entirely).
        assert!(
            harden_mountpoint(Path::new("/etc")).is_err(),
            "/etc must be deny-listed"
        );
    }

    #[test]
    fn reverify_detects_post_probe_swap() {
        let base = std::env::temp_dir().join(format!("lbx-mp-rev-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&base);
        std::fs::create_dir_all(&base).unwrap();
        let a = base.join("a");
        let b = base.join("b");
        std::fs::create_dir_all(&a).unwrap();
        std::fs::create_dir_all(&b).unwrap();
        let inode = harden_mountpoint(&a).unwrap();
        assert!(
            reverify_mountpoint(&a, inode).is_ok(),
            "unchanged mountpoint passes"
        );
        // Model the attack precisely: rename a DIFFERENT directory over
        // the probed path so `a` now resolves to `b`'s inode. (A plain
        // remove+recreate is not a reliable test: tmpfs/ext4 can reuse
        // the freed inode number immediately, which is exactly why the
        // guard also matters against inode churn -- but the deterministic
        // swap a real attacker performs is renaming a distinct object
        // into place, and that always changes the inode.)
        std::fs::rename(&b, &a).unwrap();
        assert!(
            reverify_mountpoint(&a, inode).is_err(),
            "post-probe swap must be refused"
        );
        let _ = std::fs::remove_dir_all(&base);
    }
}
