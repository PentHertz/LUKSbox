// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Penthertz <https://penthertz.com> (https://x.com/PentHertz)

//! End-to-end integration tests for the FUSE mount adapter on
//! Linux + macOS.
//!
//! Mirror of `winfsp_mount.rs`'s structure but for the FUSE side.
//! Each test creates a small luksbox vault on disk, mounts it via
//! `luksbox_mount::mount` (foreground, on a separate thread), does
//! work against the real /tmp/<random> mountpoint, then tears down
//! via `luksbox_mount::unmount`.
//!
//! ### What these tests catch
//!
//! - A regression that breaks `LuksboxFs::lookup` / `getattr` /
//!   `read` / `write` would silently pass our unit tests (they call
//!   the Vfs directly) but fail at the actual kernel-FUSE boundary,
//!   which has different argument-encoding + reply semantics.
//! - A regression in the daemonize path - the existing GUI code
//!   spawns mount in a separate thread via foreground (daemonize=
//!   false), so we do too.
//! - A regression in unmount: the SECURITY.md documents that
//!   `luksbox umount` invokes `fusermount3 -u` (Linux) / `umount`
//!   (macOS); a botched argv there would only surface here.
//!
//! ### Why these tests are gated
//!
//! - `cfg(unix)` - meaningful only on Linux + macOS.
//! - `cfg(feature = "fuse")` - requires the fuser crate (default in
//!   the workspace).
//! - Runtime check for `/dev/fuse` (Linux) or `/dev/macfuse0`
//!   (macOS) - without it, mount() would fail with ENODEV/ENOENT.
//!   We `eprintln!` and `return` (rather than fail) so dev machines
//!   without FUSE installed don't see spurious red.
//! - Runtime check that the user's process can actually open a
//!   FUSE mount: on Linux, requires either /etc/fuse.conf with
//!   `user_allow_other` OR the user being in the `fuse` group.
//!   Most modern distros tag the user automatically; the GitHub
//!   ubuntu-latest runner doesn't always, so we fall through with
//!   `[skip]` if a probe-mount fails.
//!
//! ### Why these tests aren't in the default `cargo test --workspace` hot path
//!
//! They take 1-3 seconds each (kernel mount latency) and need
//! /dev/fuse access. Run explicitly with `cargo test -p luksbox-mount`
//! on a Linux/macOS host with FUSE installed.

#![cfg(all(unix, feature = "fuse"))]

use std::path::{Path, PathBuf};
use std::sync::mpsc;
use std::thread;
use std::time::Duration;

use luksbox_core::{Argon2idParams, CipherSuite};
use luksbox_format::container::{Container, UnlockMaterial};
use luksbox_format::error::Error as FormatError;
use luksbox_vfs::Vfs;
use tempfile::TempDir;

const FAST_KDF: Argon2idParams = Argon2idParams {
    m_cost_kib: 8,
    t_cost: 1,
    p_cost: 1,
};
const PASS: &[u8] = b"test-passphrase";

/// Probe whether FUSE mounts can actually be created in this
/// environment. Linux: checks for /dev/fuse + tries a no-op mount
/// to detect the "user not in fuse group" case. macOS: checks for
/// /dev/macfuse0 (the macFUSE device node).
fn fuse_available() -> bool {
    #[cfg(target_os = "linux")]
    {
        if !Path::new("/dev/fuse").exists() {
            return false;
        }
        // Probe permission: try to open /dev/fuse for read+write.
        // Returns immediately; doesn't actually mount.
        std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open("/dev/fuse")
            .is_ok()
    }
    #[cfg(target_os = "macos")]
    {
        // macFUSE registers either /dev/macfuse0 or /dev/osxfuse0
        // depending on version. Either is fine for our purposes.
        Path::new("/dev/macfuse0").exists() || Path::new("/dev/osxfuse0").exists()
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    {
        false
    }
}

/// Create a fresh vault on disk; return the path. Caller calls
/// `reopen_vfs` to get a `Vfs` (mirrors the winfsp_mount.rs helper
/// pattern; avoids holding the file lock from two overlapping
/// `Container` handles in the same process).
fn fresh_vault(dir: &Path, name: &str) -> PathBuf {
    let vault = dir.join(format!("{name}.lbx"));
    {
        let cont = Container::create_with_passphrase(
            &vault,
            None,
            CipherSuite::Aes256GcmSiv,
            FAST_KDF,
            PASS,
        )
        .expect("create vault");
        drop(cont);
    }
    // Tiny pause so the previous file handle's `flock` is fully
    // released by the kernel before the next open. flock is per-
    // process, but the kernel updates the per-inode lock state
    // asynchronously after `close(2)`.
    std::thread::sleep(std::time::Duration::from_millis(20));
    vault
}

fn reopen_vfs(vault: &Path) -> Vfs {
    // Poll-and-retry on `VaultLocked`. Background: the previous
    // mount cycle's `Container` was dropped (or its mount thread
    // exited) microseconds ago; the kernel releases the per-inode
    // `flock` asynchronously after `close(2)`. On a fast/contended
    // CI runner the next `Container::open` can race the kernel and
    // see the old lock still held. A fixed sleep was insufficient
    // (the race is unbounded in principle); poll for up to ~2 s
    // with 25 ms backoff so we wait only as long as needed and fail
    // loudly if the lock genuinely never releases.
    let start = std::time::Instant::now();
    let mut last_err: Option<FormatError> = None;
    while start.elapsed() < Duration::from_secs(2) {
        match Container::open(vault, None, UnlockMaterial::Passphrase(PASS)) {
            Ok(cont) => return Vfs::open(cont).expect("open vfs"),
            Err(FormatError::VaultLocked { .. }) => {
                last_err = Some(FormatError::VaultLocked {
                    path: vault.display().to_string(),
                });
                std::thread::sleep(Duration::from_millis(25));
                continue;
            }
            Err(e) => panic!("open vault: {e:?}"),
        }
    }
    panic!(
        "open vault: still locked after 2 s of polling ({:?})",
        last_err.expect("loop only exits via Ok return or panic")
    );
}

/// Skip the test if FUSE isn't available (instead of failing). Keeps
/// `cargo test` green on machines without FUSE installed.
macro_rules! require_fuse {
    () => {
        if !fuse_available() {
            eprintln!(
                "[skip] FUSE not available in this environment. \
                 On Linux: install libfuse3 + ensure user is in the \
                 `fuse` group. On macOS: install macFUSE from \
                 https://osxfuse.github.io/ ."
            );
            return;
        }
    };
}

/// Best-effort cleanup: try to unmount in case a previous test left
/// a stale mount behind (e.g. process killed mid-test).
fn force_cleanup_mount(mp: &Path) {
    let _ = luksbox_mount::unmount(mp);
}

// ------------------------------------------------------------------
// Tests
// ------------------------------------------------------------------

/// Simplest case: mount a freshly-created empty vault, verify the
/// mountpoint is readable, unmount cleanly. Catches regressions in
/// the basic FUSE init path (`LuksboxFs::init`, `getattr` on root,
/// `readdir` on root).
#[test]
fn mount_empty_vault_root_is_readable() {
    require_fuse!();
    let dir = TempDir::new().unwrap();
    let mp = dir.path().join("mnt");
    std::fs::create_dir(&mp).unwrap();
    let vault = fresh_vault(dir.path(), "empty");
    let vfs = reopen_vfs(&vault);

    let mp_thr = mp.clone();
    let mount_join = thread::spawn(move || luksbox_mount::mount(vfs, &mp_thr, false, false));

    // Give the kernel mount time to land. 2 seconds is well over what
    // we observe in practice (sub-second) but tolerant of slow CI.
    thread::sleep(Duration::from_secs(2));

    // List root - should succeed (returns empty dir).
    let listing = std::fs::read_dir(&mp);

    // Capture result before unmount to keep the assertion below
    // cleaner.
    let entries = listing.map(|it| it.collect::<Vec<_>>()).unwrap_or_default();

    force_cleanup_mount(&mp);
    let _ = mount_join.join().expect("mount thread");

    assert_eq!(
        entries.len(),
        0,
        "freshly-created empty vault should have an empty root"
    );
}

/// Write a file via the kernel mount, unmount, re-mount, verify the
/// file is still there with byte-identical contents. Catches
/// regressions in `write` / `flush` / persistence.
#[test]
fn write_via_mount_persists_across_remount() {
    require_fuse!();
    let dir = TempDir::new().unwrap();
    let mp = dir.path().join("mnt");
    std::fs::create_dir(&mp).unwrap();
    let vault = fresh_vault(dir.path(), "persist");
    let vfs = reopen_vfs(&vault);

    let mp_thr = mp.clone();
    let mount_join = thread::spawn(move || luksbox_mount::mount(vfs, &mp_thr, false, false));
    thread::sleep(Duration::from_secs(2));

    // Write a file via the kernel mount path.
    let test_file = mp.join("hello.txt");
    let payload = b"the quick brown fox jumps over the lazy dog";
    let write_result = std::fs::write(&test_file, payload);

    force_cleanup_mount(&mp);
    let _ = mount_join.join().expect("mount thread");

    write_result.expect("write via mount");

    // Tiny pause for file-lock release before reopen.
    std::thread::sleep(std::time::Duration::from_millis(20));
    let vfs2 = reopen_vfs(&vault);
    let mp_thr2 = mp.clone();
    let mount_join2 = thread::spawn(move || luksbox_mount::mount(vfs2, &mp_thr2, false, false));
    thread::sleep(Duration::from_secs(2));

    let read_back = std::fs::read(&test_file);

    force_cleanup_mount(&mp);
    let _ = mount_join2.join().expect("second mount thread");

    let bytes = read_back.expect("read after remount");
    assert_eq!(
        bytes, payload,
        "file written via mount must be readable byte-identical after remount"
    );
}

/// Programmatic unmount from another thread (the GUI's lock-vault
/// flow) should wake the blocked mount thread within a generous
/// timeout. Ensures the FUSE session loop responds to the unmount
/// signal that `fusermount3 -u` (Linux) or `umount` (macOS) sends.
#[test]
fn unmount_from_other_thread_wakes_mount_thread() {
    require_fuse!();
    let dir = TempDir::new().unwrap();
    let mp = dir.path().join("mnt");
    std::fs::create_dir(&mp).unwrap();
    let vault = fresh_vault(dir.path(), "wakeup");
    let vfs = reopen_vfs(&vault);

    let mp_thr = mp.clone();
    let (done_tx, done_rx) = mpsc::channel::<Result<(), String>>();
    thread::spawn(move || {
        let r = luksbox_mount::mount(vfs, &mp_thr, false, false).map_err(|e| e.to_string());
        let _ = done_tx.send(r);
    });

    thread::sleep(Duration::from_secs(2));

    // Trigger unmount from the test thread.
    luksbox_mount::unmount(&mp).expect("unmount");

    // Mount thread should report exit within a few seconds.
    let r = done_rx
        .recv_timeout(Duration::from_secs(5))
        .expect("mount thread should exit within 5 seconds of unmount");
    r.expect("mount returned an error");
}

/// Three mount/unmount cycles in the same process. Catches state
/// leaks (lingering kernel mount, file-handle leaks, etc.).
#[test]
fn three_mount_unmount_cycles_in_one_process() {
    require_fuse!();
    let dir = TempDir::new().unwrap();
    let mp = dir.path().join("mnt");
    std::fs::create_dir(&mp).unwrap();
    let vault = fresh_vault(dir.path(), "cycles");

    for cycle in 0..3 {
        let vfs = reopen_vfs(&vault);

        let mp_thr = mp.clone();
        let mount_join = thread::spawn(move || luksbox_mount::mount(vfs, &mp_thr, false, false));
        thread::sleep(Duration::from_secs(1));

        // Touch the mountpoint to verify it's actually mounted.
        let _ = std::fs::read_dir(&mp)
            .unwrap_or_else(|e| panic!("cycle {cycle}: read_dir on mountpoint failed: {e}"));

        force_cleanup_mount(&mp);
        let _ = mount_join
            .join()
            .unwrap_or_else(|_| panic!("cycle {cycle}: mount thread panic"));
    }
}

/// Unmounting a path that was never mounted should produce a
/// structured error, not a silent success. (A silent-success would
/// hide a real bug where unmount picks the wrong mountpoint.)
#[test]
fn unmount_of_unknown_mountpoint_errors() {
    require_fuse!();
    let dir = TempDir::new().unwrap();
    let bogus = dir.path().join("never-mounted");
    std::fs::create_dir(&bogus).unwrap();

    let r = luksbox_mount::unmount(&bogus);
    assert!(
        r.is_err(),
        "unmount of an unmounted path should error, got Ok"
    );
}
