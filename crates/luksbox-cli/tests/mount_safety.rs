// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Penthertz <https://penthertz.com> (https://x.com/PentHertz)

//! End-to-end CLI tests for the mountpoint deny-list (CVE-2025-23021
//! analog). The deny-list refuses to mount onto FHS system roots
//! (`/etc`, `/usr/bin`, ...) which would let vault contents shadow
//! system-critical files for the duration of the mount.
//!
//! Linux/macOS only - Windows uses a different mountpoint model
//! (drive letters or non-existent reparse points) where this attack
//! class isn't reachable.

#![cfg(not(target_os = "windows"))]

use std::path::Path;
use std::process::{Command, Output};

use tempfile::tempdir;

fn bin() -> &'static str {
    env!("CARGO_BIN_EXE_luksbox")
}

fn run(dir: &Path, args: &[&str]) -> Output {
    Command::new(bin())
        .args(args)
        .current_dir(dir)
        .env("LUKSBOX_TEST_FAST_KDF", "1")
        .env("LUKSBOX_PASSPHRASE", "pw")
        .output()
        .expect("spawn binary")
}

fn stderr(o: &Output) -> String {
    String::from_utf8_lossy(&o.stderr).to_string()
}

fn assert_ok(out: &Output, ctx: &str) {
    assert!(
        out.status.success(),
        "{ctx} failed:\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&out.stdout),
        stderr(out)
    );
}

/// Reject mounting onto `/etc` itself.
#[test]
fn mount_rejects_etc() {
    let tmp = tempdir().unwrap();
    let dir = tmp.path();
    assert_ok(&run(dir, &["create", "vault.lbx"]), "create");

    let out = run(dir, &["mount", "vault.lbx", "/etc"]);
    assert!(
        !out.status.success(),
        "mount onto /etc must fail; stderr: {}",
        stderr(&out)
    );
    let s = stderr(&out);
    assert!(
        s.contains("/etc") && s.contains("system"),
        "stderr should explain why /etc was rejected; got: {s}"
    );
}

/// Reject mounting onto a subpath of a denied root (`/usr/local/...`).
#[test]
fn mount_rejects_subpath_of_usr() {
    let tmp = tempdir().unwrap();
    let dir = tmp.path();
    assert_ok(&run(dir, &["create", "vault.lbx"]), "create");

    // We don't mkdir under /usr; mount validation checks the
    // is_dir() / canonicalize() path first. Use a real path that
    // exists on every Linux/macOS host.
    let candidate = if Path::new("/usr/share").is_dir() {
        "/usr/share"
    } else {
        eprintln!("[skip] /usr/share missing; cannot exercise subpath rejection");
        return;
    };

    let out = run(dir, &["mount", "vault.lbx", candidate]);
    assert!(
        !out.status.success(),
        "mount onto {candidate} must fail; stderr: {}",
        stderr(&out)
    );
    let s = stderr(&out);
    assert!(
        s.contains("/usr") && s.contains("system"),
        "stderr should explain why {candidate} was rejected; got: {s}"
    );
}

/// `/run/user/<uid>/...` subpaths are NOT in the deny list. Verify a
/// path under a tempdir is not falsely rejected for being inside a
/// "looks-system-y" parent. Acts as the negative control for the deny
/// check; uses the test's own tempdir which is the canonical "safe"
/// place (under /tmp on Linux, /var/folders/... on macOS).
#[test]
fn mount_accepts_user_writable_path() {
    let tmp = tempdir().unwrap();
    let dir = tmp.path();
    assert_ok(&run(dir, &["create", "vault.lbx"]), "create");

    // Make a sub-dir that doubles as the mountpoint. We don't actually
    // wait for the mount to succeed (we'd need /dev/fuse access and a
    // way to unmount on test failure); we just assert that the
    // command is NOT rejected by the deny-check before mount(2)
    // tries to run.
    let mountpoint = dir.join("mnt");
    std::fs::create_dir(&mountpoint).unwrap();

    // -f / --foreground would block; we want a quick fail-or-succeed
    // signal. Spawn with a 2s timeout via a child + wait pattern.
    use std::time::Duration;
    let mut child = Command::new(bin())
        .args(["mount", "vault.lbx", mountpoint.to_str().unwrap()])
        .current_dir(dir)
        .env("LUKSBOX_TEST_FAST_KDF", "1")
        .env("LUKSBOX_PASSPHRASE", "pw")
        .stderr(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .spawn()
        .expect("spawn mount");

    // Give it 2s to either fail (with the deny-check error) or
    // settle into a successful daemonized state.
    std::thread::sleep(Duration::from_secs(2));

    // Best-effort cleanup; ignore the error path. Use the same
    // resolved-absolute-path approach the binary uses internally so
    // we don't reintroduce the very PATH-hijack we just fixed.
    let unmount_paths = ["/usr/bin/fusermount3", "/bin/fusermount3", "/sbin/umount"];
    for p in unmount_paths {
        if Path::new(p).is_file() {
            let _ = Command::new(p)
                .args(if p.ends_with("fusermount3") {
                    vec!["-u"]
                } else {
                    vec![]
                })
                .arg(&mountpoint)
                .status();
            break;
        }
    }
    let _ = child.kill();
    let out = child.wait_with_output().expect("wait");

    let s = String::from_utf8_lossy(&out.stderr);
    assert!(
        !s.contains("system directory") && !s.contains("deny-list"),
        "user-writable mountpoint must NOT be rejected by deny-check; \
         got stderr: {s}"
    );
}
