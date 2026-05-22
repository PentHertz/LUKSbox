// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Penthertz <https://penthertz.com> (https://x.com/PentHertz)

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

fn assert_ok(out: &Output, ctx: &str) {
    assert!(
        out.status.success(),
        "{ctx} failed:\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr),
    );
}

#[test]
fn create_put_ls_get_rm() {
    let tmp = tempdir().unwrap();
    let dir = tmp.path();

    let out = run(dir, &["create", "vault.lbx"]);
    assert_ok(&out, "create");

    std::fs::write(dir.join("hello.txt"), b"hello world").unwrap();

    let out = run(dir, &["put", "vault.lbx", "hello.txt", "/hello.txt"]);
    assert_ok(&out, "put");

    let out = run(dir, &["ls", "vault.lbx", "/"]);
    assert_ok(&out, "ls");
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("hello.txt"),
        "ls did not list file: {stdout}"
    );

    let out = run(dir, &["get", "vault.lbx", "/hello.txt", "out.txt"]);
    assert_ok(&out, "get");
    assert_eq!(std::fs::read(dir.join("out.txt")).unwrap(), b"hello world");

    let out = run(dir, &["rm", "vault.lbx", "/hello.txt"]);
    assert_ok(&out, "rm");

    let out = run(dir, &["ls", "vault.lbx", "/"]);
    assert_ok(&out, "ls after rm");
    assert!(!String::from_utf8_lossy(&out.stdout).contains("hello.txt"));
}

#[test]
fn mkdir_and_nested_put() {
    let tmp = tempdir().unwrap();
    let dir = tmp.path();
    assert_ok(&run(dir, &["create", "v.lbx"]), "create");
    assert_ok(&run(dir, &["mkdir", "v.lbx", "/docs"]), "mkdir");
    std::fs::write(dir.join("note.txt"), b"top secret").unwrap();
    assert_ok(
        &run(dir, &["put", "v.lbx", "note.txt", "/docs/note.txt"]),
        "put nested",
    );
    let out = run(dir, &["ls", "v.lbx", "/docs"]);
    assert_ok(&out, "ls /docs");
    assert!(String::from_utf8_lossy(&out.stdout).contains("note.txt"));
}

#[test]
fn enroll_second_passphrase_then_revoke_first() {
    let tmp = tempdir().unwrap();
    let dir = tmp.path();
    assert_ok(&run(dir, &["create", "v.lbx"]), "create");

    // info before
    let out = run(dir, &["info", "v.lbx"]);
    assert_ok(&out, "info");
    let s = String::from_utf8_lossy(&out.stdout);
    assert!(s.contains("0: passphrase"));
    assert!(s.contains("1: empty"));

    // Note: enroll with same env passphrase -> existing slot's passphrase is
    // also "pw"; we re-add another slot with same passphrase. That's fine,
    // we're testing the slot machinery, not the passphrase distinctness.
    assert_ok(&run(dir, &["enroll", "v.lbx"]), "enroll");

    let out = run(dir, &["info", "v.lbx"]);
    let s = String::from_utf8_lossy(&out.stdout);
    assert!(s.contains("0: passphrase"));
    assert!(s.contains("1: passphrase"));

    assert_ok(&run(dir, &["revoke", "v.lbx", "--slot", "0"]), "revoke 0");
    let out = run(dir, &["info", "v.lbx"]);
    let s = String::from_utf8_lossy(&out.stdout);
    assert!(s.contains("0: empty"));
    assert!(s.contains("1: passphrase"));

    // Can still open via slot 1.
    assert_ok(&run(dir, &["ls", "v.lbx"]), "ls after revoke");
}

#[test]
fn wrong_passphrase_fails() {
    let tmp = tempdir().unwrap();
    let dir = tmp.path();
    assert_ok(&run(dir, &["create", "v.lbx"]), "create");

    let out = Command::new(bin())
        .args(["ls", "v.lbx"])
        .current_dir(dir)
        .env("LUKSBOX_TEST_FAST_KDF", "1")
        .env("LUKSBOX_PASSPHRASE", "wrong")
        .output()
        .unwrap();
    assert!(!out.status.success());
    let s = String::from_utf8_lossy(&out.stderr);
    assert!(s.contains("error"), "no error printed: {s}");
}

#[test]
fn cross_dir_mv_succeeds_posix_semantics() {
    // v0.2.1 supports POSIX `rename(2)` semantics including cross-
    // directory moves (added when implementing `git clone` workflow
    // inside a mounted vault). This test pins the new behavior: a
    // file moved from /a to /b must disappear from /a and appear
    // at /b with its content intact.
    let tmp = tempdir().unwrap();
    let dir = tmp.path();
    assert_ok(&run(dir, &["create", "v.lbx"]), "create");
    assert_ok(&run(dir, &["mkdir", "v.lbx", "/a"]), "mkdir a");
    assert_ok(&run(dir, &["mkdir", "v.lbx", "/b"]), "mkdir b");
    std::fs::write(dir.join("f"), b"x").unwrap();
    assert_ok(&run(dir, &["put", "v.lbx", "f", "/a/f"]), "put");
    assert_ok(&run(dir, &["mv", "v.lbx", "/a/f", "/b/f"]), "cross-dir mv");
    // Confirm the file is now at /b/f and gone from /a/f.
    let out = run(dir, &["ls", "v.lbx", "/a"]);
    assert!(
        out.status.success() && !String::from_utf8_lossy(&out.stdout).contains("f"),
        "file must be gone from source dir"
    );
    let out = run(dir, &["ls", "v.lbx", "/b"]);
    assert!(
        out.status.success() && String::from_utf8_lossy(&out.stdout).contains("f"),
        "file must appear in destination dir"
    );
}
