// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Penthertz <https://penthertz.com> (https://x.com/PentHertz)

//! End-to-end tests for the `luksbox cleanup-orphans` subcommand
//! (Round 10 follow-up to 9E's atomic-write + rotation tempfile
//! conventions).
//!
//! These tests exercise the full CLI surface, not just the library
//! helpers in `luksbox-core::file_util` (which have their own unit
//! tests). They cover:
//!
//! - Empty dir: clean exit + "no orphan tempfiles" message.
//! - Atomic-write orphan present: dry-run lists it, `--delete`
//!   removes it.
//! - Rotation orphan present: dry-run AND `--delete` both leave the
//!   `.rotating` file alone (NEVER auto-delete) but flag a warning.
//! - Other vaults' tempfiles: only the named vault's orphans are
//!   touched (the prefix filter is correct end-to-end).

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

fn stdout(o: &Output) -> String {
    String::from_utf8_lossy(&o.stdout).to_string()
}

fn stderr(o: &Output) -> String {
    String::from_utf8_lossy(&o.stderr).to_string()
}

fn assert_ok(out: &Output, ctx: &str) {
    assert!(
        out.status.success(),
        "{ctx} failed:\nstdout: {}\nstderr: {}",
        stdout(out),
        stderr(out)
    );
}

#[test]
fn cleanup_orphans_on_clean_dir_reports_none() {
    let tmp = tempdir().unwrap();
    let dir = tmp.path();
    assert_ok(&run(dir, &["create", "vault.lbx"]), "create");

    let out = run(dir, &["cleanup-orphans", "vault.lbx"]);
    assert_ok(&out, "cleanup-orphans on clean dir");
    let s = stdout(&out);
    assert!(
        s.contains("no orphan tempfiles found"),
        "expected 'no orphan tempfiles found' message; got: {s}"
    );
}

#[test]
fn cleanup_orphans_dry_run_lists_atomic_tmp_without_deleting() {
    let tmp = tempdir().unwrap();
    let dir = tmp.path();
    assert_ok(&run(dir, &["create", "vault.lbx"]), "create");

    let orphan = dir.join("vault.lbx.anchor.tmp.deadbeef00112233");
    std::fs::write(&orphan, b"partial sidecar bytes").unwrap();

    let out = run(dir, &["cleanup-orphans", "vault.lbx"]);
    assert_ok(&out, "cleanup-orphans dry-run");
    let s = stdout(&out);
    assert!(
        s.contains("found 1 orphan tempfile"),
        "expected count line: {s}"
    );
    assert!(s.contains("atomic-write-tmp"), "expected kind label: {s}");
    assert!(
        s.contains("dry-run") && s.contains("--delete"),
        "expected hint about --delete: {s}"
    );

    // Dry-run must not have deleted the file.
    assert!(
        orphan.exists(),
        "dry-run must not delete atomic-write orphan"
    );
}

#[test]
fn cleanup_orphans_with_delete_removes_atomic_tmp() {
    let tmp = tempdir().unwrap();
    let dir = tmp.path();
    assert_ok(&run(dir, &["create", "vault.lbx"]), "create");

    let orphan = dir.join("vault.lbx.tmp.aabbccddeeff0011");
    std::fs::write(&orphan, b"bytes").unwrap();
    assert!(orphan.exists());

    let out = run(dir, &["cleanup-orphans", "vault.lbx", "--delete"]);
    assert_ok(&out, "cleanup-orphans --delete");
    let s = stdout(&out);
    assert!(
        s.contains("deleted 1 orphan"),
        "expected delete summary: {s}"
    );

    assert!(
        !orphan.exists(),
        "--delete must remove the atomic-write orphan"
    );
}

#[test]
fn cleanup_orphans_never_auto_deletes_rotation_tmp() {
    let tmp = tempdir().unwrap();
    let dir = tmp.path();
    assert_ok(&run(dir, &["create", "vault.lbx"]), "create");

    let rotation = dir.join("vault.lbx.rotating");
    std::fs::write(&rotation, b"in-flight rotation working copy").unwrap();

    // Even with --delete, the .rotating orphan must survive.
    let out = run(dir, &["cleanup-orphans", "vault.lbx", "--delete"]);
    assert_ok(&out, "cleanup-orphans --delete with rotation orphan");

    assert!(
        rotation.exists(),
        "--delete must NOT remove .rotating orphan (recovery state)"
    );

    let s = stderr(&out);
    assert!(
        s.contains(".rotating") && s.to_lowercase().contains("warning"),
        "expected a WARNING on stderr about the .rotating orphan; got stderr: {s}"
    );
}

#[test]
fn cleanup_orphans_only_touches_named_vault() {
    let tmp = tempdir().unwrap();
    let dir = tmp.path();
    assert_ok(&run(dir, &["create", "vault-a.lbx"]), "create vault-a");
    assert_ok(&run(dir, &["create", "vault-b.lbx"]), "create vault-b");

    let orphan_a = dir.join("vault-a.lbx.tmp.0000000000000001");
    let orphan_b = dir.join("vault-b.lbx.tmp.0000000000000002");
    std::fs::write(&orphan_a, b"a").unwrap();
    std::fs::write(&orphan_b, b"b").unwrap();

    let out = run(dir, &["cleanup-orphans", "vault-a.lbx", "--delete"]);
    assert_ok(&out, "cleanup-orphans vault-a --delete");

    assert!(
        !orphan_a.exists(),
        "vault-a's orphan should have been deleted"
    );
    assert!(
        orphan_b.exists(),
        "vault-b's orphan must NOT have been touched"
    );
}
