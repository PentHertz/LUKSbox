// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Penthertz <https://penthertz.com> (https://x.com/PentHertz)

//! R12-15 follow-up: `secure_create_or_truncate` on Windows refuses to
//! extract through ANY junction / reparse point in the path (stricter
//! than the Unix branch, which follows legitimate intermediate
//! symlinks). An intermediate junction must be refused without
//! redirecting or pre-truncating the write, a final-component reparse
//! point must be refused without destroying its target, and ordinary
//! junction-free targets (fresh + replace) must keep working. Run with:
//!
//! ```bash
//! cargo test --test windows_extract_junction -p luksbox-core
//! ```
#![cfg(windows)]

use luksbox_core::file_util::secure_create_or_truncate;
use std::io::{Read as _, Write as _};
use std::path::Path;
use std::process::Command;

/// Create a directory junction `link` -> `target` with the `mklink /J`
/// cmd builtin. Junction creation does not require administrator rights
/// (unlike file symlinks), so this runs in unprivileged CI.
fn make_junction(link: &Path, target: &Path) {
    let status = Command::new("cmd")
        .args(["/C", "mklink", "/J"])
        .arg(link)
        .arg(target)
        .status()
        .expect("spawn mklink");
    assert!(
        status.success(),
        "mklink /J {} {} failed",
        link.display(),
        target.display()
    );
}

#[test]
fn fresh_target_is_created_and_writable() {
    let dir = tempfile::tempdir().unwrap();
    let target = dir.path().join("extract.txt");

    let mut f = secure_create_or_truncate(&target).expect("fresh create must succeed");
    f.write_all(b"hello").unwrap();
    drop(f);

    assert_eq!(std::fs::read(&target).unwrap(), b"hello");
}

#[test]
fn preexisting_regular_file_is_truncated() {
    let dir = tempfile::tempdir().unwrap();
    let target = dir.path().join("extract.txt");
    std::fs::write(&target, b"stale old contents").unwrap();

    let mut f = secure_create_or_truncate(&target).expect("replace must succeed");
    // After the verified open, the file must be empty (replace semantics).
    let mut existing = String::new();
    f.read_to_string(&mut existing).unwrap();
    assert_eq!(existing, "", "open must truncate the pre-existing file");
    f.write_all(b"new").unwrap();
    drop(f);

    assert_eq!(std::fs::read(&target).unwrap(), b"new");
}

#[test]
fn intermediate_junction_in_path_is_refused() {
    // Strict Windows policy: an intermediate junction (here the parent
    // directory of the target) must be refused, NOT followed -- even
    // though it points at a directory the caller could write to. The
    // write must not land behind the junction, and nothing is truncated.
    let dir = tempfile::tempdir().unwrap();
    let real_sub = dir.path().join("real_sub");
    std::fs::create_dir(&real_sub).unwrap();
    // A pre-existing file behind the junction: it must remain untouched.
    let sentinel = real_sub.join("out.txt");
    std::fs::write(&sentinel, b"pre-existing").unwrap();

    let link_sub = dir.path().join("link_sub");
    make_junction(&link_sub, &real_sub);

    let target = link_sub.join("out.txt");
    let err = secure_create_or_truncate(&target)
        .expect_err("extraction through an intermediate junction must be refused");
    assert_eq!(err.kind(), std::io::ErrorKind::PermissionDenied);

    // The file behind the junction was neither redirected-to nor
    // truncated.
    assert_eq!(std::fs::read(&sentinel).unwrap(), b"pre-existing");
}

#[test]
fn final_component_junction_is_refused_without_destroying_target() {
    // The destination path itself is a directory junction pointing at a
    // victim directory. The helper must refuse rather than write through
    // it, and the victim's contents must be untouched.
    let dir = tempfile::tempdir().unwrap();
    let victim_dir = dir.path().join("victim_dir");
    std::fs::create_dir(&victim_dir).unwrap();
    let sentinel = victim_dir.join("secret.txt");
    std::fs::write(&sentinel, b"do not touch").unwrap();

    let evil = dir.path().join("evil");
    make_junction(&evil, &victim_dir);

    let err = secure_create_or_truncate(&evil)
        .expect_err("a reparse-point destination must be refused");
    // Either our explicit reparse-point refusal (InvalidInput) or the OS
    // refusing to open the directory reparse point for write is fine --
    // the security property is that the write is refused.
    let _ = err;

    // The victim directory and its sentinel file are intact.
    assert!(victim_dir.is_dir());
    assert_eq!(std::fs::read(&sentinel).unwrap(), b"do not touch");
}
