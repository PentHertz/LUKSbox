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
use std::path::{Path, PathBuf};
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

/// The 8.3 short form of an existing `path` (`C:\Users\RUNNER~1\...`).
/// Equal to `path` when the volume does not generate short names.
fn short_path(path: &Path) -> PathBuf {
    use std::os::windows::ffi::{OsStrExt, OsStringExt};

    #[link(name = "kernel32")]
    unsafe extern "system" {
        fn GetShortPathNameW(long_path: *const u16, short_path: *mut u16, len: u32) -> u32;
    }

    let wide: Vec<u16> = path.as_os_str().encode_wide().chain(Some(0)).collect();
    let mut buf = vec![0u16; 1024];
    // SAFETY: `wide` is NUL-terminated; `buf` has `buf.len()` slots.
    let n = unsafe { GetShortPathNameW(wide.as_ptr(), buf.as_mut_ptr(), buf.len() as u32) };
    assert!(
        n > 0 && (n as usize) < buf.len(),
        "GetShortPathNameW({}) failed: {}",
        path.display(),
        std::io::Error::last_os_error()
    );
    PathBuf::from(std::ffi::OsString::from_wide(&buf[..n as usize]))
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

    let err =
        secure_create_or_truncate(&evil).expect_err("a reparse-point destination must be refused");
    // Either our explicit reparse-point refusal (InvalidInput) or the OS
    // refusing to open the directory reparse point for write is fine --
    // the security property is that the write is refused.
    let _ = err;

    // The victim directory and its sentinel file are intact.
    assert!(victim_dir.is_dir());
    assert_eq!(std::fs::read(&sentinel).unwrap(), b"do not touch");
}

#[test]
fn short_8_3_names_in_path_are_accepted() {
    // %TEMP% is often spelled with 8.3 short names (`C:\Users\RUNNER~1\...`
    // on GitHub's runners, `C:\Users\FIRSTN~1\...` for a long user name),
    // while the opened handle's path has the long names. That difference
    // is not a junction and must not be refused (it was, found by the
    // CLI's mount_cross_process test on CI).
    let dir = tempfile::tempdir().unwrap();
    let long_dir = dir.path().join("a directory with a long name");
    std::fs::create_dir(&long_dir).unwrap();
    let short_dir = short_path(&long_dir);
    if short_dir == long_dir {
        eprintln!("[note] this volume has no 8.3 short names; testing the long path only");
    }

    let mut f = secure_create_or_truncate(&short_dir.join("extract.txt"))
        .expect("a path spelled with 8.3 short names must be accepted");
    f.write_all(b"hello").unwrap();
    drop(f);

    assert_eq!(
        std::fs::read(long_dir.join("extract.txt")).unwrap(),
        b"hello"
    );
}
