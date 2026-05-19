// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Penthertz <https://penthertz.com> (https://x.com/PentHertz)

//! Round 13 R13-01 regression: secure_create_or_truncate now opens
//! the destination through `openat(parent_dir_fd, basename, ...)` on
//! Unix, so an attacker who swaps an INTERMEDIATE directory along the
//! path cannot redirect the write. Run with:
//!
//! ```bash
//! cargo test --test round13_file_util -p luksbox-core
//! ```

use luksbox_core::file_util::secure_create_or_truncate;
use std::io::Write as _;

#[cfg(unix)]
#[test]
fn r13_01_refuses_symlinked_basename() {
    use std::os::unix::fs::symlink;
    let dir = tempfile::tempdir().unwrap();
    let real = dir.path().join("victim.txt");
    std::fs::write(&real, b"sensitive").unwrap();
    let link = dir.path().join("attacker.symlink");
    symlink(&real, &link).unwrap();

    let err = secure_create_or_truncate(&link).expect_err("symlinked basename must be refused");
    // openat(O_NOFOLLOW) returns ELOOP on Linux / EMLINK or ELOOP on
    // some BSDs; accept either.
    let code = err.raw_os_error().unwrap_or(0);
    assert!(
        code == libc::ELOOP || code == libc::EMLINK,
        "expected ELOOP/EMLINK, got errno {code} ({err:?})"
    );
    let still = std::fs::read(&real).unwrap();
    assert_eq!(still, b"sensitive");
}

#[cfg(unix)]
#[test]
fn r13_01_legitimate_intermediate_symlink_still_works() {
    // The legitimate "~/extracted -> /mnt/usb/extracted" use case
    // must continue to work: an intermediate symlink that resolves
    // to a directory the user owns is fine; only adversarial
    // redirects are refused. We model this by symlinking a sub-dir
    // and writing through it.
    use std::os::unix::fs::symlink;
    let dir = tempfile::tempdir().unwrap();
    let real_sub = dir.path().join("real_sub");
    std::fs::create_dir(&real_sub).unwrap();
    let link_sub = dir.path().join("link_sub");
    symlink(&real_sub, &link_sub).unwrap();
    let target = link_sub.join("out.txt");

    let mut f = secure_create_or_truncate(&target).expect("legitimate symlinked dir is fine");
    f.write_all(b"hello").unwrap();

    // File landed inside the real directory, not anywhere else.
    let got = std::fs::read(real_sub.join("out.txt")).unwrap();
    assert_eq!(got, b"hello");
}

#[cfg(unix)]
#[test]
fn r13_01_yields_0600_under_022_umask() {
    use std::os::unix::fs::PermissionsExt as _;
    let dir = tempfile::tempdir().unwrap();
    let target = dir.path().join("extract.txt");
    unsafe {
        libc::umask(0o022);
    }
    let _f = secure_create_or_truncate(&target).unwrap();
    let mode = std::fs::metadata(&target).unwrap().permissions().mode() & 0o7777;
    assert_eq!(
        mode, 0o600,
        "openat-based path must still set mode 0600 via fchmod"
    );
}

#[cfg(unix)]
#[test]
fn r13_01_narrows_existing_wide_file() {
    use std::os::unix::fs::PermissionsExt as _;
    let dir = tempfile::tempdir().unwrap();
    let target = dir.path().join("preexisting.txt");
    std::fs::write(&target, b"old").unwrap();
    std::fs::set_permissions(&target, std::fs::Permissions::from_mode(0o644)).unwrap();

    let _f = secure_create_or_truncate(&target).unwrap();
    let mode = std::fs::metadata(&target).unwrap().permissions().mode() & 0o7777;
    assert_eq!(mode, 0o600, "fchmod must narrow pre-existing 0644 -> 0600");
}
