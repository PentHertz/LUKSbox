// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Penthertz <https://penthertz.com> (https://x.com/PentHertz)
//
// Round 9E regression: verify that EVERY file LUKSbox writes lands on
// disk with mode 0600 (owner read+write, no group, no other), even
// when the user's umask is permissive (022).
//
// This is an integration test: it exercises the real Container API
// rather than just the file_util helper. If a future patch adds a
// new file-create site without going through `secure_create_new` /
// `atomic_secure_write`, this test fires.

#![cfg(unix)]

use std::os::unix::fs::PermissionsExt;
use std::path::Path;

use luksbox_core::{Argon2idParams, CipherSuite};
use luksbox_format::container::Container;
use tempfile::tempdir;

const WEAK_KDF: Argon2idParams = Argon2idParams {
    m_cost_kib: 8,
    t_cost: 1,
    p_cost: 1,
};

fn mode(path: &Path) -> u32 {
    std::fs::metadata(path).unwrap().permissions().mode() & 0o7777
}

fn force_permissive_umask() {
    // Many test runners inherit a tight umask from systemd / CI.
    // Force 022 so we're actually testing the "wide-default umask"
    // case that produces world-readable files via the std default.
    unsafe {
        libc::umask(0o022);
    }
}

#[test]
fn passphrase_vault_inline_header_is_0600() {
    force_permissive_umask();
    let dir = tempdir().unwrap();
    let path = dir.path().join("v.lbx");
    let _c =
        Container::create_with_passphrase(&path, None, CipherSuite::Aes256GcmSiv, WEAK_KDF, b"pp")
            .expect("create");
    drop(_c);
    assert_eq!(
        mode(&path),
        0o600,
        ".lbx file must be 0600 even under umask 022"
    );
}

#[test]
fn passphrase_vault_with_detached_header_both_files_0600() {
    force_permissive_umask();
    let dir = tempdir().unwrap();
    let path = dir.path().join("v.lbx");
    let hdr = dir.path().join("v.hdr");
    let _c = Container::create_with_passphrase(
        &path,
        Some(&hdr),
        CipherSuite::Aes256GcmSiv,
        WEAK_KDF,
        b"pp",
    )
    .expect("create");
    drop(_c);
    assert_eq!(mode(&path), 0o600, "vault file must be 0600");
    assert_eq!(mode(&hdr), 0o600, "detached header must be 0600");
}

#[test]
fn rotate_mvk_tmp_and_post_commit_file_are_0600() {
    use luksbox_format::container::UnlockMaterial;
    force_permissive_umask();
    let dir = tempdir().unwrap();
    let path = dir.path().join("v.lbx");
    {
        let _c = Container::create_with_passphrase(
            &path,
            None,
            CipherSuite::Aes256GcmSiv,
            WEAK_KDF,
            b"pp",
        )
        .expect("create");
    }
    assert_eq!(mode(&path), 0o600, "freshly-created vault must be 0600");

    // Now exercise the rotate-mvk path. Open + start rotation +
    // commit; verify the post-commit file is still 0600.
    {
        let mut c = Container::open(&path, None, UnlockMaterial::Passphrase(b"pp")).expect("open");
        c.begin_atomic_rotation().expect("begin rot");
        // The tmp file should also be 0600 mid-rotation. Find it
        // (it's in the same directory as the vault).
        let entries: Vec<_> = std::fs::read_dir(dir.path())
            .unwrap()
            .filter_map(Result::ok)
            .filter(|e| e.file_name() != "v.lbx")
            .collect();
        for e in &entries {
            let m = mode(&e.path());
            assert_eq!(
                m,
                0o600,
                "rotation tmpfile {:?} must be 0600 (got {:o})",
                e.path(),
                m
            );
        }
        c.commit_atomic_rotation().expect("commit rot");
    }
    assert_eq!(
        mode(&path),
        0o600,
        "post-rotation vault file must remain 0600"
    );
}
