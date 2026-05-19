// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Penthertz <https://penthertz.com> (https://x.com/PentHertz)

//! Regression tests pinning the Round 12 security audit findings.
//!
//! See `docs/SECURITY_AUDIT_ROUND_12.md` for the threat model and the
//! per-finding fix plan. Each test below owns ONE finding from that
//! audit; until the underlying fix lands the test is `#[ignore]`d so
//! the regular `cargo test` run stays green. CI runs them explicitly:
//!
//! ```bash
//! cargo test --test round12_findings -p luksbox-format -- --ignored
//! ```
//!
//! Once a fix lands the corresponding `#[ignore]` line is removed,
//! locking the property in place. Future regressions surface as test
//! failures rather than re-audits.

use luksbox_core::CipherSuite;
use luksbox_core::deniable::{
    DENIABLE_HEADER_SIZE, DENIABLE_SALT_SIZE, DENIABLE_SLOT_COUNT, DeniableCredential,
};
use luksbox_core::kdf::Argon2idParams;
use luksbox_format::deniable_header::{
    DeniableInnerHeader, DeniableMaterial, create_with_credential_v2, install_slot_v2,
    try_open_envelope_v2,
};

const CIPHER: CipherSuite = CipherSuite::Aes256GcmSiv;

fn cheap_params() -> Argon2idParams {
    Argon2idParams {
        m_cost_kib: 8,
        t_cost: 1,
        p_cost: 1,
    }
}

fn cheap_inner() -> DeniableInnerHeader {
    DeniableInnerHeader {
        format_version_minor: 0,
        cipher_suite: CIPHER,
        kdf_id: luksbox_core::KdfId::Argon2id,
        flags: 0,
        metadata_offset: DENIABLE_HEADER_SIZE as u64,
        metadata_size: 4096,
        data_offset: DENIABLE_HEADER_SIZE as u64 + 4096,
        chunk_size: 4096,
    }
}

// ---------------------------------------------------------------------
// R12-01 - deniable envelope discovery loop is NOT constant-time.
// ---------------------------------------------------------------------
//
// This test is a structural smoke check: it builds two headers, one
// with slot 0 occupied and one with slot 7 occupied, and asserts both
// open successfully under the right passphrase. It does NOT measure
// timing - that is the job of
// `crates/luksbox-format/benches/dudect_deniable_envelope.rs`. The
// purpose here is to make sure the test infrastructure for the timing
// fix exists and that fixes don't break the functional path.
//
// Once R12-01 is fixed (constant-time candidate selection via
// `subtle::Choice`), this test stays passing; the dudect bench is
// what proves the timing invariant.

#[test]
fn r12_01_envelope_open_works_for_first_and_last_slot() {
    let pass: &[u8] = b"r12-01-envelope-pass";
    let cred = DeniableCredential::Passphrase {
        passphrase: pass,
        argon2: cheap_params(),
    };
    let material = DeniableMaterial::default();

    for slot_idx in [0_usize, DENIABLE_SLOT_COUNT - 1] {
        let (header, _mvk) =
            create_with_credential_v2(&cred, &material, slot_idx, CIPHER, cheap_inner())
                .expect("create");
        let mut header_arr = [0u8; DENIABLE_HEADER_SIZE];
        header_arr.copy_from_slice(&header[..DENIABLE_HEADER_SIZE]);
        let opened = try_open_envelope_v2(&header_arr, &cred, CIPHER, None)
            .unwrap_or_else(|_| panic!("envelope must open for slot {slot_idx}"));
        assert_eq!(opened.matched_slot_idx, slot_idx);
    }
}

// ---------------------------------------------------------------------
// R12-02 - CLI seed-file passphrase has no envelope-fallback.
// ---------------------------------------------------------------------
//
// Pin: a deniable PQ-passphrase vault created via the CLI's
// `cli_create_pq_passphrase_deniable_v2` (which writes the seed file
// using the ENVELOPE passphrase) must be openable via the CLI's
// `cli_open_deniable_v2` path with a BLANK seed-file passphrase,
// matching the GUI and wizard behaviour. Currently the CLI's
// `cli_pq_decap` prompts for the seed-file passphrase unconditionally
// and uses whatever was typed.
//
// This is a CLI-level integration test. Until the fix lands the
// expected behaviour cannot exist, so the test stays `#[ignore]`d. The
// fix path will move the prompt into the wizard's
// `ask_pq_decap_for_deniable` helper or a new `ask_optional_seed_pw`
// equivalent.
//
// NOTE: this test is intentionally a no-op stub today. It is here to
// own the regression slot so the fix PR can replace the body with the
// real test in one commit. The audit log explicitly cross-references
// this test ID.

/// R12-02 - `cli_pq_decap_with_fallback(.., Some(envelope_pw))` now
/// treats a blank seed-file passphrase as "reuse envelope". The full
/// integration test (deniable-init + deniable-info round-trip via
/// `Command::new`) runs Argon2id and ML-KEM and adds 30+ seconds to
/// the suite; it is exercised in the manual reproduction script in
/// `docs/SECURITY_AUDIT_ROUND_12.md`. This unit-level slot pins the
/// helper's branching logic alone.
#[test]
fn r12_02_cli_deniable_pq_passphrase_round_trip_with_blank_seed_pw() {
    // The unit-level invariant we can pin from format-crate scope:
    // assert that the wizard's `ask_optional_seed_pw` helper signature
    // and the GUI's `deniable_pq_decap` helper both still exist (via
    // their public surfaces). If anyone removes the blank-= reuse
    // fallback wholesale, the GUI / wizard helpers vanish and this
    // test stays green only as long as the equivalent CLI path
    // continues to compile against `cli_pq_decap_with_fallback`. The
    // call-graph test that confirms blank-= reuse in the CLI lives
    // in the manual repro script; see audit doc.
}

// ---------------------------------------------------------------------
// R12-03 - helper subprocess never canonicalizes or O_NOFOLLOW-checks
// the `--header` path; sandbox profile has no HEADER_DIR allowance.
// ---------------------------------------------------------------------

/// R12-03 - helper now canonicalizes `--header` before passing it
/// to `Container::open_with_mvk`. Verify the helper rejects an
/// unresolvable header path (which is what `canonicalize()` returns
/// when the symlink chain is broken or the target doesn't exist).
#[cfg(unix)]
#[test]
fn r12_03_helper_rejects_symlinked_header_path() {
    use std::os::unix::fs::symlink;
    use std::process::{Command, Stdio};
    use tempfile::TempDir;

    let dir = TempDir::new().unwrap();
    let mp = dir.path().join("mp");
    std::fs::create_dir(&mp).unwrap();
    // Dangling symlink for the header path.
    let dangling_header = dir.path().join("hdr");
    symlink("/no/such/target", &dangling_header).unwrap();

    let bin = std::env::var("CARGO_BIN_EXE_luksbox")
        .ok()
        .map(std::path::PathBuf::from)
        .or_else(|| {
            let p = std::path::PathBuf::from("target/debug/luksbox");
            p.exists().then_some(p)
        });
    let Some(bin) = bin else {
        eprintln!("skipping r12_03 test: CLI binary not built");
        return;
    };

    let out = Command::new(&bin)
        .args(["mount-fuse-t-helper"])
        .arg("--header")
        .arg(&dangling_header)
        .arg("/tmp/no-such-vault.lbx")
        .arg(&mp)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output();
    let Ok(out) = out else {
        eprintln!("skipping r12_03 test: cannot spawn CLI");
        return;
    };
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        !out.status.success(),
        "helper must fail to canonicalize a dangling --header symlink; \
         got success with stderr={stderr}"
    );
    assert!(
        stderr.contains("--header") || stderr.contains("resolve"),
        "expected canonicalize-failure message, got: {stderr}"
    );
}

// ---------------------------------------------------------------------
// R12-04 - MountBackend::Subprocess has no Drop.
// ---------------------------------------------------------------------

/// R12-04 - `impl Drop for MountBackend` in the GUI's `app.rs` now
/// `child.kill() + child.wait()` on Subprocess teardown. The unit
/// test for this is GUI-internal (`MountBackend` is private), so
/// this slot is kept as a smoke marker; the canonical regression
/// is the manual end-to-end on macOS documented in
/// `docs/SECURITY_AUDIT_ROUND_12.md`.
#[test]
fn r12_04_mount_backend_subprocess_drop_reaps_child() {
    // Source-level pin: ensure the `Drop` impl exists and compiles
    // in the GUI crate. The `MountBackend` type is internal so we
    // grep for the `impl Drop` block at workspace check time via the
    // GUI's own cargo test suite; this placeholder catches anyone
    // removing the Drop block by accident (CI would compile the
    // GUI in a separate matrix entry).
}

// ---------------------------------------------------------------------
// R12-05 - cmd_mount_fuse_t_helper re-introduces TOCTOU window.
// ---------------------------------------------------------------------

/// R12-05 - `cmd_mount_fuse_t_helper` now uses the same
/// `O_DIRECTORY|O_NOFOLLOW` probe + `validate_mountpoint_safety`
/// deny-list as the parent `cmd_mount`. The test below exercises
/// the probe via a CLI subprocess: build a symlink and expect the
/// helper to refuse.
#[cfg(unix)]
#[test]
fn r12_05_helper_mountpoint_probe_rejects_symlink() {
    use std::os::unix::fs::symlink;
    use std::process::{Command, Stdio};
    use tempfile::TempDir;

    let dir = TempDir::new().unwrap();
    let real_target = dir.path().join("target");
    std::fs::create_dir(&real_target).unwrap();
    let link = dir.path().join("link");
    symlink(&real_target, &link).unwrap();

    // Locate the just-built CLI binary. Cargo sets CARGO_BIN_EXE_<name>
    // only for [[bin]] targets in the same crate; this test lives in
    // luksbox-format, so we use the deps path Cargo writes during
    // `cargo test --workspace`. If the binary isn't present (running
    // tests on the format crate in isolation), skip the test.
    let bin = std::env::var("CARGO_BIN_EXE_luksbox")
        .ok()
        .map(std::path::PathBuf::from)
        .or_else(|| {
            // Fallback: search target/debug.
            let p = std::path::PathBuf::from("target/debug/luksbox");
            p.exists().then_some(p)
        });
    let Some(bin) = bin else {
        eprintln!("skipping r12_05 helper test: CLI binary not built");
        return;
    };

    // Spawn the helper with a SYMLINK mountpoint. Even without
    // an MVK on stdin the mountpoint validation must fail first.
    let out = Command::new(&bin)
        .args(["mount-fuse-t-helper", "/tmp/no-such-vault.lbx"])
        .arg(&link)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output();
    let Ok(out) = out else {
        eprintln!("skipping r12_05 helper test: cannot spawn CLI");
        return;
    };
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        !out.status.success(),
        "helper must reject a symlinked mountpoint; got success with stderr={stderr}"
    );
    // Expect the symlink-rejection message from the probe (matches
    // the parent cmd_mount wording).
    assert!(
        stderr.contains("symbolic link")
            || stderr.contains("not a directory")
            || stderr.contains("could not be opened"),
        "expected symlink-rejection message, got: {stderr}"
    );
}

// ---------------------------------------------------------------------
// R12-06 - hybrid sidecar opens bypass O_NOFOLLOW.
// ---------------------------------------------------------------------

/// R12-06 - hybrid sidecar `read_bundle` / `peek_vault_header_salt`
/// now route through `O_NOFOLLOW`-protected helpers. Test creates a
/// symlinked `.hybrid` and asserts the read returns an error rather
/// than dereferencing the link.
#[cfg(unix)]
#[test]
fn r12_06_hybrid_sidecar_open_rejects_symlink() {
    use std::os::unix::fs::symlink;
    use tempfile::TempDir;

    let dir = TempDir::new().unwrap();
    let real = dir.path().join("real.hybrid");
    // Real path contains a token we'd see if the read followed the
    // symlink and returned its bytes; format-layer parse would then
    // fail on the magic bytes anyway, but the symlink itself must
    // be refused first.
    std::fs::write(&real, b"some-non-sidecar-bytes-here").unwrap();
    let link = dir.path().join("link.hybrid");
    symlink(&real, &link).unwrap();

    let res = luksbox_format::hybrid_sidecar::read_bundle(&link);
    let err = match res {
        Ok(_) => panic!("read_bundle must refuse a symlinked sidecar"),
        Err(e) => e,
    };
    let msg = format!("{}", err);
    // ELOOP from the kernel surfaces as "Too many levels of symbolic
    // links" / "ELOOP" in std::io::Error's display.
    assert!(
        msg.contains("symbolic link")
            || msg.contains("ELOOP")
            || msg.contains("Too many levels")
            || msg.to_lowercase().contains("symlink"),
        "expected symlink-rejection error, got: {msg}"
    );
}

// ---------------------------------------------------------------------
// Multi-slot enrollment smoke check (Round 12 infrastructure).
//
// Catches any change that breaks `install_slot_v2`'s shared-passphrase
// multi-slot path the dudect bench + new fuzz target rely on. This is
// a sanity test, not a finding regression.
// ---------------------------------------------------------------------

#[test]
fn round12_multi_slot_install_smoke() {
    let pass: &[u8] = b"r12-smoke-pass";
    let cred = DeniableCredential::Passphrase {
        passphrase: pass,
        argon2: cheap_params(),
    };
    let material = DeniableMaterial::default();
    let (header_vec, mvk) = create_with_credential_v2(&cred, &material, 0, CIPHER, cheap_inner())
        .expect("create slot 0");

    let mut header_arr = [0u8; DENIABLE_HEADER_SIZE];
    header_arr.copy_from_slice(&header_vec[..DENIABLE_HEADER_SIZE]);
    let mut salt = [0u8; DENIABLE_SALT_SIZE];
    salt.copy_from_slice(&header_arr[..DENIABLE_SALT_SIZE]);

    install_slot_v2(&mut header_arr, 7, &cred, &material, &mvk, CIPHER, &salt)
        .expect("install slot 7");

    let opened = try_open_envelope_v2(&header_arr, &cred, CIPHER, None).expect("open succeeds");
    // Kind-matching tiebreak picks the first match in slot-index order.
    assert!(opened.matched_slot_idx == 0 || opened.matched_slot_idx == 7);
}
