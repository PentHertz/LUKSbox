// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Penthertz <https://penthertz.com> (https://x.com/PentHertz)

//! TPM 2.0 sync bundles through the real binary, against the TPM that
//! `TCTI_NAME_CONF` names (swtpm in CI and in the container recipe of
//! TESTING.md); skipped when it is unset. FIDO2 is the debug build's
//! software authenticator (`LUKSBOX_TEST_FIDO2_MOCK`). A bundle made
//! with `create <folder>.lbxs` gets TPM, TPM + PIN and fused TPM + FIDO2
//! keyslots and opens with each on a second device (its own sync state,
//! the same TPM); a vault with a TPM + FIDO2 + ML-KEM keyslot converts
//! and opens the same way. Another key or a wrong PIN is refused.

// Debug builds only: the FIDO2 half is the software authenticator,
// which release builds compile out.
#![cfg(all(
    feature = "hardware",
    debug_assertions,
    any(target_os = "linux", target_os = "windows")
))]

use std::path::Path;
use std::process::{Command, Output};

use tempfile::tempdir;

const KEY: &str = "3333333333333333333333333333333333333333333333333333333333333333";
const OTHER_KEY: &str = "4444444444444444444444444444444444444444444444444444444444444444";

fn run(dir: &Path, device: &str, key: &str, pin: &str, args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_luksbox"))
        .args(args)
        .current_dir(dir)
        .env("LUKSBOX_TEST_FAST_KDF", "1")
        .env("LUKSBOX_PASSPHRASE", "pw")
        .env("LUKSBOX_NEW_PASSPHRASE", "pw")
        .env("LUKSBOX_ACCEPT_WEAK", "1")
        .env("LUKSBOX_FIDO2_PIN", "1234")
        .env("LUKSBOX_TEST_FIDO2_MOCK", key)
        .env("LUKSBOX_TPM_PIN", pin)
        .env(
            "LUKSBOX_SYNC_STATE_DIR",
            dir.join(format!("state-{device}")),
        )
        .env("LUKSBOX_DEVICE_LABEL", device)
        .output()
        .expect("spawn binary")
}

fn ok(o: Output, ctx: &str) -> String {
    assert!(
        o.status.success(),
        "{ctx} failed:\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&o.stdout),
        String::from_utf8_lossy(&o.stderr)
    );
    String::from_utf8_lossy(&o.stdout).into_owned()
}

fn tpm_available() -> bool {
    if std::env::var_os("TCTI_NAME_CONF").is_none() {
        eprintln!("skipped: set TCTI_NAME_CONF to a TPM (swtpm) to run the TPM bundle tests");
        return false;
    }
    true
}

#[test]
fn tpm_bundles_open_with_the_tpm_on_two_devices() {
    if !tpm_available() {
        return;
    }
    let tmp = tempdir().unwrap();
    let d = tmp.path();
    std::fs::write(d.join("a.txt"), "tpm bundle").unwrap();
    let as_laptop = |args: &[&str]| run(d, "laptop", KEY, "2468", args);
    let as_desktop = |args: &[&str]| run(d, "desktop", KEY, "2468", args);

    ok(
        as_laptop(&["create", "t.lbxs", "--metadata-size", "2M"]),
        "create",
    );
    ok(as_laptop(&["put", "t.lbxs", "a.txt", "/a.txt"]), "put");
    // slot 1: TPM, slot 2: TPM + PIN, slot 3: fused TPM + FIDO2.
    ok(
        as_laptop(&["enroll", "t.lbxs", "--kind", "tpm2"]),
        "enroll tpm2",
    );
    ok(
        as_laptop(&["enroll", "t.lbxs", "--kind", "tpm2-pin"]),
        "enroll tpm2-pin",
    );
    ok(
        as_laptop(&["enroll", "t.lbxs", "--kind", "tpm2-fido2"]),
        "enroll tpm2-fido2",
    );

    for flag in ["--tpm2", "--tpm2-fido2"] {
        let out = ok(as_desktop(&["cat", "t.lbxs", flag, "/a.txt"]), flag);
        assert_eq!(out, "tpm bundle", "{flag}");
    }
    assert!(
        !run(
            d,
            "desktop",
            OTHER_KEY,
            "2468",
            &["cat", "t.lbxs", "--tpm2-fido2", "/a.txt"]
        )
        .status
        .success(),
        "the fused slot opened with another FIDO2 key"
    );
    // Only the PIN slot left for the TPM alone: the PIN is needed.
    ok(
        as_laptop(&["revoke", "t.lbxs", "--slot", "1"]),
        "revoke the plain TPM slot",
    );
    let out = ok(
        as_desktop(&["cat", "t.lbxs", "--tpm2", "/a.txt"]),
        "TPM + PIN",
    );
    assert_eq!(out, "tpm bundle");
    assert!(
        !run(
            d,
            "desktop",
            KEY,
            "0000",
            &["cat", "t.lbxs", "--tpm2", "/a.txt"]
        )
        .status
        .success(),
        "a wrong TPM PIN opened it"
    );

    // TPM + FIDO2 + ML-KEM-768 on a vault, converted into a bundle.
    ok(
        as_laptop(&["create", "q.lbx", "--metadata-size", "2M"]),
        "create q",
    );
    ok(as_laptop(&["put", "q.lbx", "a.txt", "/a.txt"]), "put q");
    ok(
        as_laptop(&[
            "enroll",
            "q.lbx",
            "--kind",
            "hybrid-pq-tpm2-fido2",
            "--pq-hybrid",
            "q.kyber",
        ]),
        "enroll hybrid-pq-tpm2-fido2",
    );
    ok(
        as_laptop(&[
            "sync",
            "convert",
            "q.lbx",
            "q.lbxs",
            "--tpm2-fido2",
            "--pq-hybrid",
            "q.kyber",
        ]),
        "convert",
    );
    assert!(!d.join("q.lbxs.hybrid").exists());
    let out = ok(
        as_desktop(&[
            "cat",
            "q.lbxs",
            "--tpm2-fido2",
            "--pq-hybrid",
            "q.kyber",
            "/a.txt",
        ]),
        "open the converted TPM + FIDO2 + ML-KEM bundle",
    );
    assert_eq!(out, "tpm bundle");
}
