// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Penthertz <https://penthertz.com> (https://x.com/PentHertz)
//
// Round 9G regression: pin behaviour of `kdf-bench` + `--kdf-target-time`,
// plus the Round 15 (R15-H3) KDF-cost inheritance of `enroll` / `update`.
//
// These are integration tests against the compiled binary. The
// underlying `parse_kdf_target` + `calibrate_kdf_for_target` helpers
// could also be tested as unit tests, but exercising the CLI path
// catches argparse + dispatch bugs the unit tests would miss.

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
        .env_remove("LUKSBOX_TEST_FAST_KDF")
        .env_remove("LUKSBOX_PASSPHRASE")
        .output()
        .expect("spawn")
}

#[test]
fn kdf_bench_runs_and_reports_interactive_preset() {
    let tmp = tempdir().unwrap();
    let out = run(tmp.path(), &["kdf-bench", "--samples", "1"]);
    assert!(
        out.status.success(),
        "kdf-bench failed:\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr),
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    // The interactive preset runs in 500 ms even on slow hardware,
    // so we always get at least one row of timing data.
    assert!(
        stdout.contains("interactive"),
        "kdf-bench output missing 'interactive' row: {stdout}"
    );
    assert!(
        stdout.contains("median ms") || stdout.contains("Brute-force"),
        "kdf-bench output missing summary section: {stdout}"
    );
}

#[test]
fn kdf_target_time_creates_vault_with_calibrated_params() {
    let tmp = tempdir().unwrap();
    let dir = tmp.path();

    // Pick a small target so the test doesn't take seconds.
    let create = Command::new(bin())
        .args(["create", "v.lbx", "--kdf-target-time", "200ms"])
        .current_dir(dir)
        .env_remove("LUKSBOX_TEST_FAST_KDF")
        .env("LUKSBOX_PASSPHRASE", "calib-test-pp")
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .output()
        .expect("spawn");

    assert!(
        create.status.success(),
        "create with --kdf-target-time failed:\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&create.stdout),
        String::from_utf8_lossy(&create.stderr),
    );
    let stderr = String::from_utf8_lossy(&create.stderr);
    assert!(
        stderr.contains("calibrating Argon2id") || stderr.contains("calibrated"),
        "expected calibration progress in stderr, got: {stderr}"
    );

    // Verify the resulting vault opens (i.e. the calibrated params
    // were correctly stored + applied to wrap+unwrap the MVK).
    let info = Command::new(bin())
        .args(["info", "v.lbx"])
        .current_dir(dir)
        .output()
        .expect("spawn info");
    assert!(info.status.success(), "info on calibrated vault failed");
    let info_out = String::from_utf8_lossy(&info.stdout);
    assert!(
        info_out.contains("Argon2id"),
        "info output should show Argon2id params: {info_out}"
    );
}

#[test]
fn kdf_target_time_rejects_out_of_range_and_malformed_inputs() {
    let tmp = tempdir().unwrap();
    let dir = tmp.path();

    for bad in ["50ms", "9999s", "abc", "5", "100", "0s", "10x"] {
        let out = Command::new(bin())
            .args(["create", "v.lbx", "--kdf-target-time", bad])
            .current_dir(dir)
            .env_remove("LUKSBOX_TEST_FAST_KDF")
            .env("LUKSBOX_PASSPHRASE", "x")
            .output()
            .expect("spawn");
        assert!(
            !out.status.success(),
            "--kdf-target-time {bad:?} should have been rejected, but succeeded:\n{}",
            String::from_utf8_lossy(&out.stdout)
        );
    }
}

#[test]
fn kdf_target_time_conflicts_with_kdf_preset_flag() {
    let tmp = tempdir().unwrap();
    let dir = tmp.path();

    let out = Command::new(bin())
        .args([
            "create",
            "v.lbx",
            "--kdf",
            "interactive",
            "--kdf-target-time",
            "1s",
        ])
        .current_dir(dir)
        .env_remove("LUKSBOX_TEST_FAST_KDF")
        .env("LUKSBOX_PASSPHRASE", "x")
        .output()
        .expect("spawn");
    assert!(
        !out.status.success(),
        "--kdf and --kdf-target-time should conflict (clap should reject)"
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("conflict") || stderr.contains("cannot be used"),
        "expected clap conflict message, got: {stderr}"
    );
}

/// Argon2id `m=` values of the populated passphrase slots, as `info`
/// prints them (`  0: passphrase  (Argon2id m=8192 KiB t=3 p=4)`).
fn slot_m_costs(dir: &Path) -> Vec<String> {
    let info = Command::new(bin())
        .args(["info", "v.lbx"])
        .current_dir(dir)
        .output()
        .expect("spawn info");
    assert!(info.status.success(), "info failed");
    String::from_utf8_lossy(&info.stdout)
        .lines()
        .filter_map(|l| l.split("Argon2id m=").nth(1))
        .map(|rest| rest.split_whitespace().next().unwrap_or("").to_string())
        .collect()
}

/// R15-H3: `update` and `enroll` used to re-wrap at the interactive
/// preset (256 MiB) whatever cost the vault was created with, a silent
/// downgrade for a `--kdf sensitive` vault. They now keep the slot's own
/// cost / take the vault's strongest one. A calibrated vault has a cost
/// no preset produces, so the inherited value is observable here; the
/// real KDF has to run (no LUKSBOX_TEST_FAST_KDF) for the same reason.
#[test]
fn update_and_enroll_inherit_the_vaults_kdf_cost() {
    let tmp = tempdir().unwrap();
    let dir = tmp.path();
    let run_with = |args: &[&str], unlock: &str, new: Option<&str>| -> Output {
        let mut c = Command::new(bin());
        c.args(args)
            .current_dir(dir)
            .env_remove("LUKSBOX_TEST_FAST_KDF")
            .env_remove("LUKSBOX_NEW_PASSPHRASE")
            .env("LUKSBOX_PASSPHRASE", unlock);
        if let Some(n) = new {
            c.env("LUKSBOX_NEW_PASSPHRASE", n);
        }
        c.output().expect("spawn")
    };
    let ok = |out: &Output, what: &str| {
        assert!(
            out.status.success(),
            "{what} failed:\nstdout: {}\nstderr: {}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr),
        );
    };

    ok(
        &run_with(
            &["create", "v.lbx", "--kdf-target-time", "100ms"],
            "calib-old",
            None,
        ),
        "create",
    );
    let created = slot_m_costs(dir);
    assert_eq!(
        created.len(),
        1,
        "one passphrase slot expected: {created:?}"
    );

    ok(
        &run_with(
            &["update", "v.lbx", "--slot", "0"],
            "calib-old",
            Some("calib-new"),
        ),
        "update",
    );
    ok(
        &run_with(&["enroll", "v.lbx"], "calib-new", Some("calib-second")),
        "enroll",
    );
    assert_eq!(
        slot_m_costs(dir),
        vec![created[0].clone(), created[0].clone()],
        "update / enroll must keep the vault's calibrated Argon2id cost"
    );
}

/// `--kdf` is refused for slot kinds that carry no passphrase, before
/// the vault is even unlocked.
#[test]
fn enroll_kdf_flag_rejected_for_non_passphrase_kinds() {
    let tmp = tempdir().unwrap();
    let out = Command::new(bin())
        .args([
            "enroll",
            "missing.lbx",
            "--kind",
            "fido2",
            "--kdf",
            "moderate",
        ])
        .current_dir(tmp.path())
        .env("LUKSBOX_TEST_FAST_KDF", "1")
        .env("LUKSBOX_PASSPHRASE", "x")
        .output()
        .expect("spawn");
    assert!(!out.status.success());
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("--kdf only applies"),
        "expected the --kdf refusal, got: {stderr}"
    );
}
