// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Penthertz <https://penthertz.com> (https://x.com/PentHertz)
//
// Round 9G regression: pin behaviour of `kdf-bench` + `--kdf-target-time`.
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
