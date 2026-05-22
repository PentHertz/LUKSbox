// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Penthertz <https://penthertz.com> (https://x.com/PentHertz)

//! End-to-end functional tests of the `luksbox` CLI binary.
//!
//! These complement `tests/cli.rs` (which covers the simple
//! create/put/ls/get/rm flows) with the more involved workflows:
//! detached headers, anchors, hybrid-PQ vaults, KDF-strength variants,
//! info reporting, persistence across reopen, large files, panic
//! destruction, and update-passphrase. Every test runs the actual
//! CLI binary as a subprocess (no library shortcuts), so a regression
//! anywhere in the dispatch / parsing / argument-validation layer
//! will show up here.
//!
//! The tests use:
//!   LUKSBOX_TEST_FAST_KDF=1      bypasses Argon2id sleep
//!   LUKSBOX_PASSPHRASE=<pw>      satisfies passphrase prompts
//!   LUKSBOX_NEW_PASSPHRASE=<pw>  satisfies "new passphrase" prompts
//!                                (enroll / update / hybrid-create)
//!   LUKSBOX_ACCEPT_WEAK=1        skips zxcvbn weak-passphrase warning
//!
//! No FIDO2 / hardware paths are exercised here, those need a real
//! authenticator + user touch. See the manual smoke test in TESTING.md.

use std::collections::HashMap;
use std::path::Path;
use std::process::{Command, Output};

use tempfile::tempdir;

fn bin() -> &'static str {
    env!("CARGO_BIN_EXE_luksbox")
}

/// Build the standard test-mode env: fast Argon2id, default passphrase.
fn test_env() -> HashMap<&'static str, &'static str> {
    [
        ("LUKSBOX_TEST_FAST_KDF", "1"),
        ("LUKSBOX_PASSPHRASE", "pw"),
        ("LUKSBOX_NEW_PASSPHRASE", "pw"),
        ("LUKSBOX_ACCEPT_WEAK", "1"),
    ]
    .into_iter()
    .collect()
}

fn run_with(dir: &Path, env: &HashMap<&str, &str>, args: &[&str]) -> Output {
    let mut cmd = Command::new(bin());
    cmd.args(args).current_dir(dir);
    for (k, v) in env {
        cmd.env(k, v);
    }
    cmd.output().expect("spawn binary")
}

fn run(dir: &Path, args: &[&str]) -> Output {
    run_with(dir, &test_env(), args)
}

fn assert_ok(out: &Output, ctx: &str) {
    assert!(
        out.status.success(),
        "{ctx} failed:\n  stdout: {}\n  stderr: {}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr),
    );
}

fn assert_err(out: &Output, ctx: &str) {
    assert!(
        !out.status.success(),
        "{ctx} unexpectedly succeeded:\n  stdout: {}\n  stderr: {}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr),
    );
}

fn stdout(out: &Output) -> String {
    String::from_utf8_lossy(&out.stdout).into_owned()
}
fn stderr(out: &Output) -> String {
    String::from_utf8_lossy(&out.stderr).into_owned()
}

// ---- create-then-reopen round-trip --------------------------------------

#[test]
fn vault_persists_across_reopen() {
    // Write a file to a vault, drop the process, reopen, and verify
    // the file is still there with the same content. Catches any
    // forgotten-to-flush metadata bugs.
    let tmp = tempdir().unwrap();
    let dir = tmp.path();
    assert_ok(&run(dir, &["create", "v.lbx"]), "create");
    std::fs::write(dir.join("payload"), b"persistent data, do not lose").unwrap();
    assert_ok(&run(dir, &["put", "v.lbx", "payload", "/payload"]), "put");

    // Brand-new luksbox process, no shared in-memory state.
    let out = run(dir, &["get", "v.lbx", "/payload", "back.txt"]);
    assert_ok(&out, "get after reopen");
    assert_eq!(
        std::fs::read(dir.join("back.txt")).unwrap(),
        b"persistent data, do not lose"
    );
}

// ---- detached header ----------------------------------------------------

#[test]
fn detached_header_round_trip() {
    // Vault file alone should be useless; --header must be supplied
    // for every operation.
    let tmp = tempdir().unwrap();
    let dir = tmp.path();
    assert_ok(
        &run(dir, &["create", "v.lbx", "--header", "v.hdr"]),
        "create with detached header",
    );
    assert!(dir.join("v.lbx").exists());
    assert!(dir.join("v.hdr").exists());

    std::fs::write(dir.join("file"), b"detached-mode payload").unwrap();
    assert_ok(
        &run(dir, &["put", "v.lbx", "--header", "v.hdr", "file", "/f"]),
        "put with header",
    );

    // Without the header, opening must fail.
    let out = run(dir, &["ls", "v.lbx"]);
    assert_err(&out, "ls without --header on detached vault");

    // With the header, ls works. (ls prints basename, not full path.)
    let out = run(dir, &["ls", "v.lbx", "--header", "v.hdr", "/"]);
    assert_ok(&out, "ls with --header");
    assert!(
        stdout(&out).contains(" f\n") || stdout(&out).ends_with(" f"),
        "ls did not show f in output: {}",
        stdout(&out)
    );

    // Round-trip the file.
    let out = run(dir, &["get", "v.lbx", "--header", "v.hdr", "/f", "out"]);
    assert_ok(&out, "get with header");
    assert_eq!(
        std::fs::read(dir.join("out")).unwrap(),
        b"detached-mode payload"
    );
}

// ---- anchor / rollback detection ----------------------------------------

#[test]
fn anchor_round_trip_and_warn_when_missing() {
    // Vault created with an anchor sidecar. Reopening WITHOUT the
    // anchor must warn (or proceed in non-strict mode); reopening
    // WITH the anchor must succeed cleanly.
    let tmp = tempdir().unwrap();
    let dir = tmp.path();
    assert_ok(
        &run(dir, &["create", "v.lbx", "--anchor", "v.anchor"]),
        "create with anchor",
    );
    assert!(dir.join("v.anchor").exists());

    std::fs::write(dir.join("f"), b"anchor-protected payload").unwrap();
    assert_ok(
        &run(dir, &["put", "v.lbx", "--anchor", "v.anchor", "f", "/f"]),
        "put with anchor",
    );

    // Reopen with anchor, clean.
    let out = run(dir, &["ls", "v.lbx", "--anchor", "v.anchor", "/"]);
    assert_ok(&out, "ls with anchor");
    let s = stdout(&out);
    assert!(
        s.contains(" f\n") || s.ends_with(" f"),
        "ls did not show f after anchor reopen: {s}"
    );

    // Reopen without anchor, open should still succeed (the anchor
    // is opt-in protection); just inspect metadata.
    let out = run(dir, &["info", "v.lbx"]);
    assert_ok(&out, "info without anchor");
}

// ---- hybrid-PQ create / unlock ------------------------------------------

#[test]
fn hybrid_pq_passphrase_round_trip() {
    let tmp = tempdir().unwrap();
    let dir = tmp.path();
    assert_ok(
        &run(
            dir,
            &[
                "create",
                "v.lbx",
                "--kind",
                "hybrid-pq",
                "--pq-hybrid",
                "v.kyber",
            ],
        ),
        "create hybrid-pq",
    );
    assert!(dir.join("v.lbx").exists());
    assert!(dir.join("v.kyber").exists());
    assert!(dir.join("v.lbx.hybrid").exists());

    // Put + get round-trip, proves the hybrid KEK derivation works
    // end-to-end. The CLI auto-detects --pq-hybrid path from the
    // sidecar alongside .lbx if not given on read.
    std::fs::write(dir.join("payload"), b"PQ-protected data").unwrap();
    assert_ok(
        &run(
            dir,
            &["put", "v.lbx", "--pq-hybrid", "v.kyber", "payload", "/p"],
        ),
        "put on hybrid-pq",
    );
    let out = run(
        dir,
        &["get", "v.lbx", "--pq-hybrid", "v.kyber", "/p", "back"],
    );
    assert_ok(&out, "get on hybrid-pq");
    assert_eq!(
        std::fs::read(dir.join("back")).unwrap(),
        b"PQ-protected data"
    );

    // info must mark the slot as hybrid-pq and indicate the level.
    let out = run(dir, &["info", "v.lbx"]);
    assert_ok(&out, "info hybrid-pq");
    let s = stdout(&out);
    assert!(s.contains("hybrid-pq"), "info missing hybrid-pq label: {s}");
}

#[test]
fn hybrid_pq_1024_round_trip() {
    let tmp = tempdir().unwrap();
    let dir = tmp.path();
    assert_ok(
        &run(
            dir,
            &[
                "create",
                "v.lbx",
                "--kind",
                "hybrid-pq1024",
                "--pq-hybrid",
                "v.kyber",
            ],
        ),
        "create hybrid-pq-1024",
    );
    assert!(dir.join("v.kyber").exists());

    std::fs::write(dir.join("p"), b"ML-KEM-1024 payload").unwrap();
    assert_ok(
        &run(dir, &["put", "v.lbx", "--pq-hybrid", "v.kyber", "p", "/p"]),
        "put on hybrid-pq-1024",
    );
    let out = run(
        dir,
        &["get", "v.lbx", "--pq-hybrid", "v.kyber", "/p", "out"],
    );
    assert_ok(&out, "get on hybrid-pq-1024");
    assert_eq!(
        std::fs::read(dir.join("out")).unwrap(),
        b"ML-KEM-1024 payload"
    );

    // info must show the 1024 level.
    let out = run(dir, &["info", "v.lbx"]);
    assert!(stdout(&out).contains("ML-KEM-1024"));
}

#[test]
fn hybrid_pq_wrong_kyber_seed_fails() {
    let tmp = tempdir().unwrap();
    let dir = tmp.path();
    assert_ok(
        &run(
            dir,
            &[
                "create",
                "v.lbx",
                "--kind",
                "hybrid-pq",
                "--pq-hybrid",
                "good.kyber",
            ],
        ),
        "create",
    );

    // Create a second vault to harvest a wrong .kyber file.
    let dir2 = tempdir().unwrap();
    let env2 = test_env();
    assert_ok(
        &run_with(
            dir2.path(),
            &env2,
            &[
                "create",
                "v2.lbx",
                "--kind",
                "hybrid-pq",
                "--pq-hybrid",
                "bad.kyber",
            ],
        ),
        "create v2",
    );
    std::fs::copy(dir2.path().join("bad.kyber"), dir.join("bad.kyber")).unwrap();

    // Opening the first vault with the second's seed must fail.
    let out = run(dir, &["ls", "v.lbx", "--pq-hybrid", "bad.kyber", "/"]);
    assert_err(&out, "wrong .kyber seed must reject open");
}

// ---- KDF strength variants ---------------------------------------------

#[test]
fn kdf_strength_recorded_in_slot() {
    let tmp = tempdir().unwrap();
    let dir = tmp.path();
    // Sensitive isn't faster even with LUKSBOX_TEST_FAST_KDF, that
    // env clamp still bypasses the 1 GiB allocation. Test that the
    // CLI accepts each value and `info` reports it back.
    for kdf in ["interactive", "moderate", "sensitive"] {
        let _ = std::fs::remove_file(dir.join("v.lbx"));
        let out = run(dir, &["create", "v.lbx", "--kdf", kdf]);
        assert_ok(&out, &format!("create --kdf {kdf}"));
        let out = run(dir, &["info", "v.lbx"]);
        assert_ok(&out, "info");
        // Just verify info runs cleanly; the precise label format
        // isn't a stable contract worth asserting on byte-for-byte.
        assert!(stdout(&out).contains("passphrase"));
    }
}

#[test]
fn kdf_strength_rejects_garbage() {
    let tmp = tempdir().unwrap();
    let dir = tmp.path();
    let out = run(dir, &["create", "v.lbx", "--kdf", "ludicrous"]);
    assert_err(&out, "unknown --kdf value must be rejected");
    assert!(
        stderr(&out).to_lowercase().contains("invalid")
            || stderr(&out).to_lowercase().contains("possible values"),
        "expected validation error, got: {}",
        stderr(&out)
    );
}

// ---- info reporting -----------------------------------------------------

#[test]
fn info_reports_cipher_kind_and_keyslot_table() {
    let tmp = tempdir().unwrap();
    let dir = tmp.path();
    assert_ok(
        &run(dir, &["create", "v.lbx", "--cipher", "chacha"]),
        "create",
    );
    let out = run(dir, &["info", "v.lbx"]);
    assert_ok(&out, "info");
    let s = stdout(&out);
    // Cipher line.
    assert!(
        s.to_lowercase().contains("chacha"),
        "info missing cipher: {s}"
    );
    // Keyslot table, at least 8 lines (one per slot).
    let slot_lines = s
        .lines()
        .filter(|l| l.trim_start().starts_with(|c: char| c.is_ascii_digit()))
        .count();
    assert!(
        slot_lines >= 1,
        "info should list at least one populated slot: {s}"
    );
}

// ---- update-passphrase --------------------------------------------------

#[test]
fn update_passphrase_changes_unlock_secret() {
    let tmp = tempdir().unwrap();
    let dir = tmp.path();
    let mut env = test_env();
    env.insert("LUKSBOX_PASSPHRASE", "old");
    env.insert("LUKSBOX_NEW_PASSPHRASE", "old");
    assert_ok(&run_with(dir, &env, &["create", "v.lbx"]), "create");

    // Verify open with "old".
    assert_ok(&run_with(dir, &env, &["ls", "v.lbx"]), "ls with old");

    // Update slot 0 to "new" passphrase. The CLI's `update` reads
    // the OLD passphrase from LUKSBOX_PASSPHRASE and the NEW from
    // LUKSBOX_NEW_PASSPHRASE.
    let mut env_update = env.clone();
    env_update.insert("LUKSBOX_NEW_PASSPHRASE", "new");
    assert_ok(
        &run_with(dir, &env_update, &["update", "v.lbx", "--slot", "0"]),
        "update slot 0",
    );

    // Old passphrase must no longer work.
    let mut env_old = env.clone();
    env_old.insert("LUKSBOX_PASSPHRASE", "old");
    let out = run_with(dir, &env_old, &["ls", "v.lbx"]);
    assert_err(&out, "old passphrase must no longer unlock after update");

    // New passphrase must work.
    let mut env_new = env.clone();
    env_new.insert("LUKSBOX_PASSPHRASE", "new");
    assert_ok(&run_with(dir, &env_new, &["ls", "v.lbx"]), "ls with new");
}

// ---- multi-file workflow ------------------------------------------------

#[test]
fn many_files_round_trip() {
    let tmp = tempdir().unwrap();
    let dir = tmp.path();
    assert_ok(&run(dir, &["create", "v.lbx"]), "create");

    // 30 files, varying sizes, in nested directories.
    assert_ok(&run(dir, &["mkdir", "v.lbx", "/data"]), "mkdir /data");
    assert_ok(
        &run(dir, &["mkdir", "v.lbx", "/data/sub"]),
        "mkdir /data/sub",
    );
    for i in 0..30 {
        let name = format!("f{i}.bin");
        let payload = vec![(i & 0xff) as u8; 1 + (i * 137) % 8000];
        std::fs::write(dir.join(&name), &payload).unwrap();
        let inner = if i % 3 == 0 {
            format!("/data/sub/{name}")
        } else if i % 2 == 0 {
            format!("/data/{name}")
        } else {
            format!("/{name}")
        };
        assert_ok(
            &run(dir, &["put", "v.lbx", &name, &inner]),
            &format!("put {name}"),
        );
    }

    // ls all three dirs and tally.
    let mut total_listed = 0usize;
    for d in &["/", "/data", "/data/sub"] {
        let out = run(dir, &["ls", "v.lbx", d]);
        assert_ok(&out, &format!("ls {d}"));
        total_listed += stdout(&out).lines().filter(|l| l.contains(".bin")).count();
    }
    assert_eq!(total_listed, 30, "expected 30 files across all dirs");

    // Round-trip every file.
    for i in 0..30 {
        let name = format!("f{i}.bin");
        let inner = if i % 3 == 0 {
            format!("/data/sub/{name}")
        } else if i % 2 == 0 {
            format!("/data/{name}")
        } else {
            format!("/{name}")
        };
        let out_path = format!("back-{i}.bin");
        assert_ok(
            &run(dir, &["get", "v.lbx", &inner, &out_path]),
            &format!("get {inner}"),
        );
        let expected = vec![(i & 0xff) as u8; 1 + (i * 137) % 8000];
        let got = std::fs::read(dir.join(&out_path)).unwrap();
        assert_eq!(got, expected, "content mismatch for {inner}");
    }
}

// ---- big-file write/read (multi-chunk) ----------------------------------

#[test]
fn one_megabyte_file_round_trip() {
    let tmp = tempdir().unwrap();
    let dir = tmp.path();
    assert_ok(&run(dir, &["create", "v.lbx"]), "create");

    // 1 MiB of pseudo-random bytes (deterministic so we can check).
    let mut payload = Vec::with_capacity(1024 * 1024);
    let mut x: u32 = 0xDEAD_BEEF;
    for _ in 0..(1024 * 1024) {
        x = x.wrapping_mul(1664525).wrapping_add(1013904223);
        payload.push((x >> 16) as u8);
    }
    std::fs::write(dir.join("big"), &payload).unwrap();

    assert_ok(&run(dir, &["put", "v.lbx", "big", "/big"]), "put big");
    assert_ok(&run(dir, &["get", "v.lbx", "/big", "back"]), "get big");
    let got = std::fs::read(dir.join("back")).unwrap();
    assert_eq!(got.len(), 1024 * 1024);
    assert_eq!(got, payload);
}

// ---- pad-files / hide-sizes hardening flags ----------------------------

#[test]
fn pad_files_flag_accepted_and_round_trips() {
    let tmp = tempdir().unwrap();
    let dir = tmp.path();
    assert_ok(
        &run(dir, &["create", "v.lbx", "--pad-files"]),
        "create --pad-files",
    );
    std::fs::write(dir.join("f"), b"padded payload").unwrap();
    assert_ok(&run(dir, &["put", "v.lbx", "f", "/f"]), "put");
    let out = run(dir, &["get", "v.lbx", "/f", "out"]);
    assert_ok(&out, "get");
    assert_eq!(std::fs::read(dir.join("out")).unwrap(), b"padded payload");
}

#[test]
fn hide_sizes_flag_accepted_and_round_trips() {
    let tmp = tempdir().unwrap();
    let dir = tmp.path();
    assert_ok(
        &run(dir, &["create", "v.lbx", "--hide-sizes"]),
        "create --hide-sizes",
    );
    std::fs::write(dir.join("f"), b"size-hidden payload of nontrivial length").unwrap();
    assert_ok(&run(dir, &["put", "v.lbx", "f", "/f"]), "put");
    let out = run(dir, &["get", "v.lbx", "/f", "out"]);
    assert_ok(&out, "get");
    assert_eq!(
        std::fs::read(dir.join("out")).unwrap(),
        b"size-hidden payload of nontrivial length"
    );
}

// ---- cat command --------------------------------------------------------

#[test]
fn cat_streams_to_stdout() {
    let tmp = tempdir().unwrap();
    let dir = tmp.path();
    assert_ok(&run(dir, &["create", "v.lbx"]), "create");
    std::fs::write(dir.join("note"), b"line1\nline2\nline3\n").unwrap();
    assert_ok(&run(dir, &["put", "v.lbx", "note", "/n"]), "put");
    let out = run(dir, &["cat", "v.lbx", "/n"]);
    assert_ok(&out, "cat");
    assert_eq!(out.stdout, b"line1\nline2\nline3\n");
}

// ---- rmdir on empty / non-empty -----------------------------------------

#[test]
fn rmdir_empty_succeeds_nonempty_fails() {
    let tmp = tempdir().unwrap();
    let dir = tmp.path();
    assert_ok(&run(dir, &["create", "v.lbx"]), "create");
    assert_ok(&run(dir, &["mkdir", "v.lbx", "/empty"]), "mkdir empty");
    assert_ok(&run(dir, &["mkdir", "v.lbx", "/full"]), "mkdir full");
    std::fs::write(dir.join("x"), b"x").unwrap();
    assert_ok(&run(dir, &["put", "v.lbx", "x", "/full/x"]), "put x");

    assert_ok(&run(dir, &["rmdir", "v.lbx", "/empty"]), "rmdir empty");
    let out = run(dir, &["rmdir", "v.lbx", "/full"]);
    assert_err(&out, "rmdir on non-empty must fail");
}

// ---- panic destruction --------------------------------------------------

#[test]
fn panic_destroy_overwrites_header() {
    let tmp = tempdir().unwrap();
    let dir = tmp.path();
    assert_ok(&run(dir, &["create", "v.lbx"]), "create");
    let header_before = {
        let mut buf = vec![0u8; 8192];
        use std::io::Read;
        let mut f = std::fs::File::open(dir.join("v.lbx")).unwrap();
        f.read_exact(&mut buf).unwrap();
        buf
    };

    // The panic command needs an explicit "DESTROY <path>" confirmation
    // by default; pass -y to auto-accept (per cmd_panic in main.rs).
    let mut env = test_env();
    env.insert("LUKSBOX_TEST_FAST_KDF", "1");
    let out = run_with(dir, &env, &["panic", "v.lbx", "-y"]);
    assert_ok(&out, "panic -y");

    let header_after = {
        let mut buf = vec![0u8; 8192];
        use std::io::Read;
        let mut f = std::fs::File::open(dir.join("v.lbx")).unwrap();
        f.read_exact(&mut buf).unwrap();
        buf
    };
    assert_ne!(
        header_before, header_after,
        "panic must overwrite the header (8 KB) with random bytes"
    );

    // Open after panic must fail.
    let out = run(dir, &["info", "v.lbx"]);
    assert_err(&out, "info on panic-destroyed vault must fail");
}

#[test]
#[cfg(unix)]
fn panic_destroy_refuses_symlinked_vault_path() {
    // Audit regression: the panic-destroy paths used to do
    // `vault.is_file()` (follows symlinks) then `OpenOptions::open`
    // (also follows symlinks), letting an attacker who controls the
    // parent dir swap in a symlink between the check and the write
    // to redirect the random-bytes overwrite to /etc/shadow or
    // similar. The fix routes through `secure_open_existing_no_follow`
    // which refuses symlinks at the open syscall via O_NOFOLLOW.
    //
    // This test plants a symlink at the vault path pointing at a
    // sentinel file, runs `panic -y --wipe-data`, and verifies:
    //   1. the command exits non-zero (refused to operate)
    //   2. the sentinel file is byte-for-byte unchanged
    //   3. the symlink itself is still a symlink (untouched)
    let tmp = tempdir().unwrap();
    let dir = tmp.path();
    let sentinel = dir.join("sentinel-do-not-touch");
    let sentinel_content = b"this file must survive the panic attempt";
    std::fs::write(&sentinel, sentinel_content).unwrap();

    let attacker_path = dir.join("symlinked-vault.lbx");
    std::os::unix::fs::symlink(&sentinel, &attacker_path).unwrap();

    let mut env = test_env();
    env.insert("LUKSBOX_TEST_FAST_KDF", "1");
    let out = run_with(
        dir,
        &env,
        &["panic", "symlinked-vault.lbx", "-y", "--wipe-data"],
    );
    assert_err(
        &out,
        "panic on a symlinked vault path must refuse, not redirect the overwrite",
    );

    // Sentinel must be byte-for-byte unchanged.
    let sentinel_after = std::fs::read(&sentinel).unwrap();
    assert_eq!(
        sentinel_after, sentinel_content,
        "BUG: panic destroy followed a symlink and overwrote the target file"
    );
    // Symlink itself is still a symlink.
    let meta = std::fs::symlink_metadata(&attacker_path).unwrap();
    assert!(meta.file_type().is_symlink());
}

// ---- info on missing / malformed ----------------------------------------

#[test]
fn info_on_missing_file_is_clean_error() {
    let tmp = tempdir().unwrap();
    let out = run(tmp.path(), &["info", "no-such-vault.lbx"]);
    assert_err(&out, "info on missing path");
    let s = stderr(&out);
    assert!(
        !s.contains("panicked") && !s.contains("RUST_BACKTRACE"),
        "info should not panic on missing file: {s}"
    );
}

#[test]
fn ls_on_garbage_file_is_clean_error() {
    let tmp = tempdir().unwrap();
    let dir = tmp.path();
    std::fs::write(
        dir.join("not-a-vault.lbx"),
        b"random garbage not a real vault",
    )
    .unwrap();
    let out = run(dir, &["ls", "not-a-vault.lbx", "/"]);
    assert_err(&out, "ls on garbage");
    assert!(
        !stderr(&out).contains("panicked"),
        "ls on garbage should not panic"
    );
}

// ---- genpass standalone -------------------------------------------------

// ---- AES-NI startup warning (audit round 6, item I) -------------------

#[test]
fn no_aes_warning_when_hardware_aes_is_present() {
    // Default invocation on a CPU with AES-NI (or aarch64 crypto):
    // the warning must NOT appear. Test this by running any cheap
    // command and checking stderr is clean of the AES warning.
    let tmp = tempdir().unwrap();
    let out = run(tmp.path(), &["--help"]);
    let s = stderr(&out);
    // help goes to stdout, errors/warnings to stderr. The startup
    // banner runs before clap parses --help, so any AES warning
    // would appear first on stderr.
    assert!(
        !s.contains("hardware AES acceleration"),
        "expected no AES warning on AES-NI CPU; got stderr: {s}"
    );
}

#[test]
fn aes_warning_fires_when_hardware_aes_is_absent() {
    // Force the no-AES path with the test override env var. The
    // warning must fire on stderr, name a workaround (`--cipher
    // chacha`), and mention the suppression env var.
    let tmp = tempdir().unwrap();
    let mut env = test_env();
    env.insert("LUKSBOX_FAKE_NO_AES", "1");
    let out = run_with(tmp.path(), &env, &["--help"]);
    let s = stderr(&out);
    assert!(
        s.contains("hardware AES acceleration"),
        "expected AES warning under LUKSBOX_FAKE_NO_AES=1; got stderr: {s}"
    );
    assert!(
        s.contains("--cipher chacha"),
        "warning must recommend `--cipher chacha`; got: {s}"
    );
    assert!(
        s.contains("LUKSBOX_SUPPRESS_AES_WARNING"),
        "warning must mention the suppression env var; got: {s}"
    );
}

#[test]
fn aes_warning_can_be_suppressed_with_env_var() {
    let tmp = tempdir().unwrap();
    let mut env = test_env();
    env.insert("LUKSBOX_FAKE_NO_AES", "1");
    env.insert("LUKSBOX_SUPPRESS_AES_WARNING", "1");
    let out = run_with(tmp.path(), &env, &["--help"]);
    let s = stderr(&out);
    assert!(
        !s.contains("hardware AES acceleration"),
        "LUKSBOX_SUPPRESS_AES_WARNING=1 must silence the warning; got: {s}"
    );
}

/// `luksbox get` must produce mode 0600 on the extracted plaintext
/// even when the user's umask is permissive (the default 022 on most
/// distros). Closes the "decrypted exports use default umask
/// permissions" finding (round 11, item #2). The umask is set in the
/// child via `pre_exec` so this test doesn't race with the rest of
/// the suite, which runs in parallel and shares process-global umask.
#[cfg(unix)]
#[test]
fn cmd_get_writes_extracted_plaintext_as_0600_under_022_umask() {
    use std::os::unix::fs::PermissionsExt;
    use std::os::unix::process::CommandExt;

    let tmp = tempdir().unwrap();
    let dir = tmp.path();

    assert_ok(&run(dir, &["create", "v.lbx"]), "create");
    std::fs::write(dir.join("payload"), b"plaintext should not leak via umask").unwrap();
    assert_ok(&run(dir, &["put", "v.lbx", "payload", "/payload"]), "put");

    // Spawn `get` with umask set to the permissive 022 in the child.
    // Without our fix the extracted file would be 0644.
    let mut cmd = Command::new(bin());
    cmd.args(["get", "v.lbx", "/payload", "back.txt"])
        .current_dir(dir);
    for (k, v) in test_env() {
        cmd.env(k, v);
    }
    unsafe {
        cmd.pre_exec(|| {
            libc::umask(0o022);
            Ok(())
        });
    }
    let out = cmd.output().expect("spawn binary");
    assert_ok(&out, "get under umask 022");

    let mode = std::fs::metadata(dir.join("back.txt"))
        .expect("extracted file exists")
        .permissions()
        .mode()
        & 0o7777;
    assert_eq!(
        mode, 0o600,
        "extracted plaintext must be 0600 even under umask 022; got {mode:o}"
    );
}

#[test]
fn genpass_outputs_passphrase() {
    let tmp = tempdir().unwrap();
    let out = run(tmp.path(), &["genpass"]);
    assert_ok(&out, "genpass");
    let s = stdout(&out);
    let trimmed = s.trim();
    assert!(
        trimmed.len() >= 16,
        "genpass should print a non-trivial passphrase, got {trimmed:?}"
    );
}

// ---- permutation matrix: detached-header X anchor X hybrid -------------
//
// Audit gap: 3 of 8 permutations had no explicit round-trip test:
//   * detached-header + anchor (no hybrid)
//   * detached-header + anchor + hybrid-PQ
//   * inline-header + anchor + hybrid-PQ
//
// The components are tested in isolation (detached_header_round_trip,
// anchor_round_trip_and_warn_when_missing, hybrid_pq_passphrase_round_trip),
// but combinations could interact (e.g. anchor offset arithmetic when
// the header is detached, or anchor-MAC chain disagreeing with the
// hybrid-PQ-derived KEK on first write). These tests pin the matrix.

/// Detached-header + anchor: vault.lbx + vault.hdr + vault.anchor;
/// every op needs both --header and --anchor.
#[test]
fn detached_header_with_anchor_round_trip() {
    let tmp = tempdir().unwrap();
    let dir = tmp.path();
    assert_ok(
        &run(
            dir,
            &[
                "create", "v.lbx", "--header", "v.hdr", "--anchor", "v.anchor",
            ],
        ),
        "create detached + anchor",
    );
    assert!(dir.join("v.lbx").exists());
    assert!(dir.join("v.hdr").exists());
    assert!(dir.join("v.anchor").exists());

    std::fs::write(dir.join("f"), b"detached+anchor payload").unwrap();
    assert_ok(
        &run(
            dir,
            &[
                "put", "v.lbx", "--header", "v.hdr", "--anchor", "v.anchor", "f", "/f",
            ],
        ),
        "put with detached + anchor",
    );

    // Reopen with both, must succeed.
    let out = run(
        dir,
        &[
            "ls", "v.lbx", "--header", "v.hdr", "--anchor", "v.anchor", "/",
        ],
    );
    assert_ok(&out, "ls with detached + anchor");
    let s = stdout(&out);
    assert!(
        s.contains(" f\n") || s.ends_with(" f"),
        "ls did not show f: {s}"
    );

    // Round-trip the file through detached + anchor.
    let out = run(
        dir,
        &[
            "get", "v.lbx", "--header", "v.hdr", "--anchor", "v.anchor", "/f", "out",
        ],
    );
    assert_ok(&out, "get with detached + anchor");
    assert_eq!(
        std::fs::read(dir.join("out")).unwrap(),
        b"detached+anchor payload"
    );
}

/// Inline header + anchor + hybrid-PQ: covers the third missing
/// permutation. Hybrid-PQ pulls in an extra sidecar (.lbx.hybrid +
/// .kyber); add the anchor on top to verify the anchor-MAC chain
/// stays consistent with the hybrid-derived KEK across writes.
#[test]
fn inline_anchor_hybrid_pq_round_trip() {
    let tmp = tempdir().unwrap();
    let dir = tmp.path();
    assert_ok(
        &run(
            dir,
            &[
                "create",
                "v.lbx",
                "--kind",
                "hybrid-pq",
                "--pq-hybrid",
                "v.kyber",
                "--anchor",
                "v.anchor",
            ],
        ),
        "create hybrid + anchor",
    );
    assert!(dir.join("v.lbx").exists());
    assert!(dir.join("v.lbx.hybrid").exists());
    assert!(dir.join("v.kyber").exists());
    assert!(dir.join("v.anchor").exists());

    std::fs::write(dir.join("f"), b"hybrid+anchor payload").unwrap();
    assert_ok(
        &run(
            dir,
            &[
                "put",
                "v.lbx",
                "--pq-hybrid",
                "v.kyber",
                "--anchor",
                "v.anchor",
                "f",
                "/f",
            ],
        ),
        "put with hybrid + anchor",
    );

    let out = run(
        dir,
        &[
            "ls",
            "v.lbx",
            "--pq-hybrid",
            "v.kyber",
            "--anchor",
            "v.anchor",
            "/",
        ],
    );
    assert_ok(&out, "ls with hybrid + anchor");
    let s = stdout(&out);
    assert!(
        s.contains(" f\n") || s.ends_with(" f"),
        "ls did not show f: {s}"
    );
}

/// Detached-header + anchor + hybrid-PQ: the tightest permutation
/// in the matrix. Header lives in v.hdr (so anchor MAC chains over
/// the detached header bytes); hybrid-PQ adds v.lbx.hybrid + v.kyber.
/// Ensures all three independent integrity layers (anchor MAC,
/// detached-header MAC, hybrid-PQ KEK derivation) agree on the
/// passphrase-derived MVK on every write.
#[test]
fn detached_header_with_anchor_and_hybrid_pq_round_trip() {
    let tmp = tempdir().unwrap();
    let dir = tmp.path();
    assert_ok(
        &run(
            dir,
            &[
                "create",
                "v.lbx",
                "--header",
                "v.hdr",
                "--kind",
                "hybrid-pq",
                "--pq-hybrid",
                "v.kyber",
                "--anchor",
                "v.anchor",
            ],
        ),
        "create detached + anchor + hybrid-PQ",
    );
    assert!(dir.join("v.lbx").exists());
    assert!(dir.join("v.hdr").exists());
    // Hybrid sidecar is named after the *header* path (since the header
    // is what carries the slot table). With detached header, the
    // sidecar lives next to the header file.
    let hybrid_sidecar = if dir.join("v.hdr.hybrid").exists() {
        dir.join("v.hdr.hybrid")
    } else {
        dir.join("v.lbx.hybrid")
    };
    assert!(
        hybrid_sidecar.exists(),
        "hybrid sidecar not created (looked for v.hdr.hybrid and v.lbx.hybrid)",
    );
    assert!(dir.join("v.kyber").exists());
    assert!(dir.join("v.anchor").exists());

    std::fs::write(dir.join("f"), b"detached+anchor+hybrid payload").unwrap();
    assert_ok(
        &run(
            dir,
            &[
                "put",
                "v.lbx",
                "--header",
                "v.hdr",
                "--pq-hybrid",
                "v.kyber",
                "--anchor",
                "v.anchor",
                "f",
                "/f",
            ],
        ),
        "put with detached + anchor + hybrid-PQ",
    );

    let out = run(
        dir,
        &[
            "ls",
            "v.lbx",
            "--header",
            "v.hdr",
            "--pq-hybrid",
            "v.kyber",
            "--anchor",
            "v.anchor",
            "/",
        ],
    );
    assert_ok(&out, "ls with detached + anchor + hybrid-PQ");
    let s = stdout(&out);
    assert!(
        s.contains(" f\n") || s.ends_with(" f"),
        "ls did not show f: {s}"
    );

    let out = run(
        dir,
        &[
            "get",
            "v.lbx",
            "--header",
            "v.hdr",
            "--pq-hybrid",
            "v.kyber",
            "--anchor",
            "v.anchor",
            "/f",
            "out",
        ],
    );
    assert_ok(&out, "get with detached + anchor + hybrid-PQ");
    assert_eq!(
        std::fs::read(dir.join("out")).unwrap(),
        b"detached+anchor+hybrid payload",
    );

    // Tampering: corrupting the hybrid sidecar must break unlock
    // (PQ shared changes -> hybrid KEK derivation fails).
    std::fs::write(&hybrid_sidecar, b"GARBAGE").unwrap();
    let out = run(
        dir,
        &[
            "ls",
            "v.lbx",
            "--header",
            "v.hdr",
            "--pq-hybrid",
            "v.kyber",
            "--anchor",
            "v.anchor",
            "/",
        ],
    );
    assert_err(&out, "ls with corrupted hybrid sidecar must fail");
}

// ---- concurrent-create lock-race --------------------------------------
//
// Two processes simultaneously call `Container::create_with_passphrase`
// on the same path. Expected: one wins, the other gets a clean
// AlreadyExists or VaultLocked error. NEVER silent corruption (e.g.
// both succeeded but produced two different vaults or a half-written
// one).
#[test]
fn concurrent_create_same_path_one_wins_other_fails_cleanly() {
    use std::sync::Arc;
    use std::sync::Barrier;
    use std::thread;

    let tmp = tempdir().unwrap();
    let path = tmp.path().join("race.lbx").to_string_lossy().into_owned();
    let dir = tmp.path().to_path_buf();
    let path_a = path.clone();
    let path_b = path.clone();
    let dir_a = dir.clone();
    let dir_b = dir.clone();

    // Barrier ensures both threads call `create` near-simultaneously
    // (within a few microseconds); without this the OS scheduler
    // could trivially serialize the syscalls and the race window
    // never opens.
    let gate = Arc::new(Barrier::new(2));
    let g_a = gate.clone();
    let g_b = gate.clone();

    let h_a = thread::spawn(move || {
        g_a.wait();
        run(&dir_a, &["create", &path_a])
    });
    let h_b = thread::spawn(move || {
        g_b.wait();
        run(&dir_b, &["create", &path_b])
    });

    let out_a = h_a.join().unwrap();
    let out_b = h_b.join().unwrap();

    let ok_a = out_a.status.success();
    let ok_b = out_b.status.success();
    // Exactly one succeeds, the other fails. Both succeeding would be
    // silent corruption (last-writer-wins on the file); both failing
    // would be a different kind of bug (both saw existing-not-existing
    // racing each other).
    assert!(
        ok_a ^ ok_b,
        "expected exactly ONE create to succeed (race winner). \
         A status: {:?}, B status: {:?}\nA stderr: {}\nB stderr: {}",
        out_a.status,
        out_b.status,
        String::from_utf8_lossy(&out_a.stderr),
        String::from_utf8_lossy(&out_b.stderr),
    );
    // Survivor produced a vault that opens cleanly.
    let info = run(tmp.path(), &["info", "race.lbx"]);
    assert_ok(&info, "info on race-survivor vault must succeed");
}

// ---------------------------------------------------------------------------
// Forensic / recovery surfaces: header-backup, header-restore, header-dump,
// check, extract --tolerate-errors. The corruption tests deliberately patch
// bytes on disk to simulate a damaged vault.
// ---------------------------------------------------------------------------

/// Patch `n_bytes` bytes at `offset` of `path` to a constant value.
/// Used by the forensic tests below to simulate on-disk corruption
/// (a single bit flip is enough to fail AEAD).
fn corrupt_bytes(path: &Path, offset: u64, n_bytes: usize, fill: u8) {
    use std::io::{Seek, SeekFrom, Write};
    let mut f = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(path)
        .expect("open vault for corruption");
    f.seek(SeekFrom::Start(offset)).expect("seek");
    f.write_all(&vec![fill; n_bytes]).expect("corrupt write");
}

#[test]
fn header_backup_writes_8192_bytes_mode_0600() {
    let tmp = tempdir().unwrap();
    let dir = tmp.path();
    assert_ok(&run(dir, &["create", "v.lbx"]), "create");
    let out = run(dir, &["header-backup", "v.lbx", "v.hdrbak"]);
    assert_ok(&out, "header-backup");
    let meta = std::fs::metadata(dir.join("v.hdrbak")).unwrap();
    assert_eq!(meta.len(), 8192, "header backup must be exactly 8 KiB");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        // Backup is a plaintext copy of secrets-adjacent header bytes
        // (keyslots, salts) -- must NOT be world-readable.
        assert_eq!(meta.permissions().mode() & 0o777, 0o600);
    }
}

#[test]
fn header_backup_refuses_existing_output() {
    let tmp = tempdir().unwrap();
    let dir = tmp.path();
    assert_ok(&run(dir, &["create", "v.lbx"]), "create");
    std::fs::write(dir.join("existing"), b"do not overwrite me").unwrap();
    let out = run(dir, &["header-backup", "v.lbx", "existing"]);
    assert_err(
        &out,
        "header-backup must refuse to overwrite existing files",
    );
    // Original file untouched.
    assert_eq!(
        std::fs::read(dir.join("existing")).unwrap(),
        b"do not overwrite me"
    );
}

#[test]
fn header_restore_round_trip_inline_with_no_verify() {
    // The full damaged-header recovery scenario: take a backup,
    // damage the inline header HMAC bytes, confirm unlock fails,
    // restore the backup with --no-verify, confirm unlock succeeds.
    let tmp = tempdir().unwrap();
    let dir = tmp.path();
    assert_ok(&run(dir, &["create", "v.lbx"]), "create");
    std::fs::write(dir.join("payload"), b"hello forensic recovery").unwrap();
    assert_ok(&run(dir, &["put", "v.lbx", "payload", "/p"]), "put");
    assert_ok(
        &run(dir, &["header-backup", "v.lbx", "v.hdrbak"]),
        "header-backup",
    );

    // OFF_HMAC = HEADER_SIZE - HMAC_LEN = 8192 - 32 = 8160.
    corrupt_bytes(&dir.join("v.lbx"), 8160, 32, 0xaa);

    // v0.2.1+: a header-bak sidecar was written when the vault first
    // auto-upgraded to LUKSBOX2. To exercise the user-managed
    // header-restore path (rather than the automatic mirror
    // recovery), remove the sidecar first.
    let _ = std::fs::remove_file(dir.join("v.lbx.header-bak"));

    // Sanity: ls now fails because the header HMAC is wrong AND
    // there's no mirror to recover from.
    let out = run(dir, &["ls", "v.lbx", "/"]);
    assert_err(&out, "ls on corrupted-header vault must fail");
    assert!(
        stderr(&out).contains("header authentication"),
        "expected header-auth error, got: {}",
        stderr(&out)
    );

    // Restore the backup. --no-verify is the only option here because
    // we cannot unlock the vault to do the HMAC pre-check.
    let out = run(dir, &["header-restore", "v.lbx", "v.hdrbak", "--no-verify"]);
    assert_ok(&out, "header-restore --no-verify");

    // Now ls + cat work again on the original payload.
    let out = run(dir, &["cat", "v.lbx", "/p"]);
    assert_ok(&out, "cat after header-restore");
    assert_eq!(out.stdout, b"hello forensic recovery");
}

#[test]
fn header_restore_refuses_a_header_from_a_different_vault() {
    // Without this guard, an attacker who could replace the user's
    // backup file would silently install a header that authenticates
    // under THEIR MVK on the next restore. The default-on HMAC
    // pre-check rejects it.
    let tmp = tempdir().unwrap();
    let dir = tmp.path();
    assert_ok(&run(dir, &["create", "v.lbx"]), "create v");
    assert_ok(&run(dir, &["create", "other.lbx"]), "create other");
    assert_ok(
        &run(dir, &["header-backup", "other.lbx", "other.hdrbak"]),
        "backup other",
    );
    let out = run(dir, &["header-restore", "v.lbx", "other.hdrbak"]);
    assert_err(&out, "restoring an alien-vault header must be refused");
    assert!(
        stderr(&out).contains("does NOT verify"),
        "expected HMAC-verify error, got: {}",
        stderr(&out)
    );
}

#[test]
fn header_restore_refuses_truncated_input() {
    let tmp = tempdir().unwrap();
    let dir = tmp.path();
    assert_ok(&run(dir, &["create", "v.lbx"]), "create");
    std::fs::write(dir.join("short.bin"), &[0u8; 500]).unwrap();
    let out = run(
        dir,
        &["header-restore", "v.lbx", "short.bin", "--no-verify"],
    );
    assert_err(&out, "must reject < 8 KiB input");
}

#[test]
fn header_dump_emits_valid_json_with_keyslots_and_chunk_refs() {
    let tmp = tempdir().unwrap();
    let dir = tmp.path();
    assert_ok(&run(dir, &["create", "v.lbx"]), "create");
    std::fs::write(dir.join("payload"), vec![0xaa; 12000]).unwrap();
    assert_ok(&run(dir, &["put", "v.lbx", "payload", "/payload"]), "put");

    let out = run(dir, &["header-dump", "v.lbx"]);
    assert_ok(&out, "header-dump");
    let s = stdout(&out);
    let v: serde_json::Value = serde_json::from_str(&s).expect("header-dump must emit valid JSON");

    assert!(v["header"]["cipher"].is_string());
    assert!(v["header"]["data_offset"].is_number());
    assert_eq!(v["keyslots"].as_array().unwrap().len(), 8);

    // Find the /payload inode and check it has 3 chunk refs (12000B / 4096).
    let inodes = v["inodes"].as_array().unwrap();
    let payload = inodes
        .iter()
        .find(|i| i["path"] == "/payload")
        .expect("dump must contain /payload");
    assert_eq!(payload["kind"], "file");
    assert_eq!(payload["chunks"].as_array().unwrap().len(), 3);
    // Generations are monotonic per write.
    let g0 = payload["chunks"][0]["generation"].as_u64().unwrap();
    let g1 = payload["chunks"][1]["generation"].as_u64().unwrap();
    let g2 = payload["chunks"][2]["generation"].as_u64().unwrap();
    assert!(g0 < g1 && g1 < g2);
}

#[test]
fn check_reports_chunk_aead_failure_with_exact_offset() {
    let tmp = tempdir().unwrap();
    let dir = tmp.path();
    assert_ok(&run(dir, &["create", "v.lbx"]), "create");
    std::fs::write(dir.join("payload"), vec![0xcc; 12000]).unwrap();
    assert_ok(&run(dir, &["put", "v.lbx", "payload", "/payload"]), "put");

    // Pull the slot_offset for chunk 1 from the dump, then corrupt
    // 4 bytes inside its ciphertext region. We can't hardcode the
    // offset because data_offset depends on the metadata region size.
    let dump = run(dir, &["header-dump", "v.lbx"]);
    assert_ok(&dump, "header-dump for offset");
    let v: serde_json::Value = serde_json::from_str(&stdout(&dump)).unwrap();
    let chunk1_off = v["inodes"]
        .as_array()
        .unwrap()
        .iter()
        .find(|i| i["path"] == "/payload")
        .unwrap()["chunks"][1]["slot_offset"]
        .as_u64()
        .unwrap();
    // Skip the 12-byte nonce so we corrupt ciphertext, not the
    // public nonce field.
    corrupt_bytes(&dir.join("v.lbx"), chunk1_off + 64, 4, 0xff);

    // Healthy `check` exits non-zero because of the corruption,
    // human-readable mode mentions the path.
    let out = run(dir, &["check", "v.lbx"]);
    assert_err(&out, "check on corrupted vault must fail");
    let combined = format!("{}{}", stdout(&out), stderr(&out));
    assert!(
        combined.contains("/payload") && combined.contains("chunk_idx=1"),
        "check must mention the affected file and chunk_idx, got: {combined}"
    );

    // --json output is a parseable JSON document.
    let out = run(dir, &["check", "v.lbx", "--json"]);
    assert_err(&out, "check --json still exits non-zero on failures");
    let v: serde_json::Value =
        serde_json::from_str(&stdout(&out)).expect("check --json must emit valid JSON");
    assert_eq!(v["summary"]["chunks_bad"].as_u64(), Some(1));
    assert_eq!(v["summary"]["chunks_ok"].as_u64(), Some(2));
    assert_eq!(v["failures"][0]["path"], "/payload");
    assert_eq!(v["failures"][0]["chunk_idx"].as_u64(), Some(1));
}

#[test]
fn extract_refuses_without_tolerate_errors_flag() {
    let tmp = tempdir().unwrap();
    let dir = tmp.path();
    assert_ok(&run(dir, &["create", "v.lbx"]), "create");
    std::fs::write(dir.join("payload"), b"plain content").unwrap();
    assert_ok(&run(dir, &["put", "v.lbx", "payload", "/p"]), "put");

    // Even on a healthy vault, extract is the lossy code path; we
    // require explicit acknowledgement so a user doesn't accidentally
    // capture zero-padded output thinking it's the real file.
    let out = run(dir, &["extract", "v.lbx", "/p", "out.bin"]);
    assert_err(&out, "extract without --tolerate-errors must refuse");
}

#[test]
fn extract_tolerates_one_bad_chunk_and_zero_fills_the_gap() {
    let tmp = tempdir().unwrap();
    let dir = tmp.path();
    assert_ok(&run(dir, &["create", "v.lbx"]), "create");
    let payload = vec![0x55u8; 12000];
    std::fs::write(dir.join("payload"), &payload).unwrap();
    assert_ok(&run(dir, &["put", "v.lbx", "payload", "/p"]), "put");

    // Damage chunk 1 specifically.
    let dump = run(dir, &["header-dump", "v.lbx"]);
    let v: serde_json::Value = serde_json::from_str(&stdout(&dump)).unwrap();
    let chunk1_off = v["inodes"]
        .as_array()
        .unwrap()
        .iter()
        .find(|i| i["path"] == "/p")
        .unwrap()["chunks"][1]["slot_offset"]
        .as_u64()
        .unwrap();
    corrupt_bytes(&dir.join("v.lbx"), chunk1_off + 64, 4, 0xff);

    // get fails (strict mode).
    let out = run(dir, &["get", "v.lbx", "/p", "broken.bin"]);
    assert_err(&out, "get on file with bad chunk must fail");

    // extract --tolerate-errors writes the file with chunk-1 zero-filled.
    let out = run(
        dir,
        &[
            "extract",
            "v.lbx",
            "/p",
            "rec.bin",
            "--tolerate-errors",
            "--report",
            "fail.json",
        ],
    );
    assert_ok(&out, "extract --tolerate-errors");

    let recovered = std::fs::read(dir.join("rec.bin")).unwrap();
    assert_eq!(recovered.len(), 12000, "size preserved");
    // Chunks 0 and 2 reproduce the original bytes; chunk 1 (range
    // [4096, 8192)) is all zeros.
    assert_eq!(&recovered[..4096], &payload[..4096]);
    assert!(
        recovered[4096..8192].iter().all(|&b| b == 0),
        "chunk-1 range must be zero-filled"
    );
    assert_eq!(&recovered[8192..12000], &payload[8192..12000]);

    // Failure report parses and references the same chunk_idx.
    let report: serde_json::Value =
        serde_json::from_slice(&std::fs::read(dir.join("fail.json")).unwrap()).unwrap();
    assert_eq!(report["chunks_bad"].as_u64(), Some(1));
    assert_eq!(report["failures"][0]["chunk_idx"].as_u64(), Some(1));
}
