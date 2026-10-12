// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Penthertz <https://penthertz.com> (https://x.com/PentHertz)

//! `create --max-size`, `luksbox size` (report, `--max`, `--shrink`):
//! the vault size limit and giving back free space at the end of the
//! vault, through the real binary. Small `--metadata-size` keeps the
//! vaults a few MiB.

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
        .env("LUKSBOX_NEW_PASSPHRASE", "pw")
        .output()
        .expect("spawn binary")
}

fn stdout(o: &Output) -> String {
    String::from_utf8_lossy(&o.stdout).into_owned()
}

fn stderr(o: &Output) -> String {
    String::from_utf8_lossy(&o.stderr).into_owned()
}

fn assert_ok(o: &Output, ctx: &str) {
    assert!(
        o.status.success(),
        "{ctx} failed:\nstdout: {}\nstderr: {}",
        stdout(o),
        stderr(o)
    );
}

fn assert_fails_with(o: &Output, needle: &str, ctx: &str) {
    assert!(!o.status.success(), "{ctx} should have failed");
    assert!(
        stderr(o).contains(needle),
        "{ctx}: expected {needle:?} in stderr:\n{}",
        stderr(o)
    );
}

#[test]
fn max_size_smaller_than_the_vault_is_refused_with_the_minimum() {
    let tmp = tempdir().unwrap();
    let dir = tmp.path();
    // Default 64 MiB metadata region: 62M cannot hold the vault itself.
    let out = run(dir, &["create", "v.lbx", "--max-size", "62M"]);
    assert_fails_with(
        &out,
        "smaller than the vault itself",
        "create --max-size 62M",
    );
    assert!(
        stderr(&out).contains("Use at least 65M"),
        "{}",
        stderr(&out)
    );
    assert!(!dir.join("v.lbx").exists(), "nothing may be created");

    // A bare number is bytes; the error suggests the likely unit.
    let out = run(dir, &["create", "v.lbx", "--max-size", "6"]);
    assert_fails_with(&out, "Did you mean 6G?", "create --max-size 6");

    let out = run(dir, &["create", "v.lbx", "--max-size", "6X"]);
    assert_fails_with(&out, "unknown unit", "create --max-size 6X");
}

#[test]
fn max_size_limits_growth_and_can_be_removed() {
    let tmp = tempdir().unwrap();
    let dir = tmp.path();
    assert_ok(
        &run(
            dir,
            &[
                "create",
                "v.lbx",
                "--metadata-size",
                "1M",
                "--max-size",
                "2M",
            ],
        ),
        "create",
    );
    let out = run(dir, &["size", "v.lbx"]);
    assert_ok(&out, "size");
    assert!(
        stdout(&out).contains("Maximum size:   2.0 MB (2,097,152 bytes)"),
        "{}",
        stdout(&out)
    );

    // About 1 MiB of room for data: 4 MiB does not fit.
    std::fs::write(dir.join("big.bin"), vec![7u8; 4 * 1024 * 1024]).unwrap();
    let out = run(dir, &["put", "v.lbx", "big.bin", "/big.bin"]);
    assert_fails_with(&out, "maximum size", "put past the limit");
    assert!(std::fs::metadata(dir.join("v.lbx")).unwrap().len() <= 2 * 1024 * 1024);

    assert_ok(
        &run(dir, &["size", "v.lbx", "--max", "unlimited"]),
        "size --max unlimited",
    );
    let out = run(dir, &["size", "v.lbx"]);
    assert!(
        stdout(&out).contains("Maximum size:   unlimited"),
        "{}",
        stdout(&out)
    );
    assert_ok(
        &run(dir, &["put", "v.lbx", "big.bin", "/big.bin"]),
        "put after --max 0",
    );
}

#[test]
fn shrink_gives_back_the_free_tail() {
    let tmp = tempdir().unwrap();
    let dir = tmp.path();
    assert_ok(
        &run(dir, &["create", "v.lbx", "--metadata-size", "1M"]),
        "create",
    );
    std::fs::write(dir.join("a.bin"), vec![1u8; 512 * 1024]).unwrap();
    std::fs::write(dir.join("b.bin"), vec![2u8; 256 * 1024]).unwrap();
    assert_ok(&run(dir, &["put", "v.lbx", "a.bin", "/a.bin"]), "put a");
    assert_ok(&run(dir, &["put", "v.lbx", "b.bin", "/b.bin"]), "put b");
    assert_ok(&run(dir, &["rm", "v.lbx", "/b.bin"]), "rm b");
    let before = std::fs::metadata(dir.join("v.lbx")).unwrap().len();

    let out = run(dir, &["size", "v.lbx", "--shrink"]);
    assert_ok(&out, "size --shrink");
    assert!(stdout(&out).contains("Gave back"), "{}", stdout(&out));
    let after = std::fs::metadata(dir.join("v.lbx")).unwrap().len();
    // b.bin's 64 chunk slots (4124 bytes each) were the end of the file.
    assert_eq!(before - after, 64 * 4124);

    let out = run(dir, &["size", "v.lbx", "--shrink"]);
    assert!(
        stdout(&out).contains("Nothing to give back"),
        "{}",
        stdout(&out)
    );

    assert_ok(&run(dir, &["get", "v.lbx", "/a.bin", "a.out"]), "get a");
    assert_eq!(
        std::fs::read(dir.join("a.out")).unwrap(),
        vec![1u8; 512 * 1024]
    );
}
