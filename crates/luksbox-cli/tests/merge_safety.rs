// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Penthertz <https://penthertz.com> (https://x.com/PentHertz)

//! `luksbox merge` and `luksbox sync convert` through the real binary:
//! a merge never brings back a revoked keyslot or an older master key
//! (whichever way round the copies are given), never accepts copies
//! older than this device's rollback anchor, and never writes an anchor;
//! `sync convert` refuses a rolled-back vault; `sync gc --grace-days 0`
//! needs `--yes`.

use std::path::Path;
use std::process::{Command, Output};

use tempfile::tempdir;

fn bin() -> &'static str {
    env!("CARGO_BIN_EXE_luksbox")
}

/// Run with the default passphrase `pw`, overridden by `env`.
fn run_env(dir: &Path, env: &[(&str, &str)], args: &[&str]) -> Output {
    let mut c = Command::new(bin());
    c.args(args)
        .current_dir(dir)
        .env("LUKSBOX_TEST_FAST_KDF", "1")
        .env("LUKSBOX_PASSPHRASE", "pw")
        .env("LUKSBOX_NEW_PASSPHRASE", "pw")
        .env("LUKSBOX_SYNC_STATE_DIR", dir.join("state"))
        .env("LUKSBOX_DEVICE_LABEL", "Laptop")
        .env_remove("LUKSBOX_NO_AUTO_ANCHOR");
    for (k, v) in env {
        c.env(k, v);
    }
    c.output().expect("spawn binary")
}

fn run(dir: &Path, args: &[&str]) -> Output {
    run_env(dir, &[], args)
}

fn as_bob(dir: &Path, args: &[&str]) -> Output {
    run_env(dir, &[("LUKSBOX_PASSPHRASE", "bob-pw")], args)
}

fn out(o: &Output) -> String {
    String::from_utf8_lossy(&o.stdout).into_owned()
}

fn err(o: &Output) -> String {
    String::from_utf8_lossy(&o.stderr).into_owned()
}

fn ok(o: Output, ctx: &str) -> Output {
    assert!(
        o.status.success(),
        "{ctx} failed:\nstdout: {}\nstderr: {}",
        out(&o),
        err(&o)
    );
    o
}

fn fails_with(o: Output, needle: &str, ctx: &str) {
    assert!(
        !o.status.success(),
        "{ctx} should have failed:\nstdout: {}\nstderr: {}",
        out(&o),
        err(&o)
    );
    assert!(
        err(&o).contains(needle),
        "{ctx}: expected {needle:?} in:\n{}",
        err(&o)
    );
}

fn file(dir: &Path, name: &str, body: &str) -> String {
    std::fs::write(dir.join(name), body).unwrap();
    name.to_string()
}

/// Nothing of a refused merge's output is left behind.
fn no_output(dir: &Path, name: &str) {
    for f in [
        name.to_string(),
        format!("{name}.meta-bak"),
        format!("{name}.header-bak"),
        format!("{name}.hybrid"),
    ] {
        assert!(!dir.join(&f).exists(), "{f} was left behind");
    }
}

/// A vault with Bob enrolled, an old copy of it taken then, and Bob
/// revoked from the vault afterwards, with a secret added.
fn vault_with_bob_revoked(d: &Path) {
    ok(
        run(d, &["create", "v.lbx", "--metadata-size", "2M"]),
        "create",
    );
    ok(
        run_env(
            d,
            &[("LUKSBOX_NEW_PASSPHRASE", "bob-pw")],
            &["enroll", "v.lbx"],
        ),
        "enroll Bob",
    );
    ok(as_bob(d, &["ls", "v.lbx", "/"]), "Bob opens the vault");
    std::fs::copy(d.join("v.lbx"), d.join("old.lbx")).unwrap();
    ok(run(d, &["revoke", "v.lbx", "--slot", "1"]), "revoke Bob");
    let s = file(d, "s.txt", "after the revoke");
    ok(run(d, &["put", "v.lbx", &s, "/secret.txt"]), "put secret");
    assert!(!as_bob(d, &["ls", "v.lbx", "/"]).status.success());
}

/// F1: the old copy (Bob still enrolled) must never give the merge
/// result its keyslots, whichever way round the files are given.
#[test]
fn merge_never_brings_back_a_revoked_keyslot() {
    let tmp = tempdir().unwrap();
    let d = tmp.path();
    vault_with_bob_revoked(d);
    let o = file(d, "o.txt", "made in the old copy");
    ok(
        run(d, &["put", "old.lbx", &o, "/from-copy.txt"]),
        "edit copy",
    );

    // The vault first, the old copy second (what the CLI hint used to
    // say): the result would keep the copy's keyslots. Refused, with
    // the order to use.
    fails_with(
        run(d, &["merge", "v.lbx", "old.lbx", "-o", "m1.lbx"]),
        "older keyslot table",
        "merge with the old copy second",
    );
    no_output(d, "m1.lbx");

    // The copy first, the vault second (the documented order).
    ok(
        run(d, &["merge", "old.lbx", "v.lbx", "-o", "m2.lbx"]),
        "merge with the vault second",
    );
    let listing = out(&ok(run(d, &["ls", "m2.lbx", "/"]), "ls merged"));
    assert!(
        listing.contains("secret.txt") && listing.contains("from-copy.txt"),
        "{listing}"
    );
    assert!(
        !as_bob(d, &["cat", "m2.lbx", "/secret.txt"])
            .status
            .success(),
        "Bob opens the merge result"
    );
}

/// `luksbox rotate-mvk` only runs on a terminal: rotate the master key
/// of the vault at `path` (one passphrase slot, `pw`) through the
/// library, as it does.
fn rotate_mvk(path: &Path) {
    let c = luksbox_format::Container::open(
        path,
        None,
        luksbox_format::UnlockMaterial::Passphrase(b"pw"),
    )
    .expect("unlock for the rotation");
    let mut vfs = luksbox_vfs::Vfs::open(c).expect("open for the rotation");
    vfs.rotate_mvk(
        vec![luksbox_vfs::SlotCredential::Passphrase {
            slot_idx: 0,
            passphrase: zeroize::Zeroizing::new("pw".to_string()),
        }],
        luksbox_core::Argon2idParams {
            m_cost_kib: 64,
            t_cost: 1,
            p_cost: 1,
        },
    )
    .expect("rotate");
    vfs.flush().expect("flush");
}

/// F1: a copy from before a master-key rotation is never merged, in
/// either order (the result would be under the key Bob can derive).
#[test]
fn merge_refuses_copies_under_different_master_keys() {
    let tmp = tempdir().unwrap();
    let d = tmp.path();
    vault_with_bob_revoked(d);
    rotate_mvk(&d.join("v.lbx"));
    ok(run(d, &["ls", "v.lbx", "/"]), "the rotated vault opens");
    fails_with(
        run(d, &["merge", "v.lbx", "old.lbx", "-o", "m1.lbx"]),
        "different master keys",
        "merge, rotated vault first",
    );
    no_output(d, "m1.lbx");
    fails_with(
        run(d, &["merge", "old.lbx", "v.lbx", "-o", "m2.lbx"]),
        "different master keys",
        "merge, rotated vault second",
    );
    no_output(d, "m2.lbx");
    // Not the same vault at all.
    ok(
        run(d, &["create", "other.lbx", "--metadata-size", "2M"]),
        "create another",
    );
    fails_with(
        run(d, &["merge", "other.lbx", "v.lbx", "-o", "m3.lbx"]),
        "not copies of the same vault",
        "merge of two vaults",
    );
    no_output(d, "m3.lbx");
}

/// F1: both copies changed their keyslots since they split (same
/// generation): refused, unless the user says to keep THEIRS'.
#[test]
fn merge_of_concurrent_keyslot_changes_needs_an_explicit_choice() {
    let tmp = tempdir().unwrap();
    let d = tmp.path();
    ok(
        run(d, &["create", "v.lbx", "--metadata-size", "2M"]),
        "create",
    );
    std::fs::copy(d.join("v.lbx"), d.join("a.lbx")).unwrap();
    std::fs::copy(d.join("v.lbx"), d.join("b.lbx")).unwrap();
    ok(
        run_env(
            d,
            &[("LUKSBOX_NEW_PASSPHRASE", "alice-pw")],
            &["enroll", "a.lbx"],
        ),
        "enroll in a",
    );
    ok(
        run_env(
            d,
            &[("LUKSBOX_NEW_PASSPHRASE", "bob-pw")],
            &["enroll", "b.lbx"],
        ),
        "enroll in b",
    );
    fails_with(
        run(d, &["merge", "a.lbx", "b.lbx", "-o", "m.lbx"]),
        "--keep-theirs-keyslots",
        "merge of concurrent keyslot changes",
    );
    no_output(d, "m.lbx");
    let o = ok(
        run(
            d,
            &[
                "merge",
                "a.lbx",
                "b.lbx",
                "-o",
                "m.lbx",
                "--keep-theirs-keyslots",
            ],
        ),
        "merge with --keep-theirs-keyslots",
    );
    assert!(err(&o).contains("keeps the keyslots of"), "{}", err(&o));
    ok(as_bob(d, &["ls", "m.lbx", "/"]), "THEIRS' keyslot opens it");
}

fn anchors(d: &Path) -> Vec<(String, Vec<u8>)> {
    let mut v: Vec<_> = std::fs::read_dir(d.join("state/anchors"))
        .map(|rd| {
            rd.flatten()
                .map(|e| {
                    (
                        e.file_name().to_string_lossy().into_owned(),
                        std::fs::read(e.path()).unwrap(),
                    )
                })
                .collect()
        })
        .unwrap_or_default();
    v.sort();
    v
}

/// F2: in a cloud folder, a merge of copies that are both older than
/// what this device saw is a rollback put back for good: refused, and
/// so is converting the rolled-back vault. Neither writes an anchor.
#[test]
fn merge_and_convert_refuse_a_rolled_back_vault() {
    let tmp = tempdir().unwrap();
    let d = tmp.path();
    std::fs::create_dir(d.join("Dropbox")).unwrap();
    ok(
        run(d, &["create", "Dropbox/v.lbx", "--metadata-size", "2M"]),
        "create",
    );
    let a = file(d, "a.txt", "first");
    ok(run(d, &["put", "Dropbox/v.lbx", &a, "/a.txt"]), "put a");
    std::fs::copy(d.join("Dropbox/v.lbx"), d.join("old.lbx")).unwrap();
    let b = file(d, "b.txt", "second");
    ok(run(d, &["put", "Dropbox/v.lbx", &b, "/b.txt"]), "put b");
    // The provider puts the old version back, and an old "conflict copy"
    // next to it.
    let copy = "Dropbox/v (Desktop's conflicted copy 2026-10-13).lbx";
    std::fs::copy(d.join("old.lbx"), d.join("Dropbox/v.lbx")).unwrap();
    std::fs::copy(d.join("old.lbx"), d.join(copy)).unwrap();
    let before = anchors(d);
    assert_eq!(before.len(), 1);

    fails_with(
        run(d, &["merge", copy, "Dropbox/v.lbx", "-o", "merged.lbx"]),
        "ROLLBACK DETECTED",
        "merge of two rolled-back copies",
    );
    no_output(d, "merged.lbx");
    fails_with(
        run(d, &["sync", "convert", "Dropbox/v.lbx", "v.lbxs"]),
        "ROLLBACK DETECTED",
        "convert of a rolled-back vault",
    );
    assert!(!d.join("v.lbxs").exists());
    assert_eq!(anchors(d), before, "an anchor was written");

    // With the newer version as one of the copies the merge goes
    // through (the documented recovery), still without writing anchors.
    std::fs::remove_file(d.join(copy)).unwrap();
    ok(
        run(d, &["put", "old.lbx", &b, "/b.txt"]),
        "a copy that is newer again",
    );
    std::fs::copy(d.join("old.lbx"), d.join(copy)).unwrap();
    ok(
        run(d, &["merge", copy, "Dropbox/v.lbx", "-o", "merged.lbx"]),
        "merge with a newer copy",
    );
    assert_eq!(anchors(d), before, "an anchor was written by the merge");
}

/// F2 with an explicit `--anchor`: compared for every copy, never
/// written.
#[test]
fn merge_and_convert_check_an_explicit_anchor_without_writing_it() {
    let tmp = tempdir().unwrap();
    let d = tmp.path();
    ok(
        run(
            d,
            &[
                "create",
                "x.lbx",
                "--metadata-size",
                "2M",
                "--anchor",
                "x.anchor",
            ],
        ),
        "create with an anchor",
    );
    let a = file(d, "a.txt", "first");
    ok(
        run(d, &["put", "x.lbx", &a, "/a.txt", "--anchor", "x.anchor"]),
        "put a",
    );
    std::fs::copy(d.join("x.lbx"), d.join("x-old.lbx")).unwrap();
    let b = file(d, "b.txt", "second");
    ok(
        run(d, &["put", "x.lbx", &b, "/b.txt", "--anchor", "x.anchor"]),
        "put b",
    );
    let anchor = std::fs::read(d.join("x.anchor")).unwrap();
    fails_with(
        run(
            d,
            &[
                "merge",
                "x-old.lbx",
                "x-old.lbx",
                "-o",
                "m.lbx",
                "--anchor",
                "x.anchor",
            ],
        ),
        "ROLLBACK DETECTED",
        "merge of old copies against the anchor",
    );
    no_output(d, "m.lbx");
    fails_with(
        run(
            d,
            &[
                "sync",
                "convert",
                "x-old.lbx",
                "x.lbxs",
                "--anchor",
                "x.anchor",
            ],
        ),
        "ROLLBACK DETECTED",
        "convert of an old copy against the anchor",
    );
    assert!(!d.join("x.lbxs").exists());
    ok(
        run(
            d,
            &[
                "merge",
                "x-old.lbx",
                "x.lbx",
                "-o",
                "m.lbx",
                "--anchor",
                "x.anchor",
            ],
        ),
        "merge with the current vault",
    );
    assert_eq!(
        std::fs::read(d.join("x.anchor")).unwrap(),
        anchor,
        "the anchor was written"
    );
    ok(
        run(
            d,
            &["sync", "convert", "x.lbx", "x.lbxs", "--anchor", "x.anchor"],
        ),
        "convert of the current vault",
    );
}

/// F9: `--grace-days 0` drops the two-run protection: only with --yes.
#[test]
fn gc_without_a_grace_period_needs_yes() {
    let tmp = tempdir().unwrap();
    let d = tmp.path();
    ok(
        run(d, &["create", "v.lbx", "--metadata-size", "2M"]),
        "create",
    );
    ok(
        run(
            d,
            &["sync", "convert", "v.lbx", "v.lbxs", "--page-size", "1M"],
        ),
        "convert",
    );
    fails_with(
        run(d, &["sync", "gc", "v.lbxs", "--grace-days", "0"]),
        "--yes",
        "gc --grace-days 0",
    );
    ok(
        run(
            d,
            &["sync", "gc", "v.lbxs", "--grace-days", "0", "--dry-run"],
        ),
        "gc --grace-days 0 --dry-run",
    );
    let o = ok(
        run(d, &["sync", "gc", "v.lbxs", "--grace-days", "0", "--yes"]),
        "gc --grace-days 0 --yes",
    );
    assert!(err(&o).contains("warning: --grace-days 0"), "{}", err(&o));
    ok(run(d, &["sync", "gc", "v.lbxs"]), "gc with the defaults");
}

/// F6: the conflict-copy hint names the copy first and the vault
/// second, without the control characters a copy's name may carry.
#[cfg(unix)]
#[test]
fn conflict_copy_hint_is_in_merge_order_and_sanitized() {
    let tmp = tempdir().unwrap();
    let d = tmp.path();
    std::fs::create_dir(d.join("Dropbox")).unwrap();
    ok(
        run(d, &["create", "Dropbox/v.lbx", "--metadata-size", "2M"]),
        "create",
    );
    std::fs::copy(
        d.join("Dropbox/v.lbx"),
        d.join("Dropbox/v (conflicted copy\x1b[2J).lbx"),
    )
    .unwrap();
    let o = ok(run(d, &["ls", "Dropbox/v.lbx", "/"]), "ls");
    let e = err(&o);
    assert!(!e.contains('\x1b'), "{e:?}");
    assert!(
        e.contains(
            "luksbox merge \"Dropbox/v (conflicted copy\u{FFFD}[2J).lbx\" \"Dropbox/v.lbx\""
        ),
        "{e}"
    );
}
