// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Penthertz <https://penthertz.com> (https://x.com/PentHertz)

//! Sync bundles through the real binary: convert, use every ordinary
//! command on the bundle folder, two devices, status / verify /
//! snapshots / export, `luksbox merge` of two copies of a `.lbx`, and
//! the commands that refuse a bundle.

use std::path::Path;
use std::process::{Command, Output};

use tempfile::tempdir;

fn bin() -> &'static str {
    env!("CARGO_BIN_EXE_luksbox")
}

/// Run as `device` (its own sync state folder and label).
fn run_as(dir: &Path, device: &str, args: &[&str]) -> Output {
    Command::new(bin())
        .args(args)
        .current_dir(dir)
        .env("LUKSBOX_TEST_FAST_KDF", "1")
        .env("LUKSBOX_PASSPHRASE", "pw")
        .env("LUKSBOX_NEW_PASSPHRASE", "pw")
        .env(
            "LUKSBOX_SYNC_STATE_DIR",
            dir.join(format!("state-{device}")),
        )
        .env("LUKSBOX_DEVICE_LABEL", device)
        .output()
        .expect("spawn binary")
}

fn run(dir: &Path, args: &[&str]) -> Output {
    run_as(dir, "Laptop", args)
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
        "{ctx} should have failed:\n{}",
        out(&o)
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

#[test]
fn convert_use_and_share_a_bundle() {
    let tmp = tempdir().unwrap();
    let d = tmp.path();
    ok(
        run(d, &["create", "v.lbx", "--metadata-size", "2M"]),
        "create",
    );
    let a = file(d, "a.txt", "first file");
    ok(run(d, &["put", "v.lbx", &a, "/a.txt"]), "put");
    ok(
        run(
            d,
            &["sync", "convert", "v.lbx", "v.lbxs", "--page-size", "1M"],
        ),
        "convert",
    );
    assert!(d.join("v.lbxs/m").is_dir());

    // Ordinary commands on the bundle folder.
    let b = file(d, "b.txt", "added to the bundle");
    let o = ok(run(d, &["put", "v.lbxs", &b, "/b.txt"]), "put into bundle");
    assert!(err(&o).contains("published commit"), "{}", err(&o));
    let o = ok(run(d, &["ls", "v.lbxs", "/"]), "ls bundle");
    assert!(
        out(&o).contains("a.txt") && out(&o).contains("b.txt"),
        "{}",
        out(&o)
    );
    let o = ok(run(d, &["cat", "v.lbxs", "/b.txt"]), "cat bundle");
    assert_eq!(out(&o), "added to the bundle");

    // A second device writes; the first sees it.
    let c = file(d, "c.txt", "from the desktop");
    ok(
        run_as(d, "Desktop", &["put", "v.lbxs", &c, "/c.txt"]),
        "put as Desktop",
    );
    let o = ok(run(d, &["cat", "v.lbxs", "/c.txt"]), "cat from Laptop");
    assert_eq!(out(&o), "from the desktop");

    // Status, verify, snapshots.
    let o = ok(run(d, &["sync", "status", "v.lbxs"]), "status");
    assert!(
        out(&o).contains("newest") && out(&o).contains("snapshots"),
        "{}",
        out(&o)
    );
    let o = ok(run(d, &["sync", "verify", "v.lbxs"]), "verify");
    assert!(out(&o).contains("every object verified"), "{}", out(&o));
    let o = ok(run(d, &["sync", "snapshots", "v.lbxs"]), "snapshots");
    assert!(out(&o).lines().count() >= 3, "{}", out(&o));

    // Restore the first version of b.txt from the oldest snapshot that has it.
    let id = out(&o)
        .lines()
        .last()
        .unwrap()
        .split_whitespace()
        .next()
        .unwrap()
        .to_string();
    let _ = run(
        d,
        &[
            "sync",
            "snapshots",
            "v.lbxs",
            "--restore",
            &id,
            "--path",
            "/a.txt",
        ],
    );
    let o = ok(run(d, &["ls", "v.lbxs", "/"]), "ls after restore");
    assert!(out(&o).contains("a (restored "), "{}", out(&o));

    // Export to a single file and read it back as an ordinary vault.
    ok(run(d, &["sync", "export", "v.lbxs", "out.lbx"]), "export");
    let o = ok(run(d, &["cat", "out.lbx", "/c.txt"]), "cat exported");
    assert_eq!(out(&o), "from the desktop");

    // Commands with no bundle equivalent refuse clearly.
    fails_with(
        run(d, &["header-backup", "v.lbxs", "h.bak"]),
        "not available for a sync bundle",
        "header-backup",
    );
    fails_with(
        run(d, &["rotate-mvk", "v.lbxs"]),
        "not available for a sync bundle",
        "rotate-mvk",
    );
    fails_with(
        run(d, &["ls", "v.lbxs", "--anchor", "x.anchor"]),
        "--anchor is for .lbx files",
        "anchor",
    );
}

/// Nothing is left in this device's staging folder (`creating/`) once a
/// `create <folder>.lbxs` ended, however it ended.
fn no_staging_left(d: &Path, device: &str) {
    let creating = d.join(format!("state-{device}")).join("creating");
    let left: Vec<_> = std::fs::read_dir(&creating)
        .map(|r| r.flatten().map(|e| e.path()).collect())
        .unwrap_or_default();
    assert!(left.is_empty(), "staging folders left behind: {left:?}");
}

/// `luksbox create <folder>.lbxs` makes a sync bundle in one step, with
/// each cipher and the size-hiding flags: built in a private staging
/// folder (removed afterwards) and converted, it opens on this device
/// and on another one with the same passphrase, and works like any
/// bundle (every command takes the folder).
#[test]
fn create_makes_a_bundle() {
    let tmp = tempdir().unwrap();
    let d = tmp.path();
    let a = file(d, "a.txt", "hello bundle");
    for (name, extra) in [
        ("siv.lbxs", &[][..]),
        ("gcm.lbxs", &["--cipher", "aes-gcm"][..]),
        ("chacha.lbxs", &["--cipher", "chacha", "--pad-files"][..]),
        ("hidden.lbxs", &["--hide-sizes"][..]),
    ] {
        let mut args = vec!["create", name, "--metadata-size", "2M"];
        args.extend_from_slice(extra);
        let o = ok(run(d, &args), name);
        assert!(
            out(&o).contains(&format!("created the sync bundle {name}")),
            "{name}: {}",
            out(&o)
        );
        assert!(d.join(name).join("h").is_dir(), "{name} is a bundle folder");
        // Header and keyslots without unlocking.
        let o = ok(run(d, &["info", name]), "info");
        assert!(out(&o).contains("sync bundle"), "{}", out(&o));
        // This device writes, another one reads and writes, this one
        // sees it.
        ok(run(d, &["put", name, &a, "/a.txt"]), "put");
        let o = ok(
            run_as(d, "Desktop", &["cat", name, "/a.txt"]),
            "cat on a second device",
        );
        assert_eq!(out(&o), "hello bundle", "{name}");
        ok(
            run_as(d, "Desktop", &["mkdir", name, "/from-desktop"]),
            "mkdir",
        );
        let o = ok(run(d, &["ls", name, "/"]), "ls");
        assert!(out(&o).contains("from-desktop"), "{name}: {}", out(&o));
        ok(
            run(d, &["get", name, "/a.txt", &format!("{name}.out")]),
            "get",
        );
        assert_eq!(
            std::fs::read_to_string(d.join(format!("{name}.out"))).unwrap(),
            "hello bundle"
        );
        let o = ok(run(d, &["sync", "verify", name]), "verify");
        assert!(
            err(&o).contains("every object verified") || out(&o).contains("every object verified")
        );
    }
    no_staging_left(d, "Laptop");
    // Nothing but the bundle folders: no vault file, mirror or sidecar.
    let mut names: Vec<String> = std::fs::read_dir(d)
        .unwrap()
        .flatten()
        .map(|e| e.file_name().to_string_lossy().into_owned())
        .filter(|n| n.contains(".lbx"))
        .collect();
    names.sort();
    assert_eq!(
        names,
        [
            "chacha.lbxs",
            "chacha.lbxs.out",
            "gcm.lbxs",
            "gcm.lbxs.out",
            "hidden.lbxs",
            "hidden.lbxs.out",
            "siv.lbxs",
            "siv.lbxs.out"
        ]
    );
}

/// A post-quantum bundle (`--kind hybrid-pq` / `hybrid-pq1024`): the
/// public Kyber sidecar goes inside the bundle, not next to it, and the
/// bundle opens on both devices with the seed file, never without it.
#[test]
fn create_a_post_quantum_bundle() {
    let tmp = tempdir().unwrap();
    let d = tmp.path();
    let a = file(d, "a.txt", "post-quantum");
    for (kind, name) in [("hybrid-pq", "pq.lbxs"), ("hybrid-pq1024", "pq1024.lbxs")] {
        let seed = format!("{name}.kyber");
        let o = ok(
            run(
                d,
                &[
                    "create",
                    name,
                    "--kind",
                    kind,
                    "--pq-hybrid",
                    &seed,
                    "--metadata-size",
                    "2M",
                ],
            ),
            kind,
        );
        assert!(err(&o).contains("kept inside the bundle"), "{}", err(&o));
        assert!(
            d.join(&seed).is_file(),
            "the seed file is where it was asked"
        );
        assert!(!d.join(format!("{name}.hybrid")).exists());
        ok(
            run(d, &["put", name, "--pq-hybrid", &seed, &a, "/a.txt"]),
            "put with the seed",
        );
        let o = ok(
            run_as(d, "Desktop", &["cat", name, "--pq-hybrid", &seed, "/a.txt"]),
            "cat on a second device",
        );
        assert_eq!(out(&o), "post-quantum");
        let o = run(d, &["cat", name, "/a.txt"]);
        assert!(!o.status.success(), "{kind}: opened without the seed file");
    }
    no_staging_left(d, "Laptop");
}

/// The seeded software authenticator of debug builds
/// (`LUKSBOX_TEST_FIDO2_MOCK`): the same seed is the same security key,
/// in every process. Release builds compile it out, so the FIDO2 test
/// below is for debug builds only (a release test run would wait on the
/// real FIDO2 prompt, Windows' security key dialog included).
#[cfg(all(feature = "fido2-hardware", debug_assertions))]
const KEY: &str = "1111111111111111111111111111111111111111111111111111111111111111";
#[cfg(all(feature = "fido2-hardware", debug_assertions))]
const OTHER_KEY: &str = "2222222222222222222222222222222222222222222222222222222222222222";

/// `run_as` with a FIDO2 key "plugged in" (`key`), PIN 1234.
#[cfg(all(feature = "fido2-hardware", debug_assertions))]
fn run_with_key(dir: &Path, device: &str, key: &str, args: &[&str]) -> Output {
    Command::new(bin())
        .args(args)
        .current_dir(dir)
        .env("LUKSBOX_TEST_FAST_KDF", "1")
        .env("LUKSBOX_PASSPHRASE", "pw")
        .env("LUKSBOX_NEW_PASSPHRASE", "pw")
        .env("LUKSBOX_FIDO2_PIN", "1234")
        .env("LUKSBOX_TEST_FIDO2_MOCK", key)
        .env(
            "LUKSBOX_SYNC_STATE_DIR",
            dir.join(format!("state-{device}")),
        )
        .env("LUKSBOX_DEVICE_LABEL", device)
        .output()
        .expect("spawn binary")
}

/// FIDO2 sync bundles through the real commands, with the debug build's
/// software authenticator standing in for the security key: a FIDO2
/// (wrap), FIDO2-direct and FIDO2 + ML-KEM-768 bundle made with `create
/// <folder>.lbxs`, and a FIDO2 vault converted with `sync convert`. Each
/// opens on a second device with the same key, and not with another key
/// or without one.
#[cfg(all(feature = "fido2-hardware", debug_assertions))]
#[test]
fn fido2_bundles_with_a_software_key() {
    let tmp = tempdir().unwrap();
    let d = tmp.path();
    let a = file(d, "a.txt", "fido2 bundle");
    ok(
        run_with_key(
            d,
            "Laptop",
            KEY,
            &[
                "create",
                "f.lbx",
                "--kind",
                "fido2",
                "--metadata-size",
                "2M",
            ],
        ),
        "create a FIDO2 vault",
    );
    ok(
        run_with_key(
            d,
            "Laptop",
            KEY,
            &["sync", "convert", "f.lbx", "conv.lbxs", "--fido2"],
        ),
        "convert the FIDO2 vault",
    );
    for (kind, name, extra) in [
        ("fido2", "f.lbxs", &[][..]),
        ("fido2-direct", "fd.lbxs", &[][..]),
        (
            "hybrid-pq-fido2",
            "fpq.lbxs",
            &["--pq-hybrid", "fpq.kyber"][..],
        ),
        ("converted", "conv.lbxs", &[][..]),
    ] {
        if kind != "converted" {
            let mut args = vec!["create", name, "--kind", kind, "--metadata-size", "2M"];
            args.extend_from_slice(extra);
            let o = ok(run_with_key(d, "Laptop", KEY, &args), kind);
            assert!(
                out(&o).contains(&format!("created the sync bundle {name}")),
                "{}",
                out(&o)
            );
        }
        let o = ok(run(d, &["info", name]), "info");
        assert!(out(&o).contains("fido2"), "{kind}: {}", out(&o));
        // `--pq-hybrid` names the seed file for the post-quantum kind.
        let unlock: Vec<&str> = std::iter::once("--fido2")
            .chain(extra.iter().copied())
            .collect();
        let mut put = vec!["put", name];
        put.extend_from_slice(&unlock);
        put.extend_from_slice(&[a.as_str(), "/a.txt"]);
        ok(run_with_key(d, "Laptop", KEY, &put), "put");
        let mut cat = vec!["cat", name];
        cat.extend_from_slice(&unlock);
        cat.push("/a.txt");
        let o = ok(
            run_with_key(d, "Desktop", KEY, &cat),
            "cat on a second device",
        );
        assert_eq!(out(&o), "fido2 bundle", "{kind}");
        let o = run_with_key(d, "Desktop", OTHER_KEY, &cat);
        assert!(!o.status.success(), "{kind}: opened with another key");
        let mut no_key = vec!["cat", name];
        no_key.extend_from_slice(extra);
        no_key.push("/a.txt");
        assert!(
            !run(d, &no_key).status.success(),
            "{kind}: opened without the key"
        );
    }
    no_staging_left(d, "Laptop");
}

/// What `create <folder>.lbxs` refuses, before anything is made or once
/// the staging folder exists (a kind that cannot be the first slot):
/// either way no bundle, file or staging folder is left behind.
#[test]
fn create_bundle_refusals_leave_nothing() {
    let tmp = tempdir().unwrap();
    let d = tmp.path();
    ok(
        run(d, &["create", "b.lbxs", "--metadata-size", "2M"]),
        "create",
    );
    fails_with(
        run(d, &["create", "b.lbxs"]),
        "already exists",
        "existing bundle",
    );
    std::fs::create_dir(d.join("plain.lbxs")).unwrap();
    fails_with(
        run(d, &["create", "plain.lbxs"]),
        "already exists",
        "existing folder",
    );
    for (args, needle) in [
        (&["--anchor", "n.anchor"][..], "--anchor"),
        (&["--header", "n.hdr"][..], "--header"),
        (&["--max-size", "1G"][..], "--max-size"),
        (&["--format", "v2"][..], "v2 formats"),
        (&["--header-v2"][..], "v2 formats"),
        (&["--kind", "tpm2"][..], "cannot be the first slot"),
        (&["--kind", "hybrid-pq"][..], "requires --pq-hybrid"),
    ] {
        let mut all = vec!["create", "n.lbxs"];
        all.extend_from_slice(args);
        fails_with(run(d, &all), needle, needle);
    }
    fails_with(
        run(d, &["create", "missing/n.lbxs"]),
        "is not a folder",
        "missing parent folder",
    );
    for left in ["n.lbxs", "n.lbx", "n.anchor", "n.hdr", "missing"] {
        assert!(!d.join(left).exists(), "{left} was left behind");
    }
    no_staging_left(d, "Laptop");
    // The bundle made first still opens.
    ok(run(d, &["ls", "b.lbxs", "/"]), "ls");
}

#[test]
fn merge_two_copies_of_a_vault() {
    let tmp = tempdir().unwrap();
    let d = tmp.path();
    ok(
        run(d, &["create", "base.lbx", "--metadata-size", "2M"]),
        "create",
    );
    let s = file(d, "s.txt", "shared");
    ok(run(d, &["put", "base.lbx", &s, "/shared.txt"]), "put");
    std::fs::copy(d.join("base.lbx"), d.join("ours.lbx")).unwrap();
    std::fs::copy(d.join("base.lbx"), d.join("theirs.lbx")).unwrap();
    let o1 = file(d, "o.txt", "ours version");
    let t1 = file(d, "t.txt", "theirs version");
    // `put` never overwrites: an edit is remove + put.
    ok(run(d, &["rm", "ours.lbx", "/shared.txt"]), "rm ours");
    ok(
        run(d, &["put", "ours.lbx", &o1, "/shared.txt"]),
        "edit ours",
    );
    ok(run(d, &["rm", "theirs.lbx", "/shared.txt"]), "rm theirs");
    ok(
        run(d, &["put", "theirs.lbx", &t1, "/shared.txt"]),
        "edit theirs",
    );
    let n = file(d, "n.txt", "new in ours");
    ok(run(d, &["put", "ours.lbx", &n, "/new.txt"]), "add in ours");

    let o = ok(
        run(
            d,
            &[
                "merge",
                "ours.lbx",
                "theirs.lbx",
                "--base",
                "base.lbx",
                "-o",
                "merged.lbx",
                "--label",
                "Phone",
            ],
        ),
        "merge",
    );
    assert!(out(&o).contains("1 conflict"), "{}", out(&o));
    let o = ok(run(d, &["ls", "merged.lbx", "/"]), "ls merged");
    let listing = out(&o);
    assert!(listing.contains("new.txt"), "{listing}");
    assert!(listing.contains("shared (conflict Phone "), "{listing}");
    let o = ok(run(d, &["cat", "merged.lbx", "/shared.txt"]), "cat merged");
    assert_eq!(out(&o), "theirs version");
    // The inputs are untouched.
    let o = ok(run(d, &["cat", "ours.lbx", "/shared.txt"]), "cat ours");
    assert_eq!(out(&o), "ours version");
}

/// Phase 0: a `.lbx` in a cloud folder gets this device's automatic
/// rollback anchor. Another device's newer write is accepted; the sync
/// client keeping an older copy is refused and the conflict copy named;
/// the merge result, put in place of the vault, is accepted.
#[test]
fn vault_in_a_cloud_folder_gets_an_automatic_anchor() {
    let tmp = tempdir().unwrap();
    let d = tmp.path();
    std::fs::create_dir(d.join("Dropbox")).unwrap();
    ok(
        run(d, &["create", "Dropbox/v.lbx", "--metadata-size", "2M"]),
        "create",
    );
    let a = file(d, "a.txt", "first");
    let o = ok(run(d, &["put", "Dropbox/v.lbx", &a, "/a.txt"]), "first put");
    assert!(err(&o).contains("Dropbox folder"), "{}", err(&o));
    assert!(err(&o).contains("rollback anchor"), "{}", err(&o));
    let anchors: Vec<_> = std::fs::read_dir(d.join("state-Laptop/anchors"))
        .unwrap()
        .collect();
    assert_eq!(anchors.len(), 1);

    // The note is for the first open only.
    let o = ok(run(d, &["ls", "Dropbox/v.lbx", "/"]), "ls");
    assert!(!err(&o).contains("Dropbox folder"), "{}", err(&o));

    // Another device (its own state) writes: normal.
    let b = file(d, "b.txt", "from the desktop");
    ok(
        run_as(d, "Desktop", &["put", "Dropbox/v.lbx", &b, "/b.txt"]),
        "put as Desktop",
    );
    ok(
        run(d, &["ls", "Dropbox/v.lbx", "/"]),
        "ls after the other device wrote",
    );
    std::fs::copy(d.join("Dropbox/v.lbx"), d.join("old.lbx")).unwrap();

    // This device writes again, then the sync client keeps the older
    // copy under the vault's name and ours as a conflict copy.
    let c = file(d, "c.txt", "mine");
    ok(run(d, &["put", "Dropbox/v.lbx", &c, "/c.txt"]), "put");
    let copy = "Dropbox/v (Laptop's conflicted copy 2026-10-13).lbx";
    std::fs::rename(d.join("Dropbox/v.lbx"), d.join(copy)).unwrap();
    std::fs::copy(d.join("old.lbx"), d.join("Dropbox/v.lbx")).unwrap();
    let o = run(d, &["ls", "Dropbox/v.lbx", "/"]);
    assert!(err(&o).contains("conflicted copy"), "{}", err(&o));
    fails_with(o, "ROLLBACK DETECTED", "ls of the older copy");

    // Merge, put the result in place: accepted, nothing lost.
    ok(
        run(d, &["merge", copy, "Dropbox/v.lbx", "-o", "merged.lbx"]),
        "merge",
    );
    std::fs::rename(d.join("merged.lbx"), d.join("Dropbox/v.lbx")).unwrap();
    std::fs::remove_file(d.join(copy)).unwrap();
    let o = ok(
        run(d, &["ls", "Dropbox/v.lbx", "/"]),
        "ls of the merge result",
    );
    for f in ["a.txt", "b.txt", "c.txt"] {
        assert!(out(&o).contains(f), "{f} missing:\n{}", out(&o));
    }

    // The opt-out.
    std::fs::copy(d.join("old.lbx"), d.join("Dropbox/v.lbx")).unwrap();
    let o = Command::new(bin())
        .args(["ls", "Dropbox/v.lbx", "/"])
        .current_dir(d)
        .env("LUKSBOX_TEST_FAST_KDF", "1")
        .env("LUKSBOX_PASSPHRASE", "pw")
        .env("LUKSBOX_SYNC_STATE_DIR", d.join("state-Laptop"))
        .env("LUKSBOX_NO_AUTO_ANCHOR", "1")
        .output()
        .unwrap();
    ok(o, "ls with the automatic anchor turned off");
}

/// `sync convert` copies the vault's post-quantum sidecar into the
/// bundle: a link planted at the sidecar path must not smuggle another
/// file into the (synced) bundle folder.
#[cfg(unix)]
#[test]
fn convert_refuses_a_planted_sidecar_link() {
    let tmp = tempdir().unwrap();
    let d = tmp.path();
    ok(
        run(d, &["create", "v.lbx", "--metadata-size", "2M"]),
        "create",
    );
    std::fs::write(d.join("private.txt"), "not for the cloud").unwrap();
    std::os::unix::fs::symlink(d.join("private.txt"), d.join("v.lbx.hybrid")).unwrap();
    let o = run(
        d,
        &["sync", "convert", "v.lbx", "v.lbxs", "--page-size", "1M"],
    );
    assert!(
        !o.status.success(),
        "convert followed the link:\n{}",
        err(&o)
    );
    // Nothing of the private file reached a bundle.
    if d.join("v.lbxs/x").exists() {
        assert_eq!(std::fs::read_dir(d.join("v.lbxs/x")).unwrap().count(), 0);
    }
}

/// Copy every file of `from` missing in `to` (a sync client delivering
/// another device's objects).
fn union_into(from: &Path, to: &Path) {
    for e in std::fs::read_dir(from).unwrap().flatten() {
        let dst = to.join(e.file_name());
        if e.file_type().unwrap().is_dir() {
            std::fs::create_dir_all(&dst).unwrap();
            union_into(&e.path(), &dst);
        } else if !dst.exists() {
            std::fs::copy(e.path(), &dst).unwrap();
        }
    }
}

/// `sync verify` only inspects: it neither publishes nor merges, while
/// a writable command merges concurrent commits.
#[test]
fn verify_is_read_only() {
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
    // Two devices commit on the same base without seeing each other.
    union_into(&d.join("v.lbxs"), &d.join("other.lbxs"));
    let a = file(d, "a.txt", "from the laptop");
    ok(run(d, &["put", "v.lbxs", &a, "/a.txt"]), "put as Laptop");
    let b = file(d, "b.txt", "from the desktop");
    ok(
        run_as(d, "Desktop", &["put", "other.lbxs", &b, "/b.txt"]),
        "put as Desktop",
    );
    union_into(&d.join("other.lbxs"), &d.join("v.lbxs"));
    let manifests = |d: &Path| -> usize {
        std::fs::read_dir(d.join("v.lbxs/m"))
            .unwrap()
            .flatten()
            .map(|s| std::fs::read_dir(s.path()).unwrap().count())
            .sum()
    };
    let before = manifests(d);
    let o = ok(run(d, &["sync", "verify", "v.lbxs"]), "verify");
    assert!(out(&o).contains("every object verified"), "{}", out(&o));
    assert_eq!(manifests(d), before, "verify wrote a commit");
    // A writable command merges the two branches.
    let o = ok(run(d, &["ls", "v.lbxs", "/"]), "ls");
    assert!(manifests(d) > before, "ls did not merge:\n{}", err(&o));
}

/// Round 16: when the newest version arrived damaged, an earlier one can
/// still be written out (`sync export --snapshot`), and `revoke` on a
/// bundle says that the master key is unchanged.
#[test]
fn an_earlier_version_exports_and_revoke_warns_on_a_bundle() {
    let tmp = tempdir().unwrap();
    let d = tmp.path();
    ok(
        run(d, &["create", "v.lbx", "--metadata-size", "2M"]),
        "create",
    );
    let a = file(d, "a.txt", "first");
    ok(run(d, &["put", "v.lbx", &a, "/a.txt"]), "put");
    ok(
        run(
            d,
            &["sync", "convert", "v.lbx", "v.lbxs", "--page-size", "1M"],
        ),
        "convert",
    );
    let b = file(d, "b.txt", "second");
    ok(run(d, &["put", "v.lbxs", &b, "/b.txt"]), "put into bundle");

    // The oldest version (listed last) has a.txt only.
    let o = ok(run(d, &["sync", "snapshots", "v.lbxs"]), "snapshots");
    let oldest = out(&o)
        .lines()
        .last()
        .unwrap()
        .split_whitespace()
        .next()
        .unwrap()
        .to_string();
    ok(
        run(
            d,
            &["sync", "export", "v.lbxs", "old.lbx", "--snapshot", &oldest],
        ),
        "export --snapshot",
    );
    let o = ok(run(d, &["ls", "old.lbx", "/"]), "ls exported snapshot");
    assert!(
        out(&o).contains("a.txt") && !out(&o).contains("b.txt"),
        "{}",
        out(&o)
    );
    // An unknown id is refused, nothing is written.
    fails_with(
        run(
            d,
            &[
                "sync",
                "export",
                "v.lbxs",
                "none.lbx",
                "--snapshot",
                "ffffffff",
            ],
        ),
        "no snapshot with that id",
        "export --snapshot (unknown)",
    );
    assert!(!d.join("none.lbx").exists());

    // Revoking on a bundle: done, with the warning.
    ok(run(d, &["enroll", "v.lbxs"]), "enroll");
    let o = ok(run(d, &["revoke", "v.lbxs", "--slot", "1"]), "revoke");
    assert!(
        err(&o).contains("does not change the master key"),
        "{}",
        err(&o)
    );
}
