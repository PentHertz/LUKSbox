// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Penthertz <https://penthertz.com> (https://x.com/PentHertz)

//! Garbage collection and snapshots: two passes free space, the grace
//! period and leases protect what another device may still need,
//! foreign files are never touched, old snapshots stay readable within
//! retention, and rollback detection survives collection.

use std::path::PathBuf;

use luksbox_core::{Argon2idParams, CipherSuite};
use luksbox_format::{Container, UnlockMaterial};
use luksbox_sync::bundle::{self, ConvertOptions, OpenOptions, OpenReport, Session};
use luksbox_sync::gc::GcOptions;
use luksbox_sync::local::{LocalStore, MemLocal};
use luksbox_sync::names::{Area, Name, ObjectId};
use luksbox_sync::store::{ObjectStore, SharedMem};
use luksbox_sync::{Result, SyncError};
use luksbox_vfs::Vfs;
use tempfile::TempDir;

const PASS: &[u8] = b"pw";
const KDF: Argon2idParams = Argon2idParams {
    m_cost_kib: 8,
    t_cost: 1,
    p_cost: 1,
};

fn aggressive() -> GcOptions {
    GcOptions {
        retention_ns: 0,
        keep_last: 1,
        grace_ns: 0,
        ..GcOptions::default()
    }
}

fn open(store: &SharedMem, local: &MemLocal, label: &str) -> Result<(Session, Vfs, OpenReport)> {
    let l = local.clone();
    let (s, c, r) = Session::open(
        Box::new(store.clone()),
        move |_| Ok(Box::new(l) as Box<dyn LocalStore>),
        PathBuf::from("v.lbxs"),
        &mut UnlockMaterial::Passphrase(PASS),
        &OpenOptions {
            device_label: label.into(),
            read_only: false,
        },
    )?;
    Ok((s, Vfs::open(c).unwrap(), r))
}

fn setup(dir: &TempDir) -> (SharedMem, MemLocal) {
    let lbx = dir.path().join("v.lbx");
    let _g = luksbox_format::metadata::set_create_metadata_region_size_override(Some(2 << 20));
    let c = Container::create_with_passphrase(&lbx, None, CipherSuite::Aes256GcmSiv, KDF, PASS)
        .unwrap();
    let mut c = Vfs::open(c).unwrap().close().unwrap();
    let store = SharedMem::new();
    let local = MemLocal::default();
    let l = local.clone();
    bundle::convert(
        &mut c,
        Box::new(store.clone()),
        move |_| Ok(Box::new(l) as Box<dyn LocalStore>),
        &ConvertOptions {
            page_size: 1 << 20,
            device_label: "Laptop".into(),
            hybrid_sidecar: None,
        },
    )
    .unwrap();
    (store, local)
}

fn put(vfs: &mut Vfs, name: &str, data: &[u8]) {
    let root = vfs.root_id();
    let id = match vfs.lookup(root, name) {
        Ok(id) => id,
        Err(_) => vfs.create(root, name).unwrap(),
    };
    vfs.truncate(id, 0).unwrap();
    vfs.write(id, 0, data).unwrap();
}

fn get(vfs: &mut Vfs, name: &str) -> Option<Vec<u8>> {
    let id = vfs.lookup_path(&format!("/{name}")).ok()?;
    let mut buf = vec![0u8; 1 << 16];
    let n = vfs.read(id, 0, &mut buf).unwrap();
    buf.truncate(n);
    Some(buf)
}

/// Rewrite one file many times: every commit replaces data pages.
fn churn(store: &SharedMem, local: &MemLocal, n: usize) {
    let (mut s, mut v, _) = open(store, local, "Laptop").unwrap();
    for i in 0..n {
        put(
            &mut v,
            "churn.txt",
            format!("version {i} {}", "x".repeat(20_000)).as_bytes(),
        );
        v.flush().unwrap();
        s.publish().unwrap().unwrap();
    }
}

fn count(store: &SharedMem, area: Area) -> usize {
    store.with(|m| m.list(area).unwrap().names.len())
}

#[test]
fn two_passes_free_space_and_keep_the_vault_intact() {
    let dir = TempDir::new().unwrap();
    let (store, local) = setup(&dir);
    churn(&store, &local, 6);
    let pages_before = count(&store, Area::Page);
    let manifests_before = count(&store, Area::Manifest);

    let (mut s, v, _) = open(&store, &local, "Laptop").unwrap();
    drop(v);
    let first = s.gc(&aggressive()).unwrap();
    assert!(first.planned > 0);
    assert_eq!(first.deleted, 0, "the first pass only plans");
    let second = s.gc(&aggressive()).unwrap();
    assert!(second.deleted > 0, "the second pass deletes");
    drop(s);

    assert!(count(&store, Area::Page) < pages_before);
    assert!(count(&store, Area::Manifest) < manifests_before);
    let (_s, mut v, r) = open(&store, &local, "Laptop").unwrap();
    assert!(r.writable);
    assert!(get(&mut v, "churn.txt").unwrap().starts_with(b"version 5 "));
}

#[test]
fn grace_period_is_respected() {
    let dir = TempDir::new().unwrap();
    let (store, local) = setup(&dir);
    churn(&store, &local, 3);
    let (mut s, _v, _) = open(&store, &local, "Laptop").unwrap();
    let opts = GcOptions {
        grace_ns: u64::MAX / 2,
        ..aggressive()
    };
    s.gc(&opts).unwrap();
    let again = s.gc(&opts).unwrap();
    assert_eq!(again.deleted, 0);
}

#[test]
fn a_lease_pins_what_an_open_session_works_on() {
    let dir = TempDir::new().unwrap();
    let (store, a_local) = setup(&dir);
    let b_local = MemLocal::default();
    // B opens and keeps its session (and lease) on the current head.
    let (mut sb, mut vb, _) = open(&store, &b_local, "Desktop").unwrap();
    churn(&store, &a_local, 4);
    {
        let (mut sa, _va, _) = open(&store, &a_local, "Laptop").unwrap();
        sa.gc(&aggressive()).unwrap();
        sa.gc(&aggressive()).unwrap();
    }
    // B still reads its whole state and can publish on top of it.
    put(&mut vb, "from-b.txt", b"still works");
    let fin = sb.finish(&mut vb).unwrap();
    assert!(fin.published.is_some());
    assert_eq!(fin.merged, 1);
    drop((vb, sb));
    let (_s, mut v, _) = open(&store, &a_local, "Laptop").unwrap();
    assert_eq!(get(&mut v, "from-b.txt").unwrap(), b"still works");
    assert!(get(&mut v, "churn.txt").unwrap().starts_with(b"version 3 "));
}

#[test]
fn foreign_files_are_never_deleted() {
    let dir = TempDir::new().unwrap();
    let (store, local) = setup(&dir);
    store.with(|m| {
        m.plant(Area::Page, "ab", "holiday.jpg", b"x".to_vec());
        m.plant(
            Area::Manifest,
            "cd",
            "notes (conflicted copy).txt",
            b"y".to_vec(),
        );
    });
    churn(&store, &local, 2);
    let (mut s, _v, _) = open(&store, &local, "Laptop").unwrap();
    s.gc(&aggressive()).unwrap();
    s.gc(&aggressive()).unwrap();
    let left = store.with(|m| {
        m.raw_mut()
            .keys()
            .filter(|k| k.2 == "holiday.jpg" || k.2.contains("conflicted copy"))
            .count()
    });
    assert_eq!(left, 2);
}

#[test]
fn snapshots_within_retention_stay_readable() {
    let dir = TempDir::new().unwrap();
    let (store, local) = setup(&dir);
    churn(&store, &local, 3);
    let (mut s, _v, _) = open(&store, &local, "Laptop").unwrap();
    // Default retention (30 days): nothing young is collected.
    s.gc(&GcOptions {
        grace_ns: 0,
        ..GcOptions::default()
    })
    .unwrap();
    let snaps = s.snapshots().unwrap();
    assert!(snaps.len() >= 4);
    // An older snapshot still holds version 1 of the file, read-only.
    let mut found = false;
    for snap in snaps.iter().skip(1) {
        let mut view = s.snapshot_view(&snap.hash).unwrap();
        assert!(view.is_read_only());
        if get(&mut view, "churn.txt").is_some_and(|c| c.starts_with(b"version 1 ")) {
            found = true;
        }
    }
    assert!(found, "no snapshot holds version 1");
}

#[test]
fn rollback_is_still_detected_after_collection() {
    let dir = TempDir::new().unwrap();
    let (store, local) = setup(&dir);
    churn(&store, &local, 4);
    let newest = {
        let (mut s, _v, _) = open(&store, &local, "Laptop").unwrap();
        s.gc(&aggressive()).unwrap();
        s.gc(&aggressive()).unwrap();
        s.head().as_ref()
    };
    store.with(|m| {
        assert!(
            m.remove(Area::Manifest, &Name::Object(ObjectId(newest.oid)))
                .unwrap()
        )
    });
    match open(&store, &local, "Laptop") {
        Err(SyncError::RollbackDetected { .. }) => {}
        Err(e) => panic!("expected a rollback error, got {e}"),
        Ok(_) => panic!("rollback after collection was not detected"),
    }
}

const DAY: u64 = 24 * 3600 * 1_000_000_000;

fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos() as u64
}

/// Device B publishes a commit; its manifest has not reached the bundle
/// yet (pages and table blocks have: sync clients upload in any order).
/// Returns the hidden manifest's name and bytes.
fn commit_in_flight(store: &SharedMem) -> (Name, Vec<u8>) {
    let b_local = MemLocal::default();
    let (mut sb, mut vb, _) = open(store, &b_local, "Desktop").unwrap();
    put(&mut vb, "from-b.txt", &vec![b'b'; 300_000]);
    vb.flush().unwrap();
    let r = sb.publish().unwrap().unwrap();
    drop((vb, sb));
    let name = Name::Object(ObjectId(r.oid));
    let bytes = store.with(|m| {
        let b = m
            .read(
                Area::Manifest,
                &name,
                luksbox_sync::store::LenRule::AtMost(1 << 20),
            )
            .unwrap()
            .unwrap();
        assert!(m.remove(Area::Manifest, &name).unwrap());
        b
    });
    (name, bytes)
}

fn page_names(store: &SharedMem) -> std::collections::BTreeSet<String> {
    store.with(|m| {
        m.list(Area::Page)
            .unwrap()
            .names
            .iter()
            .map(|n| n.leaf())
            .collect()
    })
}

#[test]
fn an_upload_in_progress_survives_collection() {
    let dir = TempDir::new().unwrap();
    let (store, local) = setup(&dir);
    let (name, bytes) = commit_in_flight(&store);
    {
        let (mut s, _v, _) = open(&store, &local, "Laptop").unwrap();
        let first = s.gc(&aggressive()).unwrap();
        assert!(first.orphans > 0, "B's objects are orphans here");
        s.gc(&aggressive()).unwrap();
    }
    // B's manifest arrives: its commit is complete and merges.
    store.with(|m| m.create_new(Area::Manifest, &name, &bytes).unwrap());
    let (_s, mut v, r) = open(&store, &local, "Laptop").unwrap();
    assert!(r.writable);
    let id = v.lookup_path("/from-b.txt").unwrap();
    assert_eq!(v.stat(id).unwrap().size, 300_000);
}

#[test]
fn orphans_are_collected_after_the_orphan_grace() {
    let dir = TempDir::new().unwrap();
    let (store, local) = setup(&dir);
    let before = page_names(&store);
    let _ = commit_in_flight(&store);
    let orphans: Vec<String> = page_names(&store).difference(&before).cloned().collect();
    assert!(!orphans.is_empty());
    let (mut s, _v, _) = open(&store, &local, "Laptop").unwrap();
    s.gc(&aggressive()).unwrap();
    let later = |days: u64| GcOptions {
        now_ns: Some(now() + days * DAY),
        ..aggressive()
    };
    s.gc(&later(89)).unwrap();
    let left = page_names(&store);
    assert!(orphans.iter().all(|o| left.contains(o)), "kept 89 days");
    s.gc(&later(91)).unwrap();
    let left = page_names(&store);
    assert!(
        orphans.iter().all(|o| !left.contains(o)),
        "gone after 90 days"
    );
}

/// A device whose clock went back (a lost hardware clock) would date its
/// plan in the past, and delete at once when the clock is fixed: it
/// refuses to collect.
#[test]
fn a_clock_behind_its_own_commits_cannot_collect() {
    let dir = TempDir::new().unwrap();
    let (store, local) = setup(&dir);
    churn(&store, &local, 2);
    let (mut s, _v, _) = open(&store, &local, "Laptop").unwrap();
    match s.gc(&GcOptions {
        now_ns: Some(now() - 30 * DAY),
        ..aggressive()
    }) {
        Err(SyncError::Unsupported(why)) => assert!(why.contains("clock"), "{why}"),
        other => panic!("expected a refusal, got {other:?}"),
    }
    assert!(s.gc(&aggressive()).is_ok());
}

/// Every open records when it first saw each plan.
#[test]
fn opening_records_plan_sightings() {
    let dir = TempDir::new().unwrap();
    let (store, a_local) = setup(&dir);
    churn(&store, &a_local, 2);
    {
        let (mut sa, _va, _) = open(&store, &a_local, "Laptop").unwrap();
        assert!(sa.gc(&aggressive()).unwrap().planned > 0);
    }
    let b_local = MemLocal::default();
    drop(open(&store, &b_local, "Desktop").unwrap());
    assert!(b_local.0.lock().unwrap().contains_key("gc-seen"));
}

/// Write (or replace) `name` with `len` bytes of `fill` in A's vault, and
/// publish.
fn a_writes(store: &SharedMem, local: &MemLocal, name: &str, len: usize, fill: u8) {
    let (mut s, mut v, _) = open(store, local, "Laptop").unwrap();
    put(&mut v, name, &vec![fill; len]);
    v.flush().unwrap();
    s.publish().unwrap();
}

/// A commit still uploading reuses pages of the commit it was based on,
/// made by another device. The publishing device's lease, kept (closed)
/// after its session ended, pins that base, so collection keeps those
/// pages until the commit arrives.
#[test]
fn an_upload_in_progress_keeps_the_pages_it_reuses() {
    let dir = TempDir::new().unwrap();
    let (store, a_local) = setup(&dir);
    // A big file over several pages; B's commit leaves it alone.
    a_writes(&store, &a_local, "big.bin", 3 << 19, 1);
    let (name, bytes) = commit_in_flight(&store);
    // A deletes it and writes another file into the freed space: the
    // pages B's commit still needs for big.bin are rewritten.
    {
        let (mut s, mut v, _) = open(&store, &a_local, "Laptop").unwrap();
        let root = v.root_id();
        v.unlink(root, "big.bin").unwrap();
        v.flush().unwrap();
        s.publish().unwrap();
    }
    a_writes(&store, &a_local, "other.bin", 3 << 19, 2);
    {
        let (mut s, _v, _) = open(&store, &a_local, "Laptop").unwrap();
        s.gc(&aggressive()).unwrap();
        s.gc(&aggressive()).unwrap();
    }
    store.with(|m| m.create_new(Area::Manifest, &name, &bytes).unwrap());
    let (_s, mut v, _) = open(&store, &a_local, "Laptop").unwrap();
    // B's commit was complete and merged in.
    let id = v.lookup_path("/from-b.txt").expect("B's commit was merged");
    assert_eq!(v.stat(id).unwrap().size, 300_000);
    let id = v.lookup_path("/other.bin").unwrap();
    assert_eq!(v.stat(id).unwrap().size, 3 << 19);
}
