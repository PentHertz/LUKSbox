// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Penthertz <https://penthertz.com> (https://x.com/PentHertz)

//! What a provider that controls the bundle folder (adds, deletes,
//! alters, replays objects from its version history, withholds them) can
//! no longer do: every test asserts the safe outcome, which is a refusal,
//! a read-only open with an explicit notice, or the right vault, never a
//! wrong, older or mixed one shown or published silently.
//!
//! ```bash
//! cargo test --release --test provider_tampering -p luksbox-sync
//! ```

use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use luksbox_core::{Argon2idParams, CipherSuite};
use luksbox_format::{Container, UnlockMaterial};
use luksbox_sync::bundle::{self, ConvertOptions, OpenOptions, OpenReport, Session};
use luksbox_sync::gc::GcOptions;
use luksbox_sync::graph::Notice;
use luksbox_sync::local::{LocalStore, MemLocal};
use luksbox_sync::names::{Area, Name};
use luksbox_sync::store::{Created, LenRule, Listing, ObjectStore, SharedMem};
use luksbox_sync::table::sha256;
use luksbox_sync::{Result, SyncError};
use luksbox_vfs::Vfs;
use tempfile::TempDir;

const PASS: &[u8] = b"pw";
const KDF: Argon2idParams = Argon2idParams {
    m_cost_kib: 8,
    t_cost: 1,
    p_cost: 1,
};

type Key = (Area, String, String);

fn aggressive() -> GcOptions {
    GcOptions {
        retention_ns: 0,
        keep_last: 1,
        grace_ns: 0,
        orphan_grace_ns: 0,
        ..GcOptions::default()
    }
}

fn open_store(
    store: Box<dyn ObjectStore>,
    local: &MemLocal,
    label: &str,
    read_only: bool,
) -> Result<(Session, Vfs, OpenReport)> {
    let l = local.clone();
    let (s, c, r) = Session::open(
        store,
        move |_| Ok(Box::new(l) as Box<dyn LocalStore>),
        PathBuf::from("v.lbxs"),
        &mut UnlockMaterial::Passphrase(PASS),
        &OpenOptions {
            device_label: label.into(),
            read_only,
        },
    )?;
    let v = if read_only {
        Vfs::open_read_only(c).unwrap()
    } else {
        Vfs::open(c).unwrap()
    };
    Ok((s, v, r))
}

fn open(store: &SharedMem, local: &MemLocal, label: &str) -> Result<(Session, Vfs, OpenReport)> {
    open_store(Box::new(store.clone()), local, label, false)
}

fn open_ro(store: &SharedMem, local: &MemLocal) -> Result<(Session, Vfs, OpenReport)> {
    open_store(Box::new(store.clone()), local, "probe", true)
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

fn keys_in(store: &SharedMem, area: Area) -> Vec<Key> {
    store.with(|m| {
        m.raw_mut()
            .keys()
            .filter(|(a, _, _)| *a == area)
            .cloned()
            .collect()
    })
}

/// Commits a file, deletes it, then commits more, and collects
/// aggressively (two passes): the commit that held the file is gone.
/// Returns the store's full history before collection and that commit.
fn history_with_a_collected_commit(
    store: &SharedMem,
    local: &MemLocal,
) -> (luksbox_sync::store::MemStore, [u8; 32]) {
    let target_hash;
    {
        let (mut s, mut v, _) = open(store, local, "Laptop").unwrap();
        put(&mut v, "secret.txt", b"deleted long ago");
        v.flush().unwrap();
        target_hash = s.publish().unwrap().unwrap().hash;
        let root = v.root_id();
        v.unlink(root, "secret.txt").unwrap();
        v.flush().unwrap();
        s.publish().unwrap().unwrap();
        for i in 0..4 {
            put(&mut v, "other.txt", format!("v{i}").as_bytes());
            v.flush().unwrap();
            s.publish().unwrap().unwrap();
        }
        s.finish(&mut v).unwrap();
    }
    let history = store.with(|m| m.clone());
    {
        let (mut s, v, _) = open(store, local, "Laptop").unwrap();
        drop(v);
        s.gc(&aggressive()).unwrap();
        let r = s.gc(&aggressive()).unwrap();
        assert!(r.deleted > 0, "{r:?}");
    }
    (history, target_hash)
}

/// The provider puts back, from its version history, the manifest of
/// `target` and every page, table and header object it is missing.
/// Returns the keys it added.
fn replay(
    store: &SharedMem,
    mut history: luksbox_sync::store::MemStore,
    target: [u8; 32],
) -> Vec<Key> {
    let mut added = Vec::new();
    store.with(|m| {
        let cur = m.raw_mut();
        for ((area, shard, leaf), bytes) in history.raw_mut().iter() {
            let k = (*area, shard.clone(), leaf.clone());
            if *area == Area::Lease || cur.contains_key(&k) {
                continue;
            }
            if *area == Area::Manifest && sha256(bytes) != target {
                continue;
            }
            cur.insert(k.clone(), bytes.clone());
            added.push(k);
        }
    });
    added
}

// ---------------------------------------------------------------------
// Item 1: a garbage-collected commit put back by the provider became a
// head of its own, and was union-merged into the vault (files deleted
// long ago came back, and the merge was published).
// ---------------------------------------------------------------------

#[test]
fn a_replayed_collected_commit_is_never_merged_into_the_vault() {
    let dir = TempDir::new().unwrap();
    let (store, local) = setup(&dir);
    let (history, target) = history_with_a_collected_commit(&store, &local);
    {
        let (_s, mut v, _) = open(&store, &local, "Laptop").unwrap();
        assert!(get(&mut v, "secret.txt").is_none());
    }
    let manifests_before = keys_in(&store, Area::Manifest).len();
    assert!(!replay(&store, history, target).is_empty());

    let (mut s, mut v, r) = open(&store, &local, "Laptop").unwrap();
    assert!(r.writable, "{:?}", r.notices);
    assert_eq!(r.other_heads, 0, "{:?}", r.notices);
    assert!(
        get(&mut v, "secret.txt").is_none(),
        "a file deleted before garbage collection came back from a replayed commit"
    );
    assert_ne!(s.head().hash, target);
    // Nothing was merged or published because of it.
    assert_eq!(keys_in(&store, Area::Manifest).len(), manifests_before + 1);
    s.finish(&mut v).unwrap();
    // It is not offered as a snapshot either.
    let (s, _v, _) = open_ro(&store, &local).unwrap();
    assert!(s.snapshots().unwrap().iter().all(|x| x.hash != target));
    assert!(s.snapshot_view(&target).is_err());
}

/// The same replay, with one page of the real head withheld: the
/// replayed (months-old) state is not opened, writable or not.
#[test]
fn a_replayed_commit_never_becomes_the_head_when_the_real_head_is_withheld() {
    let dir = TempDir::new().unwrap();
    let (store, local) = setup(&dir);
    let (history, target) = history_with_a_collected_commit(&store, &local);
    let added = replay(&store, history, target);
    // A page the real head needs (one the replay did not add).
    let page = keys_in(&store, Area::Page)
        .into_iter()
        .find(|k| !added.contains(k))
        .expect("a page of the head");
    store.with(|m| m.raw_mut().remove(&page)).unwrap();

    match open(&store, &local, "Laptop") {
        Err(SyncError::NewestIncomplete { .. }) => {}
        Err(e) => panic!("expected NewestIncomplete, got {e}"),
        Ok((s, _v, r)) => panic!(
            "opened {} (writable {}) although the newest version is incomplete: {:?}",
            if s.head().hash == target {
                "the replayed commit"
            } else {
                "a commit"
            },
            r.writable,
            r.notices
        ),
    }
    // A fresh device trusts the bundle as found, but the replayed commit
    // is collected history: nothing complete is left to open.
    match open_ro(&store, &MemLocal::default()) {
        Err(SyncError::NothingComplete { .. }) => {}
        Err(e) => panic!("expected NothingComplete, got {e}"),
        Ok((s, _v, _)) => assert_ne!(s.head().hash, target, "the replayed commit was opened"),
    }
}

// ---------------------------------------------------------------------
// Item 3: the rollback check only asked that the commits this device saw
// be present. Deleting one manifest in the middle of a chain made the
// rest of it "pending", and the device opened an older state (read-only,
// with notices users are told mean sync lag).
// ---------------------------------------------------------------------

#[test]
fn deleting_a_middle_manifest_is_a_rollback_not_an_older_state() {
    let dir = TempDir::new().unwrap();
    let (store, local) = setup(&dir);
    let mut hashes = Vec::new();
    {
        let (mut s, mut v, _) = open(&store, &local, "Laptop").unwrap();
        for i in 0..5 {
            put(&mut v, "f.txt", format!("version {i}").as_bytes());
            v.flush().unwrap();
            hashes.push(s.publish().unwrap().unwrap().hash);
        }
        s.finish(&mut v).unwrap();
    }
    {
        let (_s, mut v, r) = open(&store, &local, "Laptop").unwrap();
        assert!(r.writable);
        assert_eq!(get(&mut v, "f.txt").unwrap(), b"version 4");
    }
    let k = keys_in(&store, Area::Manifest)
        .into_iter()
        .find(|k| store.with(|m| sha256(&m.raw_mut()[k]) == hashes[2]))
        .unwrap();
    store.with(|m| m.raw_mut().remove(&k)).unwrap();
    for read_only in [false, true] {
        match open_store(Box::new(store.clone()), &local, "Laptop", read_only) {
            Err(SyncError::RollbackDetected { .. }) => {}
            Err(e) => panic!("expected a rollback error, got {e}"),
            Ok((_s, mut v, r)) => panic!(
                "opened f.txt = {:?}, notices {:?}",
                get(&mut v, "f.txt").map(|b| String::from_utf8_lossy(&b).into_owned()),
                r.notices
            ),
        }
    }
}

/// Withholding one object of the newest version this device saw: a
/// writable open refuses instead of falling back to an older version; a
/// read-only open shows the older one with an explicit notice, and does
/// not move this device's anchor back.
#[test]
fn withholding_one_object_of_what_this_device_saw_refuses_instead_of_showing_an_older_state() {
    let dir = TempDir::new().unwrap();
    let (store, local) = setup(&dir);
    let before;
    {
        let (mut s, mut v, _) = open(&store, &local, "Laptop").unwrap();
        put(&mut v, "f.txt", b"old");
        v.flush().unwrap();
        s.publish().unwrap().unwrap();
        before = keys_in(&store, Area::Page);
        put(&mut v, "f.txt", b"new");
        v.flush().unwrap();
        s.publish().unwrap().unwrap();
        s.finish(&mut v).unwrap();
    }
    let page = keys_in(&store, Area::Page)
        .into_iter()
        .find(|k| !before.contains(k))
        .expect("a page only the newest commit has");
    let bytes = store.with(|m| m.raw_mut().remove(&page)).unwrap();

    assert!(matches!(
        open(&store, &local, "Laptop"),
        Err(SyncError::NewestIncomplete { .. })
    ));
    {
        let (_s, mut v, r) = open_ro(&store, &local).unwrap();
        assert!(!r.writable);
        assert!(
            r.notices.contains(&Notice::OlderThanSeen),
            "{:?}",
            r.notices
        );
        assert_eq!(get(&mut v, "f.txt").unwrap(), b"old");
    }
    // Still refused: the inspection did not make the older state this
    // device's newest.
    assert!(matches!(
        open(&store, &local, "Laptop"),
        Err(SyncError::NewestIncomplete { .. })
    ));
    // Once the object is back, the newest version opens as usual.
    store.with(|m| m.raw_mut().insert(page, bytes));
    let (_s, mut v, r) = open(&store, &local, "Laptop").unwrap();
    assert!(r.writable, "{:?}", r.notices);
    assert_eq!(get(&mut v, "f.txt").unwrap(), b"new");
}

/// Sync lag is not tampering: a commit another device built on what this
/// device saw, whose objects are still arriving, leaves this device on
/// what it saw (read-only until they are here), not refused.
#[test]
fn a_newer_commit_still_arriving_opens_what_this_device_saw_read_only() {
    let dir = TempDir::new().unwrap();
    let (store, la) = setup(&dir);
    let lb = MemLocal::default();
    {
        let (mut s, mut v, _) = open(&store, &la, "A").unwrap();
        put(&mut v, "f.txt", b"seen by A");
        v.flush().unwrap();
        s.publish().unwrap().unwrap();
        s.finish(&mut v).unwrap();
    }
    let before = keys_in(&store, Area::Page);
    {
        let (mut s, mut v, _) = open(&store, &lb, "B").unwrap();
        put(&mut v, "f.txt", b"from B");
        v.flush().unwrap();
        s.publish().unwrap().unwrap();
        s.finish(&mut v).unwrap();
    }
    let page = keys_in(&store, Area::Page)
        .into_iter()
        .find(|k| !before.contains(k))
        .unwrap();
    let bytes = store.with(|m| m.raw_mut().remove(&page)).unwrap();
    {
        let (_s, mut v, r) = open(&store, &la, "A").unwrap();
        assert!(!r.writable);
        assert!(
            r.notices
                .iter()
                .any(|n| matches!(n, Notice::Pending { .. })),
            "{:?}",
            r.notices
        );
        assert!(!r.notices.contains(&Notice::OlderThanSeen));
        assert_eq!(get(&mut v, "f.txt").unwrap(), b"seen by A");
    }
    store.with(|m| m.raw_mut().insert(page, bytes));
    let (_s, mut v, r) = open(&store, &la, "A").unwrap();
    assert!(r.writable);
    assert_eq!(get(&mut v, "f.txt").unwrap(), b"from B");
}

// ---------------------------------------------------------------------
// Item 2: a merge whose base was incomplete (or had no header object)
// silently became a two-way merge: deletions made on one side came back.
// ---------------------------------------------------------------------

/// Device A deletes x.txt while device B edits y.txt: a fork over `base`.
/// Returns the store, A's local state, and the three commits.
fn fork(dir: &TempDir) -> (SharedMem, MemLocal, [u8; 32], [u8; 32], [u8; 32], Vec<Key>) {
    let (store, la) = setup(dir);
    let lb = MemLocal::default();
    let hbase;
    {
        let (mut s, mut v, _) = open(&store, &la, "A").unwrap();
        put(&mut v, "x.txt", b"x");
        put(&mut v, "y.txt", b"y0");
        v.flush().unwrap();
        hbase = s.publish().unwrap().unwrap().hash;
        s.finish(&mut v).unwrap();
    }
    let base_pages = keys_in(&store, Area::Page);
    let (mut sb, mut vb, _) = open(&store, &lb, "B").unwrap();
    let ha = {
        let (mut sa, mut va, _) = open(&store, &la, "A").unwrap();
        let root = va.root_id();
        va.unlink(root, "x.txt").unwrap();
        va.flush().unwrap();
        sa.publish().unwrap().unwrap().hash
    };
    put(&mut vb, "y.txt", b"y1");
    vb.flush().unwrap();
    let hb = sb.publish().unwrap().unwrap().hash;
    drop((vb, sb));
    (store, la, hbase, ha, hb, base_pages)
}

#[test]
fn a_fork_is_never_merged_without_its_base() {
    // Control: with the base, the deletion survives the merge.
    {
        let dir = TempDir::new().unwrap();
        let (store, la, ..) = fork(&dir);
        let (_s, mut v, r) = open(&store, &la, "A").unwrap();
        assert!(r.writable);
        assert!(get(&mut v, "x.txt").is_none());
        assert_eq!(get(&mut v, "y.txt").unwrap(), b"y1");
    }
    let dir = TempDir::new().unwrap();
    let (store, la, hbase, ha, hb, base_pages) = fork(&dir);
    // The provider removes one page only the base uses.
    let mut removed = None;
    for k in base_pages {
        let bytes = store.with(|m| m.raw_mut().remove(&k)).unwrap();
        let ok = open_ro(&store, &MemLocal::default()).is_ok_and(|(s, _v, _r)| {
            s.snapshot_view(&ha).is_ok()
                && s.snapshot_view(&hb).is_ok()
                && s.snapshot_view(&hbase).is_err()
        });
        if ok {
            removed = Some((k, bytes));
            break;
        }
        store.with(|m| m.raw_mut().insert(k, bytes));
    }
    let (k, bytes) = removed.expect("a page only the merge base uses");
    {
        let (mut s, mut v, r) = open(&store, &la, "A").unwrap();
        assert!(
            get(&mut v, "x.txt").is_none(),
            "x.txt was deleted on one branch and came back without the merge base"
        );
        assert!(
            r.notices.contains(&Notice::MergeBaseMissing {
                heads: 1,
                local_changes: false
            }),
            "{:?}",
            r.notices
        );
        assert_eq!(r.other_heads, 1);
        let f = s.finish(&mut v).unwrap();
        assert_eq!((f.merged, f.base_missing), (0, 1));
    }
    // Once the base is back, the fork merges as usual.
    store.with(|m| m.raw_mut().insert(k, bytes));
    let (_s, mut v, r) = open(&store, &la, "A").unwrap();
    assert_eq!(r.other_heads, 0, "{:?}", r.notices);
    assert!(get(&mut v, "x.txt").is_none());
    assert_eq!(get(&mut v, "y.txt").unwrap(), b"y1");
}

/// The base's header object is gone: no merge either. The keyslot table
/// used to be picked by header generation then, which undid a removal:
/// here A revokes a passphrase (one header change) while B enrolls two
/// (two changes, a higher generation).
#[test]
fn a_fork_is_never_merged_without_its_base_header() {
    let dir = TempDir::new().unwrap();
    let (store, la) = setup(&dir);
    let lb = MemLocal::default();
    let second: &[u8] = b"second passphrase";
    {
        let (mut s, mut v, _) = open(&store, &la, "A").unwrap();
        v.container_mut().enroll_passphrase(second, KDF).unwrap();
        v.container_mut().persist_header().unwrap();
        v.flush().unwrap();
        s.publish().unwrap().unwrap();
        s.finish(&mut v).unwrap();
    }
    let base_header = keys_in(&store, Area::Header);
    let (mut sb, mut vb, _) = open(&store, &lb, "B").unwrap();
    {
        let (mut s, mut v, _) = open(&store, &la, "A").unwrap();
        v.container_mut().revoke_slot(1).unwrap();
        v.container_mut().persist_header().unwrap();
        v.flush().unwrap();
        s.publish().unwrap().unwrap();
    }
    for p in [&b"third"[..], b"fourth"] {
        vb.container_mut().enroll_passphrase(p, KDF).unwrap();
        vb.container_mut().persist_header().unwrap();
    }
    put(&mut vb, "b.txt", b"from B");
    vb.flush().unwrap();
    sb.publish().unwrap().unwrap();
    drop((vb, sb));
    // The provider withholds the header objects only the base names.
    let withheld: Vec<(Key, Vec<u8>)> = base_header
        .iter()
        .map(|k| (k.clone(), store.with(|m| m.raw_mut().remove(k)).unwrap()))
        .collect();
    {
        let (_s, mut v, r) = open(&store, &la, "A").unwrap();
        assert!(
            r.notices.contains(&Notice::MergeBaseMissing {
                heads: 1,
                local_changes: false
            }),
            "{:?}",
            r.notices
        );
        assert_eq!(
            v.container().header.keyslots[1].kind,
            luksbox_core::SlotKind::Empty,
            "the revocation was undone"
        );
        assert!(get(&mut v, "b.txt").is_none(), "merged without the base");
    }
    // With the base's header back, the keyslot tables merge one by one:
    // the removal wins, both enrollments stay.
    store.with(|m| {
        for (k, b) in withheld {
            m.raw_mut().insert(k, b);
        }
    });
    let (_s, mut v, r) = open(&store, &la, "A").unwrap();
    assert_eq!(r.other_heads, 0, "{:?}", r.notices);
    assert_eq!(get(&mut v, "b.txt").unwrap(), b"from B");
    let h = v.container().header.clone();
    assert_eq!(h.keyslots[1].kind, luksbox_core::SlotKind::Empty);
    assert_eq!(
        h.keyslots
            .iter()
            .filter(|k| k.kind != luksbox_core::SlotKind::Empty)
            .count(),
        3,
        "the original passphrase and both enrollments"
    );
}

// ---------------------------------------------------------------------
// Item 5: a damaged table block failed every open of the bundle, on
// every device, instead of making its commit incomplete.
// ---------------------------------------------------------------------

#[test]
fn a_damaged_table_block_skips_its_head_instead_of_failing_every_open() {
    let dir = TempDir::new().unwrap();
    let (store, _la, _hbase, ha, hb, _) = fork(&dir);
    // The head every device picks first, and the other one.
    let first = {
        let (s, _v, _) = open_ro(&store, &MemLocal::default()).unwrap();
        s.head().clone()
    };
    let other = if first.hash == ha { hb } else { ha };
    // Its table block (each head sealed its own) arrives damaged.
    let t = first.m.tables[0].object_id();
    let key = (Area::Table, t.shard(), t.to_hex());
    store.with(|m| m.raw_mut().get_mut(&key).unwrap()[200] ^= 1);
    // Before: Err(ObjectAuth) for everyone. Now the damaged head is
    // skipped (reported as pending) and the other one opens.
    let (s, _v, r) = open(&store, &MemLocal::default(), "C").unwrap();
    assert!(r.writable, "{:?}", r.notices);
    assert_eq!(s.head().hash, other);
    assert!(
        r.notices
            .iter()
            .any(|n| matches!(n, Notice::Pending { .. })),
        "{:?}",
        r.notices
    );
}

// ---------------------------------------------------------------------
// Item 7: a publish whose manifest reached the folder but whose folder
// sync then failed was retried with the same sequence number and new
// bytes: two commits claiming one (device, seq), an equivocation.
// ---------------------------------------------------------------------

/// A store whose `sync` fails once right after a manifest is written.
#[derive(Clone)]
struct FlakySync {
    inner: SharedMem,
    fail: Arc<AtomicBool>,
    armed: Arc<AtomicBool>,
}

impl ObjectStore for FlakySync {
    fn list(&mut self, area: Area) -> Result<Listing> {
        self.inner.list(area)
    }
    fn read(&mut self, area: Area, name: &Name, len: LenRule) -> Result<Option<Vec<u8>>> {
        self.inner.read(area, name, len)
    }
    fn create_new(&mut self, area: Area, name: &Name, bytes: &[u8]) -> Result<Created> {
        let r = self.inner.create_new(area, name, bytes);
        if area == Area::Manifest && self.fail.swap(false, Ordering::SeqCst) {
            self.armed.store(true, Ordering::SeqCst);
        }
        r
    }
    fn remove(&mut self, area: Area, name: &Name) -> Result<bool> {
        self.inner.remove(area, name)
    }
    fn sync(&mut self) -> Result<()> {
        if self.armed.swap(false, Ordering::SeqCst) {
            return Err(SyncError::Io(std::io::Error::other(
                "injected sync failure",
            )));
        }
        self.inner.sync()
    }
    fn describe(&self) -> String {
        self.inner.describe()
    }
}

#[test]
fn a_publish_whose_folder_sync_failed_never_reuses_its_sequence_number() {
    let dir = TempDir::new().unwrap();
    let (store, local) = setup(&dir);
    let flaky = FlakySync {
        inner: store.clone(),
        fail: Arc::new(AtomicBool::new(false)),
        armed: Arc::new(AtomicBool::new(false)),
    };
    let (mut s, mut v, _) = open_store(Box::new(flaky.clone()), &local, "Laptop", false).unwrap();
    put(&mut v, "one.txt", b"1");
    v.flush().unwrap();
    flaky.fail.store(true, Ordering::SeqCst);
    assert!(s.publish().is_err());
    // The manifest is in the folder already.
    let after_failure = keys_in(&store, Area::Manifest).len();
    put(&mut v, "two.txt", b"2");
    v.flush().unwrap();
    let second = s.publish().unwrap().unwrap();
    s.finish(&mut v).unwrap();
    drop((v, s));
    assert_eq!(keys_in(&store, Area::Manifest).len(), after_failure + 1);

    let (s, mut v, r) = open(&store, &MemLocal::default(), "Other").unwrap();
    assert!(
        !r.notices
            .iter()
            .any(|n| matches!(n, Notice::Equivocation { .. })),
        "{:?}",
        r.notices
    );
    assert_eq!(s.head().hash, second.hash);
    assert_eq!(get(&mut v, "one.txt").unwrap(), b"1");
    assert_eq!(get(&mut v, "two.txt").unwrap(), b"2");
    drop((v, s));
    let (_s, _v, r) = open(&store, &local, "Laptop").unwrap();
    assert!(!r.new_identity, "{:?}", r.notices);
}

// ---------------------------------------------------------------------
// Item 4: deleting a bundle wiped the local state of whatever bundle id
// the (unauthenticated) header object names carried.
// ---------------------------------------------------------------------

#[cfg(unix)]
#[test]
fn deleting_a_bundle_never_wipes_another_bundle_s_local_state() {
    let dir = TempDir::new().unwrap();
    let local_root = dir.path().join("state");
    let make = |name: &str| {
        let lbx = dir.path().join(format!("{name}.lbx"));
        let _g = luksbox_format::metadata::set_create_metadata_region_size_override(Some(2 << 20));
        let c = Container::create_with_passphrase(&lbx, None, CipherSuite::Aes256GcmSiv, KDF, PASS)
            .unwrap();
        let mut c = Vfs::open(c).unwrap().close().unwrap();
        let path = dir.path().join(format!("{name}.lbxs"));
        let bid = bundle::fs::convert(
            &mut c,
            &path,
            &local_root,
            &ConvertOptions {
                page_size: 1 << 20,
                device_label: "Laptop".into(),
                hybrid_sidecar: None,
            },
        )
        .unwrap();
        (path, bid)
    };
    let (x_path, x) = make("x");
    let (_y_path, y) = make("y");
    let x_state = local_root.join(x.to_hex());
    let y_state = local_root.join(y.to_hex());
    assert!(x_state.is_dir() && y_state.is_dir());
    // The provider renames X's header objects after Y's id.
    for e in std::fs::read_dir(x_path.join("h")).unwrap() {
        let e = e.unwrap();
        let name = e.file_name().into_string().unwrap();
        let renamed = name.replacen(&x.to_hex(), &y.to_hex(), 1);
        std::fs::rename(e.path(), x_path.join("h").join(renamed)).unwrap();
    }
    let r = bundle::fs::delete(&x_path, &local_root).unwrap();
    assert!(y_state.is_dir(), "bundle Y's local state was wiped");
    assert!(!x_state.exists(), "bundle X's own local state stays");
    assert_eq!(r.local_state_kept, Some(y.to_hex()));
}

// ---------------------------------------------------------------------
// Item 6: a crash between linking an object and removing its temporary
// name left the object with two links, refused when read, for good. An
// object with a second name now reads like any other (see below); the
// leftover name is still removed.
// ---------------------------------------------------------------------

#[cfg(unix)]
#[test]
fn a_leftover_temporary_link_is_swept_at_the_next_writable_open() {
    let dir = TempDir::new().unwrap();
    let local_root = dir.path().join("state");
    let lbx = dir.path().join("v.lbx");
    let _g = luksbox_format::metadata::set_create_metadata_region_size_override(Some(2 << 20));
    let c = Container::create_with_passphrase(&lbx, None, CipherSuite::Aes256GcmSiv, KDF, PASS)
        .unwrap();
    let mut c = Vfs::open(c).unwrap().close().unwrap();
    let path = dir.path().join("v.lbxs");
    bundle::fs::convert(&mut c, &path, &local_root, &ConvertOptions::default()).unwrap();
    // As if the process died between linkat and unlinkat for a manifest.
    let shard = std::fs::read_dir(path.join("m"))
        .unwrap()
        .next()
        .unwrap()
        .unwrap()
        .path();
    let manifest = std::fs::read_dir(&shard)
        .unwrap()
        .next()
        .unwrap()
        .unwrap()
        .path();
    let tmp = shard.join(".tmp-00112233445566778899aabbccddeeff");
    std::fs::hard_link(&manifest, &tmp).unwrap();
    // A read-only open does not touch the folder, and reads the
    // manifest through its own name.
    let (_s, _c, r) = bundle::fs::open(
        &path,
        &local_root,
        &mut UnlockMaterial::Passphrase(PASS),
        &OpenOptions {
            device_label: "Laptop".into(),
            read_only: true,
        },
    )
    .unwrap();
    assert_eq!(r.invalid_manifests, 0);
    drop((_s, _c));
    assert!(tmp.exists());
    let (_s, _c, r) = bundle::fs::open(
        &path,
        &local_root,
        &mut UnlockMaterial::Passphrase(PASS),
        &OpenOptions {
            device_label: "Laptop".into(),
            read_only: false,
        },
    )
    .unwrap();
    assert!(!tmp.exists());
    assert_eq!(r.invalid_manifests, 0);
    assert!(r.writable, "{:?}", r.notices);
}

// ---------------------------------------------------------------------
// A bundle in a Google Drive for desktop folder: while Drive uploads an
// object it holds a second name for it (`.tmp.driveupload/<n>`, a hard
// link next to the bundle). Opens refused such objects, so whichever
// commit or page was uploading at that moment looked withheld: "rollback
// detected" for a manifest this device had seen, "metadata blob
// deserialization failed" for a page holding a large file's chunk list,
// and a retry worked once the upload ended.
// ---------------------------------------------------------------------

#[cfg(unix)]
fn every_object(dir: &std::path::Path, out: &mut Vec<std::path::PathBuf>) {
    for e in std::fs::read_dir(dir).unwrap() {
        let p = e.unwrap().path();
        if p.is_dir() {
            every_object(&p, out);
        } else {
            out.push(p);
        }
    }
}

#[cfg(unix)]
#[test]
fn objects_a_sync_client_is_uploading_still_open() {
    use std::os::unix::fs::MetadataExt;

    let dir = TempDir::new().unwrap();
    let drive = dir.path().join("GoogleSync");
    std::fs::create_dir(&drive).unwrap();
    let local_root = dir.path().join("state");
    let lbx = dir.path().join("v.lbx");
    let _g = luksbox_format::metadata::set_create_metadata_region_size_override(Some(2 << 20));
    let c = Container::create_with_passphrase(&lbx, None, CipherSuite::Aes256GcmSiv, KDF, PASS)
        .unwrap();
    let mut vfs = Vfs::open(c).unwrap();
    // Over 1 MiB: its chunk list is kept in data pages, read at open.
    let big: Vec<u8> = (0..3u32 << 20)
        .map(|i| (i.wrapping_mul(2_654_435_761) >> 13) as u8)
        .collect();
    put(&mut vfs, "big.bin", &big);
    put(&mut vfs, "a.txt", b"first");
    vfs.flush().unwrap();
    let mut c = vfs.close().unwrap();
    let path = drive.join("TEst.lbxs");
    bundle::fs::convert(
        &mut c,
        &path,
        &local_root,
        &ConvertOptions {
            page_size: 1 << 20,
            device_label: "Laptop".into(),
            hybrid_sidecar: None,
        },
    )
    .unwrap();
    drop(c);
    let opts = |read_only| OpenOptions {
        device_label: "Laptop".into(),
        read_only,
    };
    // A second commit, so this device has seen more than one.
    {
        let (mut s, c, r) = bundle::fs::open(
            &path,
            &local_root,
            &mut UnlockMaterial::Passphrase(PASS),
            &opts(false),
        )
        .unwrap();
        assert!(r.writable);
        let mut v = Vfs::open(c).unwrap();
        put(&mut v, "a.txt", b"second");
        s.finish(&mut v).unwrap();
        drop(v);
        s.close().unwrap();
    }

    // Drive uploads some objects: one area at a time (a manifest gave
    // "rollback detected", a page "metadata blob deserialization
    // failed"), then everything at once while this device publishes.
    let staging = drive.join(".tmp.driveupload");
    std::fs::create_dir(&staging).unwrap();
    let mut next = 1900;
    let all = ["h", "x", "p", "t", "m", "l"];
    for areas in [&["m"][..], &["p"], &["t"], &["h"], &all] {
        let mut staged = Vec::new();
        let mut objects = Vec::new();
        for a in areas {
            every_object(&path.join(a), &mut objects);
        }
        assert!(!objects.is_empty(), "{areas:?}");
        for o in objects {
            let link = staging.join(next.to_string());
            next += 1;
            std::fs::hard_link(&o, &link).unwrap();
            assert_eq!(std::fs::metadata(&o).unwrap().nlink(), 2);
            staged.push((o, link));
        }
        let publish = areas.len() == all.len();
        for read_only in [true, false] {
            let (mut s, c, r) = bundle::fs::open(
                &path,
                &local_root,
                &mut UnlockMaterial::Passphrase(PASS),
                &opts(read_only),
            )
            .unwrap_or_else(|e| panic!("{areas:?} uploading, read_only {read_only}: {e}"));
            assert_eq!(r.invalid_manifests, 0, "{areas:?}");
            assert!(r.notices.is_empty(), "{areas:?}: {:?}", r.notices);
            assert_eq!(r.writable, !read_only);
            let mut v = if read_only {
                Vfs::open_read_only(c)
            } else {
                Vfs::open(c)
            }
            .unwrap_or_else(|e| panic!("{areas:?} uploading, read_only {read_only}: {e}"));
            let id = v.lookup_path("/big.bin").unwrap();
            let mut back = vec![0u8; big.len()];
            assert_eq!(v.read(id, 0, &mut back).unwrap(), big.len());
            assert!(back == big, "big.bin differs");
            assert_eq!(get(&mut v, "a.txt").unwrap(), b"second");
            if publish && !read_only {
                // Publishing (and collecting) while the upload runs.
                put(&mut v, "a.txt", b"third");
                s.finish(&mut v).unwrap();
            }
            drop(v);
            s.close().unwrap();
        }
        // Drive's names were never written through or removed.
        for (o, link) in staged {
            assert!(link.is_file(), "{link:?} was removed");
            if o.exists() {
                assert_eq!(std::fs::read(&link).unwrap(), std::fs::read(&o).unwrap());
            }
            std::fs::remove_file(&link).unwrap();
        }
    }

    // The upload ended.
    let (_s, c, r) = bundle::fs::open(
        &path,
        &local_root,
        &mut UnlockMaterial::Passphrase(PASS),
        &opts(false),
    )
    .unwrap();
    assert!(r.writable && r.notices.is_empty(), "{:?}", r.notices);
    let mut v = Vfs::open(c).unwrap();
    assert_eq!(get(&mut v, "a.txt").unwrap(), b"third");
}
