// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Penthertz <https://penthertz.com> (https://x.com/PentHertz)

//! Several devices on one bundle: concurrent commits are merged, offline
//! changes are replayed, copied device identities and withheld commits
//! are detected, leases are visible, and a merge never undoes a keyslot
//! change.

use std::path::PathBuf;

use luksbox_core::{Argon2idParams, CipherSuite};
use luksbox_format::{Container, UnlockMaterial};
use luksbox_sync::bundle::{self, ConvertOptions, OpenOptions, OpenReport, Session};
use luksbox_sync::graph::Notice;
use luksbox_sync::local::{LocalStore, MemLocal};
use luksbox_sync::names::{Area, Name, ObjectId};
use luksbox_sync::store::{ObjectStore, SharedMem};
use luksbox_sync::{Result, SyncError};
use luksbox_vfs::Vfs;
use tempfile::TempDir;

const PASS: &[u8] = b"correct horse battery staple";
const KDF: Argon2idParams = Argon2idParams {
    m_cost_kib: 8,
    t_cost: 1,
    p_cost: 1,
};

struct Device {
    local: MemLocal,
    label: &'static str,
}

impl Device {
    fn new(label: &'static str) -> Self {
        Self {
            local: MemLocal::default(),
            label,
        }
    }

    fn open_with(&self, store: &SharedMem, pass: &[u8]) -> Result<(Session, Vfs, OpenReport)> {
        let l = self.local.clone();
        let (s, c, r) = Session::open(
            Box::new(store.clone()),
            move |_| Ok(Box::new(l) as Box<dyn LocalStore>),
            PathBuf::from("v.lbxs"),
            &mut UnlockMaterial::Passphrase(pass),
            &OpenOptions {
                device_label: self.label.into(),
                read_only: false,
            },
        )?;
        Ok((s, Vfs::open(c).unwrap(), r))
    }

    fn open(&self, store: &SharedMem) -> (Session, Vfs, OpenReport) {
        self.open_with(store, PASS).unwrap()
    }
}

/// Bundle with `/shared.txt`, converted by device `first`.
fn bundle(dir: &TempDir, first: &Device) -> SharedMem {
    let lbx = dir.path().join("v.lbx");
    let _g = luksbox_format::metadata::set_create_metadata_region_size_override(Some(2 << 20));
    let c = Container::create_with_passphrase(&lbx, None, CipherSuite::Aes256GcmSiv, KDF, PASS)
        .unwrap();
    let mut vfs = Vfs::open(c).unwrap();
    let id = vfs.create(vfs.root_id(), "shared.txt").unwrap();
    vfs.write(id, 0, b"base").unwrap();
    vfs.flush().unwrap();
    let mut c = vfs.close().unwrap();
    let store = SharedMem::new();
    let l = first.local.clone();
    bundle::convert(
        &mut c,
        Box::new(store.clone()),
        move |_| Ok(Box::new(l) as Box<dyn LocalStore>),
        &ConvertOptions {
            page_size: 1 << 20,
            device_label: first.label.into(),
            hybrid_sidecar: None,
        },
    )
    .unwrap();
    store
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
    let mut buf = vec![0u8; 4096];
    let n = vfs.read(id, 0, &mut buf).unwrap();
    buf.truncate(n);
    Some(buf)
}

fn names(vfs: &Vfs) -> Vec<String> {
    let mut v: Vec<String> = vfs
        .readdir(vfs.root_id())
        .unwrap()
        .into_iter()
        .map(|e| e.name)
        .collect();
    v.sort();
    v
}

fn heads(store: &SharedMem, dev: &Device) -> usize {
    // A read-only open reports unmerged heads without merging them.
    let l = dev.local.clone();
    let (_s, _c, r) = Session::open(
        Box::new(store.clone()),
        move |_| Ok(Box::new(l) as Box<dyn LocalStore>),
        PathBuf::from("v.lbxs"),
        &mut UnlockMaterial::Passphrase(PASS),
        &OpenOptions {
            device_label: "probe".into(),
            read_only: true,
        },
    )
    .unwrap();
    r.other_heads + 1
}

#[test]
fn concurrent_commits_fork_and_converge() {
    let dir = TempDir::new().unwrap();
    let a = Device::new("Laptop");
    let b = Device::new("Desktop");
    let store = bundle(&dir, &a);

    let (mut sa, mut va, _) = a.open(&store);
    let (mut sb, mut vb, rb) = b.open(&store);
    // B sees A's lease.
    assert!(rb.open_elsewhere.iter().any(|(l, w)| l == "Laptop" && *w));

    put(&mut va, "from-a.txt", b"A");
    va.flush().unwrap();
    sa.publish().unwrap().unwrap();
    put(&mut vb, "from-b.txt", b"B");
    vb.flush().unwrap();
    // B publishes on its (now old) base: a second branch, no error.
    sb.publish().unwrap().unwrap();
    drop((va, vb));
    drop((sa, sb));
    assert_eq!(heads(&store, &a), 2);

    // The next writable open merges both branches.
    let (s, mut v, r) = a.open(&store);
    assert_eq!(r.other_heads, 0);
    assert_eq!(get(&mut v, "from-a.txt").unwrap(), b"A");
    assert_eq!(get(&mut v, "from-b.txt").unwrap(), b"B");
    assert_eq!(s.head().m.kind, luksbox_sync::manifest::CommitKind::Merge);
    drop((v, s));
    assert_eq!(heads(&store, &a), 1);
    let (_s, mut v, _) = b.open(&store);
    assert_eq!(get(&mut v, "from-a.txt").unwrap(), b"A");
    assert_eq!(get(&mut v, "from-b.txt").unwrap(), b"B");
}

#[test]
fn conflicting_edits_keep_both_versions() {
    let dir = TempDir::new().unwrap();
    let a = Device::new("Laptop");
    let b = Device::new("Desktop");
    let store = bundle(&dir, &a);
    let (mut sa, mut va, _) = a.open(&store);
    let (mut sb, mut vb, _) = b.open(&store);
    put(&mut va, "shared.txt", b"edited on the laptop");
    va.flush().unwrap();
    sa.publish().unwrap();
    put(&mut vb, "shared.txt", b"edited on the desktop");
    // finish(): publish, then merge the concurrent commit (lock time).
    let fin = sb.finish(&mut vb).unwrap();
    assert_eq!(fin.merged, 1);
    assert_eq!(fin.conflicts, 1);
    drop((va, vb, sa, sb));

    let (_s, v, _) = b.open(&store);
    let n = names(&v);
    assert!(n.contains(&"shared.txt".to_string()));
    // Which version keeps the name is the same on every device (the
    // merge target is chosen deterministically); the other is the copy.
    let copy = n
        .iter()
        .find(|x| x.starts_with("shared (conflict "))
        .expect("conflict copy");
    let mut v = v;
    let contents = [
        get(&mut v, "shared.txt").unwrap(),
        get(&mut v, copy).unwrap(),
    ];
    assert!(contents.contains(&b"edited on the laptop".to_vec()));
    assert!(contents.contains(&b"edited on the desktop".to_vec()));
}

#[test]
fn offline_changes_are_replayed_onto_the_newest_commit() {
    let dir = TempDir::new().unwrap();
    let a = Device::new("Laptop");
    let b = Device::new("Desktop");
    let store = bundle(&dir, &a);
    {
        let (_sb, mut vb, _) = b.open(&store);
        put(&mut vb, "offline.txt", b"written offline");
        vb.flush().unwrap();
        // B goes away without publishing.
    }
    {
        let (mut sa, mut va, _) = a.open(&store);
        put(&mut va, "online.txt", b"published meanwhile");
        va.flush().unwrap();
        sa.publish().unwrap().unwrap();
    }
    let (s, mut v, r) = b.open(&store);
    assert!(r.restored_local_changes);
    assert!(!s.has_unpublished(), "the replayed changes were published");
    assert_eq!(get(&mut v, "offline.txt").unwrap(), b"written offline");
    assert_eq!(get(&mut v, "online.txt").unwrap(), b"published meanwhile");
    drop((v, s));
    let (_s, mut v, _) = a.open(&store);
    assert_eq!(get(&mut v, "offline.txt").unwrap(), b"written offline");
}

#[test]
fn a_copied_device_identity_is_detected_and_both_branches_kept() {
    let dir = TempDir::new().unwrap();
    let a = Device::new("Laptop");
    let store = bundle(&dir, &a);
    // A copy of A's whole device state (a restored backup or VM clone).
    let clone = Device {
        local: MemLocal(std::sync::Arc::new(std::sync::Mutex::new(
            a.local.0.lock().unwrap().clone(),
        ))),
        label: "Laptop",
    };
    {
        let (mut s, mut v, _) = a.open(&store);
        put(&mut v, "a.txt", b"from the original");
        v.flush().unwrap();
        s.publish().unwrap();
    }
    {
        // The clone does not know about A's commit 2 and writes its own
        // commit 2: an equivocation.
        let (mut s, mut v, r) = clone.open(&store);
        assert!(
            r.new_identity,
            "the clone must notice its identity is in use"
        );
        put(&mut v, "clone.txt", b"from the clone");
        v.flush().unwrap();
        s.publish().unwrap();
    }
    let (_s, mut v, _) = a.open(&store);
    assert_eq!(get(&mut v, "a.txt").unwrap(), b"from the original");
    assert_eq!(get(&mut v, "clone.txt").unwrap(), b"from the clone");
}

#[test]
fn same_commit_number_from_two_installs_is_an_equivocation_not_an_outage() {
    let dir = TempDir::new().unwrap();
    let a = Device::new("Laptop");
    let store = bundle(&dir, &a);
    let clone = Device {
        local: MemLocal(std::sync::Arc::new(std::sync::Mutex::new(
            a.local.0.lock().unwrap().clone(),
        ))),
        label: "Laptop",
    };
    // Both open before either publishes, then both publish commit 2;
    // sync lag hides each one's commit from the other while it does.
    let (mut s1, mut v1, _) = a.open(&store);
    let (mut s2, mut v2, _) = clone.open(&store);
    put(&mut v1, "one.txt", b"1");
    v1.flush().unwrap();
    let first = s1.publish().unwrap().unwrap();
    let key = (
        Area::Manifest,
        ObjectId(first.oid).shard(),
        ObjectId(first.oid).to_hex(),
    );
    let lagging = store.with(|m| m.raw_mut().remove(&key).unwrap());
    put(&mut v2, "two.txt", b"2");
    v2.flush().unwrap();
    let second = s2.publish().unwrap().unwrap();
    assert_eq!((first.device, first.seq), (second.device, second.seq));
    store.with(|m| m.raw_mut().insert(key, lagging));
    drop((v1, v2, s1, s2));
    // The bundle still opens; both branches are merged; the equivocation
    // is reported and the device takes a new identity.
    let (_s, mut v, r) = a.open(&store);
    assert!(
        r.notices
            .iter()
            .any(|n| matches!(n, Notice::Equivocation { .. }))
    );
    assert!(r.new_identity);
    assert_eq!(get(&mut v, "one.txt").unwrap(), b"1");
    assert_eq!(get(&mut v, "two.txt").unwrap(), b"2");
}

#[test]
fn a_withheld_commit_blocks_writing() {
    let dir = TempDir::new().unwrap();
    let a = Device::new("Laptop");
    let b = Device::new("Desktop");
    let c = Device::new("Phone");
    let store = bundle(&dir, &a);
    let withheld = {
        let (mut s, mut v, _) = b.open(&store);
        put(&mut v, "b.txt", b"b");
        v.flush().unwrap();
        s.publish().unwrap().unwrap()
    };
    {
        // A sees B's commit and publishes on top of it.
        let (mut s, mut v, _) = a.open(&store);
        put(&mut v, "a.txt", b"a");
        v.flush().unwrap();
        s.publish().unwrap().unwrap();
    }
    // The provider hides B's commit from a new device.
    store.with(|m| {
        assert!(
            m.remove(Area::Manifest, &Name::Object(ObjectId(withheld.oid)))
                .unwrap()
        )
    });
    match c.open_with(&store, PASS) {
        Ok((_s, _v, r)) => {
            assert!(
                !r.writable,
                "a device must not write while history is withheld"
            );
            assert!(
                r.notices
                    .iter()
                    .any(|n| matches!(n, Notice::Missing { .. }))
                    || r.notices
                        .iter()
                        .any(|n| matches!(n, Notice::Pending { .. }))
            );
        }
        Err(_) => {}
    }
    // And B itself sees its own commit missing: a rollback.
    assert!(matches!(
        b.open_with(&store, PASS),
        Err(SyncError::RollbackDetected { .. })
    ));
}

#[test]
fn a_merge_never_undoes_a_revocation() {
    let dir = TempDir::new().unwrap();
    let a = Device::new("Laptop");
    let b = Device::new("Desktop");
    let store = bundle(&dir, &a);
    let second: &[u8] = b"second passphrase";
    {
        let (mut s, mut v, _) = a.open(&store);
        v.container_mut().enroll_passphrase(second, KDF).unwrap();
        v.container_mut().persist_header().unwrap();
        v.flush().unwrap();
        s.publish().unwrap().unwrap();
    }
    // B opens with the second passphrase; A then revokes the original
    // one while B edits files concurrently.
    let (mut sb, mut vb, _) = b.open_with(&store, second).unwrap();
    {
        let (mut s, mut v, _) = a.open_with(&store, second).unwrap();
        v.container_mut().revoke_slot(0).unwrap();
        v.container_mut().persist_header().unwrap();
        v.flush().unwrap();
        s.publish().unwrap().unwrap();
    }
    put(&mut vb, "b.txt", b"concurrent edit");
    vb.flush().unwrap();
    sb.publish().unwrap().unwrap();
    drop((vb, sb));
    // Merge (B's head has the higher Lamport counter or not: either way
    // the merged state must carry the revocation).
    let (_s, mut v, _) = b.open_with(&store, second).unwrap();
    assert_eq!(get(&mut v, "b.txt").unwrap(), b"concurrent edit");
    drop(v);
    match a.open_with(&store, PASS) {
        Err(SyncError::CredentialRevoked { .. }) => {}
        Err(e) => panic!("expected CredentialRevoked, got {e}"),
        Ok(_) => panic!("the revoked passphrase opens the merged bundle"),
    }
}

#[test]
fn leases_disappear_on_close() {
    let dir = TempDir::new().unwrap();
    let a = Device::new("Laptop");
    let b = Device::new("Desktop");
    let store = bundle(&dir, &a);
    let (sa, va, _) = a.open(&store);
    let (sb, _vb, r) = b.open(&store);
    assert_eq!(r.open_elsewhere.len(), 1);
    drop(va);
    sa.close().unwrap();
    assert!(
        sb.fresh_leases().unwrap().is_empty(),
        "a closed session is not open"
    );
    // A's closed lease stays (it pins what A last worked on) next to B's.
    let leases = store.with(|m| m.list(Area::Lease).unwrap().names.len());
    assert_eq!(leases, 2);
    // A's next session replaces it.
    let (_sa, _va, r) = a.open(&store);
    assert_eq!(r.open_elsewhere.len(), 1, "B is open");
    let leases = store.with(|m| m.list(Area::Lease).unwrap().names.len());
    assert_eq!(leases, 2, "one lease per device");
}

/// A heartbeat writes a new lease under a new id and removes the old
/// one: no object is ever rewritten in place (each object key seals one
/// plaintext, which the zero nonce relies on).
#[test]
fn a_heartbeat_replaces_the_lease_with_a_new_object() {
    let dir = TempDir::new().unwrap();
    let a = Device::new("Laptop");
    let b = Device::new("Desktop");
    let store = bundle(&dir, &a);
    let lease_names = || store.with(|m| m.list(Area::Lease).unwrap().names);
    let (mut sa, _va, _) = a.open(&store);
    let before = lease_names();
    assert_eq!(before.len(), 1);
    sa.heartbeat().unwrap();
    let after = lease_names();
    assert_eq!(after.len(), 1, "the old lease is removed");
    assert_ne!(before, after, "the refreshed lease is a new object");
    // Still seen by another device.
    let (_sb, _vb, r) = b.open(&store);
    assert_eq!(r.open_elsewhere.len(), 1);
}

/// Opens with `pass` on a fresh device (another computer).
fn opens_with(store: &SharedMem, pass: &[u8]) -> bool {
    Device::new("Probe").open_with(store, pass).is_ok()
}

/// Two devices enroll a passphrase at the same time, both in the first
/// free keyslot: the merge keeps both (one moves to another free slot)
/// and every passphrase still opens the bundle.
#[test]
fn concurrent_enrollments_are_merged_keyslot_by_keyslot() {
    let dir = TempDir::new().unwrap();
    let a = Device::new("Laptop");
    let b = Device::new("Desktop");
    let store = bundle(&dir, &a);
    let (mut sa, mut va, _) = a.open(&store);
    let (mut sb, mut vb, _) = b.open(&store);
    va.container_mut()
        .enroll_passphrase(b"second", KDF)
        .unwrap();
    va.container_mut().persist_header().unwrap();
    put(&mut va, "a.txt", b"from A");
    va.flush().unwrap();
    sa.publish().unwrap().unwrap();
    vb.container_mut().enroll_passphrase(b"third", KDF).unwrap();
    vb.container_mut().persist_header().unwrap();
    put(&mut vb, "b.txt", b"from B");
    vb.flush().unwrap();
    sb.publish().unwrap().unwrap();
    drop((va, sa));
    let fin = sb.finish(&mut vb).unwrap();
    assert_eq!(fin.merged, 1);
    assert_eq!(fin.header_forks, 0, "not left as a fork");
    assert!(
        fin.keyslot_notes
            .iter()
            .any(|n| n.contains("moved to slot")),
        "{:?}",
        fin.keyslot_notes
    );
    drop((vb, sb));
    for p in [PASS, b"second".as_slice(), b"third".as_slice()] {
        assert!(
            opens_with(&store, p),
            "{} no longer opens",
            String::from_utf8_lossy(p)
        );
    }
    let (_s, mut v, r) = a.open(&store);
    assert!(r.writable);
    assert_eq!(get(&mut v, "a.txt").unwrap(), b"from A");
    assert_eq!(get(&mut v, "b.txt").unwrap(), b"from B");
}

/// Changes saved on a device, with a keyslot change, never published
/// (a crash); meanwhile another device changed the keyslots. The next
/// open replays both: the keyslot tables are merged.
#[test]
fn unpublished_keyslot_changes_are_replayed_by_merging() {
    let dir = TempDir::new().unwrap();
    let a = Device::new("Laptop");
    let b = Device::new("Desktop");
    let store = bundle(&dir, &a);
    {
        let (sa, mut va, _) = a.open(&store);
        put(&mut va, "only-on-a.txt", b"unpublished");
        va.container_mut()
            .enroll_passphrase(b"second", KDF)
            .unwrap();
        va.container_mut().persist_header().unwrap();
        va.flush().unwrap();
        drop((va, sa));
    }
    {
        let (mut sb, mut vb, _) = b.open(&store);
        vb.container_mut().enroll_passphrase(b"third", KDF).unwrap();
        vb.container_mut().persist_header().unwrap();
        sb.finish(&mut vb).unwrap();
    }
    let (sa, mut va, r) = a.open(&store);
    assert!(r.writable, "{:?}", r.notices);
    assert!(r.restored_local_changes);
    assert!(!r.keyslot_notes.is_empty());
    assert_eq!(get(&mut va, "only-on-a.txt").unwrap(), b"unpublished");
    drop((va, sa));
    for p in [PASS, b"second".as_slice(), b"third".as_slice()] {
        assert!(
            opens_with(&store, p),
            "{} no longer opens",
            String::from_utf8_lossy(p)
        );
    }
}

/// Changes saved on a device and never published, whose base commit is
/// no longer complete in the bundle: the device opens read-only and says
/// so, and can discard them to write again.
#[test]
fn local_changes_on_a_lost_base_can_be_discarded() {
    let dir = TempDir::new().unwrap();
    let a = Device::new("Laptop");
    let b = Device::new("Desktop");
    let store = bundle(&dir, &a);
    let base_tables = {
        let (sa, mut va, _) = a.open(&store);
        put(&mut va, "only-on-a.txt", b"unpublished");
        va.flush().unwrap();
        let t = sa.head().m.tables.clone();
        drop((va, sa));
        t
    };
    {
        let (mut sb, mut vb, _) = b.open(&store);
        put(&mut vb, "b.txt", b"from B");
        sb.finish(&mut vb).unwrap();
    }
    // The commit A's changes were made on loses a table block B no
    // longer uses (as after garbage collection).
    let head_tables = {
        let (s, _v, r) = Device::new("Probe").open_with(&store, PASS).unwrap();
        assert!(r.writable);
        s.head().m.tables.clone()
    };
    let gone = base_tables
        .iter()
        .find(|t| !head_tables.contains(t))
        .expect("B rewrote a table block");
    store.with(|m| {
        assert!(
            m.remove(Area::Table, &Name::Object(ObjectId(gone.oid)))
                .unwrap()
        );
    });
    let (sa, _va, r) = a.open(&store);
    assert!(!r.writable);
    assert!(
        r.notices
            .contains(&Notice::UnmergedLocalChanges { recoverable: false }),
        "{:?}",
        r.notices
    );
    drop((_va, sa));
    let l = a.local.clone();
    let (mut s, c, _) = Session::open(
        Box::new(store.clone()),
        move |_| Ok(Box::new(l) as Box<dyn LocalStore>),
        PathBuf::from("v.lbxs"),
        &mut UnlockMaterial::Passphrase(PASS),
        &OpenOptions {
            device_label: "Laptop".into(),
            read_only: true,
        },
    )
    .unwrap();
    drop(c);
    assert!(s.discard_local_changes().unwrap() > 0);
    drop(s);
    let (_sa, mut va, r) = a.open(&store);
    assert!(r.writable);
    assert!(get(&mut va, "only-on-a.txt").is_none());
    assert_eq!(get(&mut va, "b.txt").unwrap(), b"from B");
}
