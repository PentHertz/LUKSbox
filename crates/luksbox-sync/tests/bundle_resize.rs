// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Penthertz <https://penthertz.com> (https://x.com/PentHertz)

//! Resizing the metadata region ("file list") of a vault in a sync
//! bundle (`Vfs::resize_metadata_region` -> `Container::relayout_external`):
//! the data area moves inside the paged image and one save holds the new
//! pages and the new header, published as an ordinary commit that other
//! devices merge with their own changes.
//!
//! ```bash
//! cargo test --test bundle_resize -p luksbox-sync
//! ```

use std::path::PathBuf;

use luksbox_core::{Argon2idParams, CipherSuite};
use luksbox_format::{Container, UnlockMaterial};
use luksbox_sync::bundle::{self, ConvertOptions, OpenOptions, OpenReport, Session};
use luksbox_sync::local::{LocalStore, MemLocal};
use luksbox_sync::store::SharedMem;
use luksbox_vfs::Vfs;
use tempfile::TempDir;

const PASS: &[u8] = b"correct horse battery staple";
const KDF: Argon2idParams = Argon2idParams {
    m_cost_kib: 8,
    t_cost: 1,
    p_cost: 1,
};
const MIB: u64 = 1 << 20;
const KIB: u64 = 1 << 10;

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

    fn open(&self, store: &SharedMem) -> (Session, Vfs) {
        let (s, v, _) = self.open_report(store);
        (s, v)
    }

    fn open_report(&self, store: &SharedMem) -> (Session, Vfs, OpenReport) {
        let l = self.local.clone();
        let (s, c, r) = Session::open(
            Box::new(store.clone()),
            move |_| Ok(Box::new(l) as Box<dyn LocalStore>),
            PathBuf::from("v.lbxs"),
            &mut UnlockMaterial::Passphrase(PASS),
            &OpenOptions {
                device_label: self.label.into(),
                read_only: false,
            },
        )
        .unwrap();
        (s, Vfs::open(c).unwrap(), r)
    }
}

fn content(i: usize, len: usize) -> Vec<u8> {
    (0..len).map(|b| (b * 31 + i * 7) as u8).collect()
}

/// A bundle (2 MiB region, 1 MiB pages) holding small files and one
/// spanning several pages, converted by `first`.
fn bundle(dir: &TempDir, first: &Device) -> (SharedMem, Vec<(String, Vec<u8>)>) {
    bundle_with(dir, first, 2 * MIB)
}

fn bundle_with(dir: &TempDir, first: &Device, region: u64) -> (SharedMem, Vec<(String, Vec<u8>)>) {
    let lbx = dir.path().join("v.lbx");
    let _g = luksbox_format::metadata::set_create_metadata_region_size_override(Some(region));
    let c = Container::create_with_passphrase(&lbx, None, CipherSuite::Aes256GcmSiv, KDF, PASS)
        .unwrap();
    let mut vfs = Vfs::open(c).unwrap();
    let mut files = Vec::new();
    for i in 0..30 {
        files.push((format!("/f-{i}.txt"), content(i, 2000 + i * 100)));
    }
    files.push(("/big.bin".into(), content(99, 3 * MIB as usize + 777)));
    for (path, data) in &files {
        put(&mut vfs, &path[1..], data);
    }
    vfs.flush().unwrap();
    let mut c = vfs.close().unwrap();
    let store = SharedMem::new();
    let l = first.local.clone();
    bundle::convert(
        &mut c,
        Box::new(store.clone()),
        move |_| Ok(Box::new(l) as Box<dyn LocalStore>),
        &ConvertOptions {
            page_size: MIB as u32,
            device_label: first.label.into(),
            hybrid_sidecar: None,
        },
    )
    .unwrap();
    (store, files)
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

fn get(vfs: &mut Vfs, path: &str) -> Vec<u8> {
    let id = vfs
        .lookup_path(path)
        .unwrap_or_else(|e| panic!("{path}: {e}"));
    let size = vfs.stat(id).unwrap().size as usize;
    let mut out = vec![0u8; size];
    let mut off = 0;
    while off < size {
        let n = vfs.read(id, off as u64, &mut out[off..]).unwrap();
        assert!(n > 0);
        off += n;
    }
    out
}

fn check(vfs: &mut Vfs, files: &[(String, Vec<u8>)], region: u64) {
    assert_eq!(vfs.container().header.metadata_size, region);
    for (path, data) in files {
        assert!(get(vfs, path) == *data, "{path} differs");
    }
}

#[test]
fn a_bundle_is_resized_published_and_reopened_with_the_new_layout() {
    let dir = TempDir::new().unwrap();
    let a = Device::new("Laptop");
    let (store, mut files) = bundle(&dir, &a);

    let (mut s, mut vfs) = a.open(&store);
    let len_before = vfs.container_mut().data_file_len().unwrap();
    vfs.resize_metadata_region(8 * MIB).unwrap();
    check(&mut vfs, &files, 8 * MIB);
    assert_eq!(
        vfs.container_mut().data_file_len().unwrap(),
        len_before + 6 * MIB,
        "the data area moved by the growth"
    );
    put(&mut vfs, "after.txt", b"written after the resize");
    files.push(("/after.txt".into(), b"written after the resize".to_vec()));
    vfs.flush().unwrap();
    s.publish().unwrap().expect("a commit");
    drop((vfs, s));

    let (mut s, mut vfs) = a.open(&store);
    check(&mut vfs, &files, 8 * MIB);
    vfs.resize_metadata_region(256 * KIB).unwrap();
    check(&mut vfs, &files, 256 * KIB);
    s.publish().unwrap().expect("a commit");
    drop((vfs, s));

    let (_s, mut vfs) = a.open(&store);
    check(&mut vfs, &files, 256 * KIB);
    assert!(
        vfs.container_mut().data_file_len().unwrap() < len_before,
        "a smaller region gives back the end of the image"
    );
}

/// Saved but not published (the device went away): the next open on
/// that device restores the resized state, and its next publish shares
/// it; other devices see the old layout until then.
#[test]
fn a_resize_saved_but_not_published_comes_back_at_the_next_open() {
    let dir = TempDir::new().unwrap();
    let a = Device::new("Laptop");
    let b = Device::new("Desktop");
    let (store, files) = bundle(&dir, &a);
    let (s, mut vfs) = a.open(&store);
    vfs.resize_metadata_region(4 * MIB).unwrap();
    drop((vfs, s));

    let (_sb, mut vb) = b.open(&store);
    check(&mut vb, &files, 2 * MIB);
    drop((vb, _sb));
    let (mut s, mut vfs) = a.open(&store);
    check(&mut vfs, &files, 4 * MIB);
    s.publish().unwrap().expect("the restored resize");
    drop((vfs, s));
    let (_sb, mut vb) = b.open(&store);
    check(&mut vb, &files, 4 * MIB);
}

/// A resize on one device, a new file on another, published on the old
/// layout: the next open merges both, whichever device opens.
#[test]
fn another_device_s_changes_merge_with_a_resize() {
    for opener in ["Laptop", "Desktop"] {
        let dir = TempDir::new().unwrap();
        let a = Device::new("Laptop");
        let b = Device::new("Desktop");
        let (store, mut files) = bundle(&dir, &a);
        let (mut sa, mut va) = a.open(&store);
        let (mut sb, mut vb) = b.open(&store);
        va.resize_metadata_region(8 * MIB).unwrap();
        put(&mut va, "from-a.txt", b"A, after its resize");
        va.flush().unwrap();
        sa.publish().unwrap().unwrap();
        put(&mut vb, "from-b.txt", b"B, on the old layout");
        vb.flush().unwrap();
        sb.publish().unwrap().unwrap();
        drop((va, vb, sa, sb));
        files.push(("/from-a.txt".into(), b"A, after its resize".to_vec()));
        files.push(("/from-b.txt".into(), b"B, on the old layout".to_vec()));

        let dev = if opener == "Laptop" { &a } else { &b };
        let (s, mut v) = dev.open(&store);
        check(&mut v, &files, 8 * MIB);
        drop((v, s));
        let other = if opener == "Laptop" { &b } else { &a };
        let (_s, mut v) = other.open(&store);
        check(&mut v, &files, 8 * MIB);
    }
}

/// Changes saved offline on the old layout, while another device resized
/// and published: replayed onto the resized commit at the next open.
#[test]
fn offline_changes_on_the_old_layout_are_replayed_onto_a_resized_commit() {
    let dir = TempDir::new().unwrap();
    let a = Device::new("Laptop");
    let b = Device::new("Desktop");
    let (store, mut files) = bundle(&dir, &a);
    let (sb, mut vb) = b.open(&store);
    put(&mut vb, "offline-b.txt", b"saved while offline");
    vb.flush().unwrap();
    drop((vb, sb));

    let (mut sa, mut va) = a.open(&store);
    va.resize_metadata_region(6 * MIB).unwrap();
    sa.publish().unwrap().unwrap();
    drop((va, sa));

    files.push(("/offline-b.txt".into(), b"saved while offline".to_vec()));
    let (_s, mut v) = b.open(&store);
    check(&mut v, &files, 6 * MIB);
}

/// A resize saved offline, while another device added files on the old
/// layout: replayed onto the newer commit, the resize included.
#[test]
fn an_offline_resize_is_replayed_onto_a_newer_commit() {
    let dir = TempDir::new().unwrap();
    let a = Device::new("Laptop");
    let b = Device::new("Desktop");
    let (store, mut files) = bundle(&dir, &a);
    let (sb, mut vb) = b.open(&store);
    vb.resize_metadata_region(6 * MIB).unwrap();
    put(&mut vb, "offline-b.txt", b"saved offline with the resize");
    vb.flush().unwrap();
    drop((vb, sb));

    let (mut sa, mut va) = a.open(&store);
    put(&mut va, "from-a.txt", b"A, old layout");
    va.flush().unwrap();
    sa.publish().unwrap().unwrap();
    drop((va, sa));

    files.push((
        "/offline-b.txt".into(),
        b"saved offline with the resize".to_vec(),
    ));
    files.push(("/from-a.txt".into(), b"A, old layout".to_vec()));
    let (s, mut v) = b.open(&store);
    check(&mut v, &files, 6 * MIB);
    drop((v, s));
    let (_s, mut v) = a.open(&store);
    check(&mut v, &files, 6 * MIB);
}

/// An offline shrink the merged file list no longer fits: the replay keeps
/// the newer commit's region, says so, and loses no file.
#[test]
fn a_shrink_the_merged_file_list_does_not_fit_keeps_the_larger_region() {
    let dir = TempDir::new().unwrap();
    let a = Device::new("Laptop");
    let b = Device::new("Desktop");
    let (store, mut files) = bundle(&dir, &a);
    let (sb, mut vb) = b.open(&store);
    vb.resize_metadata_region(64 * KIB).unwrap();
    put(&mut vb, "offline-b.txt", b"B");
    vb.flush().unwrap();
    drop((vb, sb));

    let (mut sa, mut va) = a.open(&store);
    for i in 0..2000 {
        let name = format!("many-{i:05}.txt");
        put(&mut va, &name, b"x");
        files.push((format!("/{name}"), b"x".to_vec()));
    }
    va.flush().unwrap();
    sa.publish().unwrap().unwrap();
    drop((va, sa));

    files.push(("/offline-b.txt".into(), b"B".to_vec()));
    let (s, mut v, report) = b.open_report(&store);
    check(&mut v, &files, 2 * MIB);
    assert!(
        report
            .keyslot_notes
            .iter()
            .any(|n| n.contains("file list region stays")),
        "{:?}",
        report.keyslot_notes
    );
    drop((v, s));
    let (_s, mut v) = a.open(&store);
    check(&mut v, &files, 2 * MIB);
}

/// The fork rule above never hides a real rollback: once the provider
/// removes the commit that carried the newer header (the resize), the
/// device that made it refuses the bundle.
#[test]
fn a_withheld_resize_commit_is_still_a_rollback() {
    use luksbox_sync::SyncError;
    use luksbox_sync::names::{Area, Name, ObjectId};
    use luksbox_sync::store::ObjectStore;
    let dir = TempDir::new().unwrap();
    let a = Device::new("Laptop");
    let b = Device::new("Desktop");
    let (store, _files) = bundle(&dir, &a);
    let (mut sa, mut va) = a.open(&store);
    let (mut sb, mut vb) = b.open(&store);
    va.resize_metadata_region(4 * MIB).unwrap();
    let resize = sa.publish().unwrap().unwrap();
    put(&mut vb, "from-b.txt", b"B");
    vb.flush().unwrap();
    sb.publish().unwrap().unwrap();
    drop((va, vb, sa, sb));
    store.with(|m| {
        assert!(
            m.remove(Area::Manifest, &Name::Object(ObjectId(resize.oid)))
                .unwrap()
        )
    });
    let l = a.local.clone();
    let opened = Session::open(
        Box::new(store.clone()),
        move |_| Ok(Box::new(l) as Box<dyn LocalStore>),
        PathBuf::from("v.lbxs"),
        &mut UnlockMaterial::Passphrase(PASS),
        &OpenOptions {
            device_label: "Laptop".into(),
            read_only: false,
        },
    );
    match opened {
        Err(SyncError::RollbackDetected { .. }) => {}
        Err(e) => panic!("expected a rollback error, got {e}"),
        Ok(_) => panic!("the withheld resize was not detected"),
    }
}

/// Two different resizes at the same time stay a header fork. The device
/// whose header is newer opens on its own head even when the other head
/// comes first (more commits): it never works on, or publishes over, an
/// older header than one it saw.
#[test]
fn two_different_resizes_stay_a_fork_and_neither_device_goes_back() {
    use luksbox_sync::graph::Notice;
    let dir = TempDir::new().unwrap();
    let a = Device::new("Laptop");
    let b = Device::new("Desktop");
    let (store, files) = bundle(&dir, &a);
    let (mut sa, mut va) = a.open(&store);
    let (mut sb, mut vb) = b.open(&store);
    // A: two header changes in one commit; B: one, then more commits.
    va.resize_metadata_region(8 * MIB).unwrap();
    va.resize_metadata_region(16 * MIB).unwrap();
    sa.publish().unwrap().unwrap();
    vb.resize_metadata_region(4 * MIB).unwrap();
    sb.publish().unwrap().unwrap();
    for i in 0..2 {
        put(&mut vb, &format!("b-{i}.txt"), b"B");
        vb.flush().unwrap();
        sb.publish().unwrap().unwrap();
    }
    drop((va, vb, sa, sb));

    let (s, mut v, r) = a.open_report(&store);
    check(&mut v, &files, 16 * MIB);
    assert!(
        r.notices
            .iter()
            .any(|n| matches!(n, Notice::HeaderFork { .. })),
        "{:?}",
        r.notices
    );
    put(&mut v, "a-after.txt", b"A on its own header");
    v.flush().unwrap();
    drop(v);
    drop(s);
    let (_s, mut v, _) = a.open_report(&store);
    assert_eq!(v.container().header.metadata_size, 16 * MIB);
    assert_eq!(get(&mut v, "/a-after.txt"), b"A on its own header");
    drop((v, _s));
    let (_s, mut v, _) = b.open_report(&store);
    check(&mut v, &files, 4 * MIB);
}

/// More files than the old region holds, added after growing it: merged
/// into a head on the old (smaller) layout, offline or as a fork, from
/// either device. The target grows before the merge (merging into the
/// smaller region failed as "file list full" at every open).
#[test]
fn files_added_after_growing_merge_into_a_head_on_the_smaller_layout() {
    for case in ["offline", "fork-laptop", "fork-desktop"] {
        let dir = TempDir::new().unwrap();
        let a = Device::new("Laptop");
        let b = Device::new("Desktop");
        let (store, mut files) = bundle_with(&dir, &a, 256 * KIB);
        let (mut sb, mut vb) = b.open(&store);
        let (mut sa, mut va) = a.open(&store);
        vb.resize_metadata_region(MIB).unwrap();
        for i in 0..6000 {
            let name = format!("b-{i:05}.txt");
            put(&mut vb, &name, b"b");
            files.push((format!("/{name}"), b"b".to_vec()));
        }
        vb.flush().unwrap();
        if case != "offline" {
            sb.publish().unwrap().unwrap();
        }
        drop((vb, sb));
        put(&mut va, "from-a.txt", b"A, small layout");
        va.flush().unwrap();
        sa.publish().unwrap().unwrap();
        drop((va, sa));
        files.push(("/from-a.txt".into(), b"A, small layout".to_vec()));

        let opener = if case == "fork-laptop" { &a } else { &b };
        let (s, mut v, r) = opener.open_report(&store);
        assert!(r.writable, "{case}: {:?}", r.notices);
        check(&mut v, &files, MIB);
        drop((v, s));
        let other = if case == "fork-laptop" { &b } else { &a };
        let (_s, mut v, _) = other.open_report(&store);
        check(&mut v, &files, MIB);
    }
}

/// After a header fork, finishing a session (lock, unmount) merges the
/// other heads into the head with the newest header this device saw, not
/// into the first head, whose header is older.
#[test]
fn finishing_after_a_header_fork_never_goes_back_to_an_older_header() {
    let dir = TempDir::new().unwrap();
    let a = Device::new("Laptop");
    let b = Device::new("Desktop");
    let c = Device::new("Tablet");
    let (store, mut files) = bundle(&dir, &a);
    let (mut sa, mut va) = a.open(&store);
    let (mut sb, mut vb) = b.open(&store);
    let (mut sc, mut vc) = c.open(&store);
    va.resize_metadata_region(8 * MIB).unwrap();
    va.resize_metadata_region(16 * MIB).unwrap();
    sa.publish().unwrap().unwrap();
    vb.resize_metadata_region(4 * MIB).unwrap();
    sb.publish().unwrap().unwrap();
    for i in 0..2 {
        put(&mut vb, &format!("b-{i}.txt"), b"B");
        vb.flush().unwrap();
        sb.publish().unwrap().unwrap();
    }
    put(&mut vc, "from-c.txt", b"C, base header");
    vc.flush().unwrap();
    sc.publish().unwrap().unwrap();
    drop((va, vb, vc, sa, sb, sc));
    files.push(("/from-c.txt".into(), b"C, base header".to_vec()));

    let (mut s, mut v, _) = a.open_report(&store);
    s.finish(&mut v).unwrap();
    drop((v, s));
    let (_s, mut v, _) = a.open_report(&store);
    check(&mut v, &files, 16 * MIB);
}
