// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Penthertz <https://penthertz.com> (https://x.com/PentHertz)

//! One device working on a sync bundle: convert, open, write, publish,
//! reopen; crash recovery; and the provider attacks a single device can
//! detect (rollback, tampering, revoked credential via an old header).

use std::path::PathBuf;
use std::sync::mpsc;
use std::time::Duration;

use luksbox_core::{Argon2idParams, CipherSuite};
use luksbox_format::{Container, UnlockMaterial};
use luksbox_sync::bundle::{self, ConvertOptions, OpenOptions, OpenReport, Session};
use luksbox_sync::local::{LocalStore, MemLocal};
use luksbox_sync::names::{Area, Name};
use luksbox_sync::store::{Created, LenRule, Listing, ObjectStore, SharedMem};
use luksbox_sync::{Result, SyncError};
use luksbox_vfs::Vfs;
use tempfile::TempDir;

const PASS: &[u8] = b"correct horse battery staple";
const KDF: Argon2idParams = Argon2idParams {
    m_cost_kib: 8,
    t_cost: 1,
    p_cost: 1,
};
/// Smallest allowed page, so a test vault spans many pages.
const PAGE: u32 = 1 << 20;

/// A file vault holding `/a.txt`, converted into an in-memory bundle.
fn converted(dir: &TempDir) -> (SharedMem, MemLocal) {
    let lbx = dir.path().join("v.lbx");
    // A 2 MiB metadata region keeps debug-build tests fast.
    let _g = luksbox_format::metadata::set_create_metadata_region_size_override(Some(2 << 20));
    let c = Container::create_with_passphrase(&lbx, None, CipherSuite::Aes256GcmSiv, KDF, PASS)
        .unwrap();
    let mut vfs = Vfs::open(c).unwrap();
    let id = vfs.create(vfs.root_id(), "a.txt").unwrap();
    vfs.write(id, 0, b"first file").unwrap();
    vfs.flush().unwrap();
    let mut c = vfs.close().unwrap();
    let store = SharedMem::new();
    let local = MemLocal::default();
    let l2 = local.clone();
    bundle::convert(
        &mut c,
        Box::new(store.clone()),
        move |_| Ok(Box::new(l2) as Box<dyn LocalStore>),
        &ConvertOptions {
            page_size: PAGE,
            device_label: "Laptop".into(),
            hybrid_sidecar: None,
        },
    )
    .unwrap();
    (store, local)
}

fn open_with(
    store: &SharedMem,
    local: &MemLocal,
    pass: &[u8],
) -> Result<(Session, Vfs, OpenReport)> {
    let l = local.clone();
    let (s, c, r) = Session::open(
        Box::new(store.clone()),
        move |_| Ok(Box::new(l) as Box<dyn LocalStore>),
        PathBuf::from("v.lbxs"),
        &mut UnlockMaterial::Passphrase(pass),
        &OpenOptions {
            device_label: "Laptop".into(),
            read_only: false,
        },
    )?;
    Ok((s, Vfs::open(c).unwrap(), r))
}

fn open(store: &SharedMem, local: &MemLocal) -> (Session, Vfs, OpenReport) {
    open_with(store, local, PASS).unwrap()
}

fn read(vfs: &mut Vfs, path: &str) -> std::result::Result<Vec<u8>, luksbox_vfs::Error> {
    let id = vfs.lookup_path(path)?;
    let mut buf = vec![0u8; 1 << 16];
    let n = vfs.read(id, 0, &mut buf)?;
    buf.truncate(n);
    Ok(buf)
}

fn write_file(vfs: &mut Vfs, name: &str, data: &[u8]) {
    let root = vfs.root_id();
    let id = match vfs.lookup_path(&format!("/{name}")) {
        Ok(id) => id,
        Err(_) => vfs.create(root, name).unwrap(),
    };
    vfs.write(id, 0, data).unwrap();
}

/// Flush the vault (stages locally) and publish.
fn commit(s: &mut Session, vfs: &mut Vfs) {
    vfs.flush().unwrap();
    s.publish().unwrap().expect("something to publish");
}

fn manifest_names(store: &SharedMem) -> Vec<Name> {
    store.with(|m| m.list(Area::Manifest).unwrap().names)
}

/// A store that holds its first page upload until the test lets it go.
struct GatedStore {
    inner: SharedMem,
    gate: Option<(mpsc::Sender<()>, mpsc::Receiver<()>)>,
}

impl ObjectStore for GatedStore {
    fn list(&mut self, area: Area) -> Result<Listing> {
        self.inner.list(area)
    }
    fn read(&mut self, area: Area, name: &Name, len: LenRule) -> Result<Option<Vec<u8>>> {
        self.inner.read(area, name, len)
    }
    fn create_new(&mut self, area: Area, name: &Name, bytes: &[u8]) -> Result<Created> {
        if area == Area::Page
            && let Some((started, go)) = self.gate.take()
        {
            started.send(()).unwrap();
            // A publish holding the vault's image would block the test's
            // writes, so `go` never comes: time out and let the test fail
            // rather than hang.
            let _ = go.recv_timeout(Duration::from_secs(60));
        }
        self.inner.create_new(area, name, bytes)
    }
    fn remove(&mut self, area: Area, name: &Name) -> Result<bool> {
        self.inner.remove(area, name)
    }
    fn sync(&mut self) -> Result<()> {
        self.inner.sync()
    }
    fn describe(&self) -> String {
        self.inner.describe()
    }
}

#[test]
fn the_vault_works_while_a_publish_uploads() {
    let dir = TempDir::new().unwrap();
    let (store, local) = converted(&dir);
    let (started_tx, started) = mpsc::channel();
    let (go, go_rx) = mpsc::channel();
    let gated = GatedStore {
        inner: store.clone(),
        gate: Some((started_tx, go_rx)),
    };
    let l = local.clone();
    let (s, c, _) = Session::open(
        Box::new(gated),
        move |_| Ok(Box::new(l) as Box<dyn LocalStore>),
        PathBuf::from("v.lbxs"),
        &mut UnlockMaterial::Passphrase(PASS),
        &OpenOptions {
            device_label: "Laptop".into(),
            read_only: false,
        },
    )
    .unwrap();
    let mut vfs = Vfs::open(c).unwrap();
    let start = s.head().m.seq;
    write_file(&mut vfs, "b.txt", b"saved before the upload");
    vfs.flush().unwrap();
    let upload = std::thread::spawn(move || {
        let mut s = s;
        let r = s.publish().map(|c| c.is_some());
        (s, r)
    });
    started.recv().unwrap();
    // Mid-upload: the vault reads, writes and saves.
    assert_eq!(
        read(&mut vfs, "/b.txt").unwrap(),
        b"saved before the upload"
    );
    write_file(&mut vfs, "c.txt", b"written during the upload");
    vfs.flush().unwrap();
    go.send(()).expect("the upload waited for the vault");
    let (mut s, r) = upload.join().unwrap();
    assert!(r.unwrap());
    assert_eq!(s.head().m.seq, start + 1);
    // What was saved meanwhile is the next commit.
    assert!(s.has_unpublished());
    s.publish()
        .unwrap()
        .expect("the change made during the upload");
    drop(vfs);
    drop(s);

    let (s, mut vfs, report) = open(&store, &local);
    assert!(!report.restored_local_changes);
    assert_eq!(s.head().m.seq, start + 2);
    assert_eq!(
        read(&mut vfs, "/b.txt").unwrap(),
        b"saved before the upload"
    );
    assert_eq!(
        read(&mut vfs, "/c.txt").unwrap(),
        b"written during the upload"
    );
}

#[test]
fn convert_open_write_publish_reopen() {
    let dir = TempDir::new().unwrap();
    let (store, local) = converted(&dir);
    let (mut s, mut vfs, report) = open(&store, &local);
    assert!(report.writable);
    assert!(!report.restored_local_changes);
    assert_eq!(read(&mut vfs, "/a.txt").unwrap(), b"first file");
    // Convert writes the vault, then brings its header to format v3.
    let start = s.head().m.seq;
    let manifests_start = manifest_names(&store).len();
    assert_eq!(s.head().m.header.generation, 1);

    write_file(&mut vfs, "b.txt", b"second file");
    commit(&mut s, &mut vfs);
    assert_eq!(s.head().m.seq, start + 1);
    assert!(!s.has_unpublished());
    // Nothing more to publish.
    vfs.flush().unwrap();
    assert!(s.publish().unwrap().is_none());
    drop(vfs);
    drop(s);

    let (s, mut vfs, _) = open(&store, &local);
    assert_eq!(s.head().m.seq, start + 1);
    assert_eq!(read(&mut vfs, "/a.txt").unwrap(), b"first file");
    assert_eq!(read(&mut vfs, "/b.txt").unwrap(), b"second file");
    assert_eq!(manifest_names(&store).len(), manifests_start + 1);
}

#[test]
fn small_change_uploads_few_objects() {
    let dir = TempDir::new().unwrap();
    let (store, local) = converted(&dir);
    let before = store.with(|m| m.object_count());
    let (mut s, mut vfs, _) = open(&store, &local);
    write_file(&mut vfs, "small.txt", b"x");
    commit(&mut s, &mut vfs);
    let added = store.with(|m| m.object_count()) - before;
    // A few data/metadata pages, one table block, one manifest: never
    // the 64 MiB metadata region (64 pages of 1 MiB).
    assert!(added <= 6, "a 1-byte file added {added} objects");
}

#[test]
fn saved_but_unpublished_changes_survive_a_crash() {
    let dir = TempDir::new().unwrap();
    let (store, local) = converted(&dir);
    let before = manifest_names(&store).len();
    {
        let (_s, mut vfs, _) = open(&store, &local);
        write_file(&mut vfs, "draft.txt", b"saved, not uploaded");
        vfs.flush().unwrap();
        // Crash: session and vault dropped without publishing.
    }
    assert_eq!(
        manifest_names(&store).len(),
        before,
        "nothing reached the bundle"
    );
    let (mut s, mut vfs, report) = open(&store, &local);
    assert!(report.restored_local_changes);
    assert!(s.has_unpublished());
    assert_eq!(
        read(&mut vfs, "/draft.txt").unwrap(),
        b"saved, not uploaded"
    );
    s.publish().unwrap().unwrap();
    drop(vfs);
    drop(s);
    let (_s, mut vfs, report) = open(&store, &local);
    assert!(!report.restored_local_changes);
    assert_eq!(
        read(&mut vfs, "/draft.txt").unwrap(),
        b"saved, not uploaded"
    );
}

#[test]
fn crash_while_writing_the_manifest_republishes_the_same_commit() {
    let dir = TempDir::new().unwrap();
    let (store, local) = converted(&dir);
    let before = manifest_names(&store).len();
    let start = open(&store, &local).0.head().m.seq;
    {
        let (mut s, mut vfs, _) = open(&store, &local);
        write_file(&mut vfs, "c.txt", b"almost published");
        vfs.flush().unwrap();
        *store.fail_next_create.lock().unwrap() = Some(Area::Manifest);
        assert!(s.publish().is_err());
    }
    assert_eq!(manifest_names(&store).len(), before);
    // Reopen: the recorded manifest bytes are written, not a new commit.
    let (s, mut vfs, _) = open(&store, &local);
    assert_eq!(s.head().m.seq, start + 1);
    assert_eq!(manifest_names(&store).len(), before + 1);
    assert_eq!(read(&mut vfs, "/c.txt").unwrap(), b"almost published");
}

#[test]
fn rollback_of_the_newest_commit_is_detected() {
    let dir = TempDir::new().unwrap();
    let (store, local) = converted(&dir);
    let start = open(&store, &local).0.head().m.seq;
    {
        let (mut s, mut vfs, _) = open(&store, &local);
        write_file(&mut vfs, "b.txt", b"two");
        commit(&mut s, &mut vfs);
        write_file(&mut vfs, "c.txt", b"three");
        commit(&mut s, &mut vfs);
    }
    // The provider restores the bundle to before commit 3 by removing
    // the newest manifest.
    let newest = {
        let (s, _vfs, _) = open(&store, &local);
        Name::Object(luksbox_sync::names::ObjectId(s.head().as_ref().oid))
    };
    store.with(|m| assert!(m.remove(Area::Manifest, &newest).unwrap()));
    match open_with(&store, &local, PASS) {
        Err(SyncError::RollbackDetected { seen, visible, .. }) => {
            assert_eq!((seen, visible), (start + 2, start + 1));
        }
        Err(e) => panic!("expected a rollback error, got {e}"),
        Ok(_) => panic!("rollback was not detected"),
    }
}

#[test]
fn tampered_or_swapped_objects_are_refused() {
    let dir = TempDir::new().unwrap();
    let (store, local) = converted(&dir);
    // Flip one byte in every page object: any read of the vault fails.
    store.with(|m| {
        for ((area, _, _), bytes) in m.raw_mut().iter_mut() {
            if *area == Area::Page {
                let i = bytes.len() / 2;
                bytes[i] ^= 0x40;
            }
        }
    });
    // The session opens (it checks that every object is present); the
    // first read of the vault, here its metadata, fails authentication.
    let l = local.clone();
    let (_s, c, _) = Session::open(
        Box::new(store.clone()),
        move |_| Ok(Box::new(l) as Box<dyn LocalStore>),
        PathBuf::from("v.lbxs"),
        &mut UnlockMaterial::Passphrase(PASS),
        &OpenOptions::default(),
    )
    .unwrap();
    assert!(Vfs::open(c).is_err(), "a vault with tampered pages opened");
}

#[test]
fn table_blocks_swapped_between_commits_are_refused() {
    let dir = TempDir::new().unwrap();
    let (store, local) = converted(&dir);
    // Replace a manifest's table block bytes with another valid table
    // block of the same bundle: the hash in the manifest no longer
    // matches.
    let (mut s, mut vfs, _) = open(&store, &local);
    write_file(&mut vfs, "b.txt", b"two");
    commit(&mut s, &mut vfs);
    let head_tables = s.head().m.tables.clone();
    drop(vfs);
    drop(s);
    store.with(|m| {
        let raw = m.raw_mut();
        let tables: Vec<_> = raw
            .keys()
            .filter(|(a, _, _)| *a == Area::Table)
            .cloned()
            .collect();
        assert!(tables.len() >= 2);
        let target = tables
            .iter()
            .find(|(_, _, leaf)| *leaf == luksbox_sync::names::to_hex(&head_tables[0].oid))
            .unwrap()
            .clone();
        let other = tables.iter().find(|k| **k != target).unwrap().clone();
        let bytes = raw[&other].clone();
        raw.insert(target, bytes);
    });
    assert!(open_with(&store, &local, PASS).is_err());
}

#[test]
fn foreign_files_are_ignored_and_counted() {
    let dir = TempDir::new().unwrap();
    let (store, local) = converted(&dir);
    store.with(|m| {
        m.plant(
            Area::Page,
            "ab",
            "notes (conflicted copy).txt",
            b"x".to_vec(),
        );
        m.plant(Area::Manifest, "", ".DS_Store", b"x".to_vec());
    });
    let (_s, mut vfs, report) = open(&store, &local);
    assert_eq!(
        report.foreign_entries, 1,
        "manifest-area foreign entries are counted"
    );
    assert_eq!(read(&mut vfs, "/a.txt").unwrap(), b"first file");
    // Foreign files are never deleted.
    assert_eq!(
        store.with(|m| m
            .raw_mut()
            .keys()
            .filter(|k| k.2.contains("conflicted"))
            .count()),
        1
    );
}

#[test]
fn revoked_credential_cannot_open_through_an_old_header() {
    let dir = TempDir::new().unwrap();
    let (store, local) = converted(&dir);
    let other: &[u8] = b"second passphrase";
    {
        let (mut s, mut vfs, _) = open(&store, &local);
        vfs.container_mut().enroll_passphrase(other, KDF).unwrap();
        vfs.container_mut().persist_header().unwrap();
        commit_header(&mut s, &mut vfs);
    }
    {
        // Open with the new passphrase and revoke the original one.
        let (mut s, mut vfs, _) = open_with(&store, &local, other).unwrap();
        vfs.container_mut().revoke_slot(0).unwrap();
        vfs.container_mut().persist_header().unwrap();
        commit_header(&mut s, &mut vfs);
    }
    // Old header objects are still in the bundle (as a provider could
    // keep or restore them), yet the original passphrase is refused.
    assert!(store.with(|m| m.raw_mut().keys().filter(|k| k.0 == Area::Header).count()) >= 3);
    match open_with(&store, &local, PASS) {
        Err(SyncError::CredentialRevoked { .. }) => {}
        Err(e) => panic!("expected CredentialRevoked, got {e}"),
        Ok(_) => panic!("a revoked passphrase opened the bundle"),
    }
    let (_s, mut vfs, _) = open_with(&store, &local, other).unwrap();
    assert_eq!(read(&mut vfs, "/a.txt").unwrap(), b"first file");
}

fn commit_header(s: &mut Session, vfs: &mut Vfs) {
    vfs.flush().unwrap();
    s.publish().unwrap().expect("header change published");
}

#[test]
fn read_only_open_never_stages_or_publishes() {
    let dir = TempDir::new().unwrap();
    let (store, local) = converted(&dir);
    let before = store.with(|m| m.object_count());
    let l = local.clone();
    let (mut s, c, report) = Session::open(
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
    assert!(!report.writable);
    let mut vfs = Vfs::open(c).unwrap();
    assert_eq!(read(&mut vfs, "/a.txt").unwrap(), b"first file");
    let root = vfs.root_id();
    assert!(vfs.create(root, "x").is_err());
    vfs.flush().unwrap();
    assert!(matches!(s.publish(), Err(SyncError::ReadOnly)));
    drop(vfs);
    assert_eq!(store.with(|m| m.object_count()), before);
}

#[cfg(unix)]
#[test]
fn file_system_bundle_round_trip_and_export() {
    let dir = TempDir::new().unwrap();
    let lbx = dir.path().join("v.lbx");
    let _g = luksbox_format::metadata::set_create_metadata_region_size_override(Some(2 << 20));
    let c = Container::create_with_passphrase(&lbx, None, CipherSuite::Aes256GcmSiv, KDF, PASS)
        .unwrap();
    let mut vfs = Vfs::open(c).unwrap();
    let id = vfs.create(vfs.root_id(), "a.txt").unwrap();
    vfs.write(id, 0, b"on disk").unwrap();
    vfs.flush().unwrap();
    let mut c = vfs.close().unwrap();
    let bundle_path = dir.path().join("v.lbxs");
    let local_root = dir.path().join("state");
    bundle::fs::convert(
        &mut c,
        &bundle_path,
        &local_root,
        &ConvertOptions {
            page_size: PAGE,
            device_label: "Laptop".into(),
            hybrid_sidecar: None,
        },
    )
    .unwrap();
    drop(c);
    for sub in ["h", "x", "p", "t", "m", "l"] {
        assert!(bundle_path.join(sub).is_dir());
    }

    let (mut s, c, report) = bundle::fs::open(
        &bundle_path,
        &local_root,
        &mut UnlockMaterial::Passphrase(PASS),
        &OpenOptions::default(),
    )
    .unwrap();
    assert!(report.writable);
    let mut vfs = Vfs::open(c).unwrap();
    assert_eq!(read(&mut vfs, "/a.txt").unwrap(), b"on disk");
    write_file(&mut vfs, "b.txt", b"published to the folder");
    vfs.flush().unwrap();
    s.publish().unwrap().unwrap();

    // Export back to a single file, then open it as a normal vault.
    let out = dir.path().join("exported.lbx");
    bundle::export(vfs.container_mut(), &out).unwrap();
    drop(vfs);
    drop(s);
    let c = Container::open(&out, None, UnlockMaterial::Passphrase(PASS)).unwrap();
    let mut vfs = Vfs::open(c).unwrap();
    assert_eq!(read(&mut vfs, "/a.txt").unwrap(), b"on disk");
    assert_eq!(
        read(&mut vfs, "/b.txt").unwrap(),
        b"published to the folder"
    );
    drop(vfs);

    // The folder now replaced by another bundle at the same path is
    // reported, not silently trusted.
    std::fs::rename(&bundle_path, dir.path().join("moved.lbxs")).unwrap();
    let c = Container::open(&lbx, None, UnlockMaterial::Passphrase(PASS)).unwrap();
    let mut c = c;
    bundle::fs::convert(
        &mut c,
        &bundle_path,
        &dir.path().join("state2"),
        &ConvertOptions {
            page_size: PAGE,
            device_label: "Other".into(),
            hybrid_sidecar: None,
        },
    )
    .unwrap();
    drop(c);
    match bundle::fs::open(
        &bundle_path,
        &local_root,
        &mut UnlockMaterial::Passphrase(PASS),
        &OpenOptions::default(),
    ) {
        Err(SyncError::BundleReplaced) => {}
        Err(e) => panic!("expected BundleReplaced, got {e}"),
        Ok(_) => panic!("a replaced bundle was trusted"),
    }
}

/// Deleting a bundle removes its objects and this device's state for
/// it (unpublished changes included), keeps files that are not part of
/// it, and can be run again after the user cleaned those up.
#[cfg(unix)]
#[test]
fn deleting_a_bundle_keeps_foreign_files_and_local_state_goes() {
    let dir = TempDir::new().unwrap();
    let lbx = dir.path().join("v.lbx");
    let _g = luksbox_format::metadata::set_create_metadata_region_size_override(Some(2 << 20));
    let c = Container::create_with_passphrase(&lbx, None, CipherSuite::Aes256GcmSiv, KDF, PASS)
        .unwrap();
    let mut c = Vfs::open(c).unwrap().close().unwrap();
    let bundle_path = dir.path().join("v.lbxs");
    let local_root = dir.path().join("state");
    let bid = bundle::fs::convert(
        &mut c,
        &bundle_path,
        &local_root,
        &ConvertOptions {
            page_size: PAGE,
            device_label: "Laptop".into(),
            hybrid_sidecar: None,
        },
    )
    .unwrap();
    drop(c);
    let (mut s, c, _) = bundle::fs::open(
        &bundle_path,
        &local_root,
        &mut UnlockMaterial::Passphrase(PASS),
        &OpenOptions::default(),
    )
    .unwrap();
    let mut vfs = Vfs::open(c).unwrap();
    write_file(&mut vfs, "a.txt", b"published");
    vfs.flush().unwrap();
    s.publish().unwrap().unwrap();
    // Saved on this device, never published.
    write_file(&mut vfs, "b.txt", b"only here");
    vfs.flush().unwrap();
    drop(vfs);
    drop(s);
    let local_dir = local_root.join(bid.to_hex());
    assert!(local_dir.is_dir());
    assert_eq!(
        std::fs::read_dir(local_root.join("paths")).unwrap().count(),
        1
    );

    // Not the bundle's: a file the user put inside it. Ours: a temporary
    // file an interrupted write left.
    std::fs::write(bundle_path.join("p/notes.txt"), b"mine").unwrap();
    std::fs::write(
        bundle_path.join("h/.tmp-00112233445566778899aabbccddeeff"),
        b"x",
    )
    .unwrap();

    let r = bundle::fs::delete(&bundle_path, &local_root).unwrap();
    assert!(r.objects > 5, "{r:?}");
    assert_eq!(r.foreign, 1, "{r:?}");
    assert!(!r.folder_removed);
    assert!(!bundle::fs::is_bundle(&bundle_path));
    assert_eq!(
        std::fs::read(bundle_path.join("p/notes.txt")).unwrap(),
        b"mine"
    );
    assert!(!local_dir.exists());
    assert_eq!(
        std::fs::read_dir(local_root.join("paths")).unwrap().count(),
        0
    );
    let left: Vec<_> = std::fs::read_dir(&bundle_path)
        .unwrap()
        .map(|e| e.unwrap().file_name())
        .collect();
    assert_eq!(left, vec![std::ffi::OsString::from("p")]);

    // The user moved their file out: deleting again removes the folder.
    std::fs::remove_file(bundle_path.join("p/notes.txt")).unwrap();
    let r = bundle::fs::delete(&bundle_path, &local_root).unwrap();
    assert_eq!(r.objects, 0);
    assert!(r.folder_removed);
    assert!(!bundle_path.exists());
}

/// A file or folder copied back from an earlier version lands next to
/// the original under a dated name, with that version's contents;
/// nothing in the vault is replaced.
#[test]
fn restoring_from_an_earlier_version_adds_a_dated_copy() {
    let dir = TempDir::new().unwrap();
    let (store, local) = converted(&dir);
    let (mut s, mut vfs, _) = open(&store, &local);
    let root = vfs.root_id();
    let d = vfs.mkdir(root, "docs").unwrap();
    let x = vfs.create(d, "x.txt").unwrap();
    vfs.write(x, 0, b"in a folder").unwrap();
    write_file(&mut vfs, "r.txt", b"old r");
    commit(&mut s, &mut vfs);
    let old = s.head().hash;
    write_file(&mut vfs, "r.txt", b"new r");
    commit(&mut s, &mut vfs);

    let snap = s
        .snapshots()
        .unwrap()
        .into_iter()
        .find(|v| v.hash == old)
        .expect("the older version is listed");
    let mut view = s.snapshot_view(&snap.hash).unwrap();

    let to = luksbox_sync::gc::restore_path(&mut view, &mut vfs, "/r.txt").unwrap();
    assert!(
        to.starts_with("/r (restored ") && to.ends_with(").txt"),
        "{to}"
    );
    // "(restored YYYY-MM-DD HHMM)": a date, not a raw number.
    let when = &to["/r (restored ".len()..to.len() - ").txt".len()];
    assert_eq!(when.len(), "2026-10-14 1532".len(), "{to}");
    assert_eq!(read(&mut vfs, &to).unwrap(), b"old r");
    assert_eq!(read(&mut vfs, "/r.txt").unwrap(), b"new r");
    // Again: a second copy, the first one kept.
    let again = luksbox_sync::gc::restore_path(&mut view, &mut vfs, "/r.txt").unwrap();
    assert_ne!(again, to);
    assert_eq!(read(&mut vfs, &to).unwrap(), b"old r");

    let folder = luksbox_sync::gc::restore_path(&mut view, &mut vfs, "/docs").unwrap();
    assert_eq!(
        read(&mut vfs, &format!("{folder}/x.txt")).unwrap(),
        b"in a folder"
    );
    assert!(luksbox_sync::gc::restore_path(&mut view, &mut vfs, "/").is_err());
    assert!(luksbox_sync::gc::restore_path(&mut view, &mut vfs, "/nope.txt").is_err());
}

/// A bundle this device has just made from an unlocked vault opens with
/// that vault's master key, without asking for the credential again;
/// another vault's key opens nothing. Changes made in that session
/// publish and open with the passphrase as usual.
#[test]
fn a_new_bundle_opens_with_the_key_of_the_vault_it_came_from() {
    let dir = TempDir::new().unwrap();
    let _g = luksbox_format::metadata::set_create_metadata_region_size_override(Some(2 << 20));
    let new = |name: &str| {
        Container::create_with_passphrase(
            &dir.path().join(name),
            None,
            CipherSuite::Aes256GcmSiv,
            KDF,
            PASS,
        )
        .unwrap()
    };
    let mut c = Vfs::open(new("v.lbx")).unwrap().close().unwrap();
    let mvk = c.mvk_clone();
    let other = new("other.lbx").mvk_clone();
    let store = SharedMem::new();
    let local = MemLocal::default();
    let l2 = local.clone();
    bundle::convert(
        &mut c,
        Box::new(store.clone()),
        move |_| Ok(Box::new(l2) as Box<dyn LocalStore>),
        &ConvertOptions {
            page_size: PAGE,
            device_label: "Laptop".into(),
            hybrid_sidecar: None,
        },
    )
    .unwrap();
    drop(c);
    let with_key = |key| {
        let l = local.clone();
        Session::open_with_key(
            Box::new(store.clone()),
            move |_| Ok(Box::new(l) as Box<dyn LocalStore>),
            PathBuf::from("v.lbxs"),
            key,
            &OpenOptions {
                device_label: "Laptop".into(),
                read_only: false,
            },
        )
    };

    assert!(with_key(&other).is_err());
    let (mut s, c, report) = with_key(&mvk).unwrap();
    assert!(report.writable);
    let mut vfs = Vfs::open(c).unwrap();
    write_file(&mut vfs, "k.txt", b"made right after creating");
    commit(&mut s, &mut vfs);
    drop(vfs);
    drop(s);

    let (_s, mut vfs, _) = open(&store, &local);
    assert_eq!(
        read(&mut vfs, "/k.txt").unwrap(),
        b"made right after creating"
    );
}
