// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Penthertz <https://penthertz.com> (https://x.com/PentHertz)

//! Round 16 regressions for sync bundles: what a faulty or hostile sync
//! service can do to a bundle, and what must still hold for the user's
//! data. See `docs/SECURITY_AUDIT_ROUND_16.md`.
//!
//! ```bash
//! cargo test --test round16_findings -p luksbox-sync
//! ```

use std::collections::HashSet;
use std::path::PathBuf;

use luksbox_core::{Argon2idParams, CipherSuite};
use luksbox_format::{Container, UnlockMaterial};
use luksbox_sync::bundle::{
    self, ConvertOptions, MAX_HEADER_OBJECTS, MAX_LEASES, OpenOptions, OpenReport, Session,
};
use luksbox_sync::gc::GcOptions;
use luksbox_sync::graph::Notice;
use luksbox_sync::local::{LocalStore, MemLocal};
use luksbox_sync::names::{Area, HeaderName, Name, ObjectId};
use luksbox_sync::store::{LenRule, ObjectStore, SharedMem};
use luksbox_sync::{Result, SyncError};
use luksbox_vfs::Vfs;
use tempfile::TempDir;

const PASS: &[u8] = b"correct horse battery staple";
const KDF: Argon2idParams = Argon2idParams {
    m_cost_kib: 8,
    t_cost: 1,
    p_cost: 1,
};
const PAGE: u32 = 1 << 20;

/// A file vault holding `/a.txt`, converted into an in-memory bundle.
fn converted(dir: &TempDir) -> (SharedMem, MemLocal) {
    let lbx = dir.path().join("v.lbx");
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

fn open_raw(
    store: &SharedMem,
    local: &MemLocal,
    read_only: bool,
) -> Result<(Session, Container, OpenReport)> {
    let l = local.clone();
    Session::open(
        Box::new(store.clone()),
        move |_| Ok(Box::new(l) as Box<dyn LocalStore>),
        PathBuf::from("v.lbxs"),
        &mut UnlockMaterial::Passphrase(PASS),
        &OpenOptions {
            device_label: "Laptop".into(),
            read_only,
        },
    )
}

fn open_as(
    store: &SharedMem,
    local: &MemLocal,
    read_only: bool,
) -> Result<(Session, Vfs, OpenReport)> {
    let (s, c, r) = open_raw(store, local, read_only)?;
    let vfs = if read_only {
        Vfs::open_read_only(c).unwrap()
    } else {
        Vfs::open(c).unwrap()
    };
    Ok((s, vfs, r))
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
    vfs.truncate(id, 0).unwrap();
    vfs.write(id, 0, data).unwrap();
}

/// Flush the vault (stages locally) and publish.
fn commit(s: &mut Session, vfs: &mut Vfs) {
    vfs.flush().unwrap();
    s.publish().unwrap().expect("something to publish");
}

fn page_names(store: &SharedMem) -> HashSet<Name> {
    store.with(|m| m.list(Area::Page).unwrap().names.into_iter().collect())
}

fn export_to(c: &mut Container, dest: &std::path::Path) -> Vfs {
    bundle::export(c, dest).unwrap();
    Vfs::open(Container::open(dest, None, UnlockMaterial::Passphrase(PASS)).unwrap()).unwrap()
}

// ---------------------------------------------------------------------
// R16-03: a head whose objects had not all arrived made the session
// read-only, always, even with another complete head to work on. A
// device that died mid-upload (or a provider withholding one object)
// therefore locked every device read-only for good: nobody could publish
// a commit outranking the stuck head.
// ---------------------------------------------------------------------

#[test]
fn r16_03_an_incomplete_head_is_skipped_so_the_bundle_stays_writable() {
    let dir = TempDir::new().unwrap();
    let (store, local_a) = converted(&dir);

    // Two concurrent commits on the first one: a fork with two heads.
    let local_b = MemLocal::default();
    let (mut sa, mut va, _) = open_as(&store, &local_a, false).unwrap();
    let (mut sb, mut vb, _) = open_as(&store, &local_b, false).unwrap();
    write_file(&mut va, "from-a.txt", b"A");
    write_file(&mut vb, "from-b.txt", b"B");
    commit(&mut sb, &mut vb);
    commit(&mut sa, &mut va);
    drop((va, sa, vb, sb));

    // Which head would every device pick first? Look without merging,
    // from a probe device: a device that has seen that head never goes
    // back to an older or concurrent state without it (checked below).
    let local_probe = MemLocal::default();
    let local_c = MemLocal::default();
    let (sc, vc, r) = open_as(&store, &local_probe, true).unwrap();
    assert_eq!(r.other_heads, 1, "{:?}", r.notices);
    let first = sc.head().clone();
    let other = sc
        .snapshots()
        .unwrap()
        .into_iter()
        .find(|s| s.lamport == first.m.lamport && s.hash != first.hash)
        .expect("the other head")
        .hash;
    drop((vc, sc));

    // The sync service never delivers one table block of that head.
    let doomed = Name::Object(first.m.tables[0].object_id());
    let bytes = store
        .with(|m| {
            m.read(Area::Table, &doomed, LenRule::AtMost(1 << 20))
                .unwrap()
        })
        .expect("the table block exists");
    assert!(store.with(|m| m.remove(Area::Table, &doomed).unwrap()));

    // The probe saw `first`: it refuses to open writable without it
    // (opening `other` would show a vault without what it saw), and a
    // read-only look says it is older than what it saw.
    assert!(matches!(
        open_as(&store, &local_probe, false),
        Err(SyncError::NewestIncomplete { .. })
    ));
    {
        let (_s, _v, r) = open_as(&store, &local_probe, true).unwrap();
        assert!(
            r.notices.contains(&Notice::OlderThanSeen),
            "{:?}",
            r.notices
        );
    }

    // Before R16-03: read-only, head = the convert commit, forever. A
    // device that never saw `first` complete opens `other`, writable.
    let (mut sc, mut vc, r) = open_as(&store, &local_c, false).unwrap();
    assert!(r.writable, "a complete head exists: {:?}", r.notices);
    assert_eq!(sc.head().hash, other, "the first complete head is used");
    assert!(
        r.notices
            .iter()
            .any(|n| matches!(n, Notice::Pending { count: 1 })),
        "the skipped head is reported: {:?}",
        r.notices
    );
    write_file(&mut vc, "from-c.txt", b"C");
    commit(&mut sc, &mut vc);
    drop((vc, sc));

    // Once the object arrives, the pending head is merged in like any
    // concurrent commit: nothing was lost on either side.
    store.with(|m| m.create_new(Area::Table, &doomed, &bytes).unwrap());
    let (sc, mut vc, r) = open_as(&store, &local_c, false).unwrap();
    assert!(r.writable);
    for (path, content) in [
        ("/a.txt", &b"first file"[..]),
        ("/from-a.txt", b"A"),
        ("/from-b.txt", b"B"),
        ("/from-c.txt", b"C"),
    ] {
        assert_eq!(read(&mut vc, path).unwrap(), content, "{path}");
    }
    drop((vc, sc));
}

/// When no head is complete, the newest complete ancestor still opens
/// read-only (the behaviour the design asks for while objects arrive).
#[test]
fn r16_03_with_no_complete_head_the_newest_complete_ancestor_opens_read_only() {
    let dir = TempDir::new().unwrap();
    let (store, _local_a) = converted(&dir);
    let local_b = MemLocal::default();
    let (mut sb, mut vb, _) = open_as(&store, &local_b, false).unwrap();
    write_file(&mut vb, "b.txt", b"B");
    commit(&mut sb, &mut vb);
    let b1 = sb.head().clone();
    drop((vb, sb));
    assert!(store.with(|m| {
        m.remove(Area::Table, &Name::Object(b1.m.tables[0].object_id()))
            .unwrap()
    }));

    let (sc, mut vc, r) = open_as(&store, &MemLocal::default(), false).unwrap();
    assert!(
        !r.writable,
        "head #{} by {} kind {:?}, notices {:?}, other heads {}",
        sc.head().m.seq,
        sc.head().m.device_label,
        sc.head().m.kind,
        r.notices,
        r.other_heads
    );
    // The newest complete ancestor: the commit B1 was made on (convert
    // publishes two: the vault, then its header upgrade).
    assert_eq!(sc.head().hash, b1.m.parents[0].hash);
    assert!(
        r.notices
            .iter()
            .any(|n| matches!(n, Notice::Pending { .. }))
    );
    assert_eq!(read(&mut vc, "/a.txt").unwrap(), b"first file");
    assert!(read(&mut vc, "/b.txt").is_err());
}

// ---------------------------------------------------------------------
// R16-04: a session that could not publish (opened read-only, or a
// commit another device saw was missing) silently showed the vault
// WITHOUT the changes this device had saved and never published, and
// reported none; an export from it lost them, and a user who then gave
// up on the bundle lost them for good.
// ---------------------------------------------------------------------

#[test]
fn r16_04_a_read_only_session_shows_reports_and_exports_unpublished_changes() {
    let dir = TempDir::new().unwrap();
    let (store, local) = converted(&dir);
    {
        // Saved on this device, never published (the process ended
        // before the upload: battery, crash, no network).
        let (sa, mut va, _) = open_as(&store, &local, false).unwrap();
        write_file(&mut va, "local.txt", b"saved here, not uploaded");
        va.flush().unwrap();
        drop((va, sa));
    }
    let before = page_names(&store);

    let (s, mut v, r) = open_as(&store, &local, true).unwrap();
    assert!(!r.writable);
    assert!(r.restored_local_changes, "{:?}", r.notices);
    assert!(
        r.notices
            .contains(&Notice::UnpublishedLocalChanges { shown: true }),
        "{:?}",
        r.notices
    );
    assert!(s.has_unpublished());
    assert_eq!(
        read(&mut v, "/local.txt").unwrap(),
        b"saved here, not uploaded"
    );
    assert!(v.is_read_only());
    // An export from the read-only session carries them.
    let dest = dir.path().join("rescue.lbx");
    let mut c = v.close().unwrap();
    let mut exported = export_to(&mut c, &dest);
    assert_eq!(
        read(&mut exported, "/local.txt").unwrap(),
        b"saved here, not uploaded"
    );
    drop((exported, c, s));
    // Nothing left the device: the read-only session staged and
    // published nothing.
    assert_eq!(page_names(&store), before);

    // A writable session still restores and publishes them as before.
    let (mut s, mut v, r) = open_as(&store, &local, false).unwrap();
    assert!(r.writable && r.restored_local_changes);
    assert!(
        !r.notices
            .iter()
            .any(|n| matches!(n, Notice::UnpublishedLocalChanges { .. }))
    );
    assert_eq!(
        read(&mut v, "/local.txt").unwrap(),
        b"saved here, not uploaded"
    );
    s.publish().unwrap().expect("published");
    assert!(!s.has_unpublished());
}

/// Saved on an older commit: a read-only session cannot replay them and
/// says so, instead of nothing.
#[test]
fn r16_04_unpublished_changes_on_an_older_commit_are_reported_by_a_read_only_session() {
    let dir = TempDir::new().unwrap();
    let (store, local_a) = converted(&dir);
    {
        let (sa, mut va, _) = open_as(&store, &local_a, false).unwrap();
        write_file(&mut va, "local.txt", b"A's unpublished change");
        va.flush().unwrap();
        drop((va, sa));
    }
    // Another device publishes meanwhile.
    let (mut sb, mut vb, _) = open_as(&store, &MemLocal::default(), false).unwrap();
    write_file(&mut vb, "b.txt", b"B");
    commit(&mut sb, &mut vb);
    drop((vb, sb));

    let (s, _v, r) = open_as(&store, &local_a, true).unwrap();
    assert!(
        r.notices
            .contains(&Notice::UnpublishedLocalChanges { shown: false }),
        "{:?}",
        r.notices
    );
    drop((_v, s));
    // And a writable open replays them onto the newer commit.
    let (_s, mut v, r) = open_as(&store, &local_a, false).unwrap();
    assert!(r.restored_local_changes);
    assert_eq!(
        read(&mut v, "/local.txt").unwrap(),
        b"A's unpublished change"
    );
    assert_eq!(read(&mut v, "/b.txt").unwrap(), b"B");
}

// ---------------------------------------------------------------------
// R16-05: every well-named header object in the folder was read into
// memory (and tried with the credential) before anything else: a flood
// of them was a memory / Argon2 denial of service by the provider.
// ---------------------------------------------------------------------

#[test]
fn r16_05_too_many_header_objects_are_refused_before_being_read() {
    let dir = TempDir::new().unwrap();
    let (store, local) = converted(&dir);
    let bid = {
        let (s, _c, _r) = open_raw(&store, &local, true).unwrap();
        s.bundle_id()
    };
    store.with(|m| {
        for _ in 0..MAX_HEADER_OBJECTS {
            let n = HeaderName::new(bid, 0).unwrap();
            m.plant(Area::Header, "", &n.to_name(), vec![0u8; 8192]);
        }
    });
    assert!(matches!(
        open_raw(&store, &local, true),
        Err(SyncError::Limit(_))
    ));
}

// ---------------------------------------------------------------------
// R16-06: garbage collection looked at the first 1000 leases only. A pin
// past that cap (the base of an offline device's work) was ignored, and
// its commit was collectable.
// ---------------------------------------------------------------------

#[test]
fn r16_06_gc_refuses_a_flooded_lease_folder_instead_of_ignoring_pins() {
    let dir = TempDir::new().unwrap();
    let (store, local) = converted(&dir);
    let (mut s, _v, _r) = open_as(&store, &local, false).unwrap();
    store.with(|m| {
        for _ in 0..=MAX_LEASES {
            let o = ObjectId::random().unwrap();
            m.plant(Area::Lease, "", &o.to_hex(), vec![0u8; 4096]);
        }
    });
    assert!(matches!(
        s.gc(&GcOptions::default()),
        Err(SyncError::Limit(_))
    ));
}

// ---------------------------------------------------------------------
// R16-07: a manifest may list 256 devices in `seen`; the 257th device to
// publish produced a manifest every reader rejected as malformed, and
// then read its own absence as a rollback. Now the list is capped before
// sealing and a manifest is validated before it is published.
// ---------------------------------------------------------------------

#[test]
fn r16_07_many_device_identities_do_not_brick_the_bundle() {
    // 258 devices, each opening and publishing, take several minutes in
    // a debug build (the unit test `more_devices_than_a_manifest_holds_
    // keep_the_most_active` pins the cap itself, and every publish
    // validates its manifest first). The end-to-end run is for
    // `LUKSBOX_SLOW_TESTS=1` (nightly); otherwise a short run of the
    // same loop keeps the path exercised.
    let devices = if std::env::var_os("LUKSBOX_SLOW_TESTS").is_some() {
        luksbox_sync::manifest::MAX_DEVICES + 2
    } else {
        eprintln!("[skip] full 258-device run: set LUKSBOX_SLOW_TESTS=1 (running 4 devices)");
        4
    };
    let dir = TempDir::new().unwrap();
    let (store, _local_a) = converted(&dir);
    let mut last = MemLocal::default();
    for i in 0..devices {
        let local = MemLocal::default();
        let (mut s, mut v, r) = open_as(&store, &local, false).unwrap();
        assert!(r.writable, "device {i}: {:?}", r.notices);
        write_file(&mut v, "n.txt", i.to_string().as_bytes());
        commit(&mut s, &mut v);
        assert!(s.head().m.seen.len() <= luksbox_sync::manifest::MAX_DEVICES);
        drop((v, s));
        last = local;
    }
    // The last device's commit is the head everyone sees, and it opens
    // its own state without a rollback error.
    let (s, mut v, r) = open_as(&store, &last, false).unwrap();
    assert!(r.writable, "{:?}", r.notices);
    assert_eq!(
        read(&mut v, "/n.txt").unwrap(),
        (devices - 1).to_string().as_bytes()
    );
    drop((v, s));
}

// ---------------------------------------------------------------------
// R16-08: a publish that failed in a background mount wrote its error to
// /dev/null; the user believed the changes were uploaded. The failure is
// now kept on the device until a publish succeeds.
// ---------------------------------------------------------------------

#[test]
fn r16_08_a_failed_publish_is_remembered_until_one_succeeds() {
    let dir = TempDir::new().unwrap();
    let (store, local) = converted(&dir);
    {
        let (mut s, mut v, _) = open_as(&store, &local, false).unwrap();
        assert!(s.last_publish_error().unwrap().is_none());
        write_file(&mut v, "x.txt", b"x");
        v.flush().unwrap();
        *store.fail_next_create.lock().unwrap() = Some(Area::Page);
        assert!(s.publish().is_err());
        let e = s.last_publish_error().unwrap().expect("recorded");
        assert!(e.contains("injected failure"), "{e}");
        drop((v, s));
    }
    // Still there at the next open (the mount that failed is gone).
    let (mut s, mut v, r) = open_as(&store, &local, false).unwrap();
    assert!(r.restored_local_changes);
    assert!(s.last_publish_error().unwrap().is_some());
    assert_eq!(read(&mut v, "/x.txt").unwrap(), b"x");
    s.publish().unwrap().expect("published");
    assert!(s.last_publish_error().unwrap().is_none());
}

// ---------------------------------------------------------------------
// R16-09: only the innermost per-device state folder was made private;
// the folders on the way took the umask, so another account on the
// machine could list which bundles this one uses.
// ---------------------------------------------------------------------

#[cfg(unix)]
#[test]
fn r16_09_every_local_state_folder_created_is_private() {
    use std::os::unix::fs::PermissionsExt;
    let dir = TempDir::new().unwrap();
    let root = dir.path().join("share").join("luksbox").join("sync");
    let _l = luksbox_sync::local::FsLocal::open(&root.join("abc")).unwrap();
    let mode = |p: &std::path::Path| std::fs::metadata(p).unwrap().permissions().mode() & 0o777;
    for p in [
        dir.path().join("share"),
        dir.path().join("share").join("luksbox"),
        root.clone(),
        root.join("abc"),
    ] {
        assert_eq!(mode(&p), 0o700, "{}", p.display());
    }
    assert_eq!(mode(&root.join("abc").join("lock")), 0o600);
}

// ---------------------------------------------------------------------
// Data safety under a faulty sync: when the newest commit's objects are
// all present but one is damaged, the vault does not open through the
// head; an earlier snapshot can still be exported to a `.lbx`.
// ---------------------------------------------------------------------

#[test]
fn an_earlier_snapshot_can_be_exported_when_the_head_is_damaged() {
    let dir = TempDir::new().unwrap();
    let (store, local) = converted(&dir);
    let before = page_names(&store);
    let first = {
        let (s, _c, _r) = open_raw(&store, &local, true).unwrap();
        s.head().hash
    };
    {
        let (mut s, mut v, _) = open_as(&store, &local, false).unwrap();
        write_file(&mut v, "a.txt", b"changed");
        commit(&mut s, &mut v);
        drop((v, s));
    }
    // Every page the new commit added arrives damaged.
    let added: Vec<Name> = page_names(&store).difference(&before).copied().collect();
    assert!(!added.is_empty());
    store.with(|m| {
        for n in &added {
            let k = (Area::Page, n.shard().unwrap(), n.leaf());
            m.raw_mut().get_mut(&k).unwrap()[100] ^= 1;
        }
    });

    // The session opens (every object of the head is present); the
    // damaged pages are refused when read, so the vault does not open
    // through the head.
    let (s, c, _r) = open_raw(&store, &local, true).unwrap();
    assert!(
        Vfs::open_read_only(c).is_err(),
        "a damaged page is refused, never shown"
    );
    let view = s.snapshot_view(&first).unwrap();
    let mut c = view.close().unwrap();
    let dest = dir.path().join("rescued.lbx");
    let mut rescued = export_to(&mut c, &dest);
    assert_eq!(read(&mut rescued, "/a.txt").unwrap(), b"first file");
}
