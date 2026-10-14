// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Penthertz <https://penthertz.com> (https://x.com/PentHertz)

//! Phase 0: the automatic per-device anchor for a single-file vault in a
//! cloud folder. First open trusts and records; a newer vault (another
//! device's write) moves it forward; an older one is refused, naming the
//! conflict copies; a copy at another path gets its own anchor.

use std::path::{Path, PathBuf};

use luksbox_core::{Argon2idParams, CipherSuite};
use luksbox_format::{Container, UnlockMaterial};
use luksbox_sync::cloud::{self, AutoAnchor};
use luksbox_vfs::Vfs;
use tempfile::TempDir;

const PASS: &[u8] = b"correct horse battery staple";
const KDF: Argon2idParams = Argon2idParams {
    m_cost_kib: 8,
    t_cost: 1,
    p_cost: 1,
};

/// `<tmp>/Dropbox/v.lbx` holding `/a.txt`, and an anchors folder outside it.
fn vault_in_dropbox(dir: &TempDir) -> (PathBuf, PathBuf) {
    let folder = dir.path().join("Dropbox");
    std::fs::create_dir(&folder).unwrap();
    let lbx = folder.join("v.lbx");
    let _g = luksbox_format::metadata::set_create_metadata_region_size_override(Some(2 << 20));
    let c = Container::create_with_passphrase(&lbx, None, CipherSuite::Aes256GcmSiv, KDF, PASS)
        .unwrap();
    let mut vfs = Vfs::open(c).unwrap();
    let id = vfs.create(vfs.root_id(), "a.txt").unwrap();
    vfs.write(id, 0, b"first").unwrap();
    vfs.flush().unwrap();
    drop(vfs.close().unwrap());
    (lbx, dir.path().join("app-data").join("anchors"))
}

/// Open as a front end does: unlock, attach the automatic anchor, open
/// the Vfs, settle.
fn open(lbx: &Path, anchors: &Path) -> Result<(Vfs, Option<AutoAnchor>), String> {
    let mut c =
        Container::open(lbx, None, UnlockMaterial::Passphrase(PASS)).map_err(|e| e.to_string())?;
    let a = cloud::attach_auto_anchor(&mut c, anchors)?;
    let mut vfs = Vfs::open(c).map_err(|e| e.to_string())?;
    cloud::settle_auto_anchor(&mut vfs, anchors)?;
    Ok((vfs, a))
}

/// What another device does: open without this device's anchor, write.
fn write_elsewhere(lbx: &Path, name: &str) {
    let c = Container::open(lbx, None, UnlockMaterial::Passphrase(PASS)).unwrap();
    let mut vfs = Vfs::open(c).unwrap();
    let id = vfs.create(vfs.root_id(), name).unwrap();
    vfs.write(id, 0, name.as_bytes()).unwrap();
    vfs.flush().unwrap();
    drop(vfs.close().unwrap());
}

#[test]
fn first_open_records_and_newer_moves_forward() {
    let dir = TempDir::new().unwrap();
    let (lbx, anchors) = vault_in_dropbox(&dir);
    let (vfs, a) = open(&lbx, &anchors).unwrap();
    let a = a.expect("vault in a Dropbox folder gets an anchor");
    assert!(a.created);
    assert_eq!(a.service, "Dropbox");
    assert!(a.path.starts_with(&anchors));
    assert_eq!(
        vfs.container().anchored_metadata_generation(),
        Some(vfs.vault_generation())
    );
    drop(vfs.close().unwrap());

    // Another device writes: normal, the anchor follows.
    write_elsewhere(&lbx, "b.txt");
    let (vfs, a) = open(&lbx, &anchors).unwrap();
    assert!(!a.unwrap().created);
    assert_eq!(
        vfs.container().anchored_metadata_generation(),
        Some(vfs.vault_generation())
    );
    drop(vfs.close().unwrap());
}

#[test]
fn older_copy_is_refused_and_names_the_conflict_copies() {
    let dir = TempDir::new().unwrap();
    let (lbx, anchors) = vault_in_dropbox(&dir);
    drop(open(&lbx, &anchors).unwrap().0.close().unwrap());
    let old = dir.path().join("old.lbx");
    std::fs::copy(&lbx, &old).unwrap();

    // This device writes: its flush moves the anchor.
    let (mut vfs, _) = open(&lbx, &anchors).unwrap();
    let id = vfs.create(vfs.root_id(), "mine.txt").unwrap();
    vfs.write(id, 0, b"mine").unwrap();
    vfs.flush().unwrap();
    drop(vfs.close().unwrap());

    // The sync client keeps the other device's older copy under the
    // vault's name and ours as a conflict copy.
    let copy = lbx.with_file_name("v (Laptop's conflicted copy 2026-10-13).lbx");
    std::fs::rename(&lbx, &copy).unwrap();
    std::fs::copy(&old, &lbx).unwrap();
    let err = open(&lbx, &anchors).err().expect("older copy refused");
    assert!(err.contains("ROLLBACK DETECTED"), "{err}");
    assert!(err.contains("conflicted copy"), "{err}");
    assert!(err.contains("luksbox merge"), "{err}");

    // The conflict copy is another path: its own anchor, not refused.
    let (vfs, a) = open(&copy, &anchors).unwrap();
    assert!(a.unwrap().created);
    drop(vfs.close().unwrap());

    // A merge result, raised past both, replaces the vault: accepted.
    let merged = dir.path().join("Dropbox").join("merged.lbx");
    std::fs::copy(&lbx, &merged).unwrap();
    let c = Container::open(&merged, None, UnlockMaterial::Passphrase(PASS)).unwrap();
    let mut m = Vfs::open(c).unwrap();
    let c2 = Container::open(&copy, None, UnlockMaterial::Passphrase(PASS)).unwrap();
    let copy_gen = Vfs::open_read_only(c2).unwrap().vault_generation();
    m.raise_generation_to(copy_gen.max(m.vault_generation()) + 1)
        .unwrap();
    m.flush().unwrap();
    drop(m.close().unwrap());
    std::fs::rename(&merged, &lbx).unwrap();
    let (vfs, _) = open(&lbx, &anchors).unwrap();
    drop(vfs.close().unwrap());
}

#[test]
fn outside_cloud_folders_and_explicit_anchors_are_left_alone() {
    let dir = TempDir::new().unwrap();
    let lbx = dir.path().join("v.lbx");
    let _g = luksbox_format::metadata::set_create_metadata_region_size_override(Some(2 << 20));
    let c = Container::create_with_passphrase(&lbx, None, CipherSuite::Aes256GcmSiv, KDF, PASS)
        .unwrap();
    drop(Vfs::open(c).unwrap().close().unwrap());
    let anchors = dir.path().join("anchors");
    let (vfs, a) = open(&lbx, &anchors).unwrap();
    assert!(a.is_none());
    assert!(vfs.container().anchor_path().is_none());
    drop(vfs.close().unwrap());
    assert!(!anchors.exists());

    // An explicit anchor wins over the automatic one.
    let (lbx, anchors) = vault_in_dropbox(&dir);
    let explicit = dir.path().join("mine.anchor");
    let mut c = Container::open(&lbx, None, UnlockMaterial::Passphrase(PASS)).unwrap();
    c.init_anchor(explicit.clone(), 0).unwrap();
    assert!(
        cloud::attach_auto_anchor(&mut c, &anchors)
            .unwrap()
            .is_none()
    );
    assert_eq!(c.anchor_path(), Some(explicit.as_path()));
    assert!(!cloud::is_auto_anchor(&c, &anchors));
}
