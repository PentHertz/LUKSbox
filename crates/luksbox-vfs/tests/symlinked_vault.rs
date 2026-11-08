// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Penthertz <https://penthertz.com> (https://x.com/PentHertz)

//! A vault opened through a symbolic link: an MVK rotation or a file list
//! region resize (both write a copy and rename it into place) replaces
//! the file the link points to and keeps the link. Renaming over the link
//! replaced the link with the new copy and left the real file as it was:
//! after a rotation, a full copy of the vault under the old master key.
//!
//! ```bash
//! cargo test --test symlinked_vault -p luksbox-vfs
//! ```

#![cfg(unix)]

use std::path::Path;

use luksbox_core::{Argon2idParams, CipherSuite};
use luksbox_format::{Container, UnlockMaterial};
use luksbox_vfs::{SlotCredential, Vfs};
use zeroize::Zeroizing;

const PASS: &str = "symlink-pass";
const KDF: Argon2idParams = Argon2idParams {
    m_cost_kib: 8,
    t_cost: 1,
    p_cost: 1,
};

fn open(path: &Path) -> Vfs {
    Vfs::open(Container::open(path, None, UnlockMaterial::Passphrase(PASS.as_bytes())).unwrap())
        .unwrap()
}

fn read(vfs: &mut Vfs, name: &str) -> Vec<u8> {
    let id = vfs.lookup_path(name).unwrap();
    let size = vfs.stat(id).unwrap().size as usize;
    let mut buf = vec![0u8; size];
    assert_eq!(vfs.read(id, 0, &mut buf).unwrap(), size);
    buf
}

/// `real/v.lbx` holding one file, and `link.lbx -> real/v.lbx`.
fn setup(dir: &Path) -> (std::path::PathBuf, std::path::PathBuf) {
    let real_dir = dir.join("real");
    std::fs::create_dir(&real_dir).unwrap();
    let real = real_dir.join("v.lbx");
    {
        let _g = luksbox_format::metadata::set_create_metadata_region_size_override(Some(1 << 20));
        Container::create_with_passphrase(
            &real,
            None,
            CipherSuite::Aes256GcmSiv,
            KDF,
            PASS.as_bytes(),
        )
        .unwrap();
    }
    let mut vfs = open(&real);
    let root = vfs.root_id();
    let id = vfs.create(root, "note.txt").unwrap();
    vfs.write(id, 0, b"kept across the rewrite").unwrap();
    vfs.finish().unwrap();
    drop(vfs);
    let link = dir.join("link.lbx");
    std::os::unix::fs::symlink(&real, &link).unwrap();
    (real, link)
}

fn assert_link_kept(link: &Path, real: &Path) {
    let m = std::fs::symlink_metadata(link).unwrap();
    assert!(
        m.file_type().is_symlink(),
        "the link was replaced by a file"
    );
    assert_eq!(std::fs::read_link(link).unwrap(), real);
    assert!(
        !Path::new(&format!("{}.rotating", real.display())).exists(),
        "a .rotating copy was left behind"
    );
}

#[test]
fn rotating_the_master_key_through_a_link_replaces_the_real_file() {
    let dir = tempfile::tempdir().unwrap();
    let (real, link) = setup(dir.path());
    let mvk_before = Container::open(&real, None, UnlockMaterial::Passphrase(PASS.as_bytes()))
        .unwrap()
        .mvk_clone();

    let mut vfs = open(&link);
    vfs.rotate_mvk(
        vec![SlotCredential::Passphrase {
            slot_idx: 0,
            passphrase: Zeroizing::new(PASS.to_string()),
        }],
        KDF,
    )
    .unwrap();
    vfs.finish().unwrap();
    drop(vfs);

    assert_link_kept(&link, &real);
    // The real file holds the rotated vault: a new master key, the data.
    let c = Container::open(&real, None, UnlockMaterial::Passphrase(PASS.as_bytes())).unwrap();
    assert!(
        c.mvk_clone() != mvk_before,
        "the real file still has the old master key"
    );
    drop(c);
    let mut v = open(&real);
    assert_eq!(read(&mut v, "/note.txt"), b"kept across the rewrite");
    drop(v);
    let mut v = open(&link);
    assert_eq!(read(&mut v, "/note.txt"), b"kept across the rewrite");
}

#[test]
fn resizing_the_file_list_through_a_link_replaces_the_real_file() {
    let dir = tempfile::tempdir().unwrap();
    let (real, link) = setup(dir.path());
    let len_before = std::fs::metadata(&real).unwrap().len();

    let mut vfs = open(&link);
    vfs.resize_metadata_region(2 << 20).unwrap();
    vfs.finish().unwrap();
    drop(vfs);

    assert_link_kept(&link, &real);
    assert_eq!(
        std::fs::metadata(&real).unwrap().len(),
        len_before + (1 << 20),
        "the real file was not resized"
    );
    let mut v = open(&link);
    assert_eq!(v.container().header.metadata_size, 2 << 20);
    assert_eq!(read(&mut v, "/note.txt"), b"kept across the rewrite");
}
