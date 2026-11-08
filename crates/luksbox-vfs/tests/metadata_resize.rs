// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Penthertz <https://penthertz.com> (https://x.com/PentHertz)

//! `Vfs::resize_metadata_region`: changing the size of an existing
//! vault's metadata region ("file list"), crash-safe like the master key
//! rotation.
//!
//! ```bash
//! cargo test --test metadata_resize -p luksbox-vfs
//! ```

use std::path::{Path, PathBuf};

use luksbox_core::{Argon2idParams, CipherSuite};
use luksbox_format::{Container, UnlockMaterial, anchor};
use luksbox_vfs::{Error, Vfs};

const PASS: &[u8] = b"pass";
const KDF: Argon2idParams = Argon2idParams {
    m_cost_kib: 8,
    t_cost: 1,
    p_cost: 1,
};
const KIB: u64 = 1024;

fn create(dir: &Path, region: u64) -> PathBuf {
    let vault = dir.join("v.lbx");
    let _g = luksbox_format::metadata::set_create_metadata_region_size_override(Some(region));
    Container::create_with_passphrase(&vault, None, CipherSuite::Aes256GcmSiv, KDF, PASS).unwrap();
    vault
}

fn open(vault: &Path) -> Vfs {
    Vfs::open(Container::open(vault, None, UnlockMaterial::Passphrase(PASS)).unwrap()).unwrap()
}

fn content(i: usize, len: usize) -> Vec<u8> {
    (0..len).map(|b| (b * 7 + i * 13) as u8).collect()
}

/// Small files (chunk lists in the region), one large file (its chunk
/// list in the data area) and a folder.
fn fill(vfs: &mut Vfs, n: usize) -> Vec<(String, Vec<u8>)> {
    let root = vfs.root_id();
    let docs = vfs.mkdir(root, "docs").unwrap();
    let mut files = Vec::new();
    for i in 0..n {
        let name = format!("small-{i:04}.txt");
        let data = content(i, 3000 + i * 11);
        let id = vfs.create(docs, &name).unwrap();
        vfs.write(id, 0, &data).unwrap();
        files.push((format!("/docs/{name}"), data));
    }
    let big = content(99, (2 << 20) + 123);
    let id = vfs.create(root, "big.bin").unwrap();
    vfs.write(id, 0, &big).unwrap();
    files.push(("/big.bin".into(), big));
    vfs.flush().unwrap();
    files
}

fn read_all(vfs: &mut Vfs, path: &str) -> Vec<u8> {
    let id = vfs.lookup_path(path).unwrap();
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

fn check(vault: &Path, files: &[(String, Vec<u8>)], region: u64) {
    let mut vfs = open(vault);
    assert_eq!(vfs.container().header.metadata_size, region);
    for (path, data) in files {
        assert!(
            read_all(&mut vfs, path) == *data,
            "{path} differs after the resize"
        );
    }
    drop(vfs.close().unwrap());
    let mirror = vault.with_extension("lbx.meta-bak");
    assert_eq!(
        std::fs::metadata(&mirror).unwrap().len(),
        region,
        "the metadata mirror follows the new region size"
    );
    assert!(!vault.with_extension("lbx.rotating").exists());
}

#[test]
fn grow_then_shrink_keeps_every_file() {
    let dir = tempfile::tempdir().unwrap();
    let vault = create(dir.path(), 256 * KIB);
    let mut vfs = open(&vault);
    let files = fill(&mut vfs, 40);
    let before = std::fs::metadata(&vault).unwrap().len();
    vfs.resize_metadata_region(1024 * KIB).unwrap();
    assert_eq!(
        std::fs::metadata(&vault).unwrap().len(),
        before + (1024 - 256) * KIB,
        "the data area moved by the region growth"
    );
    // The open vault keeps working after the resize.
    let root = vfs.root_id();
    let id = vfs.create(root, "after.txt").unwrap();
    vfs.write(id, 0, b"written after the resize").unwrap();
    drop(vfs.close().unwrap());
    let mut all = files.clone();
    all.push(("/after.txt".into(), b"written after the resize".to_vec()));
    check(&vault, &all, 1024 * KIB);

    let mut vfs = open(&vault);
    vfs.resize_metadata_region(192 * KIB).unwrap();
    drop(vfs.close().unwrap());
    check(&vault, &all, 192 * KIB);
}

#[test]
fn a_full_file_list_takes_new_files_again_after_growing() {
    let dir = tempfile::tempdir().unwrap();
    let vault = create(dir.path(), 128 * KIB);
    let mut vfs = open(&vault);
    let root = vfs.root_id();
    let mut made = 0usize;
    let stop = loop {
        let r = vfs
            .create(root, &format!("entry-{made:06}.txt"))
            .and_then(|id| vfs.write(id, 0, b"x").map(|_| ()));
        match r {
            Ok(()) => made += 1,
            Err(e) => break e,
        }
    };
    assert!(matches!(stop, Error::MetadataBudgetExhausted), "{stop:?}");
    // The refused entry may exist empty; drop it so the counts are exact.
    let _ = vfs.unlink(root, &format!("entry-{made:06}.txt"));
    vfs.resize_metadata_region(512 * KIB).unwrap();
    for i in 0..made {
        let id = vfs.create(root, &format!("more-{i:06}.txt")).unwrap();
        vfs.write(id, 0, b"y").unwrap();
    }
    drop(vfs.close().unwrap());
    let vfs = open(&vault);
    assert_eq!(vfs.readdir(vfs.root_id()).unwrap().len(), 2 * made);
}

#[test]
fn a_region_too_small_for_the_file_list_is_refused_and_changes_nothing() {
    let dir = tempfile::tempdir().unwrap();
    let vault = create(dir.path(), 512 * KIB);
    let mut vfs = open(&vault);
    // About 100 bytes of file list each: well over 64 KiB.
    let files = fill(&mut vfs, 1500);
    drop(vfs.close().unwrap());
    let mut vfs = open(&vault);
    let before = std::fs::read(&vault).unwrap();
    let e = vfs.resize_metadata_region(64 * KIB).unwrap_err();
    assert!(matches!(e, Error::ResizeTooSmall { .. }), "{e:?}");
    drop(vfs.close().unwrap());
    assert!(
        std::fs::read(&vault).unwrap() == before,
        "the vault was changed"
    );
    check(&vault, &files, 512 * KIB);
}

#[test]
fn a_stale_rotation_file_refuses_the_resize_and_keeps_the_vault() {
    let dir = tempfile::tempdir().unwrap();
    let vault = create(dir.path(), 256 * KIB);
    let mut vfs = open(&vault);
    let files = fill(&mut vfs, 10);
    std::fs::write(vault.with_extension("lbx.rotating"), b"left by a crash").unwrap();
    assert!(vfs.resize_metadata_region(512 * KIB).is_err());
    // Still usable, still the old layout.
    let root = vfs.root_id();
    vfs.create(root, "still.txt").unwrap();
    drop(vfs.close().unwrap());
    std::fs::remove_file(vault.with_extension("lbx.rotating")).unwrap();
    let mut vfs = open(&vault);
    assert_eq!(vfs.container().header.metadata_size, 256 * KIB);
    for (path, data) in &files {
        assert!(read_all(&mut vfs, path) == *data);
    }
}

#[test]
fn an_anchored_vault_still_opens_against_its_anchor_after_a_resize() {
    let dir = tempfile::tempdir().unwrap();
    let vault = create(dir.path(), 256 * KIB);
    let anchor_path = dir.path().join("v.anchor");
    {
        let mut c = Container::open(&vault, None, UnlockMaterial::Passphrase(PASS)).unwrap();
        c.init_anchor(anchor_path.clone(), 1).unwrap();
    }
    let mut c = Container::open(&vault, None, UnlockMaterial::Passphrase(PASS)).unwrap();
    c.set_anchor(Some(anchor_path.clone())).unwrap();
    let mut vfs = Vfs::open(c).unwrap();
    let files = fill(&mut vfs, 20);
    vfs.resize_metadata_region(768 * KIB).unwrap();
    drop(vfs.close().unwrap());

    let mut c = Container::open(&vault, None, UnlockMaterial::Passphrase(PASS)).unwrap();
    let anchor_gen = c.set_anchor(Some(anchor_path)).unwrap().unwrap();
    let mut vfs = Vfs::open(c).unwrap();
    assert!(
        matches!(
            anchor::compare(anchor_gen, vfs.vault_generation()),
            anchor::VerificationOutcome::Ok
        ),
        "the anchor was moved on with the resized vault"
    );
    for (path, data) in &files {
        assert!(read_all(&mut vfs, path) == *data);
    }
}

#[test]
fn invalid_sizes_are_refused() {
    let dir = tempfile::tempdir().unwrap();
    let inline = create(dir.path(), 256 * KIB);
    let mut vfs = open(&inline);
    for bad in [0, 1000, 32 * KIB, 100 * KIB, 128 * 1024 * KIB] {
        assert!(
            matches!(
                vfs.resize_metadata_region(bad),
                Err(Error::ResizeInvalidSize)
            ),
            "{bad} accepted"
        );
    }
    // Same size: nothing to do.
    vfs.resize_metadata_region(256 * KIB).unwrap();
}

fn create_detached(dir: &Path, region: u64) -> (PathBuf, PathBuf) {
    let vault = dir.join("d.lbx");
    let hdr = dir.join("d.hdr");
    let _g = luksbox_format::metadata::set_create_metadata_region_size_override(Some(region));
    Container::create_with_passphrase(&vault, Some(&hdr), CipherSuite::Aes256GcmSiv, KDF, PASS)
        .unwrap();
    (vault, hdr)
}

fn open_detached(vault: &Path, hdr: &Path) -> Result<Vfs, luksbox_format::Error> {
    let c = Container::open(vault, Some(hdr), UnlockMaterial::Passphrase(PASS))?;
    Ok(Vfs::open(c).unwrap())
}

fn header_region(path: &Path) -> u64 {
    let bytes = std::fs::read(path).unwrap();
    luksbox_core::header::Header::from_bytes(bytes[..luksbox_core::HEADER_SIZE].try_into().unwrap())
        .unwrap()
        .metadata_size
}

fn check_detached(vault: &Path, hdr: &Path, files: &[(String, Vec<u8>)], region: u64) {
    let mut vfs = open_detached(vault, hdr).unwrap();
    assert_eq!(vfs.container().header.metadata_size, region);
    for (path, data) in files {
        assert!(read_all(&mut vfs, path) == *data, "{path} differs");
    }
    drop(vfs.close().unwrap());
    assert_eq!(header_region(hdr), region, "the header sidecar");
    let mirror = hdr.with_extension("hdr.header-bak");
    if mirror.exists() {
        assert_eq!(header_region(&mirror), region, "the header mirror");
    }
    for leftover in [
        hdr.with_extension("hdr.resizing"),
        vault.with_extension("lbx.rotating"),
    ] {
        assert!(!leftover.exists(), "{} left behind", leftover.display());
    }
}

#[test]
fn a_detached_header_vault_is_resized_and_its_header_follows() {
    let dir = tempfile::tempdir().unwrap();
    let (vault, hdr) = create_detached(dir.path(), 256 * KIB);
    let mut vfs = open_detached(&vault, &hdr).unwrap();
    let files = fill(&mut vfs, 40);
    vfs.resize_metadata_region(1024 * KIB).unwrap();
    let root = vfs.root_id();
    let id = vfs.create(root, "after.txt").unwrap();
    vfs.write(id, 0, b"after the resize").unwrap();
    drop(vfs.close().unwrap());
    let mut all = files.clone();
    all.push(("/after.txt".into(), b"after the resize".to_vec()));
    check_detached(&vault, &hdr, &all, 1024 * KIB);

    let mut vfs = open_detached(&vault, &hdr).unwrap();
    vfs.resize_metadata_region(192 * KIB).unwrap();
    drop(vfs.close().unwrap());
    check_detached(&vault, &hdr, &all, 192 * KIB);
}

/// The intent `commit_atomic_rotation` writes for a detached header: the
/// new header, the magic, the new and the old vault length.
fn intent(header: &[u8], new_len: u64, old_len: u64) -> Vec<u8> {
    let mut v = header[..luksbox_core::HEADER_SIZE].to_vec();
    v.extend_from_slice(b"LBXRSZ01");
    v.extend_from_slice(&new_len.to_le_bytes());
    v.extend_from_slice(&old_len.to_le_bytes());
    v
}

/// Every state a crash can leave between writing the intent and removing
/// it, rebuilt from the files before and after a real resize.
#[test]
fn interrupted_detached_resizes_are_finished_or_undone_at_open() {
    let dir = tempfile::tempdir().unwrap();
    let (vault, hdr) = create_detached(dir.path(), 256 * KIB);
    let mut vfs = open_detached(&vault, &hdr).unwrap();
    let files = fill(&mut vfs, 25);
    drop(vfs.close().unwrap());
    let header_mirror = hdr.with_extension("hdr.header-bak");
    let old_vault = std::fs::read(&vault).unwrap();
    let old_hdr = std::fs::read(&hdr).unwrap();
    let old_mirror = std::fs::read(&header_mirror).ok();
    let mut vfs = open_detached(&vault, &hdr).unwrap();
    vfs.resize_metadata_region(768 * KIB).unwrap();
    drop(vfs.close().unwrap());
    let new_vault = std::fs::read(&vault).unwrap();
    let new_hdr = std::fs::read(&hdr).unwrap();
    let (new_len, old_len) = (new_vault.len() as u64, old_vault.len() as u64);
    let intent_path = hdr.with_extension("hdr.resizing");
    let copy = vault.with_extension("lbx.rotating");
    let set = |v: &[u8], h: &[u8], i: Option<Vec<u8>>, c: Option<&[u8]>| {
        std::fs::write(&vault, v).unwrap();
        std::fs::write(&hdr, h).unwrap();
        if let Some(m) = &old_mirror {
            std::fs::write(&header_mirror, m).unwrap();
        }
        match i {
            Some(i) => std::fs::write(&intent_path, i).unwrap(),
            None => drop(std::fs::remove_file(&intent_path)),
        }
        match c {
            Some(c) => std::fs::write(&copy, c).unwrap(),
            None => drop(std::fs::remove_file(&copy)),
        }
    };

    // Renamed, header not installed yet: finished.
    set(
        &new_vault,
        &old_hdr,
        Some(intent(&new_hdr, new_len, old_len)),
        None,
    );
    check_detached(&vault, &hdr, &files, 768 * KIB);
    assert!(std::fs::read(&hdr).unwrap()[..] == new_hdr[..luksbox_core::HEADER_SIZE]);

    // Not renamed (the copy is still there): undone.
    set(
        &old_vault,
        &old_hdr,
        Some(intent(&new_hdr, new_len, old_len)),
        Some(&new_vault),
    );
    check_detached(&vault, &hdr, &files, 256 * KIB);

    // Copy gone but the vault still has the old length: undone.
    set(
        &old_vault,
        &old_hdr,
        Some(intent(&new_hdr, new_len, old_len)),
        None,
    );
    check_detached(&vault, &hdr, &files, 256 * KIB);

    // Intent cut short by the crash: it is complete before the rename,
    // so the copy is still there and the resize is undone.
    set(
        &old_vault,
        &old_hdr,
        Some(intent(&new_hdr, new_len, old_len)[..100].to_vec()),
        Some(&new_vault),
    );
    check_detached(&vault, &hdr, &files, 256 * KIB);

    // Finished rename with an old `.rotating` brought back next to it
    // (a sync client): the length decides, the copy never does.
    set(
        &new_vault,
        &old_hdr,
        Some(intent(&new_hdr, new_len, old_len)),
        Some(&old_vault),
    );
    check_detached(&vault, &hdr, &files, 768 * KIB);

    // The header was already installed and has moved on since (a slot
    // enrolled after the resize): a leftover intent never overwrites it.
    set(&new_vault, &new_hdr, None, None);
    {
        let mut c = Container::open(&vault, Some(&hdr), UnlockMaterial::Passphrase(PASS)).unwrap();
        c.enroll_passphrase(b"second passphrase", KDF).unwrap();
        c.persist_header().unwrap();
    }
    std::fs::write(&intent_path, intent(&new_hdr, new_len, old_len)).unwrap();
    check_detached(&vault, &hdr, &files, 768 * KIB);
    Container::open(
        &vault,
        Some(&hdr),
        UnlockMaterial::Passphrase(b"second passphrase"),
    )
    .expect("the slot enrolled after the resize was kept");

    // An incomplete intent with no copy left: refused, not guessed.
    set(
        &new_vault,
        &old_hdr,
        Some(intent(&new_hdr, new_len, old_len)[..100].to_vec()),
        None,
    );
    let e = open_detached(&vault, &hdr).err().expect("opened");
    assert!(
        matches!(e, luksbox_format::Error::InterruptedResize(_)),
        "{e:?}"
    );

    // A length that matches neither layout: refused, never guessed (and
    // never answered from the old-layout header mirror).
    let mut odd = old_vault.clone();
    odd.extend_from_slice(&[0u8; 4096]);
    set(
        &odd,
        &old_hdr,
        Some(intent(&new_hdr, new_len, old_len)),
        None,
    );
    let e = open_detached(&vault, &hdr)
        .err()
        .expect("an ambiguous resize opened");
    assert!(
        matches!(e, luksbox_format::Error::InterruptedResize(_)),
        "{e:?}"
    );
    assert!(intent_path.exists(), "the intent was removed");
}

fn create_deniable(dir: &Path, region: u64) -> PathBuf {
    let vault = dir.join("den.dat");
    let _g = luksbox_format::metadata::set_create_metadata_region_size_override(Some(region));
    Container::create_with_passphrase_deniable(
        &vault,
        None,
        CipherSuite::Aes256GcmSiv,
        KDF,
        0,
        PASS,
    )
    .unwrap();
    vault
}

fn open_deniable(vault: &Path) -> Vfs {
    let c =
        Container::open_with_passphrase_deniable(vault, None, PASS, KDF, CipherSuite::Aes256GcmSiv)
            .unwrap();
    Vfs::open(c).unwrap()
}

/// No 4 KiB block of zeros anywhere: a deniable file must keep looking
/// random (the new region is a hole in the copy until it is written).
fn assert_looks_random(path: &Path) {
    let bytes = std::fs::read(path).unwrap();
    for (n, block) in bytes.chunks(4096).enumerate() {
        assert!(
            block.len() < 64 || block.iter().any(|&b| b != 0),
            "zero block at offset {}",
            n * 4096
        );
    }
}

#[test]
fn a_deniable_vault_is_resized_only_when_acknowledged_and_still_looks_random() {
    for v3 in [false, true] {
        let dir = tempfile::tempdir().unwrap();
        let vault = create_deniable(dir.path(), 256 * KIB);
        let mut vfs = open_deniable(&vault);
        if v3 {
            assert!(vfs.container_mut().upgrade_header_to_v3().unwrap());
        }
        let files = fill(&mut vfs, 30);
        assert!(matches!(
            vfs.resize_metadata_region(1024 * KIB),
            Err(Error::ResizeDeniable)
        ));
        vfs.resize_metadata_region_allow_deniable(1024 * KIB)
            .unwrap();
        drop(vfs.close().unwrap());
        assert_looks_random(&vault);
        let mut vfs = open_deniable(&vault);
        assert_eq!(vfs.container().header.metadata_size, 1024 * KIB, "v3 {v3}");
        for (path, data) in &files {
            assert!(
                read_all(&mut vfs, path) == *data,
                "{path} differs (v3 {v3})"
            );
        }
        vfs.resize_metadata_region_allow_deniable(320 * KIB)
            .unwrap();
        drop(vfs.close().unwrap());
        assert_looks_random(&vault);
        let mut vfs = open_deniable(&vault);
        assert_eq!(vfs.container().header.metadata_size, 320 * KIB);
        for (path, data) in &files {
            assert!(read_all(&mut vfs, path) == *data);
        }
        drop(vfs.close().unwrap());
        let names: Vec<String> = std::fs::read_dir(dir.path())
            .unwrap()
            .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
            .collect();
        assert_eq!(
            names,
            vec!["den.dat".to_string()],
            "a deniable vault leaves no other file"
        );
    }
}

/// A crash after the new copy was written but before the rename: a child
/// process (this test binary, re-run with `RESIZE_CRASH_CHILD`) starts
/// the relayout, writes a file into the copy and aborts, so nothing is
/// cleaned up and the kernel drops its locks like after a real crash.
/// The original vault must open with its old layout and old files,
/// without the change written only into the copy; the leftover
/// `.rotating` blocks the next resize until it is removed.
#[test]
fn a_crash_before_the_rename_leaves_the_original_vault() {
    if let Ok(path) = std::env::var("RESIZE_CRASH_CHILD") {
        let vault = PathBuf::from(path);
        let mut vfs = open(&vault);
        vfs.container_mut()
            .begin_atomic_relayout(1024 * KIB)
            .unwrap();
        let root = vfs.root_id();
        let id = vfs.create(root, "only-in-the-copy.txt").unwrap();
        vfs.write(id, 0, b"never committed").unwrap();
        vfs.flush().unwrap();
        assert!(vault.with_extension("lbx.rotating").exists());
        std::process::abort();
    }
    let dir = tempfile::tempdir().unwrap();
    let vault = create(dir.path(), 256 * KIB);
    let mut vfs = open(&vault);
    let files = fill(&mut vfs, 30);
    drop(vfs.close().unwrap());
    let before = std::fs::read(&vault).unwrap();

    let child = std::process::Command::new(std::env::current_exe().unwrap())
        .args([
            "--exact",
            "a_crash_before_the_rename_leaves_the_original_vault",
            "--nocapture",
        ])
        .env("RESIZE_CRASH_CHILD", &vault)
        .output()
        .unwrap();
    assert!(!child.status.success(), "the child did not crash");
    assert!(
        vault.with_extension("lbx.rotating").exists(),
        "the child stopped before writing the copy: {}",
        String::from_utf8_lossy(&child.stderr)
    );
    assert!(
        std::fs::read(&vault).unwrap() == before,
        "the original vault changed before the rename"
    );

    let mut vfs = open(&vault);
    assert_eq!(vfs.container().header.metadata_size, 256 * KIB);
    assert!(vfs.lookup_path("/only-in-the-copy.txt").is_err());
    for (path, data) in &files {
        assert!(read_all(&mut vfs, path) == *data, "{path} differs");
    }
    assert!(vfs.resize_metadata_region(1024 * KIB).is_err());
    std::fs::remove_file(vault.with_extension("lbx.rotating")).unwrap();
    vfs.resize_metadata_region(1024 * KIB).unwrap();
    drop(vfs.close().unwrap());
    check(&vault, &files, 1024 * KIB);
}
