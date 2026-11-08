// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Penthertz <https://penthertz.com> (https://x.com/PentHertz)

//! Metadata region resize, the format half: recovery of an interrupted
//! detached-header resize from its `<header>.resizing` intent (L1), stale
//! header mirrors after a resize (L2), the copy a deniable vault's rewrite
//! makes (L3) and a sync bundle's grown region (relayout_external). See
//! `docs/VAULT_SIZE.md`. The VFS-level resize tests are in
//! `crates/luksbox-vfs/tests/metadata_resize.rs`.
//!
//! ```bash
//! cargo test --test resize_recovery -p luksbox-format
//! ```

use std::path::{Path, PathBuf};

use luksbox_core::{Argon2idParams, CipherSuite, HEADER_SIZE};
use luksbox_format::{Container, Error, HeaderStore, UnlockMaterial};

const KDF: Argon2idParams = Argon2idParams {
    m_cost_kib: 8,
    t_cost: 1,
    p_cost: 1,
};
const PASS: &[u8] = b"pass";
const KIB: u64 = 1024;
/// One chunk slot of the data area (`luksbox_vfs::chunk::CHUNK_SLOT_SIZE`).
const SLOT: usize = 4124;
/// Stands in for the encrypted file list (the format layer does not
/// parse it).
const BLOB: &[u8] = b"LBM5 stands in for the file list";
/// Stands in for chunk ciphertext in the data area.
const MARK: u8 = 0x5a;

fn with_region<T>(region: u64, f: impl FnOnce() -> T) -> T {
    let _g = luksbox_format::metadata::set_create_metadata_region_size_override(Some(region));
    f()
}

/// LUKSBOX2 (mirrors on), a file list and three data slots.
fn populate(mut c: Container) {
    c.header.version_major = luksbox_core::VERSION_MAJOR_V2;
    c.mark_header_dirty();
    c.persist_header().unwrap();
    c.write_metadata(BLOB).unwrap();
    let off = c.data_offset();
    c.write_at(off, &vec![MARK; 3 * SLOT]).unwrap();
    c.flush().unwrap();
}

fn create_inline(dir: &Path, region: u64) -> PathBuf {
    let vault = dir.join("v.lbx");
    populate(with_region(region, || {
        Container::create_with_passphrase(&vault, None, CipherSuite::Aes256GcmSiv, KDF, PASS)
            .unwrap()
    }));
    vault
}

fn create_detached(dir: &Path, name: &str, region: u64) -> (PathBuf, PathBuf) {
    let vault = dir.join(format!("{name}.lbx"));
    let hdr = dir.join(format!("{name}.hdr"));
    populate(with_region(region, || {
        Container::create_with_passphrase(&vault, Some(&hdr), CipherSuite::Aes256GcmSiv, KDF, PASS)
            .unwrap()
    }));
    (vault, hdr)
}

fn open(vault: &Path, hdr: Option<&Path>, pass: &[u8]) -> Result<Container, Error> {
    Container::open(vault, hdr, UnlockMaterial::Passphrase(pass))
}

/// What `Vfs::resize_metadata_region` does with the container: the copy
/// gets the new layout and the file list, the commit renames it over the
/// vault, then a save re-establishes the mirrors.
fn resize(c: &mut Container, new_size: u64) {
    c.begin_atomic_relayout(new_size).unwrap();
    c.write_metadata(BLOB).unwrap();
    c.persist_header().unwrap();
    c.commit_atomic_rotation().unwrap();
    c.write_metadata(BLOB).unwrap();
    c.persist_header().unwrap();
}

fn read(p: &Path) -> Option<Vec<u8>> {
    std::fs::read(p).ok()
}

fn put(p: &Path, bytes: Option<&[u8]>) {
    match bytes {
        Some(b) => std::fs::write(p, b).unwrap(),
        None => drop(std::fs::remove_file(p)),
    }
}

/// The intent `commit_atomic_rotation` writes for a detached header.
fn intent(header: &[u8], new_len: u64, old_len: u64) -> Vec<u8> {
    let mut v = header[..HEADER_SIZE].to_vec();
    v.extend_from_slice(b"LBXRSZ01");
    v.extend_from_slice(&new_len.to_le_bytes());
    v.extend_from_slice(&old_len.to_le_bytes());
    v
}

fn region_of(header: &[u8]) -> u64 {
    luksbox_core::header::Header::from_bytes(header[..HEADER_SIZE].try_into().unwrap())
        .unwrap()
        .metadata_size
}

/// A detached vault before and after a real resize (256 KiB -> 768 KiB),
/// to rebuild the states a crash leaves.
struct Detached {
    vault: PathBuf,
    hdr: PathBuf,
    header_mirror: PathBuf,
    meta_mirror: PathBuf,
    intent: PathBuf,
    old_vault: Vec<u8>,
    old_hdr: Vec<u8>,
    old_header_mirror: Vec<u8>,
    old_meta_mirror: Vec<u8>,
    new_vault: Vec<u8>,
    new_hdr: Vec<u8>,
}

impl Detached {
    fn new(dir: &Path) -> Self {
        let (vault, hdr) = create_detached(dir, "d", 256 * KIB);
        let header_mirror = hdr.with_extension("hdr.header-bak");
        let meta_mirror = vault.with_extension("lbx.meta-bak");
        let old_vault = read(&vault).unwrap();
        let old_hdr = read(&hdr).unwrap();
        let old_header_mirror = read(&header_mirror).expect("a LUKSBOX2 header mirror");
        let old_meta_mirror = read(&meta_mirror).expect("a LUKSBOX2 metadata mirror");
        let mut c = open(&vault, Some(&hdr), PASS).unwrap();
        resize(&mut c, 768 * KIB);
        drop(c);
        Self {
            intent: hdr.with_extension("hdr.resizing"),
            new_vault: read(&vault).unwrap(),
            new_hdr: read(&hdr).unwrap(),
            vault,
            hdr,
            header_mirror,
            meta_mirror,
            old_vault,
            old_hdr,
            old_header_mirror,
            old_meta_mirror,
        }
    }

    /// The crash after the rename, before the header install: the new
    /// vault, the old header and its mirrors, the intent.
    fn renamed_not_installed(&self) {
        put(&self.vault, Some(&self.new_vault));
        put(&self.hdr, Some(&self.old_hdr));
        put(&self.header_mirror, Some(&self.old_header_mirror));
        put(&self.meta_mirror, Some(&self.old_meta_mirror));
        put(
            &self.intent,
            Some(&intent(
                &self.new_hdr,
                self.new_vault.len() as u64,
                self.old_vault.len() as u64,
            )),
        );
    }

    fn files(&self) -> Vec<Option<Vec<u8>>> {
        [
            &self.vault,
            &self.hdr,
            &self.header_mirror,
            &self.meta_mirror,
            &self.intent,
        ]
        .iter()
        .map(|p| read(p))
        .collect()
    }
}

// ---------------------------------------------------------------------
// L1: the recovery trusted the unauthenticated intent and ran before the
// unlock: with a wrong passphrase it deleted both mirrors and wrote the
// intent's bytes over the live header, whatever they held.
// ---------------------------------------------------------------------

#[test]
fn a_wrong_passphrase_changes_nothing_while_a_resize_is_interrupted() {
    let dir = tempfile::tempdir().unwrap();
    let d = Detached::new(dir.path());
    d.renamed_not_installed();
    let before = d.files();
    assert!(open(&d.vault, Some(&d.hdr), b"wrong passphrase").is_err());
    assert!(
        d.files() == before,
        "a failed open changed the vault, its header, a mirror or the intent"
    );

    // The right passphrase finishes it.
    let mut c = open(&d.vault, Some(&d.hdr), PASS).unwrap();
    assert_eq!(c.header.metadata_size, 768 * KIB);
    assert_eq!(&c.read_metadata().unwrap()[..], BLOB);
    drop(c);
    assert!(read(&d.hdr).unwrap()[..] == d.new_hdr[..HEADER_SIZE]);
    assert!(!d.intent.exists());
    for mirror in [&d.header_mirror, &d.meta_mirror] {
        assert!(
            read(mirror).is_none_or(|m| m != d.old_header_mirror && m != d.old_meta_mirror),
            "{} still holds the old layout",
            mirror.display()
        );
    }
}

#[test]
fn an_intent_without_a_valid_header_never_replaces_the_header() {
    let dir = tempfile::tempdir().unwrap();
    let d = Detached::new(dir.path());
    // Not resized at all; an intent whose new length is the vault's and
    // whose header is noise.
    put(&d.vault, Some(&d.new_vault));
    put(&d.hdr, Some(&d.new_hdr));
    let garbage: Vec<u8> = (0..HEADER_SIZE).map(|i| (i * 31 + 7) as u8).collect();
    put(
        &d.intent,
        Some(&intent(&garbage, d.new_vault.len() as u64, 12_345)),
    );
    let before = d.files();
    for pass in [&b"wrong passphrase"[..], PASS] {
        let e = open(&d.vault, Some(&d.hdr), pass).err().expect("opened");
        assert!(matches!(e, Error::InterruptedResize(_)), "{e:?}");
        assert!(d.files() == before, "the refused intent changed something");
    }
    // Removing it is the way out.
    std::fs::remove_file(&d.intent).unwrap();
    let mut c = open(&d.vault, Some(&d.hdr), PASS).unwrap();
    assert_eq!(&c.read_metadata().unwrap()[..], BLOB);
}

#[test]
fn an_undo_waits_for_a_verified_open() {
    let dir = tempfile::tempdir().unwrap();
    let d = Detached::new(dir.path());
    // Not renamed: the old vault and its mirrors, the copy still there.
    put(&d.vault, Some(&d.old_vault));
    put(&d.hdr, Some(&d.old_hdr));
    put(&d.header_mirror, Some(&d.old_header_mirror));
    put(&d.meta_mirror, Some(&d.old_meta_mirror));
    put(
        &d.intent,
        Some(&intent(
            &d.new_hdr,
            d.new_vault.len() as u64,
            d.old_vault.len() as u64,
        )),
    );
    let copy = d.vault.with_extension("lbx.rotating");
    put(&copy, Some(&d.new_vault));
    let before = d.files();
    assert!(open(&d.vault, Some(&d.hdr), b"wrong passphrase").is_err());
    assert!(
        d.files() == before && copy.exists(),
        "changed before the unlock"
    );
    let c = open(&d.vault, Some(&d.hdr), PASS).unwrap();
    assert_eq!(c.header.metadata_size, 256 * KIB);
    assert!(!d.intent.exists() && !copy.exists());
}

#[test]
fn an_intent_with_another_header_salt_is_ignored() {
    let dir = tempfile::tempdir().unwrap();
    let d = Detached::new(dir.path());
    // Another vault's resized header, sized to this vault's length.
    let (other_vault, other_hdr) = create_detached(dir.path(), "other", 256 * KIB);
    let mut c = open(&other_vault, Some(&other_hdr), PASS).unwrap();
    resize(&mut c, 768 * KIB);
    drop(c);
    let foreign = read(&other_hdr).unwrap();
    put(
        &d.intent,
        Some(&intent(
            &foreign,
            d.new_vault.len() as u64,
            d.old_vault.len() as u64,
        )),
    );
    let before = d.files();
    let mut c = open(&d.vault, Some(&d.hdr), PASS).expect("the foreign intent blocked the open");
    assert_eq!(c.header.metadata_size, 768 * KIB);
    assert_eq!(&c.read_metadata().unwrap()[..], BLOB);
    drop(c);
    assert!(d.files() == before, "the foreign intent changed something");
}

#[test]
fn an_intent_that_does_not_follow_from_the_live_header_is_refused() {
    let dir = tempfile::tempdir().unwrap();
    let d = Detached::new(dir.path());
    // The vault and its header were resized again (to 192 KiB) after the
    // first resize, and the first resize's intent comes back (a sync
    // client) while the vault happens to have its new length.
    let mut c = open(&d.vault, Some(&d.hdr), PASS).unwrap();
    resize(&mut c, 192 * KIB);
    drop(c);
    let mut v = read(&d.vault).unwrap();
    v.resize(d.new_vault.len(), MARK);
    put(&d.vault, Some(&v));
    put(
        &d.intent,
        Some(&intent(
            &d.new_hdr,
            d.new_vault.len() as u64,
            d.old_vault.len() as u64,
        )),
    );
    let before = d.files();
    let e = open(&d.vault, Some(&d.hdr), PASS).err().expect("opened");
    assert!(matches!(e, Error::InterruptedResize(_)), "{e:?}");
    assert!(d.files() == before);
    assert_eq!(region_of(&read(&d.hdr).unwrap()), 192 * KIB);
}

#[cfg(unix)]
#[test]
fn a_symlink_at_the_intent_path_is_not_followed() {
    let dir = tempfile::tempdir().unwrap();
    let d = Detached::new(dir.path());
    d.renamed_not_installed();
    // The real intent, moved elsewhere and linked to.
    let elsewhere = dir.path().join("elsewhere.bin");
    std::fs::rename(&d.intent, &elsewhere).unwrap();
    std::os::unix::fs::symlink(&elsewhere, &d.intent).unwrap();
    let target = read(&elsewhere);
    let hdr = read(&d.hdr);
    let e = open(&d.vault, Some(&d.hdr), PASS).err().expect("opened");
    assert!(matches!(e, Error::InterruptedResize(_)), "{e:?}");
    assert!(read(&elsewhere) == target && read(&d.hdr) == hdr);
    assert!(
        d.intent
            .symlink_metadata()
            .unwrap()
            .file_type()
            .is_symlink()
    );
}

#[cfg(unix)]
#[test]
fn a_fifo_at_the_intent_path_is_refused_without_blocking() {
    use std::os::unix::ffi::OsStrExt;
    let dir = tempfile::tempdir().unwrap();
    let d = Detached::new(dir.path());
    let c = std::ffi::CString::new(d.intent.as_os_str().as_bytes()).unwrap();
    // SAFETY: valid C string.
    assert_eq!(unsafe { libc::mkfifo(c.as_ptr(), 0o600) }, 0);
    let (vault, hdr) = (d.vault.clone(), d.hdr.clone());
    let (tx, rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let _ = tx.send(open(&vault, Some(&hdr), PASS).err());
    });
    let e = rx
        .recv_timeout(std::time::Duration::from_secs(10))
        .expect("the open blocked on a FIFO")
        .expect("opened");
    assert!(matches!(e, Error::InterruptedResize(_)), "{e:?}");
}

// ---------------------------------------------------------------------
// L2: a `.header-bak` from before a resize (left by a crash between the
// rename and the mirror removal) has the same MVK and a valid HMAC: once
// the live header failed to parse, the vault opened with the old layout.
// ---------------------------------------------------------------------

fn corrupt_inline_header(vault: &Path) {
    use std::io::{Seek, SeekFrom, Write};
    let mut f = std::fs::OpenOptions::new().write(true).open(vault).unwrap();
    f.seek(SeekFrom::Start(0)).unwrap();
    f.write_all(&[0u8; 16]).unwrap();
}

#[test]
fn a_header_mirror_from_before_a_resize_is_not_recovered_from() {
    let dir = tempfile::tempdir().unwrap();
    let vault = create_inline(dir.path(), 64 * KIB);
    let header_mirror = vault.with_extension("lbx.header-bak");
    let meta_mirror = vault.with_extension("lbx.meta-bak");
    let old_mirror = read(&header_mirror).expect("a header mirror");
    let mut c = open(&vault, None, PASS).unwrap();
    resize(&mut c, 128 * KIB);
    drop(c);
    let new_mirror = read(&header_mirror).expect("re-established");
    assert_eq!(region_of(&new_mirror), 128 * KIB);
    corrupt_inline_header(&vault);

    // With the current mirror the corrupted header is recovered...
    let c = open(&vault, None, PASS).expect("recovery from the current mirror");
    assert_eq!(c.header.metadata_size, 128 * KIB);
    // ...(without writing it back: the test corrupts it again below).
    drop(c);
    corrupt_inline_header(&vault);

    // ...but not from the one the resize left behind.
    put(&header_mirror, Some(&old_mirror));
    let before = read(&vault);
    assert!(
        open(&vault, None, PASS).is_err(),
        "opened with the old layout"
    );
    // Not even when the metadata mirror is gone too (the slot check).
    std::fs::remove_file(&meta_mirror).unwrap();
    assert!(
        open(&vault, None, PASS).is_err(),
        "opened with the old layout"
    );
    assert!(read(&vault) == before && read(&header_mirror).unwrap() == old_mirror);
}

/// A commit removes the mirrors of the vault it replaces before the
/// rename: none is left for the new vault until its first save writes
/// fresh ones.
#[test]
fn a_committed_resize_leaves_no_old_layout_mirror() {
    let dir = tempfile::tempdir().unwrap();
    let vault = create_inline(dir.path(), 64 * KIB);
    let mut c = open(&vault, None, PASS).unwrap();
    c.begin_atomic_relayout(192 * KIB).unwrap();
    c.write_metadata(BLOB).unwrap();
    c.persist_header().unwrap();
    c.commit_atomic_rotation().unwrap();
    for m in ["lbx.header-bak", "lbx.meta-bak"] {
        assert!(
            !vault.with_extension(m).exists(),
            "{m} left after the commit"
        );
    }
    c.write_metadata(BLOB).unwrap();
    c.persist_header().unwrap();
    drop(c);
    assert_eq!(
        region_of(&read(&vault.with_extension("lbx.header-bak")).unwrap()),
        192 * KIB
    );
}

// ---------------------------------------------------------------------
// L3: a deniable vault's rewrite copy was `<vault>.rotating`, a name that
// marks the file next to it as a LUKSbox vault, left forever by a crash.
// ---------------------------------------------------------------------

fn create_deniable(dir: &Path) -> PathBuf {
    let vault = dir.join("den.dat");
    with_region(64 * KIB, || {
        Container::create_with_passphrase_deniable(
            &vault,
            None,
            CipherSuite::Aes256GcmSiv,
            KDF,
            0,
            PASS,
        )
        .unwrap()
    });
    vault
}

fn open_deniable(vault: &Path) -> Container {
    Container::open_with_passphrase_deniable(vault, None, PASS, KDF, CipherSuite::Aes256GcmSiv)
        .unwrap()
}

fn names(dir: &Path) -> Vec<String> {
    let mut v: Vec<String> = std::fs::read_dir(dir)
        .unwrap()
        .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
        .collect();
    v.sort();
    v
}

#[test]
fn a_deniable_rewrite_copy_has_no_vault_shaped_name_and_a_crashed_one_is_removed() {
    let dir = tempfile::tempdir().unwrap();
    let vault = create_deniable(dir.path());
    let mut c = open_deniable(&vault);
    c.begin_atomic_relayout(128 * KIB).unwrap();
    let during = names(dir.path());
    assert_eq!(during.len(), 2, "{during:?}");
    let copy_name = during.iter().find(|n| *n != "den.dat").unwrap().clone();
    assert!(
        copy_name.starts_with('.') && copy_name.ends_with(".tmp") && !copy_name.contains("den"),
        "{copy_name}"
    );
    // The name only depends on the vault: a crash leaves this same file.
    let copy = dir.path().join(&copy_name);
    let crashed = read(&copy).unwrap();
    c.abort_atomic_rotation().unwrap();
    drop(c);
    assert_eq!(names(dir.path()), vec!["den.dat".to_string()]);

    // A crash before the rename (and an older version's `.rotating`).
    put(&copy, Some(&crashed));
    put(&vault.with_extension("dat.rotating"), Some(&crashed));
    let before = read(&vault);
    let mut c = open_deniable(&vault);
    assert_eq!(
        names(dir.path()),
        vec!["den.dat".to_string()],
        "the next unlock removes what the crash left"
    );
    // A leftover does not block the next rewrite either.
    put(&copy, Some(&crashed));
    c.begin_atomic_relayout(128 * KIB).unwrap();
    c.write_metadata(BLOB).unwrap();
    c.persist_header().unwrap();
    c.commit_atomic_rotation().unwrap();
    drop(c);
    assert_eq!(names(dir.path()), vec!["den.dat".to_string()]);
    assert!(read(&vault) != before);
    let mut c = open_deniable(&vault);
    assert_eq!(c.header.metadata_size, 128 * KIB);
    assert_eq!(&c.read_metadata().unwrap()[..], BLOB);
}

// ---------------------------------------------------------------------
// A sync bundle's region grows in place (`relayout_external`): the part
// of the image it now covers held the start of the data area, and the
// bucketed metadata write refreshes only a prefix of the region.
// ---------------------------------------------------------------------

struct Store;

impl HeaderStore for Store {
    fn store_header(&mut self, _bytes: &[u8; HEADER_SIZE]) -> std::io::Result<()> {
        Ok(())
    }
    fn store_header_with_next_save(&mut self, _bytes: &[u8; HEADER_SIZE]) -> std::io::Result<()> {
        Ok(())
    }
}

#[test]
fn a_grown_bundle_region_holds_no_data_area_bytes() {
    let dir = tempfile::tempdir().unwrap();
    let (vault, hdr) = create_detached(dir.path(), "b", 64 * KIB);
    let header: [u8; HEADER_SIZE] = read(&hdr).unwrap()[..HEADER_SIZE].try_into().unwrap();
    let image = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(&vault)
        .unwrap();
    let mut c = Container::open_external(
        Box::new(image),
        &header,
        Box::new(Store),
        dir.path().to_path_buf(),
        UnlockMaterial::Passphrase(PASS),
    )
    .unwrap();
    c.relayout_external(256 * KIB).unwrap();
    assert_eq!(c.data_offset(), 256 * KIB);
    assert_eq!(&c.read_metadata().unwrap()[..], BLOB);
    drop(c);
    let bytes = read(&vault).unwrap();
    assert!(
        bytes[256 * KIB as usize..].iter().all(|&b| b == MARK),
        "the data area moved whole"
    );
    let grown = &bytes[64 * KIB as usize..256 * KIB as usize];
    assert!(
        !grown.windows(64).any(|w| w.iter().all(|&b| b == MARK)),
        "the grown region still holds data area bytes"
    );
    assert!(
        grown.chunks(4096).all(|b| b.iter().any(|&x| x != 0)),
        "the grown region is not padded"
    );
}
