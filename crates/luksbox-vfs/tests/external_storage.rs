// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Penthertz <https://penthertz.com> (https://x.com/PentHertz)

//! Containers opened from caller-supplied storage (`Container::open_external`,
//! the base of sync bundles) and read-only views (`Vfs::open_read_only`).
//!
//! External storage must behave like a detached-header vault for every
//! read and write, while never touching the file system next to its
//! display path (no `.meta-bak` / `.header-bak` mirrors, no rotation temp
//! file). A read-only view must leave every byte of the vault unchanged,
//! including through `Drop`.

use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use luksbox_core::{Argon2idParams, CipherSuite, HEADER_SIZE};
use luksbox_format::{Container, HeaderStore, LbxFile, UnlockMaterial};
use luksbox_vfs::{Error as VfsError, Vfs};
use tempfile::TempDir;

const PASS: &[u8] = b"correct horse battery staple";
const KDF: Argon2idParams = Argon2idParams {
    m_cost_kib: 8,
    t_cost: 1,
    p_cost: 1,
};

/// In-memory image shared with the test, so it can inspect and reopen it.
#[derive(Clone)]
struct MemImage {
    bytes: Arc<Mutex<Vec<u8>>>,
    pos: u64,
}

impl MemImage {
    fn new(bytes: Vec<u8>) -> Self {
        Self {
            bytes: Arc::new(Mutex::new(bytes)),
            pos: 0,
        }
    }
    fn snapshot(&self) -> Vec<u8> {
        self.bytes.lock().unwrap().clone()
    }
}

impl Read for MemImage {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let b = self.bytes.lock().unwrap();
        let start = (self.pos as usize).min(b.len());
        let n = buf.len().min(b.len() - start);
        buf[..n].copy_from_slice(&b[start..start + n]);
        self.pos += n as u64;
        Ok(n)
    }
}

impl Write for MemImage {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        let mut b = self.bytes.lock().unwrap();
        let end = self.pos as usize + buf.len();
        if b.len() < end {
            b.resize(end, 0);
        }
        b[self.pos as usize..end].copy_from_slice(buf);
        self.pos = end as u64;
        Ok(buf.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl Seek for MemImage {
    fn seek(&mut self, to: SeekFrom) -> std::io::Result<u64> {
        let len = self.bytes.lock().unwrap().len() as i64;
        let new = match to {
            SeekFrom::Start(n) => n as i64,
            SeekFrom::End(d) => len + d,
            SeekFrom::Current(d) => self.pos as i64 + d,
        };
        if new < 0 {
            return Err(std::io::Error::from(std::io::ErrorKind::InvalidInput));
        }
        self.pos = new as u64;
        Ok(self.pos)
    }
}

impl LbxFile for MemImage {
    fn sync_all(&mut self) -> std::io::Result<()> {
        Ok(())
    }
    fn set_len(&mut self, len: u64) -> std::io::Result<()> {
        self.bytes.lock().unwrap().resize(len as usize, 0);
        Ok(())
    }
    fn inode_pair(&self) -> std::io::Result<(u64, u64)> {
        Ok((0, 0))
    }
}

/// Header store that records every header state it is given.
#[derive(Clone, Default)]
struct RecordingStore(Arc<Mutex<Vec<[u8; HEADER_SIZE]>>>);

impl HeaderStore for RecordingStore {
    fn store_header(&mut self, bytes: &[u8; HEADER_SIZE]) -> std::io::Result<()> {
        self.0.lock().unwrap().push(*bytes);
        Ok(())
    }
}

/// Create a detached-header vault holding `/hello.txt`, return its
/// image bytes (the `.lbx`) and header bytes (the `.hdr`).
fn detached_vault(dir: &TempDir) -> (Vec<u8>, [u8; HEADER_SIZE]) {
    let lbx = dir.path().join("v.lbx");
    let hdr = dir.path().join("v.hdr");
    let c =
        Container::create_with_passphrase(&lbx, Some(&hdr), CipherSuite::Aes256GcmSiv, KDF, PASS)
            .unwrap();
    let mut vfs = Vfs::open(c).unwrap();
    let id = vfs.create(vfs.root_id(), "hello.txt").unwrap();
    vfs.write(id, 0, b"hello from a file vault").unwrap();
    vfs.flush().unwrap();
    drop(vfs.close().unwrap());
    let image = std::fs::read(&lbx).unwrap();
    let header: [u8; HEADER_SIZE] = std::fs::read(&hdr).unwrap().try_into().unwrap();
    (image, header)
}

fn read_all(vfs: &mut Vfs, path: &str) -> Vec<u8> {
    let id = vfs.lookup_path(path).unwrap();
    let mut buf = vec![0u8; 4096];
    let n = vfs.read(id, 0, &mut buf).unwrap();
    buf.truncate(n);
    buf
}

fn dir_entries(p: &Path) -> Vec<PathBuf> {
    let mut v: Vec<_> = std::fs::read_dir(p)
        .unwrap()
        .map(|e| e.unwrap().path())
        .collect();
    v.sort();
    v
}

#[test]
fn external_storage_round_trips_without_touching_the_display_path() {
    let src = TempDir::new().unwrap();
    let (image, header) = detached_vault(&src);
    let display = TempDir::new().unwrap();
    let bundle_path = display.path().join("v.lbxs");
    std::fs::create_dir(&bundle_path).unwrap();

    let img = MemImage::new(image);
    let store = RecordingStore::default();
    let c = Container::open_external(
        Box::new(img.clone()),
        &header,
        Box::new(store.clone()),
        bundle_path.clone(),
        UnlockMaterial::Passphrase(PASS),
    )
    .unwrap();
    assert!(c.is_external());
    assert!(!c.supports_atomic_rotation());
    assert_eq!(c.vault_path(), bundle_path.as_path());

    let mut vfs = Vfs::open(c).unwrap();
    assert_eq!(read_all(&mut vfs, "/hello.txt"), b"hello from a file vault");
    let id = vfs.create(vfs.root_id(), "new.txt").unwrap();
    vfs.write(id, 0, b"written through external storage")
        .unwrap();
    vfs.flush().unwrap();
    // A header write goes to the store, never to a file.
    vfs.container_mut().mark_header_dirty();
    vfs.container_mut().persist_header().unwrap();
    drop(vfs.close().unwrap());

    // Nothing was created next to the display path or inside it.
    assert!(dir_entries(&bundle_path).is_empty());
    assert_eq!(dir_entries(display.path()), vec![bundle_path.clone()]);

    let stored = store.0.lock().unwrap().clone();
    assert!(!stored.is_empty(), "the header write reached the store");
    let new_header = *stored.last().unwrap();

    // Reopen from the mutated image and the last stored header.
    let c = Container::open_external(
        Box::new(MemImage::new(img.snapshot())),
        &new_header,
        Box::new(RecordingStore::default()),
        bundle_path,
        UnlockMaterial::Passphrase(PASS),
    )
    .unwrap();
    let mut vfs = Vfs::open(c).unwrap();
    assert_eq!(read_all(&mut vfs, "/hello.txt"), b"hello from a file vault");
    assert_eq!(
        read_all(&mut vfs, "/new.txt"),
        b"written through external storage"
    );
}

#[test]
fn external_storage_refuses_wrong_passphrase_and_inline_layout() {
    let src = TempDir::new().unwrap();
    let (image, header) = detached_vault(&src);
    assert!(
        Container::open_external(
            Box::new(MemImage::new(image)),
            &header,
            Box::new(RecordingStore::default()),
            PathBuf::from("b.lbxs"),
            UnlockMaterial::Passphrase(b"wrong"),
        )
        .is_err()
    );

    // An inline-header vault's header describes a layout with the
    // metadata region past offset 0; external storage refuses it.
    let lbx = src.path().join("inline.lbx");
    drop(
        Container::create_with_passphrase(&lbx, None, CipherSuite::Aes256GcmSiv, KDF, PASS)
            .unwrap(),
    );
    let bytes = std::fs::read(&lbx).unwrap();
    let header: [u8; HEADER_SIZE] = bytes[..HEADER_SIZE].try_into().unwrap();
    assert!(
        Container::open_external(
            Box::new(MemImage::new(bytes[HEADER_SIZE..].to_vec())),
            &header,
            Box::new(RecordingStore::default()),
            PathBuf::from("b.lbxs"),
            UnlockMaterial::Passphrase(PASS),
        )
        .is_err()
    );
}

#[test]
fn read_only_view_never_writes() {
    let dir = TempDir::new().unwrap();
    let lbx = dir.path().join("v.lbx");
    let c = Container::create_with_passphrase(&lbx, None, CipherSuite::Aes256GcmSiv, KDF, PASS)
        .unwrap();
    let mut vfs = Vfs::open(c).unwrap();
    let id = vfs.create(vfs.root_id(), "a.txt").unwrap();
    vfs.write(id, 0, b"original").unwrap();
    vfs.flush().unwrap();
    drop(vfs.close().unwrap());
    let before = std::fs::read(&lbx).unwrap();
    let entries_before = dir_entries(dir.path());

    let c = Container::open(&lbx, None, UnlockMaterial::Passphrase(PASS)).unwrap();
    let mut vfs = Vfs::open_read_only(c).unwrap();
    assert!(vfs.is_read_only());
    assert!(vfs.container().is_read_only());
    assert_eq!(read_all(&mut vfs, "/a.txt"), b"original");
    let root = vfs.root_id();
    let id = vfs.lookup_path("/a.txt").unwrap();
    assert!(matches!(
        vfs.write(id, 0, b"changed"),
        Err(VfsError::ReadOnlyMount)
    ));
    assert!(matches!(
        vfs.create(root, "b.txt"),
        Err(VfsError::ReadOnlyMount)
    ));
    assert!(matches!(vfs.mkdir(root, "d"), Err(VfsError::ReadOnlyMount)));
    assert!(matches!(
        vfs.unlink(root, "a.txt"),
        Err(VfsError::ReadOnlyMount)
    ));
    assert!(matches!(vfs.truncate(id, 0), Err(VfsError::ReadOnlyMount)));
    assert!(matches!(
        vfs.rename(root, "a.txt", root, "c.txt"),
        Err(VfsError::ReadOnlyMount)
    ));
    vfs.flush().unwrap();
    assert_eq!(vfs.finish().unwrap(), 0);
    // Container-level writes are refused too, even header ones.
    vfs.container_mut().mark_header_dirty();
    assert!(vfs.container_mut().persist_header().is_err());
    assert!(vfs.container_mut().write_at(0, b"x").is_err());
    drop(vfs.close().unwrap());

    assert_eq!(
        std::fs::read(&lbx).unwrap(),
        before,
        "a read-only view changed the vault"
    );
    assert_eq!(
        dir_entries(dir.path()),
        entries_before,
        "a read-only view created files"
    );
}

/// A sync client that renames its own copy over an open vault: what the
/// session saves afterwards would vanish at close, so it is copied to a
/// rescue file next to the vault, which opens with everything in it.
#[cfg(unix)]
#[test]
fn vault_replaced_while_open_is_rescued() {
    let dir = TempDir::new().unwrap();
    let lbx = dir.path().join("v.lbx");
    let _g = luksbox_format::metadata::set_create_metadata_region_size_override(Some(2 << 20));
    let c = Container::create_with_passphrase(&lbx, None, CipherSuite::Aes256GcmSiv, KDF, PASS)
        .unwrap();
    let mut vfs = Vfs::open(c).unwrap();
    let id = vfs.create(vfs.root_id(), "before.txt").unwrap();
    vfs.write(id, 0, b"saved before").unwrap();
    vfs.flush().unwrap();
    // The "sync client" replaces the file with a copy of itself.
    let copy = dir.path().join("download.tmp");
    std::fs::copy(&lbx, &copy).unwrap();
    std::fs::rename(&copy, &lbx).unwrap();
    assert!(vfs.container().replaced_on_disk());
    let id = vfs.create(vfs.root_id(), "after.txt").unwrap();
    vfs.write(id, 0, b"saved after the replacement").unwrap();
    vfs.flush().unwrap();
    drop(vfs.close().unwrap());

    let rescued: Vec<PathBuf> = dir_entries(dir.path())
        .into_iter()
        .filter(|p| {
            p.file_name()
                .unwrap()
                .to_string_lossy()
                .contains("(unsaved changes ")
        })
        .collect();
    assert_eq!(rescued.len(), 1, "{rescued:?}");
    let c = Container::open(&rescued[0], None, UnlockMaterial::Passphrase(PASS)).unwrap();
    let mut vfs = Vfs::open(c).unwrap();
    assert_eq!(read_all(&mut vfs, "/before.txt"), b"saved before");
    assert_eq!(
        read_all(&mut vfs, "/after.txt"),
        b"saved after the replacement"
    );
}

#[test]
fn raised_generation_survives_reopen_and_keeps_growing() {
    let dir = TempDir::new().unwrap();
    let lbx = dir.path().join("v.lbx");
    let _g = luksbox_format::metadata::set_create_metadata_region_size_override(Some(2 << 20));
    let c = Container::create_with_passphrase(&lbx, None, CipherSuite::Aes256GcmSiv, KDF, PASS)
        .unwrap();
    let mut vfs = Vfs::open(c).unwrap();
    let id = vfs.create(vfs.root_id(), "a.txt").unwrap();
    vfs.write(id, 0, b"kept").unwrap();
    vfs.flush().unwrap();
    let before = vfs.vault_generation();
    vfs.raise_generation_to(before + 1000).unwrap();
    // Lower targets are a no-op.
    vfs.raise_generation_to(5).unwrap();
    vfs.flush().unwrap();
    drop(vfs.close().unwrap());

    let c = Container::open(&lbx, None, UnlockMaterial::Passphrase(PASS)).unwrap();
    let mut vfs = Vfs::open(c).unwrap();
    assert!(vfs.vault_generation() >= before + 1000);
    assert_eq!(read_all(&mut vfs, "/a.txt"), b"kept");
    let g = vfs.vault_generation();
    let id = vfs.create(vfs.root_id(), "b.txt").unwrap();
    vfs.write(id, 0, b"written after the raise").unwrap();
    vfs.flush().unwrap();
    assert!(vfs.vault_generation() > g);
    drop(vfs.close().unwrap());

    let c = Container::open(&lbx, None, UnlockMaterial::Passphrase(PASS)).unwrap();
    let mut ro = Vfs::open_read_only(c).unwrap();
    assert!(matches!(
        ro.raise_generation_to(u64::MAX / 4),
        Err(VfsError::ReadOnlyMount)
    ));
    assert_eq!(read_all(&mut ro, "/b.txt"), b"written after the raise");
}
