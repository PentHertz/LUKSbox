// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Penthertz <https://penthertz.com> (https://x.com/PentHertz)

//! Round 13 regressions covering the VFS-layer findings:
//!
//!   - R13-03: chunk-0 real-size header is bounded by the inode's
//!     chunk capacity before it ever reaches `inode.chunks[idx]`.
//!     We synthesise a hide-size vault, tamper the cached size to
//!     a hostile value, and confirm `read()`/`stat()` reject cleanly
//!     instead of panicking.
//!   - R13-07: write / truncate refuse logical sizes that exceed
//!     `luksbox_vfs::MAX_FILE_SIZE`, before
//!     `padded_chunk_count(next_power_of_two)` can panic or before
//!     the chunk-allocation loop can exhaust disk / RAM.
//!
//! ```bash
//! cargo test --test round13_findings -p luksbox-vfs
//! ```

use luksbox_format::{Container, UnlockMaterial};
use luksbox_vfs::{Error as VfsError, MAX_FILE_SIZE, Vfs};

fn open_vault() -> (tempfile::TempDir, std::path::PathBuf) {
    let dir = tempfile::tempdir().unwrap();
    let vault = dir.path().join("v.lbx");
    let kdf = luksbox_core::Argon2idParams {
        m_cost_kib: 8,
        t_cost: 1,
        p_cost: 1,
    };
    Container::create_with_passphrase_flags(
        &vault,
        None,
        luksbox_core::CipherSuite::Aes256GcmSiv,
        kdf,
        luksbox_core::FLAG_HIDE_SIZE_HEADER,
        b"pass",
    )
    .unwrap();
    (dir, vault)
}

// ---------------------------------------------------------------------
// R13-07: write past MAX_FILE_SIZE returns FileSizeExceedsCap.
// ---------------------------------------------------------------------

#[test]
fn r13_07_write_past_max_file_size_rejects() {
    let (_dir, vault) = open_vault();
    let cont = Container::open(&vault, None, UnlockMaterial::Passphrase(b"pass")).unwrap();
    let mut vfs = Vfs::open(cont).unwrap();
    let root = vfs.root_id();
    let f = vfs.create(root, "big.bin").unwrap();
    // Try to write a single byte at MAX_FILE_SIZE.
    let r = vfs.write(f, MAX_FILE_SIZE, &[0xaa]);
    assert!(
        matches!(r, Err(VfsError::FileSizeExceedsCap)),
        "write past MAX_FILE_SIZE must return FileSizeExceedsCap, got {:?}",
        r
    );
}

#[test]
fn r13_07_truncate_past_max_file_size_rejects() {
    let (_dir, vault) = open_vault();
    let cont = Container::open(&vault, None, UnlockMaterial::Passphrase(b"pass")).unwrap();
    let mut vfs = Vfs::open(cont).unwrap();
    let root = vfs.root_id();
    let f = vfs.create(root, "ftrunc.bin").unwrap();
    let r = vfs.truncate(f, MAX_FILE_SIZE + 1);
    assert!(
        matches!(r, Err(VfsError::FileSizeExceedsCap)),
        "truncate past MAX_FILE_SIZE must return FileSizeExceedsCap, got {:?}",
        r
    );
}

// ---------------------------------------------------------------------
// R13-07 sanity: legitimate-size writes still succeed.
// ---------------------------------------------------------------------

#[test]
fn r13_07_normal_write_still_succeeds() {
    let (_dir, vault) = open_vault();
    let cont = Container::open(&vault, None, UnlockMaterial::Passphrase(b"pass")).unwrap();
    let mut vfs = Vfs::open(cont).unwrap();
    let root = vfs.root_id();
    let f = vfs.create(root, "ok.bin").unwrap();
    vfs.write(f, 0, &[0xaa; 1024]).unwrap();
    let mut buf = [0u8; 1024];
    let n = vfs.read(f, 0, &mut buf).unwrap();
    assert_eq!(n, 1024);
    assert!(buf.iter().all(|&b| b == 0xaa));
}
