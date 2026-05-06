// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Penthertz <https://penthertz.com> (https://x.com/PentHertz)

//! Round-6 security-invariant tests at the VFS / chunk layer:
//!
//!   D. Cross-file chunk substitution, an attacker with disk access
//!      AND the MVK swaps two chunks' on-disk bytes between
//!      different files. The chunk AAD includes `file_id`, so the
//!      receiving file's read should fail AEAD verification.
//!
//!   E. Chunk generation-counter rollback within a single chunk slot,
//!      the chunk AAD includes the per-vault monotonic generation
//!      counter. An attacker who saves a chunk slot's bytes at gen=N,
//!      waits for legit overwrite at gen=N+1, then restores the
//!      saved bytes, must fail AEAD verification because the
//!      metadata-recorded generation no longer matches the on-disk
//!      AAD.

use std::path::PathBuf;

use luksbox_core::{Argon2idParams, CipherSuite};
use luksbox_format::{Container, UnlockMaterial};
use luksbox_vfs::Vfs;
use luksbox_vfs::chunk::CHUNK_SLOT_SIZE;
use tempfile::TempDir;

const PASS: &[u8] = b"correct horse battery staple";

fn make_vault(dir: &TempDir) -> PathBuf {
    let path = dir.path().join("v.lbx");
    let _ = Container::create_with_passphrase_flags(
        &path,
        None,
        CipherSuite::Aes256Gcm,
        Argon2idParams {
            m_cost_kib: 8,
            t_cost: 1,
            p_cost: 1,
        },
        0,
        PASS,
    )
    .unwrap();
    path
}

fn open_vfs(path: &PathBuf) -> Vfs {
    let cont = Container::open(path, None, UnlockMaterial::Passphrase(PASS)).unwrap();
    Vfs::open(cont).unwrap()
}

// ---- D. Cross-file chunk substitution ----------------------------------

/// An attacker with disk access AND the MVK swaps the on-disk bytes of
/// two different files' chunk slots. Reading either file MUST fail
/// AEAD verification.
///
/// The defence is two-fold:
/// 1. Each file has its own `file_key = HKDF(MVK, salt, "lbx:file/v1:" || file_id)`.
///    Decrypting a chunk meant for file B with file A's key fails
///    immediately at the AEAD layer (wrong key -> wrong tag).
/// 2. Even if the keys somehow matched, chunk AAD includes
///    `file_id || chunk_idx || generation`, so a chunk written for
///    (file=B, idx=0) doesn't authenticate when read as (file=A, idx=0).
#[test]
fn chunk_substitution_between_files_fails_aead() {
    let dir = TempDir::new().unwrap();
    let path = make_vault(&dir);

    // Write two files with distinct, recognisable content so we can
    // tell whether substitution silently succeeded.
    let (file_a_id, file_b_id);
    {
        let mut vfs = open_vfs(&path);
        let root = vfs.root_id();
        file_a_id = vfs.create(root, "fileA").unwrap();
        file_b_id = vfs.create(root, "fileB").unwrap();
        vfs.write(file_a_id, 0, b"AAAAAAAA file-A unique content AAAAAAAA")
            .unwrap();
        vfs.write(file_b_id, 0, b"BBBBBBBB file-B unique content BBBBBBBB")
            .unwrap();
        vfs.flush().unwrap();
    }

    // Sanity round-trip without tampering.
    {
        let mut vfs = open_vfs(&path);
        let mut buf = [0u8; 64];
        let n = vfs.read(file_a_id, 0, &mut buf).unwrap();
        assert!(buf[..n].starts_with(b"AAAAAAAA"));
        let n = vfs.read(file_b_id, 0, &mut buf).unwrap();
        assert!(buf[..n].starts_with(b"BBBBBBBB"));
    }

    // Now: at the disk level, swap chunk slot 0 with chunk slot 1.
    // (File A took chunk_id 0, file B took chunk_id 1. The exact
    // assignment is allocator-dependent but stable for a fresh
    // vault.)
    let mut cont = Container::open(&path, None, UnlockMaterial::Passphrase(PASS)).unwrap();
    let data_off = cont.data_offset();
    let slot_size = CHUNK_SLOT_SIZE as usize;
    let mut slot_a = vec![0u8; slot_size];
    let mut slot_b = vec![0u8; slot_size];
    cont.read_at(data_off, &mut slot_a).unwrap();
    cont.read_at(data_off + CHUNK_SLOT_SIZE, &mut slot_b)
        .unwrap();
    assert_ne!(slot_a, slot_b, "slots should differ before swap");

    // Swap.
    cont.write_at(data_off, &slot_b).unwrap();
    cont.write_at(data_off + CHUNK_SLOT_SIZE, &slot_a).unwrap();
    drop(cont);

    // Re-open and attempt to read either file. Both must fail,
    // file A's metadata says (chunk_id=0, expected_gen=N), but slot 0
    // now contains slot B's bytes whose AAD has B's file_id.
    {
        let mut vfs = open_vfs(&path);
        let mut buf = [0u8; 64];
        let r_a = vfs.read(file_a_id, 0, &mut buf);
        let r_b = vfs.read(file_b_id, 0, &mut buf);
        assert!(
            r_a.is_err(),
            "fileA read after cross-file swap must fail (chunk AAD mismatch)"
        );
        assert!(r_b.is_err(), "fileB read after cross-file swap must fail");
    }
}

// ---- E. Chunk generation-counter rollback ------------------------------

/// An attacker with disk access AND the MVK saves a chunk slot's
/// bytes when its generation counter is N, waits for the legit user
/// to overwrite that slot at gen=N+1 (refreshes metadata's recorded
/// generation), then restores the saved old bytes. Reading the file
/// MUST fail AEAD because the slot's AAD encodes the OLD generation
/// while metadata expects the NEW one.
#[test]
fn chunk_generation_rollback_fails_aead() {
    let dir = TempDir::new().unwrap();
    let path = make_vault(&dir);

    // Write file once -> chunk allocated at gen=N.
    let file_id;
    {
        let mut vfs = open_vfs(&path);
        let root = vfs.root_id();
        file_id = vfs.create(root, "f").unwrap();
        vfs.write(file_id, 0, b"original content at gen N").unwrap();
        vfs.flush().unwrap();
    }

    // Snapshot the on-disk chunk slot bytes (slot N).
    let data_off;
    let slot_size = CHUNK_SLOT_SIZE as usize;
    let mut snapshot_old = vec![0u8; slot_size];
    {
        let mut cont = Container::open(&path, None, UnlockMaterial::Passphrase(PASS)).unwrap();
        data_off = cont.data_offset();
        cont.read_at(data_off, &mut snapshot_old).unwrap();
    } // cont dropped here -> flock released

    // Legit user overwrites the file -> same chunk slot, new
    // generation N+1, fresh nonce, new bytes on disk.
    {
        let mut vfs = open_vfs(&path);
        vfs.write(file_id, 0, b"updated content at gen N+1")
            .unwrap();
        vfs.flush().unwrap();
    }

    // Confirm the on-disk bytes really did change (sanity).
    let mut snapshot_new = vec![0u8; slot_size];
    {
        let mut cont = Container::open(&path, None, UnlockMaterial::Passphrase(PASS)).unwrap();
        cont.read_at(data_off, &mut snapshot_new).unwrap();
    }
    assert_ne!(
        snapshot_old, snapshot_new,
        "overwrite should change the on-disk slot bytes"
    );

    // Sanity: legit read works.
    {
        let mut vfs = open_vfs(&path);
        let mut buf = [0u8; 64];
        let n = vfs.read(file_id, 0, &mut buf).unwrap();
        assert!(buf[..n].starts_with(b"updated"));
    }

    // Now: attacker rolls back the slot bytes to the gen-N snapshot.
    {
        let mut cont = Container::open(&path, None, UnlockMaterial::Passphrase(PASS)).unwrap();
        cont.write_at(data_off, &snapshot_old).unwrap();
    }

    // Re-open and read. Metadata still records gen=N+1 (it was flushed
    // when the legit user wrote). The slot's AAD encodes gen=N. The
    // chunk AAD includes the generation, so AEAD verify fails.
    {
        let mut vfs = open_vfs(&path);
        let mut buf = [0u8; 64];
        let r = vfs.read(file_id, 0, &mut buf);
        assert!(
            r.is_err(),
            "rolled-back chunk slot must fail AEAD (gen mismatch in AAD)"
        );
    }
}

// ---- Bonus: chunk-position swap within the same file -------------------

/// Swap chunk_idx=0 and chunk_idx=1 inside the same file. The chunk
/// AAD includes `chunk_idx`, so AEAD verification fails.
#[test]
fn chunk_position_swap_within_file_fails_aead() {
    let dir = TempDir::new().unwrap();
    let path = make_vault(&dir);

    let file_id;
    {
        let mut vfs = open_vfs(&path);
        let root = vfs.root_id();
        file_id = vfs.create(root, "twochunks").unwrap();
        // Write 8 KB -> 2 full chunks.
        let mut payload = vec![b'A'; 4096];
        payload.extend(vec![b'B'; 4096]);
        vfs.write(file_id, 0, &payload).unwrap();
        vfs.flush().unwrap();
    }

    let mut cont = Container::open(&path, None, UnlockMaterial::Passphrase(PASS)).unwrap();
    let data_off = cont.data_offset();
    let slot_size = CHUNK_SLOT_SIZE as usize;
    let mut s0 = vec![0u8; slot_size];
    let mut s1 = vec![0u8; slot_size];
    cont.read_at(data_off, &mut s0).unwrap();
    cont.read_at(data_off + CHUNK_SLOT_SIZE, &mut s1).unwrap();

    // Swap on-disk slot 0 ↔ slot 1.
    cont.write_at(data_off, &s1).unwrap();
    cont.write_at(data_off + CHUNK_SLOT_SIZE, &s0).unwrap();
    drop(cont);

    // Re-open and attempt to read. Each chunk's AAD has its original
    // chunk_idx baked in; reading slot 0 expects chunk_idx=0 in AAD
    // but the swapped bytes have chunk_idx=1. AEAD fails.
    {
        let mut vfs = open_vfs(&path);
        let mut buf = vec![0u8; 8192];
        let r = vfs.read(file_id, 0, &mut buf);
        assert!(
            r.is_err(),
            "in-file chunk-position swap must fail AEAD (chunk_idx in AAD)"
        );
    }
}
