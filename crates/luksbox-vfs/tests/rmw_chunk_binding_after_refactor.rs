// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Penthertz <https://penthertz.com> (https://x.com/PentHertz)

//! Security ground-truth for the issue-#31 read/write refactor.
//!
//! The refactor stopped `Vfs::read`/`write` from cloning the whole
//! per-inode chunk-ref vector on every call and instead copies only the
//! O(request-length) refs the op touches. The security-critical
//! property it must preserve is the per-chunk AEAD binding:
//!
//!   * every chunk is encrypted/decrypted under AAD =
//!     `file_id || absolute_chunk_index || generation`;
//!   * a rewrite of an existing chunk must consume a FRESH generation
//!     (replay protection), and the in-memory ref must track it so the
//!     chunk still decrypts after flush + reopen;
//!   * no read/write may address the wrong chunk slot (position
//!     confusion) regardless of where in the file it lands or whether
//!     the file has spilled its chunk list to external blocks
//!     (> `V3_INLINE_CHUNK_THRESHOLD` = 1024 chunks).
//!
//! These tests deliberately drive the exact code paths the refactor
//! rewrote: mid-file overwrites, appends that extend the file, writes
//! straddling the existing/appended boundary, and full read-back across
//! the inline->external spill threshold, followed by a flush + reopen so
//! the on-disk generations are re-validated by `validate_metadata_tree`.

use luksbox_core::{Argon2idParams, CipherSuite};
use luksbox_format::{Container, UnlockMaterial};
use luksbox_vfs::Vfs;
use tempfile::tempdir;

const CHUNK: usize = 4096;

fn cheap_params() -> Argon2idParams {
    Argon2idParams {
        m_cost_kib: 8,
        t_cost: 1,
        p_cost: 1,
    }
}

/// Distinct, position-dependent 4 KiB pattern for chunk `idx`, tagged
/// with a `rev` so an overwrite produces different bytes than the
/// original fill. Position-dependence is what catches a chunk-slot
/// mix-up: swapping two chunks changes the read-back bytes.
fn pattern(idx: usize, rev: u8) -> Vec<u8> {
    let mut v = vec![0u8; CHUNK];
    for (i, b) in v.iter_mut().enumerate() {
        *b = (idx as u8)
            .wrapping_mul(31)
            .wrapping_add(rev.wrapping_mul(97))
            .wrapping_add((i as u8).wrapping_mul(7));
    }
    v
}

fn verify_all(vfs: &mut Vfs, file: u64, expected: &[Vec<u8>]) {
    let mut buf = vec![0u8; CHUNK];
    for (idx, want) in expected.iter().enumerate() {
        let n = vfs.read(file, (idx * CHUNK) as u64, &mut buf).unwrap();
        assert_eq!(n, CHUNK, "short read at chunk {idx}");
        assert_eq!(&buf, want, "chunk {idx} decrypted to the wrong bytes");
    }
}

#[test]
fn scattered_overwrites_on_spilled_file_preserve_chunk_binding() {
    // 3000 chunks > V3_INLINE_CHUNK_THRESHOLD (1024), so the file spills
    // its chunk list to external blocks -- the path where the refactor's
    // O(request) ref-copying matters most.
    const N: usize = 3000;

    let dir = tempdir().unwrap();
    let path = dir.path().join("rmw.lbx");

    let mut expected: Vec<Vec<u8>> = (0..N).map(|i| pattern(i, 0)).collect();

    {
        let c = Container::create_with_passphrase(
            &path,
            None,
            CipherSuite::Aes256GcmSiv,
            cheap_params(),
            b"rmw-binding",
        )
        .unwrap();
        let mut vfs = Vfs::open(c).unwrap();
        let root = vfs.root_id();
        let file = vfs.create(root, "big.bin").unwrap();

        // Initial fill, one chunk per write (append path).
        for i in 0..N {
            vfs.write(file, (i * CHUNK) as u64, &expected[i]).unwrap();
        }
        verify_all(&mut vfs, file, &expected);

        // Scattered single-chunk overwrites (in-place RMW path). Each
        // rewrite must consume a fresh generation and keep decrypting.
        for &idx in &[0usize, 1, 1023, 1024, 1025, 1500, 2999] {
            let repl = pattern(idx, 1);
            vfs.write(file, (idx * CHUNK) as u64, &repl).unwrap();
            expected[idx] = repl;
        }
        verify_all(&mut vfs, file, &expected);

        // A multi-chunk write straddling the existing/appended boundary:
        // overwrite the last two existing chunks AND extend by two.
        let start = N - 2;
        let span: Vec<u8> = (0..4 * CHUNK).map(|i| (i as u8) ^ 0xC3).collect();
        vfs.write(file, (start * CHUNK) as u64, &span).unwrap();
        for k in 0..4 {
            expected
                .get_mut(start + k)
                .map(|c| *c = span[k * CHUNK..(k + 1) * CHUNK].to_vec())
                .unwrap_or_else(|| expected.push(span[k * CHUNK..(k + 1) * CHUNK].to_vec()));
        }
        verify_all(&mut vfs, file, &expected);

        vfs.flush().unwrap();
        // close() drops the container lock so the reopen below succeeds.
        let _ = vfs.close().unwrap();
    }

    // Reopen: validate_metadata_tree re-checks every chunk generation
    // against next_chunk_gen, and each read re-derives the AAD. If the
    // refactor had recorded a stale/duplicate generation or an off-by-one
    // slot, this fails (either at open or at read time).
    let c = Container::open(&path, None, UnlockMaterial::Passphrase(b"rmw-binding")).unwrap();
    let mut vfs = Vfs::open(c).unwrap();
    let root = vfs.root_id();
    let file = vfs.lookup(root, "big.bin").unwrap();
    verify_all(&mut vfs, file, &expected);
}

#[test]
fn write_into_hole_past_eof_binds_every_chunk() {
    // Start writing well past EOF of an empty file: the write must
    // allocate zero-filled chunks 0..start and only bind real data at
    // `start`. Exercises the appended-only branch plus the chunk-0
    // handling when cur_len == 0.
    let dir = tempdir().unwrap();
    let path = dir.path().join("hole.lbx");

    let c = Container::create_with_passphrase(
        &path,
        None,
        CipherSuite::Aes256Gcm,
        cheap_params(),
        b"hole-binding",
    )
    .unwrap();
    let mut vfs = Vfs::open(c).unwrap();
    let root = vfs.root_id();
    let file = vfs.create(root, "sparse.bin").unwrap();

    let start = 5usize;
    let data = pattern(start, 2);
    vfs.write(file, (start * CHUNK) as u64, &data).unwrap();

    let mut buf = vec![0u8; CHUNK];
    // The hole chunks read back as zeros...
    for idx in 0..start {
        let n = vfs.read(file, (idx * CHUNK) as u64, &mut buf).unwrap();
        assert_eq!(n, CHUNK);
        assert!(buf.iter().all(|&b| b == 0), "hole chunk {idx} must be zero");
    }
    // ...and the target chunk reads back the written data.
    let n = vfs.read(file, (start * CHUNK) as u64, &mut buf).unwrap();
    assert_eq!(n, CHUNK);
    assert_eq!(buf, data, "data chunk past the hole must decrypt");
}
