// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Penthertz <https://penthertz.com> (https://x.com/PentHertz)

#![no_main]

//! Fuzz the chunk-layer AEAD decrypt path with attacker-controlled
//! on-disk bytes.
//!
//! Threat model: an attacker who can read or modify the .lbx file
//! between writes (raw block device, NFS middlebox, ZFS snapshot
//! rollback) crafts arbitrary bytes at chunk slot offsets. The chunk
//! layer reads `[nonce(12) | ct(4096) | tag(16)]` and feeds it
//! through `aead::open` with `AAD = file_id || chunk_idx || generation`.
//! We want every malformed input to either decrypt cleanly (vanishing
//! probability under a random key) or return `Err`; never panic,
//! never index out of bounds, never loop.
//!
//! Why this isn't redundant with `auth_then_process` or `vfs_ops`:
//! - `auth_then_process` fuzzes the metadata blob (DirectoryTree
//!   shape) AFTER decryption, not the chunk path.
//! - `vfs_ops` exercises the write+read cycle with attacker-controlled
//!   filenames + offsets, but the chunk bytes themselves are produced
//!   by `write_chunk` and are always valid AEAD outputs. The on-disk
//!   bytes here are never attacker-controlled in that target.
//!
//! This target exercises specifically the production callsite:
//! `chunk::read_chunk` -> `aead::open(suite, file_key, nonce, aad, ct)`.
//! Replicates the AAD construction from `chunk.rs:38-44`. Replicates
//! `file_key_for_mvk` derivation (re-exposed as `pub` in luksbox-vfs).
//!
//! AAD = `file_id_le(8) || chunk_idx_le(4) || generation_le(8)` = 20 B.
//!
//! Fuzz input layout (minimum 33 bytes: 1 + 8 + 4 + 8 + 12 + 0):
//!   [0]       suite selector mod 3 (0 = AES-GCM-SIV, 1 = AES-GCM, 2 = ChaCha)
//!   [1..9]    file_id (u64 LE)
//!   [9..13]   chunk_idx (u32 LE)
//!   [13..21]  generation (u64 LE)
//!   [21..33]  nonce (12 bytes)
//!   [33..]    ct || tag (any length the fuzzer picked, including 0)
//!
//! Inputs shorter than 33 bytes are skipped (libFuzzer's mutator will
//! quickly find the boundary). Inputs longer than 1 MiB are skipped
//! to keep iteration time bounded.

use libfuzzer_sys::fuzz_target;
use luksbox_core::{CipherSuite, MasterVolumeKey, aead};
use luksbox_vfs::chunk::file_key_for_mvk;

const MVK_BYTES: [u8; 32] = [0xA5; 32];
const HEADER_SALT: [u8; 32] = [0x5A; 32];

const SUITES: [CipherSuite; 3] = [
    CipherSuite::Aes256GcmSiv,
    CipherSuite::Aes256Gcm,
    CipherSuite::ChaCha20Poly1305,
];

const HDR_LEN: usize = 1 + 8 + 4 + 8 + 12;
const MAX_INPUT: usize = 1 << 20;

fuzz_target!(|data: &[u8]| {
    if data.len() < HDR_LEN || data.len() > MAX_INPUT {
        return;
    }
    let suite = SUITES[(data[0] as usize) % SUITES.len()];

    let file_id = u64::from_le_bytes(data[1..9].try_into().unwrap());
    let chunk_idx = u32::from_le_bytes(data[9..13].try_into().unwrap());
    let generation = u64::from_le_bytes(data[13..21].try_into().unwrap());
    let nonce: [u8; 12] = data[21..33].try_into().unwrap();
    let ct = &data[33..];

    // Mirror chunk_aad() exactly. Kept inline (not imported) because
    // it's a private fn; mismatched AAD here would defeat the test.
    let mut aad = [0u8; 20];
    aad[..8].copy_from_slice(&file_id.to_le_bytes());
    aad[8..12].copy_from_slice(&chunk_idx.to_le_bytes());
    aad[12..].copy_from_slice(&generation.to_le_bytes());

    let mvk = MasterVolumeKey::from_bytes(MVK_BYTES);
    let file_key = file_key_for_mvk(&mvk, &HEADER_SALT, file_id);

    // The actual fuzzed call. Must never panic, must never OOB on a
    // weird `ct` length, must return Err on a bad tag. A successful
    // decrypt under the fixed key with attacker-controlled bytes has
    // ~2^-128 probability per call; if the fuzzer manages it we'd see
    // a non-Err return, which is fine - we just don't make any
    // assertion about it (the AEAD already authenticated the AAD).
    let _ = aead::open(suite, &*file_key, &nonce, &aad, ct);
});
