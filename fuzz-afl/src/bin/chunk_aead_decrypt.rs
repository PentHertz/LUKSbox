//! AFL++ harness for the per-chunk AEAD decrypt path. Mirrors the
//! libfuzzer target at
//! `fuzz/fuzz_targets/chunk_aead_decrypt.rs`. AAD shape, suite
//! enumeration, and input layout MUST stay in lock-step with that
//! file; the two engines share the `fuzz/corpus/chunk_aead_decrypt/`
//! corpus.
//!
//! See the libfuzzer variant's header for threat model + rationale.

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

fn main() {
    afl::fuzz!(|data: &[u8]| {
        if data.len() < HDR_LEN || data.len() > MAX_INPUT {
            return;
        }
        let suite = SUITES[(data[0] as usize) % SUITES.len()];

        let file_id = u64::from_le_bytes(data[1..9].try_into().unwrap());
        let chunk_idx = u32::from_le_bytes(data[9..13].try_into().unwrap());
        let generation = u64::from_le_bytes(data[13..21].try_into().unwrap());
        let nonce: [u8; 12] = data[21..33].try_into().unwrap();
        let ct = &data[33..];

        let mut aad = [0u8; 20];
        aad[..8].copy_from_slice(&file_id.to_le_bytes());
        aad[8..12].copy_from_slice(&chunk_idx.to_le_bytes());
        aad[12..].copy_from_slice(&generation.to_le_bytes());

        let mvk = MasterVolumeKey::from_bytes(MVK_BYTES);
        let file_key = file_key_for_mvk(&mvk, &HEADER_SALT, file_id);

        let _ = aead::open(suite, &*file_key, &nonce, &aad, ct);
    });
}
