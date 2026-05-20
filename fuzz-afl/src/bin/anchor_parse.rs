//! AFL++ harness for the standard + deniable anchor readers.
//! Mirrors the libfuzzer target at `fuzz/fuzz_targets/anchor_parse.rs`;
//! same input layout, same constants. Shared corpus at
//! `fuzz/corpus/anchor_parse/`.

use std::io::Write;

use luksbox_core::{CipherSuite, MasterVolumeKey};
use luksbox_format::anchor;

const MVK_BYTES: [u8; 32] = [0xC3; 32];
const HEADER_SALT: [u8; 32] = [0x3C; 32];
const PER_VAULT_SALT: [u8; 32] = [0xA7; 32];

const SUITES: [CipherSuite; 3] = [
    CipherSuite::Aes256GcmSiv,
    CipherSuite::Aes256Gcm,
    CipherSuite::ChaCha20Poly1305,
];

fn main() {
    afl::fuzz!(|data: &[u8]| {
        if data.len() > 8192 {
            return;
        }
        let tmp = match tempfile::NamedTempFile::new() {
            Ok(t) => t,
            Err(_) => return,
        };
        let path = tmp.path().to_path_buf();
        if std::fs::File::create(&path)
            .and_then(|mut f| f.write_all(data))
            .is_err()
        {
            return;
        }
        let mvk = MasterVolumeKey::from_bytes(MVK_BYTES);
        let _ = anchor::read_and_verify(&path, &mvk, &HEADER_SALT);

        let suite = if data.is_empty() {
            SUITES[0]
        } else {
            SUITES[(data[0] as usize) % SUITES.len()]
        };
        let _ = anchor::deniable_read_and_verify(&path, &mvk, &PER_VAULT_SALT, suite);
    });
}
