//! AFL++ harness: arbitrary bytes through the encrypted-metadata
//! pre-AEAD framer. Even though AEAD will fail under our test MVK,
//! the framer must reject every malformed input cleanly.

use luksbox_core::{CipherSuite, MasterVolumeKey};
use luksbox_format::metadata::read_metadata;

fn main() {
    let mvk = MasterVolumeKey::from_bytes([0x42; 32]);
    let salt = [0x77u8; 32];
    afl::fuzz!(|data: &[u8]| {
        let _ = read_metadata(CipherSuite::Aes256Gcm, &mvk, &salt, data);
        let _ = read_metadata(CipherSuite::ChaCha20Poly1305, &mvk, &salt, data);
    });
}
