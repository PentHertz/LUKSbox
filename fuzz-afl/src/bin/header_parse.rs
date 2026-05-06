//! AFL++ harness: arbitrary 8 KB buffers fed to `Header::from_bytes`.
//! Mirrors `fuzz/fuzz_targets/header_parse.rs` (libfuzzer variant).

use luksbox_core::{HEADER_SIZE, Header};

fn main() {
    afl::fuzz!(|data: &[u8]| {
        if data.len() < HEADER_SIZE {
            return;
        }
        let mut buf = [0u8; HEADER_SIZE];
        buf.copy_from_slice(&data[..HEADER_SIZE]);
        let _ = Header::from_bytes(&buf);
    });
}
