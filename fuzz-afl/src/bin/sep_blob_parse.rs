//! AFL++ harness: arbitrary bytes fed to `luksbox_sep::SepBlob::from_bytes`,
//! the per-slot Secure Enclave blob decoder reached from the in-header SEP
//! region and the CryptoKit FFI return. Must never panic; malformed input
//! returns `Err(_)`. The `SepBlob` type compiles on every host (enclave ops
//! are `cfg`-gated), so this runs in ordinary Linux server fuzzing.

use luksbox_sep::SepBlob;

fn main() {
    afl::fuzz!(|data: &[u8]| {
        let _ = SepBlob::from_bytes(data);
    });
}
