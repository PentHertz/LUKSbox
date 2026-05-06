//! AFL++ harness: `.kyber` seed file parser. Magic / version /
//! safe-Argon2id-bounds / AEAD path. The DoS-guard on Argon2id params
//! lives upstream of the actual KDF run, so most inputs reject fast;
//! a few hit the real Argon2id and are slow (one iteration ≥100 ms).

use std::io::Write;

use luksbox_pq::seed_file;

const PASS: &[u8] = b"correct horse battery staple";

fn main() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("v.kyber");
    afl::fuzz!(|data: &[u8]| {
        if let Ok(mut f) = std::fs::File::create(&path) {
            if f.write_all(data).is_err() {
                return;
            }
        }
        let _ = seed_file::read(&path, PASS);
    });
}
