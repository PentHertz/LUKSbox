//! AFL++ harness: `.hybrid` sidecar parser (v1 + v2 with per-entry
//! ML-KEM level byte → variable entry size).

use std::io::Write;

use luksbox_format::hybrid_sidecar;

fn main() {
    // Pre-create the temp dir once outside the fuzz loop, saves a
    // mkdir + rmdir syscall per iteration. Each iteration just
    // overwrites the same file.
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("v.hybrid");

    afl::fuzz!(|data: &[u8]| {
        if let Ok(mut f) = std::fs::File::create(&path) {
            if f.write_all(data).is_err() {
                return;
            }
        }
        let _ = hybrid_sidecar::read(&path);
    });
}
