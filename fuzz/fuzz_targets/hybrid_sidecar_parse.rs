// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Penthertz <https://penthertz.com> (https://x.com/PentHertz)

#![no_main]

//! Parse arbitrary bytes as a `.hybrid` sidecar file. The parser handles
//! v1 (legacy ML-KEM-768 only) and v2 (per-entry level byte → variable
//! entry size). Hostile inputs we want to ensure never panic / overflow:
//!   - claim count > MAX_ENTRIES
//!   - claim level byte = 0 / 0xff
//!   - claim level=2 (1568 B pubkey + 1568 B ct) but only ship a few bytes
//!   - magic match + version 0xff
//!   - empty file
//!   - file with magic only

use std::io::Write;

use libfuzzer_sys::fuzz_target;
use luksbox_format::hybrid_sidecar;

fuzz_target!(|data: &[u8]| {
    // The sidecar parser reads from a path, so we round-trip via a temp
    // file. cheap: ~one syscall per fuzz iteration.
    let dir = match tempfile::tempdir() {
        Ok(d) => d,
        Err(_) => return,
    };
    let path = dir.path().join("v.hybrid");
    if std::fs::File::create(&path)
        .and_then(|mut f| f.write_all(data))
        .is_err()
    {
        return;
    }
    let _ = hybrid_sidecar::read(&path);
});