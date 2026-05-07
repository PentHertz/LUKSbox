// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Penthertz <https://penthertz.com> (https://x.com/PentHertz)

#![no_main]

//! Parse arbitrary bytes as a `.kyber` seed file. The parser does
//! magic / version / safe-Argon2id-bounds / AEAD-decrypt. Hostile
//! inputs we want never to panic:
//!   - any byte sequence shorter than FILE_LEN
//!   - magic match but version 0xff
//!   - magic+version match but Argon2id params at u32::MAX (DoS guard)
//!   - hostile salt / nonce / ct values
//!
//! Decryption will always fail under the constant test passphrase
//! unless the data was produced by `seed_file::write` with that
//! passphrase, that's fine, we're fuzzing the pre-AEAD parser
//! and the safe-bounds rejection path.
//!
//! ### Why we rewrite `m_cost_kib` before calling `read`
//!
//! The seed file's on-disk Argon2id params are bounded by the DoS
//! guard at `SAFE_M_COST_KIB_MAX = 4 GiB`. That bound exists so that
//! a legitimate "Sensitive" tier (1 GiB+) is allowed, while
//! u32::MAX-style hostile values get rejected. Once the fuzzer
//! discovers an input where `m_cost_kib` equals the legal maximum,
//! the parser correctly accepts it and Argon2id correctly proceeds
//! to allocate 4 GiB - which legitimately exceeds libFuzzer's
//! default 2 GiB rss_limit and aborts the run with a false-positive
//! OOM. This is not a security bug; it's the fuzzer treating a
//! legitimate-but-expensive code path as a defect.
//!
//! The DoS-guard rejection paths for hostile params are already
//! covered by the dedicated `crates/luksbox-pq/tests/seed_file_dos_guard.rs`
//! integration tests, so we don't lose that coverage by clamping
//! the fuzzer-supplied m_cost. We rewrite `m_cost_kib` to the same
//! tiny value used by `Argon2idParams::TEST_ONLY` (8 KiB) so the
//! parser exercises every other field freely while Argon2id stays
//! well inside the libFuzzer process budget.
//!
//! Bounds rewrite is in-place on a Vec copy of the input, so the
//! parser sees a synthetic "valid m_cost, attacker-chosen
//! everything-else" input. Inputs whose magic / version don't match
//! still get rejected at those earlier checks before m_cost is read.

use std::io::Write;

use libfuzzer_sys::fuzz_target;
use luksbox_pq::seed_file;

const PASS: &[u8] = b"correct horse battery staple";

/// Offset of the `m_cost_kib` field in the seed-file header layout
/// (after 8-byte magic + 1-byte version).
const M_COST_OFFSET: usize = 9;
/// Fuzz-safe Argon2id memory cost, matches `Argon2idParams::TEST_ONLY`.
/// 8 KiB is the smallest legal value the production parser accepts.
const FUZZ_M_COST_KIB: u32 = 8;

fuzz_target!(|data: &[u8]| {
    let dir = match tempfile::tempdir() {
        Ok(d) => d,
        Err(_) => return,
    };
    let path = dir.path().join("v.kyber");

    // Clamp the on-disk m_cost_kib so a legitimate-but-large value
    // (up to the SAFE_M_COST_KIB_MAX = 4 GiB bound) doesn't make
    // Argon2id legitimately allocate 4 GiB and tip libFuzzer over
    // its rss limit. See module doc-header for the full rationale.
    let mut data = data.to_vec();
    if data.len() >= M_COST_OFFSET + 4 {
        let bytes = FUZZ_M_COST_KIB.to_le_bytes();
        data[M_COST_OFFSET..M_COST_OFFSET + 4].copy_from_slice(&bytes);
    }

    if std::fs::File::create(&path)
        .and_then(|mut f| f.write_all(&data))
        .is_err()
    {
        return;
    }
    let _ = seed_file::read(&path, PASS);
});