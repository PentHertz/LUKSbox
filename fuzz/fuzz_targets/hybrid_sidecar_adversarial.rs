// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Penthertz <https://penthertz.com> (https://x.com/PentHertz)

#![no_main]

//! Adversarial-entry sidecar fuzzer.
//!
//! The sibling `hybrid_sidecar_parse` target throws random bytes at
//! `hybrid_sidecar::read` and asserts no panic. This target is more
//! structured: it builds a *structurally-valid* v2 sidecar with
//! fuzzer-controlled count, slot indices, level bytes, and pubkey/ct
//! contents, then runs the full attack chain:
//!
//!   1. Parser must either reject (duplicates / count > MAX / level
//!      mismatch / wrong-size body) OR accept cleanly.
//!   2. If accepted, the entries must round-trip back through `write`
//!      and produce the same parse output (modulo intentional
//!      reordering by the writer, which doesn't happen today).
//!   3. NO PANIC at any step.
//!
//! This target catches: integer overflows in count/length math,
//! out-of-bounds reads in find(), duplicate-slot-idx behavior,
//! length-mismatch behavior, oversized-pubkey handling.

use std::io::Write;

use libfuzzer_sys::fuzz_target;
use luksbox_format::hybrid_sidecar::{self, HybridEntry};
use luksbox_pq::PqParams;

const PUBKEY_LEN_768: usize = 1184;
const CIPHERTEXT_LEN_768: usize = 1088;
const PUBKEY_LEN_1024: usize = 1568;
const CIPHERTEXT_LEN_1024: usize = 1568;
const MAX_ENTRIES: usize = 8;

/// Build entries from fuzz input. Returns Some(entries) if we got
/// enough bytes, None otherwise. Each entry consumes:
///   1 B slot_idx | 1 B level | pubkey | ciphertext
/// Pubkey/ct sizes are determined by the level byte (parser-correct
/// shapes: 1184/1088 for Ml768, 1568/1568 for Ml1024).
fn entries_from_fuzz(data: &[u8]) -> Option<Vec<HybridEntry>> {
    if data.is_empty() {
        return None;
    }
    // First byte = entry count, capped at MAX_ENTRIES + 2 so we
    // sometimes exceed the cap and exercise the rejection path.
    let count = (data[0] as usize) % (MAX_ENTRIES + 2);
    let mut cursor = 1;
    let mut entries = Vec::with_capacity(count);
    for _ in 0..count {
        if cursor + 2 >= data.len() {
            return None;
        }
        let slot_idx = data[cursor];
        let level_byte = data[cursor + 1] & 0x01; // 0 or 1 -> Ml768 or Ml1024
        cursor += 2;
        let (level, pk_len, ct_len) = if level_byte == 0 {
            (PqParams::Ml768, PUBKEY_LEN_768, CIPHERTEXT_LEN_768)
        } else {
            (PqParams::Ml1024, PUBKEY_LEN_1024, CIPHERTEXT_LEN_1024)
        };
        if cursor + pk_len + ct_len > data.len() {
            // Pad with zero rather than abort - exercises the
            // tampered-pubkey/ct path with arbitrary content.
            let mut pubkey = vec![0u8; pk_len];
            let mut ct = vec![0u8; ct_len];
            let avail = data.len().saturating_sub(cursor);
            let pk_take = avail.min(pk_len);
            pubkey[..pk_take].copy_from_slice(&data[cursor..cursor + pk_take]);
            let ct_avail = avail.saturating_sub(pk_len);
            let ct_take = ct_avail.min(ct_len);
            if ct_take > 0 {
                ct[..ct_take].copy_from_slice(&data[cursor + pk_len..cursor + pk_len + ct_take]);
            }
            entries.push(HybridEntry { slot_idx, level, pubkey, ciphertext: ct });
            return Some(entries);
        }
        let pubkey = data[cursor..cursor + pk_len].to_vec();
        cursor += pk_len;
        let ct = data[cursor..cursor + ct_len].to_vec();
        cursor += ct_len;
        entries.push(HybridEntry { slot_idx, level, pubkey, ciphertext: ct });
    }
    Some(entries)
}

fuzz_target!(|data: &[u8]| {
    let dir = match tempfile::tempdir() {
        Ok(d) => d,
        Err(_) => return,
    };
    let path = dir.path().join("v.lbx.hybrid");

    let entries = match entries_from_fuzz(data) {
        Some(e) => e,
        None => return,
    };

    // Try writing the entries. The writer enforces the invariants
    // (count <= MAX_ENTRIES, pubkey_len/ct_len match the level
    // byte), so it may reject.
    let write_result = hybrid_sidecar::write(&path, &entries);
    if write_result.is_err() {
        // Writer correctly rejected hostile input; nothing more to
        // exercise from this seed.
        return;
    }

    // Writer accepted. Parser must either accept and round-trip
    // cleanly, OR reject (duplicates / etc.) without panic.
    let parsed = match hybrid_sidecar::read(&path) {
        Ok(p) => p,
        Err(_) => return, // parser correctly rejected (e.g. dup slot_idx)
    };

    // Round-trip property: parsed entries match what we wrote (modulo
    // the input being internally consistent, which the writer's
    // length-check already enforced).
    assert_eq!(
        parsed.len(),
        entries.len(),
        "parsed entry count != written"
    );
    for (a, b) in parsed.iter().zip(entries.iter()) {
        assert_eq!(a.slot_idx, b.slot_idx);
        assert_eq!(a.level, b.level);
        assert_eq!(a.pubkey, b.pubkey);
        assert_eq!(a.ciphertext, b.ciphertext);
    }

    // find() must not panic for any slot_idx in 0..=255 (full u8
    // domain), regardless of which slot_idxs are actually present.
    for s in 0u8..=255 {
        let _ = hybrid_sidecar::find(&parsed, s);
    }

    // Bonus: also tamper a single byte in the on-disk file and
    // verify the parser still doesn't panic on the result.
    if let Ok(bytes) = std::fs::read(&path) {
        if !bytes.is_empty() {
            let mut tampered = bytes;
            // Flip a fuzzer-chosen byte (or byte 0 if input is
            // exhausted) to exercise the parser's robustness to
            // arbitrary on-disk corruption.
            let off = (data.first().copied().unwrap_or(0) as usize) % tampered.len();
            tampered[off] ^= 0xff;
            let mut f = match std::fs::File::create(&path) {
                Ok(f) => f,
                Err(_) => return,
            };
            if f.write_all(&tampered).is_err() {
                return;
            }
            let _ = hybrid_sidecar::read(&path);
        }
    }
});
