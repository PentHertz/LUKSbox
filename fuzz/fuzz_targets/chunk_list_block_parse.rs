// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Penthertz <https://penthertz.com> (https://x.com/PentHertz)

#![no_main]

//! Fuzz `chunk::parse_chunk_list_block` (v3 metadata format). The
//! parser sees the decrypted plaintext of a chunk-list block (the
//! AEAD has already verified that an MVK-holder authored these bytes,
//! so we're inside the trust boundary). Even so, a malicious vault
//! author or a future format-version slip could plant bytes whose
//! `count` field is out of range, whose entries are bogus, or whose
//! next-pointer drives an iterator into a loop. The parser MUST:
//!   - never panic on any 4096-byte input,
//!   - never return an entry count larger than `CHUNK_LIST_ENTRIES_PER_BLOCK`,
//!   - never produce a `Some(next)` whose generation is zero (which
//!     is reserved as the "last block" sentinel).
//!
//! Smaller-than-4096 inputs are rejected unconditionally, which the
//! fuzzer can confirm by feeding them.

use libfuzzer_sys::fuzz_target;
use luksbox_vfs::chunk::{
    parse_chunk_list_block, CHUNK_LIST_ENTRIES_PER_BLOCK, CHUNK_PLAINTEXT_SIZE,
};

fuzz_target!(|data: &[u8]| {
    if data.len() != CHUNK_PLAINTEXT_SIZE {
        // The parser must reject this without panicking. Confirm.
        assert!(parse_chunk_list_block(data).is_err());
        return;
    }
    if let Ok((entries, next)) = parse_chunk_list_block(data) {
        // Invariants on success: count is bounded, and any returned
        // "next" ChunkRef has a non-zero generation (zero-gen is the
        // sentinel meaning "no next").
        assert!(entries.len() <= CHUNK_LIST_ENTRIES_PER_BLOCK);
        if let Some(n) = next {
            assert!(n.generation != 0, "next-pointer with generation=0 leaks the sentinel");
        }
    }
});
