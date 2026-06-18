// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Penthertz <https://penthertz.com> (https://x.com/PentHertz)

#![no_main]

//! Drive the in-header Secure Enclave region serializer + parser with
//! attacker-controlled slot indices, blob counts, and blob lengths.
//! Builds a real header via the public API, assigns fuzzer-chosen SEP
//! blobs (`set_sep_blob` enforces the `SepRegionFull` capacity guard),
//! serializes, and re-parses. Invariants:
//!   * never panic on any assignment pattern;
//!   * a header we built must always re-parse (`to_bytes` -> `from_bytes`);
//!   * every blob the API accepted comes back byte-identical, i.e. the
//!     region `[count][slot_idx][blob_len]` table round-trips.
//!
//! Complements `header_parse` (which fuzzes the raw 8 KiB parse): there
//! the SEP flag bit is rarely set by random mutation, so the region
//! parser stays cold without the curated `seed_sep` corpus entry.

use libfuzzer_sys::fuzz_target;
use luksbox_core::{
    Argon2idParams, CipherSuite, Header, KdfId, Keyslot, MasterVolumeKey, MAX_KEYSLOTS,
};

fuzz_target!(|data: &[u8]| {
    let mvk = MasterVolumeKey::from_bytes([0x21; 32]);
    let mut header = Header::new(CipherSuite::Aes256GcmSiv, KdfId::Argon2id, 4096, 8192);

    // Weak Argon2id params: this is a parser/serializer fuzzer, not a
    // KDF benchmark. A real keyslot keeps the header structurally
    // complete, mirroring the in-tree `sep_region_roundtrip` test.
    let weak = Argon2idParams {
        m_cost_kib: 8,
        t_cost: 1,
        p_cost: 1,
    };
    if let Ok(slot) =
        Keyslot::new_passphrase(CipherSuite::Aes256GcmSiv, &mvk, b"pw", weak, &header.header_salt)
    {
        let _ = header.install_slot(0, slot);
    }

    // Carve the fuzzer bytes into (slot_idx, blob) assignments:
    //   [count][ idx, len_lo, len_hi, <len bytes> ] ...
    let mut cur = data;
    let n = cur.first().copied().unwrap_or(0) as usize;
    cur = cur.get(1..).unwrap_or(&[]);
    let mut expected: [Option<Vec<u8>>; MAX_KEYSLOTS] = std::array::from_fn(|_| None);
    for _ in 0..n {
        if cur.len() < 3 {
            break;
        }
        let idx = (cur[0] as usize) % MAX_KEYSLOTS;
        let len = u16::from_le_bytes([cur[1], cur[2]]) as usize;
        cur = &cur[3..];
        let take = len.min(cur.len());
        let blob = cur[..take].to_vec();
        cur = &cur[take..];
        // set_sep_blob may reject (e.g. SepRegionFull); only blobs it
        // accepted are expected to survive the round-trip. A later
        // assignment to the same idx overwrites the earlier one.
        if header.set_sep_blob(idx, blob.clone()).is_ok() {
            expected[idx] = Some(blob);
        }
    }

    let bytes = header.to_bytes(&mvk);
    let parsed = Header::from_bytes(&bytes).expect("a header we built must re-parse");
    for (idx, want) in expected.iter().enumerate() {
        assert_eq!(
            parsed.sep_blob(idx),
            want.as_deref(),
            "SEP blob at slot {idx} must round-trip byte-identical"
        );
    }
});
