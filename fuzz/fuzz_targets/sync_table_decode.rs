// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Penthertz <https://penthertz.com> (https://x.com/PentHertz)

#![no_main]

//! Page-table block decoding: arbitrary plaintext (as a key holder could
//! seal) must decode into 1024 entries or fail cleanly, and what decodes
//! must encode back to the same bytes.

use libfuzzer_sys::fuzz_target;
use luksbox_sync::table::{BLOCK_PLAINTEXT_LEN, TableBlock};

fuzz_target!(|data: &[u8]| {
    let mut pt = vec![0u8; BLOCK_PLAINTEXT_LEN];
    let n = data.len().min(pt.len());
    pt[..n].copy_from_slice(&data[..n]);
    if let Ok(b) = TableBlock::decode(&pt, || "fuzz".into()) {
        assert_eq!(&b.encode()[..], &pt[..]);
    }
    let _ = TableBlock::decode(data, || "fuzz".into());
});
