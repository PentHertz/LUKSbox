// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Penthertz <https://penthertz.com> (https://x.com/PentHertz)

#![no_main]

//! Parse arbitrary bytes as a `Header`. The parser must reject garbage with an
//! `Err(_)` rather than panicking, indexing out of bounds, or looping.

use libfuzzer_sys::fuzz_target;
use luksbox_core::{HEADER_SIZE, Header};

fuzz_target!(|data: &[u8]| {
    if data.len() < HEADER_SIZE {
        return;
    }
    let mut buf = [0u8; HEADER_SIZE];
    buf.copy_from_slice(&data[..HEADER_SIZE]);
    let _ = Header::from_bytes(&buf);
});