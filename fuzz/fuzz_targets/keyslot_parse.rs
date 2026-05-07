// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Penthertz <https://penthertz.com> (https://x.com/PentHertz)

#![no_main]

//! Parse arbitrary 512-byte buffers as a `Keyslot`. Must never panic; any
//! malformed input is returned as `Err(_)`.

use libfuzzer_sys::fuzz_target;
use luksbox_core::{Keyslot, SLOT_SIZE};

fuzz_target!(|data: &[u8]| {
    if data.len() < SLOT_SIZE {
        return;
    }
    let mut buf = [0u8; SLOT_SIZE];
    buf.copy_from_slice(&data[..SLOT_SIZE]);
    let _ = Keyslot::from_bytes(&buf);
});