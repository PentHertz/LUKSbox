// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Penthertz <https://penthertz.com> (https://x.com/PentHertz)

#![no_main]

//! Parse arbitrary bytes as a `luksbox_sep::SepBlob`. This is the
//! per-slot Secure Enclave blob decoder
//! (`[flags][sep_data_len: u16 LE][sep_data][eph_pub: 65]`). It runs on
//! bytes that come straight off disk (each entry of the in-header SEP
//! region) and on the buffer returned across the Swift/CryptoKit FFI,
//! i.e. attacker-influenced input. Must never panic; any malformed
//! input is returned as `Err(_)`. The `SepBlob` type compiles on every
//! host (only the enclave ops are `cfg`-gated), so this target runs in
//! ordinary Linux CI fuzzing without macOS hardware.

use libfuzzer_sys::fuzz_target;
use luksbox_sep::SepBlob;

fuzz_target!(|data: &[u8]| {
    let _ = SepBlob::from_bytes(data);
});
