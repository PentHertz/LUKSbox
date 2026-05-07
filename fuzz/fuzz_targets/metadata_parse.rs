// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Penthertz <https://penthertz.com> (https://x.com/PentHertz)

#![no_main]

//! Parse arbitrary bytes as an encrypted metadata region. The region layout is
//! `[12 B nonce | 8 B u64 LE ct_len | ct_len bytes ciphertext+tag | zero pad]`.
//! Only the AEAD verify step would normally reject bad data, but the
//! pre-AEAD parser must be robust against hostile `ct_len` values (overflow,
//! out-of-bounds, etc.) without panicking.

use libfuzzer_sys::fuzz_target;
use luksbox_core::{CipherSuite, MasterVolumeKey};
use luksbox_format::metadata::read_metadata;

fuzz_target!(|data: &[u8]| {
    // A constant key/salt combo is fine, we don't expect AEAD to succeed,
    // we're just exercising the pre-AEAD parser on hostile inputs.
    let mvk = MasterVolumeKey::from_bytes([0x42; 32]);
    let salt = [0x77u8; 32];
    let _ = read_metadata(CipherSuite::Aes256Gcm, &mvk, &salt, data);
    let _ = read_metadata(CipherSuite::ChaCha20Poly1305, &mvk, &salt, data);
});