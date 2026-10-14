// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Penthertz <https://penthertz.com> (https://x.com/PentHertz)

#![no_main]

//! Sync bundle objects (`luksbox_sync::codec::open`): every object in a
//! bundle folder is provider-controlled bytes. Whatever the bytes, the
//! commitment and AEAD checks must end in a clean error (or, for bytes
//! that really were sealed under these keys, the plaintext), never a
//! panic, an out-of-bounds read or an allocation driven by the input.

use libfuzzer_sys::fuzz_target;
use luksbox_core::{CipherSuite, MasterVolumeKey};
use luksbox_sync::codec::{self, Binding};
use luksbox_sync::keys::{BundleKeys, Kind};
use luksbox_sync::names::{BundleId, ObjectId};

fuzz_target!(|data: &[u8]| {
    if data.len() < 34 {
        return;
    }
    let mvk = MasterVolumeKey::from_array_ref(&[7u8; 32]);
    let salt = [9u8; 32];
    let suite = match data[0] % 3 {
        0 => CipherSuite::Aes256Gcm,
        1 => CipherSuite::ChaCha20Poly1305,
        _ => CipherSuite::Aes256GcmSiv,
    };
    let keys = BundleKeys::from_subkey_fn(suite, BundleId([1; 16]), |info| {
        mvk.derive_subkey(&salt, info)
    });
    let kind = match data[1] % 4 {
        0 => Kind::Page,
        1 => Kind::Table,
        2 => Kind::Manifest,
        _ => Kind::Lease,
    };
    let oid = ObjectId([data[1]; 32]);
    let binding = if data[0] & 0x80 != 0 {
        Binding::Index(u64::from(data[1]))
    } else {
        Binding::None
    };
    let _ = codec::open(&keys, kind, &oid, binding, &data[2..], || "fuzz".into());
    let _ = codec::unframe(&data[2..], || "fuzz".into());
});
