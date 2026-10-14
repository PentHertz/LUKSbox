// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Penthertz <https://penthertz.com> (https://x.com/PentHertz)

#![no_main]

//! Manifest decoding after authentication: the input is sealed as a
//! manifest under fixed keys and opened again, so postcard decoding and
//! `Manifest::validate` see arbitrary plaintext, as they would from a
//! misbehaving key holder. Every input must end in a clean error or a
//! manifest that passes its own structural checks.

use libfuzzer_sys::fuzz_target;
use luksbox_core::{CipherSuite, MasterVolumeKey};
use luksbox_sync::codec::{self, Binding};
use luksbox_sync::keys::{BundleKeys, Kind};
use luksbox_sync::manifest::{MANIFEST_SIZES, Manifest};
use luksbox_sync::names::BundleId;

fuzz_target!(|data: &[u8]| {
    let mvk = MasterVolumeKey::from_array_ref(&[7u8; 32]);
    let salt = [9u8; 32];
    let keys = BundleKeys::from_subkey_fn(CipherSuite::Aes256GcmSiv, BundleId([1; 16]), |info| {
        mvk.derive_subkey(&salt, info)
    });
    let size = MANIFEST_SIZES[0];
    let Ok(framed) = codec::frame(data, size - codec::OVERHEAD) else {
        return;
    };
    let Ok((oid, obj)) = codec::seal_new(&keys, Kind::Manifest, Binding::None, &framed) else {
        return;
    };
    if let Ok(v) = Manifest::open(&keys, oid, &obj) {
        // Whatever decoded must re-validate and re-seal.
        assert!(v.m.validate(keys.bundle(), &|| "fuzz".into()).is_ok());
        let _ = v.m.seal(&keys);
    }
});
