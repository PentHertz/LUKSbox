// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Penthertz <https://penthertz.com> (https://x.com/PentHertz)

#![no_main]

//! Lease decoding after authentication: the input is framed and sealed
//! as a lease under fixed keys and opened again, so postcard decoding and
//! the lease's own checks see arbitrary plaintext, as they would from a
//! misbehaving key holder. Every input ends in a clean error or a lease
//! that seals again. Added in Round 16.

use libfuzzer_sys::fuzz_target;
use luksbox_core::{CipherSuite, MasterVolumeKey};
use luksbox_sync::codec::{self, Binding};
use luksbox_sync::keys::{BundleKeys, Kind};
use luksbox_sync::lease::{LEASE_LEN, Lease};
use luksbox_sync::names::BundleId;

fuzz_target!(|data: &[u8]| {
    let mvk = MasterVolumeKey::from_array_ref(&[7u8; 32]);
    let salt = [9u8; 32];
    let keys = BundleKeys::from_subkey_fn(CipherSuite::Aes256GcmSiv, BundleId([1; 16]), |info| {
        mvk.derive_subkey(&salt, info)
    });
    let Ok(framed) = codec::frame(data, LEASE_LEN - codec::OVERHEAD) else {
        return;
    };
    let Ok((oid, obj)) = codec::seal_new(&keys, Kind::Lease, Binding::None, &framed) else {
        return;
    };
    if let Ok(l) = Lease::open(&keys, oid, &obj) {
        let (oid2, obj2) = l.seal(&keys).expect("a decoded lease seals again");
        let again = Lease::open(&keys, oid2, &obj2).expect("and opens again");
        assert_eq!(again, l);
        let _ = (l.is_fresh(u64::MAX), l.pins(0));
    }
});
