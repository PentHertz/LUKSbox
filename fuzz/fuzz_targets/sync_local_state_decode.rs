// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Penthertz <https://penthertz.com> (https://x.com/PentHertz)

#![no_main]

//! The per-device state record (`<data dir>/luksbox/sync/<bid>/state`):
//! sealed under the bundle's local key. A record found on disk may be
//! garbage (a damaged or half-written file) or, after it authenticates,
//! an arbitrary postcard payload from an older or newer binary. Both
//! must end in a clean error or a state that saves again. Added in
//! Round 16.

use libfuzzer_sys::fuzz_target;
use luksbox_core::{CipherSuite, MasterVolumeKey};
use luksbox_sync::keys::BundleKeys;
use luksbox_sync::local::{LocalStore, MemLocal, seal_local};
use luksbox_sync::names::BundleId;
use luksbox_sync::state::DeviceState;

fuzz_target!(|data: &[u8]| {
    let mvk = MasterVolumeKey::from_array_ref(&[7u8; 32]);
    let salt = [9u8; 32];
    let keys = BundleKeys::from_subkey_fn(CipherSuite::Aes256GcmSiv, BundleId([1; 16]), |info| {
        mvk.derive_subkey(&salt, info)
    });
    // Raw bytes where the sealed record should be: damaged file.
    let mut local = MemLocal::default();
    local.put("state", data).unwrap();
    let _ = DeviceState::load(&keys, &mut local);
    // Authenticated but arbitrary plaintext: another binary's record.
    let Ok(sealed) = seal_local(&keys, "state", data) else {
        return;
    };
    local.put("state", &sealed).unwrap();
    if let Ok(Some(st)) = DeviceState::load(&keys, &mut local) {
        assert_eq!(st.bundle, keys.bundle().0);
        st.save(&keys, &mut local).expect("a decoded state saves again");
        let again = DeviceState::load(&keys, &mut local)
            .expect("and loads again")
            .expect("present");
        assert_eq!(again.own_seq, st.own_seq);
        assert_eq!(again.seen, st.seen);
    }
});
