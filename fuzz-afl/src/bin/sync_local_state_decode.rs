//! AFL++ harness for the sync per-device state record. Mirrors
//! `fuzz/fuzz_targets/sync_local_state_decode.rs`; shared corpus at
//! `fuzz/corpus/sync_local_state_decode/`.

use luksbox_core::{CipherSuite, MasterVolumeKey};
use luksbox_sync::keys::BundleKeys;
use luksbox_sync::local::{LocalStore, MemLocal, seal_local};
use luksbox_sync::names::BundleId;
use luksbox_sync::state::DeviceState;

fn main() {
    afl::fuzz!(|data: &[u8]| {
        let mvk = MasterVolumeKey::from_array_ref(&[7u8; 32]);
        let salt = [9u8; 32];
        let keys =
            BundleKeys::from_subkey_fn(CipherSuite::Aes256GcmSiv, BundleId([1; 16]), |info| {
                mvk.derive_subkey(&salt, info)
            });
        let mut local = MemLocal::default();
        local.put("state", data).unwrap();
        let _ = DeviceState::load(&keys, &mut local);
        let Ok(sealed) = seal_local(&keys, "state", data) else {
            return;
        };
        local.put("state", &sealed).unwrap();
        if let Ok(Some(st)) = DeviceState::load(&keys, &mut local) {
            st.save(&keys, &mut local).expect("a decoded state saves again");
            assert!(DeviceState::load(&keys, &mut local).unwrap().is_some());
        }
    });
}
