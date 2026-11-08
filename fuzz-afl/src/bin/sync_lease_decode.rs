//! AFL++ harness for sync-bundle lease decoding. Mirrors
//! `fuzz/fuzz_targets/sync_lease_decode.rs`; shared corpus at
//! `fuzz/corpus/sync_lease_decode/`.

use luksbox_core::{CipherSuite, MasterVolumeKey};
use luksbox_sync::codec::{self, Binding};
use luksbox_sync::keys::{BundleKeys, Kind};
use luksbox_sync::lease::{LEASE_LEN, Lease};
use luksbox_sync::names::BundleId;

fn main() {
    afl::fuzz!(|data: &[u8]| {
        let mvk = MasterVolumeKey::from_array_ref(&[7u8; 32]);
        let salt = [9u8; 32];
        let keys =
            BundleKeys::from_subkey_fn(CipherSuite::Aes256GcmSiv, BundleId([1; 16]), |info| {
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
            assert_eq!(Lease::open(&keys, oid2, &obj2).expect("opens again"), l);
        }
    });
}
