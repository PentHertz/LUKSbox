//! AFL++ harness for sync-bundle manifest decoding. Mirrors
//! `fuzz/fuzz_targets/sync_manifest_decode.rs`; shared corpus at
//! `fuzz/corpus/sync_manifest_decode/`.

use luksbox_core::{CipherSuite, MasterVolumeKey};
use luksbox_sync::codec::{self, Binding};
use luksbox_sync::keys::{BundleKeys, Kind};
use luksbox_sync::manifest::{MANIFEST_SIZES, Manifest};
use luksbox_sync::names::BundleId;

fn main() {
    afl::fuzz!(|data: &[u8]| {
        let mvk = MasterVolumeKey::from_array_ref(&[7u8; 32]);
        let salt = [9u8; 32];
        let keys =
            BundleKeys::from_subkey_fn(CipherSuite::Aes256GcmSiv, BundleId([1; 16]), |info| {
                mvk.derive_subkey(&salt, info)
            });
        let size = MANIFEST_SIZES[0];
        let Ok(framed) = codec::frame(data, size - codec::OVERHEAD) else {
            return;
        };
        let Ok((oid, obj)) = codec::seal_new(&keys, Kind::Manifest, Binding::None, &framed)
        else {
            return;
        };
        if let Ok(v) = Manifest::open(&keys, oid, &obj) {
            assert!(v.m.validate(keys.bundle(), &|| "fuzz".into()).is_ok());
            let _ = v.m.seal(&keys);
        }
    });
}
