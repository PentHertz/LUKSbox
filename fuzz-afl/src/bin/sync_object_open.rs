//! AFL++ harness for the sync-bundle object codec. Mirrors
//! `fuzz/fuzz_targets/sync_object_open.rs`; shared corpus at
//! `fuzz/corpus/sync_object_open/`.

use luksbox_core::{CipherSuite, MasterVolumeKey};
use luksbox_sync::codec::{self, Binding};
use luksbox_sync::keys::{BundleKeys, Kind};
use luksbox_sync::names::{BundleId, ObjectId};

fn main() {
    afl::fuzz!(|data: &[u8]| {
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
}
