// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Penthertz <https://penthertz.com> (https://x.com/PentHertz)

//! Key schedule of a sync bundle.
//!
//! One root key per object kind, each an HKDF subkey of the MVK
//! (`Container::derive_subkey`: extract with the vault's `header_salt`,
//! expand with a label that includes the bundle id). Every object then
//! gets its own encryption key and commitment key, expanded from its
//! kind's root with the object's random 256-bit id:
//!
//! ```text
//! R_kind        = HKDF(MVK, header_salt, "lbx:sync/<kind>/v1" || bid)
//! K_enc || K_com = HKDF-Expand(R_kind, "lbx:sync/obj/v1" || kind || oid, 64)
//! ```
//!
//! A key therefore encrypts exactly one object, whichever device wrote
//! it, so the AEAD nonce can be the constant zero and the design does
//! not depend on random nonces never colliding across devices.

use hkdf::Hkdf;
use luksbox_core::{CipherSuite, SubKey};
use sha2::Sha256;
use zeroize::Zeroizing;

use crate::names::{BundleId, ObjectId};

/// Kind of a sealed object. The byte value goes into every derivation
/// and every object's associated data.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
#[repr(u8)]
pub enum Kind {
    Page = 1,
    Table = 2,
    Manifest = 3,
    Lease = 4,
}

const LABEL_PAGE: &[u8] = b"lbx:sync/page/v1";
const LABEL_TABLE: &[u8] = b"lbx:sync/table/v1";
const LABEL_MANIFEST: &[u8] = b"lbx:sync/manifest/v1";
const LABEL_LEASE: &[u8] = b"lbx:sync/lease/v1";
const LABEL_LOCAL: &[u8] = b"lbx:sync/local/v1";
const LABEL_OBJECT: &[u8] = b"lbx:sync/obj/v1";

/// Root keys of one bundle under one MVK. Dropping it wipes them.
pub struct BundleKeys {
    suite: CipherSuite,
    bundle: BundleId,
    page: SubKey,
    table: SubKey,
    manifest: SubKey,
    lease: SubKey,
    local: SubKey,
}

/// Per-object keys: `enc` for the AEAD, `com` for the key commitment.
pub(crate) struct ObjectKeys {
    pub enc: Zeroizing<[u8; 32]>,
    pub com: Zeroizing<[u8; 32]>,
}

impl BundleKeys {
    /// Derive the roots for `bundle` from an unlocked container.
    pub fn from_container(container: &luksbox_format::Container, bundle: BundleId) -> Self {
        Self::from_subkey_fn(container.header.cipher_suite, bundle, |info| {
            container.derive_subkey(info)
        })
    }

    /// Derive the roots with any `derive_subkey`-shaped function (tests,
    /// test vectors).
    pub fn from_subkey_fn(
        suite: CipherSuite,
        bundle: BundleId,
        derive: impl Fn(&[u8]) -> SubKey,
    ) -> Self {
        let with_bid = |label: &[u8]| {
            let mut info = Zeroizing::new(Vec::with_capacity(label.len() + bundle.0.len()));
            info.extend_from_slice(label);
            info.extend_from_slice(&bundle.0);
            derive(&info)
        };
        Self {
            suite,
            bundle,
            page: with_bid(LABEL_PAGE),
            table: with_bid(LABEL_TABLE),
            manifest: with_bid(LABEL_MANIFEST),
            lease: with_bid(LABEL_LEASE),
            local: with_bid(LABEL_LOCAL),
        }
    }

    pub fn suite(&self) -> CipherSuite {
        self.suite
    }

    pub fn bundle(&self) -> BundleId {
        self.bundle
    }

    /// Key for this device's local state (outside the bundle).
    pub fn local_key(&self) -> &[u8; 32] {
        &self.local
    }

    fn root(&self, kind: Kind) -> &[u8; 32] {
        match kind {
            Kind::Page => &self.page,
            Kind::Table => &self.table,
            Kind::Manifest => &self.manifest,
            Kind::Lease => &self.lease,
        }
    }

    pub(crate) fn object_keys(&self, kind: Kind, oid: &ObjectId) -> ObjectKeys {
        // The roots are uniformly random 32-byte HKDF outputs, so they
        // are valid PRKs for HKDF-Expand directly.
        let hk = Hkdf::<Sha256>::from_prk(self.root(kind)).expect("32-byte PRK is HashLen");
        let mut info = [0u8; LABEL_OBJECT.len() + 1 + 32];
        info[..LABEL_OBJECT.len()].copy_from_slice(LABEL_OBJECT);
        info[LABEL_OBJECT.len()] = kind as u8;
        info[LABEL_OBJECT.len() + 1..].copy_from_slice(&oid.0);
        let mut okm = Zeroizing::new([0u8; 64]);
        hk.expand(&info, okm.as_mut_slice())
            .expect("64 <= 255 * HashLen");
        let mut enc = Zeroizing::new([0u8; 32]);
        let mut com = Zeroizing::new([0u8; 32]);
        enc.copy_from_slice(&okm[..32]);
        com.copy_from_slice(&okm[32..]);
        ObjectKeys { enc, com }
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use luksbox_core::MasterVolumeKey;

    /// Keys from a fixed MVK and salt, the same derivation a container
    /// performs.
    pub(crate) fn fixed_keys(suite: CipherSuite, bid: [u8; 16]) -> BundleKeys {
        let mvk = MasterVolumeKey::from_array_ref(&[7u8; 32]);
        let salt = [9u8; 32];
        BundleKeys::from_subkey_fn(suite, BundleId(bid), |info| mvk.derive_subkey(&salt, info))
    }

    #[test]
    fn object_keys_are_distinct_per_kind_and_object() {
        let k = fixed_keys(CipherSuite::Aes256GcmSiv, [1; 16]);
        let a = ObjectId([1; 32]);
        let b = ObjectId([2; 32]);
        let ka = k.object_keys(Kind::Page, &a);
        let kb = k.object_keys(Kind::Page, &b);
        let kt = k.object_keys(Kind::Table, &a);
        assert_ne!(*ka.enc, *kb.enc);
        assert_ne!(*ka.enc, *kt.enc);
        assert_ne!(*ka.enc, *ka.com);
        // Deterministic for the same inputs.
        assert_eq!(*k.object_keys(Kind::Page, &a).enc, *ka.enc);
    }

    #[test]
    fn bundle_id_separates_key_spaces() {
        let k1 = fixed_keys(CipherSuite::Aes256GcmSiv, [1; 16]);
        let k2 = fixed_keys(CipherSuite::Aes256GcmSiv, [2; 16]);
        let o = ObjectId([3; 32]);
        assert_ne!(
            *k1.object_keys(Kind::Manifest, &o).enc,
            *k2.object_keys(Kind::Manifest, &o).enc
        );
        assert_ne!(k1.local_key(), k2.local_key());
    }
}
