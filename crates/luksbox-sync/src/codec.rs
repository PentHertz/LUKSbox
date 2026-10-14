// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Penthertz <https://penthertz.com> (https://x.com/PentHertz)

//! Sealing and opening bundle objects.
//!
//! ```text
//! object = commit (32) || AEAD(K_enc, nonce = 0^12, AAD, plaintext) || tag (16)
//! commit = HMAC-SHA256(K_com, "lbx:sync/commit/v1" || kind || oid)
//! AAD    = "lbxs" || format u16 LE || kind u8 || bid (16) || oid (32) || binding
//! binding: page = page index u64 LE, table = block index u64 LE,
//!          manifest / lease = empty
//! ```
//!
//! No magic or version byte appears in clear: every object is uniformly
//! random bytes, and kind and version come from the folder and the
//! associated data. The commitment is checked (constant time) before the
//! AEAD runs: GCM-family AEADs do not commit to their key, so without it
//! an object could be crafted to decrypt validly under two keys.
//!
//! Object ids are generated here, never passed in: `seal_new` draws a
//! fresh id for every object, which is what makes the single-use key and
//! the zero nonce safe (invariant I2 of `docs/CLOUD_SYNC_IMPLEMENTATION.md`).

use hmac::{Hmac, Mac};
use luksbox_core::aead;
use sha2::Sha256;
use subtle::ConstantTimeEq;
use zeroize::Zeroizing;

use crate::error::{Result, SyncError};
use crate::keys::{BundleKeys, Kind};
use crate::names::ObjectId;

/// Version of the bundle object format, bound into every AAD.
pub const FORMAT_VERSION: u16 = 1;
const COMMIT_LEN: usize = 32;
const TAG_LEN: usize = 16;
/// Bytes an object adds around its plaintext.
pub const OVERHEAD: usize = COMMIT_LEN + TAG_LEN;
const COMMIT_LABEL: &[u8] = b"lbx:sync/commit/v1";
const AAD_MAGIC: &[u8] = b"lbxs";
const ZERO_NONCE: [u8; 12] = [0u8; 12];

/// Where an object sits, bound into its AAD.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Binding {
    None,
    Index(u64),
}

fn aad(keys: &BundleKeys, kind: Kind, oid: &ObjectId, binding: Binding) -> Vec<u8> {
    let mut a = Vec::with_capacity(4 + 2 + 1 + 16 + 32 + 8);
    a.extend_from_slice(AAD_MAGIC);
    a.extend_from_slice(&FORMAT_VERSION.to_le_bytes());
    a.push(kind as u8);
    a.extend_from_slice(&keys.bundle().0);
    a.extend_from_slice(&oid.0);
    if let Binding::Index(i) = binding {
        a.extend_from_slice(&i.to_le_bytes());
    }
    a
}

fn commitment(com: &[u8; 32], kind: Kind, oid: &ObjectId) -> [u8; COMMIT_LEN] {
    let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(com).expect("HMAC accepts 32-byte keys");
    mac.update(COMMIT_LABEL);
    mac.update(&[kind as u8]);
    mac.update(&oid.0);
    mac.finalize().into_bytes().into()
}

/// Seal `plaintext` as a new object with a fresh id.
pub fn seal_new(
    keys: &BundleKeys,
    kind: Kind,
    binding: Binding,
    plaintext: &[u8],
) -> Result<(ObjectId, Vec<u8>)> {
    let oid = ObjectId::random()?;
    let bytes = seal_under(keys, kind, &oid, binding, plaintext)?;
    Ok((oid, bytes))
}

/// Seal under `oid`. Private: every caller goes through `seal_new`, so
/// no id (no key) ever seals two plaintexts.
fn seal_under(
    keys: &BundleKeys,
    kind: Kind,
    oid: &ObjectId,
    binding: Binding,
    plaintext: &[u8],
) -> Result<Vec<u8>> {
    let k = keys.object_keys(kind, oid);
    let ct = aead::seal(
        keys.suite(),
        &k.enc,
        &ZERO_NONCE,
        &aad(keys, kind, oid, binding),
        plaintext,
    )?;
    let mut out = Vec::with_capacity(COMMIT_LEN + ct.len());
    out.extend_from_slice(&commitment(&k.com, kind, oid));
    out.extend_from_slice(&ct);
    Ok(out)
}

/// Verify and open an object. `display` names it in errors. Nothing of
/// the object is interpreted before both checks pass.
pub fn open(
    keys: &BundleKeys,
    kind: Kind,
    oid: &ObjectId,
    binding: Binding,
    object: &[u8],
    display: impl FnOnce() -> String,
) -> Result<Zeroizing<Vec<u8>>> {
    if object.len() < OVERHEAD {
        return Err(SyncError::ObjectAuth { name: display() });
    }
    let k = keys.object_keys(kind, oid);
    let (stored, ct) = object.split_at(COMMIT_LEN);
    let expected = commitment(&k.com, kind, oid);
    if !bool::from(stored.ct_eq(&expected)) {
        return Err(SyncError::ObjectAuth { name: display() });
    }
    match aead::open(
        keys.suite(),
        &k.enc,
        &ZERO_NONCE,
        &aad(keys, kind, oid, binding),
        ct,
    ) {
        Ok(pt) => Ok(Zeroizing::new(pt)),
        Err(_) => Err(SyncError::ObjectAuth { name: display() }),
    }
}

/// Frame a variable-length payload into exactly `total` plaintext bytes:
/// `len u32 LE || payload || zero padding`.
pub fn frame(payload: &[u8], total: usize) -> Result<Zeroizing<Vec<u8>>> {
    if payload.len() > total.saturating_sub(4) || payload.len() > u32::MAX as usize {
        return Err(SyncError::Limit("payload larger than its object size"));
    }
    let mut out = Zeroizing::new(vec![0u8; total]);
    out[..4].copy_from_slice(&(payload.len() as u32).to_le_bytes());
    out[4..4 + payload.len()].copy_from_slice(payload);
    Ok(out)
}

/// Inverse of `frame`, strict: the length must fit and every padding
/// byte must be zero, so one plaintext has exactly one valid reading.
pub fn unframe<'a>(pt: &'a [u8], display: impl FnOnce() -> String) -> Result<&'a [u8]> {
    if pt.len() < 4 {
        return Err(SyncError::Malformed {
            name: display(),
            why: "framed object too short",
        });
    }
    let len = u32::from_le_bytes(pt[..4].try_into().expect("4 bytes")) as usize;
    let body = &pt[4..];
    if len > body.len() {
        return Err(SyncError::Malformed {
            name: display(),
            why: "framed length out of range",
        });
    }
    if body[len..].iter().any(|&b| b != 0) {
        return Err(SyncError::Malformed {
            name: display(),
            why: "non-zero padding",
        });
    }
    Ok(&body[..len])
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keys::tests::fixed_keys;
    use luksbox_core::CipherSuite;

    const SUITES: [CipherSuite; 3] = [
        CipherSuite::Aes256Gcm,
        CipherSuite::ChaCha20Poly1305,
        CipherSuite::Aes256GcmSiv,
    ];

    fn name() -> String {
        "test".into()
    }

    #[test]
    fn seal_open_round_trip_every_suite() {
        for suite in SUITES {
            let k = fixed_keys(suite, [1; 16]);
            let (oid, obj) = seal_new(&k, Kind::Page, Binding::Index(5), b"hello").unwrap();
            assert_eq!(obj.len(), 5 + OVERHEAD);
            let pt = open(&k, Kind::Page, &oid, Binding::Index(5), &obj, name).unwrap();
            assert_eq!(&pt[..], b"hello");
        }
    }

    #[test]
    fn every_byte_flip_fails() {
        let k = fixed_keys(CipherSuite::Aes256GcmSiv, [1; 16]);
        let (oid, obj) = seal_new(&k, Kind::Table, Binding::Index(0), &[0x5a; 64]).unwrap();
        for i in 0..obj.len() {
            let mut bad = obj.clone();
            bad[i] ^= 0x01;
            assert!(
                open(&k, Kind::Table, &oid, Binding::Index(0), &bad, name).is_err(),
                "byte {i}"
            );
        }
        assert!(
            open(
                &k,
                Kind::Table,
                &oid,
                Binding::Index(0),
                &obj[..obj.len() - 1],
                name
            )
            .is_err()
        );
        assert!(open(&k, Kind::Table, &oid, Binding::Index(0), &[], name).is_err());
    }

    #[test]
    fn cut_and_paste_fails() {
        let k = fixed_keys(CipherSuite::Aes256Gcm, [1; 16]);
        let other_bundle = fixed_keys(CipherSuite::Aes256Gcm, [2; 16]);
        let (oid, obj) = seal_new(&k, Kind::Page, Binding::Index(3), b"page").unwrap();
        let other = ObjectId([0x11; 32]);
        // Other id, other position, other kind, other bundle: all fail.
        assert!(open(&k, Kind::Page, &other, Binding::Index(3), &obj, name).is_err());
        assert!(open(&k, Kind::Page, &oid, Binding::Index(4), &obj, name).is_err());
        assert!(open(&k, Kind::Page, &oid, Binding::None, &obj, name).is_err());
        assert!(open(&k, Kind::Table, &oid, Binding::Index(3), &obj, name).is_err());
        assert!(
            open(
                &other_bundle,
                Kind::Page,
                &oid,
                Binding::Index(3),
                &obj,
                name
            )
            .is_err()
        );
    }

    #[test]
    fn fresh_ids_for_identical_plaintexts() {
        let k = fixed_keys(CipherSuite::Aes256GcmSiv, [1; 16]);
        let (a, oa) = seal_new(&k, Kind::Page, Binding::Index(0), &[0; 32]).unwrap();
        let (b, ob) = seal_new(&k, Kind::Page, Binding::Index(0), &[0; 32]).unwrap();
        assert_ne!(a, b);
        assert_ne!(oa, ob);
    }

    #[test]
    fn frame_is_strict() {
        let f = frame(b"abc", 16).unwrap();
        assert_eq!(unframe(&f, name).unwrap(), b"abc");
        let mut bad = f.clone();
        bad[15] = 1;
        assert!(unframe(&bad, name).is_err());
        let mut long = f.clone();
        long[..4].copy_from_slice(&13u32.to_le_bytes());
        assert!(unframe(&long, name).is_err());
        assert!(frame(&[0; 13], 16).is_err());
        assert!(unframe(&[0; 3], name).is_err());
    }
}
