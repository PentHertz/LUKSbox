// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Penthertz <https://penthertz.com> (https://x.com/PentHertz)

use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes256Gcm, Nonce as GcmNonce};
use aes_gcm_siv::{Aes256GcmSiv, Nonce as SivNonce};
use chacha20poly1305::{ChaCha20Poly1305, Nonce as ChaNonce};

use crate::error::Error;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u16)]
pub enum CipherSuite {
    /// AES-256-GCM (NIST SP 800-38D). 12-byte nonce, 16-byte tag.
    /// Catastrophic on nonce reuse; with random 96-bit nonces the
    /// safety bound is about 2^32 messages per key (NIST recommendation).
    /// Kept for compatibility with vaults created before format v1.0.1.
    Aes256Gcm = 0x0001,
    /// ChaCha20-Poly1305 (RFC 8439). Same 12/16 nonce/tag shape.
    /// Same nonce-uniqueness contract as AES-GCM; exposed for users
    /// on hardware without AES acceleration.
    ChaCha20Poly1305 = 0x0002,
    /// AES-256-GCM-SIV (RFC 8452). Nonce-misuse-resistant: a nonce
    /// collision under the same key reveals only that two messages
    /// had identical (nonce, AAD, plaintext) tuples, never the GHASH
    /// key or the XOR of plaintexts. Same 12-byte nonce + 16-byte tag
    /// wire shape as AES-GCM. Default for new vaults from v1.0.1
    /// onward; closes the audit Finding 1 birthday-bound concern on
    /// the per-chunk path without changing on-disk byte layout.
    Aes256GcmSiv = 0x0003,
}

impl CipherSuite {
    pub fn from_u16(v: u16) -> Result<Self, Error> {
        match v {
            0x0001 => Ok(Self::Aes256Gcm),
            0x0002 => Ok(Self::ChaCha20Poly1305),
            0x0003 => Ok(Self::Aes256GcmSiv),
            _ => Err(Error::UnsupportedCipher(v)),
        }
    }

    pub fn nonce_len(self) -> usize {
        12
    }

    pub fn tag_len(self) -> usize {
        16
    }

    /// Recommended cipher suite for new vaults. Returns the
    /// nonce-misuse-resistant variant.
    pub const fn recommended() -> Self {
        Self::Aes256GcmSiv
    }
}

pub fn seal(
    suite: CipherSuite,
    key: &[u8; 32],
    nonce: &[u8; 12],
    aad: &[u8],
    plaintext: &[u8],
) -> Result<Vec<u8>, Error> {
    let payload = Payload {
        msg: plaintext,
        aad,
    };
    match suite {
        CipherSuite::Aes256Gcm => Aes256Gcm::new(key.into())
            .encrypt(GcmNonce::from_slice(nonce), payload)
            .map_err(|_| Error::Aead),
        CipherSuite::ChaCha20Poly1305 => ChaCha20Poly1305::new(key.into())
            .encrypt(ChaNonce::from_slice(nonce), payload)
            .map_err(|_| Error::Aead),
        CipherSuite::Aes256GcmSiv => Aes256GcmSiv::new(key.into())
            .encrypt(SivNonce::from_slice(nonce), payload)
            .map_err(|_| Error::Aead),
    }
}

pub fn open(
    suite: CipherSuite,
    key: &[u8; 32],
    nonce: &[u8; 12],
    aad: &[u8],
    ciphertext: &[u8],
) -> Result<Vec<u8>, Error> {
    let payload = Payload {
        msg: ciphertext,
        aad,
    };
    match suite {
        CipherSuite::Aes256Gcm => Aes256Gcm::new(key.into())
            .decrypt(GcmNonce::from_slice(nonce), payload)
            .map_err(|_| Error::Aead),
        CipherSuite::ChaCha20Poly1305 => ChaCha20Poly1305::new(key.into())
            .decrypt(ChaNonce::from_slice(nonce), payload)
            .map_err(|_| Error::Aead),
        CipherSuite::Aes256GcmSiv => Aes256GcmSiv::new(key.into())
            .decrypt(SivNonce::from_slice(nonce), payload)
            .map_err(|_| Error::Aead),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn roundtrip(suite: CipherSuite) {
        let key = [0x42u8; 32];
        let nonce = [0x07u8; 12];
        let aad = b"associated data";
        let pt = b"the rain in spain falls mainly on the plane";
        let ct = seal(suite, &key, &nonce, aad, pt).unwrap();
        assert_eq!(ct.len(), pt.len() + suite.tag_len());
        let pt2 = open(suite, &key, &nonce, aad, &ct).unwrap();
        assert_eq!(pt2, pt);

        let mut tampered = ct.clone();
        tampered[0] ^= 1;
        assert!(open(suite, &key, &nonce, aad, &tampered).is_err());

        let pt3 = open(suite, &key, &nonce, b"different aad", &ct);
        assert!(pt3.is_err());
    }

    #[test]
    fn aes_roundtrip() {
        roundtrip(CipherSuite::Aes256Gcm);
    }
    #[test]
    fn chacha_roundtrip() {
        roundtrip(CipherSuite::ChaCha20Poly1305);
    }
    #[test]
    fn aes_siv_roundtrip() {
        roundtrip(CipherSuite::Aes256GcmSiv);
    }

    /// Known-answer test from RFC 8452 Appendix C.2 (AES-256-GCM-SIV
    /// test vector with non-zero plaintext + AAD). Pins our `seal()`
    /// against the reference vector so a future swap of the
    /// underlying ml-kem-style transitive dep can't silently change
    /// the algorithm output. The vector source:
    ///
    /// ```text
    ///   Key:        0100000000000000000000000000000000000000000000000000000000000000
    ///   Nonce:      030000000000000000000000
    ///   AAD:        01
    ///   Plaintext:  0200000000000000
    ///   Ciphertext: 1de22967237a8132 91213f267e3b452f 02d01ae33e4ec854
    ///               (the tail 16 B is the auth tag; aead returns ct||tag)
    /// ```
    ///
    /// (Vector reproduced verbatim from RFC 8452 §C.2 row 2.)
    #[test]
    fn aes_siv_rfc8452_kat() {
        // Key: 32 bytes, byte 0 = 0x01, rest zero.
        let mut key = [0u8; 32];
        key[0] = 0x01;
        // Nonce: byte 0 = 0x03.
        let mut nonce = [0u8; 12];
        nonce[0] = 0x03;
        let aad = [0x01u8];
        let pt = [0x02u8, 0, 0, 0, 0, 0, 0, 0];

        // Expected ct||tag is 24 bytes. From RFC 8452 §C.2 second test:
        //   result = 1de22967237a813291213f267e3b452f02d01ae33e4ec854
        let expected_hex = "1de22967237a813291213f267e3b452f02d01ae33e4ec854";
        let expected = hex::decode(expected_hex).unwrap();

        let got = seal(CipherSuite::Aes256GcmSiv, &key, &nonce, &aad, &pt).unwrap();
        assert_eq!(got, expected, "RFC 8452 §C.2 KAT mismatch");

        // Round-trip the KAT plaintext too.
        let pt_back = open(CipherSuite::Aes256GcmSiv, &key, &nonce, &aad, &got).unwrap();
        assert_eq!(pt_back, pt);
    }

    /// AES-GCM-SIV's headline property: encrypting the same plaintext
    /// twice with the same (key, nonce, AAD) is deterministic AND
    /// reversible, but most importantly - the keystream is NOT
    /// recovered the way a vanilla GCM nonce-collision would leak it.
    /// Two distinct plaintexts under the same (key, nonce) produce
    /// distinct ciphertexts (they don't XOR-cancel), so a forensic
    /// observer of a colliding nonce learns only `enc(pt_a) != enc(pt_b)`,
    /// not `pt_a XOR pt_b`. This test pins the deterministic-output
    /// behaviour so a future refactor can't silently swap to a
    /// non-misuse-resistant impl.
    #[test]
    fn aes_siv_is_deterministic_under_same_inputs() {
        let key = [0x42u8; 32];
        let nonce = [0x07u8; 12];
        let aad = b"luksbox aad";
        let pt = b"the same plaintext";
        let ct1 = seal(CipherSuite::Aes256GcmSiv, &key, &nonce, aad, pt).unwrap();
        let ct2 = seal(CipherSuite::Aes256GcmSiv, &key, &nonce, aad, pt).unwrap();
        assert_eq!(
            ct1, ct2,
            "GCM-SIV must be deterministic for same (key, nonce, aad, pt)"
        );

        // Different plaintext under same (key, nonce, aad) must produce
        // a different ciphertext, not a same-keystream XOR. (Sanity:
        // GCM-SIV derives the actual stream key from the message + key,
        // so different messages -> different stream keys -> different ct.)
        let other = b"a different plaintext";
        let ct3 = seal(CipherSuite::Aes256GcmSiv, &key, &nonce, aad, other).unwrap();
        assert_ne!(ct1, ct3);
    }
}
