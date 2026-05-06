// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Penthertz <https://penthertz.com> (https://x.com/PentHertz)

//! CTAP2 hmac-secret extension cryptography for `pinUvAuthProtocol = 1`.
//!
//! Wire flow at GetAssertion time:
//!
//! 1. Platform fetches the authenticator's ECDH P-256 public key
//!    (`authenticatorClientPIN` subcommand `getKeyAgreement`).
//! 2. Platform generates an ephemeral P-256 keypair and computes
//!    `shared = SHA-256(ECDH(platformPriv, authPub).x)`, 32 B.
//! 3. Platform encrypts the salt(s) with AES-256-CBC, key=shared, IV=0¹⁶,
//!    no padding (salts are 32 B = 2 blocks).
//! 4. Platform computes `saltAuth = HMAC-SHA256(shared, saltEnc)[:16]`.
//! 5. Platform sends `{keyAgreement, saltEnc, saltAuth}` as the hmac-secret
//!    extension in GetAssertion.
//! 6. Authenticator verifies saltAuth, decrypts the salt(s), computes
//!    `hmac_out_n = HMAC-SHA256(credRandom, salt_n)`, and returns
//!    `AES-256-CBC-encrypt(shared, IV=0¹⁶, hmac_out_1 || hmac_out_2?)`.
//! 7. Platform decrypts to recover hmac-secret output(s).
//!
//! This module implements the platform side and provides simulation helpers
//! for the authenticator side so the round-trip is unit-testable in software.

use aes::Aes256;
use aes::cipher::generic_array::GenericArray;
use aes::cipher::{BlockDecrypt, BlockEncrypt};
use hmac::{Hmac, Mac};
use p256::PublicKey;
use p256::ecdh::EphemeralSecret;
use rand_core::OsRng;
use sha2::{Digest, Sha256};
use zeroize::Zeroize;

use crate::error::Error;

const ZERO_IV: [u8; 16] = [0u8; 16];

/// Platform-side ephemeral ECDH keypair used for one CTAP session.
pub struct PlatformKeyAgreement {
    secret: EphemeralSecret,
    pub public: PublicKey,
}

impl PlatformKeyAgreement {
    pub fn generate() -> Self {
        let secret = EphemeralSecret::random(&mut OsRng);
        let public = secret.public_key();
        Self { secret, public }
    }

    /// Combine our private key with the authenticator's public key to obtain
    /// the 32-byte session shared secret used by both AES-CBC and HMAC-SHA256.
    pub fn shared_secret(&self, authenticator_public: &PublicKey) -> SharedSecret {
        let dh = self.secret.diffie_hellman(authenticator_public);
        let mut hasher = Sha256::new();
        hasher.update(dh.raw_secret_bytes().as_slice());
        let digest = hasher.finalize();
        let mut s = [0u8; 32];
        s.copy_from_slice(&digest);
        SharedSecret(s)
    }
}

#[derive(Clone)]
pub struct SharedSecret([u8; 32]);

impl SharedSecret {
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl Drop for SharedSecret {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

/// Encrypt a 32-byte salt for transmission. Returns `(saltEnc, saltAuth)`
/// where `saltAuth = HMAC-SHA256(shared, saltEnc)[:16]`.
pub fn encrypt_salt(shared: &SharedSecret, salt: &[u8; 32]) -> ([u8; 32], [u8; 16]) {
    let salt_enc = aes_cbc_apply(&shared.0, salt, AesOp::Encrypt);
    let mut mac = <Hmac<Sha256>>::new_from_slice(&shared.0).expect("any-len HMAC key");
    mac.update(&salt_enc);
    let auth_full = mac.finalize().into_bytes();
    let mut auth = [0u8; 16];
    auth.copy_from_slice(&auth_full[..16]);
    (salt_enc, auth)
}

/// Decrypt the authenticator's hmac-secret response (32 B for one salt).
pub fn decrypt_output(shared: &SharedSecret, encrypted_output: &[u8; 32]) -> [u8; 32] {
    aes_cbc_apply(&shared.0, encrypted_output, AesOp::Decrypt)
}

/// Authenticator-side: verify saltAuth and decrypt the salt. Returns the
/// recovered 32-byte salt, or `HmacVerify` if the saltAuth check fails.
/// Provided here for round-trip tests; in production this code runs on the
/// authenticator firmware.
pub fn authenticator_decrypt_salt(
    shared: &SharedSecret,
    salt_enc: &[u8; 32],
    salt_auth: &[u8; 16],
) -> Result<[u8; 32], Error> {
    let mut mac = <Hmac<Sha256>>::new_from_slice(&shared.0).expect("any-len HMAC key");
    mac.update(salt_enc);
    let expected = mac.finalize().into_bytes();
    if expected[..16] != *salt_auth {
        return Err(Error::HmacVerify);
    }
    Ok(aes_cbc_apply(&shared.0, salt_enc, AesOp::Decrypt))
}

/// Authenticator-side: encrypt the hmac output for return to the platform.
pub fn authenticator_encrypt_output(shared: &SharedSecret, hmac_output: &[u8; 32]) -> [u8; 32] {
    aes_cbc_apply(&shared.0, hmac_output, AesOp::Encrypt)
}

#[derive(Clone, Copy)]
enum AesOp {
    Encrypt,
    Decrypt,
}

/// Apply AES-256-CBC over exactly 32 bytes (2 blocks) with IV = 0¹⁶ and no
/// padding, the fixed shape of every salt and every hmac output in the
/// hmac-secret protocol.
fn aes_cbc_apply(key: &[u8; 32], input: &[u8; 32], op: AesOp) -> [u8; 32] {
    let cipher = <Aes256 as aes::cipher::KeyInit>::new(GenericArray::from_slice(key));
    let mut out = [0u8; 32];
    match op {
        AesOp::Encrypt => {
            let mut b1 = GenericArray::clone_from_slice(&input[..16]);
            for (b, iv) in b1.iter_mut().zip(ZERO_IV.iter()) {
                *b ^= iv;
            }
            cipher.encrypt_block(&mut b1);
            let mut b2 = GenericArray::clone_from_slice(&input[16..]);
            for (b, prev) in b2.iter_mut().zip(b1.iter()) {
                *b ^= prev;
            }
            cipher.encrypt_block(&mut b2);
            out[..16].copy_from_slice(&b1);
            out[16..].copy_from_slice(&b2);
        }
        AesOp::Decrypt => {
            let mut b1 = GenericArray::clone_from_slice(&input[..16]);
            let saved_b1 = b1;
            cipher.decrypt_block(&mut b1);
            for (b, iv) in b1.iter_mut().zip(ZERO_IV.iter()) {
                *b ^= iv;
            }
            let mut b2 = GenericArray::clone_from_slice(&input[16..]);
            cipher.decrypt_block(&mut b2);
            for (b, prev) in b2.iter_mut().zip(saved_b1.iter()) {
                *b ^= prev;
            }
            out[..16].copy_from_slice(&b1);
            out[16..].copy_from_slice(&b2);
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ecdh_agreement_matches_on_both_sides() {
        let alice = PlatformKeyAgreement::generate();
        let bob = PlatformKeyAgreement::generate();

        let s_a = alice.shared_secret(&bob.public);
        let s_b = bob.shared_secret(&alice.public);
        assert_eq!(s_a.as_bytes(), s_b.as_bytes());
    }

    #[test]
    fn aes_cbc_roundtrip() {
        let key = [0x55u8; 32];
        let pt = [0xaau8; 32];
        let ct = aes_cbc_apply(&key, &pt, AesOp::Encrypt);
        assert_ne!(ct, pt);
        let pt2 = aes_cbc_apply(&key, &ct, AesOp::Decrypt);
        assert_eq!(pt2, pt);
    }

    #[test]
    fn full_hmac_secret_protocol_roundtrip() {
        // Two software parties: platform ↔ authenticator. Verifies the entire
        // pinUvAuthProtocol-v1 hmac-secret flow end-to-end.
        let platform = PlatformKeyAgreement::generate();
        let authenticator = PlatformKeyAgreement::generate();

        let platform_shared = platform.shared_secret(&authenticator.public);
        let authenticator_shared = authenticator.shared_secret(&platform.public);
        assert_eq!(platform_shared.as_bytes(), authenticator_shared.as_bytes());

        // Platform side: encrypt a salt and produce saltAuth.
        let salt = [0x33u8; 32];
        let (salt_enc, salt_auth) = encrypt_salt(&platform_shared, &salt);

        // Authenticator side: verify saltAuth, recover salt, compute
        // hmac_out, encrypt it for return.
        let recovered_salt =
            authenticator_decrypt_salt(&authenticator_shared, &salt_enc, &salt_auth).unwrap();
        assert_eq!(recovered_salt, salt);

        let cred_random = [0x77u8; 32];
        let hmac_out = {
            let mut mac = <Hmac<Sha256>>::new_from_slice(&cred_random).unwrap();
            mac.update(&recovered_salt);
            let out = mac.finalize().into_bytes();
            let mut h = [0u8; 32];
            h.copy_from_slice(&out);
            h
        };
        let encrypted_output = authenticator_encrypt_output(&authenticator_shared, &hmac_out);

        // Platform side: decrypt output, verify it matches the expected HMAC.
        let recovered_output = decrypt_output(&platform_shared, &encrypted_output);
        assert_eq!(recovered_output, hmac_out);
    }

    #[test]
    fn salt_auth_tamper_detected_on_authenticator() {
        let plat = PlatformKeyAgreement::generate();
        let auth = PlatformKeyAgreement::generate();
        let s_plat = plat.shared_secret(&auth.public);
        let s_auth = auth.shared_secret(&plat.public);

        let salt = [0xccu8; 32];
        let (salt_enc, mut salt_auth) = encrypt_salt(&s_plat, &salt);
        salt_auth[0] ^= 1;
        let r = authenticator_decrypt_salt(&s_auth, &salt_enc, &salt_auth);
        assert!(matches!(r, Err(Error::HmacVerify)));
    }

    /// Cross-implementation verification of `encrypt_salt`. The expected
    /// `ct` and `auth` values were generated with OpenSSL 3 against the
    /// same key + salt (round-7C audit follow-up):
    ///
    /// ```text
    /// $ KEY=0001020304050607080910111213141516171819202122232425262728293031
    /// $ openssl enc -aes-256-cbc -K $KEY -iv 0...0 -nopad -in salt.bin > ct.bin
    /// $ openssl dgst -sha256 -mac HMAC -macopt hexkey:$KEY -binary ct.bin
    /// ```
    ///
    /// If our hand-rolled `aes_cbc_apply` or HMAC handling silently
    /// disagrees with a separately-audited OpenSSL implementation, this
    /// test fails. Closes audit-package deliverable #4 (test-vector
    /// cross-check for CTAP2 §6.5.5).
    #[test]
    fn encrypt_salt_matches_openssl_test_vector() {
        let key: [u8; 32] =
            hex32("0001020304050607080910111213141516171819202122232425262728293031");
        let salt: [u8; 32] =
            hex32("0102030405060708090a0b0c0d0e0f102030405060708090a0b0c0d0e0f00102");
        let expected_ct: [u8; 32] =
            hex32("8c17f48ec93decdba201e174c3f95d3934c6a58a10b39611293a2a5b886635e0");
        let expected_auth: [u8; 16] = hex16("d2fdeed5c95ebd2be471c5388a68c0dd");

        let shared = SharedSecret::from_bytes(key);
        let (ct, auth) = encrypt_salt(&shared, &salt);
        assert_eq!(
            ct, expected_ct,
            "ciphertext disagrees with OpenSSL reference"
        );
        assert_eq!(
            auth, expected_auth,
            "saltAuth disagrees with OpenSSL HMAC-SHA256[..16]"
        );
    }

    /// Independent verification of `decrypt_output`. Vector generated
    /// by OpenSSL 3:
    ///
    /// ```text
    /// $ KEY=0001020304050607080910111213141516171819202122232425262728293031
    /// $ openssl enc -d -aes-256-cbc -K $KEY -iv 0...0 -nopad -in ct.bin > pt.bin
    /// ```
    #[test]
    fn decrypt_output_matches_openssl_test_vector() {
        let key: [u8; 32] =
            hex32("0001020304050607080910111213141516171819202122232425262728293031");
        let ct: [u8; 32] =
            hex32("fedcba98765432100123456789abcdeffedcba98765432100123456789abcdef");
        let expected_pt: [u8; 32] =
            hex32("2905772bedffe491121a3bac24a9e857d7d9cdb39babd68113397ecbad0225b8");

        let shared = SharedSecret::from_bytes(key);
        let pt = decrypt_output(&shared, &ct);
        assert_eq!(
            pt, expected_pt,
            "decrypted output disagrees with OpenSSL reference"
        );
    }

    fn hex32(s: &str) -> [u8; 32] {
        let mut out = [0u8; 32];
        assert_eq!(s.len(), 64, "expected 64 hex chars");
        for (i, byte) in out.iter_mut().enumerate() {
            *byte =
                u8::from_str_radix(&s[2 * i..2 * i + 2], 16).expect("hex digits in vector literal");
        }
        out
    }

    fn hex16(s: &str) -> [u8; 16] {
        let mut out = [0u8; 16];
        assert_eq!(s.len(), 32, "expected 32 hex chars");
        for (i, byte) in out.iter_mut().enumerate() {
            *byte =
                u8::from_str_radix(&s[2 * i..2 * i + 2], 16).expect("hex digits in vector literal");
        }
        out
    }

    #[test]
    fn wrong_shared_secret_fails_auth_check() {
        let plat = PlatformKeyAgreement::generate();
        let auth = PlatformKeyAgreement::generate();
        let bystander = PlatformKeyAgreement::generate();
        let s_plat = plat.shared_secret(&auth.public);
        let s_bystander = plat.shared_secret(&bystander.public);

        let salt = [0xddu8; 32];
        let (salt_enc, salt_auth) = encrypt_salt(&s_plat, &salt);
        // Authenticator with the wrong shared secret can't verify saltAuth.
        let r = authenticator_decrypt_salt(&s_bystander, &salt_enc, &salt_auth);
        assert!(matches!(r, Err(Error::HmacVerify)));
    }
}
