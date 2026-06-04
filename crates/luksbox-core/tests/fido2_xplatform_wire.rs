// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Penthertz <https://penthertz.com> (https://x.com/PentHertz)

//! Cross-platform FIDO2 wire-convention regression tests for the
//! v0.3.0 AAD_VERSION_V4 keyslot. These lock in the property that
//! the same on-disk slot unlocks identically on the Linux libfido2
//! path and the Windows webauthn.dll path, by simulating both
//! wire-side transformations through the in-memory MockAuthenticator.
//!
//! Background: in v0.2.2, libfido2 (Linux/macOS) passed the
//! hmac-secret salt raw to the authenticator while webauthn.dll
//! (Windows) SHA-256 prehashed it internally per W3C WebAuthn Level
//! 3 PRF behaviour. The two backends derived different HMAC outputs
//! from the same authenticator + salt + credential, making any
//! FIDO2-bearing vault platform-locked. v0.3.0 closes this by
//! requiring V4 callers to prehash explicitly on the libfido2 side
//! (matching what webauthn.dll already does), so both paths feed
//! the device `SHA-256(salt)`. This test file is the regression
//! guard for that property.

use luksbox_core::aead::CipherSuite;
use luksbox_core::kdf::Argon2idParams;
use luksbox_core::{AAD_VERSION_V4, Keyslot, MasterVolumeKey};
use luksbox_fido2::{Fido2Authenticator, MockAuthenticator, RP_ID};
use sha2::{Digest, Sha256};

const HEADER_SALT: [u8; 32] = [0x42; 32];
const TEST_KDF: Argon2idParams = Argon2idParams {
    m_cost_kib: 19_456,
    t_cost: 2,
    p_cost: 1,
};

/// Both sides of the v0.3.0 wire fix must hand the authenticator the
/// SAME 32 bytes given the SAME slot. We simulate both backends
/// against a single MockAuthenticator (acts as the device):
/// - "Linux V4 path": call `hmac_secret(..., prehash_salt=true, ...)`.
///   The mock applies `SHA-256(salt)` locally before HMACing, exactly
///   like the libfido2 backend will after the v0.3.0 patch.
/// - "Windows V4 path": webauthn.dll prehashes for us on the way to
///   the device. We model that by manually computing `SHA-256(salt)`
///   in the test and then calling `hmac_secret(..., prehash_salt=false,
///   ...)` with the already-hashed bytes. The mock then HMACs that
///   verbatim, which is what the YubiKey would actually do after
///   webauthn.dll fed it `SHA-256(salt)`.
///
/// Both code paths must produce byte-identical HMAC outputs.
#[test]
fn v4_wire_convention_converges_libfido2_and_webauthn() {
    let mut device = MockAuthenticator::new();
    let er = device.enroll(RP_ID, b"user", None).unwrap();
    let salt: [u8; 32] = [0xA7; 32];

    // Linux libfido2 path: caller asks the device for prehashed-salt
    // mode and the device's wire input is SHA-256(salt).
    let linux_out = device
        .hmac_secret(RP_ID, &er.credential.id, &salt, true, None)
        .expect("linux V4 hmac_secret");

    // Windows webauthn.dll path: caller passes raw salt, webauthn.dll
    // prehashes internally before forwarding to the device. Model by
    // pre-hashing in the test and asking the mock for raw-salt mode.
    let prehashed_salt: [u8; 32] = Sha256::digest(salt).into();
    let windows_out = device
        .hmac_secret(RP_ID, &er.credential.id, &prehashed_salt, false, None)
        .expect("windows V4 hmac_secret (prehash applied at caller)");

    assert_eq!(
        linux_out, windows_out,
        "V4 wire convention must produce identical HMAC outputs from \
         libfido2 (prehash=true) and webauthn.dll (prehash applied \
         externally + prehash=false to mock the post-API device input)",
    );
}

/// Document the pre-v0.3.0 bug for posterity: under the old V3 wire
/// convention, the same (device, credential, salt) tuple produced
/// DIFFERENT HMAC outputs on the two backends. This test asserts
/// the divergence, so any future regression that reintroduces it on
/// a V4 slot would be visible against this baseline.
#[test]
fn v3_wire_convention_diverged_pre_v0_3_0() {
    let mut device = MockAuthenticator::new();
    let er = device.enroll(RP_ID, b"user", None).unwrap();
    let salt: [u8; 32] = [0xA7; 32];

    // Pre-v0.3.0 Linux libfido2: raw salt to the device.
    let linux_v3 = device
        .hmac_secret(RP_ID, &er.credential.id, &salt, false, None)
        .unwrap();

    // Pre-v0.3.0 Windows webauthn.dll: salt SHA-256d before the
    // device sees it.
    let prehashed_salt: [u8; 32] = Sha256::digest(salt).into();
    let windows_v3 = device
        .hmac_secret(RP_ID, &er.credential.id, &prehashed_salt, false, None)
        .unwrap();

    assert_ne!(
        linux_v3, windows_v3,
        "V3 wire convention DID diverge between libfido2 and webauthn.dll \
         in v0.2.2 (this is the bug v0.3.0 fixes). If this ever starts \
         passing, something has silently changed the v0.2.2-era behaviour.",
    );
}

/// End-to-end: a V4 FIDO2 keyslot enrolled with the V4 wire
/// convention unlocks under the V4 wire convention on either
/// backend simulation. The slot's on-disk `aad_version` byte must
/// be V4, and the `fido2_salt_prehashed()` query must return true.
#[test]
fn v4_keyslot_roundtrips_through_both_backend_simulations() {
    let mvk = MasterVolumeKey::from_bytes([0x33; 32]);

    let mut device = MockAuthenticator::new();
    let er = device.enroll(RP_ID, b"user", None).unwrap();
    let salt: [u8; 32] = [0x11; 32];

    // Build the slot using the "Linux V4 path" hmac_secret.
    let enroll_hmac = device
        .hmac_secret(RP_ID, &er.credential.id, &salt, true, None)
        .unwrap();
    let slot = Keyslot::new_fido2(
        CipherSuite::Aes256Gcm,
        &mvk,
        None,
        &enroll_hmac,
        &er.credential.id,
        salt,
        TEST_KDF,
        &HEADER_SALT,
    )
    .unwrap();
    assert_eq!(slot.aad_version, AAD_VERSION_V4);
    assert!(slot.fido2_salt_prehashed());
    assert!(slot.touches_fido2());

    // Round-trip through the on-disk bytes (catches any AAD-shape
    // regression at the V4 layout level).
    let bytes = slot.to_bytes();
    let parsed = Keyslot::from_bytes(&bytes).unwrap();
    assert_eq!(parsed.aad_version, AAD_VERSION_V4);

    // Unlock via the "Linux V4 path".
    let unlock_linux = device
        .hmac_secret(
            RP_ID,
            &parsed.fido2_cred_id,
            &parsed.fido2_hmac_salt,
            parsed.fido2_salt_prehashed(),
            None,
        )
        .unwrap();
    let recovered_linux = parsed
        .unlock_fido2(CipherSuite::Aes256Gcm, None, &unlock_linux, &HEADER_SALT)
        .expect("V4 slot must unlock on the simulated Linux path");
    assert_eq!(recovered_linux.as_bytes(), mvk.as_bytes());

    // Unlock via the "Windows V4 path" — caller passes raw salt to
    // webauthn.dll, which prehashes; modelled by manual prehash then
    // mock with `prehash_salt=false`.
    let prehashed_salt: [u8; 32] = Sha256::digest(parsed.fido2_hmac_salt).into();
    let unlock_windows = device
        .hmac_secret(RP_ID, &parsed.fido2_cred_id, &prehashed_salt, false, None)
        .unwrap();
    let recovered_windows = parsed
        .unlock_fido2(CipherSuite::Aes256Gcm, None, &unlock_windows, &HEADER_SALT)
        .expect("V4 slot must unlock on the simulated Windows path");
    assert_eq!(recovered_windows.as_bytes(), mvk.as_bytes());
}
