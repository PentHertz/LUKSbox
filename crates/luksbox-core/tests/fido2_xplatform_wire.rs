// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Penthertz <https://penthertz.com> (https://x.com/PentHertz)

//! Cross-platform FIDO2 wire-convention regression tests for the
//! v0.3.0 AAD_VERSION_V4 keyslot. These lock in the property that
//! the same on-disk slot unlocks identically on the Linux libfido2
//! path and the Windows webauthn.dll path, by simulating both
//! wire-side transformations through the in-memory MockAuthenticator.
//!
//! Background: libfido2 (Linux/macOS) passes the hmac-secret salt raw
//! to the authenticator, while webauthn.dll (Windows) applies the W3C
//! WebAuthn-PRF derivation `T(x) = SHA-256("WebAuthn PRF"\0 || x)` to
//! the salt internally — even on the raw CTAP2 hmac-secret path
//! (empirically confirmed via the `xplatform_hmac_probe` example). The
//! two backends therefore derive different HMAC outputs from the same
//! authenticator + salt + credential, making a raw-salt FIDO2 vault
//! platform-locked. The V4 convention closes this by having the
//! libfido2 side apply the *identical* `T` explicitly (via
//! `webauthn_prf_salt`) so both paths feed the device `T(salt)`. This
//! test file is the regression guard for that property.
//!
//! NOTE: an earlier v0.3.0 build modelled webauthn.dll as a plain
//! `SHA-256(salt)` prehash. That was wrong — webauthn.dll applies the
//! PRF-prefixed `T`, not a bare SHA-256 — so this file now models `T`.

use luksbox_core::aead::CipherSuite;
use luksbox_core::kdf::Argon2idParams;
use luksbox_core::{AAD_VERSION_V4, Keyslot, MasterVolumeKey};
use luksbox_fido2::{Fido2Authenticator, MockAuthenticator, RP_ID, webauthn_prf_salt};

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
///   The mock applies `T(salt) = SHA-256("WebAuthn PRF"\0 || salt)`
///   locally before HMACing, exactly like the libfido2 backend does.
/// - "Windows V4 path": the Windows backend forwards the RAW salt and
///   webauthn.dll applies `T` internally on the way to the device. We
///   model that by computing `T(salt)` in the test and then calling
///   `hmac_secret(..., prehash_salt=false, ...)` with the already-
///   transformed bytes. The mock HMACs that verbatim, which is what the
///   authenticator actually does after webauthn.dll fed it `T(salt)`.
///
/// Both code paths must produce byte-identical HMAC outputs.
#[test]
fn v4_wire_convention_converges_libfido2_and_webauthn() {
    let mut device = MockAuthenticator::new();
    let er = device.enroll(RP_ID, b"user", None).unwrap();
    let salt: [u8; 32] = [0xA7; 32];

    // Linux libfido2 path: caller asks the device for the V4 convention
    // and the device's wire input is T(salt).
    let linux_out = device
        .hmac_secret(RP_ID, &er.credential.id, &salt, true, None)
        .expect("linux V4 hmac_secret");

    // Windows webauthn.dll path: caller forwards the raw salt and
    // webauthn.dll applies T internally before the device. Model by
    // computing T(salt) in the test and asking the mock for raw-salt
    // mode (the mock then HMACs T(salt) verbatim).
    let transformed_salt: [u8; 32] = webauthn_prf_salt(&salt);
    let windows_out = device
        .hmac_secret(RP_ID, &er.credential.id, &transformed_salt, false, None)
        .expect("windows V4 hmac_secret (T applied externally)");

    assert_eq!(
        linux_out, windows_out,
        "V4 wire convention must produce identical HMAC outputs from \
         libfido2 (prehash=true, T applied locally) and webauthn.dll \
         (T applied by the OS + prehash=false to mock the post-API \
         device input)",
    );
}

/// Document the legacy V1/V2/V3 raw-salt bug for posterity: under the
/// raw-salt convention, the same (device, credential, salt) tuple
/// produces DIFFERENT HMAC outputs on the two backends, because Windows
/// applies `T` and libfido2 does not. This test asserts the divergence,
/// so any future regression that reintroduces a raw-salt slot as
/// cross-platform would be visible against this baseline.
#[test]
fn v3_wire_convention_diverged_pre_v0_3_0() {
    let mut device = MockAuthenticator::new();
    let er = device.enroll(RP_ID, b"user", None).unwrap();
    let salt: [u8; 32] = [0xA7; 32];

    // Legacy Linux libfido2: raw salt to the device.
    let linux_v3 = device
        .hmac_secret(RP_ID, &er.credential.id, &salt, false, None)
        .unwrap();

    // Legacy Windows webauthn.dll: the OS applies T(salt) before the
    // device sees it (modelled by transforming in the test, then
    // raw-salt mode on the mock).
    let transformed_salt: [u8; 32] = webauthn_prf_salt(&salt);
    let windows_v3 = device
        .hmac_secret(RP_ID, &er.credential.id, &transformed_salt, false, None)
        .unwrap();

    assert_ne!(
        linux_v3, windows_v3,
        "Raw-salt (V1/V2/V3) convention DID diverge between libfido2 \
         (raw) and webauthn.dll (applies T). This is the bug the V4 \
         convention fixes. If this ever starts passing, something has \
         silently changed the legacy behaviour.",
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

    // Unlock via the "Windows V4 path" -- caller forwards the raw salt
    // to webauthn.dll, which applies T; modelled by computing T(salt)
    // then mock with `prehash_salt=false`.
    let transformed_salt: [u8; 32] = webauthn_prf_salt(&parsed.fido2_hmac_salt);
    let unlock_windows = device
        .hmac_secret(RP_ID, &parsed.fido2_cred_id, &transformed_salt, false, None)
        .unwrap();
    let recovered_windows = parsed
        .unlock_fido2(CipherSuite::Aes256Gcm, None, &unlock_windows, &HEADER_SALT)
        .expect("V4 slot must unlock on the simulated Windows path");
    assert_eq!(recovered_windows.as_bytes(), mvk.as_bytes());
}
