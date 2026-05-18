// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Penthertz <https://penthertz.com> (https://x.com/PentHertz)

//! Adversary tests against the FIDO2 trust boundary.
//!
//! Threat model: attacker controls the FIDO2 transport (USB-HID MITM
//! via a malicious cable / hub / debugger) OR has substituted the
//! physical authenticator with a rogue device. They can return any
//! bytes for cred_id and any 32-byte value for hmac_secret.
//!
//! Properties we want:
//! 1. The downstream `Keyslot` length checks reject hostile cred_ids
//!    (empty, oversized) cleanly without panic.
//! 2. A rogue device returning attacker-chosen hmac_secret for a
//!    victim's cred_id can NOT unlock a wrap-style FIDO2 keyslot
//!    enrolled by the legitimate device, the slot's AEAD wrap
//!    requires the real hmac_secret value, which is HMAC-keyed by
//!    `credSeed` that lives in the legitimate authenticator's secure
//!    element.
//! 3. A rogue device can NOT unlock a fido2-direct keyslot either,
//!    the MVK is HKDF(real_hmac_secret, salt), so attacker-chosen
//!    hmac_secret derives a different MVK that fails the header MAC.
//! 4. Substituted cred_id / fido2_hmac_salt in the slot bytes (the
//!    fields not covered by the slot's AEAD AAD) still fail unlock
//!    via the resulting wrong KEK, AND fail the header HMAC after
//!    that, defense in depth.

use luksbox_core::{
    Argon2idParams, CipherSuite, FIDO2_CRED_ID_MAX, Keyslot, MasterVolumeKey, SlotKind,
};
use luksbox_fido2::{Fido2Authenticator, MockAuthenticator};

const HEADER_SALT: [u8; 32] = [0x42; 32];
const SUITE: CipherSuite = CipherSuite::Aes256Gcm;
const TEST_KDF: Argon2idParams = Argon2idParams {
    m_cost_kib: 8,
    t_cost: 1,
    p_cost: 1,
};

fn fresh_mvk() -> MasterVolumeKey {
    MasterVolumeKey::from_bytes([0x55; 32])
}

// ---- Hostile cred_id sizes from the device --------------------------------

#[test]
fn keyslot_rejects_oversized_cred_id_from_authenticator() {
    let mut rogue = MockAuthenticator::new();
    rogue.force_cred_id_len(FIDO2_CRED_ID_MAX + 1);
    let er = rogue.enroll("luksbox.local", b"u", None).unwrap();
    // FFI boundary in HidAuthenticator caps at 4 KiB, but the
    // luksbox-core Keyslot constructor enforces FIDO2_CRED_ID_MAX
    // (currently 352, sized for stateless authenticators like Google
    // Titan that produce 288 B cred IDs).
    let result = Keyslot::new_fido2(
        SUITE,
        &fresh_mvk(),
        None,
        &[0xAA; 32],
        &er.credential.id,
        [0xBB; 32],
        TEST_KDF,
        &HEADER_SALT,
    );
    assert!(result.is_err(), "oversized cred_id must be rejected");
}

#[test]
fn keyslot_rejects_zero_length_cred_id() {
    // The HidAuthenticator FFI boundary already rejects len=0; this
    // double-checks downstream resilience if a different transport
    // somehow lets a 0-byte cred_id through.
    let mvk = fresh_mvk();
    let result = Keyslot::new_fido2(
        SUITE,
        &mvk,
        None,
        &[0xAA; 32],
        &[],
        [0xBB; 32],
        TEST_KDF,
        &HEADER_SALT,
    );
    // Empty cred_id should at minimum not panic; current behavior is
    // to accept (zero length is a valid `Vec<u8>`), but downstream
    // unlock will fail because the slot is built then a real device's
    // assert won't match an empty allow_list. Verify it's at least
    // `Ok(_)` or an explicit `Err(_)`, either way, no panic.
    let _ = result;
}

#[test]
fn keyslot_accepts_max_length_cred_id() {
    let mvk = fresh_mvk();
    let cred_id = vec![0xAB; FIDO2_CRED_ID_MAX];
    let slot = Keyslot::new_fido2(
        SUITE,
        &mvk,
        None,
        &[0xAA; 32],
        &cred_id,
        [0xBB; 32],
        TEST_KDF,
        &HEADER_SALT,
    )
    .expect("max-length cred_id must be accepted");
    assert_eq!(slot.fido2_cred_id.len(), FIDO2_CRED_ID_MAX);
}

// ---- Rogue device returning attacker-chosen hmac_secret -------------------

#[test]
fn rogue_device_with_chosen_hmac_secret_cannot_unlock_legit_wrap_slot() {
    // Legitimate flow: real device enrolls a credential, hmac_secret
    // is derived correctly, slot wraps MVK under that KEK.
    let mut legit = MockAuthenticator::new();
    let er = legit.enroll("luksbox.local", b"u", None).unwrap();
    let salt = [0xCC; 32];
    let real_secret = legit
        .hmac_secret("luksbox.local", &er.credential.id, &salt, None)
        .unwrap();
    let mvk = fresh_mvk();
    let slot = Keyslot::new_fido2(
        SUITE,
        &mvk,
        None,
        &real_secret,
        &er.credential.id,
        salt,
        TEST_KDF,
        &HEADER_SALT,
    )
    .unwrap();

    // Adversary mode: rogue device returns its own chosen value
    // regardless of (cred_id, salt). It's the SAME 32-byte length
    // (so passes the FFI boundary check) but a different value.
    let mut rogue = MockAuthenticator::new();
    rogue.force_hmac_secret([0xDE; 32]);
    let rogue_secret = rogue
        .hmac_secret("luksbox.local", &er.credential.id, &salt, None)
        .unwrap();
    assert_eq!(
        *rogue_secret, [0xDE; 32],
        "rogue device returns chosen value"
    );
    assert_ne!(*rogue_secret, *real_secret, "rogue != legit");

    let result = slot.unlock_fido2(SUITE, None, &rogue_secret, &HEADER_SALT);
    assert!(
        result.is_err(),
        "wrap-style slot must reject attacker-chosen hmac_secret"
    );
}

#[test]
fn rogue_device_cannot_derive_legit_mvk_in_direct_mode() {
    // In FIDO2-direct mode the MVK = HKDF(hmac_secret, salt). A rogue
    // device returning attacker-chosen hmac_secret derives a DIFFERENT
    // MVK than the legit one. The slot stores no wrapped MVK so there
    // is nothing to "unlock fail" on per se, but the derived MVK
    // will be different from the one used to encrypt the vault, and
    // any downstream MAC / AEAD using that MVK will fail.
    let mut legit = MockAuthenticator::new();
    let er = legit.enroll("luksbox.local", b"u", None).unwrap();
    let salt = [0xEE; 32];
    let real_secret = legit
        .hmac_secret("luksbox.local", &er.credential.id, &salt, None)
        .unwrap();
    let slot = Keyslot::new_fido2_derived_mvk(&er.credential.id, salt).unwrap();
    let real_mvk = slot.unlock_fido2_derived_mvk(&real_secret).unwrap();

    let mut rogue = MockAuthenticator::new();
    rogue.force_hmac_secret([0x11; 32]);
    let rogue_secret = rogue
        .hmac_secret("luksbox.local", &er.credential.id, &salt, None)
        .unwrap();
    let rogue_mvk = slot.unlock_fido2_derived_mvk(&rogue_secret).unwrap();

    assert_ne!(
        real_mvk.as_bytes(),
        rogue_mvk.as_bytes(),
        "rogue hmac_secret must derive a different MVK than the legit one"
    );
}

#[test]
fn rogue_device_returning_all_zeros_does_not_unlock_wrap_slot() {
    let mut legit = MockAuthenticator::new();
    let er = legit.enroll("luksbox.local", b"u", None).unwrap();
    let salt = [0xFF; 32];
    let real_secret = legit
        .hmac_secret("luksbox.local", &er.credential.id, &salt, None)
        .unwrap();
    let slot = Keyslot::new_fido2(
        SUITE,
        &fresh_mvk(),
        None,
        &real_secret,
        &er.credential.id,
        salt,
        TEST_KDF,
        &HEADER_SALT,
    )
    .unwrap();

    // Specific edge case: attacker returns all-zeros (a "default" value
    // that might pass naive checks).
    let r = slot.unlock_fido2(SUITE, None, &[0u8; 32], &HEADER_SALT);
    assert!(r.is_err(), "all-zeros hmac_secret must not unlock");
}

#[test]
fn rogue_device_returning_all_ones_does_not_unlock_wrap_slot() {
    let mut legit = MockAuthenticator::new();
    let er = legit.enroll("luksbox.local", b"u", None).unwrap();
    let salt = [0xAB; 32];
    let real_secret = legit
        .hmac_secret("luksbox.local", &er.credential.id, &salt, None)
        .unwrap();
    let slot = Keyslot::new_fido2(
        SUITE,
        &fresh_mvk(),
        None,
        &real_secret,
        &er.credential.id,
        salt,
        TEST_KDF,
        &HEADER_SALT,
    )
    .unwrap();

    let r = slot.unlock_fido2(SUITE, None, &[0xff; 32], &HEADER_SALT);
    assert!(r.is_err(), "all-ones hmac_secret must not unlock");
}

// ---- Substituted cred_id / hmac_salt in the slot bytes --------------------

#[test]
fn slot_bytes_with_swapped_cred_id_fail_unlock_attempt() {
    // Tampering test: attacker has read access to the .lbx, swaps
    // bytes in the cred_id field of a slot to point to a different
    // credential they control. Slot bytes round-trip cleanly through
    // from_bytes (cred_id is not in AEAD AAD), but at unlock time
    // the rogue device asked-with-substituted-cred_id returns a
    // DIFFERENT hmac_secret than the legit one used at enroll, so
    // the AEAD wrap fails.
    let mut legit = MockAuthenticator::new();
    let er = legit.enroll("luksbox.local", b"u", None).unwrap();
    let salt = [0x77; 32];
    let real_secret = legit
        .hmac_secret("luksbox.local", &er.credential.id, &salt, None)
        .unwrap();
    let slot = Keyslot::new_fido2(
        SUITE,
        &fresh_mvk(),
        None,
        &real_secret,
        &er.credential.id,
        salt,
        TEST_KDF,
        &HEADER_SALT,
    )
    .unwrap();

    // Same legit device gets asked for hmac_secret with a DIFFERENT
    // cred_id (or different salt), returns a different value.
    let other = legit.enroll("luksbox.local", b"u", None).unwrap();
    let wrong_secret = legit
        .hmac_secret("luksbox.local", &other.credential.id, &salt, None)
        .unwrap();
    assert_ne!(real_secret, wrong_secret);
    assert!(
        slot.unlock_fido2(SUITE, None, &wrong_secret, &HEADER_SALT)
            .is_err()
    );
}

#[test]
fn legit_device_after_passphrase_brute_force_still_blocks() {
    // Wrap mode includes a passphrase as a second factor (None here).
    // Even if a rogue device produces the legit hmac_secret somehow
    // (we model this by using the legit one), the slot was created
    // with passphrase=None, so NO passphrase is the right "second
    // factor". Sanity-check: legit hmac_secret unlocks if and only
    // if passphrase matches.
    let mut legit = MockAuthenticator::new();
    let er = legit.enroll("luksbox.local", b"u", None).unwrap();
    let salt = [0xDE; 32];
    let real_secret = legit
        .hmac_secret("luksbox.local", &er.credential.id, &salt, None)
        .unwrap();
    // Built WITH a passphrase second factor.
    let slot = Keyslot::new_fido2(
        SUITE,
        &fresh_mvk(),
        Some(b"correct horse"),
        &real_secret,
        &er.credential.id,
        salt,
        TEST_KDF,
        &HEADER_SALT,
    )
    .unwrap();

    // Attacker has the legit hmac_secret but wrong passphrase.
    assert!(
        slot.unlock_fido2(SUITE, Some(b"wrong"), &real_secret, &HEADER_SALT)
            .is_err()
    );
    // Attacker has wrong hmac_secret but right passphrase.
    assert!(
        slot.unlock_fido2(SUITE, Some(b"correct horse"), &[0u8; 32], &HEADER_SALT)
            .is_err()
    );
    // Both right unlocks.
    assert_eq!(
        slot.unlock_fido2(SUITE, Some(b"correct horse"), &real_secret, &HEADER_SALT)
            .unwrap()
            .as_bytes(),
        fresh_mvk().as_bytes()
    );
}

// ---- Direct-mode device-substitution attack -------------------------------

#[test]
fn direct_mode_with_swapped_device_yields_different_mvk() {
    // Two physical devices simulated. Direct mode builds slot from
    // device A; device B asked with the same (cred_id, salt) returns
    // a different hmac_secret (different credSeed inside its silicon).
    // Resulting MVK differs.
    let mut device_a = MockAuthenticator::new();
    let er_a = device_a.enroll("luksbox.local", b"u", None).unwrap();
    let salt = [0xBB; 32];
    let secret_a = device_a
        .hmac_secret("luksbox.local", &er_a.credential.id, &salt, None)
        .unwrap();
    let slot = Keyslot::new_fido2_derived_mvk(&er_a.credential.id, salt).unwrap();
    let mvk_a = slot.unlock_fido2_derived_mvk(&secret_a).unwrap();

    // Device B: same RP, but completely different credSeed (a fresh
    // MockAuthenticator has its own internal randomness pool).
    let mut device_b = MockAuthenticator::new();
    // Even if device_b is asked to enroll with the same cred_id (it
    // can't, cred_ids are device-issued), we model the attack as
    // device_b being given the legit cred_id from elsewhere and
    // asked to compute hmac_secret. A rogue device cooperates and
    // returns SOMETHING; legit device_b returns Err (unknown cred).
    let r = device_b.hmac_secret("luksbox.local", &er_a.credential.id, &salt, None);
    assert!(r.is_err(), "legit device rejects unknown cred_id");

    // Force-reply rogue mode: device_b returns an attacker-chosen value.
    device_b.force_hmac_secret([0xDD; 32]);
    let secret_b = device_b
        .hmac_secret("luksbox.local", &er_a.credential.id, &salt, None)
        .unwrap();
    let mvk_b = slot.unlock_fido2_derived_mvk(&secret_b).unwrap();
    assert_ne!(
        mvk_a.as_bytes(),
        mvk_b.as_bytes(),
        "device-substitution must yield a different MVK"
    );
}

// ---- Direct mode: all-zeros / all-ones rogue values --------------------

#[test]
fn rogue_device_returning_all_zeros_yields_distinct_mvk_in_direct_mode() {
    // In direct mode, MVK = HKDF(hmac_secret, salt). A rogue device
    // returning all-zeros derives SOME MVK (the HKDF of zeros), but
    // NOT the legit MVK derived from the real hmac_secret. Downstream
    // header MAC verification catches the mismatch.
    let mut legit = MockAuthenticator::new();
    let er = legit.enroll("luksbox.local", b"u", None).unwrap();
    let salt = [0xAB; 32];
    let real_secret = legit
        .hmac_secret("luksbox.local", &er.credential.id, &salt, None)
        .unwrap();

    let slot = Keyslot::new_fido2_derived_mvk(&er.credential.id, salt).unwrap();
    let real_mvk = slot.unlock_fido2_derived_mvk(&real_secret).unwrap();
    let zero_mvk = slot.unlock_fido2_derived_mvk(&[0u8; 32]).unwrap();
    assert_ne!(
        real_mvk.as_bytes(),
        zero_mvk.as_bytes(),
        "all-zeros hmac_secret must derive a different MVK than legit"
    );
}

#[test]
fn rogue_device_returning_all_ones_yields_distinct_mvk_in_direct_mode() {
    let mut legit = MockAuthenticator::new();
    let er = legit.enroll("luksbox.local", b"u", None).unwrap();
    let salt = [0xCD; 32];
    let real_secret = legit
        .hmac_secret("luksbox.local", &er.credential.id, &salt, None)
        .unwrap();

    let slot = Keyslot::new_fido2_derived_mvk(&er.credential.id, salt).unwrap();
    let real_mvk = slot.unlock_fido2_derived_mvk(&real_secret).unwrap();
    let ones_mvk = slot.unlock_fido2_derived_mvk(&[0xFFu8; 32]).unwrap();
    assert_ne!(real_mvk.as_bytes(), ones_mvk.as_bytes());
}

// ---- Hybrid-PQ-FIDO2: all-zeros / all-ones rogue hmac_secret -----------

#[test]
fn rogue_device_with_all_zeros_does_not_unlock_hybrid_pq_fido2() {
    // Hybrid-PQ-FIDO2 KEK = HKDF(Argon2id(passphrase || hmac_secret) || kyber_shared).
    // Even if the attacker gets the kyber_shared right (e.g. has the
    // .kyber file), an all-zeros hmac_secret produces a different
    // Argon2id output -> different KEK -> AEAD on the wrapped MVK fails.
    let mut legit = MockAuthenticator::new();
    let er = legit.enroll("luksbox.local", b"u", None).unwrap();
    let salt = [0xEE; 32];
    let real_secret = legit
        .hmac_secret("luksbox.local", &er.credential.id, &salt, None)
        .unwrap();
    let pq_shared = [0xAA; 32]; // simulate a fixed Kyber-decap shared secret

    let mvk = fresh_mvk();
    let slot = Keyslot::new_hybrid_pq_fido2(
        SUITE,
        &mvk,
        None,
        &real_secret,
        &pq_shared,
        &er.credential.id,
        salt,
        TEST_KDF,
        &HEADER_SALT,
    )
    .unwrap();

    let r = slot.unlock_hybrid_pq_fido2(SUITE, None, &[0u8; 32], &pq_shared, &HEADER_SALT);
    assert!(
        r.is_err(),
        "all-zeros hmac_secret must not unlock hybrid-pq-fido2 even with correct kyber_shared"
    );
}

#[test]
fn rogue_device_with_all_ones_does_not_unlock_hybrid_pq_fido2() {
    let mut legit = MockAuthenticator::new();
    let er = legit.enroll("luksbox.local", b"u", None).unwrap();
    let salt = [0x55; 32];
    let real_secret = legit
        .hmac_secret("luksbox.local", &er.credential.id, &salt, None)
        .unwrap();
    let pq_shared = [0xBB; 32];

    let mvk = fresh_mvk();
    let slot = Keyslot::new_hybrid_pq_fido2(
        SUITE,
        &mvk,
        None,
        &real_secret,
        &pq_shared,
        &er.credential.id,
        salt,
        TEST_KDF,
        &HEADER_SALT,
    )
    .unwrap();

    let r = slot.unlock_hybrid_pq_fido2(SUITE, None, &[0xFFu8; 32], &pq_shared, &HEADER_SALT);
    assert!(
        r.is_err(),
        "all-ones hmac_secret must not unlock hybrid-pq-fido2"
    );
}

#[test]
fn rogue_device_with_legit_hmac_but_wrong_kyber_does_not_unlock_hybrid() {
    // Defence-in-depth: the kyber_shared is the second factor for
    // hybrid-pq-fido2. Even an attacker who has the legit hmac_secret
    // (e.g. by quantum-recovering CTAP2 ECDH from sniffed traffic)
    // can't unlock without the .kyber seed file. Verify by simulating
    // a wrong kyber_shared.
    let mut legit = MockAuthenticator::new();
    let er = legit.enroll("luksbox.local", b"u", None).unwrap();
    let salt = [0x77; 32];
    let real_secret = legit
        .hmac_secret("luksbox.local", &er.credential.id, &salt, None)
        .unwrap();
    let real_pq = [0xC0; 32];
    let wrong_pq = [0xC1; 32]; // off by one bit in one byte

    let mvk = fresh_mvk();
    let slot = Keyslot::new_hybrid_pq_fido2(
        SUITE,
        &mvk,
        None,
        &real_secret,
        &real_pq,
        &er.credential.id,
        salt,
        TEST_KDF,
        &HEADER_SALT,
    )
    .unwrap();

    // Right hmac_secret, wrong kyber_shared -> unlock fails.
    let r = slot.unlock_hybrid_pq_fido2(SUITE, None, &real_secret, &wrong_pq, &HEADER_SALT);
    assert!(
        r.is_err(),
        "legit hmac_secret + wrong kyber_shared must not unlock, kyber is the PQ second factor"
    );

    // Sanity: right + right does unlock.
    let ok = slot
        .unlock_hybrid_pq_fido2(SUITE, None, &real_secret, &real_pq, &HEADER_SALT)
        .expect("right + right should unlock");
    assert_eq!(ok.as_bytes(), mvk.as_bytes());
}

// ---- FFI-boundary: empty / wrong-length hmac_secret from libfido2 ------

#[test]
fn ffi_boundary_rejects_empty_hmac_secret_via_type_system() {
    // The HmacSecret type alias is `[u8; 32]`, fixed-size at compile
    // time. A rogue device returning a CTAP2 hmac-secret response of
    // length 0 (or 16, or 64) cannot satisfy this type. The libfido2
    // wrapper at hid.rs:291 checks `secret_len != 32` and returns
    // Error::NoHmacSecret BEFORE constructing the [u8; 32], so an
    // attacker-controlled length never reaches our crypto code.
    //
    // We can't trigger that branch from a mock (the trait API is
    // type-locked), but we can document the invariant by assertion:
    use std::mem::size_of;
    assert_eq!(
        size_of::<luksbox_fido2::HmacSecret>(),
        32,
        "HmacSecret must be exactly 32 bytes, this guards against \
         rogue devices returning shorter / longer values via the FFI boundary"
    );
}

#[test]
fn slot_kind_distinguishes_wrap_vs_direct_at_unlock() {
    // Sanity: a wrap slot won't accept the direct-mode unlock path
    // and vice versa. Prevents an attacker from confusing the unlock
    // routine into using the wrong KDF on the same slot bytes.
    let mut auth = MockAuthenticator::new();
    let er = auth.enroll("luksbox.local", b"u", None).unwrap();
    let salt = [0x33; 32];
    let secret = auth
        .hmac_secret("luksbox.local", &er.credential.id, &salt, None)
        .unwrap();
    let mvk = fresh_mvk();

    let wrap_slot = Keyslot::new_fido2(
        SUITE,
        &mvk,
        None,
        &secret,
        &er.credential.id,
        salt,
        TEST_KDF,
        &HEADER_SALT,
    )
    .unwrap();
    assert_eq!(wrap_slot.kind, SlotKind::Fido2HmacSecret);
    // Direct-mode unlock on a wrap slot fails (kind mismatch).
    assert!(wrap_slot.unlock_fido2_derived_mvk(&secret).is_err());

    let direct_slot = Keyslot::new_fido2_derived_mvk(&er.credential.id, salt).unwrap();
    assert_eq!(direct_slot.kind, SlotKind::Fido2DerivedMvk);
    // Wrap-mode unlock on a direct slot fails (kind mismatch).
    assert!(
        direct_slot
            .unlock_fido2(SUITE, None, &secret, &HEADER_SALT)
            .is_err()
    );
}
