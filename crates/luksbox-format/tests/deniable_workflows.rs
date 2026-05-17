// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Penthertz <https://penthertz.com> (https://x.com/PentHertz)

//! End-to-end workflow + regression tests for the v2 deniable
//! header. Each test models a real user flow that broke during the
//! v1 -> v2 migration and pins the fixed behaviour so future edits
//! cannot silently re-introduce the bug.
//!
//! Why these live here, not inline in `deniable_header.rs`: the
//! inline unit tests cover single-credential round-trips; the cases
//! below all involve multiple slots, multiple vaults, or the
//! container-level enroll/rotate APIs. Keeping them in a separate
//! integration test file makes the regression intent explicit and
//! avoids bloating the inline test module.

use luksbox_core::CipherSuite;
use luksbox_core::deniable::{
    DENIABLE_HEADER_SIZE, DENIABLE_SALT_SIZE, DENIABLE_SLOT_SIZE, DENIABLE_SLOT_TABLE_OFFSET,
    DeniableCredential, DeniableKindTag,
};
use luksbox_core::kdf::Argon2idParams;
use luksbox_format::deniable_header::{
    DeniableInnerHeader, DeniableMaterial, complete_open_v2, create_with_credential_v2,
    install_slot_v2, rotate_mvk_v2, try_open_envelope_v2,
};
use luksbox_format::error::Error;

const CIPHER: CipherSuite = CipherSuite::Aes256GcmSiv;

fn cheap_params() -> Argon2idParams {
    Argon2idParams {
        m_cost_kib: 8,
        t_cost: 1,
        p_cost: 1,
    }
}

fn sane_inner() -> DeniableInnerHeader {
    DeniableInnerHeader {
        format_version_minor: 0,
        cipher_suite: CIPHER,
        kdf_id: luksbox_core::KdfId::Argon2id,
        flags: 0,
        metadata_offset: DENIABLE_HEADER_SIZE as u64,
        metadata_size: 4096,
        data_offset: DENIABLE_HEADER_SIZE as u64 + 4096,
        chunk_size: 4096,
    }
}

/// Build a vault populated with the given credential at slot 0 and
/// return the header bytes + MVK. Helper to keep individual tests
/// focused on what they actually assert.
fn fresh_vault(cred: &DeniableCredential, material: &DeniableMaterial, slot: usize) -> Vec<u8> {
    let inner = sane_inner();
    let (bytes, _) = create_with_credential_v2(cred, material, slot, CIPHER, inner)
        .expect("vault creation succeeds");
    bytes
}

// -----------------------------------------------------------------
// Test #1: multi-slot enrollment with mixed credential kinds.
//
// Regression target: the kind-matching candidate selection inside
// `try_open_envelope_v2`. Prior to the v2 migration, enrolling two
// slots with the same envelope passphrase but different kinds would
// cause the open path to return whichever slot decoded first, then
// `complete_open_v2` would fail with "credential kind mismatch" even
// though the right slot did exist.
// -----------------------------------------------------------------

#[test]
fn multi_slot_mixed_kinds_each_credential_opens_its_own_slot() {
    let inner = sane_inner();
    // Enroll a passphrase-only credential at slot 0.
    let admin = DeniableCredential::Passphrase {
        passphrase: b"shared-envelope-pass",
        argon2: cheap_params(),
    };
    let (mut header, mvk) = create_with_credential_v2(
        &admin,
        &DeniableMaterial::passphrase_only(),
        0,
        CIPHER,
        inner,
    )
    .unwrap();

    // Enroll a FIDO2-style credential at slot 3 using the SAME
    // envelope passphrase. Both slots will decode envelope-OK on a
    // unlock attempt that derives the same envelope KEK.
    let hmac_out = [0xa1u8; 32];
    let fido = DeniableCredential::Fido2Passphrase {
        passphrase: b"shared-envelope-pass",
        argon2: cheap_params(),
        hmac_secret_output: &hmac_out,
    };
    let fido_mat = DeniableMaterial {
        cred_id: vec![0xc1; 64],
        hmac_salt: Some([0xd1; 32]),
        tpm_blob: Vec::new(),
    };
    let salt: [u8; DENIABLE_SALT_SIZE] = header[..DENIABLE_SALT_SIZE].try_into().unwrap();
    let header_arr: &mut [u8; DENIABLE_HEADER_SIZE] = (&mut header[..]).try_into().unwrap();
    install_slot_v2(header_arr, 3, &fido, &fido_mat, &mvk, CIPHER, &salt).unwrap();

    // Open as passphrase-only: must land on slot 0 (kind=Passphrase),
    // not slot 3 (kind=Fido2Passphrase), even though both env-decrypt.
    let env_pp = try_open_envelope_v2(&header, &admin, CIPHER).unwrap();
    assert_eq!(env_pp.matched_slot_idx, 0);
    assert_eq!(env_pp.payload.kind, DeniableKindTag::Passphrase);
    let opened_pp = complete_open_v2(env_pp, &admin, CIPHER).unwrap();
    assert_eq!(opened_pp.mvk.as_bytes(), mvk.as_bytes());

    // Open as FIDO2: must land on slot 3, kind=Fido2Passphrase.
    let env_fido = try_open_envelope_v2(&header, &fido, CIPHER).unwrap();
    assert_eq!(env_fido.matched_slot_idx, 3);
    assert_eq!(env_fido.payload.kind, DeniableKindTag::Fido2Passphrase);
    assert_eq!(env_fido.payload.cred_id, fido_mat.cred_id);
    let opened_fido = complete_open_v2(env_fido, &fido, CIPHER).unwrap();
    assert_eq!(opened_fido.mvk.as_bytes(), mvk.as_bytes());
}

// -----------------------------------------------------------------
// Test #2: cross-vault slot splicing is rejected.
//
// Regression target: the audit fix that mixes per_vault_salt into
// the inner-header AAD (`inner_header_aad` + the v1 -> v2 prefix
// change). Two vaults built with the same envelope passphrase derive
// the same envelope KEK in isolation; but the slot AAD also binds
// `per_vault_salt` so a slot lifted from vault A and pasted into
// vault B's slot table MUST fail to open with B's salt-derived KEK.
//
// Before the fix this would have succeeded (the salt was not bound),
// leaking the property that slots could be transplanted between
// vaults sharing a passphrase.
// -----------------------------------------------------------------

#[test]
fn cross_vault_slot_splice_is_rejected() {
    let pp = b"same-pass-on-both-vaults";
    let cred = DeniableCredential::Passphrase {
        passphrase: pp,
        argon2: cheap_params(),
    };

    let vault_a = fresh_vault(&cred, &DeniableMaterial::passphrase_only(), 2);
    let mut vault_b = fresh_vault(&cred, &DeniableMaterial::passphrase_only(), 2);

    // Sanity: salts must differ. If by astronomical chance they
    // matched, the splice would be a no-op and the test would
    // wrongly pass; assert separation up front.
    assert_ne!(
        &vault_a[..DENIABLE_SALT_SIZE],
        &vault_b[..DENIABLE_SALT_SIZE]
    );

    // Splice vault A's slot 2 into vault B's slot 2 (raw bytes).
    let slot_off = DENIABLE_SLOT_TABLE_OFFSET + 2 * DENIABLE_SLOT_SIZE;
    vault_b[slot_off..slot_off + DENIABLE_SLOT_SIZE]
        .copy_from_slice(&vault_a[slot_off..slot_off + DENIABLE_SLOT_SIZE]);

    // Try to open vault B with the same passphrase. The envelope
    // AEAD outer AAD binds vault B's salt; the spliced slot was
    // sealed with vault A's salt; verification MUST fail.
    let err = try_open_envelope_v2(&vault_b, &cred, CIPHER)
        .err()
        .expect("spliced vault must not open");
    assert!(matches!(err, Error::OpaqueUnlockFailed));
}

// -----------------------------------------------------------------
// Test #3: HybridPq envelope passphrase and ML-KEM shared secret
// are cryptographically independent inputs.
//
// Background: the GUI's hybrid open flow supports a seed-file
// passphrase that may differ from the envelope passphrase. That UX
// only works if at the format layer the passphrase and the
// `mlkem_shared` are bound JOINTLY into the inner-MVK KEK so that
// (right pass + wrong shared) fails, even though by design phase 1
// envelope-discovery succeeds with the right passphrase alone (the
// "no-oracle" property requires phase 1 to depend only on the
// passphrase).
//
// The test pins both facts:
//   (a) right pass + wrong shared MUST succeed at phase 1 (since
//       phase 1 depends only on passphrase - changing this would
//       break envelope-discovery's oracle-free invariant).
//   (b) right pass + wrong shared MUST fail at phase 2 (MVK unwrap
//       uses the factors KEK which binds the shared).
//   (c) wrong pass MUST fail at phase 1 regardless of shared.
//
// Uses a real ML-KEM encap/decap pair via `luksbox_pq` so the
// shared bytes are produced by the same primitive the production
// code uses, not a hand-rolled random byte string.
// -----------------------------------------------------------------

#[test]
fn hybrid_envelope_pass_and_mlkem_shared_are_independent_inputs() {
    use luksbox_pq::{PqParams, decapsulate_with, encapsulate_with, keygen_with};

    let envelope_pass: &[u8] = b"envelope-pass-A";

    // Generate an ML-KEM-768 keypair, encapsulate to obtain a
    // (ciphertext, shared) pair. Production code reaches `shared`
    // via decapsulate(seed_from_file, ciphertext_from_sidecar);
    // the test bypasses both files since the property under test is
    // purely about how the format crate consumes `shared`.
    let (pk, seed) = keygen_with(PqParams::Ml768);
    let (ct, shared) = encapsulate_with(PqParams::Ml768, &pk).unwrap();
    let dec = decapsulate_with(PqParams::Ml768, &seed, &ct).unwrap();
    assert_eq!(&dec[..], &shared[..], "ML-KEM round-trip pre-check");
    let shared_arr: [u8; 32] = *shared;

    let cred_create = DeniableCredential::HybridPqPassphrase {
        passphrase: envelope_pass,
        argon2: cheap_params(),
        mlkem_shared: &shared_arr,
    };
    let header = fresh_vault(&cred_create, &DeniableMaterial::passphrase_only(), 1);

    // (a)+(b): right pass + wrong shared - phase 1 OK (no oracle),
    // phase 2 FAILS (factors KEK binds the shared).
    let wrong_shared = [0u8; 32];
    let cred_wrong_shared = DeniableCredential::HybridPqPassphrase {
        passphrase: envelope_pass,
        argon2: cheap_params(),
        mlkem_shared: &wrong_shared,
    };
    let env = try_open_envelope_v2(&header, &cred_wrong_shared, CIPHER)
        .expect("phase 1 envelope discovery depends only on passphrase");
    let err = complete_open_v2(env, &cred_wrong_shared, CIPHER)
        .err()
        .expect("phase 2 MVK unwrap with wrong shared must fail");
    assert!(matches!(err, Error::OpaqueUnlockFailed));

    // Same property with a foreign-vault shared (verifies that
    // unrelated valid ML-KEM output is also rejected, not just the
    // all-zeros special case).
    let (pk2, _) = keygen_with(PqParams::Ml768);
    let (_, shared2) = encapsulate_with(PqParams::Ml768, &pk2).unwrap();
    let shared2_arr: [u8; 32] = *shared2;
    let cred_mixed = DeniableCredential::HybridPqPassphrase {
        passphrase: envelope_pass,
        argon2: cheap_params(),
        mlkem_shared: &shared2_arr,
    };
    let env = try_open_envelope_v2(&header, &cred_mixed, CIPHER).unwrap();
    let err = complete_open_v2(env, &cred_mixed, CIPHER).err().unwrap();
    assert!(matches!(err, Error::OpaqueUnlockFailed));

    // (c): wrong pass fails at phase 1 regardless of shared.
    let cred_wrong_pass = DeniableCredential::HybridPqPassphrase {
        passphrase: b"completely-different-envelope-pass",
        argon2: cheap_params(),
        mlkem_shared: &shared_arr,
    };
    let err = try_open_envelope_v2(&header, &cred_wrong_pass, CIPHER)
        .err()
        .expect("wrong pass must fail envelope discovery");
    assert!(matches!(err, Error::OpaqueUnlockFailed));

    // Sanity: positive open with correct (pass, shared).
    let env = try_open_envelope_v2(&header, &cred_create, CIPHER).unwrap();
    let _ = complete_open_v2(env, &cred_create, CIPHER).unwrap();
}

// -----------------------------------------------------------------
// Test #4: MVK rotation with a mixed-kind kept set.
//
// Extends the existing single-kind rotation tests: enroll three
// slots of three different kinds, rotate dropping the middle one,
// verify the kept two open with the new MVK and the dropped one
// no longer opens at all.
// -----------------------------------------------------------------

#[test]
fn rotation_with_mixed_kept_set_preserves_kept_and_drops_others() {
    let inner = sane_inner();
    let admin = DeniableCredential::Passphrase {
        passphrase: b"admin-pass",
        argon2: cheap_params(),
    };
    let (mut header, mvk) = create_with_credential_v2(
        &admin,
        &DeniableMaterial::passphrase_only(),
        0,
        CIPHER,
        inner,
    )
    .unwrap();

    // Enroll FIDO2 at slot 3 and TPM at slot 6.
    let hmac_out = [0xa2u8; 32];
    let fido = DeniableCredential::Fido2Passphrase {
        passphrase: b"fido-pass",
        argon2: cheap_params(),
        hmac_secret_output: &hmac_out,
    };
    let fido_mat = DeniableMaterial {
        cred_id: vec![0x55; 32],
        hmac_salt: Some([0x66; 32]),
        tpm_blob: Vec::new(),
    };
    let unsealed = [0xc7u8; 32];
    let tpm = DeniableCredential::TpmPassphrase {
        passphrase: b"tpm-pass",
        argon2: cheap_params(),
        unsealed: &unsealed,
    };
    let tpm_mat = DeniableMaterial {
        cred_id: Vec::new(),
        hmac_salt: None,
        tpm_blob: vec![0x99; 1024],
    };
    let salt: [u8; DENIABLE_SALT_SIZE] = header[..DENIABLE_SALT_SIZE].try_into().unwrap();
    {
        let header_arr: &mut [u8; DENIABLE_HEADER_SIZE] = (&mut header[..]).try_into().unwrap();
        install_slot_v2(header_arr, 3, &fido, &fido_mat, &mvk, CIPHER, &salt).unwrap();
        install_slot_v2(header_arr, 6, &tpm, &tpm_mat, &mvk, CIPHER, &salt).unwrap();
    }

    // Rotate keeping only admin (slot 0) and tpm (slot 6); drop fido.
    let mut new_salt = [0u8; DENIABLE_SALT_SIZE];
    luksbox_core::deniable::fill_random(&mut new_salt).unwrap();
    let new_mvk = {
        let header_arr: &mut [u8; DENIABLE_HEADER_SIZE] = (&mut header[..]).try_into().unwrap();
        rotate_mvk_v2(
            header_arr,
            inner,
            CIPHER,
            new_salt,
            &[
                (0, &admin, &DeniableMaterial::passphrase_only()),
                (6, &tpm, &tpm_mat),
            ],
        )
        .unwrap()
    };
    assert_ne!(new_mvk.as_bytes(), mvk.as_bytes());

    // Admin still opens, recovers new MVK.
    let env = try_open_envelope_v2(&header, &admin, CIPHER).unwrap();
    let opened = complete_open_v2(env, &admin, CIPHER).unwrap();
    assert_eq!(opened.mvk.as_bytes(), new_mvk.as_bytes());
    assert_eq!(opened.matched_slot_idx, 0);

    // TPM still opens, recovers same new MVK.
    let env = try_open_envelope_v2(&header, &tpm, CIPHER).unwrap();
    let opened = complete_open_v2(env, &tpm, CIPHER).unwrap();
    assert_eq!(opened.mvk.as_bytes(), new_mvk.as_bytes());
    assert_eq!(opened.matched_slot_idx, 6);

    // FIDO is gone: try_open must opaquely fail (the slot bytes are
    // fresh OsRng now; envelope decryption produces nothing).
    let err = try_open_envelope_v2(&header, &fido, CIPHER)
        .err()
        .expect("dropped credential must not open");
    assert!(matches!(err, Error::OpaqueUnlockFailed));
}

// -----------------------------------------------------------------
// Test #5: add-slot of a different kind after init.
//
// Regression target: the variant-dispatch bug from mid-session where
// adding a TPM slot to a passphrase-only vault produced
// "credential kind mismatch (vault expects a different variant)".
// The fix routes the add-slot through `install_slot_v2` rather than
// the create-only `create_with_credential_v2`. This is the
// format-layer property: starting from a single-kind vault, we can
// install_slot_v2 a different kind and both slots open with their
// respective credentials.
// -----------------------------------------------------------------

#[test]
fn add_slot_of_different_kind_after_init_round_trips_both_slots() {
    let inner = sane_inner();
    let admin = DeniableCredential::Passphrase {
        passphrase: b"init-admin",
        argon2: cheap_params(),
    };
    let (mut header, mvk) = create_with_credential_v2(
        &admin,
        &DeniableMaterial::passphrase_only(),
        0,
        CIPHER,
        inner,
    )
    .unwrap();

    // Add a TPM-kind slot at index 4 using install_slot_v2.
    let unsealed = [0xefu8; 32];
    let tpm = DeniableCredential::TpmPassphrase {
        passphrase: b"tpm-user-pass",
        argon2: cheap_params(),
        unsealed: &unsealed,
    };
    let tpm_mat = DeniableMaterial {
        cred_id: Vec::new(),
        hmac_salt: None,
        tpm_blob: vec![0x33; 2048],
    };
    let salt: [u8; DENIABLE_SALT_SIZE] = header[..DENIABLE_SALT_SIZE].try_into().unwrap();
    {
        let header_arr: &mut [u8; DENIABLE_HEADER_SIZE] = (&mut header[..]).try_into().unwrap();
        install_slot_v2(header_arr, 4, &tpm, &tpm_mat, &mvk, CIPHER, &salt).unwrap();
    }

    // Admin still opens.
    let env = try_open_envelope_v2(&header, &admin, CIPHER).unwrap();
    let opened = complete_open_v2(env, &admin, CIPHER).unwrap();
    assert_eq!(opened.mvk.as_bytes(), mvk.as_bytes());

    // TPM slot opens with the same MVK, recovers the embedded blob.
    let env = try_open_envelope_v2(&header, &tpm, CIPHER).unwrap();
    assert_eq!(env.payload.kind, DeniableKindTag::TpmPassphrase);
    assert_eq!(env.payload.tpm_blob, tpm_mat.tpm_blob);
    let opened = complete_open_v2(env, &tpm, CIPHER).unwrap();
    assert_eq!(opened.mvk.as_bytes(), mvk.as_bytes());
    assert_eq!(opened.matched_slot_idx, 4);
}
