// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Penthertz <https://penthertz.com> (https://x.com/PentHertz)

//! Security-invariant regression tests added in audit round 6.
//!
//! Three classes of invariant locked in:
//!
//!   A. HKDF info-string uniqueness, every domain-separation tag
//!      we use to derive subkeys from the MVK is distinct from every
//!      other one. A future regression where two contexts share an
//!      info string would let an attacker who recovered one subkey
//!      use it in the other context.
//!
//!   C. Slot AEAD AAD field-by-field coverage, the slot's wrap
//!      authenticates offsets 0..76 (kind, uuid, kdf_params,
//!      kdf_salt, aead_nonce). Flipping any single bit in that
//!      region must break the AEAD verification.
//!
//!   H. Cipher-suite enum + integer overflow, `CipherSuite::from_u16`
//!      rejects unknown values; offset arithmetic guards against
//!      wraparound when an attacker-with-MVK supplies pathological
//!      header field values.

use luksbox_core::{
    Argon2idParams, CipherSuite, Keyslot, MasterVolumeKey, SLOT_SIZE, header::HEADER_MAC_INFO,
};

// ---- A. HKDF info-string uniqueness -------------------------------------

#[test]
fn hkdf_info_strings_are_pairwise_unique() {
    // Source-of-truth list. Add to this list when a new HKDF info
    // string is introduced ANYWHERE in the codebase. The test fails
    // if any two strings collide OR if any string is a prefix of
    // another (which would let a longer info collide on a shared
    // HKDF call by accident).
    //
    // Audit: grep `b"lbx:` across crates/*/src/ to confirm this list
    // matches the production code.
    let infos: &[(&str, &[u8])] = &[
        ("HEADER_MAC_INFO", b"lbx:header-mac/v1"),
        ("MVK_FROM_FIDO2_INFO", b"lbx:mvk-fido/v1"),
        ("ANCHOR_INFO", b"lbx:anchor-mac/v1"),
        ("METADATA_KEY_INFO", b"lbx:metadata-key/v1"),
        ("FILE_KEY_INFO_PREFIX", b"lbx:file/v1:"),
        ("HYBRID_KEK_INFO", b"lbx:hybrid-kek/v1"),
        ("HYBRID_FIDO_KEK_INFO", b"lbx:hybrid-fido-kek/v1"),
        // TPM-related info strings (added when fused TPM+FIDO2 +
        // hybrid-PQ-TPM kinds shipped). Each derives a distinct KEK
        // for a different multi-factor combination; collision would
        // let an attacker who recovered one path's KEK cross-use it
        // on a different path's wrap.
        ("TPM2_FIDO2_KEK_INFO", b"lbx:tpm2-fido2-kek/v1"),
        ("HYBRID_TPM2_KEK_INFO", b"lbx:hybrid-tpm-kek/v1"),
        ("HYBRID_TPM2_FIDO2_KEK_INFO", b"lbx:hybrid-tpm-fido2-kek/v1"),
        // NOTE: b"lbx:fido" is an Argon2id input prefix, NOT an HKDF
        // info string, it lives inside the message that gets stretched,
        // so collision semantics are different. Excluded from this test
        // by design.
    ];

    // Spot-check that our compiled HEADER_MAC_INFO matches what's in
    // the table. If the constant changes without the table updating,
    // the test fails noisily here rather than silently passing.
    assert_eq!(
        HEADER_MAC_INFO, b"lbx:header-mac/v1",
        "HEADER_MAC_INFO drifted from this test's source-of-truth table"
    );

    for (i, (name_a, a)) in infos.iter().enumerate() {
        for (name_b, b) in infos.iter().skip(i + 1) {
            assert_ne!(a, b, "HKDF info collision: {name_a} == {name_b}",);
            assert!(
                !a.starts_with(b) && !b.starts_with(a),
                "HKDF info prefix-collision (one is a prefix of the other): \
                 {name_a} = {a:?}, {name_b} = {b:?}",
            );
        }
    }
}

// ---- C. Slot AEAD AAD field-by-field coverage ---------------------------

const HEADER_SALT: [u8; 32] = [0x42; 32];
const TEST_KDF: Argon2idParams = Argon2idParams {
    m_cost_kib: 8,
    t_cost: 1,
    p_cost: 1,
};

fn build_passphrase_slot() -> ([u8; SLOT_SIZE], MasterVolumeKey) {
    let mvk = MasterVolumeKey::from_bytes([0x55; 32]);
    let slot = Keyslot::new_passphrase(
        CipherSuite::Aes256Gcm,
        &mvk,
        b"hunter2",
        TEST_KDF,
        &HEADER_SALT,
    )
    .unwrap();
    (slot.to_bytes(), mvk)
}

/// Per `Keyslot::wrap_mvk`, the AEAD AAD covers `buf[..SLOT_AAD_LEN]` =
/// `buf[..OFF_WRAPPED_CT]` = bytes 0..76. Every byte in that range MUST
/// be authenticated; flipping any single bit MUST break unwrap.
#[test]
fn slot_aead_aad_covers_every_byte_in_authenticated_region() {
    const SLOT_AAD_LEN: usize = 76; // mirrors keyslot.rs
    let (good_bytes, _mvk) = build_passphrase_slot();

    // Sanity: unmutated slot parses cleanly.
    let _ = Keyslot::from_bytes(&good_bytes).expect("clean slot must parse");

    let mut tampered_caught = 0usize;
    let mut tampered_total = 0usize;
    for offset in 0..SLOT_AAD_LEN {
        // Skip the kind byte specifically, flipping it can produce a
        // different valid SlotKind which `from_bytes` accepts (kinds 0..7
        // are all defined). We test kind tampering separately below.
        if offset == 0 {
            continue;
        }
        // Skip the 3 padding bytes after the kind byte (offsets 1..4).
        // They're zeroed by write_aad_region, included in AAD, but
        // they're padding, no semantic content. Flipping them should
        // still fail, but we test the structurally-meaningful bytes.
        if (1..4).contains(&offset) {
            continue;
        }
        tampered_total += 1;

        let mut bad = good_bytes;
        bad[offset] ^= 0x01;

        // The slot may parse fine (length checks pass) but the unwrap
        // must fail. Test by attempting a passphrase unlock.
        if let Ok(slot) = Keyslot::from_bytes(&bad) {
            // Try to unlock with the right passphrase. Should fail,
            // wrong AAD makes AEAD reject.
            let r = slot.unlock_passphrase(CipherSuite::Aes256Gcm, b"hunter2", &HEADER_SALT);
            if r.is_err() {
                tampered_caught += 1;
            } else {
                panic!(
                    "byte at offset {offset} flipped but unlock succeeded, \
                     AEAD AAD does NOT cover this byte (security regression)"
                );
            }
        } else {
            // from_bytes rejected, counts as caught.
            tampered_caught += 1;
        }
    }
    assert_eq!(
        tampered_caught, tampered_total,
        "expected every tampered byte in 0..{SLOT_AAD_LEN} to be caught"
    );
}

#[test]
fn slot_kind_byte_swap_changes_aad() {
    // The kind byte is part of AAD too, but flipping bit 0 of an
    // existing valid kind produces a different valid kind (e.g.
    // Passphrase=1 -> Empty=0, empty triggers the early-return path).
    // Test the security-relevant case: Passphrase=1 -> Fido2HmacSecret=2.
    let (good_bytes, _) = build_passphrase_slot();
    let mut bad = good_bytes;
    bad[0] = 2; // Fido2HmacSecret

    // from_bytes may parse, Fido2HmacSecret has different field
    // expectations but the parser is lenient if salt_len is 0 for
    // non-fido2 kinds. Either way, attempting passphrase unlock must
    // fail because the kind no longer matches the unlock path.
    match Keyslot::from_bytes(&bad) {
        Ok(slot) => {
            assert!(
                slot.unlock_passphrase(CipherSuite::Aes256Gcm, b"hunter2", &HEADER_SALT)
                    .is_err(),
                "kind-swap to Fido2HmacSecret must reject passphrase unlock"
            );
        }
        Err(_) => {
            // also fine, the parser refused
        }
    }
}

// ---- H. Cipher-suite enum bounds + offset overflow ----------------------

#[test]
fn cipher_suite_rejects_unknown_values() {
    // 0x0003 is now Aes256GcmSiv (added per audit Finding 1, RFC 8452);
    // unknown values bracket around the assigned range.
    for v in [0u16, 0x0004, 0x00ff, 0xffff] {
        assert!(
            CipherSuite::from_u16(v).is_err(),
            "cipher_suite={v:#x} should be rejected (unknown)"
        );
    }
    // Known good values still parse.
    assert!(matches!(
        CipherSuite::from_u16(0x0001),
        Ok(CipherSuite::Aes256Gcm)
    ));
    assert!(matches!(
        CipherSuite::from_u16(0x0002),
        Ok(CipherSuite::ChaCha20Poly1305)
    ));
    assert!(matches!(
        CipherSuite::from_u16(0x0003),
        Ok(CipherSuite::Aes256GcmSiv)
    ));
}

#[test]
fn header_offset_arithmetic_safe_against_overflow() {
    // The post-HMAC code in luksbox-format::Container does math on
    // metadata_offset / metadata_size / data_offset. An attacker
    // with the MVK could craft a header where metadata_offset +
    // metadata_size overflows. We verify here that the on-disk
    // representation doesn't cause panic IN THE PARSER itself,
    // post-parse use is the format crate's responsibility.
    //
    // The header parser stores raw u64 values; arithmetic on them
    // happens later in Container. As long as `Header::from_bytes`
    // doesn't crash on extreme values, this layer is safe.

    use luksbox_core::Header;
    use luksbox_core::KdfId;
    let _ = luksbox_core::HEADER_SIZE; // sanity-import

    let mvk = MasterVolumeKey::from_bytes([0x77; 32]);
    let h = Header::new(CipherSuite::Aes256Gcm, KdfId::Argon2id, 4096, 8192);
    let mut bytes = h.to_bytes(&mvk);

    // metadata_offset is u64 LE at offset 56 (per OFF_METADATA_OFFSET
    // in header.rs). metadata_size at 64. data_offset at 72. Set them
    // all to u64::MAX.
    for off in [56, 64, 72] {
        bytes[off..off + 8].copy_from_slice(&u64::MAX.to_le_bytes());
    }
    // Header MAC will fail (we mutated post-MAC), but the PARSER
    // shouldn't crash, it's not its job to validate the MAC. It just
    // needs to not panic on extreme values.
    let r = Header::from_bytes(&bytes);
    // Either parses (post-HMAC layer catches) or rejects cleanly, both fine.
    let _ = r;
}

// ---- C2. V2/V3 slot AEAD AAD covers cred_id and hmac_salt regions ----------
//
// Pre-V2, audit round 2 noted that the slot AEAD AAD covered offsets
// 0..76 only, cred_id and fido2_hmac_salt were authenticated only by
// the HEADER HMAC. Round 7C extended the AAD to also cover those
// regions (V2). The 2026 large-cred-ID follow-up extended the slot
// layout (V3) so cred_id can be up to 352 B, sized to accommodate
// authenticators that emit cred IDs larger than the typical YubiKey
// 64-byte case (Google Titan reportedly 288 B, SoloKey stateless
// mode 140 B; the exact format varies per vendor). V3 AAD covers
// the full 124..512 region. New slots created via `Keyslot::new_*`
// default to V3. These tests verify the V3 property and the legacy
// fallback for V1/V2 vaults still on disk.

// Synthetic FIDO2 slot helper: doesn't depend on MockAuthenticator
// (which lives in luksbox-fido2; a circular dep here would prevent
// luksbox-core from building). The hmac_secret can be any deterministic
// 32 bytes, the slot wrap path doesn't validate that it came from a
// real authenticator.
fn build_fido2_slot(
    cred_id: &[u8],
    salt: [u8; 32],
    hmac_secret: &[u8; 32],
) -> ([u8; SLOT_SIZE], MasterVolumeKey) {
    let mvk = MasterVolumeKey::from_bytes([0x55; 32]);
    let slot = Keyslot::new_fido2(
        CipherSuite::Aes256Gcm,
        &mvk,
        None,
        hmac_secret,
        cred_id,
        salt,
        TEST_KDF,
        &HEADER_SALT,
    )
    .unwrap();
    (slot.to_bytes(), mvk)
}

#[test]
fn v3_slot_aead_aad_covers_fido2_cred_id_region() {
    let cred_id: [u8; 16] = [0xa5; 16];
    let salt: [u8; 32] = [0x77; 32];
    let hmac_secret: [u8; 32] = [0x33; 32];
    let (mut bytes, mvk) = build_fido2_slot(&cred_id, salt, &hmac_secret);

    // Sanity: clean parse + unlock works and returns the right MVK.
    {
        let parsed = Keyslot::from_bytes(&bytes).unwrap();
        assert_eq!(
            parsed.aad_version,
            luksbox_core::AAD_VERSION_V4,
            "new FIDO2 slot must default to V4 (cross-platform salt convention)"
        );
        let recovered = parsed
            .unlock_fido2(CipherSuite::Aes256Gcm, None, &hmac_secret, &HEADER_SALT)
            .expect("clean unlock must succeed");
        assert_eq!(recovered.as_bytes(), mvk.as_bytes());
    }

    // Flip a byte inside the cred_id region (V3: offsets 128..480).
    // V3 AAD covers this whole range; tamper must trip the AEAD tag.
    bytes[128] ^= 0x01;
    let parsed = Keyslot::from_bytes(&bytes).unwrap();
    let r = parsed.unlock_fido2(CipherSuite::Aes256Gcm, None, &hmac_secret, &HEADER_SALT);
    assert!(
        r.is_err(),
        "V3 slot must reject cred_id tamper at the slot AEAD layer"
    );
}

#[test]
fn v3_slot_aead_aad_covers_fido2_hmac_salt_region() {
    let cred_id: [u8; 16] = [0xb7; 16];
    let salt: [u8; 32] = [0x88; 32];
    let hmac_secret: [u8; 32] = [0x44; 32];
    let (mut bytes, _mvk) = build_fido2_slot(&cred_id, salt, &hmac_secret);

    // V3 hmac_salt lives at offsets 480..512. Flip a byte inside it.
    bytes[480] ^= 0x01;
    let parsed = Keyslot::from_bytes(&bytes).unwrap();
    let r = parsed.unlock_fido2(CipherSuite::Aes256Gcm, None, &hmac_secret, &HEADER_SALT);
    assert!(
        r.is_err(),
        "V3 slot must reject hmac_salt tamper at the slot AEAD layer"
    );
}

/// V3 must accept and roundtrip a 288-byte cred_id (the size Google
/// Titan and similar stateless authenticators produce). Pre-V3 vaults
/// hard-capped at 128 B, blocking these devices entirely; V3 lifts the
/// cap to 352 B, which covers every known production authenticator.
#[test]
fn v3_slot_accepts_288_byte_cred_id() {
    let cred_id: Vec<u8> = (0..288).map(|i| (i & 0xff) as u8).collect();
    let salt: [u8; 32] = [0x99; 32];
    let hmac_secret: [u8; 32] = [0x66; 32];
    let (bytes, mvk) = build_fido2_slot(&cred_id, salt, &hmac_secret);

    let parsed = Keyslot::from_bytes(&bytes).unwrap();
    assert_eq!(parsed.aad_version, luksbox_core::AAD_VERSION_V4);
    assert_eq!(parsed.fido2_cred_id.len(), 288);
    assert_eq!(parsed.fido2_cred_id, cred_id);

    let recovered = parsed
        .unlock_fido2(CipherSuite::Aes256Gcm, None, &hmac_secret, &HEADER_SALT)
        .expect("clean V3 unlock must succeed for 288-byte cred_id");
    assert_eq!(recovered.as_bytes(), mvk.as_bytes());
}

#[test]
fn flipping_aad_version_byte_breaks_unlock() {
    let (mut bytes, _mvk) = build_passphrase_slot();
    // Sanity: clean unlock works.
    let _ = Keyslot::from_bytes(&bytes)
        .unwrap()
        .unlock_passphrase(CipherSuite::Aes256Gcm, b"hunter2", &HEADER_SALT)
        .expect("clean unlock");

    // Flip byte 1 (the AAD-version + layout selector). New slots are
    // V4; flip to V1. Reader will build a V1 AAD instead of V4, AND
    // V1 has a different layout (hmac_salt at 256 vs 480) for FIDO2
    // slots, AND the version byte itself sits inside the AAD region
    // so its value is part of the tag input. Any of these breaks the
    // tag check.
    assert_eq!(bytes[1], luksbox_core::AAD_VERSION_V4);
    bytes[1] = luksbox_core::AAD_VERSION_V1;
    let parsed = Keyslot::from_bytes(&bytes).unwrap();
    assert_eq!(parsed.aad_version, luksbox_core::AAD_VERSION_V1);
    let r = parsed.unlock_passphrase(CipherSuite::Aes256Gcm, b"hunter2", &HEADER_SALT);
    assert!(
        r.is_err(),
        "Tampering aad_version byte must break unlock, different AAD shape"
    );
}

#[test]
fn unknown_aad_version_byte_rejected_by_parser() {
    let (mut bytes, _mvk) = build_passphrase_slot();
    bytes[1] = 0xff;
    let r = Keyslot::from_bytes(&bytes);
    assert!(
        r.is_err(),
        "unknown aad_version (0xff) must be rejected at parse time"
    );
}

// ---- D. AAD coverage for the new TPM SlotKinds (8..14) ------------------
//
// 2026-05 audit found a real bug: build_aead_aad's salt_len matching
// list excluded the fused TPM+FIDO2 kinds (Tpm2Fido2,
// HybridPqKemTpm2Fido2, HybridPqKem1024Tpm2Fido2). The hmac_salt at
// 480..512 was written to disk by to_bytes() but excluded from AEAD
// coverage. An attacker could flip the salt without breaking the
// wrap, causing the FIDO2 authenticator to return a different
// hmac_secret -> AEAD fails -> denial of service. Not a key-recovery
// break (HMAC-SHA-256 second-preimage is infeasible) but a design-
// invariant break. The fix added the missing kinds; these tests pin
// the invariant so it can't regress.

use luksbox_core::SlotKind;

const KEK_FROM_TPM: [u8; 32] = [0x77; 32];
const PQ_SHARED: [u8; 32] = [0xee; 32];

fn fake_sealed_blob() -> Vec<u8> {
    let public = vec![0x11u8; 80];
    let private = vec![0x22u8; 200];
    let mut out = Vec::with_capacity(4 + public.len() + private.len());
    out.extend_from_slice(&(public.len() as u16).to_le_bytes());
    out.extend_from_slice(&public);
    out.extend_from_slice(&(private.len() as u16).to_le_bytes());
    out.extend_from_slice(&private);
    out
}

fn assert_offset_caught<U>(good: &[u8; SLOT_SIZE], offset: usize, unlock: U)
where
    U: Fn(&Keyslot) -> Result<MasterVolumeKey, luksbox_core::Error>,
{
    let mut bad = *good;
    bad[offset] ^= 0x01;
    if let Ok(slot) = Keyslot::from_bytes(&bad) {
        let r = unlock(&slot);
        assert!(
            r.is_err(),
            "byte at offset {offset} flipped but unlock succeeded; AEAD AAD \
             does NOT cover this byte (security regression for SlotKind {:?})",
            slot.kind,
        );
    }
}

/// V3 AAD covers: 0..76 base + 124..128 length fields + 128..128+cred_len
/// active region + (480..512 hmac_salt iff the slot kind uses one).
/// Padding past cred_len (128+cred_len..480) is NOT in AAD by design:
/// random entropy padding from to_bytes() that from_bytes() drops.
/// Safe because cred_len itself IS authenticated.
fn assert_v3_aad_covers_everything<U>(
    good: &[u8; SLOT_SIZE],
    cred_len: usize,
    fido2_uses_salt: bool,
    unlock: U,
) where
    U: Fn(&Keyslot) -> Result<MasterVolumeKey, luksbox_core::Error>,
{
    let clean = Keyslot::from_bytes(good).expect("clean slot must parse");
    unlock(&clean).expect("clean slot must unlock with the right material");

    for offset in 4..76 {
        assert_offset_caught(good, offset, &unlock);
    }
    for offset in 124..128 {
        assert_offset_caught(good, offset, &unlock);
    }
    for offset in [
        128usize,
        129,
        128 + cred_len / 4,
        128 + cred_len / 2,
        128 + cred_len - 1,
    ] {
        if offset < 128 + cred_len {
            assert_offset_caught(good, offset, &unlock);
        }
    }
    if fido2_uses_salt {
        for offset in [480usize, 481, 500, 511] {
            assert_offset_caught(good, offset, &unlock);
        }
    }
}

#[test]
fn tpm2_sealed_aad_covers_authenticated_region() {
    let mvk = MasterVolumeKey::from_bytes([0x55; 32]);
    let blob = fake_sealed_blob();
    let cred_len = blob.len();
    let slot = Keyslot::new_tpm2(
        CipherSuite::Aes256GcmSiv,
        &mvk,
        &KEK_FROM_TPM,
        &blob,
        &HEADER_SALT,
    )
    .unwrap();
    let bytes = slot.to_bytes();
    assert_v3_aad_covers_everything(&bytes, cred_len, false, |s| {
        s.unlock_tpm2(CipherSuite::Aes256GcmSiv, &KEK_FROM_TPM, &HEADER_SALT)
    });
}

#[test]
fn tpm2_sealed_pin_aad_covers_authenticated_region() {
    let mvk = MasterVolumeKey::from_bytes([0x66; 32]);
    let blob = fake_sealed_blob();
    let cred_len = blob.len();
    let slot = Keyslot::new_tpm2_pin(
        CipherSuite::Aes256GcmSiv,
        &mvk,
        &KEK_FROM_TPM,
        &blob,
        &HEADER_SALT,
    )
    .unwrap();
    let bytes = slot.to_bytes();
    assert_v3_aad_covers_everything(&bytes, cred_len, false, |s| {
        s.unlock_tpm2(CipherSuite::Aes256GcmSiv, &KEK_FROM_TPM, &HEADER_SALT)
    });
}

#[test]
fn hybrid_pq_kem_tpm2_aad_covers_authenticated_region() {
    let mvk = MasterVolumeKey::from_bytes([0x77; 32]);
    let blob = fake_sealed_blob();
    let cred_len = blob.len();
    let slot = Keyslot::new_hybrid_pq_tpm2(
        CipherSuite::Aes256GcmSiv,
        &mvk,
        &KEK_FROM_TPM,
        &PQ_SHARED,
        &blob,
        &HEADER_SALT,
    )
    .unwrap();
    let bytes = slot.to_bytes();
    assert_v3_aad_covers_everything(&bytes, cred_len, false, |s| {
        s.unlock_hybrid_pq_tpm2(
            CipherSuite::Aes256GcmSiv,
            &KEK_FROM_TPM,
            &PQ_SHARED,
            &HEADER_SALT,
        )
    });
}

#[test]
fn hybrid_pq_kem_1024_tpm2_aad_covers_authenticated_region() {
    let mvk = MasterVolumeKey::from_bytes([0x88; 32]);
    let blob = fake_sealed_blob();
    let cred_len = blob.len();
    let slot = Keyslot::new_hybrid_pq_1024_tpm2(
        CipherSuite::Aes256GcmSiv,
        &mvk,
        &KEK_FROM_TPM,
        &PQ_SHARED,
        &blob,
        &HEADER_SALT,
    )
    .unwrap();
    let bytes = slot.to_bytes();
    assert_v3_aad_covers_everything(&bytes, cred_len, false, |s| {
        s.unlock_hybrid_pq_tpm2(
            CipherSuite::Aes256GcmSiv,
            &KEK_FROM_TPM,
            &PQ_SHARED,
            &HEADER_SALT,
        )
    });
}

#[test]
fn tpm2_fido2_aad_covers_authenticated_region() {
    // The regression class. hmac_salt at 480..512 IS in AAD here
    // after the build_aead_aad fix.
    let mvk = MasterVolumeKey::from_bytes([0xa0; 32]);
    let tpm_unsealed = [0x11u8; 32];
    let hmac_secret = [0x22u8; 32];
    let blob = fake_sealed_blob();
    let cred_id = vec![0x33u8; 64];
    let hmac_salt = [0x44u8; 32];
    let combined_len = 2 + blob.len() + cred_id.len();
    let slot = Keyslot::new_tpm2_fido2(
        CipherSuite::Aes256GcmSiv,
        &mvk,
        &tpm_unsealed,
        &hmac_secret,
        &blob,
        &cred_id,
        hmac_salt,
        &HEADER_SALT,
    )
    .unwrap();
    let bytes = slot.to_bytes();
    assert_v3_aad_covers_everything(&bytes, combined_len, true, |s| {
        s.unlock_tpm2_fido2(
            CipherSuite::Aes256GcmSiv,
            &tpm_unsealed,
            &hmac_secret,
            &HEADER_SALT,
        )
    });
}

#[test]
fn hybrid_pq_kem_tpm2_fido2_aad_covers_authenticated_region() {
    let mvk = MasterVolumeKey::from_bytes([0xb0; 32]);
    let tpm_unsealed = [0x55u8; 32];
    let hmac_secret = [0x66u8; 32];
    let blob = fake_sealed_blob();
    let cred_id = vec![0x77u8; 64];
    let hmac_salt = [0x88u8; 32];
    let combined_len = 2 + blob.len() + cred_id.len();
    let slot = Keyslot::new_hybrid_pq_tpm2_fido2(
        CipherSuite::Aes256GcmSiv,
        &mvk,
        &tpm_unsealed,
        &hmac_secret,
        &PQ_SHARED,
        &blob,
        &cred_id,
        hmac_salt,
        &HEADER_SALT,
    )
    .unwrap();
    let bytes = slot.to_bytes();
    assert_v3_aad_covers_everything(&bytes, combined_len, true, |s| {
        s.unlock_hybrid_pq_tpm2_fido2(
            CipherSuite::Aes256GcmSiv,
            &tpm_unsealed,
            &hmac_secret,
            &PQ_SHARED,
            &HEADER_SALT,
        )
    });
}

#[test]
fn tpm2_kind_byte_swap_to_hybrid_breaks_aad() {
    // Different KEK derivation; AEAD must reject because kind is in AAD.
    let mvk = MasterVolumeKey::from_bytes([0x55; 32]);
    let slot = Keyslot::new_tpm2(
        CipherSuite::Aes256GcmSiv,
        &mvk,
        &KEK_FROM_TPM,
        &fake_sealed_blob(),
        &HEADER_SALT,
    )
    .unwrap();
    let mut bytes = slot.to_bytes();
    bytes[0] = SlotKind::HybridPqKemTpm2 as u8;
    if let Ok(parsed) = Keyslot::from_bytes(&bytes) {
        let r = parsed.unlock_hybrid_pq_tpm2(
            CipherSuite::Aes256GcmSiv,
            &KEK_FROM_TPM,
            &PQ_SHARED,
            &HEADER_SALT,
        );
        assert!(
            r.is_err(),
            "Tpm2Sealed -> HybridPqKemTpm2 kind swap accepted; AAD does NOT cover kind"
        );
    }
}

// ---- E. Wire-format invariants -----------------------------------------
//
// The on-disk slot is a fixed 512 B record. A regression that changed
// `Keyslot::to_bytes()` to emit anything else would silently corrupt
// the header layout (slots are packed end-to-end at fixed offsets).
// The header has a `const _: () = assert!(...)` guarding the const,
// but a runtime check pins the invariant against runtime-only
// regressions (e.g. a constructor that forgets to fill padding to
// SLOT_SIZE).

/// Every `Keyslot::to_bytes()` output is exactly SLOT_SIZE = 512 B.
/// Tests every populated SlotKind plus the empty slot.
#[test]
fn every_slot_kind_serializes_to_exactly_slot_size_bytes() {
    let mvk = MasterVolumeKey::from_bytes([0x55; 32]);
    let blob = fake_sealed_blob();
    let kek = KEK_FROM_TPM;
    let pq = PQ_SHARED;
    let cred = vec![0x33u8; 64];
    let salt = [0x44u8; 32];

    let slots: Vec<Keyslot> = vec![
        Keyslot::empty(),
        Keyslot::new_passphrase(
            CipherSuite::Aes256GcmSiv,
            &mvk,
            b"pp",
            TEST_KDF,
            &HEADER_SALT,
        )
        .unwrap(),
        Keyslot::new_tpm2(CipherSuite::Aes256GcmSiv, &mvk, &kek, &blob, &HEADER_SALT).unwrap(),
        Keyslot::new_tpm2_pin(CipherSuite::Aes256GcmSiv, &mvk, &kek, &blob, &HEADER_SALT).unwrap(),
        Keyslot::new_tpm2_fido2(
            CipherSuite::Aes256GcmSiv,
            &mvk,
            &kek,
            &kek,
            &blob,
            &cred,
            salt,
            &HEADER_SALT,
        )
        .unwrap(),
        Keyslot::new_hybrid_pq_tpm2(
            CipherSuite::Aes256GcmSiv,
            &mvk,
            &kek,
            &pq,
            &blob,
            &HEADER_SALT,
        )
        .unwrap(),
        Keyslot::new_hybrid_pq_1024_tpm2(
            CipherSuite::Aes256GcmSiv,
            &mvk,
            &kek,
            &pq,
            &blob,
            &HEADER_SALT,
        )
        .unwrap(),
        Keyslot::new_hybrid_pq_tpm2_fido2(
            CipherSuite::Aes256GcmSiv,
            &mvk,
            &kek,
            &kek,
            &pq,
            &blob,
            &cred,
            salt,
            &HEADER_SALT,
        )
        .unwrap(),
        Keyslot::new_hybrid_pq_1024_tpm2_fido2(
            CipherSuite::Aes256GcmSiv,
            &mvk,
            &kek,
            &kek,
            &pq,
            &blob,
            &cred,
            salt,
            &HEADER_SALT,
        )
        .unwrap(),
    ];
    for slot in &slots {
        let bytes = slot.to_bytes();
        assert_eq!(
            bytes.len(),
            SLOT_SIZE,
            "Keyslot::to_bytes() returned {} bytes for kind {:?}; expected SLOT_SIZE = {}",
            bytes.len(),
            slot.kind,
            SLOT_SIZE,
        );
    }
}

// ---- F. Ground-truth: same MVK unwraps from every TPM-kind keyslot -----
//
// The vault format is: ONE master volume key (MVK) wrapped under
// MULTIPLE keyslots. Each keyslot can be a different kind (passphrase
// / FIDO2 / TPM / hybrid-PQ / fused) and must independently unwrap
// to the SAME MVK. Without this invariant, multi-keyslot vaults
// would split-brain: unlocking via slot A would yield MVK_A, slot B
// would yield MVK_B, and chunks encrypted under MVK_A would not
// decrypt after a slot-A re-enroll.
//
// Existing tests cover passphrase + FIDO2; this test pins the
// invariant for the TPM-using kinds added in this audit cycle.

#[test]
fn ground_truth_same_mvk_unwraps_from_every_tpm_keyslot_kind() {
    let mvk = MasterVolumeKey::from_bytes([0xc0; 32]);
    let mvk_bytes_expected = *mvk.as_bytes();
    let blob = fake_sealed_blob();
    let kek = KEK_FROM_TPM;
    let pq = PQ_SHARED;
    let cred = vec![0x33u8; 64];
    let salt = [0x44u8; 32];

    // Wrap the same MVK under each TPM-using kind. Each constructor
    // takes the same `mvk` reference so all wraps protect identical
    // bytes; unwrap MUST return those exact bytes.
    let slots: Vec<(
        &'static str,
        Keyslot,
        Box<dyn Fn(&Keyslot) -> Result<MasterVolumeKey, luksbox_core::Error>>,
    )> = vec![
        (
            "Tpm2Sealed",
            Keyslot::new_tpm2(CipherSuite::Aes256GcmSiv, &mvk, &kek, &blob, &HEADER_SALT).unwrap(),
            Box::new(|s| s.unlock_tpm2(CipherSuite::Aes256GcmSiv, &kek, &HEADER_SALT)),
        ),
        (
            "Tpm2SealedPin",
            Keyslot::new_tpm2_pin(CipherSuite::Aes256GcmSiv, &mvk, &kek, &blob, &HEADER_SALT)
                .unwrap(),
            Box::new(|s| s.unlock_tpm2(CipherSuite::Aes256GcmSiv, &kek, &HEADER_SALT)),
        ),
        (
            "Tpm2Fido2",
            Keyslot::new_tpm2_fido2(
                CipherSuite::Aes256GcmSiv,
                &mvk,
                &kek,
                &kek,
                &blob,
                &cred,
                salt,
                &HEADER_SALT,
            )
            .unwrap(),
            Box::new(|s| s.unlock_tpm2_fido2(CipherSuite::Aes256GcmSiv, &kek, &kek, &HEADER_SALT)),
        ),
        (
            "HybridPqKemTpm2",
            Keyslot::new_hybrid_pq_tpm2(
                CipherSuite::Aes256GcmSiv,
                &mvk,
                &kek,
                &pq,
                &blob,
                &HEADER_SALT,
            )
            .unwrap(),
            Box::new(|s| {
                s.unlock_hybrid_pq_tpm2(CipherSuite::Aes256GcmSiv, &kek, &pq, &HEADER_SALT)
            }),
        ),
        (
            "HybridPqKem1024Tpm2",
            Keyslot::new_hybrid_pq_1024_tpm2(
                CipherSuite::Aes256GcmSiv,
                &mvk,
                &kek,
                &pq,
                &blob,
                &HEADER_SALT,
            )
            .unwrap(),
            Box::new(|s| {
                s.unlock_hybrid_pq_tpm2(CipherSuite::Aes256GcmSiv, &kek, &pq, &HEADER_SALT)
            }),
        ),
        (
            "HybridPqKemTpm2Fido2",
            Keyslot::new_hybrid_pq_tpm2_fido2(
                CipherSuite::Aes256GcmSiv,
                &mvk,
                &kek,
                &kek,
                &pq,
                &blob,
                &cred,
                salt,
                &HEADER_SALT,
            )
            .unwrap(),
            Box::new(|s| {
                s.unlock_hybrid_pq_tpm2_fido2(
                    CipherSuite::Aes256GcmSiv,
                    &kek,
                    &kek,
                    &pq,
                    &HEADER_SALT,
                )
            }),
        ),
        (
            "HybridPqKem1024Tpm2Fido2",
            Keyslot::new_hybrid_pq_1024_tpm2_fido2(
                CipherSuite::Aes256GcmSiv,
                &mvk,
                &kek,
                &kek,
                &pq,
                &blob,
                &cred,
                salt,
                &HEADER_SALT,
            )
            .unwrap(),
            Box::new(|s| {
                s.unlock_hybrid_pq_tpm2_fido2(
                    CipherSuite::Aes256GcmSiv,
                    &kek,
                    &kek,
                    &pq,
                    &HEADER_SALT,
                )
            }),
        ),
    ];

    // Each slot must round-trip the exact same MVK. If ANY slot
    // produces a different MVK, the entire multi-keyslot model is
    // broken; users would see "unlock succeeds but vault content
    // is garbage" or worse.
    for (name, slot, unlock) in &slots {
        let recovered = unlock(slot).unwrap_or_else(|e| panic!("{name} unlock failed: {e:?}"));
        assert_eq!(
            *recovered.as_bytes(),
            mvk_bytes_expected,
            "{name} unwrapped to a DIFFERENT MVK (multi-keyslot \
             consistency broken; this would split-brain a vault \
             with multiple kinds)",
        );
    }
}

// ---- G. Tpm2Fido2 composite blob sub-format isolation -----------------
//
// The fused TPM+FIDO2 slot uses a sub-format inside its cred_id region:
//   [tpm_blob_len: u16 LE | tpm_blob | cred_id]
//
// Round-trip tests cover the happy path. These tests exercise the
// parser in isolation against adversarial buffers (post-AEAD tampering
// would break the wrap, but a malicious caller passing arbitrary
// fido2_cred_id contents at construction time should produce safe
// None / Err results, never panic).
//
// To probe the sub-format directly we mutate `fido2_cred_id` after
// construction (the accessors don't re-validate the wrap) and assert
// the parser returns None or the expected slice.

fn build_tpm2_fido2_with_cred_id(cred_id: Vec<u8>) -> Keyslot {
    let mvk = MasterVolumeKey::from_bytes([0xa0; 32]);
    let blob = fake_sealed_blob();
    let inner_cred = vec![0x33u8; 64];
    let salt = [0x44u8; 32];
    let mut slot = Keyslot::new_tpm2_fido2(
        CipherSuite::Aes256GcmSiv,
        &mvk,
        &KEK_FROM_TPM,
        &KEK_FROM_TPM,
        &blob,
        &inner_cred,
        salt,
        &HEADER_SALT,
    )
    .unwrap();
    // Direct field swap: the wrap is now invalid (AEAD would reject)
    // but we're testing the sub-format accessor in isolation.
    slot.fido2_cred_id = cred_id;
    slot
}

#[test]
fn tpm2_fido2_subformat_short_buffer_returns_none() {
    // Less than 2 bytes -> can't read the u16 length prefix.
    for short in [vec![], vec![0u8], vec![0xff]] {
        let slot = build_tpm2_fido2_with_cred_id(short);
        assert!(slot.tpm2_fido2_sealed_blob().is_none());
        assert!(slot.tpm2_fido2_cred_id().is_none());
    }
}

#[test]
fn tpm2_fido2_subformat_blob_len_overruns_buffer_returns_none() {
    // Length prefix claims 100 bytes but only 50 follow.
    let mut buf = (100u16).to_le_bytes().to_vec();
    buf.extend(std::iter::repeat_n(0xaau8, 50));
    let slot = build_tpm2_fido2_with_cred_id(buf);
    assert!(slot.tpm2_fido2_sealed_blob().is_none());
}

#[test]
fn tpm2_fido2_subformat_zero_length_blob_returns_empty_slice() {
    // tpm_blob_len = 0 with a 50-byte cred_id following.
    let mut buf = (0u16).to_le_bytes().to_vec();
    buf.extend(std::iter::repeat_n(0xbbu8, 50));
    let slot = build_tpm2_fido2_with_cred_id(buf);
    let blob = slot
        .tpm2_fido2_sealed_blob()
        .expect("zero-len blob is valid");
    assert!(blob.is_empty());
    let cred = slot.tpm2_fido2_cred_id().expect("cred_id should follow");
    assert_eq!(cred.len(), 50);
    assert!(cred.iter().all(|&b| b == 0xbb));
}

#[test]
fn tpm2_fido2_subformat_blob_consumes_entire_region_returns_empty_cred() {
    // tpm_blob_len exactly equals (region_len - 2): blob fills to end,
    // cred_id is empty. Boundary case.
    let blob_bytes = vec![0xccu8; 100];
    let mut buf = (blob_bytes.len() as u16).to_le_bytes().to_vec();
    buf.extend_from_slice(&blob_bytes);
    let slot = build_tpm2_fido2_with_cred_id(buf);
    let blob = slot.tpm2_fido2_sealed_blob().expect("max-len blob valid");
    assert_eq!(blob.len(), 100);
    let cred = slot.tpm2_fido2_cred_id().expect("empty cred_id is valid");
    assert!(cred.is_empty());
}

#[test]
fn tpm2_fido2_subformat_blob_len_max_u16_with_short_buffer_returns_none() {
    // tpm_blob_len = 0xffff, but the buffer is only 16 bytes total.
    // Parser must NOT attempt the slice (would panic) and return None.
    let mut buf = (0xffffu16).to_le_bytes().to_vec();
    buf.extend(std::iter::repeat_n(0u8, 14));
    let slot = build_tpm2_fido2_with_cred_id(buf);
    assert!(slot.tpm2_fido2_sealed_blob().is_none());
}

#[test]
fn tpm2_fido2_subformat_wrong_kind_returns_none() {
    // Sub-format accessor only valid for Tpm2Fido2 / HybridPqKemTpm2Fido2 /
    // HybridPqKem1024Tpm2Fido2. Calling on a Passphrase slot must return
    // None without panic.
    let mvk = MasterVolumeKey::from_bytes([0; 32]);
    let pp_slot = Keyslot::new_passphrase(
        CipherSuite::Aes256GcmSiv,
        &mvk,
        b"x",
        TEST_KDF,
        &HEADER_SALT,
    )
    .unwrap();
    assert!(pp_slot.tpm2_fido2_sealed_blob().is_none());
    assert!(pp_slot.tpm2_fido2_cred_id().is_none());
}

#[test]
fn hybrid_pq_kem_tpm2_kind_byte_swap_to_1024_breaks_aad() {
    // Same KEK derivation (derive_hybrid_tpm2_kek), so without AAD
    // kind coverage this swap would silently succeed and mis-
    // advertise the slot's PQ strength.
    let mvk = MasterVolumeKey::from_bytes([0x99; 32]);
    let slot = Keyslot::new_hybrid_pq_tpm2(
        CipherSuite::Aes256GcmSiv,
        &mvk,
        &KEK_FROM_TPM,
        &PQ_SHARED,
        &fake_sealed_blob(),
        &HEADER_SALT,
    )
    .unwrap();
    let mut bytes = slot.to_bytes();
    bytes[0] = SlotKind::HybridPqKem1024Tpm2 as u8;
    if let Ok(parsed) = Keyslot::from_bytes(&bytes) {
        let r = parsed.unlock_hybrid_pq_tpm2(
            CipherSuite::Aes256GcmSiv,
            &KEK_FROM_TPM,
            &PQ_SHARED,
            &HEADER_SALT,
        );
        assert!(
            r.is_err(),
            "768 -> 1024 hybrid-PQ-TPM kind swap accepted; AAD does NOT cover kind"
        );
    }
}
