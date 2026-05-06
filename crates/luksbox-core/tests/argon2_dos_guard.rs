// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Penthertz <https://penthertz.com> (https://x.com/PentHertz)

//! Regression tests for the Argon2id-DoS-via-hostile-on-disk-params
//! attack. An attacker who has write access to the .lbx file (but NOT
//! the passphrase or the YubiKey) could otherwise set m_cost_kib =
//! u32::MAX in a keyslot's KDF params; on the next unlock attempt the
//! argon2 crate calls `hash_password_into` which tries to allocate
//! about 4 TiB of RAM -> instant OOM. Same vector applies to `.kyber` seed
//! files (covered in luksbox-pq/tests/argon2_dos_guard.rs).
//!
//! Fix: `Keyslot::from_bytes` rejects hostile params with
//! `Error::InvalidField` BEFORE any unlock attempt.

use luksbox_core::{Argon2idParams, Keyslot, MasterVolumeKey, SLOT_SIZE, SlotKind};

const HEADER_SALT: [u8; 32] = [0x42; 32];

fn build_passphrase_slot_with_params(params: Argon2idParams) -> [u8; SLOT_SIZE] {
    let suite = luksbox_core::CipherSuite::Aes256Gcm;
    let mvk = MasterVolumeKey::from_bytes([0x55; 32]);
    let slot =
        Keyslot::new_passphrase(suite, &mvk, b"hunter2", params, &HEADER_SALT).expect("slot build");
    slot.to_bytes()
}

#[test]
fn rejects_hostile_m_cost_in_passphrase_slot() {
    // Build a real slot with safe params, then mutate the m_cost_kib
    // bytes in the on-disk image to u32::MAX. from_bytes must reject
    // before any unlock attempt could pass the value to argon2.
    let mut bytes = build_passphrase_slot_with_params(Argon2idParams {
        m_cost_kib: 8,
        t_cost: 1,
        p_cost: 1,
    });
    // OFF_M_COST = 20 (per keyslot.rs constants).
    bytes[20..24].copy_from_slice(&u32::MAX.to_le_bytes());
    let err = Keyslot::from_bytes(&bytes)
        .err()
        .expect("must reject hostile m_cost");
    let msg = format!("{err:?}");
    assert!(
        msg.contains("InvalidField") || msg.contains("Invalid"),
        "expected InvalidField, got {msg}"
    );
}

#[test]
fn rejects_hostile_t_cost_in_passphrase_slot() {
    let mut bytes = build_passphrase_slot_with_params(Argon2idParams {
        m_cost_kib: 8,
        t_cost: 1,
        p_cost: 1,
    });
    // OFF_T_COST = 24.
    bytes[24..28].copy_from_slice(&u32::MAX.to_le_bytes());
    assert!(Keyslot::from_bytes(&bytes).is_err());
}

#[test]
fn rejects_hostile_p_cost_in_passphrase_slot() {
    let mut bytes = build_passphrase_slot_with_params(Argon2idParams {
        m_cost_kib: 8,
        t_cost: 1,
        p_cost: 1,
    });
    // OFF_P_COST = 28.
    bytes[28..32].copy_from_slice(&u32::MAX.to_le_bytes());
    assert!(Keyslot::from_bytes(&bytes).is_err());
}

#[test]
fn rejects_zero_m_cost_for_passphrase_kind() {
    // A passphrase slot with m_cost_kib = 0 is also rejected, argon2
    // would error anyway, but failing fast at the parser keeps the
    // failure surface small and consistent.
    let mut bytes = build_passphrase_slot_with_params(Argon2idParams {
        m_cost_kib: 8,
        t_cost: 1,
        p_cost: 1,
    });
    bytes[20..24].copy_from_slice(&0u32.to_le_bytes());
    assert!(Keyslot::from_bytes(&bytes).is_err());
}

#[test]
fn accepts_sensible_argon2_params_at_top_of_safe_envelope() {
    // The PARSER must accept anything within the safe envelope. We
    // can't actually call `new_passphrase` with 4 GiB / 64 / 16,
    // that would run Argon2id with those params and allocate 4 GiB +
    // burn 64 iterations × 16 lanes for hours. Instead, build a
    // small slot with tiny params, then mutate the on-disk bytes to
    // the maximum safe values and verify `from_bytes` accepts them.
    let mut bytes = build_passphrase_slot_with_params(Argon2idParams {
        m_cost_kib: 8,
        t_cost: 1,
        p_cost: 1,
    });
    bytes[20..24].copy_from_slice(&Argon2idParams::SAFE_M_COST_KIB_MAX.to_le_bytes());
    bytes[24..28].copy_from_slice(&Argon2idParams::SAFE_T_COST_MAX.to_le_bytes());
    bytes[28..32].copy_from_slice(&Argon2idParams::SAFE_P_COST_MAX.to_le_bytes());
    let parsed =
        Keyslot::from_bytes(&bytes).expect("max safe params at parser layer must be accepted");
    assert_eq!(parsed.kind, SlotKind::Passphrase);
    assert_eq!(
        parsed.kdf_params.m_cost_kib,
        Argon2idParams::SAFE_M_COST_KIB_MAX
    );
    assert_eq!(parsed.kdf_params.t_cost, Argon2idParams::SAFE_T_COST_MAX);
    assert_eq!(parsed.kdf_params.p_cost, Argon2idParams::SAFE_P_COST_MAX);
}

#[test]
fn rejects_one_above_safe_envelope() {
    let mut bytes = build_passphrase_slot_with_params(Argon2idParams {
        m_cost_kib: 8,
        t_cost: 1,
        p_cost: 1,
    });
    bytes[20..24].copy_from_slice(&(Argon2idParams::SAFE_M_COST_KIB_MAX + 1).to_le_bytes());
    assert!(
        Keyslot::from_bytes(&bytes).is_err(),
        "value just above safe envelope must be rejected"
    );
}

#[test]
fn empty_slot_passes_with_zero_params() {
    // Empty slots store zero params for byte-shape indistinguishability.
    // The kind == Empty branch returns before reaching the param check,
    // so this must continue to parse cleanly.
    let bytes = [0u8; SLOT_SIZE];
    let slot = Keyslot::from_bytes(&bytes).expect("empty slot must parse");
    assert_eq!(slot.kind, SlotKind::Empty);
}

#[test]
fn fido2_direct_slot_passes_with_zero_params() {
    // Fido2DerivedMvk slots also store zero KDF params (no Argon2id is
    // run for direct mode, MVK = HKDF(hmac_secret)). The check must
    // skip them.
    let cred_id = b"yk-cred-id-bytes";
    let hmac_salt = [0xAAu8; 32];
    let slot = Keyslot::new_fido2_derived_mvk(cred_id, hmac_salt).unwrap();
    let bytes = slot.to_bytes();
    let restored = Keyslot::from_bytes(&bytes).unwrap();
    assert_eq!(restored.kind, SlotKind::Fido2DerivedMvk);
    assert_eq!(restored.kdf_params.m_cost_kib, 0);
}

#[test]
fn safe_for_disk_predicate_matches_envelope() {
    // Spot-check the predicate.
    assert!(Argon2idParams::INTERACTIVE.is_sane_for_disk());
    assert!(Argon2idParams::MODERATE.is_sane_for_disk());
    assert!(Argon2idParams::SENSITIVE.is_sane_for_disk());
    assert!(
        !Argon2idParams {
            m_cost_kib: u32::MAX,
            t_cost: 3,
            p_cost: 4
        }
        .is_sane_for_disk()
    );
    assert!(
        !Argon2idParams {
            m_cost_kib: 256 * 1024,
            t_cost: u32::MAX,
            p_cost: 4
        }
        .is_sane_for_disk()
    );
    assert!(
        !Argon2idParams {
            m_cost_kib: 256 * 1024,
            t_cost: 3,
            p_cost: u32::MAX
        }
        .is_sane_for_disk()
    );
    assert!(
        !Argon2idParams {
            m_cost_kib: 0,
            t_cost: 0,
            p_cost: 0
        }
        .is_sane_for_disk()
    );
}
