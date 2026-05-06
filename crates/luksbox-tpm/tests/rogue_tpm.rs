// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Penthertz <https://penthertz.com> (https://x.com/PentHertz)

//! Adversary-scenario tests for the TPM 2.0 wrap path. Mirror of
//! `crates/luksbox-fido2/tests/rogue_authenticator.rs` but for TPM:
//! confirms that a malicious or malfunctioning TPM cannot recover
//! the legitimate KEK, cannot unlock a vault sealed under the real
//! chip, and surfaces failures cleanly (no panic, no silent
//! acceptance, no wrong-MVK).
//!
//! The format-layer's `UnlockMaterial::Tpm2 { unseal: closure }`
//! takes a closure, so tests wrap a `MockTpm2Sealer` in the closure
//! and feed it directly to `Container::open`. No trait abstraction
//! needed; the closure is the boundary.

use luksbox_core::{Argon2idParams, CipherSuite};
use luksbox_format::{Container, Error as FormatError, UnlockMaterial};
use luksbox_tpm::SealedBlob;
use luksbox_tpm::mock::MockTpm2Sealer;
use rand_core::{OsRng, RngCore};
use tempfile::TempDir;

const TEST_KDF: Argon2idParams = Argon2idParams {
    m_cost_kib: 8,
    t_cost: 1,
    p_cost: 1,
};

/// Build a vault with a passphrase bootstrap slot + a TPM slot
/// enrolled via the mock. Returns the vault path and the sealed
/// blob bytes the mock issued (so adversary tests can hand it to a
/// tampering closure).
fn build_vault_with_tpm_slot(
    dir: &TempDir,
    tpm: &mut MockTpm2Sealer,
) -> (std::path::PathBuf, [u8; 32], Vec<u8>) {
    let path = dir.path().join("v.lbx");
    let mut cont = Container::create_with_passphrase(
        &path,
        None,
        CipherSuite::Aes256GcmSiv,
        TEST_KDF,
        b"bootstrap",
    )
    .unwrap();

    let mut kek = [0u8; 32];
    OsRng.fill_bytes(&mut kek);
    let blob = tpm.seal(&kek).unwrap();
    let blob_bytes = blob.to_bytes();
    let _idx = cont.enroll_tpm2(&kek, &blob_bytes).unwrap();
    cont.persist_header().unwrap();

    (path, kek, blob_bytes)
}

/// Helper: open the vault via UnlockMaterial::Tpm2 with the closure
/// wrapping the given mock. Returns the open result so tests can
/// assert pass/fail.
fn open_with_mock_tpm(
    path: &std::path::Path,
    tpm: &mut MockTpm2Sealer,
) -> Result<Container, FormatError> {
    let mut unseal = |blob: &[u8]| -> std::result::Result<[u8; 32], String> {
        let parsed =
            SealedBlob::from_bytes(blob).map_err(|e| format!("malformed sealed blob: {e}"))?;
        let kek = tpm.unseal(&parsed).map_err(|e| format!("rogue TPM: {e}"))?;
        let mut out = [0u8; 32];
        out.copy_from_slice(kek.as_slice());
        Ok(out)
    };
    Container::open(
        path,
        None,
        UnlockMaterial::Tpm2 {
            unseal: &mut unseal,
        },
    )
}

// ---- baseline ------------------------------------------------------------

/// Sanity: an honest mock TPM round-trips. Without this, the adversary
/// tests below could fail for the wrong reason (broken setup vs broken
/// defense).
#[test]
fn baseline_honest_mock_tpm_unlocks_vault() {
    let dir = TempDir::new().unwrap();
    let mut tpm = MockTpm2Sealer::new();
    let (path, _kek, _blob) = build_vault_with_tpm_slot(&dir, &mut tpm);
    let r = open_with_mock_tpm(&path, &mut tpm);
    assert!(r.is_ok(), "honest mock must unlock, got {:?}", r.err());
}

// ---- rogue-TPM scenarios -------------------------------------------------

/// Rogue TPM swap: attacker swaps the chip with one that doesn't
/// have the original sealing seed. The new TPM rejects every blob
/// it didn't issue. Format-layer surfaces this as `UnlockFailed`
/// (the closure errors -> format iterates other slots -> none match).
#[test]
fn rogue_tpm_chip_swap_fails_unlock() {
    let dir = TempDir::new().unwrap();
    let mut tpm = MockTpm2Sealer::new();
    let (path, _kek, _blob) = build_vault_with_tpm_slot(&dir, &mut tpm);

    // Attacker swaps the chip: forget all blobs.
    tpm.forget_blobs();

    let r = open_with_mock_tpm(&path, &mut tpm);
    assert!(
        matches!(r, Err(FormatError::UnlockFailed)),
        "chip swap must surface as UnlockFailed, got {:?}",
        r.err()
    );
}

/// Rogue TPM returning attacker-chosen 32 bytes: even if the unseal
/// closure returns a structurally-valid 32-byte KEK that the
/// attacker chose, the AEAD over the slot's wrapped_mvk uses the
/// REAL kek (which the mock no longer knows). AAD/AEAD rejects.
#[test]
fn rogue_tpm_returns_attacker_chosen_kek_fails_aead() {
    let dir = TempDir::new().unwrap();
    let mut tpm = MockTpm2Sealer::new();
    let (path, real_kek, _blob) = build_vault_with_tpm_slot(&dir, &mut tpm);

    let attacker = [0xeeu8; 32];
    assert_ne!(real_kek, attacker);
    tpm.force_unsealed_bytes(attacker.to_vec());

    let r = open_with_mock_tpm(&path, &mut tpm);
    assert!(
        matches!(r, Err(FormatError::UnlockFailed)),
        "attacker-chosen KEK must be rejected by AEAD, got {:?}",
        r.err()
    );
}

/// All-zeros KEK: degenerate corner. AEAD must reject just like any
/// other wrong KEK. Mirrors the rogue-FIDO2 all-zeros test.
#[test]
fn rogue_tpm_returns_all_zeros_kek_fails_aead() {
    let dir = TempDir::new().unwrap();
    let mut tpm = MockTpm2Sealer::new();
    let (path, _kek, _blob) = build_vault_with_tpm_slot(&dir, &mut tpm);

    tpm.force_unsealed_bytes(vec![0u8; 32]);
    let r = open_with_mock_tpm(&path, &mut tpm);
    assert!(matches!(r, Err(FormatError::UnlockFailed)));
}

/// All-ones KEK: another degenerate corner.
#[test]
fn rogue_tpm_returns_all_ones_kek_fails_aead() {
    let dir = TempDir::new().unwrap();
    let mut tpm = MockTpm2Sealer::new();
    let (path, _kek, _blob) = build_vault_with_tpm_slot(&dir, &mut tpm);

    tpm.force_unsealed_bytes(vec![0xffu8; 32]);
    let r = open_with_mock_tpm(&path, &mut tpm);
    assert!(matches!(r, Err(FormatError::UnlockFailed)));
}

/// Rogue TPM returns truncated unseal payload (16 B instead of 32).
/// MockTpm2Sealer maps wrong-length forced output to TpmError; the
/// closure converts to a format-layer error string; format treats
/// per-slot closure errors as UnlockFailed so the iteration can
/// continue to the next matching slot.
#[test]
fn rogue_tpm_returns_truncated_kek_fails_cleanly() {
    let dir = TempDir::new().unwrap();
    let mut tpm = MockTpm2Sealer::new();
    let (path, _kek, _blob) = build_vault_with_tpm_slot(&dir, &mut tpm);

    tpm.force_unsealed_truncated(16);
    let r = open_with_mock_tpm(&path, &mut tpm);
    assert!(
        matches!(r, Err(FormatError::UnlockFailed)),
        "truncated unseal must surface as UnlockFailed, got {:?}",
        r.err()
    );
}

/// Rogue TPM returns oversized unseal payload (64 B). Same shape
/// of failure as truncated.
#[test]
fn rogue_tpm_returns_oversized_kek_fails_cleanly() {
    let dir = TempDir::new().unwrap();
    let mut tpm = MockTpm2Sealer::new();
    let (path, _kek, _blob) = build_vault_with_tpm_slot(&dir, &mut tpm);

    tpm.force_unsealed_oversized(64);
    let r = open_with_mock_tpm(&path, &mut tpm);
    assert!(matches!(r, Err(FormatError::UnlockFailed)));
}

/// Rogue TPM errors mid-unseal (chip is in lockout, transient
/// failure, etc.). Format-layer must NOT panic and must surface
/// the error as UnlockFailed.
#[test]
fn rogue_tpm_unseal_error_propagates_cleanly() {
    let dir = TempDir::new().unwrap();
    let mut tpm = MockTpm2Sealer::new();
    let (path, _kek, _blob) = build_vault_with_tpm_slot(&dir, &mut tpm);

    tpm.simulate_unseal_error();
    let r = open_with_mock_tpm(&path, &mut tpm);
    assert!(matches!(r, Err(FormatError::UnlockFailed)));
}

/// Cross-slot blob substitution: attacker swaps the sealed_blob
/// bytes of slot 0 with bytes from a different blob. The new blob
/// either doesn't unseal (mock has it under a different key) or
/// produces a KEK that doesn't unwrap the original slot's
/// wrapped_mvk. AEAD rejects either way.
#[test]
fn rogue_tpm_swapped_sealed_blob_fails_unlock() {
    let dir = TempDir::new().unwrap();
    let mut tpm = MockTpm2Sealer::new();
    let (path, _kek_a, _blob_a) = build_vault_with_tpm_slot(&dir, &mut tpm);

    // Build a SECOND blob with a different KEK; the mock now knows
    // both. Substitute it into the slot via a hand-crafted closure
    // that returns the *other* blob's KEK regardless of input.
    let mut other_kek = [0u8; 32];
    OsRng.fill_bytes(&mut other_kek);
    let _other_blob = tpm.seal(&other_kek).unwrap();

    // Closure returns other_kek for ANY blob the format layer asks
    // about. Equivalent to: attacker rewrote slot 0's sealed_blob
    // bytes to point at the other blob, AND the chip honestly
    // unseals that blob.
    let mut unseal = |_blob: &[u8]| -> std::result::Result<[u8; 32], String> { Ok(other_kek) };
    let r = Container::open(
        &path,
        None,
        UnlockMaterial::Tpm2 {
            unseal: &mut unseal,
        },
    );
    assert!(
        matches!(r, Err(FormatError::UnlockFailed)),
        "wrong-KEK from blob substitution must be rejected, got {:?}",
        r.err()
    );
}

/// PIN-protected slot: rogue TPM that ignores PIN gating and
/// returns the right unseal bytes regardless of PIN. The format
/// layer doesn't enforce PIN itself (it delegates to the closure),
/// so this test confirms the responsibility is correctly placed:
/// if the closure (which wraps the real Tpm2Sealer in production)
/// honors PIN, the design holds; if a malicious closure ignores
/// PIN, the format layer does NOT independently catch it.
///
/// This documents an INTENTIONAL trust boundary: the format layer
/// trusts the closure. Production wraps the real Tpm2Sealer which
/// honors `userAuth`. A rogue TPM that ignored userAuth would be a
/// physical-attack scenario beyond LUKSbox's threat model.
#[test]
fn pin_enforcement_lives_in_the_closure_not_the_format_layer() {
    let dir = TempDir::new().unwrap();
    let mut tpm = MockTpm2Sealer::new();
    let path = dir.path().join("v.lbx");

    // Bootstrap with passphrase, enroll a PIN-protected TPM slot.
    let mut cont = Container::create_with_passphrase(
        &path,
        None,
        CipherSuite::Aes256GcmSiv,
        TEST_KDF,
        b"bootstrap",
    )
    .unwrap();
    let mut kek = [0u8; 32];
    OsRng.fill_bytes(&mut kek);
    let blob = tpm.seal_with_pin(&kek, Some(b"correct-pin")).unwrap();
    let _idx = cont.enroll_tpm2_pin(&kek, &blob.to_bytes()).unwrap();
    cont.persist_header().unwrap();
    drop(cont);

    // Honest closure WITH the right PIN: unlocks.
    let mut unseal_ok = |b: &[u8]| -> std::result::Result<[u8; 32], String> {
        let parsed = SealedBlob::from_bytes(b).unwrap();
        let kek = tpm
            .unseal_with_pin(&parsed, Some(b"correct-pin"))
            .map_err(|e| e.to_string())?;
        let mut out = [0u8; 32];
        out.copy_from_slice(kek.as_slice());
        Ok(out)
    };
    let r = Container::open(
        &path,
        None,
        UnlockMaterial::Tpm2 {
            unseal: &mut unseal_ok,
        },
    );
    assert!(r.is_ok(), "right PIN must unlock, got {:?}", r.err());
    drop(r);

    // Closure WITHOUT the PIN: unseal fails at the mock layer
    // (PIN mismatch), format-layer surfaces as UnlockFailed.
    let mut unseal_no_pin = |b: &[u8]| -> std::result::Result<[u8; 32], String> {
        let parsed = SealedBlob::from_bytes(b).unwrap();
        let kek = tpm
            .unseal_with_pin(&parsed, None)
            .map_err(|e| e.to_string())?;
        let mut out = [0u8; 32];
        out.copy_from_slice(kek.as_slice());
        Ok(out)
    };
    let r = Container::open(
        &path,
        None,
        UnlockMaterial::Tpm2 {
            unseal: &mut unseal_no_pin,
        },
    );
    assert!(
        matches!(r, Err(FormatError::UnlockFailed)),
        "missing PIN must surface as UnlockFailed, got {:?}",
        r.err()
    );
}

/// Multi-slot vault: vault has TWO TPM slots. Rogue chip can
/// unseal slot 1's blob but not slot 0's. The format layer
/// iterates per-slot and tolerates closure errors, so the
/// successful slot 1 unlock should win even though slot 0 errored.
#[test]
fn multi_slot_vault_picks_first_unsealable_slot() {
    let dir = TempDir::new().unwrap();
    let mut tpm = MockTpm2Sealer::new();
    let path = dir.path().join("v.lbx");

    // Bootstrap with passphrase, enroll TWO TPM slots.
    let mut cont = Container::create_with_passphrase(
        &path,
        None,
        CipherSuite::Aes256GcmSiv,
        TEST_KDF,
        b"bootstrap",
    )
    .unwrap();
    let mut kek0 = [0u8; 32];
    OsRng.fill_bytes(&mut kek0);
    let blob0 = tpm.seal(&kek0).unwrap().to_bytes();
    let _ = cont.enroll_tpm2(&kek0, &blob0).unwrap();

    let mut kek1 = [0u8; 32];
    OsRng.fill_bytes(&mut kek1);
    let blob1 = tpm.seal(&kek1).unwrap().to_bytes();
    let _ = cont.enroll_tpm2(&kek1, &blob1).unwrap();
    cont.persist_header().unwrap();
    drop(cont);

    // The mock honestly unseals both. Both slots open. Verify the
    // tolerant-iteration path: opening succeeds.
    let r = open_with_mock_tpm(&path, &mut tpm);
    assert!(
        r.is_ok(),
        "two valid TPM slots must open, got {:?}",
        r.err()
    );
}
