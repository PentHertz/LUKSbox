// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Penthertz <https://penthertz.com> (https://x.com/PentHertz)

//! Deniable header v1 - opt-in container header where every on-disk
//! byte is computationally indistinguishable from uniform random output.
//!
//! See `docs/DENIABLE_HEADER.md` for the full design specification
//! including threat model, format layout, and the five normative
//! security invariants. This module implements the format primitives;
//! higher-level container ops (init/open/add-user/remove-user) live in
//! `luksbox-format::container`.
//!
//! ## Security invariants enforced here
//!
//! 1. **AAD binding** - every slot AEAD computation includes
//!    `b"luksbox-deniable-v1" || per_vault_salt || slot_idx`, preventing
//!    slot-shuffling attacks across vaults or across slots.
//! 2. **Constant-time trial decryption** - `trial_decrypt` always
//!    iterates all 8 slots regardless of which (if any) matches; the
//!    successful candidate is selected via `subtle::ConditionallySelectable`.
//! 3. **Empty slots from `OsRng`** - `fill_random_slot` and the unwrap
//!    rejection path both use the OS RNG so empty slots are
//!    indistinguishable from real AEAD ciphertext under any
//!    distinguisher.
//! 5. **Per-credential domain separation** - every credential KEK
//!    derivation uses a distinct HKDF `info` label exported from
//!    `hkdf_info` (invariant #4 about rotation re-randomizing all
//!    slots lives in the container-level rotation code).

use hkdf::Hkdf;
use rand_core::{OsRng, RngCore};
use sha2::Sha256;
use subtle::{Choice, ConditionallySelectable};
use zeroize::{Zeroize, Zeroizing};

use crate::aead::{self, CipherSuite};
use crate::error::Error;
use crate::kdf::{Argon2idParams, derive_kek};
use crate::key::{KEY_LEN, KeyEncryptionKey, MasterVolumeKey};

/// Total deniable header size. Identical to the standard 8 KiB header
/// so deniable mode introduces no new file-size tell.
pub const DENIABLE_HEADER_SIZE: usize = 8192;

/// Number of slots in a deniable header. Matches `MAX_KEYSLOTS` from
/// the standard format for shared muscle memory. Bumping is a format
/// version bump baked into the binary; the slot count is NOT on disk.
pub const DENIABLE_SLOT_COUNT: usize = 8;

/// Per-slot size (bytes). 60 bytes hold the AEAD nonce + wrapped MVK
/// + tag (12 + 32 + 16); the remaining 452 bytes are random padding so
/// every slot has the same wire layout regardless of how much per-slot
/// metadata a future format might want.
pub const DENIABLE_SLOT_SIZE: usize = 512;

/// Per-vault salt size at offset 0 of the deniable header.
pub const DENIABLE_SALT_SIZE: usize = 32;

/// Offset of the slot table in the header.
pub const DENIABLE_SLOT_TABLE_OFFSET: usize = DENIABLE_SALT_SIZE;

/// Offset of the encrypted inner header in the deniable header.
pub const DENIABLE_INNER_OFFSET: usize =
    DENIABLE_SLOT_TABLE_OFFSET + DENIABLE_SLOT_COUNT * DENIABLE_SLOT_SIZE;

/// Size of the encrypted inner header (bytes).
pub const DENIABLE_INNER_SIZE: usize = DENIABLE_HEADER_SIZE - DENIABLE_INNER_OFFSET;

/// Per-slot AEAD nonce length (bytes).
pub const SLOT_NONCE_LEN: usize = 12;

/// Per-slot AEAD tag length (bytes).
pub const SLOT_TAG_LEN: usize = 16;

/// Per-slot wrapped-MVK ciphertext length (32 bytes of MVK + 16 tag).
pub const SLOT_CT_AND_TAG_LEN: usize = KEY_LEN + SLOT_TAG_LEN;

// Compile-time layout invariants. If any of these fail the format is
// definitionally broken; a build that successfully links has them by
// construction.
const _: () =
    assert!(DENIABLE_SALT_SIZE + DENIABLE_SLOT_COUNT * DENIABLE_SLOT_SIZE < DENIABLE_HEADER_SIZE);
const _: () = assert!(DENIABLE_INNER_OFFSET == 32 + 8 * 512);
const _: () = assert!(DENIABLE_INNER_SIZE == 4064);
const _: () = assert!(SLOT_NONCE_LEN + SLOT_CT_AND_TAG_LEN < DENIABLE_SLOT_SIZE);

/// AAD prefix bound into every slot AEAD computation. A bump implies
/// a format version bump that the binary must learn.
pub const DENIABLE_AAD_PREFIX: &[u8] = b"luksbox-deniable-v1";

/// HKDF info labels for per-credential KEK derivation. Each credential
/// type uses a distinct label so a bug in one derivation cannot
/// contaminate another (security invariant #5). The `KEK_*` labels
/// below correspond 1:1 to `DeniableCredential` variants.
pub mod hkdf_info {
    pub const PASSPHRASE: &[u8] = b"luksbox-deniable-v1/passphrase";
    pub const FIDO2_SALT: &[u8] = b"luksbox-deniable-v1/fido2-salt";
    pub const FIDO2_KEK: &[u8] = b"luksbox-deniable-v1/fido2";
    pub const TPM_FIDO2_KEK: &[u8] = b"luksbox-deniable-v1/tpm-fido2";
    pub const PQ_CLASSICAL: &[u8] = b"luksbox-deniable-v1/pq-classical";
    pub const PQ_HYBRID_KEK: &[u8] = b"luksbox-deniable-v1/pq-hybrid";
    pub const INNER_HEADER: &[u8] = b"luksbox-deniable-v1/inner-header";

    // New (v1.1): one label per DeniableCredential variant. Each one
    // uniquely identifies the credential combination so an adversary
    // who guesses the wrong combo derives a KEK in an independent
    // space.
    pub const KEK_PASSPHRASE: &[u8] = b"luksbox-deniable-v1/kek/passphrase";
    pub const KEK_FIDO2: &[u8] = b"luksbox-deniable-v1/kek/fido2";
    pub const KEK_FIDO2_PASSPHRASE: &[u8] = b"luksbox-deniable-v1/kek/fido2+passphrase";
    pub const KEK_TPM: &[u8] = b"luksbox-deniable-v1/kek/tpm";
    pub const KEK_TPM_PASSPHRASE: &[u8] = b"luksbox-deniable-v1/kek/tpm+passphrase";
    pub const KEK_TPM_FIDO2: &[u8] = b"luksbox-deniable-v1/kek/tpm+fido2";
    pub const KEK_PQ_PASSPHRASE: &[u8] = b"luksbox-deniable-v1/kek/pq+passphrase";
    pub const KEK_PQ_FIDO2: &[u8] = b"luksbox-deniable-v1/kek/pq+fido2";
    pub const KEK_PQ_TPM: &[u8] = b"luksbox-deniable-v1/kek/pq+tpm";
    pub const KEK_PQ_TPM_FIDO2: &[u8] = b"luksbox-deniable-v1/kek/pq+tpm+fido2";
}

/// Build the AAD bound into a slot's AEAD computation:
/// `b"luksbox-deniable-v1" || per_vault_salt || (slot_idx as u8)`.
///
/// The returned `Vec` is small (52 bytes) and not sensitive; no
/// `Zeroizing` needed.
pub fn slot_aad(per_vault_salt: &[u8; DENIABLE_SALT_SIZE], slot_idx: usize) -> Vec<u8> {
    assert!(
        slot_idx < DENIABLE_SLOT_COUNT,
        "slot_idx {} out of range (DENIABLE_SLOT_COUNT={})",
        slot_idx,
        DENIABLE_SLOT_COUNT,
    );
    let mut aad = Vec::with_capacity(DENIABLE_AAD_PREFIX.len() + DENIABLE_SALT_SIZE + 1);
    aad.extend_from_slice(DENIABLE_AAD_PREFIX);
    aad.extend_from_slice(per_vault_salt);
    aad.push(slot_idx as u8);
    aad
}

/// Fill a buffer with cryptographically random bytes from the OS RNG.
/// Used for empty slots, per-vault salts, and AEAD nonces. Failure
/// surfaces as `Error::OsRng`; callers MUST treat this as fatal (do
/// not fall back to a non-cryptographic RNG).
pub fn fill_random(buf: &mut [u8]) -> Result<(), Error> {
    OsRng
        .try_fill_bytes(buf)
        .map_err(|e| Error::OsRng(e.to_string()))
}

/// Wrap an MVK into a single slot using the given KEK.
///
/// The slot is first filled with random padding (so all 512 bytes are
/// indistinguishable from real AEAD output), then the first 60 bytes
/// are overwritten with `nonce || ciphertext || tag`. Invariant #3
/// (empty == real ciphertext distribution) holds because both arrive
/// at the slot via `OsRng`.
pub fn wrap_slot(
    slot: &mut [u8; DENIABLE_SLOT_SIZE],
    kek: &KeyEncryptionKey,
    mvk: &MasterVolumeKey,
    suite: CipherSuite,
    per_vault_salt: &[u8; DENIABLE_SALT_SIZE],
    slot_idx: usize,
) -> Result<(), Error> {
    // Step 1: fill the whole slot with random padding. Done first so
    // the padding tail of an occupied slot is the same distribution
    // as an empty slot's contents (invariant #3).
    fill_random(slot)?;

    // Step 2: generate a fresh AEAD nonce. Even for AES-GCM-SIV (which
    // is nonce-misuse-resistant) we keep nonces unique; for the other
    // ciphers it is required for security.
    let mut nonce = [0u8; SLOT_NONCE_LEN];
    fill_random(&mut nonce)?;

    // Step 3: AEAD-encrypt the MVK with the slot-bound AAD. The
    // ciphertext is exactly 48 bytes (32-byte MVK + 16-byte tag).
    let aad = slot_aad(per_vault_salt, slot_idx);
    let ct = aead::seal(suite, kek.as_bytes(), &nonce, &aad, mvk.as_bytes())?;
    debug_assert_eq!(ct.len(), SLOT_CT_AND_TAG_LEN);

    // Step 4: overwrite the first 60 bytes of the slot (random
    // padding tail remains as-is). On any error before this point the
    // slot keeps its all-random contents, so no partial state leaks.
    slot[..SLOT_NONCE_LEN].copy_from_slice(&nonce);
    slot[SLOT_NONCE_LEN..SLOT_NONCE_LEN + ct.len()].copy_from_slice(&ct);
    Ok(())
}

/// Try to unwrap a single slot. Returns `Some(MVK)` if the AEAD tag
/// verifies (the KEK is correct for this slot), `None` otherwise.
///
/// NOT constant-time across slot positions on its own. The
/// constant-time loop lives in `trial_decrypt` and uses
/// `ConditionallySelectable` to select between Some/None results
/// without branching on the AEAD verdict. Use this raw function ONLY
/// when you already know which slot to attempt (e.g., after MVK-level
/// re-encryption identifies the target).
pub fn try_unwrap_slot(
    slot: &[u8; DENIABLE_SLOT_SIZE],
    kek: &KeyEncryptionKey,
    suite: CipherSuite,
    per_vault_salt: &[u8; DENIABLE_SALT_SIZE],
    slot_idx: usize,
) -> Option<MasterVolumeKey> {
    // The slice indices are statically bounded by the array length
    // (512 > 60), so these never panic at runtime.
    let nonce: [u8; SLOT_NONCE_LEN] = slot[..SLOT_NONCE_LEN].try_into().ok()?;
    let ct = &slot[SLOT_NONCE_LEN..SLOT_NONCE_LEN + SLOT_CT_AND_TAG_LEN];
    let aad = slot_aad(per_vault_salt, slot_idx);

    let pt = match aead::open(suite, kek.as_bytes(), &nonce, &aad, ct) {
        Ok(pt) => Zeroizing::new(pt),
        Err(_) => return None,
    };
    if pt.len() != KEY_LEN {
        return None;
    }
    let mut bytes = [0u8; KEY_LEN];
    bytes.copy_from_slice(&pt);
    Some(MasterVolumeKey::from_bytes(bytes))
}

/// Constant-time trial decryption across every slot.
///
/// ALWAYS iterates `DENIABLE_SLOT_COUNT` slots and runs one AEAD
/// attempt per slot, regardless of which (if any) matches. The
/// successful candidate is selected via `subtle::ConditionallySelectable`
/// so wall-clock timing reveals "an attempt happened" but not "slot N
/// matched."
///
/// Returns `Some(MVK)` if any slot decrypted, `None` if all failed.
/// The MVK is constructed only from constant-time-selected bytes; an
/// attacker who can observe the byte-level memory state of `mvk_bytes`
/// during the loop learns nothing about which slot won.
pub fn trial_decrypt(
    slots: &[[u8; DENIABLE_SLOT_SIZE]; DENIABLE_SLOT_COUNT],
    kek: &KeyEncryptionKey,
    suite: CipherSuite,
    per_vault_salt: &[u8; DENIABLE_SALT_SIZE],
) -> Option<MasterVolumeKey> {
    trial_decrypt_with_idx(slots, kek, suite, per_vault_salt).map(|(_, mvk)| mvk)
}

/// Same constant-time trial decryption as `trial_decrypt`, but also
/// returns the slot index that matched. The Container layer needs
/// the index so the GUI / CLI can show "slot N is your unlock slot"
/// and refuse to overwrite it when enrolling additional credentials.
///
/// Side-channel posture: same as `trial_decrypt`. All 8 slot
/// indices are visited; the matching index is also selected via
/// `ConditionallySelectable`. An adversary observing wall-clock
/// timing learns "an attempt happened" and nothing more.
pub fn trial_decrypt_with_idx(
    slots: &[[u8; DENIABLE_SLOT_SIZE]; DENIABLE_SLOT_COUNT],
    kek: &KeyEncryptionKey,
    suite: CipherSuite,
    per_vault_salt: &[u8; DENIABLE_SALT_SIZE],
) -> Option<(usize, MasterVolumeKey)> {
    let mut found = Choice::from(0u8);
    let mut mvk_bytes = Zeroizing::new([0u8; KEY_LEN]);
    let mut found_idx_u8: u8 = 0;

    for slot_idx in 0..DENIABLE_SLOT_COUNT {
        let attempt = try_unwrap_slot(&slots[slot_idx], kek, suite, per_vault_salt, slot_idx);
        let valid = Choice::from(attempt.is_some() as u8);

        let cand_bytes: [u8; KEY_LEN] = attempt
            .as_ref()
            .map(|m| *m.as_bytes())
            .unwrap_or([0u8; KEY_LEN]);

        for i in 0..KEY_LEN {
            mvk_bytes[i] = u8::conditional_select(&mvk_bytes[i], &cand_bytes[i], valid);
        }
        // Constant-time select for the index too. We rely on
        // DENIABLE_SLOT_COUNT <= 255 (currently 8) so a u8 holds
        // every possible slot index; the const_assert below guards
        // that invariant.
        found_idx_u8 = u8::conditional_select(&found_idx_u8, &(slot_idx as u8), valid);
        found |= valid;

        let mut cand_scrub = cand_bytes;
        cand_scrub.zeroize();
    }

    if bool::from(found) {
        Some((
            found_idx_u8 as usize,
            MasterVolumeKey::from_bytes(*mvk_bytes),
        ))
    } else {
        None
    }
}

const _: () = assert!(DENIABLE_SLOT_COUNT <= 255);

/// Derive a passphrase-credential KEK. Uses Argon2id directly on the
/// per-vault salt (no extra HKDF wrap: Argon2id already produces a
/// uniformly-distributed 32-byte output suitable for AEAD keying).
///
/// Param values come from the user at unlock time and are part of the
/// secret in deniable mode; pass values matching what `init_deniable`
/// recorded externally (e.g., the params shown at init time).
pub fn passphrase_kek(
    passphrase: &[u8],
    per_vault_salt: &[u8; DENIABLE_SALT_SIZE],
    params: Argon2idParams,
) -> Result<KeyEncryptionKey, Error> {
    derive_kek(passphrase, per_vault_salt, params)
}

/// Derive the FIDO2 hmac-secret salt from per-vault salt + credential ID.
/// Each vault gives the SAME credential a different hmac-secret output,
/// so a single FIDO2 device can be used across vaults without key reuse.
pub fn fido2_hmac_salt(
    per_vault_salt: &[u8; DENIABLE_SALT_SIZE],
    credential_id: &[u8],
) -> [u8; 32] {
    let mut out = [0u8; 32];
    let hk = Hkdf::<Sha256>::new(Some(per_vault_salt), credential_id);
    hk.expand(hkdf_info::FIDO2_SALT, &mut out)
        .expect("32 <= 255*HashLen");
    out
}

/// Derive a FIDO2-credential KEK from the device's hmac-secret output.
pub fn fido2_kek(
    hmac_output: &[u8; 32],
    per_vault_salt: &[u8; DENIABLE_SALT_SIZE],
) -> KeyEncryptionKey {
    let mut out = Zeroizing::new([0u8; KEY_LEN]);
    let hk = Hkdf::<Sha256>::new(Some(per_vault_salt), hmac_output);
    hk.expand(hkdf_info::FIDO2_KEK, out.as_mut_slice())
        .expect("32 <= 255*HashLen");
    KeyEncryptionKey::from_bytes(*out)
}

/// Derive a TPM+FIDO2 fused-credential KEK. Both factors are required
/// to unlock; either alone yields a different KEK that fails AEAD.
pub fn tpm_fido2_kek(
    tpm_unsealed: &[u8; 32],
    fido2_hmac_output: &[u8; 32],
    per_vault_salt: &[u8; DENIABLE_SALT_SIZE],
) -> KeyEncryptionKey {
    // IKM is `tpm_unsealed || fido2_hmac_output`. Wrapped in `Zeroizing`
    // so the combined keying material is wiped on every drop path.
    let mut ikm = Zeroizing::new([0u8; 64]);
    ikm[..32].copy_from_slice(tpm_unsealed);
    ikm[32..].copy_from_slice(fido2_hmac_output);
    let hk = Hkdf::<Sha256>::new(Some(per_vault_salt), ikm.as_ref());
    let mut out = Zeroizing::new([0u8; KEY_LEN]);
    hk.expand(hkdf_info::TPM_FIDO2_KEK, out.as_mut_slice())
        .expect("32 <= 255*HashLen");
    KeyEncryptionKey::from_bytes(*out)
}

/// Derive a PQ-hybrid + FIDO2 KEK. Combines a classical contribution
/// (Argon2id of passphrase against per-vault salt), the ML-KEM
/// decapsulation result, and the FIDO2 hmac-secret output.
pub fn pq_hybrid_kek(
    classical_argon2_output: &[u8; 32],
    mlkem_shared_secret: &[u8; 32],
    fido2_hmac_output: &[u8; 32],
    per_vault_salt: &[u8; DENIABLE_SALT_SIZE],
) -> KeyEncryptionKey {
    let mut ikm = Zeroizing::new([0u8; 96]);
    ikm[..32].copy_from_slice(classical_argon2_output);
    ikm[32..64].copy_from_slice(mlkem_shared_secret);
    ikm[64..].copy_from_slice(fido2_hmac_output);
    let hk = Hkdf::<Sha256>::new(Some(per_vault_salt), ikm.as_ref());
    let mut out = Zeroizing::new([0u8; KEY_LEN]);
    hk.expand(hkdf_info::PQ_HYBRID_KEK, out.as_mut_slice())
        .expect("32 <= 255*HashLen");
    KeyEncryptionKey::from_bytes(*out)
}

/// Credential combination supplied by the user at create / open /
/// enroll time for a deniable-mode slot. The variant chosen at
/// create time MUST match the variant supplied at open time;
/// otherwise the KEK derives in a different space and unlock fails
/// with `OpaqueUnlockFailed`.
///
/// The variant identity itself is NOT stored anywhere on disk -
/// this is the "user supplies everything not-in-the-file" principle
/// that makes the deniable vault file pure ciphertext. The user is
/// responsible for remembering which variant + parameters they used.
///
/// All variant inputs are by-reference so the caller controls
/// allocation + zeroize discipline.
pub enum DeniableCredential<'a> {
    /// Passphrase only. KEK = `Argon2id(passphrase, salt, params)`.
    Passphrase {
        passphrase: &'a [u8],
        argon2: Argon2idParams,
    },
    /// FIDO2 authenticator only (no passphrase). Caller has
    /// already invoked the device (discoverable cred lookup +
    /// PIN + hmac-secret extension) and supplies the 32-byte
    /// output.
    Fido2 { hmac_secret_output: &'a [u8; 32] },
    /// FIDO2 + passphrase. Both factors required.
    Fido2Passphrase {
        passphrase: &'a [u8],
        argon2: Argon2idParams,
        hmac_secret_output: &'a [u8; 32],
    },
    /// TPM only. Caller has unsealed the sealed blob (from NVRAM
    /// or sidecar) and supplies the 32-byte unsealed secret.
    Tpm { unsealed: &'a [u8; 32] },
    /// TPM + passphrase. Both factors required.
    TpmPassphrase {
        passphrase: &'a [u8],
        argon2: Argon2idParams,
        unsealed: &'a [u8; 32],
    },
    /// TPM + FIDO2. Both factors required.
    TpmFido2 {
        unsealed: &'a [u8; 32],
        hmac_secret_output: &'a [u8; 32],
    },
    /// PQ-hybrid (ML-KEM) + passphrase. Caller has done the ML-KEM
    /// decapsulation and supplies the 32-byte shared secret.
    HybridPqPassphrase {
        passphrase: &'a [u8],
        argon2: Argon2idParams,
        mlkem_shared: &'a [u8; 32],
    },
    /// PQ-hybrid + FIDO2.
    HybridPqFido2 {
        mlkem_shared: &'a [u8; 32],
        hmac_secret_output: &'a [u8; 32],
    },
    /// PQ-hybrid + TPM.
    HybridPqTpm {
        mlkem_shared: &'a [u8; 32],
        unsealed: &'a [u8; 32],
    },
    /// 3-factor: PQ-hybrid + TPM + FIDO2. All three required.
    HybridPqTpmFido2 {
        mlkem_shared: &'a [u8; 32],
        unsealed: &'a [u8; 32],
        hmac_secret_output: &'a [u8; 32],
    },
}

impl DeniableCredential<'_> {
    /// Derive the slot's KEK from this credential + the per-vault
    /// salt. Each variant uses a distinct HKDF info label so the
    /// resulting KEKs are cryptographically independent (security
    /// invariant #5).
    pub fn derive_kek(
        &self,
        per_vault_salt: &[u8; DENIABLE_SALT_SIZE],
    ) -> Result<KeyEncryptionKey, Error> {
        match self {
            Self::Passphrase { passphrase, argon2 } => {
                derive_kek(passphrase, per_vault_salt, *argon2)
            }
            Self::Fido2 { hmac_secret_output } => Ok(hkdf_kek(
                per_vault_salt,
                hmac_secret_output.as_slice(),
                hkdf_info::KEK_FIDO2,
            )),
            Self::Fido2Passphrase {
                passphrase,
                argon2,
                hmac_secret_output,
            } => {
                let pp = derive_kek(passphrase, per_vault_salt, *argon2)?;
                Ok(hkdf_combine(
                    per_vault_salt,
                    &[pp.as_bytes().as_slice(), hmac_secret_output.as_slice()],
                    hkdf_info::KEK_FIDO2_PASSPHRASE,
                ))
            }
            Self::Tpm { unsealed } => Ok(hkdf_kek(
                per_vault_salt,
                unsealed.as_slice(),
                hkdf_info::KEK_TPM,
            )),
            Self::TpmPassphrase {
                passphrase,
                argon2,
                unsealed,
            } => {
                let pp = derive_kek(passphrase, per_vault_salt, *argon2)?;
                Ok(hkdf_combine(
                    per_vault_salt,
                    &[pp.as_bytes().as_slice(), unsealed.as_slice()],
                    hkdf_info::KEK_TPM_PASSPHRASE,
                ))
            }
            Self::TpmFido2 {
                unsealed,
                hmac_secret_output,
            } => Ok(hkdf_combine(
                per_vault_salt,
                &[unsealed.as_slice(), hmac_secret_output.as_slice()],
                hkdf_info::KEK_TPM_FIDO2,
            )),
            Self::HybridPqPassphrase {
                passphrase,
                argon2,
                mlkem_shared,
            } => {
                let pp = derive_kek(passphrase, per_vault_salt, *argon2)?;
                Ok(hkdf_combine(
                    per_vault_salt,
                    &[pp.as_bytes().as_slice(), mlkem_shared.as_slice()],
                    hkdf_info::KEK_PQ_PASSPHRASE,
                ))
            }
            Self::HybridPqFido2 {
                mlkem_shared,
                hmac_secret_output,
            } => Ok(hkdf_combine(
                per_vault_salt,
                &[mlkem_shared.as_slice(), hmac_secret_output.as_slice()],
                hkdf_info::KEK_PQ_FIDO2,
            )),
            Self::HybridPqTpm {
                mlkem_shared,
                unsealed,
            } => Ok(hkdf_combine(
                per_vault_salt,
                &[mlkem_shared.as_slice(), unsealed.as_slice()],
                hkdf_info::KEK_PQ_TPM,
            )),
            Self::HybridPqTpmFido2 {
                mlkem_shared,
                unsealed,
                hmac_secret_output,
            } => Ok(hkdf_combine(
                per_vault_salt,
                &[
                    mlkem_shared.as_slice(),
                    unsealed.as_slice(),
                    hmac_secret_output.as_slice(),
                ],
                hkdf_info::KEK_PQ_TPM_FIDO2,
            )),
        }
    }

    /// Stable string label for this variant. Used by GUI / CLI for
    /// "you opened slot N with method <label>" display. Not stored
    /// on disk anywhere.
    pub fn label(&self) -> &'static str {
        match self {
            Self::Passphrase { .. } => "passphrase",
            Self::Fido2 { .. } => "fido2",
            Self::Fido2Passphrase { .. } => "fido2+passphrase",
            Self::Tpm { .. } => "tpm",
            Self::TpmPassphrase { .. } => "tpm+passphrase",
            Self::TpmFido2 { .. } => "tpm+fido2",
            Self::HybridPqPassphrase { .. } => "pq+passphrase",
            Self::HybridPqFido2 { .. } => "pq+fido2",
            Self::HybridPqTpm { .. } => "pq+tpm",
            Self::HybridPqTpmFido2 { .. } => "pq+tpm+fido2",
        }
    }
}

/// Internal: HKDF-SHA256 KEK from a single IKM with a per-credential
/// info label. The salt is the per-vault salt so two vaults with
/// the same credential material produce distinct KEKs.
fn hkdf_kek(
    per_vault_salt: &[u8; DENIABLE_SALT_SIZE],
    ikm: &[u8],
    info: &[u8],
) -> KeyEncryptionKey {
    let mut out = Zeroizing::new([0u8; KEY_LEN]);
    let hk = Hkdf::<Sha256>::new(Some(per_vault_salt), ikm);
    hk.expand(info, out.as_mut_slice())
        .expect("32 <= 255*HashLen");
    KeyEncryptionKey::from_bytes(*out)
}

/// Internal: HKDF-SHA256 KEK from a CONCATENATED IKM (multiple
/// 32-byte segments). Used by multi-factor variants where the IKM
/// is `secret1 || secret2 || ...`.
fn hkdf_combine(
    per_vault_salt: &[u8; DENIABLE_SALT_SIZE],
    segments: &[&[u8]],
    info: &[u8],
) -> KeyEncryptionKey {
    let total: usize = segments.iter().map(|s| s.len()).sum();
    let mut ikm = Zeroizing::new(Vec::<u8>::with_capacity(total));
    for s in segments {
        ikm.extend_from_slice(s);
    }
    hkdf_kek(per_vault_salt, &ikm, info)
}

/// Derive the inner-header AEAD key from the MVK. The inner header is
/// the 4064-byte encrypted region holding cipher_suite, kdf_id, flags,
/// metadata/data offsets; without the MVK it is uniform random.
pub fn inner_header_key(
    mvk: &MasterVolumeKey,
    per_vault_salt: &[u8; DENIABLE_SALT_SIZE],
) -> KeyEncryptionKey {
    let mut out = Zeroizing::new([0u8; KEY_LEN]);
    let hk = Hkdf::<Sha256>::new(Some(per_vault_salt), mvk.as_bytes());
    hk.expand(hkdf_info::INNER_HEADER, out.as_mut_slice())
        .expect("32 <= 255*HashLen");
    KeyEncryptionKey::from_bytes(*out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_salt() -> [u8; DENIABLE_SALT_SIZE] {
        let mut s = [0u8; DENIABLE_SALT_SIZE];
        for (i, b) in s.iter_mut().enumerate() {
            *b = i as u8;
        }
        s
    }

    fn test_kek(byte: u8) -> KeyEncryptionKey {
        KeyEncryptionKey::from_bytes([byte; KEY_LEN])
    }

    #[test]
    fn slot_aad_includes_prefix_salt_index() {
        let salt = test_salt();
        let aad0 = slot_aad(&salt, 0);
        let aad1 = slot_aad(&salt, 1);
        assert_ne!(aad0, aad1, "slot index must change the AAD");
        assert!(aad0.starts_with(DENIABLE_AAD_PREFIX), "prefix bound");
        assert_eq!(
            aad0[DENIABLE_AAD_PREFIX.len()..DENIABLE_AAD_PREFIX.len() + 32],
            salt
        );
        assert_eq!(aad0[DENIABLE_AAD_PREFIX.len() + 32], 0u8);
        assert_eq!(aad1[DENIABLE_AAD_PREFIX.len() + 32], 1u8);
    }

    #[test]
    #[should_panic(expected = "out of range")]
    fn slot_aad_rejects_out_of_range_index() {
        let salt = test_salt();
        let _ = slot_aad(&salt, DENIABLE_SLOT_COUNT);
    }

    #[test]
    fn wrap_then_unwrap_round_trips() {
        let salt = test_salt();
        let mvk = MasterVolumeKey::from_bytes([0xab; KEY_LEN]);
        let kek = test_kek(0x11);
        let mut slot = [0u8; DENIABLE_SLOT_SIZE];
        wrap_slot(&mut slot, &kek, &mvk, CipherSuite::Aes256GcmSiv, &salt, 3).unwrap();
        let got = try_unwrap_slot(&slot, &kek, CipherSuite::Aes256GcmSiv, &salt, 3).unwrap();
        assert_eq!(got.as_bytes(), mvk.as_bytes());
    }

    #[test]
    fn wrong_kek_fails_unwrap() {
        let salt = test_salt();
        let mvk = MasterVolumeKey::from_bytes([0xab; KEY_LEN]);
        let kek = test_kek(0x11);
        let wrong = test_kek(0x22);
        let mut slot = [0u8; DENIABLE_SLOT_SIZE];
        wrap_slot(&mut slot, &kek, &mvk, CipherSuite::Aes256GcmSiv, &salt, 0).unwrap();
        assert!(try_unwrap_slot(&slot, &wrong, CipherSuite::Aes256GcmSiv, &salt, 0).is_none());
    }

    #[test]
    fn invariant_1_aad_binding_tamper_detected() {
        // INVARIANT 1: tampering with any of the AAD components (vault
        // salt, slot index, format prefix) causes AEAD verification to
        // fail. The prefix and slot index are derived inside the
        // verification call, so we exercise the salt + slot-index axes.
        let salt = test_salt();
        let mvk = MasterVolumeKey::from_bytes([0xab; KEY_LEN]);
        let kek = test_kek(0x11);
        let mut slot = [0u8; DENIABLE_SLOT_SIZE];
        wrap_slot(&mut slot, &kek, &mvk, CipherSuite::Aes256GcmSiv, &salt, 4).unwrap();

        // Same KEK + slot bytes, but pass wrong slot_idx to verifier.
        for wrong_idx in 0..DENIABLE_SLOT_COUNT {
            if wrong_idx == 4 {
                continue;
            }
            assert!(
                try_unwrap_slot(&slot, &kek, CipherSuite::Aes256GcmSiv, &salt, wrong_idx).is_none(),
                "wrong slot_idx={} must reject; AAD binding is broken",
                wrong_idx,
            );
        }

        // Same KEK + slot bytes + slot_idx, but flip a bit in the salt.
        let mut bad_salt = salt;
        bad_salt[0] ^= 1;
        assert!(
            try_unwrap_slot(&slot, &kek, CipherSuite::Aes256GcmSiv, &bad_salt, 4).is_none(),
            "different vault salt must reject; AAD binding is broken",
        );
    }

    #[test]
    fn invariant_2_constant_time_loop_processes_all_slots() {
        // INVARIANT 2: trial_decrypt iterates ALL DENIABLE_SLOT_COUNT
        // slots regardless of where the match lives. We can't directly
        // observe loop count from outside, so we verify the
        // functional consequence: trial_decrypt finds a match
        // whether it sits in slot 0 (early) or slot
        // DENIABLE_SLOT_COUNT-1 (late). If the loop short-circuited
        // we would still find the early match; an extra check is
        // that trial_decrypt also IGNORES random data in other slots
        // and returns the right MVK from the matching slot.
        let salt = test_salt();
        let mvk = MasterVolumeKey::from_bytes([0xcd; KEY_LEN]);
        let kek = test_kek(0x33);

        for matching_idx in 0..DENIABLE_SLOT_COUNT {
            let mut slots = [[0u8; DENIABLE_SLOT_SIZE]; DENIABLE_SLOT_COUNT];
            // Fill all slots with random padding first (invariant #3).
            for slot in slots.iter_mut() {
                fill_random(slot).unwrap();
            }
            // Wrap MVK into the matching slot.
            wrap_slot(
                &mut slots[matching_idx],
                &kek,
                &mvk,
                CipherSuite::Aes256GcmSiv,
                &salt,
                matching_idx,
            )
            .unwrap();
            let got = trial_decrypt(&slots, &kek, CipherSuite::Aes256GcmSiv, &salt).unwrap();
            assert_eq!(
                got.as_bytes(),
                mvk.as_bytes(),
                "matching slot {} not found by trial_decrypt",
                matching_idx,
            );
        }
    }

    #[test]
    fn invariant_2_no_slot_match_returns_none() {
        // INVARIANT 2 continued: if every slot is random noise (no
        // KEK matches), trial_decrypt returns None and we get no
        // partial / oracle output.
        let salt = test_salt();
        let kek = test_kek(0x55);
        let mut slots = [[0u8; DENIABLE_SLOT_SIZE]; DENIABLE_SLOT_COUNT];
        for slot in slots.iter_mut() {
            fill_random(slot).unwrap();
        }
        assert!(trial_decrypt(&slots, &kek, CipherSuite::Aes256GcmSiv, &salt).is_none());
    }

    #[test]
    fn invariant_3_empty_and_occupied_slots_have_similar_entropy() {
        // INVARIANT 3: empty slots and occupied slots come from the
        // SAME distribution (uniform random). We exercise this
        // indirectly via a Shannon-entropy proxy: both should have
        // > 7.5 bits/byte over a large sample.
        // Real distribution-equivalence under cryptographic
        // distinguishers is an AEAD security property of the
        // primitives we use; here we just confirm we're not
        // introducing a trivially-distinguishable empty slot
        // (e.g., all zeros).
        let salt = test_salt();
        let kek = test_kek(0x77);
        let mvk = MasterVolumeKey::from_bytes([0x88; KEY_LEN]);

        let mut all_empty = vec![0u8; DENIABLE_SLOT_SIZE * 16];
        fill_random(&mut all_empty).unwrap();
        assert!(
            shannon_bits_per_byte(&all_empty) > 7.5,
            "empty slot bytes look low-entropy ({:.2} bits/byte); fill_random may be broken",
            shannon_bits_per_byte(&all_empty),
        );

        let mut occupied = vec![0u8; DENIABLE_SLOT_SIZE * 16];
        for chunk_idx in 0..16 {
            let s: &mut [u8; DENIABLE_SLOT_SIZE] = (&mut occupied
                [chunk_idx * DENIABLE_SLOT_SIZE..(chunk_idx + 1) * DENIABLE_SLOT_SIZE])
                .try_into()
                .unwrap();
            wrap_slot(
                s,
                &kek,
                &mvk,
                CipherSuite::Aes256GcmSiv,
                &salt,
                chunk_idx % DENIABLE_SLOT_COUNT,
            )
            .unwrap();
        }
        assert!(
            shannon_bits_per_byte(&occupied) > 7.5,
            "occupied slot bytes look low-entropy ({:.2} bits/byte)",
            shannon_bits_per_byte(&occupied),
        );
    }

    #[test]
    fn invariant_5_domain_separation_distinct_keks() {
        // INVARIANT 5: feeding the same secret through different
        // credential derivations yields cryptographically independent
        // KEKs. Using a shared 32-byte secret as both the FIDO2
        // hmac-output AND the TPM-unsealed input MUST produce
        // unequal KEKs.
        let salt = test_salt();
        let secret = [0x99u8; 32];
        let secret2 = [0xaau8; 32];

        let kek_fido2 = fido2_kek(&secret, &salt);
        let kek_tpm = tpm_fido2_kek(&secret, &secret2, &salt);
        let kek_pq = pq_hybrid_kek(&secret, &secret, &secret2, &salt);
        let kek_inner = inner_header_key(&MasterVolumeKey::from_bytes(secret), &salt);

        let pairs = [
            ("fido2 vs tpm", kek_fido2.as_bytes(), kek_tpm.as_bytes()),
            ("fido2 vs pq", kek_fido2.as_bytes(), kek_pq.as_bytes()),
            ("tpm vs pq", kek_tpm.as_bytes(), kek_pq.as_bytes()),
            ("fido2 vs inner", kek_fido2.as_bytes(), kek_inner.as_bytes()),
            ("tpm vs inner", kek_tpm.as_bytes(), kek_inner.as_bytes()),
            ("pq vs inner", kek_pq.as_bytes(), kek_inner.as_bytes()),
        ];
        for (label, a, b) in pairs.iter() {
            assert_ne!(
                a, b,
                "{}: domain separation failed; the two derivations produced identical KEKs",
                label,
            );
        }
    }

    #[test]
    fn fido2_hmac_salt_changes_per_credential() {
        let salt = test_salt();
        let cred_a = b"cred-a";
        let cred_b = b"cred-b";
        let s_a = fido2_hmac_salt(&salt, cred_a);
        let s_b = fido2_hmac_salt(&salt, cred_b);
        assert_ne!(
            s_a, s_b,
            "different credential IDs must give different hmac salts"
        );
    }

    #[test]
    fn fido2_hmac_salt_changes_per_vault() {
        let cred = b"cred";
        let salt_a = test_salt();
        let mut salt_b = test_salt();
        salt_b[0] ^= 0xff;
        let s_a = fido2_hmac_salt(&salt_a, cred);
        let s_b = fido2_hmac_salt(&salt_b, cred);
        assert_ne!(
            s_a, s_b,
            "different vault salts must give different hmac salts"
        );
    }

    #[test]
    fn passphrase_kek_changes_per_vault_salt() {
        let salt_a = test_salt();
        let mut salt_b = test_salt();
        salt_b[0] ^= 0xff;
        let kek_a = passphrase_kek(b"hunter2", &salt_a, Argon2idParams::TEST_ONLY).unwrap();
        let kek_b = passphrase_kek(b"hunter2", &salt_b, Argon2idParams::TEST_ONLY).unwrap();
        assert_ne!(
            kek_a.as_bytes(),
            kek_b.as_bytes(),
            "same passphrase + different vault salt must derive different KEKs",
        );
    }

    #[test]
    fn credential_kek_passphrase_round_trips() {
        let salt = test_salt();
        let cred = DeniableCredential::Passphrase {
            passphrase: b"hunter2",
            argon2: Argon2idParams::TEST_ONLY,
        };
        let kek_a = cred.derive_kek(&salt).unwrap();
        let kek_b = cred.derive_kek(&salt).unwrap();
        assert_eq!(
            kek_a.as_bytes(),
            kek_b.as_bytes(),
            "same credential + same salt must derive identical KEKs",
        );
    }

    #[test]
    fn credential_kek_all_variants_distinct() {
        // Identical secret material into every variant; the resulting
        // KEKs MUST all differ thanks to per-variant HKDF info
        // labels (security invariant #5 extended to the full
        // credential menu).
        let salt = test_salt();
        let secret = [0x77u8; 32];
        let other = [0x88u8; 32];
        let third = [0x99u8; 32];

        let keks: Vec<(&str, [u8; KEY_LEN])> = vec![
            (
                "passphrase",
                *DeniableCredential::Passphrase {
                    passphrase: b"x",
                    argon2: Argon2idParams::TEST_ONLY,
                }
                .derive_kek(&salt)
                .unwrap()
                .as_bytes(),
            ),
            (
                "fido2",
                *DeniableCredential::Fido2 {
                    hmac_secret_output: &secret,
                }
                .derive_kek(&salt)
                .unwrap()
                .as_bytes(),
            ),
            (
                "fido2+passphrase",
                *DeniableCredential::Fido2Passphrase {
                    passphrase: b"x",
                    argon2: Argon2idParams::TEST_ONLY,
                    hmac_secret_output: &secret,
                }
                .derive_kek(&salt)
                .unwrap()
                .as_bytes(),
            ),
            (
                "tpm",
                *DeniableCredential::Tpm { unsealed: &secret }
                    .derive_kek(&salt)
                    .unwrap()
                    .as_bytes(),
            ),
            (
                "tpm+passphrase",
                *DeniableCredential::TpmPassphrase {
                    passphrase: b"x",
                    argon2: Argon2idParams::TEST_ONLY,
                    unsealed: &secret,
                }
                .derive_kek(&salt)
                .unwrap()
                .as_bytes(),
            ),
            (
                "tpm+fido2",
                *DeniableCredential::TpmFido2 {
                    unsealed: &secret,
                    hmac_secret_output: &other,
                }
                .derive_kek(&salt)
                .unwrap()
                .as_bytes(),
            ),
            (
                "pq+passphrase",
                *DeniableCredential::HybridPqPassphrase {
                    passphrase: b"x",
                    argon2: Argon2idParams::TEST_ONLY,
                    mlkem_shared: &secret,
                }
                .derive_kek(&salt)
                .unwrap()
                .as_bytes(),
            ),
            (
                "pq+fido2",
                *DeniableCredential::HybridPqFido2 {
                    mlkem_shared: &secret,
                    hmac_secret_output: &other,
                }
                .derive_kek(&salt)
                .unwrap()
                .as_bytes(),
            ),
            (
                "pq+tpm",
                *DeniableCredential::HybridPqTpm {
                    mlkem_shared: &secret,
                    unsealed: &other,
                }
                .derive_kek(&salt)
                .unwrap()
                .as_bytes(),
            ),
            (
                "pq+tpm+fido2",
                *DeniableCredential::HybridPqTpmFido2 {
                    mlkem_shared: &secret,
                    unsealed: &other,
                    hmac_secret_output: &third,
                }
                .derive_kek(&salt)
                .unwrap()
                .as_bytes(),
            ),
        ];

        for (i, (l_label, l_kek)) in keks.iter().enumerate() {
            for (r_label, r_kek) in keks.iter().skip(i + 1) {
                assert_ne!(
                    l_kek, r_kek,
                    "variants {} and {} produced identical KEKs - domain separation broken",
                    l_label, r_label,
                );
            }
        }
    }

    #[test]
    fn credential_kek_changes_per_salt() {
        let salt_a = test_salt();
        let mut salt_b = test_salt();
        salt_b[0] ^= 0xff;
        let secret = [0x42u8; 32];
        let cred = DeniableCredential::Fido2 {
            hmac_secret_output: &secret,
        };
        let kek_a = cred.derive_kek(&salt_a).unwrap();
        let kek_b = cred.derive_kek(&salt_b).unwrap();
        assert_ne!(
            kek_a.as_bytes(),
            kek_b.as_bytes(),
            "different vault salts must give different KEKs",
        );
    }

    #[test]
    fn credential_label_is_stable() {
        // GUI / CLI display strings; pinning them so changing a
        // label is a deliberate user-facing decision.
        let secret = [0u8; 32];
        assert_eq!(
            DeniableCredential::Passphrase {
                passphrase: b"x",
                argon2: Argon2idParams::TEST_ONLY,
            }
            .label(),
            "passphrase",
        );
        assert_eq!(
            DeniableCredential::Fido2 {
                hmac_secret_output: &secret
            }
            .label(),
            "fido2",
        );
        assert_eq!(
            DeniableCredential::HybridPqTpmFido2 {
                mlkem_shared: &secret,
                unsealed: &secret,
                hmac_secret_output: &secret,
            }
            .label(),
            "pq+tpm+fido2",
        );
    }

    /// Shannon entropy in bits/byte over a buffer. Trivially noticed
    /// distinguishers (all-zero, all-one, repeating pattern) score
    /// far below 7.5; uniform random scores ~7.99 for buffers > 1
    /// KiB. Used by invariant #3 as a cheap sanity check.
    fn shannon_bits_per_byte(buf: &[u8]) -> f64 {
        let mut counts = [0u64; 256];
        for &b in buf {
            counts[b as usize] += 1;
        }
        let n = buf.len() as f64;
        let mut h = 0.0;
        for &c in counts.iter() {
            if c == 0 {
                continue;
            }
            let p = c as f64 / n;
            h -= p * p.log2();
        }
        h
    }
}
