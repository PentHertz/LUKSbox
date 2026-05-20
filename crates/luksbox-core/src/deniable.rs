// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Penthertz <https://penthertz.com> (https://x.com/PentHertz)

//! Deniable header v2 - opt-in container header where every on-disk
//! byte is computationally indistinguishable from uniform random output.
//!
//! See `docs/DENIABLE_HEADER.md` for the full design specification
//! including threat model, format layout, and the five normative
//! security invariants. This module implements the format primitives;
//! higher-level container ops (init/open/add-user/remove-user) live in
//! `luksbox-format::container`.
//!
//! ## v2 vs v1
//!
//! v1 (8 KiB header, 512 B slots wrapping only the MVK, external
//! `cred_id` / `hmac_salt` / `.tpm-blob` sidecars) was paused mid-impl
//! and never shipped publicly. v2 bumps the slot to 4 KiB and embeds
//! all authenticator-bound material (`cred_id`, `hmac_salt`, TPM
//! sealed blob) inside the slot envelope, eliminating the TPM
//! sidecar. v2 makes a passphrase mandatory for every deniable
//! credential (it's the only discovery factor that can decrypt the
//! envelope without itself being inside the envelope).
//!
//! ## Security invariants enforced here
//!
//! 1. **AAD binding** - every slot AEAD computation includes
//!    `b"luksbox-deniable-v2" || per_vault_salt || slot_idx`, preventing
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
use zeroize::Zeroizing;

use crate::aead::{self, CipherSuite};
use crate::error::Error;
use crate::kdf::{Argon2idParams, derive_kek};
use crate::key::{KEY_LEN, KeyEncryptionKey, MasterVolumeKey};

/// Total deniable header size. v2 = salt + 8 * 4 KiB slot table +
/// inner header = 36864 bytes. Larger than v1's 8 KiB and larger than
/// the standard 8 KiB header, but still trivial in absolute terms and
/// pays for the embedded credential material that eliminates the v1
/// `.tpm-blob` sidecar + the external `cred_id` / `hmac_salt`
/// requirement.
pub const DENIABLE_HEADER_SIZE: usize = 36864;

/// Number of slots in a deniable header. Matches `MAX_KEYSLOTS` from
/// the standard format for shared muscle memory. Bumping is a format
/// version bump baked into the binary; the slot count is NOT on disk.
pub const DENIABLE_SLOT_COUNT: usize = 8;

/// Per-slot size (bytes). v2 bumped this from 512 to 4096 so the
/// AEAD envelope can carry every authenticator-bound piece of
/// material (`cred_id` up to ~1 KiB, `hmac_salt` 32 B, TPM sealed
/// blob up to ~3 KiB, inner `wrapped_mvk` 48 B, random padding for
/// the rest). The exact in-envelope layout is encoded by
/// `slot_payload::SlotPayload`; this constant just guarantees the
/// envelope has room for any combination of those fields.
pub const DENIABLE_SLOT_SIZE: usize = 4096;

/// Per-vault salt size at offset 0 of the deniable header.
pub const DENIABLE_SALT_SIZE: usize = 32;

/// Offset of the slot table in the header.
pub const DENIABLE_SLOT_TABLE_OFFSET: usize = DENIABLE_SALT_SIZE;

/// Offset of the encrypted inner header in the deniable header.
pub const DENIABLE_INNER_OFFSET: usize =
    DENIABLE_SLOT_TABLE_OFFSET + DENIABLE_SLOT_COUNT * DENIABLE_SLOT_SIZE;

/// Size of the encrypted inner header (bytes). Unchanged from v1 at
/// 4064 - the inner header structure didn't grow; only the slot table
/// did.
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
const _: () = assert!(DENIABLE_INNER_OFFSET == 32 + 8 * 4096);
const _: () = assert!(DENIABLE_INNER_SIZE == 4064);
const _: () = assert!(SLOT_NONCE_LEN + SLOT_CT_AND_TAG_LEN < DENIABLE_SLOT_SIZE);

/// AAD prefix bound into every slot AEAD computation. v2 bump means
/// any stray v1 bytes cannot accidentally decrypt under v2 keying.
pub const DENIABLE_AAD_PREFIX: &[u8] = b"luksbox-deniable-v2";

/// HKDF info labels for per-credential KEK derivation. Each credential
/// type uses a distinct label so a bug in one derivation cannot
/// contaminate another (security invariant #5). The `KEK_*` labels
/// below correspond 1:1 to `DeniableCredential` variants.
///
/// Two layers of KEKs in v2:
///
/// - `KEK_ENVELOPE` derives the outer slot envelope key from the
///   passphrase. There is only one of these because the envelope is
///   always passphrase-keyed in v2 (the discovery factor).
/// - `KEK_*_PASSPHRASE` (one per variant) derive the inner
///   `wrapped_mvk` key from `KEK_envelope || <secondary factors>`.
///
/// The v1 labels (without the `+passphrase` suffix) are retained for
/// the v1 single-step `derive_kek` API used by code that has not yet
/// migrated to the v2 two-step envelope/factors API. New code should
/// not reference them.
pub mod hkdf_info {
    pub const INNER_HEADER: &[u8] = b"luksbox-deniable-v2/inner-header";

    /// Outer-envelope KEK label. Always passphrase-derived (Argon2id
    /// directly, no HKDF), so this constant is only used as a domain
    /// separator if a future variant needs a non-Argon2id outer
    /// derivation. Reserved.
    pub const KEK_ENVELOPE: &[u8] = b"luksbox-deniable-v2/kek/envelope";

    // v2 labels: one per DeniableCredential variant that carries a
    // passphrase. Each one uniquely identifies the credential
    // combination so an adversary who guesses the wrong combo
    // derives a KEK in an independent space.
    pub const KEK_PASSPHRASE: &[u8] = b"luksbox-deniable-v2/kek/passphrase";
    pub const KEK_FIDO2_PASSPHRASE: &[u8] = b"luksbox-deniable-v2/kek/fido2+passphrase";
    pub const KEK_TPM_PASSPHRASE: &[u8] = b"luksbox-deniable-v2/kek/tpm+passphrase";
    pub const KEK_TPM_FIDO2_PASSPHRASE: &[u8] = b"luksbox-deniable-v2/kek/tpm+fido2+passphrase";
    pub const KEK_PQ_PASSPHRASE: &[u8] = b"luksbox-deniable-v2/kek/pq+passphrase";
    pub const KEK_PQ_FIDO2_PASSPHRASE: &[u8] = b"luksbox-deniable-v2/kek/pq+fido2+passphrase";
    pub const KEK_PQ_TPM_PASSPHRASE: &[u8] = b"luksbox-deniable-v2/kek/pq+tpm+passphrase";
    pub const KEK_PQ_TPM_FIDO2_PASSPHRASE: &[u8] =
        b"luksbox-deniable-v2/kek/pq+tpm+fido2+passphrase";
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

        // Round 12 fix R12-13: wrap the candidate bytes in
        // `Zeroizing` so the Drop-on-scope-exit path zeroes the
        // STORAGE rather than a separately-named Copy. The previous
        // `let mut cand_scrub = cand_bytes; cand_scrub.zeroize()`
        // wiped a copy and left the original `[u8;32]` (which is
        // Copy) sitting on the stack until the frame reused the
        // slot.
        let cand_bytes: Zeroizing<[u8; KEY_LEN]> = Zeroizing::new(
            attempt
                .as_ref()
                .map(|m| *m.as_bytes())
                .unwrap_or([0u8; KEY_LEN]),
        );

        for i in 0..KEY_LEN {
            mvk_bytes[i] = u8::conditional_select(&mvk_bytes[i], &cand_bytes[i], valid);
        }
        // Constant-time select for the index too. We rely on
        // DENIABLE_SLOT_COUNT <= 255 (currently 8) so a u8 holds
        // every possible slot index; the const_assert below guards
        // that invariant.
        found_idx_u8 = u8::conditional_select(&found_idx_u8, &(slot_idx as u8), valid);
        found |= valid;
        // `cand_bytes` drops here and wipes its storage.
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

// v1 standalone helpers `fido2_hmac_salt`, `fido2_kek`,
// `tpm_fido2_kek`, `pq_hybrid_kek` were removed in v2. v2 derives
// FIDO2 hmac_salt as fresh random at enroll time (stored inside the
// slot envelope), and per-variant KEK derivation goes through
// `DeniableCredential::derive_envelope_kek` +
// `derive_factors_kek` so the two-layer envelope semantics are
// enforced by the type system.

/// Credential combination supplied by the user at create / open /
/// enroll time for a deniable-mode slot. v2 makes the passphrase
/// mandatory for every variant: it derives `KEK_envelope` which is
/// the only key that can open the slot envelope (without itself
/// being inside the slot).
///
/// The variant identity itself is NOT stored anywhere on disk in
/// plaintext - it's encoded as a 1-byte kind tag INSIDE the
/// envelope, only visible after `KEK_envelope` decrypts the
/// envelope. This means the user is responsible for remembering
/// which variant + parameters they used (the same as v1).
///
/// Pure-FIDO2 / pure-TPM / non-passphrase variants from v1 are
/// removed - they were the variants that required external
/// material (`.tpm-blob` sidecar, hex `cred_id` / `hmac_salt`) and
/// caused the deniability tells v2 set out to fix.
///
/// All variant inputs are by-reference so the caller controls
/// allocation + zeroize discipline.
pub enum DeniableCredential<'a> {
    /// Passphrase only. `KEK_envelope = Argon2id(passphrase, salt,
    /// params)`; `KEK_factors = HKDF(salt, envelope_kek, label)` so
    /// the inner `wrapped_mvk` is keyed independently of the envelope.
    Passphrase {
        passphrase: &'a [u8],
        argon2: Argon2idParams,
    },
    /// Passphrase + FIDO2. `cred_id` and `hmac_salt` live inside the
    /// slot envelope; `hmac_secret_output` is the 32-byte response
    /// the device produces when the host calls
    /// `get_assertion(cred_id, hmac_salt)`.
    Fido2Passphrase {
        passphrase: &'a [u8],
        argon2: Argon2idParams,
        hmac_secret_output: &'a [u8; 32],
    },
    /// Passphrase + TPM. The TPM sealed blob lives inside the slot
    /// envelope; `unsealed` is the 32-byte secret the TPM returns
    /// from `TPM2_Unseal(tpm_blob)`.
    TpmPassphrase {
        passphrase: &'a [u8],
        argon2: Argon2idParams,
        unsealed: &'a [u8; 32],
    },
    /// 3-factor: passphrase + TPM + FIDO2. All three required.
    TpmFido2Passphrase {
        passphrase: &'a [u8],
        argon2: Argon2idParams,
        unsealed: &'a [u8; 32],
        hmac_secret_output: &'a [u8; 32],
    },
    /// Passphrase + PQ-hybrid (ML-KEM). Caller has done the ML-KEM
    /// decapsulation (using the `.kyber` sidecar) and supplies the
    /// 32-byte shared secret.
    HybridPqPassphrase {
        passphrase: &'a [u8],
        argon2: Argon2idParams,
        mlkem_shared: &'a [u8; 32],
    },
    /// Passphrase + PQ + FIDO2.
    HybridPqFido2Passphrase {
        passphrase: &'a [u8],
        argon2: Argon2idParams,
        mlkem_shared: &'a [u8; 32],
        hmac_secret_output: &'a [u8; 32],
    },
    /// Passphrase + PQ + TPM.
    HybridPqTpmPassphrase {
        passphrase: &'a [u8],
        argon2: Argon2idParams,
        mlkem_shared: &'a [u8; 32],
        unsealed: &'a [u8; 32],
    },
    /// 4-factor: passphrase + PQ + TPM + FIDO2. All four required.
    HybridPqTpmFido2Passphrase {
        passphrase: &'a [u8],
        argon2: Argon2idParams,
        mlkem_shared: &'a [u8; 32],
        unsealed: &'a [u8; 32],
        hmac_secret_output: &'a [u8; 32],
    },
}

/// Numeric tag stored inside the slot envelope as `kind`. The
/// variant identity is recoverable from the tag without needing to
/// re-derive any KEK; this is what lets the open path "discover" the
/// variant after envelope decryption succeeds.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum DeniableKindTag {
    Passphrase = 1,
    Fido2Passphrase = 2,
    TpmPassphrase = 3,
    TpmFido2Passphrase = 4,
    HybridPqPassphrase = 5,
    HybridPqFido2Passphrase = 6,
    HybridPqTpmPassphrase = 7,
    HybridPqTpmFido2Passphrase = 8,
}

impl DeniableKindTag {
    pub fn from_u8(v: u8) -> Option<Self> {
        match v {
            1 => Some(Self::Passphrase),
            2 => Some(Self::Fido2Passphrase),
            3 => Some(Self::TpmPassphrase),
            4 => Some(Self::TpmFido2Passphrase),
            5 => Some(Self::HybridPqPassphrase),
            6 => Some(Self::HybridPqFido2Passphrase),
            7 => Some(Self::HybridPqTpmPassphrase),
            8 => Some(Self::HybridPqTpmFido2Passphrase),
            _ => None,
        }
    }
}

impl From<DeniableKindTag> for u8 {
    fn from(t: DeniableKindTag) -> u8 {
        t as u8
    }
}

impl DeniableCredential<'_> {
    /// Return the per-variant kind tag for embedding in the slot
    /// envelope's `kind` byte. Every v2 variant has one by
    /// construction (the type system enforces it).
    pub fn kind_tag(&self) -> DeniableKindTag {
        match self {
            Self::Passphrase { .. } => DeniableKindTag::Passphrase,
            Self::Fido2Passphrase { .. } => DeniableKindTag::Fido2Passphrase,
            Self::TpmPassphrase { .. } => DeniableKindTag::TpmPassphrase,
            Self::TpmFido2Passphrase { .. } => DeniableKindTag::TpmFido2Passphrase,
            Self::HybridPqPassphrase { .. } => DeniableKindTag::HybridPqPassphrase,
            Self::HybridPqFido2Passphrase { .. } => DeniableKindTag::HybridPqFido2Passphrase,
            Self::HybridPqTpmPassphrase { .. } => DeniableKindTag::HybridPqTpmPassphrase,
            Self::HybridPqTpmFido2Passphrase { .. } => DeniableKindTag::HybridPqTpmFido2Passphrase,
        }
    }

    /// Return the variant's passphrase + Argon2id params. Every v2
    /// variant has them by construction.
    pub fn passphrase_inputs(&self) -> (&[u8], Argon2idParams) {
        match self {
            Self::Passphrase { passphrase, argon2 }
            | Self::Fido2Passphrase {
                passphrase, argon2, ..
            }
            | Self::TpmPassphrase {
                passphrase, argon2, ..
            }
            | Self::TpmFido2Passphrase {
                passphrase, argon2, ..
            }
            | Self::HybridPqPassphrase {
                passphrase, argon2, ..
            }
            | Self::HybridPqFido2Passphrase {
                passphrase, argon2, ..
            }
            | Self::HybridPqTpmPassphrase {
                passphrase, argon2, ..
            }
            | Self::HybridPqTpmFido2Passphrase {
                passphrase, argon2, ..
            } => (passphrase, *argon2),
        }
    }

    /// Derive the outer slot envelope KEK. v2 invariant: the
    /// envelope key is always the passphrase-Argon2id output - it is
    /// what makes the envelope discoverable without an oracle.
    pub fn derive_envelope_kek(
        &self,
        per_vault_salt: &[u8; DENIABLE_SALT_SIZE],
    ) -> Result<KeyEncryptionKey, Error> {
        let (passphrase, argon2) = self.passphrase_inputs();
        derive_kek(passphrase, per_vault_salt, argon2)
    }

    /// Derive the inner `wrapped_mvk` KEK from the envelope KEK +
    /// per-variant secondary factors. Each variant uses a distinct
    /// HKDF info label so the resulting KEKs are cryptographically
    /// independent (security invariant #5).
    pub fn derive_factors_kek(
        &self,
        per_vault_salt: &[u8; DENIABLE_SALT_SIZE],
        envelope_kek: &KeyEncryptionKey,
    ) -> KeyEncryptionKey {
        match self {
            Self::Passphrase { .. } => hkdf_combine(
                per_vault_salt,
                &[envelope_kek.as_bytes().as_slice()],
                hkdf_info::KEK_PASSPHRASE,
            ),
            Self::Fido2Passphrase {
                hmac_secret_output, ..
            } => hkdf_combine(
                per_vault_salt,
                &[
                    envelope_kek.as_bytes().as_slice(),
                    hmac_secret_output.as_slice(),
                ],
                hkdf_info::KEK_FIDO2_PASSPHRASE,
            ),
            Self::TpmPassphrase { unsealed, .. } => hkdf_combine(
                per_vault_salt,
                &[envelope_kek.as_bytes().as_slice(), unsealed.as_slice()],
                hkdf_info::KEK_TPM_PASSPHRASE,
            ),
            Self::TpmFido2Passphrase {
                unsealed,
                hmac_secret_output,
                ..
            } => hkdf_combine(
                per_vault_salt,
                &[
                    envelope_kek.as_bytes().as_slice(),
                    unsealed.as_slice(),
                    hmac_secret_output.as_slice(),
                ],
                hkdf_info::KEK_TPM_FIDO2_PASSPHRASE,
            ),
            Self::HybridPqPassphrase { mlkem_shared, .. } => hkdf_combine(
                per_vault_salt,
                &[envelope_kek.as_bytes().as_slice(), mlkem_shared.as_slice()],
                hkdf_info::KEK_PQ_PASSPHRASE,
            ),
            Self::HybridPqFido2Passphrase {
                mlkem_shared,
                hmac_secret_output,
                ..
            } => hkdf_combine(
                per_vault_salt,
                &[
                    envelope_kek.as_bytes().as_slice(),
                    mlkem_shared.as_slice(),
                    hmac_secret_output.as_slice(),
                ],
                hkdf_info::KEK_PQ_FIDO2_PASSPHRASE,
            ),
            Self::HybridPqTpmPassphrase {
                mlkem_shared,
                unsealed,
                ..
            } => hkdf_combine(
                per_vault_salt,
                &[
                    envelope_kek.as_bytes().as_slice(),
                    mlkem_shared.as_slice(),
                    unsealed.as_slice(),
                ],
                hkdf_info::KEK_PQ_TPM_PASSPHRASE,
            ),
            Self::HybridPqTpmFido2Passphrase {
                mlkem_shared,
                unsealed,
                hmac_secret_output,
                ..
            } => hkdf_combine(
                per_vault_salt,
                &[
                    envelope_kek.as_bytes().as_slice(),
                    mlkem_shared.as_slice(),
                    unsealed.as_slice(),
                    hmac_secret_output.as_slice(),
                ],
                hkdf_info::KEK_PQ_TPM_FIDO2_PASSPHRASE,
            ),
        }
    }

    /// Stable string label for this variant. Used by GUI / CLI for
    /// "you opened slot N with method <label>" display. Not stored
    /// on disk anywhere.
    pub fn label(&self) -> &'static str {
        match self {
            Self::Passphrase { .. } => "passphrase",
            Self::Fido2Passphrase { .. } => "fido2+passphrase",
            Self::TpmPassphrase { .. } => "tpm+passphrase",
            Self::TpmFido2Passphrase { .. } => "tpm+fido2+passphrase",
            Self::HybridPqPassphrase { .. } => "pq+passphrase",
            Self::HybridPqFido2Passphrase { .. } => "pq+fido2+passphrase",
            Self::HybridPqTpmPassphrase { .. } => "pq+tpm+passphrase",
            Self::HybridPqTpmFido2Passphrase { .. } => "pq+tpm+fido2+passphrase",
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

// ============================================================
// v2 slot payload: in-envelope material + wrapped MVK
// ============================================================

/// v2 slot payload structures + encode / decode. The payload is the
/// plaintext that lives inside the AEAD outer envelope of a v2
/// deniable slot. It carries the credential material (`cred_id`,
/// `hmac_salt`, `tpm_blob`) that previously required a sidecar or
/// external storage, plus the inner `wrapped_mvk` ciphertext.
///
/// See `docs/DENIABLE_HEADER.md` "Per-slot structure (v2)" for the
/// byte layout. This module is the canonical encoder/decoder for it.
pub mod slot_payload {
    use super::{
        DENIABLE_SLOT_SIZE, DeniableKindTag, Error, KEY_LEN, SLOT_NONCE_LEN, SLOT_TAG_LEN,
    };
    use zeroize::Zeroize;

    /// Fixed header inside the payload: kind tag + 3 lengths +
    /// reserved bytes. Always exactly 8 bytes.
    pub const PAYLOAD_HEADER_LEN: usize = 8;

    /// Inner wrapped-MVK envelope: 12-byte nonce + 32-byte MVK + 16-byte
    /// AEAD tag. Always exactly 60 bytes.
    pub const WRAPPED_MVK_LEN: usize = SLOT_NONCE_LEN + KEY_LEN + SLOT_TAG_LEN;

    /// Maximum FIDO2 credential id length permitted in a slot. The
    /// CTAP2 spec allows up to 1023 bytes; we cap at 1024 for a clean
    /// power-of-two budget. Realistic devices stay well under 256 B.
    pub const CRED_ID_MAX_LEN: usize = 1024;

    /// Exact FIDO2 `hmac_salt` length (when present).
    pub const HMAC_SALT_LEN: usize = 32;

    /// Maximum TPM2 sealed blob length permitted in a slot. Most real
    /// TPM2_PolicyAuthorize-bound sealed objects come out at
    /// 1.5-3 KiB; the cap leaves ~400 B of safety margin.
    pub const TPM_BLOB_MAX_LEN: usize = 3500;

    /// Total plaintext length of the payload that lives inside the
    /// AEAD outer envelope. `DENIABLE_SLOT_SIZE - nonce - tag`. The
    /// remaining budget for material is
    /// `PAYLOAD_PLAINTEXT_LEN - PAYLOAD_HEADER_LEN - WRAPPED_MVK_LEN`.
    pub const PAYLOAD_PLAINTEXT_LEN: usize = DENIABLE_SLOT_SIZE - SLOT_NONCE_LEN - SLOT_TAG_LEN;

    /// Combined budget for cred_id + hmac_salt + tpm_blob in a single
    /// slot. Validated at encode time; over-budget material returns
    /// `Error::InvalidField`.
    pub const MATERIAL_BUDGET: usize = PAYLOAD_PLAINTEXT_LEN - PAYLOAD_HEADER_LEN - WRAPPED_MVK_LEN;

    // Compile-time sanity checks for the layout constants.
    const _: () = assert!(PAYLOAD_PLAINTEXT_LEN == 4068);
    const _: () = assert!(WRAPPED_MVK_LEN == 60);
    const _: () = assert!(MATERIAL_BUDGET == 4000);
    const _: () = assert!(CRED_ID_MAX_LEN + HMAC_SALT_LEN + TPM_BLOB_MAX_LEN >= MATERIAL_BUDGET);

    /// Owned slot payload: all the bytes that go inside the outer
    /// envelope, parsed into named fields. Construct via
    /// `SlotPayload::new` (validates lengths against the budget),
    /// emit on-the-wire bytes via `encode`, parse incoming bytes via
    /// `decode`. The wrapped-MVK fields are opaque to this module -
    /// callers seal them with `KEK_factors` before constructing the
    /// payload and open them with `KEK_factors` after decoding.
    #[derive(Debug)]
    pub struct SlotPayload {
        pub kind: DeniableKindTag,
        pub cred_id: Vec<u8>,
        /// `Some([..; 32])` only for variants whose `kind` has a
        /// FIDO2 factor. `None` otherwise (and the on-disk
        /// `hmac_salt_len` is 0).
        pub hmac_salt: Option<[u8; HMAC_SALT_LEN]>,
        pub tpm_blob: Vec<u8>,
        pub wrapped_mvk_nonce: [u8; SLOT_NONCE_LEN],
        /// `KEK_factors`-sealed MVK + tag: exactly
        /// `KEY_LEN + SLOT_TAG_LEN = 48 bytes`.
        pub wrapped_mvk_ct_and_tag: [u8; KEY_LEN + SLOT_TAG_LEN],
    }

    impl Drop for SlotPayload {
        fn drop(&mut self) {
            // Best-effort cleanup. cred_id and tpm_blob may contain
            // device-bound material that doesn't break confidentiality
            // if leaked, but zeroizing is a defensive default.
            self.cred_id.zeroize();
            self.tpm_blob.zeroize();
            self.wrapped_mvk_nonce.zeroize();
            self.wrapped_mvk_ct_and_tag.zeroize();
            if let Some(salt) = self.hmac_salt.as_mut() {
                salt.zeroize();
            }
        }
    }

    impl SlotPayload {
        /// Construct a new payload, validating each field against its
        /// per-variant cap and the joint material budget. Returns
        /// `Error::InvalidField` on over-budget or
        /// `Error::InvalidField` on length-cap violations (cred_id >
        /// `CRED_ID_MAX_LEN`, tpm_blob > `TPM_BLOB_MAX_LEN`).
        pub fn new(
            kind: DeniableKindTag,
            cred_id: Vec<u8>,
            hmac_salt: Option<[u8; HMAC_SALT_LEN]>,
            tpm_blob: Vec<u8>,
            wrapped_mvk_nonce: [u8; SLOT_NONCE_LEN],
            wrapped_mvk_ct_and_tag: [u8; KEY_LEN + SLOT_TAG_LEN],
        ) -> Result<Self, Error> {
            if cred_id.len() > CRED_ID_MAX_LEN {
                return Err(Error::InvalidField);
            }
            if tpm_blob.len() > TPM_BLOB_MAX_LEN {
                return Err(Error::InvalidField);
            }
            let salt_len = if hmac_salt.is_some() {
                HMAC_SALT_LEN
            } else {
                0
            };
            let material = cred_id.len() + salt_len + tpm_blob.len();
            if material > MATERIAL_BUDGET {
                return Err(Error::InvalidField);
            }
            Ok(Self {
                kind,
                cred_id,
                hmac_salt,
                tpm_blob,
                wrapped_mvk_nonce,
                wrapped_mvk_ct_and_tag,
            })
        }

        /// Serialise the payload + random padding into a
        /// `PAYLOAD_PLAINTEXT_LEN`-byte buffer ready for AEAD-sealing
        /// with `KEK_envelope`. The trailing padding is filled with
        /// OS-RNG bytes so the envelope ciphertext is the same length
        /// regardless of variant - otherwise the envelope's length
        /// would leak the slot kind.
        pub fn encode(&self) -> Result<[u8; PAYLOAD_PLAINTEXT_LEN], Error> {
            let salt_len = if self.hmac_salt.is_some() {
                HMAC_SALT_LEN
            } else {
                0
            };
            let mut buf = [0u8; PAYLOAD_PLAINTEXT_LEN];
            // Fixed header.
            buf[0] = self.kind as u8;
            buf[1..3].copy_from_slice(&(self.cred_id.len() as u16).to_le_bytes());
            buf[3] = salt_len as u8;
            buf[4..6].copy_from_slice(&(self.tpm_blob.len() as u16).to_le_bytes());
            // bytes 6..8 reserved, already 0.

            // Variable material.
            let mut off = PAYLOAD_HEADER_LEN;
            buf[off..off + self.cred_id.len()].copy_from_slice(&self.cred_id);
            off += self.cred_id.len();
            if let Some(salt) = self.hmac_salt.as_ref() {
                buf[off..off + HMAC_SALT_LEN].copy_from_slice(salt);
                off += HMAC_SALT_LEN;
            }
            buf[off..off + self.tpm_blob.len()].copy_from_slice(&self.tpm_blob);
            off += self.tpm_blob.len();

            // Inner wrapped_mvk (nonce + ct + tag).
            buf[off..off + SLOT_NONCE_LEN].copy_from_slice(&self.wrapped_mvk_nonce);
            off += SLOT_NONCE_LEN;
            buf[off..off + KEY_LEN + SLOT_TAG_LEN].copy_from_slice(&self.wrapped_mvk_ct_and_tag);
            off += KEY_LEN + SLOT_TAG_LEN;

            // Trailing padding from OsRng so envelope length doesn't
            // leak variant identity via the visible ciphertext length.
            super::fill_random(&mut buf[off..])?;

            Ok(buf)
        }

        /// Parse the decrypted envelope plaintext back into a
        /// `SlotPayload`. Returns `Error::InvalidField` on any
        /// length-cap violation, unknown `kind`, or layout that runs
        /// past the buffer (a malicious envelope could otherwise
        /// claim absurd lengths).
        pub fn decode(buf: &[u8; PAYLOAD_PLAINTEXT_LEN]) -> Result<Self, Error> {
            let kind = DeniableKindTag::from_u8(buf[0]).ok_or(Error::InvalidField)?;
            let cred_id_len = u16::from_le_bytes([buf[1], buf[2]]) as usize;
            let hmac_salt_len = buf[3] as usize;
            let tpm_blob_len = u16::from_le_bytes([buf[4], buf[5]]) as usize;
            // bytes 6..8 reserved, must be 0 for forward-compat. A
            // future v2.1 may use them; for now reject non-zero as
            // a probable corruption.
            if buf[6] != 0 || buf[7] != 0 {
                return Err(Error::InvalidField);
            }

            // Length caps.
            if cred_id_len > CRED_ID_MAX_LEN {
                return Err(Error::InvalidField);
            }
            if !(hmac_salt_len == 0 || hmac_salt_len == HMAC_SALT_LEN) {
                return Err(Error::InvalidField);
            }
            if tpm_blob_len > TPM_BLOB_MAX_LEN {
                return Err(Error::InvalidField);
            }
            // Joint material budget.
            let material = cred_id_len + hmac_salt_len + tpm_blob_len;
            if material > MATERIAL_BUDGET {
                return Err(Error::InvalidField);
            }

            // Per-kind well-formedness: the kind tag declares which
            // material MUST be present. A tampered envelope that
            // tag-forged could claim an inconsistent shape (e.g.
            // `kind = Passphrase` but `cred_id_len = 64`), which
            // would still parse cleanly here. The per-variant create
            // / open flows enforce consistency at the call site; we
            // only check structural bounds here.
            let mut off = PAYLOAD_HEADER_LEN;
            let cred_id = buf[off..off + cred_id_len].to_vec();
            off += cred_id_len;

            let hmac_salt = if hmac_salt_len == HMAC_SALT_LEN {
                let mut s = [0u8; HMAC_SALT_LEN];
                s.copy_from_slice(&buf[off..off + HMAC_SALT_LEN]);
                off += HMAC_SALT_LEN;
                Some(s)
            } else {
                None
            };

            let tpm_blob = buf[off..off + tpm_blob_len].to_vec();
            off += tpm_blob_len;

            let mut wrapped_mvk_nonce = [0u8; SLOT_NONCE_LEN];
            wrapped_mvk_nonce.copy_from_slice(&buf[off..off + SLOT_NONCE_LEN]);
            off += SLOT_NONCE_LEN;

            let mut wrapped_mvk_ct_and_tag = [0u8; KEY_LEN + SLOT_TAG_LEN];
            wrapped_mvk_ct_and_tag.copy_from_slice(&buf[off..off + KEY_LEN + SLOT_TAG_LEN]);

            Ok(Self {
                kind,
                cred_id,
                hmac_salt,
                tpm_blob,
                wrapped_mvk_nonce,
                wrapped_mvk_ct_and_tag,
            })
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        fn dummy_payload(kind: DeniableKindTag) -> SlotPayload {
            let cred_id = match kind {
                DeniableKindTag::Fido2Passphrase
                | DeniableKindTag::TpmFido2Passphrase
                | DeniableKindTag::HybridPqFido2Passphrase
                | DeniableKindTag::HybridPqTpmFido2Passphrase => vec![0xaa; 64],
                _ => Vec::new(),
            };
            let hmac_salt = match kind {
                DeniableKindTag::Fido2Passphrase
                | DeniableKindTag::TpmFido2Passphrase
                | DeniableKindTag::HybridPqFido2Passphrase
                | DeniableKindTag::HybridPqTpmFido2Passphrase => Some([0xbb; HMAC_SALT_LEN]),
                _ => None,
            };
            let tpm_blob = match kind {
                DeniableKindTag::TpmPassphrase
                | DeniableKindTag::TpmFido2Passphrase
                | DeniableKindTag::HybridPqTpmPassphrase
                | DeniableKindTag::HybridPqTpmFido2Passphrase => vec![0xcc; 1800],
                _ => Vec::new(),
            };
            SlotPayload::new(
                kind,
                cred_id,
                hmac_salt,
                tpm_blob,
                [0xdd; SLOT_NONCE_LEN],
                [0xee; KEY_LEN + SLOT_TAG_LEN],
            )
            .expect("dummy payload fits in budget")
        }

        #[test]
        fn round_trip_every_kind() {
            for kind in [
                DeniableKindTag::Passphrase,
                DeniableKindTag::Fido2Passphrase,
                DeniableKindTag::TpmPassphrase,
                DeniableKindTag::TpmFido2Passphrase,
                DeniableKindTag::HybridPqPassphrase,
                DeniableKindTag::HybridPqFido2Passphrase,
                DeniableKindTag::HybridPqTpmPassphrase,
                DeniableKindTag::HybridPqTpmFido2Passphrase,
            ] {
                let p = dummy_payload(kind);
                let cred_id = p.cred_id.clone();
                let salt = p.hmac_salt;
                let blob = p.tpm_blob.clone();
                let nonce = p.wrapped_mvk_nonce;
                let ct = p.wrapped_mvk_ct_and_tag;
                let buf = p.encode().expect("encode succeeds");
                let dec = SlotPayload::decode(&buf).expect("decode succeeds");
                assert_eq!(dec.kind, kind);
                assert_eq!(dec.cred_id, cred_id);
                assert_eq!(dec.hmac_salt, salt);
                assert_eq!(dec.tpm_blob, blob);
                assert_eq!(dec.wrapped_mvk_nonce, nonce);
                assert_eq!(dec.wrapped_mvk_ct_and_tag, ct);
            }
        }

        #[test]
        fn encoded_length_is_constant_regardless_of_variant() {
            // Every variant encodes to exactly PAYLOAD_PLAINTEXT_LEN
            // bytes (random padding fills the rest). This is what
            // prevents the envelope ciphertext length from leaking
            // the slot kind.
            for kind in [
                DeniableKindTag::Passphrase,
                DeniableKindTag::Fido2Passphrase,
                DeniableKindTag::TpmPassphrase,
                DeniableKindTag::TpmFido2Passphrase,
                DeniableKindTag::HybridPqPassphrase,
                DeniableKindTag::HybridPqFido2Passphrase,
                DeniableKindTag::HybridPqTpmPassphrase,
                DeniableKindTag::HybridPqTpmFido2Passphrase,
            ] {
                let buf = dummy_payload(kind).encode().unwrap();
                assert_eq!(buf.len(), PAYLOAD_PLAINTEXT_LEN);
            }
        }

        #[test]
        fn over_budget_material_rejected_at_construct() {
            // 1024 + 32 + 3500 = 4556 > MATERIAL_BUDGET (4000).
            let err = SlotPayload::new(
                DeniableKindTag::TpmFido2Passphrase,
                vec![0; CRED_ID_MAX_LEN],
                Some([0; HMAC_SALT_LEN]),
                vec![0; TPM_BLOB_MAX_LEN],
                [0; SLOT_NONCE_LEN],
                [0; KEY_LEN + SLOT_TAG_LEN],
            )
            .err()
            .unwrap();
            assert!(matches!(err, Error::InvalidField));
        }

        #[test]
        fn over_long_cred_id_rejected() {
            let err = SlotPayload::new(
                DeniableKindTag::Fido2Passphrase,
                vec![0; CRED_ID_MAX_LEN + 1],
                Some([0; HMAC_SALT_LEN]),
                Vec::new(),
                [0; SLOT_NONCE_LEN],
                [0; KEY_LEN + SLOT_TAG_LEN],
            )
            .err()
            .unwrap();
            assert!(matches!(err, Error::InvalidField));
        }

        #[test]
        fn over_long_tpm_blob_rejected() {
            let err = SlotPayload::new(
                DeniableKindTag::TpmPassphrase,
                Vec::new(),
                None,
                vec![0; TPM_BLOB_MAX_LEN + 1],
                [0; SLOT_NONCE_LEN],
                [0; KEY_LEN + SLOT_TAG_LEN],
            )
            .err()
            .unwrap();
            assert!(matches!(err, Error::InvalidField));
        }

        #[test]
        fn decode_rejects_unknown_kind() {
            let mut buf = [0u8; PAYLOAD_PLAINTEXT_LEN];
            buf[0] = 0xff; // not a valid DeniableKindTag
            let err = SlotPayload::decode(&buf).err().unwrap();
            assert!(matches!(err, Error::InvalidField));
        }

        #[test]
        fn decode_rejects_nonzero_reserved_bytes() {
            // Encode a minimal passphrase payload then flip a
            // reserved byte; decode must reject.
            let mut buf = dummy_payload(DeniableKindTag::Passphrase).encode().unwrap();
            buf[6] = 1;
            let err = SlotPayload::decode(&buf).err().unwrap();
            assert!(matches!(err, Error::InvalidField));
        }

        #[test]
        fn decode_rejects_bad_hmac_salt_len() {
            let mut buf = dummy_payload(DeniableKindTag::Fido2Passphrase)
                .encode()
                .unwrap();
            buf[3] = 16; // valid values are 0 or 32
            let err = SlotPayload::decode(&buf).err().unwrap();
            assert!(matches!(err, Error::InvalidField));
        }

        #[test]
        fn decode_rejects_over_budget_lengths() {
            let mut buf = [0u8; PAYLOAD_PLAINTEXT_LEN];
            buf[0] = DeniableKindTag::TpmFido2Passphrase as u8;
            // cred_id_len = 1024 (max ok)
            buf[1..3].copy_from_slice(&(CRED_ID_MAX_LEN as u16).to_le_bytes());
            // hmac_salt_len = 32
            buf[3] = HMAC_SALT_LEN as u8;
            // tpm_blob_len = 3500 (max ok) - but joint = 1024 + 32 + 3500 = 4556 > 4000
            buf[4..6].copy_from_slice(&(TPM_BLOB_MAX_LEN as u16).to_le_bytes());
            let err = SlotPayload::decode(&buf).err().unwrap();
            assert!(matches!(err, Error::InvalidField));
        }
    }
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
    fn invariant_5_v2_domain_separation_distinct_factors_keks() {
        // INVARIANT 5 (v2): feeding the same secondary secrets through
        // different DeniableCredential variants yields cryptographically
        // independent KEK_factors. Reusing the same 32-byte secret as
        // both an hmac-secret output AND a TPM-unsealed input MUST
        // produce unequal factor KEKs for the relevant variants.
        let salt = test_salt();
        let secret = [0x99u8; 32];
        let other = [0xaau8; 32];
        let env_kek = KeyEncryptionKey::from_bytes([0x42u8; KEY_LEN]);

        let kek_fido2pp = DeniableCredential::Fido2Passphrase {
            passphrase: b"x",
            argon2: Argon2idParams::TEST_ONLY,
            hmac_secret_output: &secret,
        }
        .derive_factors_kek(&salt, &env_kek);

        let kek_tpmpp = DeniableCredential::TpmPassphrase {
            passphrase: b"x",
            argon2: Argon2idParams::TEST_ONLY,
            unsealed: &secret,
        }
        .derive_factors_kek(&salt, &env_kek);

        let kek_tpm_fido2pp = DeniableCredential::TpmFido2Passphrase {
            passphrase: b"x",
            argon2: Argon2idParams::TEST_ONLY,
            unsealed: &secret,
            hmac_secret_output: &other,
        }
        .derive_factors_kek(&salt, &env_kek);

        let kek_inner = inner_header_key(&MasterVolumeKey::from_bytes(secret), &salt);

        let pairs = [
            (
                "fido2pp vs tpmpp",
                kek_fido2pp.as_bytes(),
                kek_tpmpp.as_bytes(),
            ),
            (
                "fido2pp vs tpm+fido2pp",
                kek_fido2pp.as_bytes(),
                kek_tpm_fido2pp.as_bytes(),
            ),
            (
                "tpmpp vs tpm+fido2pp",
                kek_tpmpp.as_bytes(),
                kek_tpm_fido2pp.as_bytes(),
            ),
            (
                "fido2pp vs inner",
                kek_fido2pp.as_bytes(),
                kek_inner.as_bytes(),
            ),
            ("tpmpp vs inner", kek_tpmpp.as_bytes(), kek_inner.as_bytes()),
            (
                "tpm+fido2pp vs inner",
                kek_tpm_fido2pp.as_bytes(),
                kek_inner.as_bytes(),
            ),
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
    fn credential_envelope_kek_passphrase_round_trips() {
        let salt = test_salt();
        let cred = DeniableCredential::Passphrase {
            passphrase: b"hunter2",
            argon2: Argon2idParams::TEST_ONLY,
        };
        let kek_a = cred.derive_envelope_kek(&salt).unwrap();
        let kek_b = cred.derive_envelope_kek(&salt).unwrap();
        assert_eq!(
            kek_a.as_bytes(),
            kek_b.as_bytes(),
            "same credential + same salt must derive identical envelope KEKs",
        );
    }

    #[test]
    fn credential_factors_kek_all_variants_distinct() {
        // Identical secret material into every variant; the resulting
        // factor KEKs MUST all differ thanks to per-variant HKDF info
        // labels (security invariant #5 extended to the full
        // credential menu).
        let salt = test_salt();
        let env_kek = KeyEncryptionKey::from_bytes([0x42u8; KEY_LEN]);
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
                .derive_factors_kek(&salt, &env_kek)
                .as_bytes(),
            ),
            (
                "fido2+passphrase",
                *DeniableCredential::Fido2Passphrase {
                    passphrase: b"x",
                    argon2: Argon2idParams::TEST_ONLY,
                    hmac_secret_output: &secret,
                }
                .derive_factors_kek(&salt, &env_kek)
                .as_bytes(),
            ),
            (
                "tpm+passphrase",
                *DeniableCredential::TpmPassphrase {
                    passphrase: b"x",
                    argon2: Argon2idParams::TEST_ONLY,
                    unsealed: &secret,
                }
                .derive_factors_kek(&salt, &env_kek)
                .as_bytes(),
            ),
            (
                "tpm+fido2+passphrase",
                *DeniableCredential::TpmFido2Passphrase {
                    passphrase: b"x",
                    argon2: Argon2idParams::TEST_ONLY,
                    unsealed: &secret,
                    hmac_secret_output: &other,
                }
                .derive_factors_kek(&salt, &env_kek)
                .as_bytes(),
            ),
            (
                "pq+passphrase",
                *DeniableCredential::HybridPqPassphrase {
                    passphrase: b"x",
                    argon2: Argon2idParams::TEST_ONLY,
                    mlkem_shared: &secret,
                }
                .derive_factors_kek(&salt, &env_kek)
                .as_bytes(),
            ),
            (
                "pq+fido2+passphrase",
                *DeniableCredential::HybridPqFido2Passphrase {
                    passphrase: b"x",
                    argon2: Argon2idParams::TEST_ONLY,
                    mlkem_shared: &secret,
                    hmac_secret_output: &other,
                }
                .derive_factors_kek(&salt, &env_kek)
                .as_bytes(),
            ),
            (
                "pq+tpm+passphrase",
                *DeniableCredential::HybridPqTpmPassphrase {
                    passphrase: b"x",
                    argon2: Argon2idParams::TEST_ONLY,
                    mlkem_shared: &secret,
                    unsealed: &other,
                }
                .derive_factors_kek(&salt, &env_kek)
                .as_bytes(),
            ),
            (
                "pq+tpm+fido2+passphrase",
                *DeniableCredential::HybridPqTpmFido2Passphrase {
                    passphrase: b"x",
                    argon2: Argon2idParams::TEST_ONLY,
                    mlkem_shared: &secret,
                    unsealed: &other,
                    hmac_secret_output: &third,
                }
                .derive_factors_kek(&salt, &env_kek)
                .as_bytes(),
            ),
        ];

        for (i, (l_label, l_kek)) in keks.iter().enumerate() {
            for (r_label, r_kek) in keks.iter().skip(i + 1) {
                assert_ne!(
                    l_kek, r_kek,
                    "variants {} and {} produced identical factor KEKs - domain separation broken",
                    l_label, r_label,
                );
            }
        }
    }

    #[test]
    fn credential_envelope_kek_changes_per_salt() {
        let salt_a = test_salt();
        let mut salt_b = test_salt();
        salt_b[0] ^= 0xff;
        let cred = DeniableCredential::Passphrase {
            passphrase: b"hunter2",
            argon2: Argon2idParams::TEST_ONLY,
        };
        let kek_a = cred.derive_envelope_kek(&salt_a).unwrap();
        let kek_b = cred.derive_envelope_kek(&salt_b).unwrap();
        assert_ne!(
            kek_a.as_bytes(),
            kek_b.as_bytes(),
            "different vault salts must give different envelope KEKs",
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
            DeniableCredential::Fido2Passphrase {
                passphrase: b"x",
                argon2: Argon2idParams::TEST_ONLY,
                hmac_secret_output: &secret,
            }
            .label(),
            "fido2+passphrase",
        );
        assert_eq!(
            DeniableCredential::HybridPqTpmFido2Passphrase {
                passphrase: b"x",
                argon2: Argon2idParams::TEST_ONLY,
                mlkem_shared: &secret,
                unsealed: &secret,
                hmac_secret_output: &secret,
            }
            .label(),
            "pq+tpm+fido2+passphrase",
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
