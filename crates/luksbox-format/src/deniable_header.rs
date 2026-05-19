// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Penthertz <https://penthertz.com> (https://x.com/PentHertz)

//! High-level `DeniableHeader` type: serialise / parse the full 8 KiB
//! deniable-mode header (per-vault salt + slot table + AEAD-encrypted
//! inner header). Wraps the lower-level primitives in
//! `luksbox_core::deniable`.
//!
//! See `docs/DENIABLE_HEADER.md` for the on-disk layout and the five
//! normative security invariants. This file implements:
//!
//! - `DeniableHeader::create_with_passphrase` - generate fresh vault
//!   header, occupied slot 0 wraps the MVK with the passphrase KEK,
//!   slots 1..8 hold OsRng padding, inner header encrypted with the
//!   MVK-derived inner-header key.
//! - `DeniableHeader::open_with_passphrase` - takes 8 KiB on-disk
//!   bytes + user-supplied passphrase + Argon2id params + cipher
//!   suite, runs constant-time trial decryption across all 8 slots,
//!   decrypts the inner header on success, returns the recovered MVK
//!   and the parsed inner-header fields.
//!
//! All failure modes collapse into a single `Error::OpaqueUnlockFailed`
//! variant so an attacker observing error output learns nothing about
//! which stage failed (wrong passphrase vs wrong cipher vs wrong
//! Argon2 params vs corrupt inner header all read the same).

#[cfg(test)]
use luksbox_core::Argon2idParams;
use luksbox_core::deniable::{
    self, DENIABLE_AAD_PREFIX, DENIABLE_HEADER_SIZE, DENIABLE_INNER_OFFSET, DENIABLE_INNER_SIZE,
    DENIABLE_SALT_SIZE, DENIABLE_SLOT_COUNT, DENIABLE_SLOT_SIZE, DENIABLE_SLOT_TABLE_OFFSET,
    SLOT_NONCE_LEN, SLOT_TAG_LEN,
};
use luksbox_core::{CipherSuite, KdfId, MasterVolumeKey, aead};
use subtle::{Choice, ConditionallySelectable, ConstantTimeEq};
use zeroize::Zeroizing;

use crate::error::Error;

/// Plaintext fields of the encrypted inner header. Kept in plain
/// memory (not zeroized) because none of these are secret on their
/// own; the secret is the MVK that decrypts the AEAD blob holding
/// them. Stable on-disk shape - field order matches the wire layout
/// in `serialise_inner` / `parse_inner`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DeniableInnerHeader {
    /// Format minor version. Major version is implicit ("v1"),
    /// encoded only in the HKDF info labels and AAD prefix.
    pub format_version_minor: u16,
    pub cipher_suite: CipherSuite,
    pub kdf_id: KdfId,
    pub flags: u32,
    pub metadata_offset: u64,
    pub metadata_size: u64,
    pub data_offset: u64,
    /// Chunk size in bytes. Always 4096 for v1; field is present so a
    /// future format can change it without re-encoding.
    pub chunk_size: u32,
}

/// Static prefix for the inner-header AEAD AAD. The full AAD is
/// `INNER_AAD_PREFIX || per_vault_salt`, built per call via
/// `inner_header_aad()`. The per-vault salt is already in the
/// inner-header KEK derivation (HKDF salt input) so this is
/// belt-and-suspenders: future MVK-reuse scenarios that would
/// otherwise allow swapping inner headers between vaults are
/// rejected by the AAD check too.
const INNER_AAD_PREFIX: &[u8] = b"luksbox-deniable-v2/inner-header-aad";

/// Build the inner-header AEAD AAD: `INNER_AAD_PREFIX || per_vault_salt`.
/// Used by create / open / rotate so an inner-header ciphertext
/// from one vault cannot decrypt against another vault's MVK even
/// if the MVK is somehow shared.
fn inner_header_aad(per_vault_salt: &[u8; DENIABLE_SALT_SIZE]) -> Vec<u8> {
    let mut aad = Vec::with_capacity(INNER_AAD_PREFIX.len() + DENIABLE_SALT_SIZE);
    aad.extend_from_slice(INNER_AAD_PREFIX);
    aad.extend_from_slice(per_vault_salt);
    aad
}

/// Plaintext size of the inner header (bytes). 28 bytes of AEAD
/// overhead (12 nonce + 16 tag) inside a 4064-byte region leaves
/// 4036 bytes for the plaintext. Compile-time-asserted below.
const INNER_PLAINTEXT_LEN: usize = DENIABLE_INNER_SIZE - SLOT_NONCE_LEN - SLOT_TAG_LEN;

/// Result of opening a deniable header.
pub struct OpenedDeniableHeader {
    pub mvk: MasterVolumeKey,
    pub inner: DeniableInnerHeader,
    /// The 32-byte per-vault salt read from offset 0. Caller may need
    /// this to derive secondary keys (metadata-region keys etc.).
    pub per_vault_salt: [u8; DENIABLE_SALT_SIZE],
    /// Slot index whose AEAD decryption produced the MVK. The
    /// admin needs to know this to (a) avoid overwriting their own
    /// unlock slot when enrolling additional credentials, and (b)
    /// surface it in the UI as "Slot N (your credential)". Visible
    /// only to whoever holds the credential that opened the vault;
    /// an external observer cannot infer slot occupancy.
    pub matched_slot_idx: usize,
}

const _: () = assert!(DENIABLE_HEADER_SIZE == 36864);
const _: () = assert!(INNER_PLAINTEXT_LEN == 4036);

/// Serialised size of the inner header's public fields. Stable
/// on-disk shape -- also stable on the wire when the GUI hands off
/// deniable state to the FUSE-T mount helper subprocess.
pub const DENIABLE_INNER_HEADER_SERIALIZED_LEN: usize = 38;

impl DeniableInnerHeader {
    /// Public serialiser: writes the 38-byte stable wire form of
    /// the inner header. Used by the mount-helper handoff protocol
    /// to pass the already-decrypted inner header from the
    /// unlocked-in-parent Container to the helper subprocess (the
    /// helper can't re-decrypt it without the credential).
    pub fn serialise_for_handoff(&self) -> [u8; DENIABLE_INNER_HEADER_SERIALIZED_LEN] {
        let z = self.serialise();
        let mut out = [0u8; DENIABLE_INNER_HEADER_SERIALIZED_LEN];
        out.copy_from_slice(&z[..DENIABLE_INNER_HEADER_SERIALIZED_LEN]);
        out
    }

    /// Public parser: same shape as `serialise_for_handoff`. Mirror
    /// of the disk-form parse (`parse`) with the same field-by-field
    /// sanity checks so a malformed handoff buffer can never produce
    /// an out-of-range inner header that downstream code trusts.
    pub fn parse_from_handoff(
        buf: &[u8; DENIABLE_INNER_HEADER_SERIALIZED_LEN],
    ) -> Result<Self, Error> {
        Self::parse(buf)
    }

    fn serialise(&self) -> Zeroizing<Vec<u8>> {
        let mut out = Zeroizing::new(vec![0u8; INNER_PLAINTEXT_LEN]);
        out[0..2].copy_from_slice(&self.format_version_minor.to_le_bytes());
        out[2..4].copy_from_slice(&(self.cipher_suite as u16).to_le_bytes());
        out[4..6].copy_from_slice(&(self.kdf_id as u16).to_le_bytes());
        out[6..10].copy_from_slice(&self.flags.to_le_bytes());
        out[10..18].copy_from_slice(&self.metadata_offset.to_le_bytes());
        out[18..26].copy_from_slice(&self.metadata_size.to_le_bytes());
        out[26..34].copy_from_slice(&self.data_offset.to_le_bytes());
        out[34..38].copy_from_slice(&self.chunk_size.to_le_bytes());
        // bytes 38..INNER_PLAINTEXT_LEN are zero padding. The whole
        // buffer is wrapped in Zeroizing so even the padding is wiped
        // on drop in case it later carries sensitive data.
        out
    }

    fn parse(buf: &[u8]) -> Result<Self, Error> {
        if buf.len() < 38 {
            return Err(Error::Crypto(luksbox_core::Error::BufferTooShort {
                expected: 38,
                got: buf.len(),
            }));
        }
        let format_version_minor = u16::from_le_bytes(buf[0..2].try_into().unwrap());
        let cipher_suite = CipherSuite::from_u16(u16::from_le_bytes(buf[2..4].try_into().unwrap()))
            .map_err(Error::Crypto)?;
        let kdf_id = KdfId::from_u16(u16::from_le_bytes(buf[4..6].try_into().unwrap()))
            .map_err(Error::Crypto)?;
        let flags = u32::from_le_bytes(buf[6..10].try_into().unwrap());
        let metadata_offset = u64::from_le_bytes(buf[10..18].try_into().unwrap());
        let metadata_size = u64::from_le_bytes(buf[18..26].try_into().unwrap());
        let data_offset = u64::from_le_bytes(buf[26..34].try_into().unwrap());
        let chunk_size = u32::from_le_bytes(buf[34..38].try_into().unwrap());

        // DoS / sanity guards on attacker-controllable fields. An
        // adversary who somehow recovers the MVK + tag-forges a
        // crafted inner header could otherwise drive ridiculous
        // allocations or seek positions in downstream code; cap them
        // at values comfortably above any honest vault.
        if metadata_size > luksbox_core::header::MAX_METADATA_SIZE {
            return Err(Error::Crypto(luksbox_core::Error::InvalidField));
        }
        // Chunk size must be a small power of two between 512 B and 64 KiB.
        // Standard vaults use exactly 4096; rejecting outside that
        // envelope keeps `vfs` allocations bounded.
        if !matches!(
            chunk_size,
            512 | 1024 | 2048 | 4096 | 8192 | 16384 | 32768 | 65536
        ) {
            return Err(Error::Crypto(luksbox_core::Error::InvalidField));
        }
        // data_offset > metadata_offset always (data follows metadata).
        if data_offset < metadata_offset.saturating_add(metadata_size) {
            return Err(Error::Crypto(luksbox_core::Error::InvalidField));
        }
        // metadata_offset must be >= DENIABLE_HEADER_SIZE (header
        // occupies the first 8 KiB).
        if metadata_offset < DENIABLE_HEADER_SIZE as u64 {
            return Err(Error::Crypto(luksbox_core::Error::InvalidField));
        }

        Ok(DeniableInnerHeader {
            format_version_minor,
            cipher_suite,
            kdf_id,
            flags,
            metadata_offset,
            metadata_size,
            data_offset,
            chunk_size,
        })
    }
}

// v1 `create_with_passphrase` and `open_with_passphrase` were removed
// in v2; callers use `create_with_credential_v2` and
// `try_open_envelope_v2` + `complete_open_v2` instead, which encode
// the two-layer envelope and embedded material.

/// Helper - re-export the AAD prefix for callers that need to bind
/// downstream blobs to the same vault identity (e.g. metadata region
/// AEAD that wants to be tied to this specific header).
pub const AAD_PREFIX: &[u8] = DENIABLE_AAD_PREFIX;

// ============================================================
// v2 two-layer envelope: create / open with embedded material
// ============================================================

/// AAD bound into the inner `wrapped_mvk` AEAD (v2 only). Distinct
/// from the outer envelope AAD via a suffix so a forged outer
/// envelope cannot replay an inner ciphertext from another slot.
const INNER_SLOT_AAD_PREFIX: &[u8] = b"luksbox-deniable-v2/inner-slot";

fn inner_slot_aad(per_vault_salt: &[u8; DENIABLE_SALT_SIZE], slot_idx: usize) -> Vec<u8> {
    assert!(slot_idx < DENIABLE_SLOT_COUNT);
    let mut aad = Vec::with_capacity(INNER_SLOT_AAD_PREFIX.len() + DENIABLE_SALT_SIZE + 1);
    aad.extend_from_slice(INNER_SLOT_AAD_PREFIX);
    aad.extend_from_slice(per_vault_salt);
    aad.push(slot_idx as u8);
    aad
}

/// Plain-language material the caller provides to the v2 create
/// flow. The host has already enrolled the FIDO2 credential / sealed
/// the TPM blob / done the ML-KEM encap; these are the resulting
/// non-secret bytes that need to live inside the slot envelope.
#[derive(Debug, Default)]
pub struct DeniableMaterial {
    /// FIDO2 credential id. Empty if the slot does not bind a FIDO2
    /// factor.
    pub cred_id: Vec<u8>,
    /// FIDO2 hmac-secret salt. `None` if the slot does not bind a
    /// FIDO2 factor; `Some` if it does. The host generated this as
    /// fresh randomness at enroll time and will replay it to the
    /// authenticator at each unlock.
    pub hmac_salt: Option<[u8; 32]>,
    /// TPM2 sealed blob. Empty if the slot does not bind a TPM
    /// factor.
    pub tpm_blob: Vec<u8>,
}

impl DeniableMaterial {
    /// Convenience: passphrase-only slot has no material.
    pub fn passphrase_only() -> Self {
        Self::default()
    }
}

/// Build a fresh v2 deniable header with `slot_idx` occupied by a
/// two-layer envelope wrapping `material` + the MVK.
///
/// Steps:
/// 1. Generate per-vault salt + MVK + inner-header nonce.
/// 2. Derive `KEK_envelope` from passphrase, `KEK_factors` from
///    `(envelope_kek || secondaries)`.
/// 3. AEAD-seal the MVK with `KEK_factors` (inner ct + tag = 48 B).
/// 4. Build the slot payload (`SlotPayload`): kind tag, material,
///    inner wrapped_mvk, random padding to 4068 B.
/// 5. AEAD-seal the payload with `KEK_envelope` (outer ct + tag =
///    4084 B). Prefix with envelope nonce (12 B) to fill the 4096 B
///    slot exactly.
/// 6. Fill the other 7 slots with fresh OsRng so they are
///    indistinguishable from occupied envelopes.
/// 7. AEAD-seal the inner header (cipher_suite, kdf_id, offsets)
///    with the MVK-derived inner-header key.
pub fn create_with_credential_v2(
    credential: &luksbox_core::deniable::DeniableCredential,
    material: &DeniableMaterial,
    slot_idx: usize,
    cipher_suite: CipherSuite,
    inner: DeniableInnerHeader,
) -> Result<(Vec<u8>, MasterVolumeKey), Error> {
    use luksbox_core::deniable::{
        DENIABLE_SLOT_COUNT,
        slot_payload::{PAYLOAD_PLAINTEXT_LEN, SlotPayload},
    };

    if slot_idx >= DENIABLE_SLOT_COUNT {
        return Err(Error::Crypto(luksbox_core::Error::InvalidKeyslotIndex(
            slot_idx,
        )));
    }

    // Kind tag is mandatory for v2 - rejects v1 passphraseless
    // variants up-front with a clean structural error rather than
    // building a corrupt slot.
    let kind = credential.kind_tag();

    let mut per_vault_salt = [0u8; DENIABLE_SALT_SIZE];
    deniable::fill_random(&mut per_vault_salt).map_err(Error::Crypto)?;

    let mvk = MasterVolumeKey::try_random()
        .map_err(|e| Error::Crypto(luksbox_core::Error::OsRng(e.to_string())))?;

    // Step 2: derive envelope + factors KEKs.
    let env_kek = credential
        .derive_envelope_kek(&per_vault_salt)
        .map_err(Error::Crypto)?;
    let factors_kek = credential.derive_factors_kek(&per_vault_salt, &env_kek);

    // Step 3: seal the MVK with KEK_factors.
    let mut wrapped_mvk_nonce = [0u8; SLOT_NONCE_LEN];
    deniable::fill_random(&mut wrapped_mvk_nonce).map_err(Error::Crypto)?;
    let inner_aad = inner_slot_aad(&per_vault_salt, slot_idx);
    let wrapped_mvk_ct = luksbox_core::aead::seal(
        cipher_suite,
        factors_kek.as_bytes(),
        &wrapped_mvk_nonce,
        &inner_aad,
        mvk.as_bytes(),
    )
    .map_err(Error::Crypto)?;
    debug_assert_eq!(
        wrapped_mvk_ct.len(),
        luksbox_core::key::KEY_LEN + SLOT_TAG_LEN
    );
    let mut wrapped_mvk_arr = [0u8; 48];
    wrapped_mvk_arr.copy_from_slice(&wrapped_mvk_ct);

    // Step 4: build payload.
    let payload = SlotPayload::new(
        kind,
        material.cred_id.clone(),
        material.hmac_salt,
        material.tpm_blob.clone(),
        wrapped_mvk_nonce,
        wrapped_mvk_arr,
    )
    .map_err(Error::Crypto)?;
    let payload_bytes = payload.encode().map_err(Error::Crypto)?;
    debug_assert_eq!(payload_bytes.len(), PAYLOAD_PLAINTEXT_LEN);

    // Step 5: seal payload with KEK_envelope.
    let mut env_nonce = [0u8; SLOT_NONCE_LEN];
    deniable::fill_random(&mut env_nonce).map_err(Error::Crypto)?;
    let outer_aad = deniable::slot_aad(&per_vault_salt, slot_idx);
    let env_ct = luksbox_core::aead::seal(
        cipher_suite,
        env_kek.as_bytes(),
        &env_nonce,
        &outer_aad,
        &payload_bytes,
    )
    .map_err(Error::Crypto)?;
    debug_assert_eq!(env_ct.len(), PAYLOAD_PLAINTEXT_LEN + SLOT_TAG_LEN);

    // Build slot bytes: nonce || env_ct (fills slot exactly).
    let mut slots = vec![[0u8; DENIABLE_SLOT_SIZE]; DENIABLE_SLOT_COUNT];
    for slot in slots.iter_mut() {
        deniable::fill_random(slot).map_err(Error::Crypto)?;
    }
    let target = &mut slots[slot_idx];
    target[..SLOT_NONCE_LEN].copy_from_slice(&env_nonce);
    target[SLOT_NONCE_LEN..SLOT_NONCE_LEN + env_ct.len()].copy_from_slice(&env_ct);
    debug_assert_eq!(SLOT_NONCE_LEN + env_ct.len(), DENIABLE_SLOT_SIZE);

    // Step 7: seal the inner header with MVK-derived key.
    let inner_pt = inner.serialise();
    let inner_key = deniable::inner_header_key(&mvk, &per_vault_salt);
    let mut inner_nonce = [0u8; SLOT_NONCE_LEN];
    deniable::fill_random(&mut inner_nonce).map_err(Error::Crypto)?;
    let inner_aad_bytes = inner_header_aad(&per_vault_salt);
    let inner_ct = aead::seal(
        cipher_suite,
        inner_key.as_bytes(),
        &inner_nonce,
        &inner_aad_bytes,
        &inner_pt,
    )
    .map_err(Error::Crypto)?;

    // Assemble final 36864-byte header.
    let mut header = vec![0u8; DENIABLE_HEADER_SIZE];
    header[..DENIABLE_SALT_SIZE].copy_from_slice(&per_vault_salt);
    for (i, slot) in slots.iter().enumerate() {
        let off = DENIABLE_SLOT_TABLE_OFFSET + i * DENIABLE_SLOT_SIZE;
        header[off..off + DENIABLE_SLOT_SIZE].copy_from_slice(slot);
    }
    header[DENIABLE_INNER_OFFSET..DENIABLE_INNER_OFFSET + SLOT_NONCE_LEN]
        .copy_from_slice(&inner_nonce);
    let ct_off = DENIABLE_INNER_OFFSET + SLOT_NONCE_LEN;
    header[ct_off..ct_off + inner_ct.len()].copy_from_slice(&inner_ct);

    Ok((header, mvk))
}

/// Intermediate state after v2 envelope discovery. Hand this to
/// `complete_open_v2` together with a fully-populated
/// `DeniableCredential` (one that includes the secondaries the
/// caller derived from the payload's `cred_id` / `hmac_salt` /
/// `tpm_blob`).
pub struct OpenedDeniableEnvelope {
    pub envelope_kek: luksbox_core::KeyEncryptionKey,
    pub per_vault_salt: [u8; DENIABLE_SALT_SIZE],
    pub matched_slot_idx: usize,
    pub payload: luksbox_core::deniable::slot_payload::SlotPayload,
    /// Inner-header bytes (nonce + ciphertext + tag) carved out of
    /// the on-disk header. Hand back to `complete_open_v2` so the
    /// MVK can decrypt the inner header without re-reading the file.
    pub inner_header_region: Vec<u8>,
}

/// Phase 1 of v2 open: derive `KEK_envelope` from the passphrase,
/// constant-time trial-decrypt the 8 slot envelopes, return the
/// matched slot's payload (which exposes the slot kind +
/// authenticator material the caller needs to drive secondaries).
///
/// `passphrase` and `argon2` are pulled from the supplied credential
/// (any v2 `*Passphrase` variant works as a discovery key here;
/// secondaries inside the credential are ignored at this phase).
pub fn try_open_envelope_v2(
    header_bytes: &[u8],
    credential: &luksbox_core::deniable::DeniableCredential,
    cipher_suite: CipherSuite,
    want_kind: Option<luksbox_core::deniable::DeniableKindTag>,
) -> Result<OpenedDeniableEnvelope, Error> {
    use luksbox_core::deniable::{DENIABLE_SLOT_COUNT, slot_payload::SlotPayload};

    if header_bytes.len() < DENIABLE_HEADER_SIZE {
        return Err(Error::OpaqueUnlockFailed);
    }

    let header: &[u8; DENIABLE_HEADER_SIZE] =
        header_bytes[..DENIABLE_HEADER_SIZE].try_into().unwrap();
    let mut per_vault_salt = [0u8; DENIABLE_SALT_SIZE];
    per_vault_salt.copy_from_slice(&header[..DENIABLE_SALT_SIZE]);

    // Derive envelope KEK; v1 passphraseless variants fail here as
    // they have no passphrase.
    let env_kek = match credential.derive_envelope_kek(&per_vault_salt) {
        Ok(k) => k,
        Err(_) => return Err(Error::OpaqueUnlockFailed),
    };

    // Round 12 fix R12-01: constant-time envelope discovery.
    //
    // Earlier implementations branched on AEAD-open success, pushed
    // matches into a heap Vec, and ran `SlotPayload::decode` only on
    // successful slots. Heap-allocator activity and per-iteration
    // wall-clock then depended on (a) whether any slot matched and
    // (b) WHICH slot matched, leaking the slot index via dudect.
    //
    // The pattern below performs IDENTICAL work for every slot
    // inside the loop:
    //  - Always run `aead::open` (RustCrypto AEAD primitives are
    //    constant-time on tag verification; the only success/failure
    //    asymmetry is the success path's Vec allocation, which
    //    happens BEFORE the tag check inside the upstream impl).
    //  - Always allocate a fixed-size plaintext scratch buffer.
    //  - Always memcpy `PAYLOAD_PLAINTEXT_LEN` bytes into it (real
    //    plaintext on AEAD success, zero pad on failure) using
    //    `subtle::Choice` driven byte selection so the write itself
    //    is unconditional.
    //  - Track AEAD-OK and kind-match as `subtle::Choice` (0/1).
    //
    // Decoding into the variable-length `SlotPayload` (which owns
    // heap-allocated `Vec<u8>` for cred_id / tpm_blob) is deferred
    // to AFTER the loop, run exactly ONCE on the constant-time-chosen
    // slot's plaintext. That way the heap-allocator activity is the
    // same regardless of which slot index matched.
    const PT_LEN: usize = luksbox_core::deniable::slot_payload::PAYLOAD_PLAINTEXT_LEN;
    // Production phase-1 callers pass the user's intended unlock
    // kind via `want_kind`. They CANNOT pass it through
    // `credential.kind_tag()` because they construct a
    // passphrase-only `DeniableCredential::Passphrase` here --
    // they don't yet have the FIDO2 / TPM / ML-KEM secondaries
    // that distinguish the higher variants. If callers relied on
    // credential.kind_tag() instead, kind-preference below would
    // always pick a Passphrase slot, so a freshly-enrolled FIDO2 /
    // TPM / hybrid-PQ slot whose envelope passphrase matches an
    // existing Passphrase slot 0 would never win discovery and the
    // wizard / GUI would surface "credential kind mismatch (vault
    // expects a different variant)".
    //
    // Tests / fuzzers / benches pass `None`, which means
    // "fall back to credential.kind_tag() (legacy v2 behavior)".
    // That is safe in those contexts because they build a
    // fully-typed credential with all secondaries up front, so
    // kind_tag() is already correct.
    let want_kind_u8: u8 = want_kind.unwrap_or_else(|| credential.kind_tag()).into();

    let mut all_pt: [Zeroizing<[u8; PT_LEN]>; DENIABLE_SLOT_COUNT] =
        std::array::from_fn(|_| Zeroizing::new([0u8; PT_LEN]));
    let mut ok_any: [Choice; DENIABLE_SLOT_COUNT] = [Choice::from(0u8); DENIABLE_SLOT_COUNT];
    let mut ok_kind: [Choice; DENIABLE_SLOT_COUNT] = [Choice::from(0u8); DENIABLE_SLOT_COUNT];

    for slot_idx in 0..DENIABLE_SLOT_COUNT {
        let off = DENIABLE_SLOT_TABLE_OFFSET + slot_idx * DENIABLE_SLOT_SIZE;
        let slot = &header[off..off + DENIABLE_SLOT_SIZE];
        let env_nonce: [u8; SLOT_NONCE_LEN] = slot[..SLOT_NONCE_LEN].try_into().unwrap();
        let env_ct = &slot[SLOT_NONCE_LEN..];
        let outer_aad = deniable::slot_aad(&per_vault_salt, slot_idx);

        // Always allocate scratch for the AEAD result so the success
        // path doesn't burn an extra Vec allocation visible to the
        // allocator. RustCrypto's AEAD impls don't expose an in-place
        // open API for our wrapper, so we accept the upstream Vec
        // alloc and memcpy out in fixed-size form below.
        let pt_res = aead::open(
            cipher_suite,
            env_kek.as_bytes(),
            &env_nonce,
            &outer_aad,
            env_ct,
        );

        // Unconditional fixed-size copy. On AEAD success, source is
        // the returned plaintext; on failure, source is a stack
        // zero buffer. Either way we write PT_LEN bytes into all_pt.
        let zero_src = [0u8; PT_LEN];
        let mut src_bytes: Zeroizing<Vec<u8>> = Zeroizing::new(vec![0u8; PT_LEN]);
        let aead_ok = match pt_res {
            Ok(v) if v.len() == PT_LEN => {
                src_bytes.copy_from_slice(&v[..]);
                Choice::from(1u8)
            }
            _ => {
                src_bytes.copy_from_slice(&zero_src[..]);
                Choice::from(0u8)
            }
        };
        all_pt[slot_idx].copy_from_slice(&src_bytes[..]);

        // Kind-byte match. SlotPayload's wire layout puts the kind
        // byte at offset 0; if AEAD failed, all_pt[slot_idx][0] == 0
        // which doesn't match any valid DeniableKindTag (range 1..=8)
        // so kind_match collapses to 0.
        let kind_byte = all_pt[slot_idx][0];
        let kind_match = kind_byte.ct_eq(&want_kind_u8);

        ok_any[slot_idx] = aead_ok;
        ok_kind[slot_idx] = aead_ok & kind_match;
    }

    // Constant-time pick:
    //  - matched_slot_idx defaults to 0.
    //  - Reverse-sweep so the FIRST matching slot wins (reverse so
    //    earlier indices overwrite later picks, matching the legacy
    //    behaviour).
    //  - Prefer ok_kind hits; fall back to ok_any so
    //    `complete_open_v2`'s kind-mismatch error path fires
    //    deterministically (preserves the legacy fallback semantic).
    let mut matched_slot_idx_u8: u8 = 0;
    let mut found_kind = Choice::from(0u8);
    for i in (0..DENIABLE_SLOT_COUNT).rev() {
        let i_u8 = i as u8;
        let pick = ok_kind[i];
        matched_slot_idx_u8 = u8::conditional_select(&matched_slot_idx_u8, &i_u8, pick);
        found_kind |= pick;
    }
    let mut matched_slot_idx_any_u8: u8 = 0;
    let mut found_any = Choice::from(0u8);
    for i in (0..DENIABLE_SLOT_COUNT).rev() {
        let i_u8 = i as u8;
        let pick = ok_any[i];
        matched_slot_idx_any_u8 = u8::conditional_select(&matched_slot_idx_any_u8, &i_u8, pick);
        found_any |= pick;
    }
    matched_slot_idx_u8 =
        u8::conditional_select(&matched_slot_idx_any_u8, &matched_slot_idx_u8, found_kind);

    // No slot matched at all -> opaque failure.
    if bool::from(!found_any) {
        return Err(Error::OpaqueUnlockFailed);
    }

    let matched_slot_idx = matched_slot_idx_u8 as usize;

    // Decode the chosen slot's plaintext once. Variable-length heap
    // allocations (cred_id / tpm_blob Vecs) happen here, exactly
    // once, on a single fixed-position buffer. The allocator pattern
    // is the same regardless of which slot index won the constant-
    // time pick.
    let payload =
        SlotPayload::decode(&*all_pt[matched_slot_idx]).map_err(|_| Error::OpaqueUnlockFailed)?;

    // Carve inner header region for phase 2.
    let inner_region = header[DENIABLE_INNER_OFFSET..].to_vec();

    Ok(OpenedDeniableEnvelope {
        envelope_kek: env_kek,
        per_vault_salt,
        matched_slot_idx,
        payload,
        inner_header_region: inner_region,
    })
}

/// Phase 2 of v2 open: given the envelope output + a credential
/// containing the secondaries the caller derived from the payload
/// (e.g. host already drove FIDO2 / TPM / ML-KEM), derive
/// `KEK_factors`, unwrap the inner MVK, decrypt the inner header.
///
/// The `credential.kind_tag()` MUST match `opened.payload.kind` or
/// this returns `Error::OpaqueUnlockFailed` (the caller asked for a
/// variant that does not match what the slot actually carries).
pub fn complete_open_v2(
    opened: OpenedDeniableEnvelope,
    credential: &luksbox_core::deniable::DeniableCredential,
    cipher_suite: CipherSuite,
) -> Result<OpenedDeniableHeader, Error> {
    // Variant cross-check.
    if credential.kind_tag() != opened.payload.kind {
        return Err(Error::OpaqueUnlockFailed);
    }

    // Derive factors KEK and unwrap the inner MVK.
    let factors_kek = credential.derive_factors_kek(&opened.per_vault_salt, &opened.envelope_kek);
    let inner_aad = inner_slot_aad(&opened.per_vault_salt, opened.matched_slot_idx);
    let mvk_pt = match luksbox_core::aead::open(
        cipher_suite,
        factors_kek.as_bytes(),
        &opened.payload.wrapped_mvk_nonce,
        &inner_aad,
        &opened.payload.wrapped_mvk_ct_and_tag,
    ) {
        Ok(pt) => Zeroizing::new(pt),
        Err(_) => return Err(Error::OpaqueUnlockFailed),
    };
    if mvk_pt.len() != luksbox_core::key::KEY_LEN {
        return Err(Error::OpaqueUnlockFailed);
    }
    let mut mvk_bytes = [0u8; luksbox_core::key::KEY_LEN];
    mvk_bytes.copy_from_slice(&mvk_pt);
    let mvk = MasterVolumeKey::from_bytes(mvk_bytes);

    // Decrypt and parse inner header.
    if opened.inner_header_region.len() < DENIABLE_INNER_SIZE {
        return Err(Error::OpaqueUnlockFailed);
    }
    let nonce: [u8; SLOT_NONCE_LEN] = opened.inner_header_region[..SLOT_NONCE_LEN]
        .try_into()
        .unwrap();
    let inner_ct = &opened.inner_header_region[SLOT_NONCE_LEN..DENIABLE_INNER_SIZE];
    let inner_key = deniable::inner_header_key(&mvk, &opened.per_vault_salt);
    let inner_aad_bytes = inner_header_aad(&opened.per_vault_salt);
    let inner_pt = match aead::open(
        cipher_suite,
        inner_key.as_bytes(),
        &nonce,
        &inner_aad_bytes,
        inner_ct,
    ) {
        Ok(pt) => Zeroizing::new(pt),
        Err(_) => return Err(Error::OpaqueUnlockFailed),
    };
    let inner = DeniableInnerHeader::parse(&inner_pt).map_err(|_| Error::OpaqueUnlockFailed)?;

    Ok(OpenedDeniableHeader {
        mvk,
        inner,
        per_vault_salt: opened.per_vault_salt,
        matched_slot_idx: opened.matched_slot_idx,
    })
}

/// Install a v2 slot into an existing header. Used by
/// `Container::enroll_*_deniable` to add a new credential to a
/// vault. Caller already opened the vault (has the MVK) and supplies
/// (a) the new credential, (b) the material to embed, (c) the
/// target slot index.
pub fn install_slot_v2(
    header_bytes: &mut [u8; DENIABLE_HEADER_SIZE],
    slot_idx: usize,
    credential: &luksbox_core::deniable::DeniableCredential,
    material: &DeniableMaterial,
    mvk: &MasterVolumeKey,
    cipher_suite: CipherSuite,
    per_vault_salt: &[u8; DENIABLE_SALT_SIZE],
) -> Result<(), Error> {
    use luksbox_core::deniable::{DENIABLE_SLOT_COUNT, slot_payload::SlotPayload};

    if slot_idx >= DENIABLE_SLOT_COUNT {
        return Err(Error::Crypto(luksbox_core::Error::InvalidKeyslotIndex(
            slot_idx,
        )));
    }
    let kind = credential.kind_tag();

    let env_kek = credential
        .derive_envelope_kek(per_vault_salt)
        .map_err(Error::Crypto)?;
    let factors_kek = credential.derive_factors_kek(per_vault_salt, &env_kek);

    // Seal MVK with factors KEK.
    let mut wrapped_mvk_nonce = [0u8; SLOT_NONCE_LEN];
    deniable::fill_random(&mut wrapped_mvk_nonce).map_err(Error::Crypto)?;
    let inner_aad = inner_slot_aad(per_vault_salt, slot_idx);
    let wrapped_mvk_ct = luksbox_core::aead::seal(
        cipher_suite,
        factors_kek.as_bytes(),
        &wrapped_mvk_nonce,
        &inner_aad,
        mvk.as_bytes(),
    )
    .map_err(Error::Crypto)?;
    let mut wrapped_mvk_arr = [0u8; 48];
    wrapped_mvk_arr.copy_from_slice(&wrapped_mvk_ct);

    let payload = SlotPayload::new(
        kind,
        material.cred_id.clone(),
        material.hmac_salt,
        material.tpm_blob.clone(),
        wrapped_mvk_nonce,
        wrapped_mvk_arr,
    )
    .map_err(Error::Crypto)?;
    let payload_bytes = payload.encode().map_err(Error::Crypto)?;

    let mut env_nonce = [0u8; SLOT_NONCE_LEN];
    deniable::fill_random(&mut env_nonce).map_err(Error::Crypto)?;
    let outer_aad = deniable::slot_aad(per_vault_salt, slot_idx);
    let env_ct = luksbox_core::aead::seal(
        cipher_suite,
        env_kek.as_bytes(),
        &env_nonce,
        &outer_aad,
        &payload_bytes,
    )
    .map_err(Error::Crypto)?;

    let off = DENIABLE_SLOT_TABLE_OFFSET + slot_idx * DENIABLE_SLOT_SIZE;
    let slot: &mut [u8; DENIABLE_SLOT_SIZE] = (&mut header_bytes[off..off + DENIABLE_SLOT_SIZE])
        .try_into()
        .expect("slot slice is statically sized");
    // Fill slot fully with random first so any unused tail bytes are
    // OsRng-shaped, then overwrite the envelope region.
    deniable::fill_random(slot).map_err(Error::Crypto)?;
    slot[..SLOT_NONCE_LEN].copy_from_slice(&env_nonce);
    slot[SLOT_NONCE_LEN..SLOT_NONCE_LEN + env_ct.len()].copy_from_slice(&env_ct);
    Ok(())
}

// ============================================================
// Credential-agnostic create / open
// ============================================================

// v1 single-step `create_with_credential`, `open_with_credential`,
// and `install_slot_with_credential` were removed in v2. Callers now
// use `create_with_credential_v2` (two-layer envelope + embedded
// material), `try_open_envelope_v2` + `complete_open_v2`, and
// `install_slot_v2` respectively.

// ============================================================
// Slot lifecycle: install / clear / rotate
// ============================================================

// v1 single-step `install_slot` was removed in v2; callers use
// `install_slot_v2` above which encodes the slot payload (kind tag +
// embedded cred_id/hmac_salt/tpm_blob + inner wrapped MVK) inside a
// passphrase-keyed outer envelope.

/// Overwrite `slot_idx` with fresh `OsRng` bytes so it becomes
/// indistinguishable from an unused slot. Use case: an admin holds
/// the MVK and removes a known user.
///
/// IMPORTANT: this leaves the OTHER slots untouched, so an attacker
/// who has before/after snapshots of the slot table sees exactly
/// which slot changed - and thus learns "someone was removed from
/// slot N." If you need to defeat such a watcher, do a full
/// `rotate_mvk` after the removal: it re-randomizes every slot so
/// the diff reveals nothing.
pub fn clear_slot(
    header_bytes: &mut [u8; DENIABLE_HEADER_SIZE],
    slot_idx: usize,
) -> Result<(), Error> {
    if slot_idx >= DENIABLE_SLOT_COUNT {
        return Err(Error::Crypto(luksbox_core::Error::InvalidKeyslotIndex(
            slot_idx,
        )));
    }
    let off = DENIABLE_SLOT_TABLE_OFFSET + slot_idx * DENIABLE_SLOT_SIZE;
    deniable::fill_random(&mut header_bytes[off..off + DENIABLE_SLOT_SIZE])
        .map_err(Error::Crypto)?;
    Ok(())
}

/// v2 full MVK rotation with re-randomized slots (security invariant
/// #4). Regenerates the per-vault salt + MVK + inner-header
/// ciphertext + every slot. Each kept slot is re-installed as a v2
/// envelope under the new per-vault salt, wrapping the new MVK with
/// a freshly-derived `KEK_envelope` and `KEK_factors`. Slots not in
/// `keep_slots` get fresh `OsRng` bytes so the before/after diff
/// reveals nothing about which slots were occupied.
///
/// `keep_slots` is `[(slot_idx, credential, material)]`. Each entry's
/// material is re-embedded in the new envelope (cred_id / hmac_salt /
/// tpm_blob carry over - the rotation re-keys the envelope, not the
/// authenticator). Caller is responsible for re-supplying the same
/// secondary outputs the credential needs (`hmac_secret_output`,
/// `unsealed`, `mlkem_shared`).
///
/// On success returns the new MVK. The header buffer is left in a
/// fully-rotated state - all 36864 bytes are guaranteed to differ
/// from the input on a successful return (salt + MVK + nonces + tags
/// all come from `OsRng`).
///
/// On error the buffer is left in its original state - the new
/// header is built in a temporary and only memcpy'd in on full
/// success, so partial failures cannot leave the vault unbootable.
pub fn rotate_mvk_v2(
    header_bytes: &mut [u8; DENIABLE_HEADER_SIZE],
    inner: DeniableInnerHeader,
    cipher_suite: CipherSuite,
    new_per_vault_salt: [u8; DENIABLE_SALT_SIZE],
    keep_slots: &[(
        usize,
        &luksbox_core::deniable::DeniableCredential,
        &DeniableMaterial,
    )],
) -> Result<MasterVolumeKey, Error> {
    use luksbox_core::deniable::slot_payload::SlotPayload;

    // Validate slot indices BEFORE doing any expensive work.
    for (idx, _, _) in keep_slots {
        if *idx >= DENIABLE_SLOT_COUNT {
            return Err(Error::Crypto(luksbox_core::Error::InvalidKeyslotIndex(
                *idx,
            )));
        }
    }
    // Reject duplicate slot indices - two credentials pointing at
    // the same slot would be ambiguous and silently letting the
    // second overwrite the first is a footgun.
    let mut seen = [false; DENIABLE_SLOT_COUNT];
    for (idx, _, _) in keep_slots {
        if seen[*idx] {
            return Err(Error::Crypto(luksbox_core::Error::InvalidField));
        }
        seen[*idx] = true;
    }

    let new_mvk = MasterVolumeKey::try_random()
        .map_err(|e| Error::Crypto(luksbox_core::Error::OsRng(e.to_string())))?;

    // Build the slot table in a temp buffer so failure leaves the
    // input header untouched. Start every slot with fresh OsRng,
    // then overwrite kept ones with v2 envelopes.
    let mut new_slots = vec![[0u8; DENIABLE_SLOT_SIZE]; DENIABLE_SLOT_COUNT];
    for slot in new_slots.iter_mut() {
        deniable::fill_random(slot).map_err(Error::Crypto)?;
    }

    for (slot_idx, cred, material) in keep_slots {
        let kind = cred.kind_tag();
        let env_kek = cred
            .derive_envelope_kek(&new_per_vault_salt)
            .map_err(Error::Crypto)?;
        let factors_kek = cred.derive_factors_kek(&new_per_vault_salt, &env_kek);

        // Seal the new MVK with the new factors KEK.
        let mut wrapped_mvk_nonce = [0u8; SLOT_NONCE_LEN];
        deniable::fill_random(&mut wrapped_mvk_nonce).map_err(Error::Crypto)?;
        let inner_aad = inner_slot_aad(&new_per_vault_salt, *slot_idx);
        let wrapped_mvk_ct = luksbox_core::aead::seal(
            cipher_suite,
            factors_kek.as_bytes(),
            &wrapped_mvk_nonce,
            &inner_aad,
            new_mvk.as_bytes(),
        )
        .map_err(Error::Crypto)?;
        let mut wrapped_mvk_arr = [0u8; 48];
        wrapped_mvk_arr.copy_from_slice(&wrapped_mvk_ct);

        // Build + seal the v2 payload.
        let payload = SlotPayload::new(
            kind,
            material.cred_id.clone(),
            material.hmac_salt,
            material.tpm_blob.clone(),
            wrapped_mvk_nonce,
            wrapped_mvk_arr,
        )
        .map_err(Error::Crypto)?;
        let payload_bytes = payload.encode().map_err(Error::Crypto)?;

        let mut env_nonce = [0u8; SLOT_NONCE_LEN];
        deniable::fill_random(&mut env_nonce).map_err(Error::Crypto)?;
        let outer_aad = deniable::slot_aad(&new_per_vault_salt, *slot_idx);
        let env_ct = luksbox_core::aead::seal(
            cipher_suite,
            env_kek.as_bytes(),
            &env_nonce,
            &outer_aad,
            &payload_bytes,
        )
        .map_err(Error::Crypto)?;

        let target = &mut new_slots[*slot_idx];
        target[..SLOT_NONCE_LEN].copy_from_slice(&env_nonce);
        target[SLOT_NONCE_LEN..SLOT_NONCE_LEN + env_ct.len()].copy_from_slice(&env_ct);
    }

    // Re-encrypt the inner header with the new MVK's key.
    let inner_pt = inner.serialise();
    let inner_key = deniable::inner_header_key(&new_mvk, &new_per_vault_salt);
    let mut inner_nonce = [0u8; SLOT_NONCE_LEN];
    deniable::fill_random(&mut inner_nonce).map_err(Error::Crypto)?;
    let inner_aad_bytes = inner_header_aad(&new_per_vault_salt);
    let inner_ct = aead::seal(
        cipher_suite,
        inner_key.as_bytes(),
        &inner_nonce,
        &inner_aad_bytes,
        &inner_pt,
    )
    .map_err(Error::Crypto)?;

    // Assemble the new header in a temp buffer.
    let mut new_header = vec![0u8; DENIABLE_HEADER_SIZE];
    new_header[..DENIABLE_SALT_SIZE].copy_from_slice(&new_per_vault_salt);
    for (i, slot) in new_slots.iter().enumerate() {
        let off = DENIABLE_SLOT_TABLE_OFFSET + i * DENIABLE_SLOT_SIZE;
        new_header[off..off + DENIABLE_SLOT_SIZE].copy_from_slice(slot);
    }
    new_header[DENIABLE_INNER_OFFSET..DENIABLE_INNER_OFFSET + SLOT_NONCE_LEN]
        .copy_from_slice(&inner_nonce);
    let ct_off = DENIABLE_INNER_OFFSET + SLOT_NONCE_LEN;
    new_header[ct_off..ct_off + inner_ct.len()].copy_from_slice(&inner_ct);

    // Commit: single memcpy into the caller's buffer. Until this
    // point any error has left header_bytes untouched.
    header_bytes.copy_from_slice(&new_header);
    Ok(new_mvk)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Cheap Argon2id params for tests. `Argon2idParams::TEST_ONLY`
    /// in `luksbox-core` is `#[cfg(test)]`-gated and not available to
    /// downstream crates; mirror it here. Must still satisfy
    /// `is_sane_for_disk` (m_cost >= 8, t/p >= 1).
    fn cheap_test_params() -> Argon2idParams {
        Argon2idParams {
            m_cost_kib: 8,
            t_cost: 1,
            p_cost: 1,
        }
    }

    fn sane_inner() -> DeniableInnerHeader {
        DeniableInnerHeader {
            format_version_minor: 0,
            cipher_suite: CipherSuite::Aes256GcmSiv,
            kdf_id: KdfId::Argon2id,
            flags: 0,
            metadata_offset: DENIABLE_HEADER_SIZE as u64,
            metadata_size: 1 << 20,
            data_offset: DENIABLE_HEADER_SIZE as u64 + (1 << 20),
            chunk_size: 4096,
        }
    }

    #[test]
    fn v2_create_then_open_round_trips_passphrase_only() {
        let inner = sane_inner();
        let cred = luksbox_core::deniable::DeniableCredential::Passphrase {
            passphrase: b"hunter2",
            argon2: cheap_test_params(),
        };
        let (header, mvk) = create_with_credential_v2(
            &cred,
            &DeniableMaterial::passphrase_only(),
            3,
            CipherSuite::Aes256GcmSiv,
            inner,
        )
        .unwrap();
        assert_eq!(header.len(), DENIABLE_HEADER_SIZE);

        // Open: phase 1 trial-decrypt + phase 2 unwrap MVK.
        let opened_env =
            try_open_envelope_v2(&header, &cred, CipherSuite::Aes256GcmSiv, None).unwrap();
        assert_eq!(opened_env.matched_slot_idx, 3);
        assert_eq!(
            opened_env.payload.kind,
            luksbox_core::deniable::DeniableKindTag::Passphrase
        );
        let opened = complete_open_v2(opened_env, &cred, CipherSuite::Aes256GcmSiv).unwrap();
        assert_eq!(opened.mvk.as_bytes(), mvk.as_bytes());
        assert_eq!(opened.inner, inner);
        assert_eq!(opened.matched_slot_idx, 3);
    }

    #[test]
    fn v2_round_trip_with_fido2_material_embedded() {
        let inner = sane_inner();
        let hmac_output = [0x42u8; 32];
        let cred = luksbox_core::deniable::DeniableCredential::Fido2Passphrase {
            passphrase: b"hunter2",
            argon2: cheap_test_params(),
            hmac_secret_output: &hmac_output,
        };
        let material = DeniableMaterial {
            cred_id: vec![0xaa; 64],
            hmac_salt: Some([0xbb; 32]),
            tpm_blob: Vec::new(),
        };
        let (header, mvk) =
            create_with_credential_v2(&cred, &material, 0, CipherSuite::Aes256GcmSiv, inner)
                .unwrap();

        let opened_env =
            try_open_envelope_v2(&header, &cred, CipherSuite::Aes256GcmSiv, None).unwrap();
        // The recovered payload exposes cred_id + hmac_salt the host
        // needs to drive the FIDO2 authenticator (which would then
        // produce the hmac_output the caller already has).
        assert_eq!(opened_env.payload.cred_id, material.cred_id);
        assert_eq!(opened_env.payload.hmac_salt, material.hmac_salt);
        let opened = complete_open_v2(opened_env, &cred, CipherSuite::Aes256GcmSiv).unwrap();
        assert_eq!(opened.mvk.as_bytes(), mvk.as_bytes());
    }

    #[test]
    fn v2_round_trip_with_tpm_blob_embedded() {
        let inner = sane_inner();
        let unsealed = [0xcdu8; 32];
        let cred = luksbox_core::deniable::DeniableCredential::TpmPassphrase {
            passphrase: b"vault-pass",
            argon2: cheap_test_params(),
            unsealed: &unsealed,
        };
        // ~1.8 KB TPM blob - realistic size.
        let blob = vec![0x77; 1800];
        let material = DeniableMaterial {
            cred_id: Vec::new(),
            hmac_salt: None,
            tpm_blob: blob.clone(),
        };
        let (header, mvk) =
            create_with_credential_v2(&cred, &material, 5, CipherSuite::ChaCha20Poly1305, inner)
                .unwrap();

        let opened_env =
            try_open_envelope_v2(&header, &cred, CipherSuite::ChaCha20Poly1305, None).unwrap();
        assert_eq!(opened_env.payload.tpm_blob, blob);
        assert!(opened_env.payload.cred_id.is_empty());
        let opened = complete_open_v2(opened_env, &cred, CipherSuite::ChaCha20Poly1305).unwrap();
        assert_eq!(opened.mvk.as_bytes(), mvk.as_bytes());
    }

    #[test]
    fn v2_wrong_passphrase_returns_opaque_error() {
        let inner = sane_inner();
        let cred = luksbox_core::deniable::DeniableCredential::Passphrase {
            passphrase: b"correct",
            argon2: cheap_test_params(),
        };
        let (header, _) = create_with_credential_v2(
            &cred,
            &DeniableMaterial::passphrase_only(),
            0,
            CipherSuite::Aes256GcmSiv,
            inner,
        )
        .unwrap();

        let wrong = luksbox_core::deniable::DeniableCredential::Passphrase {
            passphrase: b"wrong",
            argon2: cheap_test_params(),
        };
        let err = try_open_envelope_v2(&header, &wrong, CipherSuite::Aes256GcmSiv, None)
            .err()
            .unwrap();
        assert!(matches!(err, Error::OpaqueUnlockFailed));
    }

    #[test]
    fn v2_complete_open_rejects_variant_mismatch() {
        // Slot was created with Passphrase; trying to complete with
        // a Fido2Passphrase credential must fail at kind-tag check.
        let inner = sane_inner();
        let cred_pp = luksbox_core::deniable::DeniableCredential::Passphrase {
            passphrase: b"hunter2",
            argon2: cheap_test_params(),
        };
        let (header, _) = create_with_credential_v2(
            &cred_pp,
            &DeniableMaterial::passphrase_only(),
            0,
            CipherSuite::Aes256GcmSiv,
            inner,
        )
        .unwrap();

        let opened_env =
            try_open_envelope_v2(&header, &cred_pp, CipherSuite::Aes256GcmSiv, None).unwrap();
        let hmac_out = [0x00u8; 32];
        let wrong_kind = luksbox_core::deniable::DeniableCredential::Fido2Passphrase {
            passphrase: b"hunter2",
            argon2: cheap_test_params(),
            hmac_secret_output: &hmac_out,
        };
        let err = complete_open_v2(opened_env, &wrong_kind, CipherSuite::Aes256GcmSiv)
            .err()
            .unwrap();
        assert!(matches!(err, Error::OpaqueUnlockFailed));
    }

    // v1 single-step `create_with_passphrase` / `open_with_passphrase`
    // tests were removed in v2; equivalent coverage of v2 envelope
    // round-trip and opaque-failure invariants lives in the v2_*
    // tests above. Two complementary container-level invariants
    // (header looks uniformly random, two same-passphrase vaults
    // get different salts) are exercised via the v2 round-trip
    // tests in `crates/luksbox-format/src/container.rs`.

    #[test]
    fn inner_header_parser_rejects_insane_metadata_size() {
        let mut inner = sane_inner();
        inner.metadata_size = luksbox_core::header::MAX_METADATA_SIZE + 1;
        let buf = inner.serialise();
        let err = DeniableInnerHeader::parse(&buf).err().unwrap();
        assert!(matches!(err, Error::Crypto(_)));
    }

    #[test]
    fn inner_header_parser_rejects_invalid_chunk_size() {
        let mut inner = sane_inner();
        inner.chunk_size = 1000; // not a power of two in our envelope
        let buf = inner.serialise();
        let err = DeniableInnerHeader::parse(&buf).err().unwrap();
        assert!(matches!(err, Error::Crypto(_)));
    }

    #[test]
    fn inner_header_parser_rejects_metadata_before_header() {
        let mut inner = sane_inner();
        inner.metadata_offset = 1024; // less than DENIABLE_HEADER_SIZE
        inner.data_offset = inner.metadata_offset + inner.metadata_size;
        let buf = inner.serialise();
        let err = DeniableInnerHeader::parse(&buf).err().unwrap();
        assert!(matches!(err, Error::Crypto(_)));
    }

    #[test]
    fn inner_header_parser_rejects_data_overlapping_metadata() {
        let mut inner = sane_inner();
        inner.data_offset = inner.metadata_offset; // would overlap
        let buf = inner.serialise();
        let err = DeniableInnerHeader::parse(&buf).err().unwrap();
        assert!(matches!(err, Error::Crypto(_)));
    }

    // v1 single-step `install_slot` + `clear_slot` tests were
    // removed in v2. Container-level equivalents now live in
    // `crates/luksbox-format/src/container.rs`:
    //   - install_slot equivalent: `enroll_credential_v2_deniable`
    //     (covered by `deniable_container_enroll_mixed_credentials`,
    //     `deniable_container_enroll_second_passphrase_persists`,
    //     `deniable_container_enroll_refuses_admin_own_slot`)
    //   - clear_slot equivalent: `Container::clear_deniable_slot`
    //     (covered by `deniable_container_clear_slot_removes_credential`)
    //   - rotation: covered by v2 rotate_mvk_v2_* tests below +
    //     container-level `deniable_container_rotate_mvk_v2_*` tests.

    #[test]
    fn v2_rotate_mvk_round_trips_with_kept_slots() {
        // Create a v2 deniable header with a Passphrase slot at
        // index 2, rotate it (re-keying the slot under a new salt +
        // new MVK), then confirm the slot still opens with the same
        // credential and yields the new MVK.
        let inner = sane_inner();
        let cred = luksbox_core::deniable::DeniableCredential::Passphrase {
            passphrase: b"admin",
            argon2: cheap_test_params(),
        };
        let (mut header, _initial_mvk) = create_with_credential_v2(
            &cred,
            &DeniableMaterial::passphrase_only(),
            2,
            CipherSuite::Aes256GcmSiv,
            inner,
        )
        .unwrap();
        let header_before = header.clone();

        let mut new_salt = [0u8; DENIABLE_SALT_SIZE];
        luksbox_core::deniable::fill_random(&mut new_salt).unwrap();
        let header_arr: &mut [u8; DENIABLE_HEADER_SIZE] = (&mut header[..]).try_into().unwrap();
        let new_mvk = rotate_mvk_v2(
            header_arr,
            inner,
            CipherSuite::Aes256GcmSiv,
            new_salt,
            &[(2, &cred, &DeniableMaterial::passphrase_only())],
        )
        .unwrap();

        // Salt must have changed.
        assert_ne!(
            &header_before[..DENIABLE_SALT_SIZE],
            &header[..DENIABLE_SALT_SIZE],
        );

        // The slot table region should differ in almost every byte
        // (32 KiB of envelope ciphertext + random fillers,
        // ~128 coincidental matches expected by chance).
        let before_slots = &header_before[DENIABLE_SLOT_TABLE_OFFSET
            ..DENIABLE_SLOT_TABLE_OFFSET + DENIABLE_SLOT_COUNT * DENIABLE_SLOT_SIZE];
        let after_slots = &header[DENIABLE_SLOT_TABLE_OFFSET
            ..DENIABLE_SLOT_TABLE_OFFSET + DENIABLE_SLOT_COUNT * DENIABLE_SLOT_SIZE];
        let equal: usize = before_slots
            .iter()
            .zip(after_slots.iter())
            .filter(|(a, b)| a == b)
            .count();
        assert!(equal < 400, "rotation left {equal} bytes unchanged");

        // Open with the same credential against the rotated header
        // and confirm we recover the new MVK.
        let env = try_open_envelope_v2(&header, &cred, CipherSuite::Aes256GcmSiv, None).unwrap();
        let opened = complete_open_v2(env, &cred, CipherSuite::Aes256GcmSiv).unwrap();
        assert_eq!(opened.mvk.as_bytes(), new_mvk.as_bytes());
        assert_eq!(opened.matched_slot_idx, 2);
    }

    #[test]
    fn v2_rotate_mvk_with_dropped_slot_loses_that_credential() {
        // Create a vault with two slots, rotate keeping only one,
        // confirm the dropped credential can no longer open.
        let inner = sane_inner();
        let admin = luksbox_core::deniable::DeniableCredential::Passphrase {
            passphrase: b"admin",
            argon2: cheap_test_params(),
        };
        let (mut header, _) = create_with_credential_v2(
            &admin,
            &DeniableMaterial::passphrase_only(),
            0,
            CipherSuite::Aes256GcmSiv,
            inner,
        )
        .unwrap();
        let bob = luksbox_core::deniable::DeniableCredential::Passphrase {
            passphrase: b"bob",
            argon2: cheap_test_params(),
        };
        // Install Bob at slot 4 using the v2 install path. Need to
        // recover the per_vault_salt + MVK first.
        let salt: [u8; DENIABLE_SALT_SIZE] = header[..DENIABLE_SALT_SIZE].try_into().unwrap();
        let env_open =
            try_open_envelope_v2(&header, &admin, CipherSuite::Aes256GcmSiv, None).unwrap();
        let opened_admin = complete_open_v2(env_open, &admin, CipherSuite::Aes256GcmSiv).unwrap();
        let admin_mvk = opened_admin.mvk;
        let header_arr: &mut [u8; DENIABLE_HEADER_SIZE] = (&mut header[..]).try_into().unwrap();
        install_slot_v2(
            header_arr,
            4,
            &bob,
            &DeniableMaterial::passphrase_only(),
            &admin_mvk,
            CipherSuite::Aes256GcmSiv,
            &salt,
        )
        .unwrap();

        // Rotate keeping admin at 0 only. Bob's slot 4 should be
        // overwritten with fresh OsRng and no longer unlock.
        let mut new_salt = [0u8; DENIABLE_SALT_SIZE];
        luksbox_core::deniable::fill_random(&mut new_salt).unwrap();
        let header_arr: &mut [u8; DENIABLE_HEADER_SIZE] = (&mut header[..]).try_into().unwrap();
        let _new_mvk = rotate_mvk_v2(
            header_arr,
            inner,
            CipherSuite::Aes256GcmSiv,
            new_salt,
            &[(0, &admin, &DeniableMaterial::passphrase_only())],
        )
        .unwrap();

        // Admin still opens at slot 0.
        let env_admin =
            try_open_envelope_v2(&header, &admin, CipherSuite::Aes256GcmSiv, None).unwrap();
        assert_eq!(env_admin.matched_slot_idx, 0);
        complete_open_v2(env_admin, &admin, CipherSuite::Aes256GcmSiv).unwrap();

        // Bob's envelope is now random noise.
        let bob_err = try_open_envelope_v2(&header, &bob, CipherSuite::Aes256GcmSiv, None)
            .err()
            .unwrap();
        assert!(matches!(bob_err, Error::OpaqueUnlockFailed));
    }

    #[test]
    fn v2_rotate_mvk_rejects_duplicate_slot_indices() {
        let inner = sane_inner();
        let cred = luksbox_core::deniable::DeniableCredential::Passphrase {
            passphrase: b"admin",
            argon2: cheap_test_params(),
        };
        let (mut header, _) = create_with_credential_v2(
            &cred,
            &DeniableMaterial::passphrase_only(),
            0,
            CipherSuite::Aes256GcmSiv,
            inner,
        )
        .unwrap();
        let mut new_salt = [0u8; DENIABLE_SALT_SIZE];
        luksbox_core::deniable::fill_random(&mut new_salt).unwrap();
        let header_arr: &mut [u8; DENIABLE_HEADER_SIZE] = (&mut header[..]).try_into().unwrap();
        let err = rotate_mvk_v2(
            header_arr,
            inner,
            CipherSuite::Aes256GcmSiv,
            new_salt,
            &[
                (0, &cred, &DeniableMaterial::passphrase_only()),
                (0, &cred, &DeniableMaterial::passphrase_only()),
            ],
        )
        .err()
        .unwrap();
        assert!(matches!(err, Error::Crypto(_)));
    }

    #[test]
    fn v2_rotate_mvk_leaves_header_intact_on_failure() {
        let inner = sane_inner();
        let cred = luksbox_core::deniable::DeniableCredential::Passphrase {
            passphrase: b"admin",
            argon2: cheap_test_params(),
        };
        let (mut header, _) = create_with_credential_v2(
            &cred,
            &DeniableMaterial::passphrase_only(),
            0,
            CipherSuite::Aes256GcmSiv,
            inner,
        )
        .unwrap();
        let header_before = header.clone();
        let mut new_salt = [0u8; DENIABLE_SALT_SIZE];
        luksbox_core::deniable::fill_random(&mut new_salt).unwrap();
        let header_arr: &mut [u8; DENIABLE_HEADER_SIZE] = (&mut header[..]).try_into().unwrap();
        let err = rotate_mvk_v2(
            header_arr,
            inner,
            CipherSuite::Aes256GcmSiv,
            new_salt,
            // Out-of-range slot index aborts before any mutation.
            &[(
                DENIABLE_SLOT_COUNT,
                &cred,
                &DeniableMaterial::passphrase_only(),
            )],
        )
        .err()
        .unwrap();
        assert!(matches!(
            err,
            Error::Crypto(luksbox_core::Error::InvalidKeyslotIndex(_)),
        ));
        assert_eq!(
            header, header_before,
            "failed rotation must not mutate input"
        );
    }

    /// Shannon entropy in bits/byte. Mirrors the helper in
    /// `luksbox_core::deniable::tests`. Uniform random over a > 1 KiB
    /// buffer scores ~7.99. Retained for any future v2 entropy test.
    #[allow(dead_code)]
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
