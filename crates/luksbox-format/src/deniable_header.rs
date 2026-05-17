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

use luksbox_core::deniable::{
    self, DENIABLE_AAD_PREFIX, DENIABLE_HEADER_SIZE, DENIABLE_INNER_OFFSET, DENIABLE_INNER_SIZE,
    DENIABLE_SALT_SIZE, DENIABLE_SLOT_COUNT, DENIABLE_SLOT_SIZE, DENIABLE_SLOT_TABLE_OFFSET,
    SLOT_NONCE_LEN, SLOT_TAG_LEN,
};
use luksbox_core::{Argon2idParams, CipherSuite, KdfId, MasterVolumeKey, aead};
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

/// Magic-equivalent for the inner header. Not on-disk - bound into
/// the AAD of the inner-header AEAD so an attacker who somehow
/// recovers the MVK still cannot substitute an arbitrary "looks like
/// random plaintext" blob without it tripping the AAD check.
const INNER_AAD: &[u8] = b"luksbox-deniable-v1/inner-header-aad";

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

const _: () = assert!(DENIABLE_HEADER_SIZE == 8192);
const _: () = assert!(INNER_PLAINTEXT_LEN == 4036);

impl DeniableInnerHeader {
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

/// Build a fresh 8 KiB deniable header sealed by a passphrase
/// credential in slot 0. The remaining 7 slots are filled with fresh
/// `OsRng` bytes (invariant #3).
///
/// Returns the assembled 8 KiB header bytes plus the MVK that was
/// generated and wrapped into slot 0. Caller is responsible for
/// writing the bytes to disk and for keeping the MVK in memory if
/// further setup work needs it.
pub fn create_with_passphrase(
    passphrase: &[u8],
    argon2_params: Argon2idParams,
    cipher_suite: CipherSuite,
    inner: DeniableInnerHeader,
) -> Result<(Vec<u8>, MasterVolumeKey), Error> {
    // Guard against insane params before doing the Argon2id stretch
    // (which can otherwise allocate up to 4 GiB on a hostile input).
    if !argon2_params.is_sane_for_disk() {
        return Err(Error::Crypto(luksbox_core::Error::InvalidField));
    }

    let mut per_vault_salt = [0u8; DENIABLE_SALT_SIZE];
    deniable::fill_random(&mut per_vault_salt).map_err(Error::Crypto)?;

    let mvk = MasterVolumeKey::try_random()
        .map_err(|e| Error::Crypto(luksbox_core::Error::OsRng(e.to_string())))?;

    // Build the slot table: occupied slot 0 + 7 random fillers.
    let mut slots = [[0u8; DENIABLE_SLOT_SIZE]; DENIABLE_SLOT_COUNT];
    for slot in slots.iter_mut() {
        deniable::fill_random(slot).map_err(Error::Crypto)?;
    }
    let pass_kek = deniable::passphrase_kek(passphrase, &per_vault_salt, argon2_params)
        .map_err(Error::Crypto)?;
    deniable::wrap_slot(
        &mut slots[0],
        &pass_kek,
        &mvk,
        cipher_suite,
        &per_vault_salt,
        0,
    )
    .map_err(Error::Crypto)?;

    // Encrypt the inner header with the MVK-derived inner-header key.
    let inner_pt = inner.serialise();
    let inner_key = deniable::inner_header_key(&mvk, &per_vault_salt);
    let mut inner_nonce = [0u8; SLOT_NONCE_LEN];
    deniable::fill_random(&mut inner_nonce).map_err(Error::Crypto)?;
    let inner_ct = aead::seal(
        cipher_suite,
        inner_key.as_bytes(),
        &inner_nonce,
        INNER_AAD,
        &inner_pt,
    )
    .map_err(Error::Crypto)?;
    debug_assert_eq!(inner_ct.len(), INNER_PLAINTEXT_LEN + SLOT_TAG_LEN);

    // Assemble the 8 KiB header buffer: salt || slots || (nonce ||
    // ciphertext+tag). No random padding needed past the inner
    // ciphertext because INNER_OFFSET + SLOT_NONCE_LEN + ct.len() ==
    // DENIABLE_HEADER_SIZE by construction.
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
    debug_assert_eq!(ct_off + inner_ct.len(), DENIABLE_HEADER_SIZE);

    Ok((header, mvk))
}

/// Attempt to open an 8 KiB deniable header with the user's passphrase
/// credential + Argon2 params + cipher choice.
///
/// On success returns the recovered MVK and the parsed inner header.
/// On ANY failure path returns `Error::OpaqueUnlockFailed` - the
/// single error variant ensures an attacker observing error output
/// cannot tell which step (passphrase vs params vs cipher vs corrupt
/// header) failed.
///
/// Bytes shorter than `DENIABLE_HEADER_SIZE` also collapse to
/// `OpaqueUnlockFailed` so an adversary truncating the file does not
/// get a distinguishable error either.
pub fn open_with_passphrase(
    header_bytes: &[u8],
    passphrase: &[u8],
    argon2_params: Argon2idParams,
    cipher_suite: CipherSuite,
) -> Result<OpenedDeniableHeader, Error> {
    if header_bytes.len() < DENIABLE_HEADER_SIZE {
        return Err(Error::OpaqueUnlockFailed);
    }
    // DoS guard - same params envelope as the on-disk parsers use,
    // applied before Argon2id runs so a hostile caller cannot drive a
    // 4 GiB allocation just by mis-typing.
    if !argon2_params.is_sane_for_disk() {
        return Err(Error::OpaqueUnlockFailed);
    }

    let header: &[u8; DENIABLE_HEADER_SIZE] =
        header_bytes[..DENIABLE_HEADER_SIZE].try_into().unwrap();
    let mut per_vault_salt = [0u8; DENIABLE_SALT_SIZE];
    per_vault_salt.copy_from_slice(&header[..DENIABLE_SALT_SIZE]);

    // Derive KEK from passphrase + per-vault salt + Argon2id params.
    let kek = match deniable::passphrase_kek(passphrase, &per_vault_salt, argon2_params) {
        Ok(k) => k,
        Err(_) => return Err(Error::OpaqueUnlockFailed),
    };

    // Carve the slot table out of the header buffer.
    let mut slots = [[0u8; DENIABLE_SLOT_SIZE]; DENIABLE_SLOT_COUNT];
    for i in 0..DENIABLE_SLOT_COUNT {
        let off = DENIABLE_SLOT_TABLE_OFFSET + i * DENIABLE_SLOT_SIZE;
        slots[i].copy_from_slice(&header[off..off + DENIABLE_SLOT_SIZE]);
    }

    // Constant-time trial decryption across all 8 slots (invariant
    // #2). The `_with_idx` variant also returns which slot matched
    // so the caller can surface "slot N is your credential" in UIs
    // and refuse to overwrite it when enrolling additional users.
    let (matched_slot_idx, mvk) =
        match deniable::trial_decrypt_with_idx(&slots, &kek, cipher_suite, &per_vault_salt) {
            Some(m) => m,
            None => return Err(Error::OpaqueUnlockFailed),
        };

    // Decrypt and parse the inner header.
    let inner_region = &header[DENIABLE_INNER_OFFSET..];
    debug_assert_eq!(inner_region.len(), DENIABLE_INNER_SIZE);
    let nonce: [u8; SLOT_NONCE_LEN] = inner_region[..SLOT_NONCE_LEN].try_into().unwrap();
    let inner_ct = &inner_region[SLOT_NONCE_LEN..];

    let inner_key = deniable::inner_header_key(&mvk, &per_vault_salt);
    let inner_pt = match aead::open(
        cipher_suite,
        inner_key.as_bytes(),
        &nonce,
        INNER_AAD,
        inner_ct,
    ) {
        Ok(pt) => Zeroizing::new(pt),
        Err(_) => return Err(Error::OpaqueUnlockFailed),
    };
    let inner = match DeniableInnerHeader::parse(&inner_pt) {
        Ok(i) => i,
        // Inner header parse failure ALSO collapses to opaque error -
        // a successful AEAD verification that yields garbage plaintext
        // implies tag-forgery (negligible probability) or a downgrade
        // attack; either way we do not want to distinguish it.
        Err(_) => return Err(Error::OpaqueUnlockFailed),
    };

    Ok(OpenedDeniableHeader {
        mvk,
        inner,
        per_vault_salt,
        matched_slot_idx,
    })
}

/// Helper - re-export the AAD prefix for callers that need to bind
/// downstream blobs to the same vault identity (e.g. metadata region
/// AEAD that wants to be tied to this specific header).
pub const AAD_PREFIX: &[u8] = DENIABLE_AAD_PREFIX;

// ============================================================
// Credential-agnostic create / open
// ============================================================

/// Same as `create_with_passphrase` but accepts any
/// `DeniableCredential` variant. Wraps the MVK with the
/// credential-derived KEK at slot `slot_idx` (0..7).
pub fn create_with_credential(
    credential: &luksbox_core::deniable::DeniableCredential,
    slot_idx: usize,
    cipher_suite: CipherSuite,
    inner: DeniableInnerHeader,
) -> Result<(Vec<u8>, MasterVolumeKey), Error> {
    use luksbox_core::deniable::DENIABLE_SLOT_COUNT;

    if slot_idx >= DENIABLE_SLOT_COUNT {
        return Err(Error::Crypto(luksbox_core::Error::InvalidKeyslotIndex(
            slot_idx,
        )));
    }

    let mut per_vault_salt = [0u8; DENIABLE_SALT_SIZE];
    deniable::fill_random(&mut per_vault_salt).map_err(Error::Crypto)?;

    let mvk = MasterVolumeKey::try_random()
        .map_err(|e| Error::Crypto(luksbox_core::Error::OsRng(e.to_string())))?;

    let mut slots = [[0u8; DENIABLE_SLOT_SIZE]; DENIABLE_SLOT_COUNT];
    for slot in slots.iter_mut() {
        deniable::fill_random(slot).map_err(Error::Crypto)?;
    }
    let kek = credential
        .derive_kek(&per_vault_salt)
        .map_err(Error::Crypto)?;
    deniable::wrap_slot(
        &mut slots[slot_idx],
        &kek,
        &mvk,
        cipher_suite,
        &per_vault_salt,
        slot_idx,
    )
    .map_err(Error::Crypto)?;

    let inner_pt = inner.serialise();
    let inner_key = deniable::inner_header_key(&mvk, &per_vault_salt);
    let mut inner_nonce = [0u8; SLOT_NONCE_LEN];
    deniable::fill_random(&mut inner_nonce).map_err(Error::Crypto)?;
    let inner_ct = aead::seal(
        cipher_suite,
        inner_key.as_bytes(),
        &inner_nonce,
        INNER_AAD,
        &inner_pt,
    )
    .map_err(Error::Crypto)?;

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

/// Same as `open_with_passphrase` but accepts any
/// `DeniableCredential` variant. If `slot_idx` is `Some(n)`, only
/// slot `n` is attempted (fast path when the user knows their slot).
/// If `None`, all 8 slots are trial-decrypted constant-time
/// (discovery path).
pub fn open_with_credential(
    header_bytes: &[u8],
    credential: &luksbox_core::deniable::DeniableCredential,
    slot_idx: Option<usize>,
    cipher_suite: CipherSuite,
) -> Result<OpenedDeniableHeader, Error> {
    use luksbox_core::deniable::DENIABLE_SLOT_COUNT;

    if header_bytes.len() < DENIABLE_HEADER_SIZE {
        return Err(Error::OpaqueUnlockFailed);
    }
    if let Some(idx) = slot_idx {
        if idx >= DENIABLE_SLOT_COUNT {
            return Err(Error::OpaqueUnlockFailed);
        }
    }

    let header: &[u8; DENIABLE_HEADER_SIZE] =
        header_bytes[..DENIABLE_HEADER_SIZE].try_into().unwrap();
    let mut per_vault_salt = [0u8; DENIABLE_SALT_SIZE];
    per_vault_salt.copy_from_slice(&header[..DENIABLE_SALT_SIZE]);

    let kek = match credential.derive_kek(&per_vault_salt) {
        Ok(k) => k,
        Err(_) => return Err(Error::OpaqueUnlockFailed),
    };

    let mut slots = [[0u8; DENIABLE_SLOT_SIZE]; DENIABLE_SLOT_COUNT];
    for i in 0..DENIABLE_SLOT_COUNT {
        let off = DENIABLE_SLOT_TABLE_OFFSET + i * DENIABLE_SLOT_SIZE;
        slots[i].copy_from_slice(&header[off..off + DENIABLE_SLOT_SIZE]);
    }

    let (matched_slot_idx, mvk) = match slot_idx {
        Some(idx) => {
            // Fast path: user knows the slot. Single AEAD attempt.
            match deniable::try_unwrap_slot(&slots[idx], &kek, cipher_suite, &per_vault_salt, idx) {
                Some(m) => (idx, m),
                None => return Err(Error::OpaqueUnlockFailed),
            }
        }
        None => {
            // Discovery path: trial-decrypt all 8 constant-time.
            match deniable::trial_decrypt_with_idx(&slots, &kek, cipher_suite, &per_vault_salt) {
                Some(m) => m,
                None => return Err(Error::OpaqueUnlockFailed),
            }
        }
    };

    let inner_region = &header[DENIABLE_INNER_OFFSET..];
    let nonce: [u8; SLOT_NONCE_LEN] = inner_region[..SLOT_NONCE_LEN].try_into().unwrap();
    let inner_ct = &inner_region[SLOT_NONCE_LEN..];

    let inner_key = deniable::inner_header_key(&mvk, &per_vault_salt);
    let inner_pt = match aead::open(
        cipher_suite,
        inner_key.as_bytes(),
        &nonce,
        INNER_AAD,
        inner_ct,
    ) {
        Ok(pt) => Zeroizing::new(pt),
        Err(_) => return Err(Error::OpaqueUnlockFailed),
    };
    let inner = match DeniableInnerHeader::parse(&inner_pt) {
        Ok(i) => i,
        Err(_) => return Err(Error::OpaqueUnlockFailed),
    };

    Ok(OpenedDeniableHeader {
        mvk,
        inner,
        per_vault_salt,
        matched_slot_idx,
    })
}

/// Install a wrapped MVK into a slot using a given credential.
/// Used by Container::enroll_*_deniable.
pub fn install_slot_with_credential(
    header_bytes: &mut [u8; DENIABLE_HEADER_SIZE],
    slot_idx: usize,
    credential: &luksbox_core::deniable::DeniableCredential,
    mvk: &MasterVolumeKey,
    cipher_suite: CipherSuite,
    per_vault_salt: &[u8; DENIABLE_SALT_SIZE],
) -> Result<(), Error> {
    let kek = credential
        .derive_kek(per_vault_salt)
        .map_err(Error::Crypto)?;
    install_slot(
        header_bytes,
        slot_idx,
        &kek,
        mvk,
        cipher_suite,
        per_vault_salt,
    )
}

// ============================================================
// Slot lifecycle: install / clear / rotate
// ============================================================

/// Install a fresh slot at `slot_idx`, wrapping the existing MVK
/// under the supplied KEK. Overwrites whatever bytes were at that
/// slot - existing occupants are wiped.
///
/// Use case: an admin holds the MVK and wants to add a new user.
/// Caller must pick a `slot_idx` that no current user occupies;
/// from the admin's POV any slot whose contents do not AEAD-decrypt
/// with the admin's own KEK is "candidate empty" (could be either
/// empty or another user; both look identical without that user's
/// credential). See `docs/DENIABLE_HEADER.md` for the multi-user
/// model.
///
/// `per_vault_salt` must match the one already in `header_bytes` at
/// offset 0 (extract via `OpenedDeniableHeader.per_vault_salt`); if
/// they disagree the AAD binding fails on subsequent unlocks.
pub fn install_slot(
    header_bytes: &mut [u8; DENIABLE_HEADER_SIZE],
    slot_idx: usize,
    kek: &luksbox_core::KeyEncryptionKey,
    mvk: &MasterVolumeKey,
    cipher_suite: CipherSuite,
    per_vault_salt: &[u8; DENIABLE_SALT_SIZE],
) -> Result<(), Error> {
    if slot_idx >= DENIABLE_SLOT_COUNT {
        return Err(Error::Crypto(luksbox_core::Error::InvalidKeyslotIndex(
            slot_idx,
        )));
    }
    let off = DENIABLE_SLOT_TABLE_OFFSET + slot_idx * DENIABLE_SLOT_SIZE;
    let slot: &mut [u8; DENIABLE_SLOT_SIZE] = (&mut header_bytes[off..off + DENIABLE_SLOT_SIZE])
        .try_into()
        .expect("slot slice is statically sized");
    deniable::wrap_slot(slot, kek, mvk, cipher_suite, per_vault_salt, slot_idx)
        .map_err(Error::Crypto)
}

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

/// Full MVK rotation with re-randomized slots (security invariant
/// #4). Regenerates the per-vault salt + MVK + inner-header
/// ciphertext + every slot. Slots whose `(slot_idx, new_KEK)` pair
/// is supplied in `keep_slots` get the new MVK wrapped under the
/// new KEK; all other slots get fresh `OsRng` bytes.
///
/// The caller is responsible for deriving each retained user's KEK
/// against the NEW salt before calling. Practical flow:
/// 1. Generate `new_per_vault_salt` via `deniable::fill_random`.
/// 2. For each user being kept, prompt for their credential and
///    derive `KEK = passphrase_kek(passphrase, &new_per_vault_salt,
///    params)` (or the FIDO2 / TPM / PQ equivalent).
/// 3. Call this function with all `(slot_idx, KEK)` pairs.
///
/// On success returns the new MVK. The header buffer is left in a
/// fully-rotated state - all 8192 bytes are guaranteed to differ
/// from the input on a successful return (overwhelmingly likely:
/// the salt + MVK + nonces + tags all come from `OsRng` so the
/// pre-rotation byte pattern survives only by 2^-256 chance per
/// region).
///
/// On error the buffer is left in its original state - the new
/// header is built in a temporary and only memcpy'd in on full
/// success, so partial failures cannot leave the vault unbootable.
pub fn rotate_mvk(
    header_bytes: &mut [u8; DENIABLE_HEADER_SIZE],
    inner: DeniableInnerHeader,
    cipher_suite: CipherSuite,
    new_per_vault_salt: [u8; DENIABLE_SALT_SIZE],
    keep_slots: &[(usize, luksbox_core::KeyEncryptionKey)],
) -> Result<MasterVolumeKey, Error> {
    // Validate slot indices BEFORE doing any expensive work.
    for (idx, _) in keep_slots {
        if *idx >= DENIABLE_SLOT_COUNT {
            return Err(Error::Crypto(luksbox_core::Error::InvalidKeyslotIndex(
                *idx,
            )));
        }
    }
    // Reject duplicate slot indices - two KEKs pointing at the same
    // slot would be ambiguous (which one wins?), and silently letting
    // the second overwrite the first is a footgun.
    let mut seen = [false; DENIABLE_SLOT_COUNT];
    for (idx, _) in keep_slots {
        if seen[*idx] {
            return Err(Error::Crypto(luksbox_core::Error::InvalidField));
        }
        seen[*idx] = true;
    }

    let new_mvk = MasterVolumeKey::try_random()
        .map_err(|e| Error::Crypto(luksbox_core::Error::OsRng(e.to_string())))?;

    // Build the slot table in a temp buffer so failure leaves the
    // input header untouched. Start every slot with fresh OsRng,
    // then overwrite the kept ones with real ciphertext.
    let mut new_slots = [[0u8; DENIABLE_SLOT_SIZE]; DENIABLE_SLOT_COUNT];
    for slot in new_slots.iter_mut() {
        deniable::fill_random(slot).map_err(Error::Crypto)?;
    }
    for (idx, kek) in keep_slots {
        deniable::wrap_slot(
            &mut new_slots[*idx],
            kek,
            &new_mvk,
            cipher_suite,
            &new_per_vault_salt,
            *idx,
        )
        .map_err(Error::Crypto)?;
    }

    // Re-encrypt the inner header with the new MVK's key.
    let inner_pt = inner.serialise();
    let inner_key = deniable::inner_header_key(&new_mvk, &new_per_vault_salt);
    let mut inner_nonce = [0u8; SLOT_NONCE_LEN];
    deniable::fill_random(&mut inner_nonce).map_err(Error::Crypto)?;
    let inner_ct = aead::seal(
        cipher_suite,
        inner_key.as_bytes(),
        &inner_nonce,
        INNER_AAD,
        &inner_pt,
    )
    .map_err(Error::Crypto)?;

    // Assemble the new header in a temp buffer.
    let mut new_header = [0u8; DENIABLE_HEADER_SIZE];
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
    fn create_then_open_round_trips() {
        let inner = sane_inner();
        let (header, mvk) = create_with_passphrase(
            b"hunter2",
            cheap_test_params(),
            CipherSuite::Aes256GcmSiv,
            inner,
        )
        .unwrap();
        assert_eq!(header.len(), DENIABLE_HEADER_SIZE);

        let opened = open_with_passphrase(
            &header,
            b"hunter2",
            cheap_test_params(),
            CipherSuite::Aes256GcmSiv,
        )
        .unwrap();
        assert_eq!(opened.mvk.as_bytes(), mvk.as_bytes());
        assert_eq!(opened.inner, inner);
    }

    #[test]
    fn wrong_passphrase_returns_opaque_error() {
        let inner = sane_inner();
        let (header, _) = create_with_passphrase(
            b"hunter2",
            cheap_test_params(),
            CipherSuite::Aes256GcmSiv,
            inner,
        )
        .unwrap();

        let err = open_with_passphrase(
            &header,
            b"wrong-password",
            cheap_test_params(),
            CipherSuite::Aes256GcmSiv,
        )
        .err()
        .unwrap();
        assert!(matches!(err, Error::OpaqueUnlockFailed));
    }

    #[test]
    fn wrong_cipher_returns_opaque_error() {
        // INVARIANT: wrong cipher choice fails identically to wrong
        // passphrase - no oracle for "is the cipher right?".
        let inner = sane_inner();
        let (header, _) = create_with_passphrase(
            b"hunter2",
            cheap_test_params(),
            CipherSuite::Aes256GcmSiv,
            inner,
        )
        .unwrap();

        let err = open_with_passphrase(
            &header,
            b"hunter2",
            cheap_test_params(),
            CipherSuite::ChaCha20Poly1305,
        )
        .err()
        .unwrap();
        assert!(matches!(err, Error::OpaqueUnlockFailed));
    }

    #[test]
    fn wrong_argon2_params_returns_opaque_error() {
        // INVARIANT: wrong Argon2 params fail identically.
        let inner = sane_inner();
        let (header, _) = create_with_passphrase(
            b"hunter2",
            cheap_test_params(),
            CipherSuite::Aes256GcmSiv,
            inner,
        )
        .unwrap();

        let mut wrong_params = cheap_test_params();
        wrong_params.t_cost += 1;
        let err =
            open_with_passphrase(&header, b"hunter2", wrong_params, CipherSuite::Aes256GcmSiv)
                .err()
                .unwrap();
        assert!(matches!(err, Error::OpaqueUnlockFailed));
    }

    #[test]
    fn truncated_header_returns_opaque_error() {
        let err = open_with_passphrase(
            b"too short",
            b"hunter2",
            cheap_test_params(),
            CipherSuite::Aes256GcmSiv,
        )
        .err()
        .unwrap();
        assert!(matches!(err, Error::OpaqueUnlockFailed));
    }

    #[test]
    fn insane_params_at_open_return_opaque_error() {
        // Caller cannot drive a 4 GiB allocation via a hostile m_cost.
        let mut bad = cheap_test_params();
        bad.m_cost_kib = u32::MAX;
        let err = open_with_passphrase(
            &[0u8; DENIABLE_HEADER_SIZE],
            b"hunter2",
            bad,
            CipherSuite::Aes256GcmSiv,
        )
        .err()
        .unwrap();
        assert!(matches!(err, Error::OpaqueUnlockFailed));
    }

    #[test]
    fn insane_params_at_create_return_invalid_field() {
        let mut bad = cheap_test_params();
        bad.m_cost_kib = u32::MAX;
        let err = create_with_passphrase(b"hunter2", bad, CipherSuite::Aes256GcmSiv, sane_inner())
            .err()
            .unwrap();
        // create_with_passphrase is NOT user-facing (caller is a
        // trusted CLI/GUI), so it surfaces a structured error instead
        // of the opaque-unlock-failed variant.
        assert!(matches!(err, Error::Crypto(_)));
    }

    #[test]
    fn header_is_fully_random_looking() {
        // Sanity: a freshly-created header should have high Shannon
        // entropy (the magic, version, and structural offsets are all
        // hidden inside AEAD ciphertext or random bytes). Compare to
        // the standard format which has 8+2+2+4+... = ~30 bytes of
        // plaintext structure at well-known offsets.
        let inner = sane_inner();
        let (header, _) = create_with_passphrase(
            b"hunter2",
            cheap_test_params(),
            CipherSuite::Aes256GcmSiv,
            inner,
        )
        .unwrap();
        let h = shannon_bits_per_byte(&header);
        assert!(h > 7.9, "header entropy {:.3} too low", h);
    }

    #[test]
    fn two_headers_with_same_passphrase_have_different_salts() {
        // Two fresh vaults with the same passphrase MUST have
        // different per-vault salts, otherwise the wrapped MVK at
        // slot 0 would be the same in both - a structural fingerprint
        // visible to anyone with the passphrase.
        let inner = sane_inner();
        let (h1, _) = create_with_passphrase(
            b"hunter2",
            cheap_test_params(),
            CipherSuite::Aes256GcmSiv,
            inner,
        )
        .unwrap();
        let (h2, _) = create_with_passphrase(
            b"hunter2",
            cheap_test_params(),
            CipherSuite::Aes256GcmSiv,
            inner,
        )
        .unwrap();
        assert_ne!(&h1[..DENIABLE_SALT_SIZE], &h2[..DENIABLE_SALT_SIZE]);
    }

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

    #[test]
    fn install_slot_lets_a_second_user_unlock() {
        let inner = sane_inner();
        let (mut header, mvk) = create_with_passphrase(
            b"admin",
            cheap_test_params(),
            CipherSuite::Aes256GcmSiv,
            inner,
        )
        .unwrap();
        // Pull the per-vault salt out of slot 0's preamble.
        let salt: [u8; DENIABLE_SALT_SIZE] = header[..DENIABLE_SALT_SIZE].try_into().unwrap();

        // Admin installs a second user in slot 3.
        let bob_kek =
            luksbox_core::deniable::passphrase_kek(b"bobspassword", &salt, cheap_test_params())
                .unwrap();
        let header_arr: &mut [u8; DENIABLE_HEADER_SIZE] = (&mut header[..]).try_into().unwrap();
        install_slot(
            header_arr,
            3,
            &bob_kek,
            &mvk,
            CipherSuite::Aes256GcmSiv,
            &salt,
        )
        .unwrap();

        // Bob can now open the vault with his passphrase.
        let opened_bob = open_with_passphrase(
            &header,
            b"bobspassword",
            cheap_test_params(),
            CipherSuite::Aes256GcmSiv,
        )
        .unwrap();
        assert_eq!(opened_bob.mvk.as_bytes(), mvk.as_bytes());

        // And the admin can still open it with the original passphrase.
        let opened_admin = open_with_passphrase(
            &header,
            b"admin",
            cheap_test_params(),
            CipherSuite::Aes256GcmSiv,
        )
        .unwrap();
        assert_eq!(opened_admin.mvk.as_bytes(), mvk.as_bytes());
    }

    #[test]
    fn install_slot_rejects_out_of_range_index() {
        let inner = sane_inner();
        let (mut header, mvk) = create_with_passphrase(
            b"admin",
            cheap_test_params(),
            CipherSuite::Aes256GcmSiv,
            inner,
        )
        .unwrap();
        let salt: [u8; DENIABLE_SALT_SIZE] = header[..DENIABLE_SALT_SIZE].try_into().unwrap();
        let kek = luksbox_core::deniable::passphrase_kek(b"x", &salt, cheap_test_params()).unwrap();
        let header_arr: &mut [u8; DENIABLE_HEADER_SIZE] = (&mut header[..]).try_into().unwrap();
        let err = install_slot(
            header_arr,
            DENIABLE_SLOT_COUNT,
            &kek,
            &mvk,
            CipherSuite::Aes256GcmSiv,
            &salt,
        )
        .err()
        .unwrap();
        assert!(matches!(
            err,
            Error::Crypto(luksbox_core::Error::InvalidKeyslotIndex(_)),
        ));
    }

    #[test]
    fn clear_slot_makes_the_credential_unusable() {
        let inner = sane_inner();
        let (mut header, mvk) = create_with_passphrase(
            b"admin",
            cheap_test_params(),
            CipherSuite::Aes256GcmSiv,
            inner,
        )
        .unwrap();
        let salt: [u8; DENIABLE_SALT_SIZE] = header[..DENIABLE_SALT_SIZE].try_into().unwrap();
        let bob_kek =
            luksbox_core::deniable::passphrase_kek(b"bobspassword", &salt, cheap_test_params())
                .unwrap();
        let header_arr: &mut [u8; DENIABLE_HEADER_SIZE] = (&mut header[..]).try_into().unwrap();
        install_slot(
            header_arr,
            5,
            &bob_kek,
            &mvk,
            CipherSuite::Aes256GcmSiv,
            &salt,
        )
        .unwrap();
        // Confirm Bob can open before clear.
        assert!(
            open_with_passphrase(
                &header,
                b"bobspassword",
                cheap_test_params(),
                CipherSuite::Aes256GcmSiv
            )
            .is_ok()
        );
        // Admin removes Bob.
        let header_arr: &mut [u8; DENIABLE_HEADER_SIZE] = (&mut header[..]).try_into().unwrap();
        clear_slot(header_arr, 5).unwrap();
        // Bob can no longer open; admin still can.
        assert!(matches!(
            open_with_passphrase(
                &header,
                b"bobspassword",
                cheap_test_params(),
                CipherSuite::Aes256GcmSiv,
            ),
            Err(Error::OpaqueUnlockFailed),
        ));
        assert!(
            open_with_passphrase(
                &header,
                b"admin",
                cheap_test_params(),
                CipherSuite::Aes256GcmSiv,
            )
            .is_ok()
        );
    }

    #[test]
    fn invariant_4_rotation_rerandomises_every_slot_byte() {
        // INVARIANT 4: rotate_mvk re-randomizes every slot in the
        // table, so an attacker with before/after snapshots cannot
        // identify the occupied subset by diffing.
        let inner = sane_inner();
        let (mut header, _) = create_with_passphrase(
            b"admin",
            cheap_test_params(),
            CipherSuite::Aes256GcmSiv,
            inner,
        )
        .unwrap();
        let header_before = header.clone();

        // Build a totally fresh salt + a new admin KEK against it.
        let mut new_salt = [0u8; DENIABLE_SALT_SIZE];
        luksbox_core::deniable::fill_random(&mut new_salt).unwrap();
        let new_admin_kek =
            luksbox_core::deniable::passphrase_kek(b"admin", &new_salt, cheap_test_params())
                .unwrap();
        let header_arr: &mut [u8; DENIABLE_HEADER_SIZE] = (&mut header[..]).try_into().unwrap();
        let new_mvk = rotate_mvk(
            header_arr,
            inner,
            CipherSuite::Aes256GcmSiv,
            new_salt,
            &[(0, new_admin_kek)],
        )
        .unwrap();

        // Every byte in the slot table region MUST differ between
        // before and after - this is the actual invariant.
        let before_slots = &header_before[DENIABLE_SLOT_TABLE_OFFSET
            ..DENIABLE_SLOT_TABLE_OFFSET + DENIABLE_SLOT_COUNT * DENIABLE_SLOT_SIZE];
        let after_slots = &header[DENIABLE_SLOT_TABLE_OFFSET
            ..DENIABLE_SLOT_TABLE_OFFSET + DENIABLE_SLOT_COUNT * DENIABLE_SLOT_SIZE];
        let mut equal_byte_runs = 0usize;
        for (a, b) in before_slots.iter().zip(after_slots.iter()) {
            if a == b {
                equal_byte_runs += 1;
            }
        }
        // 8 * 512 = 4096 bytes. A few coincidental matches are
        // possible (each byte has 1/256 chance), expected count ~16.
        // A run > 100 means rotation left a recognisable region
        // intact - invariant broken.
        assert!(
            equal_byte_runs < 100,
            "rotation left {} bytes unchanged in the slot table; expected ~16 by chance",
            equal_byte_runs,
        );

        // Salt MUST also have changed (we supplied a new one).
        assert_ne!(
            &header_before[..DENIABLE_SALT_SIZE],
            &header[..DENIABLE_SALT_SIZE],
        );

        // New admin KEK must open with the new salt; the old salt
        // would derive a different KEK, so admin re-deriving against
        // the new salt is the only path that works.
        let opened = open_with_passphrase(
            &header,
            b"admin",
            cheap_test_params(),
            CipherSuite::Aes256GcmSiv,
        )
        .unwrap();
        assert_eq!(opened.mvk.as_bytes(), new_mvk.as_bytes());
    }

    #[test]
    fn rotate_mvk_rejects_duplicate_slot_indices() {
        // Two KEKs for the same slot index is ambiguous and the API
        // refuses it.
        let inner = sane_inner();
        let (mut header, _) = create_with_passphrase(
            b"admin",
            cheap_test_params(),
            CipherSuite::Aes256GcmSiv,
            inner,
        )
        .unwrap();
        let mut new_salt = [0u8; DENIABLE_SALT_SIZE];
        luksbox_core::deniable::fill_random(&mut new_salt).unwrap();
        let kek_a =
            luksbox_core::deniable::passphrase_kek(b"a", &new_salt, cheap_test_params()).unwrap();
        let kek_b =
            luksbox_core::deniable::passphrase_kek(b"b", &new_salt, cheap_test_params()).unwrap();
        let header_arr: &mut [u8; DENIABLE_HEADER_SIZE] = (&mut header[..]).try_into().unwrap();
        let err = rotate_mvk(
            header_arr,
            inner,
            CipherSuite::Aes256GcmSiv,
            new_salt,
            &[(0, kek_a), (0, kek_b)],
        )
        .err()
        .unwrap();
        assert!(matches!(err, Error::Crypto(_)));
    }

    #[test]
    fn rotate_mvk_leaves_header_intact_on_failure() {
        // Bad slot index aborts rotation BEFORE any buffer mutation,
        // so the input header is byte-identical after the failed call.
        let inner = sane_inner();
        let (mut header, _) = create_with_passphrase(
            b"admin",
            cheap_test_params(),
            CipherSuite::Aes256GcmSiv,
            inner,
        )
        .unwrap();
        let header_before = header.clone();
        let mut new_salt = [0u8; DENIABLE_SALT_SIZE];
        luksbox_core::deniable::fill_random(&mut new_salt).unwrap();
        let bad_kek =
            luksbox_core::deniable::passphrase_kek(b"x", &new_salt, cheap_test_params()).unwrap();
        let header_arr: &mut [u8; DENIABLE_HEADER_SIZE] = (&mut header[..]).try_into().unwrap();
        let err = rotate_mvk(
            header_arr,
            inner,
            CipherSuite::Aes256GcmSiv,
            new_salt,
            &[(DENIABLE_SLOT_COUNT, bad_kek)],
        )
        .err()
        .unwrap();
        assert!(matches!(
            err,
            Error::Crypto(luksbox_core::Error::InvalidKeyslotIndex(_)),
        ));
        assert_eq!(
            header, header_before,
            "failed rotation must not mutate the input header"
        );
    }

    /// Shannon entropy in bits/byte. Mirrors the helper in
    /// `luksbox_core::deniable::tests`. Uniform random over a > 1 KiB
    /// buffer scores ~7.99.
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
