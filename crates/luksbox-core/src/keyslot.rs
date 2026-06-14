// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Penthertz <https://penthertz.com> (https://x.com/PentHertz)

use hkdf::Hkdf;
use rand_core::{OsRng, RngCore};
use sha2::Sha256;
use zeroize::{Zeroize, Zeroizing};

use crate::aead::{self, CipherSuite};
use crate::error::Error;
use crate::kdf::{
    Argon2idParams, derive_hybrid_fido2_kek, derive_hybrid_kek, derive_kek, derive_kek_with_fido2,
};
use crate::key::{KEY_LEN, KeyEncryptionKey, MasterVolumeKey};

/// HKDF info string for deriving the MVK directly from a YubiKey's
/// hmac-secret output. Domain-separated from any other use of the
/// hmac_secret value (e.g. as a wrap-KEK input).
const MVK_FROM_FIDO2_INFO: &[u8] = b"lbx:mvk-fido/v1";
/// Domain-separation tag for the fused TPM+FIDO2 KEK derivation.
/// HKDF salt = header_salt (per-vault), IKM = tpm_unsealed || hmac_secret.
const TPM2_FIDO2_KEK_INFO: &[u8] = b"lbx:tpm2-fido2-kek/v1";
/// Domain-separation tag for the hybrid TPM + ML-KEM KEK derivation.
/// HKDF salt = header_salt, IKM = tpm_unsealed || pq_shared.
const HYBRID_TPM2_KEK_INFO: &[u8] = b"lbx:hybrid-tpm-kek/v1";
/// Domain-separation tag for the hybrid TPM + FIDO2 + ML-KEM KEK
/// derivation. IKM = tpm_unsealed || hmac_secret || pq_shared.
const HYBRID_TPM2_FIDO2_KEK_INFO: &[u8] = b"lbx:hybrid-tpm-fido2-kek/v1";

/// Derive the KEK for a fused TPM+FIDO2 keyslot. Both inputs are
/// 32-byte high-entropy values (TPM unseal output + FIDO2 hmac-secret),
/// so HKDF mixing under the per-vault `header_salt` is sufficient -
/// no Argon2id stretching needed.
fn derive_tpm2_fido2_kek(
    tpm_unsealed: &[u8; KEY_LEN],
    hmac_secret: &[u8; KEY_LEN],
    header_salt: &[u8; 32],
) -> KeyEncryptionKey {
    // Both buffers wrapped so the IKM concatenation and the derived KEK
    // are scrubbed on drop (including panic paths). KeyEncryptionKey
    // itself is ZeroizeOnDrop, but its constructor takes the bytes by
    // value, so the on-stack `out` array would otherwise be left with
    // a residue copy of the KEK bytes after the move.
    let mut ikm = Zeroizing::new([0u8; 64]);
    ikm[..KEY_LEN].copy_from_slice(tpm_unsealed);
    ikm[KEY_LEN..].copy_from_slice(hmac_secret);
    let hk = Hkdf::<Sha256>::new(Some(header_salt), ikm.as_ref());
    let mut out = Zeroizing::new([0u8; KEY_LEN]);
    hk.expand(TPM2_FIDO2_KEK_INFO, out.as_mut_slice())
        .expect("32 <= 255 * HashLen");
    KeyEncryptionKey::from_zeroizing(&out)
}

/// Derive the KEK for a hybrid TPM + ML-KEM keyslot. Mixes the TPM
/// unseal output with the Kyber-decapsulated shared secret. Both
/// 32 B high-entropy; HKDF is sufficient.
fn derive_hybrid_tpm2_kek(
    tpm_unsealed: &[u8; KEY_LEN],
    pq_shared: &[u8; KEY_LEN],
    header_salt: &[u8; 32],
) -> KeyEncryptionKey {
    let mut ikm = Zeroizing::new([0u8; 64]);
    ikm[..KEY_LEN].copy_from_slice(tpm_unsealed);
    ikm[KEY_LEN..].copy_from_slice(pq_shared);
    let hk = Hkdf::<Sha256>::new(Some(header_salt), ikm.as_ref());
    let mut out = Zeroizing::new([0u8; KEY_LEN]);
    hk.expand(HYBRID_TPM2_KEK_INFO, out.as_mut_slice())
        .expect("32 <= 255 * HashLen");
    KeyEncryptionKey::from_zeroizing(&out)
}

/// Derive the KEK for the maximum-paranoia hybrid TPM + FIDO2 + ML-KEM
/// keyslot. Three independent 32 B inputs concatenated as IKM.
fn derive_hybrid_tpm2_fido2_kek(
    tpm_unsealed: &[u8; KEY_LEN],
    hmac_secret: &[u8; KEY_LEN],
    pq_shared: &[u8; KEY_LEN],
    header_salt: &[u8; 32],
) -> KeyEncryptionKey {
    let mut ikm = Zeroizing::new([0u8; 96]);
    ikm[..KEY_LEN].copy_from_slice(tpm_unsealed);
    ikm[KEY_LEN..2 * KEY_LEN].copy_from_slice(hmac_secret);
    ikm[2 * KEY_LEN..].copy_from_slice(pq_shared);
    let hk = Hkdf::<Sha256>::new(Some(header_salt), ikm.as_ref());
    let mut out = Zeroizing::new([0u8; KEY_LEN]);
    hk.expand(HYBRID_TPM2_FIDO2_KEK_INFO, out.as_mut_slice())
        .expect("32 <= 255 * HashLen");
    KeyEncryptionKey::from_zeroizing(&out)
}

/// Derive the MVK directly from a YubiKey's hmac-secret response.
/// `salt` is the slot's `fido2_hmac_salt`; `hmac_secret` is the 32-byte
/// authenticator output. Used by `SlotKind::Fido2DerivedMvk`.
pub fn derive_mvk_from_fido2(salt: &[u8; 32], hmac_secret: &[u8; 32]) -> MasterVolumeKey {
    let hk = Hkdf::<Sha256>::new(Some(salt), hmac_secret);
    let mut out = Zeroizing::new([0u8; KEY_LEN]);
    hk.expand(MVK_FROM_FIDO2_INFO, out.as_mut_slice())
        .expect("32 <= 255 * HashLen");
    MasterVolumeKey::from_zeroizing(&out)
}

pub const SLOT_SIZE: usize = 512;
/// Maximum FIDO2 credential ID byte length we accept FROM CALLERS into
/// new slots. Bumped from 128 to 352 to accommodate authenticators
/// that produce larger cred IDs than the typical YubiKey 64-byte case.
/// Reported real-world sizes: Google Titan 288 B, SoloKey stateless
/// mode 140 B, various other vendors in the 100-300 B range. The
/// CTAP2 spec caps cred IDs at 1023 B; 352 covers every authenticator
/// we've seen reports of with comfortable margin. Bump higher if a
/// future device exceeds it.
///
/// On-disk encoding: V3 slots reserve bytes 128..480 (= 352 B) for the
/// cred ID. V1/V2 slots reserve only bytes 128..256 (= 128 B); reading
/// a V1/V2 slot enforces `cred_len <= 128` regardless of this constant.
pub const FIDO2_CRED_ID_MAX: usize = 352;
/// Maximum cred ID stored in legacy V1/V2 slots. Reading a V1/V2 slot
/// with `cred_len` above this is a corruption / format error and
/// results in `Error::Fido2CredIdTooLong`.
pub const FIDO2_CRED_ID_MAX_V1V2: usize = 128;
pub const FIDO2_HMAC_SALT_LEN: usize = 32;

const OFF_KIND: usize = 0;
/// Byte at offset 1 of a slot. Determines the on-disk layout AND the
/// AEAD AAD shape used to wrap/unwrap this slot's MVK.
///
/// - `AAD_VERSION_V1 = 0`: AAD = `bytes[0..76] || header_salt`. Original
///   format. cred_id and hmac_salt are protected only by the header
///   HMAC. Layout: cred_id at 128..256 (128 B max), hmac_salt at
///   256..288, padding at 288..512.
/// - `AAD_VERSION_V2 = 1`: AAD = `bytes[0..76] || bytes[124..288] ||
///   header_salt`. cred_len, hmac_salt_len, cred_id, and hmac_salt
///   are also pulled into the slot AEAD AAD (defence in depth, audit
///   round 2). Same byte layout as V1.
/// - `AAD_VERSION_V3 = 2`: AAD = `bytes[0..76] || bytes[124..512] ||
///   header_salt`. **NEW LAYOUT**: cred_id occupies bytes 128..480
///   (352 B max), hmac_salt moves to 480..512. Designed to support
///   FIDO2 authenticators that produce cred IDs larger than the
///   typical YubiKey 64-byte case (Google Titan reportedly emits
///   288 B cred IDs; SoloKey stateless mode emits 140 B; the exact
///   format and reason vary per vendor and aren't always publicly
///   documented). Any byte not part of a structured field is random
///   padding for entropy obfuscation.
/// - `AAD_VERSION_V4 = 3`: byte layout identical to V3 (same AAD
///   shape, same cred_id/hmac_salt offsets). The only difference is
///   the WIRE-side interpretation of `fido2_hmac_salt` for FIDO2-
///   touching slot kinds: V4 slots use the W3C WebAuthn-PRF salt
///   derivation, so the authenticator computes
///   `HMAC-SHA256(device_secret, T(fido2_hmac_salt))` where
///   `T(x) = SHA-256("WebAuthn PRF"\0 || x)`. On the libfido2
///   (Linux + macOS) side we apply `T` explicitly before the device
///   (libfido2 forwards salts verbatim); on the webauthn.dll
///   (Windows) side we forward the RAW salt and webauthn.dll applies
///   the *identical* `T` internally. Both backends converge on the
///   same device input, fixing the cross-platform incompatibility.
///
///   IMPORTANT (V4 redefined): an EARLIER v0.3.0 build defined V4 as a
///   plain `SHA-256(salt)` prehash. That never actually round-tripped
///   through Windows, because webauthn.dll applies the PRF-prefixed
///   `T`, not a bare SHA-256 -- so that build's V4 vaults are
///   libfido2-only and cannot be opened by this build (the device
///   input differs). V4 now denotes the PRF-prefixed convention. V4
///   slots are cross-platform; V1/V2/V3 FIDO2 slots stay
///   Linux/macOS-only.
///
/// Stored INSIDE the AAD region (offset 1, within the 0..76 range), so
/// a tamper that flips the version byte at unwrap time changes the
/// AAD shape AND tags a different byte sequence, breaking the AEAD.
///
/// Existing V1/V2/V3 vaults on disk continue to read under their
/// original layout/wire format. New slots created by any
/// `Keyslot::new_*` constructor are V4: passphrase / TPM slots gain
/// nothing from V4 (no FIDO2 salt to prehash) but the version bump
/// is uniform so `aad_version >= V4` is a single test for "this
/// vault was created post-FIDO2-cross-platform-fix".
const OFF_AAD_VERSION: usize = 1;
pub const AAD_VERSION_V1: u8 = 0;
pub const AAD_VERSION_V2: u8 = 1;
pub const AAD_VERSION_V3: u8 = 2;
pub const AAD_VERSION_V4: u8 = 3;
const OFF_UUID: usize = 4;
const OFF_M_COST: usize = 20;
const OFF_T_COST: usize = 24;
const OFF_P_COST: usize = 28;
const OFF_KDF_SALT: usize = 32;
const OFF_AEAD_NONCE: usize = 64;
const OFF_WRAPPED_CT: usize = 76;
const OFF_WRAPPED_TAG: usize = 108;
const OFF_CRED_LEN: usize = 124;
const OFF_HMAC_SALT_LEN: usize = 126;
const OFF_CRED: usize = 128;
/// V1/V2 hmac_salt offset (fixed at 256, immediately after the 128 B
/// cred_id region). Used when reading legacy slots.
const OFF_HMAC_SALT_V1V2: usize = 256;
/// V3 hmac_salt offset (fixed at 480, leaving 128..480 = 352 B for
/// the cred_id region). Used when reading or writing V3 slots.
const OFF_HMAC_SALT_V3: usize = 480;
const SLOT_AAD_LEN: usize = OFF_WRAPPED_CT;

/// Pick the cred_id capacity + hmac_salt offset for a slot's
/// AAD/layout version.
const fn slot_layout(aad_version: u8) -> (usize, usize) {
    match aad_version {
        // V1, V2: legacy 128 B cred_id, hmac_salt at 256
        AAD_VERSION_V1 | AAD_VERSION_V2 => (FIDO2_CRED_ID_MAX_V1V2, OFF_HMAC_SALT_V1V2),
        // V3 (or any future version that compares >= V3): 352 B cred_id,
        // hmac_salt at 480
        _ => (FIDO2_CRED_ID_MAX, OFF_HMAC_SALT_V3),
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum SlotKind {
    Empty = 0,
    /// Passphrase keyslot: KEK = Argon2id(passphrase, salt); wraps the MVK.
    Passphrase = 1,
    /// FIDO2 wrap-style: KEK = Argon2id(b"lbx:fido" || passphrase || hmac_secret, salt);
    /// wraps a random MVK. Standard model, MVK can be wrapped under multiple
    /// keyslots, supports rotation, etc.
    Fido2HmacSecret = 2,
    /// FIDO2 derived-MVK: MVK = HKDF(salt=slot.hmac_salt, ikm=hmac_secret,
    /// info=b"lbx:mvk-fido/v1"). No wrap. The vault has no wrapped MVK to
    /// brute-force; recovering the MVK requires possession of the YubiKey.
    /// Trade-off: only valid as the first keyslot at create time
    /// (subsequent slots wrap that derived MVK as a regular `Fido2HmacSecret`
    /// or `Passphrase` slot). No backup is possible at the MVK layer, losing
    /// the YubiKey loses the vault.
    Fido2DerivedMvk = 3,
    /// Hybrid passphrase + ML-KEM-768 (FIPS 203) keyslot.
    /// KEK = HKDF(Argon2id(passphrase, salt) || pq_shared_secret).
    /// The Kyber public key + ciphertext live in the `<vault>.lbx.hybrid`
    /// sidecar; the user's Kyber seed lives in a separate `.kyber` file
    /// they keep on different trusted storage. Both are required to
    /// unlock; a quantum-capable adversary who breaks the classical
    /// Argon2id wrap still cannot recover the MVK without the seed.
    /// On-disk slot bytes are byte-identical to a `Passphrase` slot.
    HybridPqKemPassphrase = 4,
    /// Hybrid FIDO2 + ML-KEM-768. Like `Fido2HmacSecret` but the KEK
    /// derives from BOTH the FIDO2 hmac-secret output AND a Kyber
    /// decapsulation:
    ///   `KEK = HKDF(salt, fido2_kek || pq_shared, "lbx:hybrid-fido-kek/v1")`.
    /// This is the hybrid that closes the actual PQ gap in luksbox's
    /// threat model: the ECDH-P256 inside CTAP2 is the only asymmetric
    /// crypto on the FIDO2 wire, so a CRQC adversary who recorded
    /// USB-HID traffic at enroll/unlock could quantum-recover the
    /// hmac_secret and then the KEK. Adding Kyber means even with that
    /// they still need the seed file.
    /// On-disk slot bytes are byte-identical to a `Fido2HmacSecret` slot.
    HybridPqKemFido2 = 5,
    /// Same as `HybridPqKemPassphrase` but using the higher-strength
    /// ML-KEM-1024 (FIPS 203 security category 5, about  AES-256). Eligible
    /// for ANSSI's "Élevé" tier and any threat model where the user
    /// wants the cryptographic-overkill option. On-disk slot bytes
    /// are byte-identical to a `Passphrase` slot; only the kind byte
    /// and the sidecar entry's level byte differ.
    HybridPqKem1024Passphrase = 6,
    /// Same as `HybridPqKemFido2` but with ML-KEM-1024.
    HybridPqKem1024Fido2 = 7,
    /// TPM 2.0-sealed keyslot: a random KEK is generated at enroll
    /// time and sealed under a TPM-resident SRK; the MVK is wrapped
    /// with that KEK. To unlock, the TPM unseals the KEK; without
    /// the original TPM the wrapped MVK is uncrackable regardless
    /// of passphrase strength (no passphrase is involved at all).
    /// The sealed blob (TPM2B_PUBLIC + TPM2B_PRIVATE) lives in the
    /// variable-length region (`fido2_cred_id` field, repurposed as
    /// a generic per-slot blob); the wrapped MVK + tag occupy the
    /// usual `wrapped_ct` / `wrapped_tag` fields, same shape as
    /// every other slot kind. No Argon2id is run for this slot
    /// kind (the KEK comes from the TPM directly), so the
    /// `kdf_params` fields are zero on disk and exempt from the
    /// usual on-read sanity check.
    /// Linux-only at runtime: enrollment + unlock require
    /// `libtss2-esys` and a TPM 2.0 device. Other platforms can
    /// READ a vault containing this slot kind and use other slots
    /// to unlock; only TPM-slot operations themselves are gated.
    Tpm2Sealed = 8,
    /// **Fused** TPM 2.0 + FIDO2 keyslot: unlock requires BOTH the
    /// local TPM (to unseal the wrap-key half) AND a connected
    /// FIDO2 authenticator (to provide the hmac-secret half). The
    /// KEK is `HKDF(header_salt, tpm_unsealed || hmac_secret,
    /// "lbx:tpm2-fido2-kek/v1")`. Either factor alone fails.
    ///
    /// Loss of either factor permanently kills this slot, pair
    /// with a separate Passphrase or FIDO2 slot for recovery, OR
    /// accept the tradeoff and treat the vault as
    /// "unrecoverable on TPM/key loss" (the highest-paranoia mode).
    ///
    /// On-disk layout: the variable-length region (cred_id field,
    /// repurposed) holds a sub-format
    /// `[tpm_blob_len: u16 LE | tpm_blob | fido2_cred_id]`. Total
    /// must fit in `FIDO2_CRED_ID_MAX` (352 B). For typical
    /// YubiKey-class authenticators (cred_id about 60-80 B) + a TPM
    /// sealed-data-object (about 280 B) this fits comfortably; for
    /// larger cred IDs (Google Titan about 288 B, some SoloKeys
    /// stateless mode about 140 B) the constructor returns
    /// `Fido2CredIdTooLong` - use independent Tpm2Sealed +
    /// Fido2HmacSecret slots instead.
    Tpm2Fido2 = 9,
    /// TPM 2.0-sealed keyslot with a user PIN gating the unseal.
    /// Wire-shape on disk is identical to `Tpm2Sealed` (same
    /// SealedBlob in the variable-length region, same wrapped MVK),
    /// but the SealedBlob's TPM-side `userAuth` field is non-empty
    /// so the chip refuses unseal without the matching PIN.
    /// Wrong PINs count toward the chip's dictionary-attack
    /// lockout (about 32 attempts -> multi-hour cooldown), so even a
    /// 4-6 digit PIN is secure on the original hardware.
    /// Loss of either the chip OR the PIN permanently kills this
    /// slot - pair with a Passphrase / FIDO2 recovery slot.
    Tpm2SealedPin = 10,
    /// Hybrid TPM 2.0 + ML-KEM-768 keyslot. KEK derives from BOTH
    /// the TPM unseal output AND a Kyber decapsulation:
    ///   `KEK = HKDF(salt, tpm_unsealed || pq_shared, "lbx:hybrid-tpm-kek/v1")`.
    /// Closes the quantum gap in the TPM-only path: the TPM's wrap
    /// is RSA-2048 / ECC P-256, both quantum-broken. Adding ML-KEM
    /// means a CRQC adversary who steals the vault file + captures
    /// the TPM's published public key still can't recover the MVK
    /// without the Kyber seed file. On-disk slot bytes are
    /// byte-identical to a `Tpm2Sealed` slot; only the kind byte
    /// and the .lbx.hybrid sidecar entry differ.
    HybridPqKemTpm2 = 11,
    /// Hybrid TPM 2.0 + FIDO2 + ML-KEM-768 keyslot. The
    /// maximum-paranoia mode: KEK derives from THREE independent
    /// secrets (TPM unseal output, FIDO2 hmac-secret output, Kyber
    /// decapsulation). On-disk slot bytes are byte-identical to a
    /// `Tpm2Fido2` slot (sub-format inside cred_id region holding
    /// the TPM blob + FIDO2 cred_id); only the kind byte and the
    /// .lbx.hybrid sidecar entry differ. Loss of any factor kills
    /// the slot. Subject to the same 352 B cred_id-region
    /// constraint as `Tpm2Fido2`.
    HybridPqKemTpm2Fido2 = 12,
    /// Same as `HybridPqKemTpm2` but with ML-KEM-1024 (FIPS 203
    /// security category 5, ~AES-256). Wire-shape on disk is
    /// byte-identical; only the kind byte and the .hybrid sidecar
    /// entry's level byte differ.
    HybridPqKem1024Tpm2 = 13,
    /// Same as `HybridPqKemTpm2Fido2` but with ML-KEM-1024.
    HybridPqKem1024Tpm2Fido2 = 14,
}

impl SlotKind {
    /// True for any of the hybrid-PQ slot kinds. Includes the
    /// TPM-bound combinations (768 + 1024 variants) alongside the
    /// original passphrase/FIDO2 hybrids.
    pub fn is_hybrid_pq(self) -> bool {
        matches!(
            self,
            Self::HybridPqKemPassphrase
                | Self::HybridPqKemFido2
                | Self::HybridPqKem1024Passphrase
                | Self::HybridPqKem1024Fido2
                | Self::HybridPqKemTpm2
                | Self::HybridPqKemTpm2Fido2
                | Self::HybridPqKem1024Tpm2
                | Self::HybridPqKem1024Tpm2Fido2
        )
    }

    /// True for the ML-KEM-1024 hybrid kinds (passphrase, FIDO2,
    /// TPM, TPM+FIDO2 variants).
    pub fn is_hybrid_pq_1024(self) -> bool {
        matches!(
            self,
            Self::HybridPqKem1024Passphrase
                | Self::HybridPqKem1024Fido2
                | Self::HybridPqKem1024Tpm2
                | Self::HybridPqKem1024Tpm2Fido2
        )
    }

    /// True for the passphrase-side hybrid kinds (vs FIDO2-side).
    pub fn is_hybrid_pq_passphrase(self) -> bool {
        matches!(
            self,
            Self::HybridPqKemPassphrase | Self::HybridPqKem1024Passphrase
        )
    }

    /// True for the FIDO2-side hybrid kinds.
    pub fn is_hybrid_pq_fido2(self) -> bool {
        matches!(self, Self::HybridPqKemFido2 | Self::HybridPqKem1024Fido2)
    }

    /// True for any TPM 2.0-backed slot kind (Tpm2-only, fused
    /// TPM+FIDO2, PIN-protected, or PQ-hybrid TPM variants in
    /// either ML-KEM-768 or 1024 strength).
    pub fn is_tpm2(self) -> bool {
        matches!(
            self,
            Self::Tpm2Sealed
                | Self::Tpm2Fido2
                | Self::Tpm2SealedPin
                | Self::HybridPqKemTpm2
                | Self::HybridPqKemTpm2Fido2
                | Self::HybridPqKem1024Tpm2
                | Self::HybridPqKem1024Tpm2Fido2
        )
    }

    /// True for the fused TPM+FIDO2 slot kinds (plain or hybrid-PQ
    /// 768/1024).
    pub fn is_tpm2_fido2(self) -> bool {
        matches!(
            self,
            Self::Tpm2Fido2 | Self::HybridPqKemTpm2Fido2 | Self::HybridPqKem1024Tpm2Fido2
        )
    }

    /// True iff this kind requires a user PIN to unseal (currently
    /// only `Tpm2SealedPin`; future PIN+FIDO2 / PIN+PQ combos would
    /// be added here).
    pub fn is_tpm2_pin(self) -> bool {
        matches!(self, Self::Tpm2SealedPin)
    }
}

impl SlotKind {
    fn from_u8(v: u8) -> Result<Self, Error> {
        match v {
            0 => Ok(Self::Empty),
            1 => Ok(Self::Passphrase),
            2 => Ok(Self::Fido2HmacSecret),
            3 => Ok(Self::Fido2DerivedMvk),
            4 => Ok(Self::HybridPqKemPassphrase),
            5 => Ok(Self::HybridPqKemFido2),
            6 => Ok(Self::HybridPqKem1024Passphrase),
            7 => Ok(Self::HybridPqKem1024Fido2),
            8 => Ok(Self::Tpm2Sealed),
            9 => Ok(Self::Tpm2Fido2),
            10 => Ok(Self::Tpm2SealedPin),
            11 => Ok(Self::HybridPqKemTpm2),
            12 => Ok(Self::HybridPqKemTpm2Fido2),
            13 => Ok(Self::HybridPqKem1024Tpm2),
            14 => Ok(Self::HybridPqKem1024Tpm2Fido2),
            _ => Err(Error::UnsupportedSlotKind(v)),
        }
    }
}

/// One on-disk keyslot. Always 512 bytes; a fully-zero slot is `Empty`.
///
/// The wrapped MVK (32 B ciphertext + 16 B tag) is sealed with the per-slot KEK
/// using the container's `cipher_suite`, with AAD =
///    `slot_bytes[0..76] || header_salt`
/// so any tamper on the slot params or relocation between containers fails the AEAD tag.
#[derive(Clone)]
pub struct Keyslot {
    pub kind: SlotKind,
    /// AEAD AAD shape, see `OFF_AAD_VERSION` doc. Set by every
    /// `Keyslot::new_*` constructor to `AAD_VERSION_V4`. Read by
    /// `from_bytes` from the on-disk byte. Empty slots leave it 0.
    pub aad_version: u8,
    pub uuid: [u8; 16],
    pub kdf_params: Argon2idParams,
    pub kdf_salt: [u8; 32],
    pub aead_nonce: [u8; 12],
    pub wrapped_ct: [u8; 32],
    pub wrapped_tag: [u8; 16],
    pub fido2_cred_id: Vec<u8>,
    pub fido2_hmac_salt: [u8; 32],
}

// Custom Drop so the heap-allocated cred_id buffer is wiped before
// the allocator reuses its pages. cred_id is a public CTAP2 handle
// (not cryptographically secret), but the rest of the codebase
// uniformly zeroizes its heap-resident byte buffers and not doing it
// here is a defense-in-depth inconsistency flagged in a security
// review. `Vec::zeroize` from the zeroize crate writes zeros across
// the full capacity (not just the active length) and then truncates,
// so any over-allocation from `to_vec()` / `combined` builders is
// cleared too. The fixed-size [u8; N] arrays on this struct live in
// the struct's own storage; they are zeroed by Rust's automatic drop
// glue when the Keyslot is destructured (no allocator handoff), so
// no extra wiping is needed for those.
impl Drop for Keyslot {
    fn drop(&mut self) {
        use zeroize::Zeroize as _;
        self.fido2_cred_id.zeroize();
    }
}

impl Keyslot {
    pub fn empty() -> Self {
        Self {
            kind: SlotKind::Empty,
            // Empty slots aren't AEAD-checked; aad_version is unused.
            aad_version: AAD_VERSION_V1,
            uuid: [0; 16],
            kdf_params: Argon2idParams {
                m_cost_kib: 0,
                t_cost: 0,
                p_cost: 0,
            },
            kdf_salt: [0; 32],
            aead_nonce: [0; 12],
            wrapped_ct: [0; 32],
            wrapped_tag: [0; 16],
            fido2_cred_id: Vec::new(),
            fido2_hmac_salt: [0; 32],
        }
    }

    pub fn is_empty(&self) -> bool {
        matches!(self.kind, SlotKind::Empty)
    }

    /// Does this slot's wire format use the V4 cross-platform FIDO2
    /// salt convention (the W3C WebAuthn-PRF derivation
    /// `T(x) = SHA-256("WebAuthn PRF"\0 || x)`) before the salt reaches
    /// the authenticator? The boolean is forwarded to
    /// `Fido2Authenticator::hmac_secret`'s `prehash_salt` parameter.
    ///
    /// V1/V2/V3 FIDO2 slots: false -- libfido2 sends the raw salt.
    /// These slots are Linux/macOS-only because webauthn.dll on Windows
    /// unconditionally applies `T`, producing a different HMAC output.
    /// V4+ FIDO2 slots: true -- the libfido2 backend applies `T`
    /// locally, and the Windows backend forwards the raw salt and lets
    /// webauthn.dll apply the identical `T`. Both converge
    /// cross-platform.
    ///
    /// (The name predates the V4 redefinition: it is no longer a plain
    /// SHA-256 "prehash" but the PRF-prefixed derivation. Kept as-is to
    /// avoid churning ~80 call sites; semantics are documented here.)
    ///
    /// Non-FIDO2 slot kinds return false (the result is unused for
    /// them; `fido2_hmac_salt` is all zeros and never sent to a
    /// device).
    pub fn fido2_salt_prehashed(&self) -> bool {
        self.aad_version >= AAD_VERSION_V4
    }

    /// True for any slot kind whose unlock path drives the FIDO2
    /// hmac-secret extension. Useful for the Windows "v1/v2/v3
    /// FIDO2 slot is Linux-only, run `luksbox migrate-fido2-slot`"
    /// guard at unlock time and for the `luksbox info` slot table.
    pub fn touches_fido2(&self) -> bool {
        matches!(
            self.kind,
            SlotKind::Fido2HmacSecret
                | SlotKind::Fido2DerivedMvk
                | SlotKind::HybridPqKemFido2
                | SlotKind::HybridPqKem1024Fido2
                | SlotKind::Tpm2Fido2
                | SlotKind::HybridPqKemTpm2Fido2
                | SlotKind::HybridPqKem1024Tpm2Fido2
        )
    }

    /// Create a passphrase keyslot wrapping `mvk`.
    pub fn new_passphrase(
        suite: CipherSuite,
        mvk: &MasterVolumeKey,
        passphrase: &[u8],
        kdf_params: Argon2idParams,
        header_salt: &[u8; 32],
    ) -> Result<Self, Error> {
        let mut uuid = [0u8; 16];
        let mut kdf_salt = [0u8; 32];
        let mut aead_nonce = [0u8; 12];
        OsRng
            .try_fill_bytes(&mut uuid)
            .map_err(|e| Error::OsRng(e.to_string()))?;
        OsRng
            .try_fill_bytes(&mut kdf_salt)
            .map_err(|e| Error::OsRng(e.to_string()))?;
        OsRng
            .try_fill_bytes(&mut aead_nonce)
            .map_err(|e| Error::OsRng(e.to_string()))?;

        let mut slot = Self {
            kind: SlotKind::Passphrase,
            aad_version: AAD_VERSION_V4,
            uuid,
            kdf_params,
            kdf_salt,
            aead_nonce,
            wrapped_ct: [0; 32],
            wrapped_tag: [0; 16],
            fido2_cred_id: Vec::new(),
            fido2_hmac_salt: [0; 32],
        };
        let kek = derive_kek(passphrase, &kdf_salt, kdf_params)?;
        slot.wrap_mvk(suite, &kek, mvk, header_salt)?;
        Ok(slot)
    }

    /// Create a FIDO2 hmac-secret keyslot wrapping `mvk`. `hmac_secret` is the
    /// 32-byte authenticator output for `fido2_hmac_salt`, optionally combined
    /// with a passphrase before stretching.
    pub fn new_fido2(
        suite: CipherSuite,
        mvk: &MasterVolumeKey,
        passphrase: Option<&[u8]>,
        hmac_secret: &[u8; 32],
        cred_id: &[u8],
        hmac_salt: [u8; 32],
        kdf_params: Argon2idParams,
        header_salt: &[u8; 32],
    ) -> Result<Self, Error> {
        if cred_id.len() > FIDO2_CRED_ID_MAX {
            return Err(Error::Fido2CredIdTooLong(cred_id.len()));
        }
        let mut uuid = [0u8; 16];
        let mut kdf_salt = [0u8; 32];
        let mut aead_nonce = [0u8; 12];
        OsRng
            .try_fill_bytes(&mut uuid)
            .map_err(|e| Error::OsRng(e.to_string()))?;
        OsRng
            .try_fill_bytes(&mut kdf_salt)
            .map_err(|e| Error::OsRng(e.to_string()))?;
        OsRng
            .try_fill_bytes(&mut aead_nonce)
            .map_err(|e| Error::OsRng(e.to_string()))?;

        let mut slot = Self {
            kind: SlotKind::Fido2HmacSecret,
            aad_version: AAD_VERSION_V4,
            uuid,
            kdf_params,
            kdf_salt,
            aead_nonce,
            wrapped_ct: [0; 32],
            wrapped_tag: [0; 16],
            fido2_cred_id: cred_id.to_vec(),
            fido2_hmac_salt: hmac_salt,
        };
        let pass = passphrase.unwrap_or(b"");
        let kek = derive_kek_with_fido2(pass, hmac_secret, &kdf_salt, kdf_params)?;
        slot.wrap_mvk(suite, &kek, mvk, header_salt)?;
        Ok(slot)
    }

    /// Build a TPM 2.0-sealed keyslot wrapping `mvk` under
    /// `kek_from_tpm` (a 32-byte random KEK that the caller has
    /// already sealed via `luksbox_tpm::Tpm2Sealer::seal` and whose
    /// resulting blob bytes are passed in `sealed_blob`).
    ///
    /// This module deliberately doesn't depend on `luksbox-tpm` -
    /// the TPM I/O happens up in `luksbox-format::Container`. From
    /// `luksbox-core`'s point of view the KEK is just a 32-byte
    /// secret like any other; the TPM aspect only matters for
    /// where it came from + where it lives (the sealed blob in
    /// `sealed_blob`).
    ///
    /// `sealed_blob` length is bounded by the slot's variable
    /// region capacity (`FIDO2_CRED_ID_MAX` = 352 B in V3); a real
    /// TPM-sealed-data-object blob is typically 250-300 B, so this
    /// fits with margin.
    pub fn new_tpm2(
        suite: CipherSuite,
        mvk: &MasterVolumeKey,
        kek_from_tpm: &[u8; KEY_LEN],
        sealed_blob: &[u8],
        header_salt: &[u8; 32],
    ) -> Result<Self, Error> {
        if sealed_blob.len() > FIDO2_CRED_ID_MAX {
            // Same error type as cred-id-too-long; conceptually it's
            // the same "variable blob doesn't fit in the slot's
            // reserved region" condition, just with a different
            // semantic for the blob.
            return Err(Error::Fido2CredIdTooLong(sealed_blob.len()));
        }
        let mut uuid = [0u8; 16];
        let mut aead_nonce = [0u8; 12];
        OsRng
            .try_fill_bytes(&mut uuid)
            .map_err(|e| Error::OsRng(e.to_string()))?;
        OsRng
            .try_fill_bytes(&mut aead_nonce)
            .map_err(|e| Error::OsRng(e.to_string()))?;

        let mut slot = Self {
            kind: SlotKind::Tpm2Sealed,
            aad_version: AAD_VERSION_V4,
            uuid,
            // No Argon2id is run for TPM-sealed slots - the KEK
            // comes from the TPM unseal directly. Zero params
            // signal this and are exempt from the on-read sanity
            // check (see `from_bytes`'s `kdf_runs_argon2`).
            kdf_params: Argon2idParams {
                m_cost_kib: 0,
                t_cost: 0,
                p_cost: 0,
            },
            // The KDF salt field is unused for TPM slots but we
            // fill it with random bytes anyway to keep the
            // on-disk byte distribution indistinguishable from
            // other slot kinds.
            kdf_salt: {
                let mut s = [0u8; 32];
                OsRng
                    .try_fill_bytes(&mut s)
                    .map_err(|e| Error::OsRng(e.to_string()))?;
                s
            },
            aead_nonce,
            wrapped_ct: [0; 32],
            wrapped_tag: [0; 16],
            // `fido2_cred_id` is repurposed as the generic
            // variable-length per-slot blob; for Tpm2Sealed slots
            // it carries the TPM SealedBlob bytes
            // (TPM2B_PUBLIC + TPM2B_PRIVATE with length prefixes,
            // see `luksbox_tpm::SealedBlob::to_bytes`).
            fido2_cred_id: sealed_blob.to_vec(),
            fido2_hmac_salt: [0; 32],
        };
        let kek = KeyEncryptionKey::from_array_ref(kek_from_tpm);
        slot.wrap_mvk(suite, &kek, mvk, header_salt)?;
        Ok(slot)
    }

    /// Recover the MVK from a TPM-sealed slot. Caller must have
    /// already obtained `kek_from_tpm` by calling
    /// `luksbox_tpm::Tpm2Sealer::unseal(self.tpm2_sealed_blob())`
    /// (or `unseal_with_pin` for `Tpm2SealedPin` slots).
    ///
    /// Accepts both `Tpm2Sealed` and `Tpm2SealedPin` because the
    /// MVK-unwrap logic is identical for both - the PIN is enforced
    /// at the TPM layer, not here. Reject the other TPM kinds
    /// (which have different KEK derivations).
    pub fn unlock_tpm2(
        &self,
        suite: CipherSuite,
        kek_from_tpm: &[u8; KEY_LEN],
        header_salt: &[u8; 32],
    ) -> Result<MasterVolumeKey, Error> {
        if !matches!(self.kind, SlotKind::Tpm2Sealed | SlotKind::Tpm2SealedPin) {
            return Err(Error::InvalidField);
        }
        let kek = KeyEncryptionKey::from_array_ref(kek_from_tpm);
        self.unwrap_mvk(suite, &kek, header_salt)
    }

    /// Accessor for the TPM SealedBlob bytes stored in this slot.
    /// Returns `None` for non-TPM slot kinds OR for the fused kinds
    /// which use a sub-format (use `tpm2_fido2_sealed_blob` for
    /// those).
    ///
    /// Covers `Tpm2Sealed`, `Tpm2SealedPin`, `HybridPqKemTpm2`,
    /// and `HybridPqKem1024Tpm2` - all four store the raw
    /// SealedBlob bytes in the variable-length region with no
    /// sub-format.
    pub fn tpm2_sealed_blob(&self) -> Option<&[u8]> {
        if matches!(
            self.kind,
            SlotKind::Tpm2Sealed
                | SlotKind::Tpm2SealedPin
                | SlotKind::HybridPqKemTpm2
                | SlotKind::HybridPqKem1024Tpm2
        ) {
            Some(&self.fido2_cred_id)
        } else {
            None
        }
    }

    /// Build a fused TPM+FIDO2 keyslot wrapping `mvk` under a KEK
    /// derived from BOTH `tpm_unsealed` (a 32-byte value the caller
    /// has already sealed via `Tpm2Sealer::seal` and whose blob
    /// bytes are passed in `sealed_blob`) AND `hmac_secret` (the
    /// FIDO2 authenticator's hmac-secret output for `hmac_salt`).
    ///
    /// On-disk: the variable-length region packs
    /// `[tpm_blob_len: u16 LE | tpm_blob | cred_id]`. Total must
    /// fit `FIDO2_CRED_ID_MAX` (352 B). For typical YubiKey
    /// authenticators (cred_id about 60-80 B) plus a TPM sealed-data
    /// object (about 280 B) this fits with margin; for larger cred IDs
    /// (Google Titan about 288 B) it overflows and this constructor
    /// returns `Fido2CredIdTooLong`.
    pub fn new_tpm2_fido2(
        suite: CipherSuite,
        mvk: &MasterVolumeKey,
        tpm_unsealed: &[u8; KEY_LEN],
        hmac_secret: &[u8; KEY_LEN],
        sealed_blob: &[u8],
        cred_id: &[u8],
        hmac_salt: [u8; 32],
        header_salt: &[u8; 32],
    ) -> Result<Self, Error> {
        // 2-byte length prefix + sealed_blob + cred_id, all packed
        // into the cred_id region.
        let combined_len = 2usize
            .checked_add(sealed_blob.len())
            .and_then(|n| n.checked_add(cred_id.len()))
            .ok_or(Error::InvalidField)?;
        if combined_len > FIDO2_CRED_ID_MAX {
            return Err(Error::Fido2CredIdTooLong(combined_len));
        }
        if sealed_blob.len() > u16::MAX as usize {
            return Err(Error::InvalidField);
        }
        let mut combined = Vec::with_capacity(combined_len);
        combined.extend_from_slice(&(sealed_blob.len() as u16).to_le_bytes());
        combined.extend_from_slice(sealed_blob);
        combined.extend_from_slice(cred_id);

        let mut uuid = [0u8; 16];
        let mut aead_nonce = [0u8; 12];
        OsRng
            .try_fill_bytes(&mut uuid)
            .map_err(|e| Error::OsRng(e.to_string()))?;
        OsRng
            .try_fill_bytes(&mut aead_nonce)
            .map_err(|e| Error::OsRng(e.to_string()))?;

        let mut slot = Self {
            kind: SlotKind::Tpm2Fido2,
            aad_version: AAD_VERSION_V4,
            uuid,
            // No Argon2id for the fused kind, both inputs are
            // already 32-byte high-entropy values, HKDF mixing is
            // sufficient. Zero params, exempt from on-read sanity.
            kdf_params: Argon2idParams {
                m_cost_kib: 0,
                t_cost: 0,
                p_cost: 0,
            },
            kdf_salt: {
                let mut s = [0u8; 32];
                OsRng
                    .try_fill_bytes(&mut s)
                    .map_err(|e| Error::OsRng(e.to_string()))?;
                s
            },
            aead_nonce,
            wrapped_ct: [0; 32],
            wrapped_tag: [0; 16],
            fido2_cred_id: combined,
            fido2_hmac_salt: hmac_salt,
        };
        let kek = derive_tpm2_fido2_kek(tpm_unsealed, hmac_secret, header_salt);
        slot.wrap_mvk(suite, &kek, mvk, header_salt)?;
        Ok(slot)
    }

    /// Recover the MVK from a fused TPM+FIDO2 slot. Caller has
    /// already obtained `tpm_unsealed` (via the slot's blob through
    /// `Tpm2Sealer::unseal`) AND `hmac_secret` (via a FIDO2 touch
    /// using the slot's cred_id + hmac_salt). Either factor wrong
    /// -> AEAD failure.
    pub fn unlock_tpm2_fido2(
        &self,
        suite: CipherSuite,
        tpm_unsealed: &[u8; KEY_LEN],
        hmac_secret: &[u8; KEY_LEN],
        header_salt: &[u8; 32],
    ) -> Result<MasterVolumeKey, Error> {
        if self.kind != SlotKind::Tpm2Fido2 {
            return Err(Error::InvalidField);
        }
        let kek = derive_tpm2_fido2_kek(tpm_unsealed, hmac_secret, header_salt);
        self.unwrap_mvk(suite, &kek, header_salt)
    }

    /// Accessor for the TPM-half of a fused TPM+FIDO2 slot's
    /// variable region. Covers `Tpm2Fido2`, `HybridPqKemTpm2Fido2`,
    /// and `HybridPqKem1024Tpm2Fido2` (all three use the same
    /// sub-format inside the cred_id region).
    pub fn tpm2_fido2_sealed_blob(&self) -> Option<&[u8]> {
        if !matches!(
            self.kind,
            SlotKind::Tpm2Fido2
                | SlotKind::HybridPqKemTpm2Fido2
                | SlotKind::HybridPqKem1024Tpm2Fido2
        ) {
            return None;
        }
        let buf = &self.fido2_cred_id;
        if buf.len() < 2 {
            return None;
        }
        let blob_len = u16::from_le_bytes([buf[0], buf[1]]) as usize;
        if buf.len() < 2 + blob_len {
            return None;
        }
        Some(&buf[2..2 + blob_len])
    }

    /// Accessor for the FIDO2 cred_id half of a fused TPM+FIDO2
    /// slot's variable region. Covers `Tpm2Fido2`,
    /// `HybridPqKemTpm2Fido2`, and `HybridPqKem1024Tpm2Fido2`.
    pub fn tpm2_fido2_cred_id(&self) -> Option<&[u8]> {
        if !matches!(
            self.kind,
            SlotKind::Tpm2Fido2
                | SlotKind::HybridPqKemTpm2Fido2
                | SlotKind::HybridPqKem1024Tpm2Fido2
        ) {
            return None;
        }
        let buf = &self.fido2_cred_id;
        if buf.len() < 2 {
            return None;
        }
        let blob_len = u16::from_le_bytes([buf[0], buf[1]]) as usize;
        let off = 2usize.checked_add(blob_len)?;
        if buf.len() < off {
            return None;
        }
        Some(&buf[off..])
    }

    /// Build a TPM-sealed keyslot whose unseal requires a user PIN.
    /// The PIN is enforced at the TPM layer (the SealedBlob's
    /// userAuth was set via `Tpm2Sealer::seal_with_pin(_, Some)`);
    /// our wrap of the MVK under the unsealed KEK uses
    /// AES-GCM-SIV with the same shape as `Tpm2Sealed`, only the
    /// slot's `kind` byte differs.
    ///
    /// We can't delegate to `new_tpm2` because the AEAD AAD
    /// includes `kind` - we must set it BEFORE wrap_mvk so the
    /// tag matches at unlock.
    pub fn new_tpm2_pin(
        suite: CipherSuite,
        mvk: &MasterVolumeKey,
        kek_from_tpm: &[u8; KEY_LEN],
        sealed_blob: &[u8],
        header_salt: &[u8; 32],
    ) -> Result<Self, Error> {
        if sealed_blob.len() > FIDO2_CRED_ID_MAX {
            return Err(Error::Fido2CredIdTooLong(sealed_blob.len()));
        }
        let mut uuid = [0u8; 16];
        let mut aead_nonce = [0u8; 12];
        OsRng
            .try_fill_bytes(&mut uuid)
            .map_err(|e| Error::OsRng(e.to_string()))?;
        OsRng
            .try_fill_bytes(&mut aead_nonce)
            .map_err(|e| Error::OsRng(e.to_string()))?;
        let mut slot = Self {
            kind: SlotKind::Tpm2SealedPin,
            aad_version: AAD_VERSION_V4,
            uuid,
            kdf_params: Argon2idParams {
                m_cost_kib: 0,
                t_cost: 0,
                p_cost: 0,
            },
            kdf_salt: {
                let mut s = [0u8; 32];
                OsRng
                    .try_fill_bytes(&mut s)
                    .map_err(|e| Error::OsRng(e.to_string()))?;
                s
            },
            aead_nonce,
            wrapped_ct: [0; 32],
            wrapped_tag: [0; 16],
            fido2_cred_id: sealed_blob.to_vec(),
            fido2_hmac_salt: [0; 32],
        };
        let kek = KeyEncryptionKey::from_array_ref(kek_from_tpm);
        slot.wrap_mvk(suite, &kek, mvk, header_salt)?;
        Ok(slot)
    }

    /// Build a hybrid TPM + ML-KEM keyslot. KEK derives from BOTH
    /// the TPM unseal output AND the Kyber-decapsulated shared
    /// secret. Caller stores the Kyber pubkey + ciphertext in the
    /// `.lbx.hybrid` sidecar (existing per-slot v2 format).
    /// On-disk slot bytes are identical to `Tpm2Sealed` apart from
    /// the kind byte; only the .hybrid sidecar entry differentiates.
    pub fn new_hybrid_pq_tpm2(
        suite: CipherSuite,
        mvk: &MasterVolumeKey,
        kek_from_tpm: &[u8; KEY_LEN],
        pq_shared: &[u8; KEY_LEN],
        sealed_blob: &[u8],
        header_salt: &[u8; 32],
    ) -> Result<Self, Error> {
        if sealed_blob.len() > FIDO2_CRED_ID_MAX {
            return Err(Error::Fido2CredIdTooLong(sealed_blob.len()));
        }
        let mut uuid = [0u8; 16];
        let mut aead_nonce = [0u8; 12];
        OsRng
            .try_fill_bytes(&mut uuid)
            .map_err(|e| Error::OsRng(e.to_string()))?;
        OsRng
            .try_fill_bytes(&mut aead_nonce)
            .map_err(|e| Error::OsRng(e.to_string()))?;
        let mut slot = Self {
            kind: SlotKind::HybridPqKemTpm2,
            aad_version: AAD_VERSION_V4,
            uuid,
            kdf_params: Argon2idParams {
                m_cost_kib: 0,
                t_cost: 0,
                p_cost: 0,
            },
            kdf_salt: {
                let mut s = [0u8; 32];
                OsRng
                    .try_fill_bytes(&mut s)
                    .map_err(|e| Error::OsRng(e.to_string()))?;
                s
            },
            aead_nonce,
            wrapped_ct: [0; 32],
            wrapped_tag: [0; 16],
            fido2_cred_id: sealed_blob.to_vec(),
            fido2_hmac_salt: [0; 32],
        };
        let kek = derive_hybrid_tpm2_kek(kek_from_tpm, pq_shared, header_salt);
        slot.wrap_mvk(suite, &kek, mvk, header_salt)?;
        Ok(slot)
    }

    /// Recover the MVK from a hybrid TPM + ML-KEM slot. Accepts
    /// both 768 and 1024 variants (KEK derivation is identical;
    /// only the on-disk slot kind byte and the .hybrid sidecar
    /// entry's level byte differ).
    pub fn unlock_hybrid_pq_tpm2(
        &self,
        suite: CipherSuite,
        kek_from_tpm: &[u8; KEY_LEN],
        pq_shared: &[u8; KEY_LEN],
        header_salt: &[u8; 32],
    ) -> Result<MasterVolumeKey, Error> {
        if !matches!(
            self.kind,
            SlotKind::HybridPqKemTpm2 | SlotKind::HybridPqKem1024Tpm2
        ) {
            return Err(Error::InvalidField);
        }
        let kek = derive_hybrid_tpm2_kek(kek_from_tpm, pq_shared, header_salt);
        self.unwrap_mvk(suite, &kek, header_salt)
    }

    /// Build the maximum-paranoia hybrid TPM + FIDO2 + ML-KEM
    /// keyslot. KEK derives from THREE 32 B inputs (TPM unseal,
    /// FIDO2 hmac-secret, Kyber decap). On-disk slot bytes use the
    /// same sub-format as `Tpm2Fido2` (`[tpm_blob_len|blob|cred_id]`
    /// in the variable region + hmac_salt at OFF_HMAC_SALT_V3);
    /// only the kind byte differs.
    pub fn new_hybrid_pq_tpm2_fido2(
        suite: CipherSuite,
        mvk: &MasterVolumeKey,
        tpm_unsealed: &[u8; KEY_LEN],
        hmac_secret: &[u8; KEY_LEN],
        pq_shared: &[u8; KEY_LEN],
        sealed_blob: &[u8],
        cred_id: &[u8],
        hmac_salt: [u8; 32],
        header_salt: &[u8; 32],
    ) -> Result<Self, Error> {
        let combined_len = 2usize
            .checked_add(sealed_blob.len())
            .and_then(|n| n.checked_add(cred_id.len()))
            .ok_or(Error::InvalidField)?;
        if combined_len > FIDO2_CRED_ID_MAX {
            return Err(Error::Fido2CredIdTooLong(combined_len));
        }
        if sealed_blob.len() > u16::MAX as usize {
            return Err(Error::InvalidField);
        }
        let mut combined = Vec::with_capacity(combined_len);
        combined.extend_from_slice(&(sealed_blob.len() as u16).to_le_bytes());
        combined.extend_from_slice(sealed_blob);
        combined.extend_from_slice(cred_id);

        let mut uuid = [0u8; 16];
        let mut aead_nonce = [0u8; 12];
        OsRng
            .try_fill_bytes(&mut uuid)
            .map_err(|e| Error::OsRng(e.to_string()))?;
        OsRng
            .try_fill_bytes(&mut aead_nonce)
            .map_err(|e| Error::OsRng(e.to_string()))?;
        let mut slot = Self {
            kind: SlotKind::HybridPqKemTpm2Fido2,
            aad_version: AAD_VERSION_V4,
            uuid,
            kdf_params: Argon2idParams {
                m_cost_kib: 0,
                t_cost: 0,
                p_cost: 0,
            },
            kdf_salt: {
                let mut s = [0u8; 32];
                OsRng
                    .try_fill_bytes(&mut s)
                    .map_err(|e| Error::OsRng(e.to_string()))?;
                s
            },
            aead_nonce,
            wrapped_ct: [0; 32],
            wrapped_tag: [0; 16],
            fido2_cred_id: combined,
            fido2_hmac_salt: hmac_salt,
        };
        let kek = derive_hybrid_tpm2_fido2_kek(tpm_unsealed, hmac_secret, pq_shared, header_salt);
        slot.wrap_mvk(suite, &kek, mvk, header_salt)?;
        Ok(slot)
    }

    /// Recover the MVK from the hybrid TPM + FIDO2 + ML-KEM slot.
    /// Accepts both 768 and 1024 variants since the KEK derivation
    /// is identical (only the on-disk slot kind byte and the
    /// .hybrid sidecar entry's level byte differ).
    pub fn unlock_hybrid_pq_tpm2_fido2(
        &self,
        suite: CipherSuite,
        tpm_unsealed: &[u8; KEY_LEN],
        hmac_secret: &[u8; KEY_LEN],
        pq_shared: &[u8; KEY_LEN],
        header_salt: &[u8; 32],
    ) -> Result<MasterVolumeKey, Error> {
        if !matches!(
            self.kind,
            SlotKind::HybridPqKemTpm2Fido2 | SlotKind::HybridPqKem1024Tpm2Fido2
        ) {
            return Err(Error::InvalidField);
        }
        let kek = derive_hybrid_tpm2_fido2_kek(tpm_unsealed, hmac_secret, pq_shared, header_salt);
        self.unwrap_mvk(suite, &kek, header_salt)
    }

    /// ML-KEM-1024 variant of `new_hybrid_pq_tpm2`. Identical KEK
    /// derivation; only the slot's `kind` byte differs (= 13 vs 11).
    /// Caller is responsible for using ML-KEM-1024 when generating
    /// the Kyber keypair + storing `level = Ml1024` in the
    /// .lbx.hybrid sidecar entry.
    pub fn new_hybrid_pq_1024_tpm2(
        suite: CipherSuite,
        mvk: &MasterVolumeKey,
        kek_from_tpm: &[u8; KEY_LEN],
        pq_shared: &[u8; KEY_LEN],
        sealed_blob: &[u8],
        header_salt: &[u8; 32],
    ) -> Result<Self, Error> {
        let mut s = Self::new_hybrid_pq_tpm2(
            suite,
            mvk,
            kek_from_tpm,
            pq_shared,
            sealed_blob,
            header_salt,
        )?;
        s.kind = SlotKind::HybridPqKem1024Tpm2;
        // Re-wrap with the new kind byte in the AAD - the kind is
        // part of the header AAD region so changing it after wrap
        // would break the AEAD tag.
        s.wrapped_ct = [0; 32];
        s.wrapped_tag = [0; 16];
        // Re-derive a fresh aead_nonce so we don't reuse the 768
        // slot's nonce under a different kind (defense in depth).
        OsRng
            .try_fill_bytes(&mut s.aead_nonce)
            .map_err(|e| Error::OsRng(e.to_string()))?;
        let kek = derive_hybrid_tpm2_kek(kek_from_tpm, pq_shared, header_salt);
        s.wrap_mvk(suite, &kek, mvk, header_salt)?;
        Ok(s)
    }

    /// ML-KEM-1024 variant of `new_hybrid_pq_tpm2_fido2`.
    pub fn new_hybrid_pq_1024_tpm2_fido2(
        suite: CipherSuite,
        mvk: &MasterVolumeKey,
        tpm_unsealed: &[u8; KEY_LEN],
        hmac_secret: &[u8; KEY_LEN],
        pq_shared: &[u8; KEY_LEN],
        sealed_blob: &[u8],
        cred_id: &[u8],
        hmac_salt: [u8; 32],
        header_salt: &[u8; 32],
    ) -> Result<Self, Error> {
        let mut s = Self::new_hybrid_pq_tpm2_fido2(
            suite,
            mvk,
            tpm_unsealed,
            hmac_secret,
            pq_shared,
            sealed_blob,
            cred_id,
            hmac_salt,
            header_salt,
        )?;
        s.kind = SlotKind::HybridPqKem1024Tpm2Fido2;
        s.wrapped_ct = [0; 32];
        s.wrapped_tag = [0; 16];
        OsRng
            .try_fill_bytes(&mut s.aead_nonce)
            .map_err(|e| Error::OsRng(e.to_string()))?;
        let kek = derive_hybrid_tpm2_fido2_kek(tpm_unsealed, hmac_secret, pq_shared, header_salt);
        s.wrap_mvk(suite, &kek, mvk, header_salt)?;
        Ok(s)
    }

    /// Try to recover the MVK from a passphrase slot.
    pub fn unlock_passphrase(
        &self,
        suite: CipherSuite,
        passphrase: &[u8],
        header_salt: &[u8; 32],
    ) -> Result<MasterVolumeKey, Error> {
        if self.kind != SlotKind::Passphrase {
            return Err(Error::InvalidField);
        }
        let kek = derive_kek(passphrase, &self.kdf_salt, self.kdf_params)?;
        self.unwrap_mvk(suite, &kek, header_salt)
    }

    /// Build a hybrid passphrase + ML-KEM keyslot wrapping `mvk`. The
    /// caller is responsible for separately storing the Kyber public key
    /// and ciphertext in the `<vault>.lbx.hybrid` sidecar (this module
    /// doesn't see the sidecar, slot bytes are byte-identical to a
    /// plain passphrase slot apart from the kind byte). Defaults to
    /// kind=4 (HybridPqKemPassphrase, ML-KEM-768); use
    /// `new_hybrid_pq_1024_passphrase` for the higher-strength variant.
    pub fn new_hybrid_pq_passphrase(
        suite: CipherSuite,
        mvk: &MasterVolumeKey,
        passphrase: &[u8],
        pq_shared: &[u8; 32],
        kdf_params: Argon2idParams,
        header_salt: &[u8; 32],
    ) -> Result<Self, Error> {
        Self::build_hybrid_pq_passphrase(
            SlotKind::HybridPqKemPassphrase,
            suite,
            mvk,
            passphrase,
            pq_shared,
            kdf_params,
            header_salt,
        )
    }

    /// Internal: shared body for the 768 and 1024 passphrase-hybrid
    /// constructors. The kind byte is part of the AEAD AAD, so it
    /// MUST be set before `wrap_mvk` runs, that's why this needs to
    /// be a single function with the kind parameterised, not a
    /// "construct then mutate" pattern.
    fn build_hybrid_pq_passphrase(
        kind: SlotKind,
        suite: CipherSuite,
        mvk: &MasterVolumeKey,
        passphrase: &[u8],
        pq_shared: &[u8; 32],
        kdf_params: Argon2idParams,
        header_salt: &[u8; 32],
    ) -> Result<Self, Error> {
        debug_assert!(kind.is_hybrid_pq_passphrase());
        let mut uuid = [0u8; 16];
        let mut kdf_salt = [0u8; 32];
        let mut aead_nonce = [0u8; 12];
        OsRng
            .try_fill_bytes(&mut uuid)
            .map_err(|e| Error::OsRng(e.to_string()))?;
        OsRng
            .try_fill_bytes(&mut kdf_salt)
            .map_err(|e| Error::OsRng(e.to_string()))?;
        OsRng
            .try_fill_bytes(&mut aead_nonce)
            .map_err(|e| Error::OsRng(e.to_string()))?;

        let mut slot = Self {
            kind,
            aad_version: AAD_VERSION_V4,
            uuid,
            kdf_params,
            kdf_salt,
            aead_nonce,
            wrapped_ct: [0; 32],
            wrapped_tag: [0; 16],
            fido2_cred_id: Vec::new(),
            fido2_hmac_salt: [0; 32],
        };
        let kek = derive_hybrid_kek(passphrase, pq_shared, &kdf_salt, kdf_params)?;
        slot.wrap_mvk(suite, &kek, mvk, header_salt)?;
        Ok(slot)
    }

    /// Recover the MVK from a hybrid keyslot. The caller has already
    /// fetched the Kyber pubkey + ciphertext from the sidecar and the
    /// seed from the user's `.kyber` file, run `decapsulate`, and is
    /// passing the resulting 32-byte shared secret here.
    pub fn unlock_hybrid_pq_passphrase(
        &self,
        suite: CipherSuite,
        passphrase: &[u8],
        pq_shared: &[u8; 32],
        header_salt: &[u8; 32],
    ) -> Result<MasterVolumeKey, Error> {
        // Accepts both the ML-KEM-768 and ML-KEM-1024 passphrase
        // hybrid kinds, the slot's KDF / AEAD is identical regardless
        // of which Kyber parameter set produced `pq_shared`. The kind
        // byte distinguishes the levels for the sidecar lookup; once
        // we have a 32-byte shared, the unwrap path is uniform.
        if !self.kind.is_hybrid_pq_passphrase() {
            return Err(Error::InvalidField);
        }
        let kek = derive_hybrid_kek(passphrase, pq_shared, &self.kdf_salt, self.kdf_params)?;
        self.unwrap_mvk(suite, &kek, header_salt)
    }

    /// ML-KEM-1024 variant of `new_hybrid_pq_passphrase`. Identical
    /// KDF/AEAD; only the slot's `kind` byte differs (= 6 instead of
    /// 4). The caller is responsible for performing the encapsulation
    /// against an ML-KEM-1024 keypair and storing the matching
    /// 1568-byte ciphertext in the v2 sidecar with `level = 2`.
    pub fn new_hybrid_pq_1024_passphrase(
        suite: CipherSuite,
        mvk: &MasterVolumeKey,
        passphrase: &[u8],
        pq_shared: &[u8; 32],
        kdf_params: Argon2idParams,
        header_salt: &[u8; 32],
    ) -> Result<Self, Error> {
        Self::build_hybrid_pq_passphrase(
            SlotKind::HybridPqKem1024Passphrase,
            suite,
            mvk,
            passphrase,
            pq_shared,
            kdf_params,
            header_salt,
        )
    }

    /// Build a hybrid FIDO2 + ML-KEM keyslot wrapping `mvk`. Defaults
    /// to ML-KEM-768; use `new_hybrid_pq_1024_fido2` for ML-KEM-1024.
    pub fn new_hybrid_pq_fido2(
        suite: CipherSuite,
        mvk: &MasterVolumeKey,
        passphrase: Option<&[u8]>,
        hmac_secret: &[u8; 32],
        pq_shared: &[u8; 32],
        cred_id: &[u8],
        hmac_salt: [u8; 32],
        kdf_params: Argon2idParams,
        header_salt: &[u8; 32],
    ) -> Result<Self, Error> {
        Self::build_hybrid_pq_fido2(
            SlotKind::HybridPqKemFido2,
            suite,
            mvk,
            passphrase,
            hmac_secret,
            pq_shared,
            cred_id,
            hmac_salt,
            kdf_params,
            header_salt,
        )
    }

    /// ML-KEM-1024 variant of `new_hybrid_pq_fido2`.
    pub fn new_hybrid_pq_1024_fido2(
        suite: CipherSuite,
        mvk: &MasterVolumeKey,
        passphrase: Option<&[u8]>,
        hmac_secret: &[u8; 32],
        pq_shared: &[u8; 32],
        cred_id: &[u8],
        hmac_salt: [u8; 32],
        kdf_params: Argon2idParams,
        header_salt: &[u8; 32],
    ) -> Result<Self, Error> {
        Self::build_hybrid_pq_fido2(
            SlotKind::HybridPqKem1024Fido2,
            suite,
            mvk,
            passphrase,
            hmac_secret,
            pq_shared,
            cred_id,
            hmac_salt,
            kdf_params,
            header_salt,
        )
    }

    fn build_hybrid_pq_fido2(
        kind: SlotKind,
        suite: CipherSuite,
        mvk: &MasterVolumeKey,
        passphrase: Option<&[u8]>,
        hmac_secret: &[u8; 32],
        pq_shared: &[u8; 32],
        cred_id: &[u8],
        hmac_salt: [u8; 32],
        kdf_params: Argon2idParams,
        header_salt: &[u8; 32],
    ) -> Result<Self, Error> {
        debug_assert!(kind.is_hybrid_pq_fido2());
        if cred_id.len() > FIDO2_CRED_ID_MAX {
            return Err(Error::Fido2CredIdTooLong(cred_id.len()));
        }
        let mut uuid = [0u8; 16];
        let mut kdf_salt = [0u8; 32];
        let mut aead_nonce = [0u8; 12];
        OsRng
            .try_fill_bytes(&mut uuid)
            .map_err(|e| Error::OsRng(e.to_string()))?;
        OsRng
            .try_fill_bytes(&mut kdf_salt)
            .map_err(|e| Error::OsRng(e.to_string()))?;
        OsRng
            .try_fill_bytes(&mut aead_nonce)
            .map_err(|e| Error::OsRng(e.to_string()))?;

        let mut slot = Self {
            kind,
            aad_version: AAD_VERSION_V4,
            uuid,
            kdf_params,
            kdf_salt,
            aead_nonce,
            wrapped_ct: [0; 32],
            wrapped_tag: [0; 16],
            fido2_cred_id: cred_id.to_vec(),
            fido2_hmac_salt: hmac_salt,
        };
        let pass = passphrase.unwrap_or(b"");
        let kek = derive_hybrid_fido2_kek(pass, hmac_secret, pq_shared, &kdf_salt, kdf_params)?;
        slot.wrap_mvk(suite, &kek, mvk, header_salt)?;
        Ok(slot)
    }

    /// Recover the MVK from a hybrid FIDO2 + ML-KEM keyslot. Caller
    /// already produced both the FIDO2 hmac_secret (via the YubiKey)
    /// and the Kyber shared secret (via decapsulate over the sidecar
    /// ciphertext + the seed-file seed).
    pub fn unlock_hybrid_pq_fido2(
        &self,
        suite: CipherSuite,
        passphrase: Option<&[u8]>,
        hmac_secret: &[u8; 32],
        pq_shared: &[u8; 32],
        header_salt: &[u8; 32],
    ) -> Result<MasterVolumeKey, Error> {
        // Accepts both ML-KEM-768 and ML-KEM-1024 FIDO2 hybrid kinds.
        if !self.kind.is_hybrid_pq_fido2() {
            return Err(Error::InvalidField);
        }
        let pass = passphrase.unwrap_or(b"");
        let kek = derive_hybrid_fido2_kek(
            pass,
            hmac_secret,
            pq_shared,
            &self.kdf_salt,
            self.kdf_params,
        )?;
        self.unwrap_mvk(suite, &kek, header_salt)
    }

    /// Try to recover the MVK from a FIDO2 slot, given the hmac-secret output
    /// produced by the authenticator for `self.fido2_hmac_salt`.
    pub fn unlock_fido2(
        &self,
        suite: CipherSuite,
        passphrase: Option<&[u8]>,
        hmac_secret: &[u8; 32],
        header_salt: &[u8; 32],
    ) -> Result<MasterVolumeKey, Error> {
        if self.kind != SlotKind::Fido2HmacSecret {
            return Err(Error::InvalidField);
        }
        let pass = passphrase.unwrap_or(b"");
        let kek = derive_kek_with_fido2(pass, hmac_secret, &self.kdf_salt, self.kdf_params)?;
        self.unwrap_mvk(suite, &kek, header_salt)
    }

    /// Construct a derived-MVK FIDO2 keyslot. Stores cred_id + hmac_salt
    /// only; no wrapped MVK (that's the whole point, there's nothing to
    /// brute-force in the vault). The unused wrap fields are filled with
    /// random bytes for entropy / indistinguishability.
    pub fn new_fido2_derived_mvk(cred_id: &[u8], hmac_salt: [u8; 32]) -> Result<Self, Error> {
        if cred_id.len() > FIDO2_CRED_ID_MAX {
            return Err(Error::Fido2CredIdTooLong(cred_id.len()));
        }
        let mut uuid = [0u8; 16];
        let mut kdf_salt = [0u8; 32];
        let mut aead_nonce = [0u8; 12];
        let mut wrapped_ct = [0u8; 32];
        let mut wrapped_tag = [0u8; 16];
        OsRng
            .try_fill_bytes(&mut uuid)
            .map_err(|e| Error::OsRng(e.to_string()))?;
        OsRng
            .try_fill_bytes(&mut kdf_salt)
            .map_err(|e| Error::OsRng(e.to_string()))?;
        OsRng
            .try_fill_bytes(&mut aead_nonce)
            .map_err(|e| Error::OsRng(e.to_string()))?;
        OsRng
            .try_fill_bytes(&mut wrapped_ct)
            .map_err(|e| Error::OsRng(e.to_string()))?;
        OsRng
            .try_fill_bytes(&mut wrapped_tag)
            .map_err(|e| Error::OsRng(e.to_string()))?;
        Ok(Self {
            kind: SlotKind::Fido2DerivedMvk,
            aad_version: AAD_VERSION_V4,
            uuid,
            // KDF/AEAD params here are unused for derived-MVK slots, but
            // we fill them with non-zero junk so the slot is byte-shape
            // indistinguishable from a wrap-style FIDO2 slot.
            kdf_params: Argon2idParams {
                m_cost_kib: 0,
                t_cost: 0,
                p_cost: 0,
            },
            kdf_salt,
            aead_nonce,
            wrapped_ct,
            wrapped_tag,
            fido2_cred_id: cred_id.to_vec(),
            fido2_hmac_salt: hmac_salt,
        })
    }

    /// Recover the MVK directly from the YubiKey's hmac-secret output.
    /// Caller is expected to verify the result via the header HMAC.
    pub fn unlock_fido2_derived_mvk(
        &self,
        hmac_secret: &[u8; 32],
    ) -> Result<MasterVolumeKey, Error> {
        if self.kind != SlotKind::Fido2DerivedMvk {
            return Err(Error::InvalidField);
        }
        Ok(derive_mvk_from_fido2(&self.fido2_hmac_salt, hmac_secret))
    }

    fn wrap_mvk(
        &mut self,
        suite: CipherSuite,
        kek: &KeyEncryptionKey,
        mvk: &MasterVolumeKey,
        header_salt: &[u8; 32],
    ) -> Result<(), Error> {
        let mut aad = self.build_aead_aad(header_salt);
        let ct = aead::seal(
            suite,
            kek.as_bytes(),
            &self.aead_nonce,
            &aad,
            mvk.as_bytes(),
        )?;
        if ct.len() != KEY_LEN + suite.tag_len() {
            return Err(Error::Aead);
        }
        self.wrapped_ct.copy_from_slice(&ct[..KEY_LEN]);
        self.wrapped_tag.copy_from_slice(&ct[KEY_LEN..]);
        aad.zeroize();
        Ok(())
    }

    fn unwrap_mvk(
        &self,
        suite: CipherSuite,
        kek: &KeyEncryptionKey,
        header_salt: &[u8; 32],
    ) -> Result<MasterVolumeKey, Error> {
        let mut aad = self.build_aead_aad(header_salt);
        let mut ct = Vec::with_capacity(KEY_LEN + suite.tag_len());
        ct.extend_from_slice(&self.wrapped_ct);
        ct.extend_from_slice(&self.wrapped_tag);
        // The AEAD `open` returns a fresh `Vec<u8>` whose contents are
        // the plaintext MVK. Wrap it in `Zeroizing` so that the plaintext
        // heap allocation is scrubbed on every drop path (success, length
        // mismatch, panic). Without this wrapper the 32 plaintext bytes
        // sit in the heap until the allocator reuses the slot.
        let pt = Zeroizing::new(
            aead::open(suite, kek.as_bytes(), &self.aead_nonce, &aad, &ct)
                .map_err(|_| Error::KeyslotAuthFailed)?,
        );
        if pt.len() != KEY_LEN {
            return Err(Error::KeyslotAuthFailed);
        }
        let mut mvk = Zeroizing::new([0u8; KEY_LEN]);
        mvk.copy_from_slice(&pt);
        let key = MasterVolumeKey::from_zeroizing(&mvk);
        ct.zeroize();
        aad.zeroize();
        Ok(key)
    }

    /// Write the AAD-covered part of the slot (offsets 0..76) into `dst`. The
    /// remainder is left to the caller (zeroed in our serializer).
    ///
    /// Byte 1 carries `self.aad_version`, the AEAD AAD shape. Existing
    /// V1 slots on disk have it = 0 (zeroed by old code). New slots have
    /// it = `AAD_VERSION_V2` = 1, signalling that cred_id + hmac_salt
    /// were also pulled into the AAD at wrap time.
    fn write_aad_region(&self, dst: &mut [u8]) {
        debug_assert!(dst.len() >= SLOT_AAD_LEN);
        dst[OFF_KIND] = self.kind as u8;
        dst[OFF_AAD_VERSION] = self.aad_version;
        dst[OFF_AAD_VERSION + 1..OFF_UUID].fill(0);
        dst[OFF_UUID..OFF_UUID + 16].copy_from_slice(&self.uuid);
        dst[OFF_M_COST..OFF_M_COST + 4].copy_from_slice(&self.kdf_params.m_cost_kib.to_le_bytes());
        dst[OFF_T_COST..OFF_T_COST + 4].copy_from_slice(&self.kdf_params.t_cost.to_le_bytes());
        dst[OFF_P_COST..OFF_P_COST + 4].copy_from_slice(&self.kdf_params.p_cost.to_le_bytes());
        dst[OFF_KDF_SALT..OFF_KDF_SALT + 32].copy_from_slice(&self.kdf_salt);
        dst[OFF_AEAD_NONCE..OFF_AEAD_NONCE + 12].copy_from_slice(&self.aead_nonce);
    }

    /// Build the AEAD AAD for this slot's wrap/unwrap. Shape and scope
    /// are determined by `self.aad_version`:
    ///
    /// - V1 (legacy): `slot[0..76] || header_salt`. cred / hmac_salt
    ///   covered only by the header HMAC.
    /// - V2 (legacy default): `slot[0..76] || slot[124..288] ||
    ///   header_salt`. Covers cred_len, hmac_salt_len, cred_id (128 B
    ///   max), and hmac_salt (32 B at offset 256).
    /// - V3 (current default, supports stateless authenticators):
    ///   `slot[0..76] || slot[124..512] || header_salt`. Covers
    ///   cred_len, hmac_salt_len, cred_id (352 B max at offsets
    ///   128..480), and hmac_salt (32 B at 480..512). Wider range
    ///   than V2 because the layout repurposes the previously-padding
    ///   region 288..512 for the extended cred_id.
    ///
    /// For non-FIDO2 slot kinds the cred / hmac_salt regions are
    /// zero-filled before AAD computation, so the AAD reduces to a
    /// constant-shape envelope regardless of slot kind.
    ///
    /// The aad_version byte sits at offset 1 inside the SLOT_AAD_LEN
    /// (0..76) range, so a tamper that flips V2->V3 (or any version
    /// transition) changes the AAD shape AND the version byte,
    /// breaking the AEAD tag at unwrap time.
    fn build_aead_aad(&self, header_salt: &[u8; 32]) -> Vec<u8> {
        let mut buf = vec![0u8; SLOT_SIZE];
        self.write_aad_region(&mut buf);
        let (cred_max, off_hmac_salt) = slot_layout(self.aad_version);
        if self.aad_version >= AAD_VERSION_V2 {
            // Mirror what to_bytes lays down for the cred / hmac_salt
            // fields so the AAD matches what we persist. Same defensive
            // clamp as `to_bytes` (a no-op for constructor-built slots;
            // it bounds an oversized externally-built cred_id so AAD
            // computation can't panic or `as u16`-truncate, and stays
            // byte-identical to what `to_bytes` writes).
            let cred = &self.fido2_cred_id[..self.fido2_cred_id.len().min(cred_max)];
            let cred_len = cred.len() as u16;
            // SECURITY: this list MUST mirror the equivalent matches!()
            // in `to_bytes` exactly. Any kind that writes a real
            // hmac_salt via to_bytes MUST also include it in AAD here,
            // otherwise the salt bytes are written to disk but excluded
            // from AEAD coverage; an attacker could then flip the salt
            // without breaking the wrap, causing the user's FIDO2
            // authenticator to return a different hmac_secret at unlock
            // time -> AEAD fails -> denial of service. Not a key
            // recovery break (HMAC-SHA-256 second-preimage is
            // infeasible) but a design-invariant break worth pinning
            // with a test. The three fused TPM+FIDO2 kinds were missed
            // when they were originally added; restored 2026-05.
            let salt_len = if matches!(
                self.kind,
                SlotKind::Fido2HmacSecret
                    | SlotKind::Fido2DerivedMvk
                    | SlotKind::HybridPqKemFido2
                    | SlotKind::HybridPqKem1024Fido2
                    | SlotKind::Tpm2Fido2
                    | SlotKind::HybridPqKemTpm2Fido2
                    | SlotKind::HybridPqKem1024Tpm2Fido2,
            ) {
                FIDO2_HMAC_SALT_LEN as u16
            } else {
                0
            };
            buf[OFF_CRED_LEN..OFF_CRED_LEN + 2].copy_from_slice(&cred_len.to_le_bytes());
            buf[OFF_HMAC_SALT_LEN..OFF_HMAC_SALT_LEN + 2].copy_from_slice(&salt_len.to_le_bytes());
            if cred_len > 0 {
                buf[OFF_CRED..OFF_CRED + cred.len()].copy_from_slice(cred);
            }
            if salt_len > 0 {
                buf[off_hmac_salt..off_hmac_salt + FIDO2_HMAC_SALT_LEN]
                    .copy_from_slice(&self.fido2_hmac_salt);
            }
        }
        // V3 AAD covers the full extended region (124..512 = 388 B);
        // V2 covers 124..288 = 164 B; V1 covers nothing past 0..76.
        let aad_tail_end = if self.aad_version >= AAD_VERSION_V3 {
            SLOT_SIZE
        } else {
            OFF_HMAC_SALT_V1V2 + FIDO2_HMAC_SALT_LEN
        };
        let mut aad = Vec::with_capacity(SLOT_AAD_LEN + (aad_tail_end - OFF_CRED_LEN) + 32);
        aad.extend_from_slice(&buf[..SLOT_AAD_LEN]);
        if self.aad_version >= AAD_VERSION_V2 {
            aad.extend_from_slice(&buf[OFF_CRED_LEN..aad_tail_end]);
        }
        aad.extend_from_slice(header_salt);
        buf.zeroize();
        aad
    }

    pub fn to_bytes(&self) -> [u8; SLOT_SIZE] {
        // Fill the entire slot with random bytes, then overwrite with
        // structured fields. For empty slots we keep the kind byte = 0
        // (so `from_bytes` can still detect emptiness) but randomize
        // everything after; otherwise an unused slot leaks 512 zero
        // bytes per slot to entropy analysis.
        //
        // RNG failure here would only impact entropy padding (a minor
        // information leak about slot occupancy via zero-byte
        // detectability), not crypto correctness, the actual keying
        // material was generated in `Keyslot::new_*` and went through
        // `try_fill_bytes` with proper error propagation. Keep the
        // panic with explicit `expect` so the failure mode is visible.
        let mut buf = [0u8; SLOT_SIZE];
        OsRng
            .try_fill_bytes(&mut buf)
            .expect("OS RNG failure during slot serialization (entropy padding)");
        if self.is_empty() {
            buf[OFF_KIND] = 0;
            return buf;
        }
        self.write_aad_region(&mut buf);
        buf[OFF_WRAPPED_CT..OFF_WRAPPED_CT + 32].copy_from_slice(&self.wrapped_ct);
        buf[OFF_WRAPPED_TAG..OFF_WRAPPED_TAG + 16].copy_from_slice(&self.wrapped_tag);

        let (cred_max, off_hmac_salt) = slot_layout(self.aad_version);
        // `cred_len` is the length of whatever sits in the
        // variable-length region: a real FIDO2 cred_id for the
        // FIDO2 / hybrid-FIDO2 kinds, the TPM SealedBlob bytes for
        // Tpm2Sealed, zero for passphrase-only kinds.
        //
        // Defense-in-depth: every `new_*` constructor caps this length
        // at FIDO2_CRED_ID_MAX (<= `cred_max` for the slot's version),
        // so the clamp below is a no-op for any slot built through the
        // public API. It only guards against an externally-constructed
        // `Keyslot` (the fields are `pub`) carrying an oversized buffer,
        // turning a would-be out-of-bounds slice panic and a silent
        // `as u16` truncation into a bounded copy. Debug builds assert
        // so the bug surfaces in tests rather than in production.
        debug_assert!(
            self.fido2_cred_id.len() <= cred_max,
            "cred_id length {} exceeds slot region {cred_max}; Keyslot built outside new_*",
            self.fido2_cred_id.len()
        );
        let cred = &self.fido2_cred_id[..self.fido2_cred_id.len().min(cred_max)];
        let cred_len = cred.len() as u16;
        // `salt_len` is non-zero only when the slot actually
        // carries a FIDO2 hmac_salt. TPM-sealed slots have no
        // FIDO2 component so this stays 0.
        let salt_len = if matches!(
            self.kind,
            SlotKind::Fido2HmacSecret
                | SlotKind::Fido2DerivedMvk
                | SlotKind::HybridPqKemFido2
                | SlotKind::HybridPqKem1024Fido2
                | SlotKind::Tpm2Fido2
                | SlotKind::HybridPqKemTpm2Fido2
                | SlotKind::HybridPqKem1024Tpm2Fido2,
        ) {
            FIDO2_HMAC_SALT_LEN as u16
        } else {
            0
        };
        buf[OFF_CRED_LEN..OFF_CRED_LEN + 2].copy_from_slice(&cred_len.to_le_bytes());
        buf[OFF_HMAC_SALT_LEN..OFF_HMAC_SALT_LEN + 2].copy_from_slice(&salt_len.to_le_bytes());
        if cred_len > 0 {
            buf[OFF_CRED..OFF_CRED + cred.len()].copy_from_slice(cred);
        }
        if salt_len > 0 {
            buf[off_hmac_salt..off_hmac_salt + FIDO2_HMAC_SALT_LEN]
                .copy_from_slice(&self.fido2_hmac_salt);
        }
        buf
    }

    pub fn from_bytes(buf: &[u8; SLOT_SIZE]) -> Result<Self, Error> {
        let kind = SlotKind::from_u8(buf[OFF_KIND])?;
        if kind == SlotKind::Empty {
            return Ok(Self::empty());
        }
        // AEAD AAD shape selector. V1 vaults have byte 1 = 0 (zeroed by
        // the old `write_aad_region`); newer vaults set it to V2 = 1.
        // Higher values are reserved for future format extensions and
        // currently rejected to avoid silently treating unknown shapes
        // as one we know.
        let aad_version = buf[OFF_AAD_VERSION];
        if aad_version > AAD_VERSION_V4 {
            return Err(Error::InvalidField);
        }
        let mut uuid = [0u8; 16];
        uuid.copy_from_slice(&buf[OFF_UUID..OFF_UUID + 16]);
        let m_cost_kib = u32::from_le_bytes(buf[OFF_M_COST..OFF_M_COST + 4].try_into().unwrap());
        let t_cost = u32::from_le_bytes(buf[OFF_T_COST..OFF_T_COST + 4].try_into().unwrap());
        let p_cost = u32::from_le_bytes(buf[OFF_P_COST..OFF_P_COST + 4].try_into().unwrap());
        let mut kdf_salt = [0u8; 32];
        kdf_salt.copy_from_slice(&buf[OFF_KDF_SALT..OFF_KDF_SALT + 32]);
        let mut aead_nonce = [0u8; 12];
        aead_nonce.copy_from_slice(&buf[OFF_AEAD_NONCE..OFF_AEAD_NONCE + 12]);
        let mut wrapped_ct = [0u8; 32];
        wrapped_ct.copy_from_slice(&buf[OFF_WRAPPED_CT..OFF_WRAPPED_CT + 32]);
        let mut wrapped_tag = [0u8; 16];
        wrapped_tag.copy_from_slice(&buf[OFF_WRAPPED_TAG..OFF_WRAPPED_TAG + 16]);

        let cred_len =
            u16::from_le_bytes(buf[OFF_CRED_LEN..OFF_CRED_LEN + 2].try_into().unwrap()) as usize;
        let salt_len = u16::from_le_bytes(
            buf[OFF_HMAC_SALT_LEN..OFF_HMAC_SALT_LEN + 2]
                .try_into()
                .unwrap(),
        ) as usize;
        // The cred_id capacity depends on the slot's on-disk layout
        // version. V3 reserves bytes 128..480 (352 B); V1/V2 only
        // reserve 128..256 (128 B). Reading a V1/V2 slot with cred_len
        // above its layout cap is a corruption / format error.
        let (cred_max_for_version, off_hmac_salt) = slot_layout(aad_version);
        if cred_len > cred_max_for_version {
            return Err(Error::Fido2CredIdTooLong(cred_len));
        }
        // DoS guard: reject hostile Argon2id params from the on-disk
        // slot bytes BEFORE any unlock attempt could pass them to the
        // argon2 crate. An attacker with write-access to the .lbx
        // could otherwise set m_cost_kib = u32::MAX, causing a 4 TiB
        // allocation request and OOM on every unlock.
        // Slot kinds that don't run Argon2id (Fido2DerivedMvk uses pure
        // HKDF, Empty has no crypto) keep their zero/garbage params
        // stored on disk for byte-shape indistinguishability and are
        // exempt from this check.
        let kdf_runs_argon2 = matches!(
            kind,
            SlotKind::Passphrase
                | SlotKind::Fido2HmacSecret
                | SlotKind::HybridPqKemPassphrase
                | SlotKind::HybridPqKemFido2
                | SlotKind::HybridPqKem1024Passphrase
                | SlotKind::HybridPqKem1024Fido2,
        );
        let kdf_params_for_check = Argon2idParams {
            m_cost_kib,
            t_cost,
            p_cost,
        };
        if kdf_runs_argon2 && !kdf_params_for_check.is_sane_for_disk() {
            return Err(Error::InvalidField);
        }
        let mut fido2_cred_id = Vec::new();
        let mut fido2_hmac_salt = [0u8; 32];
        if matches!(
            kind,
            SlotKind::Fido2HmacSecret
                | SlotKind::Fido2DerivedMvk
                | SlotKind::HybridPqKemFido2
                | SlotKind::HybridPqKem1024Fido2
                | SlotKind::Tpm2Fido2
                | SlotKind::HybridPqKemTpm2Fido2
                | SlotKind::HybridPqKem1024Tpm2Fido2,
        ) {
            if salt_len != FIDO2_HMAC_SALT_LEN {
                return Err(Error::InvalidField);
            }
            fido2_cred_id.extend_from_slice(&buf[OFF_CRED..OFF_CRED + cred_len]);
            fido2_hmac_salt.copy_from_slice(&buf[off_hmac_salt..off_hmac_salt + 32]);
        }
        // TPM-only slots (Tpm2Sealed, Tpm2SealedPin, HybridPqKemTpm2,
        // HybridPqKem1024Tpm2): the variable-length region holds the
        // raw SealedBlob bytes (no FIDO2 hmac_salt, salt_len must be
        // 0). Fused kinds are handled by the salt-bearing arm above.
        if matches!(
            kind,
            SlotKind::Tpm2Sealed
                | SlotKind::Tpm2SealedPin
                | SlotKind::HybridPqKemTpm2
                | SlotKind::HybridPqKem1024Tpm2
        ) {
            if salt_len != 0 {
                return Err(Error::InvalidField);
            }
            fido2_cred_id.extend_from_slice(&buf[OFF_CRED..OFF_CRED + cred_len]);
            // fido2_hmac_salt stays zero - TPM-only slots don't have one.
        }

        Ok(Self {
            kind,
            aad_version,
            uuid,
            kdf_params: Argon2idParams {
                m_cost_kib,
                t_cost,
                p_cost,
            },
            kdf_salt,
            aead_nonce,
            wrapped_ct,
            wrapped_tag,
            fido2_cred_id,
            fido2_hmac_salt,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn passphrase_roundtrip() {
        let suite = CipherSuite::Aes256Gcm;
        let mvk = MasterVolumeKey::from_bytes([0xa5; 32]);
        let header_salt = [0x11u8; 32];
        let slot = Keyslot::new_passphrase(
            suite,
            &mvk,
            b"correct horse battery staple",
            Argon2idParams::TEST_ONLY,
            &header_salt,
        )
        .unwrap();

        let bytes = slot.to_bytes();
        let restored = Keyslot::from_bytes(&bytes).unwrap();

        let recovered = restored
            .unlock_passphrase(suite, b"correct horse battery staple", &header_salt)
            .unwrap();
        assert_eq!(recovered.as_bytes(), mvk.as_bytes());

        assert!(
            restored
                .unlock_passphrase(suite, b"wrong passphrase", &header_salt)
                .is_err()
        );
    }

    // ---- Regression: serialization is panic-safe against an
    // externally-constructed (constructor-bypassing) Keyslot whose
    // cred_id exceeds the slot region. The `new_*` constructors cap
    // cred_id at FIDO2_CRED_ID_MAX, but the struct fields are `pub`, so
    // external crate code can build an invalid slot. `to_bytes` /
    // `build_aead_aad` must not out-of-bounds panic or silently
    // `as u16`-truncate; they clamp to the region with a debug_assert.

    /// Build an invalid slot directly via its public fields (bypassing
    /// the length-validating constructors): cred_id is 1000 B, far over
    /// the 352 B V4 cap.
    fn oversized_external_slot() -> Keyslot {
        Keyslot {
            kind: SlotKind::Fido2HmacSecret,
            aad_version: AAD_VERSION_V4,
            uuid: [0u8; 16],
            kdf_params: Argon2idParams {
                m_cost_kib: 0,
                t_cost: 0,
                p_cost: 0,
            },
            kdf_salt: [0u8; 32],
            aead_nonce: [0u8; 12],
            wrapped_ct: [0u8; 32],
            wrapped_tag: [0u8; 16],
            fido2_cred_id: vec![0xABu8; 1000],
            fido2_hmac_salt: [0x42u8; 32],
        }
    }

    /// The clamp must not affect the largest *valid* cred_id: a cred_id
    /// exactly at the V4 cap round-trips unchanged.
    #[test]
    fn to_bytes_roundtrips_cred_id_at_max() {
        let cred = vec![0xCDu8; FIDO2_CRED_ID_MAX];
        let slot = Keyslot::new_fido2_derived_mvk(&cred, [0x42u8; 32]).unwrap();
        let bytes = slot.to_bytes();
        let restored = Keyslot::from_bytes(&bytes).unwrap();
        assert_eq!(restored.fido2_cred_id, cred);
    }

    /// In debug builds the oversized slot trips the `debug_assert`, so
    /// the misuse surfaces loudly during development/testing.
    #[cfg(debug_assertions)]
    #[test]
    #[should_panic(expected = "exceeds slot region")]
    fn oversized_external_cred_id_asserts_in_debug() {
        let _ = oversized_external_slot().to_bytes();
    }

    /// In release builds (`cargo test --release`) the `debug_assert` is
    /// compiled out, so the clamp is what protects us: `to_bytes` and
    /// `build_aead_aad` must complete without panicking and the on-disk
    /// `cred_len` must be clamped to the region capacity (not the bogus
    /// 1000, and not a `u16`-truncated value).
    #[cfg(not(debug_assertions))]
    #[test]
    fn oversized_external_cred_id_clamps_in_release() {
        let bytes = oversized_external_slot().to_bytes();
        let cred_len = u16::from_le_bytes([bytes[OFF_CRED_LEN], bytes[OFF_CRED_LEN + 1]]);
        assert_eq!(cred_len as usize, FIDO2_CRED_ID_MAX);
        // The companion AAD path must also be panic-safe on the same slot.
        let _ = oversized_external_slot().build_aead_aad(&[0u8; 32]);
    }

    #[test]
    fn fido2_derived_mvk_roundtrip() {
        let cred_id = b"derived-cred";
        let hmac_salt = [0xaau8; 32];
        let hmac_secret = [0xbbu8; 32];

        let slot = Keyslot::new_fido2_derived_mvk(cred_id, hmac_salt).unwrap();
        assert_eq!(slot.kind, SlotKind::Fido2DerivedMvk);

        // Same hmac_secret -> same MVK (deterministic).
        let mvk1 = slot.unlock_fido2_derived_mvk(&hmac_secret).unwrap();
        let mvk2 = slot.unlock_fido2_derived_mvk(&hmac_secret).unwrap();
        assert_eq!(mvk1.as_bytes(), mvk2.as_bytes());

        // Different hmac_secret -> different MVK.
        let mut other = hmac_secret;
        other[0] ^= 1;
        let mvk3 = slot.unlock_fido2_derived_mvk(&other).unwrap();
        assert_ne!(mvk1.as_bytes(), mvk3.as_bytes());

        // Round-trip through bytes.
        let bytes = slot.to_bytes();
        let restored = Keyslot::from_bytes(&bytes).unwrap();
        assert_eq!(restored.kind, SlotKind::Fido2DerivedMvk);
        assert_eq!(restored.fido2_cred_id, cred_id);
        assert_eq!(restored.fido2_hmac_salt, hmac_salt);
        let mvk4 = restored.unlock_fido2_derived_mvk(&hmac_secret).unwrap();
        assert_eq!(mvk1.as_bytes(), mvk4.as_bytes());

        // Calling unlock_fido2_derived_mvk on a wrong-kind slot errors.
        let mvk_only = MasterVolumeKey::from_bytes([0; 32]);
        let pp_slot = Keyslot::new_passphrase(
            CipherSuite::Aes256Gcm,
            &mvk_only,
            b"x",
            Argon2idParams::TEST_ONLY,
            &[0u8; 32],
        )
        .unwrap();
        assert!(pp_slot.unlock_fido2_derived_mvk(&hmac_secret).is_err());
    }

    #[test]
    fn fido2_roundtrip() {
        let suite = CipherSuite::ChaCha20Poly1305;
        let mvk = MasterVolumeKey::from_bytes([0x33; 32]);
        let header_salt = [0x22u8; 32];
        let cred_id = b"this is a credential id";
        let hmac_salt = [0x44u8; 32];
        let hmac_secret = [0x55u8; 32];

        let slot = Keyslot::new_fido2(
            suite,
            &mvk,
            None,
            &hmac_secret,
            cred_id,
            hmac_salt,
            Argon2idParams::TEST_ONLY,
            &header_salt,
        )
        .unwrap();

        let bytes = slot.to_bytes();
        let restored = Keyslot::from_bytes(&bytes).unwrap();
        assert_eq!(restored.fido2_cred_id, cred_id);
        assert_eq!(restored.fido2_hmac_salt, hmac_salt);

        let ok = restored
            .unlock_fido2(suite, None, &hmac_secret, &header_salt)
            .unwrap();
        assert_eq!(ok.as_bytes(), mvk.as_bytes());

        let mut wrong = hmac_secret;
        wrong[0] ^= 1;
        assert!(
            restored
                .unlock_fido2(suite, None, &wrong, &header_salt)
                .is_err()
        );

        let mut other_header = header_salt;
        other_header[0] ^= 1;
        assert!(
            restored
                .unlock_fido2(suite, None, &hmac_secret, &other_header)
                .is_err()
        );
    }

    #[test]
    fn hybrid_fido_roundtrip_preserves_cred_id_and_salt() {
        let suite = CipherSuite::Aes256Gcm;
        let mvk = MasterVolumeKey::from_bytes([0x66; 32]);
        let header_salt = [0x11u8; 32];
        let cred_id = b"yk-cred-id-bytes";
        let hmac_salt = [0xAA; 32];
        let hmac_secret = [0xBB; 32];
        let pq_shared = [0xCC; 32];

        for kind in [SlotKind::HybridPqKemFido2, SlotKind::HybridPqKem1024Fido2] {
            let slot = Keyslot::build_hybrid_pq_fido2(
                kind,
                suite,
                &mvk,
                None,
                &hmac_secret,
                &pq_shared,
                cred_id,
                hmac_salt,
                Argon2idParams::TEST_ONLY,
                &header_salt,
            )
            .unwrap();
            let bytes = slot.to_bytes();
            let restored = Keyslot::from_bytes(&bytes).unwrap();
            assert_eq!(restored.kind, kind);
            assert_eq!(
                restored.fido2_cred_id, cred_id,
                "cred_id round-trip ({kind:?})"
            );
            assert_eq!(
                restored.fido2_hmac_salt, hmac_salt,
                "hmac_salt round-trip ({kind:?})"
            );
        }
    }

    #[test]
    fn slot_tamper_detected() {
        let suite = CipherSuite::Aes256Gcm;
        let mvk = MasterVolumeKey::from_bytes([0x77; 32]);
        let header_salt = [0x88u8; 32];
        let slot = Keyslot::new_passphrase(
            suite,
            &mvk,
            b"hunter2",
            Argon2idParams::TEST_ONLY,
            &header_salt,
        )
        .unwrap();
        let mut bytes = slot.to_bytes();
        bytes[OFF_KDF_SALT] ^= 0x01;
        let restored = Keyslot::from_bytes(&bytes).unwrap();
        assert!(
            restored
                .unlock_passphrase(suite, b"hunter2", &header_salt)
                .is_err()
        );
    }

    #[test]
    fn tpm2_slot_roundtrip_and_unlock() {
        // The TPM I/O is mocked out at this layer - we just supply a
        // random "KEK" and a fake "SealedBlob byte run" and verify
        // the slot wraps the MVK, serializes, deserializes, and
        // unlocks back to the same MVK when the KEK is re-supplied.
        // The real TPM seal/unseal happens in luksbox-format /
        // Container::open (Day 3).
        let suite = CipherSuite::Aes256GcmSiv;
        let mvk = MasterVolumeKey::random();
        let header_salt = [0xAB; 32];
        let kek = [0x42u8; 32];
        // Fake SealedBlob bytes; the real format is
        // length-prefixed TPM2B_PUBLIC + TPM2B_PRIVATE, but
        // luksbox-core treats it as opaque.
        let fake_blob = vec![0xCD; 280];

        let slot = Keyslot::new_tpm2(suite, &mvk, &kek, &fake_blob, &header_salt).unwrap();
        assert_eq!(slot.kind, SlotKind::Tpm2Sealed);
        assert_eq!(slot.aad_version, AAD_VERSION_V4);
        assert_eq!(slot.tpm2_sealed_blob().unwrap(), fake_blob.as_slice());

        // Round-trip through the on-disk byte layout.
        let bytes = slot.to_bytes();
        let restored = Keyslot::from_bytes(&bytes).unwrap();
        assert_eq!(restored.kind, SlotKind::Tpm2Sealed);
        assert_eq!(restored.tpm2_sealed_blob().unwrap(), fake_blob.as_slice());

        // Same KEK -> same MVK back.
        let recovered = restored.unlock_tpm2(suite, &kek, &header_salt).unwrap();
        assert_eq!(recovered.as_bytes(), mvk.as_bytes());

        // Wrong KEK -> AEAD failure.
        let wrong_kek = [0x99u8; 32];
        assert!(
            restored
                .unlock_tpm2(suite, &wrong_kek, &header_salt)
                .is_err()
        );
    }

    #[test]
    fn tpm2_slot_rejects_oversize_blob() {
        // Variable region capacity in V3 is 352 bytes
        // (FIDO2_CRED_ID_MAX). Anything larger MUST be rejected at
        // construction; otherwise to_bytes would panic on the
        // copy_from_slice.
        let mvk = MasterVolumeKey::random();
        let header_salt = [0u8; 32];
        let kek = [0u8; 32];
        let too_big = vec![0u8; FIDO2_CRED_ID_MAX + 1];
        let res = Keyslot::new_tpm2(
            CipherSuite::Aes256GcmSiv,
            &mvk,
            &kek,
            &too_big,
            &header_salt,
        );
        assert!(matches!(res, Err(Error::Fido2CredIdTooLong(_))));
    }

    #[test]
    fn slot_kind_from_u8_recognises_tpm2_kinds() {
        // Hard regression test for the kind-byte allocation. Kinds
        // 8-14 are now defined; 15 and beyond remain unallocated.
        assert_eq!(SlotKind::from_u8(8).unwrap(), SlotKind::Tpm2Sealed);
        assert_eq!(SlotKind::from_u8(9).unwrap(), SlotKind::Tpm2Fido2);
        assert_eq!(SlotKind::from_u8(10).unwrap(), SlotKind::Tpm2SealedPin);
        assert_eq!(SlotKind::from_u8(11).unwrap(), SlotKind::HybridPqKemTpm2);
        assert_eq!(
            SlotKind::from_u8(12).unwrap(),
            SlotKind::HybridPqKemTpm2Fido2
        );
        assert_eq!(
            SlotKind::from_u8(13).unwrap(),
            SlotKind::HybridPqKem1024Tpm2
        );
        assert_eq!(
            SlotKind::from_u8(14).unwrap(),
            SlotKind::HybridPqKem1024Tpm2Fido2
        );
        assert!(matches!(
            SlotKind::from_u8(15),
            Err(Error::UnsupportedSlotKind(15))
        ));
    }

    #[test]
    fn hybrid_pq_1024_tpm2_roundtrip_and_unlock() {
        // 1024 variant: same KEK derivation as 768, only kind byte
        // differs. Verify the slot serializes, deserializes, and
        // unlocks correctly.
        let suite = CipherSuite::Aes256GcmSiv;
        let mvk = MasterVolumeKey::random();
        let header_salt = [0xAA; 32];
        let tpm_kek = [0x11u8; 32];
        let pq_shared = [0x22u8; 32];
        let fake_blob = vec![0x33u8; 240];

        let slot = Keyslot::new_hybrid_pq_1024_tpm2(
            suite,
            &mvk,
            &tpm_kek,
            &pq_shared,
            &fake_blob,
            &header_salt,
        )
        .unwrap();
        assert_eq!(slot.kind, SlotKind::HybridPqKem1024Tpm2);
        assert!(slot.kind.is_tpm2());
        assert!(slot.kind.is_hybrid_pq());
        assert!(slot.kind.is_hybrid_pq_1024());

        let bytes = slot.to_bytes();
        let restored = Keyslot::from_bytes(&bytes).unwrap();
        assert_eq!(restored.kind, SlotKind::HybridPqKem1024Tpm2);
        let recovered = restored
            .unlock_hybrid_pq_tpm2(suite, &tpm_kek, &pq_shared, &header_salt)
            .unwrap();
        assert_eq!(recovered.as_bytes(), mvk.as_bytes());
    }

    #[test]
    fn hybrid_pq_1024_tpm2_fido2_roundtrip() {
        let suite = CipherSuite::Aes256GcmSiv;
        let mvk = MasterVolumeKey::random();
        let header_salt = [0xBB; 32];
        let tpm = [0x44u8; 32];
        let hs = [0x55u8; 32];
        let pq = [0x66u8; 32];
        let blob = vec![0x77u8; 200];
        let cred = vec![0x88u8; 60];

        let slot = Keyslot::new_hybrid_pq_1024_tpm2_fido2(
            suite,
            &mvk,
            &tpm,
            &hs,
            &pq,
            &blob,
            &cred,
            [0x99u8; 32],
            &header_salt,
        )
        .unwrap();
        assert_eq!(slot.kind, SlotKind::HybridPqKem1024Tpm2Fido2);
        assert!(slot.kind.is_tpm2_fido2());
        assert!(slot.kind.is_hybrid_pq_1024());

        let bytes = slot.to_bytes();
        let restored = Keyslot::from_bytes(&bytes).unwrap();
        let recovered = restored
            .unlock_hybrid_pq_tpm2_fido2(suite, &tpm, &hs, &pq, &header_salt)
            .unwrap();
        assert_eq!(recovered.as_bytes(), mvk.as_bytes());
    }

    #[test]
    fn tpm2_pin_slot_roundtrip_and_unlock() {
        // Same wrap as Tpm2Sealed; the difference is the kind byte
        // (so the unlock dispatcher knows to prompt for a PIN
        // before calling Tpm2Sealer::unseal_with_pin).
        let suite = CipherSuite::Aes256GcmSiv;
        let mvk = MasterVolumeKey::random();
        let header_salt = [0x12; 32];
        let kek = [0x34u8; 32];
        let fake_blob = vec![0x56u8; 240];

        let slot = Keyslot::new_tpm2_pin(suite, &mvk, &kek, &fake_blob, &header_salt).unwrap();
        assert_eq!(slot.kind, SlotKind::Tpm2SealedPin);
        assert!(slot.kind.is_tpm2());
        assert!(slot.kind.is_tpm2_pin());
        assert_eq!(slot.tpm2_sealed_blob().unwrap(), fake_blob.as_slice());

        let bytes = slot.to_bytes();
        let restored = Keyslot::from_bytes(&bytes).unwrap();
        assert_eq!(restored.kind, SlotKind::Tpm2SealedPin);
        // The same KEK that wrapped the MVK must unlock it. PIN
        // validation happens at the TPM layer, NOT in unlock_tpm2 -
        // by the time we call unlock_tpm2, the caller has already
        // unsealed using the right PIN. So unlock_tpm2 works on a
        // Tpm2SealedPin slot too if the caller has the KEK.
        let recovered = restored.unlock_tpm2(suite, &kek, &header_salt).unwrap();
        assert_eq!(recovered.as_bytes(), mvk.as_bytes());
    }

    #[test]
    fn hybrid_pq_tpm2_roundtrip_and_unlock() {
        let suite = CipherSuite::Aes256GcmSiv;
        let mvk = MasterVolumeKey::random();
        let header_salt = [0x21; 32];
        let tpm_kek = [0x10u8; 32];
        let pq_shared = [0x20u8; 32];
        let fake_blob = vec![0x30u8; 240];

        let slot = Keyslot::new_hybrid_pq_tpm2(
            suite,
            &mvk,
            &tpm_kek,
            &pq_shared,
            &fake_blob,
            &header_salt,
        )
        .unwrap();
        assert_eq!(slot.kind, SlotKind::HybridPqKemTpm2);
        assert!(slot.kind.is_tpm2());
        assert!(slot.kind.is_hybrid_pq());

        let bytes = slot.to_bytes();
        let restored = Keyslot::from_bytes(&bytes).unwrap();
        assert_eq!(restored.kind, SlotKind::HybridPqKemTpm2);

        let recovered = restored
            .unlock_hybrid_pq_tpm2(suite, &tpm_kek, &pq_shared, &header_salt)
            .unwrap();
        assert_eq!(recovered.as_bytes(), mvk.as_bytes());

        // Wrong TPM half -> AEAD failure.
        let wrong_tpm = [0xFFu8; 32];
        assert!(
            restored
                .unlock_hybrid_pq_tpm2(suite, &wrong_tpm, &pq_shared, &header_salt)
                .is_err()
        );
        // Wrong PQ half -> AEAD failure.
        let wrong_pq = [0xEEu8; 32];
        assert!(
            restored
                .unlock_hybrid_pq_tpm2(suite, &tpm_kek, &wrong_pq, &header_salt)
                .is_err()
        );
    }

    #[test]
    fn hybrid_pq_tpm2_fido2_roundtrip_and_3factor_matrix() {
        let suite = CipherSuite::Aes256GcmSiv;
        let mvk = MasterVolumeKey::random();
        let header_salt = [0x33; 32];
        let tpm_unsealed = [0x40u8; 32];
        let hmac_secret = [0x50u8; 32];
        let pq_shared = [0x60u8; 32];
        let fake_blob = vec![0x70u8; 200];
        let cred_id = vec![0x80u8; 60];
        let hmac_salt = [0x42u8; 32];

        let slot = Keyslot::new_hybrid_pq_tpm2_fido2(
            suite,
            &mvk,
            &tpm_unsealed,
            &hmac_secret,
            &pq_shared,
            &fake_blob,
            &cred_id,
            hmac_salt,
            &header_salt,
        )
        .unwrap();
        assert_eq!(slot.kind, SlotKind::HybridPqKemTpm2Fido2);
        assert!(slot.kind.is_tpm2());
        assert!(slot.kind.is_tpm2_fido2());
        assert!(slot.kind.is_hybrid_pq());
        assert_eq!(slot.tpm2_fido2_sealed_blob().unwrap(), fake_blob.as_slice());
        assert_eq!(slot.tpm2_fido2_cred_id().unwrap(), cred_id.as_slice());
        assert_eq!(slot.fido2_hmac_salt, hmac_salt);

        let bytes = slot.to_bytes();
        let restored = Keyslot::from_bytes(&bytes).unwrap();
        assert_eq!(restored.kind, SlotKind::HybridPqKemTpm2Fido2);

        // All three correct -> success.
        let recovered = restored
            .unlock_hybrid_pq_tpm2_fido2(
                suite,
                &tpm_unsealed,
                &hmac_secret,
                &pq_shared,
                &header_salt,
            )
            .unwrap();
        assert_eq!(recovered.as_bytes(), mvk.as_bytes());
        // Each-factor-wrong matrix:
        for (label, t, f, p) in [
            ("wrong tpm", [0xAAu8; 32], hmac_secret, pq_shared),
            ("wrong fido", tpm_unsealed, [0xBBu8; 32], pq_shared),
            ("wrong pq", tpm_unsealed, hmac_secret, [0xCCu8; 32]),
        ] {
            let r = restored.unlock_hybrid_pq_tpm2_fido2(suite, &t, &f, &p, &header_salt);
            assert!(r.is_err(), "{label}: must fail");
        }
    }

    #[test]
    fn tpm2_fido2_slot_roundtrip_and_unlock() {
        // Mocked TPM (just a 32-byte value) + mocked FIDO2
        // hmac_secret + a fake SealedBlob and cred_id. Verifies
        // the slot wraps the MVK, serializes through to_bytes,
        // deserializes via from_bytes, and unlock recovers the
        // same MVK iff BOTH inputs are correct.
        let suite = CipherSuite::Aes256GcmSiv;
        let mvk = MasterVolumeKey::random();
        let header_salt = [0xAB; 32];
        let tpm_unsealed = [0x42u8; 32];
        let hmac_secret = [0x73u8; 32];
        let fake_blob = vec![0xCDu8; 240];
        let cred_id = vec![0xEFu8; 64]; // typical YubiKey cred_id
        let hmac_salt = [0x11u8; 32];

        let slot = Keyslot::new_tpm2_fido2(
            suite,
            &mvk,
            &tpm_unsealed,
            &hmac_secret,
            &fake_blob,
            &cred_id,
            hmac_salt,
            &header_salt,
        )
        .unwrap();
        assert_eq!(slot.kind, SlotKind::Tpm2Fido2);
        assert_eq!(slot.tpm2_fido2_sealed_blob().unwrap(), fake_blob.as_slice());
        assert_eq!(slot.tpm2_fido2_cred_id().unwrap(), cred_id.as_slice());
        assert_eq!(slot.fido2_hmac_salt, hmac_salt);

        // Round-trip through the on-disk byte layout.
        let bytes = slot.to_bytes();
        let restored = Keyslot::from_bytes(&bytes).unwrap();
        assert_eq!(restored.kind, SlotKind::Tpm2Fido2);
        assert_eq!(
            restored.tpm2_fido2_sealed_blob().unwrap(),
            fake_blob.as_slice()
        );
        assert_eq!(restored.tpm2_fido2_cred_id().unwrap(), cred_id.as_slice());
        assert_eq!(restored.fido2_hmac_salt, hmac_salt);

        // Both factors correct -> recovers the MVK.
        let recovered = restored
            .unlock_tpm2_fido2(suite, &tpm_unsealed, &hmac_secret, &header_salt)
            .unwrap();
        assert_eq!(recovered.as_bytes(), mvk.as_bytes());

        // Wrong TPM half -> AEAD failure.
        let wrong_tpm = [0x99u8; 32];
        assert!(
            restored
                .unlock_tpm2_fido2(suite, &wrong_tpm, &hmac_secret, &header_salt)
                .is_err()
        );
        // Wrong FIDO2 half -> AEAD failure.
        let wrong_fido = [0x88u8; 32];
        assert!(
            restored
                .unlock_tpm2_fido2(suite, &tpm_unsealed, &wrong_fido, &header_salt)
                .is_err()
        );
        // Both halves wrong -> AEAD failure.
        assert!(
            restored
                .unlock_tpm2_fido2(suite, &wrong_tpm, &wrong_fido, &header_salt)
                .is_err()
        );
    }

    #[test]
    fn tpm2_fido2_rejects_oversize_combined_blob() {
        // A typical TPM SealedBlob is about 280 B; a Google Titan
        // cred_id is about 288 B. Combined: about 570 > 352 (FIDO2_CRED_ID_MAX).
        // Constructor must reject rather than silently truncate.
        let mvk = MasterVolumeKey::random();
        let big_blob = vec![0u8; 280];
        let big_cred = vec![0u8; 288];
        let res = Keyslot::new_tpm2_fido2(
            CipherSuite::Aes256GcmSiv,
            &mvk,
            &[0u8; 32],
            &[0u8; 32],
            &big_blob,
            &big_cred,
            [0u8; 32],
            &[0u8; 32],
        );
        assert!(matches!(res, Err(Error::Fido2CredIdTooLong(_))));
    }

    #[test]
    fn empty_slot_roundtrip() {
        // From-bytes of an all-zero buffer yields an empty Keyslot.
        let bytes = [0u8; SLOT_SIZE];
        let s = Keyslot::from_bytes(&bytes).unwrap();
        assert!(s.is_empty());

        // Re-serializing an empty slot keeps kind=0 but randomizes the
        // tail (so unused slots don't leak as zeros to entropy analysis).
        let regenerated = s.to_bytes();
        assert_eq!(regenerated[0], 0, "kind byte must remain 0 for empty slots");
        // The regenerated bytes must still parse as an empty slot.
        let reparsed = Keyslot::from_bytes(&regenerated).unwrap();
        assert!(reparsed.is_empty());
        // And the tail should not be all zeros (very high probability).
        assert!(regenerated[1..].iter().any(|&b| b != 0));
    }
}
