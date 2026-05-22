// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Penthertz <https://penthertz.com> (https://x.com/PentHertz)

use hmac::{Hmac, Mac};
use rand_core::{OsRng, RngCore};
use sha2::Sha256;
use subtle::ConstantTimeEq;

use crate::aead::CipherSuite;
use crate::error::Error;
use crate::kdf::KdfId;
use crate::key::MasterVolumeKey;
use crate::keyslot::{Keyslot, SLOT_SIZE};

pub const HEADER_SIZE: usize = 8192;
pub const MAX_KEYSLOTS: usize = 8;
pub const HMAC_LEN: usize = 32;
pub const HEADER_MAC_INFO: &[u8] = b"lbx:header-mac/v1";

/// Smallest accepted `chunk_size` field (sub-block alignment floor).
/// Anything below this would explode chunk counts and AEAD-tag overhead
/// for any non-trivial file.
pub const MIN_CHUNK_SIZE: u32 = 512;
/// Largest accepted `chunk_size` field. The runtime currently hard-codes
/// 4096 via `luksbox_vfs::CHUNK_PLAINTEXT_SIZE`, so the header field is
/// informational + reserved for future format extension. The 1 MiB cap
/// allows future growth while refusing pathological values that could
/// trigger huge per-chunk allocations.
pub const MAX_CHUNK_SIZE: u32 = 1 << 20;
/// Largest accepted `metadata_size` field. Raised in v0.2.1 from 16 MiB
/// to 64 MiB so the encoded directory tree for vaults with thousands of
/// inodes plus their inline chunk-ref tables fits without spilling to
/// `MetadataBudgetExhausted` (the underlying cause of v0.2.0's surface
/// "no space left on device" failure at vault scales around 13 GB with
/// 5k+ small files). The cap still bounds the worst-case
/// `vec![0u8; metadata_size as usize]` allocation in `read_metadata`
/// against a vault crafted by a hostile MVK holder.
pub const MAX_METADATA_SIZE: u64 = 64 << 20;

/// On-disk magic byte sequence used by LUKSbox v0.2.0 and earlier.
pub const MAGIC_V1: [u8; 8] = *b"LUKSBOX1";
/// On-disk magic byte sequence introduced in v0.2.1 alongside the
/// sidecar-mirror durability fix. Old binaries reject this magic via
/// the version-major check in `Header::from_bytes`, which is the
/// correct behavior (they'd silently miss the recovery sidecars).
pub const MAGIC_V2: [u8; 8] = *b"LUKSBOX2";

pub const VERSION_MAJOR_V1: u16 = 1;
pub const VERSION_MAJOR_V2: u16 = 2;
const VERSION_MINOR: u16 = 0;

const OFF_MAGIC: usize = 0;
const OFF_VER_MAJOR: usize = 8;
const OFF_VER_MINOR: usize = 10;
const OFF_HEADER_SIZE: usize = 12;
const OFF_CIPHER: usize = 16;
const OFF_KDF: usize = 18;
const OFF_CHUNK_SIZE: usize = 20;
const OFF_HEADER_SALT: usize = 24;
const OFF_METADATA_OFFSET: usize = 56;
const OFF_METADATA_SIZE: usize = 64;
const OFF_DATA_OFFSET: usize = 72;
const OFF_KEYSLOT_COUNT: usize = 80;
const OFF_FLAGS: usize = 84;
const OFF_KEYSLOTS: usize = 96;
const OFF_HMAC: usize = HEADER_SIZE - HMAC_LEN;

/// Bit 0 of `Header::flags`. When set, the VFS allocates chunks for each
/// file in power-of-2-sized buckets (1, 2, 4, 8, 16, 32, ...) instead of
/// `ceil(size/CHUNK)`. Hides per-file chunk count from a disk-level
/// observer (forensics, untrusted storage, etc.) within a 2x bucket.
///
/// On its own this leaves `Inode.size` exact in the AEAD-encrypted metadata
/// blob, an MVK-holder still reads precise sizes. To also hide the
/// metadata-side size, combine with `FLAG_HIDE_SIZE_HEADER`.
pub const FLAG_PAD_FILES_POW2: u32 = 1 << 0;

/// Bit 1 of `Header::flags`. When set, each file's REAL byte length is
/// stored as the first 8 bytes (u64 LE) of chunk 0's plaintext, and
/// `Inode.size` is set to `chunks.len() * 4096` (a coarse, padding-aware
/// value that doesn't reveal the exact size). Combined with
/// `FLAG_PAD_FILES_POW2`, the size revealed to anyone holding the MVK
/// (incl. via `ls -l` on the FUSE mount) is rounded to the bucket size.
///
/// Cost: chunk 0 has 8 bytes less data capacity (4088 vs 4096); first
/// stat on each file performs one chunk-decrypt to fetch the real size
/// (subsequent stats hit an in-memory cache). Caveat: an attacker who
/// can decrypt arbitrary file content (which an MVK-holder generally can)
/// also recovers the real size from chunk 0. The hiding is meaningful
/// against partial exposures (memory snapshots that captured the
/// metadata-decrypt operation but not file content; metadata-only
/// backups; `ls -l` on a mounted vault) but is NOT a hard guarantee
/// against a fully-capable MVK-holder.
pub const FLAG_HIDE_SIZE_HEADER: u32 = 1 << 1;

/// Bit 2 of `Header::flags`. When set, the container keeps a
/// previous-good copy of the 8 KiB header at `<storage_path>.header-bak`
/// rotated via temp+rename before every overwrite of the live header
/// region. On open, if the live header fails to parse or HMAC-verify,
/// the recovery path reads and verifies the mirror, and on a successful
/// fallback marks `header_dirty` so the next clean shutdown re-establishes
/// the live region.
///
/// HMAC-authenticated by `verify_hmac`, so an attacker who flips this
/// bit to make the recovery path ignore the mirror will fail HMAC.
pub const FLAG_HAS_HEADER_MIRROR: u32 = 1 << 2;

/// Bit 3 of `Header::flags`. Same guarantee as `FLAG_HAS_HEADER_MIRROR`
/// but for the AEAD-encrypted metadata region at `<vault>.lbx.meta-bak`.
/// The mirror is sized to match `metadata_size` so a `read_metadata`
/// against the mirror behaves identically to one against the live region.
pub const FLAG_HAS_METADATA_MIRROR: u32 = 1 << 3;

const _: () = assert!(OFF_KEYSLOTS + MAX_KEYSLOTS * SLOT_SIZE <= OFF_HMAC);

#[derive(Clone)]
pub struct Header {
    pub cipher_suite: CipherSuite,
    pub kdf: KdfId,
    pub chunk_size: u32,
    pub flags: u32,
    pub header_salt: [u8; 32],
    pub metadata_offset: u64,
    pub metadata_size: u64,
    pub data_offset: u64,
    pub keyslots: [Keyslot; MAX_KEYSLOTS],
    /// On-disk format major version. `1` = LUKSBOX1 (v0.2.0 and earlier,
    /// no sidecar mirrors). `2` = LUKSBOX2 (v0.2.1+, supports the
    /// header/metadata mirror sidecars guarded by FLAG_HAS_*_MIRROR).
    /// Default `try_new` builds a v1 header for back-compat; container
    /// code that wants new vaults on v2 sets this explicitly.
    pub version_major: u16,
}

impl Header {
    /// Construct a new header with a fresh random `header_salt`.
    /// Returns `Err` only on OS RNG failure (extremely rare; system is
    /// broken if it happens). Production paths should use this; tests
    /// and examples can use the panic-on-failure `new` shim.
    pub fn try_new(
        cipher_suite: CipherSuite,
        kdf: KdfId,
        chunk_size: u32,
        data_offset: u64,
    ) -> Result<Self, Error> {
        let mut header_salt = [0u8; 32];
        OsRng
            .try_fill_bytes(&mut header_salt)
            .map_err(|e| Error::OsRng(e.to_string()))?;
        Ok(Self {
            cipher_suite,
            kdf,
            chunk_size,
            flags: 0,
            header_salt,
            metadata_offset: HEADER_SIZE as u64,
            metadata_size: 0,
            data_offset,
            keyslots: core::array::from_fn(|_| Keyslot::empty()),
            version_major: VERSION_MAJOR_V1,
        })
    }

    /// Convenience wrapper: panics on OS RNG failure. Prefer `try_new`
    /// in new production code.
    pub fn new(cipher_suite: CipherSuite, kdf: KdfId, chunk_size: u32, data_offset: u64) -> Self {
        Self::try_new(cipher_suite, kdf, chunk_size, data_offset)
            .expect("OS RNG failure during Header::new")
    }

    /// Whether per-file chunk counts are padded to powers of 2.
    pub fn pad_files_pow2(&self) -> bool {
        (self.flags & FLAG_PAD_FILES_POW2) != 0
    }

    /// Whether the chunk-0 plaintext begins with a u64 LE real-size header.
    /// When set, `Inode.size` is the (padded) chunk capacity rather than
    /// the real file length.
    pub fn hide_size_header(&self) -> bool {
        (self.flags & FLAG_HIDE_SIZE_HEADER) != 0
    }

    /// Whether a previous-good header copy is persisted at the sidecar
    /// `<storage_path>.header-bak`. v0.2.1+ vaults set this on first
    /// flush after open.
    pub fn has_header_mirror(&self) -> bool {
        (self.flags & FLAG_HAS_HEADER_MIRROR) != 0
    }

    /// Whether a previous-good metadata copy is persisted at the
    /// sidecar `<vault>.lbx.meta-bak`. v0.2.1+ vaults set this on first
    /// flush after open.
    pub fn has_metadata_mirror(&self) -> bool {
        (self.flags & FLAG_HAS_METADATA_MIRROR) != 0
    }

    /// Find the lowest-index empty slot.
    pub fn first_free_slot(&self) -> Result<usize, Error> {
        self.keyslots
            .iter()
            .position(|s| s.is_empty())
            .ok_or(Error::NoFreeKeyslot)
    }

    pub fn install_slot(&mut self, idx: usize, slot: Keyslot) -> Result<(), Error> {
        if idx >= MAX_KEYSLOTS {
            return Err(Error::InvalidKeyslotIndex(idx));
        }
        self.keyslots[idx] = slot;
        Ok(())
    }

    pub fn revoke_slot(&mut self, idx: usize) -> Result<(), Error> {
        if idx >= MAX_KEYSLOTS {
            return Err(Error::InvalidKeyslotIndex(idx));
        }
        self.keyslots[idx] = Keyslot::empty();
        Ok(())
    }

    /// Serialize, computing the HMAC under a key derived from `mvk`.
    pub fn to_bytes(&self, mvk: &MasterVolumeKey) -> [u8; HEADER_SIZE] {
        let mut buf = self.serialize_unauth();
        let mac_key = mvk.derive_subkey(&self.header_salt, HEADER_MAC_INFO);
        let tag = compute_hmac(&*mac_key, &buf[..OFF_HMAC]);
        buf[OFF_HMAC..].copy_from_slice(&tag);
        buf
    }

    /// Parse without verifying the HMAC. Caller must verify by recomputing once
    /// an MVK candidate has been recovered from a keyslot.
    pub fn from_bytes(buf: &[u8; HEADER_SIZE]) -> Result<Self, Error> {
        let magic_bytes: &[u8] = &buf[OFF_MAGIC..OFF_MAGIC + 8];
        let version_major = if magic_bytes == MAGIC_V1 {
            VERSION_MAJOR_V1
        } else if magic_bytes == MAGIC_V2 {
            VERSION_MAJOR_V2
        } else {
            return Err(Error::InvalidMagic);
        };
        let major = u16::from_le_bytes(buf[OFF_VER_MAJOR..OFF_VER_MAJOR + 2].try_into().unwrap());
        let minor = u16::from_le_bytes(buf[OFF_VER_MINOR..OFF_VER_MINOR + 2].try_into().unwrap());
        // The magic byte sequence and the version_major field are two
        // independent encodings of the same fact; refuse a header where
        // they disagree (would indicate format confusion or an attempt
        // to feed v2 fields into the v1 parsing path).
        if major != version_major {
            return Err(Error::UnsupportedVersion { major, minor });
        }
        let header_size = u32::from_le_bytes(
            buf[OFF_HEADER_SIZE..OFF_HEADER_SIZE + 4]
                .try_into()
                .unwrap(),
        ) as usize;
        if header_size != HEADER_SIZE {
            return Err(Error::InvalidField);
        }
        let cipher_suite = CipherSuite::from_u16(u16::from_le_bytes(
            buf[OFF_CIPHER..OFF_CIPHER + 2].try_into().unwrap(),
        ))?;
        let kdf = KdfId::from_u16(u16::from_le_bytes(
            buf[OFF_KDF..OFF_KDF + 2].try_into().unwrap(),
        ))?;
        let chunk_size =
            u32::from_le_bytes(buf[OFF_CHUNK_SIZE..OFF_CHUNK_SIZE + 4].try_into().unwrap());
        // Range-check chunk_size BEFORE accepting the header. A
        // collaborator who has the MVK can craft a header that
        // authenticates correctly but reports a nonsense chunk size;
        // we don't want that to wrap a downstream `vec![0u8; chunk_size
        // as usize]` allocation. Currently the runtime ignores this
        // field and uses CHUNK_PLAINTEXT_SIZE = 4096 anyway, but the
        // cap leaves room for a future format extension while
        // refusing pathological values that would explode chunk
        // counts or trigger huge allocations.
        if !(MIN_CHUNK_SIZE..=MAX_CHUNK_SIZE).contains(&chunk_size) {
            return Err(Error::InvalidField);
        }
        let flags = u32::from_le_bytes(buf[OFF_FLAGS..OFF_FLAGS + 4].try_into().unwrap());
        let mut header_salt = [0u8; 32];
        header_salt.copy_from_slice(&buf[OFF_HEADER_SALT..OFF_HEADER_SALT + 32]);
        let metadata_offset = u64::from_le_bytes(
            buf[OFF_METADATA_OFFSET..OFF_METADATA_OFFSET + 8]
                .try_into()
                .unwrap(),
        );
        let metadata_size = u64::from_le_bytes(
            buf[OFF_METADATA_SIZE..OFF_METADATA_SIZE + 8]
                .try_into()
                .unwrap(),
        );
        let data_offset = u64::from_le_bytes(
            buf[OFF_DATA_OFFSET..OFF_DATA_OFFSET + 8]
                .try_into()
                .unwrap(),
        );
        // The DoS-relevant cap. `read_metadata` does
        // `vec![0u8; header.metadata_size as usize]`; without this
        // check, a u64::MAX value passed by a collaborator who can
        // produce a valid-AEAD vault would attempt an exabyte-scale
        // allocation. Real vaults have about 1 MiB of metadata at most
        // (DEFAULT_METADATA_REGION_SIZE in luksbox-format); 16 MiB
        // gives 16x headroom for future growth and remains well below
        // any realistic OOM threshold.
        if metadata_size > MAX_METADATA_SIZE {
            return Err(Error::InvalidField);
        }
        // Overflow guard: a hostile metadata_offset close to u64::MAX
        // combined with a non-zero metadata_size could wrap the seek
        // arithmetic in `read_metadata`. checked_add catches it
        // before any allocation/seek happens. The resulting
        // `metadata_end` is then reused by the layout checks below.
        let metadata_end = metadata_offset
            .checked_add(metadata_size)
            .ok_or(Error::InvalidField)?;
        // Layout sanity. These fields are HMAC-authenticated, but the
        // MVK holder can still produce a valid HMAC over a structurally
        // invalid layout. Two cases to reject:
        //   (a) `metadata_offset` lands inside the inline-header
        //       region (1..HEADER_SIZE). Detached-header vaults
        //       legitimately use `metadata_offset == 0` (the .lbx
        //       starts with metadata because the header lives in a
        //       sidecar); inline-header vaults use
        //       `metadata_offset >= HEADER_SIZE`. Anything in between
        //       would let later `write_metadata` calls scribble
        //       inside the inline-header bytes we just parsed.
        //   (b) `data_offset < metadata_end` would let chunk writes
        //       alias the encrypted metadata region.
        // The deniable header parser enforces the equivalent invariants
        // (see `crates/luksbox-format/src/deniable_header.rs` parse()).
        if metadata_offset > 0 && metadata_offset < HEADER_SIZE as u64 {
            return Err(Error::InvalidField);
        }
        if data_offset < metadata_end {
            return Err(Error::InvalidField);
        }
        let keyslot_count = u32::from_le_bytes(
            buf[OFF_KEYSLOT_COUNT..OFF_KEYSLOT_COUNT + 4]
                .try_into()
                .unwrap(),
        ) as usize;
        if keyslot_count != MAX_KEYSLOTS {
            return Err(Error::InvalidField);
        }

        let mut keyslots: [Keyslot; MAX_KEYSLOTS] = core::array::from_fn(|_| Keyslot::empty());
        for i in 0..MAX_KEYSLOTS {
            let off = OFF_KEYSLOTS + i * SLOT_SIZE;
            let slot_bytes: &[u8; SLOT_SIZE] = buf[off..off + SLOT_SIZE].try_into().unwrap();
            keyslots[i] = Keyslot::from_bytes(slot_bytes)?;
        }

        Ok(Self {
            cipher_suite,
            kdf,
            chunk_size,
            flags,
            header_salt,
            metadata_offset,
            metadata_size,
            data_offset,
            keyslots,
            version_major,
        })
    }

    /// Verify the HMAC. Call after a candidate MVK has been recovered.
    pub fn verify_hmac(&self, raw: &[u8; HEADER_SIZE], mvk: &MasterVolumeKey) -> Result<(), Error> {
        let mac_key = mvk.derive_subkey(&self.header_salt, HEADER_MAC_INFO);
        let expected = compute_hmac(&*mac_key, &raw[..OFF_HMAC]);
        if expected.ct_eq(&raw[OFF_HMAC..]).into() {
            Ok(())
        } else {
            Err(Error::HeaderAuthFailed)
        }
    }

    fn serialize_unauth(&self) -> [u8; HEADER_SIZE] {
        let mut buf = [0u8; HEADER_SIZE];
        // Random-fill the area between the last keyslot and the HMAC so
        // unused header padding is indistinguishable from ciphertext.
        // Empty bytes elsewhere are written by the structured-field
        // copies below; the HMAC trailer (OFF_HMAC..HEADER_SIZE) stays
        // zero here so the HMAC computation in `to_bytes` doesn't
        // include itself.
        let reserved_end = OFF_HMAC;
        let reserved_start = OFF_KEYSLOTS + MAX_KEYSLOTS * SLOT_SIZE;
        // Header padding fill, non-cryptographic (entropy obfuscation
        // for the unused reserved region; AEAD doesn't authenticate it).
        // Document the panic explicitly. Crypto-bearing RNG calls
        // (header_salt, slot KDF salt, slot AEAD nonces) all use
        // try_fill_bytes elsewhere with proper Result propagation.
        OsRng
            .try_fill_bytes(&mut buf[reserved_start..reserved_end])
            .expect("OS RNG failure during header padding fill");

        let magic = match self.version_major {
            VERSION_MAJOR_V2 => MAGIC_V2,
            // Default to v1 magic for any other value, including 0 from
            // a freshly-built `Header` that hasn't been initialized via
            // try_new (defensive; try_new always sets v1).
            _ => MAGIC_V1,
        };
        buf[OFF_MAGIC..OFF_MAGIC + 8].copy_from_slice(&magic);
        buf[OFF_VER_MAJOR..OFF_VER_MAJOR + 2].copy_from_slice(&self.version_major.to_le_bytes());
        buf[OFF_VER_MINOR..OFF_VER_MINOR + 2].copy_from_slice(&VERSION_MINOR.to_le_bytes());
        buf[OFF_HEADER_SIZE..OFF_HEADER_SIZE + 4]
            .copy_from_slice(&(HEADER_SIZE as u32).to_le_bytes());
        buf[OFF_CIPHER..OFF_CIPHER + 2].copy_from_slice(&(self.cipher_suite as u16).to_le_bytes());
        buf[OFF_KDF..OFF_KDF + 2].copy_from_slice(&(self.kdf as u16).to_le_bytes());
        buf[OFF_CHUNK_SIZE..OFF_CHUNK_SIZE + 4].copy_from_slice(&self.chunk_size.to_le_bytes());
        buf[OFF_HEADER_SALT..OFF_HEADER_SALT + 32].copy_from_slice(&self.header_salt);
        buf[OFF_METADATA_OFFSET..OFF_METADATA_OFFSET + 8]
            .copy_from_slice(&self.metadata_offset.to_le_bytes());
        buf[OFF_METADATA_SIZE..OFF_METADATA_SIZE + 8]
            .copy_from_slice(&self.metadata_size.to_le_bytes());
        buf[OFF_DATA_OFFSET..OFF_DATA_OFFSET + 8].copy_from_slice(&self.data_offset.to_le_bytes());
        buf[OFF_KEYSLOT_COUNT..OFF_KEYSLOT_COUNT + 4]
            .copy_from_slice(&(MAX_KEYSLOTS as u32).to_le_bytes());
        buf[OFF_FLAGS..OFF_FLAGS + 4].copy_from_slice(&self.flags.to_le_bytes());

        for (i, slot) in self.keyslots.iter().enumerate() {
            let off = OFF_KEYSLOTS + i * SLOT_SIZE;
            buf[off..off + SLOT_SIZE].copy_from_slice(&slot.to_bytes());
        }
        buf
    }
}

fn compute_hmac(key: &[u8; 32], data: &[u8]) -> [u8; HMAC_LEN] {
    let mut mac = <Hmac<Sha256>>::new_from_slice(key).expect("HMAC accepts any-length key");
    mac.update(data);
    let out = mac.finalize().into_bytes();
    let mut tag = [0u8; HMAC_LEN];
    tag.copy_from_slice(&out);
    tag
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::kdf::Argon2idParams;
    use crate::keyslot::Keyslot;

    #[test]
    fn header_roundtrip_and_unlock() {
        let suite = CipherSuite::Aes256Gcm;
        let mvk = MasterVolumeKey::from_bytes([0x99; 32]);
        let mut header = Header::new(suite, KdfId::Argon2id, 4096, HEADER_SIZE as u64);

        let slot = Keyslot::new_passphrase(
            suite,
            &mvk,
            b"a strong passphrase",
            Argon2idParams::TEST_ONLY,
            &header.header_salt,
        )
        .unwrap();
        header.install_slot(0, slot).unwrap();

        let bytes = header.to_bytes(&mvk);

        let parsed = Header::from_bytes(&bytes).unwrap();
        assert_eq!(parsed.cipher_suite, suite);
        assert_eq!(parsed.chunk_size, 4096);
        assert_eq!(parsed.header_salt, header.header_salt);

        let recovered = parsed.keyslots[0]
            .unlock_passphrase(suite, b"a strong passphrase", &parsed.header_salt)
            .unwrap();
        assert_eq!(recovered.as_bytes(), mvk.as_bytes());

        parsed.verify_hmac(&bytes, &recovered).unwrap();
    }

    #[test]
    fn header_tamper_detected_after_unlock() {
        let suite = CipherSuite::Aes256Gcm;
        let mvk = MasterVolumeKey::from_bytes([0xab; 32]);
        let mut header = Header::new(suite, KdfId::Argon2id, 4096, HEADER_SIZE as u64);
        let slot = Keyslot::new_passphrase(
            suite,
            &mvk,
            b"pw",
            Argon2idParams::TEST_ONLY,
            &header.header_salt,
        )
        .unwrap();
        header.install_slot(0, slot).unwrap();
        let mut bytes = header.to_bytes(&mvk);
        bytes[OFF_CHUNK_SIZE] ^= 1;

        let parsed = Header::from_bytes(&bytes).unwrap();
        let recovered = parsed.keyslots[0]
            .unlock_passphrase(suite, b"pw", &parsed.header_salt)
            .unwrap();
        assert!(parsed.verify_hmac(&bytes, &recovered).is_err());
    }

    #[test]
    fn invalid_magic_rejected() {
        let mut bytes = [0u8; HEADER_SIZE];
        bytes[..8].copy_from_slice(b"NOTLBX01");
        assert!(matches!(
            Header::from_bytes(&bytes),
            Err(Error::InvalidMagic)
        ));
    }

    /// Build a syntactically-valid header bytestream we can mutate to
    /// test the field-cap rejections. The HMAC trailer is left blank;
    /// `from_bytes` parses without verifying it, so caps fire first.
    fn well_formed_header_bytes() -> [u8; HEADER_SIZE] {
        let mvk = MasterVolumeKey::from_bytes([0x42; 32]);
        let header = Header::new(
            CipherSuite::Aes256GcmSiv,
            KdfId::Argon2id,
            4096,
            HEADER_SIZE as u64,
        );
        header.to_bytes(&mvk)
    }

    #[test]
    fn header_rejects_oversize_metadata_size() {
        // A collaborator who has the MVK could ship a vault with a
        // metadata_size of u64::MAX, hoping our `read_metadata` would
        // try to allocate exabytes. The cap rejects it before we even
        // verify the HMAC.
        let mut bytes = well_formed_header_bytes();
        let bogus = (MAX_METADATA_SIZE + 1).to_le_bytes();
        bytes[OFF_METADATA_SIZE..OFF_METADATA_SIZE + 8].copy_from_slice(&bogus);
        assert!(matches!(
            Header::from_bytes(&bytes),
            Err(Error::InvalidField)
        ));
    }

    #[test]
    fn header_rejects_metadata_offset_size_overflow() {
        // metadata_offset close to u64::MAX with non-zero metadata_size
        // would wrap arithmetic in `read_metadata`'s seek+allocate path.
        let mut bytes = well_formed_header_bytes();
        bytes[OFF_METADATA_OFFSET..OFF_METADATA_OFFSET + 8]
            .copy_from_slice(&u64::MAX.to_le_bytes());
        bytes[OFF_METADATA_SIZE..OFF_METADATA_SIZE + 8].copy_from_slice(&1u64.to_le_bytes());
        assert!(matches!(
            Header::from_bytes(&bytes),
            Err(Error::InvalidField)
        ));
    }

    #[test]
    fn header_rejects_data_offset_inside_metadata_region() {
        // Authenticated fields still need semantic validation. A
        // malicious MVK holder can produce a valid header HMAC where
        // chunk slot 0 starts inside the encrypted metadata region;
        // accepting it would let chunk writes alias the metadata blob.
        let mut bytes = well_formed_header_bytes();
        let metadata_offset = u64::from_le_bytes(
            bytes[OFF_METADATA_OFFSET..OFF_METADATA_OFFSET + 8]
                .try_into()
                .unwrap(),
        );
        bytes[OFF_METADATA_SIZE..OFF_METADATA_SIZE + 8].copy_from_slice(&4096u64.to_le_bytes());
        bytes[OFF_DATA_OFFSET..OFF_DATA_OFFSET + 8].copy_from_slice(&metadata_offset.to_le_bytes());
        assert!(matches!(
            Header::from_bytes(&bytes),
            Err(Error::InvalidField)
        ));
    }

    #[test]
    fn header_rejects_metadata_offset_inside_header_region() {
        // Same threat-model as the previous test, one layer earlier:
        // an MVK holder can claim metadata_offset < HEADER_SIZE so
        // that downstream `write_metadata` calls overwrite the
        // authenticated header bytes themselves. The deniable parser
        // already enforces the analogous `metadata_offset <
        // DENIABLE_HEADER_SIZE` rejection.
        let mut bytes = well_formed_header_bytes();
        bytes[OFF_METADATA_OFFSET..OFF_METADATA_OFFSET + 8]
            .copy_from_slice(&((HEADER_SIZE as u64) - 1).to_le_bytes());
        assert!(matches!(
            Header::from_bytes(&bytes),
            Err(Error::InvalidField)
        ));
    }

    #[test]
    fn header_rejects_chunk_size_below_min() {
        let mut bytes = well_formed_header_bytes();
        bytes[OFF_CHUNK_SIZE..OFF_CHUNK_SIZE + 4].copy_from_slice(&0u32.to_le_bytes());
        assert!(matches!(
            Header::from_bytes(&bytes),
            Err(Error::InvalidField)
        ));
    }

    #[test]
    fn header_rejects_chunk_size_above_max() {
        let mut bytes = well_formed_header_bytes();
        bytes[OFF_CHUNK_SIZE..OFF_CHUNK_SIZE + 4]
            .copy_from_slice(&(MAX_CHUNK_SIZE + 1).to_le_bytes());
        assert!(matches!(
            Header::from_bytes(&bytes),
            Err(Error::InvalidField)
        ));
    }

    #[test]
    fn header_default_try_new_is_v1() {
        let h = Header::new(
            CipherSuite::Aes256Gcm,
            KdfId::Argon2id,
            4096,
            HEADER_SIZE as u64,
        );
        assert_eq!(h.version_major, VERSION_MAJOR_V1);
        assert!(!h.has_header_mirror());
        assert!(!h.has_metadata_mirror());
    }

    #[test]
    fn header_v2_roundtrip() {
        let suite = CipherSuite::Aes256Gcm;
        let mvk = MasterVolumeKey::from_bytes([0x77; 32]);
        let mut header = Header::new(suite, KdfId::Argon2id, 4096, HEADER_SIZE as u64);
        header.version_major = VERSION_MAJOR_V2;
        header.flags |= FLAG_HAS_HEADER_MIRROR | FLAG_HAS_METADATA_MIRROR;
        let slot = Keyslot::new_passphrase(
            suite,
            &mvk,
            b"v2 vault",
            Argon2idParams::TEST_ONLY,
            &header.header_salt,
        )
        .unwrap();
        header.install_slot(0, slot).unwrap();

        let bytes = header.to_bytes(&mvk);
        assert_eq!(&bytes[OFF_MAGIC..OFF_MAGIC + 8], &MAGIC_V2);

        let parsed = Header::from_bytes(&bytes).unwrap();
        assert_eq!(parsed.version_major, VERSION_MAJOR_V2);
        assert!(parsed.has_header_mirror());
        assert!(parsed.has_metadata_mirror());

        let recovered = parsed.keyslots[0]
            .unlock_passphrase(suite, b"v2 vault", &parsed.header_salt)
            .unwrap();
        parsed.verify_hmac(&bytes, &recovered).unwrap();
    }

    #[test]
    fn header_v1_magic_with_v2_version_field_rejected() {
        // A vault built with LUKSBOX1 magic but a version_major of 2
        // in the structured field is an inconsistent on-disk state.
        // Reject it so neither half of the encoding can be used to
        // smuggle the other through.
        let mut bytes = well_formed_header_bytes();
        bytes[OFF_VER_MAJOR..OFF_VER_MAJOR + 2].copy_from_slice(&VERSION_MAJOR_V2.to_le_bytes());
        assert!(matches!(
            Header::from_bytes(&bytes),
            Err(Error::UnsupportedVersion { .. })
        ));
    }

    #[test]
    fn header_unknown_magic_still_rejected() {
        let mut bytes = [0u8; HEADER_SIZE];
        bytes[..8].copy_from_slice(b"LUKSBOX3");
        assert!(matches!(
            Header::from_bytes(&bytes),
            Err(Error::InvalidMagic)
        ));
    }

    #[test]
    fn header_mirror_flag_bits_disjoint() {
        // Guard against an accidental collision with the existing
        // privacy-padding flag bits.
        assert_ne!(
            FLAG_HAS_HEADER_MIRROR & FLAG_PAD_FILES_POW2,
            FLAG_HAS_HEADER_MIRROR
        );
        assert_ne!(
            FLAG_HAS_HEADER_MIRROR & FLAG_HIDE_SIZE_HEADER,
            FLAG_HAS_HEADER_MIRROR
        );
        assert_ne!(
            FLAG_HAS_METADATA_MIRROR & FLAG_PAD_FILES_POW2,
            FLAG_HAS_METADATA_MIRROR
        );
        assert_ne!(
            FLAG_HAS_METADATA_MIRROR & FLAG_HIDE_SIZE_HEADER,
            FLAG_HAS_METADATA_MIRROR
        );
        assert_ne!(FLAG_HAS_HEADER_MIRROR, FLAG_HAS_METADATA_MIRROR);
    }

    #[test]
    fn header_max_metadata_size_is_64_mib() {
        // Pin the cap so any future change is intentional. The plan
        // raises it from 16 MiB (v0.2.0) to 64 MiB to fit large-vault
        // chunk-ref tables without spilling to ENOSPC.
        assert_eq!(MAX_METADATA_SIZE, 64 << 20);
    }
}
