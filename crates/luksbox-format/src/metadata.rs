// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Penthertz <https://penthertz.com> (https://x.com/PentHertz)

use rand_core::{OsRng, RngCore};
use zeroize::Zeroizing;

use luksbox_core::{CipherSuite, MasterVolumeKey, SubKey, aead};

use crate::error::Error;

/// Default metadata region size: 16 MiB. Holds the encrypted directory tree
/// and any small global metadata, re-encrypted on every write.
///
/// Sized to fill the format-level cap [`luksbox_core::header::MAX_METADATA_SIZE`]
/// (also 16 MiB). Practical vault-data headroom before the chunk-ref list
/// overflows: **~8-10 GiB**, depending on directory depth, file count, and
/// how big the chunk IDs grow (a single ChunkRef is two u64 postcard varints,
/// 4-6 B at realistic IDs; plus per-inode + Vec-length overhead). The
/// original 1 MiB default silently lost data around ~800 MiB of total stored
/// content. Bumping to 16 MiB pushes the ceiling out by ~12x.
///
/// To support vaults beyond ~10 GiB the on-disk format itself needs work:
/// either raise `MAX_METADATA_SIZE` (forward-compat-breaking change for old
/// readers) or move the per-file chunk list out-of-line into the data area
/// (proper format v2). Both are deferred to a future release.
///
/// On-disk cost: an empty vault is at least `metadata_offset + 16 MiB`. For
/// the typical "encrypted backup of $HOME on a USB stick" use case this is
/// rounding error; for very small demo vaults, override via the
/// `--metadata-size` CLI flag.
pub const DEFAULT_METADATA_REGION_SIZE: u64 = 16 * 1024 * 1024;

/// Per-blob fixed overhead on disk: 12 B nonce + 8 B ciphertext-length + 16 B tag.
pub const METADATA_OVERHEAD: usize = 12 + 8 + 16;

/// Magic prefix written ahead of the postcard payload in v2 metadata blobs
/// (`b"LBM2"`). Counted alongside the postcard size when budgeting the AEAD
/// plaintext, but defined in `luksbox-vfs::vfs`. Kept here as a known
/// upper-bound constant for the fail-fast check in `Vfs::write`:
/// any caller estimating the metadata budget should subtract this too.
pub const METADATA_MAGIC_LEN: usize = 4;

/// Maximum useful postcard payload that fits in a metadata region of the given
/// size. Returns the largest `plaintext.len()` for which `write_metadata`
/// would NOT return `Error::MetadataTooLarge`, minus the magic prefix the
/// VFS layer prepends to the postcard payload. Saturates at zero for
/// pathologically small regions.
///
/// Used by `Vfs::write` (and friends) to fail mid-write with ENOSPC as soon
/// as the dirty tree would no longer serialize within the on-disk budget,
/// instead of letting `cp` claim success and only surfacing the failure at
/// flush time — which causes silent data loss because the chunks are
/// already on disk but the metadata pointer is not.
pub fn payload_budget_for(region_size: u64) -> usize {
    let cap = region_size as usize;
    cap.saturating_sub(METADATA_OVERHEAD)
        .saturating_sub(METADATA_MAGIC_LEN)
}

// ----------------------------------------------------------------------
// Thread-local override for the per-vault metadata region size at create
// time. The 17 `Container::create_with_*` constructors all funnel through
// `create_internal` (or a parallel path for the FIDO2-derived-MVK and
// deniable creates); rather than threading an `Option<u64>` through every
// signature, the CLI / GUI / wizard layer sets this override on the
// thread that's about to call create. `create_internal` reads it and
// resets it on drop so a leaked override can't poison a later create on
// the same thread.
//
// Why thread-local and not a parameter: parameter plumbing through 17
// public function signatures was rejected (large API surface change,
// breaks every external consumer). Why thread-local and not process-
// global: lets concurrent creates on different threads pick different
// sizes (e.g. a GUI background worker creating one vault while the user
// inspects another from a different code path). Reset-on-drop via a
// guard makes leaks impossible.
//
// Scope: ONLY used at create time. Open / read / write paths read the
// metadata region size from the on-disk header field, never from this
// override. So an existing vault always uses its written-at-create
// size regardless of what's been set here later.
// ----------------------------------------------------------------------
thread_local! {
    static CREATE_METADATA_SIZE_OVERRIDE: std::cell::Cell<Option<u64>> =
        const { std::cell::Cell::new(None) };
}

/// Read the current thread-local metadata-region-size override, or
/// fall back to `DEFAULT_METADATA_REGION_SIZE`. The on-disk cap
/// [`luksbox_core::header::MAX_METADATA_SIZE`] (16 MiB today) is also
/// enforced by the header parser at create time, so callers that set
/// an absurd override get a clean rejection.
pub fn resolved_create_metadata_region_size() -> u64 {
    CREATE_METADATA_SIZE_OVERRIDE
        .with(|c| c.get())
        .unwrap_or(DEFAULT_METADATA_REGION_SIZE)
}

/// RAII guard returned by [`set_create_metadata_region_size_override`].
/// Restores the previous override on drop so a panic between set and
/// create-call can't poison a later create on the same thread.
pub struct CreateMetadataSizeOverrideGuard {
    previous: Option<u64>,
}

impl Drop for CreateMetadataSizeOverrideGuard {
    fn drop(&mut self) {
        CREATE_METADATA_SIZE_OVERRIDE.with(|c| c.set(self.previous));
    }
}

/// Set the metadata-region size for any `Container::create_with_*` call
/// made on this thread until the returned guard is dropped. `None`
/// restores the default. Stacking guards is supported (Drop restores
/// the previous value, not unconditionally `None`).
///
/// Example (CLI flag):
/// ```ignore
/// let _g = set_create_metadata_region_size_override(Some(8 * 1024 * 1024));
/// Container::create_with_passphrase(/* ... */)?;
/// // guard drops here, override clears
/// ```
pub fn set_create_metadata_region_size_override(
    size: Option<u64>,
) -> CreateMetadataSizeOverrideGuard {
    let previous = CREATE_METADATA_SIZE_OVERRIDE.with(|c| c.replace(size));
    CreateMetadataSizeOverrideGuard { previous }
}

const NONCE_LEN: usize = 12;
const LEN_FIELD_LEN: usize = 8;
const TAG_LEN: usize = 16;

const METADATA_KEY_INFO: &[u8] = b"lbx:metadata-key/v1";

fn metadata_key(mvk: &MasterVolumeKey, header_salt: &[u8; 32]) -> SubKey {
    mvk.derive_subkey(header_salt, METADATA_KEY_INFO)
}

/// Serialize an encrypted metadata blob into a fixed-size on-disk region.
/// Region must be exactly `region_size` bytes.
///
/// Layout written into `region`:
/// ```text
///   [ 12 B nonce | 8 B u64 LE ct_len | ct_len bytes ciphertext+tag | zero-pad ]
/// ```
/// AAD = `header_salt || ct_len.to_le_bytes()`, authenticates the length and
/// binds the blob to its container.
pub fn write_metadata(
    suite: CipherSuite,
    mvk: &MasterVolumeKey,
    header_salt: &[u8; 32],
    plaintext: &[u8],
    region: &mut [u8],
) -> Result<(), Error> {
    if plaintext.len() + METADATA_OVERHEAD > region.len() {
        return Err(Error::MetadataTooLarge);
    }
    let mut nonce = [0u8; NONCE_LEN];
    OsRng
        .try_fill_bytes(&mut nonce)
        .map_err(|e| Error::Crypto(luksbox_core::Error::OsRng(e.to_string())))?;

    let key = metadata_key(mvk, header_salt);
    let ct_len = (plaintext.len() + TAG_LEN) as u64;

    let mut aad = [0u8; 32 + LEN_FIELD_LEN];
    aad[..32].copy_from_slice(header_salt);
    aad[32..].copy_from_slice(&ct_len.to_le_bytes());

    let ct = aead::seal(suite, &*key, &nonce, &aad, plaintext)?;
    debug_assert_eq!(ct.len(), ct_len as usize);

    // Fill the entire region with random bytes BEFORE writing the real
    // {nonce, ct_len, ciphertext+tag} prefix. Without this, a small
    // metadata blob (e.g. an empty directory tree) leaves about 1 MiB of zeros
    // in the file, which is trivially detectable by entropy analysis
    // (`ent` reports about 0.13 bits/byte) and leaks how much metadata the
    // vault holds. The padding is unauthenticated, AEAD only protects
    // the ct_len-byte prefix, but that's fine: we just need it to be
    // indistinguishable from ciphertext to an external observer.
    // RNG failure here is non-cryptographic (the AEAD nonce above used
    // try_fill_bytes); document the panic explicitly.
    OsRng
        .try_fill_bytes(region)
        .expect("OS RNG failure during metadata padding fill");
    region[..NONCE_LEN].copy_from_slice(&nonce);
    region[NONCE_LEN..NONCE_LEN + LEN_FIELD_LEN].copy_from_slice(&ct_len.to_le_bytes());
    region[NONCE_LEN + LEN_FIELD_LEN..NONCE_LEN + LEN_FIELD_LEN + ct.len()].copy_from_slice(&ct);
    Ok(())
}

/// Parse and decrypt an on-disk metadata region. Returned plaintext is
/// `Zeroizing<Vec<u8>>` so the directory-tree blob is memset-to-zero when
/// the caller drops it (after deserializing into the in-memory tree).
pub fn read_metadata(
    suite: CipherSuite,
    mvk: &MasterVolumeKey,
    header_salt: &[u8; 32],
    region: &[u8],
) -> Result<Zeroizing<Vec<u8>>, Error> {
    if region.len() < METADATA_OVERHEAD {
        return Err(Error::MetadataCorrupt);
    }
    let mut nonce = [0u8; NONCE_LEN];
    nonce.copy_from_slice(&region[..NONCE_LEN]);
    let ct_len = u64::from_le_bytes(
        region[NONCE_LEN..NONCE_LEN + LEN_FIELD_LEN]
            .try_into()
            .unwrap(),
    ) as usize;

    let body_start = NONCE_LEN + LEN_FIELD_LEN;
    let body_end = match body_start.checked_add(ct_len) {
        Some(v) => v,
        None => return Err(Error::MetadataCorrupt),
    };
    if ct_len < TAG_LEN || body_end > region.len() {
        return Err(Error::MetadataCorrupt);
    }
    let ct = &region[body_start..body_end];

    let key = metadata_key(mvk, header_salt);
    let mut aad = [0u8; 32 + LEN_FIELD_LEN];
    aad[..32].copy_from_slice(header_salt);
    aad[32..].copy_from_slice(&(ct_len as u64).to_le_bytes());

    let pt = aead::open(suite, &*key, &nonce, &aad, ct)?;
    Ok(Zeroizing::new(pt))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn metadata_roundtrip_empty() {
        let mvk = MasterVolumeKey::from_bytes([0x11; 32]);
        let salt = [0x22u8; 32];
        let mut region = vec![0u8; DEFAULT_METADATA_REGION_SIZE as usize];
        write_metadata(CipherSuite::Aes256Gcm, &mvk, &salt, b"", &mut region).unwrap();
        let pt = read_metadata(CipherSuite::Aes256Gcm, &mvk, &salt, &region).unwrap();
        assert_eq!(&**pt, b"");
    }

    #[test]
    fn metadata_roundtrip_payload() {
        let mvk = MasterVolumeKey::from_bytes([0x33; 32]);
        let salt = [0x44u8; 32];
        let mut region = vec![0u8; DEFAULT_METADATA_REGION_SIZE as usize];
        let payload = b"directory-tree-bytes-go-here-this-is-our-fake-blob-for-now";
        write_metadata(
            CipherSuite::ChaCha20Poly1305,
            &mvk,
            &salt,
            payload,
            &mut region,
        )
        .unwrap();
        let pt = read_metadata(CipherSuite::ChaCha20Poly1305, &mvk, &salt, &region).unwrap();
        assert_eq!(&**pt, payload);
    }

    #[test]
    fn metadata_tamper_detected() {
        let mvk = MasterVolumeKey::from_bytes([0x55; 32]);
        let salt = [0x66u8; 32];
        let mut region = vec![0u8; DEFAULT_METADATA_REGION_SIZE as usize];
        write_metadata(CipherSuite::Aes256Gcm, &mvk, &salt, b"hello", &mut region).unwrap();
        region[NONCE_LEN + LEN_FIELD_LEN] ^= 1;
        assert!(read_metadata(CipherSuite::Aes256Gcm, &mvk, &salt, &region).is_err());
    }

    #[test]
    fn metadata_too_large() {
        let mvk = MasterVolumeKey::from_bytes([0x77; 32]);
        let salt = [0x88u8; 32];
        let mut region = vec![0u8; 256];
        let huge = vec![0u8; 4096];
        let r = write_metadata(CipherSuite::Aes256Gcm, &mvk, &salt, &huge, &mut region);
        assert!(matches!(r, Err(Error::MetadataTooLarge)));
    }

    #[test]
    fn metadata_ct_len_overflow_rejected() {
        // Regression for fuzz-found crash: ct_len = u64::MAX would wrap
        // body_start + ct_len, fooling the bounds check.
        let mvk = MasterVolumeKey::from_bytes([0x42; 32]);
        let salt = [0x77u8; 32];
        let mut region = vec![0u8; 64];
        region[..NONCE_LEN].copy_from_slice(&[0xab; NONCE_LEN]);
        region[NONCE_LEN..NONCE_LEN + LEN_FIELD_LEN].copy_from_slice(&u64::MAX.to_le_bytes());
        let r = read_metadata(CipherSuite::Aes256Gcm, &mvk, &salt, &region);
        assert!(matches!(r, Err(Error::MetadataCorrupt)));
    }

    #[test]
    fn metadata_wrong_salt_rejected() {
        let mvk = MasterVolumeKey::from_bytes([0x99; 32]);
        let salt = [0xaau8; 32];
        let mut region = vec![0u8; DEFAULT_METADATA_REGION_SIZE as usize];
        write_metadata(CipherSuite::Aes256Gcm, &mvk, &salt, b"x", &mut region).unwrap();
        let mut other = salt;
        other[0] ^= 1;
        assert!(read_metadata(CipherSuite::Aes256Gcm, &mvk, &other, &region).is_err());
    }
}
