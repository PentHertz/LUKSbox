// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Penthertz <https://penthertz.com> (https://x.com/PentHertz)

use rand_core::{OsRng, RngCore};
use zeroize::Zeroizing;

use luksbox_core::{CipherSuite, MasterVolumeKey, SubKey, aead};

use crate::error::Error;

/// Default metadata region size: 64 MiB (raised from 16 MiB in v0.2.1).
/// Holds the encrypted directory tree and any small global metadata,
/// re-encrypted on every write.
///
/// Sized to match the format-level cap
/// [`luksbox_core::header::MAX_METADATA_SIZE`]. The bump from 16 MiB
/// pushes the in-line chunk-ref table out from a ~10 GiB practical
/// ceiling to ~40+ GiB and addresses the v0.2.0 user-visible
/// "no space left on device" failure that hit when a directory tree
/// with thousands of inodes plus their inline chunk-ref vectors
/// overflowed the smaller region during a heavy copy.
///
/// New-vault default; existing v0.2.0 vaults keep their on-disk
/// `metadata_size` field (16 MiB) and never grow the region in place.
/// Beyond the cap, the format-v5 spill threshold (256 chunks per inode
/// instead of 1024) keeps the encoded tree compact for very large vaults.
///
/// On-disk cost: an empty new vault is at least `metadata_offset + 64 MiB`.
/// For the typical "encrypted backup of $HOME on a USB stick" use case
/// this is rounding error; for very small demo vaults, override via the
/// `--metadata-size` CLI flag.
pub const DEFAULT_METADATA_REGION_SIZE: u64 = 64 * 1024 * 1024;

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
/// flush time -- which causes silent data loss because the chunks are
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
/// fall back to `DEFAULT_METADATA_REGION_SIZE`, clamped to the on-disk
/// cap [`luksbox_core::header::MAX_METADATA_SIZE`] (64 MiB).
///
/// The clamp is load-bearing: `Header::from_bytes` rejects any
/// `metadata_size > MAX_METADATA_SIZE` at OPEN time, but the create path
/// (`Header::to_bytes`) does NOT validate. Without clamping here, a
/// caller-supplied override above the cap (e.g. `--metadata-size 100M`)
/// would write a header that can never be re-opened -- an unreopenable
/// vault -- and could overflow the `metadata_offset + region_size`
/// arithmetic in `create_internal`. Clamping at this single choke point
/// keeps every created vault reopenable regardless of what any front-end
/// passes. Overrides at or below the cap (the common `--metadata-size`
/// case, and the 64 MiB default) pass through unchanged.
pub fn resolved_create_metadata_region_size() -> u64 {
    let requested = CREATE_METADATA_SIZE_OVERRIDE
        .with(|c| c.get())
        .unwrap_or(DEFAULT_METADATA_REGION_SIZE);
    requested.min(luksbox_core::header::MAX_METADATA_SIZE)
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
/// R15-D2: HKDF label of the per-vault key that masks the length field.
const METADATA_LEN_MASK_INFO: &[u8] = b"lbx:metadata-len-mask/v1";

fn metadata_key(mvk: &MasterVolumeKey, header_salt: &[u8; 32]) -> SubKey {
    mvk.derive_subkey(header_salt, METADATA_KEY_INFO)
}

/// R15-D2: 8-byte mask for the `ct_len` field, unique per write because
/// it is bound to the fresh region nonce: `HMAC-SHA256(mask_key, nonce)[..8]`
/// with `mask_key = HKDF(MVK, header_salt, "lbx:metadata-len-mask/v1")`.
/// Without the MVK the masked field is indistinguishable from the random
/// padding around it.
fn len_mask(mvk: &MasterVolumeKey, header_salt: &[u8; 32], nonce: &[u8; NONCE_LEN]) -> [u8; 8] {
    use hmac::{Hmac, Mac};
    let key = mvk.derive_subkey(header_salt, METADATA_LEN_MASK_INFO);
    let mut mac =
        <Hmac<sha2::Sha256> as Mac>::new_from_slice(&key[..]).expect("HMAC accepts any key length");
    mac.update(nonce);
    let out = mac.finalize().into_bytes();
    let mut m = [0u8; 8];
    m.copy_from_slice(&out[..8]);
    m
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
    write_metadata_opts(suite, mvk, header_salt, plaintext, region, false)
}

/// `write_metadata` with the R15-D2 length-field masking switch
/// (`mask_len` = the vault header's `FLAG_MASKED_METADATA_LEN`).
pub fn write_metadata_opts(
    suite: CipherSuite,
    mvk: &MasterVolumeKey,
    header_salt: &[u8; 32],
    plaintext: &[u8],
    region: &mut [u8],
    mask_len: bool,
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

    let ct = aead::seal(suite, &key, &nonce, &aad, plaintext)?;
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
    fill_padding(region);
    region[..NONCE_LEN].copy_from_slice(&nonce);
    let stored_len = if mask_len {
        ct_len ^ u64::from_le_bytes(len_mask(mvk, header_salt, &nonce))
    } else {
        ct_len
    };
    region[NONCE_LEN..NONCE_LEN + LEN_FIELD_LEN].copy_from_slice(&stored_len.to_le_bytes());
    region[NONCE_LEN + LEN_FIELD_LEN..NONCE_LEN + LEN_FIELD_LEN + ct.len()].copy_from_slice(&ct);
    Ok(())
}

/// Fill `region` with random-looking padding for `write_metadata_opts`:
/// a ChaCha20 keystream under a fresh key from the OS RNG, rather than
/// OS RNG output directly. macOS caps getentropy(2) at 256 bytes a call,
/// so filling the 64 MiB default region took about 262k syscalls
/// (~250 ms) on every flush, and a FUSE-T mount flushes once per file
/// closed. A keystream under a single-use random key is
/// indistinguishable from uniform bytes, which is all the padding needs.
/// The zero IV is safe because the key is never reused, and the region
/// (at most `MAX_METADATA_SIZE`) is far below ChaCha20's 256 GiB limit.
fn fill_padding(region: &mut [u8]) {
    use chacha20::cipher::{KeyIvInit, StreamCipher};
    let mut key = Zeroizing::new([0u8; 32]);
    OsRng
        .try_fill_bytes(&mut key[..])
        .expect("OS RNG failure during metadata padding fill");
    region.fill(0);
    chacha20::ChaCha20::new(&(*key).into(), &[0u8; 12].into()).apply_keystream(region);
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
    read_metadata_opts(suite, mvk, header_salt, region, false)
}

/// `read_metadata` with the R15-D2 length-field masking switch.
pub fn read_metadata_opts(
    suite: CipherSuite,
    mvk: &MasterVolumeKey,
    header_salt: &[u8; 32],
    region: &[u8],
    mask_len: bool,
) -> Result<Zeroizing<Vec<u8>>, Error> {
    if region.len() < METADATA_OVERHEAD {
        return Err(Error::MetadataCorrupt);
    }
    let mut nonce = [0u8; NONCE_LEN];
    nonce.copy_from_slice(&region[..NONCE_LEN]);
    let stored_len = u64::from_le_bytes(
        region[NONCE_LEN..NONCE_LEN + LEN_FIELD_LEN]
            .try_into()
            .unwrap(),
    );
    let ct_len = if mask_len {
        stored_len ^ u64::from_le_bytes(len_mask(mvk, header_salt, &nonce))
    } else {
        stored_len
    };
    // Unmasked or not, `ct_len` is still unauthenticated input here; the
    // bounds checks below and the AAD binding keep it harmless.
    let ct_len = usize::try_from(ct_len).map_err(|_| Error::MetadataCorrupt)?;

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

    let pt = aead::open(suite, &key, &nonce, &aad, ct)?;
    Ok(Zeroizing::new(pt))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// R15-D2: with masking on, the on-disk length field must not be the
    /// plaintext `u64 LE` length (whose high bytes are zero), the region
    /// must round-trip, and a reader that does not apply the mask must
    /// fail cleanly.
    #[test]
    fn masked_length_field_is_not_plaintext_and_roundtrips() {
        let mvk = MasterVolumeKey::random();
        let salt = [0x5au8; 32];
        let pt = b"directory tree bytes";
        let mut region = vec![0u8; 4096];
        write_metadata_opts(
            CipherSuite::Aes256GcmSiv,
            &mvk,
            &salt,
            pt,
            &mut region,
            true,
        )
        .unwrap();
        let ct_len = (pt.len() + TAG_LEN) as u64;
        assert_ne!(
            &region[NONCE_LEN..NONCE_LEN + LEN_FIELD_LEN],
            &ct_len.to_le_bytes()[..],
            "masked field must differ from the plaintext length"
        );
        assert!(
            region[NONCE_LEN + 4..NONCE_LEN + 8].iter().any(|&b| b != 0),
            "masked high bytes must not be the tell-tale zeros"
        );
        let back =
            read_metadata_opts(CipherSuite::Aes256GcmSiv, &mvk, &salt, &region, true).unwrap();
        assert_eq!(&back[..], pt);
        assert!(
            read_metadata_opts(CipherSuite::Aes256GcmSiv, &mvk, &salt, &region, false).is_err()
        );
        // Unmasked writes stay byte-compatible with the legacy reader.
        let mut region2 = vec![0u8; 4096];
        write_metadata(CipherSuite::Aes256GcmSiv, &mvk, &salt, pt, &mut region2).unwrap();
        assert_eq!(
            &region2[NONCE_LEN..NONCE_LEN + LEN_FIELD_LEN],
            &ct_len.to_le_bytes()[..]
        );
        assert_eq!(
            &read_metadata(CipherSuite::Aes256GcmSiv, &mvk, &salt, &region2).unwrap()[..],
            pt
        );
    }

    #[test]
    fn oversize_create_override_is_clamped_to_max() {
        // A caller-supplied override above the on-disk cap must be
        // clamped so the created vault stays reopenable (Header::from_bytes
        // rejects metadata_size > MAX_METADATA_SIZE at open) and the
        // metadata_offset + region_size math cannot overflow. Security
        // audit follow-up.
        let _g = set_create_metadata_region_size_override(Some(
            luksbox_core::header::MAX_METADATA_SIZE + 100 * 1024 * 1024,
        ));
        assert_eq!(
            resolved_create_metadata_region_size(),
            luksbox_core::header::MAX_METADATA_SIZE,
            "override above MAX_METADATA_SIZE must clamp to the cap"
        );
    }

    #[test]
    fn in_range_create_override_passes_through() {
        // The common case (small demo vault) is untouched by the clamp.
        let want = 8 * 1024 * 1024;
        let _g = set_create_metadata_region_size_override(Some(want));
        assert_eq!(resolved_create_metadata_region_size(), want);
    }

    #[test]
    fn default_create_metadata_size_is_unclamped() {
        // No override: the 64 MiB default equals the cap, so it passes
        // through unchanged (regression guard against clamping below the
        // default and breaking every new vault).
        assert_eq!(
            resolved_create_metadata_region_size(),
            DEFAULT_METADATA_REGION_SIZE
        );
        assert!(DEFAULT_METADATA_REGION_SIZE <= luksbox_core::header::MAX_METADATA_SIZE);
    }

    #[test]
    fn metadata_roundtrip_empty() {
        let mvk = MasterVolumeKey::from_bytes([0x11; 32]);
        let salt = [0x22u8; 32];
        let mut region = vec![0u8; DEFAULT_METADATA_REGION_SIZE as usize];
        write_metadata(CipherSuite::Aes256Gcm, &mvk, &salt, b"", &mut region).unwrap();
        let pt = read_metadata(CipherSuite::Aes256Gcm, &mvk, &salt, &region).unwrap();
        assert_eq!(&**pt, b"");
    }

    /// The padding after the blob looks uniform (every byte value about
    /// equally common) and is fresh on every write, so two snapshots of
    /// the region differ throughout, not just where the blob is.
    #[test]
    fn metadata_padding_is_uniform_and_fresh_per_write() {
        let mvk = MasterVolumeKey::from_bytes([0x55; 32]);
        let salt = [0x66u8; 32];
        let pt = b"same blob both times";
        let pad_start = METADATA_OVERHEAD + pt.len();
        let mut a = vec![0u8; 1 << 20];
        let mut b = vec![0u8; 1 << 20];
        write_metadata(CipherSuite::Aes256GcmSiv, &mvk, &salt, pt, &mut a).unwrap();
        write_metadata(CipherSuite::Aes256GcmSiv, &mvk, &salt, pt, &mut b).unwrap();
        let mut counts = [0u64; 256];
        for &x in &a[pad_start..] {
            counts[x as usize] += 1;
        }
        let expected = (a.len() - pad_start) as f64 / 256.0;
        let chi2: f64 = counts
            .iter()
            .map(|&c| (c as f64 - expected).powi(2) / expected)
            .sum();
        // 255 degrees of freedom: mean 255, and 400 is far past p = 1e-6.
        assert!(
            chi2 < 400.0,
            "padding byte histogram is skewed: chi2 = {chi2}"
        );
        let same = a[pad_start..]
            .iter()
            .zip(&b[pad_start..])
            .filter(|(x, y)| x == y)
            .count();
        // Independent uniform bytes match 1 time in 256.
        assert!(
            same < (a.len() - pad_start) / 128,
            "padding repeats across writes"
        );
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
