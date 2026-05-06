// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Penthertz <https://penthertz.com> (https://x.com/PentHertz)

use rand_core::{OsRng, RngCore};
use zeroize::Zeroizing;

use luksbox_core::{CipherSuite, MasterVolumeKey, SubKey, aead};

use crate::error::Error;

/// Default metadata region size: 1 MiB. Holds the encrypted directory tree and
/// any small global metadata. Re-encrypted on every write.
pub const DEFAULT_METADATA_REGION_SIZE: u64 = 1024 * 1024;

/// Per-blob fixed overhead on disk: 12 B nonce + 8 B ciphertext-length + 16 B tag.
pub const METADATA_OVERHEAD: usize = 12 + 8 + 16;

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
