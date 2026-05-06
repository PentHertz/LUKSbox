// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Penthertz <https://penthertz.com> (https://x.com/PentHertz)

use luksbox_core::{SubKey, aead};
use luksbox_format::Container;
use rand_core::{OsRng, RngCore};
use zeroize::Zeroizing;

use crate::error::Error;
use crate::tree::ChunkRef;

/// Plaintext bytes per chunk. Every on-disk chunk slot stores exactly this many
/// plaintext bytes (zero-padded as needed); logical file size in the inode
/// bounds reads/writes.
pub const CHUNK_PLAINTEXT_SIZE: usize = 4096;

pub const CHUNK_NONCE_LEN: usize = 12;
pub const CHUNK_TAG_LEN: usize = 16;

/// Bytes occupied by one chunk on disk: nonce ‖ ciphertext ‖ tag.
pub const CHUNK_SLOT_SIZE: u64 = (CHUNK_NONCE_LEN + CHUNK_PLAINTEXT_SIZE + CHUNK_TAG_LEN) as u64;

pub const FILE_KEY_INFO_PREFIX: &[u8] = b"lbx:file/v1:";

#[inline]
pub fn slot_offset(data_offset: u64, chunk_id: u64) -> Result<u64, Error> {
    let relative = chunk_id
        .checked_mul(CHUNK_SLOT_SIZE)
        .ok_or(Error::OffsetOverflow)?;
    data_offset
        .checked_add(relative)
        .ok_or(Error::OffsetOverflow)
}

/// AAD = `file_id_le ‖ chunk_idx_le`. Binds a chunk to its file and to its
/// position in that file, moving a chunk between files or positions fails the
/// AEAD tag.
fn chunk_aad(file_id: u64, chunk_idx: u32, generation: u64) -> [u8; 20] {
    let mut aad = [0u8; 20];
    aad[..8].copy_from_slice(&file_id.to_le_bytes());
    aad[8..12].copy_from_slice(&chunk_idx.to_le_bytes());
    aad[12..].copy_from_slice(&generation.to_le_bytes());
    aad
}

/// Read and decrypt one chunk slot. Returns a `Zeroizing<Vec<u8>>` of
/// 4096 plaintext bytes; cleared on drop so file content doesn't linger
/// in freed allocations. AAD includes the chunk's generation counter,
/// which must match what was used at write time (replay protection).
pub fn read_chunk(
    container: &mut Container,
    file_key: &SubKey,
    file_id: u64,
    chunk_idx: u32,
    chunk: ChunkRef,
) -> Result<Zeroizing<Vec<u8>>, Error> {
    let suite = container.cipher_suite();
    let off = slot_offset(container.data_offset(), chunk.id)?;

    let mut buf = vec![0u8; CHUNK_NONCE_LEN + CHUNK_PLAINTEXT_SIZE + CHUNK_TAG_LEN];
    container.read_at(off, &mut buf)?;

    let mut nonce = [0u8; CHUNK_NONCE_LEN];
    nonce.copy_from_slice(&buf[..CHUNK_NONCE_LEN]);
    let ct = &buf[CHUNK_NONCE_LEN..];

    let aad = chunk_aad(file_id, chunk_idx, chunk.generation);
    let pt = aead::open(suite, &**file_key, &nonce, &aad, ct)?;
    Ok(Zeroizing::new(pt))
}

/// Encrypt and write one chunk slot. `plaintext` must be exactly
/// `CHUNK_PLAINTEXT_SIZE` bytes (the caller zero-pads short tails).
/// `chunk.generation` must be a fresh monotonic value from
/// `DirectoryTree::alloc_chunk_gen()`, caller responsibility.
pub fn write_chunk(
    container: &mut Container,
    file_key: &SubKey,
    file_id: u64,
    chunk_idx: u32,
    chunk: ChunkRef,
    plaintext: &[u8],
) -> Result<(), Error> {
    assert_eq!(plaintext.len(), CHUNK_PLAINTEXT_SIZE);
    let suite = container.cipher_suite();
    let off = slot_offset(container.data_offset(), chunk.id)?;

    let mut nonce = [0u8; CHUNK_NONCE_LEN];
    OsRng
        .try_fill_bytes(&mut nonce)
        .map_err(|e| Error::Crypto(luksbox_core::Error::OsRng(e.to_string())))?;

    let aad = chunk_aad(file_id, chunk_idx, chunk.generation);
    let ct = aead::seal(suite, &**file_key, &nonce, &aad, plaintext)?;
    debug_assert_eq!(ct.len(), CHUNK_PLAINTEXT_SIZE + CHUNK_TAG_LEN);

    let mut on_disk = Vec::with_capacity(CHUNK_NONCE_LEN + ct.len());
    on_disk.extend_from_slice(&nonce);
    on_disk.extend_from_slice(&ct);
    container.write_at(off, &on_disk)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn slot_offset_rejects_multiply_overflow() {
        assert!(matches!(
            slot_offset(0, u64::MAX),
            Err(Error::OffsetOverflow)
        ));
    }

    #[test]
    fn slot_offset_rejects_add_overflow() {
        assert!(matches!(
            slot_offset(u64::MAX - 10, 1),
            Err(Error::OffsetOverflow)
        ));
    }
}

pub fn file_key(container: &Container, file_id: u64) -> SubKey {
    let mut info = Vec::with_capacity(FILE_KEY_INFO_PREFIX.len() + 8);
    info.extend_from_slice(FILE_KEY_INFO_PREFIX);
    info.extend_from_slice(&file_id.to_le_bytes());
    container.derive_subkey(&info)
}

/// Derive `file_key` from an explicit MVK rather than the Container's
/// current MVK. Used by MVK rotation, which needs to derive both
/// old- and new-MVK file_keys to re-encrypt every chunk.
pub fn file_key_for_mvk(
    mvk: &luksbox_core::MasterVolumeKey,
    header_salt: &[u8; 32],
    file_id: u64,
) -> SubKey {
    let mut info = Vec::with_capacity(FILE_KEY_INFO_PREFIX.len() + 8);
    info.extend_from_slice(FILE_KEY_INFO_PREFIX);
    info.extend_from_slice(&file_id.to_le_bytes());
    mvk.derive_subkey(header_salt, &info)
}
