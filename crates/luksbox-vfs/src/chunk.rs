// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Penthertz <https://penthertz.com> (https://x.com/PentHertz)

use luksbox_core::{SubKey, aead};
use luksbox_format::Container;
use rand_core::{OsRng, RngCore};
use zeroize::Zeroizing;

use crate::error::Error;
use crate::tree::{CHUNK_LIST_FILE_ID_BIT, ChunkRef};

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

// ----------------------------------------------------------------------
// V3 metadata format: external chunk-list blocks
// ----------------------------------------------------------------------
//
// In v3, files whose chunk count exceeds `V3_INLINE_CHUNK_THRESHOLD`
// spill their chunk list out of the metadata region into a linked
// chain of encrypted 4 KiB blocks in the data area. Each block holds
// up to `CHUNK_LIST_ENTRIES_PER_BLOCK` ChunkRefs of data chunks for
// the owning file, plus a single "next" ChunkRef that points to the
// follow-on block (or zero if last). Blocks are encrypted with the
// SAME chunk-AEAD machinery as data chunks but under a SYNTHETIC
// file_id derived by setting the high bit of the real file_id --
// so the AEAD AAD intrinsically distinguishes "chunk-list block for
// file F" from "data chunk for file F" without any AAD-shape change.
//
// Plaintext layout (4096 bytes total):
//   [ 0..  4]  u32 LE  count of valid ChunkRef entries in this block
//   [ 4..  N]  count * 16 bytes:  count x ChunkRef (8 B id, 8 B gen)
//   [ N..N+16] next ChunkRef (zero if last block; non-zero points at
//              the next block in the chain -- chunk-list blocks are
//              themselves chunks, so a ChunkRef into the same data area)
//   [N+16..4096]  random padding
//
// Random padding is mandatory: without it the block's ciphertext
// would have a very predictable length-of-zeros tail revealing how
// few entries are in the block. Same indistinguishability argument
// as the metadata-region padding.

/// Maximum data ChunkRefs we pack into a single 4 KiB chunk-list
/// block. (4096 - 4 - 16) / 16 = 254 with one byte of slack.
pub const CHUNK_LIST_ENTRIES_PER_BLOCK: usize = 254;

const CHUNK_LIST_COUNT_OFFSET: usize = 0;
const CHUNK_LIST_ENTRIES_OFFSET: usize = 4;
const CHUNK_LIST_NEXT_OFFSET: usize = CHUNK_LIST_ENTRIES_OFFSET + CHUNK_LIST_ENTRIES_PER_BLOCK * 16;
const _: () = assert!(CHUNK_LIST_NEXT_OFFSET + 16 <= CHUNK_PLAINTEXT_SIZE);

/// Synthetic file_id used for the chunk-list-block chain of a file
/// with id `file_id`. Sets the high bit so the AEAD AAD that
/// `read_chunk` / `write_chunk` builds is distinct from any AAD
/// for a real file. Real file_ids are allocated sequentially from
/// `ROOT_ID + 1` and never approach 2⁶³, so the reserved range is
/// always free.
#[inline]
pub fn list_file_id(file_id: u64) -> u64 {
    debug_assert!(
        file_id & CHUNK_LIST_FILE_ID_BIT == 0,
        "file_id already in the reserved chunk-list range: {file_id:#x}"
    );
    file_id | CHUNK_LIST_FILE_ID_BIT
}

/// Derive the per-file key used to encrypt chunk-list blocks for
/// `file_id`. Distinct from `file_key(file_id)` because the info
/// label includes `file_id | (1<<63)`. An attacker who recovers a
/// chunk-list block cannot present it as a data chunk for the same
/// file (different AEAD key + different AAD).
pub fn list_file_key(container: &Container, file_id: u64) -> SubKey {
    file_key(container, list_file_id(file_id))
}

/// Encode a ChunkRef into 16 bytes: u64 LE id ‖ u64 LE generation.
/// Used by chunk-list block (de)serialisation. Zero (id=0, gen=0)
/// is the canonical "no entry" / "end of chain" sentinel -- chunk_id
/// 0 is reserved (the first real chunk id is 0 too, BUT chunk_id
/// allocation in `DirectoryTree::alloc_chunk_id` returns
/// `next_chunk_id` starting at 0, so a freshly-allocated chunk-list
/// block could legitimately hold ChunkRef { id: 0, generation: G }.
/// To disambiguate, we use BOTH zeros (generation=0 is illegitimate
/// since `alloc_chunk_gen` starts at 1) as the sentinel).
#[inline]
fn encode_chunk_ref(cr: ChunkRef) -> [u8; 16] {
    let mut out = [0u8; 16];
    out[..8].copy_from_slice(&cr.id.to_le_bytes());
    out[8..].copy_from_slice(&cr.generation.to_le_bytes());
    out
}

#[inline]
fn decode_chunk_ref(b: &[u8]) -> ChunkRef {
    debug_assert_eq!(b.len(), 16);
    ChunkRef {
        id: u64::from_le_bytes(b[..8].try_into().unwrap()),
        generation: u64::from_le_bytes(b[8..16].try_into().unwrap()),
    }
}

/// Encoded chunk-list block: serialised to a 4 KiB plaintext buffer
/// ready to hand to `write_chunk`. The caller supplies the next-block
/// ChunkRef (zero if last); fills random padding into the trailing
/// bytes so the encrypted block's length isn't a fingerprint for the
/// number of entries.
pub fn encode_chunk_list_block(
    entries: &[ChunkRef],
    next: Option<ChunkRef>,
) -> Result<[u8; CHUNK_PLAINTEXT_SIZE], Error> {
    if entries.len() > CHUNK_LIST_ENTRIES_PER_BLOCK {
        return Err(Error::Crypto(luksbox_core::Error::InvalidField));
    }
    let mut buf = [0u8; CHUNK_PLAINTEXT_SIZE];
    // Random padding for the whole buffer first; we then overwrite
    // the structured prefix and the next-pointer. Random padding is
    // unauthenticated (AEAD only authenticates the encrypted payload
    // as a whole, but every byte IS inside the ciphertext) and serves
    // ONLY the indistinguishability goal: tail bytes look like ct.
    OsRng
        .try_fill_bytes(&mut buf)
        .map_err(|e| Error::Crypto(luksbox_core::Error::OsRng(e.to_string())))?;
    let count = entries.len() as u32;
    buf[CHUNK_LIST_COUNT_OFFSET..CHUNK_LIST_COUNT_OFFSET + 4].copy_from_slice(&count.to_le_bytes());
    for (i, cr) in entries.iter().enumerate() {
        let start = CHUNK_LIST_ENTRIES_OFFSET + i * 16;
        buf[start..start + 16].copy_from_slice(&encode_chunk_ref(*cr));
    }
    let next_bytes = match next {
        Some(cr) => encode_chunk_ref(cr),
        None => [0u8; 16],
    };
    buf[CHUNK_LIST_NEXT_OFFSET..CHUNK_LIST_NEXT_OFFSET + 16].copy_from_slice(&next_bytes);
    Ok(buf)
}

/// Parse a chunk-list block from its 4 KiB plaintext. Returns
/// `(entries, next_block_or_none)`. The `count` field at offset 0
/// is range-checked against `CHUNK_LIST_ENTRIES_PER_BLOCK` so a
/// crafted or corrupt block can't drive a huge allocation.
pub fn parse_chunk_list_block(
    plaintext: &[u8],
) -> Result<(Vec<ChunkRef>, Option<ChunkRef>), Error> {
    if plaintext.len() != CHUNK_PLAINTEXT_SIZE {
        return Err(Error::Crypto(luksbox_core::Error::InvalidField));
    }
    let count = u32::from_le_bytes(
        plaintext[CHUNK_LIST_COUNT_OFFSET..CHUNK_LIST_COUNT_OFFSET + 4]
            .try_into()
            .unwrap(),
    ) as usize;
    if count > CHUNK_LIST_ENTRIES_PER_BLOCK {
        return Err(Error::Crypto(luksbox_core::Error::InvalidField));
    }
    let mut entries = Vec::with_capacity(count);
    for i in 0..count {
        let start = CHUNK_LIST_ENTRIES_OFFSET + i * 16;
        entries.push(decode_chunk_ref(&plaintext[start..start + 16]));
    }
    let next_ref =
        decode_chunk_ref(&plaintext[CHUNK_LIST_NEXT_OFFSET..CHUNK_LIST_NEXT_OFFSET + 16]);
    // Sentinel: generation=0 means "no next block". Generation
    // values are allocated starting at 1 by `alloc_chunk_gen`, so
    // 0 cannot legitimately appear in a real ChunkRef.
    let next = if next_ref.generation == 0 {
        None
    } else {
        Some(next_ref)
    };
    Ok((entries, next))
}

/// Walk a chunk-list-block chain for `file_id`, decrypting each
/// block in turn and concatenating the contained ChunkRefs into a
/// single Vec. Also returns the ChunkRefs of the *list-blocks
/// themselves* (so the caller can free them on next flush / unlink).
///
/// `expected_count` is the total data-chunk count the inode claims
/// to have; the walk refuses to allocate more than this in the
/// returned Vec, so a forged chain with a bogus length field can't
/// drive an unbounded allocation. A walk that recovers more entries
/// than `expected_count`, or hits more than `max_blocks` chunk-list
/// blocks before finishing, is rejected as corrupt.
///
/// `max_blocks = ceil(expected_count / CHUNK_LIST_ENTRIES_PER_BLOCK) + 2`
/// allows slack for an empty trailing block but caps DoS.
///
/// **Hard ceiling**: `expected_count` is capped at
/// `MAX_FILE_SIZE / CHUNK_PLAINTEXT_SIZE` (the largest chunk count
/// any honest writer could produce -- per-file size cap is enforced
/// at write/truncate time). A blob claiming a count past that limit
/// can only come from a forged metadata (requires MVK) or on-disk
/// corruption (cosmic ray / bad block). In either case the right
/// behaviour is to fail fast with `InvalidField` instead of letting
/// the loop run for ~7x10¹⁶ iterations under a `u64::MAX` claim.
pub fn walk_chunk_list_chain(
    container: &mut Container,
    file_id: u64,
    head: ChunkRef,
    expected_count: u64,
) -> Result<(Vec<ChunkRef>, Vec<ChunkRef>), Error> {
    // Hard ceiling on expected_count. Mirrors the per-file size cap
    // enforced by Vfs::write / Vfs::truncate: MAX_FILE_SIZE = 1<<44,
    // CHUNK_PLAINTEXT_SIZE = 4096, so max legitimate chunk count is
    // 1<<32. Reject anything beyond it as structurally invalid
    // BEFORE entering the loop so a forged or corrupted metadata
    // blob can't drive an unbounded walk.
    const MAX_LEGITIMATE_CHUNK_COUNT: u64 = (1u64 << 44) / 4096; // = 1 << 32
    if expected_count > MAX_LEGITIMATE_CHUNK_COUNT {
        return Err(Error::Crypto(luksbox_core::Error::InvalidField));
    }
    let list_key = list_file_key(container, file_id);
    let synth_id = list_file_id(file_id);
    let max_entries = expected_count as usize;
    let max_blocks = max_entries
        .div_ceil(CHUNK_LIST_ENTRIES_PER_BLOCK)
        .saturating_add(2);
    let mut entries: Vec<ChunkRef> = Vec::with_capacity(max_entries.min(1 << 16));
    let mut list_blocks: Vec<ChunkRef> = Vec::new();
    let mut current = Some(head);
    let mut block_idx: u32 = 0;
    while let Some(cref) = current {
        if list_blocks.len() >= max_blocks {
            return Err(Error::Crypto(luksbox_core::Error::InvalidField));
        }
        list_blocks.push(cref);
        let pt = read_chunk(container, &list_key, synth_id, block_idx, cref)?;
        let (mut block_entries, next) = parse_chunk_list_block(&pt)?;
        if entries.len() + block_entries.len() > max_entries.max(1) {
            return Err(Error::Crypto(luksbox_core::Error::InvalidField));
        }
        entries.append(&mut block_entries);
        current = next;
        block_idx = block_idx.checked_add(1).ok_or(Error::OffsetOverflow)?;
    }
    if entries.len() as u64 != expected_count {
        // The on-disk count and the walked count disagree. Refuse
        // rather than mount a half-walked file.
        return Err(Error::Crypto(luksbox_core::Error::InvalidField));
    }
    Ok((entries, list_blocks))
}

/// Encrypt and write a chunk-list block at the given `chunk` slot
/// (caller has already allocated the slot via `DirectoryTree::
/// alloc_chunk_id` + fresh generation). The block is encrypted under
/// the file's chunk-list key with chunk_idx = `block_idx` in the
/// chunk-list-block AAD, so the AEAD binds the block to its position
/// in the chain.
pub fn write_chunk_list_block(
    container: &mut Container,
    file_id: u64,
    block_idx: u32,
    chunk: ChunkRef,
    entries: &[ChunkRef],
    next: Option<ChunkRef>,
) -> Result<(), Error> {
    let plaintext = encode_chunk_list_block(entries, next)?;
    let list_key = list_file_key(container, file_id);
    let synth_id = list_file_id(file_id);
    write_chunk(container, &list_key, synth_id, block_idx, chunk, &plaintext)
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

/// Same as `file_key_for_mvk` but for the synthetic file_id that
/// names a file's chunk-list-block chain (v3 metadata format). MVK
/// rotation derives both the old and new list-file-keys via this
/// helper to re-encrypt each chunk-list block under the new MVK
/// alongside the data chunks. Without this, post-rotation reads
/// would silently fail to decrypt the chunk-list chain -- losing the
/// file's chunk pointers permanently.
pub fn list_file_key_for_mvk(
    mvk: &luksbox_core::MasterVolumeKey,
    header_salt: &[u8; 32],
    file_id: u64,
) -> SubKey {
    file_key_for_mvk(mvk, header_salt, list_file_id(file_id))
}
