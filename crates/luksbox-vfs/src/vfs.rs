// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Penthertz <https://penthertz.com> (https://x.com/PentHertz)

use std::collections::BTreeSet;

use luksbox_format::Container;

use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use crate::chunk::{self, CHUNK_PLAINTEXT_SIZE};
use crate::error::Error;
use crate::tree::{
    ChunkId, ChunkRef, DirectoryTree, FileId, Inode, InodeKind, ROOT_ID,
    V3_INLINE_CHUNK_THRESHOLD,
};

/// Credentials for one keyslot during MVK rotation. Caller (typically the
/// CLI) collects one of these per populated slot before calling
/// `Vfs::rotate_mvk`.
///
/// For FIDO2 wrap-style slots, two distinct hmac-secret outputs are needed:
/// one to verify the OLD slot (computed against `slot.fido2_hmac_salt`),
/// and one to wrap the NEW slot (computed against a fresh `new_hmac_salt`
/// the caller generates). Each requires a YubiKey touch.
pub enum SlotCredential {
    Passphrase {
        slot_idx: usize,
        passphrase: Zeroizing<String>,
    },
    Fido2Wrap {
        slot_idx: usize,
        /// Optional passphrase mixed into the FIDO2 KEK derivation (matches
        /// the original keyslot's `passphrase` argument at enroll time).
        passphrase: Option<Zeroizing<String>>,
        /// Authenticator output for `slot.fido2_hmac_salt` (the old salt).
        /// Used to re-derive the OLD KEK and verify the slot.
        hmac_secret_for_verify: Zeroizing<[u8; 32]>,
        /// Authenticator output for `new_hmac_salt`. Used to derive the
        /// NEW KEK that wraps the new MVK.
        hmac_secret_for_new_wrap: Zeroizing<[u8; 32]>,
        cred_id: Vec<u8>,
        new_hmac_salt: [u8; 32],
    },
}

impl SlotCredential {
    pub fn slot_idx(&self) -> usize {
        match self {
            Self::Passphrase { slot_idx, .. } => *slot_idx,
            Self::Fido2Wrap { slot_idx, .. } => *slot_idx,
        }
    }
}

/// Borrow-shaped DeniableCredential builder for the rotation path.
/// Returns the borrowed credential, owning slot_idx + DeniableMaterial
/// borrow. Validates that the kind tag matches the present
/// Option-typed secondary factors so a mis-built rotation credential
/// fails fast at the Vfs boundary with a typed Error::Format error
/// instead of propagating a None-unwrap from inside the AEAD path.
fn build_borrowed_deniable_credential(
    c: &DeniableRotationCredential,
) -> Result<
    (
        usize,
        luksbox_core::deniable::DeniableCredential<'_>,
        &luksbox_format::deniable_header::DeniableMaterial,
    ),
    Error,
> {
    use luksbox_core::deniable::{DeniableCredential as DC, DeniableKindTag as K};
    let pp = c.passphrase.as_slice();
    let arg = c.argon2;
    let bad_kind = || {
        Error::Format(luksbox_format::Error::Crypto(
            luksbox_core::Error::InvalidField,
        ))
    };
    let cred = match c.kind {
        K::Passphrase => {
            if c.hmac_secret_output.is_some() || c.unsealed.is_some() || c.mlkem_shared.is_some() {
                return Err(bad_kind());
            }
            DC::Passphrase {
                passphrase: pp,
                argon2: arg,
            }
        }
        K::Fido2Passphrase => {
            let hs = c.hmac_secret_output.as_ref().ok_or_else(bad_kind)?;
            if c.unsealed.is_some() || c.mlkem_shared.is_some() {
                return Err(bad_kind());
            }
            DC::Fido2Passphrase {
                passphrase: pp,
                argon2: arg,
                hmac_secret_output: &**hs,
            }
        }
        K::TpmPassphrase => {
            let u = c.unsealed.as_ref().ok_or_else(bad_kind)?;
            if c.hmac_secret_output.is_some() || c.mlkem_shared.is_some() {
                return Err(bad_kind());
            }
            DC::TpmPassphrase {
                passphrase: pp,
                argon2: arg,
                unsealed: &**u,
            }
        }
        K::TpmFido2Passphrase => {
            let u = c.unsealed.as_ref().ok_or_else(bad_kind)?;
            let hs = c.hmac_secret_output.as_ref().ok_or_else(bad_kind)?;
            if c.mlkem_shared.is_some() {
                return Err(bad_kind());
            }
            DC::TpmFido2Passphrase {
                passphrase: pp,
                argon2: arg,
                unsealed: &**u,
                hmac_secret_output: &**hs,
            }
        }
        K::HybridPqPassphrase => {
            let m = c.mlkem_shared.as_ref().ok_or_else(bad_kind)?;
            if c.hmac_secret_output.is_some() || c.unsealed.is_some() {
                return Err(bad_kind());
            }
            DC::HybridPqPassphrase {
                passphrase: pp,
                argon2: arg,
                mlkem_shared: &**m,
            }
        }
        K::HybridPqFido2Passphrase => {
            let m = c.mlkem_shared.as_ref().ok_or_else(bad_kind)?;
            let hs = c.hmac_secret_output.as_ref().ok_or_else(bad_kind)?;
            if c.unsealed.is_some() {
                return Err(bad_kind());
            }
            DC::HybridPqFido2Passphrase {
                passphrase: pp,
                argon2: arg,
                mlkem_shared: &**m,
                hmac_secret_output: &**hs,
            }
        }
        K::HybridPqTpmPassphrase => {
            let m = c.mlkem_shared.as_ref().ok_or_else(bad_kind)?;
            let u = c.unsealed.as_ref().ok_or_else(bad_kind)?;
            if c.hmac_secret_output.is_some() {
                return Err(bad_kind());
            }
            DC::HybridPqTpmPassphrase {
                passphrase: pp,
                argon2: arg,
                mlkem_shared: &**m,
                unsealed: &**u,
            }
        }
        K::HybridPqTpmFido2Passphrase => {
            let m = c.mlkem_shared.as_ref().ok_or_else(bad_kind)?;
            let u = c.unsealed.as_ref().ok_or_else(bad_kind)?;
            let hs = c.hmac_secret_output.as_ref().ok_or_else(bad_kind)?;
            DC::HybridPqTpmFido2Passphrase {
                passphrase: pp,
                argon2: arg,
                mlkem_shared: &**m,
                unsealed: &**u,
                hmac_secret_output: &**hs,
            }
        }
    };
    Ok((c.slot_idx, cred, &c.material))
}

/// One credential entry for `Vfs::rotate_mvk_deniable`. Owned-bytes
/// shape (`Zeroizing<Vec<u8>>` / `Zeroizing<[u8; 32]>`) avoids
/// lifetime gymnastics in the credentials vector while keeping every
/// secret wiped on drop.
///
/// Covers all 8 `DeniableCredential` kinds via the `kind` tag + the
/// matching set of `Option`-typed secondary-factor fields:
///
/// | Kind                       | Required factor fields                    |
/// |----------------------------|-------------------------------------------|
/// | Passphrase                 | (none)                                    |
/// | Fido2Passphrase            | hmac_secret_output                        |
/// | TpmPassphrase              | unsealed                                  |
/// | TpmFido2Passphrase         | unsealed, hmac_secret_output              |
/// | HybridPqPassphrase         | mlkem_shared                              |
/// | HybridPqFido2Passphrase    | mlkem_shared, hmac_secret_output          |
/// | HybridPqTpmPassphrase      | mlkem_shared, unsealed                    |
/// | HybridPqTpmFido2Passphrase | mlkem_shared, unsealed, hmac_secret_output|
///
/// Caller is responsible for re-running the secondary factors before
/// constructing this credential: FIDO2 assertion against the same
/// `(cred_id, hmac_salt)` baked into `material`, TPM unseal of the
/// `tpm_blob` in `material`, ML-KEM decap of the public ciphertext
/// stored in the user's `.kyber` sidecar. The rotation will validate
/// that the supplied factors actually unlock the current envelope
/// (anti-typo check) before re-wrapping under the new MVK.
pub struct DeniableRotationCredential {
    pub slot_idx: usize,
    pub kind: luksbox_core::deniable::DeniableKindTag,
    pub passphrase: Zeroizing<Vec<u8>>,
    pub argon2: luksbox_core::Argon2idParams,
    pub material: luksbox_format::deniable_header::DeniableMaterial,
    /// FIDO2 hmac-secret response (32 B from the authenticator).
    /// Required for `*Fido2Passphrase` kinds; must be `None` for others.
    pub hmac_secret_output: Option<Zeroizing<[u8; 32]>>,
    /// TPM2 unsealed bytes (32 B from `TPM2_Unseal(tpm_blob)`).
    /// Required for `Tpm*Passphrase` kinds; must be `None` for others.
    pub unsealed: Option<Zeroizing<[u8; 32]>>,
    /// ML-KEM decap shared secret (32 B). Required for
    /// `HybridPq*Passphrase` kinds; must be `None` for others.
    pub mlkem_shared: Option<Zeroizing<[u8; 32]>>,
}

/// Compute the on-disk chunk count for a logical chunk requirement,
/// honoring the vault's `pad_files_pow2` mode.
///
/// Without padding: `needed` (1:1).
/// With padding:    next power of 2 ≥ `needed` (so 1->1, 2->2, 3->4, 5->8, ...).
///
/// 0 stays 0 (an empty file still uses 0 chunks regardless of mode).
fn padded_chunk_count(needed: usize, padding_on: bool) -> usize {
    if !padding_on || needed <= 1 {
        needed
    } else {
        needed.next_power_of_two()
    }
}

/// 8 bytes at the start of chunk 0's plaintext when `FLAG_HIDE_SIZE_HEADER`
/// is set: u64 LE of the file's real byte length.
const SIZE_HEADER_LEN: usize = 8;

/// Round 13 fix R13-07: hard per-file logical-size cap. Picked at 2^44
/// (16 TiB) — three orders of magnitude beyond the largest real-world
/// vault payload we've heard of, but small enough that
/// `padded_chunk_count` (which calls `next_power_of_two`) cannot
/// overflow on a 64-bit `usize` and the chunk-allocation loops in
/// `write`/`truncate` cannot exhaust RAM before returning.
///
/// Without this cap, an attacker (or a buggy caller) supplying
/// `offset + buf.len()` close to `u64::MAX` would reach
/// `required_chunks` and `padded_chunk_count` with a value whose
/// next-power-of-two is `usize::MAX/2 + 1`, then either panic
/// (next_power_of_two debug-assert) or commit gigabytes of zero-filled
/// chunk allocations before the host runs out of space.
///
/// The CLI/FUSE/WinFsp surfaces never legitimately produce sizes
/// anywhere near this cap; legitimate workloads bottom out at TiB-class
/// payloads which fit comfortably. Callers exceeding the cap receive
/// `Error::FileSizeExceedsCap` instead of a panic / OOM.
pub const MAX_FILE_SIZE: u64 = 1u64 << 44;

/// Number of chunks needed to hold a file of `real_size` bytes, accounting
/// for the chunk-0 size-header in `hide_size` mode.
///
/// Returns `usize::MAX` if the (already-bounded) addition somehow
/// overflows; callers above (`read`/`write`) reject offset overflow
/// before reaching this helper, so this saturating fallback is purely
/// defense-in-depth.
fn required_chunks(real_size: u64, hide_size: bool) -> usize {
    if real_size == 0 {
        return 0;
    }
    let with_header = if hide_size {
        real_size.saturating_add(SIZE_HEADER_LEN as u64)
    } else {
        real_size
    };
    ((with_header - 1) / CHUNK_PLAINTEXT_SIZE as u64 + 1) as usize
}

/// Translate a file-relative byte offset to `(chunk_idx, in_chunk_offset)`.
/// In `hide_size` mode, file byte 0 lives at chunk 0 byte 8.
fn file_to_chunk(offset: u64, hide_size: bool) -> Result<(usize, usize), Error> {
    let total = if hide_size {
        offset
            .checked_add(SIZE_HEADER_LEN as u64)
            .ok_or(Error::OffsetOverflow)?
    } else {
        offset
    };
    let chunk_idx = (total / CHUNK_PLAINTEXT_SIZE as u64) as usize;
    let in_chunk = (total % CHUNK_PLAINTEXT_SIZE as u64) as usize;
    Ok((chunk_idx, in_chunk))
}

/// File-byte range (start..end) that a given chunk holds, accounting for
/// the chunk-0 header in hide-size mode.
fn chunk_file_range(chunk_idx: usize, hide_size: bool) -> Result<(u64, u64), Error> {
    let chunk_size = CHUNK_PLAINTEXT_SIZE as u64;
    if hide_size && chunk_idx == 0 {
        // Chunk 0: file bytes 0..(4096-8) = 0..4088
        Ok((0, chunk_size - SIZE_HEADER_LEN as u64))
    } else if hide_size {
        // Chunk i>0: file bytes (4088 + (i-1)*4096) .. (4088 + i*4096)
        let start = (chunk_size - SIZE_HEADER_LEN as u64)
            .checked_add(
                (chunk_idx as u64)
                    .checked_sub(1)
                    .and_then(|i| i.checked_mul(chunk_size))
                    .ok_or(Error::OffsetOverflow)?,
            )
            .ok_or(Error::OffsetOverflow)?;
        let end = start.checked_add(chunk_size).ok_or(Error::OffsetOverflow)?;
        Ok((start, end))
    } else {
        // Normal mode: chunk i covers file bytes [i*4096, (i+1)*4096)
        let start = (chunk_idx as u64)
            .checked_mul(chunk_size)
            .ok_or(Error::OffsetOverflow)?;
        let end = start.checked_add(chunk_size).ok_or(Error::OffsetOverflow)?;
        Ok((start, end))
    }
}

/// Write the 8-byte u64 LE size header at the start of a chunk-0 plaintext
/// buffer.
fn install_size_header(buf: &mut [u8], size: u64) {
    buf[..SIZE_HEADER_LEN].copy_from_slice(&size.to_le_bytes());
}

#[derive(Debug, Clone)]
pub struct Stat {
    pub id: FileId,
    pub kind: InodeKind,
    pub size: u64,
    pub mtime_ns: u64,
}

#[derive(Debug, Clone)]
pub struct DirEntry {
    pub name: String,
    pub id: FileId,
    pub kind: InodeKind,
}

/// Vault-wide tree counters. Surfaced for forensic tooling
/// (`header dump` JSON output).
#[derive(Debug, Clone, Copy)]
pub struct TreeCounters {
    /// Next chunk_id to be allocated for a fresh write.
    pub next_chunk_id: u64,
    /// Next chunk-generation counter (monotonic, used in chunk AAD
    /// for replay protection).
    pub next_chunk_gen: u64,
    /// Next file_id to be allocated.
    pub next_file_id: u64,
    /// Number of chunk_ids on the LIFO free-list (freed and reusable).
    pub free_chunk_count: u64,
}

/// Decoder cap: 64 MiB. Above any realistic legitimate metadata blob
/// (about 600 K files with average path lengths), well below "OOM the
/// user's machine". Enforced at the Vfs layer BEFORE handing to
/// postcard so the deserializer doesn't even start on a hostile-
/// length payload.
const METADATA_DECODE_LIMIT_BYTES: usize = 64 * 1024 * 1024;

/// 4-byte magic + 1-byte version = "LBM\x02". Required prefix on
/// metadata blobs in the v2 format (inline-only chunk lists).
const METADATA_V2_MAGIC: &[u8; 4] = b"LBM\x02";

/// 4-byte magic + 1-byte version = "LBM\x03". Required prefix on
/// metadata blobs in the v3 format, which extends v2 by allowing
/// any single inode's chunk list to spill out of the metadata
/// region into a linked chain of encrypted chunk-list blocks in
/// the data area (`chunk::write_chunk_list_block` family). The
/// in-memory `DirectoryTree` is identical between v2 and v3; only
/// the on-disk serialisation differs. v2 readers refuse v3 blobs
/// cleanly via the version-byte mismatch rather than silently
/// mis-decoding (postcard schemas differ — v3 uses
/// `InodeV3OnDisk` which has an extra `chunks_external` field).
const METADATA_V3_MAGIC: &[u8; 4] = b"LBM\x03";

/// Environment-variable gate for the v3 (external chunk-list)
/// metadata format. Historic naming kept (`LUKSBOX_FORMAT_V2`) so
/// scripts that opted into v3 during the v0.2-dev cycle still work
/// unchanged. From the default-flip release onward v3 is the default
/// for new vaults; set this env var to `0` / `false` / `no` to opt
/// back to v2 (kept readable by older LUKSbox binaries).
const FORMAT_V3_ENV_VAR: &str = "LUKSBOX_FORMAT_V2";

// Thread-local override that takes precedence over the env var, used
// by tests (env vars are process-wide and race against parallel test
// runs). Production callers should rely on the env var or the
// explicit override guard below; we DON'T expose a Vfs::open variant
// that takes the format because the choice should live with the
// vault, not with the per-call API.
thread_local! {
    static FORMAT_V3_THREAD_LOCAL: std::cell::Cell<Option<bool>> =
        const { std::cell::Cell::new(None) };
}

/// RAII guard for the thread-local v3 override. Restores the previous
/// value on drop so nested or sibling calls aren't poisoned.
pub struct FormatV3OverrideGuard {
    previous: Option<bool>,
}

impl Drop for FormatV3OverrideGuard {
    fn drop(&mut self) {
        FORMAT_V3_THREAD_LOCAL.with(|c| c.set(self.previous));
    }
}

/// Test / programmatic override for whether a fresh vault opened on
/// this thread should be initialised in the v3 metadata format.
/// Takes precedence over `LUKSBOX_FORMAT_V2`. `None` clears the
/// override (falls back to env-var resolution).
pub fn set_format_v3_override(v: Option<bool>) -> FormatV3OverrideGuard {
    let previous = FORMAT_V3_THREAD_LOCAL.with(|c| c.replace(v));
    FormatV3OverrideGuard { previous }
}

fn use_v3_for_fresh_vault() -> bool {
    // Thread-local wins over env var so parallel tests can each pick
    // their own format without races.
    if let Some(v) = FORMAT_V3_THREAD_LOCAL.with(|c| c.get()) {
        return v;
    }
    // Default v3 from this release on. The historic env var name
    // (`LUKSBOX_FORMAT_V2`) is kept; an explicit "0"/"false"/"no"
    // value opts back to v2 for users who need to keep new vaults
    // openable by pre-v0.2.0 LUKSbox binaries.
    !matches!(
        std::env::var(FORMAT_V3_ENV_VAR).as_deref(),
        Ok("0") | Ok("false") | Ok("no") | Ok("off")
    )
}

/// v3 on-disk Inode. Same shape as in-memory `Inode` except the
/// chunk list either stays inline (small files, `chunks_external =
/// None`) or moves to an external chain (large files, `chunks =
/// empty` and `chunks_external = Some((head, count))`). `head` is
/// the first chunk-list block in the chain; `count` is the total
/// data-chunk count so the read path can DoS-bound the chain walk
/// and reject corrupt chains.
///
/// `cached_real_size` / `external_list_blocks` are in-memory only
/// in the working `Inode` and never serialised — they're absent here.
#[derive(Serialize, Deserialize, Debug, Clone)]
struct InodeV3OnDisk {
    id: FileId,
    parent: FileId,
    kind: InodeKind,
    size: u64,
    mtime_ns: u64,
    chunks: Vec<ChunkRef>,
    chunks_external: Option<(ChunkRef, u64)>,
    children: std::collections::BTreeMap<String, FileId>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
struct DirectoryTreeV3OnDisk {
    root: FileId,
    next_file_id: FileId,
    next_chunk_id: ChunkId,
    next_chunk_gen: u64,
    free_chunks: Vec<ChunkId>,
    inodes: std::collections::BTreeMap<FileId, InodeV3OnDisk>,
}

fn invalid_metadata<T>() -> Result<T, Error> {
    Err(Error::MetadataDeserialize)
}

/// Validate the authenticated metadata tree before any VFS operation trusts
/// it. The AEAD says "this came from someone with the MVK"; these checks say
/// "it is also structurally sane and cannot drive offset/id wraparound."
fn validate_metadata_tree(
    tree: &DirectoryTree,
    data_offset: u64,
    hide_size: bool,
) -> Result<(), Error> {
    use crate::tree::CHUNK_LIST_FILE_ID_BIT;
    if tree.root != ROOT_ID
        || tree.next_file_id <= ROOT_ID
        || tree.next_file_id == u64::MAX
        || tree.next_file_id >= CHUNK_LIST_FILE_ID_BIT
        || tree.next_chunk_gen == 0
        || tree.next_chunk_gen == u64::MAX
        || chunk::slot_offset(data_offset, tree.next_chunk_id).is_err()
    {
        // CHUNK_LIST_FILE_ID_BIT (1<<63) ceiling: real file_ids
        // must never enter the synthetic range that names v3
        // chunk-list-block chains, otherwise the next allocated
        // file_id would AAD-collide with a chunk-list block. Real
        // allocation starts at ROOT_ID + 1 = 2 and increments by
        // one per file, so reaching 1<<63 isn't physically possible
        // with honest writes; the check is defense in depth against
        // a malicious metadata blob (forged with MVK) that tries
        // to drive a future allocation into the reserved range.
        return invalid_metadata();
    }

    let root = tree
        .inodes
        .get(&ROOT_ID)
        .ok_or(Error::MetadataDeserialize)?;
    if root.id != ROOT_ID || root.parent != ROOT_ID || root.kind != InodeKind::Directory {
        return invalid_metadata();
    }

    let mut referenced_inodes = BTreeSet::new();
    let mut live_chunks = BTreeSet::new();

    for (&id, inode) in &tree.inodes {
        if inode.id != id || id >= tree.next_file_id {
            return invalid_metadata();
        }
        if id != ROOT_ID {
            let parent = tree
                .inodes
                .get(&inode.parent)
                .ok_or(Error::MetadataDeserialize)?;
            if parent.kind != InodeKind::Directory {
                return invalid_metadata();
            }
        }

        match inode.kind {
            InodeKind::Directory => {
                if inode.size != 0 || !inode.chunks.is_empty() {
                    return invalid_metadata();
                }
                for (name, &child_id) in &inode.children {
                    if validate_name(name).is_err() || child_id == ROOT_ID {
                        return invalid_metadata();
                    }
                    let child = tree
                        .inodes
                        .get(&child_id)
                        .ok_or(Error::MetadataDeserialize)?;
                    if child.parent != id || !referenced_inodes.insert(child_id) {
                        return invalid_metadata();
                    }
                }
            }
            InodeKind::File => {
                if !inode.children.is_empty() {
                    return invalid_metadata();
                }
                if hide_size {
                    let expected_capacity = (inode.chunks.len() as u64)
                        .checked_mul(CHUNK_PLAINTEXT_SIZE as u64)
                        .ok_or(Error::MetadataDeserialize)?;
                    if inode.size != expected_capacity {
                        return invalid_metadata();
                    }
                } else if inode.chunks.len() < required_chunks(inode.size, false) {
                    return invalid_metadata();
                }
                for chunk_ref in &inode.chunks {
                    if chunk_ref.id >= tree.next_chunk_id
                        || chunk_ref.generation == 0
                        || chunk_ref.generation >= tree.next_chunk_gen
                        || chunk::slot_offset(data_offset, chunk_ref.id).is_err()
                        || !live_chunks.insert(chunk_ref.id)
                    {
                        return invalid_metadata();
                    }
                }
                // v3: the chunk-list blocks owned by this inode also
                // occupy chunk slots in the data area; they must
                // satisfy the same sanity bounds AND must not collide
                // with data chunk IDs already in `live_chunks` (a
                // chunk-list block ID == a data chunk ID would let
                // one decryption attempt cover the other slot).
                // Generations are still strictly less than
                // `next_chunk_gen`. Always empty for v2-format vaults.
                for cref in &inode.external_list_blocks {
                    if cref.id >= tree.next_chunk_id
                        || cref.generation == 0
                        || cref.generation >= tree.next_chunk_gen
                        || chunk::slot_offset(data_offset, cref.id).is_err()
                        || !live_chunks.insert(cref.id)
                    {
                        return invalid_metadata();
                    }
                }
            }
        }
    }

    for &id in tree.inodes.keys() {
        if id != ROOT_ID && !referenced_inodes.contains(&id) {
            return invalid_metadata();
        }
    }

    let mut free_chunks = BTreeSet::new();
    for &id in &tree.free_chunks {
        if id >= tree.next_chunk_id
            || live_chunks.contains(&id)
            || chunk::slot_offset(data_offset, id).is_err()
            || !free_chunks.insert(id)
        {
            return invalid_metadata();
        }
    }

    Ok(())
}

/// Convert the v3 on-disk shape back into the working in-memory
/// `DirectoryTree`. For each inode that's external, walk the
/// chunk-list chain to fully materialise `chunks` and record the
/// list-block ChunkRefs in `external_list_blocks`. Inodes that
/// were inline keep their chunks vec as-is.
///
/// All chain walks happen here at open time, NOT lazily on access.
/// The trade-off is memory (a fully-loaded 10 GiB file's chunks vec
/// is ~40 MiB) for simplicity (all the existing read/write/truncate
/// code is unchanged and sees a single materialised representation).
fn v3_on_disk_to_in_memory(
    v3: DirectoryTreeV3OnDisk,
    container: &mut luksbox_format::Container,
) -> Result<DirectoryTree, Error> {
    let mut inodes: std::collections::BTreeMap<FileId, crate::tree::Inode> =
        std::collections::BTreeMap::new();
    for (id, od) in v3.inodes {
        let (chunks, external_list_blocks) = match od.chunks_external {
            None => (od.chunks, Vec::new()),
            Some((head, expected_count)) => {
                if !od.chunks.is_empty() {
                    // v3 invariant: chunks_external => inline chunks
                    // vec MUST be empty. A blob that violates this is
                    // either corrupt or a forgery; refuse.
                    return Err(Error::MetadataDeserialize);
                }
                chunk::walk_chunk_list_chain(container, od.id, head, expected_count)
                    .map_err(|_| Error::MetadataDeserialize)?
            }
        };
        inodes.insert(
            id,
            crate::tree::Inode {
                id: od.id,
                parent: od.parent,
                kind: od.kind,
                size: od.size,
                mtime_ns: od.mtime_ns,
                chunks,
                children: od.children,
                cached_real_size: None,
                external_list_blocks,
            },
        );
    }
    Ok(DirectoryTree {
        root: v3.root,
        next_file_id: v3.next_file_id,
        next_chunk_id: v3.next_chunk_id,
        next_chunk_gen: v3.next_chunk_gen,
        free_chunks: v3.free_chunks,
        inodes,
    })
}

/// Encrypted VFS atop a `Container`. Buffers the directory tree in memory and
/// writes it back to the metadata blob on `flush` / `close` / drop.
pub struct Vfs {
    container: Container,
    tree: DirectoryTree,
    dirty: bool,
    /// On-disk metadata format for this vault. Locked at first flush:
    /// v2 (LBM2) writes all chunk lists inline; v3 (LBM3) spills any
    /// inode with chunks.len() > `V3_INLINE_CHUNK_THRESHOLD` to an
    /// external chunk-list-block chain. A vault that was created LBM2
    /// stays LBM2 forever; a vault opted into LBM3 at create time
    /// (`LUKSBOX_FORMAT_V2=1`) stays LBM3. Migration between formats
    /// is out-of-band (re-create the vault).
    use_v3_format: bool,
}

impl Vfs {
    /// Open a Vfs over an already-unlocked container. If the metadata blob is
    /// empty (freshly created container), initializes a fresh tree.
    pub fn open(mut container: Container) -> Result<Self, Error> {
        let blob = container.read_metadata()?;
        let (tree, use_v3_format) = if blob.is_empty() {
            // Fresh vault: pick the format based on the env-var gate.
            // The choice is then locked in by the first flush writing
            // the LBM2 / LBM3 magic onto disk.
            (DirectoryTree::new(), use_v3_for_fresh_vault())
        } else if blob.len() >= METADATA_V3_MAGIC.len()
            && &blob[..METADATA_V3_MAGIC.len()] == METADATA_V3_MAGIC
        {
            let payload = &blob[METADATA_V3_MAGIC.len()..];
            if payload.len() > METADATA_DECODE_LIMIT_BYTES {
                return Err(Error::MetadataDeserialize);
            }
            let v3: DirectoryTreeV3OnDisk =
                postcard::from_bytes(payload).map_err(|_| Error::MetadataDeserialize)?;
            (v3_on_disk_to_in_memory(v3, &mut container)?, true)
        } else if blob.len() >= METADATA_V2_MAGIC.len()
            && &blob[..METADATA_V2_MAGIC.len()] == METADATA_V2_MAGIC
        {
            let payload = &blob[METADATA_V2_MAGIC.len()..];
            if payload.len() > METADATA_DECODE_LIMIT_BYTES {
                return Err(Error::MetadataDeserialize);
            }
            (
                postcard::from_bytes::<DirectoryTree>(payload)
                    .map_err(|_| Error::MetadataDeserialize)?,
                false,
            )
        } else {
            // Neither LBM2 nor LBM3 — unsupported version, refuse cleanly.
            return Err(Error::MetadataDeserialize);
        };
        validate_metadata_tree(
            &tree,
            container.data_offset(),
            container.header.hide_size_header(),
        )?;
        Ok(Self {
            container,
            tree,
            dirty: false,
            use_v3_format,
        })
    }

    /// Whether this vault is using the v3 metadata format. Visible
    /// to tests; production code should not branch on it (the Vfs
    /// internals handle format-specific behaviour transparently).
    pub fn uses_v3_metadata(&self) -> bool {
        self.use_v3_format
    }

    pub fn flush(&mut self) -> Result<(), Error> {
        if !self.dirty {
            return Ok(());
        }
        validate_metadata_tree(
            &self.tree,
            self.container.data_offset(),
            self.container.header.hide_size_header(),
        )?;
        let bytes = if self.use_v3_format {
            // v3: spill any inode whose chunk list exceeds
            // V3_INLINE_CHUNK_THRESHOLD into an external chunk-list
            // chain, then serialise the spilled tree as
            // DirectoryTreeV3OnDisk. Spilling writes chunk-list
            // blocks AND mutates inode.external_list_blocks for
            // bookkeeping; old external_list_blocks (from a
            // previous flush) are freed during the spill.
            let v3 = self.spill_to_v3_on_disk()?;
            let payload =
                postcard::to_allocvec(&v3).map_err(|_| Error::MetadataSerialize)?;
            if payload.len() > METADATA_DECODE_LIMIT_BYTES {
                return Err(Error::MetadataSerialize);
            }
            let mut bytes = Vec::with_capacity(METADATA_V3_MAGIC.len() + payload.len());
            bytes.extend_from_slice(METADATA_V3_MAGIC);
            bytes.extend_from_slice(&payload);
            bytes
        } else {
            // v2: plain postcard of the whole tree, all chunks inline.
            let payload =
                postcard::to_allocvec(&self.tree).map_err(|_| Error::MetadataSerialize)?;
            if payload.len() > METADATA_DECODE_LIMIT_BYTES {
                return Err(Error::MetadataSerialize);
            }
            let mut bytes = Vec::with_capacity(METADATA_V2_MAGIC.len() + payload.len());
            bytes.extend_from_slice(METADATA_V2_MAGIC);
            bytes.extend_from_slice(&payload);
            bytes
        };
        self.container.write_metadata(&bytes)?;
        // If the container has an anchor sidecar configured, push the
        // current vault generation to it so a future open can detect
        // rollback via `anchor::compare`.
        self.container.write_anchor(self.tree.next_chunk_gen)?;
        self.dirty = false;
        Ok(())
    }

    /// For each inode in the in-memory tree, decide between inline
    /// and external storage and build the on-disk v3 representation.
    /// Inodes whose chunks vec exceeds `V3_INLINE_CHUNK_THRESHOLD`
    /// are spilled: a fresh chain of chunk-list blocks is written,
    /// the inode's old `external_list_blocks` are returned to the
    /// free pool, and the on-disk Inode carries
    /// `chunks_external = Some((head, count))` with an empty inline
    /// chunks vec. Inodes that fit inline keep their old behaviour
    /// (chunks inline, chunks_external = None); if such an inode
    /// previously had external blocks (shrunk past the threshold),
    /// those blocks are freed.
    fn spill_to_v3_on_disk(&mut self) -> Result<DirectoryTreeV3OnDisk, Error> {
        // Pull the inode IDs out first so we can mutably borrow
        // self.tree per-iteration without aliasing.
        let inode_ids: Vec<FileId> = self.tree.inodes.keys().copied().collect();
        let mut on_disk_inodes: std::collections::BTreeMap<FileId, InodeV3OnDisk> =
            std::collections::BTreeMap::new();
        for id in inode_ids {
            // Snapshot the inode's spill-relevant data while the
            // immutable borrow is alive, then re-borrow mutably to
            // update external_list_blocks.
            let (chunks_len, file_needs_external) = {
                let inode = self.tree.inodes.get(&id).expect("id from keys()");
                (
                    inode.chunks.len(),
                    inode.kind == InodeKind::File
                        && inode.chunks.len() > V3_INLINE_CHUNK_THRESHOLD,
                )
            };
            // Free any previously-allocated external_list_blocks; we
            // either rewrite them fresh (still external) or no longer
            // need them (shrunk back to inline).
            let old_externals: Vec<ChunkRef> = self
                .tree
                .inodes
                .get_mut(&id)
                .expect("id from keys()")
                .external_list_blocks
                .drain(..)
                .collect();
            for cref in &old_externals {
                self.tree.free_chunk_id(cref.id);
            }
            if file_needs_external {
                // Write the chunk list as a chain of external blocks.
                // We need a snapshot of `chunks` and `id` from the
                // immutable borrow, but write_chunk_list_block mutates
                // self.container, so do the snapshot first.
                let chunks_snapshot: Vec<ChunkRef> = self
                    .tree
                    .inodes
                    .get(&id)
                    .expect("id from keys()")
                    .chunks
                    .clone();
                let (head, count, new_externals) =
                    self.write_external_chain_for(id, &chunks_snapshot)?;
                debug_assert_eq!(count as usize, chunks_len);
                // Record the new external_list_blocks on the inode.
                let inode_mut = self
                    .tree
                    .inodes
                    .get_mut(&id)
                    .expect("id from keys()");
                inode_mut.external_list_blocks = new_externals;
                on_disk_inodes.insert(
                    id,
                    InodeV3OnDisk {
                        id: inode_mut.id,
                        parent: inode_mut.parent,
                        kind: inode_mut.kind,
                        size: inode_mut.size,
                        mtime_ns: inode_mut.mtime_ns,
                        chunks: Vec::new(),
                        chunks_external: Some((head, count)),
                        children: inode_mut.children.clone(),
                    },
                );
            } else {
                // Inline. (external_list_blocks just got cleared above
                // — chunks are already in the in-memory `chunks` vec.)
                let inode = self.tree.inodes.get(&id).expect("id from keys()");
                on_disk_inodes.insert(
                    id,
                    InodeV3OnDisk {
                        id: inode.id,
                        parent: inode.parent,
                        kind: inode.kind,
                        size: inode.size,
                        mtime_ns: inode.mtime_ns,
                        chunks: inode.chunks.clone(),
                        chunks_external: None,
                        children: inode.children.clone(),
                    },
                );
            }
        }
        Ok(DirectoryTreeV3OnDisk {
            root: self.tree.root,
            next_file_id: self.tree.next_file_id,
            next_chunk_id: self.tree.next_chunk_id,
            next_chunk_gen: self.tree.next_chunk_gen,
            free_chunks: self.tree.free_chunks.clone(),
            inodes: on_disk_inodes,
        })
    }

    /// Pack `entries` into a chain of chunk-list blocks owned by
    /// `file_id`. Returns `(head, count, list_block_refs)`. Each
    /// block is allocated a fresh ChunkId + generation from the
    /// tree, so the chain is replay-safe against any prior external
    /// chain at the same file_id.
    fn write_external_chain_for(
        &mut self,
        file_id: FileId,
        entries: &[ChunkRef],
    ) -> Result<(ChunkRef, u64, Vec<ChunkRef>), Error> {
        use chunk::CHUNK_LIST_ENTRIES_PER_BLOCK;
        // Allocate ChunkRefs for every list-block up front so we can
        // backfill the `next` pointers as we write each block.
        let block_count = entries.len().div_ceil(CHUNK_LIST_ENTRIES_PER_BLOCK);
        let mut block_refs: Vec<ChunkRef> = Vec::with_capacity(block_count);
        for _ in 0..block_count {
            let id = self
                .tree
                .alloc_chunk_id()
                .ok_or(Error::IdSpaceExhausted)?;
            let generation = self
                .tree
                .alloc_chunk_gen()
                .ok_or(Error::IdSpaceExhausted)?;
            block_refs.push(ChunkRef { id, generation });
        }
        // Write the blocks. Each block_idx is its position in the
        // chain (0, 1, 2, ...); the AEAD AAD binds it to that
        // position so a reordered chain fails decryption.
        for (idx, block) in block_refs.iter().enumerate() {
            let start = idx * CHUNK_LIST_ENTRIES_PER_BLOCK;
            let end = (start + CHUNK_LIST_ENTRIES_PER_BLOCK).min(entries.len());
            let next = block_refs.get(idx + 1).copied();
            chunk::write_chunk_list_block(
                &mut self.container,
                file_id,
                idx as u32,
                *block,
                &entries[start..end],
                next,
            )?;
        }
        Ok((block_refs[0], entries.len() as u64, block_refs))
    }

    /// Current monotonic vault-generation counter. Compare with an
    /// anchor file's generation via `luksbox_format::anchor::compare`
    /// to detect rollback.
    pub fn vault_generation(&self) -> u64 {
        self.tree.next_chunk_gen
    }

    /// Pre-flight check: would adding `extra_chunks` to file `id`'s chunk
    /// list push the serialised directory tree past the vault's metadata
    /// region? Returns `Err(Error::MetadataBudgetExhausted)` if yes,
    /// `Ok(())` otherwise. Used by `write` / `truncate` BEFORE any chunk
    /// allocation so callers see ENOSPC at the FUSE layer instead of
    /// silently writing chunks the metadata blob can never point at.
    ///
    /// Two estimation strategies, one per format:
    ///
    /// - **v2 (`use_v3_format = false`)**: every ChunkRef lands inline
    ///   in the metadata blob. Serialise the current tree once
    ///   (postcard, fast), add a conservative 12 B per new chunk
    ///   (worst-case two u64 varints + Vec-length slack), and compare
    ///   to the budget. Same as before this fix.
    ///
    /// - **v3 (`use_v3_format = true`)**: any inode whose chunk count
    ///   exceeds `V3_INLINE_CHUNK_THRESHOLD` spills its chunk list out
    ///   of the metadata region at flush time. The on-disk Inode for
    ///   such an inode carries a constant-size head ChunkRef + count
    ///   (~24 B), not the materialised chunks vec. The check therefore
    ///   estimates the **post-spill** size: per-inode, count inline
    ///   chunks if `chunks.len() + (this file's added chunks?)` would
    ///   stay <= threshold, else count the fixed external-stub cost.
    ///   This means a 100 GiB v3 file (~25M chunks) projects to ~24 B
    ///   in the metadata blob, not ~300 MB, so the check actually
    ///   permits the writes v3 is designed to support.
    ///
    /// False positives are acceptable (we refuse a write that would
    /// have just barely fit, user gets ENOSPC, recoverable); false
    /// negatives are NOT (chunks land on disk, metadata can't address
    /// them, silent loss).
    fn check_metadata_budget_for_chunks(
        &self,
        id: FileId,
        extra_chunks: usize,
    ) -> Result<(), Error> {
        // Region size lives on the on-disk header (set at create time,
        // honored on every open). Constant for the life of this Vfs.
        let region_size = self.container.header.metadata_size;
        let budget = luksbox_format::metadata::payload_budget_for(region_size);

        if !self.use_v3_format {
            // v2: every chunk is inline. Same logic as before the fix.
            let current = postcard::to_allocvec(&self.tree)
                .map_err(|_| Error::MetadataSerialize)?
                .len();
            let projected = current.saturating_add(extra_chunks.saturating_mul(12));
            if projected > budget {
                return Err(Error::MetadataBudgetExhausted);
            }
            return Ok(());
        }

        // v3: estimate the size of the SPILLED tree. We serialize a
        // DirectoryTreeV3OnDisk that mirrors `self.tree` with each
        // inode rendered in its on-disk form (inline if under
        // threshold, External stub if over). For the file `id` that's
        // about to grow, project the post-add chunk count and use
        // that projected count when deciding inline vs external.
        //
        // The serialisation is bounded by inode count + per-inode
        // fixed overhead (~100 B in postcard, plus children and
        // path-name bytes for directories). Even with 100k tiny
        // files the projection is well under the 16 MiB budget.
        //
        // We don't actually need to BUILD spill blocks here — the
        // estimate is just an InodeV3OnDisk with empty inline chunks
        // and a placeholder (ChunkRef, count). The placeholder bytes
        // postcard-encode identically to the real values (same shape).
        let placeholder = ChunkRef { id: 0, generation: 1 };
        let mut on_disk_inodes: std::collections::BTreeMap<FileId, InodeV3OnDisk> =
            std::collections::BTreeMap::new();
        for (&inode_id, inode) in self.tree.inodes.iter() {
            // Project the chunks vec for this file: target file `id`
            // gets `chunks.len() + extra_chunks`; everyone else is
            // current size.
            let projected_chunk_count = if inode_id == id {
                inode.chunks.len().saturating_add(extra_chunks)
            } else {
                inode.chunks.len()
            };
            let renders_external = inode.kind == InodeKind::File
                && projected_chunk_count > V3_INLINE_CHUNK_THRESHOLD;
            on_disk_inodes.insert(
                inode_id,
                if renders_external {
                    InodeV3OnDisk {
                        id: inode.id,
                        parent: inode.parent,
                        kind: inode.kind,
                        size: inode.size,
                        mtime_ns: inode.mtime_ns,
                        chunks: Vec::new(),
                        chunks_external: Some((placeholder, projected_chunk_count as u64)),
                        children: inode.children.clone(),
                    }
                } else {
                    // Inline path: count the PROJECTED chunks as if
                    // they were already in the vec. We approximate
                    // each projected ChunkRef as the placeholder; for
                    // a file that's currently inline and won't spill
                    // even after growing, this gives a slight under-
                    // estimate (the real new ChunkRefs will have
                    // larger varint encodings as id/gen grow). Add
                    // 12 B per projected chunk (same upper bound as
                    // the v2 path) as the worst-case correction.
                    let chunks = if inode_id == id {
                        let mut v = inode.chunks.clone();
                        v.extend(std::iter::repeat_n(placeholder, extra_chunks));
                        v
                    } else {
                        inode.chunks.clone()
                    };
                    InodeV3OnDisk {
                        id: inode.id,
                        parent: inode.parent,
                        kind: inode.kind,
                        size: inode.size,
                        mtime_ns: inode.mtime_ns,
                        chunks,
                        chunks_external: None,
                        children: inode.children.clone(),
                    }
                },
            );
        }
        let projected_tree = DirectoryTreeV3OnDisk {
            root: self.tree.root,
            next_file_id: self.tree.next_file_id,
            next_chunk_id: self.tree.next_chunk_id,
            next_chunk_gen: self.tree.next_chunk_gen,
            free_chunks: self.tree.free_chunks.clone(),
            inodes: on_disk_inodes,
        };
        let projected = postcard::to_allocvec(&projected_tree)
            .map_err(|_| Error::MetadataSerialize)?
            .len();
        // Slack for varint growth on placeholder values being smaller
        // than the real values we'll write at flush time. Even the
        // worst-case correction (a few KiB) is dwarfed by the budget.
        let slack = 4096;
        if projected.saturating_add(slack) > budget {
            return Err(Error::MetadataBudgetExhausted);
        }
        Ok(())
    }

    pub fn close(mut self) -> Result<Container, Error> {
        self.flush()?;
        Ok(self.container)
    }

    /// Read-only access to the underlying `Container`. Useful for callers
    /// that want to inspect header / keyslot state without taking the
    /// container apart.
    pub fn container(&self) -> &Container {
        &self.container
    }

    /// Mutable access to the underlying `Container`. Used by callers that
    /// need to enroll/revoke keyslots or call `persist_header`. Don't
    /// move chunks around through this, use the Vfs API for that.
    pub fn container_mut(&mut self) -> &mut Container {
        &mut self.container
    }

    pub fn root_id(&self) -> FileId {
        self.tree.root
    }

    pub fn parent_of(&self, id: FileId) -> Result<FileId, Error> {
        Ok(self.tree.inodes.get(&id).ok_or(Error::NotFound)?.parent)
    }

    pub fn stat(&mut self, id: FileId) -> Result<Stat, Error> {
        let real_size = self.real_size(id)?;
        let inode = self.tree.inodes.get(&id).ok_or(Error::NotFound)?;
        Ok(Stat {
            id: inode.id,
            kind: inode.kind,
            size: real_size,
            mtime_ns: inode.mtime_ns,
        })
    }

    /// Per-file ordered chunk references. Returned as a freshly-allocated
    /// `Vec` so the caller can iterate without holding a `&self` borrow
    /// (the chunk decrypt path needs `&mut Container`). Used by the
    /// forensic-only CLI surfaces (`check`, `extract --tolerate-errors`,
    /// `header dump`) to walk a file's chunks at the format level.
    pub fn file_chunks(&self, id: FileId) -> Result<Vec<crate::tree::ChunkRef>, Error> {
        let inode = self.tree.inodes.get(&id).ok_or(Error::NotFound)?;
        if inode.kind != InodeKind::File {
            return Err(Error::NotAFile);
        }
        Ok(inode.chunks.clone())
    }

    /// All FileIds in the tree (BFS order from root). For forensic
    /// dumps that need to enumerate every inode without recursing
    /// through `readdir` themselves.
    pub fn all_file_ids(&self) -> Vec<FileId> {
        self.tree.inodes.keys().copied().collect()
    }

    /// Inode kind without going through `stat` (avoids the
    /// hide-size chunk decrypt that `stat` performs for files).
    pub fn inode_kind(&self, id: FileId) -> Result<InodeKind, Error> {
        Ok(self.tree.inodes.get(&id).ok_or(Error::NotFound)?.kind)
    }

    /// Stored (non-real) size. In hide-size mode this is the padded
    /// chunk capacity; the real size is in chunk 0. Used by forensic
    /// surfaces that want the raw value without triggering a chunk
    /// decrypt.
    pub fn inode_size_raw(&self, id: FileId) -> Result<u64, Error> {
        Ok(self.tree.inodes.get(&id).ok_or(Error::NotFound)?.size)
    }

    /// Counts of allocated/free chunks across the whole vault, plus
    /// the next-id and next-generation counters. Used by `header dump`
    /// to surface tree-level state for forensics.
    pub fn tree_counters(&self) -> TreeCounters {
        TreeCounters {
            next_chunk_id: self.tree.next_chunk_id,
            next_chunk_gen: self.tree.next_chunk_gen,
            next_file_id: self.tree.next_file_id,
            free_chunk_count: self.tree.free_chunks.len() as u64,
        }
    }

    /// Get the real (logical) byte length of a file, decoding the chunk-0
    /// header in `FLAG_HIDE_SIZE_HEADER` mode (cached after first lookup).
    /// In normal mode this is just `inode.size`.
    ///
    /// Round 13 fix R13-03: the chunk-0 size header is authenticated by
    /// the chunk AEAD, but its value is otherwise unconstrained by the
    /// container layer — `validate_metadata_tree` only checks that the
    /// stored `inode.size` matches `chunks.len() * CHUNK_PLAINTEXT_SIZE`
    /// (the padded capacity), not the real-size u64. An authenticated
    /// writer (legitimate vault owner or anyone with the MVK) could
    /// craft a chunk-0 whose size header decodes to a value far larger
    /// than the allocated chunk capacity. The cached value would then
    /// flow into `read()` / `write()` / `stat()`, where
    /// `inode.chunks[chunk_idx]` panics on out-of-range access. We
    /// reject hostile values here, before they reach the cache.
    fn real_size(&mut self, id: FileId) -> Result<u64, Error> {
        let inode = self.tree.inodes.get(&id).ok_or(Error::NotFound)?;
        if inode.kind != InodeKind::File {
            // Directories etc. have size = 0 in our model; stat returns 0.
            return Ok(0);
        }
        let hide_size = self.container.header.hide_size_header();
        if !hide_size {
            return Ok(inode.size);
        }
        if let Some(s) = inode.cached_real_size {
            return Ok(s);
        }
        if inode.chunks.is_empty() {
            // Empty file in hide-size mode: no chunk to decrypt.
            self.tree.inodes.get_mut(&id).unwrap().cached_real_size = Some(0);
            return Ok(0);
        }
        // Decrypt chunk 0 to extract the size header.
        let chunk0 = inode.chunks[0];
        let chunks_len = inode.chunks.len();
        let key = chunk::file_key(&self.container, id);
        let pt = chunk::read_chunk(&mut self.container, &key, id, 0, chunk0)?;
        let mut size_buf = [0u8; SIZE_HEADER_LEN];
        size_buf.copy_from_slice(&pt[..SIZE_HEADER_LEN]);
        let size = u64::from_le_bytes(size_buf);
        // R13-03: the maximum legal real-size is the allocated chunk
        // capacity minus the 8-byte chunk-0 size header. Bigger values
        // are corrupt (or attacker-supplied) and must be refused before
        // any downstream offset calculation reaches `inode.chunks[idx]`.
        let max_real = (chunks_len as u64)
            .checked_mul(CHUNK_PLAINTEXT_SIZE as u64)
            .and_then(|cap| cap.checked_sub(SIZE_HEADER_LEN as u64))
            .ok_or(Error::MetadataDeserialize)?;
        if size > max_real {
            return Err(Error::MetadataDeserialize);
        }
        self.tree.inodes.get_mut(&id).unwrap().cached_real_size = Some(size);
        Ok(size)
    }

    pub fn readdir(&self, id: FileId) -> Result<Vec<DirEntry>, Error> {
        let inode = self.require_dir(id)?;
        Ok(inode
            .children
            .iter()
            .map(|(name, &child_id)| {
                let kind = self
                    .tree
                    .inodes
                    .get(&child_id)
                    .map(|i| i.kind)
                    .unwrap_or(InodeKind::File);
                DirEntry {
                    name: name.clone(),
                    id: child_id,
                    kind,
                }
            })
            .collect())
    }

    pub fn lookup(&self, parent: FileId, name: &str) -> Result<FileId, Error> {
        let inode = self.require_dir(parent)?;
        inode.children.get(name).copied().ok_or(Error::NotFound)
    }

    pub fn lookup_path(&self, path: &str) -> Result<FileId, Error> {
        let mut cur = self.tree.root;
        for seg in path.split('/').filter(|s| !s.is_empty()) {
            cur = self.lookup(cur, seg)?;
        }
        Ok(cur)
    }

    pub fn mkdir(&mut self, parent: FileId, name: &str) -> Result<FileId, Error> {
        validate_name(name)?;
        self.require_dir(parent)?;
        if self.tree.inodes[&parent].children.contains_key(name) {
            return Err(Error::AlreadyExists);
        }
        let id = self.tree.alloc_file_id().ok_or(Error::IdSpaceExhausted)?;
        self.tree.inodes.insert(
            id,
            Inode {
                id,
                parent,
                kind: InodeKind::Directory,
                size: 0,
                mtime_ns: 0,
                chunks: Vec::new(),
                children: Default::default(),
                cached_real_size: None,
                external_list_blocks: Vec::new(),
            },
        );
        self.tree
            .inodes
            .get_mut(&parent)
            .unwrap()
            .children
            .insert(name.to_string(), id);
        self.dirty = true;
        Ok(id)
    }

    pub fn create(&mut self, parent: FileId, name: &str) -> Result<FileId, Error> {
        validate_name(name)?;
        self.require_dir(parent)?;
        if self.tree.inodes[&parent].children.contains_key(name) {
            return Err(Error::AlreadyExists);
        }
        let id = self.tree.alloc_file_id().ok_or(Error::IdSpaceExhausted)?;
        self.tree.inodes.insert(
            id,
            Inode {
                id,
                parent,
                kind: InodeKind::File,
                size: 0,
                mtime_ns: 0,
                chunks: Vec::new(),
                children: Default::default(),
                cached_real_size: None,
                external_list_blocks: Vec::new(),
            },
        );
        self.tree
            .inodes
            .get_mut(&parent)
            .unwrap()
            .children
            .insert(name.to_string(), id);
        self.dirty = true;
        Ok(id)
    }

    pub fn read(&mut self, id: FileId, offset: u64, buf: &mut [u8]) -> Result<usize, Error> {
        let real = self.real_size(id)?;
        let inode = self.tree.inodes.get(&id).ok_or(Error::NotFound)?.clone();
        if inode.kind != InodeKind::File {
            return Err(Error::NotAFile);
        }
        if offset >= real || buf.is_empty() {
            return Ok(0);
        }
        // checked_add guards against an attacker-supplied offset close
        // to u64::MAX. The .min(real) below would otherwise be reached
        // via wrapping arithmetic in release builds.
        let requested_end = offset
            .checked_add(buf.len() as u64)
            .ok_or(Error::OffsetOverflow)?;
        let read_end = requested_end.min(real);
        let read_len = (read_end - offset) as usize;
        let hide_size = self.container.header.hide_size_header();
        let (first_chunk, _) = file_to_chunk(offset, hide_size)?;
        let (last_chunk, _) = file_to_chunk(read_end - 1, hide_size)?;

        let key = chunk::file_key(&self.container, id);
        let mut buf_pos = 0usize;
        for chunk_idx in first_chunk..=last_chunk {
            // Compute the chunk's file-byte coverage.
            let (chunk_file_start, chunk_file_end) = chunk_file_range(chunk_idx, hide_size)?;
            let in_chunk_offset = offset
                .max(chunk_file_start)
                .saturating_sub(chunk_file_start);
            let in_chunk_end = read_end
                .min(chunk_file_end)
                .saturating_sub(chunk_file_start);
            let len_here = (in_chunk_end - in_chunk_offset) as usize;
            let chunk_data_start = if hide_size && chunk_idx == 0 {
                SIZE_HEADER_LEN
            } else {
                0
            };
            let read_start_in_chunk = chunk_data_start + in_chunk_offset as usize;
            let read_end_in_chunk = chunk_data_start + in_chunk_end as usize;

            let pt = chunk::read_chunk(
                &mut self.container,
                &key,
                id,
                chunk_idx as u32,
                inode.chunks[chunk_idx],
            )?;
            buf[buf_pos..buf_pos + len_here]
                .copy_from_slice(&pt[read_start_in_chunk..read_end_in_chunk]);
            buf_pos += len_here;
        }
        Ok(read_len)
    }

    pub fn write(&mut self, id: FileId, offset: u64, buf: &[u8]) -> Result<usize, Error> {
        if buf.is_empty() {
            return Ok(0);
        }
        let old_real = self.real_size(id)?;
        let inode = self.tree.inodes.get(&id).ok_or(Error::NotFound)?.clone();
        if inode.kind != InodeKind::File {
            return Err(Error::NotAFile);
        }
        // Same overflow guard as `read`. Without checked_add, a
        // malicious or buggy caller could wrap `new_end` and we'd
        // truncate the file rather than refuse the write.
        let new_end = offset
            .checked_add(buf.len() as u64)
            .ok_or(Error::OffsetOverflow)?;
        // R13-07: refuse writes whose target logical size exceeds the
        // per-file cap before we feed `padded_chunk_count` /
        // `next_power_of_two` something that would panic or allocate
        // astronomic amounts of disk.
        if new_end > MAX_FILE_SIZE {
            return Err(Error::FileSizeExceedsCap);
        }
        let new_real = old_real.max(new_end);

        let hide_size = self.container.header.hide_size_header();
        let padding_on = self.container.header.pad_files_pow2();
        let target_count = padded_chunk_count(required_chunks(new_real, hide_size), padding_on);

        let (first_chunk, _) = file_to_chunk(offset, hide_size)?;
        let (last_chunk, _) = file_to_chunk(new_end - 1, hide_size)?;

        let key = chunk::file_key(&self.container, id);
        let mut chunks = inode.chunks.clone();

        // Pre-flight the metadata budget BEFORE allocating any new
        // chunks. Each new ChunkRef adds two u64s to the on-disk
        // directory tree (postcard-varint encoded); for large files
        // this grows the metadata blob past the vault's fixed-size
        // metadata region, at which point `Vfs::flush` would refuse
        // the write. The old code only caught this at flush time —
        // by then the encrypted chunks were already on disk but the
        // metadata pointer was not, so on the next mount the file
        // was invisible and the chunks were orphaned (silent data
        // loss). Fail here, BEFORE the chunk-allocation loop, so
        // `cp` / `dd` sees ENOSPC at the FUSE layer and exits with
        // a real error.
        if chunks.len() < target_count {
            self.check_metadata_budget_for_chunks(id, target_count - chunks.len())?;
        }

        // Allocate any missing chunks up to target_count as zero-filled.
        // Covers file extension, sparse holes (write past EOF), and
        // pow2 padding. In hide-size mode, the new chunk 0 (if just
        // allocated) gets its size header set below.
        let zero = vec![0u8; CHUNK_PLAINTEXT_SIZE];
        while chunks.len() < target_count {
            let cref = ChunkRef {
                id: self.tree.alloc_chunk_id().ok_or(Error::IdSpaceExhausted)?,
                generation: self.tree.alloc_chunk_gen().ok_or(Error::IdSpaceExhausted)?,
            };
            let chunk_idx = chunks.len() as u32;
            chunk::write_chunk(&mut self.container, &key, id, chunk_idx, cref, &zero)?;
            chunks.push(cref);
        }

        // Read-modify-write over the covered range. Each rewrite gets a
        // fresh generation counter (replay protection).
        let mut buf_pos = 0usize;
        for chunk_idx in first_chunk..=last_chunk {
            let (chunk_file_start, chunk_file_end) = chunk_file_range(chunk_idx, hide_size)?;
            let in_chunk_offset = offset
                .max(chunk_file_start)
                .saturating_sub(chunk_file_start);
            let in_chunk_end = new_end.min(chunk_file_end).saturating_sub(chunk_file_start);
            let len_here = (in_chunk_end - in_chunk_offset) as usize;
            let data_start = if hide_size && chunk_idx == 0 {
                SIZE_HEADER_LEN
            } else {
                0
            };
            let pt_start = data_start + in_chunk_offset as usize;
            let pt_end = data_start + in_chunk_end as usize;

            let mut pt = chunk::read_chunk(
                &mut self.container,
                &key,
                id,
                chunk_idx as u32,
                chunks[chunk_idx],
            )?;
            pt[pt_start..pt_end].copy_from_slice(&buf[buf_pos..buf_pos + len_here]);
            // If this is chunk 0 in hide-size mode, refresh the size header
            // (the write may have grown the file).
            if hide_size && chunk_idx == 0 {
                install_size_header(&mut pt, new_real);
            }
            // Bump generation before re-writing.
            chunks[chunk_idx].generation =
                self.tree.alloc_chunk_gen().ok_or(Error::IdSpaceExhausted)?;
            chunk::write_chunk(
                &mut self.container,
                &key,
                id,
                chunk_idx as u32,
                chunks[chunk_idx],
                &pt,
            )?;
            buf_pos += len_here;
        }

        // If hide-size and chunk 0 wasn't in the rewritten range but the
        // file grew, refresh chunk 0's size header.
        if hide_size && new_real != old_real && first_chunk > 0 && !chunks.is_empty() {
            let mut pt = chunk::read_chunk(&mut self.container, &key, id, 0, chunks[0])?;
            install_size_header(&mut pt, new_real);
            chunks[0].generation = self.tree.alloc_chunk_gen().ok_or(Error::IdSpaceExhausted)?;
            chunk::write_chunk(&mut self.container, &key, id, 0, chunks[0], &pt)?;
        }

        // Persist updated inode metadata. In hide-size mode, inode.size is
        // padded chunk capacity (not real size); cached_real_size carries
        // the truth for in-memory stat hits.
        let inode_size_field = if hide_size {
            chunks.len() as u64 * CHUNK_PLAINTEXT_SIZE as u64
        } else {
            new_real
        };
        let inode_mut = self.tree.inodes.get_mut(&id).unwrap();
        inode_mut.chunks = chunks;
        inode_mut.size = inode_size_field;
        if hide_size {
            inode_mut.cached_real_size = Some(new_real);
        }
        self.dirty = true;
        Ok(buf.len())
    }

    pub fn truncate(&mut self, id: FileId, new_size: u64) -> Result<(), Error> {
        // R13-07: refuse oversize truncates for the same reason as
        // write(): the chunk-allocation loop below would otherwise
        // commit zeros for billions of chunks before the host runs
        // out of space, and `padded_chunk_count`'s
        // `next_power_of_two` would panic.
        if new_size > MAX_FILE_SIZE {
            return Err(Error::FileSizeExceedsCap);
        }
        let inode = self.tree.inodes.get(&id).ok_or(Error::NotFound)?.clone();
        if inode.kind != InodeKind::File {
            return Err(Error::NotAFile);
        }
        let hide_size = self.container.header.hide_size_header();
        let padding_on = self.container.header.pad_files_pow2();
        let needed = required_chunks(new_size, hide_size);
        let new_chunk_count = padded_chunk_count(needed, padding_on);

        let key = chunk::file_key(&self.container, id);
        let mut chunks = inode.chunks.clone();

        while chunks.len() > new_chunk_count {
            let cref = chunks.pop().unwrap();
            self.tree.free_chunk_id(cref.id);
        }

        // Same metadata-budget pre-flight as `write`. Only relevant
        // for the truncate-up branch (shrinks never grow the chunk
        // list).
        if chunks.len() < new_chunk_count {
            self.check_metadata_budget_for_chunks(id, new_chunk_count - chunks.len())?;
        }

        let zero = vec![0u8; CHUNK_PLAINTEXT_SIZE];
        while chunks.len() < new_chunk_count {
            let cref = ChunkRef {
                id: self.tree.alloc_chunk_id().ok_or(Error::IdSpaceExhausted)?,
                generation: self.tree.alloc_chunk_gen().ok_or(Error::IdSpaceExhausted)?,
            };
            let chunk_idx = chunks.len() as u32;
            chunk::write_chunk(&mut self.container, &key, id, chunk_idx, cref, &zero)?;
            chunks.push(cref);
        }

        // In hide-size mode, refresh the chunk-0 size header.
        if hide_size && !chunks.is_empty() {
            let mut pt = chunk::read_chunk(&mut self.container, &key, id, 0, chunks[0])?;
            install_size_header(&mut pt, new_size);
            chunks[0].generation = self.tree.alloc_chunk_gen().ok_or(Error::IdSpaceExhausted)?;
            chunk::write_chunk(&mut self.container, &key, id, 0, chunks[0], &pt)?;
        }

        let inode_size_field = if hide_size {
            chunks.len() as u64 * CHUNK_PLAINTEXT_SIZE as u64
        } else {
            new_size
        };
        let inode_mut = self.tree.inodes.get_mut(&id).unwrap();
        inode_mut.chunks = chunks;
        inode_mut.size = inode_size_field;
        if hide_size {
            inode_mut.cached_real_size = Some(new_size);
        }
        self.dirty = true;
        Ok(())
    }

    pub fn unlink(&mut self, parent: FileId, name: &str) -> Result<(), Error> {
        let parent_inode = self.require_dir(parent)?;
        let target_id = *parent_inode.children.get(name).ok_or(Error::NotFound)?;
        let target = self.tree.inodes.get(&target_id).unwrap();
        if target.kind != InodeKind::File {
            return Err(Error::IsADirectory);
        }
        let chunks = target.chunks.clone();
        // v3: also free any chunk-list-block slots the file owns in
        // the data area. Without this they would leak (data area
        // chunks holding stale chunk-list bytes that no inode points
        // at). The blocks themselves stay encrypted on disk; the
        // slots return to free_chunks and get overwritten on the next
        // allocation cycle. v2 vaults leave external_list_blocks
        // empty so this loop is a no-op for them.
        let list_blocks = target.external_list_blocks.clone();
        for cref in chunks {
            self.tree.free_chunk_id(cref.id);
        }
        for cref in list_blocks {
            self.tree.free_chunk_id(cref.id);
        }
        self.tree.inodes.remove(&target_id);
        self.tree
            .inodes
            .get_mut(&parent)
            .unwrap()
            .children
            .remove(name);
        self.dirty = true;
        Ok(())
    }

    pub fn rmdir(&mut self, parent: FileId, name: &str) -> Result<(), Error> {
        let parent_inode = self.require_dir(parent)?;
        let target_id = *parent_inode.children.get(name).ok_or(Error::NotFound)?;
        let target = self.tree.inodes.get(&target_id).unwrap();
        if target.kind != InodeKind::Directory {
            return Err(Error::NotADirectory);
        }
        if !target.children.is_empty() {
            return Err(Error::NotEmpty);
        }
        self.tree.inodes.remove(&target_id);
        self.tree
            .inodes
            .get_mut(&parent)
            .unwrap()
            .children
            .remove(name);
        self.dirty = true;
        Ok(())
    }

    /// Within-directory rename. Cross-directory rename is intentionally not in v1.
    pub fn rename(&mut self, parent: FileId, old_name: &str, new_name: &str) -> Result<(), Error> {
        validate_name(new_name)?;
        let dir = self.tree.inodes.get_mut(&parent).ok_or(Error::NotFound)?;
        if dir.kind != InodeKind::Directory {
            return Err(Error::NotADirectory);
        }
        if dir.children.contains_key(new_name) {
            return Err(Error::AlreadyExists);
        }
        let id = dir.children.remove(old_name).ok_or(Error::NotFound)?;
        dir.children.insert(new_name.to_string(), id);
        self.dirty = true;
        Ok(())
    }

    /// MVK rotation. Re-encrypts every chunk with new MVK-derived file_keys,
    /// re-encrypts the metadata blob with the new MVK-derived metadata_key,
    /// and rebuilds every populated keyslot under fresh random salts, each
    /// slot's user-secret (passphrase, hmac_secret) is preserved but the
    /// wrapped MVK and the AEAD nonce/salt all rotate.
    ///
    /// `credentials` must cover every populated keyslot in the vault. Each
    /// is verified by re-deriving its old KEK and confirming it unlocks the
    /// existing slot to the same MVK currently held by the container; if
    /// any verification fails, no on-disk changes are made.
    ///
    /// **Limitations**:
    /// - Vaults containing a `Fido2DerivedMvk` slot can't be rotated (the
    ///   MVK is YubiKey-derived; rotating it invalidates that derivation).
    /// - **Crash-safety**: inline-header vaults rotate atomically, all
    ///   re-encrypted bytes go to a `<vault>.rotating` temp file that is
    ///   `fsync`'d and atomically renamed over the original at commit.
    ///   A crash before commit leaves the original vault intact; after
    ///   commit, the new vault is durably in place. Detached-header mode
    ///   is NOT yet crash-safe (would need a 2-file commit protocol);
    ///   the rotation runs in-place with a warning. Back up the sidecar
    ///   header before rotating in detached mode.
    pub fn rotate_mvk(
        &mut self,
        credentials: Vec<SlotCredential>,
        kdf_params: luksbox_core::Argon2idParams,
    ) -> Result<(), Error> {
        use luksbox_core::{MasterVolumeKey, SlotKind};

        // Reject any fido2-direct slots upfront.
        for slot in &self.container.header.keyslots {
            if slot.kind == SlotKind::Fido2DerivedMvk {
                return Err(Error::Format(luksbox_format::Error::Crypto(
                    luksbox_core::Error::InvalidField,
                )));
            }
        }

        // Verify the credential set covers every populated slot exactly once.
        let populated: std::collections::BTreeSet<usize> = (0..luksbox_core::MAX_KEYSLOTS)
            .filter(|&i| self.container.header.keyslots[i].kind != SlotKind::Empty)
            .collect();
        let supplied: std::collections::BTreeSet<usize> =
            credentials.iter().map(|c| c.slot_idx()).collect();
        if populated != supplied {
            return Err(Error::Format(luksbox_format::Error::Crypto(
                luksbox_core::Error::InvalidField,
            )));
        }

        // Verify each credential unlocks its slot to the SAME MVK currently
        // held by the container. This is the safety net, if any cred is
        // wrong (typoed passphrase, wrong YubiKey), we abort before
        // touching any chunk.
        let header_salt = *self.container.header_salt();
        let suite = self.container.cipher_suite();
        let current_mvk = self.container.mvk_clone();
        for cred in &credentials {
            let slot = &self.container.header.keyslots[cred.slot_idx()];
            let derived = match cred {
                SlotCredential::Passphrase { passphrase, .. } => {
                    slot.unlock_passphrase(suite, passphrase.as_bytes(), &header_salt)
                }
                SlotCredential::Fido2Wrap {
                    passphrase,
                    hmac_secret_for_verify,
                    ..
                } => slot.unlock_fido2(
                    suite,
                    passphrase.as_ref().map(|p| p.as_bytes()),
                    &*hmac_secret_for_verify,
                    &header_salt,
                ),
            }
            .map_err(|e| Error::Format(luksbox_format::Error::Crypto(e)))?;
            if derived.as_bytes() != current_mvk.as_bytes() {
                return Err(Error::Format(luksbox_format::Error::Crypto(
                    luksbox_core::Error::InvalidField,
                )));
            }
        }

        // All credentials verified. Generate the new MVK.
        let new_mvk = MasterVolumeKey::try_random().map_err(|e| {
            Error::Format(luksbox_format::Error::Crypto(luksbox_core::Error::OsRng(
                e.to_string(),
            )))
        })?;

        // Begin crash-safe rotation if the container supports it (inline
        // mode). All subsequent writes go to a <vault>.rotating temp
        // file; the original is untouched until commit.
        let crash_safe = self.container.supports_atomic_rotation();
        if crash_safe {
            self.container
                .begin_atomic_rotation()
                .map_err(Error::Format)?;
        } else {
            eprintln!(
                "warning: detached-header mode does not support crash-safe \
                 rotation. A crash mid-rotation may leave the vault in a \
                 broken state. Back up the header sidecar before continuing."
            );
        }

        // From here on, any error must trigger abort_atomic_rotation()
        // before returning. Wrap in a closure to centralize cleanup.
        let mut do_rotation = || -> Result<(), Error> {
            // Re-encrypt every chunk: read with old file_key, write with new.
            for (&file_id, inode) in self.tree.inodes.iter() {
                if inode.kind != InodeKind::File {
                    continue;
                }
                for (chunk_idx, chunk_ref) in inode.chunks.iter().enumerate() {
                    let old_fk = chunk::file_key_for_mvk(&current_mvk, &header_salt, file_id);
                    let new_fk = chunk::file_key_for_mvk(&new_mvk, &header_salt, file_id);
                    let mut aad = [0u8; 20];
                    aad[..8].copy_from_slice(&file_id.to_le_bytes());
                    aad[8..12].copy_from_slice(&(chunk_idx as u32).to_le_bytes());
                    aad[12..].copy_from_slice(&chunk_ref.generation.to_le_bytes());
                    self.container
                        .rekey_chunk_at(chunk_ref.id, &*old_fk, &*new_fk, &aad)?;
                }
                // v3: also re-encrypt every chunk-list block this
                // file owns. They live in the same data area but
                // under a synthetic file_id with the high bit set,
                // so the AAD's file_id field uses that synthetic
                // value and the rekey targets a DIFFERENT file_key
                // (`list_file_key_for_mvk`). Without this, post-
                // rotation reads of a spilled file's chunk-list
                // chain would fail AEAD verification (the chain
                // blocks would still be encrypted under the old
                // MVK's list file_key) and the file's data chunks
                // would be unreachable. v2 vaults have empty
                // external_list_blocks so this loop is a no-op for
                // them.
                let list_synth_id = chunk::list_file_id(file_id);
                for (block_idx, block_ref) in inode.external_list_blocks.iter().enumerate() {
                    let old_lfk = chunk::list_file_key_for_mvk(&current_mvk, &header_salt, file_id);
                    let new_lfk = chunk::list_file_key_for_mvk(&new_mvk, &header_salt, file_id);
                    let mut aad = [0u8; 20];
                    aad[..8].copy_from_slice(&list_synth_id.to_le_bytes());
                    aad[8..12].copy_from_slice(&(block_idx as u32).to_le_bytes());
                    aad[12..].copy_from_slice(&block_ref.generation.to_le_bytes());
                    self.container
                        .rekey_chunk_at(block_ref.id, &*old_lfk, &*new_lfk, &aad)?;
                }
            }

            // Re-encrypt the metadata blob with new_mvk's metadata_key.
            self.container.rekey_metadata(&new_mvk)?;

            // Build new keyslots wrapping new_mvk. Each rebuilt slot uses a
            // fresh random kdf_salt / aead_nonce / hmac_salt for forward
            // security.
            use luksbox_core::Keyslot;
            let mut new_slots: Vec<(usize, Keyslot)> = Vec::with_capacity(credentials.len());
            for cred in &credentials {
                let slot = match cred {
                    SlotCredential::Passphrase {
                        slot_idx,
                        passphrase,
                    } => {
                        let s = Keyslot::new_passphrase(
                            suite,
                            &new_mvk,
                            passphrase.as_bytes(),
                            kdf_params,
                            &header_salt,
                        )
                        .map_err(luksbox_format::Error::Crypto)?;
                        (*slot_idx, s)
                    }
                    SlotCredential::Fido2Wrap {
                        slot_idx,
                        passphrase,
                        hmac_secret_for_new_wrap,
                        cred_id,
                        new_hmac_salt,
                        ..
                    } => {
                        let s = Keyslot::new_fido2(
                            suite,
                            &new_mvk,
                            passphrase.as_ref().map(|p| p.as_bytes()),
                            &*hmac_secret_for_new_wrap,
                            cred_id,
                            *new_hmac_salt,
                            kdf_params,
                            &header_salt,
                        )
                        .map_err(luksbox_format::Error::Crypto)?;
                        (*slot_idx, s)
                    }
                };
                new_slots.push(slot);
            }

            self.container
                .install_rotated_mvk_multi(new_mvk.clone(), new_slots)
                .map_err(Error::Format)?;
            self.container.persist_header().map_err(Error::Format)?;
            Ok(())
        };

        let result = do_rotation();

        match (crash_safe, result) {
            (true, Ok(())) => {
                // Commit: fsync + atomic rename. After this returns, the
                // rotated vault is durably installed.
                self.container
                    .commit_atomic_rotation()
                    .map_err(Error::Format)?;
                Ok(())
            }
            (true, Err(e)) => {
                // Abort: discard the temp file, reopen the original. The
                // original is untouched, so the Vfs's in-memory state
                // (which still references the old MVK / chunks) remains
                // valid against the original file.
                let _ = self.container.abort_atomic_rotation();
                Err(e)
            }
            (false, r) => r,
        }
    }

    /// Full MVK rotation for **deniable** vaults: rotates the slot
    /// envelopes AND re-encrypts every chunk + chunk-list block AND
    /// re-encrypts the metadata blob under the new MVK + new
    /// per-vault salt. Companion to `rotate_mvk` for standard vaults.
    ///
    /// Why this exists: `Container::rotate_mvk_v2_deniable` rotates
    /// JUST the slot envelopes — it generates a new MVK + per-vault
    /// salt and rewraps the slot under those, but does NOT re-encrypt
    /// chunks (which were encrypted under the OLD MVK's file_keys).
    /// Calling it on a vault with content silently corrupts the
    /// vault: the next open recovers the new MVK from the envelope,
    /// tries to read chunks with new-MVK-derived file_keys, and
    /// AEAD-fails. This method does the full job.
    ///
    /// v3 (external chunk-list blocks): the same loop re-encrypts
    /// chunk-list blocks under the new MVK's list_file_key. Without
    /// it, a deniable v3 vault would lose access to spilled files
    /// after rotation.
    ///
    /// Crash safety: inline-header deniable vaults support atomic
    /// rotation via the `.rotating` temp file. Detached headers
    /// aren't a thing for deniable (the format requires inline by
    /// design).
    pub fn rotate_mvk_deniable(
        &mut self,
        credentials: Vec<DeniableRotationCredential>,
    ) -> Result<(), Error> {
        use luksbox_core::deniable::DeniableCredential;

        if !self.container.is_deniable() {
            return Err(Error::Format(luksbox_format::Error::Crypto(
                luksbox_core::Error::InvalidField,
            )));
        }

        // 1. Snapshot the OLD state. All chunk + chunk-list block
        //    re-encryption uses these to derive the old file_key /
        //    list_file_key. After `rotate_mvk_v2_deniable` returns,
        //    container.mvk / header.header_salt are the NEW values.
        let old_mvk = self.container.mvk_clone();
        let old_salt = self.container.header.header_salt;

        // 2. Read the metadata blob BEFORE the rotation flips the
        //    container's state — `read_metadata` uses
        //    container.mvk + header_salt to derive metadata_key.
        //    After rotation those values point at the new state,
        //    so a delayed read would AEAD-fail on the still-old
        //    on-disk ciphertext.
        let metadata_plaintext = self.container.read_metadata()?;

        // 3. Begin atomic rotation if supported. All chunk + metadata
        //    writes from here land in <vault>.rotating; the original
        //    file is untouched until commit.
        let crash_safe = self.container.supports_atomic_rotation();
        if crash_safe {
            self.container
                .begin_atomic_rotation()
                .map_err(Error::Format)?;
        }

        let do_rotation = |this: &mut Self| -> Result<(), Error> {
            // 4. Rotate the slot envelopes — generates new_mvk + new_salt
            //    internally and updates container state.
            // Build the borrowed DeniableCredential per row, then
            // hand a borrow vec to rotate_mvk_v2_deniable.
            // build_deniable_credential validates that the optional
            // secondary-factor fields match the kind tag (e.g.
            // Fido2Passphrase requires hmac_secret_output = Some)
            // so a malformed input fails fast with a typed error
            // instead of constructing a wrong DeniableCredential.
            let cred_refs: Vec<(
                usize,
                DeniableCredential<'_>,
                &luksbox_format::deniable_header::DeniableMaterial,
            )> = credentials
                .iter()
                .map(build_borrowed_deniable_credential)
                .collect::<Result<Vec<_>, _>>()?;
            let cred_tuples: Vec<(
                usize,
                &DeniableCredential,
                &luksbox_format::deniable_header::DeniableMaterial,
            )> = cred_refs.iter().map(|(i, c, m)| (*i, c, *m)).collect();
            this.container
                .rotate_mvk_v2_deniable(&cred_tuples)
                .map_err(Error::Format)?;

            // 5. Container now holds the NEW mvk + new salt.
            let new_mvk = this.container.mvk_clone();

            // 6. Re-encrypt every chunk: derive old key from snapshotted
            //    (old_mvk, old_salt); derive new key from (new_mvk,
            //    new_salt). AAD shape is unchanged (file_id ||
            //    chunk_idx || generation).
            for (&file_id, inode) in this.tree.inodes.iter() {
                if inode.kind != InodeKind::File {
                    continue;
                }
                for (chunk_idx, chunk_ref) in inode.chunks.iter().enumerate() {
                    let old_fk = chunk::file_key_for_mvk(&old_mvk, &old_salt, file_id);
                    let new_fk = chunk::file_key_for_mvk(
                        &new_mvk,
                        &this.container.header.header_salt,
                        file_id,
                    );
                    let mut aad = [0u8; 20];
                    aad[..8].copy_from_slice(&file_id.to_le_bytes());
                    aad[8..12].copy_from_slice(&(chunk_idx as u32).to_le_bytes());
                    aad[12..].copy_from_slice(&chunk_ref.generation.to_le_bytes());
                    this.container
                        .rekey_chunk_at(chunk_ref.id, &*old_fk, &*new_fk, &aad)?;
                }
                // v3: chunk-list blocks under the synthetic-file_id
                // list key. Same derivation pattern but via
                // list_file_key_for_mvk.
                let list_synth_id = chunk::list_file_id(file_id);
                for (block_idx, block_ref) in inode.external_list_blocks.iter().enumerate() {
                    let old_lfk = chunk::list_file_key_for_mvk(&old_mvk, &old_salt, file_id);
                    let new_lfk = chunk::list_file_key_for_mvk(
                        &new_mvk,
                        &this.container.header.header_salt,
                        file_id,
                    );
                    let mut aad = [0u8; 20];
                    aad[..8].copy_from_slice(&list_synth_id.to_le_bytes());
                    aad[8..12].copy_from_slice(&(block_idx as u32).to_le_bytes());
                    aad[12..].copy_from_slice(&block_ref.generation.to_le_bytes());
                    this.container
                        .rekey_chunk_at(block_ref.id, &*old_lfk, &*new_lfk, &aad)?;
                }
            }

            // 7. Write the metadata blob under the new state. Container's
            //    write_metadata uses the CURRENT (new) mvk + salt.
            this.container.write_metadata(&metadata_plaintext)?;

            // 8. Persist the rotated deniable header.
            this.container.persist_header().map_err(Error::Format)?;
            Ok(())
        };

        let result = do_rotation(self);

        match (crash_safe, result) {
            (true, Ok(())) => {
                self.container
                    .commit_atomic_rotation()
                    .map_err(Error::Format)?;
                Ok(())
            }
            (true, Err(e)) => {
                let _ = self.container.abort_atomic_rotation();
                Err(e)
            }
            (false, r) => r,
        }
    }

    fn require_dir(&self, id: FileId) -> Result<&Inode, Error> {
        let inode = self.tree.inodes.get(&id).ok_or(Error::NotFound)?;
        if inode.kind != InodeKind::Directory {
            return Err(Error::NotADirectory);
        }
        Ok(inode)
    }
}

fn validate_name(name: &str) -> Result<(), Error> {
    if name.is_empty() || name == "." || name == ".." || name.contains('/') || name.contains('\0') {
        Err(Error::InvalidPath(name.to_string()))
    } else {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use luksbox_core::{Argon2idParams, CipherSuite};
    use luksbox_format::UnlockMaterial;
    use std::path::Path;
    use tempfile::tempdir;

    fn test_params() -> Argon2idParams {
        Argon2idParams {
            m_cost_kib: 8,
            t_cost: 1,
            p_cost: 1,
        }
    }

    fn create_container(path: &Path) -> Container {
        Container::create_with_passphrase(path, None, CipherSuite::Aes256Gcm, test_params(), b"pw")
            .unwrap()
    }

    fn open_container(path: &Path) -> Container {
        Container::open(path, None, UnlockMaterial::Passphrase(b"pw")).unwrap()
    }

    fn write_raw_tree_metadata(container: &mut Container, tree: &DirectoryTree) {
        let payload = postcard::to_allocvec(tree).unwrap();
        let mut bytes = Vec::with_capacity(METADATA_V2_MAGIC.len() + payload.len());
        bytes.extend_from_slice(METADATA_V2_MAGIC);
        bytes.extend_from_slice(&payload);
        container.write_metadata(&bytes).unwrap();
    }

    #[test]
    fn empty_vfs_root_has_no_children() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("a.lbx");
        let c = create_container(&path);
        let vfs = Vfs::open(c).unwrap();
        assert_eq!(vfs.readdir(vfs.root_id()).unwrap().len(), 0);
    }

    #[test]
    fn mkdir_and_readdir() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("a.lbx");
        let mut vfs = Vfs::open(create_container(&path)).unwrap();
        let root = vfs.root_id();
        vfs.mkdir(root, "docs").unwrap();
        vfs.mkdir(root, "src").unwrap();
        let entries = vfs.readdir(root).unwrap();
        let mut names: Vec<_> = entries.iter().map(|e| e.name.as_str()).collect();
        names.sort();
        assert_eq!(names, vec!["docs", "src"]);
    }

    #[test]
    fn write_then_read_small_file() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("a.lbx");
        let mut vfs = Vfs::open(create_container(&path)).unwrap();
        let root = vfs.root_id();
        let f = vfs.create(root, "hello.txt").unwrap();
        let payload = b"hello world";
        let n = vfs.write(f, 0, payload).unwrap();
        assert_eq!(n, payload.len());
        assert_eq!(vfs.stat(f).unwrap().size, payload.len() as u64);
        let mut buf = vec![0u8; payload.len()];
        let r = vfs.read(f, 0, &mut buf).unwrap();
        assert_eq!(r, payload.len());
        assert_eq!(&buf, payload);
    }

    #[test]
    fn write_multi_chunk_file() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("a.lbx");
        let mut vfs = Vfs::open(create_container(&path)).unwrap();
        let root = vfs.root_id();
        let f = vfs.create(root, "big").unwrap();
        let payload: Vec<u8> = (0..10_000).map(|i| (i % 251) as u8).collect();
        vfs.write(f, 0, &payload).unwrap();
        let mut buf = vec![0u8; payload.len()];
        vfs.read(f, 0, &mut buf).unwrap();
        assert_eq!(buf, payload);
    }

    #[test]
    fn read_past_eof_returns_short() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("a.lbx");
        let mut vfs = Vfs::open(create_container(&path)).unwrap();
        let root = vfs.root_id();
        let f = vfs.create(root, "x").unwrap();
        vfs.write(f, 0, b"abc").unwrap();
        let mut buf = [0u8; 100];
        let r = vfs.read(f, 0, &mut buf).unwrap();
        assert_eq!(r, 3);
        assert_eq!(&buf[..3], b"abc");
        let r2 = vfs.read(f, 100, &mut buf).unwrap();
        assert_eq!(r2, 0);
    }

    #[test]
    fn sparse_write_zero_fills_hole() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("a.lbx");
        let mut vfs = Vfs::open(create_container(&path)).unwrap();
        let root = vfs.root_id();
        let f = vfs.create(root, "sparse").unwrap();
        vfs.write(f, 5000, b"tail").unwrap();
        assert_eq!(vfs.stat(f).unwrap().size, 5004);
        let mut buf = vec![0u8; 5004];
        vfs.read(f, 0, &mut buf).unwrap();
        for &b in &buf[..5000] {
            assert_eq!(b, 0);
        }
        assert_eq!(&buf[5000..], b"tail");
    }

    #[test]
    fn overwrite_within_chunk() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("a.lbx");
        let mut vfs = Vfs::open(create_container(&path)).unwrap();
        let root = vfs.root_id();
        let f = vfs.create(root, "x").unwrap();
        vfs.write(f, 0, b"hello world").unwrap();
        vfs.write(f, 6, b"WORLD").unwrap();
        let mut buf = vec![0u8; 11];
        vfs.read(f, 0, &mut buf).unwrap();
        assert_eq!(&buf, b"hello WORLD");
    }

    #[test]
    fn truncate_shrink_frees_chunks() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("a.lbx");
        let mut vfs = Vfs::open(create_container(&path)).unwrap();
        let root = vfs.root_id();
        let f = vfs.create(root, "x").unwrap();
        let payload = vec![0xabu8; 20_000];
        vfs.write(f, 0, &payload).unwrap();
        let chunks_before = vfs.tree.inodes[&f].chunks.len();
        let free_before = vfs.tree.free_chunks.len();
        vfs.truncate(f, 100).unwrap();
        let chunks_after = vfs.tree.inodes[&f].chunks.len();
        let free_after = vfs.tree.free_chunks.len();
        assert!(chunks_after < chunks_before);
        assert!(free_after > free_before);
        assert_eq!(vfs.stat(f).unwrap().size, 100);
    }

    #[test]
    fn truncate_grow_zero_fills() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("a.lbx");
        let mut vfs = Vfs::open(create_container(&path)).unwrap();
        let root = vfs.root_id();
        let f = vfs.create(root, "x").unwrap();
        vfs.write(f, 0, b"hi").unwrap();
        vfs.truncate(f, 6000).unwrap();
        assert_eq!(vfs.stat(f).unwrap().size, 6000);
        let mut buf = vec![0u8; 6000];
        vfs.read(f, 0, &mut buf).unwrap();
        assert_eq!(&buf[..2], b"hi");
        for &b in &buf[2..] {
            assert_eq!(b, 0);
        }
    }

    #[test]
    fn unlink_frees_chunks_for_reuse() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("a.lbx");
        let mut vfs = Vfs::open(create_container(&path)).unwrap();
        let root = vfs.root_id();
        let f = vfs.create(root, "x").unwrap();
        vfs.write(f, 0, &vec![1u8; 8000]).unwrap();
        let next_chunk_id_before = vfs.tree.next_chunk_id;
        vfs.unlink(root, "x").unwrap();
        // create another file and write 8 KB, should reuse the freed chunks
        let g = vfs.create(root, "y").unwrap();
        vfs.write(g, 0, &vec![2u8; 8000]).unwrap();
        // next_chunk_id should not have grown (we reused freed slots)
        assert_eq!(vfs.tree.next_chunk_id, next_chunk_id_before);
    }

    #[test]
    fn rmdir_empty_ok_nonempty_fails() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("a.lbx");
        let mut vfs = Vfs::open(create_container(&path)).unwrap();
        let root = vfs.root_id();
        let _ = vfs.mkdir(root, "d").unwrap();
        vfs.rmdir(root, "d").unwrap();
        assert!(vfs.lookup(root, "d").is_err());

        let d = vfs.mkdir(root, "d").unwrap();
        vfs.create(d, "f").unwrap();
        let r = vfs.rmdir(root, "d");
        assert!(matches!(r, Err(Error::NotEmpty)));
    }

    #[test]
    fn persist_and_reopen() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("a.lbx");
        let payload: Vec<u8> = (0..5000).map(|i| (i & 0xff) as u8).collect();

        {
            let mut vfs = Vfs::open(create_container(&path)).unwrap();
            let root = vfs.root_id();
            vfs.mkdir(root, "d").unwrap();
            let d = vfs.lookup(root, "d").unwrap();
            let f = vfs.create(d, "blob").unwrap();
            vfs.write(f, 0, &payload).unwrap();
            vfs.flush().unwrap();
        }

        let mut vfs = Vfs::open(open_container(&path)).unwrap();
        let root = vfs.root_id();
        let d = vfs.lookup(root, "d").unwrap();
        let f = vfs.lookup(d, "blob").unwrap();
        assert_eq!(vfs.stat(f).unwrap().size, payload.len() as u64);
        let mut buf = vec![0u8; payload.len()];
        vfs.read(f, 0, &mut buf).unwrap();
        assert_eq!(buf, payload);
    }

    #[test]
    fn rename_within_dir() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("a.lbx");
        let mut vfs = Vfs::open(create_container(&path)).unwrap();
        let root = vfs.root_id();
        let f = vfs.create(root, "old").unwrap();
        vfs.write(f, 0, b"hi").unwrap();
        vfs.rename(root, "old", "new").unwrap();
        assert!(vfs.lookup(root, "old").is_err());
        let g = vfs.lookup(root, "new").unwrap();
        assert_eq!(g, f);
    }

    #[test]
    fn write_fails_with_metadata_budget_exhausted_when_region_too_small() {
        // Pre-fix bug: writing more chunks than fit in the metadata
        // region produced silent data loss — the chunks landed on disk
        // but `Vfs::flush` failed at unmount with MetadataTooLarge, so
        // the file was invisible on the next open. With the pre-flight
        // budget check, the FUSE layer now sees the error mid-write
        // and maps it to ENOSPC.
        //
        // We force the condition by creating a vault with the smallest
        // legal metadata region (64 KiB, the CLI floor) so we can hit
        // the wall without writing gigabytes.
        use luksbox_format::metadata::set_create_metadata_region_size_override;
        let dir = tempdir().unwrap();
        let path = dir.path().join("tight.lbx");
        // Explicit v2: v3 spills out of the metadata region so the
        // tight-region wall doesn't trip; v2 IS the format that
        // hits MetadataBudgetExhausted, which is what this test
        // pins.
        let _v2 = set_format_v3_override(Some(false));
        let cont = {
            let _g = set_create_metadata_region_size_override(Some(64 * 1024));
            Container::create_with_passphrase(
                &path,
                None,
                CipherSuite::Aes256Gcm,
                test_params(),
                b"pw",
            )
            .unwrap()
        };
        let mut vfs = Vfs::open(cont).unwrap();
        assert!(!vfs.uses_v3_metadata(), "test precondition");
        let root = vfs.root_id();
        let f = vfs.create(root, "huge").unwrap();

        // Each chunk is 4 KiB. A 64 KiB metadata region holds the AEAD
        // overhead + magic + the tree, so the practical chunk-list
        // ceiling lands well under 10k chunks (= 40 MiB of file data).
        // Try to write 100 MiB; the pre-flight should refuse long
        // before all the chunks are allocated.
        let buf = vec![0xCDu8; 8 * 1024 * 1024]; // 8 MiB at a time
        let mut written = 0u64;
        let final_err: Error = loop {
            match vfs.write(f, written, &buf) {
                Ok(n) => {
                    written += n as u64;
                    if written >= 200 * 1024 * 1024 {
                        panic!(
                            "expected MetadataBudgetExhausted before 200 MiB; got {written} \
                             bytes written without error"
                        );
                    }
                }
                Err(e) => break e,
            }
        };
        assert!(
            matches!(final_err, Error::MetadataBudgetExhausted),
            "expected MetadataBudgetExhausted, got {final_err:?}"
        );
    }

    #[test]
    fn write_succeeds_inside_default_metadata_budget() {
        // Sanity: with the default 16 MiB region, writing well under
        // the budget must succeed — make sure the pre-flight isn't
        // over-aggressive and refusing legitimate writes.
        let dir = tempdir().unwrap();
        let path = dir.path().join("ok.lbx");
        let mut vfs = Vfs::open(create_container(&path)).unwrap();
        let root = vfs.root_id();
        let f = vfs.create(root, "medium").unwrap();
        // 4 MiB file, well within the ~8-10 GiB ceiling of the new
        // default 16 MiB region.
        let buf = vec![0x11u8; 4 * 1024 * 1024];
        vfs.write(f, 0, &buf).unwrap();
        vfs.flush().unwrap();
        // And the same bytes come back.
        let mut got = vec![0u8; buf.len()];
        let n = vfs.read(f, 0, &mut got).unwrap();
        assert_eq!(n, buf.len());
        assert_eq!(got, buf);
    }

    #[test]
    fn truncate_grow_fails_with_metadata_budget_exhausted() {
        // Same guarantee as the write path. truncate-up allocates
        // zero-filled chunks; the pre-flight has to catch the budget
        // bust there too. Force v2 since v3 spills past the wall.
        use luksbox_format::metadata::set_create_metadata_region_size_override;
        let dir = tempdir().unwrap();
        let path = dir.path().join("trunc.lbx");
        let _v2 = set_format_v3_override(Some(false));
        let cont = {
            let _g = set_create_metadata_region_size_override(Some(64 * 1024));
            Container::create_with_passphrase(
                &path,
                None,
                CipherSuite::Aes256Gcm,
                test_params(),
                b"pw",
            )
            .unwrap()
        };
        let mut vfs = Vfs::open(cont).unwrap();
        let root = vfs.root_id();
        let f = vfs.create(root, "to-grow").unwrap();
        // 200 MiB truncate would need ~50k chunks; won't fit.
        let err = vfs.truncate(f, 200 * 1024 * 1024).err().unwrap();
        assert!(
            matches!(err, Error::MetadataBudgetExhausted),
            "expected MetadataBudgetExhausted, got {err:?}"
        );
    }

    #[test]
    fn v3_small_file_stays_inline_no_chunk_list_blocks_written() {
        // Under V3_INLINE_CHUNK_THRESHOLD: even with the v3 format
        // gate flipped on, small files stay inline. Verifies the
        // inline branch of spill_to_v3_on_disk and that there is no
        // extra-chunk allocation overhead for vaults full of small
        // files.
        use crate::tree::V3_INLINE_CHUNK_THRESHOLD;
        let dir = tempdir().unwrap();
        let path = dir.path().join("v3-small.lbx");
        let cont = Container::create_with_passphrase(
            &path,
            None,
            CipherSuite::Aes256Gcm,
            test_params(),
            b"pw",
        )
        .unwrap();
        // Enable v3 only for the freshly-opened Vfs.
        let mut vfs = with_v3_env(|| Vfs::open(cont)).unwrap();
        assert!(vfs.uses_v3_metadata());

        let root = vfs.root_id();
        let f = vfs.create(root, "small").unwrap();
        // Well under the threshold (1024 chunks ~ 4 MiB). 64 KiB
        // requires 16 chunks.
        vfs.write(f, 0, &vec![0x77u8; 64 * 1024]).unwrap();
        let chunk_count_before_flush = vfs.tree.inodes[&f].chunks.len();
        assert!(chunk_count_before_flush < V3_INLINE_CHUNK_THRESHOLD);
        vfs.flush().unwrap();
        // After flush the inode must NOT carry any external list
        // blocks (it fit inline).
        assert!(vfs.tree.inodes[&f].external_list_blocks.is_empty());
        // Round-trip: close + reopen + read.
        drop(vfs);
        let cont = Container::open(&path, None, UnlockMaterial::Passphrase(b"pw")).unwrap();
        let mut vfs = Vfs::open(cont).unwrap();
        assert!(vfs.uses_v3_metadata(), "reopen must detect v3 from LBM3 magic");
        let f = vfs.lookup(vfs.root_id(), "small").unwrap();
        let mut buf = vec![0u8; 64 * 1024];
        let n = vfs.read(f, 0, &mut buf).unwrap();
        assert_eq!(n, 64 * 1024);
        assert!(buf.iter().all(|&b| b == 0x77));
    }

    #[test]
    fn v3_large_file_spills_to_external_chunk_list_blocks() {
        // Above V3_INLINE_CHUNK_THRESHOLD: the inode's chunk list
        // moves out of the metadata region into encrypted chunk-list
        // blocks. The same vault can hold files that would have
        // hard-failed under v2 (1 MiB region) and even under the new
        // v2 default (16 MiB region) once large enough.
        use crate::tree::V3_INLINE_CHUNK_THRESHOLD;
        let dir = tempdir().unwrap();
        let path = dir.path().join("v3-big.lbx");
        let cont = Container::create_with_passphrase(
            &path,
            None,
            CipherSuite::Aes256Gcm,
            test_params(),
            b"pw",
        )
        .unwrap();
        let mut vfs = with_v3_env(|| Vfs::open(cont)).unwrap();
        let root = vfs.root_id();
        let f = vfs.create(root, "big").unwrap();
        // 8 MiB file => 2048 chunks; doubles the threshold (1024)
        // so the chunk list MUST spill, exercising the external-
        // chain write path AND multi-block chunk-list walks (2048 /
        // 254 entries-per-block = 9 chunk-list blocks).
        let size = 8 * 1024 * 1024usize;
        let buf: Vec<u8> = (0..size).map(|i| (i & 0xFF) as u8).collect();
        vfs.write(f, 0, &buf).unwrap();
        let chunks_in_inode = vfs.tree.inodes[&f].chunks.len();
        assert!(
            chunks_in_inode > V3_INLINE_CHUNK_THRESHOLD,
            "expected chunks > threshold, got {chunks_in_inode}"
        );
        vfs.flush().unwrap();
        // Post-flush the inode must record the external list blocks
        // (>= 1 because 2048 chunks > 254 entries-per-block).
        let externals = vfs.tree.inodes[&f].external_list_blocks.clone();
        assert!(
            !externals.is_empty(),
            "v3 spill must record external_list_blocks"
        );
        // Round-trip: close + reopen + read back the whole file.
        drop(vfs);
        let cont = Container::open(&path, None, UnlockMaterial::Passphrase(b"pw")).unwrap();
        let mut vfs = Vfs::open(cont).unwrap();
        assert!(vfs.uses_v3_metadata());
        let f = vfs.lookup(vfs.root_id(), "big").unwrap();
        // After re-open the chunks vec must be materialised back to
        // its original count, AND external_list_blocks must be
        // populated from the walked chain so a follow-on unlink
        // would correctly free them.
        assert_eq!(vfs.tree.inodes[&f].chunks.len(), chunks_in_inode);
        assert_eq!(vfs.tree.inodes[&f].external_list_blocks.len(), externals.len());
        let mut readback = vec![0u8; size];
        let n = vfs.read(f, 0, &mut readback).unwrap();
        assert_eq!(n, size);
        assert_eq!(readback, buf, "byte-for-byte read of a spilled v3 file");
    }

    #[test]
    fn v3_deniable_spill_round_trip() {
        // Smoke test: does the existing LBM3 magic dispatch +
        // chunk-list-block spill work for deniable vaults too? In
        // theory yes, because Container::{read,write}_metadata is
        // format-agnostic (both standard and deniable populate the
        // header.metadata_* fields) and chunk-list blocks live in
        // the data area like any other encrypted chunk. This test
        // pins that hypothesis: create a deniable vault opted into
        // v3, write a spillable file, close, reopen via the deniable
        // path, read back byte-for-byte.
        use luksbox_format::Container;
        let dir = tempdir().unwrap();
        let path = dir.path().join("v3-deniable.lbx");
        let _g = set_format_v3_override(Some(true));
        let cont = Container::create_with_passphrase_deniable(
            &path,
            None,
            CipherSuite::Aes256Gcm,
            test_params(),
            0,
            b"pw",
        )
        .unwrap();
        let mut vfs = Vfs::open(cont).unwrap();
        assert!(vfs.uses_v3_metadata(), "deniable vault must respect the v3 override");
        assert!(vfs.container().is_deniable());
        let root = vfs.root_id();
        let f = vfs.create(root, "big").unwrap();
        let size = 8 * 1024 * 1024usize;
        let payload: Vec<u8> = (0..size).map(|i| ((i * 41) & 0xff) as u8).collect();
        vfs.write(f, 0, &payload).unwrap();
        vfs.flush().unwrap();
        let block_count = vfs.tree.inodes[&f].external_list_blocks.len();
        assert!(
            block_count > 0,
            "deniable v3 vault must spill above V3_INLINE_CHUNK_THRESHOLD"
        );
        drop(vfs);
        drop(_g);

        // Reopen via the deniable open path.
        let cont = Container::open_with_passphrase_deniable(
            &path,
            None,
            b"pw",
            test_params(),
            CipherSuite::Aes256Gcm,
        )
        .unwrap();
        let mut vfs = Vfs::open(cont).unwrap();
        assert!(vfs.uses_v3_metadata());
        assert!(vfs.container().is_deniable());
        let f = vfs.lookup(vfs.root_id(), "big").unwrap();
        let mut got = vec![0u8; size];
        vfs.read(f, 0, &mut got).unwrap();
        assert_eq!(got, payload, "deniable v3 file must round-trip byte-for-byte");
    }

    #[test]
    fn v3_deniable_unlink_frees_external_blocks_same_as_standard() {
        // Smoke-test the cleanup path on deniable v3: unlinking a
        // spilled file must return both its data chunks AND its
        // chunk-list-block ChunkIds to the free pool, same as
        // standard v3. Without this, repeated create/unlink cycles
        // on a deniable v3 vault would leak chunks until the next
        // chunk_id allocation wraps (effectively never).
        use luksbox_format::Container;
        let dir = tempdir().unwrap();
        let path = dir.path().join("v3-deniable-unlink.lbx");
        let _g = set_format_v3_override(Some(true));
        let cont = Container::create_with_passphrase_deniable(
            &path,
            None,
            CipherSuite::Aes256Gcm,
            test_params(),
            0,
            b"pw",
        )
        .unwrap();
        let mut vfs = Vfs::open(cont).unwrap();
        assert!(vfs.uses_v3_metadata() && vfs.container().is_deniable());
        let root = vfs.root_id();
        let f = vfs.create(root, "doomed").unwrap();
        vfs.write(f, 0, &vec![0xBBu8; 8 * 1024 * 1024]).unwrap();
        vfs.flush().unwrap();
        let block_count = vfs.tree.inodes[&f].external_list_blocks.len();
        let data_chunk_count = vfs.tree.inodes[&f].chunks.len();
        assert!(block_count > 0);
        let free_before = vfs.tree.free_chunks.len();
        vfs.unlink(root, "doomed").unwrap();
        assert_eq!(
            vfs.tree.free_chunks.len(),
            free_before + data_chunk_count + block_count,
            "deniable unlink of a spilled file must free data chunks AND chunk-list blocks"
        );
    }

    #[test]
    fn v3_deniable_full_rotate_round_trips_spilled_file() {
        // End-to-end: create a deniable v3 vault, write a spillable
        // file, call the FULL deniable rotation (envelopes + chunks
        // + chunk-list blocks + metadata), close, reopen via the
        // deniable open path, read the file back byte-for-byte.
        // This is the deniable counterpart of
        // `v3_rotate_mvk_reencrypts_chunk_list_blocks`. Catches any
        // regression where the rotation forgets to re-encrypt one
        // of the four artifact kinds.
        use luksbox_format::Container;
        use luksbox_format::deniable_header::DeniableMaterial;
        let dir = tempdir().unwrap();
        let path = dir.path().join("v3-deniable-fullrot.lbx");
        let _g = set_format_v3_override(Some(true));
        let cont = Container::create_with_passphrase_deniable(
            &path,
            None,
            CipherSuite::Aes256Gcm,
            test_params(),
            0,
            b"pw",
        )
        .unwrap();
        let mut vfs = Vfs::open(cont).unwrap();
        assert!(vfs.uses_v3_metadata() && vfs.container().is_deniable());
        let root = vfs.root_id();
        let f = vfs.create(root, "big").unwrap();
        let size = 8 * 1024 * 1024usize;
        let payload: Vec<u8> = (0..size).map(|i| ((i * 13) & 0xff) as u8).collect();
        vfs.write(f, 0, &payload).unwrap();
        vfs.flush().unwrap();
        let block_count = vfs.tree.inodes[&f].external_list_blocks.len();
        assert!(block_count > 0, "test precondition: file must spill");

        // Full deniable rotation: envelopes + chunks + chunk-list
        // blocks + metadata blob all under fresh MVK + per-vault salt.
        let creds = vec![DeniableRotationCredential {
            slot_idx: 0,
            kind: luksbox_core::deniable::DeniableKindTag::Passphrase,
            passphrase: Zeroizing::new(b"pw".to_vec()),
            argon2: test_params(),
            material: DeniableMaterial::passphrase_only(),
            hmac_secret_output: None,
            unsealed: None,
            mlkem_shared: None,
        }];
        vfs.rotate_mvk_deniable(creds).unwrap();
        let _ = vfs.close().unwrap();
        drop(_g);

        // Reopen via the deniable open path; passphrase unchanged.
        let cont = Container::open_with_passphrase_deniable(
            &path,
            None,
            b"pw",
            test_params(),
            CipherSuite::Aes256Gcm,
        )
        .unwrap();
        let mut vfs = Vfs::open(cont).unwrap();
        assert!(vfs.uses_v3_metadata() && vfs.container().is_deniable());
        let f = vfs.lookup(vfs.root_id(), "big").unwrap();
        let mut got = vec![0u8; size];
        vfs.read(f, 0, &mut got).unwrap();
        assert_eq!(
            got, payload,
            "post-rotation deniable v3 file must decrypt byte-for-byte"
        );
    }

    #[test]
    fn v2_deniable_full_rotate_round_trips_inline_file() {
        // Same as above but for v2 deniable (no chunk-list blocks).
        // Confirms the rotation method works for plain v2 deniable too,
        // since the bug was pre-existing across both formats.
        use luksbox_format::Container;
        use luksbox_format::deniable_header::DeniableMaterial;
        let dir = tempdir().unwrap();
        let path = dir.path().join("v2-deniable-fullrot.lbx");
        // Force v2 explicitly: this test exists to pin v2-deniable
        // rotation; v3 is the default now.
        let _v2 = set_format_v3_override(Some(false));
        let cont = Container::create_with_passphrase_deniable(
            &path,
            None,
            CipherSuite::Aes256Gcm,
            test_params(),
            0,
            b"pw",
        )
        .unwrap();
        let mut vfs = Vfs::open(cont).unwrap();
        assert!(!vfs.uses_v3_metadata() && vfs.container().is_deniable());
        let root = vfs.root_id();
        let f = vfs.create(root, "small").unwrap();
        let payload = vec![0xC9u8; 64 * 1024];
        vfs.write(f, 0, &payload).unwrap();
        vfs.flush().unwrap();
        assert!(vfs.tree.inodes[&f].external_list_blocks.is_empty());

        let creds = vec![DeniableRotationCredential {
            slot_idx: 0,
            kind: luksbox_core::deniable::DeniableKindTag::Passphrase,
            passphrase: Zeroizing::new(b"pw".to_vec()),
            argon2: test_params(),
            material: DeniableMaterial::passphrase_only(),
            hmac_secret_output: None,
            unsealed: None,
            mlkem_shared: None,
        }];
        vfs.rotate_mvk_deniable(creds).unwrap();
        let _ = vfs.close().unwrap();

        let cont = Container::open_with_passphrase_deniable(
            &path,
            None,
            b"pw",
            test_params(),
            CipherSuite::Aes256Gcm,
        )
        .unwrap();
        let mut vfs = Vfs::open(cont).unwrap();
        let f = vfs.lookup(vfs.root_id(), "small").unwrap();
        let mut got = vec![0u8; payload.len()];
        vfs.read(f, 0, &mut got).unwrap();
        assert_eq!(got, payload, "post-rotation v2 deniable file must decrypt");
    }

    /// Perf measurement for v3 open with progressively larger
    /// spilled files. NOT part of regular CI (marked `#[ignore]`).
    /// Run manually with:
    ///   cargo test -p luksbox-vfs --release -- --ignored \
    ///       --nocapture v3_open_perf_baseline
    ///
    /// The point is to establish a baseline for the v3 open cost so
    /// we know whether lazy loading is needed before flipping the
    /// default. Reports wall time for create + open + read at three
    /// vault sizes; extrapolate to estimate huge-vault performance.
    #[test]
    #[ignore = "perf benchmark; run with --ignored --release"]
    fn v3_open_perf_baseline() {
        use std::time::Instant;
        for &mib in &[64usize, 256, 1024] {
            let dir = tempdir().unwrap();
            let path = dir.path().join(format!("perf-{mib}m.lbx"));
            let _g = set_format_v3_override(Some(true));
            let cont = Container::create_with_passphrase(
                &path,
                None,
                CipherSuite::Aes256Gcm,
                test_params(),
                b"pw",
            )
            .unwrap();
            let mut vfs = Vfs::open(cont).unwrap();
            let root = vfs.root_id();
            let f = vfs.create(root, "big").unwrap();

            let t_write = Instant::now();
            let chunk = vec![0xCDu8; 4 * 1024 * 1024]; // 4 MiB at a time
            let total = mib * 1024 * 1024;
            let mut off = 0u64;
            while (off as usize) < total {
                let want = std::cmp::min(chunk.len(), total - off as usize);
                vfs.write(f, off, &chunk[..want]).unwrap();
                off += want as u64;
            }
            vfs.flush().unwrap();
            let write_ms = t_write.elapsed().as_millis();
            let list_blocks = vfs.tree.inodes[&f].external_list_blocks.len();
            let chunks = vfs.tree.inodes[&f].chunks.len();
            drop(vfs);
            drop(_g);

            let t_open = Instant::now();
            let cont = Container::open(&path, None, UnlockMaterial::Passphrase(b"pw")).unwrap();
            let mut vfs = Vfs::open(cont).unwrap();
            let open_ms = t_open.elapsed().as_millis();

            let t_read = Instant::now();
            let f = vfs.lookup(vfs.root_id(), "big").unwrap();
            let mut buf = vec![0u8; 4 * 1024 * 1024];
            let mut off = 0u64;
            while off < total as u64 {
                let want = ((total as u64 - off).min(buf.len() as u64)) as usize;
                vfs.read(f, off, &mut buf[..want]).unwrap();
                off += want as u64;
            }
            let read_ms = t_read.elapsed().as_millis();

            eprintln!(
                "v3 perf {mib} MiB: chunks={chunks} list-blocks={list_blocks} \
                 write={write_ms}ms open={open_ms}ms read={read_ms}ms"
            );
        }
    }

    #[test]
    fn v3_deniable_fido2_passphrase_full_rotate_round_trips() {
        // Same crypto invariant as v3_deniable_full_rotate_round_trips_spilled_file
        // but for a FIDO2Passphrase deniable slot. Confirms the
        // build_borrowed_deniable_credential dispatch correctly
        // constructs a Fido2Passphrase variant with the supplied
        // hmac_secret_output, and the rotation completes end-to-end.
        use luksbox_core::deniable::DeniableCredential;
        use luksbox_core::deniable::DeniableKindTag;
        use luksbox_format::Container;
        use luksbox_format::deniable_header::DeniableMaterial;
        let dir = tempdir().unwrap();
        let path = dir.path().join("v3-deniable-fido2-rot.lbx");
        let hmac = [0xaau8; 32];
        let material = DeniableMaterial {
            cred_id: vec![0xcd; 64],
            hmac_salt: Some([0xef; 32]),
            tpm_blob: Vec::new(),
        };
        let cred = DeniableCredential::Fido2Passphrase {
            passphrase: b"pw",
            argon2: test_params(),
            hmac_secret_output: &hmac,
        };
        let _g = set_format_v3_override(Some(true));
        let cont = Container::create_with_credential_v2_deniable(
            &path,
            None,
            CipherSuite::Aes256Gcm,
            0,
            1, // slot_idx
            &cred,
            &material,
        )
        .unwrap();
        let mut vfs = Vfs::open(cont).unwrap();
        assert!(vfs.uses_v3_metadata() && vfs.container().is_deniable());
        // Write a small payload (no need to spill — tests the
        // FIDO2-bound rotation independently of v3 spill mechanics).
        let root = vfs.root_id();
        let f = vfs.create(root, "data").unwrap();
        let payload = vec![0x7Fu8; 16 * 1024];
        vfs.write(f, 0, &payload).unwrap();
        vfs.flush().unwrap();

        let rot_cred = DeniableRotationCredential {
            slot_idx: 1,
            kind: DeniableKindTag::Fido2Passphrase,
            passphrase: Zeroizing::new(b"pw".to_vec()),
            argon2: test_params(),
            material,
            hmac_secret_output: Some(Zeroizing::new(hmac)),
            unsealed: None,
            mlkem_shared: None,
        };
        vfs.rotate_mvk_deniable(vec![rot_cred]).unwrap();
        let _ = vfs.close().unwrap();
        drop(_g);

        // Reopen via the FIDO2-deniable two-phase open path.
        let cred_reopen = DeniableCredential::Fido2Passphrase {
            passphrase: b"pw",
            argon2: test_params(),
            hmac_secret_output: &hmac,
        };
        let env = Container::try_open_envelope_v2_deniable(
            &path,
            None,
            &cred_reopen,
            CipherSuite::Aes256Gcm,
        )
        .unwrap();
        let cont = Container::complete_open_v2_deniable(env, &cred_reopen).unwrap();
        let mut vfs = Vfs::open(cont).unwrap();
        assert!(vfs.uses_v3_metadata() && vfs.container().is_deniable());
        let f = vfs.lookup(vfs.root_id(), "data").unwrap();
        let mut got = vec![0u8; payload.len()];
        vfs.read(f, 0, &mut got).unwrap();
        assert_eq!(got, payload);
    }

    #[test]
    fn deniable_rotation_credential_kind_mismatch_refused() {
        // build_borrowed_deniable_credential validates that the kind
        // tag matches the present Option fields. Passing a Passphrase
        // kind with hmac_secret_output set must be refused; passing a
        // Fido2Passphrase kind without hmac_secret_output must be
        // refused. Catches caller bugs before they propagate into a
        // mis-built DeniableCredential at the AEAD layer.
        use luksbox_core::deniable::DeniableKindTag;
        use luksbox_format::Container;
        use luksbox_format::deniable_header::DeniableMaterial;
        let dir = tempdir().unwrap();
        let path = dir.path().join("dummy.lbx");
        let cont = Container::create_with_passphrase_deniable(
            &path,
            None,
            CipherSuite::Aes256Gcm,
            test_params(),
            0,
            b"pw",
        )
        .unwrap();
        let mut vfs = Vfs::open(cont).unwrap();

        // Case 1: Passphrase kind with stray hmac_secret_output.
        let bad1 = DeniableRotationCredential {
            slot_idx: 0,
            kind: DeniableKindTag::Passphrase,
            passphrase: Zeroizing::new(b"pw".to_vec()),
            argon2: test_params(),
            material: DeniableMaterial::passphrase_only(),
            hmac_secret_output: Some(Zeroizing::new([0u8; 32])),
            unsealed: None,
            mlkem_shared: None,
        };
        assert!(matches!(
            vfs.rotate_mvk_deniable(vec![bad1]),
            Err(Error::Format(_))
        ));

        // Case 2: Fido2Passphrase kind missing hmac_secret_output.
        let bad2 = DeniableRotationCredential {
            slot_idx: 0,
            kind: DeniableKindTag::Fido2Passphrase,
            passphrase: Zeroizing::new(b"pw".to_vec()),
            argon2: test_params(),
            material: DeniableMaterial::passphrase_only(),
            hmac_secret_output: None,
            unsealed: None,
            mlkem_shared: None,
        };
        assert!(matches!(
            vfs.rotate_mvk_deniable(vec![bad2]),
            Err(Error::Format(_))
        ));
    }

    #[test]
    fn rotate_mvk_deniable_refuses_standard_vault() {
        // The deniable rotation path uses Container::rotate_mvk_v2_deniable
        // internally, which panics on a non-deniable container. Refuse
        // at the Vfs boundary with a clean error so callers get a
        // typed Error::Crypto instead.
        use luksbox_format::Container;
        use luksbox_format::deniable_header::DeniableMaterial;
        let dir = tempdir().unwrap();
        let path = dir.path().join("standard.lbx");
        let cont = Container::create_with_passphrase(
            &path,
            None,
            CipherSuite::Aes256Gcm,
            test_params(),
            b"pw",
        )
        .unwrap();
        let mut vfs = Vfs::open(cont).unwrap();
        let creds = vec![DeniableRotationCredential {
            slot_idx: 0,
            kind: luksbox_core::deniable::DeniableKindTag::Passphrase,
            passphrase: Zeroizing::new(b"pw".to_vec()),
            argon2: test_params(),
            material: DeniableMaterial::passphrase_only(),
            hmac_secret_output: None,
            unsealed: None,
            mlkem_shared: None,
        }];
        let err = vfs.rotate_mvk_deniable(creds).unwrap_err();
        assert!(matches!(err, Error::Format(_)));
    }

    #[test]
    fn v3_migration_copies_files_byte_for_byte_across_formats() {
        // Models the `luksbox migrate-to-v3` flow at the VFS layer:
        // open a v2 vault, write some files (including one spillable
        // under v3 but inline under v2), open a fresh v3 vault, copy
        // the tree across, verify every byte matches in the new
        // vault. This is the cross-format read-then-write path the
        // CLI migration depends on; if VFS::read or write disagrees
        // between formats, migration would silently corrupt data.
        let dir = tempdir().unwrap();
        let v2_path = dir.path().join("src-v2.lbx");
        let v3_path = dir.path().join("dst-v3.lbx");

        // 1. Create a v2 vault + populate it. Force v2 explicitly
        // since v3 is the default now.
        let v2_guard = set_format_v3_override(Some(false));
        let cont_v2 = Container::create_with_passphrase(
            &v2_path,
            None,
            CipherSuite::Aes256Gcm,
            test_params(),
            b"pw",
        )
        .unwrap();
        // The guard must stay alive across Vfs::open — that's where
        // the format is actually picked (the fresh-vault branch reads
        // the thread-local).
        let mut src = Vfs::open(cont_v2).unwrap();
        drop(v2_guard);
        assert!(!src.uses_v3_metadata());
        let root = src.root_id();
        let sub = src.mkdir(root, "sub").unwrap();
        let f1 = src.create(root, "small.txt").unwrap();
        src.write(f1, 0, b"hello world").unwrap();
        let f2 = src.create(sub, "nested.bin").unwrap();
        let payload: Vec<u8> = (0..4096 * 5).map(|i| (i * 17) as u8).collect();
        src.write(f2, 0, &payload).unwrap();
        src.flush().unwrap();

        // 2. Create the destination as v3. The override must stay
        // alive until Vfs::open reads the env-or-thread-local on
        // the EMPTY metadata-blob branch.
        let _g = set_format_v3_override(Some(true));
        let cont_v3 = Container::create_with_passphrase(
            &v3_path,
            None,
            CipherSuite::Aes256Gcm,
            test_params(),
            b"pw",
        )
        .unwrap();
        let mut dst = Vfs::open(cont_v3).unwrap();
        drop(_g);
        assert!(dst.uses_v3_metadata());

        // 3. Copy: same recursive walk the CLI migrate uses.
        fn copy(src: &mut Vfs, sdir: FileId, dst: &mut Vfs, ddir: FileId) {
            let entries = src.readdir(sdir).unwrap();
            for e in entries {
                let st = src.stat(e.id).unwrap();
                match st.kind {
                    InodeKind::Directory => {
                        let nd = dst.mkdir(ddir, &e.name).unwrap();
                        copy(src, e.id, dst, nd);
                    }
                    InodeKind::File => {
                        let nf = dst.create(ddir, &e.name).unwrap();
                        let mut buf = vec![0u8; 65536];
                        let mut off = 0u64;
                        while off < st.size {
                            let want = (st.size - off).min(buf.len() as u64) as usize;
                            let n = src.read(e.id, off, &mut buf[..want]).unwrap();
                            if n == 0 {
                                break;
                            }
                            dst.write(nf, off, &buf[..n]).unwrap();
                            off += n as u64;
                        }
                    }
                }
            }
        }
        let dst_root = dst.root_id();
        copy(&mut src, root, &mut dst, dst_root);
        dst.flush().unwrap();
        drop(src);
        drop(dst);

        // 4. Verify by reopening dst.
        let cont = Container::open(&v3_path, None, UnlockMaterial::Passphrase(b"pw")).unwrap();
        let mut dst = Vfs::open(cont).unwrap();
        assert!(dst.uses_v3_metadata());
        let f1 = dst.lookup_path("/small.txt").unwrap();
        let mut buf = vec![0u8; 11];
        dst.read(f1, 0, &mut buf).unwrap();
        assert_eq!(&buf, b"hello world");
        let f2 = dst.lookup_path("/sub/nested.bin").unwrap();
        let mut back = vec![0u8; payload.len()];
        dst.read(f2, 0, &mut back).unwrap();
        assert_eq!(back, payload);
    }

    #[test]
    fn v3_truncate_down_through_threshold_frees_external_blocks() {
        // A file that was above V3_INLINE_CHUNK_THRESHOLD and got
        // truncated below it must (a) keep working, (b) have its
        // external chunk-list blocks freed back to the data area at
        // the next flush. Without the spill-then-free logic, the
        // blocks would leak and the file's chunks would still
        // appear "spilled" on next open even though they now fit
        // inline.
        let dir = tempdir().unwrap();
        let path = dir.path().join("v3-trunc.lbx");
        let cont = Container::create_with_passphrase(
            &path,
            None,
            CipherSuite::Aes256Gcm,
            test_params(),
            b"pw",
        )
        .unwrap();
        let mut vfs = with_v3_env(|| Vfs::open(cont)).unwrap();
        let root = vfs.root_id();
        let f = vfs.create(root, "shrinker").unwrap();

        // Grow well past threshold (8 MiB ~ 2048 chunks > 1024).
        vfs.write(f, 0, &vec![0x55u8; 8 * 1024 * 1024]).unwrap();
        vfs.flush().unwrap();
        let blocks_after_grow = vfs.tree.inodes[&f].external_list_blocks.len();
        assert!(blocks_after_grow > 0);
        let free_after_grow = vfs.tree.free_chunks.len();

        // Shrink to 64 KiB (16 chunks, way below threshold).
        vfs.truncate(f, 64 * 1024).unwrap();
        vfs.flush().unwrap();
        // External blocks must be gone now: chunks.len() <=
        // V3_INLINE_CHUNK_THRESHOLD => spill_to_v3_on_disk frees
        // them and writes the inode inline.
        assert!(
            vfs.tree.inodes[&f].external_list_blocks.is_empty(),
            "post-shrink, external_list_blocks must be empty"
        );
        // The block ChunkIds should have returned to free_chunks
        // (plus the data chunks freed by the truncate-down itself).
        assert!(
            vfs.tree.free_chunks.len() > free_after_grow,
            "shrink must return chunk-list block IDs to free_chunks"
        );

        // Round-trip: reopen + read the surviving 64 KiB.
        let _ = vfs.close().unwrap();
        let cont = Container::open(&path, None, UnlockMaterial::Passphrase(b"pw")).unwrap();
        let mut vfs = Vfs::open(cont).unwrap();
        let f = vfs.lookup(vfs.root_id(), "shrinker").unwrap();
        assert!(vfs.tree.inodes[&f].external_list_blocks.is_empty());
        let mut buf = vec![0u8; 64 * 1024];
        vfs.read(f, 0, &mut buf).unwrap();
        assert!(buf.iter().all(|&b| b == 0x55));
    }

    #[test]
    fn v3_unlink_frees_external_list_blocks() {
        // Without the v3 cleanup in unlink, the chunk-list blocks
        // would leak: their ChunkIds would never return to
        // free_chunks and the slots would never be reused.
        let dir = tempdir().unwrap();
        let path = dir.path().join("v3-unlink.lbx");
        let cont = Container::create_with_passphrase(
            &path,
            None,
            CipherSuite::Aes256Gcm,
            test_params(),
            b"pw",
        )
        .unwrap();
        let mut vfs = with_v3_env(|| Vfs::open(cont)).unwrap();
        let root = vfs.root_id();
        let f = vfs.create(root, "doomed").unwrap();
        vfs.write(f, 0, &vec![0xAAu8; 8 * 1024 * 1024]).unwrap();
        vfs.flush().unwrap();
        let block_count = vfs.tree.inodes[&f].external_list_blocks.len();
        let data_chunk_count = vfs.tree.inodes[&f].chunks.len();
        assert!(block_count > 0);
        let free_before = vfs.tree.free_chunks.len();

        vfs.unlink(root, "doomed").unwrap();
        // All data chunks AND all chunk-list blocks must have come
        // back to the free pool.
        assert_eq!(
            vfs.tree.free_chunks.len(),
            free_before + data_chunk_count + block_count,
            "unlink of a spilled file must free both data chunks AND chunk-list blocks"
        );
    }

    /// Thread-local v3 override for tests. Race-free across parallel
    /// `cargo test` runs because the override is per-thread, unlike
    /// the env var which is process-global.
    fn with_v3_env<T>(f: impl FnOnce() -> T) -> T {
        let _g = super::set_format_v3_override(Some(true));
        f()
    }

    #[test]
    fn override_metadata_size_is_stored_in_header() {
        // The thread-local override must end up in the on-disk header
        // so that the next open sees the same region size. Without
        // this, the open-side read would assume the default and the
        // write/read offsets would slide.
        use luksbox_format::metadata::set_create_metadata_region_size_override;
        let dir = tempdir().unwrap();
        let path = dir.path().join("custom.lbx");
        let custom = 2 * 1024 * 1024u64; // 2 MiB
        let cont = {
            let _g = set_create_metadata_region_size_override(Some(custom));
            Container::create_with_passphrase(
                &path,
                None,
                CipherSuite::Aes256Gcm,
                test_params(),
                b"pw",
            )
            .unwrap()
        };
        assert_eq!(cont.header.metadata_size, custom);
        drop(cont);

        // And the open-side recovers the same value.
        let reopened = Container::open(&path, None, UnlockMaterial::Passphrase(b"pw")).unwrap();
        assert_eq!(reopened.header.metadata_size, custom);
    }

    #[test]
    fn rotate_mvk_multi_slot_passphrase() {
        use luksbox_format::Container;
        use zeroize::Zeroizing;
        let dir = tempdir().unwrap();
        let path = dir.path().join("rot.lbx");
        // Create vault, enroll a 2nd passphrase slot.
        let mut cont = Container::create_with_passphrase(
            &path,
            None,
            CipherSuite::Aes256Gcm,
            test_params(),
            b"alpha",
        )
        .unwrap();
        cont.enroll_passphrase(b"beta", test_params()).unwrap();
        cont.persist_header().unwrap();
        // Write a multi-chunk payload.
        let payload: Vec<u8> = (0..15_000).map(|i| (i & 0xff) as u8).collect();
        let mut vfs = Vfs::open(cont).unwrap();
        let root = vfs.root_id();
        let f = vfs.create(root, "blob").unwrap();
        vfs.write(f, 0, &payload).unwrap();
        vfs.flush().unwrap();
        // Rotate, supplying credentials for both slots.
        let creds = vec![
            SlotCredential::Passphrase {
                slot_idx: 0,
                passphrase: Zeroizing::new("alpha".to_string()),
            },
            SlotCredential::Passphrase {
                slot_idx: 1,
                passphrase: Zeroizing::new("beta".to_string()),
            },
        ];
        vfs.rotate_mvk(creds, test_params()).unwrap();
        vfs.flush().unwrap();
        // Drop everything and re-open with each passphrase to confirm
        // both still work + data is intact.
        let _ = vfs.close().unwrap();
        for pw in [b"alpha".as_ref(), b"beta".as_ref()] {
            let cont = Container::open(&path, None, UnlockMaterial::Passphrase(pw)).unwrap();
            let mut vfs = Vfs::open(cont).unwrap();
            let f = vfs.lookup_path("/blob").unwrap();
            let mut buf = vec![0u8; payload.len()];
            vfs.read(f, 0, &mut buf).unwrap();
            assert_eq!(
                buf,
                payload,
                "after rotation: payload mismatch via {:?}",
                String::from_utf8_lossy(pw)
            );
        }
    }

    #[test]
    fn v3_budget_check_permits_writes_a_v2_vault_would_refuse() {
        // The reason v3 exists: v2 vaults with a tight metadata
        // region (or even the new 16 MiB default) hit the budget
        // check around ~10 GiB of stored content because the
        // per-chunk ChunkRef list grows linearly in the metadata
        // blob. v3 spills that list out so the metadata blob stays
        // small no matter how many chunks the file has. This test
        // exercises the budget check directly: build a v3 vault
        // with a small metadata region (so the v2 budget would
        // explode at a fraction of the file size), write enough
        // chunks to far exceed the v2 ceiling, confirm the budget
        // check still permits the writes.
        use luksbox_format::metadata::set_create_metadata_region_size_override;
        let dir = tempdir().unwrap();
        let path = dir.path().join("v3-budget.lbx");
        // 256 KiB metadata region (well below the default 16 MiB).
        // A v2 vault with this region would max out at a few
        // thousand chunks. v3 must blow past that comfortably.
        let cont = {
            let _g = set_create_metadata_region_size_override(Some(256 * 1024));
            let _v3 = set_format_v3_override(Some(true));
            Container::create_with_passphrase(
                &path,
                None,
                CipherSuite::Aes256Gcm,
                test_params(),
                b"pw",
            )
            .unwrap()
        };
        let mut vfs = with_v3_env(|| Vfs::open(cont)).unwrap();
        assert!(vfs.uses_v3_metadata());

        let root = vfs.root_id();
        let f = vfs.create(root, "huge").unwrap();
        // 12 MiB at 4 KiB per chunk = 3072 chunks; v2 with a 256 KiB
        // region would refuse around chunk ~5000. 3072 is well past
        // V3_INLINE_CHUNK_THRESHOLD (1024), so the file spills and
        // the budget check must permit it.
        let size = 12 * 1024 * 1024usize;
        let buf = vec![0xEEu8; size];
        let n = vfs.write(f, 0, &buf).unwrap();
        assert_eq!(n, size);
        // Sanity: actually spills.
        assert!(vfs.tree.inodes[&f].chunks.len() > V3_INLINE_CHUNK_THRESHOLD);
        // Flush + reopen + read.
        vfs.flush().unwrap();
        drop(vfs);
        let cont = Container::open(&path, None, UnlockMaterial::Passphrase(b"pw")).unwrap();
        let mut vfs = Vfs::open(cont).unwrap();
        let f = vfs.lookup(vfs.root_id(), "huge").unwrap();
        let mut got = vec![0u8; size];
        vfs.read(f, 0, &mut got).unwrap();
        assert_eq!(got, buf);
    }

    #[test]
    fn v2_budget_check_still_refuses_oversize_in_tight_region() {
        // Mirror of the test above for v2: same tight region, same
        // big write — must still trip MetadataBudgetExhausted.
        // Catches a regression where the v2 branch of
        // check_metadata_budget_for_chunks gets accidentally loosened.
        // Force v2 explicitly since v3 is the default now.
        use luksbox_format::metadata::set_create_metadata_region_size_override;
        let dir = tempdir().unwrap();
        let path = dir.path().join("v2-tight.lbx");
        let _v2 = set_format_v3_override(Some(false));
        let cont = {
            let _g = set_create_metadata_region_size_override(Some(64 * 1024));
            Container::create_with_passphrase(
                &path,
                None,
                CipherSuite::Aes256Gcm,
                test_params(),
                b"pw",
            )
            .unwrap()
        };
        let mut vfs = Vfs::open(cont).unwrap();
        assert!(!vfs.uses_v3_metadata(), "test precondition: must be v2");

        let root = vfs.root_id();
        let f = vfs.create(root, "huge").unwrap();
        let buf = vec![0x11u8; 8 * 1024 * 1024];
        let mut written = 0usize;
        let final_err = loop {
            match vfs.write(f, written as u64, &buf) {
                Ok(n) => {
                    written += n;
                    if written >= 200 * 1024 * 1024 {
                        panic!("v2 budget should have tripped before 200 MiB");
                    }
                }
                Err(e) => break e,
            }
        };
        assert!(matches!(final_err, Error::MetadataBudgetExhausted));
    }

    #[test]
    fn v3_aad_isolation_data_chunks_and_list_blocks_cannot_be_swapped() {
        // Crypto invariant: even though data chunks and chunk-list
        // blocks share the same data area, their AEAD keys (file_key
        // vs list_file_key) and AADs (file_id vs synthetic file_id
        // with high bit set) are disjoint by construction. An
        // attacker who somehow places a data chunk's ciphertext into
        // a chunk-list block's slot (or vice versa) cannot make it
        // decrypt — even with full MVK access, derivation of the
        // "wrong" key for the slot is what the AAD-shape difference
        // catches.
        use crate::chunk::{file_key, list_file_key, read_chunk, walk_chunk_list_chain};
        use crate::tree::CHUNK_LIST_FILE_ID_BIT;

        let dir = tempdir().unwrap();
        let path = dir.path().join("v3-aad.lbx");
        let cont = Container::create_with_passphrase(
            &path,
            None,
            CipherSuite::Aes256Gcm,
            test_params(),
            b"pw",
        )
        .unwrap();
        let mut vfs = with_v3_env(|| Vfs::open(cont)).unwrap();
        let root = vfs.root_id();
        let f = vfs.create(root, "spill").unwrap();
        // 8 MiB => spills, generates several chunk-list blocks.
        vfs.write(f, 0, &vec![0x33u8; 8 * 1024 * 1024]).unwrap();
        vfs.flush().unwrap();

        let file_id = f;
        let data_chunk_ref = vfs.tree.inodes[&f].chunks[0];
        let list_block_ref = vfs.tree.inodes[&f].external_list_blocks[0];

        // 1. Decrypting the data chunk under the DATA file_key
        //    must succeed (sanity).
        let data_key = file_key(&vfs.container, file_id);
        let _data_plaintext = read_chunk(&mut vfs.container, &data_key, file_id, 0, data_chunk_ref)
            .expect("data chunk must decrypt under data key");

        // 2. Decrypting the data chunk under the LIST file_key with
        //    the LIST AAD shape (synthetic file_id, block_idx) must
        //    FAIL — wrong key + wrong AAD.
        let list_key = list_file_key(&vfs.container, file_id);
        let synth_id = file_id | CHUNK_LIST_FILE_ID_BIT;
        let err = read_chunk(&mut vfs.container, &list_key, synth_id, 0, data_chunk_ref)
            .err()
            .expect("data chunk must NOT decrypt under list key");
        // Crypto error of some kind — we don't care which variant,
        // just that the AEAD refused.
        assert!(matches!(err, Error::Crypto(_)), "expected AEAD failure, got {err:?}");

        // 3. Decrypting the list block under the DATA file_key with
        //    the DATA AAD shape (real file_id, chunk_idx=0) must
        //    also FAIL — symmetric guarantee.
        let err = read_chunk(&mut vfs.container, &data_key, file_id, 0, list_block_ref)
            .err()
            .expect("list block must NOT decrypt under data key");
        assert!(matches!(err, Error::Crypto(_)), "expected AEAD failure, got {err:?}");

        // 4. The legitimate walk over the chain MUST still succeed —
        //    this is the positive control.
        let head = list_block_ref;
        let expected_count = vfs.tree.inodes[&f].chunks.len() as u64;
        let (walked, _blocks) =
            walk_chunk_list_chain(&mut vfs.container, file_id, head, expected_count)
                .expect("legitimate walk must succeed");
        assert_eq!(walked.len() as u64, expected_count);
    }

    #[test]
    fn v3_rotate_mvk_reencrypts_chunk_list_blocks() {
        // Without re-encrypting chunk-list blocks under the new MVK,
        // post-rotation reads of a v3-spilled file would AEAD-fail
        // on the FIRST chunk-list block lookup (the synthetic
        // list_file_key would not match what's on disk). The file's
        // data chunks would be unreachable and the file would
        // effectively be lost. Verifies the rotation loop now walks
        // external_list_blocks alongside chunks.
        use luksbox_format::Container;
        use zeroize::Zeroizing;
        let dir = tempdir().unwrap();
        let path = dir.path().join("v3-rot.lbx");
        let cont = Container::create_with_passphrase(
            &path,
            None,
            CipherSuite::Aes256Gcm,
            test_params(),
            b"alpha",
        )
        .unwrap();
        // Create vault as v3 + write a file that spills.
        let mut vfs = with_v3_env(|| Vfs::open(cont)).unwrap();
        assert!(vfs.uses_v3_metadata());
        let root = vfs.root_id();
        let f = vfs.create(root, "big").unwrap();
        let size = 8 * 1024 * 1024usize;
        let payload: Vec<u8> = (0..size).map(|i| ((i * 31) & 0xff) as u8).collect();
        vfs.write(f, 0, &payload).unwrap();
        vfs.flush().unwrap();
        let blocks_before = vfs.tree.inodes[&f].external_list_blocks.len();
        assert!(blocks_before > 0, "test precondition: file must have spilled");

        // Rotate.
        let creds = vec![SlotCredential::Passphrase {
            slot_idx: 0,
            passphrase: Zeroizing::new("alpha".to_string()),
        }];
        vfs.rotate_mvk(creds, test_params()).unwrap();
        vfs.flush().unwrap();
        let _ = vfs.close().unwrap();

        // Reopen + read the whole file. The chunk-list-block walk
        // and every chunk decrypt MUST succeed under the new MVK.
        let cont = Container::open(&path, None, UnlockMaterial::Passphrase(b"alpha")).unwrap();
        let mut vfs = Vfs::open(cont).unwrap();
        let f = vfs.lookup(vfs.root_id(), "big").unwrap();
        let mut readback = vec![0u8; size];
        let n = vfs.read(f, 0, &mut readback).unwrap();
        assert_eq!(n, size);
        assert_eq!(
            readback, payload,
            "post-rotation v3 file must decrypt byte-for-byte"
        );
    }

    #[test]
    fn rotate_mvk_rejects_missing_slot_creds() {
        use luksbox_format::Container;
        use zeroize::Zeroizing;
        let dir = tempdir().unwrap();
        let path = dir.path().join("rot.lbx");
        let mut cont = Container::create_with_passphrase(
            &path,
            None,
            CipherSuite::Aes256Gcm,
            test_params(),
            b"alpha",
        )
        .unwrap();
        cont.enroll_passphrase(b"beta", test_params()).unwrap();
        cont.persist_header().unwrap();
        let mut vfs = Vfs::open(cont).unwrap();
        // Only supply one cred when there are two populated slots.
        let creds = vec![SlotCredential::Passphrase {
            slot_idx: 0,
            passphrase: Zeroizing::new("alpha".to_string()),
        }];
        assert!(vfs.rotate_mvk(creds, test_params()).is_err());
    }

    #[test]
    fn rotate_mvk_rejects_wrong_credential() {
        use luksbox_format::Container;
        use zeroize::Zeroizing;
        let dir = tempdir().unwrap();
        let path = dir.path().join("rot.lbx");
        Container::create_with_passphrase(
            &path,
            None,
            CipherSuite::Aes256Gcm,
            test_params(),
            b"alpha",
        )
        .unwrap();
        let cont = Container::open(&path, None, UnlockMaterial::Passphrase(b"alpha")).unwrap();
        let mut vfs = Vfs::open(cont).unwrap();
        // Wrong passphrase for the only slot.
        let creds = vec![SlotCredential::Passphrase {
            slot_idx: 0,
            passphrase: Zeroizing::new("WRONG".to_string()),
        }];
        assert!(vfs.rotate_mvk(creds, test_params()).is_err());
        // Vault must still be usable with the original passphrase
        // (rotation aborted before any on-disk changes). Drop the
        // first handle first, Container holds an OS-level flock
        // since the round-6 audit, so a concurrent open would
        // (correctly) be rejected.
        drop(vfs);
        let _ = Container::open(&path, None, UnlockMaterial::Passphrase(b"alpha")).unwrap();
    }

    #[test]
    fn padded_chunk_count_math() {
        assert_eq!(padded_chunk_count(0, true), 0);
        assert_eq!(padded_chunk_count(0, false), 0);
        assert_eq!(padded_chunk_count(1, true), 1);
        assert_eq!(padded_chunk_count(2, true), 2);
        assert_eq!(padded_chunk_count(3, true), 4);
        assert_eq!(padded_chunk_count(5, true), 8);
        assert_eq!(padded_chunk_count(13, true), 16);
        assert_eq!(padded_chunk_count(25, true), 32);
        assert_eq!(padded_chunk_count(33, true), 64);
        // Padding off -> 1:1.
        for n in 0..40 {
            assert_eq!(padded_chunk_count(n, false), n);
        }
    }

    #[test]
    fn hide_size_header_roundtrips_various_sizes() {
        use luksbox_format::Container;
        let dir = tempdir().unwrap();
        let path = dir.path().join("hs.lbx");
        Container::create_with_passphrase_flags(
            &path,
            None,
            CipherSuite::Aes256Gcm,
            test_params(),
            luksbox_core::FLAG_PAD_FILES_POW2 | luksbox_core::FLAG_HIDE_SIZE_HEADER,
            b"pw",
        )
        .unwrap();
        let cont = Container::open(&path, None, UnlockMaterial::Passphrase(b"pw")).unwrap();
        let mut vfs = Vfs::open(cont).unwrap();
        let root = vfs.root_id();

        // Various sizes including edge cases around the chunk-0 4088-byte capacity.
        for &size in &[0usize, 1, 100, 4087, 4088, 4089, 8000, 12_000, 50_000] {
            let f = vfs.create(root, &format!("f{size}")).unwrap();
            let payload: Vec<u8> = (0..size).map(|i| (i & 0xff) as u8).collect();
            if size > 0 {
                vfs.write(f, 0, &payload).unwrap();
            }
            // Stat returns real size (not padded).
            assert_eq!(vfs.stat(f).unwrap().size, size as u64);
            // Read returns payload byte-for-byte.
            let mut buf = vec![0u8; size];
            let n = vfs.read(f, 0, &mut buf).unwrap();
            assert_eq!(n, size);
            assert_eq!(buf, payload);
            // Inode.size in metadata is the PADDED chunk capacity, not the
            // real size, that's what an MVK-holder would see directly
            // without decrypting chunk 0.
            let chunk_count = vfs.tree.inodes[&f].chunks.len();
            let metadata_size = vfs.tree.inodes[&f].size;
            assert_eq!(
                metadata_size,
                chunk_count as u64 * CHUNK_PLAINTEXT_SIZE as u64,
                "inode.size should be padded chunks * 4096 (got {metadata_size})"
            );
        }
    }

    #[test]
    fn hide_size_truncate_updates_real_size() {
        use luksbox_format::Container;
        let dir = tempdir().unwrap();
        let path = dir.path().join("ht.lbx");
        Container::create_with_passphrase_flags(
            &path,
            None,
            CipherSuite::Aes256Gcm,
            test_params(),
            luksbox_core::FLAG_PAD_FILES_POW2 | luksbox_core::FLAG_HIDE_SIZE_HEADER,
            b"pw",
        )
        .unwrap();
        let cont = Container::open(&path, None, UnlockMaterial::Passphrase(b"pw")).unwrap();
        let mut vfs = Vfs::open(cont).unwrap();
        let root = vfs.root_id();
        let f = vfs.create(root, "x").unwrap();
        vfs.write(f, 0, &vec![0xab; 12_000]).unwrap();
        assert_eq!(vfs.stat(f).unwrap().size, 12_000);
        vfs.truncate(f, 50).unwrap();
        assert_eq!(vfs.stat(f).unwrap().size, 50);
        let mut buf = vec![0u8; 50];
        vfs.read(f, 0, &mut buf).unwrap();
        assert_eq!(&buf, &vec![0xab; 50]);
        vfs.truncate(f, 0).unwrap();
        assert_eq!(vfs.stat(f).unwrap().size, 0);
        assert!(vfs.tree.inodes[&f].chunks.is_empty());
    }

    #[test]
    fn hide_size_persists_across_reopen() {
        use luksbox_format::Container;
        let dir = tempdir().unwrap();
        let path = dir.path().join("hp.lbx");
        Container::create_with_passphrase_flags(
            &path,
            None,
            CipherSuite::Aes256Gcm,
            test_params(),
            luksbox_core::FLAG_PAD_FILES_POW2 | luksbox_core::FLAG_HIDE_SIZE_HEADER,
            b"pw",
        )
        .unwrap();
        let payload: Vec<u8> = (0..15_000).map(|i| (i % 251) as u8).collect();
        {
            let cont = Container::open(&path, None, UnlockMaterial::Passphrase(b"pw")).unwrap();
            let mut vfs = Vfs::open(cont).unwrap();
            let root = vfs.root_id();
            let f = vfs.create(root, "blob").unwrap();
            vfs.write(f, 0, &payload).unwrap();
            vfs.flush().unwrap();
        }
        // Re-open and verify stat + read both still produce the real size.
        let cont = Container::open(&path, None, UnlockMaterial::Passphrase(b"pw")).unwrap();
        let mut vfs = Vfs::open(cont).unwrap();
        let f = vfs.lookup_path("/blob").unwrap();
        // First stat triggers a chunk-0 decrypt to populate the cache.
        assert_eq!(vfs.stat(f).unwrap().size, 15_000);
        // Second stat hits the cache.
        assert_eq!(vfs.stat(f).unwrap().size, 15_000);
        let mut buf = vec![0u8; 15_000];
        vfs.read(f, 0, &mut buf).unwrap();
        assert_eq!(buf, payload);
    }

    #[test]
    fn pad_files_pow2_inflates_chunk_vec() {
        use luksbox_format::Container;
        let dir = tempdir().unwrap();
        let path = dir.path().join("p.lbx");
        Container::create_with_passphrase_flags(
            &path,
            None,
            CipherSuite::Aes256Gcm,
            test_params(),
            luksbox_core::FLAG_PAD_FILES_POW2,
            b"pw",
        )
        .unwrap();
        let cont = Container::open(&path, None, UnlockMaterial::Passphrase(b"pw")).unwrap();
        let mut vfs = Vfs::open(cont).unwrap();
        let root = vfs.root_id();
        let f = vfs.create(root, "x").unwrap();
        // 12_000 bytes -> 3 chunks unpadded, 4 chunks padded
        let payload = vec![0xab; 12_000];
        vfs.write(f, 0, &payload).unwrap();
        // Verify chunks vec is pow2-rounded.
        assert_eq!(
            vfs.tree.inodes[&f].chunks.len(),
            4,
            "expected pow2 chunk count"
        );
        // And the file still reads back verbatim.
        let mut buf = vec![0u8; 12_000];
        vfs.read(f, 0, &mut buf).unwrap();
        assert_eq!(buf, payload);
    }

    #[test]
    fn lookup_path_traverses() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("a.lbx");
        let mut vfs = Vfs::open(create_container(&path)).unwrap();
        let root = vfs.root_id();
        let a = vfs.mkdir(root, "a").unwrap();
        let b = vfs.mkdir(a, "b").unwrap();
        let f = vfs.create(b, "f").unwrap();
        assert_eq!(vfs.lookup_path("/a/b/f").unwrap(), f);
        assert_eq!(vfs.lookup_path("a/b/f").unwrap(), f);
    }

    // Note: there's no companion `read_rejects_offset_overflow` test
    // because `read` short-circuits on `offset >= real` before the
    // overflow guard, and we can't materialize a u64::MAX-byte file
    // to bypass that branch. The guard is still kept as
    // defense-in-depth against future refactors that might remove the
    // early-return.
    #[test]
    fn write_rejects_offset_overflow() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("a.lbx");
        let mut vfs = Vfs::open(create_container(&path)).unwrap();
        let root = vfs.root_id();
        let f = vfs.create(root, "x").unwrap();
        let payload = vec![0u8; 16];
        // Same overflow shape as the read test.
        let res = vfs.write(f, u64::MAX - 4, &payload);
        assert!(
            matches!(res, Err(Error::OffsetOverflow)),
            "write with overflowing offset must return OffsetOverflow, got {res:?}"
        );
    }

    #[test]
    fn malicious_metadata_with_wrapping_chunk_id_is_rejected_on_open() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("a.lbx");
        let mut container = create_container(&path);

        let mut tree = DirectoryTree::new();
        let file_id = 2;
        tree.next_file_id = 3;
        tree.next_chunk_id = u64::MAX;
        tree.next_chunk_gen = 2;
        tree.inodes
            .get_mut(&ROOT_ID)
            .unwrap()
            .children
            .insert("x".to_string(), file_id);
        tree.inodes.insert(
            file_id,
            Inode {
                id: file_id,
                parent: ROOT_ID,
                kind: InodeKind::File,
                size: 1,
                mtime_ns: 0,
                chunks: vec![ChunkRef {
                    id: u64::MAX,
                    generation: 1,
                }],
                children: Default::default(),
                cached_real_size: None,
                external_list_blocks: Vec::new(),
            },
        );
        write_raw_tree_metadata(&mut container, &tree);
        drop(container);

        let container = open_container(&path);
        let err = match Vfs::open(container) {
            Ok(_) => panic!("malicious wrapping chunk id must be rejected"),
            Err(e) => e,
        };
        assert!(matches!(err, Error::MetadataDeserialize), "{err:?}");
    }

    #[test]
    fn malformed_metadata_tree_edges_are_rejected_on_open() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("a.lbx");
        let mut container = create_container(&path);

        let mut tree = DirectoryTree::new();
        tree.next_file_id = 43;
        tree.inodes
            .get_mut(&ROOT_ID)
            .unwrap()
            .children
            .insert("missing".to_string(), 42);
        write_raw_tree_metadata(&mut container, &tree);
        drop(container);

        let container = open_container(&path);
        let err = match Vfs::open(container) {
            Ok(_) => panic!("metadata with a missing child inode must be rejected"),
            Err(e) => e,
        };
        assert!(matches!(err, Error::MetadataDeserialize), "{err:?}");
    }

    #[test]
    fn exhausted_file_id_space_fails_cleanly() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("a.lbx");
        let mut vfs = Vfs::open(create_container(&path)).unwrap();
        let root = vfs.root_id();
        vfs.tree.next_file_id = u64::MAX;
        let err = vfs.create(root, "x").unwrap_err();
        assert!(matches!(err, Error::IdSpaceExhausted), "{err:?}");
    }
}
