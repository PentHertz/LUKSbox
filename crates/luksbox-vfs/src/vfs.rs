// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Penthertz <https://penthertz.com> (https://x.com/PentHertz)

use std::collections::BTreeSet;

use luksbox_format::Container;

use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use crate::chunk::{self, CHUNK_PLAINTEXT_SIZE};
use crate::error::Error;
use crate::tree::{
    ChunkId, ChunkRef, DirectoryTree, FileId, Inode, InodeKind, ROOT_ID, V3_INLINE_CHUNK_THRESHOLD,
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
/// (16 TiB) -- three orders of magnitude beyond the largest real-world
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
    /// POSIX mode bits (12 bits used: `0o7777`). Persisted via LBM4
    /// for vaults that have used `chmod`; LBM2/LBM3 vaults synthesise
    /// the default for the inode's kind. Mount layers should mask
    /// with `0o7777` and OR in the file-type bits themselves.
    pub mode: u32,
    /// POSIX hardlink count. >= 1 for every inode that exists.
    /// Pre-LBM4 vaults always report `1` for files, `1` for
    /// directories (the mount layer adds the conventional `+1`
    /// for directories when reporting nlink to the kernel).
    pub link_count: u32,
}

#[derive(Debug, Clone)]
pub struct DirEntry {
    pub name: String,
    pub id: FileId,
    pub kind: InodeKind,
}

/// Snapshot of how much of the vault's metadata region is currently
/// consumed by the encoded directory tree. The cap is configured at
/// vault create time (default 64 MiB for v0.2.1+); used + spillover
/// estimates approach the cap as inode count grows. CLI `info` prints
/// this; the GUI polls it for an in-app low-capacity notification so
/// users get an early warning before the hard `MetadataBudgetExhausted`
/// (ENOSPC) error fires.
#[derive(Debug, Clone, Copy)]
pub struct MetadataBudgetStatus {
    /// Current encoded size of the in-memory tree in bytes.
    pub used_bytes: usize,
    /// Hard cap. Once `used_bytes` reaches this, the next write that
    /// would grow the tree fails with `MetadataBudgetExhausted`.
    pub budget_bytes: usize,
}

impl MetadataBudgetStatus {
    /// Usage as percentage 0..=100. Saturates at 100.
    pub fn used_pct(self) -> u32 {
        if self.budget_bytes == 0 {
            return 0;
        }
        let pct = (self.used_bytes as u128 * 100 / self.budget_bytes as u128) as u32;
        pct.min(100)
    }

    /// Soft-warning threshold: at or above 75% of capacity. The GUI
    /// surfaces a non-blocking notification here; the CLI's `info`
    /// flags the vault as approaching its metadata cap.
    pub fn near_capacity(self) -> bool {
        self.used_pct() >= 75
    }

    /// Hard-warning threshold: at or above 90% of capacity. The next
    /// few writes are likely to start failing with
    /// `MetadataBudgetExhausted`. The GUI surfaces a blocking
    /// notification recommending the user archive content or
    /// migrate to a new vault.
    pub fn critical_capacity(self) -> bool {
        self.used_pct() >= 90
    }
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
/// mis-decoding (postcard schemas differ -- v3 uses
/// `InodeV3OnDisk` which has an extra `chunks_external` field).
const METADATA_V3_MAGIC: &[u8; 4] = b"LBM\x03";

/// 4-byte magic + 1-byte version = "LBM\x04". Required prefix on
/// metadata blobs in the v4 format, which extends v3 by adding
/// per-inode `mode` (POSIX mode bits, for chmod persistence) and
/// `link_count` (POSIX hardlink count). New vaults default to v4.
/// Existing v2/v3 vaults stay in their original format on read
/// until an op that requires LBM4 (`chmod` to a non-default mode,
/// or `link` creating a second hardlink) is performed; the next
/// flush then auto-upgrades to LBM4. v2/v3 readers refuse v4 blobs
/// cleanly via the version-byte mismatch rather than silently
/// mis-decoding.
///
/// **Migration**: LBM4 is a one-way upgrade. Once a vault is
/// written as LBM4, older LUKSbox binaries can no longer open it.
/// The auto-upgrade rule (trigger only when chmod/link is used)
/// means a user can stay on the old format if they avoid those
/// operations -- relevant for users still distributing pre-v0.3
/// LUKSbox binaries.
const METADATA_V4_MAGIC: &[u8; 4] = b"LBM\x04";

/// v5 metadata magic. Introduced in v0.2.1 alongside the durability
/// fix (sidecar mirrors). Structurally identical to LBM4 on disk; the
/// difference is operational:
///   - the write path uses the lower `V5_INLINE_CHUNK_THRESHOLD` so
///     large vaults stay within the 64 MiB metadata cap without
///     spilling to MetadataBudgetExhausted;
///   - the on-disk header carries LUKSBOX2 magic and the
///     FLAG_HAS_*_MIRROR bits.
///
/// Pre-LBM5 binaries refuse to open vaults at this magic via the
/// dispatch in `Vfs::open`, which is correct: a v0.2.0 binary would
/// silently miss the recovery sidecars.
const METADATA_V5_MAGIC: &[u8; 4] = b"LBM\x05";

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

/// On-disk metadata format. The `Vfs` carries one of these per
/// open vault so the flush path knows which serialiser to use.
/// New vaults default to `V4`; existing v2/v3 vaults stay in
/// their original format until an op that requires LBM4 (chmod
/// to a non-default mode, or link to nlink>1) is performed,
/// at which point the next flush auto-upgrades.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
enum MetadataFormat {
    V2,
    V3,
    V4,
    V5,
}

impl MetadataFormat {
    /// Format used by a freshly-created vault. Defaults to V5 (v0.2.1+
    /// durability layout: lower spill threshold, paired with LUKSBOX2
    /// header + mirror sidecars). Users who need backward compat with
    /// pre-v0.3 LUKSbox binaries can opt back to V2 via
    /// `LUKSBOX_FORMAT_V2=1`. There is no V3-only or V4-only opt-out
    /// path: those formats are read-supported indefinitely but new
    /// vaults skip straight to V5.
    fn for_fresh_vault() -> Self {
        if use_v3_for_fresh_vault() {
            Self::V5
        } else {
            Self::V2
        }
    }

    /// Spill threshold for this format: any inode whose inline chunk
    /// list would exceed this count is split out into an external
    /// chunk-list block chain. Smaller = more compact metadata blob at
    /// the cost of one extra read per large file's first chunk-list
    /// fetch. V5 lowers from V3/V4's 1024 to 256 to keep the encoded
    /// tree under the 64 MiB cap for very large vaults.
    fn inline_chunk_threshold(self) -> usize {
        match self {
            MetadataFormat::V2 | MetadataFormat::V3 | MetadataFormat::V4 => {
                V3_INLINE_CHUNK_THRESHOLD
            }
            MetadataFormat::V5 => crate::tree::V5_INLINE_CHUNK_THRESHOLD,
        }
    }
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
/// in the working `Inode` and never serialised -- they're absent here.
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

/// v4 on-disk Inode. Superset of v3: same shape plus two trailing
/// fields, `mode` (POSIX mode bits, persists chmod) and
/// `link_count` (POSIX hardlink count, persists multi-linked files).
///
/// **Field ordering matters for postcard**: new fields are appended
/// so a v4 inode without mode/link_count bytes would deserialize as
/// truncated. The v4 read path is reached only by the LBM4 magic
/// check, so this is never invoked on shorter-than-expected bytes
/// in practice. Defense-in-depth: corrupt truncated v4 blob fails
/// postcard decode -> Error::MetadataDeserialize, never silent.
///
/// `cached_real_size` / `external_list_blocks` remain in-memory
/// only (#[serde(skip)] on the working `Inode`).
#[derive(Serialize, Deserialize, Debug, Clone)]
struct InodeV4OnDisk {
    id: FileId,
    parent: FileId,
    kind: InodeKind,
    size: u64,
    mtime_ns: u64,
    chunks: Vec<ChunkRef>,
    chunks_external: Option<(ChunkRef, u64)>,
    children: std::collections::BTreeMap<String, FileId>,
    mode: u32,
    link_count: u32,
    /// Symlink target. `Some(s)` iff `kind == InodeKind::Symlink`.
    /// Validation at load time (in `v4_on_disk_to_in_memory`) rejects
    /// any target that's absolute, contains `..` or `.` components,
    /// contains NUL, or exceeds `MAX_SYMLINK_TARGET_LEN` bytes. The
    /// validation is identical to what `Vfs::symlink` enforces at
    /// create time, so a vault written by us will always round-trip
    /// cleanly. A vault containing a malicious symlink target (e.g.
    /// `/etc/shadow`) is REJECTED at open time, before any FUSE
    /// callback can return it to the kernel. This is the
    /// load-time half of the supply-chain attack defense.
    symlink_target: Option<String>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
struct DirectoryTreeV4OnDisk {
    root: FileId,
    next_file_id: FileId,
    next_chunk_id: ChunkId,
    next_chunk_gen: u64,
    free_chunks: Vec<ChunkId>,
    inodes: std::collections::BTreeMap<FileId, InodeV4OnDisk>,
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

    // Count how many directory entries point at each inode. LBM4
    // hardlinks allow N > 1; pre-LBM4 always 1. We cross-check
    // against `inode.link_count` at the end -- if they disagree
    // the metadata is corrupt (or attacker-forged after the chunk
    // referencing check).
    let mut entry_counts: std::collections::BTreeMap<FileId, u32> =
        std::collections::BTreeMap::new();
    let mut live_chunks = BTreeSet::new();

    for (&id, inode) in &tree.inodes {
        if inode.id != id || id >= tree.next_file_id {
            return invalid_metadata();
        }
        if id != ROOT_ID {
            // For non-root inodes the `parent` field names ONE of
            // the directories holding an entry to this inode. For
            // single-linked files and for directories it's the
            // unique parent; for multi-linked files (LBM4) it's
            // one of the N parents. Either way, `parent` must be
            // a real directory inode.
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
                // Directories MUST NOT carry a symlink_target -- same
                // defensive reasoning as the File branch below.
                if inode.symlink_target.is_some() {
                    return invalid_metadata();
                }
                // Directories can't be hardlinked (POSIX), so
                // link_count for a directory is meaningful only as
                // "1" (matches the conventional "the directory
                // itself counts as one link via `.`"). Reject any
                // other value to keep the invariant tight.
                if inode.link_count != 1 {
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
                    // Tally an entry-count toward the target inode.
                    // If `child` is a directory, also enforce
                    // single-parent (no two dir entries to one
                    // dir, which would create a cycle).
                    let count = entry_counts.entry(child_id).or_insert(0);
                    *count = count.saturating_add(1);
                    if child.kind == InodeKind::Directory && *count > 1 {
                        // Two directory entries pointing at one
                        // directory inode -- only legitimate as
                        // root's self-loop, which we already
                        // excluded above (child_id == ROOT_ID).
                        return invalid_metadata();
                    }
                }
            }
            InodeKind::Symlink => {
                // Symlinks: no children, no chunks, link_count == 1
                // (hardlinks to symlinks are theoretically POSIX-
                // valid but we don't support them -- the LBM4 design
                // says one directory entry per Symlink inode), and
                // MUST carry a target. The target must satisfy the
                // same sanity rules as `Vfs::symlink` enforces at
                // create time; `v4_on_disk_to_in_memory` runs the
                // check too, but we re-check here so a forged in-
                // memory tree caught by `tree_needs_v4_format` ->
                // flush -> validator can't poison the on-disk blob.
                if !inode.children.is_empty()
                    || !inode.chunks.is_empty()
                    || !inode.external_list_blocks.is_empty()
                    || inode.link_count != 1
                {
                    return invalid_metadata();
                }
                match inode.symlink_target.as_deref() {
                    Some(t) if is_safe_symlink_target(t) => {}
                    _ => return invalid_metadata(),
                }
            }
            InodeKind::File => {
                if !inode.children.is_empty() {
                    return invalid_metadata();
                }
                // Files MUST NOT carry a symlink_target. Defensive
                // against a forged inode that's File-kind but has
                // a target stuck on it (which would round-trip
                // through serde and confuse readlink's invariant).
                if inode.symlink_target.is_some() {
                    return invalid_metadata();
                }
                // File inodes MUST have link_count >= 1. A persisted
                // file with link_count == 0 is corrupt -- unlink
                // would have freed its chunks. (The v4 read path
                // already rejects link_count == 0, but defense-in-
                // depth: pre-LBM4 vaults populate link_count = 1 in
                // memory, so this catches a forged-in-memory case
                // before flush gets a chance to re-serialise it.)
                if inode.link_count == 0 {
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

    // Every non-root inode must be referenced from at least one
    // directory entry, AND for File inodes the count of directory
    // entries pointing at the inode must EQUAL its `link_count`
    // (LBM4 hardlinks; pre-LBM4 vaults always have link_count == 1
    // so this collapses to "exactly one entry"). This is the
    // critical invariant for refcount-correct unlink: if the
    // entry-count and link_count diverge, a later unlink could
    // free chunks while another directory entry still points at
    // them (use-after-free of ciphertext slots).
    for (&id, inode) in &tree.inodes {
        if id == ROOT_ID {
            continue;
        }
        let count = entry_counts.get(&id).copied().unwrap_or(0);
        if count == 0 {
            // Unreachable inode -- garbage that unlink should have
            // cleaned up.
            return invalid_metadata();
        }
        if inode.kind == InodeKind::File && count != inode.link_count {
            return invalid_metadata();
        }
        // Symlinks aren't hardlinkable in our format (one entry per
        // symlink inode). Combined with the `link_count == 1` check
        // for the symlink itself, count must equal 1.
        if inode.kind == InodeKind::Symlink && count != 1 {
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
                // LBM3 on disk doesn't carry mode/link_count, so we
                // populate sensible defaults. They become persisted
                // only if a later op (chmod, link) triggers an
                // auto-upgrade to LBM4 at flush time.
                mode: crate::tree::default_mode_for_kind(od.kind),
                link_count: 1,
                symlink_target: None,
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

/// LBM4 counterpart to `v3_on_disk_to_in_memory`. Identical chunk-
/// chain expansion logic; the additional work is copying the new
/// per-inode `mode` and `link_count` fields straight from disk into
/// the in-memory `Inode` (instead of substituting defaults like the
/// LBM3 reader does).
///
/// Defensive bounds check: `link_count == 0` is a corrupt vault
/// (every existing inode is reachable from at least one directory
/// entry, so its refcount must be >= 1). Refuse rather than letting
/// a subsequent `unlink` underflow to u32::MAX and skip the chunk-
/// free path. `mode` has no upper bound check -- POSIX mode bits
/// are a `u16` semantically but `u32` storage is forward-compat
/// (S_ISUID/S_ISGID extensions, anyone). The mount layers mask out
/// bits they don't understand.
fn v4_on_disk_to_in_memory(
    v4: DirectoryTreeV4OnDisk,
    container: &mut luksbox_format::Container,
) -> Result<DirectoryTree, Error> {
    let mut inodes: std::collections::BTreeMap<FileId, crate::tree::Inode> =
        std::collections::BTreeMap::new();
    for (id, od) in v4.inodes {
        if od.link_count == 0 {
            // Corrupt: every inode must have at least one directory
            // entry pointing at it (otherwise it would have been
            // freed by unlink), so refcount must be >= 1.
            return Err(Error::MetadataDeserialize);
        }
        // Symlink presence-of-target invariant. Match the create-
        // time invariant: Symlink -> Some, non-Symlink -> None.
        // Validate the target with the same rules `Vfs::symlink`
        // applies at create time, so a vault carrying a
        // maliciously-authored symlink target (absolute, contains
        // `..`, contains NUL, oversize) is REFUSED at open time
        // -- the FUSE readlink callback never sees the bytes,
        // closing the `/etc/shadow` supply-chain hole even if the
        // vault was written by a non-LUKSbox tool.
        match (od.kind, od.symlink_target.as_deref()) {
            (InodeKind::Symlink, Some(t)) => {
                if !is_safe_symlink_target(t) {
                    return Err(Error::MetadataDeserialize);
                }
            }
            (InodeKind::Symlink, None) | (_, Some(_)) => {
                return Err(Error::MetadataDeserialize);
            }
            _ => {}
        }
        let (chunks, external_list_blocks) = match od.chunks_external {
            None => (od.chunks, Vec::new()),
            Some((head, expected_count)) => {
                if !od.chunks.is_empty() {
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
                mode: od.mode,
                link_count: od.link_count,
                symlink_target: od.symlink_target,
            },
        );
    }
    Ok(DirectoryTree {
        root: v4.root,
        next_file_id: v4.next_file_id,
        next_chunk_id: v4.next_chunk_id,
        next_chunk_gen: v4.next_chunk_gen,
        free_chunks: v4.free_chunks,
        inodes,
    })
}

/// Encrypted VFS atop a `Container`. Buffers the directory tree in memory and
/// writes it back to the metadata blob on `flush` / `close` / drop.
pub struct Vfs {
    container: Container,
    tree: DirectoryTree,
    dirty: bool,
    /// On-disk metadata format for this vault. New vaults default
    /// to V5 (v0.2.1+ shape: lower spill threshold, paired with
    /// LUKSBOX2 header and sidecar mirrors). Existing V2/V3 vaults
    /// retain their format on open and auto-upgrade to V5 on the
    /// first flush against a dirty tree. Downgrade is not supported.
    format: MetadataFormat,
    /// Highest metadata-budget-usage percentage we've already warned
    /// about. The eprintln warning in `flush` fires only on upward
    /// threshold crossings (>=75% once, then >=90% once) per Vfs
    /// instance, so CLI users see the message exactly when capacity
    /// changes from healthy to concerning without spamming on every
    /// subsequent flush.
    last_warned_pct: u32,
    /// Set once we've emitted the "vault size beyond the tested
    /// boundary" advisory for this Vfs session. v0.2.1 has been
    /// ground-truth tested up to ~30 GiB of stored content; beyond
    /// that the format is expected to work but is in untested
    /// territory and we ask users to verify unlocks + report issues.
    /// One-shot per session via this latch.
    warned_beyond_tested_size: bool,
}

/// Vault on-disk size beyond which the runtime emits a one-shot
/// "untested territory" advisory. Aligns with the validation
/// boundary documented in CRYPTO_SPEC.md and PROJECT_OVERVIEW.md.
const TESTED_VAULT_SIZE_BYTES: u64 = 30 * 1024 * 1024 * 1024;

impl Vfs {
    /// Open a Vfs over an already-unlocked container. If the metadata blob is
    /// empty (freshly created container), initializes a fresh tree.
    pub fn open(mut container: Container) -> Result<Self, Error> {
        let blob = container.read_metadata()?;
        let (tree, format) = if blob.is_empty() {
            // Fresh vault: pick the format based on the env-var gate.
            // The choice is locked in by the first flush writing the
            // appropriate magic onto disk.
            (DirectoryTree::new(), MetadataFormat::for_fresh_vault())
        } else if blob.len() >= METADATA_V5_MAGIC.len()
            && &blob[..METADATA_V5_MAGIC.len()] == METADATA_V5_MAGIC
        {
            // LBM5: structurally the v4 on-disk shape. The lower
            // V5_INLINE_CHUNK_THRESHOLD is a write-side invariant
            // only; the read path tolerates any inline count up to
            // the postcard decode limit so we stay forward-compatible
            // with future threshold tweaks.
            let payload = &blob[METADATA_V5_MAGIC.len()..];
            if payload.len() > METADATA_DECODE_LIMIT_BYTES {
                return Err(Error::MetadataDeserialize);
            }
            let v4: DirectoryTreeV4OnDisk =
                postcard::from_bytes(payload).map_err(|_| Error::MetadataDeserialize)?;
            (
                v4_on_disk_to_in_memory(v4, &mut container)?,
                MetadataFormat::V5,
            )
        } else if blob.len() >= METADATA_V4_MAGIC.len()
            && &blob[..METADATA_V4_MAGIC.len()] == METADATA_V4_MAGIC
        {
            let payload = &blob[METADATA_V4_MAGIC.len()..];
            if payload.len() > METADATA_DECODE_LIMIT_BYTES {
                return Err(Error::MetadataDeserialize);
            }
            let v4: DirectoryTreeV4OnDisk =
                postcard::from_bytes(payload).map_err(|_| Error::MetadataDeserialize)?;
            (
                v4_on_disk_to_in_memory(v4, &mut container)?,
                MetadataFormat::V4,
            )
        } else if blob.len() >= METADATA_V3_MAGIC.len()
            && &blob[..METADATA_V3_MAGIC.len()] == METADATA_V3_MAGIC
        {
            let payload = &blob[METADATA_V3_MAGIC.len()..];
            if payload.len() > METADATA_DECODE_LIMIT_BYTES {
                return Err(Error::MetadataDeserialize);
            }
            let v3: DirectoryTreeV3OnDisk =
                postcard::from_bytes(payload).map_err(|_| Error::MetadataDeserialize)?;
            (
                v3_on_disk_to_in_memory(v3, &mut container)?,
                MetadataFormat::V3,
            )
        } else if blob.len() >= METADATA_V2_MAGIC.len()
            && &blob[..METADATA_V2_MAGIC.len()] == METADATA_V2_MAGIC
        {
            let payload = &blob[METADATA_V2_MAGIC.len()..];
            if payload.len() > METADATA_DECODE_LIMIT_BYTES {
                return Err(Error::MetadataDeserialize);
            }
            let mut tree: DirectoryTree =
                postcard::from_bytes(payload).map_err(|_| Error::MetadataDeserialize)?;
            // V2 on-disk inodes don't carry mode/link_count; the
            // serde-skip defaults assign DEFAULT_FILE_MODE to every
            // inode. Patch directories to the conventional 0o755 so
            // the FUSE layer reports sensible mode bits on first
            // stat. link_count stays 1 (set by the skip-default).
            for inode in tree.inodes.values_mut() {
                inode.mode = crate::tree::default_mode_for_kind(inode.kind);
            }
            (tree, MetadataFormat::V2)
        } else {
            // Not LBM2/3/4/5 -- unsupported version, refuse cleanly.
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
            format,
            last_warned_pct: 0,
            warned_beyond_tested_size: false,
        })
    }

    /// Whether this vault uses any non-v2 metadata format (v3 or v4).
    /// Visible to tests; production code should not branch on it.
    /// Preserved name for backward compat with existing tests.
    pub fn uses_v3_metadata(&self) -> bool {
        !matches!(self.format, MetadataFormat::V2)
    }

    /// Whether this vault is currently in (or has been upgraded to)
    /// the v4-or-later metadata format (v4 or v5). v4 was where
    /// persistent chmod and hardlinks landed; v5 adds the lower spill
    /// threshold and is paired with the durability mirrors. Both are
    /// equally capable for the chmod/link feature set.
    pub fn uses_v4_metadata(&self) -> bool {
        matches!(self.format, MetadataFormat::V4 | MetadataFormat::V5)
    }

    /// Whether this vault is on the v0.2.1 v5 metadata format.
    pub fn uses_v5_metadata(&self) -> bool {
        matches!(self.format, MetadataFormat::V5)
    }

    /// Whether the vault's on-disk size is beyond the v0.2.1
    /// ground-truth-tested boundary (~30 GiB). GUI callers poll this
    /// to surface a one-shot advisory toast asking the user to verify
    /// the vault still unlocks and report issues if it doesn't.
    /// Cheap: a single `stat()` against the vault path.
    pub fn is_beyond_tested_size(&self) -> bool {
        std::fs::metadata(self.container.vault_path())
            .map(|m| m.len() > TESTED_VAULT_SIZE_BYTES)
            .unwrap_or(false)
    }

    /// Current metadata-region budget usage in bytes plus the cap.
    /// The CLI's `info` subcommand surfaces this, and the GUI polls
    /// it for status display so users get an in-app warning before
    /// they hit the cap on large file-count vaults (5k+ inodes
    /// approaching the 64 MiB region).
    ///
    /// O(N) over inodes: serializes a snapshot of the current tree.
    /// Cheap enough to call periodically (once per CLI `info` /
    /// once per GUI refresh tick); not cheap enough for hot-path
    /// callers like statfs.
    pub fn metadata_budget_status(&self) -> MetadataBudgetStatus {
        let budget =
            luksbox_format::metadata::payload_budget_for(self.container.header.metadata_size);
        // Encode the in-memory tree the same way the next flush
        // would, modulo the per-format magic prefix (4 B). The
        // projection in `check_metadata_budget_for_chunks` is for
        // pre-flighting writes; for status display we just want the
        // current encoded size, so a plain to_allocvec is enough.
        let used = postcard::to_allocvec(&self.tree)
            .map(|v| v.len())
            .unwrap_or(0);
        MetadataBudgetStatus {
            used_bytes: used,
            budget_bytes: budget,
        }
    }

    pub fn flush(&mut self) -> Result<(), Error> {
        // Force a flush even when the tree is clean if the most recent
        // open recovered the metadata blob from a sidecar mirror. The
        // recovery path is correct but the live region is stale until
        // the next flush rewrites it; without this force-trigger the
        // vault could close clean and the next crash would leave us
        // without a current live AND without a current mirror.
        let metadata_recovered = self.container.metadata_was_recovered_from_mirror();
        if !self.dirty && !metadata_recovered {
            return Ok(());
        }
        validate_metadata_tree(
            &self.tree,
            self.container.data_offset(),
            self.container.header.hide_size_header(),
        )?;
        // v0.2.1 auto-upgrade: any flush against a LUKSBOX1 vault
        // bumps it to LUKSBOX2 + LBM5. One-way; the next crash gets
        // mirror recovery, but the cost is that pre-v0.3 binaries
        // can no longer open the vault. The user picked auto-upgrade
        // on next flush explicitly.
        //
        // Explicit deniable-mode exclusion: deniable vaults must NOT
        // auto-upgrade, because the upgrade implies on-disk sidecar
        // mirrors (`<vault>.lbx.{header,meta}-bak`) which are a
        // distinguishability beacon defeating the deniability
        // property. Deniable vaults keep their existing in-place
        // overwrite + internal-redundancy crash-safety story. See
        // `Container::is_v2_format` for the parallel guard on the
        // write path.
        if self.container.header.version_major == luksbox_core::VERSION_MAJOR_V1
            && !self.container.is_deniable()
        {
            self.container.header.version_major = luksbox_core::VERSION_MAJOR_V2;
            self.container.mark_header_dirty();
            // Bump the metadata format too. V5 supersedes V2/V3/V4
            // for the v0.2.1+ shape: lower spill threshold, paired
            // with the LUKSBOX2 header.
            self.format = MetadataFormat::V5;
        }
        // Auto-upgrade to V4 if any inode has been touched by an
        // LBM4-only op (non-default mode, or hardlink count > 1).
        // Skipped for V5 which already covers those features.
        let needs_v4 = self.tree_needs_v4_format();
        if matches!(self.format, MetadataFormat::V2 | MetadataFormat::V3) && needs_v4 {
            self.format = MetadataFormat::V4;
        }
        let bytes = match self.format {
            MetadataFormat::V5 => {
                // v5: same on-disk shape as v4, lower spill threshold
                // applied via `self.format.inline_chunk_threshold()`
                // inside `spill_to_v3_on_disk`. Magic differs so
                // pre-LBM5 binaries refuse the vault (they'd miss the
                // sidecar mirror recovery path).
                let v4 = self.spill_to_v4_on_disk()?;
                let payload = postcard::to_allocvec(&v4).map_err(|_| Error::MetadataSerialize)?;
                if payload.len() > METADATA_DECODE_LIMIT_BYTES {
                    return Err(Error::MetadataSerialize);
                }
                let mut bytes = Vec::with_capacity(METADATA_V5_MAGIC.len() + payload.len());
                bytes.extend_from_slice(METADATA_V5_MAGIC);
                bytes.extend_from_slice(&payload);
                bytes
            }
            MetadataFormat::V4 => {
                // v4: same spill machinery as v3 + per-inode
                // mode/link_count. spill_to_v4_on_disk reuses
                // spill_to_v3_on_disk's chunk-list-block handling.
                let v4 = self.spill_to_v4_on_disk()?;
                let payload = postcard::to_allocvec(&v4).map_err(|_| Error::MetadataSerialize)?;
                if payload.len() > METADATA_DECODE_LIMIT_BYTES {
                    return Err(Error::MetadataSerialize);
                }
                let mut bytes = Vec::with_capacity(METADATA_V4_MAGIC.len() + payload.len());
                bytes.extend_from_slice(METADATA_V4_MAGIC);
                bytes.extend_from_slice(&payload);
                bytes
            }
            MetadataFormat::V3 => {
                // v3: spill any inode whose chunk list exceeds
                // V3_INLINE_CHUNK_THRESHOLD into an external chunk-
                // list chain, then serialise the spilled tree as
                // DirectoryTreeV3OnDisk. Spilling writes chunk-list
                // blocks AND mutates inode.external_list_blocks for
                // bookkeeping; old external_list_blocks (from a
                // previous flush) are freed during the spill.
                let v3 = self.spill_to_v3_on_disk()?;
                let payload = postcard::to_allocvec(&v3).map_err(|_| Error::MetadataSerialize)?;
                if payload.len() > METADATA_DECODE_LIMIT_BYTES {
                    return Err(Error::MetadataSerialize);
                }
                let mut bytes = Vec::with_capacity(METADATA_V3_MAGIC.len() + payload.len());
                bytes.extend_from_slice(METADATA_V3_MAGIC);
                bytes.extend_from_slice(&payload);
                bytes
            }
            MetadataFormat::V2 => {
                // v2: plain postcard of the whole tree, all chunks
                // inline. Inode's mode/link_count fields are
                // serde-skipped, so the on-disk shape is unchanged
                // from pre-LBM4 code (preserves backward compat).
                let payload =
                    postcard::to_allocvec(&self.tree).map_err(|_| Error::MetadataSerialize)?;
                if payload.len() > METADATA_DECODE_LIMIT_BYTES {
                    return Err(Error::MetadataSerialize);
                }
                let mut bytes = Vec::with_capacity(METADATA_V2_MAGIC.len() + payload.len());
                bytes.extend_from_slice(METADATA_V2_MAGIC);
                bytes.extend_from_slice(&payload);
                bytes
            }
        };
        self.container.write_metadata(&bytes)?;
        // The live metadata region has been re-established. Clear the
        // recovery flag so subsequent clean flushes (when the tree is
        // not dirty) take the fast path.
        self.container.clear_metadata_recovered_flag();
        // Soft-warn on stderr when the metadata region is nearing
        // capacity. CLI users see it directly; the mount subprocess'
        // stderr is captured by the GUI / system log. The GUI's own
        // status indicator (via `Vfs::metadata_budget_status`) is the
        // primary in-app surface; this eprintln is the
        // CLI-equivalent so headless users get the same heads-up
        // before hitting the hard ENOSPC. State-tracked via the
        // `last_warned_pct` field so the message fires only on
        // upward threshold crossings, not on every flush.
        let pct = ((bytes.len() as u128 * 100)
            / luksbox_format::metadata::payload_budget_for(self.container.header.metadata_size)
                as u128) as u32;
        let pct = pct.min(100);
        if pct >= 90 && self.last_warned_pct < 90 {
            eprintln!(
                "luksbox: warn: metadata region at {pct}% capacity ({} / {} bytes). \
                 Further writes may fail with 'no space left on device'. \
                 Consider archiving content or migrating to a new vault \
                 (create with --metadata-size larger than the default 64 MiB).",
                bytes.len(),
                luksbox_format::metadata::payload_budget_for(self.container.header.metadata_size,),
            );
            self.last_warned_pct = pct;
        } else if pct >= 75 && self.last_warned_pct < 75 {
            eprintln!(
                "luksbox: note: metadata region at {pct}% capacity ({} / {} bytes). \
                 The metadata region (not the host disk) is the bottleneck for \
                 vaults with very large inode counts; if many more files are \
                 expected, consider re-creating with a larger --metadata-size.",
                bytes.len(),
                luksbox_format::metadata::payload_budget_for(self.container.header.metadata_size,),
            );
            self.last_warned_pct = pct;
        }
        // Tested-boundary advisory. v0.2.1 was ground-truth tested
        // up to TESTED_VAULT_SIZE_BYTES (~30 GiB) of stored content.
        // Beyond that the format is expected to work but is in
        // untested territory; ask the user to verify unlocks +
        // report issues. One-shot per Vfs session via the latch.
        if !self.warned_beyond_tested_size {
            if let Ok(meta) = std::fs::metadata(self.container.vault_path()) {
                if meta.len() > TESTED_VAULT_SIZE_BYTES {
                    eprintln!(
                        "luksbox: note: vault on-disk size ({} GiB) is beyond the \
                         tested boundary (~30 GiB). The format is expected to handle \
                         larger vaults but this usage has not been ground-truth tested. \
                         Please periodically close and reopen the vault to verify it \
                         still unlocks, and report any anomalies at \
                         https://github.com/PentHertz/LUKSbox/issues.",
                        meta.len() / (1024 * 1024 * 1024)
                    );
                    self.warned_beyond_tested_size = true;
                }
            }
        }
        // If the container has an anchor sidecar configured, push the
        // current vault generation to it so a future open can detect
        // rollback via `anchor::compare`.
        self.container.write_anchor(self.tree.next_chunk_gen)?;
        self.dirty = false;
        Ok(())
    }

    /// Detects whether the in-memory tree has any inode that
    /// requires LBM4 persistence: a non-default mode (chmod was
    /// used), or link_count > 1 (hardlink was created). LBM2/LBM3
    /// can't carry these fields, so a tree that needs them must be
    /// upgraded to LBM4 on the next flush.
    ///
    /// Cheap: O(N) over inodes, no allocations. Called once per
    /// flush.
    fn tree_needs_v4_format(&self) -> bool {
        for inode in self.tree.inodes.values() {
            if inode.link_count != 1 {
                return true;
            }
            // Symlinks are LBM4-only (the kind variant doesn't
            // exist in v2/v3 postcard encoding). Any symlink in
            // the tree forces an upgrade.
            if inode.kind == InodeKind::Symlink {
                return true;
            }
            // default_mode_for_kind only knows File/Directory; for
            // Symlink we treat 0o777 as the conventional default
            // (POSIX: symlinks have no enforceable mode).
            let default_mode = match inode.kind {
                InodeKind::File => crate::tree::DEFAULT_FILE_MODE,
                InodeKind::Directory => crate::tree::DEFAULT_DIR_MODE,
                InodeKind::Symlink => 0o777,
            };
            if inode.mode != default_mode {
                return true;
            }
        }
        false
    }

    /// Mirror of `spill_to_v3_on_disk` that produces the v4 on-disk
    /// shape. Reuses the v3 chunk-list-spill machinery via delegation
    /// rather than duplicating it -- the only difference between v3
    /// and v4 is per-inode `mode` + `link_count`, which we copy from
    /// the in-memory tree after the v3 spill resolves chunks.
    fn spill_to_v4_on_disk(&mut self) -> Result<DirectoryTreeV4OnDisk, Error> {
        let v3 = self.spill_to_v3_on_disk()?;
        let inodes_v4: std::collections::BTreeMap<FileId, InodeV4OnDisk> =
            v3.inodes
                .into_iter()
                .map(|(id, od)| {
                    let inode =
                        self.tree.inodes.get(&id).expect(
                            "v3 spill enumerates only ids that exist in the in-memory tree",
                        );
                    (
                        id,
                        InodeV4OnDisk {
                            id: od.id,
                            parent: od.parent,
                            kind: od.kind,
                            size: od.size,
                            mtime_ns: od.mtime_ns,
                            chunks: od.chunks,
                            chunks_external: od.chunks_external,
                            children: od.children,
                            mode: inode.mode,
                            link_count: inode.link_count,
                            symlink_target: inode.symlink_target.clone(),
                        },
                    )
                })
                .collect();
        Ok(DirectoryTreeV4OnDisk {
            root: v3.root,
            next_file_id: v3.next_file_id,
            next_chunk_id: v3.next_chunk_id,
            next_chunk_gen: v3.next_chunk_gen,
            free_chunks: v3.free_chunks,
            inodes: inodes_v4,
        })
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
            let threshold = self.format.inline_chunk_threshold();
            let (chunks_len, file_needs_external) = {
                let inode = self.tree.inodes.get(&id).expect("id from keys()");
                (
                    inode.chunks.len(),
                    inode.kind == InodeKind::File && inode.chunks.len() > threshold,
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
                let inode_mut = self.tree.inodes.get_mut(&id).expect("id from keys()");
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
                // -- chunks are already in the in-memory `chunks` vec.)
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
            let id = self.tree.alloc_chunk_id().ok_or(Error::IdSpaceExhausted)?;
            let generation = self.tree.alloc_chunk_gen().ok_or(Error::IdSpaceExhausted)?;
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
    /// - **v2 (`format == V2`)**: every ChunkRef lands inline in the
    ///   metadata blob. Serialise the current tree once (postcard,
    ///   fast), add a conservative 12 B per new chunk (worst-case
    ///   two u64 varints + Vec-length slack), and compare to the
    ///   budget. Same as before this fix.
    ///
    /// - **v3 / v4 (`format != V2`)**: any inode whose chunk count
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

        if matches!(self.format, MetadataFormat::V2) {
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
        // We don't actually need to BUILD spill blocks here -- the
        // estimate is just an InodeV3OnDisk with empty inline chunks
        // and a placeholder (ChunkRef, count). The placeholder bytes
        // postcard-encode identically to the real values (same shape).
        let placeholder = ChunkRef {
            id: 0,
            generation: 1,
        };
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
                && projected_chunk_count > self.format.inline_chunk_threshold();
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
            mode: inode.mode,
            link_count: inode.link_count,
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
    /// container layer -- `validate_metadata_tree` only checks that the
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
                mode: crate::tree::DEFAULT_DIR_MODE,
                link_count: 1,
                symlink_target: None,
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

    /// Create a regular file with the default mode (`0o644`).
    /// Convenience wrapper preserved for CLI / GUI callers that
    /// don't care about the mode; FUSE callers that get a mode from
    /// `open(O_CREAT, mode)` should use [`Vfs::create_with_mode`] so
    /// the executable bit on scripts and binaries survives a
    /// `git clone` into a mounted vault (the previous path defaulted
    /// every newly-created file to 0o644 regardless of what the
    /// caller passed).
    pub fn create(&mut self, parent: FileId, name: &str) -> Result<FileId, Error> {
        self.create_with_mode(parent, name, crate::tree::DEFAULT_FILE_MODE)
    }

    /// Create a regular file with a specific POSIX permission mode.
    /// Mode is masked to `0o7777` (strips any S_IF* file-type bits a
    /// FUSE caller might have included). The FUSE umask, if any, is
    /// the caller's responsibility to apply BEFORE passing the mode
    /// here; FUSE clients call us with the already-umasked value.
    pub fn create_with_mode(
        &mut self,
        parent: FileId,
        name: &str,
        mode: u32,
    ) -> Result<FileId, Error> {
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
                mode: mode & 0o7777,
                link_count: 1,
                symlink_target: None,
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
        // the write. The old code only caught this at flush time --
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

    /// Unlink: refcount-aware as of LBM4. Removes the directory
    /// entry first, then decrements the target's `link_count`. The
    /// chunks (and v3 chunk-list blocks) are freed ONLY when
    /// `link_count` reaches zero -- i.e. when the last hardlink is
    /// removed. This is the POSIX `unlink(2)` contract and the only
    /// way hardlinks can be safe: freeing chunks on the first unlink
    /// would silently corrupt the OTHER directory entries that still
    /// point at the inode, because their chunk references would
    /// dangle into freed slots that the next allocation cycle could
    /// overwrite -- a "use-after-free of ciphertext", surfacing as
    /// garbled reads (decryption against a different file_key, or a
    /// chunk written under a different generation than the AAD
    /// expects, both of which would fail AEAD and read EIO; not
    /// silent disclosure, but data loss).
    ///
    /// For pre-LBM4 vaults, link_count is always 1 (set by the read
    /// path) so the refcount-decrement immediately hits zero and the
    /// behaviour is identical to the pre-LBM4 unlink.
    ///
    /// **Security**: link_count is `u32`. Subtracting from a stored
    /// `0` (which v4_on_disk_to_in_memory rejects, but defense-in-
    /// depth) would wrap to u32::MAX and skip the free-on-zero
    /// branch. We use `saturating_sub(1)` so the worst case is "the
    /// chunks leak" rather than "freed chunks reallocated to another
    /// file, ciphertext substitution" -- the former is a recoverable
    /// space bug, the latter is a confidentiality bug.
    pub fn unlink(&mut self, parent: FileId, name: &str) -> Result<(), Error> {
        let parent_inode = self.require_dir(parent)?;
        let target_id = *parent_inode.children.get(name).ok_or(Error::NotFound)?;
        let target = self.tree.inodes.get(&target_id).unwrap();
        // POSIX `unlink(2)` removes files AND symlinks. Directories
        // require `rmdir(2)` instead.
        if target.kind == InodeKind::Directory {
            return Err(Error::IsADirectory);
        }

        // Remove the directory entry first. Doing so before the
        // refcount mutation keeps the invariant that
        // "validate_metadata_tree's directory-entry count for an
        // inode == its link_count" holds at every observable point
        // between operations (even mid-Vfs::unlink if we ever
        // re-entered concurrently, which Mutex serialization
        // prevents anyway).
        self.tree
            .inodes
            .get_mut(&parent)
            .unwrap()
            .children
            .remove(name);

        // Saturating-sub: a corrupt vault that reached us with
        // link_count == 0 would wrap to u32::MAX without it. The
        // worst case post-fix is "this unlink freed an entry but the
        // inode survives with link_count=0 and leaks chunks"; the
        // worst case pre-fix would have been "wrap to u32::MAX,
        // unlink any number of times without ever freeing" --
        // confidentiality-preserving but leaks unbounded chunks.
        let target_mut = self.tree.inodes.get_mut(&target_id).unwrap();
        target_mut.link_count = target_mut.link_count.saturating_sub(1);
        let now_zero = target_mut.link_count == 0;

        if now_zero {
            // Last hardlink gone -- free chunks + chunk-list blocks
            // and drop the inode entirely. Matches the pre-LBM4
            // behaviour, which assumed link_count was always 1.
            let chunks = target_mut.chunks.clone();
            let list_blocks = target_mut.external_list_blocks.clone();
            for cref in chunks {
                self.tree.free_chunk_id(cref.id);
            }
            for cref in list_blocks {
                self.tree.free_chunk_id(cref.id);
            }
            self.tree.inodes.remove(&target_id);
        }
        // If still nonzero, the inode remains and is reachable via
        // its other directory entries; chunks stay allocated.
        self.dirty = true;
        Ok(())
    }

    /// Persistently change an inode's POSIX mode bits. Triggers
    /// auto-upgrade to LBM4 on next flush if the new mode differs
    /// from the kind's default. Only applies to files / directories
    /// that exist; returns NotFound otherwise.
    ///
    /// **Security**: chmod is a metadata-only op; it doesn't touch
    /// chunk slots, free lists, or anything that could leak
    /// ciphertext. We don't validate the mode bits (POSIX mode is
    /// caller-supplied user-space data), just store them as-is.
    /// Mount layers mask out bits they don't understand.
    pub fn chmod(&mut self, id: FileId, mode: u32) -> Result<(), Error> {
        let inode = self.tree.inodes.get_mut(&id).ok_or(Error::NotFound)?;
        // Mask to the POSIX-defined mode bits (12 bits: 0o7777 =
        // setuid|setgid|sticky + 9 permission bits). Higher bits
        // are file-type identifiers in stat(2) (S_IFREG/S_IFDIR)
        // and don't belong in stored mode. Defense: silently strip
        // them rather than reject; some callers (libfuse) pass the
        // full mode including type bits.
        inode.mode = mode & 0o7777;
        self.dirty = true;
        Ok(())
    }

    /// Create a symlink at `(parent, name)` whose stored target is
    /// `target`. **Strict target sanitization** -- the target MUST
    /// satisfy `is_safe_symlink_target`:
    ///
    /// - Not empty
    /// - Bytes < `MAX_SYMLINK_TARGET_LEN` (PATH_MAX = 4096)
    /// - Not absolute (doesn't start with `/` or `\` or a Windows
    ///   drive-letter prefix like `C:`)
    /// - No NUL bytes (would truncate at the C-string boundary
    ///   when crossing back through the FUSE callback)
    /// - No path components equal to `..` -- prevents the
    ///   `secret -> ../../../etc/shadow` supply-chain attack class
    /// - No path components equal to `.` -- not strictly a security
    ///   bug (just a no-op component) but breaks the
    ///   "components are file names or `..`" assumption other code
    ///   relies on, and confuses any future symlink-follower
    ///
    /// This is the **strictest reasonable design**. Some legitimate
    /// uses (like `git`'s `.git/objects/info/alternates -> ../../
    /// other-repo/...`) won't work. We accept that trade-off:
    /// LUKSbox is a confidentiality-first vault, not a general
    /// shared filesystem, and the cost of a single CVE in this code
    /// path would be catastrophic (data exfil via symlink chain).
    ///
    /// A future "controlled-`..`" mode that resolves targets
    /// against the symlink's parent directory and verifies the
    /// result stays within the vault root could be added later as
    /// an opt-in.
    pub fn symlink(&mut self, parent: FileId, name: &str, target: &str) -> Result<FileId, Error> {
        validate_name(name)?;
        if !is_safe_symlink_target(target) {
            return Err(Error::InvalidPath(target.to_string()));
        }
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
                kind: InodeKind::Symlink,
                size: target.len() as u64,
                mtime_ns: 0,
                chunks: Vec::new(),
                children: Default::default(),
                cached_real_size: None,
                external_list_blocks: Vec::new(),
                // POSIX symlinks have no enforceable mode; the
                // kernel checks the target's mode instead. 0o777
                // matches what mainstream filesystems return.
                mode: 0o777,
                link_count: 1,
                symlink_target: Some(target.to_string()),
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

    /// Read a symlink's stored target. Returns `Error::NotFound`
    /// if `id` doesn't exist; returns `Error::NotAFile` (mapped to
    /// EINVAL by the mount layer) if `id` is not a symlink.
    pub fn readlink(&self, id: FileId) -> Result<String, Error> {
        let inode = self.tree.inodes.get(&id).ok_or(Error::NotFound)?;
        if inode.kind != InodeKind::Symlink {
            return Err(Error::NotAFile);
        }
        Ok(inode
            .symlink_target
            .clone()
            .expect("invariant: Symlink kind always carries a target"))
    }

    /// Hardlink: add a new directory entry `(new_parent, new_name)`
    /// pointing to the existing inode at `target_id`. POSIX
    /// `link(2)`: only files can be hardlinked (directories are
    /// reserved for `..` resolution and would create cycles).
    /// Increments the target's `link_count`. Auto-upgrades to LBM4
    /// on next flush because link_count becomes > 1.
    ///
    /// **Security considerations:**
    /// - target must already exist (no creating phantom inodes)
    /// - target must be a File (POSIX forbids dir hardlinks; allowing
    ///   them would let `is_descendant_of` cycle-guard miss true
    ///   cycles and let trees grow loops)
    /// - new_parent must exist + be a directory
    /// - new_name must not already exist in new_parent (POSIX would
    ///   require EEXIST; we don't replace because replace + new link
    ///   semantics are ambiguous and easy to get wrong)
    /// - link_count is `u32`; saturating_add caps at u32::MAX. A
    ///   vault that legitimately has 2^32 hardlinks to one inode is
    ///   absurd; cap by failing the link rather than wrapping
    pub fn link(
        &mut self,
        target_id: FileId,
        new_parent: FileId,
        new_name: &str,
    ) -> Result<(), Error> {
        validate_name(new_name)?;

        // Validate target. Only regular files can be hardlinked
        // -- POSIX forbids dir hardlinks (cycle defense), and our
        // LBM4 format invariant is "one directory entry per
        // Symlink inode" (the per-symlink target is the link; a
        // second name to the same target would be a different
        // symlink with the same target, semantically clearer to
        // create separately). For Symlinks we map the rejection
        // to NotAFile -> EINVAL at the mount layer.
        let target = self.tree.inodes.get(&target_id).ok_or(Error::NotFound)?;
        match target.kind {
            InodeKind::File => {}
            InodeKind::Directory => return Err(Error::IsADirectory),
            InodeKind::Symlink => return Err(Error::NotAFile),
        }
        let cur_count = target.link_count;
        // u32 overflow guard. POSIX `link(2)` returns EMLINK for
        // "too many links". We map that to AlreadyExists since we
        // don't have a dedicated EMLINK variant; the FUSE errno
        // mapping is close enough (most callers treat both as
        // "can't link, fall back to copy"). A real 2^32-link inode
        // is astronomical -- this is purely defensive.
        if cur_count == u32::MAX {
            return Err(Error::AlreadyExists);
        }

        // Validate new_parent.
        let new_dir = self.tree.inodes.get(&new_parent).ok_or(Error::NotFound)?;
        if new_dir.kind != InodeKind::Directory {
            return Err(Error::NotADirectory);
        }
        if new_dir.children.contains_key(new_name) {
            return Err(Error::AlreadyExists);
        }

        // Mutate: insert directory entry, bump refcount.
        self.tree
            .inodes
            .get_mut(&new_parent)
            .unwrap()
            .children
            .insert(new_name.to_string(), target_id);
        let target_mut = self.tree.inodes.get_mut(&target_id).unwrap();
        target_mut.link_count = target_mut.link_count.saturating_add(1);
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

    /// Full POSIX `rename(2)` -- within-directory AND cross-directory.
    ///
    /// **Replacement**: if `new_name` already exists in `new_parent`,
    /// the existing entry is atomically replaced (POSIX requires this;
    /// the pre-fix behavior of returning `AlreadyExists` broke every
    /// program that uses the "write temp + rename onto target" atomic-
    /// write idiom, including git, sqlite WAL checkpointing, and most
    /// editor save flows). Type-compatibility is enforced first:
    ///
    /// - file -> file: replace, freeing the displaced file's chunks.
    /// - dir -> empty dir: replace, dropping the displaced empty dir.
    /// - file -> dir: rejected with `IsADirectory`.
    /// - dir -> file: rejected with `NotADirectory`.
    /// - dir -> non-empty dir: rejected with `NotEmpty`.
    /// - same target inode (old == new entry): no-op success.
    ///
    /// **Cycle guard**: when the source is a directory, the rename is
    /// rejected with `RenameCycle` (-> EINVAL) if `new_parent` equals
    /// `src` or sits inside `src`'s subtree. Without the guard the
    /// tree would gain a cycle and the next traversal would loop.
    ///
    /// The implementation is three phases (validate, free, move) so
    /// any rejection leaves on-disk state untouched. All chunk-freeing
    /// matches the `unlink` cleanup path so a replaced file's data
    /// blocks return to `free_chunks` instead of leaking.
    pub fn rename(
        &mut self,
        old_parent: FileId,
        old_name: &str,
        new_parent: FileId,
        new_name: &str,
    ) -> Result<(), Error> {
        validate_name(old_name)?;
        validate_name(new_name)?;

        // POSIX: rename(x, x) within the same dir is a no-op success.
        // Doing the check up-front also avoids the Phase 2/3 work for
        // a trivially-equivalent call.
        if old_parent == new_parent && old_name == new_name {
            let dir = self.tree.inodes.get(&old_parent).ok_or(Error::NotFound)?;
            if dir.kind != InodeKind::Directory {
                return Err(Error::NotADirectory);
            }
            if !dir.children.contains_key(old_name) {
                return Err(Error::NotFound);
            }
            return Ok(());
        }

        // ---- Phase 1: validate everything before mutating ---------------
        // Both parents must exist and be directories. Source must
        // exist under its old name.
        let old_dir = self.tree.inodes.get(&old_parent).ok_or(Error::NotFound)?;
        if old_dir.kind != InodeKind::Directory {
            return Err(Error::NotADirectory);
        }
        let src_id = *old_dir.children.get(old_name).ok_or(Error::NotFound)?;
        let new_dir = self.tree.inodes.get(&new_parent).ok_or(Error::NotFound)?;
        if new_dir.kind != InodeKind::Directory {
            return Err(Error::NotADirectory);
        }

        // Cycle guard. Only meaningful when src is a directory; files
        // can't have descendants. `new_parent == src_id` is the
        // self-rename case ("rename /a into /a"); `is_descendant`
        // catches the deeper case ("rename /a into /a/b/..."). The
        // helper uses a visited-set so a corrupt cyclic on-disk tree
        // can't make the check loop forever.
        let src_kind = self.tree.inodes.get(&src_id).unwrap().kind;
        if src_kind == InodeKind::Directory
            && (new_parent == src_id || self.is_descendant_of(src_id, new_parent))
        {
            return Err(Error::RenameCycle);
        }

        // Look up displaced target in `new_parent` and validate
        // type-compatibility. `dir.children.get(name).copied()` is
        // a fresh immutable borrow on `new_dir`, but `new_dir` is
        // already borrowed above -- re-fetch through `inodes.get`
        // to keep the borrow checker happy without an interleaved
        // `&mut` (Phase 3 is the only `&mut` access).
        let displaced = {
            let new_dir = self.tree.inodes.get(&new_parent).unwrap();
            if let Some(&dst_id) = new_dir.children.get(new_name) {
                // Same inode would only happen via hardlinks, which we
                // don't support yet. Defensive: treat as no-op so a
                // future hardlink patch can't accidentally drop the
                // only reference to the inode.
                if src_id == dst_id {
                    return Ok(());
                }
                let dst = self.tree.inodes.get(&dst_id).unwrap();
                match (src_kind, dst.kind) {
                    (InodeKind::Directory, InodeKind::Directory) => {
                        if !dst.children.is_empty() {
                            return Err(Error::NotEmpty);
                        }
                    }
                    (InodeKind::Directory, _) => return Err(Error::NotADirectory),
                    (_, InodeKind::Directory) => return Err(Error::IsADirectory),
                    _ => {}
                }
                Some(dst_id)
            } else {
                None
            }
        };

        // ---- Phase 2: free the displaced inode's data chunks ------------
        // Only file inodes have chunks; empty directories have none.
        // Matches the cleanup path in `unlink` so we don't leak data-
        // area slots when a file is replaced via rename. Borrow-scope
        // block keeps the immutable `inodes.get` alive only as long as
        // it takes to clone out the chunk lists, so the subsequent
        // `tree.free_chunk_id` (mutates `tree.free_chunks`) compiles.
        if let Some(dst_id) = displaced {
            let (chunks, list_blocks) = {
                let dst = self.tree.inodes.get(&dst_id).unwrap();
                (dst.chunks.clone(), dst.external_list_blocks.clone())
            };
            for cref in chunks {
                self.tree.free_chunk_id(cref.id);
            }
            for cref in list_blocks {
                self.tree.free_chunk_id(cref.id);
            }
            self.tree.inodes.remove(&dst_id);
        }

        // ---- Phase 3: move the directory entry --------------------------
        if old_parent == new_parent {
            // Same dir: a single get_mut handles both remove + insert.
            let dir = self.tree.inodes.get_mut(&old_parent).unwrap();
            let id = dir.children.remove(old_name).unwrap();
            // `insert` overwrites any existing entry for `new_name`,
            // whose inode we already removed in Phase 2 (if any).
            dir.children.insert(new_name.to_string(), id);
        } else {
            // Cross-dir: two distinct `get_mut`s. Scope the first to
            // its remove so the &mut borrow drops before the second
            // get_mut runs. old_parent != new_parent in this branch
            // so the two borrows reference different map entries.
            let id = {
                let old_dir = self.tree.inodes.get_mut(&old_parent).unwrap();
                old_dir.children.remove(old_name).unwrap()
            };
            let new_dir = self.tree.inodes.get_mut(&new_parent).unwrap();
            new_dir.children.insert(new_name.to_string(), id);
        }
        self.dirty = true;
        Ok(())
    }

    /// Returns `true` if `candidate` lives anywhere in the subtree
    /// rooted at `root` (exclusive of `root` itself -- the caller
    /// checks equality separately when it matters). Used by `rename`
    /// to detect cross-directory moves that would create a cycle.
    ///
    /// Uses a visited-set so a corrupt on-disk tree with an existing
    /// cycle cannot make the traversal loop forever. Cost is O(N) in
    /// the size of `root`'s subtree.
    ///
    /// Defense-in-depth: walks `children` regardless of `kind`. The
    /// well-formed invariant is "only Directory inodes have non-empty
    /// `children`", but if a corrupted or attacker-influenced vault
    /// ever has a File-kind inode that nonetheless carries children
    /// (or a future Symlink variant with embedded entries), skipping
    /// based on kind would let those children hide from the cycle
    /// check -- a rename into one of them would then create a real
    /// directory cycle, and the next traversal (read_directory,
    /// flush, rotate_mvk) would loop forever. Walking unconditionally
    /// costs nothing on well-formed vaults (the `children` BTreeMap
    /// on a File is normally empty) and closes the corruption-induced
    /// cycle-injection vector.
    fn is_descendant_of(&self, root: FileId, candidate: FileId) -> bool {
        let mut stack = vec![root];
        let mut visited: std::collections::BTreeSet<FileId> = std::collections::BTreeSet::new();
        while let Some(cur) = stack.pop() {
            if !visited.insert(cur) {
                continue;
            }
            let inode = match self.tree.inodes.get(&cur) {
                Some(i) => i,
                None => continue,
            };
            for &child_id in inode.children.values() {
                if child_id == candidate {
                    return true;
                }
                stack.push(child_id);
            }
        }
        false
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
    /// JUST the slot envelopes -- it generates a new MVK + per-vault
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
        //    container's state -- `read_metadata` uses
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
            // 4. Rotate the slot envelopes -- generates new_mvk + new_salt
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
            // Use the envelope-only primitive: the guarded
            // `rotate_mvk_v2_deniable` would refuse here because the
            // metadata blob is non-empty (vault has content), but
            // we're providing the full chunk + chunk-list-block +
            // metadata re-encryption pass right below, so the
            // envelope-only call is exactly what we want.
            this.container
                .rotate_mvk_v2_deniable_envelope_only(&cred_tuples)
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

/// POSIX-ish single-name validation. Rejects empty, ".", "..", any
/// component containing a path separator (forward OR backslash) or
/// NUL, and any name longer than `MAX_NAME_LEN_BYTES`.
///
/// The length cap matches Linux NAME_MAX = 255 and the WinFsp /
/// libfuse limits, so a name we accept here will also be accepted by
/// every mount backend. Without the cap, a programmatic caller (a
/// caller bypassing the mount layer -- CLI, library, fuzzer) could
/// submit megabyte-sized names that bloat the metadata blob's
/// postcard encoding linearly and amplify a single `mkdir` into a
/// large allocation. Defense-in-depth against the metadata-budget
/// DoS class.
///
/// **Cross-platform zip-slip defense**: backslash `\` is rejected
/// even on POSIX hosts because LUKSbox vaults are portable -- a
/// vault created on Linux with `cmd.exe\..\..\Windows\System32\drivers\etc\hosts`
/// as a filename would pass `validate_name` if we only checked `/`,
/// and when later opened on Windows the GUI's "extract directory"
/// feature does `local.join(&ent.name)` -- on Windows that treats
/// `\` as a separator, so the join would resolve OUTSIDE the
/// destination directory and write to a system-controlled path
/// under the user's process privileges. Rejecting `\` at the format
/// boundary blocks the attack regardless of which host eventually
/// extracts the vault. The trade-off is that genuine Linux files
/// containing `\` cannot be added to a vault, which we accept as
/// a security/portability win.
const MAX_NAME_LEN_BYTES: usize = 255;

fn validate_name(name: &str) -> Result<(), Error> {
    if name.is_empty()
        || name == "."
        || name == ".."
        || name.len() > MAX_NAME_LEN_BYTES
        || name.contains('/')
        || name.contains('\\')
        || name.contains('\0')
    {
        Err(Error::InvalidPath(name.to_string()))
    } else {
        Ok(())
    }
}

/// Strict symlink-target sanitization. Returns `true` iff `target`
/// is safe to store in the vault.
///
/// The rules block the `/etc/shadow`-class supply-chain attack:
///
/// 1. **Empty rejected**: an empty target is nonsense in POSIX and
///    causes readlink to return EINVAL on every read; refuse at
///    create time.
/// 2. **Length-capped** (PATH_MAX = 4096): bounds metadata-blob
///    growth and FUSE readlink buffer copies.
/// 3. **Absolute path rejected**: starts with `/`, `\`, or a drive-
///    letter prefix (`C:`). The kernel would resolve an absolute
///    target against the host filesystem, exposing host files via
///    a vault read.
/// 4. **NUL byte rejected**: would truncate the target at the C-
///    string boundary when copied through the FUSE callback,
///    silently producing a different target than what was stored.
/// 5. **No `..` components**: a single `..` could escape the
///    symlink's parent directory. Even chained `..`s with valid
///    components in between still escape if the chain depth >
///    parent depth in the vault. Easiest correct policy: refuse
///    `..` entirely. (Trade-off documented on `Vfs::symlink`.)
/// 6. **No `.` components**: not a security bug, but they're a
///    no-op that confuses any future symlink-following resolver
///    (e.g. counting `..` depth would have to skip `.`); refuse.
///
/// Components are split on BOTH `/` and `\` so a target stored on
/// one OS doesn't bypass validation when read on another -- the
/// same cross-platform-portability reasoning as `validate_name`.
pub fn is_safe_symlink_target(target: &str) -> bool {
    if target.is_empty() {
        return false;
    }
    if target.len() > crate::tree::MAX_SYMLINK_TARGET_LEN {
        return false;
    }
    if target.contains('\0') {
        return false;
    }
    // Absolute markers.
    let bytes = target.as_bytes();
    if bytes[0] == b'/' || bytes[0] == b'\\' {
        return false;
    }
    // Windows drive-letter prefix ("C:..."): two-byte sequence
    // where byte 1 is `:` and byte 0 is an ASCII letter. Cross-
    // platform reject (we don't care what OS this vault is opened
    // on; if a drive-letter target could ever make it to a
    // Windows host's readlink, that's a Windows-side escape).
    if bytes.len() >= 2 && bytes[1] == b':' && bytes[0].is_ascii_alphabetic() {
        return false;
    }
    // Per-component rejections. Split on both separators.
    for component in target.split(|c| c == '/' || c == '\\') {
        if component == ".." || component == "." {
            return false;
        }
    }
    true
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
        vfs.rename(root, "old", root, "new").unwrap();
        assert!(vfs.lookup(root, "old").is_err());
        let g = vfs.lookup(root, "new").unwrap();
        assert_eq!(g, f);
    }

    /// POSIX `rename(2)` MUST atomically replace an existing target
    /// file. The pre-fix behavior returned `AlreadyExists`, breaking
    /// every program using the "write temp + rename onto target"
    /// atomic-write idiom -- the symptom that surfaced this was
    /// `git clone` failing with "could not write config file ... File
    /// exists" because git's `commit_lock_file_to()` issues exactly
    /// this rename.
    #[test]
    fn rename_replaces_existing_file_atomic_write_idiom() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("a.lbx");
        let mut vfs = Vfs::open(create_container(&path)).unwrap();
        let root = vfs.root_id();
        // Simulate the atomic-write pattern: a real target file
        // already in place, plus a freshly-written temp file holding
        // the new contents.
        let target = vfs.create(root, "config").unwrap();
        vfs.write(target, 0, b"old contents").unwrap();
        let tmp = vfs.create(root, "config.lock").unwrap();
        vfs.write(tmp, 0, b"new contents").unwrap();

        // The rename used to fail with AlreadyExists; must now succeed.
        vfs.rename(root, "config.lock", root, "config").unwrap();

        // The new entry holds the temp file's inode + bytes.
        let after = vfs.lookup(root, "config").unwrap();
        assert_eq!(after, tmp, "target should now reference temp inode");
        let mut buf = vec![0u8; b"new contents".len()];
        vfs.read(after, 0, &mut buf).unwrap();
        assert_eq!(buf, b"new contents");
        // The temp name is gone.
        assert!(vfs.lookup(root, "config.lock").is_err());
    }

    /// When a file is displaced by rename, its data-area chunks MUST
    /// return to the free list -- otherwise repeated atomic-writes
    /// (git pack repacking, sqlite checkpoints) would leak ciphertext
    /// chunks forever. Same invariant `unlink` already guarantees.
    #[test]
    fn rename_frees_displaced_file_chunks() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("a.lbx");
        let mut vfs = Vfs::open(create_container(&path)).unwrap();
        let root = vfs.root_id();

        let displaced = vfs.create(root, "big").unwrap();
        // Multi-chunk payload so `chunks` is non-empty.
        vfs.write(displaced, 0, &vec![0xAAu8; 32 * 1024]).unwrap();
        let displaced_chunks: Vec<_> = vfs.tree.inodes.get(&displaced).unwrap().chunks.clone();
        assert!(
            !displaced_chunks.is_empty(),
            "test precondition: displaced file should have allocated chunks"
        );

        let replacement = vfs.create(root, "small").unwrap();
        vfs.write(replacement, 0, b"x").unwrap();

        vfs.rename(root, "small", root, "big").unwrap();

        // The displaced inode is gone from the inode table.
        assert!(
            !vfs.tree.inodes.contains_key(&displaced),
            "displaced inode must be removed after rename-replace"
        );
        // Every chunk the displaced file owned is now in free_chunks
        // so a subsequent allocation can reuse the slot.
        for cref in &displaced_chunks {
            assert!(
                vfs.tree.free_chunks.contains(&cref.id),
                "displaced chunk {} was not freed",
                cref.id
            );
        }
        // Replacement file's data is intact under the new name.
        let after = vfs.lookup(root, "big").unwrap();
        assert_eq!(after, replacement);
    }

    /// Empty-directory replacement: `rename(d1, d2)` where both are
    /// directories and d2 is empty must succeed (POSIX); the empty d2
    /// inode is dropped.
    #[test]
    fn rename_replaces_empty_directory() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("a.lbx");
        let mut vfs = Vfs::open(create_container(&path)).unwrap();
        let root = vfs.root_id();

        let src_dir = vfs.mkdir(root, "src").unwrap();
        vfs.create(src_dir, "inside").unwrap();
        let empty_dst = vfs.mkdir(root, "dst").unwrap();

        vfs.rename(root, "src", root, "dst").unwrap();

        // Replaced inode is gone.
        assert!(!vfs.tree.inodes.contains_key(&empty_dst));
        // Children of the original src dir transferred under the new name.
        let after = vfs.lookup(root, "dst").unwrap();
        assert_eq!(after, src_dir);
        assert!(vfs.lookup(after, "inside").is_ok());
        assert!(vfs.lookup(root, "src").is_err());
    }

    /// Type-mismatch and non-empty-directory rejections must surface
    /// BEFORE any mutation (Phase 1 validation). Pre/post inode counts
    /// confirm nothing leaked.
    #[test]
    fn rename_rejects_type_mismatches_without_side_effects() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("a.lbx");
        let mut vfs = Vfs::open(create_container(&path)).unwrap();
        let root = vfs.root_id();

        let f = vfs.create(root, "afile").unwrap();
        let d = vfs.mkdir(root, "adir").unwrap();
        let d2 = vfs.mkdir(root, "fulldir").unwrap();
        vfs.create(d2, "child").unwrap();

        let before = vfs.tree.inodes.len();

        // dir -> non-empty dir: NotEmpty
        assert!(matches!(
            vfs.rename(root, "adir", root, "fulldir"),
            Err(Error::NotEmpty)
        ));
        // file -> dir: IsADirectory
        assert!(matches!(
            vfs.rename(root, "afile", root, "adir"),
            Err(Error::IsADirectory)
        ));
        // dir -> file: NotADirectory
        assert!(matches!(
            vfs.rename(root, "adir", root, "afile"),
            Err(Error::NotADirectory)
        ));

        // None of the rejections may have mutated the tree.
        assert_eq!(vfs.tree.inodes.len(), before);
        assert_eq!(vfs.lookup(root, "afile").unwrap(), f);
        assert_eq!(vfs.lookup(root, "adir").unwrap(), d);
        assert_eq!(vfs.lookup(root, "fulldir").unwrap(), d2);
    }

    /// `rename(x, x)` is a no-op success per POSIX. Crucially, it must
    /// not run Phase 2 (which would free the inode's chunks and leave
    /// the directory entry dangling).
    #[test]
    fn rename_same_name_is_no_op_success() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("a.lbx");
        let mut vfs = Vfs::open(create_container(&path)).unwrap();
        let root = vfs.root_id();

        let f = vfs.create(root, "file").unwrap();
        vfs.write(f, 0, b"intact").unwrap();
        let chunks_before: Vec<_> = vfs.tree.inodes.get(&f).unwrap().chunks.clone();

        vfs.rename(root, "file", root, "file").unwrap();

        let chunks_after: Vec<_> = vfs.tree.inodes.get(&f).unwrap().chunks.clone();
        assert_eq!(
            chunks_before, chunks_after,
            "no-op rename must not free chunks"
        );
        let mut buf = vec![0u8; b"intact".len()];
        vfs.read(f, 0, &mut buf).unwrap();
        assert_eq!(buf, b"intact");
    }

    /// Even when names match, `rename(missing, missing)` returns
    /// ENOENT (POSIX). Guards the early-out path from masking errors.
    #[test]
    fn rename_same_name_missing_source_returns_not_found() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("a.lbx");
        let mut vfs = Vfs::open(create_container(&path)).unwrap();
        let root = vfs.root_id();
        assert!(matches!(
            vfs.rename(root, "absent", root, "absent"),
            Err(Error::NotFound)
        ));
    }

    /// Cross-directory move (no displacement). The git-objects
    /// "atomically promote tmp/ -> aa/bbbb" idiom -- without this,
    /// `git clone` fails after the same-dir rename fix unblocks it.
    #[test]
    fn rename_cross_directory_moves_file() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("a.lbx");
        let mut vfs = Vfs::open(create_container(&path)).unwrap();
        let root = vfs.root_id();

        let src_dir = vfs.mkdir(root, "tmp").unwrap();
        let dst_dir = vfs.mkdir(root, "objects").unwrap();
        let f = vfs.create(src_dir, "deadbeef").unwrap();
        vfs.write(f, 0, b"object contents").unwrap();

        vfs.rename(src_dir, "deadbeef", dst_dir, "ab12").unwrap();

        // Source name is gone, destination has the same inode + bytes.
        assert!(vfs.lookup(src_dir, "deadbeef").is_err());
        let moved = vfs.lookup(dst_dir, "ab12").unwrap();
        assert_eq!(moved, f);
        let mut buf = vec![0u8; b"object contents".len()];
        vfs.read(moved, 0, &mut buf).unwrap();
        assert_eq!(buf, b"object contents");
    }

    /// Cross-directory move that displaces an existing target file
    /// must free the displaced file's chunks (same invariant as the
    /// same-dir replace test, just across parents).
    #[test]
    fn rename_cross_directory_replace_frees_displaced_chunks() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("a.lbx");
        let mut vfs = Vfs::open(create_container(&path)).unwrap();
        let root = vfs.root_id();

        let src_dir = vfs.mkdir(root, "src").unwrap();
        let dst_dir = vfs.mkdir(root, "dst").unwrap();
        let source = vfs.create(src_dir, "incoming").unwrap();
        vfs.write(source, 0, b"new").unwrap();
        let displaced = vfs.create(dst_dir, "target").unwrap();
        vfs.write(displaced, 0, &vec![0xCDu8; 32 * 1024]).unwrap();
        let displaced_chunks: Vec<_> = vfs.tree.inodes.get(&displaced).unwrap().chunks.clone();
        assert!(
            !displaced_chunks.is_empty(),
            "test precondition: displaced file should have allocated chunks"
        );

        vfs.rename(src_dir, "incoming", dst_dir, "target").unwrap();

        assert!(!vfs.tree.inodes.contains_key(&displaced));
        for cref in &displaced_chunks {
            assert!(
                vfs.tree.free_chunks.contains(&cref.id),
                "displaced chunk {} was not freed",
                cref.id
            );
        }
        assert!(vfs.lookup(src_dir, "incoming").is_err());
        let after = vfs.lookup(dst_dir, "target").unwrap();
        assert_eq!(after, source);
    }

    /// Cycle guard: renaming a directory onto itself must be rejected
    /// with `RenameCycle`. Without the guard the tree would gain a
    /// self-loop and the next traversal would diverge.
    #[test]
    fn rename_directory_into_itself_is_rejected() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("a.lbx");
        let mut vfs = Vfs::open(create_container(&path)).unwrap();
        let root = vfs.root_id();
        let d = vfs.mkdir(root, "d").unwrap();
        assert!(matches!(
            vfs.rename(root, "d", d, "x"),
            Err(Error::RenameCycle)
        ));
    }

    /// Cycle guard: renaming a directory into one of its descendants
    /// must be rejected with `RenameCycle`. POSIX requires EINVAL.
    #[test]
    fn rename_directory_into_descendant_is_rejected() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("a.lbx");
        let mut vfs = Vfs::open(create_container(&path)).unwrap();
        let root = vfs.root_id();
        // Build /a/b/c/d ; try to move /a under /a/b/c.
        let a = vfs.mkdir(root, "a").unwrap();
        let b = vfs.mkdir(a, "b").unwrap();
        let c = vfs.mkdir(b, "c").unwrap();
        let _d = vfs.mkdir(c, "d").unwrap();

        assert!(matches!(
            vfs.rename(root, "a", c, "moved"),
            Err(Error::RenameCycle)
        ));
        // Pre-existing tree is untouched.
        assert!(vfs.lookup(root, "a").is_ok());
        assert!(vfs.lookup(a, "b").is_ok());
    }

    /// Cycle guard must NOT trigger when the source is a file -- only
    /// directories can ever produce cycles. A file's "subtree" is empty.
    #[test]
    fn rename_cycle_guard_does_not_block_file_into_subtree_position() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("a.lbx");
        let mut vfs = Vfs::open(create_container(&path)).unwrap();
        let root = vfs.root_id();
        let outer = vfs.mkdir(root, "outer").unwrap();
        let inner = vfs.mkdir(outer, "inner").unwrap();
        let f = vfs.create(root, "f").unwrap();
        vfs.write(f, 0, b"hi").unwrap();

        // Moving a file into a deeply-nested dir is fine.
        vfs.rename(root, "f", inner, "f").unwrap();
        assert_eq!(vfs.lookup(inner, "f").unwrap(), f);
        assert!(vfs.lookup(root, "f").is_err());
    }

    /// Cross-dir rename must reject if either parent is missing,
    /// without mutating the tree on either side.
    #[test]
    fn rename_rejects_missing_parents() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("a.lbx");
        let mut vfs = Vfs::open(create_container(&path)).unwrap();
        let root = vfs.root_id();
        let src_dir = vfs.mkdir(root, "src").unwrap();
        vfs.create(src_dir, "x").unwrap();
        let before = vfs.tree.inodes.len();

        // Bogus FileId (we don't expose the constructor; use a u64 we
        // know doesn't collide with any real id by going way past the
        // ones the test allocated).
        let bogus = u64::MAX - 1;
        assert!(matches!(
            vfs.rename(src_dir, "x", bogus, "x"),
            Err(Error::NotFound)
        ));
        assert!(matches!(
            vfs.rename(bogus, "x", src_dir, "x"),
            Err(Error::NotFound)
        ));
        // Tree is byte-identical after both rejections.
        assert_eq!(vfs.tree.inodes.len(), before);
        assert!(vfs.lookup(src_dir, "x").is_ok());
    }

    /// Adversarial: a corrupted (or future-buggy) vault could carry
    /// a `File`-kind inode that nonetheless has children. The pre-
    /// hardening cycle guard skipped File-kind inodes' children, so
    /// an attacker who could plant such an inode could trick rename
    /// into creating a directory cycle. After the hardening, the
    /// guard walks `children` regardless of `kind` and the rename
    /// is rejected with `RenameCycle`.
    ///
    /// The corruption is simulated by reaching into the in-memory
    /// tree directly (only possible from inside the crate; mirrors
    /// what a deserialization bug on a malformed blob could produce).
    #[test]
    fn cycle_guard_rejects_corrupted_file_kind_inode_hosting_target() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("a.lbx");
        let mut vfs = Vfs::open(create_container(&path)).unwrap();
        let root = vfs.root_id();

        // Build a normal subtree, then corrupt the intermediate inode
        // to look like a File while still owning its child.
        let outer = vfs.mkdir(root, "outer").unwrap();
        let middle = vfs.mkdir(outer, "middle").unwrap();
        let inner = vfs.mkdir(middle, "inner").unwrap();

        // Corruption: flip middle's kind without touching its children.
        // A real attacker would need to author a malformed metadata
        // blob to land in this state, but defense-in-depth: the
        // cycle guard must still reject regardless.
        vfs.tree.inodes.get_mut(&middle).unwrap().kind = InodeKind::File;

        // Renaming /outer (which transitively contains the corrupted
        // /outer/middle/inner) under `inner` MUST be rejected: it
        // would otherwise complete the cycle outer -> middle ->
        // inner -> outer.
        assert!(matches!(
            vfs.rename(root, "outer", inner, "loop"),
            Err(Error::RenameCycle)
        ));
    }

    /// Cross-platform zip-slip defense: a vault entry name containing
    /// `\` would be safe on Linux's `Path::join` but escape on
    /// Windows's. validate_name rejects it at the format layer so a
    /// vault is safe to extract on any host.
    #[test]
    fn validate_name_rejects_backslash() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("a.lbx");
        let mut vfs = Vfs::open(create_container(&path)).unwrap();
        let root = vfs.root_id();
        // Any backslash in the name is rejected.
        assert!(matches!(
            vfs.create(root, "harmless\\name"),
            Err(Error::InvalidPath(_))
        ));
        // Concrete attack string from the threat model:
        // `..\\..\\Windows\\System32\\drivers\\etc\\hosts` would
        // resolve through `Path::join` on Windows as a directory-
        // traversal escape if it made it past validate_name.
        assert!(matches!(
            vfs.create(root, "..\\..\\Windows\\System32\\drivers\\etc\\hosts"),
            Err(Error::InvalidPath(_))
        ));
        // Mkdir + rename go through the same gate.
        assert!(matches!(
            vfs.mkdir(root, "bad\\dir"),
            Err(Error::InvalidPath(_))
        ));
        vfs.create(root, "ok").unwrap();
        assert!(matches!(
            vfs.rename(root, "ok", root, "renamed\\to"),
            Err(Error::InvalidPath(_))
        ));
    }

    /// Length-cap defense for `validate_name`: programmatic callers
    /// must not be able to submit megabyte-sized names that bloat the
    /// metadata blob linearly. Mirrors NAME_MAX = 255 on Linux.
    #[test]
    fn validate_name_rejects_oversize() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("a.lbx");
        let mut vfs = Vfs::open(create_container(&path)).unwrap();
        let root = vfs.root_id();

        // 256 bytes -- one over NAME_MAX.
        let oversize = "x".repeat(256);
        assert!(matches!(
            vfs.create(root, &oversize),
            Err(Error::InvalidPath(_))
        ));
        // Exactly NAME_MAX must still work (255 bytes).
        let at_cap = "y".repeat(255);
        vfs.create(root, &at_cap).unwrap();
        // And rename's name validation enforces the cap on both
        // sides (old and new name).
        assert!(matches!(
            vfs.rename(root, &at_cap, root, &oversize),
            Err(Error::InvalidPath(_))
        ));
    }

    /// Adversarial round-trip: rename a-> b -> c -> a many times, with
    /// a file write between each, and confirm the inode's chunk list
    /// is intact + no chunks have been spuriously freed. The classic
    /// "atomic-write loop" pattern.
    #[test]
    fn rename_round_trip_loop_does_not_leak_or_drop_chunks() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("a.lbx");
        let mut vfs = Vfs::open(create_container(&path)).unwrap();
        let root = vfs.root_id();
        let f = vfs.create(root, "a").unwrap();
        vfs.write(f, 0, b"payload-v0").unwrap();
        let initial_chunks: Vec<_> = vfs.tree.inodes.get(&f).unwrap().chunks.clone();

        for i in 0..32 {
            // Each iteration: a -> b, b -> c, c -> a, with no writes
            // in between (so the chunk set must be preserved exactly).
            vfs.rename(root, "a", root, "b").unwrap();
            vfs.rename(root, "b", root, "c").unwrap();
            vfs.rename(root, "c", root, "a").unwrap();
            let now: Vec<_> = vfs.tree.inodes.get(&f).unwrap().chunks.clone();
            assert_eq!(
                now, initial_chunks,
                "chunks must survive {i}-th rename-loop iteration unchanged",
            );
            // free_chunks must NOT have grown via spurious frees.
            assert!(
                vfs.tree.free_chunks.is_empty(),
                "rename of a unique non-displacing entry must not free chunks (iter {i})",
            );
        }
    }

    // ============================================================
    // LBM4 / chmod / hardlink tests
    // ============================================================

    /// chmod stores the new mode and `stat` returns it. End-to-end:
    /// the typical git filemode probe (chmod 0o755, stat, expect
    /// **Regression test for the v0.2.1 `git clone` executable-bit
    /// bug**: `Vfs::create_with_mode(parent, name, 0o755)` must land
    /// the file at 0o755 on first `stat`, WITHOUT any subsequent
    /// chmod, and the mode must survive flush+reopen.
    ///
    /// Why this is the right test: git uses `open(O_CREAT, 0o100755)`
    /// to materialise executable files from the index. The FUSE
    /// `create` callback receives that mode and threads it through
    /// `Vfs::create_with_mode`. Earlier code ignored the mode and
    /// defaulted every newly-created file to 0o644, so `git clone`
    /// of a repo containing executable scripts or binaries silently
    /// dropped the +x bit unless git followed up with a chmod (and
    /// not every git version does).
    #[test]
    fn create_with_mode_lands_at_requested_mode_then_persists() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("a.lbx");
        let f = {
            let mut vfs = Vfs::open(create_container(&path)).unwrap();
            let root = vfs.root_id();
            // Simulate git: open(O_CREAT, 0o755) -> create with mode.
            let f = vfs.create_with_mode(root, "setup.sh", 0o755).unwrap();
            assert_eq!(
                vfs.stat(f).unwrap().mode,
                0o755,
                "create_with_mode must land at the requested mode, not the default"
            );
            vfs.flush().unwrap();
            assert!(
                vfs.uses_v4_metadata(),
                "non-default mode at create time must trigger LBM4+ format"
            );
            f
        };
        // Reopen and confirm the executable bit survived.
        let mut vfs = Vfs::open(open_container(&path)).unwrap();
        assert_eq!(
            vfs.stat(f).unwrap().mode,
            0o755,
            "executable bit must round-trip through flush+reopen"
        );
    }

    /// `Vfs::create` (no-mode convenience wrapper) still defaults to
    /// 0o644 so CLI / GUI callers that don't care about the mode
    /// get the legacy behavior.
    #[test]
    fn create_without_mode_defaults_to_0o644() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("a.lbx");
        let mut vfs = Vfs::open(create_container(&path)).unwrap();
        let root = vfs.root_id();
        let f = vfs.create(root, "doc.txt").unwrap();
        assert_eq!(vfs.stat(f).unwrap().mode, 0o644);
    }

    /// 0o755) succeeds across a flush+reopen cycle.
    #[test]
    fn chmod_persists_across_flush_and_reopen() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("a.lbx");
        let f = {
            let mut vfs = Vfs::open(create_container(&path)).unwrap();
            let root = vfs.root_id();
            let f = vfs.create(root, "script.sh").unwrap();
            // Default mode is 0o644 for a fresh file.
            assert_eq!(vfs.stat(f).unwrap().mode, 0o644);
            vfs.chmod(f, 0o755).unwrap();
            assert_eq!(vfs.stat(f).unwrap().mode, 0o755);
            vfs.flush().unwrap();
            // After flush the format must be V4 (auto-upgrade fired
            // because mode != default).
            assert!(vfs.uses_v4_metadata(), "chmod must trigger LBM4 upgrade");
            f
        };

        // Reopen. The mode must round-trip from disk.
        let mut vfs = Vfs::open(open_container(&path)).unwrap();
        assert!(vfs.uses_v4_metadata(), "reopen must detect LBM4 from magic");
        assert_eq!(vfs.stat(f).unwrap().mode, 0o755);
    }

    /// chmod masks input to `0o7777` so file-type bits (S_IFREG etc.)
    /// passed by libfuse's setattr never end up in the stored mode
    /// field -- otherwise a subsequent stat would report the wrong
    /// file type.
    #[test]
    fn chmod_masks_file_type_bits() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("a.lbx");
        let mut vfs = Vfs::open(create_container(&path)).unwrap();
        let root = vfs.root_id();
        let f = vfs.create(root, "x").unwrap();
        // S_IFREG (0o100000) | 0o644 -- this is what libfuse's
        // setattr will pass.
        vfs.chmod(f, 0o100644).unwrap();
        let s = vfs.stat(f).unwrap();
        assert_eq!(s.mode, 0o644, "file-type bits must be masked out");
    }

    /// In v0.2.1, the per-feature auto-upgrade to LBM4 (formerly the
    /// only auto-upgrade trigger) is superseded by the unconditional
    /// LBM5 + LUKSBOX2 upgrade on any flush against a LUKSBOX1 vault.
    /// So a v0.2.0-envelope vault always lands on V5 after the first
    /// flush regardless of whether chmod was a no-op or a real change.
    /// The chmod-specific check (`tree_needs_v4_format`) still governs
    /// the narrower V2/V3 -> V4 case for vaults that somehow miss the
    /// LUKSBOX1 upgrade (e.g. a corrupt header.version_major reading
    /// as 2 already but with V2 metadata).
    #[test]
    fn flush_without_v4_features_still_upgrades_v1_vault_to_v5() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("a.lbx");
        let _v2_guard = set_format_v3_override(Some(false));
        let mut vfs = Vfs::open(create_container(&path)).unwrap();
        let root = vfs.root_id();
        let f = vfs.create(root, "x").unwrap();
        vfs.write(f, 0, b"hi").unwrap();
        // Apply the default mode (no-op chmod). The v4-specific
        // trigger does NOT fire (mode is unchanged), but the
        // v0.2.1 LUKSBOX1 -> LUKSBOX2 + LBM5 trigger does, because
        // the vault was created with v1 header.
        vfs.chmod(f, 0o644).unwrap();
        vfs.flush().unwrap();
        assert!(
            vfs.uses_v5_metadata(),
            "v0.2.0-envelope vault must upgrade to LBM5 on first flush"
        );
        assert_eq!(
            vfs.container.header.version_major,
            luksbox_core::VERSION_MAJOR_V2,
            "v0.2.0-envelope vault must upgrade to LUKSBOX2 header on first flush"
        );
    }

    /// **Critical security invariant**: hardlinks share chunks.
    /// Unlinking one of N hardlinks must NOT free the underlying
    /// chunks -- doing so would leave the other N-1 directory
    /// entries pointing at freed chunk slots. Next `alloc_chunk_id`
    /// could hand those slots to a different file, and the
    /// surviving links would then decrypt-against-wrong-key /
    /// fail-AEAD on read (data loss; not silent disclosure, but
    /// loss of vault integrity).
    #[test]
    fn link_then_unlink_one_of_two_keeps_chunks_alive() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("a.lbx");
        let mut vfs = Vfs::open(create_container(&path)).unwrap();
        let root = vfs.root_id();
        let f = vfs.create(root, "orig").unwrap();
        vfs.write(f, 0, b"shared payload").unwrap();
        let orig_chunks: Vec<_> = vfs.tree.inodes.get(&f).unwrap().chunks.clone();
        assert!(!orig_chunks.is_empty());

        // Link "orig" under a new name. nlink: 1 -> 2.
        vfs.link(f, root, "alias").unwrap();
        assert_eq!(vfs.stat(f).unwrap().link_count, 2);

        // Unlink the original name. nlink: 2 -> 1. Inode + chunks
        // MUST stay alive because "alias" still points to them.
        vfs.unlink(root, "orig").unwrap();
        assert!(
            vfs.tree.inodes.contains_key(&f),
            "inode must survive while alias links remain",
        );
        let still_there = vfs.lookup(root, "alias").unwrap();
        assert_eq!(still_there, f);
        // Chunks MUST still be live (not in free_chunks).
        for cref in &orig_chunks {
            assert!(
                !vfs.tree.free_chunks.contains(&cref.id),
                "chunk {} freed prematurely while alias still references it",
                cref.id
            );
        }
        // Reading through the surviving alias still works.
        let mut buf = vec![0u8; b"shared payload".len()];
        vfs.read(still_there, 0, &mut buf).unwrap();
        assert_eq!(buf, b"shared payload");

        // Now unlink the LAST link. nlink: 1 -> 0. Inode + chunks
        // must finally be freed.
        vfs.unlink(root, "alias").unwrap();
        assert!(!vfs.tree.inodes.contains_key(&f));
        for cref in &orig_chunks {
            assert!(
                vfs.tree.free_chunks.contains(&cref.id),
                "chunk {} must be freed after the last link is removed",
                cref.id
            );
        }
    }

    /// Multi-link round-trip through flush + reopen. The persisted
    /// link_count must match the directory-entry count after reload
    /// (otherwise `validate_metadata_tree` rejects the vault).
    #[test]
    fn hardlinks_persist_across_flush_and_reopen() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("a.lbx");
        {
            let mut vfs = Vfs::open(create_container(&path)).unwrap();
            let root = vfs.root_id();
            let f = vfs.create(root, "a").unwrap();
            vfs.write(f, 0, b"hardlinked").unwrap();
            vfs.link(f, root, "b").unwrap();
            vfs.link(f, root, "c").unwrap();
            assert_eq!(vfs.stat(f).unwrap().link_count, 3);
            vfs.flush().unwrap();
            assert!(vfs.uses_v4_metadata());
        }
        let mut vfs = Vfs::open(open_container(&path)).unwrap();
        assert!(vfs.uses_v4_metadata());
        let root = vfs.root_id();
        // All three names resolve to the same inode.
        let ia = vfs.lookup(root, "a").unwrap();
        let ib = vfs.lookup(root, "b").unwrap();
        let ic = vfs.lookup(root, "c").unwrap();
        assert_eq!(ia, ib);
        assert_eq!(ib, ic);
        assert_eq!(vfs.stat(ia).unwrap().link_count, 3);
    }

    /// **Security**: a forged-in-memory inode with `link_count = 0`
    /// (which could only happen via a future bug or attacker-
    /// authored vault) must be rejected at flush time. The v4 read
    /// path also rejects link_count == 0 at load, but defense-in-
    /// depth: catch it at write too so we never persist a vault
    /// that the next reader would reject.
    #[test]
    fn forged_link_count_zero_is_rejected_at_flush() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("a.lbx");
        let mut vfs = Vfs::open(create_container(&path)).unwrap();
        let root = vfs.root_id();
        let f = vfs.create(root, "x").unwrap();
        // Forge link_count = 0 (impossible via the public API).
        vfs.tree.inodes.get_mut(&f).unwrap().link_count = 0;
        vfs.dirty = true;
        match vfs.flush() {
            Err(Error::MetadataDeserialize) => {} // validator caught it
            Ok(()) => panic!("flush must reject link_count == 0"),
            Err(e) => panic!("expected MetadataDeserialize, got {e:?}"),
        }
    }

    /// **Security**: link() must reject targets that are directories.
    /// POSIX bans dir hardlinks; allowing them would make `is_
    /// descendant_of` cycle-guard miss cycles created via hardlink
    /// instead of rename, and the next traversal (readdir, flush,
    /// rotate_mvk) would loop forever.
    #[test]
    fn link_rejects_directory_target() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("a.lbx");
        let mut vfs = Vfs::open(create_container(&path)).unwrap();
        let root = vfs.root_id();
        let d = vfs.mkdir(root, "d").unwrap();
        assert!(matches!(
            vfs.link(d, root, "d_alias"),
            Err(Error::IsADirectory)
        ));
        // Tree byte-identical: no entry created, nlink unchanged.
        assert!(vfs.lookup(root, "d_alias").is_err());
        assert_eq!(vfs.stat(d).unwrap().link_count, 1);
    }

    /// **Security**: link() rejects duplicate target name in
    /// new_parent. The alternative (replace) would silently free
    /// the displaced inode without refcount-decrementing the OTHER
    /// directory entries pointing at it -- same use-after-free
    /// class as the unsafe-unlink case.
    #[test]
    fn link_rejects_collision_with_existing_entry() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("a.lbx");
        let mut vfs = Vfs::open(create_container(&path)).unwrap();
        let root = vfs.root_id();
        let f = vfs.create(root, "src").unwrap();
        vfs.create(root, "taken").unwrap();
        assert!(matches!(
            vfs.link(f, root, "taken"),
            Err(Error::AlreadyExists)
        ));
        assert_eq!(vfs.stat(f).unwrap().link_count, 1);
    }

    /// **Security defense-in-depth**: u32::MAX hardlinks is
    /// astronomical (would need 4 TiB of directory entries) but
    /// the overflow guard must still fire. Without it,
    /// `saturating_add(1)` would cap silently and the next unlink
    /// would over-decrement (subtracting from a "true" count of
    /// MAX+1 + saturated link wouldn't match the entry count, so
    /// flush would reject -- but we belt-and-suspenders here).
    #[test]
    fn link_rejects_when_link_count_would_overflow_u32() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("a.lbx");
        let mut vfs = Vfs::open(create_container(&path)).unwrap();
        let root = vfs.root_id();
        let f = vfs.create(root, "x").unwrap();
        // Set link_count to the cap, bypassing the public link()
        // (which is exactly what we're stress-testing).
        vfs.tree.inodes.get_mut(&f).unwrap().link_count = u32::MAX;
        assert!(matches!(
            vfs.link(f, root, "alias"),
            Err(Error::AlreadyExists) // mapped to EMLINK at FUSE
        ));
    }

    /// **Security**: refcount-aware unlink uses `saturating_sub(1)`
    /// so a corrupt in-memory link_count of 0 doesn't wrap to
    /// u32::MAX (which would let unlimited unlinks succeed without
    /// freeing chunks). After saturating-sub, the worst case is
    /// "chunks leak"; without it, the worst case would be "chunks
    /// reallocated to a different file, ciphertext substitution".
    #[test]
    fn unlink_saturates_on_zero_link_count_without_underflow() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("a.lbx");
        let mut vfs = Vfs::open(create_container(&path)).unwrap();
        let root = vfs.root_id();
        let f = vfs.create(root, "x").unwrap();
        // Forge link_count = 0 (corrupt). Saturating-sub would
        // keep it at 0 (not wrap to MAX), so unlink frees the
        // chunks immediately even though the public path normally
        // never reaches link_count == 0 while an entry is present.
        vfs.tree.inodes.get_mut(&f).unwrap().link_count = 0;
        vfs.unlink(root, "x").unwrap();
        assert!(!vfs.tree.inodes.contains_key(&f));
        // Did NOT wrap: a second unlink (impossible here -- entry
        // is gone -- but the invariant of saturating-sub matters
        // for the case where the entry remained).
    }

    // ============================================================
    // Symlink security tests
    // ============================================================
    //
    // Threat model: a vault is a supply-chain artifact. An attacker
    // distributes a "useful" vault with a passphrase they control.
    // The victim mounts it, browses with a file manager, or any
    // tool auto-previews symlinks. Without our sanitization, a
    // vault containing `secret -> /etc/shadow` would let the
    // attacker exfiltrate host files via the victim's UID. Same
    // CVE class as CVE-2018-1002200 / CVE-2017-1000117.
    //
    // The defense is `is_safe_symlink_target`, enforced at:
    //   1. `Vfs::symlink` create-time
    //   2. `v4_on_disk_to_in_memory` load-time (so a forged vault
    //      authored by a non-LUKSbox tool is rejected at open)
    //   3. `validate_metadata_tree` flush-time (so a forged in-
    //      memory tree can't be persisted)
    //
    // These tests pin all three layers.

    #[test]
    fn is_safe_symlink_target_blocks_absolute_paths() {
        assert!(!is_safe_symlink_target("/etc/shadow"));
        assert!(!is_safe_symlink_target("/"));
        assert!(!is_safe_symlink_target("\\Windows\\System32"));
        assert!(!is_safe_symlink_target("C:\\Windows"));
        assert!(!is_safe_symlink_target("c:relative"));
    }

    #[test]
    fn is_safe_symlink_target_blocks_traversal_components() {
        assert!(!is_safe_symlink_target(".."));
        assert!(!is_safe_symlink_target("../etc/shadow"));
        assert!(!is_safe_symlink_target("a/../b"));
        assert!(!is_safe_symlink_target("a/b/.."));
        assert!(!is_safe_symlink_target("..\\..\\hosts"));
        // single `.` also rejected per design
        assert!(!is_safe_symlink_target("./a"));
        assert!(!is_safe_symlink_target("a/./b"));
    }

    #[test]
    fn is_safe_symlink_target_blocks_nul_and_empty_and_oversize() {
        assert!(!is_safe_symlink_target(""));
        assert!(!is_safe_symlink_target("file\0bytes"));
        let too_long = "a".repeat(crate::tree::MAX_SYMLINK_TARGET_LEN + 1);
        assert!(!is_safe_symlink_target(&too_long));
        // Exactly at the cap is OK.
        let at_cap = "a".repeat(crate::tree::MAX_SYMLINK_TARGET_LEN);
        assert!(is_safe_symlink_target(&at_cap));
    }

    #[test]
    fn is_safe_symlink_target_accepts_ordinary_relative_paths() {
        assert!(is_safe_symlink_target("README.md"));
        assert!(is_safe_symlink_target("subdir/file"));
        assert!(is_safe_symlink_target("a/b/c/d.txt"));
        assert!(is_safe_symlink_target("name-with-dashes"));
        assert!(is_safe_symlink_target("name with spaces"));
    }

    /// Vfs::symlink end-to-end: create, stat, readlink, persist.
    #[test]
    fn symlink_create_stat_readlink_persist_roundtrip() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("a.lbx");
        let id = {
            let mut vfs = Vfs::open(create_container(&path)).unwrap();
            let root = vfs.root_id();
            vfs.create(root, "target.txt").unwrap();
            let id = vfs.symlink(root, "link", "target.txt").unwrap();
            let stat = vfs.stat(id).unwrap();
            assert_eq!(stat.kind, InodeKind::Symlink);
            assert_eq!(vfs.readlink(id).unwrap(), "target.txt");
            vfs.flush().unwrap();
            assert!(vfs.uses_v4_metadata(), "symlink must force LBM4 upgrade");
            id
        };
        let mut vfs = Vfs::open(open_container(&path)).unwrap();
        assert!(vfs.uses_v4_metadata());
        assert_eq!(vfs.readlink(id).unwrap(), "target.txt");
    }

    /// **CRITICAL SECURITY**: `secret -> /etc/shadow` style targets
    /// are rejected at create time.
    #[test]
    fn symlink_rejects_absolute_target_etc_shadow_attack() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("a.lbx");
        let mut vfs = Vfs::open(create_container(&path)).unwrap();
        let root = vfs.root_id();
        assert!(matches!(
            vfs.symlink(root, "evil", "/etc/shadow"),
            Err(Error::InvalidPath(_))
        ));
        assert!(matches!(
            vfs.symlink(root, "evil2", "\\Windows\\System32\\drivers\\etc\\hosts"),
            Err(Error::InvalidPath(_))
        ));
        // No inode was created.
        assert!(vfs.lookup(root, "evil").is_err());
        assert!(vfs.lookup(root, "evil2").is_err());
    }

    /// **CRITICAL SECURITY**: relative-with-traversal targets
    /// (`../../etc/shadow`) are rejected too.
    #[test]
    fn symlink_rejects_traversal_target() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("a.lbx");
        let mut vfs = Vfs::open(create_container(&path)).unwrap();
        let root = vfs.root_id();
        assert!(matches!(
            vfs.symlink(root, "escape", "../../../etc/shadow"),
            Err(Error::InvalidPath(_))
        ));
        assert!(matches!(
            vfs.symlink(root, "subtle", "valid/../../etc/shadow"),
            Err(Error::InvalidPath(_))
        ));
    }

    /// **CRITICAL SECURITY (load-time)**: a vault forged with a
    /// malicious symlink target -- which our `Vfs::symlink` would
    /// never have produced -- must be REJECTED at `Vfs::open` time
    /// so the FUSE readlink callback never returns the bytes to
    /// the kernel.
    #[test]
    fn forged_malicious_symlink_target_rejected_at_open() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("a.lbx");
        // First, create a legitimate vault with a legitimate symlink.
        {
            let mut vfs = Vfs::open(create_container(&path)).unwrap();
            let root = vfs.root_id();
            vfs.create(root, "real.txt").unwrap();
            vfs.symlink(root, "link", "real.txt").unwrap();
            vfs.flush().unwrap();
        }
        // Open, mutate the symlink target in memory to the attack
        // string, force a flush. The validator MUST refuse.
        {
            let mut vfs = Vfs::open(open_container(&path)).unwrap();
            let root = vfs.root_id();
            let link_id = vfs.lookup(root, "link").unwrap();
            vfs.tree.inodes.get_mut(&link_id).unwrap().symlink_target =
                Some("/etc/shadow".to_string());
            vfs.dirty = true;
            assert!(matches!(vfs.flush(), Err(Error::MetadataDeserialize)));
        }
    }

    /// Symlink rejects empty-name, oversize, and NUL via the
    /// underlying `validate_name` on the link's own name.
    #[test]
    fn symlink_link_name_uses_validate_name() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("a.lbx");
        let mut vfs = Vfs::open(create_container(&path)).unwrap();
        let root = vfs.root_id();
        assert!(matches!(
            vfs.symlink(root, "", "target"),
            Err(Error::InvalidPath(_))
        ));
        assert!(matches!(
            vfs.symlink(root, "name/with/slash", "target"),
            Err(Error::InvalidPath(_))
        ));
        assert!(matches!(
            vfs.symlink(root, "name\\with\\backslash", "target"),
            Err(Error::InvalidPath(_))
        ));
    }

    /// Symlinks cannot be hardlinked (LBM4 format invariant: one
    /// directory entry per symlink inode).
    #[test]
    fn link_rejects_symlink_target() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("a.lbx");
        let mut vfs = Vfs::open(create_container(&path)).unwrap();
        let root = vfs.root_id();
        let sym = vfs.symlink(root, "link", "target").unwrap();
        assert!(matches!(vfs.link(sym, root, "link2"), Err(Error::NotAFile)));
    }

    /// Unlink works on symlinks (POSIX `unlink(2)` removes regular
    /// files AND symlinks; only directories require `rmdir`).
    #[test]
    fn unlink_works_on_symlinks() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("a.lbx");
        let mut vfs = Vfs::open(create_container(&path)).unwrap();
        let root = vfs.root_id();
        let sym = vfs.symlink(root, "link", "target").unwrap();
        vfs.unlink(root, "link").unwrap();
        assert!(!vfs.tree.inodes.contains_key(&sym));
        assert!(vfs.lookup(root, "link").is_err());
    }

    /// readlink on a non-symlink returns NotAFile (mapped to
    /// EINVAL at the mount layer).
    #[test]
    fn readlink_on_file_or_dir_fails_cleanly() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("a.lbx");
        let mut vfs = Vfs::open(create_container(&path)).unwrap();
        let root = vfs.root_id();
        let f = vfs.create(root, "f").unwrap();
        assert!(matches!(vfs.readlink(f), Err(Error::NotAFile)));
        assert!(matches!(vfs.readlink(root), Err(Error::NotAFile)));
    }

    #[test]
    fn write_fails_with_metadata_budget_exhausted_when_region_too_small() {
        // Pre-fix bug: writing more chunks than fit in the metadata
        // region produced silent data loss -- the chunks landed on disk
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
    fn v0_2_0_style_vault_auto_upgrades_to_luksbox2_on_first_flush() {
        // A v0.2.0 on-disk vault is characterised by:
        //   - header magic LUKSBOX1 (header.version_major == 1)
        //   - metadata magic LBM2 (set_format_v3_override(Some(false)))
        //   - no mirror sidecars
        //
        // We can't construct that exact state via the v0.2.1 code path
        // because the first flush itself triggers the auto-upgrade.
        // What we test instead is that, given a freshly created vault
        // built with the v0.2.0 envelope (LUKSBOX1 + LBM2 + no
        // mirrors), the FIRST flush flips it to LUKSBOX2 + LBM5 with
        // mirrors. The simulation is faithful because the on-disk
        // bytes are byte-for-byte identical to what a v0.2.0 binary
        // would have written.
        let dir = tempdir().unwrap();
        let path = dir.path().join("upgrade.lbx");
        // Phase 1: create a v0.2.0-style vault and write some
        // metadata so the on-disk blob carries a real LBM2 magic
        // (not empty). The format override forces v2 metadata; the
        // header is v1 by default of Header::try_new. After this
        // block the vault on disk is indistinguishable from one a
        // v0.2.0 binary would have produced.
        {
            let _v2 = set_format_v3_override(Some(false));
            let mut vfs = Vfs::open(create_container(&path)).unwrap();
            let root = vfs.root_id();
            let f = vfs.create(root, "before.txt").unwrap();
            vfs.write(f, 0, b"pre-upgrade").unwrap();
            // Force the v1 header + v2 metadata wire image. The flush
            // we're about to call here would (with v0.2.1 logic)
            // auto-upgrade -- we want this flush to NOT do that so we
            // can test the upgrade firing on a SECOND, post-reopen
            // flush. Temporarily revert the in-memory state right
            // before flush so this flush behaves like a v0.2.0 flush.
            vfs.container.header.version_major = luksbox_core::VERSION_MAJOR_V1;
            vfs.format = MetadataFormat::V2;
            // Bypass the upgrade trigger by writing directly through
            // the v2-format path. We call the normal flush() but the
            // upgrade-on-v1 guard then bumps it back; to suppress
            // that we manually serialize the v2 blob and write it.
            // Easiest: just exit without flushing, then write the
            // blob through a private path. Cleaner approach below
            // bypasses the auto-upgrade via a temporary override of
            // the format check by writing the bytes directly.
            let payload = postcard::to_allocvec(&vfs.tree)
                .map_err(|_| Error::MetadataSerialize)
                .unwrap();
            let mut bytes = Vec::with_capacity(METADATA_V2_MAGIC.len() + payload.len());
            bytes.extend_from_slice(METADATA_V2_MAGIC);
            bytes.extend_from_slice(&payload);
            vfs.container.write_metadata(&bytes).unwrap();
            vfs.dirty = false;
            // Don't call vfs.flush() (it would auto-upgrade). Drop
            // here triggers Container::drop -> persist_header, which
            // in v1 mode writes the header in place without mirrors.
        }
        let mirror_meta = path.with_file_name(format!(
            "{}.meta-bak",
            path.file_name().unwrap().to_string_lossy()
        ));
        let mirror_header = path.with_file_name(format!(
            "{}.header-bak",
            path.file_name().unwrap().to_string_lossy()
        ));
        assert!(
            !mirror_meta.exists(),
            "phase 1 (just-created v0.2.0-style vault): no metadata mirror should exist yet"
        );
        assert!(
            !mirror_header.exists(),
            "phase 1 (just-created v0.2.0-style vault): no header mirror should exist yet"
        );
        // Confirm the on-disk header magic is LUKSBOX1.
        {
            let raw_header = std::fs::read(&path).unwrap();
            assert_eq!(
                &raw_header[..8],
                &luksbox_core::MAGIC_V1,
                "phase 1: on-disk header should carry LUKSBOX1 magic"
            );
        }
        // Phase 2: reopen with the default v0.2.1 paths and trigger a
        // flush by writing a file. The flush must auto-upgrade to
        // LUKSBOX2 + V5 + mirrors-on-disk.
        {
            let mut vfs = Vfs::open(open_container(&path)).unwrap();
            assert_eq!(
                vfs.container.header.version_major,
                luksbox_core::VERSION_MAJOR_V1,
                "phase 2 entry: in-memory header still v1 (matches disk)"
            );
            assert!(
                !vfs.uses_v3_metadata(),
                "phase 2 entry: in-memory format still v2 (matches disk)"
            );
            let root = vfs.root_id();
            let f = vfs.create(root, "after.txt").unwrap();
            vfs.write(f, 0, b"post-upgrade").unwrap();
            vfs.flush().unwrap();
            assert!(vfs.uses_v5_metadata(), "flush must upgrade to V5");
            assert_eq!(
                vfs.container.header.version_major,
                luksbox_core::VERSION_MAJOR_V2,
                "flush must upgrade header to LUKSBOX2"
            );
        }
        // Phase 3: confirm on-disk state: LUKSBOX2 magic, both
        // mirrors present.
        {
            let raw_header = std::fs::read(&path).unwrap();
            assert_eq!(
                &raw_header[..8],
                &luksbox_core::MAGIC_V2,
                "phase 3: on-disk header must carry LUKSBOX2 magic after upgrade"
            );
            assert!(
                mirror_meta.exists(),
                "phase 3: metadata mirror must exist after upgrade"
            );
            assert!(
                mirror_header.exists(),
                "phase 3: header mirror must exist after upgrade"
            );
        }
        // Phase 4: reopen with v0.2.1 binary one more time and check
        // the file written in phase 2 is still readable through the
        // upgraded format.
        {
            let mut vfs = Vfs::open(open_container(&path)).unwrap();
            assert!(vfs.uses_v5_metadata());
            let root = vfs.root_id();
            let after = vfs.lookup(root, "after.txt").unwrap();
            let mut buf = [0u8; 64];
            let n = vfs.read(after, 0, &mut buf).unwrap();
            assert_eq!(&buf[..n], b"post-upgrade");
        }
    }

    #[test]
    fn v5_format_writes_lbm5_magic_to_disk() {
        // Fresh vaults default to v5. After flush, the on-disk
        // metadata blob must carry the LBM\x05 magic so older binaries
        // refuse it cleanly.
        let dir = tempdir().unwrap();
        let path = dir.path().join("v5.lbx");
        {
            let mut vfs = Vfs::open(create_container(&path)).unwrap();
            assert!(vfs.uses_v5_metadata(), "fresh vault must default to V5");
            let root = vfs.root_id();
            let f = vfs.create(root, "hello").unwrap();
            vfs.write(f, 0, b"v5 payload").unwrap();
            vfs.flush().unwrap();
        }
        // Reopen with a fresh container and verify on-disk magic.
        let mut c = open_container(&path);
        let raw = c.read_metadata().unwrap();
        assert!(
            raw.starts_with(METADATA_V5_MAGIC),
            "v5 vault must serialise with LBM5 magic, got prefix {:?}",
            &raw[..raw.len().min(8)]
        );
        // And the read path must accept LBM5 and round-trip the data.
        let vfs = Vfs::open(c).unwrap();
        assert!(vfs.uses_v5_metadata());
    }

    #[test]
    fn v5_spill_threshold_is_lower_than_v3() {
        // The whole point of v5 is the lower threshold; pin it so a
        // future accidental bump back to 1024 fails this test.
        assert!(
            MetadataFormat::V5.inline_chunk_threshold()
                < MetadataFormat::V4.inline_chunk_threshold(),
            "v5 threshold must be < v4 threshold (otherwise v5 buys nothing)"
        );
        assert_eq!(
            MetadataFormat::V5.inline_chunk_threshold(),
            crate::tree::V5_INLINE_CHUNK_THRESHOLD
        );
    }

    #[test]
    fn write_succeeds_inside_default_metadata_budget() {
        // Sanity: with the default 16 MiB region, writing well under
        // the budget must succeed -- make sure the pre-flight isn't
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
        assert!(
            vfs.uses_v3_metadata(),
            "reopen must detect v3 from LBM3 magic"
        );
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
        assert_eq!(
            vfs.tree.inodes[&f].external_list_blocks.len(),
            externals.len()
        );
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
        assert!(
            vfs.uses_v3_metadata(),
            "deniable vault must respect the v3 override"
        );
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
        assert_eq!(
            got, payload,
            "deniable v3 file must round-trip byte-for-byte"
        );
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
        // Write a small payload (no need to spill -- tests the
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
            None,
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
        // The guard must stay alive across Vfs::open -- that's where
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
                    InodeKind::Symlink => {
                        let target = src.readlink(e.id).unwrap();
                        dst.symlink(ddir, &e.name, &target).unwrap();
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
        // big write -- must still trip MetadataBudgetExhausted.
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
    fn v3_walk_chunk_list_chain_caps_expected_count() {
        // DoS hardening: walk_chunk_list_chain takes expected_count
        // straight from the on-disk InodeV3OnDisk's chunks_external
        // tuple. A forged metadata blob (requires MVK, but is the
        // realistic post-MVK-compromise DoS) could claim
        // expected_count = u64::MAX and drive the walk's max_blocks
        // bound to ~7e16 iterations. The cap at
        // MAX_FILE_SIZE / CHUNK_PLAINTEXT_SIZE = 2^32 cuts that off
        // before any chunk-list read happens.
        use crate::chunk::walk_chunk_list_chain;
        let dir = tempdir().unwrap();
        let path = dir.path().join("walk-cap.lbx");
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
        let f = vfs.create(root, "x").unwrap();
        // Tiny write so we have a real ChunkRef to feed as head (the
        // walk will read it as a chunk-list block, which fails AEAD --
        // but the cap-check fires BEFORE the read, so we never reach
        // the AEAD path. Verifying the early-return is the point.).
        vfs.write(f, 0, b"hi").unwrap();
        let head = vfs.tree.inodes[&f].chunks[0];

        // Honest legitimate count is fine -- it doesn't trip the cap
        // even though the walk itself would fail AEAD on this fake
        // chain (we don't actually have a chunk-list block here).
        // Just confirms the cap doesn't block valid claims.
        let limit: u64 = (1u64 << 44) / 4096; // = 1 << 32
        // Now try expected_count above the cap. Must error with
        // InvalidField BEFORE any IO.
        let too_big = limit + 1;
        let err = walk_chunk_list_chain(&mut vfs.container, f, head, too_big)
            .err()
            .expect("walk must refuse expected_count beyond MAX_FILE_SIZE/CHUNK_SIZE");
        // Type-check the error: Crypto(InvalidField).
        match err {
            Error::Crypto(luksbox_core::Error::InvalidField) => {}
            other => panic!("expected Crypto(InvalidField), got {other:?}"),
        }

        // And u64::MAX too -- the saturating math in max_blocks
        // wouldn't have helped without the upfront cap.
        let err = walk_chunk_list_chain(&mut vfs.container, f, head, u64::MAX)
            .err()
            .expect("walk must refuse u64::MAX expected_count");
        assert!(matches!(
            err,
            Error::Crypto(luksbox_core::Error::InvalidField)
        ));
    }

    #[test]
    fn v3_aad_isolation_data_chunks_and_list_blocks_cannot_be_swapped() {
        // Crypto invariant: even though data chunks and chunk-list
        // blocks share the same data area, their AEAD keys (file_key
        // vs list_file_key) and AADs (file_id vs synthetic file_id
        // with high bit set) are disjoint by construction. An
        // attacker who somehow places a data chunk's ciphertext into
        // a chunk-list block's slot (or vice versa) cannot make it
        // decrypt -- even with full MVK access, derivation of the
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
        //    FAIL -- wrong key + wrong AAD.
        let list_key = list_file_key(&vfs.container, file_id);
        let synth_id = file_id | CHUNK_LIST_FILE_ID_BIT;
        let err = read_chunk(&mut vfs.container, &list_key, synth_id, 0, data_chunk_ref)
            .err()
            .expect("data chunk must NOT decrypt under list key");
        // Crypto error of some kind -- we don't care which variant,
        // just that the AEAD refused.
        assert!(
            matches!(err, Error::Crypto(_)),
            "expected AEAD failure, got {err:?}"
        );

        // 3. Decrypting the list block under the DATA file_key with
        //    the DATA AAD shape (real file_id, chunk_idx=0) must
        //    also FAIL -- symmetric guarantee.
        let err = read_chunk(&mut vfs.container, &data_key, file_id, 0, list_block_ref)
            .err()
            .expect("list block must NOT decrypt under data key");
        assert!(
            matches!(err, Error::Crypto(_)),
            "expected AEAD failure, got {err:?}"
        );

        // 4. The legitimate walk over the chain MUST still succeed --
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
        assert!(
            blocks_before > 0,
            "test precondition: file must have spilled"
        );

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
                mode: crate::tree::DEFAULT_FILE_MODE,
                link_count: 1,
                symlink_target: None,
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
