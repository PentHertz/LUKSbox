// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Penthertz <https://penthertz.com> (https://x.com/PentHertz)

//! `<vault>.lbx.hybrid` sidecar format. Holds the public Kyber blobs
//! (encapsulation key + ciphertext) for every hybrid keyslot in the
//! vault, indexed by slot number.
//!
//! ## v3 wire format (current default for new writes)
//!
//! Adds a 32-byte vault binding (a copy of the vault's `header_salt`)
//! to the sidecar header. Callers who load the sidecar for a known
//! vault can compare against the salt they read from the header file
//! and detect cross-vault sidecar swaps BEFORE running ML-KEM decap +
//! AEAD verification. The salt is already published in the (non-
//! encrypted) container header, so storing a copy in the sidecar
//! leaks zero additional information.
//!
//! ```text
//! magic         8 B   "lbxhybr1" (ASCII; unchanged)
//! version       1 B   0x03
//! count         1 B   number of populated entries (max 8)
//! reserved      6 B   zero-pad
//! header_salt  32 B   copy of the vault's header_salt (binding)
//! entries       variable per entry x count (same shape as v2)
//! ```
//!
//! ## v2 wire format (legacy read; written when caller has no salt)
//!
//! ```text
//! magic         8 B   "lbxhybr1"
//! version       1 B   0x02
//! count         1 B
//! reserved      6 B   zero-pad
//! entries       variable per entry x count
//!                  slot_idx     1 B
//!                  level        1 B   1 = ML-KEM-768, 2 = ML-KEM-1024
//!                  pubkey      1184 B (level=1) or 1568 B (level=2)
//!                  ciphertext  1088 B (level=1) or 1568 B (level=2)
//! ```
//!
//! ## v1 wire format (legacy read-only)
//!
//! v1 omitted the `level` byte and assumed ML-KEM-768 throughout.
//! Existing vaults created before LUKSbox added ML-KEM-1024 support
//! still use v1; the reader auto-detects via the version byte and
//! treats every entry as `level = 1`.
//!
//! Even without v3, tampering is caught by the existing AEAD tag on
//! the slot's `wrapped_mvk`: a flipped byte in the sidecar's pubkey or
//! ciphertext produces a different shared key (FIPS 203 Sec.6.3
//! implicit rejection), the wrong combined KEK, and AEAD tag
//! verification fails cleanly. v3 promotes this from "fails at
//! decrypt" to "fails at parse with a clear error", which is both
//! faster and produces better diagnostics for legitimate users who
//! accidentally cross-pollinated sidecars between vaults.

use std::fs;
use std::io::Read;
use std::path::{Path, PathBuf};

use luksbox_core::file_util::atomic_secure_write;
use luksbox_pq::PqParams;

use crate::Error;

/// Round 12 fix R12-06 / Round 13 fix R13-06: read the hybrid sidecar
/// with `O_NOFOLLOW` so an attacker who swapped the `.hybrid` file for
/// a symlink (e.g. to `/etc/passwd` or to a FIFO that stalls forever)
/// is refused at the format layer. Mirrors `anchor::open_anchor_for_read`.
///
/// R13-06: also size-bound the read. The hybrid sidecar is at most
/// `HEADER_LEN_V3 + MAX_ENTRIES * MAX_ENTRY_LEN` bytes (about 23 KiB).
/// Without an upper bound a hostile sidecar (or a device file) could
/// cause `read_to_end` to allocate gigabytes before the length-check
/// rejects it. We `stat` first, refuse non-regular files, refuse files
/// larger than the cap, then `read_exact`.
///
/// Windows: open with `FILE_FLAG_OPEN_REPARSE_POINT` and refuse the
/// file if `FILE_ATTRIBUTE_REPARSE_POINT` is set (mirrors
/// `luksbox-core::file_util::secure_create_or_truncate`). Closes the
/// R12-15 follow-up that left Windows hybrid sidecars exposed to
/// reparse-point swaps under `%LOCALAPPDATA%`.
fn read_sidecar_bytes(path: &Path) -> std::io::Result<Vec<u8>> {
    // Upper bound: v3 header + 8 entries each at the larger ML-KEM-1024
    // shape (1 + 1 + 1568 + 1568 = 3138 B). Cap rounded up to 32 KiB
    // for headroom against future entry-shape growth.
    const MAX_SIDECAR_BYTES: u64 = 32 * 1024;
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        let mut f = fs::OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW)
            .open(path)?;
        let meta = f.metadata()?;
        if !meta.is_file() {
            return Err(std::io::Error::other(format!(
                "hybrid sidecar {}: not a regular file (refusing FIFO/device/dir)",
                path.display()
            )));
        }
        if meta.len() > MAX_SIDECAR_BYTES {
            return Err(std::io::Error::other(format!(
                "hybrid sidecar {}: {} bytes exceeds max {} (DoS preflight)",
                path.display(),
                meta.len(),
                MAX_SIDECAR_BYTES
            )));
        }
        let mut buf = vec![0u8; meta.len() as usize];
        f.read_exact(&mut buf)?;
        Ok(buf)
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt as _;
        use std::os::windows::fs::OpenOptionsExt as _;
        // FILE_FLAG_OPEN_REPARSE_POINT = 0x00200000
        let mut f = fs::OpenOptions::new()
            .read(true)
            .custom_flags(0x0020_0000)
            .open(path)?;
        let meta = f.metadata()?;
        // FILE_ATTRIBUTE_REPARSE_POINT = 0x00000400
        if meta.file_attributes() & 0x0000_0400 != 0 {
            return Err(std::io::Error::other(format!(
                "hybrid sidecar {}: is a reparse point (symlink/junction); refused",
                path.display()
            )));
        }
        if meta.len() > MAX_SIDECAR_BYTES {
            return Err(std::io::Error::other(format!(
                "hybrid sidecar {}: {} bytes exceeds max {} (DoS preflight)",
                path.display(),
                meta.len(),
                MAX_SIDECAR_BYTES
            )));
        }
        let mut buf = vec![0u8; meta.len() as usize];
        f.read_exact(&mut buf)?;
        Ok(buf)
    }
    #[cfg(not(any(unix, windows)))]
    {
        let bytes = fs::read(path)?;
        if bytes.len() as u64 > MAX_SIDECAR_BYTES {
            return Err(std::io::Error::other("hybrid sidecar exceeds size cap"));
        }
        Ok(bytes)
    }
}

const MAGIC: [u8; 8] = *b"lbxhybr1";
const VERSION_V1: u8 = 0x01;
const VERSION_V2: u8 = 0x02;
const VERSION_V3: u8 = 0x03;
const HEADER_LEN: usize = 16;
const BINDING_LEN: usize = 32;
const HEADER_LEN_V3: usize = HEADER_LEN + BINDING_LEN;

const PUBKEY_LEN_768: usize = 1184;
const CIPHERTEXT_LEN_768: usize = 1088;
#[allow(dead_code)]
const PUBKEY_LEN_1024: usize = 1568;
#[allow(dead_code)]
const CIPHERTEXT_LEN_1024: usize = 1568;

const ENTRY_LEN_V1: usize = 1 + PUBKEY_LEN_768 + CIPHERTEXT_LEN_768;
const MAX_ENTRIES: usize = 8;

#[derive(Clone)]
pub struct HybridEntry {
    pub slot_idx: u8,
    pub level: PqParams,
    pub pubkey: Vec<u8>,
    pub ciphertext: Vec<u8>,
}

impl HybridEntry {
    /// Convenience constructor for ML-KEM-768 entries (the default
    /// when callers don't specify a level explicitly).
    pub fn new_ml768(slot_idx: u8, pubkey: Vec<u8>, ciphertext: Vec<u8>) -> Self {
        Self {
            slot_idx,
            level: PqParams::Ml768,
            pubkey,
            ciphertext,
        }
    }

    /// Convenience constructor for ML-KEM-1024 entries.
    pub fn new_ml1024(slot_idx: u8, pubkey: Vec<u8>, ciphertext: Vec<u8>) -> Self {
        Self {
            slot_idx,
            level: PqParams::Ml1024,
            pubkey,
            ciphertext,
        }
    }
}

/// Conventional sidecar path for a given vault, `<vault>.hybrid`.
pub fn sidecar_path(vault: &Path) -> PathBuf {
    let mut p = vault.as_os_str().to_owned();
    p.push(".hybrid");
    PathBuf::from(p)
}

/// Result of `read_bundle`: the parsed entries plus an optional
/// 32-byte vault binding (present iff the on-disk sidecar is v3).
/// Callers verify the binding against the vault's `header_salt`
/// before trusting the entries.
#[derive(Clone)]
pub struct SidecarBundle {
    pub entries: Vec<HybridEntry>,
    pub binding: Option<[u8; BINDING_LEN]>,
}

/// v3 writer: writes a sidecar with a 32-byte vault binding header
/// field. Use this when the caller has the vault's `header_salt`
/// available; new code should prefer this over `write`.
pub fn write_with_binding(
    path: &Path,
    entries: &[HybridEntry],
    binding: &[u8; BINDING_LEN],
) -> Result<(), Error> {
    validate_entries(entries)?;
    let total: usize = HEADER_LEN_V3
        + entries
            .iter()
            .map(|e| 2 + e.pubkey.len() + e.ciphertext.len())
            .sum::<usize>();
    let mut buf = Vec::with_capacity(total);
    buf.extend_from_slice(&MAGIC);
    buf.push(VERSION_V3);
    buf.push(entries.len() as u8);
    buf.extend_from_slice(&[0u8; 6]);
    buf.extend_from_slice(binding);
    for e in entries {
        buf.push(e.slot_idx);
        buf.push(e.level.level_byte());
        buf.extend_from_slice(&e.pubkey);
        buf.extend_from_slice(&e.ciphertext);
    }
    atomic_secure_write(path, &buf)?;
    Ok(())
}

/// Read a sidecar and return the parsed entries plus binding (if v3).
/// Existing call sites that don't yet plumb the vault salt should use
/// `read` instead; both functions share the same parser.
pub fn read_bundle(path: &Path) -> Result<SidecarBundle, Error> {
    let bytes = read_sidecar_bytes(path)?;
    parse_bundle(&bytes)
}

/// In-memory parser; useful for fuzz harnesses that build the bytes
/// inline. Same semantics as `read_bundle`.
pub fn parse_bundle(bytes: &[u8]) -> Result<SidecarBundle, Error> {
    if bytes.len() < HEADER_LEN {
        return Err(Error::Io(std::io::Error::other(
            "hybrid sidecar too short for header",
        )));
    }
    if bytes[..8] != MAGIC {
        return Err(Error::Io(std::io::Error::other(
            "hybrid sidecar: missing magic bytes",
        )));
    }
    let version = bytes[8];
    let count = bytes[9] as usize;
    if count > MAX_ENTRIES {
        return Err(Error::Io(std::io::Error::other(format!(
            "hybrid sidecar: count {} exceeds max {}",
            count, MAX_ENTRIES
        ))));
    }
    let (entries, binding) = match version {
        VERSION_V1 => (read_v1_body(bytes, count)?, None),
        VERSION_V2 => (read_v2_body(bytes, count, HEADER_LEN)?, None),
        VERSION_V3 => {
            if bytes.len() < HEADER_LEN_V3 {
                return Err(Error::Io(std::io::Error::other(
                    "hybrid sidecar v3: too short for binding header",
                )));
            }
            let mut binding = [0u8; BINDING_LEN];
            binding.copy_from_slice(&bytes[HEADER_LEN..HEADER_LEN_V3]);
            (read_v2_body(bytes, count, HEADER_LEN_V3)?, Some(binding))
        }
        other => {
            return Err(Error::Io(std::io::Error::other(format!(
                "hybrid sidecar: unsupported version {} (expected 1, 2, or 3)",
                other
            ))));
        }
    };
    reject_duplicate_slot_idx(&entries)?;
    Ok(SidecarBundle { entries, binding })
}

/// Verify a sidecar's v3 binding against an expected `header_salt`.
/// Returns `Ok(())` if the sidecar is v3 and the binding matches, OR
/// if the sidecar is v1/v2 (no binding to check, older format).
/// Returns `Err` only on a v3 sidecar with a mismatching binding.
/// Convenience wrapper for unlock-time call sites: peek at the vault
/// header to recover `header_salt`, read the sidecar bundle, and
/// verify the v3 binding matches. Returns just the entries on
/// success (the bundle is consumed). v1/v2 sidecars (no binding to
/// check) pass through unchanged.
///
/// Use this instead of `read()` at every site where a sidecar load
/// immediately precedes a `Container::open` against the same vault.
/// Catches cross-vault sidecar swaps at sidecar load time, before
/// the wrong decap output flows into ML-KEM and the wrong combined
/// KEK reaches AEAD verification (which would have caught it
/// anyway, but later and with a worse error message).
pub fn read_for_vault(
    sidecar_path: &Path,
    vault_path: &Path,
    header_path: Option<&Path>,
) -> Result<Vec<HybridEntry>, Error> {
    let bundle = read_bundle(sidecar_path)?;
    // v1/v2 sidecars: no binding to verify; trust falls back to the
    // downstream AEAD tag the way it always has on older vaults.
    if bundle.binding.is_none() {
        return Ok(bundle.entries);
    }
    let salt = peek_vault_header_salt(vault_path, header_path)?;
    verify_binding(&bundle, &salt)?;
    Ok(bundle.entries)
}

/// Read just the 32-byte `header_salt` from a vault file (or its
/// detached-header sidecar). Used by `read_for_vault` to load the
/// vault binding without a full `Container::open` (which would
/// need credentials we don't have yet at this point).
fn peek_vault_header_salt(
    vault_path: &Path,
    header_path: Option<&Path>,
) -> Result<[u8; BINDING_LEN], Error> {
    use luksbox_core::HEADER_SIZE;
    let src = header_path.unwrap_or(vault_path);
    // Round 12 fix R12-06 (continued): pre-binding header peek also
    // refuses symlinks via `O_NOFOLLOW`. Without this an attacker
    // who controls the path between the GUI's preflight and
    // `read_for_vault`'s arrival could divert the salt read.
    #[cfg(unix)]
    let mut f = {
        use std::os::unix::fs::OpenOptionsExt as _;
        fs::OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW)
            .open(src)?
    };
    #[cfg(not(unix))]
    let mut f = fs::File::open(src)?;
    let mut buf = [0u8; HEADER_SIZE];
    f.read_exact(&mut buf)?;
    let header = luksbox_core::Header::from_bytes(&buf)
        .map_err(|e| Error::Io(std::io::Error::other(format!("peek header: {e}"))))?;
    Ok(header.header_salt)
}

pub fn verify_binding(
    bundle: &SidecarBundle,
    expected_salt: &[u8; BINDING_LEN],
) -> Result<(), Error> {
    match &bundle.binding {
        None => Ok(()),
        Some(b) => {
            // Constant-time compare to avoid signaling which byte
            // differed (defense-in-depth; the salt isn't secret but
            // habits matter).
            use subtle::ConstantTimeEq;
            if b.ct_eq(expected_salt).into() {
                Ok(())
            } else {
                Err(Error::Io(std::io::Error::other(
                    "hybrid sidecar v3: vault binding mismatch \
                     (sidecar belongs to a different vault, or vault \
                     header was rotated; rebuild the sidecar from the \
                     wizard)",
                )))
            }
        }
    }
}

fn validate_entries(entries: &[HybridEntry]) -> Result<(), Error> {
    if entries.len() > MAX_ENTRIES {
        return Err(Error::Io(std::io::Error::other(format!(
            "too many hybrid entries: {} (max {})",
            entries.len(),
            MAX_ENTRIES
        ))));
    }
    for e in entries {
        if e.pubkey.len() != e.level.public_key_len() {
            return Err(Error::Io(std::io::Error::other(format!(
                "hybrid entry {:?}: pubkey len {} != expected {}",
                e.level,
                e.pubkey.len(),
                e.level.public_key_len()
            ))));
        }
        if e.ciphertext.len() != e.level.ciphertext_len() {
            return Err(Error::Io(std::io::Error::other(format!(
                "hybrid entry {:?}: ciphertext len {} != expected {}",
                e.level,
                e.ciphertext.len(),
                e.level.ciphertext_len()
            ))));
        }
    }
    Ok(())
}

fn reject_duplicate_slot_idx(entries: &[HybridEntry]) -> Result<(), Error> {
    let mut seen = [false; 256];
    for e in entries {
        let key = e.slot_idx as usize;
        if seen[key] {
            return Err(Error::Io(std::io::Error::other(format!(
                "hybrid sidecar: duplicate entry for slot {} (rejected to \
                 eliminate find()-returns-first ambiguity; rebuild the \
                 sidecar from the wizard)",
                e.slot_idx
            ))));
        }
        seen[key] = true;
    }
    Ok(())
}

/// Legacy v2 writer. Prefer `write_with_binding` (v3) in new code:
/// v2 lacks the vault binding, so an attacker who can swap the
/// sidecar between two vaults causes a confusing AEAD failure rather
/// than a clear "wrong sidecar" error. v2 is kept for callers that
/// don't have the vault salt available (e.g. test harnesses).
pub fn write(path: &Path, entries: &[HybridEntry]) -> Result<(), Error> {
    validate_entries(entries)?;
    let total: usize = HEADER_LEN
        + entries
            .iter()
            .map(|e| 2 + e.pubkey.len() + e.ciphertext.len())
            .sum::<usize>();
    let mut buf = Vec::with_capacity(total);
    buf.extend_from_slice(&MAGIC);
    buf.push(VERSION_V2);
    buf.push(entries.len() as u8);
    buf.extend_from_slice(&[0u8; 6]);
    for e in entries {
        buf.push(e.slot_idx);
        buf.push(e.level.level_byte());
        buf.extend_from_slice(&e.pubkey);
        buf.extend_from_slice(&e.ciphertext);
    }
    // Round 9E: atomic_secure_write produces a random-named 0600
    // tmpfile, fsyncs, renames atomically.
    atomic_secure_write(path, &buf)?;
    Ok(())
}

/// Legacy reader that ignores any v3 binding. Existing call sites
/// use this; new code should call `read_bundle` + `verify_binding`
/// to reject cross-vault sidecar swaps at parse time instead of
/// post-AEAD-failure.
pub fn read(path: &Path) -> Result<Vec<HybridEntry>, Error> {
    Ok(read_bundle(path)?.entries)
}

fn read_v1_body(bytes: &[u8], count: usize) -> Result<Vec<HybridEntry>, Error> {
    let expected = HEADER_LEN + count * ENTRY_LEN_V1;
    if bytes.len() != expected {
        return Err(Error::Io(std::io::Error::other(format!(
            "hybrid sidecar v1: length {} != expected {}",
            bytes.len(),
            expected
        ))));
    }
    let mut entries = Vec::with_capacity(count);
    let mut off = HEADER_LEN;
    for _ in 0..count {
        let slot_idx = bytes[off];
        let pk = bytes[off + 1..off + 1 + PUBKEY_LEN_768].to_vec();
        let ct =
            bytes[off + 1 + PUBKEY_LEN_768..off + 1 + PUBKEY_LEN_768 + CIPHERTEXT_LEN_768].to_vec();
        entries.push(HybridEntry {
            slot_idx,
            level: PqParams::Ml768,
            pubkey: pk,
            ciphertext: ct,
        });
        off += ENTRY_LEN_V1;
    }
    Ok(entries)
}

fn read_v2_body(bytes: &[u8], count: usize, start_off: usize) -> Result<Vec<HybridEntry>, Error> {
    let mut entries = Vec::with_capacity(count);
    let mut off = start_off;
    for i in 0..count {
        if off + 2 > bytes.len() {
            return Err(Error::Io(std::io::Error::other(format!(
                "hybrid sidecar v2: truncated at entry {i}"
            ))));
        }
        let slot_idx = bytes[off];
        let level_byte = bytes[off + 1];
        let level = PqParams::from_level_byte(level_byte).map_err(|_| {
            Error::Io(std::io::Error::other(format!(
                "hybrid sidecar v2 entry {i}: unknown level byte {level_byte}"
            )))
        })?;
        let pk_len = level.public_key_len();
        let ct_len = level.ciphertext_len();
        let body_off = off + 2;
        let end = body_off + pk_len + ct_len;
        if end > bytes.len() {
            return Err(Error::Io(std::io::Error::other(format!(
                "hybrid sidecar v2: entry {i} ({:?}) overruns file (need {} bytes, have {})",
                level,
                end,
                bytes.len()
            ))));
        }
        let pk = bytes[body_off..body_off + pk_len].to_vec();
        let ct = bytes[body_off + pk_len..end].to_vec();
        entries.push(HybridEntry {
            slot_idx,
            level,
            pubkey: pk,
            ciphertext: ct,
        });
        off = end;
    }
    if off != bytes.len() {
        return Err(Error::Io(std::io::Error::other(format!(
            "hybrid sidecar v2: trailing {} bytes past last entry",
            bytes.len() - off
        ))));
    }
    Ok(entries)
}

/// Find the entry for a given slot index.
pub fn find<'a>(entries: &'a [HybridEntry], slot_idx: u8) -> Option<&'a HybridEntry> {
    entries.iter().find(|e| e.slot_idx == slot_idx)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::env::temp_dir;

    fn fake_768(idx: u8, pk_seed: u8, ct_seed: u8) -> HybridEntry {
        HybridEntry::new_ml768(
            idx,
            vec![pk_seed; PUBKEY_LEN_768],
            vec![ct_seed; CIPHERTEXT_LEN_768],
        )
    }

    fn fake_1024(idx: u8, pk_seed: u8, ct_seed: u8) -> HybridEntry {
        HybridEntry::new_ml1024(
            idx,
            vec![pk_seed; PUBKEY_LEN_1024],
            vec![ct_seed; CIPHERTEXT_LEN_1024],
        )
    }

    fn tmp(name: &str) -> PathBuf {
        let p = temp_dir().join(format!("luksbox-hybrid-test-{name}.hybrid"));
        let _ = fs::remove_file(&p);
        p
    }

    #[test]
    fn v2_round_trip_768_only() {
        let path = tmp("v2-768");
        let entries = vec![fake_768(0, 0x11, 0x22), fake_768(3, 0x33, 0x44)];
        write(&path, &entries).unwrap();
        let read_back = read(&path).unwrap();
        assert_eq!(read_back.len(), 2);
        assert_eq!(read_back[0].level, PqParams::Ml768);
        assert_eq!(read_back[0].pubkey, entries[0].pubkey);
        let _ = fs::remove_file(&path);
    }

    #[test]
    fn v2_round_trip_1024_only() {
        let path = tmp("v2-1024");
        let entries = vec![fake_1024(0, 0xaa, 0xbb)];
        write(&path, &entries).unwrap();
        let read_back = read(&path).unwrap();
        assert_eq!(read_back.len(), 1);
        assert_eq!(read_back[0].level, PqParams::Ml1024);
        assert_eq!(read_back[0].pubkey.len(), PUBKEY_LEN_1024);
        assert_eq!(read_back[0].ciphertext.len(), CIPHERTEXT_LEN_1024);
        let _ = fs::remove_file(&path);
    }

    #[test]
    fn v2_round_trip_mixed() {
        let path = tmp("v2-mixed");
        let entries = vec![
            fake_768(0, 0x11, 0x22),
            fake_1024(1, 0xaa, 0xbb),
            fake_768(3, 0x33, 0x44),
        ];
        write(&path, &entries).unwrap();
        let read_back = read(&path).unwrap();
        assert_eq!(read_back.len(), 3);
        assert_eq!(read_back[0].level, PqParams::Ml768);
        assert_eq!(read_back[1].level, PqParams::Ml1024);
        assert_eq!(read_back[2].level, PqParams::Ml768);
        let _ = fs::remove_file(&path);
    }

    /// v1 sidecars (created before ML-KEM-1024 support landed) must
    /// still be readable. We fabricate a v1 file by hand and confirm
    /// the reader returns ML-KEM-768 entries.
    #[test]
    fn v1_legacy_read_still_works() {
        let path = tmp("v1-legacy");
        let mut buf = Vec::new();
        buf.extend_from_slice(&MAGIC);
        buf.push(VERSION_V1);
        buf.push(2u8); // count
        buf.extend_from_slice(&[0u8; 6]);
        for (idx, pk_seed, ct_seed) in [(0u8, 0x11u8, 0x22u8), (5u8, 0x55u8, 0x66u8)] {
            buf.push(idx);
            buf.extend(std::iter::repeat(pk_seed).take(PUBKEY_LEN_768));
            buf.extend(std::iter::repeat(ct_seed).take(CIPHERTEXT_LEN_768));
        }
        fs::write(&path, &buf).unwrap();
        let entries = read(&path).unwrap();
        assert_eq!(entries.len(), 2);
        for e in &entries {
            assert_eq!(e.level, PqParams::Ml768);
            assert_eq!(e.pubkey.len(), PUBKEY_LEN_768);
            assert_eq!(e.ciphertext.len(), CIPHERTEXT_LEN_768);
        }
        let _ = fs::remove_file(&path);
    }

    #[test]
    fn empty_sidecar_round_trips() {
        let path = tmp("empty");
        write(&path, &[]).unwrap();
        let read_back = read(&path).unwrap();
        assert!(read_back.is_empty());
        let _ = fs::remove_file(&path);
    }

    #[test]
    fn wrong_magic_rejected() {
        let path = tmp("wrong-magic");
        fs::write(&path, vec![0u8; 16]).unwrap();
        let r = read(&path);
        assert!(r.is_err());
        let _ = fs::remove_file(&path);
    }

    #[test]
    fn unknown_version_rejected() {
        let path = tmp("v99");
        let mut buf = Vec::new();
        buf.extend_from_slice(&MAGIC);
        buf.push(0x99);
        buf.push(0);
        buf.extend_from_slice(&[0u8; 6]);
        fs::write(&path, &buf).unwrap();
        let r = read(&path);
        assert!(r.is_err());
        let _ = fs::remove_file(&path);
    }

    #[test]
    fn unknown_level_byte_rejected() {
        let path = tmp("v2-bad-level");
        let mut buf = Vec::new();
        buf.extend_from_slice(&MAGIC);
        buf.push(VERSION_V2);
        buf.push(1);
        buf.extend_from_slice(&[0u8; 6]);
        buf.push(0); // slot_idx
        buf.push(99); // unknown level byte
        // Can't tell how much to write past this, just write garbage
        buf.extend(std::iter::repeat(0u8).take(100));
        fs::write(&path, &buf).unwrap();
        let r = read(&path);
        assert!(r.is_err());
        let _ = fs::remove_file(&path);
    }

    /// Defense-in-depth: a sidecar with two entries claiming the
    /// same slot_idx is rejected at parse. Without this, find()
    /// returns the first match, so an attacker who could inject a
    /// hostile entry before a legitimate one would have it picked
    /// first; garbage pq_shared still causes AEAD reject (no key
    /// leak) but the ambiguity is itself a smell.
    #[test]
    fn duplicate_slot_idx_rejected() {
        let path = tmp("dup-slot");
        let entries = vec![fake_768(3, 0x11, 0x22), fake_768(3, 0xaa, 0xbb)];
        write(&path, &entries).unwrap();
        let count_or_err = match read(&path) {
            Ok(v) => Err(v.len()),
            Err(e) => Ok(e),
        };
        let err = count_or_err.unwrap_or_else(|n| {
            panic!("two entries with slot_idx=3 must be rejected at parse, got {n} entries")
        });
        let msg = format!("{err:?}");
        assert!(
            msg.contains("duplicate"),
            "error must mention 'duplicate', got: {msg}"
        );
        let _ = fs::remove_file(&path);
    }

    // ---- v3 vault binding tests ----------------------------------

    #[test]
    fn v3_round_trip_with_binding() {
        let path = tmp("v3-binding");
        let salt = [0xa5u8; 32];
        let entries = vec![fake_768(0, 0x11, 0x22), fake_1024(2, 0xaa, 0xbb)];
        write_with_binding(&path, &entries, &salt).unwrap();
        let bundle = read_bundle(&path).unwrap();
        assert_eq!(bundle.entries.len(), 2);
        assert_eq!(bundle.binding, Some(salt));
        verify_binding(&bundle, &salt).unwrap();
        let _ = fs::remove_file(&path);
    }

    #[test]
    fn v3_binding_mismatch_rejected() {
        let path = tmp("v3-mismatch");
        let salt_writer = [0x33u8; 32];
        let salt_other = [0x77u8; 32];
        let entries = vec![fake_768(0, 0x11, 0x22)];
        write_with_binding(&path, &entries, &salt_writer).unwrap();
        let bundle = read_bundle(&path).unwrap();
        assert!(
            verify_binding(&bundle, &salt_other).is_err(),
            "v3 binding mismatch must error, didn't"
        );
        // Same data, correct salt: must succeed.
        verify_binding(&bundle, &salt_writer).unwrap();
        let _ = fs::remove_file(&path);
    }

    /// Cross-vault swap scenario: vault A's sidecar cannot
    /// impersonate vault B's, even if both contain the same slot
    /// indices and ML-KEM levels.
    #[test]
    fn v3_swap_between_vaults_rejected() {
        let path_a = tmp("v3-vault-a");
        let path_b = tmp("v3-vault-b");
        let salt_a = [0x11u8; 32];
        let salt_b = [0x22u8; 32];
        let entries_a = vec![fake_768(0, 0xaa, 0xbb)];
        let entries_b = vec![fake_768(0, 0xcc, 0xdd)];
        write_with_binding(&path_a, &entries_a, &salt_a).unwrap();
        write_with_binding(&path_b, &entries_b, &salt_b).unwrap();
        // Attacker swaps A's sidecar into B's path. Reading B's
        // sidecar (now A's content) and verifying against B's salt
        // must fail.
        std::fs::copy(&path_a, &path_b).unwrap();
        let bundle_b = read_bundle(&path_b).unwrap();
        assert!(
            verify_binding(&bundle_b, &salt_b).is_err(),
            "swapped sidecar must fail binding check against B's salt"
        );
        let _ = fs::remove_file(&path_a);
        let _ = fs::remove_file(&path_b);
    }

    /// Back-compat: v2 sidecars (no binding) must still load via
    /// `read_bundle`, with `binding == None`. `verify_binding`
    /// against any salt returns Ok (no binding to check).
    #[test]
    fn v2_loads_via_read_bundle_with_no_binding() {
        let path = tmp("v2-via-bundle");
        let entries = vec![fake_768(0, 0x11, 0x22)];
        write(&path, &entries).unwrap();
        let bundle = read_bundle(&path).unwrap();
        assert!(bundle.binding.is_none());
        verify_binding(&bundle, &[0xff; 32]).unwrap();
        verify_binding(&bundle, &[0x00; 32]).unwrap();
        let _ = fs::remove_file(&path);
    }

    /// A v3 sidecar truncated below `HEADER_LEN_V3` (so the binding
    /// is partial) must be rejected, not silently fall back to v2.
    #[test]
    fn v3_truncated_binding_rejected() {
        let path = tmp("v3-trunc-binding");
        let mut buf = Vec::new();
        buf.extend_from_slice(&MAGIC);
        buf.push(VERSION_V3);
        buf.push(0u8); // count
        buf.extend_from_slice(&[0u8; 6]);
        buf.extend_from_slice(&[0u8; 16]); // half a binding
        fs::write(&path, &buf).unwrap();
        let r = read_bundle(&path);
        assert!(r.is_err(), "truncated v3 binding must Err");
        let _ = fs::remove_file(&path);
    }

    /// Sanity: distinct slot indices still parse cleanly.
    #[test]
    fn distinct_slot_indices_accepted() {
        let path = tmp("distinct-slots");
        let entries = vec![
            fake_768(0, 0x11, 0x22),
            fake_768(1, 0x33, 0x44),
            fake_768(7, 0x55, 0x66),
        ];
        write(&path, &entries).unwrap();
        let parsed = read(&path).expect("distinct slot indices must parse");
        assert_eq!(parsed.len(), 3);
        let _ = fs::remove_file(&path);
    }
}
