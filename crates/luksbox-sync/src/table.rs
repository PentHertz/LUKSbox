// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Penthertz <https://penthertz.com> (https://x.com/PentHertz)

//! Page-table blocks.
//!
//! Block `j` lists pages `[j * 1024, (j + 1) * 1024)` of the container
//! image. Each entry is `oid (32) || sha256(page object bytes) (32)`; an
//! all-zero entry is a hole (never written, reads as zeros). A manifest
//! lists the blocks the same way, so the manifest's hash commits to every
//! page: changing one page rewrites one block, not the whole table.

use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use crate::codec::{self, Binding, OVERHEAD};
use crate::error::{Result, SyncError};
use crate::keys::{BundleKeys, Kind};
use crate::names::ObjectId;

pub const ENTRIES_PER_BLOCK: usize = 1024;
const ENTRY_LEN: usize = 64;
pub const BLOCK_PLAINTEXT_LEN: usize = ENTRIES_PER_BLOCK * ENTRY_LEN;
/// Size of a sealed table-block object.
pub const BLOCK_OBJECT_LEN: usize = BLOCK_PLAINTEXT_LEN + OVERHEAD;

/// Reference to a sealed object: its id and the SHA-256 of its bytes.
#[derive(Clone, Copy, PartialEq, Eq, Debug, serde::Serialize, serde::Deserialize)]
pub struct ObjRef {
    pub oid: [u8; 32],
    pub hash: [u8; 32],
}

impl ObjRef {
    pub fn of(oid: ObjectId, object: &[u8]) -> Self {
        Self {
            oid: oid.0,
            hash: sha256(object),
        }
    }

    pub fn object_id(&self) -> ObjectId {
        ObjectId(self.oid)
    }

    /// Whether `object` is exactly the referenced bytes.
    pub fn matches(&self, object: &[u8]) -> bool {
        // Not secret: both values are public ciphertext digests.
        sha256(object) == self.hash
    }
}

pub fn sha256(bytes: &[u8]) -> [u8; 32] {
    Sha256::digest(bytes).into()
}

/// One decoded table block.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct TableBlock {
    pub entries: Vec<Option<ObjRef>>,
}

impl Default for TableBlock {
    fn default() -> Self {
        Self {
            entries: vec![None; ENTRIES_PER_BLOCK],
        }
    }
}

impl TableBlock {
    pub fn encode(&self) -> Zeroizing<Vec<u8>> {
        debug_assert_eq!(self.entries.len(), ENTRIES_PER_BLOCK);
        let mut out = Zeroizing::new(vec![0u8; BLOCK_PLAINTEXT_LEN]);
        for (i, e) in self.entries.iter().enumerate() {
            if let Some(r) = e {
                out[i * ENTRY_LEN..i * ENTRY_LEN + 32].copy_from_slice(&r.oid);
                out[i * ENTRY_LEN + 32..(i + 1) * ENTRY_LEN].copy_from_slice(&r.hash);
            }
        }
        out
    }

    pub fn decode(pt: &[u8], display: impl Fn() -> String) -> Result<Self> {
        if pt.len() != BLOCK_PLAINTEXT_LEN {
            return Err(SyncError::Malformed {
                name: display(),
                why: "table block has the wrong length",
            });
        }
        let mut entries = Vec::with_capacity(ENTRIES_PER_BLOCK);
        for e in pt.chunks_exact(ENTRY_LEN) {
            let oid: [u8; 32] = e[..32].try_into().expect("32 bytes");
            let hash: [u8; 32] = e[32..].try_into().expect("32 bytes");
            if oid == [0u8; 32] {
                if hash != [0u8; 32] {
                    return Err(SyncError::Malformed {
                        name: display(),
                        why: "table hole with a non-zero hash",
                    });
                }
                entries.push(None);
            } else {
                entries.push(Some(ObjRef { oid, hash }));
            }
        }
        Ok(Self { entries })
    }

    /// Seal this block as a new object for position `index`.
    pub fn seal(&self, keys: &BundleKeys, index: u64) -> Result<(ObjRef, Vec<u8>)> {
        let (oid, bytes) =
            codec::seal_new(keys, Kind::Table, Binding::Index(index), &self.encode())?;
        Ok((ObjRef::of(oid, &bytes), bytes))
    }

    /// Verify and decode a sealed block found at position `index`.
    pub fn open(keys: &BundleKeys, r: &ObjRef, index: u64, object: &[u8]) -> Result<Self> {
        let display = || format!("t/{}", r.object_id().to_hex());
        if !r.matches(object) {
            return Err(SyncError::ObjectAuth { name: display() });
        }
        let pt = codec::open(
            keys,
            Kind::Table,
            &r.object_id(),
            Binding::Index(index),
            object,
            display,
        )?;
        Self::decode(&pt, display)
    }
}

/// Number of pages for an image of `len` bytes.
pub fn page_count(len: u64, page_size: u64) -> u64 {
    len.div_ceil(page_size)
}

/// Number of table blocks for `pages` pages.
pub fn block_count(pages: u64) -> u64 {
    pages.div_ceil(ENTRIES_PER_BLOCK as u64)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keys::tests::fixed_keys;
    use luksbox_core::CipherSuite;

    #[test]
    fn block_round_trip_with_holes() {
        let k = fixed_keys(CipherSuite::Aes256GcmSiv, [1; 16]);
        let mut b = TableBlock::default();
        b.entries[0] = Some(ObjRef {
            oid: [1; 32],
            hash: [2; 32],
        });
        b.entries[1023] = Some(ObjRef {
            oid: [3; 32],
            hash: [4; 32],
        });
        let (r, obj) = b.seal(&k, 7).unwrap();
        assert_eq!(obj.len(), BLOCK_OBJECT_LEN);
        assert_eq!(TableBlock::open(&k, &r, 7, &obj).unwrap(), b);
        // Wrong position, or bytes not matching the reference: refused.
        assert!(TableBlock::open(&k, &r, 8, &obj).is_err());
        let mut bad = obj.clone();
        bad[100] ^= 1;
        assert!(TableBlock::open(&k, &r, 7, &bad).is_err());
    }

    #[test]
    fn hole_with_hash_is_malformed() {
        let mut pt = vec![0u8; BLOCK_PLAINTEXT_LEN];
        pt[40] = 1;
        assert!(TableBlock::decode(&pt, || "x".into()).is_err());
        assert!(TableBlock::decode(&pt[..10], || "x".into()).is_err());
    }

    #[test]
    fn counts() {
        assert_eq!(page_count(0, 4096), 0);
        assert_eq!(page_count(1, 4096), 1);
        assert_eq!(page_count(4096, 4096), 1);
        assert_eq!(page_count(4097, 4096), 2);
        assert_eq!(block_count(1024), 1);
        assert_eq!(block_count(1025), 2);
    }
}
