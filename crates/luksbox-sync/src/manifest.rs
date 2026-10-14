// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Penthertz <https://penthertz.com> (https://x.com/PentHertz)

//! Manifests: the commits of a bundle.
//!
//! A manifest names one complete state of the vault (header, page size,
//! image length, table blocks) and its place in the history (device,
//! sequence number, parents, what it saw of every other device). It is
//! postcard-encoded, framed and zero-padded to one of four fixed sizes,
//! then sealed. `sha256(manifest object bytes)` is the identity other
//! manifests and the local state refer to: it commits to the whole state.

use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use crate::codec::{self, Binding, OVERHEAD};
use crate::error::{Result, SyncError};
use crate::keys::{BundleKeys, Kind};
use crate::names::{BundleId, ObjectId, fill_random, to_hex};
use crate::table::{ObjRef, block_count, page_count, sha256};

/// Manifest object sizes. A manifest uses the smallest that fits; the
/// size reveals only roughly how large the vault is (its table-block
/// list), never which device committed.
pub const MANIFEST_SIZES: [usize; 4] = [16 * 1024, 64 * 1024, 256 * 1024, 1024 * 1024];
/// Allowed page sizes: 1, 4 and 16 MiB.
pub const PAGE_SIZES: [u32; 3] = [1 << 20, 4 << 20, 16 << 20];
pub const FORMAT: u16 = 1;
pub const MAX_PARENTS: usize = 8;
pub const MAX_DEVICES: usize = 256;
pub const MAX_LABEL: usize = 64;
const MAX_MERGE_LOG: usize = 4096;
/// Most objects one garbage-collection plan lists (it must fit in a
/// 1 MiB manifest); larger collections take several passes.
pub const MAX_GC_OBJECTS: usize = 24_000;

/// Random id of one device for one bundle.
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub struct DeviceId(pub [u8; 16]);

impl DeviceId {
    pub fn random() -> Result<Self> {
        let mut b = [0u8; 16];
        fill_random(&mut b)?;
        Ok(Self(b))
    }

    pub fn short(&self) -> String {
        to_hex(&self.0[..4])
    }
}

impl std::fmt::Debug for DeviceId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Device({})", self.short())
    }
}

/// Reference to another manifest by position and identity.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct ManifestRef {
    pub device: DeviceId,
    pub seq: u64,
    pub oid: [u8; 32],
    /// `sha256` of the manifest object bytes.
    pub hash: [u8; 32],
}

/// Newest commit seen from one device.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct Seen {
    pub device: DeviceId,
    pub seq: u64,
    pub hash: [u8; 32],
}

/// History below `min_seq` of `device` was deleted on purpose.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct Checkpoint {
    pub device: DeviceId,
    pub min_seq: u64,
}

/// The header this state uses.
#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct HeaderRef {
    /// Leaf name of the `h/` object, or `None` when the header is kept
    /// outside the bundle (detached).
    pub name: Option<String>,
    /// `sha256` of the 8 KiB header bytes.
    pub hash: [u8; 32],
    pub generation: u64,
}

/// Raw object outside the sealed kinds (`x/` hybrid sidecar).
#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct NamedRef {
    pub name: String,
    pub hash: [u8; 32],
}

#[derive(Clone, Copy, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub enum CommitKind {
    /// First commit, made by `sync convert`.
    Convert,
    /// Ordinary changes.
    Commit,
    /// Merge of concurrent commits (two or more parents).
    Merge,
    /// MVK rotation: every page rewritten under the new key.
    Rotation,
    /// Files restored from a snapshot into a new commit.
    Restore,
    /// No change to the vault: records a garbage-collection plan and
    /// checkpoints (`gc`).
    Gc,
}

/// One decision a merge made, for the user and for audit.
#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct MergeEvent {
    pub path: String,
    pub what: String,
}

/// Objects a garbage-collection pass found unreachable. They may be
/// deleted by a later pass at least `gc::GRACE` after this plan was
/// published, if still unreachable then.
#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct GcPlan {
    pub wall_clock_ns: u64,
    pub lamport: u64,
    pub objects: Vec<(u8, [u8; 32])>,
}

#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct Manifest {
    pub format: u16,
    pub bundle: [u8; 16],
    pub device: DeviceId,
    pub seq: u64,
    pub lamport: u64,
    /// Informative only: never used for ordering.
    pub wall_clock_ns: u64,
    pub parents: Vec<ManifestRef>,
    pub seen: Vec<Seen>,
    pub checkpoint: Vec<Checkpoint>,
    pub header: HeaderRef,
    pub hybrid: Option<NamedRef>,
    pub page_size: u32,
    pub logical_len: u64,
    pub tables: Vec<ObjRef>,
    pub kind: CommitKind,
    pub merge_log: Vec<MergeEvent>,
    pub gc_plan: Option<GcPlan>,
    pub device_label: String,
}

/// A verified manifest together with where it came from.
#[derive(Clone, Debug)]
pub struct Verified {
    pub oid: ObjectId,
    /// `sha256` of the manifest object bytes.
    pub hash: [u8; 32],
    pub size: usize,
    pub m: Manifest,
}

impl Verified {
    pub fn as_ref(&self) -> ManifestRef {
        ManifestRef {
            device: self.m.device,
            seq: self.m.seq,
            oid: self.oid.0,
            hash: self.hash,
        }
    }
}

/// Keep a device label to printable, filename-safe characters.
pub fn sanitize_label(label: &str) -> String {
    let mut out = String::new();
    for c in label.chars() {
        let ok = c.is_alphanumeric() || matches!(c, ' ' | '-' | '_' | '.');
        let c = if ok { c } else { '-' };
        if out.len() + c.len_utf8() > MAX_LABEL {
            break;
        }
        out.push(c);
    }
    let t = out.trim();
    if t.is_empty() {
        "device".to_string()
    } else {
        t.to_string()
    }
}

impl Manifest {
    /// Structural checks that do not need the rest of the bundle.
    pub fn validate(&self, bundle: BundleId, display: &dyn Fn() -> String) -> Result<()> {
        let bad = |why: &'static str| SyncError::Malformed {
            name: display(),
            why,
        };
        if self.format != FORMAT {
            return Err(bad("unknown manifest format"));
        }
        if self.bundle != bundle.0 {
            return Err(bad("manifest of another bundle"));
        }
        if self.seq == 0 {
            return Err(bad("sequence numbers start at 1"));
        }
        if self.parents.len() > MAX_PARENTS
            || self.seen.len() > MAX_DEVICES
            || self.checkpoint.len() > MAX_DEVICES
        {
            return Err(bad("too many parents or devices"));
        }
        if self
            .gc_plan
            .as_ref()
            .is_some_and(|p| p.objects.len() > MAX_GC_OBJECTS)
        {
            return Err(bad("garbage-collection plan too long"));
        }
        if self.merge_log.len() > MAX_MERGE_LOG {
            return Err(bad("merge log too long"));
        }
        if !PAGE_SIZES.contains(&self.page_size) {
            return Err(bad("unsupported page size"));
        }
        let blocks = block_count(page_count(self.logical_len, self.page_size as u64));
        if self.tables.len() as u64 != blocks {
            return Err(bad("table count does not match the image length"));
        }
        if self.device_label != sanitize_label(&self.device_label) {
            return Err(bad("device label not sanitized"));
        }
        match self.kind {
            CommitKind::Convert if !self.parents.is_empty() => {
                return Err(bad("a convert commit has no parent"));
            }
            CommitKind::Merge if self.parents.len() < 2 => {
                return Err(bad("a merge has at least two parents"));
            }
            CommitKind::Commit | CommitKind::Rotation | CommitKind::Restore | CommitKind::Gc
                if self.parents.len() != 1 =>
            {
                return Err(bad("a commit has exactly one parent"));
            }
            _ => {}
        }
        // A device appears at most once in `seen` and `checkpoint`.
        let mut ds: Vec<DeviceId> = self.seen.iter().map(|s| s.device).collect();
        ds.sort();
        if ds.windows(2).any(|w| w[0] == w[1]) {
            return Err(bad("device listed twice in seen"));
        }
        let mut cs: Vec<DeviceId> = self.checkpoint.iter().map(|c| c.device).collect();
        cs.sort();
        if cs.windows(2).any(|w| w[0] == w[1]) {
            return Err(bad("device listed twice in checkpoint"));
        }
        Ok(())
    }

    /// Serialize, frame into the smallest manifest size, and seal.
    pub fn seal(&self, keys: &BundleKeys) -> Result<(ObjectId, Vec<u8>)> {
        let payload = Zeroizing::new(
            postcard::to_allocvec(self)
                .map_err(|_| SyncError::Limit("manifest does not serialize"))?,
        );
        let size = MANIFEST_SIZES
            .iter()
            .copied()
            .find(|&s| payload.len() + 4 + OVERHEAD <= s)
            .ok_or(SyncError::Limit("manifest larger than 1 MiB"))?;
        let framed = codec::frame(&payload, size - OVERHEAD)?;
        codec::seal_new(keys, Kind::Manifest, Binding::None, &framed)
    }

    /// Verify and decode a manifest object.
    pub fn open(keys: &BundleKeys, oid: ObjectId, object: &[u8]) -> Result<Verified> {
        let display = || format!("m/{}", oid.to_hex());
        if !MANIFEST_SIZES.contains(&object.len()) {
            return Err(SyncError::Refused {
                what: display(),
                why: "wrong size for a manifest",
            });
        }
        let pt = codec::open(keys, Kind::Manifest, &oid, Binding::None, object, display)?;
        let payload = codec::unframe(&pt, display)?;
        let (m, rest): (Manifest, &[u8]) =
            postcard::take_from_bytes(payload).map_err(|_| SyncError::Malformed {
                name: display(),
                why: "manifest does not decode",
            })?;
        if !rest.is_empty() {
            return Err(SyncError::Malformed {
                name: display(),
                why: "trailing bytes after the manifest",
            });
        }
        m.validate(keys.bundle(), &display)?;
        Ok(Verified {
            oid,
            hash: sha256(object),
            size: object.len(),
            m,
        })
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::keys::tests::fixed_keys;
    use luksbox_core::CipherSuite;

    pub(crate) fn sample(bundle: [u8; 16]) -> Manifest {
        Manifest {
            format: FORMAT,
            bundle,
            device: DeviceId([5; 16]),
            seq: 1,
            lamport: 1,
            wall_clock_ns: 0,
            parents: vec![],
            seen: vec![],
            checkpoint: vec![],
            header: HeaderRef {
                name: Some("h".into()),
                hash: [0; 32],
                generation: 1,
            },
            hybrid: None,
            page_size: 1 << 20,
            logical_len: (1 << 20) * 3 + 5,
            tables: vec![ObjRef {
                oid: [1; 32],
                hash: [2; 32],
            }],
            kind: CommitKind::Convert,
            merge_log: vec![],
            gc_plan: None,
            device_label: "Laptop".into(),
        }
    }

    #[test]
    fn seal_open_round_trip() {
        let k = fixed_keys(CipherSuite::Aes256GcmSiv, [1; 16]);
        let m = sample([1; 16]);
        let (oid, obj) = m.seal(&k).unwrap();
        assert_eq!(obj.len(), MANIFEST_SIZES[0]);
        let v = Manifest::open(&k, oid, &obj).unwrap();
        assert_eq!(v.m, m);
        assert_eq!(v.hash, sha256(&obj));
    }

    #[test]
    fn validation_rejects_inconsistent_manifests() {
        let k = fixed_keys(CipherSuite::Aes256GcmSiv, [1; 16]);
        let d = || "m".to_string();
        let mut m = sample([1; 16]);
        assert!(m.validate(k.bundle(), &d).is_ok());
        m.tables.push(ObjRef {
            oid: [1; 32],
            hash: [2; 32],
        });
        assert!(m.validate(k.bundle(), &d).is_err());
        let mut m = sample([2; 16]);
        assert!(m.validate(k.bundle(), &d).is_err());
        m = sample([1; 16]);
        m.page_size = 12345;
        assert!(m.validate(k.bundle(), &d).is_err());
        m = sample([1; 16]);
        m.kind = CommitKind::Commit;
        assert!(m.validate(k.bundle(), &d).is_err());
        m = sample([1; 16]);
        m.device_label = "a/b".into();
        assert!(m.validate(k.bundle(), &d).is_err());
    }

    #[test]
    fn labels_are_sanitized() {
        assert_eq!(sanitize_label("Mac Book/Pro:2"), "Mac Book-Pro-2");
        assert_eq!(sanitize_label("   "), "device");
        assert!(sanitize_label(&"x".repeat(200)).len() <= MAX_LABEL);
    }
}
