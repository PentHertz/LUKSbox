// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Penthertz <https://penthertz.com> (https://x.com/PentHertz)

//! Object names and their grammar.
//!
//! Every name in a bundle is lowercase hex of a fixed length, matched
//! exactly. Anything else in the folder (sync-client conflict copies,
//! `.DS_Store`, uppercase or Unicode-normalised variants, editor
//! leftovers) is "foreign": counted and reported, never parsed and never
//! deleted automatically. Fixed-length hex keeps clear of
//! case-insensitive file systems, characters some providers reject,
//! path-length limits, and the names sync clients skip.

use rand_core::{OsRng, RngCore};

use crate::error::{Result, SyncError};

/// Length of an object id in bytes (64 hex characters).
pub const OID_LEN: usize = 32;
/// Length of a bundle id in bytes (32 hex characters).
pub const BID_LEN: usize = 16;
/// Random part of header-object names, in bytes.
const RND_LEN: usize = 16;
/// Prefix of our own temporary files (`.tmp-<32 hex>`).
pub const TMP_PREFIX: &str = ".tmp-";

/// Random 256-bit object id. Also the per-object key derivation input
/// (`keys::BundleKeys::object_keys`), so an id is never reused: it is
/// drawn from the OS RNG for every new object.
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct ObjectId(pub [u8; OID_LEN]);

impl ObjectId {
    pub fn random() -> Result<Self> {
        let mut b = [0u8; OID_LEN];
        fill_random(&mut b)?;
        Ok(Self(b))
    }

    pub fn to_hex(&self) -> String {
        to_hex(&self.0)
    }

    pub fn parse(s: &str) -> Option<Self> {
        parse_hex_exact::<OID_LEN>(s).map(Self)
    }

    /// Two-character shard folder (`p/<aa>/<oid>`), so no folder holds
    /// more than a few thousand entries for a 1 TiB vault.
    pub fn shard(&self) -> String {
        to_hex(&self.0[..1])
    }
}

impl std::fmt::Debug for ObjectId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "ObjectId({})", &self.to_hex()[..16])
    }
}

/// Random id of a bundle, chosen when it is created and never changed
/// (MVK rotation keeps it). Public: it appears in header-object names,
/// so a device can find its local state before unlocking. It is bound
/// into every object's associated data and every key derivation.
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct BundleId(pub [u8; BID_LEN]);

impl BundleId {
    pub fn random() -> Result<Self> {
        let mut b = [0u8; BID_LEN];
        fill_random(&mut b)?;
        Ok(Self(b))
    }

    pub fn to_hex(&self) -> String {
        to_hex(&self.0)
    }

    pub fn parse(s: &str) -> Option<Self> {
        parse_hex_exact::<BID_LEN>(s).map(Self)
    }
}

impl std::fmt::Debug for BundleId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "BundleId({})", self.to_hex())
    }
}

/// Name of a header object (`h/`) or hybrid-sidecar object (`x/`):
/// `<bid 32 hex>-<header generation 16 hex>-<random 32 hex>`. The
/// generation in the name is only a hint for trying newest first; the
/// authoritative value is inside the HMAC'd header.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub struct HeaderName {
    pub bundle: BundleId,
    pub generation: u64,
    pub rnd: [u8; RND_LEN],
}

impl HeaderName {
    pub fn new(bundle: BundleId, generation: u64) -> Result<Self> {
        let mut rnd = [0u8; RND_LEN];
        fill_random(&mut rnd)?;
        Ok(Self {
            bundle,
            generation,
            rnd,
        })
    }

    pub fn to_name(&self) -> String {
        format!(
            "{}-{:016x}-{}",
            self.bundle.to_hex(),
            self.generation,
            to_hex(&self.rnd)
        )
    }

    pub fn parse(s: &str) -> Option<Self> {
        // Exact shape: 32 + 1 + 16 + 1 + 32 = 82 bytes, ASCII only.
        if s.len() != 2 * BID_LEN + 1 + 16 + 1 + 2 * RND_LEN || !s.is_ascii() {
            return None;
        }
        let (bid, rest) = s.split_at(2 * BID_LEN);
        let rest = rest.strip_prefix('-')?;
        let (generation, rest) = rest.split_at(16);
        let rnd = rest.strip_prefix('-')?;
        let generation = u64::from_be_bytes(parse_hex_exact::<8>(generation)?);
        Some(Self {
            bundle: BundleId::parse(bid)?,
            generation,
            rnd: parse_hex_exact::<RND_LEN>(rnd)?,
        })
    }
}

/// The folders of a bundle.
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Debug)]
pub enum Area {
    /// `h/`: header objects (raw 8 KiB LUKSBOX3 headers).
    Header,
    /// `x/`: hybrid post-quantum sidecar objects (raw sidecar bytes).
    Hybrid,
    /// `p/<aa>/`: sealed pages of the container image.
    Page,
    /// `t/<aa>/`: sealed page-table blocks.
    Table,
    /// `m/<aa>/`: sealed manifests (commits).
    Manifest,
    /// `l/`: sealed leases (one per open session).
    Lease,
}

impl Area {
    pub const ALL: [Area; 6] = [
        Area::Header,
        Area::Hybrid,
        Area::Page,
        Area::Table,
        Area::Manifest,
        Area::Lease,
    ];

    pub fn dir(self) -> &'static str {
        match self {
            Area::Header => "h",
            Area::Hybrid => "x",
            Area::Page => "p",
            Area::Table => "t",
            Area::Manifest => "m",
            Area::Lease => "l",
        }
    }

    /// Whether objects sit one shard folder deeper (`p/<aa>/<oid>`).
    pub fn sharded(self) -> bool {
        matches!(self, Area::Page | Area::Table | Area::Manifest)
    }

    /// Whether names in this area are header-style names.
    pub fn header_named(self) -> bool {
        matches!(self, Area::Header | Area::Hybrid)
    }
}

/// A validated object name within an area.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub enum Name {
    Header(HeaderName),
    Object(ObjectId),
}

impl Name {
    /// Leaf file name (without the shard folder).
    pub fn leaf(&self) -> String {
        match self {
            Name::Header(h) => h.to_name(),
            Name::Object(o) => o.to_hex(),
        }
    }

    /// Shard folder for sharded areas.
    pub fn shard(&self) -> Option<String> {
        match self {
            Name::Object(o) => Some(o.shard()),
            Name::Header(_) => None,
        }
    }

    /// Parse a leaf name found in `area`. `None` means foreign.
    pub fn parse_in(area: Area, leaf: &str) -> Option<Self> {
        if area.header_named() {
            HeaderName::parse(leaf).map(Name::Header)
        } else {
            ObjectId::parse(leaf).map(Name::Object)
        }
    }

    /// Display form `area/[shard/]leaf`, for errors and reports.
    pub fn display(&self, area: Area) -> String {
        match self.shard() {
            Some(sh) if area.sharded() => format!("{}/{}/{}", area.dir(), sh, self.leaf()),
            _ => format!("{}/{}", area.dir(), self.leaf()),
        }
    }

    pub fn object_id(&self) -> Option<ObjectId> {
        match self {
            Name::Object(o) => Some(*o),
            Name::Header(_) => None,
        }
    }
}

/// Whether `leaf` is one of our temporary files (`.tmp-<32 hex>`).
pub fn is_tmp_name(leaf: &str) -> bool {
    leaf.strip_prefix(TMP_PREFIX)
        .is_some_and(|rest| parse_hex_exact::<RND_LEN>(rest).is_some())
}

/// Fresh temporary leaf name.
pub fn tmp_name() -> Result<String> {
    let mut rnd = [0u8; RND_LEN];
    fill_random(&mut rnd)?;
    Ok(format!("{TMP_PREFIX}{}", to_hex(&rnd)))
}

/// Whether `leaf` is a valid shard folder name (`[0-9a-f]{2}`).
pub fn is_shard_name(leaf: &str) -> bool {
    parse_hex_exact::<1>(leaf).is_some()
}

pub(crate) fn fill_random(buf: &mut [u8]) -> Result<()> {
    OsRng
        .try_fill_bytes(buf)
        .map_err(|e| SyncError::Crypto(luksbox_core::Error::OsRng(e.to_string())))
}

pub fn to_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push(HEX[(b >> 4) as usize] as char);
        s.push(HEX[(b & 0x0f) as usize] as char);
    }
    s
}

/// Parse exactly `2*N` lowercase hex characters. Uppercase is refused
/// on purpose: we only ever write lowercase, so an uppercase name is a
/// different (foreign) file, never an alias of ours.
pub fn parse_hex_exact<const N: usize>(s: &str) -> Option<[u8; N]> {
    let b = s.as_bytes();
    if b.len() != 2 * N {
        return None;
    }
    let mut out = [0u8; N];
    for (i, pair) in b.chunks_exact(2).enumerate() {
        out[i] = (nibble(pair[0])? << 4) | nibble(pair[1])?;
    }
    Some(out)
}

fn nibble(c: u8) -> Option<u8> {
    match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'a'..=b'f' => Some(c - b'a' + 10),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn object_id_round_trip_and_shard() {
        let o = ObjectId::random().unwrap();
        let h = o.to_hex();
        assert_eq!(h.len(), 64);
        assert_eq!(ObjectId::parse(&h), Some(o));
        assert_eq!(o.shard(), h[..2]);
    }

    #[test]
    fn grammar_refuses_lookalikes() {
        let h = ObjectId([0xab; OID_LEN]).to_hex();
        assert!(ObjectId::parse(&h).is_some());
        assert!(ObjectId::parse(&h.to_uppercase()).is_none());
        assert!(ObjectId::parse(&h[..63]).is_none());
        assert!(ObjectId::parse(&format!("{h}0")).is_none());
        assert!(ObjectId::parse(&format!("{} (1)", h)).is_none());
        assert!(ObjectId::parse(&h.replacen(&h[..1], "g", 1)).is_none());
        // Non-ASCII of the right byte length must not slip through.
        let mut odd = h.clone();
        odd.replace_range(..2, "é");
        assert!(ObjectId::parse(&odd).is_none());
    }

    #[test]
    fn header_name_round_trip() {
        let b = BundleId::random().unwrap();
        let n = HeaderName::new(b, 0x0123_4567_89ab_cdef).unwrap();
        let s = n.to_name();
        assert_eq!(s.len(), 82);
        let p = HeaderName::parse(&s).unwrap();
        assert_eq!(p, n);
        assert!(HeaderName::parse(&s.replace('-', "_")).is_none());
        assert!(HeaderName::parse(&s[..81]).is_none());
        assert!(HeaderName::parse(&format!("{s} copy")).is_none());
    }

    #[test]
    fn tmp_and_shard_names() {
        let t = tmp_name().unwrap();
        assert!(is_tmp_name(&t));
        assert!(!is_tmp_name(".tmp-xyz"));
        assert!(is_shard_name("0f"));
        assert!(!is_shard_name("0F"));
        assert!(!is_shard_name("0"));
        assert!(Name::parse_in(Area::Header, &ObjectId::random().unwrap().to_hex()).is_none());
    }
}
