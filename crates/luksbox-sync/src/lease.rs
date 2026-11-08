// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Penthertz <https://penthertz.com> (https://x.com/PentHertz)

//! Leases: "this vault is open on that device".
//!
//! A session that may write puts a sealed, fixed-size lease in `l/` and
//! refreshes it while open. A refresh is a new lease under a new id,
//! then the old one is removed: like every bundle object, a lease is
//! sealed once under its own key and never rewritten (the zero nonce of
//! `codec` relies on it).
//!
//! On close the lease is not removed but replaced by a *closed* one
//! (not reported as open), which the device's next session replaces in
//! turn. It keeps pinning what the device last worked on: a commit it
//! published may still be uploading (sync clients upload in any order,
//! and a laptop may be closed mid-upload), and other devices cannot see
//! it yet to keep what it reuses. Another device opening the bundle reads the fresh ones and
//! can warn ("open on Laptop, seen 2 min ago"). A lease is advice, never
//! a lock: sync is eventually consistent, so two devices can miss each
//! other's lease; merging is what keeps that safe. Leases also pin the
//! commit a session works on, so garbage collection keeps its objects.

use serde::{Deserialize, Serialize};

use crate::codec::{self, Binding, OVERHEAD};
use crate::error::{Result, SyncError};
use crate::keys::{BundleKeys, Kind};
use crate::manifest::{DeviceId, ManifestRef};
use crate::names::ObjectId;

/// Size of a lease object.
pub const LEASE_LEN: usize = 4096;
const FORMAT: u16 = 2;
/// A lease refreshed within this long counts as an open session.
pub const FRESH_NS: u64 = 15 * 60 * 1_000_000_000;
/// After this long without a refresh, a lease no longer pins anything.
pub const PIN_NS: u64 = 90 * 24 * 3600 * 1_000_000_000;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Lease {
    pub format: u16,
    pub bundle: [u8; 16],
    pub device: DeviceId,
    pub label: String,
    pub writable: bool,
    /// Commit the session works on (kept by garbage collection).
    pub base: ManifestRef,
    /// The newest commit on `base`'s first-parent line made by another
    /// device: one the others already have. Kept by garbage collection
    /// too, so a commit of this device still on its way (which they
    /// cannot see) finds every page it reuses.
    pub pin: Option<ManifestRef>,
    /// The session ended (the lease only pins now).
    pub closed: bool,
    pub opened_ns: u64,
    pub heartbeat_ns: u64,
}

impl Lease {
    pub fn seal(&self, keys: &BundleKeys) -> Result<(ObjectId, Vec<u8>)> {
        let payload = postcard::to_allocvec(self).map_err(|_| SyncError::Limit("lease"))?;
        let framed = codec::frame(&payload, LEASE_LEN - OVERHEAD)?;
        codec::seal_new(keys, Kind::Lease, Binding::None, &framed)
    }

    pub fn open(keys: &BundleKeys, id: ObjectId, object: &[u8]) -> Result<Self> {
        let display = || format!("l/{}", id.to_hex());
        let pt = codec::open(keys, Kind::Lease, &id, Binding::None, object, display)?;
        let payload = codec::unframe(&pt, display)?;
        let (mut l, rest): (Lease, &[u8]) =
            postcard::take_from_bytes(payload).map_err(|_| SyncError::Malformed {
                name: display(),
                why: "lease does not decode",
            })?;
        if !rest.is_empty() || l.format != FORMAT || l.bundle != keys.bundle().0 {
            return Err(SyncError::Malformed {
                name: display(),
                why: "not a lease of this bundle",
            });
        }
        // The label is shown to the user ("also open on <label>"): kept
        // to printable, filename-safe characters and a bounded length, as
        // a manifest's is, whatever the device that sealed it wrote (no
        // terminal escapes, line breaks or bidirectional overrides). Not
        // refused: a lease still pins what it pins.
        l.label = crate::manifest::sanitize_label(&l.label);
        Ok(l)
    }

    pub fn new(
        bundle: [u8; 16],
        device: DeviceId,
        label: String,
        writable: bool,
        base: ManifestRef,
        pin: Option<ManifestRef>,
        now: u64,
    ) -> Self {
        Self {
            format: FORMAT,
            bundle,
            device,
            label,
            writable,
            base,
            pin,
            closed: false,
            opened_ns: now,
            heartbeat_ns: now,
        }
    }

    /// An open session refreshed recently.
    pub fn is_fresh(&self, now: u64) -> bool {
        !self.closed && now.saturating_sub(self.heartbeat_ns) < FRESH_NS
    }

    /// Still pins `base` and `pin` for garbage collection.
    pub fn pins(&self, now: u64) -> bool {
        now.saturating_sub(self.heartbeat_ns) < PIN_NS
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keys::tests::fixed_keys;
    use luksbox_core::CipherSuite;

    /// A lease's label is shown to the user ("also open on <label>"):
    /// whatever its sealer wrote, it comes back printable and bounded.
    #[test]
    fn a_lease_label_is_sanitized_when_read() {
        let k = fixed_keys(CipherSuite::Aes256GcmSiv, [1; 16]);
        let base = ManifestRef {
            device: DeviceId([2; 16]),
            seq: 1,
            oid: [3; 32],
            hash: [4; 32],
        };
        let evil = format!("Laptop\x1b[2J\r\n\u{202e}{}", "x".repeat(500));
        let l = Lease::new([1; 16], DeviceId([2; 16]), evil, true, base, None, 5);
        let (id, bytes) = l.seal(&k).unwrap();
        let back = Lease::open(&k, id, &bytes).unwrap();
        assert!(back.label.starts_with("Laptop"), "{}", back.label);
        assert!(
            !back
                .label
                .chars()
                .any(|c| c.is_control() || c == '\u{202e}')
        );
        assert!(back.label.len() <= crate::manifest::MAX_LABEL);
        // Everything else is as sealed.
        assert_eq!((back.base, back.writable), (base, true));
    }
}
