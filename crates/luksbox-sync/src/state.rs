// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Penthertz <https://penthertz.com> (https://x.com/PentHertz)

//! The sealed per-device state: this device's identity in the bundle,
//! and the newest commit it has seen from every device (its anchor).

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use crate::error::{Result, SyncError};
use crate::keys::BundleKeys;
use crate::local::{LocalStore, open_local, seal_local};
use crate::manifest::{DeviceId, ManifestRef};

const NAME: &str = "state";
const FORMAT: u16 = 1;
/// Exact bytes of the manifest being published, kept until it is in the
/// bundle so a crash mid-publish re-publishes the same commit instead of
/// writing a second one with the same sequence number.
pub(crate) const PENDING_MANIFEST: &str = "manifest-pending";

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DeviceState {
    pub format: u16,
    pub bundle: [u8; 16],
    pub device: DeviceId,
    pub label: String,
    /// Sequence number of this device's newest published commit.
    pub own_seq: u64,
    /// Newest commit seen from every device, this one included.
    pub seen: BTreeMap<DeviceId, (u64, [u8; 32])>,
    /// Highest header generation seen in a verified commit.
    pub max_header_generation: u64,
    /// Commit the last session opened or published.
    pub head: Option<ManifestRef>,
    /// Commit being published (its bytes are in `PENDING_MANIFEST`).
    pub publishing: Option<ManifestRef>,
}

impl DeviceState {
    pub fn new(bundle: [u8; 16], label: String) -> Result<Self> {
        Ok(Self {
            format: FORMAT,
            bundle,
            device: DeviceId::random()?,
            label,
            own_seq: 0,
            seen: BTreeMap::new(),
            max_header_generation: 0,
            head: None,
            publishing: None,
        })
    }

    /// Record that `r` was seen (never moves a device backwards).
    pub fn see(&mut self, r: &ManifestRef) {
        let e = self.seen.entry(r.device).or_insert((0, [0; 32]));
        if r.seq > e.0 {
            *e = (r.seq, r.hash);
        }
    }

    pub fn load(keys: &BundleKeys, local: &mut dyn LocalStore) -> Result<Option<Self>> {
        let Some(sealed) = local.get(NAME)? else {
            return Ok(None);
        };
        let pt = open_local(keys, NAME, &sealed)?;
        let s: DeviceState = postcard::from_bytes(&pt).map_err(|_| SyncError::Malformed {
            name: "local device state".into(),
            why: "does not decode",
        })?;
        if s.format != FORMAT || s.bundle != keys.bundle().0 {
            return Err(SyncError::Malformed {
                name: "local device state".into(),
                why: "unknown format or another bundle",
            });
        }
        Ok(Some(s))
    }

    pub fn save(&self, keys: &BundleKeys, local: &mut dyn LocalStore) -> Result<()> {
        let pt = Zeroizing::new(
            postcard::to_allocvec(self).map_err(|_| SyncError::Limit("device state"))?,
        );
        local.put(NAME, &seal_local(keys, NAME, &pt)?)
    }
}
