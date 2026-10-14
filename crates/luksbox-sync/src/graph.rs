// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Penthertz <https://penthertz.com> (https://x.com/PentHertz)

//! The commit graph of a bundle, and the checks run on it at open.
//!
//! Inputs are manifests that already verified (AEAD, commitment,
//! structure). The provider can still hide, delay, reorder or restore
//! them, so:
//!
//! - a commit is **usable** only if its whole ancestry is present, and
//!   every commit of its device between the newest checkpoint and itself
//!   is present too; anything else is **pending** (sync lag or
//!   withholding, indistinguishable at this point);
//! - two different commits claiming the same `(device, seq)` are an
//!   **equivocation**: a copied device identity or a former key holder;
//! - this device's own observations (`DeviceState::seen`) must still be
//!   there: anything older is a **rollback**;
//! - commits other devices say they saw must be there too, otherwise
//!   one device's history is being **withheld** from this one. Until they
//!   arrive the bundle can be read but not written.

use std::collections::{BTreeMap, HashMap, HashSet};

use crate::error::{Result, SyncError};
use crate::manifest::{DeviceId, ManifestRef, Verified};
use crate::state::DeviceState;

pub type Hash = [u8; 32];

#[derive(Default)]
pub struct Graph {
    pub all: HashMap<Hash, Verified>,
    pub by_pos: HashMap<(DeviceId, u64), Hash>,
    pub usable: HashSet<Hash>,
    pub heads: Vec<Hash>,
    /// Newest usable commit per device.
    pub newest: BTreeMap<DeviceId, (u64, Hash)>,
    /// Lowest kept sequence number per device: the highest checkpoint
    /// any verified commit declared. Commits below it may be absent.
    pub checkpoint: BTreeMap<DeviceId, u64>,
    /// Positions claimed by more than one commit, with every hash.
    pub equivocations: BTreeMap<(DeviceId, u64), Vec<Hash>>,
}

/// Something the user should know that does not stop the open.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Notice {
    /// Commits that are present but not usable yet (ancestry missing).
    Pending { count: usize },
    /// A commit another device saw is not here yet: sync lag or
    /// withholding. Writing is refused until it arrives.
    Missing { device: DeviceId, seq: u64 },
    /// This device had no state for the bundle: the bundle is trusted as
    /// found (trust on first use).
    FirstOpen,
    /// Two different commits claim one device and sequence number: two
    /// installations share a device identity (a copied profile, a
    /// restored VM), or a former key holder is writing. Both branches are
    /// kept and merged like concurrent commits; the user should find out
    /// which device it was.
    Equivocation { device: DeviceId, seq: u64 },
    /// Concurrent commits changed the keyslot table differently: they
    /// are not merged automatically; the user picks one.
    HeaderFork { heads: usize },
    /// Changes saved on this device and never published could not be
    /// replayed onto the newest commit; the vault is read-only until they
    /// are dealt with (`Session::discard_local_changes`). `recoverable`:
    /// they are what the session shows (read-only), so they can be copied
    /// out or exported first; otherwise the commit they were made on is
    /// no longer in the bundle and they cannot be rebuilt.
    UnmergedLocalChanges { recoverable: bool },
}

impl Graph {
    pub fn build(list: Vec<Verified>) -> Result<Self> {
        let mut g = Graph::default();
        for v in list {
            let pos = (v.m.device, v.m.seq);
            if let Some(other) = g.by_pos.get(&pos).copied()
                && other != v.hash
            {
                let e = g.equivocations.entry(pos).or_insert_with(|| vec![other]);
                if !e.contains(&v.hash) {
                    e.push(v.hash);
                }
            }
            for c in &v.m.checkpoint {
                let e = g.checkpoint.entry(c.device).or_insert(0);
                *e = (*e).max(c.min_seq);
            }
            g.by_pos.entry(pos).or_insert(v.hash);
            g.all.insert(v.hash, v);
        }
        // Per device: the run of sequence numbers with no gap above the
        // checkpoint. Commits past a gap are pending.
        let mut contiguous: BTreeMap<DeviceId, u64> = BTreeMap::new();
        let mut devices: Vec<DeviceId> = g.all.values().map(|v| v.m.device).collect();
        devices.sort();
        devices.dedup();
        for d in devices {
            let floor = g.checkpoint.get(&d).copied().unwrap_or(0);
            let mut s = floor.max(1);
            // Below the checkpoint nothing is required to be present.
            if floor > 1 && !g.by_pos.contains_key(&(d, floor)) {
                // The first kept commit may itself be missing; then the
                // device has nothing contiguous.
                contiguous.insert(d, floor.saturating_sub(1));
                continue;
            }
            while g.by_pos.contains_key(&(d, s)) {
                s += 1;
            }
            contiguous.insert(d, s - 1);
        }
        // Usable: contiguous for its device, and every parent usable (or
        // below a checkpoint). Iterate to a fixed point; the graph is a
        // DAG of at most MAX manifests, so this terminates.
        let mut changed = true;
        while changed {
            changed = false;
            for (h, v) in &g.all {
                if g.usable.contains(h) {
                    continue;
                }
                if v.m.seq > contiguous.get(&v.m.device).copied().unwrap_or(0) {
                    continue;
                }
                let parents_ok = v.m.parents.iter().all(|p| {
                    // Below the device's lowest kept commit: deleted on purpose.
                    if p.seq < g.checkpoint.get(&p.device).copied().unwrap_or(0) {
                        return true;
                    }
                    g.all.get(&p.hash).is_some_and(|pv| {
                        pv.m.device == p.device && pv.m.seq == p.seq && pv.oid.0 == p.oid
                    }) && g.usable.contains(&p.hash)
                });
                if parents_ok {
                    g.usable.insert(*h);
                    changed = true;
                }
            }
        }
        let referenced: HashSet<Hash> = g
            .usable
            .iter()
            .flat_map(|h| g.all[h].m.parents.iter().map(|p| p.hash))
            .collect();
        g.heads = g
            .usable
            .iter()
            .copied()
            .filter(|h| !referenced.contains(h))
            .collect();
        g.heads
            .sort_by_key(|h| std::cmp::Reverse((g.all[h].m.lamport, *h)));
        for h in &g.usable {
            let m = &g.all[h].m;
            let e = g.newest.entry(m.device).or_insert((0, [0; 32]));
            if m.seq > e.0 {
                *e = (m.seq, *h);
            }
        }
        Ok(g)
    }

    pub fn pending(&self) -> usize {
        self.all.len() - self.usable.len()
    }

    fn checkpoint_of(&self, d: &DeviceId) -> u64 {
        self.checkpoint.get(d).copied().unwrap_or(0)
    }

    /// Compare with what this device has already seen, and with what
    /// every usable commit says its author saw.
    pub fn check(&self, state: Option<&DeviceState>) -> Result<Vec<Notice>> {
        let mut notices = Vec::new();
        for (device, seq) in self.equivocations.keys() {
            notices.push(Notice::Equivocation {
                device: *device,
                seq: *seq,
            });
        }
        if self.pending() > 0 {
            notices.push(Notice::Pending {
                count: self.pending(),
            });
        }
        match state {
            None => notices.push(Notice::FirstOpen),
            Some(st) => {
                for (d, (seq, hash)) in &st.seen {
                    if *seq < self.checkpoint_of(d) {
                        continue;
                    }
                    match self.by_pos.get(&(*d, *seq)) {
                        Some(_) if self.has_at(d, *seq, hash) => {}
                        Some(_) => {
                            return Err(SyncError::Equivocation {
                                device: d.short(),
                                seq: *seq,
                            });
                        }
                        None => {
                            return Err(SyncError::RollbackDetected {
                                device: d.short(),
                                seen: *seq,
                                visible: self.newest.get(d).map(|n| n.0).unwrap_or(0),
                            });
                        }
                    }
                }
                // This device's own commits: none may exist that it did
                // not write.
                if let Some((seq, _)) = self.newest.get(&st.device) {
                    let explained = st.publishing.is_some_and(|p| {
                        p.seq == *seq && self.by_pos.get(&(st.device, *seq)) == Some(&p.hash)
                    });
                    if *seq > st.own_seq && !explained {
                        return Err(SyncError::IdentityConflict);
                    }
                }
                // Another installation wrote under this device's identity:
                // whoever notices takes a new one.
                if self.equivocations.keys().any(|(d, _)| *d == st.device) {
                    return Err(SyncError::IdentityConflict);
                }
            }
        }
        // Every verified commit is evidence, usable or not: one waiting
        // for a missing ancestor proves that ancestor exists.
        for v in self.all.values() {
            let m = &v.m;
            let claims = m
                .seen
                .iter()
                .map(|s| (s.device, s.seq, s.hash))
                .chain(m.parents.iter().map(|p| (p.device, p.seq, p.hash)));
            for (d, seq, hash) in claims {
                if seq < self.checkpoint_of(&d) {
                    continue;
                }
                match self.by_pos.get(&(d, seq)) {
                    Some(_) if self.has_at(&d, seq, &hash) => {}
                    Some(_) => {
                        return Err(SyncError::Equivocation {
                            device: d.short(),
                            seq,
                        });
                    }
                    None => {
                        let n = Notice::Missing { device: d, seq };
                        if !notices.contains(&n) {
                            notices.push(n);
                        }
                    }
                }
            }
        }
        Ok(notices)
    }

    /// Whether the commit `hash` sits at `(device, seq)` (one of several
    /// if that position is equivocated).
    fn has_at(&self, device: &DeviceId, seq: u64, hash: &Hash) -> bool {
        match self.equivocations.get(&(*device, seq)) {
            Some(all) => all.contains(hash),
            None => self.by_pos.get(&(*device, seq)) == Some(hash),
        }
    }

    pub fn head_ref(&self, h: &Hash) -> ManifestRef {
        self.all[h].as_ref()
    }
}

/// Whether the notices allow writing (no commit referenced elsewhere is
/// missing here).
pub fn writable(notices: &[Notice]) -> bool {
    !notices.iter().any(|n| matches!(n, Notice::Missing { .. }))
}
