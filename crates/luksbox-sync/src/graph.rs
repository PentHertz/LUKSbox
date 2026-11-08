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
//! - a commit below its device's checkpoint is **collected** history:
//!   garbage collection deleted it, or will (a plan still waiting keeps
//!   its manifest), or the provider put it back from its version history.
//!   It is never usable and never a head. One still present can be the
//!   base of a merge, but only as reached from both heads through their
//!   own authenticated first-parent links (`bundle::common_ancestor`): a
//!   manifest the provider puts back is never reached unless it is that
//!   ancestor;
//! - two different commits claiming the same `(device, seq)` are an
//!   **equivocation**: a copied device identity or a former key holder;
//! - this device's own observations (`DeviceState::seen`) must still be
//!   there and usable: anything older is a **rollback**;
//! - commits other devices say they saw must be there too, otherwise
//!   one device's history is being **withheld** from this one. Until they
//!   arrive the bundle can be read but not written.

use std::collections::{BTreeMap, HashMap, HashSet, VecDeque};

use crate::error::{Result, SyncError};
use crate::manifest::{CommitKind, DeviceId, ManifestRef, Verified};
use crate::state::DeviceState;

pub type Hash = [u8; 32];

#[derive(Default)]
pub struct Graph {
    /// Every verified manifest, collected ones included (garbage
    /// collection reads the plans they hold).
    pub all: HashMap<Hash, Verified>,
    /// Position of every commit at or above its device's checkpoint.
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
    /// Commits below their device's checkpoint (see the module docs).
    pub collected: HashSet<Hash>,
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
    /// Changes saved on this device and never published, in a session
    /// that cannot publish them (opened read-only, or a commit another
    /// device saw is missing here). `shown`: they were saved on the
    /// commit this session shows and are part of what it shows (so they
    /// can be read and exported); otherwise they were saved on an older
    /// commit and wait for a writable session to replay them (R16-04).
    UnpublishedLocalChanges { shown: bool },
    /// Concurrent versions were not merged automatically: the version
    /// they both come from (the merge base) is not complete in the
    /// bundle (some of its objects or its keyslot table are missing:
    /// sync lag, or the provider withholds or removed them), or they
    /// have none in common here. A merge without it would bring back
    /// files one side deleted, or undo a keyslot removal. `heads`: how
    /// many concurrent heads were left as they are; `local_changes`:
    /// this device's own unpublished changes wait too (the session is
    /// read-only and shows them). Merged once the base is here.
    MergeBaseMissing { heads: usize, local_changes: bool },
    /// Read-only inspection only (`OpenOptions::read_only`): the newest
    /// version this device has seen cannot be opened (objects missing
    /// or damaged: sync lag, or the provider withholds or altered them),
    /// so an older version is shown. A writable open refuses instead
    /// (`SyncError::NewestIncomplete`).
    OlderThanSeen,
}

impl Graph {
    pub fn build(list: Vec<Verified>) -> Result<Self> {
        let mut g = Graph::default();
        // Checkpoints first: they decide which commits are collected.
        for v in &list {
            for c in &v.m.checkpoint {
                let e = g.checkpoint.entry(c.device).or_insert(0);
                *e = (*e).max(c.min_seq);
            }
        }
        for v in list {
            if v.m.seq < g.checkpoint_of(&v.m.device) {
                // Collected history, or a replay of it: kept for the
                // plans it may hold, never part of the live graph.
                g.collected.insert(v.hash);
                g.all.insert(v.hash, v);
                continue;
            }
            let pos = (v.m.device, v.m.seq);
            if let Some(other) = g.by_pos.get(&pos).copied()
                && other != v.hash
            {
                let e = g.equivocations.entry(pos).or_insert_with(|| vec![other]);
                if !e.contains(&v.hash) {
                    e.push(v.hash);
                }
            }
            g.by_pos.entry(pos).or_insert(v.hash);
            g.all.insert(v.hash, v);
        }
        // Per device: the run of sequence numbers with no gap above the
        // checkpoint. Commits past a gap are pending.
        let mut contiguous: BTreeMap<DeviceId, u64> = BTreeMap::new();
        let mut devices: Vec<DeviceId> = g.by_pos.keys().map(|(d, _)| *d).collect();
        devices.sort();
        devices.dedup();
        for d in devices {
            let floor = g.checkpoint_of(&d);
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
        // below its device's checkpoint, deleted on purpose). Parents
        // first (Kahn's algorithm over the parent links), so this is
        // linear in the size of the graph; a cycle (which no sealed
        // manifest can form) never becomes usable.
        let mut waiting: HashMap<Hash, usize> = HashMap::new();
        let mut children: HashMap<Hash, Vec<Hash>> = HashMap::new();
        let mut ready: VecDeque<Hash> = VecDeque::new();
        for (h, v) in &g.all {
            if g.collected.contains(h)
                || v.m.seq > contiguous.get(&v.m.device).copied().unwrap_or(0)
            {
                continue;
            }
            let mut deps = 0usize;
            let mut broken = false;
            for p in &v.m.parents {
                if p.seq < g.checkpoint_of(&p.device) {
                    continue;
                }
                let ok = !g.collected.contains(&p.hash)
                    && g.all.get(&p.hash).is_some_and(|pv| {
                        pv.m.device == p.device && pv.m.seq == p.seq && pv.oid.0 == p.oid
                    });
                if !ok {
                    broken = true;
                    break;
                }
                deps += 1;
                children.entry(p.hash).or_default().push(*h);
            }
            if broken {
                continue;
            }
            if deps == 0 {
                ready.push_back(*h);
            } else {
                waiting.insert(*h, deps);
            }
        }
        while let Some(h) = ready.pop_front() {
            if !g.usable.insert(h) {
                continue;
            }
            for c in children.get(&h).map(Vec::as_slice).unwrap_or_default() {
                if let Some(n) = waiting.get_mut(c) {
                    *n -= 1;
                    if *n == 0 {
                        waiting.remove(c);
                        ready.push_back(*c);
                    }
                }
            }
        }
        let referenced: HashSet<Hash> = g
            .usable
            .iter()
            .flat_map(|h| g.all[h].m.parents.iter().map(|p| p.hash))
            .collect();
        // A commit nothing here refers to is a head, unless a
        // garbage-collection commit vouches it is an ancestor: a device's
        // newest commit stays forever (other devices' `seen` names it),
        // while the commits that merged it are collected in time. As a
        // head it would never merge (no common ancestor left), or merge
        // two-way and bring back what was deleted since.
        let gcs: Vec<&Verified> = g
            .usable
            .iter()
            .map(|h| &g.all[h])
            .filter(|v| v.m.kind == CommitKind::Gc)
            .collect();
        g.heads = g
            .usable
            .iter()
            .copied()
            .filter(|h| !referenced.contains(h))
            .filter(|h| {
                let x = g.all[h].as_ref();
                !gcs.iter().any(|gc| g.gc_covers(gc, &x))
            })
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

    /// Commits present that are not usable yet (collected history does
    /// not count: it is never going to be).
    pub fn pending(&self) -> usize {
        self.all.len() - self.usable.len() - self.collected.len()
    }

    pub fn checkpoint_of(&self, d: &DeviceId) -> u64 {
        self.checkpoint.get(d).copied().unwrap_or(0)
    }

    /// Newest usable sequence number of `d` (0 if none), for messages.
    fn visible(&self, d: &DeviceId) -> u64 {
        self.newest.get(d).map(|n| n.0).unwrap_or(0)
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
                        // There, and its whole history with it: a commit
                        // this device saw usable that no longer is lost
                        // part of its ancestry (a manifest deleted in the
                        // middle of a chain), which would otherwise open
                        // an older state with only "pending" to show.
                        Some(_) if self.has_at(d, *seq, hash) => {
                            if !self.usable.contains(hash) {
                                return Err(SyncError::RollbackDetected {
                                    device: d.short(),
                                    seen: *seq,
                                    visible: self.visible(d),
                                });
                            }
                        }
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
                                visible: self.visible(d),
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
        // for a missing ancestor proves that ancestor exists. Collected
        // history is not: what it refers to was deleted on purpose.
        for (h, v) in &self.all {
            if self.collected.contains(h) {
                continue;
            }
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

    /// Whether the garbage-collection commit `gc` vouches that `x` is one
    /// of its ancestors. A collection pass runs only with a single head
    /// and nothing pending, after checking that every commit its device
    /// saw is there and usable: each of those was an ancestor of that
    /// head, hence of `gc`. So are its device's earlier commits, and the
    /// earlier commits of every device it saw (their run of sequence
    /// numbers was complete). A position claimed twice (an equivocation)
    /// is never vouched for: which of the two it saw is unknown.
    fn gc_covers(&self, gc: &Verified, x: &ManifestRef) -> bool {
        if gc.m.kind != CommitKind::Gc
            || gc.hash == x.hash
            || self.equivocations.contains_key(&(x.device, x.seq))
        {
            return false;
        }
        if gc.m.device == x.device {
            return gc.m.seq > x.seq;
        }
        gc.m.seen.iter().any(|s| {
            s.device == x.device && (s.seq > x.seq || (s.seq == x.seq && s.hash == x.hash))
        })
    }

    /// What a device whose anchor (the commit it last opened or
    /// published, `DeviceState::head`) is `anchor` may open: the anchor
    /// and every usable commit descending from it (design invariant I5:
    /// never a state older than one this device has seen). `None` without
    /// an anchor (first open: trust on first use).
    ///
    /// An anchor below its device's checkpoint was garbage-collected
    /// after a long time offline: the commits its device kept (all newer
    /// than it) stand in for it. An anchor that should be here and is not
    /// usable (its manifest or part of its history is gone) is a
    /// rollback.
    pub fn lineage(&self, anchor: Option<&ManifestRef>) -> Result<Option<HashSet<Hash>>> {
        let Some(a) = anchor else { return Ok(None) };
        let rollback = || SyncError::RollbackDetected {
            device: a.device.short(),
            seen: a.seq,
            visible: self.visible(&a.device),
        };
        // Garbage-collection commits that vouch for the anchor descend
        // from it, even where the commits in between were collected.
        let covering = self
            .usable
            .iter()
            .filter(|h| self.gc_covers(&self.all[*h], a))
            .copied();
        let seeds: Vec<Hash> = if self.usable.contains(&a.hash) {
            std::iter::once(a.hash).chain(covering).collect()
        } else if a.seq < self.checkpoint_of(&a.device) {
            let covering: Vec<Hash> = covering.collect();
            if covering.is_empty() {
                self.usable
                    .iter()
                    .filter(|h| self.all[*h].m.device == a.device)
                    .copied()
                    .collect()
            } else {
                covering
            }
        } else {
            return Err(rollback());
        };
        if seeds.is_empty() {
            return Err(rollback());
        }
        let mut children: HashMap<Hash, Vec<Hash>> = HashMap::new();
        for h in &self.usable {
            for p in &self.all[h].m.parents {
                if self.usable.contains(&p.hash) {
                    children.entry(p.hash).or_default().push(*h);
                }
            }
        }
        let mut out: HashSet<Hash> = HashSet::new();
        let mut stack = seeds;
        while let Some(h) = stack.pop() {
            if out.insert(h)
                && let Some(c) = children.get(&h)
            {
                stack.extend(c.iter().copied());
            }
        }
        Ok(Some(out))
    }
}

/// Whether the notices allow writing (no commit referenced elsewhere is
/// missing here).
pub fn writable(notices: &[Notice]) -> bool {
    !notices.iter().any(|n| matches!(n, Notice::Missing { .. }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::manifest::{Checkpoint, CommitKind, FORMAT, HeaderRef, Manifest};
    use crate::names::ObjectId;

    fn id(n: u64) -> Hash {
        let mut h = [0u8; 32];
        h[..8].copy_from_slice(&n.to_le_bytes());
        h[31] = 1;
        h
    }

    /// Commit number `seq` of device `d` (hash `id(n)`), on `parents`.
    fn commit(n: u64, d: u8, seq: u64, parents: &[&Verified], checkpoint: u64) -> Verified {
        Verified {
            oid: ObjectId(id(n)),
            hash: id(n),
            size: 16 * 1024,
            m: Manifest {
                format: FORMAT,
                bundle: [1; 16],
                device: DeviceId([d; 16]),
                seq,
                lamport: n,
                wall_clock_ns: 0,
                parents: parents.iter().map(|p| p.as_ref()).collect(),
                seen: vec![],
                checkpoint: if checkpoint > 0 {
                    vec![Checkpoint {
                        device: DeviceId([d; 16]),
                        min_seq: checkpoint,
                    }]
                } else {
                    vec![]
                },
                header: HeaderRef {
                    name: None,
                    hash: [0; 32],
                    generation: 0,
                },
                hybrid: None,
                page_size: 1 << 20,
                logical_len: 0,
                tables: vec![],
                kind: if parents.is_empty() {
                    CommitKind::Convert
                } else {
                    CommitKind::Commit
                },
                merge_log: vec![],
                gc_plan: None,
                device_label: "d".into(),
            },
        }
    }

    /// One device's chain of `n` commits; the last declares `checkpoint`.
    fn chain(n: u64, checkpoint: u64) -> Vec<Verified> {
        let mut out: Vec<Verified> = Vec::new();
        for i in 1..=n {
            let parents: Vec<&Verified> = out.last().into_iter().collect();
            let cp = if i == n { checkpoint } else { 0 };
            let v = commit(i, 7, i, &parents, cp);
            out.push(v);
        }
        out
    }

    /// The fixed-point loop this replaced was quadratic in the length of
    /// a chain (one more commit usable per pass, in hash order).
    #[test]
    fn a_long_chain_builds_in_one_pass() {
        let n = 30_000;
        let mut list = chain(n, 0);
        list.reverse();
        let g = Graph::build(list).unwrap();
        assert_eq!(g.usable.len(), n as usize);
        assert_eq!(g.heads, vec![id(n)]);
        assert_eq!(g.pending(), 0);
    }

    #[test]
    fn collected_history_is_never_usable_nor_a_head() {
        // Commits 1..=10, the last declaring that 8 is the lowest kept;
        // commit 3 is still (or again) in the folder.
        let all = chain(10, 8);
        let list: Vec<Verified> = all
            .iter()
            .filter(|v| v.m.seq >= 8 || v.m.seq == 3)
            .cloned()
            .collect();
        let g = Graph::build(list).unwrap();
        assert!(g.collected.contains(&id(3)));
        assert!(!g.usable.contains(&id(3)));
        assert_eq!(g.heads, vec![id(10)]);
        assert_eq!(g.pending(), 0, "collected history is not pending");
        assert_eq!(g.newest[&DeviceId([7; 16])], (10, id(10)));
    }

    #[test]
    fn the_lineage_of_an_anchor_is_it_and_what_descends_from_it() {
        let all = chain(10, 0);
        let g = Graph::build(all.clone()).unwrap();
        let l = g.lineage(Some(&all[6].as_ref())).unwrap().unwrap();
        let want: HashSet<Hash> = (7..=10).map(id).collect();
        assert_eq!(l, want);
        assert!(g.lineage(None).unwrap().is_none());
        // An anchor that should be here and is not: a rollback.
        let g = Graph::build(all[..5].to_vec()).unwrap();
        assert!(matches!(
            g.lineage(Some(&all[6].as_ref())),
            Err(SyncError::RollbackDetected { .. })
        ));
        // An anchor below the checkpoint was collected: what its device
        // kept stands in for it.
        let kept: Vec<Verified> = chain(10, 8).into_iter().filter(|v| v.m.seq >= 8).collect();
        let g = Graph::build(kept).unwrap();
        let l = g.lineage(Some(&all[2].as_ref())).unwrap().unwrap();
        assert_eq!(l, (8..=10).map(id).collect());
    }

    #[test]
    fn a_seen_commit_that_lost_its_history_is_a_rollback() {
        let all = chain(5, 0);
        let mut st = DeviceState::new([1; 16], "x".into()).unwrap();
        st.seen.insert(DeviceId([7; 16]), (5, id(5)));
        assert!(Graph::build(all.clone()).unwrap().check(Some(&st)).is_ok());
        // Commit 3 deleted: 4 and 5 are still there, but not usable.
        let list: Vec<Verified> = all.into_iter().filter(|v| v.m.seq != 3).collect();
        let g = Graph::build(list).unwrap();
        assert!(g.by_pos.contains_key(&(DeviceId([7; 16]), 5)));
        assert!(matches!(
            g.check(Some(&st)),
            Err(SyncError::RollbackDetected {
                seen: 5,
                visible: 2,
                ..
            })
        ));
    }
}
