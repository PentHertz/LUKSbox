// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Penthertz <https://penthertz.com> (https://x.com/PentHertz)

//! Garbage collection, retention and snapshots.
//!
//! **Roots** (never deleted, nor anything reachable from them): every
//! device's newest commit, every commit newer than the retention period
//! or among the last `keep_last`, and the commit every fresh-enough lease
//! pins. Reachable from a commit: its manifest, header and hybrid
//! objects, table blocks and pages.
//!
//! **Two passes.** A pass lists what is unreachable and publishes it as
//! a plan, in a `Gc` commit that also raises the per-device checkpoints
//! (the lowest commit each device keeps). A later pass deletes the
//! objects of plans at least `grace` old that are *still* unreachable
//! then. A device that went offline with work based on an old commit
//! therefore never finds that commit's objects deleted under it within
//! the grace period, and its lease pins them for longer.
//!
//! **Orphans.** An unreachable object that no commit known here refers
//! to is most likely part of a commit still on its way: sync clients
//! upload files in any order, so another device's pages can arrive
//! days before its manifest (a laptop closed mid-upload). The plan flags
//! such objects, and they wait `orphan_grace` (the lease pin, 90 days)
//! instead of `grace`. If the manifest arrives meanwhile they become
//! reachable and stay.
//!
//! **Age of a plan.** The plan's own clock is another device's and may
//! be wrong, so each device also records when it first saw each plan
//! (local record `gc-seen`). A plan is as old as the younger of the two;
//! a plan dated in the future counts from its local sighting only. A
//! device whose clock is behind its own earlier commits or sightings
//! (it went back, for example a lost hardware clock) refuses to
//! collect: its plans would look old at once once the clock is fixed.
//!
//! Deletion is by validated name only; foreign files are never touched.

use std::collections::{BTreeMap, HashMap, HashSet};

use crate::bundle::{Session, complete, header_candidates, load_manifests, now_ns, stamp, vfs_err};
use crate::error::{Result, SyncError};
use crate::graph::{Graph, writable};
use crate::keys::BundleKeys;
use crate::lease::{LEASE_LEN, Lease, PIN_NS};
use crate::local::{LocalStore, open_local, seal_local};
use crate::manifest::{CommitKind, DeviceId, GcPlan, MAX_GC_OBJECTS, Verified};
use crate::names::{Area, Name};
use crate::store::LenRule;
use crate::table::{BLOCK_OBJECT_LEN, TableBlock, sha256};

const DAY_NS: u64 = 24 * 3600 * 1_000_000_000;
/// Flag on a plan entry's area tag: no known commit referred to the
/// object when it was planned.
const ORPHAN: u8 = 0x80;
/// Local record of when this device first saw each plan.
const SIGHTINGS: &str = "gc-seen";
/// How far this device's clock may be behind its own earlier records
/// before collection is refused.
const CLOCK_SLACK_NS: u64 = 3600 * 1_000_000_000;

#[derive(Clone, Debug)]
pub struct GcOptions {
    /// Keep every commit at most this old (by its informative clock).
    pub retention_ns: u64,
    /// And always the last this many commits.
    pub keep_last: usize,
    /// Delete planned objects only once the plan is this old.
    pub grace_ns: u64,
    /// The same for objects no known commit referred to when planned
    /// (never less than `grace_ns`).
    pub orphan_grace_ns: u64,
    /// Report only; publish and delete nothing.
    pub dry_run: bool,
    /// The time to use instead of the system clock (tests, simulations).
    pub now_ns: Option<u64>,
}

impl Default for GcOptions {
    fn default() -> Self {
        Self {
            retention_ns: 30 * DAY_NS,
            keep_last: 50,
            grace_ns: 7 * DAY_NS,
            orphan_grace_ns: PIN_NS,
            dry_run: false,
            now_ns: None,
        }
    }
}

/// When this device first saw each plan (by manifest hash).
fn load_sightings(
    keys: &BundleKeys,
    local: &mut dyn LocalStore,
) -> Result<BTreeMap<[u8; 32], u64>> {
    let Some(sealed) = local.get(SIGHTINGS)? else {
        return Ok(BTreeMap::new());
    };
    let pt = open_local(keys, SIGHTINGS, &sealed)?;
    let v: Vec<([u8; 32], u64)> = postcard::from_bytes(&pt).map_err(|_| SyncError::Malformed {
        name: "local gc sightings".into(),
        why: "does not decode",
    })?;
    Ok(v.into_iter().collect())
}

fn save_sightings(
    keys: &BundleKeys,
    local: &mut dyn LocalStore,
    seen: &BTreeMap<[u8; 32], u64>,
) -> Result<()> {
    let v: Vec<([u8; 32], u64)> = seen.iter().map(|(h, t)| (*h, *t)).collect();
    let pt = postcard::to_allocvec(&v).map_err(|_| SyncError::Limit("gc sightings"))?;
    local.put(SIGHTINGS, &seal_local(keys, SIGHTINGS, &pt)?)
}

/// Record the plans in `graph` this device has not seen before (at
/// `now`), and forget plans no longer in the bundle. Called at every
/// open and every collection.
pub(crate) fn note_plan_sightings(
    keys: &BundleKeys,
    local: &mut dyn LocalStore,
    graph: &Graph,
    now: u64,
) -> Result<BTreeMap<[u8; 32], u64>> {
    let mut seen = load_sightings(keys, local)?;
    let before = seen.clone();
    seen.retain(|h, _| graph.all.contains_key(h));
    for (h, v) in &graph.all {
        if v.m.gc_plan.is_some() {
            seen.entry(*h).or_insert(now);
        }
    }
    if seen != before {
        save_sightings(keys, local, &seen)?;
    }
    Ok(seen)
}

/// How old a plan counts as: the younger of its own clock and this
/// device's first sighting (a plan dated in the future: the sighting).
fn plan_age(plan: &GcPlan, first_seen: u64, now: u64) -> u64 {
    let by_local = now.saturating_sub(first_seen);
    if plan.wall_clock_ns > now {
        return by_local;
    }
    (now - plan.wall_clock_ns).min(by_local)
}

#[derive(Debug, Default)]
pub struct GcReport {
    /// Objects newly found unreachable and put in a plan.
    pub planned: usize,
    /// Objects deleted (from older plans, still unreachable).
    pub deleted: usize,
    /// Of `planned`, objects no known commit refers to (likely another
    /// device's upload in progress): they wait the orphan grace period.
    pub orphans: usize,
    /// Commits kept as roots.
    pub roots: usize,
    /// Foreign entries seen in the bundle (never deleted).
    pub foreign: usize,
}

/// One commit as listed by `Session::snapshots`.
#[derive(Clone, Debug)]
pub struct Snapshot {
    pub hash: [u8; 32],
    pub device: DeviceId,
    pub device_label: String,
    pub seq: u64,
    pub lamport: u64,
    pub wall_clock_ns: u64,
    pub kind: CommitKind,
    /// Keyslot table generation this snapshot uses.
    pub header_generation: u64,
    pub header_hash: [u8; 32],
}

/// `(area tag, object id)` as recorded in a plan.
type Obj = (u8, [u8; 32]);

fn area_tag(a: Area) -> u8 {
    match a {
        Area::Page => 1,
        Area::Table => 2,
        Area::Manifest => 3,
        Area::Header => 4,
        Area::Hybrid => 5,
        Area::Lease => 6,
    }
}

impl Session {
    /// Every usable commit, newest first.
    pub fn snapshots(&self) -> Result<Vec<Snapshot>> {
        let (manifests, _, _) = load_manifests(&self.store, &self.keys)?;
        let graph = Graph::build(manifests)?;
        let mut out: Vec<Snapshot> = graph
            .usable
            .iter()
            .map(|h| {
                let m = &graph.all[h].m;
                Snapshot {
                    hash: *h,
                    device: m.device,
                    device_label: m.device_label.clone(),
                    seq: m.seq,
                    lamport: m.lamport,
                    wall_clock_ns: m.wall_clock_ns,
                    kind: m.kind,
                    header_generation: m.header.generation,
                    header_hash: m.header.hash,
                }
            })
            .collect();
        out.sort_by_key(|s| std::cmp::Reverse((s.lamport, s.hash)));
        Ok(out)
    }

    /// A read-only view of one snapshot (to browse or copy files from).
    pub fn snapshot_view(&self, hash: &[u8; 32]) -> Result<luksbox_vfs::Vfs> {
        let (manifests, _, _) = load_manifests(&self.store, &self.keys)?;
        let graph = Graph::build(manifests)?;
        let v = graph
            .usable
            .contains(hash)
            .then(|| graph.all[hash].clone())
            .ok_or(SyncError::Unsupported("no such snapshot"))?;
        if complete(&self.store, &self.keys, &v)?.is_none() {
            return Err(SyncError::Unsupported(
                "that snapshot's objects are not all present",
            ));
        }
        self.view(&v)
    }
}

/// Copy `inner` (a file, or a folder with everything in it) out of a
/// snapshot `view` into the `live` vault, next to where it was, as
/// "<name> (restored <date>)" (UTC, as in conflict copies): nothing in
/// the vault is replaced. Missing parent folders are created. Returns
/// the new path. Does not save `live`.
pub fn restore_path(
    view: &mut luksbox_vfs::Vfs,
    live: &mut luksbox_vfs::Vfs,
    inner: &str,
) -> Result<String> {
    let trimmed = inner.trim_end_matches('/');
    if trimmed.is_empty() {
        return Err(SyncError::Unsupported(
            "pick a file or folder to restore, not the whole vault",
        ));
    }
    let src = view
        .lookup_path(trimmed)
        .map_err(|_| SyncError::Unsupported("that path is not in this snapshot"))?;
    let (dir, name) = trimmed.rsplit_once('/').unwrap_or(("", trimmed));
    let mut parent = live.root_id();
    for part in dir.split('/').filter(|s| !s.is_empty()) {
        parent = match live.lookup(parent, part) {
            Ok(id) => id,
            Err(_) => live.mkdir(parent, part).map_err(vfs_err)?,
        };
    }
    let when = stamp(now_ns());
    let (base, ext) = match name.rfind('.') {
        Some(i) if i > 0 => (&name[..i], &name[i..]),
        _ => (name, ""),
    };
    let mut target = format!("{base} (restored {when}){ext}");
    let mut n = 2;
    while live.lookup(parent, &target).is_ok() {
        target = format!("{base} (restored {when} {n}){ext}");
        n += 1;
    }
    copy_tree(view, src, live, parent, &target)?;
    Ok(format!("{dir}/{target}"))
}

fn copy_tree(
    view: &mut luksbox_vfs::Vfs,
    src: u64,
    live: &mut luksbox_vfs::Vfs,
    parent: u64,
    name: &str,
) -> Result<()> {
    use luksbox_vfs::InodeKind;
    let st = view.stat(src).map_err(vfs_err)?;
    match st.kind {
        InodeKind::Directory => {
            let d = live.mkdir(parent, name).map_err(vfs_err)?;
            for e in view.readdir(src).map_err(vfs_err)? {
                copy_tree(view, e.id, live, d, &e.name)?;
            }
        }
        InodeKind::Symlink => {
            let t = view.readlink(src).map_err(vfs_err)?;
            live.symlink(parent, name, &t).map_err(vfs_err)?;
        }
        InodeKind::File => {
            let id = live
                .create_with_mode(parent, name, st.mode)
                .map_err(vfs_err)?;
            let mut buf = zeroize::Zeroizing::new(vec![0u8; 1 << 20]);
            let mut off = 0u64;
            while off < st.size {
                let n = view.read(src, off, &mut buf).map_err(vfs_err)?;
                if n == 0 {
                    break;
                }
                live.write(id, off, &buf[..n]).map_err(vfs_err)?;
                off += n as u64;
            }
            live.set_mtime(id, st.mtime_ns).map_err(vfs_err)?;
        }
    }
    Ok(())
}

impl Session {
    /// Objects `v` refers to, as far as its table blocks are here and
    /// verify (an incomplete commit still counts for what can be read).
    /// Used to tell objects some known commit uses from orphans.
    fn referenced(
        &self,
        v: &Verified,
        out: &mut HashSet<Obj>,
        tables_done: &mut HashSet<[u8; 32]>,
    ) -> Result<()> {
        out.insert((area_tag(Area::Manifest), v.oid.0));
        if let Some(n) = &v.m.header.name {
            out.insert((area_tag(Area::Header), sha256(n.as_bytes())));
        }
        if let Some(x) = &v.m.hybrid {
            out.insert((area_tag(Area::Hybrid), sha256(x.name.as_bytes())));
        }
        let mut s = self.store.lock().expect("store lock");
        for (b, r) in v.m.tables.iter().enumerate() {
            out.insert((area_tag(Area::Table), r.oid));
            if !tables_done.insert(r.oid) {
                continue;
            }
            let Ok(Some(obj)) = s.read(
                Area::Table,
                &Name::Object(r.object_id()),
                LenRule::Exact(BLOCK_OBJECT_LEN),
            ) else {
                continue;
            };
            let Ok(block) = TableBlock::open(&self.keys, r, b as u64, &obj) else {
                continue;
            };
            for e in block.entries.into_iter().flatten() {
                out.insert((area_tag(Area::Page), e.oid));
            }
        }
        Ok(())
    }

    /// Objects reachable from `v`: its manifest, header, hybrid sidecar,
    /// table blocks and pages.
    fn reachable(
        &self,
        v: &Verified,
        out: &mut HashSet<Obj>,
        tables_done: &mut HashSet<[u8; 32]>,
    ) -> Result<()> {
        out.insert((area_tag(Area::Manifest), v.oid.0));
        let blocks = complete(&self.store, &self.keys, v)?.ok_or(SyncError::Unsupported(
            "a kept commit is incomplete; collect later",
        ))?;
        for (r, block) in v.m.tables.iter().zip(blocks) {
            out.insert((area_tag(Area::Table), r.oid));
            if !tables_done.insert(r.oid) {
                continue;
            }
            for e in block.entries.into_iter().flatten() {
                out.insert((area_tag(Area::Page), e.oid));
            }
        }
        Ok(())
    }

    /// Run one garbage-collection pass. Needs a writable session, one
    /// head and no commit missing (it refuses rather than guess).
    pub fn gc(&mut self, opts: &GcOptions) -> Result<GcReport> {
        if !self.writable {
            return Err(SyncError::ReadOnly);
        }
        let now = opts.now_ns.unwrap_or_else(now_ns);
        let (manifests, _, foreign) = load_manifests(&self.store, &self.keys)?;
        let graph = Graph::build(manifests)?;
        let notices = graph.check(Some(&self.state))?;
        if !writable(&notices) || graph.pending() > 0 {
            return Err(SyncError::Unsupported(
                "some commits have not arrived yet; collect later",
            ));
        }
        if graph.heads.len() != 1 || graph.heads[0] != self.head.hash {
            return Err(SyncError::Unsupported(
                "concurrent commits must be merged before collecting",
            ));
        }
        let mut report = GcReport {
            foreign,
            ..GcReport::default()
        };

        // Roots.
        let mut roots: HashSet<[u8; 32]> = HashSet::new();
        for (_, h) in graph.newest.values() {
            roots.insert(*h);
        }
        let mut by_age: Vec<&Verified> = graph.usable.iter().map(|h| &graph.all[h]).collect();
        by_age.sort_by_key(|v| std::cmp::Reverse((v.m.lamport, v.hash)));
        for v in by_age.iter().take(opts.keep_last) {
            roots.insert(v.hash);
        }
        for v in &by_age {
            if now.saturating_sub(v.m.wall_clock_ns) <= opts.retention_ns {
                roots.insert(v.hash);
            }
        }
        // Leases pin their base (and the commit before it another device
        // made) for PIN_NS; older ones are removed below.
        let mut expired_leases: Vec<Name> = Vec::new();
        {
            let mut s = self.store.lock().expect("store lock");
            let leases = s.list(Area::Lease)?;
            for n in leases.names.iter().take(1000) {
                let Some(id) = n.object_id() else { continue };
                if let Ok(Some(b)) = s.read(Area::Lease, n, LenRule::Exact(LEASE_LEN))
                    && let Ok(l) = Lease::open(&self.keys, id, &b)
                {
                    if l.pins(now) {
                        roots.insert(l.base.hash);
                        if let Some(p) = l.pin {
                            roots.insert(p.hash);
                        }
                    } else {
                        expired_leases.push(*n);
                    }
                }
            }
        }
        report.roots = roots.len();

        let mut keep: HashSet<Obj> = HashSet::new();
        let mut tables_done = HashSet::new();
        let mut header_names: HashSet<String> = HashSet::new();
        for h in &roots {
            let Some(v) = graph.all.get(h) else { continue };
            self.reachable(v, &mut keep, &mut tables_done)?;
            if let Some(n) = &v.m.header.name {
                header_names.insert(n.clone());
            }
            if let Some(x) = &v.m.hybrid {
                header_names.insert(x.name.clone());
            }
        }
        // Checkpoints: per device, the lowest sequence number among its
        // kept commits (never below what is already declared). Every
        // manifest at or above its device's checkpoint stays, kept or not,
        // so sequence numbers stay contiguous; only the ones below can go.
        let mut checkpoint: BTreeMap<DeviceId, u64> = BTreeMap::new();
        for h in &roots {
            if let Some(v) = graph.all.get(h) {
                let e = checkpoint.entry(v.m.device).or_insert(u64::MAX);
                *e = (*e).min(v.m.seq);
            }
        }
        for (d, min) in &graph.checkpoint {
            let e = checkpoint.entry(*d).or_insert(*min);
            *e = (*e).max(*min);
        }
        for v in graph.all.values() {
            let floor = checkpoint.get(&v.m.device).copied().unwrap_or(0);
            // A plan still waiting for its grace period keeps the commit
            // that records it (only the manifest, not its state).
            let plan_pending =
                v.m.gc_plan
                    .as_ref()
                    .is_some_and(|p| now.saturating_sub(p.wall_clock_ns) < opts.grace_ns);
            if v.m.seq >= floor || plan_pending {
                keep.insert((area_tag(Area::Manifest), v.oid.0));
            }
        }

        // Everything present that no root reaches.
        let mut unreachable: Vec<(Area, Name)> = Vec::new();
        {
            let mut s = self.store.lock().expect("store lock");
            for area in [Area::Page, Area::Table, Area::Manifest] {
                for n in s.list(area)?.names {
                    let Some(id) = n.object_id() else { continue };
                    if !keep.contains(&(area_tag(area), id.0)) {
                        unreachable.push((area, n));
                    }
                }
            }
            let (_, candidates) = header_candidates(&mut **s)?;
            for (hn, _) in candidates {
                if !header_names.contains(&hn.to_name()) {
                    unreachable.push((Area::Header, Name::Header(hn)));
                }
            }
            for n in s.list(Area::Hybrid)?.names {
                if let Name::Header(hn) = n
                    && !header_names.contains(&hn.to_name())
                {
                    unreachable.push((Area::Hybrid, n));
                }
            }
        }
        let unreachable_by_key: HashMap<Obj, (Area, Name)> = unreachable
            .iter()
            .map(|(a, n)| ((area_tag(*a), name_key(n)), (*a, *n)))
            .collect();

        // Every object some known commit refers to, complete or not:
        // what is unreachable and outside this set is an orphan.
        let mut known: HashSet<Obj> = HashSet::new();
        let mut known_tables = HashSet::new();
        for v in graph.all.values() {
            self.referenced(v, &mut known, &mut known_tables)?;
        }

        // A clock that went back would date this pass's plan in the past.
        let own_latest = graph
            .all
            .values()
            .filter(|v| v.m.device == self.state.device)
            .map(|v| v.m.wall_clock_ns)
            .max()
            .unwrap_or(0);
        let seen_latest = {
            let mut l = self.local.lock().expect("local lock");
            load_sightings(&self.keys, &mut **l)?
                .into_values()
                .max()
                .unwrap_or(0)
        };
        if own_latest.max(seen_latest) > now.saturating_add(CLOCK_SLACK_NS) {
            return Err(SyncError::Unsupported(
                "this device's clock is behind its own earlier commits; correct the system \
                 clock before collecting",
            ));
        }

        // Pass 2: apply older plans, past their grace period, to what is
        // still unreachable now.
        let mut sightings = {
            let mut l = self.local.lock().expect("local lock");
            note_plan_sightings(&self.keys, &mut **l, &graph, now)?
        };
        let orphan_grace = opts.orphan_grace_ns.max(opts.grace_ns);
        let mut planned_before: HashSet<Obj> = HashSet::new();
        let mut to_delete: Vec<(Area, Name)> = Vec::new();
        for (h, v) in &graph.all {
            let Some(plan) = &v.m.gc_plan else { continue };
            let age = plan_age(plan, sightings.get(h).copied().unwrap_or(now), now);
            for &(tag, id) in &plan.objects {
                let key = (tag & !ORPHAN, id);
                planned_before.insert(key);
                let needed = if tag & ORPHAN != 0 {
                    orphan_grace
                } else {
                    opts.grace_ns
                };
                if age >= needed
                    && let Some(e) = unreachable_by_key.get(&key)
                {
                    to_delete.push(*e);
                }
            }
        }
        to_delete.sort_by_key(|(a, n)| (area_tag(*a), name_key(n)));
        to_delete.dedup();

        // Pass 1: plan what is newly unreachable.
        let new_plan: Vec<Obj> = unreachable_by_key
            .keys()
            .filter(|o| !planned_before.contains(o))
            .copied()
            .take(MAX_GC_OBJECTS)
            .collect();
        report.planned = new_plan.len();
        if opts.dry_run {
            report.deleted = to_delete.len();
            return Ok(report);
        }
        {
            let mut s = self.store.lock().expect("store lock");
            for (a, n) in &to_delete {
                if s.remove(*a, n)? {
                    report.deleted += 1;
                }
            }
            for n in &expired_leases {
                s.remove(Area::Lease, n)?;
            }
            s.sync()?;
        }
        if !new_plan.is_empty() {
            let mut objects: Vec<Obj> = new_plan
                .into_iter()
                .map(|(tag, id)| {
                    if known.contains(&(tag, id)) {
                        (tag, id)
                    } else {
                        report.orphans += 1;
                        (tag | ORPHAN, id)
                    }
                })
                .collect();
            objects.sort();
            let plan = GcPlan {
                wall_clock_ns: now,
                lamport: self.head.m.lamport + 1,
                objects,
            };
            if let Some(r) =
                self.publish_full(CommitKind::Gc, &[], vec![], Some(plan), Some(checkpoint))?
            {
                // This device saw its own plan now.
                sightings.insert(r.hash, now);
                let mut l = self.local.lock().expect("local lock");
                save_sightings(&self.keys, &mut **l, &sightings)?;
            }
        }
        Ok(report)
    }
}

fn name_key(n: &Name) -> [u8; 32] {
    match n {
        Name::Object(o) => o.0,
        // Header-style names: key by a digest of the name.
        Name::Header(h) => crate::table::sha256(h.to_name().as_bytes()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn plan(at: u64) -> GcPlan {
        GcPlan {
            wall_clock_ns: at,
            lamport: 1,
            objects: vec![],
        }
    }

    #[test]
    fn a_plan_is_as_old_as_the_younger_of_its_clock_and_its_sighting() {
        let now = 1_000 * DAY_NS;
        // Both agree.
        assert_eq!(
            plan_age(&plan(now - 8 * DAY_NS), now - 8 * DAY_NS, now),
            8 * DAY_NS
        );
        // Its author's clock was behind: seen here only a day ago.
        assert_eq!(
            plan_age(&plan(now - 100 * DAY_NS), now - DAY_NS, now),
            DAY_NS
        );
        // Seen here long ago, but made recently by its own clock.
        assert_eq!(plan_age(&plan(now - DAY_NS), now - 9 * DAY_NS, now), DAY_NS);
        // Dated in the future: the sighting alone.
        assert_eq!(
            plan_age(&plan(now + 50 * DAY_NS), now - 3 * DAY_NS, now),
            3 * DAY_NS
        );
    }
}
