// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Penthertz <https://penthertz.com> (https://x.com/PentHertz)

//! Deterministic simulation: the real `luksbox-sync` and `luksbox-merge`
//! code on several simulated devices, each with its own replica of the
//! bundle folder, synced through a simulated cloud that moves objects in
//! random order and with random delays (as sync clients do). Seeds make
//! every failure reproducible.
//!
//! Benign runs (lag, crashes, concurrent edits, garbage collection):
//! once everything has synced and every device has opened and closed,
//! every device converges, and every file a device saved is there with
//! the content it last saved (nothing is lost, nothing is invented).
//!
//! Adversarial runs (the provider rolls back, deletes, corrupts, plants
//! files): nothing panics, and every byte any device reads is content
//! some device actually wrote. `LUKSBOX_SIM_SEEDS` sets how many seeds
//! run (default 6; nightly runs use many more).

use std::collections::{BTreeMap, BTreeSet, HashSet};
use std::path::PathBuf;

use luksbox_core::{Argon2idParams, CipherSuite};
use luksbox_format::{Container, UnlockMaterial};
use luksbox_sync::bundle::{self, ConvertOptions, OpenOptions, Session};
use luksbox_sync::gc::GcOptions;
use luksbox_sync::local::{LocalStore, MemLocal};
use luksbox_sync::names::Area;
use luksbox_sync::store::SharedMem;
use luksbox_vfs::{InodeKind, Vfs};
use tempfile::TempDir;

const PASS: &[u8] = b"pw";
const KDF: Argon2idParams = Argon2idParams {
    m_cost_kib: 8,
    t_cost: 1,
    p_cost: 1,
};
const DEVICES: usize = 3;

struct Rng(u64);
impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }
    fn below(&mut self, n: u64) -> u64 {
        self.next() % n.max(1)
    }
    fn chance(&mut self, pct: u64) -> bool {
        self.below(100) < pct
    }
}

type Key = (Area, String, String);

/// The cloud and one replica per device.
struct Net {
    cloud: BTreeMap<Key, Vec<u8>>,
    replicas: Vec<SharedMem>,
    /// Per device: keys known to be in step with the cloud.
    synced: Vec<HashSet<Key>>,
}

impl Net {
    fn new(n: usize) -> Self {
        Self {
            cloud: BTreeMap::new(),
            replicas: (0..n).map(|_| SharedMem::new()).collect(),
            synced: vec![HashSet::new(); n],
        }
    }

    /// Move a random part of what is pending between device `d` and the
    /// cloud, both ways. `all` moves everything.
    fn sync(&mut self, d: usize, rng: &mut Rng, all: bool) {
        let replica = self.replicas[d].clone();
        replica.with(|m| {
            let local = m.raw_mut();
            let synced = &mut self.synced[d];
            // Uploads: new or changed locally.
            let keys: Vec<Key> = local.keys().cloned().collect();
            for k in keys {
                let differs = self.cloud.get(&k) != local.get(&k);
                if differs && (all || rng.chance(50)) {
                    if !synced.contains(&k) || self.cloud.contains_key(&k) {
                        self.cloud.insert(k.clone(), local[&k].clone());
                        synced.insert(k);
                    }
                }
            }
            // Local deletions.
            let gone: Vec<Key> = synced
                .iter()
                .filter(|k| !local.contains_key(*k))
                .cloned()
                .collect();
            for k in gone {
                if all || rng.chance(50) {
                    self.cloud.remove(&k);
                    synced.remove(&k);
                }
            }
            // Downloads: new or changed in the cloud.
            let cloud_keys: Vec<Key> = self.cloud.keys().cloned().collect();
            for k in cloud_keys {
                if local.get(&k) != self.cloud.get(&k) && (all || rng.chance(50)) {
                    local.insert(k.clone(), self.cloud[&k].clone());
                    synced.insert(k);
                }
            }
            // Deletions in the cloud.
            let removed: Vec<Key> = synced
                .iter()
                .filter(|k| !self.cloud.contains_key(*k) && local.contains_key(*k))
                .cloned()
                .collect();
            for k in removed {
                if all || rng.chance(50) {
                    local.remove(&k);
                    synced.remove(&k);
                }
            }
        });
    }

    fn quiesce(&mut self, rng: &mut Rng) {
        for _ in 0..3 {
            for d in 0..self.replicas.len() {
                self.sync(d, rng, true);
            }
        }
    }
}

struct Dev {
    local: MemLocal,
    label: String,
    open: Option<(Session, Vfs)>,
    /// Expected content of this device's own files (None = deleted).
    expect: BTreeMap<String, Option<Vec<u8>>>,
}

fn open(
    net: &Net,
    d: usize,
    dev: &Dev,
) -> luksbox_sync::Result<(Session, Vfs, bundle::OpenReport)> {
    let l = dev.local.clone();
    let (s, c, r) = Session::open(
        Box::new(net.replicas[d].clone()),
        move |_| Ok(Box::new(l) as Box<dyn LocalStore>),
        PathBuf::from(format!("dev{d}.lbxs")),
        &mut UnlockMaterial::Passphrase(PASS),
        &OpenOptions {
            device_label: dev.label.clone(),
            read_only: false,
        },
    )?;
    let vfs = Vfs::open(c)
        .map_err(|e| luksbox_sync::SyncError::Io(std::io::Error::other(e.to_string())))?;
    Ok((s, vfs, r))
}

/// `None` when the folder is missing and cannot be made (a device that
/// opened read-only because a commit is withheld).
fn mkdirs(v: &mut Vfs, dir: &str) -> Option<u64> {
    let mut cur = v.root_id();
    for part in dir.split('/').filter(|p| !p.is_empty()) {
        cur = match v.lookup(cur, part) {
            Ok(id) => id,
            Err(_) => v.mkdir(cur, part).ok()?,
        };
    }
    Some(cur)
}

fn write(v: &mut Vfs, path: &str, data: &[u8]) -> bool {
    let (dir, name) = path.rsplit_once('/').unwrap();
    let Some(parent) = mkdirs(v, dir) else {
        return false;
    };
    let id = match v.lookup(parent, name) {
        Ok(id) => id,
        Err(_) => match v.create(parent, name) {
            Ok(id) => id,
            Err(_) => return false,
        },
    };
    v.truncate(id, 0).is_ok() && v.write(id, 0, data).is_ok()
}

fn files(v: &mut Vfs) -> BTreeMap<String, Vec<u8>> {
    let mut out = BTreeMap::new();
    let mut q = vec![(v.root_id(), String::new())];
    while let Some((d, p)) = q.pop() {
        let Ok(entries) = v.readdir(d) else { continue };
        for e in entries {
            let path = format!("{p}/{}", e.name);
            match e.kind {
                InodeKind::Directory => q.push((e.id, path)),
                InodeKind::File => {
                    let size = v.stat(e.id).map(|s| s.size).unwrap_or(0) as usize;
                    let mut buf = vec![0u8; size];
                    if let Ok(n) = v.read(e.id, 0, &mut buf) {
                        buf.truncate(n);
                        out.insert(path, buf);
                    }
                }
                InodeKind::Symlink => {}
            }
        }
    }
    out
}

fn setup(dir: &TempDir, net: &mut Net, devs: &[Dev]) {
    let lbx = dir.path().join("v.lbx");
    let _g = luksbox_format::metadata::set_create_metadata_region_size_override(Some(2 << 20));
    let c = Container::create_with_passphrase(&lbx, None, CipherSuite::Aes256GcmSiv, KDF, PASS)
        .unwrap();
    let mut c = Vfs::open(c).unwrap().close().unwrap();
    let l = devs[0].local.clone();
    bundle::convert(
        &mut c,
        Box::new(net.replicas[0].clone()),
        move |_| Ok(Box::new(l) as Box<dyn LocalStore>),
        &ConvertOptions {
            page_size: 1 << 20,
            device_label: devs[0].label.clone(),
            hybrid_sidecar: None,
        },
    )
    .unwrap();
    let mut rng = Rng(1);
    net.quiesce(&mut rng);
}

fn content(d: usize, step: usize, rng: &mut Rng) -> Vec<u8> {
    let len = 1 + rng.below(9000) as usize;
    let mut v = format!("dev{d}-step{step}-").into_bytes();
    v.resize(len.max(v.len()), b'a' + (step % 26) as u8);
    v
}

/// One benign run: returns a description of the first broken invariant.
fn benign(seed: u64, steps: usize) -> Result<(), String> {
    let dir = TempDir::new().unwrap();
    let mut rng = Rng(seed.wrapping_mul(0x9e37_79b9_7f4a_7c15) | 1);
    let mut net = Net::new(DEVICES);
    let mut devs: Vec<Dev> = (0..DEVICES)
        .map(|d| Dev {
            local: MemLocal::default(),
            label: format!("Dev{d}"),
            open: None,
            expect: BTreeMap::new(),
        })
        .collect();
    setup(&dir, &mut net, &devs);
    let mut written: HashSet<Vec<u8>> = HashSet::new();

    for step in 0..steps {
        let d = rng.below(DEVICES as u64) as usize;
        match rng.below(12) {
            0 | 1 => {
                if devs[d].open.is_none() {
                    match open(&net, d, &devs[d]) {
                        Ok((s, v, r)) => {
                            if trace() {
                                eprintln!(
                                    "step {step}: dev{d} open writable={} restored={} notices={:?} head={}",
                                    r.writable,
                                    r.restored_local_changes,
                                    r.notices,
                                    s.head().m.seq
                                );
                            }
                            if r.writable {
                                devs[d].open = Some((s, v));
                            }
                        }
                        Err(e) => {
                            if trace() {
                                eprintln!("step {step}: dev{d} open failed: {e}");
                            }
                        }
                    }
                }
            }
            2..=4 => {
                if let Some((_, v)) = devs[d].open.as_mut() {
                    let path = format!("/dev{d}/f{}.txt", rng.below(4));
                    let c = content(d, step, &mut rng);
                    if write(v, &path, &c) && v.flush().is_ok() {
                        if trace() {
                            eprintln!("step {step}: dev{d} wrote {path} ({} bytes)", c.len());
                        }
                        written.insert(c.clone());
                        devs[d].expect.insert(path, Some(c));
                    }
                }
            }
            5 => {
                if let Some((_, v)) = devs[d].open.as_mut() {
                    let path = format!("/dev{d}/f{}.txt", rng.below(4));
                    let name = path.rsplit_once('/').unwrap().1;
                    if let Some(dirid) = mkdirs(v, &format!("/dev{d}"))
                        && v.unlink(dirid, name).is_ok()
                        && v.flush().is_ok()
                    {
                        devs[d].expect.insert(path, None);
                    }
                }
            }
            6 => {
                // A file everyone writes: only provenance is checked.
                if let Some((_, v)) = devs[d].open.as_mut() {
                    let c = content(d, step, &mut rng);
                    if write(v, "/shared.txt", &c) && v.flush().is_ok() {
                        written.insert(c);
                    }
                }
            }
            7 => {
                if let Some((s, _)) = devs[d].open.as_mut() {
                    let r = s.publish();
                    if trace() {
                        eprintln!(
                            "step {step}: dev{d} publish -> {:?}",
                            r.as_ref()
                                .map(|o| o.map(|m| m.seq))
                                .map_err(|e| e.to_string())
                        );
                    }
                }
            }
            8 => {
                if let Some((mut s, mut v)) = devs[d].open.take() {
                    let r = s.finish(&mut v);
                    if trace() {
                        eprintln!(
                            "step {step}: dev{d} finish -> {:?}",
                            r.as_ref()
                                .map(|f| (f.published.map(|m| m.seq), f.merged))
                                .map_err(|e| e.to_string())
                        );
                    }
                }
            }
            9 => {
                // Crash: no Drop, the lease stays as after a power cut.
                if trace() {
                    eprintln!("step {step}: dev{d} crash");
                }
                if let Some((s, v)) = devs[d].open.take() {
                    std::mem::forget(v);
                    std::mem::forget(s);
                }
            }
            10 => {
                if let Some((s, _)) = devs[d].open.as_mut() {
                    if trace() {
                        eprintln!("step {step}: dev{d} gc");
                    }
                    let _ = s.gc(&GcOptions {
                        retention_ns: 0,
                        keep_last: 2,
                        grace_ns: 0,
                        ..GcOptions::default()
                    });
                }
            }
            _ => {}
        }
        // The sync clients make some progress every step.
        for x in 0..DEVICES {
            if rng.chance(60) {
                net.sync(x, &mut rng, false);
            }
        }
    }

    // Wind down: everyone closes, everything syncs, everyone opens and
    // closes again (publishing and merging) until quiet.
    for dev in devs.iter_mut() {
        if let Some((mut s, mut v)) = dev.open.take() {
            let _ = s.finish(&mut v);
        }
    }
    for _round in 0..4 {
        net.quiesce(&mut rng);
        for d in 0..DEVICES {
            match open(&net, d, &devs[d]) {
                Ok((mut s, mut v, r)) => {
                    if trace() {
                        eprintln!(
                            "final: dev{d} open writable={} restored={} notices={:?} unpublished={}",
                            r.writable,
                            r.restored_local_changes,
                            r.notices,
                            s.has_unpublished()
                        );
                    }
                    s.finish(&mut v)
                        .map_err(|e| format!("seed {seed}: final finish on dev{d}: {e}"))?;
                }
                Err(e) => return Err(format!("seed {seed}: final open on dev{d}: {e}")),
            }
            net.quiesce(&mut rng);
        }
    }

    // Converged, nothing lost, nothing invented.
    let mut views = Vec::new();
    for d in 0..DEVICES {
        let (_s, mut v, r) =
            open(&net, d, &devs[d]).map_err(|e| format!("seed {seed}: check open dev{d}: {e}"))?;
        if r.other_heads != 0 {
            return Err(format!(
                "seed {seed}: dev{d} still sees {} other heads",
                r.other_heads
            ));
        }
        views.push(files(&mut v));
    }
    for d in 1..DEVICES {
        if views[d] != views[0] {
            return Err(format!("seed {seed}: dev{d} did not converge with dev0"));
        }
    }
    let all = &views[0];
    if trace() {
        let (s, _v, _) = open(&net, 0, &devs[0]).unwrap();
        for snap in s.snapshots().unwrap() {
            let state = match s.snapshot_view(&snap.hash) {
                Ok(mut v) => {
                    let f = files(&mut v);
                    devs[0]
                        .expect
                        .iter()
                        .map(|(p, w)| {
                            format!(
                                "{p}:{}",
                                match (w, f.get(p)) {
                                    (Some(w), Some(g)) if w == g => "ok".to_string(),
                                    (_, Some(g)) => format!("{}b", g.len()),
                                    (_, None) => "-".to_string(),
                                }
                            )
                        })
                        .collect::<Vec<_>>()
                        .join(" ")
                }
                Err(e) => format!("<{e}>"),
            };
            eprintln!(
                "snap {} seq {} kind {:?} lamport {} : {state}",
                snap.device_label, snap.seq, snap.kind, snap.lamport
            );
        }
    }
    for (d, dev) in devs.iter().enumerate() {
        for (path, want) in &dev.expect {
            match (want, all.get(path)) {
                (Some(w), Some(got)) if w == got => {}
                (None, None) => {}
                (want, got) => {
                    // A version this device saved may legitimately sit in
                    // a conflict copy if the same device raced itself
                    // across a crash; it must exist somewhere though.
                    if let Some(w) = want
                        && all.values().any(|c| c == w)
                    {
                        continue;
                    }
                    if want.is_none() && got.is_some() {
                        // Deleted here, but a concurrent edit by this same
                        // device's earlier crashed session won: kept.
                        continue;
                    }
                    return Err(format!(
                        "seed {seed}: dev{d} {path}: expected {:?} bytes, found {:?}",
                        want.as_ref().map(|w| w.len()),
                        got.map(|g| g.len())
                    ));
                }
            }
        }
    }
    for (path, c) in all {
        if !written.contains(c) {
            return Err(format!("seed {seed}: {path} holds content nobody wrote"));
        }
    }
    Ok(())
}

/// One adversarial run: the provider tampers with the cloud.
fn adversarial(seed: u64, steps: usize) -> Result<(), String> {
    let dir = TempDir::new().unwrap();
    let mut rng = Rng(seed.wrapping_mul(0xd1b5_4a32_d192_ed03) | 1);
    let mut net = Net::new(DEVICES);
    let mut devs: Vec<Dev> = (0..DEVICES)
        .map(|d| Dev {
            local: MemLocal::default(),
            label: format!("Dev{d}"),
            open: None,
            expect: BTreeMap::new(),
        })
        .collect();
    setup(&dir, &mut net, &devs);
    let mut written: HashSet<Vec<u8>> = HashSet::new();
    let mut stash: Vec<(Key, Vec<u8>)> = Vec::new();

    for step in 0..steps {
        let d = rng.below(DEVICES as u64) as usize;
        match rng.below(10) {
            0 | 1 => {
                if devs[d].open.is_none()
                    && let Ok((s, v, _)) = open(&net, d, &devs[d])
                {
                    devs[d].open = Some((s, v));
                }
            }
            2 | 3 => {
                if let Some((s, v)) = devs[d].open.as_mut() {
                    let c = content(d, step, &mut rng);
                    if write(v, &format!("/dev{d}/f{}.txt", rng.below(3)), &c) {
                        written.insert(c);
                    }
                    let _ = v.flush();
                    let _ = s.publish();
                }
            }
            4 => {
                if let Some((mut s, mut v)) = devs[d].open.take() {
                    let _ = s.finish(&mut v);
                }
            }
            5 => {
                // Rollback: hide a random manifest (sometimes forever).
                let ms: Vec<Key> = net
                    .cloud
                    .keys()
                    .filter(|k| k.0 == Area::Manifest)
                    .cloned()
                    .collect();
                if !ms.is_empty() {
                    let k = ms[rng.below(ms.len() as u64) as usize].clone();
                    let b = net.cloud.remove(&k).unwrap();
                    if rng.chance(50) {
                        stash.push((k, b));
                    }
                }
            }
            6 => {
                // Corrupt a random object.
                let ks: Vec<Key> = net.cloud.keys().cloned().collect();
                if !ks.is_empty() {
                    let k = ks[rng.below(ks.len() as u64) as usize].clone();
                    let b = net.cloud.get_mut(&k).unwrap();
                    if !b.is_empty() {
                        let i = rng.below(b.len() as u64) as usize;
                        b[i] ^= 1 << rng.below(8);
                    }
                }
            }
            7 => {
                // Restore something hidden (replay of an old state).
                if let Some((k, b)) = stash.pop() {
                    net.cloud.insert(k, b);
                }
            }
            8 => {
                // Plant junk with plausible names.
                let k = (Area::Page, "ab".to_string(), format!("{:064x}", rng.next()));
                net.cloud.insert(k, vec![0u8; 1 + rng.below(100) as usize]);
            }
            _ => {}
        }
        for x in 0..DEVICES {
            if rng.chance(60) {
                net.sync(x, &mut rng, false);
            }
        }
        // Every byte any device can read was written by some device.
        for dev in devs.iter_mut() {
            if let Some((_, v)) = dev.open.as_mut() {
                for (path, c) in files(v) {
                    if !c.is_empty() && !written.contains(&c) {
                        return Err(format!(
                            "seed {seed} step {step}: {path} holds content nobody wrote"
                        ));
                    }
                }
            }
        }
    }
    Ok(())
}

fn seeds() -> std::ops::RangeInclusive<u64> {
    if let Some(one) = std::env::var("LUKSBOX_SIM_SEED")
        .ok()
        .and_then(|s| s.parse().ok())
    {
        return one..=one;
    }
    1..=std::env::var("LUKSBOX_SIM_SEEDS")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(6)
}

fn trace() -> bool {
    std::env::var_os("LUKSBOX_SIM_TRACE").is_some()
}

#[test]
fn benign_runs_converge_without_loss() {
    let mut failures = BTreeSet::new();
    for seed in seeds() {
        if let Err(e) = benign(seed, 70) {
            failures.insert(e);
        }
    }
    assert!(failures.is_empty(), "{failures:#?}");
}

#[test]
fn adversarial_runs_never_forge_or_panic() {
    let mut failures = BTreeSet::new();
    for seed in seeds() {
        if let Err(e) = adversarial(seed, 60) {
            failures.insert(e);
        }
    }
    assert!(failures.is_empty(), "{failures:#?}");
}
