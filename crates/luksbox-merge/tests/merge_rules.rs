// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Penthertz <https://penthertz.com> (https://x.com/PentHertz)

//! The merge rules, one by one, and a randomized "nothing is lost"
//! property over many pairs of concurrent edit sequences.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

use luksbox_core::{Argon2idParams, CipherSuite};
use luksbox_format::{Container, UnlockMaterial};
use luksbox_merge::{Options, merge};
use luksbox_vfs::{FileId, InodeKind, Vfs};
use tempfile::TempDir;

const PASS: &[u8] = b"pw";
const KDF: Argon2idParams = Argon2idParams {
    m_cost_kib: 8,
    t_cost: 1,
    p_cost: 1,
};

fn opts() -> Options {
    Options {
        label: "Laptop".into(),
        stamp: "2026-10-13 1032".into(),
    }
}

fn open(p: &Path) -> Vfs {
    Vfs::open(Container::open(p, None, UnlockMaterial::Passphrase(PASS)).unwrap()).unwrap()
}

fn open_ro(p: &Path) -> Vfs {
    Vfs::open_read_only(Container::open(p, None, UnlockMaterial::Passphrase(PASS)).unwrap())
        .unwrap()
}

fn mkdirs(v: &mut Vfs, path: &str) -> FileId {
    let mut cur = v.root_id();
    for part in path.split('/').filter(|s| !s.is_empty()) {
        cur = match v.lookup(cur, part) {
            Ok(id) => id,
            Err(_) => v.mkdir(cur, part).unwrap(),
        };
    }
    cur
}

fn put(v: &mut Vfs, path: &str, data: &[u8]) {
    let (dir, name) = path.rsplit_once('/').unwrap();
    let parent = mkdirs(v, dir);
    let id = match v.lookup(parent, name) {
        Ok(id) => id,
        Err(_) => v.create(parent, name).unwrap(),
    };
    v.truncate(id, 0).unwrap();
    v.write(id, 0, data).unwrap();
}

fn del(v: &mut Vfs, path: &str) {
    let (dir, name) = path.rsplit_once('/').unwrap();
    let parent = if dir.is_empty() {
        v.root_id()
    } else {
        v.lookup_path(dir).unwrap()
    };
    v.unlink(parent, name).unwrap();
}

fn mv(v: &mut Vfs, from: &str, to: &str) {
    let (fd, fname) = from.rsplit_once('/').unwrap();
    let (td, tname) = to.rsplit_once('/').unwrap();
    let fp = if fd.is_empty() {
        v.root_id()
    } else {
        v.lookup_path(fd).unwrap()
    };
    let tp = mkdirs(v, td);
    v.rename(fp, fname, tp, tname).unwrap();
}

/// Every file of the vault: path -> content.
fn files(v: &mut Vfs) -> BTreeMap<String, Vec<u8>> {
    let mut out = BTreeMap::new();
    let mut q = vec![(v.root_id(), String::new())];
    while let Some((d, p)) = q.pop() {
        for e in v.readdir(d).unwrap() {
            let path = format!("{p}/{}", e.name);
            match e.kind {
                InodeKind::Directory => q.push((e.id, path)),
                InodeKind::File => {
                    let size = v.stat(e.id).unwrap().size as usize;
                    let mut buf = vec![0u8; size];
                    let n = v.read(e.id, 0, &mut buf).unwrap();
                    buf.truncate(n);
                    out.insert(path, buf);
                }
                InodeKind::Symlink => {}
            }
        }
    }
    out
}

struct Setup {
    _dir: TempDir,
    base: PathBuf,
    ours: PathBuf,
    theirs: PathBuf,
}

/// A base vault with a few files, copied to `ours` and `theirs`.
fn setup(init: impl FnOnce(&mut Vfs)) -> Setup {
    let dir = TempDir::new().unwrap();
    let base = dir.path().join("base.lbx");
    let _g = luksbox_format::metadata::set_create_metadata_region_size_override(Some(2 << 20));
    let c = Container::create_with_passphrase(&base, None, CipherSuite::Aes256GcmSiv, KDF, PASS)
        .unwrap();
    let mut v = Vfs::open(c).unwrap();
    init(&mut v);
    v.flush().unwrap();
    drop(v.close().unwrap());
    let ours = dir.path().join("ours.lbx");
    let theirs = dir.path().join("theirs.lbx");
    std::fs::copy(&base, &ours).unwrap();
    std::fs::copy(&base, &theirs).unwrap();
    Setup {
        _dir: dir,
        base,
        ours,
        theirs,
    }
}

/// Apply edits, merge ours into theirs, return the merged files and the
/// outcome.
fn run(
    s: &Setup,
    with_base: bool,
    edit_ours: impl FnOnce(&mut Vfs),
    edit_theirs: impl FnOnce(&mut Vfs),
) -> (BTreeMap<String, Vec<u8>>, luksbox_merge::Outcome) {
    {
        let mut o = open(&s.ours);
        edit_ours(&mut o);
        o.flush().unwrap();
    }
    {
        let mut t = open(&s.theirs);
        edit_theirs(&mut t);
        t.flush().unwrap();
    }
    let mut base = open_ro(&s.base);
    let mut ours = open_ro(&s.ours);
    let mut target = open(&s.theirs);
    let out = merge(
        if with_base { Some(&mut base) } else { None },
        &mut ours,
        &mut target,
        &opts(),
    )
    .unwrap();
    target.flush().unwrap();
    let f = files(&mut target);
    (f, out)
}

fn base_files(v: &mut Vfs) {
    put(v, "/keep.txt", b"keep");
    put(v, "/edit.txt", b"original");
    put(v, "/del.txt", b"to delete");
    put(v, "/mv.txt", b"to move");
    put(v, "/dir/a.txt", b"in dir");
}

fn conflict(path_stem: &str, ext: &str) -> String {
    format!("{path_stem} (conflict Laptop 2026-10-13 1032){ext}")
}

#[test]
fn one_sided_changes_all_apply() {
    let s = setup(base_files);
    let (f, out) = run(
        &s,
        true,
        |o| {
            put(o, "/edit.txt", b"edited here");
            del(o, "/del.txt");
            put(o, "/new.txt", b"new here");
            mv(o, "/mv.txt", "/moved/mv.txt");
            put(o, "/newdir/deep/x.txt", b"deep");
        },
        |_| {},
    );
    assert_eq!(out.conflicts, 0);
    assert_eq!(f["/edit.txt"], b"edited here");
    assert!(!f.contains_key("/del.txt"));
    assert_eq!(f["/new.txt"], b"new here");
    assert!(!f.contains_key("/mv.txt"));
    assert_eq!(f["/moved/mv.txt"], b"to move");
    assert_eq!(f["/newdir/deep/x.txt"], b"deep");
    assert_eq!(f["/keep.txt"], b"keep");
    assert_eq!(f["/dir/a.txt"], b"in dir");
}

#[test]
fn both_edit_differently_keeps_both() {
    let s = setup(base_files);
    let (f, out) = run(
        &s,
        true,
        |o| put(o, "/edit.txt", b"ours"),
        |t| put(t, "/edit.txt", b"theirs"),
    );
    assert_eq!(out.conflicts, 1);
    assert_eq!(f["/edit.txt"], b"theirs");
    assert_eq!(f[&conflict("/edit", ".txt")], b"ours");
}

#[test]
fn both_edit_identically_is_not_a_conflict() {
    let s = setup(base_files);
    let (f, out) = run(
        &s,
        true,
        |o| put(o, "/edit.txt", b"same"),
        |t| put(t, "/edit.txt", b"same"),
    );
    assert_eq!(out.conflicts, 0);
    assert_eq!(f["/edit.txt"], b"same");
    assert_eq!(f.len(), 5);
}

#[test]
fn edit_beats_delete_both_ways() {
    let s = setup(base_files);
    let (f, _) = run(
        &s,
        true,
        |o| del(o, "/edit.txt"),
        |t| put(t, "/edit.txt", b"edited there"),
    );
    assert_eq!(f["/edit.txt"], b"edited there");

    let s = setup(base_files);
    let (f, _) = run(
        &s,
        true,
        |o| put(o, "/edit.txt", b"edited here"),
        |t| del(t, "/edit.txt"),
    );
    assert_eq!(f["/edit.txt"], b"edited here");
}

#[test]
fn same_new_path_different_content() {
    let s = setup(base_files);
    let (f, out) = run(
        &s,
        true,
        |o| put(o, "/report.pdf", b"ours"),
        |t| put(t, "/report.pdf", b"theirs"),
    );
    assert_eq!(out.conflicts, 1);
    assert_eq!(f["/report.pdf"], b"theirs");
    assert_eq!(f[&conflict("/report", ".pdf")], b"ours");
}

#[test]
fn folder_deleted_there_with_files_added_here_is_kept() {
    let s = setup(base_files);
    let (f, _) = run(
        &s,
        true,
        |o| put(o, "/dir/b.txt", b"added here"),
        |t| {
            del(t, "/dir/a.txt");
            let root = t.root_id();
            t.rmdir(root, "dir").unwrap();
        },
    );
    assert_eq!(f["/dir/b.txt"], b"added here");
    assert!(!f.contains_key("/dir/a.txt"));
}

#[test]
fn renamed_on_both_sides_keeps_theirs() {
    let s = setup(base_files);
    let (f, out) = run(
        &s,
        true,
        |o| mv(o, "/mv.txt", "/ours-name.txt"),
        |t| mv(t, "/mv.txt", "/theirs-name.txt"),
    );
    assert_eq!(f["/theirs-name.txt"], b"to move");
    assert!(!f.contains_key("/ours-name.txt"));
    assert!(
        out.events
            .iter()
            .any(|e| e.what.contains("renamed on both sides"))
    );
}

/// Each side moved one folder into the other: applying ours' move would
/// put a folder inside itself. The merge must not fail (it runs on
/// every writable open of a bundle); ours' move is left undone and
/// logged, and no file is lost.
#[test]
fn crossed_folder_moves_do_not_fail_the_merge() {
    let s = setup(|v| {
        put(v, "/a/x.txt", b"x");
        put(v, "/b/y.txt", b"y");
    });
    let (f, out) = run(&s, true, |o| mv(o, "/a", "/b/a"), |t| mv(t, "/b", "/a/b"));
    assert_eq!(f["/a/x.txt"], b"x");
    assert_eq!(f["/a/b/y.txt"], b"y");
    assert!(
        out.events.iter().any(|e| e.what.contains("into itself")),
        "{:?}",
        out.events
    );
}

#[test]
fn union_without_base() {
    let s = setup(base_files);
    let (f, out) = run(
        &s,
        false,
        |o| put(o, "/only-ours.txt", b"o"),
        |t| put(t, "/edit.txt", b"theirs edit"),
    );
    assert_eq!(f["/only-ours.txt"], b"o");
    assert_eq!(f["/edit.txt"], b"theirs edit");
    // Ours' unchanged /edit.txt ("original") differs from theirs' edit:
    // without a base it cannot be told apart from a change, so it is kept
    // as a conflict copy rather than dropped.
    assert_eq!(f[&conflict("/edit", ".txt")], b"original");
    assert!(out.conflicts >= 1);
}

#[test]
fn merge_into_read_only_target_is_refused() {
    let s = setup(base_files);
    let mut ours = open_ro(&s.ours);
    let mut target = open_ro(&s.theirs);
    assert!(merge(None, &mut ours, &mut target, &opts()).is_err());
}

/// Tiny deterministic PRNG for the property test.
struct Rng(u64);
impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }
    fn pick<'a>(&mut self, v: &'a [String]) -> Option<&'a String> {
        if v.is_empty() {
            None
        } else {
            Some(&v[(self.next() % v.len() as u64) as usize])
        }
    }
}

fn random_edits(v: &mut Vfs, rng: &mut Rng, tag: &str) {
    for step in 0..12 {
        let existing: Vec<String> = files(v).keys().cloned().collect();
        match rng.next() % 5 {
            0 | 1 => {
                let p = format!("/d{}/f{}.txt", rng.next() % 3, rng.next() % 6);
                put(v, &p, format!("{tag}-{step}-{}", rng.next()).as_bytes());
            }
            2 => {
                if let Some(p) = rng.pick(&existing).cloned() {
                    put(v, &p, format!("{tag}-edit-{step}").as_bytes());
                }
            }
            3 => {
                if let Some(p) = rng.pick(&existing).cloned() {
                    del(v, &p);
                }
            }
            _ => {
                if let Some(p) = rng.pick(&existing).cloned() {
                    let to = format!("/m{}/r{}-{step}.txt", rng.next() % 2, tag);
                    mv(v, &p, &to);
                }
            }
        }
    }
}

#[test]
fn randomized_merges_never_lose_a_version() {
    for seed in 1..=12u64 {
        let s = setup(|v| {
            for i in 0..4 {
                put(
                    v,
                    &format!("/d{}/f{i}.txt", i % 2),
                    format!("base-{i}").as_bytes(),
                );
            }
        });
        let base_contents: BTreeSet<Vec<u8>> = files(&mut open_ro(&s.base)).into_values().collect();
        let mut rng = Rng(seed.wrapping_mul(0x9e37_79b9_7f4a_7c15));
        let mut rng2 = Rng(seed.wrapping_mul(0xd1b5_4a32_d192_ed03).wrapping_add(7));
        {
            let mut o = open(&s.ours);
            random_edits(&mut o, &mut rng, "o");
            o.flush().unwrap();
        }
        {
            let mut t = open(&s.theirs);
            random_edits(&mut t, &mut rng2, "t");
            t.flush().unwrap();
        }
        let ours_files = files(&mut open_ro(&s.ours));
        let theirs_files = files(&mut open_ro(&s.theirs));
        let mut base = open_ro(&s.base);
        let mut ours = open_ro(&s.ours);
        let mut target = open(&s.theirs);
        merge(Some(&mut base), &mut ours, &mut target, &opts()).unwrap();
        target.flush().unwrap();
        let merged: BTreeSet<Vec<u8>> = files(&mut target).into_values().collect();
        // Every version either side wrote (anything not already in the
        // base) survives the merge somewhere.
        for (p, c) in ours_files.iter().chain(theirs_files.iter()) {
            if !base_contents.contains(c) {
                assert!(merged.contains(c), "seed {seed}: version of {p} lost");
            }
        }
    }
}
