// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Penthertz <https://penthertz.com> (https://x.com/PentHertz)

#![no_main]

//! Folder listings of a bundle: every entry name, shard folder name and
//! placement is provider-controlled. Whatever is planted, a listing
//! returns only names that parse back to themselves and sit where their
//! name says, counts the rest as foreign, and never panics. Added in
//! Round 16.

use libfuzzer_sys::fuzz_target;
use luksbox_sync::names::{Area, Name};
use luksbox_sync::store::{MemStore, ObjectStore};

fn text(b: &[u8]) -> String {
    // Mostly hex-looking so valid names are reachable, with the odd
    // other character.
    b.iter()
        .map(|&c| match c % 20 {
            0..=15 => char::from(b"0123456789abcdef"[(c % 16) as usize]),
            16 => 'A',
            17 => '.',
            18 => '-',
            _ => ' ',
        })
        .collect()
}

fuzz_target!(|data: &[u8]| {
    let mut store = MemStore::new();
    let mut rest = data;
    let mut planted = 0;
    while rest.len() >= 4 && planted < 64 {
        let area = Area::ALL[(rest[0] % 6) as usize];
        let shard_len = (rest[1] % 4) as usize;
        let leaf_len = (rest[2] as usize) % 96;
        rest = &rest[3..];
        let shard: String = text(&rest[..shard_len.min(rest.len())]);
        rest = &rest[shard_len.min(rest.len())..];
        let leaf: String = text(&rest[..leaf_len.min(rest.len())]);
        rest = &rest[leaf_len.min(rest.len())..];
        if leaf.is_empty() {
            continue;
        }
        store.plant(area, &shard, &leaf, vec![0u8; 3]);
        planted += 1;
    }
    for area in Area::ALL {
        let l = store.list(area).expect("a listing never fails on names");
        for n in &l.names {
            let leaf = n.leaf();
            assert_eq!(Name::parse_in(area, &leaf), Some(*n), "prints back as itself");
            if area.sharded() {
                assert_eq!(n.shard().as_deref(), Some(&leaf[..2]));
            }
            // What was listed can be read.
            let _ = store.read(area, n, luksbox_sync::store::LenRule::Exact(3));
        }
        assert!(l.names.len() + l.foreign_count + l.tmp_count <= planted);
    }
});
