// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Penthertz <https://penthertz.com> (https://x.com/PentHertz)

#![no_main]

//! The real bundle folder (`FsStore`) with hostile contents: symbolic
//! links (to a file outside the bundle and to folders), hard links,
//! FIFOs, folders where files belong and files where folders belong,
//! wrong sizes and arbitrary names, all placed by the fuzzer. Invariant
//! I7: nothing outside the bundle is ever read (the sentinel's bytes
//! never come back), nothing is followed, and no operation panics.
//! Added in Round 16.

use std::os::unix::fs::symlink;
use std::path::Path;

use libfuzzer_sys::fuzz_target;
use luksbox_sync::fs_store::FsStore;
use luksbox_sync::names::{Area, Name, ObjectId};
use luksbox_sync::store::{LenRule, ObjectStore};

const SENTINEL: &[u8] = b"SECRET-OUTSIDE-THE-BUNDLE-0123456789abcdef0123456789abcdef0123456789abcdef";

fn hexish(b: &[u8]) -> String {
    b.iter()
        .map(|&c| match c % 18 {
            0..=15 => char::from(b"0123456789abcdef"[(c % 16) as usize]),
            16 => 'A',
            _ => '.',
        })
        .collect()
}

fn mkfifo(p: &Path) {
    use std::os::unix::ffi::OsStrExt;
    if let Ok(c) = std::ffi::CString::new(p.as_os_str().as_bytes()) {
        // SAFETY: valid C string.
        unsafe {
            libc::mkfifo(c.as_ptr(), 0o600);
        }
    }
}

fuzz_target!(|data: &[u8]| {
    let Ok(dir) = tempfile::tempdir() else { return };
    let outside = dir.path().join("outside.bin");
    std::fs::write(&outside, SENTINEL).unwrap();
    let bundle = dir.path().join("v.lbxs");
    let Ok(mut store) = FsStore::create(&bundle) else { return };

    // A legitimate object to collide with.
    let real = Name::Object(ObjectId([0x5a; 32]));
    let _ = store.create_new(Area::Page, &real, &[1u8; 64]);

    let mut rest = data;
    let mut planted = 0;
    while rest.len() >= 4 && planted < 24 {
        let kind = rest[0] % 7;
        let area = Area::ALL[(rest[1] % 6) as usize];
        let len = (rest[2] as usize) % 70;
        rest = &rest[3..];
        let leaf = hexish(&rest[..len.min(rest.len())]);
        rest = &rest[len.min(rest.len())..];
        if leaf.is_empty() || leaf == "." || leaf == ".." {
            continue;
        }
        planted += 1;
        let adir = bundle.join(area.dir());
        // Objects sit in a shard folder named after their first two
        // characters; the fuzzer may place them there or not.
        let parent = if area.sharded() && leaf.len() >= 2 && kind % 2 == 0 {
            let p = adir.join(&leaf[..2]);
            let _ = std::fs::create_dir(&p);
            p
        } else {
            adir
        };
        let target = parent.join(&leaf);
        match kind {
            0 => {
                let _ = std::fs::write(&target, &SENTINEL[..SENTINEL.len().min(64)]);
            }
            1 => {
                let _ = symlink(&outside, &target);
            }
            2 => {
                let _ = symlink(dir.path(), &target);
            }
            3 => {
                let _ = std::fs::hard_link(&outside, &target);
            }
            4 => mkfifo(&target),
            5 => {
                let _ = std::fs::create_dir(&target);
            }
            _ => {
                // A shard folder replaced by a link to the outside.
                if area.sharded() && leaf.len() >= 2 {
                    let shard = bundle.join(area.dir()).join(&leaf[..2]);
                    let _ = std::fs::remove_dir(&shard);
                    let _ = symlink(dir.path(), &shard);
                }
            }
        }
    }

    for area in Area::ALL {
        let Ok(listing) = store.list(area) else { continue };
        for n in &listing.names {
            match store.read(area, n, LenRule::AtMost(1 << 16)) {
                Ok(Some(bytes)) => {
                    assert!(
                        !bytes.windows(16).any(|w| w == &SENTINEL[..16]),
                        "bytes from outside the bundle came back through {}",
                        n.display(area)
                    );
                }
                Ok(None) | Err(_) => {}
            }
        }
        // Creating and removing under hostile shards never panics and
        // never writes outside: the sentinel file keeps its bytes.
        let fresh = ObjectId::random().unwrap();
        let name = Name::Object(fresh);
        let _ = store.create_new(area, &name, b"new");
        let _ = store.remove(area, &name);
        let _ = store.sync();
    }
    assert_eq!(std::fs::read(&outside).unwrap(), SENTINEL);
});
