// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Penthertz <https://penthertz.com> (https://x.com/PentHertz)

#![no_main]

//! The evil provider, end to end: a real bundle (three commits of one
//! device, two versions of each file) is built once; every input then
//! applies a fuzzer-chosen sequence of faults to a copy of its folder
//! (delete, damage, truncate, duplicate under a new name, swap two
//! objects of an area, plant garbage) and the device opens it with its
//! real state. Whatever happened, opening never panics, and every byte
//! read from a vault that opened is content the device actually wrote
//! (invariants I1, I4, I5). Added in Round 16.

use std::path::PathBuf;
use std::sync::{Arc, Mutex, OnceLock};

use libfuzzer_sys::fuzz_target;
use luksbox_core::{Argon2idParams, CipherSuite, MasterVolumeKey};
use luksbox_format::Container;
use luksbox_sync::bundle::{self, ConvertOptions, OpenOptions, Session};
use luksbox_sync::local::{LocalStore, MemLocal};
use luksbox_sync::names::Area;
use luksbox_sync::store::{MemStore, ObjectStore, SharedMem};
use luksbox_vfs::Vfs;

const KDF: Argon2idParams = Argon2idParams {
    m_cost_kib: 8,
    t_cost: 1,
    p_cost: 1,
};
const PASS: &[u8] = b"pw";
const FILES: [&str; 2] = ["/a.txt", "/dir/b.txt"];
const V1: [&[u8]; 2] = [b"a version one", b"b version one"];
const V2: [&[u8]; 2] = [b"a version two, longer", b"b2"];

struct Fixture {
    store: MemStore,
    local: std::collections::BTreeMap<String, Vec<u8>>,
    mvk: MasterVolumeKey,
}

fn fixture() -> &'static Fixture {
    static F: OnceLock<Fixture> = OnceLock::new();
    F.get_or_init(|| {
        let d = tempfile::tempdir().unwrap();
        let _g = luksbox_format::metadata::set_create_metadata_region_size_override(Some(64 << 10));
        let lbx = d.path().join("v.lbx");
        let c = Container::create_with_passphrase(&lbx, None, CipherSuite::Aes256GcmSiv, KDF, PASS)
            .unwrap();
        let mut vfs = Vfs::open(c).unwrap();
        let root = vfs.root_id();
        let a = vfs.create(root, "a.txt").unwrap();
        vfs.write(a, 0, V1[0]).unwrap();
        let dir = vfs.mkdir(root, "dir").unwrap();
        let b = vfs.create(dir, "b.txt").unwrap();
        vfs.write(b, 0, V1[1]).unwrap();
        vfs.flush().unwrap();
        let mut c = vfs.close().unwrap();
        let mvk = c.mvk_clone();
        let shared = SharedMem::new();
        let local = MemLocal::default();
        let l2 = local.clone();
        bundle::convert(
            &mut c,
            Box::new(shared.clone()),
            move |_| Ok(Box::new(l2) as Box<dyn LocalStore>),
            &ConvertOptions {
                page_size: 1 << 20,
                device_label: "Laptop".into(),
                hybrid_sidecar: None,
            },
        )
        .unwrap();
        // Two more commits: new versions of both files.
        for round in 0..2 {
            let l2 = local.clone();
            let (mut s, c, _) = Session::open_with_key(
                Box::new(shared.clone()),
                move |_| Ok(Box::new(l2) as Box<dyn LocalStore>),
                PathBuf::from("v.lbxs"),
                &mvk,
                &OpenOptions {
                    device_label: "Laptop".into(),
                    read_only: false,
                },
            )
            .unwrap();
            let mut vfs = Vfs::open(c).unwrap();
            let id = vfs.lookup_path(FILES[round]).unwrap();
            vfs.truncate(id, 0).unwrap();
            vfs.write(id, 0, V2[round]).unwrap();
            vfs.flush().unwrap();
            s.publish().unwrap();
            drop(vfs);
            s.close().unwrap();
        }
        Fixture {
            store: shared.with(|m| m.clone()),
            local: local.0.lock().unwrap().clone(),
            mvk,
        }
    })
}

fn read(vfs: &mut Vfs, path: &str) -> Option<Vec<u8>> {
    let id = vfs.lookup_path(path).ok()?;
    let mut buf = vec![0u8; 256];
    let n = vfs.read(id, 0, &mut buf).ok()?;
    buf.truncate(n);
    Some(buf)
}

fuzz_target!(|data: &[u8]| {
    let fx = fixture();
    let mut store = fx.store.clone();
    // Faults, one per 3 bytes: op, area, which object.
    for f in data.chunks_exact(3).take(24) {
        let area = Area::ALL[(f[1] % 6) as usize];
        let names = match store.list(area) {
            Ok(l) => l.names,
            Err(_) => continue,
        };
        if names.is_empty() {
            continue;
        }
        let pick = names[(f[2] as usize) % names.len()];
        match f[0] % 7 {
            0 => {
                let _ = store.remove(area, &pick);
            }
            1 | 2 => {
                // Damage one byte, at a position driven by the input.
                let key = (
                    area,
                    if area.sharded() { pick.shard().unwrap_or_default() } else { String::new() },
                    pick.leaf(),
                );
                if let Some(v) = store.raw_mut().get_mut(&key)
                    && !v.is_empty()
                {
                    let i = (f[2] as usize * 131) % v.len();
                    v[i] ^= 1 + (f[1] / 6);
                }
            }
            3 => {
                let key = (
                    area,
                    if area.sharded() { pick.shard().unwrap_or_default() } else { String::new() },
                    pick.leaf(),
                );
                if let Some(v) = store.raw_mut().get_mut(&key) {
                    let cut = (f[2] as usize * 977) % (v.len() + 1);
                    v.truncate(cut);
                }
            }
            4 => {
                // The same bytes under a fresh (valid) name.
                if let Ok(Some(bytes)) =
                    store.read(area, &pick, luksbox_sync::store::LenRule::AtMost(32 << 20))
                {
                    let fresh = luksbox_sync::names::Name::Object(
                        luksbox_sync::names::ObjectId::random().unwrap(),
                    );
                    if !area.header_named() {
                        let _ = store.create_new(area, &fresh, &bytes);
                    }
                }
            }
            5 => {
                // Swap two objects of the area.
                let other = names[(f[2] as usize / 3) % names.len()];
                let k = |n: &luksbox_sync::names::Name| {
                    (
                        area,
                        if area.sharded() { n.shard().unwrap_or_default() } else { String::new() },
                        n.leaf(),
                    )
                };
                let (ka, kb) = (k(&pick), k(&other));
                let raw = store.raw_mut();
                if let (Some(a), Some(b)) = (raw.get(&ka).cloned(), raw.get(&kb).cloned()) {
                    raw.insert(ka, b);
                    raw.insert(kb, a);
                }
            }
            _ => {
                store.plant(area, "", "not an object (conflicted copy)", vec![f[2]; 7]);
            }
        }
    }

    let shared = SharedMem {
        inner: Arc::new(Mutex::new(store)),
        fail_next_create: Arc::new(Mutex::new(None)),
    };
    let local = MemLocal(Arc::new(Mutex::new(fx.local.clone())));
    let opened = Session::open_with_key(
        Box::new(shared),
        move |_| Ok(Box::new(local) as Box<dyn LocalStore>),
        PathBuf::from("v.lbxs"),
        &fx.mvk,
        &OpenOptions {
            device_label: "Laptop".into(),
            read_only: true,
        },
    );
    let Ok((session, container, _report)) = opened else {
        return;
    };
    let Ok(mut vfs) = Vfs::open_read_only(container) else {
        return;
    };
    for (i, path) in FILES.iter().enumerate() {
        if let Some(bytes) = read(&mut vfs, path) {
            assert!(
                bytes == V1[i] || bytes == V2[i],
                "{path}: bytes nobody wrote came back: {bytes:?}"
            );
        }
    }
    drop(vfs);
    drop(session);
});
