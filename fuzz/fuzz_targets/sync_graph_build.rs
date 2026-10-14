// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Penthertz <https://penthertz.com> (https://x.com/PentHertz)

#![no_main]

//! Commit-graph construction and checks over arbitrary histories: the
//! provider chooses which manifests a device sees, and key holders can
//! write any (device, seq, parents, seen, checkpoint) combination. Graph
//! building and `check` must terminate and never panic, whatever cycles,
//! gaps, duplicates or dangling references the input describes.

use libfuzzer_sys::fuzz_target;
use luksbox_sync::graph::Graph;
use luksbox_sync::manifest::{
    Checkpoint, CommitKind, DeviceId, FORMAT, HeaderRef, Manifest, ManifestRef, Seen, Verified,
};
use luksbox_sync::names::ObjectId;
use luksbox_sync::state::DeviceState;

fn h(x: u8) -> [u8; 32] {
    [x; 32]
}

fuzz_target!(|data: &[u8]| {
    // Each 6-byte record: id, device, seq, parent id, seen id, checkpoint.
    let mut list = Vec::new();
    for r in data.chunks_exact(6).take(64) {
        let (id, dev, seq, parent, seen, cp) =
            (r[0], r[1] % 4, u64::from(r[2] % 8), r[3], r[4], r[5] % 4);
        let device = DeviceId([dev; 16]);
        let m = Manifest {
            format: FORMAT,
            bundle: [1; 16],
            device,
            seq: seq + 1,
            lamport: u64::from(id),
            wall_clock_ns: 0,
            parents: if parent % 3 == 0 {
                vec![]
            } else {
                vec![ManifestRef {
                    device: DeviceId([parent % 4; 16]),
                    seq: u64::from(parent % 8) + 1,
                    oid: h(parent),
                    hash: h(parent),
                }]
            },
            seen: vec![Seen {
                device: DeviceId([seen % 4; 16]),
                seq: u64::from(seen % 8) + 1,
                hash: h(seen),
            }],
            checkpoint: vec![Checkpoint {
                device: DeviceId([cp; 16]),
                min_seq: u64::from(r[5] % 3),
            }],
            header: HeaderRef {
                name: None,
                hash: [0; 32],
                generation: 0,
            },
            hybrid: None,
            page_size: 1 << 20,
            logical_len: 0,
            tables: vec![],
            kind: CommitKind::Commit,
            merge_log: vec![],
            gc_plan: None,
            device_label: "d".into(),
        };
        list.push(Verified {
            oid: ObjectId(h(id)),
            hash: h(id),
            size: 16 * 1024,
            m,
        });
    }
    let Ok(g) = Graph::build(list) else { return };
    let _ = g.check(None);
    if let Ok(mut st) = DeviceState::new([1; 16], "x".into()) {
        st.device = DeviceId([data.first().copied().unwrap_or(0) % 4; 16]);
        st.own_seq = u64::from(data.get(1).copied().unwrap_or(0) % 8);
        for (i, b) in data.iter().take(4).enumerate() {
            st.seen
                .insert(DeviceId([i as u8; 16]), (u64::from(*b % 8), h(*b)));
        }
        let _ = g.check(Some(&st));
    }
});
