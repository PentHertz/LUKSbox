// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Penthertz <https://penthertz.com> (https://x.com/PentHertz)

#![no_main]

//! Fuzz the **post-authentication** processing pipeline with a
//! fixed MVK.
//!
//! Threat model: an attacker who has somehow obtained the MVK (or
//! is a malicious co-tenant of a vault who can craft a valid
//! metadata blob) feeds attacker-controlled bytes through the
//! decrypt → magic-prefix-check → postcard-decode → walk-tree path.
//! We want every step to either reject cleanly or produce a
//! structurally valid DirectoryTree that can be interrogated
//! without panic.
//!
//! Pipeline exercised per fuzz iteration:
//!
//!   1. Take fuzz bytes as the *plaintext* metadata blob (whatever
//!      the post-AEAD decoder will see).
//!   2. AEAD-encrypt under the fixed MVK + salt via
//!      `metadata::write_metadata` into a 1 MiB region.
//!   3. AEAD-decrypt via `metadata::read_metadata` (always succeeds,
//!      fixed MVK matches).
//!   4. Magic-prefix dispatch: blob must start with `LBM\x02`.
//!      Reject otherwise (this exercises the production check).
//!   5. `postcard::from_bytes::<DirectoryTreeShape>` on the payload.
//!      THIS is the attacker-controlled deserialization step.
//!   6. If decode succeeds, walk the tree (every inode, chunk,
//!      child-name). Any panic here is a bug.
//!
//! Switched from bincode to postcard in round 7E (post-bincode
//! migration). The magic-prefix dispatch in production lives in
//! `Vfs::open`; this harness mirrors it to fuzz the whole shape.

use std::collections::BTreeMap;

use libfuzzer_sys::fuzz_target;
use luksbox_core::{CipherSuite, MasterVolumeKey};
use luksbox_format::metadata::{DEFAULT_METADATA_REGION_SIZE, read_metadata, write_metadata};

const MVK_BYTES: [u8; 32] = [0x55; 32];
const HEADER_SALT: [u8; 32] = [0x77; 32];
const SUITE: CipherSuite = CipherSuite::Aes256Gcm;
const MAX_PLAINTEXT: usize = (DEFAULT_METADATA_REGION_SIZE as usize) - 36; // - METADATA_OVERHEAD

fuzz_target!(|data: &[u8]| {
    // Reject inputs too large for the fixed-size region, that's a
    // user-config concern, not a security one. We're fuzzing the
    // decode pipeline, not the size limit.
    if data.len() > MAX_PLAINTEXT {
        return;
    }

    let mvk = MasterVolumeKey::from_bytes(MVK_BYTES);
    let mut region = vec![0u8; DEFAULT_METADATA_REGION_SIZE as usize];

    // Step 1+2: encrypt the fuzz bytes as if they were the legitimate
    // plaintext output of bincode-encoding a DirectoryTree.
    if write_metadata(SUITE, &mvk, &HEADER_SALT, data, &mut region).is_err() {
        return;
    }

    // Step 3: AEAD-decrypt, must succeed under the matching MVK.
    let plaintext = match read_metadata(SUITE, &mvk, &HEADER_SALT, &region) {
        Ok(pt) => pt,
        Err(_) => return,
    };

    // Step 4: magic-prefix check, then step 5: postcard-decode.
    // Mirrors the production dispatch in `luksbox_vfs::Vfs::open`.
    const MAGIC: &[u8; 4] = b"LBM\x02";
    const LIMIT: usize = 64 * 1024 * 1024;
    if plaintext.len() < MAGIC.len() || &plaintext[..MAGIC.len()] != MAGIC {
        return;
    }
    let payload = &plaintext[MAGIC.len()..];
    if payload.len() > LIMIT {
        return;
    }
    let Ok(tree) = postcard::from_bytes::<DirectoryTreeShape>(payload) else {
        return;
    };

    // Step 5: walk the resulting tree without panic. Anything that
    // panics here is a real bug, we have an authenticated structure
    // and yet can't safely interrogate it.
    walk_tree(&tree);
});

/// Mirrors `luksbox_vfs::DirectoryTree`'s on-the-wire shape so we
/// can decode it without depending on the vfs crate (which has
/// extra non-fuzz-friendly deps).
#[derive(serde::Deserialize)]
struct DirectoryTreeShape {
    #[allow(dead_code)]
    pub root: u64,
    #[allow(dead_code)]
    pub next_file_id: u64,
    #[allow(dead_code)]
    pub next_chunk_id: u64,
    #[allow(dead_code)]
    pub next_chunk_gen: u64,
    pub free_chunks: Vec<u64>,
    pub inodes: BTreeMap<u64, InodeShape>,
}

#[derive(serde::Deserialize)]
struct InodeShape {
    #[allow(dead_code)]
    pub id: u64,
    #[allow(dead_code)]
    pub parent: u64,
    #[allow(dead_code)]
    pub kind: InodeKindShape,
    #[allow(dead_code)]
    pub size: u64,
    #[allow(dead_code)]
    pub mtime_ns: u64,
    pub chunks: Vec<ChunkRefShape>,
    pub children: BTreeMap<String, u64>,
}

#[derive(serde::Deserialize)]
enum InodeKindShape {
    File,
    Directory,
}

#[derive(serde::Deserialize)]
struct ChunkRefShape {
    #[allow(dead_code)]
    pub id: u64,
    #[allow(dead_code)]
    pub generation: u64,
}

fn walk_tree(t: &DirectoryTreeShape) {
    // Dereference everything serde populated. Catches:
    //  - Out-of-bounds memory access in any Vec/BTreeMap iteration
    //  - Panics on UTF-8 decoding of children-key strings (serde
    //    rejects non-UTF8 at decode time, so any panic here would
    //    be a serde bug we want to surface)
    //  - Stack overflow from absurdly deep nesting (unlikely with
    //    BTreeMap, but cheap to check)
    let _ = t.free_chunks.len();
    for (file_id, inode) in &t.inodes {
        let _ = *file_id;
        for chunk in &inode.chunks {
            let _ = chunk.id;
        }
        for (name, child) in &inode.children {
            // Force string traversal so any lazy-UTF8 panic surfaces.
            let _ = name.len();
            let _ = name.chars().count();
            let _ = *child;
        }
    }
}