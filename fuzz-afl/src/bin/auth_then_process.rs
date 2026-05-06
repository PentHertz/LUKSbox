//! AFL++ harness: post-AEAD bincode decode of `DirectoryTree` with
//! a fixed MVK. Same logic as `fuzz/fuzz_targets/auth_then_process.rs`
//! (libfuzzer variant). This is the harness that found the bincode-
//! OOM bug, running it on a server with `cargo afl fuzz -t 5000ms`
//! plus AFL++'s timeout-detection catches a wider class of slow-path
//! DoS than libFuzzer's default behaviour.

use std::collections::BTreeMap;

use luksbox_core::{CipherSuite, MasterVolumeKey};
use luksbox_format::metadata::{DEFAULT_METADATA_REGION_SIZE, read_metadata, write_metadata};

const MVK_BYTES: [u8; 32] = [0x55; 32];
const HEADER_SALT: [u8; 32] = [0x77; 32];
const SUITE: CipherSuite = CipherSuite::Aes256Gcm;
const MAX_PLAINTEXT: usize = (DEFAULT_METADATA_REGION_SIZE as usize) - 36;

fn main() {
    let mvk = MasterVolumeKey::from_bytes(MVK_BYTES);
    let mut region = vec![0u8; DEFAULT_METADATA_REGION_SIZE as usize];
    // 64 MiB cap mirrors the production decoder in luksbox-vfs::vfs.
    const LIMIT: usize = 64 * 1024 * 1024;

    afl::fuzz!(|data: &[u8]| {
        if data.len() > MAX_PLAINTEXT {
            return;
        }
        if write_metadata(SUITE, &mvk, &HEADER_SALT, data, &mut region).is_err() {
            return;
        }
        let plaintext = match read_metadata(SUITE, &mvk, &HEADER_SALT, &region) {
            Ok(pt) => pt,
            Err(_) => return,
        };
        let cfg = bincode::config::standard().with_limit::<LIMIT>();
        let decoded: Result<(DirectoryTreeShape, usize), _> =
            bincode::serde::decode_from_slice(&plaintext, cfg);
        let Ok((tree, _consumed)) = decoded else {
            return;
        };
        walk_tree(&tree);
    });
}

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
    let _ = t.free_chunks.len();
    for (file_id, inode) in &t.inodes {
        let _ = *file_id;
        for chunk in &inode.chunks {
            let _ = chunk.id;
        }
        for (name, child) in &inode.children {
            let _ = name.len();
            let _ = name.chars().count();
            let _ = *child;
        }
    }
}
