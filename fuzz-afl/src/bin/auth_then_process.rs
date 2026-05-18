//! AFL++ harness: post-AEAD decode of the magic-prefixed
//! `DirectoryTree` blob with a fixed MVK. Same logic as
//! `fuzz/fuzz_targets/auth_then_process.rs` (libfuzzer variant).
//! Updated 2026-05 to mirror the libfuzzer migration off bincode to
//! postcard + the `LBM\x02` magic-prefix dispatch added to
//! `Vfs::open`. Originally this harness found a bincode-OOM bug,
//! kept as the AFL++ counterpart so timeout-detection (which AFL++
//! does at -t Nms granularity) catches the slow-path DoS class.

use std::collections::BTreeMap;

use luksbox_core::{CipherSuite, MasterVolumeKey};
use luksbox_format::metadata::{DEFAULT_METADATA_REGION_SIZE, read_metadata, write_metadata};

const MVK_BYTES: [u8; 32] = [0x55; 32];
const HEADER_SALT: [u8; 32] = [0x77; 32];
const SUITE: CipherSuite = CipherSuite::Aes256Gcm;
const MAX_PLAINTEXT: usize = (DEFAULT_METADATA_REGION_SIZE as usize) - 36;

fn main() {
    afl::fuzz!(|data: &[u8]| {
        if data.len() > MAX_PLAINTEXT {
            return;
        }
        let mvk = MasterVolumeKey::from_bytes(MVK_BYTES);
        let mut region = vec![0u8; DEFAULT_METADATA_REGION_SIZE as usize];

        if write_metadata(SUITE, &mvk, &HEADER_SALT, data, &mut region).is_err() {
            return;
        }
        let plaintext = match read_metadata(SUITE, &mvk, &HEADER_SALT, &region) {
            Ok(pt) => pt,
            Err(_) => return,
        };

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
