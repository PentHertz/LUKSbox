//! AFL++ harness for sync-bundle page-table decoding. Mirrors
//! `fuzz/fuzz_targets/sync_table_decode.rs`; shared corpus at
//! `fuzz/corpus/sync_table_decode/`.

use luksbox_sync::table::{BLOCK_PLAINTEXT_LEN, TableBlock};

fn main() {
    afl::fuzz!(|data: &[u8]| {
        let mut pt = vec![0u8; BLOCK_PLAINTEXT_LEN];
        let n = data.len().min(pt.len());
        pt[..n].copy_from_slice(&data[..n]);
        if let Ok(b) = TableBlock::decode(&pt, || "fuzz".into()) {
            assert_eq!(&b.encode()[..], &pt[..]);
        }
        let _ = TableBlock::decode(data, || "fuzz".into());
    });
}
