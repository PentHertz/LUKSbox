// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Penthertz <https://penthertz.com> (https://x.com/PentHertz)

//! Vault I/O regressions: the free list overflowing the metadata region
//! (M1) and a failed write corrupting a chunk it already rewrote in place
//! (M2).
//!
//! ```bash
//! cargo test --release --test vault_io_regressions -p luksbox-vfs
//! ```

use std::io::{Seek, SeekFrom, Write};
use std::path::Path;

use luksbox_core::{Argon2idParams, CipherSuite};
use luksbox_format::{Container, UnlockMaterial};
use luksbox_vfs::chunk::{CHUNK_PLAINTEXT_SIZE, CHUNK_SLOT_SIZE};
use luksbox_vfs::{Error, Vfs};

const PASS: &[u8] = b"pass";
const KDF: Argon2idParams = Argon2idParams {
    m_cost_kib: 8,
    t_cost: 1,
    p_cost: 1,
};
const MIB: usize = 1 << 20;

fn create(vault: &Path, region: u64, flags: u32) {
    let _g = luksbox_format::metadata::set_create_metadata_region_size_override(Some(region));
    Container::create_with_passphrase_flags(
        vault,
        None,
        CipherSuite::Aes256GcmSiv,
        KDF,
        flags,
        PASS,
    )
    .unwrap();
}

fn open(vault: &Path) -> Vfs {
    Vfs::open(Container::open(vault, None, UnlockMaterial::Passphrase(PASS)).unwrap()).unwrap()
}

/// Write `mib` MiB of `byte` to `id` from offset 0, 1 MiB at a time.
fn fill(vfs: &mut Vfs, id: u64, mib: usize, byte: u8) {
    let block = vec![byte; MIB];
    for i in 0..mib {
        vfs.write(id, (i * MIB) as u64, &block).unwrap();
    }
}

fn read_all(vfs: &mut Vfs, id: u64) -> Vec<u8> {
    let size = vfs.stat(id).unwrap().size as usize;
    let mut buf = vec![0u8; size];
    assert_eq!(vfs.read(id, 0, &mut buf).unwrap(), size);
    buf
}

fn file_len(vault: &Path) -> u64 {
    std::fs::metadata(vault).unwrap().len()
}

/// Overwrite 16 bytes inside chunk slot `slot` on disk.
fn damage_slot(vfs: &Vfs, vault: &Path, slot: u64) {
    let off = vfs.container().data_offset() + slot * CHUNK_SLOT_SIZE + 100;
    let mut f = std::fs::OpenOptions::new().write(true).open(vault).unwrap();
    f.seek(SeekFrom::Start(off)).unwrap();
    f.write_all(&[0xFF; 16]).unwrap();
}

// ---------------------------------------------------------------------
// M1: a large file keeps its chunk list outside the metadata region, so
// it costs almost nothing there until it is deleted; then every one of
// its slots went to the free list, which is stored inline. Shrinking the
// region checked only the list of the moment, and nothing bounded the
// free list: the save after the delete failed ("metadata blob is larger
// than the metadata region"), and so did every later one (in a mount,
// every change was lost at unmount).
// ---------------------------------------------------------------------

/// The reproduction: shrinking the region under what the free list can
/// grow to is refused up front, and the region it asks for works.
#[test]
fn m1_region_shrink_counts_the_free_list_large_files_can_produce() {
    let dir = tempfile::tempdir().unwrap();
    let vault = dir.path().join("v.lbx");
    create(&vault, 1 << 20, 0);
    let mut vfs = open(&vault);
    let root = vfs.root_id();
    let big = vfs.create(root, "big.bin").unwrap();
    fill(&mut vfs, big, 112, 0xA5);
    vfs.flush().unwrap();

    let st = vfs.metadata_budget_status();
    let small_budget = luksbox_format::metadata::payload_budget_for(64 * 1024);
    // 112 MiB = 28 672 slots at 3 bytes each in the free list: more than a
    // 64 KiB region, although the tree itself is a few hundred bytes.
    assert!(st.free_list_bytes > small_budget, "{st:?}");
    assert!(st.used_bytes > small_budget, "{st:?}");
    assert!(st.entries_used_pct() < 5, "{st:?}");
    assert!(!st.near_capacity(), "nothing is refused on the free list");

    let needed = match vfs.resize_metadata_region(64 * 1024) {
        Err(Error::ResizeTooSmall { needed }) => needed,
        other => panic!("expected ResizeTooSmall, got {other:?}"),
    };
    assert!(needed > 64 * 1024 && needed < 1 << 20, "{needed}");
    assert_eq!(vfs.container().header.metadata_size, 1 << 20);

    // The size it asks for holds the free list of the delete.
    vfs.resize_metadata_region(needed).unwrap();
    let note = vfs.create(root, "note.txt").unwrap();
    vfs.write(note, 0, b"hello").unwrap();
    vfs.unlink(root, "big.bin").unwrap();
    vfs.flush().unwrap();
    vfs.finish().unwrap();
    drop(vfs);

    let mut vfs = open(&vault);
    assert!(vfs.lookup_path("/big.bin").is_err());
    let note = vfs.lookup_path("/note.txt").unwrap();
    assert_eq!(read_all(&mut vfs, note), b"hello");
    // Growing the region is never refused, whatever the free list needs.
    vfs.resize_metadata_region(2 << 20).unwrap();
}

/// A region already too small for the free list (made before this fix,
/// or created small): deleting a large file in the middle of the data
/// area saves anyway, keeping only the part of the free list that fits;
/// the next open finds the rest again and new data reuses it.
#[test]
fn m1_delete_in_a_small_region_never_makes_saves_fail() {
    let dir = tempfile::tempdir().unwrap();
    let vault = dir.path().join("v.lbx");
    create(&vault, 64 * 1024, 0);
    let mut vfs = open(&vault);
    let root = vfs.root_id();
    let big = vfs.create(root, "big.bin").unwrap();
    fill(&mut vfs, big, 112, 0xA5);
    vfs.flush().unwrap();
    // A file after it, so the deleted slots are not at the end.
    let note = vfs.create(root, "note.txt").unwrap();
    vfs.write(note, 0, b"hello").unwrap();
    vfs.flush().unwrap();
    let len_before = file_len(&vault);

    vfs.unlink(root, "big.bin").unwrap();
    vfs.flush()
        .expect("the save after a large delete must succeed");
    // New entries are not refused either (the free list never blocks).
    let after = vfs.create(root, "after.txt").unwrap();
    vfs.write(after, 0, b"still saving").unwrap();
    vfs.flush().unwrap();
    // The freed slots are reused in this session already.
    let again = vfs.create(root, "again.bin").unwrap();
    fill(&mut vfs, again, 16, 0x11);
    vfs.flush().unwrap();
    assert_eq!(file_len(&vault), len_before, "reused, not grown");
    vfs.finish().unwrap();
    drop(vfs);

    let mut vfs = open(&vault);
    assert!(vfs.lookup_path("/big.bin").is_err());
    let note = vfs.lookup_path("/note.txt").unwrap();
    assert_eq!(read_all(&mut vfs, note), b"hello");
    let after = vfs.lookup_path("/after.txt").unwrap();
    assert_eq!(read_all(&mut vfs, after), b"still saving");
    // The slots the saved list left out are free again after the open.
    let report = vfs.space_report().unwrap();
    assert!(
        report.free_inside >= 90 * MIB as u64,
        "free slots found again at open: {report:?}"
    );
    let again = vfs.lookup_path("/again.bin").unwrap();
    assert!(read_all(&mut vfs, again).iter().all(|&b| b == 0x11));
    let more = vfs.create(root, "more.bin").unwrap();
    fill(&mut vfs, more, 80, 0x22);
    vfs.flush().unwrap();
    assert_eq!(file_len(&vault), len_before, "found-again slots reused");
    drop(vfs);
    let mut vfs = open(&vault);
    let more = vfs.lookup_path("/more.bin").unwrap();
    assert!(read_all(&mut vfs, more).iter().all(|&b| b == 0x22));
}

/// Deleting the last file of the data area: its slots leave the free list
/// by lowering `next_chunk_id` (the file keeps its length until `shrink`),
/// and new writes go there again.
#[test]
fn m1_delete_at_the_end_drops_the_free_tail_from_the_list() {
    let dir = tempfile::tempdir().unwrap();
    let vault = dir.path().join("v.lbx");
    create(&vault, 64 * 1024, 0);
    let mut vfs = open(&vault);
    let root = vfs.root_id();
    let note = vfs.create(root, "note.txt").unwrap();
    vfs.write(note, 0, b"hello").unwrap();
    vfs.flush().unwrap();
    let big = vfs.create(root, "big.bin").unwrap();
    fill(&mut vfs, big, 112, 0xA5);
    vfs.flush().unwrap();
    let len_before = file_len(&vault);

    vfs.unlink(root, "big.bin").unwrap();
    vfs.flush().unwrap();
    let counters = vfs.tree_counters();
    assert_eq!(counters.next_chunk_id, 1, "only note.txt's slot is left");
    assert_eq!(counters.free_chunk_count, 0);
    let report = vfs.space_report().unwrap();
    assert_eq!(report.file_size, len_before);
    assert!(report.free_inside >= 112 * MIB as u64, "{report:?}");
    assert!(report.reclaimable >= 112 * MIB as u64, "{report:?}");
    drop(vfs);

    let mut vfs = open(&vault);
    let note = vfs.lookup_path("/note.txt").unwrap();
    assert_eq!(read_all(&mut vfs, note), b"hello");
    let again = vfs.create(root, "again.bin").unwrap();
    fill(&mut vfs, again, 100, 0x33);
    vfs.flush().unwrap();
    assert_eq!(file_len(&vault), len_before, "the tail is reused");
    assert!(vfs.shrink().unwrap() > 0);
    drop(vfs);
    let mut vfs = open(&vault);
    let again = vfs.lookup_path("/again.bin").unwrap();
    assert!(read_all(&mut vfs, again).iter().all(|&b| b == 0x33));
}

/// Copy-on-write retires the old slot of every chunk an overwrite
/// rewrites: overwriting a large file in a small region filled the free
/// list without any delete.
#[test]
fn m1_overwriting_a_large_file_in_a_small_region_saves() {
    let dir = tempfile::tempdir().unwrap();
    let vault = dir.path().join("v.lbx");
    create(&vault, 64 * 1024, 0);
    let mut vfs = open(&vault);
    let root = vfs.root_id();
    let big = vfs.create(root, "big.bin").unwrap();
    fill(&mut vfs, big, 100, 1);
    vfs.flush().unwrap();
    fill(&mut vfs, big, 100, 2);
    vfs.flush().unwrap();
    fill(&mut vfs, big, 100, 3);
    vfs.flush().unwrap();
    drop(vfs);
    let mut vfs = open(&vault);
    let big = vfs.lookup_path("/big.bin").unwrap();
    assert!(read_all(&mut vfs, big).iter().all(|&b| b == 3));
}

/// A file whose chunk list lives outside the region, cut down to the
/// inline threshold, moves its whole list into the region: refused up
/// front when it does not fit, instead of every later save failing.
#[test]
fn m1_truncate_that_moves_a_chunk_list_into_a_full_region_is_refused() {
    let dir = tempfile::tempdir().unwrap();
    let vault = dir.path().join("v.lbx");
    create(&vault, 64 * 1024, 0);
    let mut vfs = open(&vault);
    let root = vfs.root_id();
    // 400 chunks: over the 256-chunk inline threshold.
    let big = vfs.create(root, "big.bin").unwrap();
    vfs.write(big, 0, &vec![7u8; 400 * CHUNK_PLAINTEXT_SIZE])
        .unwrap();
    let pads: Vec<u64> = (0..12)
        .map(|i| vfs.create(root, &format!("pad{i}")).unwrap())
        .collect();
    vfs.flush().unwrap();
    // Fill the region with names, then with inline chunk lists, up to
    // what writes are refused at.
    let long = "n".repeat(200);
    for i in 0.. {
        match vfs.mkdir(root, &format!("{long}{i}")) {
            Ok(_) => {}
            Err(Error::MetadataBudgetExhausted) => break,
            Err(e) => panic!("{e:?}"),
        }
    }
    let chunk = vec![9u8; CHUNK_PLAINTEXT_SIZE];
    'fill: for &pad in &pads {
        for c in 0..256u64 {
            match vfs.write(pad, c * CHUNK_PLAINTEXT_SIZE as u64, &chunk) {
                Ok(_) => {}
                Err(Error::MetadataBudgetExhausted) => break 'fill,
                Err(e) => panic!("{e:?}"),
            }
        }
    }
    vfs.flush().unwrap();

    let r = vfs.truncate(big, 256 * CHUNK_PLAINTEXT_SIZE as u64);
    assert!(matches!(r, Err(Error::MetadataBudgetExhausted)), "{r:?}");
    assert_eq!(
        vfs.stat(big).unwrap().size,
        400 * CHUNK_PLAINTEXT_SIZE as u64
    );
    vfs.flush().unwrap();
    // Cutting it further (or deleting it) is fine.
    vfs.truncate(big, 0).unwrap();
    vfs.flush().unwrap();
    drop(vfs);
    let mut vfs = open(&vault);
    let big = vfs.lookup_path("/big.bin").unwrap();
    assert_eq!(vfs.stat(big).unwrap().size, 0);
}

// ---------------------------------------------------------------------
// M2: a chunk written since the last save is rewritten in place
// (`rewrite_target`). The new refs of a write were recorded in the inode
// only once every chunk had been written, so a failure later in the same
// call left the inode with the OLD generation of a slot that now held
// ciphertext under the new one: that chunk failed its AEAD check for
// good. A save in the middle of the call persisted the same stale ref.
// ---------------------------------------------------------------------

/// The reproduction: a write over chunks 0 and 1 fails on chunk 1.
#[test]
fn m2_failed_write_keeps_the_chunk_it_rewrote_in_place() {
    let dir = tempfile::tempdir().unwrap();
    let vault = dir.path().join("v.lbx");
    create(&vault, 1 << 20, 0);
    let mut vfs = open(&vault);
    let root = vfs.root_id();
    let id = vfs.create(root, "f").unwrap();
    vfs.write(id, 0, &vec![1u8; 8192]).unwrap(); // chunks 0,1 -> slots 0,1
    vfs.flush().unwrap();
    vfs.write(id, 0, &vec![2u8; 4096]).unwrap(); // chunk 0 COW -> slot 2, unsaved
    damage_slot(&vfs, &vault, 1);

    let r = vfs.write(id, 0, &vec![3u8; 8192]);
    assert!(r.is_err(), "chunk 1 does not decrypt: {r:?}");
    // Chunk 0 was rewritten in place before the failure: it reads, with
    // its new contents, and the size did not change.
    assert_eq!(vfs.stat(id).unwrap().size, 8192);
    let mut b = vec![0u8; 4096];
    vfs.read(id, 0, &mut b).unwrap();
    assert!(b.iter().all(|&x| x == 3));
    vfs.flush().unwrap();
    drop(vfs);
    let mut vfs = open(&vault);
    let id = vfs.lookup_path("/f").unwrap();
    vfs.read(id, 0, &mut b).unwrap();
    assert!(b.iter().all(|&x| x == 3));
}

/// Same for `truncate`: the zeroing of the old tail of the last chunk
/// (R15-E2) rewrites it in place, then growing the file fails at the
/// vault's maximum size.
#[test]
fn m2_failed_truncate_keeps_the_chunk_it_zeroed_in_place() {
    let dir = tempfile::tempdir().unwrap();
    let vault = dir.path().join("v.lbx");
    create(&vault, 1 << 20, 0);
    let mut vfs = open(&vault);
    let root = vfs.root_id();
    let id = vfs.create(root, "f").unwrap();
    vfs.write(id, 0, &vec![1u8; 4096]).unwrap();
    vfs.flush().unwrap();
    // No room to grow: every new slot is refused.
    let size = vfs.space_report().unwrap().file_size;
    vfs.set_max_vault_size(size).unwrap();
    vfs.flush().unwrap();
    // No free slot: this rewrite happens in place, so chunk 0 now has a
    // generation the last save does not know.
    vfs.write(id, 0, &vec![2u8; 4096]).unwrap();
    vfs.truncate(id, 100).unwrap();

    let r = vfs.truncate(id, 8192);
    assert!(matches!(r, Err(Error::VaultSizeLimit { .. })), "{r:?}");
    assert_eq!(vfs.stat(id).unwrap().size, 100);
    let mut b = vec![0u8; 100];
    vfs.read(id, 0, &mut b).unwrap();
    assert!(b.iter().all(|&x| x == 2));
    vfs.flush().unwrap();
    drop(vfs);
    let mut vfs = open(&vault);
    let id = vfs.lookup_path("/f").unwrap();
    assert_eq!(vfs.stat(id).unwrap().size, 100);
    vfs.read(id, 0, &mut b).unwrap();
    assert!(b.iter().all(|&x| x == 2));
}

/// A save in the middle of a write (at the maximum size, `alloc_slot`
/// saves to recycle retired slots) persisted the inode with the old
/// generation of a chunk the same write had already rewritten in place.
/// A crash right after left that chunk unreadable.
#[test]
fn m2_save_in_the_middle_of_a_write_records_the_chunks_it_rewrote() {
    let dir = tempfile::tempdir().unwrap();
    let vault = dir.path().join("v.lbx");
    create(&vault, 4 << 20, 0);
    {
        let mut vfs = open(&vault);
        let root = vfs.root_id();
        let f = vfs.create(root, "f").unwrap();
        vfs.write(f, 0, &vec![1u8; 8192]).unwrap();
        let g = vfs.create(root, "g").unwrap();
        vfs.write(g, 0, &vec![5u8; 1100 * CHUNK_PLAINTEXT_SIZE])
            .unwrap();
        vfs.flush().unwrap();
        let size = vfs.space_report().unwrap().file_size;
        vfs.set_max_vault_size(size).unwrap();
        vfs.flush().unwrap();
        // In place (no free slot): chunk 0 is newer than the last save.
        vfs.write(f, 0, &vec![2u8; 4096]).unwrap();
        // Over 1024 slots retired: the next copy-on-write that finds no
        // free slot saves to recycle them.
        vfs.unlink(root, "g").unwrap();
        // Chunk 0 in place, then chunk 1 copy-on-write, which saves.
        vfs.write(f, 0, &vec![3u8; 8192]).unwrap();
        // Crash: the save in the middle of the write is the last one.
        drop(vfs);
    }
    let mut vfs = open(&vault);
    let f = vfs.lookup_path("/f").unwrap();
    let data = read_all(&mut vfs, f);
    assert!(data[..4096].iter().all(|&x| x == 3), "chunk 0 is readable");
    assert!(data[4096..].iter().all(|&x| x == 1), "chunk 1 as saved");
    assert!(vfs.lookup_path("/g").is_err());
}

/// Hide-size vaults keep the real size in chunk 0. A write that grows the
/// file rewrote chunk 0 with the NEW size first; failing on a later chunk
/// then left a size larger than the chunks the inode kept (the vault
/// refused to read the file after reopening).
#[test]
fn m2_failed_growing_write_keeps_the_hidden_size_consistent() {
    let dir = tempfile::tempdir().unwrap();
    let vault = dir.path().join("v.lbx");
    create(&vault, 1 << 20, luksbox_core::FLAG_HIDE_SIZE_HEADER);
    let mut vfs = open(&vault);
    let root = vfs.root_id();
    let id = vfs.create(root, "f").unwrap();
    // 6000 bytes: chunk 0 (4088 bytes after the size header) and chunk 1.
    vfs.write(id, 0, &vec![1u8; 6000]).unwrap();
    vfs.flush().unwrap();
    let chunk1_slot = vfs.file_chunks(id).unwrap()[1].id;
    damage_slot(&vfs, &vault, chunk1_slot);

    // Covers chunks 0 and 1 and appends chunk 2: fails reading chunk 1.
    let r = vfs.write(id, 0, &vec![2u8; 9000]);
    assert!(r.is_err(), "{r:?}");
    assert_eq!(vfs.stat(id).unwrap().size, 6000);
    let mut b = vec![0u8; 4000];
    vfs.read(id, 0, &mut b).unwrap();
    assert!(b.iter().all(|&x| x == 2));
    vfs.flush().unwrap();
    drop(vfs);

    let mut vfs = open(&vault);
    let id = vfs.lookup_path("/f").unwrap();
    assert_eq!(vfs.stat(id).unwrap().size, 6000);
    vfs.read(id, 0, &mut b).unwrap();
    assert!(b.iter().all(|&x| x == 2));
}
