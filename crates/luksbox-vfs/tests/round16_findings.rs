// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Penthertz <https://penthertz.com> (https://x.com/PentHertz)

//! Round 16 regressions at the VFS layer. See
//! `docs/SECURITY_AUDIT_ROUND_16.md`.
//!
//! ```bash
//! cargo test --test round16_findings -p luksbox-vfs
//! ```

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

fn open(vault: &std::path::Path) -> Vfs {
    Vfs::open(Container::open(vault, None, UnlockMaterial::Passphrase(PASS)).unwrap()).unwrap()
}

// ---------------------------------------------------------------------
// R16-02: a write that failed on the vault size limit (or ENOSPC) after
// allocating a slot at the end of the file handed that slot back to
// `pending_free` without marking the tree dirty. `shrink` then lowered
// `next_chunk_id` below it and the next flush serialised the stale id
// into the free list: the vault refused to open afterwards.
// ---------------------------------------------------------------------

#[test]
fn r16_02_shrink_after_a_failed_write_keeps_the_vault_openable() {
    let dir = tempfile::tempdir().unwrap();
    let vault = dir.path().join("v.lbx");
    let _g = luksbox_format::metadata::set_create_metadata_region_size_override(Some(2 << 20));
    Container::create_with_passphrase(&vault, None, CipherSuite::Aes256GcmSiv, KDF, PASS).unwrap();

    let chunk = vec![1u8; CHUNK_PLAINTEXT_SIZE];
    {
        let mut vfs = open(&vault);
        let root = vfs.root_id();
        let a = vfs.create(root, "a.bin").unwrap();
        vfs.write(a, 0, &chunk).unwrap();
        // The file the failing write will extend: made and saved first,
        // so nothing else leaves the tree dirty.
        vfs.create(root, "b.bin").unwrap();
        vfs.flush().unwrap();
        // Room for exactly one more slot.
        let size = vfs.space_report().unwrap().file_size;
        vfs.set_max_vault_size(size + CHUNK_SLOT_SIZE).unwrap();
        vfs.flush().unwrap();

        let b = vfs.lookup_path("/b.bin").unwrap();
        let three = vec![2u8; 3 * CHUNK_PLAINTEXT_SIZE];
        assert!(
            matches!(vfs.write(b, 0, &three), Err(Error::VaultSizeLimit { .. })),
            "the second new slot is past the limit"
        );
        // The slot the failed write allocated lies past the shrink cut.
        vfs.shrink().unwrap();
        drop(vfs.close().unwrap());
    }

    // Before R16-02: `MetadataDeserialize` (a free slot at or past
    // `next_chunk_id`).
    let mut vfs = open(&vault);
    let a = vfs.lookup_path("/a.bin").unwrap();
    let mut buf = vec![0u8; CHUNK_PLAINTEXT_SIZE];
    assert_eq!(vfs.read(a, 0, &mut buf).unwrap(), CHUNK_PLAINTEXT_SIZE);
    assert_eq!(buf, chunk);
    // And the vault keeps working: the limit still holds, writing within
    // it works.
    let b = vfs.lookup_path("/b.bin").unwrap();
    vfs.write(b, 0, &chunk).unwrap();
    vfs.flush().unwrap();
}

// ---------------------------------------------------------------------
// R16-01 (format layer, needs a header-v3 vault): a header recovered
// from the `.header-bak` mirror was persisted on `Drop` as a NEW header
// state (generation + 1), even when the anchor had just refused it as a
// rollback. Corrupting the live header and planting a pre-revocation
// mirror therefore laundered an old keyslot table past the anchor on the
// second open.
// ---------------------------------------------------------------------

mod r16_01 {
    use std::io::{Read as _, Seek as _, SeekFrom, Write as _};
    use std::path::{Path, PathBuf};

    use luksbox_core::{Argon2idParams, CipherSuite, HEADER_SIZE};
    use luksbox_format::{Container, Error, UnlockMaterial};
    use luksbox_vfs::Vfs;

    const KDF: Argon2idParams = Argon2idParams {
        m_cost_kib: 8,
        t_cost: 1,
        p_cost: 1,
    };
    const ONE: &[u8] = b"first passphrase";
    const TWO: &[u8] = b"second passphrase";

    fn read_header(vault: &Path) -> [u8; HEADER_SIZE] {
        let mut f = std::fs::File::open(vault).unwrap();
        let mut h = [0u8; HEADER_SIZE];
        f.read_exact(&mut h).unwrap();
        h
    }

    fn overwrite_header(vault: &Path, bytes: &[u8; HEADER_SIZE]) {
        let mut f = std::fs::OpenOptions::new().write(true).open(vault).unwrap();
        f.seek(SeekFrom::Start(0)).unwrap();
        f.write_all(bytes).unwrap();
        f.sync_all().unwrap();
    }

    /// A header-v3 vault with its header mirror and an anchor.
    fn create(dir: &Path) -> (PathBuf, PathBuf, PathBuf) {
        let vault = dir.join("v.lbx");
        let mirror = dir.join("v.lbx.header-bak");
        let anchor = dir.join("v.anchor");
        let _g =
            luksbox_format::metadata::set_create_metadata_region_size_override(Some(64 * 1024));
        let c =
            Container::create_with_passphrase(&vault, None, CipherSuite::Aes256GcmSiv, KDF, ONE)
                .unwrap();
        let mut vfs = Vfs::open(c).unwrap();
        assert!(vfs.upgrade_header_to_v3().unwrap());
        vfs.flush().unwrap();
        drop(vfs.close().unwrap());
        let mut c = Container::open(&vault, None, UnlockMaterial::Passphrase(ONE)).unwrap();
        assert!(c.header_generation().is_some(), "header v3");
        c.init_anchor(anchor.clone(), 1).unwrap();
        drop(c);
        assert!(mirror.is_file(), "a v3 vault keeps a header mirror");
        (vault, mirror, anchor)
    }

    #[test]
    fn recovered_header_is_not_a_new_state_so_the_anchor_keeps_refusing_it() {
        let dir = tempfile::tempdir().unwrap();
        let (vault, mirror, anchor) = create(dir.path());
        let old_mirror = std::fs::read(&mirror).unwrap();
        let old_header = read_header(&vault);
        assert_eq!(old_mirror, old_header, "the mirror holds the header bytes");

        // A second keyslot: header generation and anchor move forward.
        {
            let mut c = Container::open(&vault, None, UnlockMaterial::Passphrase(ONE)).unwrap();
            c.set_anchor(Some(anchor.clone())).unwrap();
            c.enroll_passphrase(TWO, KDF).unwrap();
            c.persist_header().unwrap();
        }
        assert_ne!(read_header(&vault), old_header);
        Container::open(&vault, None, UnlockMaterial::Passphrase(TWO))
            .expect("the second passphrase opens the vault");

        // The attack: garbage over the live header, the old mirror back.
        overwrite_header(&vault, &[0u8; HEADER_SIZE]);
        std::fs::write(&mirror, &old_mirror).unwrap();

        // First open: recovery from the mirror, then the anchor refuses.
        {
            let mut c = Container::open(&vault, None, UnlockMaterial::Passphrase(ONE))
                .expect("recovered from the mirror");
            assert!(
                matches!(
                    c.set_anchor(Some(anchor.clone())),
                    Err(Error::HeaderRollbackDetected { .. })
                ),
                "the anchor must refuse the rolled-back keyslot table"
            );
            // Dropped here: before R16-01 this wrote the old table at a
            // new generation that the anchor then accepted.
        }

        // The live header is the mirror's bytes (repaired, same
        // generation), not a fresh state...
        assert_eq!(
            read_header(&vault).to_vec(),
            old_mirror,
            "the recovered header is re-established byte for byte"
        );
        // ... so the second open is refused too.
        {
            let mut c = Container::open(&vault, None, UnlockMaterial::Passphrase(ONE)).unwrap();
            assert!(
                matches!(
                    c.set_anchor(Some(anchor.clone())),
                    Err(Error::HeaderRollbackDetected { .. })
                ),
                "a rolled-back keyslot table must stay detected on every open"
            );
        }
    }

    /// A recovered header that the user then changes is a new state: the
    /// ordinary path still bumps the generation and writes the mirror.
    #[test]
    fn a_change_after_recovery_is_still_persisted_as_a_new_state() {
        let dir = tempfile::tempdir().unwrap();
        let (vault, mirror, _anchor) = create(dir.path());
        let old_mirror = std::fs::read(&mirror).unwrap();
        overwrite_header(&vault, &[0u8; HEADER_SIZE]);
        let gen_before;
        {
            let mut c = Container::open(&vault, None, UnlockMaterial::Passphrase(ONE)).unwrap();
            gen_before = c.header_generation().unwrap();
            c.enroll_passphrase(TWO, KDF).unwrap();
        }
        let live = read_header(&vault);
        assert_ne!(live.to_vec(), old_mirror);
        assert_eq!(std::fs::read(&mirror).unwrap(), live.to_vec());
        let c = Container::open(&vault, None, UnlockMaterial::Passphrase(TWO)).unwrap();
        assert_eq!(c.header_generation().unwrap(), gen_before + 1);
    }
}

// ---------------------------------------------------------------------
// Filling the metadata region with many small files: the creates must
// be refused with `MetadataBudgetExhausted` while the tree still fits,
// so the save that follows succeeds and keeps every file made before.
// (Seen with `luksbox put` of 5 000 small files into a nearly full 1 MiB
// region: nothing was refused, and the save at the end failed with
// "metadata blob is larger than the metadata region", losing the whole
// import.)
// ---------------------------------------------------------------------

#[test]
fn many_small_files_stop_before_the_metadata_region_overflows() {
    let dir = tempfile::tempdir().unwrap();
    let vault = dir.path().join("v.lbx");
    let _g = luksbox_format::metadata::set_create_metadata_region_size_override(Some(256 << 10));
    Container::create_with_passphrase(&vault, None, CipherSuite::Aes256GcmSiv, KDF, PASS).unwrap();
    let mut vfs = open(&vault);
    let root = vfs.root_id();
    let mut made = 0usize;
    let stop = loop {
        let name = format!("file-number-{made:06}.txt");
        let r = vfs
            .create(root, &name)
            .and_then(|id| vfs.write(id, 0, b"x").map(|_| ()));
        match r {
            Ok(()) => made += 1,
            Err(e) => break e,
        }
        assert!(made < 100_000, "never refused");
    };
    assert!(
        matches!(stop, Error::MetadataBudgetExhausted),
        "stopped with {stop:?} after {made} files"
    );
    vfs.flush()
        .unwrap_or_else(|e| panic!("save after {made} files failed: {e}"));
    drop(vfs.close().unwrap());
    let vfs = open(&vault);
    let n = vfs.readdir(vfs.root_id()).unwrap().len();
    // The refused file may exist empty (created, then its write refused).
    assert!(n == made || n == made + 1, "{n} entries for {made} files");
}

/// Same with empty files and folders, which no write ever checked.
#[test]
fn empty_files_and_folders_stop_before_the_metadata_region_overflows() {
    let dir = tempfile::tempdir().unwrap();
    let vault = dir.path().join("v.lbx");
    let _g = luksbox_format::metadata::set_create_metadata_region_size_override(Some(256 << 10));
    Container::create_with_passphrase(&vault, None, CipherSuite::Aes256GcmSiv, KDF, PASS).unwrap();
    let mut vfs = open(&vault);
    let root = vfs.root_id();
    let mut made = 0usize;
    let stop = loop {
        let name = format!("entry-number-{made:06}");
        let r = if made.is_multiple_of(2) {
            vfs.create(root, &name).map(|_| ())
        } else {
            vfs.mkdir(root, &name).map(|_| ())
        };
        match r {
            Ok(()) => made += 1,
            Err(e) => break e,
        }
        assert!(made < 100_000, "never refused");
    };
    assert!(
        matches!(stop, Error::MetadataBudgetExhausted),
        "stopped with {stop:?} after {made} entries"
    );
    vfs.flush()
        .unwrap_or_else(|e| panic!("save after {made} entries failed: {e}"));
    // Deletes still work on the full vault and make room again.
    for i in (0..400).step_by(2) {
        vfs.unlink(root, &format!("entry-number-{i:06}")).unwrap();
    }
    vfs.create(root, "after-delete").unwrap();
    vfs.flush().unwrap();
    drop(vfs.close().unwrap());
    let vfs = open(&vault);
    assert_eq!(vfs.readdir(vfs.root_id()).unwrap().len(), made - 200 + 1);
}
