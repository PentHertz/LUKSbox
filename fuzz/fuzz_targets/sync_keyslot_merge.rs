// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Penthertz <https://penthertz.com> (https://x.com/PentHertz)

#![no_main]

//! Keyslot tables changed concurrently on two devices are merged slot by
//! slot (`CRYPTO_SPEC.md` 22.10). The fuzzer picks what each side did to
//! each slot (kept, removed, changed, enrolled into a free one, the
//! header frame changed) and the rules that matter for security must
//! hold on every merge: a removal is never undone, no slot appears that
//! neither side had, and the merged generation is above both sides'.
//! Added in Round 16.

use std::sync::OnceLock;

use libfuzzer_sys::fuzz_target;
use luksbox_core::{Argon2idParams, CipherSuite, Header, Keyslot, SlotKind};
use luksbox_format::Container;
use luksbox_sync::bundle::merge_keyslot_tables;

const KDF: Argon2idParams = Argon2idParams {
    m_cost_kib: 8,
    t_cost: 1,
    p_cost: 1,
};

/// A real header-v3 table with slots 0..3 in use.
fn base() -> &'static Header {
    static BASE: OnceLock<Header> = OnceLock::new();
    BASE.get_or_init(|| {
        let d = tempfile::tempdir().unwrap();
        let _g = luksbox_format::metadata::set_create_metadata_region_size_override(Some(64 << 10));
        let mut c = Container::create_with_passphrase(
            &d.path().join("v.lbx"),
            None,
            CipherSuite::Aes256GcmSiv,
            KDF,
            b"one",
        )
        .unwrap();
        c.upgrade_header_to_v3().unwrap();
        c.enroll_passphrase(b"two", KDF).unwrap();
        c.enroll_passphrase(b"three", KDF).unwrap();
        c.enroll_passphrase(b"four", KDF).unwrap();
        c.set_read_only();
        c.header.clone()
    })
}

/// What identifies a slot's wrapping (the fields the merge compares).
fn ident(k: &Keyslot) -> (u8, [u8; 16], [u8; 32], [u8; 16]) {
    (k.kind as u8, k.uuid, k.wrapped_ct, k.wrapped_tag)
}

/// One side's version of the table, driven by one byte per slot.
fn side(base: &Header, ops: &[u8], frame: u8) -> Header {
    let mut h = base.clone();
    for (i, &op) in ops.iter().enumerate().take(h.keyslots.len()) {
        match op % 6 {
            0 | 1 => {}
            2 => {
                h.keyslots[i] = Keyslot::empty();
                h.sep_blobs[i] = None;
            }
            3 => {
                if h.keyslots[i].kind != SlotKind::Empty {
                    h.keyslots[i].wrapped_tag[0] ^= 1 + (op / 6);
                }
            }
            4 => {
                // Enroll: copy a used slot's wrapping into this one with
                // a fresh identity.
                let src = (op as usize / 6) % h.keyslots.len();
                if h.keyslots[i].kind == SlotKind::Empty
                    && base.keyslots[src].kind != SlotKind::Empty
                {
                    let mut k = base.keyslots[src].clone();
                    k.uuid[0] ^= 0x80 | op;
                    k.wrapped_tag[1] ^= op;
                    h.keyslots[i] = k;
                }
            }
            _ => {
                h.keyslots[i].kdf_params.t_cost = (h.keyslots[i].kdf_params.t_cost % 4) + 1;
            }
        }
    }
    match frame % 8 {
        0 => h.chunk_size = h.chunk_size.saturating_mul(2).max(h.chunk_size),
        1 => h.flags ^= luksbox_core::header::FLAG_PAD_FILES_POW2,
        _ => {}
    }
    h
}

fuzz_target!(|data: &[u8]| {
    if data.len() < 18 {
        return;
    }
    let base = base();
    let n = base.keyslots.len();
    let target = side(base, &data[..n], data[2 * n]);
    let other = side(base, &data[n..2 * n], data[2 * n + 1]);
    let Some((merged, _notes)) = merge_keyslot_tables(base, &target, &other) else {
        return;
    };
    let known: Vec<_> = target
        .keyslots
        .iter()
        .chain(other.keyslots.iter())
        .filter(|k| k.kind != SlotKind::Empty)
        .map(ident)
        .collect();
    for i in 0..n {
        let in_base = base.keyslots[i].kind != SlotKind::Empty;
        let removed = target.keyslots[i].kind == SlotKind::Empty
            || other.keyslots[i].kind == SlotKind::Empty;
        if in_base && removed {
            assert_eq!(
                merged.keyslots[i].kind,
                SlotKind::Empty,
                "slot {i}: a removal must never be undone by a merge"
            );
        }
        if merged.keyslots[i].kind != SlotKind::Empty {
            assert!(
                known.contains(&ident(&merged.keyslots[i])),
                "slot {i}: a merge must not invent a keyslot"
            );
        }
    }
    assert!(
        merged.header_generation > target.header_generation.max(other.header_generation),
        "the merged header is a newer state than both sides"
    );
});
