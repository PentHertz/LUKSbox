// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Penthertz <https://penthertz.com> (https://x.com/PentHertz)

//! Chunk-level write/read round-trip per cipher suite.
//!
//! The VFS chunk path is the highest-throughput AEAD use site in
//! LUKSbox: every file write/read goes through `aead::seal/open`
//! under a per-file derived key. Adding `Aes256GcmSiv` as a third
//! suite (audit Finding 1 patch) needs to be exercised end-to-end
//! through the chunk layer, not just at the AEAD primitive - the
//! suite identifier flows through Header -> Container -> Vfs ->
//! chunk.rs and any of those hops could in principle drop or
//! mistranslate it.

use luksbox_core::{Argon2idParams, CipherSuite};
use luksbox_format::{Container, UnlockMaterial};
use luksbox_vfs::Vfs;
use tempfile::tempdir;

fn test_params() -> Argon2idParams {
    Argon2idParams {
        m_cost_kib: 8,
        t_cost: 1,
        p_cost: 1,
    }
}

fn write_then_read_under(suite: CipherSuite) {
    let dir = tempdir().unwrap();
    let path = dir.path().join(format!("v_{suite:?}.lbx"));

    // Spans two chunks (4096 plaintext bytes per chunk slot) so we
    // exercise multi-chunk read/write under the suite, not just one.
    let payload: Vec<u8> = (0..(4096 * 2 + 17)).map(|i| (i & 0xff) as u8).collect();

    {
        let c = Container::create_with_passphrase(
            &path,
            None,
            suite,
            test_params(),
            b"chunk-suite-test",
        )
        .unwrap();
        let mut vfs = Vfs::open(c).unwrap();
        let root = vfs.root_id();
        let f = vfs.create(root, "data").unwrap();
        vfs.write(f, 0, &payload).unwrap();
        vfs.flush().unwrap();
    }

    let c = Container::open(&path, None, UnlockMaterial::Passphrase(b"chunk-suite-test")).unwrap();
    assert_eq!(c.cipher_suite(), suite);
    let mut vfs = Vfs::open(c).unwrap();
    let root = vfs.root_id();
    let f = vfs.lookup(root, "data").unwrap();
    let mut buf = vec![0u8; payload.len()];
    let n = vfs.read(f, 0, &mut buf).unwrap();
    assert_eq!(n, payload.len(), "{suite:?}: short read");
    assert_eq!(buf, payload, "{suite:?}: chunk roundtrip mismatch");
}

#[test]
fn chunk_roundtrip_aes_256_gcm() {
    write_then_read_under(CipherSuite::Aes256Gcm);
}

#[test]
fn chunk_roundtrip_chacha20_poly1305() {
    write_then_read_under(CipherSuite::ChaCha20Poly1305);
}

#[test]
fn chunk_roundtrip_aes_256_gcm_siv() {
    write_then_read_under(CipherSuite::Aes256GcmSiv);
}
