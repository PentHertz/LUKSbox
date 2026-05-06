// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Penthertz <https://penthertz.com> (https://x.com/PentHertz)

//! Integration test for the full hybrid PQ vault lifecycle:
//!
//!   1. Generate an ML-KEM-768 keypair.
//!   2. Encapsulate against the public key, gives us `(ciphertext,
//!      shared_secret)`.
//!   3. Write the secret seed to a `.kyber` file, encrypted under the
//!      user's passphrase.
//!   4. Write the `(public_key, ciphertext)` pair to a `.hybrid` sidecar
//!      next to the vault.
//!   5. Create the vault with `Container::create_with_hybrid_pq_passphrase`,
//!      using the same `shared_secret`.
//!   6. Drop everything from memory.
//!   7. Reopen: read the `.hybrid` sidecar to get `(public_key, ciphertext)`,
//!      read the `.kyber` file (with the passphrase) to get the seed,
//!      `decapsulate(seed, ciphertext)` to reproduce the same shared
//!      secret, and open the container with hybrid material.
//!   8. Confirm the metadata blob round-trips.
//!   9. Negative tests:
//!       - missing `.kyber` file -> can't open
//!       - tampered `.kyber` file (wrong passphrase) -> can't open
//!       - tampered `.hybrid` sidecar (flip a byte in ciphertext) -> can't open
//!       - opening as plain Passphrase (without hybrid material) -> fails

use std::fs;

use luksbox_core::{Argon2idParams, CipherSuite};
use luksbox_format::container::Container;
use luksbox_format::hybrid_sidecar::{self, HybridEntry};
use luksbox_format::{Error, UnlockMaterial};
use luksbox_pq::{decapsulate, encapsulate, keygen, seed_file};

fn fast_kdf() -> Argon2idParams {
    Argon2idParams {
        m_cost_kib: 8,
        t_cost: 1,
        p_cost: 1,
    }
}

fn fast_seed_kdf() -> seed_file::KdfParams {
    seed_file::KdfParams {
        m_cost_kib: 8,
        t_cost: 1,
        p_cost: 1,
    }
}

#[test]
fn create_open_round_trip() {
    let tmp = tempfile::tempdir().unwrap();
    let vault = tmp.path().join("v.lbx");
    let kyber_path = tmp.path().join("user.kyber");
    let sidecar_path = hybrid_sidecar::sidecar_path(&vault);
    let passphrase: &[u8] = b"hunter2";

    // -- step 1: keygen + encapsulate -----------------------------------
    let (pk, seed) = keygen();
    let (ct, shared_at_create) = encapsulate(&pk).unwrap();

    // -- step 2: write the seed to a .kyber file ------------------------
    seed_file::write(&kyber_path, &seed, passphrase, fast_seed_kdf()).unwrap();

    // -- step 3: write the public Kyber blobs to the .hybrid sidecar ----
    hybrid_sidecar::write(
        &sidecar_path,
        &[HybridEntry::new_ml768(0, pk.to_vec(), ct.to_vec())],
    )
    .unwrap();

    // -- step 4: create the vault with the same shared secret -----------
    {
        let mut c = Container::create_with_hybrid_pq_passphrase(
            &vault,
            None,
            CipherSuite::Aes256Gcm,
            fast_kdf(),
            0,
            passphrase,
            &shared_at_create,
        )
        .unwrap();
        c.write_metadata(b"top secret hybrid data").unwrap();
    }

    // ---- step 5-7: reopen via the documented user flow ----------------
    let recovered_seed = seed_file::read(&kyber_path, passphrase).unwrap();
    let entries = hybrid_sidecar::read(&sidecar_path).unwrap();
    let entry = hybrid_sidecar::find(&entries, 0).expect("slot 0 present");
    let shared_at_open = decapsulate(&recovered_seed, &entry.ciphertext).unwrap();
    assert_eq!(*shared_at_create, *shared_at_open);

    let mut c = Container::open(
        &vault,
        None,
        UnlockMaterial::HybridPqPassphrase {
            passphrase,
            pq_shared: &shared_at_open,
        },
    )
    .unwrap();
    let blob = c.read_metadata().unwrap();
    assert_eq!(&**blob, b"top secret hybrid data");
}

#[test]
fn missing_kyber_file_blocks_open() {
    let tmp = tempfile::tempdir().unwrap();
    let vault = tmp.path().join("v.lbx");
    let sidecar_path = hybrid_sidecar::sidecar_path(&vault);
    let passphrase: &[u8] = b"hunter2";

    let (pk, seed) = keygen();
    let (ct, shared) = encapsulate(&pk).unwrap();

    // We deliberately do NOT write a .kyber file.

    hybrid_sidecar::write(
        &sidecar_path,
        &[HybridEntry::new_ml768(0, pk.to_vec(), ct.to_vec())],
    )
    .unwrap();
    {
        Container::create_with_hybrid_pq_passphrase(
            &vault,
            None,
            CipherSuite::Aes256Gcm,
            fast_kdf(),
            0,
            passphrase,
            &shared,
        )
        .unwrap();
    }
    drop(seed); // simulate user lost the seed file

    // Open attempt without the kyber file: the attacker has no way to
    // recover `pq_shared`. Plain passphrase open fails because the slot
    // isn't of kind Passphrase.
    let r = Container::open(&vault, None, UnlockMaterial::Passphrase(passphrase));
    assert!(matches!(r, Err(Error::UnlockFailed)));
}

#[test]
fn tampered_kyber_file_blocks_open() {
    let tmp = tempfile::tempdir().unwrap();
    let vault = tmp.path().join("v.lbx");
    let kyber_path = tmp.path().join("user.kyber");
    let sidecar_path = hybrid_sidecar::sidecar_path(&vault);
    let passphrase: &[u8] = b"hunter2";

    let (pk, seed) = keygen();
    let (ct, shared) = encapsulate(&pk).unwrap();
    seed_file::write(&kyber_path, &seed, passphrase, fast_seed_kdf()).unwrap();
    hybrid_sidecar::write(
        &sidecar_path,
        &[HybridEntry::new_ml768(0, pk.to_vec(), ct.to_vec())],
    )
    .unwrap();
    {
        Container::create_with_hybrid_pq_passphrase(
            &vault,
            None,
            CipherSuite::Aes256Gcm,
            fast_kdf(),
            0,
            passphrase,
            &shared,
        )
        .unwrap();
    }

    // Wrong passphrase against the kyber file -> seed_file::read errors.
    let r = seed_file::read(&kyber_path, b"WRONGpw");
    assert!(r.is_err());

    // Flipping a byte in the kyber wrapped-seed region is also caught.
    let mut bytes = fs::read(&kyber_path).unwrap();
    let last = bytes.len() - 1;
    bytes[last] ^= 0x01;
    fs::write(&kyber_path, &bytes).unwrap();
    let r = seed_file::read(&kyber_path, passphrase);
    assert!(r.is_err());
}

#[test]
fn tampered_hybrid_sidecar_blocks_open() {
    let tmp = tempfile::tempdir().unwrap();
    let vault = tmp.path().join("v.lbx");
    let kyber_path = tmp.path().join("user.kyber");
    let sidecar_path = hybrid_sidecar::sidecar_path(&vault);
    let passphrase: &[u8] = b"hunter2";

    let (pk, seed) = keygen();
    let (ct, shared) = encapsulate(&pk).unwrap();
    seed_file::write(&kyber_path, &seed, passphrase, fast_seed_kdf()).unwrap();
    hybrid_sidecar::write(
        &sidecar_path,
        &[HybridEntry::new_ml768(0, pk.to_vec(), ct.to_vec())],
    )
    .unwrap();
    {
        Container::create_with_hybrid_pq_passphrase(
            &vault,
            None,
            CipherSuite::Aes256Gcm,
            fast_kdf(),
            0,
            passphrase,
            &shared,
        )
        .unwrap();
    }

    // Flip a byte in the sidecar's ciphertext region.
    let mut bytes = fs::read(&sidecar_path).unwrap();
    let last = bytes.len() - 1;
    bytes[last] ^= 0x42;
    fs::write(&sidecar_path, &bytes).unwrap();

    // The user's view: read sidecar, read kyber, decapsulate with the
    // tampered ciphertext -> wrong shared (FIPS 203 implicit rejection),
    // wrong combined KEK, AEAD tag fails on wrapped_mvk.
    let recovered_seed = seed_file::read(&kyber_path, passphrase).unwrap();
    let entries = hybrid_sidecar::read(&sidecar_path).unwrap();
    let entry = hybrid_sidecar::find(&entries, 0).unwrap();
    let bad_shared = decapsulate(&recovered_seed, &entry.ciphertext).unwrap();
    let r = Container::open(
        &vault,
        None,
        UnlockMaterial::HybridPqPassphrase {
            passphrase,
            pq_shared: &bad_shared,
        },
    );
    assert!(matches!(r, Err(Error::UnlockFailed)));
}
