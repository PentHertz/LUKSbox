// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Penthertz <https://penthertz.com> (https://x.com/PentHertz)

//! Sync bundles with the keyslot kinds that need hardware: TPM 2.0 (plain,
//! PIN, fused with FIDO2, post-quantum hybrid, both), the Secure Enclave
//! (plain, Touch ID, with FIDO2, with a passphrase, post-quantum hybrid,
//! both) and FIDO2 (wrap, with a passphrase, post-quantum hybrid), with
//! the mock TPM, Secure Enclave and authenticator standing in for the
//! chips and the key. For each kind, a vault holding only that keyslot
//! is converted into a bundle folder on disk; a second device (its own
//! sync state) with the same chip or key opens it, reads what the first
//! wrote and writes back; the same device's chip opens it again after
//! that publish; another chip or key does not.

use std::path::Path;

use luksbox_core::{Argon2idParams, CipherSuite, SlotKind};
use luksbox_fido2::{Fido2Authenticator, MockAuthenticator, RP_ID};
use luksbox_format::{Container, UnlockMaterial};
use luksbox_sep::SepBlob;
use luksbox_sep::mock::MockSepSealer;
use luksbox_sync::bundle::{self, ConvertOptions, OpenOptions};
use luksbox_tpm::SealedBlob;
use luksbox_tpm::mock::MockTpm2Sealer;
use luksbox_vfs::Vfs;
use tempfile::TempDir;

const BOOT: &[u8] = b"bootstrap passphrase";
const SLOT_PW: &[u8] = b"slot passphrase";
const TPM_PIN: &[u8] = b"2468";
const KDF: Argon2idParams = Argon2idParams {
    m_cost_kib: 8,
    t_cost: 1,
    p_cost: 1,
};
const PQ: [u8; 32] = [0x5a; 32];
const SALT: [u8; 32] = [0x33; 32];

/// The chips and the key one machine has.
struct Machine {
    tpm: MockTpm2Sealer,
    sep: MockSepSealer,
    key: MockAuthenticator,
}

impl Machine {
    fn new(key_seed: u8) -> Self {
        Self {
            tpm: MockTpm2Sealer::new(),
            sep: MockSepSealer::new(),
            key: MockAuthenticator::seeded([key_seed; 32]),
        }
    }
}

/// A FIDO2 credential on `m`'s key: its id and the hmac-secret for SALT.
fn fido2(m: &mut Machine) -> (Vec<u8>, [u8; 32]) {
    let cred = m.key.enroll(RP_ID, b"user", None).unwrap().credential.id;
    let h = m.key.hmac_secret(RP_ID, &cred, &SALT, true, None).unwrap();
    (cred, h.0)
}

fn hmac_for(m: &mut Machine, cred: &[u8]) -> Option<[u8; 32]> {
    m.key
        .hmac_secret(RP_ID, cred, &SALT, true, None)
        .ok()
        .map(|h| h.0)
}

fn tpm_unseal(m: &mut Machine, blob: &[u8]) -> Result<[u8; 32], String> {
    let b = SealedBlob::from_bytes(blob).map_err(|e| e.to_string())?;
    // A PIN slot's blob needs the PIN; a plain one opens either way.
    let k = m
        .tpm
        .unseal_with_pin(&b, Some(TPM_PIN))
        .or_else(|_| m.tpm.unseal(&b))
        .map_err(|e| e.to_string())?;
    Ok(*k)
}

fn sep_unseal(m: &mut Machine, blob: &[u8]) -> Result<[u8; 32], String> {
    let b = SepBlob::from_bytes(blob).map_err(|e| e.to_string())?;
    Ok(*m.sep.unseal(&b).map_err(|e| e.to_string())?)
}

#[derive(Clone, Copy, Debug)]
enum Kind {
    Tpm,
    TpmPin,
    TpmFido2,
    HybridTpm,
    HybridTpmFido2,
    Sep,
    SepBiometric,
    SepFido2,
    SepPassphrase,
    HybridSep,
    HybridSepFido2,
    Fido2,
    Fido2Passphrase,
    HybridFido2,
}

/// Enrol `kind` on `c` with `m`'s chips and key; returns the FIDO2
/// credential id it uses (empty when none).
fn enroll(c: &mut Container, m: &mut Machine, kind: Kind) -> Vec<u8> {
    let mut secret = [0u8; 32];
    rand_fill(&mut secret);
    let (cred, hmac) = match kind {
        Kind::TpmFido2
        | Kind::HybridTpmFido2
        | Kind::SepFido2
        | Kind::HybridSepFido2
        | Kind::Fido2
        | Kind::Fido2Passphrase
        | Kind::HybridFido2 => fido2(m),
        _ => (Vec::new(), [0; 32]),
    };
    let sep = |m: &mut Machine, bio: bool| {
        let (k, blob) = if bio {
            m.sep.seal_biometric().unwrap()
        } else {
            m.sep.seal().unwrap()
        };
        (*k, blob.to_bytes())
    };
    match kind {
        Kind::Tpm => {
            let blob = m.tpm.seal(&secret).unwrap().to_bytes();
            c.enroll_tpm2(&secret, &blob).unwrap();
        }
        Kind::TpmPin => {
            let blob = m
                .tpm
                .seal_with_pin(&secret, Some(TPM_PIN))
                .unwrap()
                .to_bytes();
            c.enroll_tpm2_pin(&secret, &blob).unwrap();
        }
        Kind::TpmFido2 => {
            let blob = m.tpm.seal(&secret).unwrap().to_bytes();
            c.enroll_tpm2_fido2(&secret, &hmac, &blob, &cred, SALT)
                .unwrap();
        }
        Kind::HybridTpm => {
            let blob = m.tpm.seal(&secret).unwrap().to_bytes();
            c.enroll_hybrid_pq_tpm2(&secret, &PQ, &blob).unwrap();
        }
        Kind::HybridTpmFido2 => {
            let blob = m.tpm.seal(&secret).unwrap().to_bytes();
            c.enroll_hybrid_pq_tpm2_fido2(&secret, &hmac, &PQ, &blob, &cred, SALT)
                .unwrap();
        }
        Kind::Sep | Kind::SepBiometric => {
            let bio = matches!(kind, Kind::SepBiometric);
            let (k, blob) = sep(m, bio);
            let sk = if bio {
                SlotKind::SepSealedBiometric
            } else {
                SlotKind::SepSealed
            };
            c.enroll_sep(sk, &k, &blob, None, None, KDF, None, &[], [0; 32])
                .unwrap();
        }
        Kind::SepFido2 => {
            let (k, blob) = sep(m, false);
            c.enroll_sep(
                SlotKind::SepFido2,
                &k,
                &blob,
                Some(&hmac),
                None,
                KDF,
                None,
                &cred,
                SALT,
            )
            .unwrap();
        }
        Kind::SepPassphrase => {
            let (k, blob) = sep(m, false);
            c.enroll_sep(
                SlotKind::SepPassphrase,
                &k,
                &blob,
                None,
                Some(SLOT_PW),
                KDF,
                None,
                &[],
                [0; 32],
            )
            .unwrap();
        }
        Kind::HybridSep => {
            let (k, blob) = sep(m, false);
            c.enroll_sep(
                SlotKind::HybridPqKemSep,
                &k,
                &blob,
                None,
                None,
                KDF,
                Some(&PQ),
                &[],
                [0; 32],
            )
            .unwrap();
        }
        Kind::HybridSepFido2 => {
            let (k, blob) = sep(m, false);
            c.enroll_sep(
                SlotKind::HybridPqKemSepFido2,
                &k,
                &blob,
                Some(&hmac),
                None,
                KDF,
                Some(&PQ),
                &cred,
                SALT,
            )
            .unwrap();
        }
        Kind::Fido2 => {
            c.enroll_fido2(None, &hmac, &cred, SALT, KDF).unwrap();
        }
        Kind::Fido2Passphrase => {
            c.enroll_fido2(Some(SLOT_PW), &hmac, &cred, SALT, KDF)
                .unwrap();
        }
        Kind::HybridFido2 => {
            c.enroll_hybrid_pq_fido2(None, &hmac, &PQ, &cred, SALT, KDF)
                .unwrap();
        }
    }
    cred
}

fn rand_fill(b: &mut [u8]) {
    use rand_core::RngCore;
    rand_core::OsRng.fill_bytes(b);
}

/// Open the bundle at `path` as the device whose sync state is
/// `state`, unlocking `kind` with `m`'s chips and key.
fn open(
    path: &Path,
    state: &Path,
    m: &mut Machine,
    kind: Kind,
    cred: &[u8],
) -> luksbox_sync::Result<(bundle::Session, Vfs)> {
    let hmac = hmac_for(m, cred);
    let opts = OpenOptions {
        device_label: state.file_name().unwrap().to_string_lossy().into_owned(),
        read_only: false,
    };
    let mut unseal_tpm = |b: &[u8]| tpm_unseal(m, b);
    let (s, c, _) = match kind {
        Kind::Tpm | Kind::TpmPin => bundle::fs::open(
            path,
            state,
            &mut UnlockMaterial::Tpm2 {
                unseal: &mut unseal_tpm,
            },
            &opts,
        )?,
        Kind::TpmFido2 => bundle::fs::open(
            path,
            state,
            &mut UnlockMaterial::Tpm2Fido2 {
                unseal: &mut unseal_tpm,
                cred_id: cred,
                hmac_secret: &hmac.unwrap_or([0; 32]),
            },
            &opts,
        )?,
        Kind::HybridTpm => bundle::fs::open(
            path,
            state,
            &mut UnlockMaterial::HybridPqTpm2 {
                unseal: &mut unseal_tpm,
                pq_shared: &PQ,
            },
            &opts,
        )?,
        Kind::HybridTpmFido2 => bundle::fs::open(
            path,
            state,
            &mut UnlockMaterial::HybridPqTpm2Fido2 {
                unseal: &mut unseal_tpm,
                cred_id: cred,
                hmac_secret: &hmac.unwrap_or([0; 32]),
                pq_shared: &PQ,
            },
            &opts,
        )?,
        Kind::Sep
        | Kind::SepBiometric
        | Kind::SepFido2
        | Kind::SepPassphrase
        | Kind::HybridSep
        | Kind::HybridSepFido2 => {
            let h = hmac;
            let mut unseal_sep = |b: &[u8]| sep_unseal(m, b);
            bundle::fs::open(
                path,
                state,
                &mut UnlockMaterial::Sep {
                    unseal: &mut unseal_sep,
                    hmac_secret: matches!(kind, Kind::SepFido2 | Kind::HybridSepFido2)
                        .then_some(h.as_ref())
                        .flatten(),
                    passphrase: matches!(kind, Kind::SepPassphrase).then_some(SLOT_PW),
                    pq_shared: matches!(kind, Kind::HybridSep | Kind::HybridSepFido2)
                        .then_some(&PQ),
                },
                &opts,
            )?
        }
        Kind::Fido2 | Kind::Fido2Passphrase => bundle::fs::open(
            path,
            state,
            &mut UnlockMaterial::Fido2 {
                passphrase: matches!(kind, Kind::Fido2Passphrase).then_some(SLOT_PW),
                cred_id: cred,
                hmac_secret: &hmac.unwrap_or([0; 32]),
            },
            &opts,
        )?,
        Kind::HybridFido2 => bundle::fs::open(
            path,
            state,
            &mut UnlockMaterial::HybridPqFido2 {
                passphrase: None,
                cred_id: cred,
                hmac_secret: &hmac.unwrap_or([0; 32]),
                pq_shared: &PQ,
            },
            &opts,
        )?,
    };
    Ok((s, Vfs::open(c).unwrap()))
}

fn read(vfs: &mut Vfs, name: &str) -> Vec<u8> {
    let id = vfs.lookup(vfs.root_id(), name).unwrap();
    let mut buf = vec![0u8; 64];
    let n = vfs.read(id, 0, &mut buf).unwrap();
    buf.truncate(n);
    buf
}

fn write(vfs: &mut Vfs, name: &str, data: &[u8]) {
    let id = vfs.create(vfs.root_id(), name).unwrap();
    vfs.write(id, 0, data).unwrap();
    vfs.flush().unwrap();
}

#[test]
fn every_hardware_keyslot_kind_creates_and_opens_a_bundle() {
    for kind in [
        Kind::Tpm,
        Kind::TpmPin,
        Kind::TpmFido2,
        Kind::HybridTpm,
        Kind::HybridTpmFido2,
        Kind::Sep,
        Kind::SepBiometric,
        Kind::SepFido2,
        Kind::SepPassphrase,
        Kind::HybridSep,
        Kind::HybridSepFido2,
        Kind::Fido2,
        Kind::Fido2Passphrase,
        Kind::HybridFido2,
    ] {
        let dir = TempDir::new().unwrap();
        let d = dir.path();
        let (state_a, state_b) = (d.join("laptop"), d.join("desktop"));
        let mut m = Machine::new(1);

        // A vault with only this kind's keyslot (the bootstrap passphrase
        // it was created with is revoked), one file, made into a bundle.
        let _g = luksbox_format::metadata::set_create_metadata_region_size_override(Some(2 << 20));
        let mut c = Container::create_with_passphrase(
            &d.join("v.lbx"),
            None,
            CipherSuite::Aes256GcmSiv,
            KDF,
            BOOT,
        )
        .unwrap();
        let cred = enroll(&mut c, &mut m, kind);
        c.revoke_slot(0).unwrap();
        c.persist_header().unwrap();
        let mut vfs = Vfs::open(c).unwrap();
        write(&mut vfs, "a.txt", b"from the laptop");
        let bundle_path = d.join("v.lbxs");
        bundle::fs::convert(
            vfs.container_mut(),
            &bundle_path,
            &state_a,
            &ConvertOptions {
                page_size: bundle::DEFAULT_PAGE_SIZE,
                device_label: "laptop".into(),
                hybrid_sidecar: None,
            },
        )
        .unwrap_or_else(|e| panic!("{kind:?}: convert: {e}"));
        drop(vfs);

        // The bootstrap passphrase no longer opens it.
        let refused = bundle::fs::open(
            &bundle_path,
            &state_b,
            &mut UnlockMaterial::Passphrase(BOOT),
            &OpenOptions::default(),
        );
        assert!(
            refused.is_err(),
            "{kind:?}: the revoked passphrase opened it"
        );

        // A second device with the same chip or key: reads, writes.
        let (mut s, mut vfs) = open(&bundle_path, &state_b, &mut m, kind, &cred)
            .unwrap_or_else(|e| panic!("{kind:?}: second device: {e}"));
        assert_eq!(read(&mut vfs, "a.txt"), b"from the laptop", "{kind:?}");
        write(&mut vfs, "b.txt", b"from the desktop");
        s.finish(&mut vfs).unwrap();
        drop(vfs);
        drop(s);

        // The first device sees the second one's write.
        let (mut s, mut vfs) = open(&bundle_path, &state_a, &mut m, kind, &cred)
            .unwrap_or_else(|e| panic!("{kind:?}: first device again: {e}"));
        assert_eq!(read(&mut vfs, "b.txt"), b"from the desktop", "{kind:?}");
        s.finish(&mut vfs).unwrap();
        drop(vfs);
        drop(s);

        // Another machine's chips and key do not open it.
        let mut other = Machine::new(2);
        assert!(
            open(&bundle_path, &d.join("other"), &mut other, kind, &cred).is_err(),
            "{kind:?}: another machine opened it"
        );
    }
}
