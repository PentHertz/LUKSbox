//! AFL++ harness: arbitrary 36 KiB+ buffers fed to the v2 deniable
//! envelope-open path. Mirrors `fuzz/fuzz_targets/deniable_header_parse.rs`
//! (libfuzzer variant).
//!
//! Closes the pre-existing AFL gap on the deniable surface: the
//! parallel `fuzz/` (libfuzzer) and `fuzz-afl/` (AFL++) directories
//! are meant to track the same target set so the two fuzzing
//! engines' different mutator personalities have a chance to find
//! distinct bugs (see `FUZZING.md`).

use luksbox_core::deniable::{DENIABLE_HEADER_SIZE, DeniableCredential};
use luksbox_core::{Argon2idParams, CipherSuite};
use luksbox_format::deniable_header::{complete_open_v2, try_open_envelope_v2};
use luksbox_format::error::Error;

fn main() {
    afl::fuzz!(|data: &[u8]| {
        if data.len() < DENIABLE_HEADER_SIZE + 64 {
            return;
        }

        let header = &data[..DENIABLE_HEADER_SIZE];
        let rest = &data[DENIABLE_HEADER_SIZE..];

        let pass_len = (rest[0] as usize).min(rest.len() - 1).min(256);
        let passphrase = &rest[1..1 + pass_len];

        let cipher = match rest.get(257).copied().unwrap_or(0) % 3 {
            0 => CipherSuite::Aes256GcmSiv,
            1 => CipherSuite::Aes256Gcm,
            _ => CipherSuite::ChaCha20Poly1305,
        };

        let params = Argon2idParams {
            m_cost_kib: 8,
            t_cost: 1,
            p_cost: 1,
        };

        let cred = DeniableCredential::Passphrase {
            passphrase,
            argon2: params,
        };

        let envelope = match try_open_envelope_v2(header, &cred, cipher, None) {
            Ok(env) => env,
            Err(Error::OpaqueUnlockFailed) => return,
            Err(other) => panic!(
                "v2 envelope-open returned a non-opaque error, leaking the failure mode: {other:?}"
            ),
        };

        match complete_open_v2(&envelope, &cred, cipher) {
            Ok(_) => {}
            Err(Error::OpaqueUnlockFailed) => {}
            Err(other) => panic!(
                "v2 complete_open returned a non-opaque error, leaking the failure mode: {other:?}"
            ),
        }
    });
}
