// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Penthertz <https://penthertz.com> (https://x.com/PentHertz)

#![no_main]

//! Adversarial deniable-header parse target (v2). Feed the v2
//! envelope-open path arbitrary bytes (passphrase, header buffer,
//! cipher choice) and ensure it NEVER panics, indexes out of bounds,
//! allocates wildly, or distinguishes failure modes.
//!
//! Threat model: attacker writes any 36 KiB-or-larger blob to the
//! header position of a `.lbx` file, attacker also controls the
//! passphrase the GUI sends (e.g., a confused-deputy scenario). The
//! crate's parser is the last line of defence; it MUST be robust.
//!
//! Invariants checked:
//! 1. Never panic.
//! 2. Never allocate more than a few KiB on hostile input (we cap
//!    Argon2 cost via `is_sane_for_disk`; the slot-payload decoder
//!    additionally caps cred_id / hmac_salt / tpm_blob lengths and
//!    rejects out-of-budget combinations BEFORE allocating against
//!    them; the inner-header parser rejects out-of-envelope offsets
//!    on a tag-forged decryption).
//! 3. ALWAYS return `Error::OpaqueUnlockFailed` on any failure
//!    (single error variant; no oracle leakage about which step
//!    rejected the input).
//!
//! Both phases are exercised: phase 1 (envelope discovery via
//! passphrase) and, when the fuzzer lucky-generates a passing
//! envelope, phase 2 (inner MVK unwrap + inner-header decrypt).

use libfuzzer_sys::fuzz_target;
use luksbox_core::deniable::{DENIABLE_HEADER_SIZE, DeniableCredential};
use luksbox_core::{Argon2idParams, CipherSuite};
use luksbox_format::deniable_header::{complete_open_v2, try_open_envelope_v2};
use luksbox_format::error::Error;

fuzz_target!(|data: &[u8]| {
    // Feed at least DENIABLE_HEADER_SIZE bytes; under that the path
    // is the one-line truncation guard that we cover in unit tests.
    // Fuzzing the post-truncation path costs more cycles for more
    // signal.
    if data.len() < DENIABLE_HEADER_SIZE + 64 {
        return;
    }

    // First 36 KiB go to the header buffer; remaining bytes
    // pseudo-randomly source the passphrase + cipher choice. This
    // lets one fuzzer run sweep across the {header, passphrase,
    // cipher} cartesian product without duplicating loops.
    let header = &data[..DENIABLE_HEADER_SIZE];
    let rest = &data[DENIABLE_HEADER_SIZE..];

    // Passphrase from up to 256 bytes of remaining input. Includes
    // empty + zero-length + binary garbage.
    let pass_len = (rest[0] as usize).min(rest.len() - 1).min(256);
    let passphrase = &rest[1..1 + pass_len];

    // Cipher choice cycles through the three real options.
    let cipher = match rest.get(257).copied().unwrap_or(0) % 3 {
        0 => CipherSuite::Aes256GcmSiv,
        1 => CipherSuite::Aes256Gcm,
        _ => CipherSuite::ChaCha20Poly1305,
    };

    // Argon2 params: keep them in the sane envelope so we don't burn
    // fuzzer time on the explicit rejection branch (which is covered
    // by unit tests). The realistic adversary scenario is "you have
    // the right envelope but wrong values," which is what we want
    // the AEAD verification path to defend against.
    let params = Argon2idParams {
        m_cost_kib: 8,
        t_cost: 1,
        p_cost: 1,
    };

    let cred = DeniableCredential::Passphrase {
        passphrase,
        argon2: params,
    };

    // Phase 1: envelope discovery. Must collapse every failure into
    // OpaqueUnlockFailed.
    let envelope = match try_open_envelope_v2(header, &cred, cipher) {
        Ok(env) => env,
        Err(Error::OpaqueUnlockFailed) => {
            // Expected outcome for the overwhelming majority of
            // inputs. Done for this iteration.
            return;
        }
        Err(other) => {
            panic!(
                "v2 envelope-open returned a non-opaque error, leaking the failure mode: {:?}",
                other
            );
        }
    };

    // Phase 1 succeeded by chance (effectively impossible without a
    // valid header + passphrase combination, but technically allowed
    // and not a bug). Run phase 2 too to exercise the inner-header
    // decryption + parse path. complete_open_v2 must also collapse
    // every failure into OpaqueUnlockFailed.
    match complete_open_v2(envelope, &cred, cipher) {
        Ok(_) => {
            // Fuzzer hit a valid full open by chance.
        }
        Err(Error::OpaqueUnlockFailed) => {
            // Phase 2 rejected an envelope that phase 1 accepted -
            // valid path (e.g. inner-header parse rejects
            // tag-forged garbage). Single opaque error preserved.
        }
        Err(other) => {
            panic!(
                "v2 complete_open returned a non-opaque error, leaking the failure mode: {:?}",
                other
            );
        }
    }
});
