// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Penthertz <https://penthertz.com> (https://x.com/PentHertz)

#![no_main]

//! Adversarial deniable-header parse target. Feed the open path
//! arbitrary bytes (passphrase, header buffer, cipher choice) and
//! ensure it NEVER panics, indexes out of bounds, allocates wildly,
//! or distinguishes failure modes.
//!
//! Threat model: attacker writes any 8 KiB-or-larger blob to the
//! header position of a `.lbx` file, attacker also controls the
//! passphrase the GUI sends (e.g., a confused-deputy scenario). The
//! crate's parser is the last line of defence; it MUST be robust.
//!
//! Invariants checked:
//! 1. Never panic.
//! 2. Never allocate more than a few KiB on hostile input (we cap
//!    Argon2 cost via `is_sane_for_disk`; the parser additionally
//!    rejects out-of-envelope inner-header fields BEFORE allocating
//!    against them).
//! 3. ALWAYS return `Error::OpaqueUnlockFailed` on any failure
//!    (single error variant; no oracle leakage about which step
//!    rejected the input).

use libfuzzer_sys::fuzz_target;
use luksbox_core::{Argon2idParams, CipherSuite};
use luksbox_core::deniable::DENIABLE_HEADER_SIZE;
use luksbox_format::deniable_header::open_with_passphrase;
use luksbox_format::error::Error;

fuzz_target!(|data: &[u8]| {
    // Feed at least DENIABLE_HEADER_SIZE bytes; under that the path
    // is the one-line truncation guard that we cover in unit tests.
    // Fuzzing the post-truncation path costs more cycles for more
    // signal.
    if data.len() < DENIABLE_HEADER_SIZE + 64 {
        return;
    }

    // First 8 KiB go to the header buffer; remaining bytes
    // pseudo-randomly source the passphrase + cipher choice + Argon2
    // params. This lets one fuzzer run sweep across the {header,
    // passphrase, params, cipher} cartesian product without
    // duplicating loops.
    let header = &data[..DENIABLE_HEADER_SIZE];
    let rest = &data[DENIABLE_HEADER_SIZE..];

    // Passphrase from up to 256 bytes of remaining input. Including
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

    // Single allowed outcome: `OpaqueUnlockFailed`, OR a successful
    // open (which can happen if the fuzzer happens to generate a
    // valid header + passphrase combination - effectively impossible
    // by chance but technically allowed and not a bug).
    match open_with_passphrase(header, passphrase, params, cipher) {
        Ok(_) => {
            // Fuzzer hit a valid open by chance, that's fine. Don't
            // panic; just return.
        }
        Err(Error::OpaqueUnlockFailed) => {
            // Expected outcome for the overwhelming majority of inputs.
        }
        Err(other) => {
            // Any other error variant is a leak: the open path is
            // supposed to collapse all failure modes into
            // OpaqueUnlockFailed. If something else surfaces it's a
            // real bug worth investigating.
            panic!(
                "deniable open returned a non-opaque error, leaking the failure mode: {:?}",
                other
            );
        }
    }
});
