// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Penthertz <https://penthertz.com> (https://x.com/PentHertz)

#![no_main]

//! Panic-resistance fuzz target for the WebAuthn device-path
//! classifier.
//!
//! `classify_device_path` and `is_windows_hello_path` consume strings
//! that come from user input - the `--fido2-device` CLI flag, the
//! `LUKSBOX_FIDO2_DEVICE` env var, the GUI dropdown selection, and
//! the `device_path` field stored in `.lbx` keyslot headers (which
//! after vault-import could be attacker-controlled). These are tiny
//! string functions but the consequence of a panic is the same as in
//! `winfsp_path_parse`: the caller is somewhere deep in the unlock
//! flow and a panic kills the GUI / CLI process.
//!
//! Invariants checked:
//!   - Neither function panics on any UTF-8 input.
//!   - If `is_windows_hello_path` returns true, `classify_device_path`
//!     MUST return `AttachmentHint::Platform`. The two are documented
//!     as consistent and a regression in either would break the
//!     "Windows Hello path -> platform attachment" routing that drives
//!     the prompt UX.

use libfuzzer_sys::fuzz_target;
use luksbox_fido2::webauthn_paths::{AttachmentHint, classify_device_path, is_windows_hello_path};

fuzz_target!(|data: &[u8]| {
    let Ok(s) = std::str::from_utf8(data) else {
        return;
    };

    let hint = classify_device_path(s);
    let is_hello = is_windows_hello_path(s);

    // Cross-predicate consistency: hello-path implies platform attach.
    if is_hello {
        assert_eq!(
            hint,
            AttachmentHint::Platform,
            "is_windows_hello_path(true) but classify={hint:?} for {s:?}"
        );
    }

    // The classifier output is one of the three documented variants;
    // matching exhaustively here makes future-added variants surface
    // as a build break in the fuzz harness rather than a silent gap.
    match hint {
        AttachmentHint::Any | AttachmentHint::Platform | AttachmentHint::CrossPlatform => {}
    }
});
