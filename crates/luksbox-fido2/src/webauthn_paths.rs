// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Penthertz <https://penthertz.com> (https://x.com/PentHertz)

//! Pure-Rust device-path classifier for the Windows WebAuthn path.
//!
//! Compiled on every platform (no FFI deps) so the alias / classifier
//! logic is unit-testable + fuzz-testable from Linux / macOS without
//! actually linking against `webauthn.dll`. The Windows-only
//! `webauthn.rs` module imports the constants and `classify_device_path`
//! from here, then maps the resulting `AttachmentHint` to the
//! `WEBAUTHN_AUTHENTICATOR_ATTACHMENT_*` constants from the Win32
//! crate at the moment of the FFI call.
//!
//! Why a dedicated module: the device-path string comes from user
//! input (the `--fido2-device` CLI flag, the GUI dropdown, the
//! `LUKSBOX_FIDO2_DEVICE` env var). Anything that touches user input
//! deserves a panic-resistance fuzz target, regardless of how simple
//! the parser looks. Past audits have repeatedly turned up bugs in
//! "obviously correct" string-classification code (wrong bound on a
//! `to_ascii_lowercase` allocation, panicking on invalid UTF-8 from a
//! re-decoded source, etc.); keeping this in its own module with a
//! companion fuzz target catches that regression class cheaply.

/// Synthetic device "paths" used in the `--fido2-device` flag and the
/// GUI dropdown. These don't correspond to real OS device paths; they
/// are handles for "what attachment hint should we send to
/// `webauthn.dll`". Aliases (`winhello://`, `windows://hello`, ...) are
/// accepted via `is_windows_hello_path` so existing scripts keep
/// working.
pub const PATH_ANY: &str = "webauthn://any";
pub const PATH_PLATFORM: &str = "webauthn://platform";
pub const PATH_CROSS_PLATFORM: &str = "webauthn://cross-platform";

/// Which authenticator class Windows should offer in its WebAuthn
/// prompt. Pure data; the Windows-only `webauthn.rs` maps this to the
/// `WEBAUTHN_AUTHENTICATOR_ATTACHMENT_*` C constant at the FFI call
/// site.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AttachmentHint {
    /// Windows shows its standard "Use Windows Hello, or insert your
    /// security key" picker (the broadest UX).
    Any,
    /// Only the platform authenticator (Windows Hello: face, finger-
    /// print, PIN). USB / NFC keys are hidden from the prompt.
    Platform,
    /// Only roaming authenticators (USB / NFC / BLE security keys).
    /// Windows Hello is hidden from the prompt.
    CrossPlatform,
}

/// True iff `path` is one of the recognized aliases for Windows
/// Hello. Accepted forms (case-insensitive): `winhello://`, `winhello`,
/// `windows://hello`, `hello`, `webauthn://platform`. The alias list
/// is duplicated between this crate and the libfido2-backed `hid.rs`
/// for legacy reasons; this is the canonical implementation.
pub fn is_windows_hello_path(path: &str) -> bool {
    // Defence-in-depth: reject implausibly large paths so an attacker
    // can't trigger a multi-MB heap allocation by passing a crafted
    // long string into the lowercasing step. 256 bytes is generous;
    // every valid path is under 32 chars.
    if path.len() > 256 {
        return false;
    }
    let lower = path.to_ascii_lowercase();
    lower == "winhello://"
        || lower == "winhello"
        || lower == "windows://hello"
        || lower == "hello"
        || lower == PATH_PLATFORM
}

/// Classify a device-path string into the WebAuthn attachment hint
/// that drives Windows' authenticator picker. Unknown / garbage paths
/// fall through to `Any` (the safe default: user gets the standard
/// Windows picker and chooses themselves).
pub fn classify_device_path(path: &str) -> AttachmentHint {
    // Same length cap as is_windows_hello_path: prevent unbounded
    // allocations on garbage input. Above the cap, treat as Any.
    if path.len() > 256 {
        return AttachmentHint::Any;
    }
    if is_windows_hello_path(path) {
        return AttachmentHint::Platform;
    }
    let lower = path.to_ascii_lowercase();
    if lower == PATH_CROSS_PLATFORM
        || lower == "webauthn://usb"
        || lower == "webauthn://cross"
        || lower == "webauthn://nfc"
        || lower == "webauthn://ble"
    {
        return AttachmentHint::CrossPlatform;
    }
    AttachmentHint::Any
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn winhello_aliases_match() {
        for alias in [
            "winhello://",
            "winhello",
            "windows://hello",
            "hello",
            "webauthn://platform",
            "WINHELLO://",
            "Windows://Hello",
        ] {
            assert!(is_windows_hello_path(alias), "alias {alias:?}");
            assert_eq!(classify_device_path(alias), AttachmentHint::Platform);
        }
    }

    #[test]
    fn cross_platform_aliases_match() {
        for alias in [
            PATH_CROSS_PLATFORM,
            "webauthn://usb",
            "webauthn://cross",
            "webauthn://nfc",
            "webauthn://ble",
            "WEBAUTHN://USB",
        ] {
            assert!(!is_windows_hello_path(alias), "alias {alias:?}");
            assert_eq!(
                classify_device_path(alias),
                AttachmentHint::CrossPlatform,
                "alias {alias:?}"
            );
        }
    }

    #[test]
    fn unknown_paths_fallback_to_any() {
        for s in [
            "",
            "/dev/hidraw0",
            "ioreg://...",
            "webauthn://any",
            "garbage",
            "winhellox", // close but not exact
        ] {
            assert!(!is_windows_hello_path(s), "should not match: {s:?}");
            assert_eq!(classify_device_path(s), AttachmentHint::Any, "input {s:?}");
        }
    }

    #[test]
    fn oversized_input_does_not_panic() {
        // 1 MiB string. Both functions must short-circuit.
        let big = "a".repeat(1 << 20);
        assert!(!is_windows_hello_path(&big));
        assert_eq!(classify_device_path(&big), AttachmentHint::Any);
    }

    #[test]
    fn unicode_does_not_panic() {
        for s in ["wíñhello", "𝓦inhello://", "\u{0}", "\u{0}wH://"] {
            // Don't care what they classify as, just that nothing panics
            // and the answer is consistent across the two predicates.
            let hello = is_windows_hello_path(s);
            let class = classify_device_path(s);
            if hello {
                assert_eq!(class, AttachmentHint::Platform);
            }
        }
    }
}
