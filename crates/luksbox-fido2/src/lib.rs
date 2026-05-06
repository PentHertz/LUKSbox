// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Penthertz <https://penthertz.com> (https://x.com/PentHertz)

//! luksbox-fido2, FIDO2 hmac-secret authenticator interface.
//!
//! Scope of this crate:
//! - `Fido2Authenticator` trait: clean abstraction over real and mock devices.
//! - `MockAuthenticator`: deterministic in-memory simulation for unit tests of
//!   higher-level crates.
//! - `protocol`: CTAP2 hmac-secret extension cryptography for
//!   `pinUvAuthProtocol = 1`, ECDH P-256 key agreement, AES-256-CBC salt
//!   encryption, saltAuth, and output decryption. Standalone-testable.
//!
//! Out of scope (deferred until hardware-in-the-loop testing is available):
//! - CBOR encoding of CTAP2 commands. CTAP2 canonical CBOR is exacting and
//!   wire-format mistakes only surface as opaque rejection from the device;
//!   we will not ship untested wire code.
//! - CTAPHID transport (USB HID framing, channel allocation, init).

pub mod authenticator;
pub mod error;
pub mod mock;
pub mod protocol;

// Pure-Rust path-string classifier for the Windows WebAuthn flow.
// Compiled on every platform (no FFI deps) so the alias / classifier
// logic can be unit-tested + fuzzed without linking webauthn.dll.
// See `webauthn_paths.rs` for the rationale; this is the canonical
// home of `is_windows_hello_path` and the per-attachment routing.
pub mod webauthn_paths;

// Platform split:
//
// - Linux / macOS (and by extension every non-Windows target): use
//   libfido2 + raw HID via `hid.rs`. Standard FIDO2 path.
// - Windows: use `webauthn.dll` directly via `webauthn.rs`. Required
//   because the FIDO HID device class is reserved for the WebAuthn
//   system service since Windows 10 1903; non-elevated processes
//   can't open FIDO HID devices via libfido2's path. webauthn.dll
//   is the system service that holds the privilege; calling into it
//   gets us USB security keys + Windows Hello, both without admin.
//   See `webauthn.rs` doc-header for the full rationale.
//
// Both modules expose a `HidAuthenticator` type implementing the
// same `Fido2Authenticator` trait, plus a `DeviceInfo` enumeration
// type and a `random_user_handle()` helper. Callers don't see Windows
// as special; the platform-conditional re-exports below give them
// the right impl for free.
#[cfg(all(feature = "hardware", not(target_os = "windows")))]
pub mod ffi;
#[cfg(all(feature = "hardware", not(target_os = "windows")))]
pub mod hid;

#[cfg(all(feature = "hardware", target_os = "windows"))]
pub mod webauthn;

pub use crate::authenticator::{Credential, EnrollResult, Fido2Authenticator, HmacSecret, RP_ID};
pub use crate::error::Error;
pub use crate::mock::MockAuthenticator;

#[cfg(all(feature = "hardware", not(target_os = "windows")))]
pub use crate::hid::{HidAuthenticator, random_user_handle};

// On Windows, re-export the webauthn-backed type AS `HidAuthenticator`
// so call sites in luksbox-cli / luksbox-gui (which don't and shouldn't
// know about the platform split) compile unchanged.
#[cfg(all(feature = "hardware", target_os = "windows"))]
pub use crate::webauthn::{WebAuthnAuthenticator as HidAuthenticator, random_user_handle};

// is_windows_hello_path is needed by code outside this crate even when
// the real hardware backend is feature-disabled. The classifier is pure
// Rust, so keep it available in no-default builds for CLI/GUI prompt
// generation and tests.
pub use crate::webauthn_paths::is_windows_hello_path;
