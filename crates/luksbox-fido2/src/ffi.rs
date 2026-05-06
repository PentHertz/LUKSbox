// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Penthertz <https://penthertz.com> (https://x.com/PentHertz)

//! libfido2 FFI bindings.
//!
//! Generated at build time by `build.rs` via `bindgen` against the headers
//! of the actually-linked libfido2 (resolved via pkg-config / vcpkg /
//! `LIBFIDO2_LIB_DIR` env override). The generated file lives at
//! `$OUT_DIR/fido2_bindings.rs` and is included unchanged below.
//!
//! Bindings prior to round 7C of the audit were hand-rolled (a 122-line
//! `unsafe extern "C"` block translated by hand from libfido2 1.14's
//! `<fido.h>`). Round 7B verified the hand-rolled signatures matched
//! 1.14 byte-for-byte but could not prove they remained correct under
//! distro-version skew, bindgen closes that risk by regenerating
//! against whatever headers actually link.
//!
//! Allowlist: `build.rs` restricts the generated surface to the
//! functions / constants / opaque types we actually call. Keeps the
//! bindings small (~few hundred lines vs about 5 KLOC that `<fido.h>` would
//! generate) and the unsafe surface a future reviewer has to walk to
//! the same set we used pre-bindgen.

#![allow(non_camel_case_types, non_upper_case_globals, dead_code)]

include!(concat!(env!("OUT_DIR"), "/fido2_bindings.rs"));

// `fido_opt_t` is a C enum; bindgen emits its variants prefixed with the
// type name (`fido_opt_t_FIDO_OPT_OMIT`, etc.). Re-export under the bare
// names that match libfido2's own public API and our pre-bindgen
// callsites.
pub const FIDO_OPT_OMIT: fido_opt_t = fido_opt_t_FIDO_OPT_OMIT;
pub const FIDO_OPT_FALSE: fido_opt_t = fido_opt_t_FIDO_OPT_FALSE;
pub const FIDO_OPT_TRUE: fido_opt_t = fido_opt_t_FIDO_OPT_TRUE;

/// libfido2 version string captured at build time by `build.rs` via
/// pkg-config. `None` if the link path was a manual override or if the
/// `hardware` feature is disabled (no link, no probe). Used by
/// `HidAuthenticator::new()` to emit a one-line diagnostic when
/// `LUKSBOX_FIDO2_DEBUG=1`, lets operators verify which libfido2 the
/// binary is talking to without ldd / strace.
pub const LIBFIDO2_LINK_VERSION: Option<&str> = option_env!("LUKSBOX_LIBFIDO2_VERSION");
