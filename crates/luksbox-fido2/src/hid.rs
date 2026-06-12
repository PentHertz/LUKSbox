// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Penthertz <https://penthertz.com> (https://x.com/PentHertz)

//! Real-hardware `Fido2Authenticator` backed by libfido2.
//!
//! Stateless: each call to `enroll` / `hmac_secret` discovers the first
//! FIDO2 hidraw device via `fido_dev_info_manifest`, opens it, performs
//! the operation, and closes it. Suitable for interactive CLI use where
//! every operation is gated on a user touch anyway.

use std::ffi::{CStr, CString};
use std::os::raw::c_int;

use rand_core::{OsRng, RngCore};
use zeroize::Zeroizing;

use crate::authenticator::{Credential, EnrollResult, Fido2Authenticator, HmacSecret};
use crate::error::Error;
use crate::ffi::*;

/// We don't use the WebAuthn challenge semantics, the `.lbx` keyslot
/// AAD already binds the wrap to the container. Pass an all-zero
/// 32-byte client-data-hash so libfido2 doesn't reject our calls.
const ZERO_CLIENTDATA_HASH: [u8; 32] = [0u8; 32];

const MAX_DEVICES: usize = 64;

/// One enumerated FIDO2 authenticator. `path` is the libfido2 device
/// path (a hidraw node on Linux, an HID path on Windows/macOS, or a
/// `winhello://` pseudo-path when libfido2's Windows Hello bridge is
/// active) and is what gets passed to `HidAuthenticator::with_device`
/// to bind operations to a specific authenticator. `label` is the
/// human-readable "Manufacturer Product" string suitable for display.
#[derive(Debug, Clone)]
pub struct DeviceInfo {
    pub path: String,
    pub label: String,
}

/// FIDO2 authenticator handle. Bind to a specific device via
/// `with_device(path)` (where `path` came from `detect_all`), or use
/// `new()` to fall back to the first device libfido2 enumerates (the
/// historical behavior). The device-selection field is consulted at
/// each `enroll` / `hmac_secret` call, not cached, so the choice
/// can be changed between operations.
pub struct HidAuthenticator {
    /// `None` = pick the first enumerated device (legacy behavior).
    /// `Some(path)` = open exactly that device, fail with a clear
    /// error if it's no longer present.
    device_path: Option<CString>,
}

impl HidAuthenticator {
    pub fn new() -> Self {
        let debug = std::env::var_os("LUKSBOX_FIDO2_DEBUG").is_some();
        let flags = if debug { FIDO_DEBUG } else { 0 };
        unsafe { fido_init(flags) };
        if debug {
            // Helpful when triaging "works on my distro but fails on
            // the user's" reports, pkg-config'd version goes here.
            let v = LIBFIDO2_LINK_VERSION.unwrap_or("unknown");
            eprintln!("luksbox: libfido2 link version: {v}");
        }
        Self { device_path: None }
    }

    /// Bind this authenticator to a specific device by libfido2 path
    /// (as returned in `DeviceInfo::path` from `detect_all`).
    /// Subsequent `enroll`/`hmac_secret` calls open that exact device,
    /// failing with a clear "device disappeared" error if it's no
    /// longer plugged in. Use `new()` for the legacy "first device
    /// wins" behavior.
    pub fn with_device(path: impl Into<String>) -> Self {
        let mut s = Self::new();
        if let Ok(c) = CString::new(path.into()) {
            s.device_path = Some(c);
        }
        s
    }

    /// Cheap, touch-free probe: ask libfido2 to enumerate FIDO2 devices and
    /// return whether any are visible. Useful for the GUI to decide whether
    /// to show the "FIDO2 (recommended)" path by default. Returns `Err` only
    /// if libfido2 itself fails (very rare); a missing key returns `Ok(false)`.
    pub fn devices_present() -> Result<bool, Error> {
        Ok(Self::detect_first().ok().flatten().is_some())
    }

    /// Detect the first FIDO2 HID device and return its
    /// "Manufacturer Product" label (e.g. "Yubico YubiKey OTP+FIDO+CCID",
    /// "SoloKeys Solo 2", "Token2 PIN+", "Nitrokey 3", or "Windows
    /// Hello" via libfido2's WinHello bridge on Windows). Returns
    /// `Ok(None)` when no FIDO2 device is plugged in, `Err` only on
    /// libfido2 failure.
    ///
    /// Convenience wrapper around `detect_all` for callers that only
    /// want the first device's label. Prefer `detect_all` when you
    /// need to enumerate or let the user pick.
    pub fn detect_first() -> Result<Option<String>, Error> {
        Ok(Self::detect_all()?.into_iter().next().map(|d| d.label))
    }

    /// Enumerate every FIDO2 device libfido2 can see, returning a
    /// `(path, label)` per device. Brand-agnostic: works with any
    /// CTAP2-compliant authenticator (Yubico, SoloKeys, Nitrokey,
    /// Token2, OnlyKey, Trezor T, etc.) plus the Windows Hello platform
    /// authenticator on Windows (libfido2 exposes it as a
    /// `winhello://` pseudo-device when present).
    ///
    /// Use the returned `path` with `with_device(path)` to bind a
    /// `HidAuthenticator` to a specific device. Empty Vec means no
    /// devices are visible right now (different from `Err`, which
    /// indicates a libfido2 failure).
    pub fn detect_all() -> Result<Vec<DeviceInfo>, Error> {
        unsafe {
            fido_init(0);
            let info_ptr = fido_dev_info_new(MAX_DEVICES);
            if info_ptr.is_null() {
                return Err(Error::Other("fido_dev_info_new returned null".into()));
            }
            let info = DevInfoList {
                ptr: info_ptr,
                capacity: MAX_DEVICES,
            };
            let mut found: usize = 0;
            let rc = fido_dev_info_manifest(info.ptr, info.capacity, &mut found);
            if rc != FIDO_OK {
                return Err(map_err_at("fido_dev_info_manifest", rc));
            }
            let mut out = Vec::with_capacity(found);
            for i in 0..found {
                let entry = fido_dev_info_ptr(info.ptr, i);
                if entry.is_null() {
                    continue;
                }
                let path_ptr = fido_dev_info_path(entry);
                if path_ptr.is_null() {
                    continue;
                }
                let path = CStr::from_ptr(path_ptr).to_string_lossy().into_owned();
                let mfr = cstr_or_empty(fido_dev_info_manufacturer_string(entry));
                let prod = cstr_or_empty(fido_dev_info_product_string(entry));
                let label = format_label(&mfr, &prod);
                out.push(DeviceInfo { path, label });
            }
            Ok(out)
        }
    }
}

unsafe fn cstr_or_empty(p: *const std::os::raw::c_char) -> String {
    if p.is_null() {
        return String::new();
    }
    unsafe { CStr::from_ptr(p).to_string_lossy().trim().to_string() }
}

fn format_label(manufacturer: &str, product: &str) -> String {
    match (manufacturer.is_empty(), product.is_empty()) {
        (false, false) => {
            // Avoid "Yubico YubiKey..." doubling up if the product
            // string already starts with the manufacturer.
            if product
                .to_ascii_lowercase()
                .starts_with(&manufacturer.to_ascii_lowercase())
            {
                product.to_string()
            } else {
                format!("{manufacturer} {product}")
            }
        }
        (false, true) => manufacturer.to_string(),
        (true, false) => product.to_string(),
        (true, true) => "FIDO2 device".into(),
    }
}

impl Default for HidAuthenticator {
    fn default() -> Self {
        Self::new()
    }
}

impl Fido2Authenticator for HidAuthenticator {
    // SAFETY/LIFETIME contract for the unsafe block below:
    //
    // - `dev`, `cred` are RAII handles wrapping libfido2-allocated
    //   objects. Their `Drop` impls call `fido_dev_free` /
    //   `fido_cred_free`. Per libfido2 (man 3 fido_cred_free,
    //   fido_dev_free): both are safe to call on partially-configured
    //   objects, including those that hit an early error mid-setup.
    //   So any `?` early-return below correctly cleans up.
    //
    // - The CStrings (`rp`, `rp_name`, `user_name`, `display_name`,
    //   and `pin_cstr` further down) are stack locals with explicit
    //   bindings. Pointers passed to libfido2 (`.as_ptr()`) borrow
    //   their heap allocations; the CStrings outlive every FFI call
    //   that uses them because all FFI calls happen in this function
    //   body, before any of the bindings drops.
    //
    // - `user_handle: &[u8]` is borrowed from the caller and outlives
    //   this function call.
    //
    // - The final `from_raw_parts(id_ptr, id_len).to_vec()` runs while
    //   `cred` is still alive on the stack. Per libfido2, the cred_id
    //   buffer is owned by `cred` until `fido_cred_free`. The vec
    //   allocation copies the bytes synchronously; no dangling pointer.
    //
    // - THREAD-SAFETY: each call to `enroll`/`hmac_secret` opens its
    //   own `fido_dev_t`. We never share a dev handle across threads,
    //   so libfido2's per-dev "no concurrent operations" rule is
    //   trivially satisfied. `fido_init` (called once in `new()`) is
    //   documented as idempotent and thread-safe.
    fn enroll(
        &mut self,
        rp_id: &str,
        user_handle: &[u8],
        pin: Option<&str>,
    ) -> Result<EnrollResult, Error> {
        let dev = open_device(self.device_path.as_deref())?;
        let cred = CredHandle::new()?;

        let rp = cstring(rp_id)?;
        let rp_name = cstring("luksbox")?;
        let user_name = cstring("luksbox-user")?;
        let display_name = cstring("luksbox")?;

        unsafe {
            checked_at(
                "fido_cred_set_type",
                fido_cred_set_type(cred.ptr, COSE_ES256),
            )?;
            checked_at(
                "fido_cred_set_clientdata_hash",
                fido_cred_set_clientdata_hash(
                    cred.ptr,
                    ZERO_CLIENTDATA_HASH.as_ptr(),
                    ZERO_CLIENTDATA_HASH.len(),
                ),
            )?;
            checked_at(
                "fido_cred_set_rp",
                fido_cred_set_rp(cred.ptr, rp.as_ptr(), rp_name.as_ptr()),
            )?;
            checked_at(
                "fido_cred_set_user",
                fido_cred_set_user(
                    cred.ptr,
                    user_handle.as_ptr(),
                    user_handle.len(),
                    user_name.as_ptr(),
                    display_name.as_ptr(),
                    std::ptr::null(),
                ),
            )?;
            checked_at(
                "fido_cred_set_extensions",
                fido_cred_set_extensions(cred.ptr, FIDO_EXT_HMAC_SECRET),
            )?;
            checked_at(
                "fido_cred_set_rk",
                fido_cred_set_rk(cred.ptr, FIDO_OPT_FALSE),
            )?;
            checked_at(
                "fido_cred_set_uv",
                fido_cred_set_uv(
                    cred.ptr,
                    if pin.is_some() {
                        FIDO_OPT_TRUE
                    } else {
                        FIDO_OPT_OMIT
                    },
                ),
            )?;

            // `pin_cstr` owns the heap allocation; `cstr_ptr_or_null`
            // borrows it for the FFI call. Do NOT extract a `*const c_char`
            // into a local, see the helper's doc comment.
            let pin_cstr = pin.map(cstring).transpose()?;

            maybe_winhello_context(
                &self.device_path,
                "credential enrollment",
                checked_at(
                    "fido_dev_make_cred",
                    fido_dev_make_cred(dev.ptr, cred.ptr, cstr_ptr_or_null(&pin_cstr)),
                ),
            )?;

            let id_ptr = fido_cred_id_ptr(cred.ptr);
            let id_len = fido_cred_id_len(cred.ptr);
            if id_ptr.is_null() || id_len == 0 {
                return Err(Error::Other(
                    "authenticator returned empty credential id".into(),
                ));
            }
            // Defence against rogue/MITM authenticator returning a hostile
            // cred_id length: real CTAP2 cred_ids are typically 16-256 B
            // (Yubico is 16 B; some stacks go up to 1023 B per CTAP spec
            // section 6 "credentialIdLength"). A malicious device that
            // claims `id_len = u32::MAX` would otherwise drive an OOM
            // before the downstream `Keyslot::new_*` length check (which
            // caps at FIDO2_CRED_ID_MAX = 128) can run. Reject early at
            // the FFI boundary with a generous 4 KiB cap, way above any
            // legitimate authenticator value, way below "OOM the user".
            const MAX_CRED_ID_FROM_DEVICE: usize = 4096;
            if id_len > MAX_CRED_ID_FROM_DEVICE {
                return Err(Error::Other(format!(
                    "authenticator returned implausibly large credential id ({id_len} B); \
                     refusing to allocate (cap {MAX_CRED_ID_FROM_DEVICE})"
                )));
            }
            // Sanity-check the FFI pointer before constructing a slice.
            // libfido2's contract is that `fido_cred_id_ptr` returns
            // either a valid pointer with `fido_cred_id_len` bytes
            // readable, or NULL on no-credential. A buggy / hostile-
            // firmware authenticator that returns a non-null but
            // dangling pointer would otherwise cause `from_raw_parts`
            // to read uninitialised memory. Realistic exploitation
            // requires both libfido2 misbehaviour AND a hostile USB
            // device, but the check is cheap and keeps the unsafe
            // block honest.
            if id_ptr.is_null() {
                return Err(Error::Other(
                    "libfido2 returned (id_len > 0, id_ptr = NULL); \
                     refusing to construct slice from null pointer"
                        .into(),
                ));
            }
            let id = std::slice::from_raw_parts(id_ptr, id_len).to_vec();
            Ok(EnrollResult {
                credential: Credential { id },
            })
        }
    }

    // SAFETY/LIFETIME contract: same shape as enroll() above. The
    // 32-byte hmac_secret returned by libfido2 is owned by `assert`
    // until `fido_assert_free`; we copy it into a stack `[u8; 32]`
    // synchronously inside the unsafe block and return that, so no
    // libfido2-owned pointer escapes.
    fn hmac_secret(
        &mut self,
        rp_id: &str,
        cred_id: &[u8],
        salt: &[u8; 32],
        prehash_salt: bool,
        pin: Option<&str>,
    ) -> Result<HmacSecret, Error> {
        let dev = open_device(self.device_path.as_deref())?;
        let assert = AssertHandle::new()?;

        let rp = cstring(rp_id)?;

        // V4 slots (`prehash_salt=true`) want the authenticator to see
        // SHA-256(salt) so the wire HMAC matches what webauthn.dll
        // produces on Windows (which prehashes automatically). libfido2
        // is a CTAP2-level library and passes whatever bytes we hand
        // it to the device verbatim, so we have to do the prehash
        // ourselves here. The Zeroizing wrapper scrubs the 32 B
        // digest after this method returns regardless of unwind path.
        let salt_to_send: Zeroizing<[u8; 32]> = if prehash_salt {
            use sha2::{Digest, Sha256};
            let mut out = Zeroizing::new([0u8; 32]);
            let digest = Sha256::digest(salt);
            out.copy_from_slice(&digest);
            out
        } else {
            Zeroizing::new(*salt)
        };

        unsafe {
            checked_at(
                "fido_assert_set_clientdata_hash",
                fido_assert_set_clientdata_hash(
                    assert.ptr,
                    ZERO_CLIENTDATA_HASH.as_ptr(),
                    ZERO_CLIENTDATA_HASH.len(),
                ),
            )?;
            checked_at(
                "fido_assert_set_rp",
                fido_assert_set_rp(assert.ptr, rp.as_ptr()),
            )?;
            checked_at(
                "fido_assert_allow_cred",
                fido_assert_allow_cred(assert.ptr, cred_id.as_ptr(), cred_id.len()),
            )?;
            checked_at(
                "fido_assert_set_extensions",
                fido_assert_set_extensions(assert.ptr, FIDO_EXT_HMAC_SECRET),
            )?;
            checked_at(
                "fido_assert_set_hmac_salt",
                fido_assert_set_hmac_salt(
                    assert.ptr,
                    salt_to_send.as_ptr(),
                    salt_to_send.len(),
                ),
            )?;
            checked_at(
                "fido_assert_set_up",
                fido_assert_set_up(assert.ptr, FIDO_OPT_TRUE),
            )?;
            checked_at(
                "fido_assert_set_uv",
                fido_assert_set_uv(
                    assert.ptr,
                    if pin.is_some() {
                        FIDO_OPT_TRUE
                    } else {
                        FIDO_OPT_OMIT
                    },
                ),
            )?;

            // See enroll(), same lifetime invariant for the PIN pointer.
            let pin_cstr = pin.map(cstring).transpose()?;

            maybe_winhello_context(
                &self.device_path,
                "assertion",
                checked_at(
                    "fido_dev_get_assert",
                    fido_dev_get_assert(dev.ptr, assert.ptr, cstr_ptr_or_null(&pin_cstr)),
                ),
            )?;

            if fido_assert_count(assert.ptr) == 0 {
                return Err(Error::Other("no assertion returned".into()));
            }
            let secret_ptr = fido_assert_hmac_secret_ptr(assert.ptr, 0);
            let secret_len = fido_assert_hmac_secret_len(assert.ptr, 0);
            if secret_ptr.is_null() || secret_len != 32 {
                return Err(Error::NoHmacSecret);
            }
            let mut out = [0u8; 32];
            out.copy_from_slice(std::slice::from_raw_parts(secret_ptr, 32));
            Ok(HmacSecret(out))
        }
    }
}

/// Generate a fresh 16-byte FIDO2 user handle for a new credential. Random
/// per enrollment; non-resident creds don't require this to be stable.
///
/// Returns `Err` only on OS RNG failure, which in practice means the host
/// is so broken that enrollment can't proceed anyway (no `/dev/urandom`,
/// no `getrandom(2)`, no `BCryptGenRandom`). Surfaced as `Error::Other`
/// rather than panicking so callers can show a useful message.
pub fn random_user_handle() -> Result<[u8; 16], Error> {
    let mut h = [0u8; 16];
    OsRng
        .try_fill_bytes(&mut h)
        .map_err(|e| Error::Other(format!("OS RNG failure generating user handle: {e}")))?;
    Ok(h)
}

// ---- internal RAII wrappers -------------------------------------------------

struct DevHandle {
    ptr: *mut fido_dev_t,
}

impl Drop for DevHandle {
    fn drop(&mut self) {
        unsafe {
            if !self.ptr.is_null() {
                fido_dev_close(self.ptr);
                let mut p = self.ptr;
                fido_dev_free(&mut p);
                // Null out our copy so a hypothetical future double-drop
                // (Rust guarantees this can't happen on stack values, but
                // belt-and-suspenders for any pointer escape) becomes a
                // no-op rather than a use-after-free.
                self.ptr = std::ptr::null_mut();
            }
        }
    }
}

struct DevInfoList {
    ptr: *mut fido_dev_info_t,
    capacity: usize,
}

impl Drop for DevInfoList {
    fn drop(&mut self) {
        unsafe {
            if !self.ptr.is_null() {
                let mut p = self.ptr;
                fido_dev_info_free(&mut p, self.capacity);
                self.ptr = std::ptr::null_mut();
            }
        }
    }
}

struct CredHandle {
    ptr: *mut fido_cred_t,
}

impl CredHandle {
    fn new() -> Result<Self, Error> {
        unsafe {
            let ptr = fido_cred_new();
            if ptr.is_null() {
                return Err(Error::Other("fido_cred_new returned null".into()));
            }
            Ok(Self { ptr })
        }
    }
}

impl Drop for CredHandle {
    fn drop(&mut self) {
        unsafe {
            if !self.ptr.is_null() {
                let mut p = self.ptr;
                fido_cred_free(&mut p);
                self.ptr = std::ptr::null_mut();
            }
        }
    }
}

struct AssertHandle {
    ptr: *mut fido_assert_t,
}

impl AssertHandle {
    fn new() -> Result<Self, Error> {
        unsafe {
            let ptr = fido_assert_new();
            if ptr.is_null() {
                return Err(Error::Other("fido_assert_new returned null".into()));
            }
            Ok(Self { ptr })
        }
    }
}

impl Drop for AssertHandle {
    fn drop(&mut self) {
        unsafe {
            if !self.ptr.is_null() {
                let mut p = self.ptr;
                fido_assert_free(&mut p);
                self.ptr = std::ptr::null_mut();
            }
        }
    }
}

/// Open a FIDO2 HID device. If `pinned_path` is `Some`, opens that
/// exact device and fails with a clear "no longer present" error if
/// it can't be found in the current enumeration. If `None`, opens
/// the first device libfido2 enumerates (legacy behavior).
fn open_device(pinned_path: Option<&CStr>) -> Result<DevHandle, Error> {
    unsafe {
        let info_ptr = fido_dev_info_new(MAX_DEVICES);
        if info_ptr.is_null() {
            return Err(Error::Other("fido_dev_info_new returned null".into()));
        }
        let info = DevInfoList {
            ptr: info_ptr,
            capacity: MAX_DEVICES,
        };

        let mut found: usize = 0;
        let rc = fido_dev_info_manifest(info.ptr, info.capacity, &mut found);
        if rc != FIDO_OK {
            return Err(map_err_at("fido_dev_info_manifest", rc));
        }
        if found == 0 {
            return Err(Error::Other("no FIDO2 devices found".into()));
        }

        // Pick the entry: pinned path if given, otherwise index 0.
        let chosen_idx = if let Some(want) = pinned_path {
            let want_str = want.to_string_lossy();
            let mut chosen: Option<usize> = None;
            for i in 0..found {
                let entry = fido_dev_info_ptr(info.ptr, i);
                if entry.is_null() {
                    continue;
                }
                let path_ptr = fido_dev_info_path(entry);
                if path_ptr.is_null() {
                    continue;
                }
                let actual = CStr::from_ptr(path_ptr);
                if actual == want || winhello_paths_equivalent(&want_str, &actual.to_string_lossy())
                {
                    chosen = Some(i);
                    break;
                }
            }
            match chosen {
                Some(i) => i,
                None => {
                    return Err(Error::Other(format!(
                        "selected FIDO2 device ({}) is no longer plugged in; \
                         re-detect or pick another",
                        want.to_string_lossy()
                    )));
                }
            }
        } else {
            0
        };

        let entry = fido_dev_info_ptr(info.ptr, chosen_idx);
        if entry.is_null() {
            return Err(Error::Other("fido_dev_info_ptr returned null".into()));
        }
        let path_ptr = fido_dev_info_path(entry);
        if path_ptr.is_null() {
            return Err(Error::Other("device path is null".into()));
        }
        let path = CStr::from_ptr(path_ptr).to_owned();

        let dev_ptr = fido_dev_new();
        if dev_ptr.is_null() {
            return Err(Error::Other("fido_dev_new returned null".into()));
        }
        let rc = fido_dev_open(dev_ptr, path.as_ptr());
        if rc != FIDO_OK {
            let mut p = dev_ptr;
            fido_dev_free(&mut p);
            return Err(map_err_at("fido_dev_open", rc));
        }
        Ok(DevHandle { ptr: dev_ptr })
    }
}

fn cstring(s: &str) -> Result<CString, Error> {
    CString::new(s).map_err(|_| Error::Other("string contains nul byte".into()))
}

/// Returns a `*const c_char` pointer suitable for passing to libfido2 FFI
/// calls that accept `const char *` (e.g. the optional PIN argument).
///
/// The pointer is borrowed from the `Option<CString>`'s heap allocation
/// and is valid only while the referent lives. This helper takes
/// `&Option<CString>` (not `Option<CString>`) on purpose, the caller
/// is forced to keep the binding alive in their scope, so the pointer
/// can't outlive the storage. A future refactor that tries to encapsulate
/// "make a pin pointer" into a function returning the bare `*const c_char`
/// would not compile against this signature, which is the intended
/// guard-rail.
fn cstr_ptr_or_null(s: &Option<CString>) -> *const std::os::raw::c_char {
    s.as_ref().map_or(std::ptr::null(), |c| c.as_ptr())
}

/// True when `path` refers to the Windows Hello pseudo-device
/// libfido2 exposes via its WinHello bridge. Multiple historical
/// spellings are accepted: libfido2 >= 1.13 reports the device as
/// `windows://hello`, older versions used `winhello://`, and we
/// accept the bare-keyword forms `windows`, `hello`, `winhello`
/// for user friendliness on the `--fido2-device` CLI flag.
///
/// Pub so the GUI / CLI can detect "is the selected device the
/// platform authenticator" without each call site reimplementing
/// the alias list.
pub fn is_windows_hello_path(path: &str) -> bool {
    // Single source of truth: forward to the platform-agnostic module
    // so the alias list lives in one place. Keep this function pub so
    // the GUI / CLI's existing `use luksbox_fido2::hid::is_windows_hello_path`
    // call sites compile unchanged.
    crate::webauthn_paths::is_windows_hello_path(path)
}

fn winhello_paths_equivalent(a: &str, b: &str) -> bool {
    is_windows_hello_path(a) && is_windows_hello_path(b)
}

fn checked_at(call: &'static str, rc: c_int) -> Result<(), Error> {
    if rc == FIDO_OK {
        Ok(())
    } else {
        Err(map_err_at(call, rc))
    }
}

fn map_err_at(call: &'static str, rc: c_int) -> Error {
    match rc {
        FIDO_ERR_PIN_INVALID | FIDO_ERR_PIN_AUTH_INVALID => Error::PinIncorrect,
        FIDO_ERR_PIN_REQUIRED => Error::PinRequired,
        FIDO_ERR_PIN_NOT_SET => Error::Other(
            "FIDO2 PIN is not set on the authenticator, \
             enroll a PIN with the device's vendor tool first \
             (e.g. ykman fido access change-pin), then retry"
                .into(),
        ),
        FIDO_ERR_PIN_BLOCKED => Error::Other("FIDO2 PIN is blocked, reset the FIDO app".into()),
        FIDO_ERR_USER_ACTION_TIMEOUT | FIDO_ERR_TIMEOUT => Error::TouchTimeout,
        FIDO_ERR_USER_PRESENCE_REQUIRED => Error::TouchTimeout,
        FIDO_ERR_INVALID_CREDENTIAL => Error::Other("invalid credential id".into()),
        _ => Error::Other(format!("{call}: {} ({rc})", strerr(rc))),
    }
}

/// Re-wrap an `Err` with Windows Hello-specific context when the
/// failing device was the WinHello bridge. libfido2 maps every
/// underlying WebAuthn error to FIDO_ERR_INTERNAL, leaving callers
/// with an opaque "fido_dev_make_cred: FIDO_ERR_INTERNAL" message
/// that's wrong-blame for the user (it sounds like libfido2 broke,
/// not Windows). The most common real causes when targeting
/// `winhello://`:
///   - Windows version too old for the hmac-secret extension
///     (LUKSbox needs Win 11 22H2 = build 22621, October 2022).
///   - User cancelled the Windows Hello prompt.
///   - Windows Hello not set up at all (no PIN/biometric enrolled).
///   - Camera/fingerprint hardware unavailable when only that
///     method is enrolled.
/// We don't have enough info to disambiguate, so the wrapper lists
/// all four. Better than the raw libfido2 string by a wide margin.
fn maybe_winhello_context<T>(
    device_path: &Option<CString>,
    op: &'static str,
    res: Result<T, Error>,
) -> Result<T, Error> {
    let Err(e) = &res else { return res };
    let is_winhello = device_path
        .as_ref()
        .and_then(|c| c.to_str().ok())
        .map(|s| s.starts_with("winhello://"))
        .unwrap_or(false);
    if !is_winhello {
        return res;
    }
    let raw = format!("{e}");
    if !raw.contains("FIDO_ERR_INTERNAL") && !raw.contains("internal") {
        return res;
    }
    Err(Error::Other(format!(
        "Windows Hello {op} failed (libfido2 returned FIDO_ERR_INTERNAL). \
         Common causes: \
         (a) Windows version too old, LUKSbox needs Windows 11 22H2 (build 22621, October 2022) or newer for the hmac-secret extension; \
         (b) you cancelled the Windows Hello prompt; \
         (c) Windows Hello isn't set up at all (open Settings -> Accounts -> Sign-in options to add a PIN, fingerprint, or face); \
         (d) the only enrolled method needs hardware that isn't available right now (camera covered, fingerprint reader disconnected). \
         The underlying libfido2 error: {raw}"
    )))
}

fn strerr(rc: c_int) -> String {
    unsafe {
        let p = fido_strerr(rc);
        if p.is_null() {
            return format!("libfido2 rc={rc:#x}");
        }
        CStr::from_ptr(p).to_string_lossy().into_owned()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Audit regression: an earlier version of `ffi.rs` declared
    /// `FIDO_ERR_USER_PRESENCE_REQUIRED = 0x35`, which is actually
    /// `FIDO_ERR_PIN_NOT_SET` in libfido2's `<fido/err.h>`. Symptom:
    /// a "PIN not set" reply from the authenticator was mistakenly
    /// surfaced to the user as `Error::TouchTimeout` ("touch your
    /// YubiKey"), when the actual remediation is to enroll a PIN.
    /// Lock the values down so a future copy/paste or distro-skew
    /// can't silently re-introduce the confusion.
    #[test]
    fn fido_err_constants_match_libfido2_err_h() {
        assert_eq!(FIDO_ERR_TIMEOUT, 0x05);
        assert_eq!(FIDO_ERR_INVALID_CREDENTIAL, 0x22);
        assert_eq!(FIDO_ERR_USER_ACTION_TIMEOUT, 0x2f);
        assert_eq!(FIDO_ERR_PIN_INVALID, 0x31);
        assert_eq!(FIDO_ERR_PIN_BLOCKED, 0x32);
        assert_eq!(FIDO_ERR_PIN_AUTH_INVALID, 0x33);
        assert_eq!(FIDO_ERR_PIN_NOT_SET, 0x35);
        assert_eq!(FIDO_ERR_PIN_REQUIRED, 0x36);
        assert_eq!(FIDO_ERR_USER_PRESENCE_REQUIRED, -8);
        // Ensure no constant accidentally collides with another in
        // the subset we map specially.
        let codes = [
            FIDO_ERR_TIMEOUT,
            FIDO_ERR_INVALID_CREDENTIAL,
            FIDO_ERR_USER_ACTION_TIMEOUT,
            FIDO_ERR_PIN_INVALID,
            FIDO_ERR_PIN_BLOCKED,
            FIDO_ERR_PIN_AUTH_INVALID,
            FIDO_ERR_PIN_NOT_SET,
            FIDO_ERR_PIN_REQUIRED,
            FIDO_ERR_USER_PRESENCE_REQUIRED,
        ];
        for (i, a) in codes.iter().enumerate() {
            for b in &codes[i + 1..] {
                assert_ne!(a, b, "two FIDO_ERR_* constants collided: {a} == {b}");
            }
        }
    }

    #[test]
    fn pin_not_set_maps_to_descriptive_error_not_touch_timeout() {
        let e = map_err_at("test", FIDO_ERR_PIN_NOT_SET);
        // Must NOT be TouchTimeout, that was the bug. Must contain
        // a hint about the PIN.
        match e {
            Error::TouchTimeout => panic!("PIN_NOT_SET incorrectly maps to TouchTimeout"),
            Error::Other(msg) => {
                let lower = msg.to_ascii_lowercase();
                assert!(
                    lower.contains("pin"),
                    "PIN_NOT_SET message should mention PIN, got: {msg}"
                );
            }
            other => panic!("PIN_NOT_SET maps to unexpected variant: {other:?}"),
        }
    }

    #[test]
    fn user_presence_required_maps_to_touch_timeout() {
        let e = map_err_at("test", FIDO_ERR_USER_PRESENCE_REQUIRED);
        assert!(
            matches!(e, Error::TouchTimeout),
            "USER_PRESENCE_REQUIRED should map to TouchTimeout"
        );
    }
}
