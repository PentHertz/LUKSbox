// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Penthertz <https://penthertz.com> (https://x.com/PentHertz)

//! Windows-only `Fido2Authenticator` backed by Microsoft's WebAuthn
//! API (`webauthn.dll`).
//!
//! # Why this exists
//!
//! On Windows, libfido2's raw HID enumeration path doesn't work for
//! non-elevated processes. Since Windows 10 1903 Microsoft reserved
//! the FIDO HID device class for the WebAuthn system service:
//! `SetupDiGetClassDevs` will *enumerate* FIDO HID devices, but a
//! `CreateFile` open on them returns ERROR_ACCESS_DENIED. libfido2
//! silently drops devices it can't open, so end users see "no FIDO2
//! device found" with their YubiKey clearly plugged in. Running the
//! process elevated works around this but is hostile UX, and YubiKey
//! Authenticator / 1Password / web browsers all show that
//! non-elevated USB FIDO2 access is achievable through the right API.
//!
//! That right API is `webauthn.dll`. It's a system service that holds
//! the FIDO HID privilege on behalf of every user-mode process.
//! Calling its `WebAuthNAuthenticatorMakeCredential` /
//! `WebAuthNAuthenticatorGetAssertion` triggers Microsoft's standard
//! "Use Windows Hello, or insert your security key" prompt - which
//! transparently picks Windows Hello, USB, NFC, or BLE based on the
//! attachment hint and what's plugged in. No elevation required.
//!
//! # Architecture
//!
//! This module implements the same `Fido2Authenticator` trait as
//! `hid::HidAuthenticator` (the libfido2 path used on Linux / macOS),
//! so callers don't see Windows as special. `lib.rs` re-exports
//! `WebAuthnAuthenticator` as `HidAuthenticator` on Windows; on other
//! OSes, `HidAuthenticator` remains the libfido2-backed type.
//!
//! # Device selection
//!
//! webauthn.dll abstracts away physical-device selection: callers say
//! "platform" (Windows Hello), "cross-platform" (USB / NFC / BLE),
//! or "any" (Windows shows a picker). We map the user's
//! `--fido2-device` flag to that attachment hint:
//!
//!   - `windows://hello`, `winhello://`, etc. -> PLATFORM
//!   - `webauthn://usb`, `webauthn://cross-platform` -> CROSS_PLATFORM
//!   - anything else (or unset) -> ANY (Windows picks)
//!
//! Listing devices via `detect_all` returns three synthetic entries
//! (any, platform, cross-platform). The GUI shows them in the picker
//! exactly like libfido2 devices, so the same UX code works.

use std::ffi::c_void;
use std::ptr;

use windows::Win32::Foundation::BOOL;
use windows::Win32::Networking::WindowsWebServices::*;
use windows::Win32::UI::WindowsAndMessaging::GetForegroundWindow;
use windows_core::{HSTRING, PCWSTR};

use crate::authenticator::{Credential, EnrollResult, Fido2Authenticator, HmacSecret};
use crate::error::Error;
use crate::webauthn_paths::{
    AttachmentHint, PATH_ANY, PATH_CROSS_PLATFORM, PATH_PLATFORM, classify_device_path,
};

/// We don't use the WebAuthn challenge semantics; the `.lbx` keyslot
/// AAD already binds the wrap to the container. Pass an all-zero
/// 32-byte client-data-hash so webauthn.dll doesn't reject our calls.
const ZERO_CLIENTDATA_HASH: [u8; 32] = [0u8; 32];

/// CTAP2 spec section 6.1: `user.id` is a byte string of 0-64 bytes.
/// Anything larger is a corrupted vault header or a programming bug
/// upstream - refuse before we hand it to webauthn.dll, since the
/// FFI takes a `u32` length and silently accepts anything that fits.
const MAX_USER_HANDLE_LEN: usize = 64;

/// CTAP2 spec section 6.1 caps `credential.id` at 1023 bytes. We accept up
/// to 4 KiB on the device-output path (see `MAX_CRED_ID_FROM_DEVICE`
/// below) for vendor-extension headroom; the input-validation cap
/// here mirrors that - anything bigger means our header parser
/// produced a malformed or attacker-controlled cred_id.
const MAX_CRED_ID_INPUT_LEN: usize = 4096;

/// One enumerated FIDO2 authenticator entry. Matches the layout of
/// `hid::DeviceInfo` so the GUI / CLI device picker code can be the
/// same on every OS.
#[derive(Debug, Clone)]
pub struct DeviceInfo {
    pub path: String,
    pub label: String,
}

/// `Fido2Authenticator` impl backed by webauthn.dll. Stateless: each
/// call into `enroll` / `hmac_secret` is a fresh WebAuthn invocation
/// that triggers Windows's own UX (face / fingerprint / PIN prompt
/// for Windows Hello, "insert security key" prompt for USB, etc.).
pub struct WebAuthnAuthenticator {
    /// Attachment hint cached from `with_device`. Drives which kinds
    /// of authenticators Windows offers in its prompt.
    attachment: u32,
}

impl WebAuthnAuthenticator {
    pub fn new() -> Self {
        Self {
            attachment: WEBAUTHN_AUTHENTICATOR_ATTACHMENT_ANY,
        }
    }

    /// Bind this authenticator to a specific attachment kind by
    /// "device path". The path strings recognized:
    ///
    ///   - PATH_PLATFORM / "windows://hello" / "winhello://" /
    ///     "winhello" / "hello" -> only Windows Hello is offered
    ///   - PATH_CROSS_PLATFORM / "webauthn://usb" -> only USB / NFC /
    ///     BLE security keys are offered
    ///   - PATH_ANY / anything else -> Windows picks (default)
    ///
    /// The attachment hint is the only knob webauthn.dll exposes -
    /// you can't pin to a specific physical key by serial number.
    /// This is by design (privacy + UX consistency across apps).
    pub fn with_device(path: impl Into<String>) -> Self {
        let p = path.into();
        // Routing logic lives in the platform-agnostic
        // `webauthn_paths::classify_device_path` so it can be unit-
        // tested + fuzzed without webauthn.dll. We just translate the
        // resulting hint to the C-side WEBAUTHN_AUTHENTICATOR_ATTACHMENT_*
        // constant at the FFI boundary.
        let attachment = match classify_device_path(&p) {
            AttachmentHint::Platform => WEBAUTHN_AUTHENTICATOR_ATTACHMENT_PLATFORM,
            AttachmentHint::CrossPlatform => WEBAUTHN_AUTHENTICATOR_ATTACHMENT_CROSS_PLATFORM,
            AttachmentHint::Any => WEBAUTHN_AUTHENTICATOR_ATTACHMENT_ANY,
        };
        Self { attachment }
    }

    /// Cheap probe: `webauthn.dll` is always present on supported
    /// Windows versions, so this just confirms the API is loadable
    /// and reports a non-zero version.
    pub fn devices_present() -> Result<bool, Error> {
        let v = unsafe { WebAuthNGetApiVersionNumber() };
        Ok(v != 0)
    }

    /// Convenience for callers that just want a single label.
    pub fn detect_first() -> Result<Option<String>, Error> {
        Ok(Self::detect_all()?.into_iter().next().map(|d| d.label))
    }

    /// Return three synthetic device entries: "any", "Windows Hello"
    /// (platform), and "Security key" (cross-platform). Mirrors the
    /// libfido2 enumeration shape so the same UI code consumes both.
    /// We don't enumerate physical devices here because webauthn.dll
    /// doesn't expose that - Windows decides at prompt time which
    /// authenticator to use, based on what's plugged in.
    pub fn detect_all() -> Result<Vec<DeviceInfo>, Error> {
        if !Self::devices_present()? {
            return Ok(Vec::new());
        }
        Ok(vec![
            DeviceInfo {
                path: PATH_ANY.into(),
                label: "Windows authentication (Hello or security key)".into(),
            },
            DeviceInfo {
                path: PATH_PLATFORM.into(),
                label: "Windows Hello (face / fingerprint / PIN)".into(),
            },
            DeviceInfo {
                path: PATH_CROSS_PLATFORM.into(),
                label: "Security key (USB / NFC)".into(),
            },
        ])
    }
}

impl Default for WebAuthnAuthenticator {
    fn default() -> Self {
        Self::new()
    }
}

impl Fido2Authenticator for WebAuthnAuthenticator {
    fn enroll(
        &mut self,
        rp_id: &str,
        user_handle: &[u8],
        _pin: Option<&str>,
    ) -> Result<EnrollResult, Error> {
        // PIN is unused on Windows: webauthn.dll handles user
        // verification through its own UI (face / fingerprint / PIN
        // for Windows Hello; PIN entry for USB security keys). Asking
        // for the PIN on the CLI side is harmless but not consulted.

        // Defence-in-depth bounds check on caller-supplied byte slices.
        // CTAP2 caps user.id at 64 B (section 6.1); a larger slice means a
        // logic bug upstream or attacker-controlled input. Catching it
        // here gives a clear error message before webauthn.dll silently
        // truncates via the u32 length cast.
        if user_handle.len() > MAX_USER_HANDLE_LEN {
            return Err(Error::Other(format!(
                "user_handle is {} B; CTAP2 caps user.id at {} B",
                user_handle.len(),
                MAX_USER_HANDLE_LEN
            )));
        }
        if user_handle.is_empty() {
            return Err(Error::Other(
                "user_handle is empty; webauthn.dll requires a non-empty user.id".into(),
            ));
        }
        // rp_id is usually our compile-time `RP_ID` constant ("luksbox.local"),
        // but defence-in-depth: refuse implausibly large strings before we
        // wide-encode them. WebAuthn spec doesn't formally cap rp_id but 256 B
        // is well above any legitimate value.
        if rp_id.len() > 256 {
            return Err(Error::Other(format!(
                "rp_id is {} B; refusing - legitimate values are < 256 B",
                rp_id.len()
            )));
        }

        // Convert Rust strings -> wide strings for the Win32 API.
        // `HSTRING` keeps the underlying UTF-16 buffer alive for the
        // lifetime of the binding; PCWSTR borrows from it. Don't
        // collapse these into temporaries unless the .as_ptr() use
        // is in the same statement - see security_descriptor lifetime
        // rules in `winfsp.rs` for the analogous pattern.
        let rp_id_w = HSTRING::from(rp_id);
        let rp_name_w = HSTRING::from("luksbox");
        let user_name_w = HSTRING::from("luksbox-user");
        let user_display_w = HSTRING::from("luksbox");

        let rp_info = WEBAUTHN_RP_ENTITY_INFORMATION {
            dwVersion: WEBAUTHN_RP_ENTITY_INFORMATION_CURRENT_VERSION,
            pwszId: PCWSTR(rp_id_w.as_ptr()),
            pwszName: PCWSTR(rp_name_w.as_ptr()),
            pwszIcon: PCWSTR::null(),
        };

        let mut user_id = user_handle.to_vec();
        let user_info = WEBAUTHN_USER_ENTITY_INFORMATION {
            dwVersion: WEBAUTHN_USER_ENTITY_INFORMATION_CURRENT_VERSION,
            cbId: user_id.len() as u32,
            pbId: user_id.as_mut_ptr(),
            pwszName: PCWSTR(user_name_w.as_ptr()),
            pwszIcon: PCWSTR::null(),
            pwszDisplayName: PCWSTR(user_display_w.as_ptr()),
        };

        // Request ES256 (COSE alg -7), the same algorithm the libfido2
        // path uses (COSE_ES256). Windows Hello + every modern USB key
        // supports it; older keys that only do RS256 are out of scope.
        let mut cose_param = WEBAUTHN_COSE_CREDENTIAL_PARAMETER {
            dwVersion: WEBAUTHN_COSE_CREDENTIAL_PARAMETER_CURRENT_VERSION,
            pwszCredentialType: WEBAUTHN_CREDENTIAL_TYPE_PUBLIC_KEY,
            lAlg: -7,
        };
        let cose_creds = WEBAUTHN_COSE_CREDENTIAL_PARAMETERS {
            cCredentialParameters: 1,
            pCredentialParameters: &mut cose_param as *mut _,
        };

        let mut clientdata_buf = ZERO_CLIENTDATA_HASH;
        let client_data = WEBAUTHN_CLIENT_DATA {
            dwVersion: WEBAUTHN_CLIENT_DATA_CURRENT_VERSION,
            cbClientDataJSON: clientdata_buf.len() as u32,
            pbClientDataJSON: clientdata_buf.as_mut_ptr(),
            pwszHashAlgId: WEBAUTHN_HASH_ALGORITHM_SHA_256,
        };

        // hmac-secret extension: for makeCredential, the value is a
        // BOOL signaling "I want hmac-secret enabled on this cred".
        // We always want it (it's the entire point of LUKSbox's
        // FIDO2 keyslot scheme).
        let mut hmac_secret_enable: BOOL = BOOL(1);
        let mut hmac_ext = WEBAUTHN_EXTENSION {
            pwszExtensionIdentifier: WEBAUTHN_EXTENSIONS_IDENTIFIER_HMAC_SECRET,
            cbExtension: std::mem::size_of::<BOOL>() as u32,
            pvExtension: &mut hmac_secret_enable as *mut _ as *mut c_void,
        };
        let extensions = WEBAUTHN_EXTENSIONS {
            cExtensions: 1,
            pExtensions: &mut hmac_ext as *mut _,
        };

        let options = WEBAUTHN_AUTHENTICATOR_MAKE_CREDENTIAL_OPTIONS {
            dwVersion: WEBAUTHN_AUTHENTICATOR_MAKE_CREDENTIAL_OPTIONS_CURRENT_VERSION,
            dwTimeoutMilliseconds: 60_000,
            CredentialList: WEBAUTHN_CREDENTIALS::default(),
            Extensions: extensions,
            dwAuthenticatorAttachment: self.attachment,
            // Non-discoverable credential: cred_id is stored in the
            // .lbx vault header, not on the authenticator. Matches the
            // libfido2 path's FIDO_OPT_FALSE for resident key.
            bRequireResidentKey: BOOL(0),
            // hmac-secret REQUIRES user verification per CTAP2 spec.
            // Windows Hello / PIN-protected USB keys both satisfy this.
            dwUserVerificationRequirement: WEBAUTHN_USER_VERIFICATION_REQUIREMENT_REQUIRED,
            // We don't care about attestation: we're not verifying the
            // authenticator's identity, just deriving keying material.
            dwAttestationConveyancePreference: WEBAUTHN_ATTESTATION_CONVEYANCE_PREFERENCE_NONE,
            dwFlags: 0,
            pCancellationId: ptr::null_mut(),
            pExcludeCredentialList: ptr::null_mut(),
            dwEnterpriseAttestation: 0,
            dwLargeBlobSupport: WEBAUTHN_LARGE_BLOB_SUPPORT_NONE,
            bPreferResidentKey: BOOL(0),
            bBrowserInPrivateMode: BOOL(0),
            bEnablePrf: BOOL(0),
            pLinkedDevice: ptr::null_mut(),
            cbJsonExt: 0,
            pbJsonExt: ptr::null_mut(),
        };

        let hwnd = unsafe { GetForegroundWindow() };

        let attestation_ptr = unsafe {
            WebAuthNAuthenticatorMakeCredential(
                hwnd,
                &rp_info,
                &user_info,
                &cose_creds,
                &client_data,
                Some(&options),
            )
            .map_err(|e| {
                Error::Other(format!(
                    "WebAuthNAuthenticatorMakeCredential failed: {} (HRESULT 0x{:08X}). \
                     Common causes: user cancelled the prompt, hardware not present, \
                     PIN not set on the security key, or Windows Hello not configured. \
                     For LUKSbox FIDO2 keyslots, Windows 11 22H2+ is required for \
                     Windows Hello (the hmac-secret extension was added then).",
                    e.message(),
                    e.code().0,
                ))
            })?
        };

        if attestation_ptr.is_null() {
            return Err(Error::Other(
                "WebAuthNAuthenticatorMakeCredential returned null without error".into(),
            ));
        }

        // SAFETY: webauthn.dll just gave us a non-null pointer to a
        // WEBAUTHN_CREDENTIAL_ATTESTATION it allocated; it's valid
        // until we call WebAuthNFreeCredentialAttestation. We copy
        // the credential bytes out into a Vec before freeing.
        let cred_id = unsafe {
            let attestation = &*attestation_ptr;
            if attestation.pbCredentialId.is_null() || attestation.cbCredentialId == 0 {
                WebAuthNFreeCredentialAttestation(Some(attestation_ptr));
                return Err(Error::Other(
                    "WebAuthn returned credential attestation with empty credential id".into(),
                ));
            }
            // Defence-in-depth length cap (see hid.rs for the same
            // logic): real CTAP2 cred_ids are 16-256 B, the spec caps
            // at 1023, we accept up to 4 KiB.
            const MAX_CRED_ID_FROM_DEVICE: usize = 4096;
            let len = attestation.cbCredentialId as usize;
            if len > MAX_CRED_ID_FROM_DEVICE {
                WebAuthNFreeCredentialAttestation(Some(attestation_ptr));
                return Err(Error::Other(format!(
                    "WebAuthn returned implausibly large credential id ({len} B); \
                     refusing to allocate. Cap is {MAX_CRED_ID_FROM_DEVICE} B."
                )));
            }
            let id = std::slice::from_raw_parts(attestation.pbCredentialId, len).to_vec();
            WebAuthNFreeCredentialAttestation(Some(attestation_ptr));
            id
        };

        Ok(EnrollResult {
            credential: Credential { id: cred_id },
        })
    }

    fn hmac_secret(
        &mut self,
        rp_id: &str,
        cred_id: &[u8],
        salt: &[u8; 32],
        _pin: Option<&str>,
    ) -> Result<HmacSecret, Error> {
        // Defence-in-depth on caller-supplied bytes. cred_id comes
        // from the .lbx vault keyslot; a corrupted or tampered keyslot
        // could in principle produce a multi-MB cred_id that we'd
        // memcpy then hand to webauthn.dll's u32 length-cast field. Cap
        // before any allocation. Same numbers as the `enroll` path so
        // round-tripped values match the input bound.
        if rp_id.len() > 256 {
            return Err(Error::Other(format!(
                "rp_id is {} B; refusing - legitimate values are < 256 B",
                rp_id.len()
            )));
        }
        if cred_id.is_empty() {
            return Err(Error::Other(
                "cred_id is empty; cannot assert against an unspecified credential".into(),
            ));
        }
        if cred_id.len() > MAX_CRED_ID_INPUT_LEN {
            return Err(Error::Other(format!(
                "cred_id is {} B; refusing - CTAP2 caps cred IDs at 1023 B \
                 and we accept up to {} B for vendor-extension headroom",
                cred_id.len(),
                MAX_CRED_ID_INPUT_LEN
            )));
        }

        let rp_id_w = HSTRING::from(rp_id);

        // Allow-list with the single credential we want to assert.
        let mut cred_id_buf = cred_id.to_vec();
        let mut credential_ex = WEBAUTHN_CREDENTIAL_EX {
            dwVersion: WEBAUTHN_CREDENTIAL_EX_CURRENT_VERSION,
            cbId: cred_id_buf.len() as u32,
            pbId: cred_id_buf.as_mut_ptr(),
            pwszCredentialType: WEBAUTHN_CREDENTIAL_TYPE_PUBLIC_KEY,
            // Allow every transport - Windows picks the right one
            // based on attachment hint and what's plugged in.
            dwTransports: WEBAUTHN_CTAP_TRANSPORT_USB
                | WEBAUTHN_CTAP_TRANSPORT_NFC
                | WEBAUTHN_CTAP_TRANSPORT_BLE
                | WEBAUTHN_CTAP_TRANSPORT_INTERNAL,
        };
        let mut credential_ex_ptr: *mut WEBAUTHN_CREDENTIAL_EX = &mut credential_ex;
        let allow_list = WEBAUTHN_CREDENTIAL_LIST {
            cCredentials: 1,
            ppCredentials: &mut credential_ex_ptr,
        };

        let mut clientdata_buf = ZERO_CLIENTDATA_HASH;
        let client_data = WEBAUTHN_CLIENT_DATA {
            dwVersion: WEBAUTHN_CLIENT_DATA_CURRENT_VERSION,
            cbClientDataJSON: clientdata_buf.len() as u32,
            pbClientDataJSON: clientdata_buf.as_mut_ptr(),
            pwszHashAlgId: WEBAUTHN_HASH_ALGORITHM_SHA_256,
        };

        // hmac-secret salt for getAssertion lives on a dedicated field
        // (`pHmacSecretSaltValues`) on the OPTIONS struct, not in the
        // generic Extensions array. The Global salt applies to every
        // credential in the allow-list (we have one).
        let mut salt_buf: [u8; 32] = *salt;
        let mut hmac_salt = WEBAUTHN_HMAC_SECRET_SALT {
            cbFirst: salt_buf.len() as u32,
            pbFirst: salt_buf.as_mut_ptr(),
            cbSecond: 0,
            pbSecond: ptr::null_mut(),
        };
        let mut salt_values = WEBAUTHN_HMAC_SECRET_SALT_VALUES {
            pGlobalHmacSalt: &mut hmac_salt,
            cCredWithHmacSecretSaltList: 0,
            pCredWithHmacSecretSaltList: ptr::null_mut(),
        };

        let options = WEBAUTHN_AUTHENTICATOR_GET_ASSERTION_OPTIONS {
            dwVersion: WEBAUTHN_AUTHENTICATOR_GET_ASSERTION_OPTIONS_CURRENT_VERSION,
            dwTimeoutMilliseconds: 60_000,
            CredentialList: WEBAUTHN_CREDENTIALS::default(),
            Extensions: WEBAUTHN_EXTENSIONS::default(),
            dwAuthenticatorAttachment: self.attachment,
            dwUserVerificationRequirement: WEBAUTHN_USER_VERIFICATION_REQUIREMENT_REQUIRED,
            dwFlags: 0,
            pwszU2fAppId: PCWSTR::null(),
            pbU2fAppId: ptr::null_mut(),
            pCancellationId: ptr::null_mut(),
            pAllowCredentialList: &allow_list as *const _ as *mut _,
            dwCredLargeBlobOperation: WEBAUTHN_CRED_LARGE_BLOB_OPERATION_NONE,
            cbCredLargeBlob: 0,
            pbCredLargeBlob: ptr::null_mut(),
            pHmacSecretSaltValues: &mut salt_values,
            bBrowserInPrivateMode: BOOL(0),
            pLinkedDevice: ptr::null_mut(),
            bAutoFill: BOOL(0),
            cbJsonExt: 0,
            pbJsonExt: ptr::null_mut(),
        };

        let hwnd = unsafe { GetForegroundWindow() };

        let assertion_ptr = unsafe {
            WebAuthNAuthenticatorGetAssertion(
                hwnd,
                PCWSTR(rp_id_w.as_ptr()),
                &client_data,
                Some(&options),
            )
            .map_err(|e| {
                Error::Other(format!(
                    "WebAuthNAuthenticatorGetAssertion failed: {} (HRESULT 0x{:08X}). \
                     Common causes: user cancelled the prompt, the security key isn't \
                     plugged in, the credential was registered against a different \
                     authenticator, or the hmac-secret extension is unavailable.",
                    e.message(),
                    e.code().0,
                ))
            })?
        };

        if assertion_ptr.is_null() {
            return Err(Error::Other(
                "WebAuthNAuthenticatorGetAssertion returned null without error".into(),
            ));
        }

        // SAFETY: webauthn.dll just gave us a non-null pointer to a
        // WEBAUTHN_ASSERTION it allocated; valid until we call
        // WebAuthNFreeAssertion. We copy the 32 hmac-secret bytes
        // out before freeing.
        let secret = unsafe {
            let assertion = &*assertion_ptr;
            // The hmac-secret derived value lives in `pHmacSecret`
            // (a *mut WEBAUTHN_HMAC_SECRET_SALT, where pbFirst is the
            // 32-byte derived secret). If absent, the authenticator
            // didn't return one, treat as failure.
            if assertion.pHmacSecret.is_null() {
                WebAuthNFreeAssertion(assertion_ptr);
                return Err(Error::Other(
                    "WebAuthn assertion returned no hmac-secret value (extension may not be \
                     supported on this authenticator; for Windows Hello, requires Windows 11 22H2+)"
                        .into(),
                ));
            }
            let s = &*assertion.pHmacSecret;
            // Validate the FFI contract before trusting either pointer
            // or length. webauthn.dll's documented behaviour is that
            // `pbFirst` is a non-null pointer to `cbFirst` bytes for
            // the duration of the assertion. We additionally enforce
            // `cbFirst == 32` since hmac-secret per CTAP2 sec.6.5 is a
            // fixed 32-byte HMAC-SHA256 output.
            //
            // FFI trust note: we do not range-check `pbFirst` further
            // because webauthn.dll is part of Windows itself - same
            // trust boundary as `kernel32.dll` or `bcrypt.dll`. If
            // webauthn.dll is compromised the entire process is
            // already owned. By contrast, the libfido2-on-Linux/macOS
            // path (hid.rs) defends against compromised USB devices
            // via libfido2 and adds its own pointer-not-null check
            // because the trust boundary there is "C library +
            // attacker-controlled USB peripheral", which is weaker.
            if s.pbFirst.is_null() || s.cbFirst != 32 {
                WebAuthNFreeAssertion(assertion_ptr);
                return Err(Error::Other(format!(
                    "WebAuthn returned hmac-secret with unexpected size ({} B, expected 32)",
                    s.cbFirst
                )));
            }
            let mut out = [0u8; 32];
            std::ptr::copy_nonoverlapping(s.pbFirst, out.as_mut_ptr(), 32);
            WebAuthNFreeAssertion(assertion_ptr);
            out
        };

        // Round 12 fix R12-19: HmacSecret is now a newtype with
        // Zeroize+ZeroizeOnDrop; wrap the raw bytes once on the way
        // out so the consumer's stack copy is wiped on Drop.
        Ok(HmacSecret(secret))
    }
}

/// Generate a 16-byte random user handle. Same shape as the libfido2
/// path's `random_user_handle` so callers are unchanged.
pub fn random_user_handle() -> Result<[u8; 16], Error> {
    use rand_core::{OsRng, RngCore};
    let mut buf = [0u8; 16];
    OsRng
        .try_fill_bytes(&mut buf)
        .map_err(|e| Error::Other(format!("OS RNG failure generating user handle: {e}")))?;
    Ok(buf)
}
