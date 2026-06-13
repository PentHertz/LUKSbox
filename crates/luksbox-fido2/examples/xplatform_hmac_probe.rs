// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Penthertz <https://penthertz.com> (https://x.com/PentHertz)

//! Cross-platform FIDO2 hmac-secret salt-convention probe.
//!
//! Determines EXACTLY what salt the platform hands to the
//! authenticator's CTAP2 hmac-secret extension, so we can tell why a
//! V4 keyslot created on Linux fails to open on Windows (or vice
//! versa) with `crypto: keyslot authentication failed`.
//!
//! Background: a V4 keyslot's KEK derives from
//! `HMAC-SHA256(CredRandom, device_salt)`. For Linux and Windows to
//! agree, the bytes the authenticator hashes (`device_salt`) must be
//! identical on both. Linux (libfido2) lets us choose `device_salt`
//! exactly. Windows (webauthn.dll) applies its OWN transform `T` to
//! the salt we pass and we cannot read `T` directly -- so we measure
//! it: enroll one throwaway credential, then compare the device's
//! hmac-secret output across the candidate transforms.
//!
//! HOW TO RUN (same physical authenticator on both machines):
//!   1. Linux / macOS:
//!        cargo run -p luksbox-fido2 --features hardware \
//!          --example xplatform_hmac_probe
//!      Touch the key when prompted. It prints a `PROBE_CRED_ID=` line
//!      plus three outputs A / B / C.
//!   2. Windows (same key plugged in), using the printed cred id:
//!        $env:PROBE_CRED_ID="<hex from step 1>"
//!        cargo run -p luksbox-fido2 --features hardware \
//!          --example xplatform_hmac_probe
//!      It prints output W.
//!   3. Whichever of A / B / C equals W identifies Windows' transform:
//!        W == A  -> Windows passes the salt RAW (no hash). Fix: V4
//!                   must NOT prehash on Linux (raw salt on both).
//!        W == B  -> Windows does plain SHA-256(salt). The current fix
//!                   is correct and the bug is elsewhere -- report back.
//!        W == C  -> Windows does SHA-256("WebAuthn PRF"\0 || salt)
//!                   (the W3C PRF prefix). Fix: Linux V4 must hash with
//!                   that same prefix before sending to libfido2.
//!
//! SECURITY NOTE: this prints raw hmac-secret bytes for a THROWAWAY
//! credential and a fixed public salt. Use a test key / test
//! credential; don't paste the output anywhere tied to a real vault.

use luksbox_fido2::{Fido2Authenticator, HidAuthenticator, RP_ID, random_user_handle};

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn decode_hex(s: &str) -> Option<Vec<u8>> {
    if s.len() % 2 != 0 {
        return None;
    }
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).ok())
        .collect()
}

// W3C WebAuthn Level 3 PRF -> CTAP2 hmac-secret salt derivation.
// Only used on the libfido2 side (candidate C); dead on Windows.
#[allow(dead_code)]
fn prf_prefixed(salt: &[u8; 32]) -> [u8; 32] {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(b"WebAuthn PRF");
    h.update([0x00]);
    h.update(salt);
    let mut out = [0u8; 32];
    out.copy_from_slice(&h.finalize());
    out
}

fn main() {
    let pin = std::env::var("LUKSBOX_FIDO2_PIN").ok();
    let mut auth = HidAuthenticator::new();

    // Fixed, public probe salt so both machines use identical input.
    let salt = [0x42u8; 32];

    // Reuse one credential across machines: enroll on the first run,
    // carry the printed cred id to the other machine via PROBE_CRED_ID.
    let cred_id: Vec<u8> = match std::env::var("PROBE_CRED_ID") {
        Ok(h) if !h.trim().is_empty() => {
            decode_hex(h.trim()).expect("PROBE_CRED_ID must be valid hex")
        }
        _ => {
            eprintln!("No PROBE_CRED_ID set: enrolling a throwaway credential.");
            eprintln!("TOUCH YOUR KEY to enroll...");
            let user = random_user_handle().expect("OS RNG");
            let er = auth
                .enroll(RP_ID, &user, pin.as_deref())
                .expect("enroll failed");
            er.credential.id
        }
    };
    println!("PROBE_CRED_ID={}", hex(&cred_id));
    println!("salt=42..42 (32 bytes)");
    println!("platform={}", std::env::consts::OS);

    #[cfg(not(target_os = "windows"))]
    {
        // libfido2: we control device_salt exactly. prehash=false ->
        // device sees the bytes verbatim; prehash=true -> device sees
        // SHA-256(salt) (the V4 unlock path).
        eprintln!("TOUCH for A (raw salt)...");
        let a = auth
            .hmac_secret(RP_ID, &cred_id, &salt, false, pin.as_deref())
            .expect("assert A");
        eprintln!("TOUCH for B (sha256 salt = the V4 unlock path)...");
        let b = auth
            .hmac_secret(RP_ID, &cred_id, &salt, true, pin.as_deref())
            .expect("assert B");
        let prefixed = prf_prefixed(&salt);
        eprintln!("TOUCH for C (sha256 of WebAuthn-PRF-prefixed salt)...");
        let c = auth
            .hmac_secret(RP_ID, &cred_id, &prefixed, false, pin.as_deref())
            .expect("assert C");
        println!("A_raw          = {}", hex(&*a));
        println!("B_sha256       = {}", hex(&*b));
        println!("C_prf_prefixed = {}", hex(&*c));
        println!();
        println!("Now run this on Windows with PROBE_CRED_ID set to the value above.");
        println!("Whichever of A/B/C equals Windows' W identifies the transform");
        println!("(see this file's header comment for what each outcome means).");
    }

    #[cfg(target_os = "windows")]
    {
        // webauthn.dll applies its own transform T to `salt`.
        // prehash=false is rejected by the webauthn backend, so use
        // true -- the real V4 unlock path.
        eprintln!("TOUCH / Windows Hello for W...");
        let w = auth
            .hmac_secret(RP_ID, &cred_id, &salt, true, pin.as_deref())
            .expect("assert W");
        println!("W_windows      = {}", hex(&*w));
        println!();
        println!("Compare W_windows to the A/B/C printed by the Linux run.");
    }
}
