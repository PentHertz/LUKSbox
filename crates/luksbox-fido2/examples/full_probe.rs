// End-to-end FIDO2 hardware test covering:
//   A. Negative cross-device (wrong device cleanly rejected)
//   B. Tamper detection on the actual on-disk .lbx file
//   C. Real .lbx vault roundtrip via Container::create + Container::open
//
// Touch budget on Titan:
//   T1, T2: enroll + initial assert
//   T3:     fresh assert for Container::open (test C)
//   T4:     assert during tampered hmac_salt unlock attempt (test B)
//   T5:     assert during tampered wrapped_ct unlock attempt (test B)
// (Tampered cred_id and tampered aad_version trigger "unknown credential"
//  / parse failure before any device touch is needed.)
//
// 0 touches on YubiKey: it instantly returns "unknown credential" when
// asked to assert against a cred_id that wasn't enrolled on it.

use luksbox_core::{Argon2idParams, CipherSuite};
use luksbox_fido2::{Fido2Authenticator, HidAuthenticator, random_user_handle};
use luksbox_format::container::{Container, UnlockMaterial};

const RP: &str = "luksbox.local";
const SUITE: CipherSuite = CipherSuite::Aes256GcmSiv;
const TEST_KDF: Argon2idParams = Argon2idParams {
    m_cost_kib: 8,
    t_cost: 1,
    p_cost: 1,
};

fn auth_for(path: &str) -> HidAuthenticator {
    HidAuthenticator::with_device(path.to_string())
}

fn assert_for(
    label: &str,
    path: &str,
    cred: &[u8],
    salt: &[u8; 32],
    pin: Option<&str>,
) -> [u8; 32] {
    let mut a = auth_for(path);
    let h = a
        .hmac_secret(RP, cred, salt, pin)
        .unwrap_or_else(|e| panic!("{label} assert failed: {e:?}"));
    *h
}

fn pass_or_fail(passed: bool) -> &'static str {
    if passed { "PASS" } else { "FAIL" }
}

fn main() {
    println!("=== Full FIDO2 hardware integration test ===\n");

    let devs = HidAuthenticator::detect_all().expect("detect");
    let titan = devs
        .iter()
        .find(|d| d.label.to_lowercase().contains("titan"))
        .expect("Titan not plugged in")
        .path
        .clone();
    let yubikey = devs
        .iter()
        .find(|d| d.label.to_lowercase().contains("yubikey"))
        .expect("YubiKey not plugged in")
        .path
        .clone();
    println!("Titan   = {titan}");
    println!("YubiKey = {yubikey}\n");
    let pin = std::env::var("LUKSBOX_FIDO2_PIN").ok();

    // ---- Phase C1: enroll Titan + initial assert (2 touches) ----
    println!("--- Phase C1: enroll Titan + derive initial wrap-secret ---");
    let mut titan_auth = auth_for(&titan);
    let user = random_user_handle().expect("OS RNG");

    println!("TOUCH 1 (Titan)  enroll");
    let er = titan_auth
        .enroll(RP, &user, pin.as_deref())
        .expect("Titan enroll");
    let cred_id = er.credential.id.clone();
    println!("  cred_id length = {} bytes", cred_id.len());

    let salt = [0x77u8; 32];
    println!("TOUCH 2 (Titan)  assert (for vault create)");
    let secret_for_create = assert_for("Titan", &titan, &cred_id, &salt, pin.as_deref());

    // ---- Phase C2: actually create a .lbx vault on disk ----
    let tmpdir = tempfile::tempdir().expect("tempdir");
    let vault_path = tmpdir.path().join("probe.lbx");
    println!(
        "\n--- Phase C2: Container::create_with_fido2 -> {} ---",
        vault_path.display()
    );
    let _container = Container::create_with_fido2(
        &vault_path,
        None, // no detached header
        SUITE,
        TEST_KDF,
        None, // no backup passphrase
        &secret_for_create,
        &cred_id,
        salt,
    )
    .expect("Container::create_with_fido2 failed");
    drop(_container);
    let vault_size = std::fs::metadata(&vault_path).unwrap().len();
    println!(
        "  OK  vault file = {} bytes (header 8 KiB + metadata region)",
        vault_size
    );

    // ---- Phase C3: real Container::open via fresh device assert ----
    println!("\n--- Phase C3: Container::open via fresh assert (full roundtrip) ---");
    println!("TOUCH 3 (Titan)  assert (for vault open)");
    let secret_for_open = assert_for("Titan", &titan, &cred_id, &salt, pin.as_deref());
    let opened = Container::open(
        &vault_path,
        None,
        UnlockMaterial::Fido2 {
            passphrase: None,
            cred_id: &cred_id,
            hmac_secret: &secret_for_open,
        },
    );
    let test_c = match opened {
        Ok(c) => {
            println!("  OK  Container::open succeeded (header HMAC + slot AEAD verified)");
            drop(c);
            true
        }
        Err(e) => {
            println!("  FAIL  open returned: {e:?}");
            false
        }
    };

    // Sanity: same secret should re-open without re-touching the device.
    println!("  same secret -> same KEK -> same MVK; open is idempotent");
    let _ = Container::open(
        &vault_path,
        None,
        UnlockMaterial::Fido2 {
            passphrase: None,
            cred_id: &cred_id,
            hmac_secret: &secret_for_open,
        },
    )
    .expect("re-open with cached secret");

    // ---- Phase A: NEGATIVE cross-device (YubiKey asked for Titan cred) ----
    println!("\n--- Phase A: negative cross-device test ---");
    println!("(no touch expected: YubiKey rejects Titan cred_id immediately)");
    let mut yk = auth_for(&yubikey);
    let yk_attempt = yk.hmac_secret(RP, &cred_id, &salt, pin.as_deref());
    let test_a = match yk_attempt {
        Err(e) => {
            println!("  OK  YubiKey rejected: {e:?}");
            true
        }
        Ok(s) => {
            // If YubiKey somehow returned an hmac_secret value (it really
            // shouldn't, but if it did): try it as the unlock material
            // and confirm the AEAD fails.
            println!(
                "  WARN  YubiKey returned a secret ({}...): trying it against the vault",
                hex(&s[..8])
            );
            let r = Container::open(
                &vault_path,
                None,
                UnlockMaterial::Fido2 {
                    passphrase: None,
                    cred_id: &cred_id,
                    hmac_secret: &s,
                },
            );
            let aead_caught = r.is_err();
            println!(
                "  Container::open with wrong-device secret -> {}",
                if aead_caught {
                    "rejected by AEAD (expected)"
                } else {
                    "ACCEPTED (regression!)"
                }
            );
            aead_caught
        }
    };

    // ---- Phase B: TAMPER tests on the actual .lbx file ----
    println!("\n--- Phase B: on-disk tamper tests ---");
    let baseline_bytes = std::fs::read(&vault_path).expect("read vault");

    // Find slot 0 inside the header to know which bytes to flip.
    // Header layout: 256 B header header + slot 0 starts at offset 256.
    // (see crates/luksbox-core/src/header.rs)
    use luksbox_core::SLOT_SIZE;
    const SLOT_REGION_OFFSET: usize = 256;
    let slot0_offset = SLOT_REGION_OFFSET;
    println!(
        "  slot 0 spans bytes {}..{} of the vault file",
        slot0_offset,
        slot0_offset + SLOT_SIZE
    );

    // B1: cred_id byte flip (offset 128 inside the slot)
    println!("\n  B1: flip 1 byte inside cred_id (offset 128 in slot)");
    println!("  (no touch expected: device returns 'unknown credential')");
    let r_b1 = tamper_and_open(
        &vault_path,
        &baseline_bytes,
        slot0_offset + 128,
        &titan,
        &cred_id,
        &salt,
        pin.as_deref(),
    );
    let test_b1 = r_b1.is_err();
    println!(
        "    open result: {}  -> {}",
        match &r_b1 {
            Ok(_) => "OK".into(),
            Err(e) => format!("Err({e:?})"),
        },
        pass_or_fail(test_b1)
    );

    // B2: hmac_salt byte flip (offset 480 in V3 layout)
    println!("\n  B2: flip 1 byte inside hmac_salt (V3 offset 480 in slot)");
    println!("TOUCH 4 (Titan)  assert (device responds, but unwrap will fail)");
    let r_b2 = tamper_and_open(
        &vault_path,
        &baseline_bytes,
        slot0_offset + 480,
        &titan,
        &cred_id,
        &salt,
        pin.as_deref(),
    );
    let test_b2 = r_b2.is_err();
    println!(
        "    open result: {}  -> {}",
        match &r_b2 {
            Ok(_) => "OK".into(),
            Err(e) => format!("Err({e:?})"),
        },
        pass_or_fail(test_b2)
    );

    // B3: wrapped_ct byte flip (offset 76 in slot)
    println!("\n  B3: flip 1 byte inside wrapped_ct (offset 76 in slot)");
    println!("TOUCH 5 (Titan)  assert (device responds, AEAD tag will fail)");
    let r_b3 = tamper_and_open(
        &vault_path,
        &baseline_bytes,
        slot0_offset + 76,
        &titan,
        &cred_id,
        &salt,
        pin.as_deref(),
    );
    let test_b3 = r_b3.is_err();
    println!(
        "    open result: {}  -> {}",
        match &r_b3 {
            Ok(_) => "OK".into(),
            Err(e) => format!("Err({e:?})"),
        },
        pass_or_fail(test_b3)
    );

    // B4: aad_version byte flip (offset 1 in slot, V3 -> V1)
    println!("\n  B4: flip aad_version byte (offset 1 in slot, V3=2 -> V1=0)");
    println!("  (no touch expected: V1 layout reads cred_id from wrong offsets,");
    println!("   garbage cred sent to device -> 'unknown credential')");
    let mut tampered = baseline_bytes.clone();
    tampered[slot0_offset + 1] = 0; // V1
    std::fs::write(&vault_path, &tampered).expect("write tampered");
    let r_b4 = open_with_fresh_assert(&vault_path, &titan, &cred_id, &salt, pin.as_deref());
    // Restore baseline for next test.
    std::fs::write(&vault_path, &baseline_bytes).expect("restore");
    let test_b4 = r_b4.is_err();
    println!(
        "    open result: {}  -> {}",
        match &r_b4 {
            Ok(_) => "OK".into(),
            Err(e) => format!("Err({e:?})"),
        },
        pass_or_fail(test_b4)
    );

    // Sanity: after all tampering, restore baseline + reopen with fresh
    // assert to confirm we didn't accidentally corrupt the file.
    println!("\n  Sanity: baseline restored, re-open with cached secret should still work");
    let sanity = Container::open(
        &vault_path,
        None,
        UnlockMaterial::Fido2 {
            passphrase: None,
            cred_id: &cred_id,
            hmac_secret: &secret_for_open,
        },
    );
    let sanity_ok = sanity.is_ok();
    println!("    {}", pass_or_fail(sanity_ok));

    // ---- Summary ----
    println!("\n=== RESULTS ===");
    println!(
        "  C  Container roundtrip via real .lbx file:           {}",
        pass_or_fail(test_c)
    );
    println!(
        "  A  Negative cross-device (YubiKey can't open Titan): {}",
        pass_or_fail(test_a)
    );
    println!(
        "  B1 cred_id tamper rejected:                          {}",
        pass_or_fail(test_b1)
    );
    println!(
        "  B2 hmac_salt tamper rejected (V3 AAD coverage):      {}",
        pass_or_fail(test_b2)
    );
    println!(
        "  B3 wrapped_ct tamper rejected (AEAD tag):            {}",
        pass_or_fail(test_b3)
    );
    println!(
        "  B4 aad_version tamper rejected:                      {}",
        pass_or_fail(test_b4)
    );
    println!(
        "  S  Baseline integrity preserved across tampering:    {}",
        pass_or_fail(sanity_ok)
    );

    let all_pass = test_c && test_a && test_b1 && test_b2 && test_b3 && test_b4 && sanity_ok;
    println!(
        "\n  Overall: {}",
        if all_pass {
            "ALL TESTS PASS"
        } else {
            "FAILURES PRESENT"
        }
    );
    if !all_pass {
        std::process::exit(1);
    }
}

fn tamper_and_open(
    vault_path: &std::path::Path,
    baseline: &[u8],
    byte_offset: usize,
    titan_path: &str,
    cred_id: &[u8],
    salt: &[u8; 32],
    pin: Option<&str>,
) -> Result<(), String> {
    let mut tampered = baseline.to_vec();
    tampered[byte_offset] ^= 0x01;
    std::fs::write(vault_path, &tampered).expect("write tampered");
    let r = open_with_fresh_assert(vault_path, titan_path, cred_id, salt, pin);
    // Restore baseline for next test.
    std::fs::write(vault_path, baseline).expect("restore");
    r
}

fn open_with_fresh_assert(
    vault_path: &std::path::Path,
    titan_path: &str,
    cred_id: &[u8],
    salt: &[u8; 32],
    pin: Option<&str>,
) -> Result<(), String> {
    let mut auth = auth_for(titan_path);
    let secret = match auth.hmac_secret(RP, cred_id, salt, pin) {
        Ok(s) => s,
        Err(e) => return Err(format!("device assert failed: {e:?}")),
    };
    Container::open(
        vault_path,
        None,
        UnlockMaterial::Fido2 {
            passphrase: None,
            cred_id,
            hmac_secret: &secret,
        },
    )
    .map(|_| ())
    .map_err(|e| format!("{e:?}"))
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}
