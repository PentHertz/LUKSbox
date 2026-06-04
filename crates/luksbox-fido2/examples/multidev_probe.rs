// Multi-device FIDO2 keyslot test on real hardware.
// Enrolls Titan + YubiKey as two slots wrapping the SAME MVK, then
// verifies each device can independently unlock and recover that MVK.
// Exercises the V3 slot layout end-to-end (288-byte Titan cred_id +
// 64-byte YubiKey cred_id in adjacent slots, on-disk roundtrip).
//
// Touch sequence (6 total):
//   T1 Titan enroll   T2 Titan assert (wrap)
//   T3 YubiKey enroll T4 YubiKey assert (wrap)
//   T5 Titan assert (unlock)
//   T6 YubiKey assert (unlock)

use luksbox_core::{
    AAD_VERSION_V3, Argon2idParams, CipherSuite, Keyslot, MasterVolumeKey, SLOT_SIZE, SlotKind,
};
use luksbox_fido2::{Fido2Authenticator, HidAuthenticator, random_user_handle};

const RP: &str = "luksbox.local";
const HEADER_SALT: [u8; 32] = [0x42; 32];
const SUITE: CipherSuite = CipherSuite::Aes256GcmSiv;
const TEST_KDF: Argon2idParams = Argon2idParams {
    m_cost_kib: 8,
    t_cost: 1,
    p_cost: 1,
};

fn auth_for(path: &str) -> HidAuthenticator {
    HidAuthenticator::with_device(path.to_string())
}

fn enroll_and_wrap(
    label: &str,
    path: &str,
    mvk: &MasterVolumeKey,
    pin: Option<&str>,
    touch_n: u32,
) -> (Keyslot, Vec<u8>) {
    println!("\n--- {label} (path={path}) ---");
    let mut auth = auth_for(path);
    let user = random_user_handle().expect("OS RNG");

    println!("TOUCH {} ({})  enroll", touch_n, label);
    let er = auth
        .enroll(RP, &user, pin)
        .unwrap_or_else(|e| panic!("{label} enroll failed: {e:?}"));
    println!("  cred_id length = {} bytes", er.credential.id.len());

    let salt = {
        let mut s = [0u8; 32];
        for (i, b) in s.iter_mut().enumerate() {
            *b = (i as u8) ^ (touch_n as u8);
        }
        s
    };

    println!("TOUCH {} ({})  assert (derive KEK)", touch_n + 1, label);
    let secret = auth
        .hmac_secret(RP, &er.credential.id, &salt, true, pin)
        .unwrap_or_else(|e| panic!("{label} assert failed: {e:?}"));

    let slot = Keyslot::new_fido2(
        SUITE,
        mvk,
        None,
        &secret,
        &er.credential.id,
        salt,
        TEST_KDF,
        &HEADER_SALT,
    )
    .unwrap_or_else(|e| panic!("{label} keyslot construction failed: {e:?}"));

    println!(
        "  slot built  aad_version={} cred_id_stored={}B salt_used=0x{:02x}{:02x}..",
        slot.aad_version,
        slot.fido2_cred_id.len(),
        salt[0],
        salt[1]
    );
    assert_eq!(slot.aad_version, AAD_VERSION_V3, "must be V3");
    assert_eq!(slot.kind as u8, SlotKind::Fido2HmacSecret as u8);
    (slot, er.credential.id)
}

fn unlock_via(
    label: &str,
    path: &str,
    slot_bytes: [u8; SLOT_SIZE],
    pin: Option<&str>,
    touch_n: u32,
) -> MasterVolumeKey {
    println!("\n--- UNLOCK via {label} ---");
    let parsed = Keyslot::from_bytes(&slot_bytes).expect("slot parse");
    println!(
        "  parsed back  kind={:?} aad_version={} cred_id={}B",
        parsed.kind,
        parsed.aad_version,
        parsed.fido2_cred_id.len()
    );

    let mut auth = auth_for(path);
    println!("TOUCH {} ({})  assert (unlock)", touch_n, label);
    let secret = auth
        .hmac_secret(
            RP,
            &parsed.fido2_cred_id,
            &parsed.fido2_hmac_salt,
            parsed.fido2_salt_prehashed(),
            pin,
        )
        .unwrap_or_else(|e| panic!("{label} unlock-assert failed: {e:?}"));

    parsed
        .unlock_fido2(SUITE, None, &secret, &HEADER_SALT)
        .unwrap_or_else(|e| panic!("{label} unwrap failed: {e:?}"))
}

fn main() {
    println!("=== Multi-device FIDO2 keyslot test (V3 layout, real hardware) ===");

    let devs = HidAuthenticator::detect_all().expect("detect");
    println!("\nDetected {} device(s):", devs.len());
    for d in &devs {
        println!("  path={}  label={}", d.path, d.label);
    }

    let titan = devs
        .iter()
        .find(|d| d.label.to_lowercase().contains("titan"))
        .expect("Titan not found - plug it in");
    let yubikey = devs
        .iter()
        .find(|d| d.label.to_lowercase().contains("yubikey"))
        .expect("YubiKey not found - plug it in");
    println!("\nUsing:");
    println!("  Titan   = {}", titan.path);
    println!("  YubiKey = {}", yubikey.path);

    let pin = std::env::var("LUKSBOX_FIDO2_PIN").ok();

    // Single random MVK that both slots will wrap.
    let mvk = MasterVolumeKey::from_bytes({
        use rand_core::{OsRng, RngCore};
        let mut k = [0u8; 32];
        OsRng.fill_bytes(&mut k);
        k
    });
    let mvk_expected = mvk.as_bytes().to_vec();
    println!(
        "\nTarget MVK (random for this run): {}",
        mvk_expected
            .iter()
            .take(16)
            .map(|b| format!("{b:02x}"))
            .collect::<String>()
    );

    // ---- Phase 1: enroll both devices, build both slots ----
    let (slot_titan, _titan_cred) = enroll_and_wrap("Titan", &titan.path, &mvk, pin.as_deref(), 1);
    let (slot_yk, _yk_cred) = enroll_and_wrap("YubiKey", &yubikey.path, &mvk, pin.as_deref(), 3);

    // Serialize both slots to the on-disk shape, then parse back.
    let slot_titan_bytes: [u8; SLOT_SIZE] = slot_titan.to_bytes();
    let slot_yk_bytes: [u8; SLOT_SIZE] = slot_yk.to_bytes();
    println!("\nBoth slots serialized to {SLOT_SIZE}-byte on-disk form.");
    println!(
        "  Titan slot[1]   (aad_version) = 0x{:02x} (V3 = 0x02)",
        slot_titan_bytes[1]
    );
    println!(
        "  YubiKey slot[1] (aad_version) = 0x{:02x} (V3 = 0x02)",
        slot_yk_bytes[1]
    );

    // ---- Phase 2: unlock from each device, verify same MVK ----
    let mvk_titan = unlock_via("Titan", &titan.path, slot_titan_bytes, pin.as_deref(), 5);
    let mvk_yk = unlock_via("YubiKey", &yubikey.path, slot_yk_bytes, pin.as_deref(), 6);

    let titan_match = mvk_titan.as_bytes() == mvk_expected.as_slice();
    let yk_match = mvk_yk.as_bytes() == mvk_expected.as_slice();
    let cross_match = mvk_titan.as_bytes() == mvk_yk.as_bytes();

    println!("\n=== RESULTS ===");
    println!(
        "  Titan-unlocked MVK   matches enrollment MVK: {}",
        if titan_match { "PASS" } else { "FAIL" }
    );
    println!(
        "  YubiKey-unlocked MVK matches enrollment MVK: {}",
        if yk_match { "PASS" } else { "FAIL" }
    );
    println!(
        "  Both devices recover IDENTICAL MVK:          {}",
        if cross_match { "PASS" } else { "FAIL" }
    );

    if titan_match && yk_match && cross_match {
        println!(
            "\n  Multi-device redundancy works on real hardware. Either physical key alone can recover the same MVK from its own keyslot. V3 layout roundtrips a 288-byte cred_id correctly through to_bytes/from_bytes/unlock."
        );
    } else {
        std::process::exit(1);
    }
}
