// Hardware probe for FIDO2 keyslot V3 + hmac-secret determinism.
// One enroll + three asserts:
//   - Salt A, twice  -> must produce the SAME hmac_secret (determinism)
//   - Salt B         -> must produce a DIFFERENT hmac_secret (HMAC over salt)

use luksbox_fido2::{Fido2Authenticator, HidAuthenticator, random_user_handle};

fn hexdump(b: &[u8], n: usize) -> String {
    b.iter()
        .take(n)
        .map(|x| format!("{x:02x}"))
        .collect::<Vec<_>>()
        .join("")
}

fn main() {
    println!("=== FIDO2 hardware probe ===\n");

    let devs = HidAuthenticator::detect_all().expect("detect");
    println!("Detected {} device(s):", devs.len());
    for d in &devs {
        println!("  path={:?} label={:?}", d.path, d.label);
    }

    let pin = std::env::var("LUKSBOX_FIDO2_PIN").ok();
    let mut auth = HidAuthenticator::new();
    let user = random_user_handle().expect("OS RNG");
    let rp = "luksbox.local";

    println!("\n--- ENROLL ---");
    println!("TOUCH YOUR KEY (1/4)");
    let er = auth
        .enroll(rp, &user, pin.as_deref())
        .expect("enroll failed");
    println!(
        "OK  cred_id length = {} bytes  (V3 cap = 352 B, headroom {} B)",
        er.credential.id.len(),
        352 - er.credential.id.len()
    );

    let salt_a = [0x55u8; 32];
    let salt_b = [0xaau8; 32];

    println!("\n--- ASSERT 1: salt = 0x55..55 ---");
    println!("TOUCH YOUR KEY (2/4)");
    let s_a1 = auth
        .hmac_secret(rp, &er.credential.id, &salt_a, true, pin.as_deref())
        .expect("assert A1 failed");
    println!("hmac_secret = {}", hexdump(&*s_a1, 32));

    println!("\n--- ASSERT 2: salt = 0x55..55 (same as #1) ---");
    println!("TOUCH YOUR KEY (3/4)");
    let s_a2 = auth
        .hmac_secret(rp, &er.credential.id, &salt_a, true, pin.as_deref())
        .expect("assert A2 failed");
    println!("hmac_secret = {}", hexdump(&*s_a2, 32));

    println!("\n--- ASSERT 3: salt = 0xaa..aa (different) ---");
    println!("TOUCH YOUR KEY (4/4)");
    let s_b = auth
        .hmac_secret(rp, &er.credential.id, &salt_b, true, pin.as_deref())
        .expect("assert B failed");
    println!("hmac_secret = {}", hexdump(&*s_b, 32));

    println!("\n=== Verification ===");
    let det_ok = s_a1 == s_a2;
    let var_ok = s_a1 != s_b;
    println!(
        "Determinism (same salt -> same secret): {}",
        if det_ok { "PASS" } else { "FAIL" }
    );
    println!(
        "Variability (diff salt -> diff secret): {}",
        if var_ok { "PASS" } else { "FAIL" }
    );

    if !det_ok {
        eprintln!(
            "\nWARN: same-salt asserts differ. Either the device doesn't support hmac-secret correctly, or our request is varying something between calls."
        );
    }
    if !var_ok {
        eprintln!(
            "\nWARN: different-salt asserts gave the same secret. Strongly anomalous - device might be ignoring the salt input."
        );
    }
    if det_ok && var_ok {
        println!(
            "\n  Determinism + variability both hold. LUKSbox can safely use this device's hmac-secret as keying material."
        );
    }
}
