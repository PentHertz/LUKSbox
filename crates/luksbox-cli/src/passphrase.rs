// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Penthertz <https://penthertz.com> (https://x.com/PentHertz)

//! Passphrase strength estimation and strong-passphrase generation.
//!
//! - **Strength**: thin wrapper around `zxcvbn`, returning a numeric score
//!   (0-4) and an estimated bits-of-entropy figure.
//! - **Generation**: 16 random base32 characters from `OsRng`, about 80 bits
//!   entropy. Copy-pasteable, no wordlist embedded.

use rand_core::{OsRng, RngCore};
use zeroize::Zeroizing;

/// zxcvbn score below which we treat the passphrase as weak. zxcvbn's
/// scoring buckets:
///   0 (<10³ guesses)  - instant
///   1 (10³-10⁶)       - online unthrottled attack feasible
///   2 (10⁶-10⁸)       - online throttled attack feasible
///   3 (10⁸-10¹⁰)      - safe against online; weak against fast offline
///   4 (>10¹⁰)         - safe against offline brute-force
/// Score 3 is the minimum we accept without warning. Argon2id stretching
/// effectively boosts the brute-force cost by another about 25 bits in practice.
pub const MIN_ACCEPTABLE_SCORE: u8 = 3;

#[derive(Debug, Clone)]
pub struct Strength {
    /// 0 (weak) -> 4 (strong) zxcvbn score.
    pub score: u8,
    /// Estimated log2 of the guess count.
    pub bits: f64,
    /// Human-readable advice, if any.
    pub feedback: Option<String>,
}

pub fn estimate(passphrase: &str) -> Strength {
    let est = zxcvbn::zxcvbn(passphrase, &[]);
    let bits = (est.guesses() as f64).log2();
    let feedback = est.feedback().map(|f| {
        let warning = f.warning().map(|w| format!("{w:?}")).unwrap_or_default();
        let suggestions: Vec<String> = f.suggestions().iter().map(|s| format!("{s:?}")).collect();
        let mut parts = Vec::new();
        if !warning.is_empty() {
            parts.push(warning);
        }
        parts.extend(suggestions);
        parts.join(", ")
    });
    Strength {
        score: u8::from(est.score()),
        bits,
        feedback,
    }
}

#[cfg(test)]
fn is_weak(passphrase: &str) -> bool {
    estimate(passphrase).score < MIN_ACCEPTABLE_SCORE
}

/// R15-H3: Argon2id memory floor (KiB) below which a NEW keyslot's cost
/// is flagged as weak: 64 MiB, the memory figure of RFC 9106's second
/// recommended option ("if much less memory is available": 64 MiB,
/// t=3). Below it a GPU / ASIC attacker running many guesses in
/// parallel is no longer memory-bound. The on-disk sanity envelope
/// (`Argon2idParams::is_sane_for_disk`) goes down to 8 KiB, which is a
/// DoS bound for parsers, not a strength recommendation.
pub const KDF_FLOOR_M_COST_KIB: u32 = 64 * 1024;

/// R15-H3: floor on total Argon2id work, memory (KiB) x passes: the same
/// RFC 9106 64 MiB / t=3 point. A large memory cost does not make up for
/// a single pass at 64 MiB, and vice versa.
pub const KDF_FLOOR_WORK: u64 = KDF_FLOOR_M_COST_KIB as u64 * 3;

/// R15-H3: one place that decides whether Argon2id parameters chosen for
/// a NEW keyslot are weak, so `create --kdf-target-time`,
/// `deniable-init --argon2-*`, the wizard's custom KDF and the
/// inherited cost of `enroll` / `update` / `rotate-mvk` all apply the
/// same bar. Returns a one-line reason, or `None` when the parameters
/// meet the floor. Every built-in preset (`interactive` and up) passes.
pub fn kdf_weakness(params: &luksbox_core::Argon2idParams) -> Option<String> {
    let work = u64::from(params.m_cost_kib) * u64::from(params.t_cost);
    if params.m_cost_kib < KDF_FLOOR_M_COST_KIB {
        Some(format!(
            "Argon2id memory cost {} KiB is below the {} MiB floor (RFC 9106)",
            params.m_cost_kib,
            KDF_FLOOR_M_COST_KIB / 1024
        ))
    } else if work < KDF_FLOOR_WORK {
        Some(format!(
            "Argon2id cost {} MiB x {} pass(es) is below the {} MiB x 3 floor (RFC 9106)",
            params.m_cost_kib / 1024,
            params.t_cost,
            KDF_FLOOR_M_COST_KIB / 1024
        ))
    } else {
        None
    }
}

/// Rough ordering of Argon2id costs (memory x passes, then memory), used
/// to pick the strongest cost already present in a vault.
pub fn kdf_work(params: &luksbox_core::Argon2idParams) -> (u64, u32) {
    (
        u64::from(params.m_cost_kib) * u64::from(params.t_cost),
        params.m_cost_kib,
    )
}

/// Length (in characters) of a generated passphrase. 20 chars x about 4.95
/// bits/char ~ 99 bits of entropy from `OsRng`. The reason for "20 not 16":
/// zxcvbn's heuristics sometimes find sub-patterns in random strings and
/// score them lower than theoretical entropy, so we keep generous headroom.
pub const GENERATED_LEN: usize = 20;

/// Generate a `GENERATED_LEN`-character passphrase from `OsRng`. The
/// alphabet excludes visually-confusable characters (no I/L/O/0/1) so
/// it's still copy-paste-friendly when read off paper or a YubiKey LED.
///
/// Returns Err on RNG failure rather than panicking. Generating a
/// passphrase is security-critical: if `/dev/urandom` is unhealthy
/// the user must know about it instead of getting a process abort.
pub fn generate() -> Result<Zeroizing<String>, String> {
    const ALPHABET: &[u8] = b"ABCDEFGHJKMNPQRSTUVWXYZ23456789";
    let mut bytes = Zeroizing::new([0u8; 32]);
    OsRng
        .try_fill_bytes(bytes.as_mut_slice())
        .map_err(|e| format!("OS RNG failure during passphrase generation: {e}"))?;
    let mut out = String::with_capacity(GENERATED_LEN);
    for &b in &bytes[..GENERATED_LEN] {
        out.push(ALPHABET[(b as usize) % ALPHABET.len()] as char);
    }
    Ok(Zeroizing::new(out))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn weak_passphrases_flagged() {
        assert!(is_weak("password"));
        assert!(is_weak("12345678"));
        assert!(is_weak("hunter2"));
    }

    #[test]
    fn long_random_passphrase_strong() {
        // base32 16-char string is about 76 bits, above threshold.
        for _ in 0..20 {
            let pp = generate().expect("OS RNG must succeed in tests");
            assert!(
                !is_weak(&pp),
                "generated passphrase should not be weak: {pp:?}"
            );
        }
    }

    #[test]
    fn generate_is_unique() {
        let a = generate().expect("OS RNG must succeed in tests");
        let b = generate().expect("OS RNG must succeed in tests");
        assert_ne!(*a, *b);
    }

    #[test]
    fn builtin_kdf_presets_meet_the_floor() {
        use luksbox_core::Argon2idParams;
        for p in [
            Argon2idParams::INTERACTIVE,
            Argon2idParams::MODERATE,
            Argon2idParams::SENSITIVE,
        ] {
            assert_eq!(kdf_weakness(&p), None, "{p:?}");
        }
        // RFC 9106's memory-constrained option is exactly on the floor.
        let rfc = Argon2idParams {
            m_cost_kib: 64 * 1024,
            t_cost: 3,
            p_cost: 4,
        };
        assert_eq!(kdf_weakness(&rfc), None);
    }

    #[test]
    fn weak_kdf_params_flagged() {
        use luksbox_core::Argon2idParams;
        // The on-disk minimum is accepted by the parsers but is no KDF.
        let tiny = Argon2idParams {
            m_cost_kib: 8,
            t_cost: 1,
            p_cost: 1,
        };
        assert!(kdf_weakness(&tiny).is_some());
        // Memory below the floor, however many passes.
        let low_mem = Argon2idParams {
            m_cost_kib: 32 * 1024,
            t_cost: 16,
            p_cost: 4,
        };
        assert!(kdf_weakness(&low_mem).is_some());
        // Enough memory, too little total work.
        let one_pass = Argon2idParams {
            m_cost_kib: 128 * 1024,
            t_cost: 1,
            p_cost: 4,
        };
        assert!(kdf_weakness(&one_pass).is_some());
    }

    #[test]
    fn kdf_work_orders_presets() {
        use luksbox_core::Argon2idParams;
        assert!(kdf_work(&Argon2idParams::SENSITIVE) > kdf_work(&Argon2idParams::MODERATE));
        assert!(kdf_work(&Argon2idParams::MODERATE) > kdf_work(&Argon2idParams::INTERACTIVE));
    }

    #[test]
    fn generate_is_expected_length() {
        for _ in 0..10 {
            let pp = generate().expect("OS RNG must succeed in tests");
            assert_eq!(pp.len(), GENERATED_LEN);
        }
    }
}
