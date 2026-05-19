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
    fn generate_is_expected_length() {
        for _ in 0..10 {
            let pp = generate().expect("OS RNG must succeed in tests");
            assert_eq!(pp.len(), GENERATED_LEN);
        }
    }
}
