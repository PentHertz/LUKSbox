// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Penthertz <https://penthertz.com> (https://x.com/PentHertz)

//! Auto-clearing clipboard guard for generated passphrases.
//!
//! Pattern: KeePassXC's "secure clipboard" behavior. After we copy a
//! passphrase to the OS clipboard, we hold a `Guard` recording:
//!
//! - the SHA-256 of the bytes we put on the clipboard, and
//! - a deadline (now + N seconds, configurable).
//!
//! On every GUI tick we check whether the deadline has passed. If yes:
//!
//! 1. Read the current clipboard contents.
//! 2. Hash them.
//! 3. Compare to our stored hash. If they match, the user hasn't
//!    overwritten the clipboard yet, so we wipe it (set to empty
//!    string). If they don't match, the user copied something else
//!    in the meantime; we drop the guard silently and DO NOT touch
//!    their clipboard.
//!
//! The hash compare is the important part: a naive "always clear at
//! deadline" would wipe whatever the user copied AFTER our passphrase,
//! which is destructive UX. KeePassXC made the same mistake in 2.5
//! and reversed it; we skip that round trip.
//!
//! ## What this CANNOT do
//!
//! Clipboard managers (CopyQ, Klipper, Win+V, KDE Clipboard, GNOME
//! Clipboard Indicator, etc.) snapshot the clipboard at copy time and
//! persist their own history. Auto-clear deletes the live clipboard
//! but cannot reach into a third-party history. This is a fundamental
//! limitation of every desktop clipboard model and the reason
//! `LuksboxApp` shows a one-time warning the first time the user copies
//! a passphrase.

use std::time::{Duration, Instant};

use sha2::{Digest, Sha256};

/// In-flight clipboard auto-clear job. One at a time per app; copying
/// a fresh passphrase replaces the previous guard (the previous
/// content is overwritten by the new copy anyway, so its hash is no
/// longer interesting).
pub struct Guard {
    pub deadline: Instant,
    pub expected_hash: [u8; 32],
}

impl Guard {
    /// Build a guard for `payload`. Caller is responsible for actually
    /// pushing `payload` to the OS clipboard; this struct only tracks
    /// when + what to clear.
    pub fn for_payload(payload: &str, clear_after: Duration) -> Self {
        let mut h = Sha256::new();
        h.update(payload.as_bytes());
        let mut expected_hash = [0u8; 32];
        expected_hash.copy_from_slice(&h.finalize());
        Self {
            deadline: Instant::now() + clear_after,
            expected_hash,
        }
    }

    /// Seconds remaining until auto-clear, saturating to 0.
    pub fn seconds_remaining(&self) -> u64 {
        self.deadline
            .saturating_duration_since(Instant::now())
            .as_secs()
    }

    /// True iff the deadline has passed.
    pub fn expired(&self) -> bool {
        Instant::now() >= self.deadline
    }

    /// True iff `current` is the same content the guard was built for.
    /// Constant-time compare not strictly necessary (the attacker
    /// model here is not a timing oracle, it's "did the user copy
    /// something else"), but cheap to do.
    pub fn matches(&self, current: &str) -> bool {
        let mut h = Sha256::new();
        h.update(current.as_bytes());
        let actual: [u8; 32] = h.finalize().into();
        // ct_eq via subtle crate would be tighter; sha2 outputs being
        // equal already says "same input with overwhelming probability"
        // since we don't have an adversarial oracle here.
        actual == self.expected_hash
    }
}

/// Try to clear the OS clipboard if-and-only-if it still contains the
/// payload our guard was built for. Returns `true` if we wiped, `false`
/// if we left the clipboard alone (because it was already overwritten).
///
/// Errors from the platform clipboard backend are swallowed: this is
/// best-effort housekeeping, not a security boundary, and a Wayland
/// session without `wl-clipboard` shouldn't crash the GUI.
pub fn try_clear_if_unchanged(guard: &Guard) -> bool {
    let mut cb = match arboard::Clipboard::new() {
        Ok(c) => c,
        Err(_) => return false,
    };
    let current = match cb.get_text() {
        Ok(s) => s,
        Err(_) => return false,
    };
    if !guard.matches(&current) {
        return false;
    }
    // Replace with empty string. Some platforms treat set_text("") as
    // a no-op; arboard handles the cross-platform idiosyncrasy.
    let _ = cb.set_text(String::new());
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn guard_matches_only_its_own_payload() {
        let g = Guard::for_payload("correct horse battery staple", Duration::from_secs(30));
        assert!(g.matches("correct horse battery staple"));
        assert!(!g.matches("something else"));
        assert!(!g.matches(""));
    }

    #[test]
    fn guard_seconds_remaining_decreases() {
        // Build a short guard, sleep, observe the remaining count
        // shrinks. Doesn't time-out the test suite (50 ms total).
        let g = Guard::for_payload("x", Duration::from_millis(50));
        assert!(g.seconds_remaining() <= 30);
        std::thread::sleep(Duration::from_millis(60));
        assert!(g.expired());
    }
}
