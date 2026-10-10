// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Penthertz <https://penthertz.com> (https://x.com/PentHertz)

use thiserror::Error;

#[derive(Debug, Error)]
pub enum Error {
    #[error("authenticator returned no hmac-secret extension data")]
    NoHmacSecret,

    #[error("invalid credential id length: {0}")]
    InvalidCredId(usize),

    #[error("PIN required")]
    PinRequired,

    #[error("PIN incorrect")]
    PinIncorrect,

    #[error("FIDO2 PIN is blocked, reset the FIDO app")]
    PinBlocked,

    #[error("user touch timeout")]
    TouchTimeout,

    #[error("ECDH key agreement failed")]
    KeyAgreement,

    #[error("AES-CBC error")]
    AesCbc,

    #[error("HMAC verification failed")]
    HmacVerify,

    #[error("hardware authenticator not implemented (transport layer pending)")]
    NotImplemented,

    #[error("authenticator error: {0}")]
    Other(String),
}

impl Error {
    /// The PIN was rejected or is blocked. A caller walking several
    /// keyslots must stop instead of presenting the same PIN to the
    /// next credential: every wrong-PIN attempt uses up one of the
    /// authenticator's PIN retries (8, then the PIN is blocked).
    pub fn is_pin_failure(&self) -> bool {
        matches!(self, Self::PinIncorrect | Self::PinBlocked)
    }
}
