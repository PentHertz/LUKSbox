// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Penthertz <https://penthertz.com> (https://x.com/PentHertz)

use thiserror::Error;

#[derive(Debug, Error)]
pub enum SyncError {
    #[error("io: {0}")]
    Io(#[from] std::io::Error),

    #[error("vault: {0}")]
    Format(#[from] luksbox_format::Error),

    #[error("crypto: {0}")]
    Crypto(#[from] luksbox_core::Error),

    /// Something in the bundle folder is not what a bundle may contain
    /// (a link, a FIFO, a file of the wrong size, a name outside the
    /// grammar where one was required). The folder is written by the
    /// sync client on the provider's behalf, so this is treated as
    /// hostile input and refused, never followed or "repaired".
    #[error("refused {what} in the bundle: {why}")]
    Refused { what: String, why: &'static str },

    /// An object's key commitment or AEAD tag did not verify: it was
    /// modified, truncated, moved, or does not belong to this bundle.
    #[error("object {name} failed authentication")]
    ObjectAuth { name: String },

    /// An object authenticated but its content breaks the format
    /// (bad framing, non-zero padding, a value out of range). Only an
    /// MVK holder can produce one, so this indicates a bug or a
    /// misbehaving device, not the provider.
    #[error("object {name} is malformed: {why}")]
    Malformed { name: String, why: &'static str },

    /// A hard limit protecting memory and time was reached (too many
    /// objects listed, a manifest too large). A flooded folder is a
    /// denial of service, reported as such.
    #[error("limit reached: {0}")]
    Limit(&'static str),

    /// `create_new` found an object with the same name and different
    /// bytes. Names are random 256-bit ids, so this is never an
    /// accident.
    #[error("an object named {name} already exists with different content")]
    Collision { name: String },

    #[error("not a sync bundle: {0}")]
    NotABundle(String),

    /// A device's history is older than what this device already saw.
    #[error(
        "rollback detected: this device saw commit {seen} from {device}, \
         the bundle now shows {visible}"
    )]
    RollbackDetected {
        device: String,
        seen: u64,
        visible: u64,
    },

    /// Two different commits claim the same device and sequence number.
    #[error(
        "two different commits claim to be commit {seq} of device {device}: \
         two installations share one device identity, or a former key \
         holder is writing"
    )]
    Equivocation { device: String, seq: u64 },

    /// A verified commit says it saw history that the bundle does not
    /// contain: one device's commits are being hidden from another.
    #[error(
        "commits are being withheld: a verified commit saw commit {expected} \
         from {device}, the bundle only shows {visible}"
    )]
    WithholdingDetected {
        device: String,
        expected: u64,
        visible: u64,
    },

    /// A commit refers to a parent that is not in the bundle (yet).
    #[error("commit {seq} of device {device} is missing from the bundle")]
    MissingHistory { device: String, seq: u64 },

    /// This device's own history in the bundle is ahead of its local
    /// state: another installation is using the same device identity.
    #[error(
        "another installation is using this device's identity (copied \
         profile or restored backup); this device takes a new identity"
    )]
    IdentityConflict,

    /// The credential opens an older header but not the one the newest
    /// commit names.
    #[error("this credential was revoked (keyslot table generation {since_generation})")]
    CredentialRevoked { since_generation: u64 },

    /// The bundle folder at this path held a different vault before.
    #[error(
        "this folder held a different sync bundle the last time this device \
         opened it"
    )]
    BundleReplaced,

    /// No commit has all of its objects present yet.
    #[error("no complete commit in the bundle yet ({pending} still arriving)")]
    NothingComplete { pending: usize },

    #[error("{0}")]
    Unsupported(&'static str),

    #[error("the bundle is open read-only")]
    ReadOnly,
}

pub type Result<T> = std::result::Result<T, SyncError>;
