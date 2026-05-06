// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Penthertz <https://penthertz.com> (https://x.com/PentHertz)

use crate::error::Error;

/// Default Relying-Party ID stamped into every luksbox credential. Stable
/// across versions so re-enrollment isn't needed on upgrade.
pub const RP_ID: &str = "luksbox.local";

#[derive(Debug, Clone)]
pub struct Credential {
    pub id: Vec<u8>,
}

#[derive(Debug, Clone)]
pub struct EnrollResult {
    pub credential: Credential,
}

pub type HmacSecret = [u8; 32];

/// All operations require user presence (touch). Operations may also require
/// a PIN if the authenticator was provisioned with one.
pub trait Fido2Authenticator {
    /// Enroll a new credential with the hmac-secret extension. The returned
    /// credential id is what gets stored in a luksbox keyslot.
    fn enroll(
        &mut self,
        rp_id: &str,
        user_handle: &[u8],
        pin: Option<&str>,
    ) -> Result<EnrollResult, Error>;

    /// Compute hmac-secret(salt) for an existing credential.
    fn hmac_secret(
        &mut self,
        rp_id: &str,
        cred_id: &[u8],
        salt: &[u8; 32],
        pin: Option<&str>,
    ) -> Result<HmacSecret, Error>;
}
