// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Penthertz <https://penthertz.com> (https://x.com/PentHertz)

//! Keep the reasons a hardware unseal failed.
//!
//! `Container::open` treats an error from the TPM / Secure Enclave
//! unseal closure of `UnlockMaterial` as "this slot is not for this
//! machine, try the next one", and reports only `Error::UnlockFailed`
//! when none opens. That is the right control flow, but it threw away
//! the reason the user needs: a TPM in dictionary-attack lockout, a
//! substituted SRK, a cancelled Touch ID prompt, a PIN slot skipped
//! because no PIN was given. Front ends route their closure results
//! through [`UnsealErrors::record`] and word the final error with
//! [`UnsealErrors::explain`].

use std::fmt::Display;

/// Distinct error messages returned by an unseal closure, in order.
#[derive(Debug, Default)]
pub struct UnsealErrors(Vec<String>);

impl UnsealErrors {
    /// Pass `result` through, remembering its error message (once).
    pub fn record<T>(&mut self, result: Result<T, String>) -> Result<T, String> {
        if let Err(e) = &result
            && !self.0.contains(e)
        {
            self.0.push(e.clone());
        }
        result
    }

    /// `error`, followed by the recorded unseal failures if any.
    pub fn explain(&self, error: impl Display) -> String {
        if self.0.is_empty() {
            error.to_string()
        } else {
            format!("{error} ({})", self.0.join("; "))
        }
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::UnsealErrors;

    #[test]
    fn keeps_distinct_reasons_in_order() {
        let mut errs = UnsealErrors::default();
        assert_eq!(errs.explain("unlock failed"), "unlock failed");
        let _ = errs.record::<()>(Err("TPM in lockout".into()));
        let _ = errs.record::<()>(Err("TPM in lockout".into()));
        assert_eq!(errs.record(Ok(7)), Ok(7));
        let _ = errs.record::<()>(Err("PIN slot skipped".into()));
        assert_eq!(
            errs.explain("unlock failed"),
            "unlock failed (TPM in lockout; PIN slot skipped)"
        );
    }
}
