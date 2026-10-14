// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Penthertz <https://penthertz.com> (https://x.com/PentHertz)

//! luksbox-format, on-disk I/O for `.lbx` containers.
//!
//! File layout:
//! ```text
//! [ 0 .. 8192          ]   Header (luksbox-core)
//! [ 8192 .. data_off   ]   Encrypted metadata region (1 MiB by default)
//! [ data_off ..        ]   File-data area (chunked AEAD; managed by luksbox-vfs)
//! ```

pub mod anchor;
pub mod container;
pub mod deniable_header;
pub mod error;
pub mod hybrid_sidecar;
pub mod metadata;
#[cfg(feature = "test-injection")]
pub mod sim_file;
pub mod unseal_errors;

pub use crate::container::{Container, HeaderStore, LbxFile, UnlockMaterial};
pub use crate::error::Error;
pub use crate::metadata::{DEFAULT_METADATA_REGION_SIZE, METADATA_OVERHEAD};
pub use crate::unseal_errors::UnsealErrors;

/// Space available to the current user on the disk holding `path` (an
/// existing file or directory), for size settings that offer or warn
/// about it.
pub fn available_disk_space(path: &std::path::Path) -> std::io::Result<u64> {
    fs2::available_space(path)
}

// Test-injection surface (feature-gated). Compiled out of release
// builds entirely; only callers that opt in via [dev-dependencies]
// with `features = ["test-injection"]` see these.
#[cfg(feature = "test-injection")]
pub use crate::container::{
    FlushOp, flush_op_log_snapshot, reset_flush_op_log, set_crash_after_mirror_for_test,
};
#[cfg(feature = "test-injection")]
pub use crate::sim_file::{SharedSimFile, SimFile};
