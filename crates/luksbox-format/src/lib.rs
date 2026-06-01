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
pub mod sim_file;

pub use crate::container::{
    Container, FlushOp, LbxFile, UnlockMaterial, flush_op_log_snapshot, reset_flush_op_log,
    set_crash_after_mirror_for_test,
};
pub use crate::error::Error;
pub use crate::metadata::{DEFAULT_METADATA_REGION_SIZE, METADATA_OVERHEAD};
pub use crate::sim_file::{SharedSimFile, SimFile};
