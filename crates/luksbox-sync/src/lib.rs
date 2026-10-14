// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Penthertz <https://penthertz.com> (https://x.com/PentHertz)

//! luksbox-sync: sync bundles (`.lbxs`).
//!
//! A sync bundle stores a vault as immutable, individually sealed
//! objects in a folder that a cloud sync client (Dropbox, Google Drive,
//! OneDrive, iCloud Drive, Nextcloud, Syncthing...) replicates. The
//! container format underneath is unchanged; this crate only changes
//! where its bytes live, and adds an authenticated commit history on
//! top. Design and security rationale: `docs/CLOUD_SYNC_DESIGN.md` and
//! `docs/CLOUD_SYNC_IMPLEMENTATION.md`.

pub mod bundle;
pub mod cloud;
pub mod codec;
pub mod error;
#[cfg(unix)]
pub mod fs_store;
#[cfg(windows)]
#[path = "fs_store_win.rs"]
pub mod fs_store;
pub mod gc;
pub mod graph;
pub mod image;
pub mod keys;
pub mod lease;
pub mod local;
pub mod manifest;
pub mod names;
pub mod state;
pub mod store;
pub mod table;

pub use crate::error::{Result, SyncError};
