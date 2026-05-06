// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Penthertz <https://penthertz.com> (https://x.com/PentHertz)

//! Tiny persistent preferences blob, owner-only, stored next to
//! `recent.json` under `$XDG_DATA_HOME/luksbox/preferences.json`.
//!
//! Currently holds the "user has dismissed the clipboard-history
//! warning" flag so we don't nag on every copy. Best-effort: write
//! failures are silently ignored, the user just sees the warning
//! again next session.
//!
//! Permissions contract is the same as `recent.rs` (0700 dir, 0600
//! file via `secure_create_dir_all` + `atomic_secure_write`). The flag
//! itself isn't sensitive but keeping the whole `~/.local/share/luksbox`
//! tree owner-only is the simpler invariant.

use std::fs;
use std::path::PathBuf;

use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct Preferences {
    /// True after the user has acknowledged the one-time clipboard
    /// warning. We never reset this; if the user wants to re-see the
    /// warning they can delete `preferences.json` manually.
    #[serde(default)]
    pub clipboard_warning_acknowledged: bool,
}

fn store_path() -> Option<PathBuf> {
    let dir = dirs::data_dir()?.join("luksbox");
    let _ = luksbox_core::file_util::secure_create_dir_all(&dir);
    Some(dir.join("preferences.json"))
}

pub fn load() -> Preferences {
    let Some(p) = store_path() else {
        return Preferences::default();
    };
    let Ok(bytes) = fs::read(p) else {
        return Preferences::default();
    };
    serde_json::from_slice(&bytes).unwrap_or_default()
}

pub fn save(prefs: &Preferences) {
    let Some(p) = store_path() else { return };
    let Ok(bytes) = serde_json::to_vec_pretty(prefs) else {
        return;
    };
    let _ = luksbox_core::file_util::atomic_secure_write(&p, &bytes);
}
