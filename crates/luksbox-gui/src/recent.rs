// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Penthertz <https://penthertz.com> (https://x.com/PentHertz)

//! Persistent list of recently-opened vaults. JSON file in
//! `dirs::data_dir()/luksbox/recent.json`. Best-effort; on failure we
//! silently fall back to an empty list, the GUI still works without
//! history.
//!
//! ## Permissions contract
//!
//! `recent.json` lists vault paths the user has opened, with sidecar
//! locations and capability flags (FIDO2 enrolled, hybrid-PQ present,
//! cipher choice). That's structural intelligence about the user's
//! vault inventory - not the vault keys themselves, but enough for an
//! attacker on the same multi-user host to enumerate "which files to
//! steal and which authenticator the user enrolled". So:
//!
//! - Containing directory is created mode 0700 (`secure_create_dir_all`).
//! - File itself is written mode 0600 atomically via the temp+rename
//!   helper (`atomic_secure_write`) so a crash mid-write doesn't
//!   leave a corrupt or wider-permission JSON on disk.
//!
//! On Unix `dirs::data_dir()` resolves to `$XDG_DATA_HOME` (typically
//! `~/.local/share`). That path is conventionally already user-private
//! on modern distros, but we don't rely on the conventional umask;
//! the file/dir modes here are enforced regardless.

use std::fs;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RecentVault {
    pub path: PathBuf,
    pub header_path: Option<PathBuf>,
    pub anchor_path: Option<PathBuf>,
    pub last_opened: Option<i64>,
    pub cipher: String,
    pub has_fido2: bool,
    #[serde(default)]
    pub has_hybrid_pq: bool,
    /// Whether the vault has any TPM-bound keyslot (any of
    /// `Tpm2Sealed`, `Tpm2SealedPin`, `Tpm2Fido2`, `HybridPqKemTpm2`,
    /// `HybridPqKem1024Tpm2`, `HybridPqKemTpm2Fido2`,
    /// `HybridPqKem1024Tpm2Fido2`). Defaulted for back-compat with
    /// pre-existing `recent.json` entries written without this field.
    #[serde(default)]
    pub has_tpm: bool,
}

fn store_path() -> Option<PathBuf> {
    let dir = dirs::data_dir()?.join("luksbox");
    let _ = luksbox_core::file_util::secure_create_dir_all(&dir);
    Some(dir.join("recent.json"))
}

pub fn load() -> Vec<RecentVault> {
    let Some(p) = store_path() else {
        return Vec::new();
    };
    let Ok(bytes) = fs::read(p) else {
        return Vec::new();
    };
    serde_json::from_slice(&bytes).unwrap_or_default()
}

pub fn save(list: &[RecentVault]) {
    let Some(p) = store_path() else { return };
    let Ok(bytes) = serde_json::to_vec_pretty(list) else {
        return;
    };
    let _ = luksbox_core::file_util::atomic_secure_write(&p, &bytes);
}

pub fn upsert(entry: RecentVault) {
    let mut list = load();
    list.retain(|e| e.path != entry.path);
    list.insert(0, entry);
    list.truncate(20);
    save(&list);
}

pub fn forget(path: &Path) {
    let mut list = load();
    list.retain(|e| e.path != path);
    save(&list);
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    fn mode_of(path: &Path) -> u32 {
        std::fs::metadata(path).unwrap().permissions().mode() & 0o7777
    }

    /// Asserts the recents file ends up 0600 and its containing dir
    /// 0700, regardless of process umask. Without the
    /// `secure_create_dir_all` + `atomic_secure_write` switch, a 022
    /// umask would yield 0755 / 0644.
    #[test]
    fn save_writes_file_0600_and_dir_0700_under_022_umask() {
        let tmp = tempfile::tempdir().unwrap();
        // Force a permissive umask so a non-secure helper would fail.
        unsafe {
            libc::umask(0o022);
            // SAFETY: this test mutates a process-global env var.
            // The luksbox-gui binary has no other tests that read
            // XDG_DATA_HOME, so there's no parallel-test race here.
            std::env::set_var("XDG_DATA_HOME", tmp.path());
        }

        let entry = RecentVault {
            path: PathBuf::from("/tmp/dummy.lbx"),
            header_path: None,
            anchor_path: None,
            last_opened: Some(0),
            cipher: "aes-256-gcm-siv".to_string(),
            has_fido2: false,
            has_hybrid_pq: false,
            has_tpm: false,
        };
        save(&[entry]);

        let dir = tmp.path().join("luksbox");
        let file = dir.join("recent.json");
        assert!(file.is_file(), "save should produce {}", file.display());
        assert_eq!(mode_of(&dir), 0o700, "containing dir must be 0700");
        assert_eq!(mode_of(&file), 0o600, "recent.json must be 0600");

        // Round-trip: load() reads back our entry.
        let loaded = load();
        assert_eq!(loaded.len(), 1);
        assert_eq!(loaded[0].path, PathBuf::from("/tmp/dummy.lbx"));

        unsafe {
            std::env::remove_var("XDG_DATA_HOME");
        }
    }
}
