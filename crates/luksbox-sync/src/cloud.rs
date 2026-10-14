// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Penthertz <https://penthertz.com> (https://x.com/PentHertz)

//! Single-file vaults in a cloud-synced folder (phase 0 of
//! `docs/CLOUD_SYNC_DESIGN.md`): recognising such a folder, and the
//! conflict copies sync clients make of a vault, so the front ends can
//! warn and suggest a sync bundle or `luksbox merge`; and the automatic
//! per-device rollback anchor for such a vault.
//!
//! The folder and copy recognition are heuristics: they decide what to
//! *say*, and whether this device keeps an anchor, never what to trust.

use std::path::{Path, PathBuf};

use luksbox_format::Container;
use luksbox_vfs::Vfs;
use sha2::{Digest, Sha256};

/// Set (to anything but `0`) to open vaults in cloud folders without the
/// automatic anchor.
pub const NO_AUTO_ANCHOR_ENV: &str = "LUKSBOX_NO_AUTO_ANCHOR";

/// The sync service a path appears to live under, if any.
pub fn cloud_service(path: &Path) -> Option<&'static str> {
    let abs = std::path::absolute(path).ok()?;
    let lower = abs.to_string_lossy().to_lowercase();
    let comps: Vec<String> = abs
        .components()
        .map(|c| c.as_os_str().to_string_lossy().to_lowercase())
        .collect();
    // macOS File Provider locations (Dropbox, Google Drive, OneDrive,
    // Box, ...) and iCloud Drive.
    if lower.contains("/library/cloudstorage/") {
        for (needle, name) in [
            ("dropbox", "Dropbox"),
            ("googledrive", "Google Drive"),
            ("onedrive", "OneDrive"),
            ("box", "Box"),
        ] {
            if lower.contains(&format!("/library/cloudstorage/{needle}")) {
                return Some(name);
            }
        }
        return Some("a cloud storage provider");
    }
    if lower.contains("/library/mobile documents/com~apple~clouddocs") {
        return Some("iCloud Drive");
    }
    for c in &comps {
        let c = c.as_str();
        if c == "dropbox" || c.starts_with("dropbox (") {
            return Some("Dropbox");
        }
        if c == "onedrive" || c.starts_with("onedrive - ") {
            return Some("OneDrive");
        }
        if c == "my drive" || c == "google drive" || c == "googledrive" {
            return Some("Google Drive");
        }
        if c == "nextcloud" || c == "owncloud" {
            return Some("Nextcloud");
        }
        if c == "icloud drive" || c == "iclouddrive" {
            return Some("iCloud Drive");
        }
    }
    // Marker files sync clients keep in the folders they manage.
    let mut dir = abs.parent();
    while let Some(d) = dir {
        if d.join(".dropbox").exists() || d.join(".dropbox.cache").exists() {
            return Some("Dropbox");
        }
        if d.join(".stfolder").exists() {
            return Some("Syncthing");
        }
        if d.join(".sync_").exists() || d.join(".owncloudsync.log").exists() {
            return Some("Nextcloud");
        }
        dir = d.parent();
    }
    None
}

/// Copies a sync client made of `vault` next to it after a conflict:
/// Dropbox `name (… conflicted copy …).lbx`, Google Drive `name (1).lbx`,
/// OneDrive `name-<PC>.lbx`, Syncthing `name.sync-conflict-….lbx`,
/// Nextcloud `name (conflicted copy …).lbx`, iCloud `name 2.lbx`.
pub fn conflict_copies(vault: &Path) -> Vec<PathBuf> {
    let (Some(dir), Some(stem), ext) = (
        vault
            .parent()
            .filter(|p| !p.as_os_str().is_empty())
            .or(Some(Path::new("."))),
        vault.file_stem().and_then(|s| s.to_str()),
        vault.extension().and_then(|e| e.to_str()).unwrap_or(""),
    ) else {
        return Vec::new();
    };
    let Ok(rd) = std::fs::read_dir(dir) else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for e in rd.flatten() {
        let name = e.file_name();
        let Some(name) = name.to_str() else { continue };
        let p = dir.join(name);
        if p == vault {
            continue;
        }
        let (n_stem, n_ext) = match name.rsplit_once('.') {
            Some((s, x)) => (s, x),
            None => (name, ""),
        };
        if n_ext != ext {
            continue;
        }
        let Some(rest) = n_stem.strip_prefix(stem) else {
            continue;
        };
        let lower = rest.to_lowercase();
        let looks = lower.contains("conflicted copy")
            || lower.contains("conflict")
            // Our own rescue copy (`Vfs::rescue_if_replaced`).
            || lower.starts_with(" (unsaved changes ")
            || lower.starts_with(".sync-conflict-")
            || (rest.starts_with(" (") && rest.ends_with(')') && rest[2..rest.len() - 1].chars().all(|c| c.is_ascii_digit()))
            || (rest.starts_with(' ') && rest[1..].chars().all(|c| c.is_ascii_digit()) && rest.len() > 1)
            || (rest.starts_with('-') && rest.len() > 1 && !rest[1..].contains(' ') && rest[1..].chars().all(|c| c.is_ascii_alphanumeric() || c == '-'));
        if looks {
            out.push(p);
        }
    }
    out.sort();
    out
}

/// The automatic anchor attached by [`attach_auto_anchor`].
#[derive(Debug, Clone)]
pub struct AutoAnchor {
    pub path: PathBuf,
    /// The sync service the vault's folder belongs to.
    pub service: &'static str,
    /// Created by this open: the first time this device opens the vault
    /// at this path, trusted as found.
    pub created: bool,
}

/// The anchor file for `vault` in `anchors_dir`: one per vault (header
/// salt) and path, so a copy of the vault elsewhere (a conflict copy, a
/// merge result) gets its own instead of being refused against this
/// one's history.
pub fn auto_anchor_file(anchors_dir: &Path, vault: &Path, header_salt: &[u8; 32]) -> PathBuf {
    let p = std::fs::canonicalize(vault)
        .or_else(|_| std::path::absolute(vault))
        .unwrap_or_else(|_| vault.to_path_buf());
    let mut h = Sha256::new();
    h.update(b"lbx:auto-anchor/v1\0");
    h.update(header_salt);
    #[cfg(unix)]
    {
        use std::os::unix::ffi::OsStrExt;
        h.update(p.as_os_str().as_bytes());
    }
    #[cfg(windows)]
    {
        use std::os::windows::ffi::OsStrExt;
        for u in p.as_os_str().encode_wide() {
            h.update(u.to_le_bytes());
        }
    }
    let d: [u8; 32] = h.finalize().into();
    anchors_dir.join(format!("{}.anchor", crate::names::to_hex(&d)))
}

fn env_opt_out() -> bool {
    std::env::var_os(NO_AUTO_ANCHOR_ENV).is_some_and(|v| !v.is_empty() && v != "0")
}

/// Phase 0, item 4: for a single-file vault in a cloud folder, opened
/// without an anchor of its own, keep one in this device's app data
/// (`anchors_dir`). Verifies it (the header half of rollback detection,
/// inside `Container::set_anchor`), or creates it on the first open.
/// [`settle_auto_anchor`] does the metadata half once the vault is open.
/// Not for deniable vaults (an anchor named after the vault would
/// betray one) nor sync bundles (they keep their own state).
pub fn attach_auto_anchor(
    cont: &mut Container,
    anchors_dir: &Path,
) -> Result<Option<AutoAnchor>, String> {
    if cont.anchor_path().is_some() || cont.is_deniable() || cont.is_external() || env_opt_out() {
        return Ok(None);
    }
    let vault = cont.vault_path().to_path_buf();
    let Some(service) = cloud_service(&vault) else {
        return Ok(None);
    };
    let path = auto_anchor_file(anchors_dir, &vault, cont.header_salt());
    if std::fs::symlink_metadata(&path).is_ok() {
        return match cont.set_anchor(Some(path.clone())) {
            Ok(_) => Ok(Some(AutoAnchor {
                path,
                service,
                created: false,
            })),
            Err(luksbox_format::Error::HeaderRollbackDetected {
                anchor_header_gen,
                header_gen,
            }) => Err(format!(
                "ROLLBACK DETECTED: this device has already seen keyslot table generation \
                 {anchor_header_gen} of this vault, but the file in the {service} folder has \
                 generation {header_gen} (older). An older keyslot table can bring back a \
                 revoked passphrase or key. {} Refusing to open. To accept this copy as it is, \
                 delete {} (or set {NO_AUTO_ANCHOR_ENV}=1).",
                restore_hint(&vault, service),
                path.display()
            )),
            Err(e) => Err(format!(
                "this device's rollback anchor for this vault ({}) does not verify ({e}). \
                 Either the master key was rotated on another device (then delete that file \
                 and open again), or the {service} folder holds a copy from before such a \
                 rotation. To open without it, set {NO_AUTO_ANCHOR_ENV}=1.",
                path.display()
            )),
        };
    }
    std::fs::create_dir_all(anchors_dir).map_err(|e| anchor_dir_err(anchors_dir, &e))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(anchors_dir, std::fs::Permissions::from_mode(0o700))
            .map_err(|e| anchor_dir_err(anchors_dir, &e))?;
    }
    // Generation 0 for now: the metadata generation is only known once
    // the vault is open, and `settle_auto_anchor` moves it there.
    cont.init_anchor(path.clone(), 0).map_err(|e| {
        format!(
            "cannot create this device's rollback anchor {} ({e}); set {NO_AUTO_ANCHOR_ENV}=1 \
             to open without it",
            path.display()
        )
    })?;
    Ok(Some(AutoAnchor {
        path,
        service,
        created: true,
    }))
}

fn anchor_dir_err(dir: &Path, e: &std::io::Error) -> String {
    format!(
        "cannot prepare {} for this device's rollback anchors ({e}); set {NO_AUTO_ANCHOR_ENV}=1 \
         to open without them",
        dir.display()
    )
}

fn restore_hint(vault: &Path, service: &str) -> String {
    let copies = conflict_copies(vault);
    let mut s = format!(
        "Either {service} kept an older copy after a sync conflict, or restored an old \
         version, or someone put an old copy back."
    );
    if !copies.is_empty() {
        s.push_str(" Copies next to the vault that may hold the newer changes: ");
        s.push_str(
            &copies
                .iter()
                .map(|p| {
                    format!(
                        "\"{}\"",
                        p.file_name().unwrap_or_default().to_string_lossy()
                    )
                })
                .collect::<Vec<_>>()
                .join(", "),
        );
        s.push_str("; merge them with `luksbox merge`.");
    }
    s
}

/// Whether the vault's anchor is an automatic one (kept in `anchors_dir`).
pub fn is_auto_anchor(cont: &Container, anchors_dir: &Path) -> bool {
    cont.anchor_path()
        .is_some_and(|p| p.parent() == Some(anchors_dir))
}

/// The metadata half for an automatic anchor, once the vault is open:
/// refuse a vault older than what this device has seen; move the anchor
/// forward to a newer one (written by another device, which is normal
/// for a vault in a cloud folder). No-op for any other anchor.
pub fn settle_auto_anchor(vfs: &mut Vfs, anchors_dir: &Path) -> Result<(), String> {
    if !is_auto_anchor(vfs.container(), anchors_dir) {
        return Ok(());
    }
    let Some(seen) = vfs.container().anchored_metadata_generation() else {
        return Ok(());
    };
    let now = vfs.vault_generation();
    if seen > now {
        let vault = vfs.container().vault_path().to_path_buf();
        let service = cloud_service(&vault).unwrap_or("sync");
        let anchor = vfs
            .container()
            .anchor_path()
            .map(|p| p.display().to_string())
            .unwrap_or_default();
        return Err(format!(
            "ROLLBACK DETECTED: this device has already seen generation {seen} of this vault, \
             but the file in the {service} folder is at generation {now} (older). {} Refusing \
             to open. To accept this copy as it is, delete {anchor} (or set \
             {NO_AUTO_ANCHOR_ENV}=1).",
            restore_hint(&vault, service)
        ));
    }
    if seen < now {
        vfs.container_mut()
            .write_anchor(now)
            .map_err(|e| format!("cannot update this device's rollback anchor: {e}"))?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn recognises_cloud_folders() {
        assert_eq!(
            cloud_service(Path::new("/home/a/Dropbox/v.lbx")),
            Some("Dropbox")
        );
        assert_eq!(
            cloud_service(Path::new(
                "/Users/a/Library/CloudStorage/GoogleDrive-a@b.c/My Drive/v.lbx"
            )),
            Some("Google Drive")
        );
        assert_eq!(
            cloud_service(Path::new(
                "/Users/a/Library/Mobile Documents/com~apple~CloudDocs/v.lbx"
            )),
            Some("iCloud Drive")
        );
        assert_eq!(
            cloud_service(Path::new("/home/a/OneDrive - Contoso/v.lbx")),
            Some("OneDrive")
        );
        assert_eq!(cloud_service(Path::new("/home/a/documents/v.lbx")), None);
    }

    #[test]
    fn finds_conflict_copies() {
        let d = tempfile::tempdir().unwrap();
        let v = d.path().join("vault.lbx");
        for n in [
            "vault.lbx",
            "vault (Laptop's conflicted copy 2026-10-13).lbx",
            "vault (1).lbx",
            "vault-DESKTOP-AB12.lbx",
            "vault.sync-conflict-20261013-101010-ABCDEFG.lbx",
            "vault 2.lbx",
            "vault.lbx.meta-bak",
            "vault2.lbx",
            "other.lbx",
            "vault (copy for Bob).lbx",
            "vault (unsaved changes 1791880000).lbx",
        ] {
            std::fs::write(d.path().join(n), b"x").unwrap();
        }
        let found: Vec<String> = conflict_copies(&v)
            .iter()
            .map(|p| p.file_name().unwrap().to_string_lossy().to_string())
            .collect();
        assert_eq!(found.len(), 6, "{found:?}");
        assert!(
            !found
                .iter()
                .any(|f| f == "vault2.lbx" || f == "other.lbx" || f.ends_with("meta-bak"))
        );
    }
}
