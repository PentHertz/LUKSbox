// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Penthertz <https://penthertz.com> (https://x.com/PentHertz)

//! Filesystem helpers for creating files that hold encrypted material.
//!
//! Round 9E (audit follow-up) introduced these helpers to enforce a
//! single permission contract for every file LUKSbox writes:
//!
//!   **Owner-only (mode 0600 on POSIX) regardless of user umask.**
//!
//! Why: the user's `umask` on most Linux distros defaults to `022`,
//! which yields world-readable files. The `.lbx` / `.hdr` / `.kyber`
//! / `.hybrid` / `.anchor` files all hold material an offline
//! attacker could use:
//!
//! - `.lbx` / `.hdr`: wrapped MVK ciphertext, KDF salt, AEAD nonce.
//!   A reader can offline-brute-force the passphrase keyslot, rate-
//!   limited by Argon2id (about 2 g/s on commodity CPUs at our
//!   defaults). Even though it's encrypted, restricting access to
//!   the owner removes the offline-attack surface entirely from
//!   non-owner users on multi-user systems.
//! - `.kyber`: passphrase-encrypted ML-KEM seed. Same rationale.
//! - `.hybrid`: ML-KEM public key + ciphertext. Doesn't leak the
//!   private side, but no reason to make it world-readable either.
//! - `.anchor`: HMAC tag under an MVK-derived key. Reading it
//!   doesn't break the vault (forging requires the MVK), but
//!   tightening the permission costs nothing.
//!
//! Without these helpers, `OpenOptions::new().create_new(true).open()`
//! produces a file with mode `(0666 & ~umask)`, which is `0644` on
//! a default `022`-umask system - world-readable.
//!
//! Windows: file mode bits don't apply; files inherit the parent
//! directory's NTFS ACL. The user-home default ACL is owner-only,
//! so the practical outcome matches POSIX. We don't override the
//! ACL explicitly (would require windows-acl crate dependency); if
//! a user creates a vault under a directory with permissive ACLs,
//! they're explicitly opting into that exposure.

use std::fs::{File, OpenOptions};
use std::io;
use std::path::{Path, PathBuf};
use std::time::SystemTime;

#[cfg(unix)]
use std::os::unix::fs::OpenOptionsExt;

/// File mode for newly-created LUKSbox files (POSIX). `rw-------`.
#[cfg(unix)]
pub const SECURE_FILE_MODE: u32 = 0o600;

/// Directory mode for LUKSbox-created directories that hold decrypted
/// plaintext (extraction targets). `rwx------`. Unix only; Windows uses
/// inherited ACLs from the parent.
#[cfg(unix)]
pub const SECURE_DIR_MODE: u32 = 0o700;

/// Create a new file with the LUKSbox secure permission contract.
///
/// On Unix: equivalent to `open(path, O_RDWR | O_CREAT | O_EXCL, 0600)`.
/// The `0600` mode is set BEFORE any data is written, so even a
/// concurrent reader can't observe the file in a wider-permission
/// state.
///
/// On Windows: `OpenOptions::new().read(true).write(true).create_new(true)`.
/// File ACL is inherited from the parent directory.
///
/// `create_new(true)` makes this fail if the path already exists -
/// matches LUKSbox's anti-clobber policy across the codebase.
pub fn secure_create_new(path: &Path) -> io::Result<File> {
    let mut o = OpenOptions::new();
    o.read(true).write(true).create_new(true);
    #[cfg(unix)]
    o.mode(SECURE_FILE_MODE);
    o.open(path)
}

/// Like `secure_create_new` but allows opening an existing file
/// (truncate-then-write semantics). Used for sidecar updates AND for
/// extracting plaintext from a vault to a host path (`luksbox get`,
/// wizard extract, GUI extract). `0600` is re-applied via explicit
/// chmod after open to handle the case where the file existed with a
/// wider mode (e.g. user manually chmod'd it).
///
/// On Unix, `O_NOFOLLOW` is added so that if the destination path
/// already exists as a symlink, `open` fails with `ELOOP` instead of
/// following the link and writing the vault contents into the link
/// target. Without this guard, an attacker who can pre-create a
/// symlink at the destination (e.g. `/tmp/output.txt` → `/etc/passwd`)
/// would have arbitrary file overwrite if `luksbox get` runs as a user
/// with write permission to the target, a privilege-escalation
/// primitive when invoked as root, an integrity-tampering primitive
/// otherwise. Users who genuinely want to extract through a symlink
/// can resolve it manually first (`readlink -f`) or remove the link.
/// `O_NOFOLLOW` only refuses the FINAL path component; intermediate
/// directory symlinks are still followed (refusing those would break
/// legitimate setups like `~/extracted -> /mnt/usb/extracted`).
pub fn secure_create_or_truncate(path: &Path) -> io::Result<File> {
    let mut o = OpenOptions::new();
    o.read(true).write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        o.mode(SECURE_FILE_MODE);
        o.custom_flags(libc::O_NOFOLLOW);
    }
    let f = o.open(path)?;

    // If the file pre-existed with a wider mode, the .mode() above
    // is a no-op (umask only applies on creation, not on truncate).
    // Force-narrow it. `set_permissions` follows symlinks, but we've
    // already established via `O_NOFOLLOW` above that the path is not
    // a symlink, so this can only chmod the regular file we just
    // opened, not an attacker-controlled symlink target.
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let perms = std::fs::Permissions::from_mode(SECURE_FILE_MODE);
        std::fs::set_permissions(path, perms)?;
    }

    Ok(f)
}

/// Recursive directory creation with the LUKSbox secure permission
/// contract. Behaves like `fs::create_dir_all` but every directory
/// component this call newly creates is mode 0700 on Unix
/// (`SECURE_DIR_MODE`), regardless of the process umask.
///
/// Pre-existing directories on the path are left untouched (we don't
/// chmod the user's `$HOME` to 0700 because they passed
/// `~/extract/foo` as an extraction target). Only the components this
/// call creates are narrowed.
///
/// On Windows, falls back to plain `fs::create_dir_all`; ACL hygiene
/// is inherited from the parent.
pub fn secure_create_dir_all(path: &Path) -> io::Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        let mut b = std::fs::DirBuilder::new();
        b.recursive(true).mode(SECURE_DIR_MODE);
        b.create(path)
    }
    #[cfg(not(unix))]
    {
        std::fs::create_dir_all(path)
    }
}

/// Make the directory entry for `path` durable after a create, remove, or
/// rename. POSIX requires syncing the parent directory separately from the
/// file itself; syncing only the file does not guarantee the renamed entry
/// survives power loss.
///
/// On Windows the same guarantee is delivered by opening a handle to the
/// parent directory with `FILE_FLAG_BACKUP_SEMANTICS` (CreateFile rejects
/// directory paths without it) and calling `FlushFileBuffers` via
/// `sync_all()`. Other non-Unix targets (none built today) fall through to
/// a no-op rather than silently breaking the rename.
pub fn sync_parent_dir(path: &Path) -> io::Result<()> {
    fn parent_for(path: &Path) -> &Path {
        path.parent()
            .filter(|p| !p.as_os_str().is_empty())
            .unwrap_or_else(|| Path::new("."))
    }
    #[cfg(unix)]
    {
        let dir = File::open(parent_for(path))?;
        dir.sync_all()
    }
    #[cfg(windows)]
    {
        use std::fs::OpenOptions;
        use std::os::windows::fs::OpenOptionsExt;
        // FILE_FLAG_BACKUP_SEMANTICS (winnt.h: 0x02000000) is the documented
        // flag that lets `CreateFileW` open a directory handle. Without it,
        // open() on a directory path returns ERROR_ACCESS_DENIED. With it,
        // `sync_all()` issues `FlushFileBuffers` against the directory,
        // committing pending rename/create entries to the on-disk metadata
        // log. Same crash-durability guarantee as the POSIX branch.
        const FILE_FLAG_BACKUP_SEMANTICS: u32 = 0x0200_0000;
        let dir = OpenOptions::new()
            .read(true)
            .custom_flags(FILE_FLAG_BACKUP_SEMANTICS)
            .open(parent_for(path))?;
        dir.sync_all()
    }
    #[cfg(not(any(unix, windows)))]
    {
        let _ = path;
        Ok(())
    }
}

/// Atomic, owner-only file replacement: write `bytes` to a unique
/// `<path>.tmp.<rand>` neighbour with mode 0600, fsync it, then
/// `rename(2)` over `path`, then fsync the parent directory. Replaces
/// the unsafe pattern of
/// `fs::write(tmp); fs::rename(tmp, path)` which produces tmp
/// files with `0644` permissions during the window before rename.
pub fn atomic_secure_write(path: &Path, bytes: &[u8]) -> io::Result<()> {
    use std::io::Write as _;

    // Random suffix so concurrent writers don't collide.
    let mut rand_bytes = [0u8; 8];
    use rand_core::{OsRng, RngCore};
    OsRng
        .try_fill_bytes(&mut rand_bytes)
        .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("rng: {e}")))?;
    let suffix: String = rand_bytes.iter().map(|b| format!("{b:02x}")).collect();

    let mut tmp_path = path.to_path_buf();
    let new_name = match path.file_name() {
        Some(n) => format!("{}.tmp.{}", n.to_string_lossy(), suffix),
        None => format!("luksbox.tmp.{suffix}"),
    };
    tmp_path.set_file_name(new_name);

    let mut f = secure_create_new(&tmp_path)?;
    f.write_all(bytes)?;
    f.flush()?;
    // Force the bytes to disk before rename so a crash mid-rename
    // doesn't leave a half-written file at `path`.
    f.sync_all()?;
    drop(f);

    // POSIX rename is atomic on the same filesystem. Windows has
    // ReplaceFileW which is similar.
    std::fs::rename(&tmp_path, path)?;
    sync_parent_dir(path)
}

// ----------------------------------------------------------------------
// Orphan tempfile cleanup (Round 10, follow-up to 9E)
// ----------------------------------------------------------------------
//
// LUKSbox writes sidecars (anchor, hybrid, header) atomically:
//
//   1. write `<base>.tmp.<16hex>` with mode 0600
//   2. fsync
//   3. rename(tmp, base)
//
// MVK rotation in inline mode writes to `<base>.rotating` and renames at
// commit. If the process crashes (or the host loses power) between
// steps 1 and 3, the temp file is left behind:
//
//   - `.tmp.<16hex>` orphans: contain a partial / fully-written but un-
//     renamed copy of a sidecar. Safe to delete (the rename never landed
//     so the canonical file is either the previous version or absent).
//   - `.rotating` orphans: the in-progress rotation's working copy. May
//     be the ONLY surviving copy if the rotation crashed AFTER the
//     vault was substantially re-encrypted; never auto-delete. Surface
//     to the user instead.
//
// `find_orphan_tempfiles` enumerates both kinds for a given vault path
// without touching disk state. Callers (CLI `cleanup-orphans` subcommand,
// GUI startup hook in future) decide what to do with the result.

/// Why a tempfile is considered an orphan.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OrphanKind {
    /// `<base>.tmp.<16hex>` - leftover from a crashed `atomic_secure_write`.
    /// Safe to delete; contents are an aborted partial sidecar.
    AtomicWriteTmp,
    /// `<base>.rotating` - leftover from a crashed `begin_atomic_rotation`.
    /// May be the only surviving copy of an in-progress MVK rotation;
    /// **never auto-delete**. Surface to the user with strong wording.
    RotationTmp,
}

/// One orphan tempfile found next to a vault.
#[derive(Debug, Clone)]
pub struct OrphanTempfile {
    pub path: PathBuf,
    pub kind: OrphanKind,
    pub size: u64,
    pub modified: Option<SystemTime>,
}

/// Scan the parent directory of `vault_path` for tempfiles that match
/// the conventions used by `atomic_secure_write` and the inline-mode
/// rotation flow.
///
/// Returns an empty vec if the parent directory doesn't exist (e.g.
/// the vault path itself doesn't exist). Returns an `io::Error` only
/// if `read_dir` fails for a reason other than NotFound (permission
/// denied, etc.).
///
/// Matching rules:
///
/// - `<vault_filename>.tmp.<exactly-16-lowercase-hex>` -> AtomicWriteTmp
/// - `<vault_filename>.rotating` (exact suffix) -> RotationTmp
/// - Also matches sidecar tempfiles where the `<vault_filename>` is
///   replaced by any of the conventional sidecar basenames:
///     * `<vault_filename>.hdr.tmp.<16hex>`
///     * `<vault_filename>.anchor.tmp.<16hex>`
///     * `<vault_filename>.hybrid.tmp.<16hex>`
///     * `<vault_filename>.kyber.tmp.<16hex>`
///   We don't enforce the sidecar substring strictly; the
///   `<vault_filename>` prefix + `.tmp.<16hex>` suffix is sufficient.
pub fn find_orphan_tempfiles(vault_path: &Path) -> io::Result<Vec<OrphanTempfile>> {
    let dir = match vault_path.parent() {
        Some(d) if !d.as_os_str().is_empty() => d.to_path_buf(),
        _ => PathBuf::from("."),
    };
    let vault_name = match vault_path.file_name().and_then(|n| n.to_str()) {
        Some(n) => n.to_owned(),
        // Non-UTF8 vault names: skip orphan scan (no false-positive
        // matches possible without a comparable string form).
        None => return Ok(Vec::new()),
    };

    let read = match std::fs::read_dir(&dir) {
        Ok(it) => it,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(e) => return Err(e),
    };

    let mut out = Vec::new();
    for entry in read.flatten() {
        let name = match entry.file_name().into_string() {
            Ok(s) => s,
            Err(_) => continue, // non-UTF8 names can't match our prefix
        };
        // Don't include the vault file itself (hits when callers pass a
        // vault path whose name happens to overlap a tmp suffix).
        if name == vault_name {
            continue;
        }
        let kind = if let Some(stripped) = name.strip_prefix(&vault_name) {
            classify_tempfile_suffix(stripped)
        } else {
            None
        };
        let Some(kind) = kind else { continue };
        let path = entry.path();
        let meta = entry.metadata().ok();
        let size = meta.as_ref().map(|m| m.len()).unwrap_or(0);
        let modified = meta.as_ref().and_then(|m| m.modified().ok());
        out.push(OrphanTempfile {
            path,
            kind,
            size,
            modified,
        });
    }
    // Stable order so test output + CLI listing are deterministic.
    out.sort_by(|a, b| a.path.cmp(&b.path));
    Ok(out)
}

/// Inspect the suffix that follows the vault filename. Returns the
/// orphan kind if recognized, `None` otherwise. Pulled out as a free
/// fn so it's unit-testable independently of the disk.
fn classify_tempfile_suffix(suffix: &str) -> Option<OrphanKind> {
    // `.rotating` exact suffix match - used for both the vault itself
    // and (theoretically) any sidecar; either way it's a rotation tmp.
    if suffix == ".rotating" {
        return Some(OrphanKind::RotationTmp);
    }
    // `.tmp.<16hex>` - `atomic_secure_write` random suffix is exactly
    // 8 random bytes formatted as `{:02x}` -> 16 lowercase hex chars.
    // Allow an optional sidecar segment between the vault name and
    // `.tmp` (e.g. `.hdr`, `.anchor`, `.hybrid`, `.kyber`).
    let after_sidecar = match suffix.find(".tmp.") {
        Some(idx) => &suffix[idx + ".tmp.".len()..],
        None => return None,
    };
    if after_sidecar.len() == 16
        && after_sidecar
            .bytes()
            .all(|b| b.is_ascii_hexdigit() && (b.is_ascii_digit() || b.is_ascii_lowercase()))
    {
        return Some(OrphanKind::AtomicWriteTmp);
    }
    None
}

/// Delete the given `AtomicWriteTmp` orphans. Skips `RotationTmp`
/// entries silently - caller must surface those to the user
/// separately and never auto-delete them.
///
/// Returns `(deleted_paths, errors)` so callers can show a per-file
/// report. Deletion of one orphan failing does not prevent the next
/// from being attempted.
pub fn delete_atomic_write_orphans(
    orphans: &[OrphanTempfile],
) -> (Vec<PathBuf>, Vec<(PathBuf, io::Error)>) {
    let mut deleted = Vec::new();
    let mut errors = Vec::new();
    for o in orphans {
        if o.kind != OrphanKind::AtomicWriteTmp {
            continue;
        }
        match std::fs::remove_file(&o.path) {
            Ok(_) => deleted.push(o.path.clone()),
            Err(e) => errors.push((o.path.clone(), e)),
        }
    }
    (deleted, errors)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[cfg(unix)]
    fn mode_of(path: &Path) -> u32 {
        use std::os::unix::fs::PermissionsExt;
        std::fs::metadata(path).unwrap().permissions().mode() & 0o7777
    }

    #[cfg(unix)]
    #[test]
    fn secure_create_new_yields_0600_under_022_umask() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("vault.lbx");

        // Force a permissive umask so a non-secure helper would
        // produce 0644. If our helper doesn't override, this test
        // fails.
        unsafe {
            libc::umask(0o022);
        }

        let _f = secure_create_new(&path).unwrap();
        assert_eq!(
            mode_of(&path),
            0o600,
            "secure_create_new must produce mode 0600 even under umask 022"
        );
    }

    #[cfg(unix)]
    #[test]
    fn secure_create_or_truncate_narrows_existing_wide_file() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("preexisting.lbx");

        // Create a pre-existing file with mode 0644 (the broken case).
        std::fs::write(&path, b"old contents").unwrap();
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
        assert_eq!(mode_of(&path), 0o644);

        // Re-open via the helper. Mode must narrow to 0600.
        let _f = secure_create_or_truncate(&path).unwrap();
        assert_eq!(
            mode_of(&path),
            0o600,
            "secure_create_or_truncate must narrow pre-existing 0644 -> 0600"
        );
    }

    /// Symlink-target overwrite guard for plaintext extraction. If the
    /// destination path already exists as a symlink (e.g. attacker pre-
    /// created `/tmp/output` -> `/etc/passwd`), `secure_create_or_truncate`
    /// must fail with `ELOOP` rather than truncate the symlink target
    /// and write vault contents into it. The legitimate "symlink in an
    /// intermediate dir" case (e.g. `~/extracted -> /mnt/usb/extracted`,
    /// then a regular file under it) is unaffected, only the FINAL
    /// component is checked.
    #[cfg(unix)]
    #[test]
    fn secure_create_or_truncate_refuses_symlink_destination() {
        let dir = tempdir().unwrap();
        let target_real = dir.path().join("victim.txt");
        std::fs::write(&target_real, b"sensitive contents").unwrap();
        let link = dir.path().join("attacker.symlink");
        std::os::unix::fs::symlink(&target_real, &link).unwrap();

        let err = secure_create_or_truncate(&link)
            .expect_err("opening a symlink for write+truncate must fail");
        assert_eq!(
            err.raw_os_error(),
            Some(libc::ELOOP),
            "expected ELOOP for symlink dst, got {err:?}"
        );

        // Sanity: the original sensitive contents weren't touched.
        let still = std::fs::read(&target_real).unwrap();
        assert_eq!(still, b"sensitive contents");
    }

    #[cfg(unix)]
    #[test]
    fn secure_create_dir_all_yields_0700_under_022_umask() {
        let dir = tempdir().unwrap();
        let target = dir.path().join("a/b/c");

        unsafe {
            libc::umask(0o022);
        }
        secure_create_dir_all(&target).unwrap();

        // Every component this call newly creates must be 0700.
        for p in [
            &target,
            &target.parent().unwrap().to_path_buf(),
            &target.parent().unwrap().parent().unwrap().to_path_buf(),
        ] {
            assert_eq!(
                mode_of(p),
                0o700,
                "secure_create_dir_all must produce mode 0700 at {} even under umask 022",
                p.display(),
            );
        }
    }

    #[cfg(unix)]
    #[test]
    fn secure_create_dir_all_does_not_chmod_preexisting_components() {
        // Pre-existing parent dirs (e.g. the user's $HOME) must NOT be
        // chmod'd to 0700 by a recursive create. Only newly-created
        // components are narrowed.
        let dir = tempdir().unwrap();
        let parent = dir.path().join("preexisting_parent");
        std::fs::create_dir(&parent).unwrap();
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&parent, std::fs::Permissions::from_mode(0o755)).unwrap();
        assert_eq!(mode_of(&parent), 0o755);

        let leaf = parent.join("new_child");
        secure_create_dir_all(&leaf).unwrap();

        assert_eq!(
            mode_of(&parent),
            0o755,
            "pre-existing parent must be untouched"
        );
        assert_eq!(mode_of(&leaf), 0o700, "newly created leaf must be 0700");
    }

    #[cfg(unix)]
    #[test]
    fn atomic_secure_write_yields_0600() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("anchor.dat");
        unsafe {
            libc::umask(0o022);
        }
        atomic_secure_write(&path, b"anchor bytes").unwrap();
        assert_eq!(mode_of(&path), 0o600);
        assert_eq!(std::fs::read(&path).unwrap(), b"anchor bytes");
    }

    #[cfg(unix)]
    #[test]
    fn atomic_secure_write_leaves_no_tempfile_on_success() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("vault.hdr");
        atomic_secure_write(&path, &vec![0xAA; 1024]).unwrap();

        // The directory should contain only the final file, no
        // .tmp.* leftovers.
        let entries: Vec<_> = std::fs::read_dir(dir.path())
            .unwrap()
            .filter_map(Result::ok)
            .map(|e| e.file_name().into_string().unwrap())
            .collect();
        assert_eq!(entries, vec!["vault.hdr".to_string()]);
    }

    // ------------------------------------------------------------------
    // Orphan-tempfile cleanup tests
    // ------------------------------------------------------------------

    #[test]
    fn classify_tempfile_suffix_recognizes_atomic_write_tmp() {
        assert_eq!(
            classify_tempfile_suffix(".tmp.0123456789abcdef"),
            Some(OrphanKind::AtomicWriteTmp)
        );
        assert_eq!(
            classify_tempfile_suffix(".hdr.tmp.deadbeef00112233"),
            Some(OrphanKind::AtomicWriteTmp)
        );
        assert_eq!(
            classify_tempfile_suffix(".anchor.tmp.aaaaaaaaaaaaaaaa"),
            Some(OrphanKind::AtomicWriteTmp)
        );
    }

    #[test]
    fn classify_tempfile_suffix_recognizes_rotation_tmp() {
        assert_eq!(
            classify_tempfile_suffix(".rotating"),
            Some(OrphanKind::RotationTmp)
        );
    }

    #[test]
    fn classify_tempfile_suffix_rejects_unrelated() {
        // Wrong suffix length (15 chars).
        assert_eq!(classify_tempfile_suffix(".tmp.0123456789abcde"), None);
        // Uppercase hex (we emit lowercase).
        assert_eq!(classify_tempfile_suffix(".tmp.DEADBEEF00112233"), None);
        // Non-hex chars.
        assert_eq!(classify_tempfile_suffix(".tmp.zzzzzzzzzzzzzzzz"), None);
        // Random unrelated suffix.
        assert_eq!(classify_tempfile_suffix(".bak"), None);
        // Empty.
        assert_eq!(classify_tempfile_suffix(""), None);
        // Final extension only (the vault file itself).
        assert_eq!(classify_tempfile_suffix(".lbx"), None);
    }

    #[test]
    fn find_orphan_tempfiles_empty_dir_returns_empty() {
        let dir = tempdir().unwrap();
        let vault = dir.path().join("vault.lbx");
        let orphans = find_orphan_tempfiles(&vault).unwrap();
        assert!(orphans.is_empty());
    }

    #[test]
    fn find_orphan_tempfiles_finds_atomic_write_orphan() {
        let dir = tempdir().unwrap();
        let vault = dir.path().join("vault.lbx");
        // Drop the vault itself + a tmp orphan + an unrelated file.
        std::fs::write(&vault, b"vault contents").unwrap();
        std::fs::write(
            dir.path().join("vault.lbx.anchor.tmp.deadbeef00112233"),
            b"partial anchor",
        )
        .unwrap();
        std::fs::write(dir.path().join("unrelated.txt"), b"hello").unwrap();

        let orphans = find_orphan_tempfiles(&vault).unwrap();
        assert_eq!(orphans.len(), 1, "should find exactly one orphan");
        assert_eq!(orphans[0].kind, OrphanKind::AtomicWriteTmp);
        assert_eq!(
            orphans[0].path.file_name().unwrap(),
            "vault.lbx.anchor.tmp.deadbeef00112233"
        );
    }

    #[test]
    fn find_orphan_tempfiles_finds_rotation_orphan() {
        let dir = tempdir().unwrap();
        let vault = dir.path().join("vault.lbx");
        std::fs::write(&vault, b"vault").unwrap();
        std::fs::write(dir.path().join("vault.lbx.rotating"), b"in-flight rotation").unwrap();

        let orphans = find_orphan_tempfiles(&vault).unwrap();
        assert_eq!(orphans.len(), 1);
        assert_eq!(orphans[0].kind, OrphanKind::RotationTmp);
    }

    #[test]
    fn find_orphan_tempfiles_does_not_match_other_vaults() {
        // Two vaults in the same dir; ensure we only get tempfiles for
        // the one we asked about.
        let dir = tempdir().unwrap();
        let vault_a = dir.path().join("vault-a.lbx");
        let vault_b = dir.path().join("vault-b.lbx");
        std::fs::write(&vault_a, b"a").unwrap();
        std::fs::write(&vault_b, b"b").unwrap();
        std::fs::write(
            dir.path().join("vault-a.lbx.tmp.0000000011112222"),
            b"a tmp",
        )
        .unwrap();
        std::fs::write(
            dir.path().join("vault-b.lbx.tmp.3333333344445555"),
            b"b tmp",
        )
        .unwrap();

        let orphans_a = find_orphan_tempfiles(&vault_a).unwrap();
        assert_eq!(orphans_a.len(), 1);
        assert_eq!(
            orphans_a[0].path.file_name().unwrap(),
            "vault-a.lbx.tmp.0000000011112222"
        );

        let orphans_b = find_orphan_tempfiles(&vault_b).unwrap();
        assert_eq!(orphans_b.len(), 1);
        assert_eq!(
            orphans_b[0].path.file_name().unwrap(),
            "vault-b.lbx.tmp.3333333344445555"
        );
    }

    #[test]
    fn delete_atomic_write_orphans_removes_only_atomic_kind() {
        let dir = tempdir().unwrap();
        let vault = dir.path().join("vault.lbx");
        let atomic_orphan = dir.path().join("vault.lbx.tmp.aabbccddeeff0011");
        let rotation_orphan = dir.path().join("vault.lbx.rotating");
        std::fs::write(&vault, b"v").unwrap();
        std::fs::write(&atomic_orphan, b"x").unwrap();
        std::fs::write(&rotation_orphan, b"y").unwrap();

        let orphans = find_orphan_tempfiles(&vault).unwrap();
        assert_eq!(orphans.len(), 2);

        let (deleted, errors) = delete_atomic_write_orphans(&orphans);
        assert_eq!(deleted.len(), 1);
        assert_eq!(
            deleted[0].file_name().unwrap(),
            "vault.lbx.tmp.aabbccddeeff0011"
        );
        assert!(errors.is_empty());

        // Atomic gone, rotation preserved (must surface to user, not
        // auto-delete).
        assert!(!atomic_orphan.exists());
        assert!(rotation_orphan.exists());

        // Re-scan: only the rotation orphan remains.
        let after = find_orphan_tempfiles(&vault).unwrap();
        assert_eq!(after.len(), 1);
        assert_eq!(after[0].kind, OrphanKind::RotationTmp);
    }

    #[test]
    fn find_orphan_tempfiles_nonexistent_vault_returns_empty() {
        // Pointing at a vault under a directory that doesn't exist
        // should be Ok(empty), not Err. Lets callers run cleanup
        // unconditionally without pre-checking existence.
        let dir = tempdir().unwrap();
        let nonexistent_subdir = dir.path().join("does-not-exist");
        let vault = nonexistent_subdir.join("vault.lbx");
        let orphans = find_orphan_tempfiles(&vault).unwrap();
        assert!(orphans.is_empty());
    }
}
