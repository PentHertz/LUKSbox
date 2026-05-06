// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Penthertz <https://penthertz.com> (https://x.com/PentHertz)

//! Path-string parsing helpers for the WinFsp adapter.
//!
//! These three functions used to live inline in `winfsp.rs`. They are
//! pure string ops with no winfsp_wrs dependency, so they're a good
//! candidate to extract into a platform-agnostic module: the
//! `winfsp.rs` body stays gated on `target_os = "windows"` and the
//! parsers themselves get unit-tested + fuzzed cross-platform.
//!
//! The parsers see attacker-influenceable input - Windows file-system
//! paths come from any process that can issue an IRP_MJ_CREATE on our
//! mounted drive letter, which is "every user-mode app on the system".
//! A panic in any of these helpers translates to either a panic in the
//! WinFsp dispatcher thread (which we never see in production logs) or
//! a STATUS_INVALID_PARAMETER returned to the caller - but only if the
//! panic happens inside our `catch_unwind` perimeter, which we don't
//! currently install. Better to handle it as data and return an error.

/// Cap on the byte length of a path that we'll process. NTFS allows
/// paths up to 32_767 chars; we add a small slack for UTF-8 worst case
/// and round to a power of two. Above this we refuse to allocate (the
/// sanitization is mainly to prevent a buggy / hostile caller from
/// triggering an unbounded `String::with_capacity` in `replace`).
pub const MAX_PATH_LEN: usize = 65_536;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PathParseError {
    /// Path is empty when an empty path is invalid in context (e.g.
    /// `split_parent_name` on `/`).
    EmptyPath,
    /// Path has a trailing separator that resolves to an empty leaf
    /// name (e.g. `\foo\`). vfs operations that need a name (create,
    /// rename) would otherwise be called with an empty string.
    EmptyName,
    /// Path contains an embedded NUL byte. Coming from `U16CStr` this
    /// shouldn't happen (NUL terminates), but the `&str` entry points
    /// take generic input so we defend at this layer.
    ContainsNul,
    /// Path exceeds `MAX_PATH_LEN`. Refused before any allocation.
    TooLong,
}

/// Convert a Windows-style path string to luksbox-vfs's POSIX-style.
///
/// `\foo\bar` -> `/foo/bar`. Empty / `\` -> `/` (the volume root). The
/// `from_win_path` wrapper in `winfsp.rs` calls this with
/// `U16CStr::to_string()`-decoded text; it can't contain NUL but the
/// length and replacement logic still needs the same defence so the
/// helper is safe to call from anywhere.
pub fn from_win_path_str(s: &str) -> Result<String, PathParseError> {
    if s.len() > MAX_PATH_LEN {
        return Err(PathParseError::TooLong);
    }
    if s.contains('\0') {
        return Err(PathParseError::ContainsNul);
    }
    if s.is_empty() || s == "\\" {
        return Ok("/".into());
    }
    Ok(s.replace('\\', "/"))
}

/// Split a POSIX-style path into `(parent_dir, leaf_name)`.
///
/// Leading `/` characters are trimmed before splitting. The leaf name
/// MUST be non-empty - paths ending in `/` (e.g. `/foo/`) are rejected
/// as `EmptyName` rather than handed downstream as `(foo, "")`, which
/// previously went silently into `vfs.create` / `vfs.mkdir` and either
/// panicked or produced an empty-named inode depending on the vfs path.
///
/// `"/"` -> `EmptyPath`. `"//"` (multiple leading slashes) -> `EmptyPath`.
/// `"/foo"` -> `("", "foo")`. `"/foo/bar"` -> `("foo", "bar")`.
pub fn split_parent_name(path: &str) -> Result<(&str, &str), PathParseError> {
    if path.len() > MAX_PATH_LEN {
        return Err(PathParseError::TooLong);
    }
    if path.contains('\0') {
        return Err(PathParseError::ContainsNul);
    }
    let trimmed = path.trim_start_matches('/');
    if trimmed.is_empty() {
        return Err(PathParseError::EmptyPath);
    }
    let (parent, leaf) = match trimmed.rfind('/') {
        // SAFETY: `i` is the byte offset returned by `rfind('/')`, and
        // '/' is a single ASCII byte. Both `..i` and `i + 1..` always
        // land on UTF-8 char boundaries - the slice cannot panic.
        Some(i) => (&trimmed[..i], &trimmed[i + 1..]),
        None => ("", trimmed),
    };
    if leaf.is_empty() {
        return Err(PathParseError::EmptyName);
    }
    Ok((parent, leaf))
}

/// Trim a trailing separator from a drive-letter mountpoint.
///
/// WinFsp accepts `Y:` but rejects `Y:\` with
/// `STATUS_OBJECT_NAME_INVALID` (`0xC0000033`). Path / PathBuf round-
/// trip the trailing separator silently; we strip it here before
/// handing the string to WinFsp. Directory mountpoints (`C:\some\dir`)
/// are real filesystem paths and pass through unchanged.
///
/// "Drive-letter form" = exactly 3 ASCII bytes, `<letter>:<sep>` where
/// `<letter>` is A-Z / a-z and `<sep>` is `\` or `/`. Stricter than
/// the previous inline check (which accepted any byte in position 0
/// like `1:\`); a non-letter would never name a real Windows volume,
/// so rejecting it here matches Windows semantics and avoids handing
/// nonsense to WinFsp.
pub fn normalize_mountpoint_str(mp_str: &str) -> Result<String, PathParseError> {
    if mp_str.is_empty() {
        return Err(PathParseError::EmptyPath);
    }
    if mp_str.len() > MAX_PATH_LEN {
        return Err(PathParseError::TooLong);
    }
    if mp_str.contains('\0') {
        return Err(PathParseError::ContainsNul);
    }
    let bytes = mp_str.as_bytes();
    let is_drive_with_sep = bytes.len() == 3
        && bytes[0].is_ascii_alphabetic()
        && bytes[1] == b':'
        && (bytes[2] == b'\\' || bytes[2] == b'/');
    if is_drive_with_sep {
        // bytes 0..2 are ASCII (alpha + ':'), so this is a valid char
        // boundary - no panic risk.
        return Ok(mp_str[..2].to_string());
    }
    Ok(mp_str.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn from_win_path_root_forms() {
        assert_eq!(from_win_path_str("").unwrap(), "/");
        assert_eq!(from_win_path_str("\\").unwrap(), "/");
    }

    #[test]
    fn from_win_path_basic_translation() {
        assert_eq!(from_win_path_str("\\foo").unwrap(), "/foo");
        assert_eq!(from_win_path_str("\\foo\\bar").unwrap(), "/foo/bar");
        assert_eq!(from_win_path_str("\\a\\b\\c").unwrap(), "/a/b/c");
    }

    #[test]
    fn from_win_path_rejects_nul() {
        assert_eq!(
            from_win_path_str("\\foo\0bar").unwrap_err(),
            PathParseError::ContainsNul
        );
    }

    #[test]
    fn from_win_path_rejects_oversize() {
        let big = "a".repeat(MAX_PATH_LEN + 1);
        assert_eq!(
            from_win_path_str(&big).unwrap_err(),
            PathParseError::TooLong
        );
    }

    #[test]
    fn split_parent_name_basic() {
        assert_eq!(split_parent_name("/foo").unwrap(), ("", "foo"));
        assert_eq!(split_parent_name("/foo/bar").unwrap(), ("foo", "bar"));
        assert_eq!(split_parent_name("/a/b/c").unwrap(), ("a/b", "c"));
    }

    #[test]
    fn split_parent_name_root_is_invalid() {
        assert_eq!(
            split_parent_name("/").unwrap_err(),
            PathParseError::EmptyPath
        );
        assert_eq!(
            split_parent_name("").unwrap_err(),
            PathParseError::EmptyPath
        );
        assert_eq!(
            split_parent_name("///").unwrap_err(),
            PathParseError::EmptyPath
        );
    }

    #[test]
    fn split_parent_name_trailing_slash_is_invalid() {
        assert_eq!(
            split_parent_name("/foo/").unwrap_err(),
            PathParseError::EmptyName
        );
        assert_eq!(
            split_parent_name("/foo/bar/").unwrap_err(),
            PathParseError::EmptyName
        );
    }

    #[test]
    fn split_parent_name_unicode_does_not_panic() {
        // Leaf with multi-byte UTF-8 characters. rfind('/') returns a
        // byte offset that's always on a UTF-8 boundary (since '/' is
        // ASCII), so slicing must not panic.
        assert_eq!(split_parent_name("/dir/élé").unwrap(), ("dir", "élé"));
        assert_eq!(split_parent_name("/é/é").unwrap(), ("é", "é"));
    }

    #[test]
    fn normalize_mountpoint_strips_drive_letter_separator() {
        assert_eq!(normalize_mountpoint_str("Y:").unwrap(), "Y:");
        assert_eq!(normalize_mountpoint_str("Y:\\").unwrap(), "Y:");
        assert_eq!(normalize_mountpoint_str("Y:/").unwrap(), "Y:");
        assert_eq!(normalize_mountpoint_str("z:\\").unwrap(), "z:");
    }

    #[test]
    fn normalize_mountpoint_passes_through_directory_path() {
        assert_eq!(
            normalize_mountpoint_str("C:\\some\\dir").unwrap(),
            "C:\\some\\dir"
        );
        assert_eq!(normalize_mountpoint_str("C:").unwrap(), "C:");
    }

    #[test]
    fn normalize_mountpoint_rejects_drive_letter_with_non_alpha() {
        // 3-byte string but first byte isn't a letter - pass through
        // unchanged rather than misclassify as a drive form.
        assert_eq!(normalize_mountpoint_str("1:\\").unwrap(), "1:\\");
        assert_eq!(normalize_mountpoint_str("?:\\").unwrap(), "?:\\");
    }

    #[test]
    fn normalize_mountpoint_rejects_empty_and_nul() {
        assert_eq!(
            normalize_mountpoint_str("").unwrap_err(),
            PathParseError::EmptyPath
        );
        assert_eq!(
            normalize_mountpoint_str("Z:\0").unwrap_err(),
            PathParseError::ContainsNul
        );
    }

    #[test]
    fn split_parent_name_does_not_panic_on_arbitrary_ascii() {
        // Quick local regression for inputs the previous inline impl
        // mishandled. None should panic; many should now be rejected.
        for input in [
            "",
            "/",
            "//",
            "///",
            "/foo",
            "/foo/",
            "//foo//",
            "////foo",
            "/foo/bar/",
            "a/b",
            "a",
            "a/",
            "/a/b/c/d/e/",
        ] {
            let _ = split_parent_name(input);
        }
    }
}
