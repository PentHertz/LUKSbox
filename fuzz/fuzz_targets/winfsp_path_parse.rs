// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Penthertz <https://penthertz.com> (https://x.com/PentHertz)

#![no_main]

//! Panic-resistance fuzz target for the WinFsp path-parsing helpers.
//!
//! The three functions exercised here are called from inside WinFsp's
//! kernel-driven dispatcher on every `IRP_MJ_CREATE` / `_RENAME` /
//! `_QUERY_INFORMATION` / etc. against our mounted drive. The path
//! input is attacker-influenceable: any user-mode process on the
//! Windows host can issue a `CreateFile` against `Z:\<anything>` and
//! have the bytes flow into our callbacks. A panic in our parser
//! manifests as either an unwind across the FFI boundary (UB) or a
//! crashed dispatcher thread that leaves the mount in a broken state.
//! Either way: we want every input to either parse or return an error,
//! never panic.
//!
//! Cross-checks the three parsers against each other where applicable
//! to catch invariant violations beyond "doesn't panic".

use libfuzzer_sys::fuzz_target;
use luksbox_mount::winfsp_path::{
    PathParseError, from_win_path_str, normalize_mountpoint_str, split_parent_name,
};

fuzz_target!(|data: &[u8]| {
    // U16CStr decodes to UTF-8; use the same fuzz constraint so we
    // exercise the same input space the WinFsp adapter actually sees.
    let Ok(s) = std::str::from_utf8(data) else {
        return;
    };

    // Parser 1: Windows-path -> POSIX-path translation. Documented
    // invariants on the output (Ok branch only):
    //   - no NUL byte (rejected by the parser)
    //   - no backslash byte (every `\` was translated to `/`)
    //   - non-empty (empty input is mapped to `/`)
    // Output is NOT guaranteed to be root-anchored: in real use the
    // input always starts with `\` so the output starts with `/`, but
    // a relative input like `foo\bar` round-trips to `foo/bar` and
    // that's intentional. No assertion on the leading byte.
    if let Ok(converted) = from_win_path_str(s) {
        assert!(
            !converted.contains('\0'),
            "from_win_path_str output contains NUL: {converted:?}"
        );
        assert!(
            !converted.contains('\\'),
            "from_win_path_str left backslash in output: {converted:?}"
        );
        assert!(
            !converted.is_empty(),
            "from_win_path_str output is empty for input {s:?}"
        );

        // Output must always be a valid input to split_parent_name OR
        // a documented error variant. Cross-checking enforces that
        // the two parsers stay in sync: e.g. if from_win_path_str
        // started silently producing trailing slashes, this catches it.
        match split_parent_name(&converted) {
            Ok((_parent, leaf)) => {
                assert!(
                    !leaf.is_empty(),
                    "split_parent_name returned empty leaf for {converted:?}"
                );
                assert!(
                    !leaf.contains('/'),
                    "split_parent_name leaf still contains slash: {leaf:?}"
                );
            }
            Err(PathParseError::EmptyPath) => {
                // Acceptable: input was the volume root or all-slashes.
                assert!(
                    converted.chars().all(|c| c == '/'),
                    "EmptyPath but converted has non-slash content: {converted:?}"
                );
            }
            Err(PathParseError::EmptyName) => {
                // Acceptable: converted ends with a separator.
                assert!(
                    converted.ends_with('/'),
                    "EmptyName but converted does not end with /: {converted:?}"
                );
            }
            Err(PathParseError::TooLong) => {
                assert!(
                    converted.len() > luksbox_mount::winfsp_path::MAX_PATH_LEN,
                    "TooLong but len={}",
                    converted.len()
                );
            }
            Err(PathParseError::ContainsNul) => {
                // Already asserted above that converted has no NUL,
                // so this branch should be unreachable.
                panic!("ContainsNul on output we already checked: {converted:?}");
            }
        }
    }

    // Parser 2: split on raw input. No assertions on the result other
    // than not panicking - many byte strings are nonsensical paths.
    let _ = split_parent_name(s);

    // Parser 3: mountpoint normalization. Documented invariants on
    // the output (Ok branch):
    //   - no NUL (rejected by the parser)
    //   - non-empty (empty input is rejected)
    //   - len() <= input len() (the function only shrinks via the
    //     drive-letter trailing-separator strip)
    //   - if a drive-separator strip happened, the output is exactly
    //     `<alpha>:` (3-byte input, alpha first byte, `:`, sep).
    if let Ok(out) = normalize_mountpoint_str(s) {
        assert!(!out.contains('\0'));
        assert!(!out.is_empty());
        assert!(
            out.len() <= s.len(),
            "normalize_mountpoint_str grew the input: {s:?} -> {out:?}"
        );
        // If the function stripped a separator, the result is exactly
        // 2 ASCII bytes <alpha>:`. Detect this case via the input
        // pattern (3 bytes <alpha>:<sep>) and verify.
        let in_bytes = s.as_bytes();
        let stripped = in_bytes.len() == 3
            && in_bytes[0].is_ascii_alphabetic()
            && in_bytes[1] == b':'
            && (in_bytes[2] == b'\\' || in_bytes[2] == b'/');
        if stripped {
            assert_eq!(out.len(), 2);
            assert!(out.as_bytes()[0].is_ascii_alphabetic());
            assert_eq!(out.as_bytes()[1], b':');
        }
    }
});
