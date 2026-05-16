// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Penthertz <https://penthertz.com>
//
// PLACEHOLDER SNAPSHOT - REGENERATE BEFORE USE
//
// This file is the committed snapshot target for the libfuse-t Rust
// bindings. The regular build path (default) ignores this file and
// regenerates bindings into OUT_DIR via bindgen on every build. The
// snapshot exists so that a future Phase-2 flip can use the
// committed bindings as the default and skip bindgen entirely
// (smaller build-time supply chain, deterministic output across
// hosts).
//
// To populate this file, on a macOS host with FUSE-T installed:
//
//   brew tap macos-fuse-t/homebrew-cask
//   brew install --cask fuse-t
//   cargo build -p luksbox-fuse-t --features regenerate-bindings
//
// `build.rs` then writes the bindgen output here. Inspect with
// `git diff` and commit if the changes are consistent with the
// libfuse-t version bumped (cross-check against the upstream
// header changelog).
//
// Until this file is populated by the regenerate workflow, leaving
// it in this placeholder state is harmless: nothing includes it
// from `sys.rs` yet. Trying to opt INTO snapshot mode while this
// placeholder is still here would produce a compile error from
// `sys.rs`'s include site (intentional, you must not skip bindgen
// against an empty snapshot).

compile_error!(
    "luksbox-fuse-t: src/bindings_generated.rs is the placeholder snapshot. \
     Regenerate it on a macOS+FUSE-T host first, see the file header for the \
     workflow. Until then, build without the `prebuilt-bindings` feature so \
     bindgen runs every build and writes to OUT_DIR (the default path)."
);
