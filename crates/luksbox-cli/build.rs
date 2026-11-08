// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Penthertz <https://penthertz.com> (https://x.com/PentHertz)

// Build script for luksbox-cli: on macOS with the `fuse-t` feature,
// adds FUSE-T's library folder to the binary's rpath (see below).
// No-op everywhere else.

fn main() {
    println!("cargo:rerun-if-changed=build.rs");
    fuse_t_rpath();
}

/// macOS + `fuse-t`: libfuse-t.dylib's install name is
/// `@rpath/libfuse-t.dylib`, and FUSE-T's own `fuse-t.pc` asks for
/// `-Wl,-rpath,<libdir>`, which the pkg-config probe in luksbox-fuse-t
/// drops (and a library's build script cannot add link arguments to the
/// binaries that use it). Without it a locally built binary aborts at
/// launch ("Library not loaded: @rpath/libfuse-t.dylib") unless
/// DYLD_FALLBACK_LIBRARY_PATH is set. Release bundles rewrite the
/// reference with dylibbundler, so this only matters for local builds.
fn fuse_t_rpath() {
    println!("cargo:rerun-if-env-changed=FUSE_T_LIB_DIR");
    println!("cargo:rerun-if-env-changed=PKG_CONFIG_PATH");
    if std::env::var("CARGO_CFG_TARGET_OS").as_deref() != Ok("macos")
        || std::env::var_os("CARGO_FEATURE_FUSE_T").is_none()
    {
        return;
    }
    let mut dirs: Vec<std::path::PathBuf> = Vec::new();
    if let Some(d) = std::env::var_os("FUSE_T_LIB_DIR") {
        dirs.push(d.into());
    }
    if let Some(p) = std::env::var_os("PKG_CONFIG_PATH") {
        // `<prefix>/lib/pkgconfig` -> `<prefix>/lib`
        dirs.extend(std::env::split_paths(&p).filter_map(|d| d.parent().map(|q| q.to_path_buf())));
    }
    dirs.push("/usr/local/lib".into());
    dirs.push("/opt/homebrew/lib".into());
    if let Some(d) = dirs.iter().find(|d| d.join("libfuse-t.dylib").is_file()) {
        println!("cargo:rustc-link-arg=-Wl,-rpath,{}", d.display());
    }
}
