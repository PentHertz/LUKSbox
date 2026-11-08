// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Penthertz <https://penthertz.com> (https://x.com/PentHertz)

// Build script for luksbox-gui.
//
// On Windows: embeds assets/icon.ico into luksbox-gui.exe via a
// generated .rc + windres/rc.exe link step (handled by the
// `winresource` crate). The icon then shows in Explorer, the
// taskbar, alt-tab, and the title bar.
//
// On every other target: no-op. The runtime window icon is set in
// main.rs via eframe's NativeOptions and is sufficient on Linux +
// macOS-while-running. The macOS Finder icon comes from the .app
// bundle's Resources/icon.icns, not from the binary.
//
// If assets/icon.ico is missing (the user hasn't run
// scripts/build_icons.sh yet) we deliberately don't fail, the build
// continues and the resulting .exe simply uses the default Windows
// icon. This keeps `cargo build` working on a fresh checkout without
// ImageMagick.

fn main() {
    // Re-run only when the icon source or this script changes.
    println!("cargo:rerun-if-changed=assets/icon.ico");
    println!("cargo:rerun-if-changed=build.rs");
    fuse_t_rpath();

    #[cfg(windows)]
    {
        let ico = std::path::Path::new("assets/icon.ico");
        if ico.exists() {
            let mut res = winresource::WindowsResource::new();
            res.set_icon("assets/icon.ico");
            // Optional version metadata, shows up in the .exe's
            // Properties dialog. Keeps the binary self-describing.
            res.set("ProductName", "LUKSbox");
            res.set("FileDescription", "LUKSbox encrypted-container desktop GUI");
            res.set("CompanyName", "Penthertz");
            res.set("LegalCopyright", "MIT licensed");
            if let Err(e) = res.compile() {
                // Don't fail the build, the GUI still works without
                // the embedded icon. Surface the reason as a warning
                // so a CI maintainer notices.
                println!("cargo:warning=winresource failed to embed icon: {e}");
            }
        } else {
            println!(
                "cargo:warning=assets/icon.ico missing, run scripts/build_icons.sh to embed the .exe icon"
            );
        }
    }
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
