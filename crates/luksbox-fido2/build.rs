// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Penthertz <https://penthertz.com> (https://x.com/PentHertz)

// Cargo runs this build script unconditionally, but the libfido2 link
// AND the bindgen binding regeneration only happen when the `hardware`
// feature is enabled, gated by Cargo via the CARGO_FEATURE_HARDWARE
// env var.
//
// Linkage resolution strategy (first match wins):
//
//   1. **Env-var override**, `LIBFIDO2_LIB_DIR` (and optional
//      `LIBFIDO2_LIB_NAME`, default `fido2`). Lets the user point at any
//      install layout, useful on Windows MSVC, msys2, custom prefixes,
//      cross-compilation, sandboxed build envs. With this path, bindgen
//      uses `LIBFIDO2_INCLUDE_DIR` (or `$LIBFIDO2_LIB_DIR/../include`)
//      to find the headers.
//
//   2. **pkg-config**, Linux/macOS path. Reads `libfido2.pc` for both
//      the link directives and bindgen's include paths.
//
//   3. **vcpkg**, Windows path. bindgen uses the vcpkg-reported include
//      paths.
//
// Bindings: bindgen regenerates `OUT_DIR/fido2_bindings.rs` against the
// actually-linked libfido2 headers. `src/ffi.rs` `include!`s the result.
// Replaces the hand-rolled `unsafe extern "C"` block we used through
// audit round 7B; closes the manual-translation provenance risk.

use std::env;
use std::path::PathBuf;

fn main() {
    if env::var_os("CARGO_FEATURE_HARDWARE").is_none() {
        return;
    }

    // On Windows the FIDO2 path is webauthn.dll (see
    // `src/webauthn.rs`), not libfido2 - the libfido2 + raw HID
    // approach is broken for non-elevated processes since Windows 10
    // 1903 (FIDO HID class is reserved for the WebAuthn system
    // service). webauthn.dll is dynamically linked via the `windows`
    // crate's `windows_targets::link!("webauthn.dll" ...)` macro, no
    // build-script work needed. Skip the libfido2 probe entirely.
    let target = env::var("TARGET").unwrap_or_default();
    if target.contains("windows") {
        return;
    }

    println!("cargo:rerun-if-env-changed=LIBFIDO2_LIB_DIR");
    println!("cargo:rerun-if-env-changed=LIBFIDO2_LIB_NAME");
    println!("cargo:rerun-if-env-changed=LIBFIDO2_INCLUDE_DIR");
    println!("cargo:rerun-if-env-changed=LIBFIDO2_TARGET");
    println!("cargo:rerun-if-env-changed=VCPKG_ROOT");

    // Honor the LIBFIDO2_LIB_DIR override only when it's actually
    // for this build's target. setup_mingw_libfido2.sh exports the
    // var into your shell so a Linux host can cross-link a Windows
    // build; without this guard the same shell's next native cargo
    // build picks up the MinGW .a archive and the linker dies with
    // "neither ET_REL nor LLVM bitcode" + undefined fido_* symbols.
    // Treat a tagged override targeting a different triple as if
    // the override were absent and fall through to pkg-config /
    // vcpkg.
    let override_target_matches = match env::var("LIBFIDO2_TARGET") {
        Ok(t) if !t.is_empty() => t == target,
        _ => true,
    };
    let lib_dir_override = env::var("LIBFIDO2_LIB_DIR")
        .ok()
        .filter(|_| override_target_matches);
    if env::var_os("LIBFIDO2_LIB_DIR").is_some() && !override_target_matches {
        println!(
            "cargo:warning=LIBFIDO2_LIB_DIR is set but LIBFIDO2_TARGET={:?} \
             does not match this build's TARGET={:?}; ignoring override and \
             falling back to pkg-config/vcpkg",
            env::var("LIBFIDO2_TARGET").unwrap_or_default(),
            target,
        );
    }

    let include_paths: Vec<PathBuf> = if let Some(lib_dir) = lib_dir_override {
        // Manual override path.
        let lib_name = env::var("LIBFIDO2_LIB_NAME").unwrap_or_else(|_| "fido2".into());
        println!("cargo:rustc-link-search=native={lib_dir}");
        println!("cargo:rustc-link-lib={lib_name}");
        println!("cargo:rustc-env=LUKSBOX_LIBFIDO2_VERSION=manual-override");
        // Best-effort include-path inference.
        let inc = env::var("LIBFIDO2_INCLUDE_DIR")
            .map(PathBuf::from)
            .unwrap_or_else(|_| {
                let mut p = PathBuf::from(&lib_dir);
                p.pop();
                p.push("include");
                p
            });
        vec![inc]
    } else if let Ok(lib) = pkg_config::Config::new()
        .atleast_version("1.10")
        .probe("libfido2")
    {
        // pkg-config path. Minimum 1.10, matches Debian Bullseye's
        // package; every symbol we call is ≥ 1.4 so this is conservative.
        println!("cargo:rustc-env=LUKSBOX_LIBFIDO2_VERSION={}", lib.version);
        lib.include_paths
    } else if let Ok(lib) = vcpkg::find_package("libfido2") {
        // Windows path via vcpkg.
        println!("cargo:rustc-env=LUKSBOX_LIBFIDO2_VERSION=vcpkg");
        lib.include_paths
    } else {
        let hint = if target.contains("windows") {
            "Install via vcpkg (`vcpkg install libfido2:x64-windows`) and set \
             VCPKG_ROOT, or set LIBFIDO2_LIB_DIR + LIBFIDO2_LIB_NAME to point at \
             a manual build."
        } else if target.contains("apple") {
            "Install via Homebrew: `brew install libfido2 pkg-config`."
        } else {
            "Install libfido2-dev (Debian/Ubuntu) or libfido2-devel (RHEL) and \
             pkg-config."
        };
        panic!("libfido2 not found. {hint}");
    };

    // ---- bindgen ----------------------------------------------------------

    let mut builder = bindgen::Builder::default()
        .header_contents("wrapper.h", "#include <fido.h>\n")
        // Restrict the generated surface to the symbols we actually use.
        // Keeps the bindings small (a few hundred lines vs the about 5k that
        // `<fido.h>` would generate), makes diff-against-libfido2-version
        // tractable for review, and limits the unsafe surface that
        // future maintainers / auditors must walk.
        .allowlist_function("fido_(init|dev_(new|free|info_(new|free|manifest|ptr|path|manufacturer_string|product_string)|open|close|make_cred|get_assert)|cred_(new|free|set_type|set_clientdata_hash|set_rp|set_user|set_extensions|set_rk|set_uv|id_ptr|id_len)|assert_(new|free|set_clientdata_hash|set_rp|allow_cred|set_extensions|set_hmac_salt|set_up|set_uv|count|hmac_secret_ptr|hmac_secret_len)|strerr)")
        .allowlist_var("FIDO_(OK|DEBUG|ERR_.*|EXT_HMAC_SECRET|OPT_.*)")
        .allowlist_var("COSE_ES256")
        .allowlist_type("fido_(dev|cred|assert|dev_info|opt)_t")
        // libfido2's `<fido/err.h>` mixes positive (CTAP-defined) and
        // negative (libfido2-internal) error codes. Bindgen's default
        // would type the positive ones as `u32` and the negative ones
        // as `i32`, breaking match-arm consistency at our call sites.
        // Force everything to `i32` (== `c_int`), matching libfido2's
        // own function-return type.
        .default_macro_constant_type(bindgen::MacroTypeVariation::Signed)
        // Generate `unsafe extern "C"` blocks (Rust 2024 requirement) and
        // pure constant declarations for the macros we need.
        .wrap_unsafe_ops(true)
        // libfido2 doesn't change layout in patch releases; we don't need
        // bindgen's heuristics for layout tests.
        .layout_tests(false)
        .derive_debug(false)
        .merge_extern_blocks(true)
        // Make the generated bindings idiomatic: `*mut fido_dev_t` instead
        // of `*mut fido_dev`. This matches what we had hand-rolled.
        .generate_comments(false);

    for path in &include_paths {
        builder = builder.clang_arg(format!("-I{}", path.display()));
    }

    // libclang (without the matching `clang-tools` / `clang-XX` package
    // installed) doesn't ship its own bundled stddef.h / limits.h /
    // stdint.h. /usr/include/limits.h does `#include_next <limits.h>`
    // expecting to find the toolchain's copy; bindgen-clang then fails
    // with "limits.h: file not found" on minimal hosts. Probe gcc and
    // clang for their resource dirs and add them as fallback search
    // paths. Best-effort, failures here aren't fatal because most dev
    // environments ship one of the two.
    for cmd in ["clang", "gcc"] {
        if let Ok(out) = std::process::Command::new(cmd)
            .arg("-print-file-name=include")
            .output()
        {
            if out.status.success() {
                let dir = String::from_utf8_lossy(&out.stdout).trim().to_string();
                if !dir.is_empty() && std::path::Path::new(&dir).exists() {
                    builder = builder.clang_arg(format!("-isystem{dir}"));
                }
            }
        }
    }

    let out_dir = PathBuf::from(env::var("OUT_DIR").expect("OUT_DIR set by cargo"));
    let out_path = out_dir.join("fido2_bindings.rs");

    let bindings = builder
        .generate()
        .unwrap_or_else(|e| panic!("bindgen failed to generate libfido2 bindings: {e}"));
    bindings
        .write_to_file(&out_path)
        .unwrap_or_else(|e| panic!("could not write libfido2 bindings to {out_path:?}: {e}"));
}
