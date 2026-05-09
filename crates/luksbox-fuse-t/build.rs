// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Penthertz <https://penthertz.com> (https://x.com/PentHertz)

//! Build script for luksbox-fuse-t.
//!
//! On macOS:
//!   1. Probe pkg-config for `fuse-t.pc`. FUSE-T installs this at
//!      `/usr/local/lib/pkgconfig/fuse-t.pc` (Homebrew --cask fuse-t).
//!      The probe yields `-L/usr/local/lib -lfuse-t -I/usr/local/include`.
//!   2. Run bindgen against `<fuse_t/fuse.h>` (or the libfuse 2.x
//!      `<fuse.h>` shipped in FUSE-T's include dir, depending on which
//!      install layout is on the host) to generate Rust declarations
//!      for the libfuse 2.x high-level API used by `src/sys.rs`.
//!   3. Emit `cargo:rustc-link-lib=fuse-t` so the final binary links
//!      libfuse-t.dylib at runtime.
//!
//! On non-macOS targets the build script is a no-op, the crate's
//! `lib.rs` exposes a stub `mount()` that returns `Error::Unsupported`.
//!
//! If FUSE-T is not installed on the macOS build host, the probe fails
//! with a clear message pointing at the install command. The crate
//! still has to be in the workspace (so the workspace resolves), but
//! `luksbox-mount` only depends on it when the `fuse-t` feature is on,
//! so a host without FUSE-T can build the rest of the workspace by
//! omitting that feature.

#[cfg(target_os = "macos")]
fn main() {
    use std::env;
    use std::path::PathBuf;

    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-changed=wrapper.h");
    println!("cargo:rerun-if-env-changed=FUSE_T_INCLUDE_DIR");
    println!("cargo:rerun-if-env-changed=PKG_CONFIG_PATH");

    // Step 1: pkg-config probe. We accept either `fuse-t.pc` (FUSE-T's
    // canonical .pc file) or the libfuse 2.x-compatible `fuse.pc` that
    // some FUSE-T builds also install. Order matters, prefer the
    // FUSE-T-native .pc since that names libfuse-t.dylib explicitly.
    //
    // Version contract: we target the libfuse 2.9 ABI (FUSE_USE_VERSION
    // = 29), which FUSE-T 1.x has shipped since its first release. The
    // `>=1.0.0` floor is the minimum we've validated against; lower
    // versions might work but haven't been tested. Upper bound is left
    // open, FUSE-T's 1.x line has been ABI-stable so far. If a 2.x
    // release breaks this, src/ops.rs's runtime `fuse_version()` check
    // catches the mismatch at mount time.
    let probe = pkg_config::Config::new()
        .atleast_version("1.0.0")
        .probe("fuse-t")
        .or_else(|first_err| {
            // Fallback for hand-built FUSE-T installs that only register
            // the libfuse 2.9 ABI .pc. Caller must provide
            // FUSE_T_INCLUDE_DIR if the headers aren't in the standard
            // locations. We still emit the link flag manually below so
            // we don't accidentally pick up macFUSE's libfuse if both
            // are installed.
            pkg_config::Config::new()
                .atleast_version("2.6.0")
                .probe("fuse-t-libfuse2")
                .map_err(|second_err| {
                    eprintln!(
                        "luksbox-fuse-t: pkg-config could not find FUSE-T.\n  \
                         tried: fuse-t (>= 1.0.0): {first_err}\n  \
                         tried: fuse-t-libfuse2 (>= 2.6.0): {second_err}\n\n\
                         Install FUSE-T and re-run:\n  \
                         brew install --cask fuse-t\n\n\
                         If you installed FUSE-T to a non-standard prefix, \
                         export PKG_CONFIG_PATH=/your/prefix/lib/pkgconfig \
                         before re-running cargo build."
                    );
                    panic!("FUSE-T not detected; see above");
                })
        })
        .expect("pkg-config probe panicked");

    // pkg_config::probe automatically emits `cargo:rustc-link-lib=...`
    // for every library named in the .pc Libs: line. If the probe
    // succeeded for `fuse-t.pc` we're done with link flags. Defensive:
    // re-emit explicitly so the link is unambiguous regardless of how
    // .pc-named the library.
    println!("cargo:rustc-link-lib=fuse-t");

    // Step 2: bindgen against the FUSE-T headers. We wrap the includes
    // in a small `wrapper.h` (committed alongside this build.rs) so the
    // bindgen invocation is identical regardless of whether the host
    // installed FUSE-T's `<fuse_t/fuse.h>` or the libfuse-2.9-shaped
    // `<fuse.h>`.
    let mut builder = bindgen::Builder::default()
        .header("wrapper.h")
        // FUSE-T's include dir is in the pkg-config result; surface it
        // to clang.
        .clang_args(
            probe
                .include_paths
                .iter()
                .map(|p| format!("-I{}", p.display())),
        )
        // Rust 2024 edition (which the workspace uses) promotes the
        // `unsafe_op_in_unsafe_fn` lint to a hard error: every unsafe
        // operation inside an `unsafe fn` body must be wrapped in an
        // explicit `unsafe { ... }` block. bindgen's default output
        // relies on the 2021 behaviour (the `unsafe fn` body was
        // implicitly unsafe, no inner block needed). `wrap_unsafe_ops`
        // makes bindgen emit the explicit blocks, which compiles
        // under both editions. Without it, the bitfield helper code
        // bindgen generates for `struct fuse_operations`'s flag bits
        // fails to build on 2024 with E0133.
        .wrap_unsafe_ops(true)
        // FUSE protocol version macros. libfuse 2.x checks
        // FUSE_USE_VERSION at compile time and reshapes
        // `struct fuse_operations` accordingly. We pin to 29 (libfuse
        // 2.9), matching what FUSE-T claims to provide. A 3.x-style
        // bind would need FUSE_USE_VERSION=31 and the `fuse_lowlevel.h`
        // headers, that's a Phase 2 expansion if FUSE-T's libfuse 2.x
        // shim turns out to be too thin for our needs.
        .clang_arg("-DFUSE_USE_VERSION=29")
        .clang_arg("-D_FILE_OFFSET_BITS=64")
        // Allowlist. We don't want bindgen to pull in every libc decl
        // it transitively reaches; restrict to the FUSE symbols we
        // actually call from `src/sys.rs`. If the binding ever needs a
        // new symbol, add it here so the surface area stays auditable.
        .allowlist_function("fuse_.*")
        .allowlist_type("fuse_.*")
        .allowlist_var("FUSE_.*")
        // libc types referenced by FUSE callbacks. Keep these
        // explicit, do NOT use blocklist_type, we want the strict types
        // generated so the safe wrapper enforces the right signatures.
        .allowlist_type("stat")
        .allowlist_type("statvfs")
        .allowlist_type("timespec")
        .allowlist_type("flock")
        .layout_tests(false)
        // FUSE has a few callback-typed function pointers; bindgen's
        // default `derive_default` produces compile errors on those.
        .derive_default(false)
        // Use core + libc for std types so the binding compiles in
        // no_std contexts too (we don't need that today, but it costs
        // nothing and keeps the binding lean).
        .use_core();

    // If a custom include dir was provided via env, prepend it.
    if let Ok(dir) = env::var("FUSE_T_INCLUDE_DIR") {
        builder = builder.clang_arg(format!("-I{dir}"));
    }

    let bindings = builder.generate().expect(
        "bindgen failed to generate FUSE-T bindings; \
                 check that fuse_t/fuse.h or fuse.h is reachable via \
                 the include paths printed above",
    );

    let out_path = PathBuf::from(env::var("OUT_DIR").unwrap());
    bindings
        .write_to_file(out_path.join("bindings.rs"))
        .expect("failed to write FUSE-T bindings.rs");

    // Snapshot mode: when `regenerate-bindings` is on, ALSO write the
    // generated bindings into the source tree at
    // `src/bindings_generated.rs` so a developer can `git diff` and
    // commit them. The regular include in `src/sys.rs` reads from
    // OUT_DIR (Phase 1); Phase 2 flips to read the committed snapshot
    // by default and gate bindgen behind this feature.
    if env::var("CARGO_FEATURE_REGENERATE_BINDINGS").is_ok() {
        let manifest_dir = PathBuf::from(env::var("CARGO_MANIFEST_DIR").unwrap());
        let snapshot = manifest_dir.join("src").join("bindings_generated.rs");
        bindings
            .write_to_file(&snapshot)
            .expect("failed to write FUSE-T bindings snapshot");
        println!(
            "cargo:warning=wrote bindings snapshot to {}",
            snapshot.display()
        );
    }
}

#[cfg(not(target_os = "macos"))]
fn main() {
    // Non-macOS: nothing to do. The crate's lib.rs exposes a stub
    // `mount()` that errors at runtime, and luksbox-mount only takes
    // a dependency on this crate inside a `cfg(target_os = "macos")`
    // target table.
    println!("cargo:rerun-if-changed=build.rs");
}
