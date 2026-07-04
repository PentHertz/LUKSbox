// Compiles and links the CryptoKit Swift shim, but ONLY on
// `all(feature = "hardware", target_os = "macos")` AND only when a
// Swift toolchain (`swiftc`) is actually present. Every other build
// (default, any non-macOS target, OR a macOS cross-build from a host
// without swiftc such as osxcross) compiles the pure-Rust stub + mock
// and needs no Swift toolchain. The `sep_real` cfg, emitted only when
// the shim is built, gates the real backend in src/lib.rs.

use std::env;
use std::path::PathBuf;
use std::process::Command;

fn main() {
    // Declare the cfg name unconditionally so `#[cfg(sep_real)]` in the
    // crate never trips the unexpected-cfg lint, regardless of platform.
    println!("cargo::rustc-check-cfg=cfg(sep_real)");

    let target_os = env::var("CARGO_CFG_TARGET_OS").unwrap_or_default();
    let hardware = env::var("CARGO_FEATURE_HARDWARE").is_ok();

    if target_os != "macos" || !hardware {
        // Stub build: nothing to compile or link.
        return;
    }

    // The real backend needs `swiftc` (CryptoKit Secure Enclave shim).
    // If it's missing -- e.g. cross-compiling to macOS from Linux via
    // osxcross, which provides clang but no Swift toolchain -- fall
    // back to the stub instead of failing the build. SEP ops then
    // return `NotCompiledIn` at runtime, exactly like a non-macOS
    // target. This keeps `--features hardware` (which also drives the
    // FIDO2/TPM links) buildable everywhere.
    let have_swiftc = Command::new("swiftc")
        .arg("--version")
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false);
    if !have_swiftc {
        println!(
            "cargo:warning=swiftc not found; luksbox-sep Secure Enclave backend \
             compiled as a stub (SEP enroll/unlock will error at runtime). Build \
             on a real macOS host with the Swift toolchain to enable it."
        );
        return;
    }

    let shim = "swift/SepShim.swift";
    println!("cargo:rerun-if-changed={shim}");
    println!("cargo:rerun-if-changed=build.rs");

    let out_dir = PathBuf::from(env::var("OUT_DIR").expect("OUT_DIR"));
    let archive = out_dir.join("libluksbox_sepshim.a");

    // Static archive of the shim, so the downstream `luksbox-cli` /
    // `luksbox-gui` binary needs NO dylib at runtime (an earlier
    // dynamic approach broke because a dependency build script's rpath
    // doesn't propagate to the downstream binary's link). Apple no
    // longer supports `-static-stdlib`, so the Swift RUNTIME stays
    // dynamic - but it ships in the dyld shared cache (`/usr/lib/swift`)
    // on every macOS >= 10.14.4, resolved automatically at runtime. The
    // archive's objects carry LC_LINKER_OPTION autolink entries that
    // request swiftCore et al.; we just give the linker the SDK's Swift
    // stub dir so they resolve at link time.
    let status = Command::new("swiftc")
        .args([
            "-emit-library",
            "-static",
            "-O",
            "-module-name",
            "LuksboxSepShim",
            "-o",
        ])
        .arg(&archive)
        .arg(shim)
        .status()
        .expect("failed to invoke swiftc");
    assert!(status.success(), "swiftc failed to build {shim}");

    // SDK Swift lib dir (link-time .tbd stubs for the runtime).
    if let Ok(out) = Command::new("xcrun").args(["--show-sdk-path"]).output() {
        if out.status.success() {
            let sdk = String::from_utf8_lossy(&out.stdout).trim().to_string();
            if !sdk.is_empty() {
                println!("cargo:rustc-link-search=native={sdk}/usr/lib/swift");
            }
        }
    }
    // Runtime Swift libs (dyld shared cache); also the historical
    // on-disk location, harmless if absent.
    println!("cargo:rustc-link-search=native=/usr/lib/swift");

    println!("cargo:rustc-link-search=native={}", out_dir.display());
    println!("cargo:rustc-link-lib=static=luksbox_sepshim");

    // Frameworks the shim pulls in.
    println!("cargo:rustc-link-lib=framework=CoreFoundation");
    println!("cargo:rustc-link-lib=framework=Foundation");
    println!("cargo:rustc-link-lib=framework=Security");
    println!("cargo:rustc-link-lib=framework=LocalAuthentication");

    // Real backend is available: gate it on in src/lib.rs.
    println!("cargo:rustc-cfg=sep_real");
}
