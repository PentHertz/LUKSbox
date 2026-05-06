# Building luksbox

End-to-end build guide for `luksbox` (CLI) and `luksbox-gui` on every
supported target. Three paths:

| Path | When |
|---|---|
| **Native** (this file, sections per OS) | You're on the OS you want to build for. |
| **Cross-compile from Linux** ([§ Cross-compiling](#cross-compiling-from-linux)) | One Linux box, multiple targets. Uses [`scripts/build_release.sh`](scripts/build_release.sh). |
| **GitHub Actions** ([§ CI release](#ci-release-no-local-toolchain-needed)) | You don't want to install any of the below; let the workflow runners build. |

If you only want to **run** a prebuilt binary, jump to
[Runtime dependencies](#runtime-dependencies-end-users).

---

## Common prerequisites (every platform)

- **Rust 1.88+** (workspace MSRV, pinned in `Cargo.toml`).
  Install via [rustup](https://rustup.rs).
- **Git**, to clone the repo.
- A C toolchain (`cc` / `clang` / MSVC), required by `bindgen` for the
  libfido2 FFI bindings and by some sys crates.

The CLI's default feature set is `["hardware"]`, which links against
**libfido2** (Yubico's reference C library). If you don't need YubiKey
support, build with `--no-default-features` and skip every libfido2
dependency in this guide.

### Optional, app icons

The Windows `.exe` icon and the macOS `.app` icon are derived from
`crates/luksbox-gui/assets/icon.png` by `scripts/build_icons.sh`
(needs ImageMagick). The script writes:

- `crates/luksbox-gui/assets/icon.ico` - embedded into `luksbox-gui.exe`
  by the GUI crate's `build.rs` via the `winresource` crate.
- `crates/luksbox-gui/assets/icon.icns` - copied into the macOS .app
  bundle's `Contents/Resources/`.

Both files are `.gitignored`. Run the script once after a fresh
checkout if you want the embedded `.exe` icon:

```bash
bash scripts/build_icons.sh
```

`cargo build` works without it (the build script just emits a warning
and skips the icon embed). On Linux there's nothing to generate, the
window/launcher icon comes from `assets/icon.png` directly via
`dist/luksbox.desktop` + `eframe`'s runtime icon API.

---

## Native build, Linux

### Build dependencies (Debian / Ubuntu)

```bash
sudo apt update
sudo apt install -y \
    build-essential pkg-config clang \
    libfido2-dev libssl-dev libudev-dev zlib1g-dev \
    libfuse3-dev
```

For the GUI (egui + GTK3 file picker via `rfd`):

```bash
sudo apt install -y libgtk-3-dev
```

### Build dependencies (Fedora / RHEL)

```bash
sudo dnf install -y \
    gcc clang pkgconfig \
    libfido2-devel openssl-devel systemd-devel zlib-devel \
    fuse3-devel
# GUI:
sudo dnf install -y gtk3-devel
```

### Build dependencies (Arch)

```bash
sudo pacman -S --needed \
    base-devel clang pkgconf \
    libfido2 openssl systemd-libs zlib \
    fuse3
# GUI:
sudo pacman -S --needed gtk3
```

### Build

```bash
git clone <repo-url> luksbox && cd luksbox
cargo build --release -p luksbox-cli                 # CLI, with libfido2
cargo build --release -p luksbox-gui                 # GUI
cargo build --release --no-default-features          # software-only (no libfido2)
```

Binaries land in `target/release/luksbox` and `target/release/luksbox-gui`.

### Smoke test

```bash
cargo test --workspace --exclude luksbox-fuzz --exclude luksbox-fuzz-afl
./target/release/luksbox --help
```

---

## Native build, macOS

Works on both Intel (`x86_64-apple-darwin`) and Apple Silicon
(`aarch64-apple-darwin`). Build naturally for whichever Mac you're on.

### Build dependencies

1. **Xcode Command Line Tools** (provides `clang`, `cc`, headers):
   ```bash
   xcode-select --install
   ```

2. **Homebrew + libfido2 + pkg-config**:
   ```bash
   /bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"
   brew install libfido2 pkg-config
   ```

3. **macFUSE** (required for the `mount` subcommand):
   ```bash
   brew install --cask macfuse
   ```
   macFUSE installs a kernel extension that macOS blocks by default.
   On first install, approve it under **System Settings -> Privacy &
   Security**, then reboot. **Apple Silicon** also needs the
   security policy lowered to "Reduced Security" via Recovery Mode
   first (boot holding the power button, -> Options ->
   Startup Security Utility -> Reduced Security -> check "Allow user
   management of kernel extensions from identified developers").
   Both are one-time per-machine setup. Without macFUSE the CLI
   still builds and every subcommand *except* `mount` works.

   FUSE-T (https://www.fuse-t.org/) is a tempting alternative
   because it's kext-free (uses NFS internally), but the underlying
   `fuser` Rust crate we use hard-requires the libfuse2 ABI on macOS
   that only macFUSE provides; FUSE-T provides only libfuse3.
   Switching to FUSE-T would mean swapping `fuser` for a
   libfuse3-aware Rust crate (no widely-used one ships today).

   **The `fuse` feature is gated on macFUSE being detectable at
   build time.** `scripts/build_release.sh` and
   `.github/workflows/release.yml` probe for `fuse.pc` in
   `/usr/local/lib/pkgconfig`, `/opt/homebrew/lib/pkgconfig`, and
   `/Library/Frameworks/macFUSE.framework/Versions/A/lib/pkgconfig`,
   and only enable the `fuse` feature when one is found. If you
   build the CLI/GUI before installing macFUSE, the resulting binary
   will compile fine but `luksbox mount ...` returns
   `mount target not supported on this platform` - install macFUSE,
   then `cargo clean -p luksbox-mount` and rebuild. A plain
   `cargo build --release -p luksbox-cli` (no `--no-default-features`)
   uses the workspace defaults `["hardware", "fuse", "winfsp"]` and
   pulls in `fuse` automatically as long as `pkg-config libfuse`
   resolves.

### Plumb pkg-config

Homebrew's prefix differs between Intel and Apple Silicon:

```bash
# Apple Silicon
export PKG_CONFIG_PATH="$(brew --prefix libfido2)/lib/pkgconfig:$(brew --prefix openssl@3)/lib/pkgconfig"
# Intel, same line works because `brew --prefix` resolves correctly
```

Add that line to your `~/.zshrc` if you'll be rebuilding often.

### Build

```bash
git clone <repo-url> luksbox && cd luksbox
cargo build --release -p luksbox-cli
cargo build --release -p luksbox-gui
```

If `cargo build` complains it can't find `fido.h`, your
`PKG_CONFIG_PATH` isn't set, re-export it.

### Universal binary (Intel + Apple Silicon in one)

```bash
rustup target add x86_64-apple-darwin aarch64-apple-darwin
cargo build --release --target x86_64-apple-darwin -p luksbox-cli
cargo build --release --target aarch64-apple-darwin -p luksbox-cli
mkdir -p dist/macos-universal
lipo -create -output dist/macos-universal/luksbox \
    target/x86_64-apple-darwin/release/luksbox \
    target/aarch64-apple-darwin/release/luksbox
file dist/macos-universal/luksbox        # -> "Mach-O universal binary with 2 architectures"
```

---

## Native build, Windows

Two flavours: **MSVC** (recommended, matches the official release)
and **MSYS2 / MinGW** (works with the same scripts you'd use on
Linux).

### MSVC build (recommended)

1. **Install Rust with the MSVC toolchain** from <https://rustup.rs>.
   Pick `x86_64-pc-windows-msvc` when prompted.

2. **Install the Visual Studio Build Tools** (the C compiler + Windows
   SDK rustup will use):
   - Download the [Build Tools for Visual Studio](https://visualstudio.microsoft.com/downloads/#build-tools-for-visual-studio-2022).
   - In the installer pick **"Desktop development with C++"**,
     that gives you `cl.exe`, `link.exe`, the Windows 10/11 SDK,
     and CMake.

3. **Install vcpkg + libfido2** (built once, reused by every cargo build):
   ```powershell
   git clone https://github.com/microsoft/vcpkg "$env:USERPROFILE\vcpkg"
   & "$env:USERPROFILE\vcpkg\bootstrap-vcpkg.bat"
   & "$env:USERPROFILE\vcpkg\vcpkg.exe" install libfido2:x64-windows-static-md
   $env:VCPKG_ROOT     = "$env:USERPROFILE\vcpkg"
   $env:VCPKGRS_TRIPLET = "x64-windows-static-md"
   ```
   The `vcpkg` Rust crate (used by `luksbox-fido2/build.rs`) will
   pick up `$VCPKG_ROOT` and `$VCPKGRS_TRIPLET` and link statically
   against libfido2 + its transitive deps (libcbor, libcrypto, zlib,
   hidapi).

4. **Install LLVM** (provides `libclang.dll` that `bindgen` needs):
   ```powershell
   winget install LLVM.LLVM
   $env:LIBCLANG_PATH = "C:\Program Files\LLVM\bin"
   ```

5. **WinFsp** (only for the `mount` subcommand):
   - Download and install **WinFsp 2.x** from <https://winfsp.dev>.
     This installs the kernel driver (needed at runtime) and the dev
     headers (needed at build time for the `winfsp_wrs` crate).
   - To verify both build-time and runtime work end-to-end:
     ```powershell
     cargo test --release -p luksbox-mount --test winfsp_mount -- --test-threads=1
     ```
     This mounts a real luksbox vault on a free drive letter, queries
     it via Win32, and tears it down - so a green run proves the
     SDK + driver + Rust binding pipeline are all wired up correctly.
     See [`crates/luksbox-mount/src/winfsp.rs`](crates/luksbox-mount/src/winfsp.rs)
     for the gotchas the WinFsp adapter has hit on Win11 / WinFsp 2.x
     (the file's top-level docstring catalogues them).

6. **Build**:
   ```powershell
   git clone <repo-url> luksbox
   cd luksbox
   cargo build --release -p luksbox-cli
   cargo build --release -p luksbox-gui
   ```
   Binaries: `target\release\luksbox.exe`, `target\release\luksbox-gui.exe`.

### MSYS2 / MinGW build (alternative)

1. Install [MSYS2](https://www.msys2.org), open the **MSYS2 MINGW64**
   shell, then:
   ```bash
   pacman -Syu
   pacman -S --needed mingw-w64-x86_64-toolchain mingw-w64-x86_64-clang \
                      mingw-w64-x86_64-pkgconf mingw-w64-x86_64-libfido2 \
                      mingw-w64-x86_64-rust git
   ```
2. From the same shell:
   ```bash
   git clone <repo-url> luksbox && cd luksbox
   cargo build --release -p luksbox-cli
   ```
   The `--features hardware` build works because mingw-w64 has its own
   libfido2 package. WinFsp is still required separately for `mount`.

---

## Cross-compiling from Linux

Use [`scripts/build_release.sh`](scripts/build_release.sh), it covers
all 5 targets and prints clear setup hints when a tool is missing. This
section explains the prerequisites for each target so the script can
actually do its work.

### Linux x86_64 -> Linux arm64

```bash
sudo apt install -y gcc-aarch64-linux-gnu
rustup target add aarch64-unknown-linux-gnu
```

For `--features hardware` (libfido2 link against the arm64 sysroot),
also enable arm64 multiarch:

```bash
sudo dpkg --add-architecture arm64
sudo apt update
sudo apt install -y \
    libfido2-dev:arm64 libssl-dev:arm64 libudev-dev:arm64 zlib1g-dev:arm64
```

The script auto-sets `PKG_CONFIG_ALLOW_CROSS=1`,
`PKG_CONFIG_PATH=/usr/lib/aarch64-linux-gnu/pkgconfig`, and
`PKG_CONFIG_SYSROOT_DIR=/`.

```bash
scripts/build_release.sh --targets linux-arm64
```

### Linux x86_64 -> Windows x86_64 (MinGW)

```bash
sudo apt install -y mingw-w64
rustup target add x86_64-pc-windows-gnu
```

**Caveat, libfido2 on mingw cross**: Debian doesn't package libfido2
for the mingw cross-toolchain, so by default
`scripts/build_release.sh` builds the windows target with
`--no-default-features` (no FIDO2 hardware support). Three ways to
get a hardware-enabled Windows binary:

- **Recommended (clean)**: build on a real Windows host using the MSVC
  instructions above, or run `scripts/build_release.sh --gh-dispatch`
  to let the GitHub Actions runner build it with vcpkg.

- **MSYS2 prebuilt packages**: MSYS2 ships precompiled
  `mingw-w64-x86_64-libfido2` (and its transitive deps: libcbor,
  OpenSSL, zlib, hidapi). The helper script
  [`scripts/setup_mingw_libfido2.sh`](scripts/setup_mingw_libfido2.sh)
  fetches them, extracts a local sysroot, and prints the env vars
  `luksbox-fido2/build.rs` understands:
  ```bash
  sudo apt install -y zstd clang
  source <(scripts/setup_mingw_libfido2.sh)                # downloads if needed,
                                                            # then exports env
  scripts/build_release.sh --targets windows-amd64 --gui   # now with libfido2
  ```
  The sysroot lives in `~/.cache/luksbox/mingw-libfido2`. Re-run the
  setup periodically to pick up new libfido2 releases.

- **DIY from source**: cross-build libfido2 + libcbor + OpenSSL with
  mingw yourself and point `LIBFIDO2_LIB_DIR` /
  `LIBFIDO2_INCLUDE_DIR` at the result. Several hours of plumbing,
  only worth it if you can't use any of the above.

**Caveat, WinFsp on mingw cross**: the `mount` subcommand on Windows
links against the WinFsp 2.x SDK. **The MinGW cross-build from Linux
does NOT include WinFsp**, and `luksbox mount` on the resulting `.exe`
returns `MountError::Unsupported`. Every other subcommand (open, ls,
get, put, mkdir, rm, rotate-mvk, enroll, ...) works normally.

Why it doesn't work: `winfsp_wrs_sys`'s `build.rs` decides whether to
emit link directives based on `cfg!(target_os = "windows")`, which
evaluates against the *host* the build script runs on, not the
*target* being built. From a Linux host that returns false, so cargo
never adds `-L`/`-l` for WinFsp, and the linker fails on the first
`Fsp*` symbol. The
[`scripts/setup_mingw_winfsp.sh`](scripts/setup_mingw_winfsp.sh)
helper exists for the day someone patches winfsp_wrs_sys to be
target-conditional; until then, exporting `WINFSP_INC`/`WINFSP_LIB`
won't help.

Three working alternatives for a `mount`-capable Windows binary:

- **`--gh-dispatch`** (recommended): runs `release.yml` on a real
  Windows runner with vcpkg + WinFsp SDK. Produces a working `.exe`
  with no host-side setup.
- **Build natively on Windows** following the MSVC instructions above.
- **Skip mount**: stick with the cross-build's CLI/GUI, accept that
  `mount` returns "not supported". For most use cases (CLI commands,
  GUI file browser) this is fine.

```bash
scripts/build_release.sh --targets windows-amd64           # CLI + libfido2,
                                                            # no mount
```

### Linux x86_64 -> macOS (Intel + Apple Silicon)

This needs **osxcross**, a third-party toolchain that lets you target
Mach-O from Linux. **Apple's license forbids redistributing the macOS
SDK**, so you have to fetch it yourself from a Mac (or your Apple
Developer Downloads page) and let osxcross repackage it.

#### One-time osxcross setup

```bash
# 1. Build prerequisites
sudo apt install -y clang cmake patch python3 libssl-dev lzma-dev libxml2-dev

# 2. Get the toolchain source
git clone https://github.com/tpoechtrager/osxcross
cd osxcross

# 3. Obtain the macOS SDK (Apple license, you provide it):
#    - On a Mac: cd /Applications/Xcode.app/Contents/Developer/Platforms/MacOSX.platform/Developer/SDKs
#      then `tar -czf MacOSX14.sdk.tar.gz MacOSX14.sdk` and copy it over.
#    - Or download Xcode_*.xip from https://developer.apple.com/download
#      and run `tools/gen_sdk_package.sh` from osxcross.
mv MacOSX14.sdk.tar.gz tarballs/

# 4. Build the cross-toolchain (~30 min)
UNATTENDED=1 ./build.sh

# 5. Export so the build script finds it
export OSXCROSS_ROOT="$PWD/target"
export PATH="$OSXCROSS_ROOT/bin:$PATH"
```

#### libfido2 in the cross sysroot

osxcross ships an `osxcross-macports` wrapper that fetches and unpacks
prebuilt MacPorts packages into `$OSXCROSS_ROOT/macports/pkgs`:

```bash
"$OSXCROSS_ROOT/bin/osxcross-macports" install libfido2
```

The script auto-discovers this and sets `PKG_CONFIG_PATH` /
`PKG_CONFIG_SYSROOT_DIR` to point at the MacPorts tree.

#### Build

```bash
rustup target add x86_64-apple-darwin aarch64-apple-darwin
scripts/build_release.sh --targets macos-amd64,macos-arm64
```

If you don't want to deal with osxcross, two cleaner options:
- Build natively on a Mac (instructions above).
- Trigger CI: `scripts/build_release.sh --gh-dispatch`.

### `cross` (Docker) as an alternative

Every non-host target the script supports can be routed through
[`cross`](https://github.com/cross-rs/cross) instead of the native
toolchain, useful if you'd rather pull a Docker image than apt-install
a multi-GB cross-compiler:

```bash
cargo install cross --git https://github.com/cross-rs/cross
scripts/build_release.sh --use-cross --targets linux-arm64,windows-amd64
```

`cross` doesn't help for macOS targets (no Apple SDK in any image).

---

## CI release (no local toolchain needed)

The repo ships [`.github/workflows/release.yml`](.github/workflows/release.yml)
which builds Linux amd64, Windows amd64 (MSVC), macOS Intel and macOS
Apple Silicon on real runners with full libfido2 support. Trigger it:

```bash
scripts/build_release.sh --gh-dispatch        # needs `gh` CLI authed
# or, on the GitHub UI: Actions -> Release -> "Run workflow"
# or, on a tag push:    git tag v0.1.x && git push --tags
```

Artifacts attached to each GitHub Release:

| Target | Artifact | Notes |
|---|---|---|
| Linux x86_64 | `luksbox-vX.Y.Z-x86_64-linux.tar.gz` | extract, run `./install.sh` (offers TPM perm setup if a TPM is present) |
| Linux aarch64 | `luksbox-vX.Y.Z-aarch64-linux.tar.gz` | extract, run `./install.sh` (offers TPM perm setup if a TPM is present) |
| macOS aarch64 (.dmg) | `luksbox-vX.Y.Z-aarch64-macos.dmg` | drag .app to /Applications, libfido2 bundled inside |
| macOS aarch64 (portable) | `luksbox-vX.Y.Z-aarch64-macos-portable.tar.gz` | bare CLI + GUI binaries, no .app, no Gatekeeper quarantine |
| Windows x86_64 (installer) | `luksbox-vX.Y.Z-x86_64-windows.msi` | double-click, .lbx association + Start menu + PATH |
| Windows x86_64 (portable) | `luksbox-vX.Y.Z-x86_64-windows.zip` | unzip, run, no install |
| All targets | `SHA256SUMS.txt` | `sha256sum -c` to verify |

The macOS **portable .tar.gz** is the .dmg's binaries flattened into
a `bin/` + `Frameworks/` layout. Use it when you don't want to deal
with the .app bundle, the Gatekeeper "downloaded from the internet"
warning, or the `com.apple.quarantine` xattr - extracting via
`tar xzf` from Terminal does not propagate quarantine to the
extracted files. Run in place with `./bin/luksbox` /
`./bin/luksbox-gui`; do NOT move `bin/luksbox` alone into
`/usr/local/bin` because the bundled dylibs are referenced via
`@executable_path/../Frameworks/` and the relative path only
resolves from inside the extracted tree. The archive ships with a
`README-MACOS.txt` that spells this out.

Both macOS artifacts ship with FUSE support compiled in iff the CI
runner had macFUSE installed when the workflow ran, see "macFUSE"
under [Native build, macOS](#native-build-macos).

### Optional, code signing + notarization

Without certs the workflow still builds usable artifacts, but:
- macOS shows a Gatekeeper warning at first launch (right-click -> Open).
- Windows shows a SmartScreen warning ("Windows protected your PC").
- The MSI installs without complaint but the .exe inside is unsigned.

To turn on signing, add these GitHub Actions repository secrets:

**macOS** (Apple Developer Program, $99/yr):
- `APPLE_DEV_ID_CERT_P12_BASE64`, the .p12 export of your Developer ID Application certificate, base64-encoded
- `APPLE_DEV_ID_CERT_PASSWORD`, the password used when exporting the .p12
- `APPLE_DEV_ID_IDENTITY`, the certificate's Common Name (e.g. `Developer ID Application: Penthertz (TEAMID)`)
- `APPLE_NOTARY_USER`, your Apple ID
- `APPLE_NOTARY_PASSWORD`, an app-specific password from appleid.apple.com
- `APPLE_NOTARY_TEAM_ID`, your Apple Developer Team ID

**Windows** (any Authenticode certificate):
- `WINDOWS_PFX_BASE64`, the .pfx file base64-encoded
- `WINDOWS_PFX_PASSWORD`, the password protecting the .pfx

The `if:` guards on each signing step are `secrets.X != ''` so the
build silently skips the step on forks / CI runs without secrets.

---

## Runtime dependencies (end users)

What a user needs **installed** to run a prebuilt `luksbox` binary,
i.e., what *isn't* statically linked.

### Linux (Debian / Ubuntu)

```bash
sudo apt install -y \
    libfido2-1            \  # FIDO2 / YubiKey support
    libfuse3-3            \  # for `luksbox mount`
    libgtk-3-0               # only if you use luksbox-gui
```

`libssl3`, `libudev1`, `zlib1g` are part of any modern desktop install
but listed here for reference.

### Linux (Fedora / RHEL)

```bash
sudo dnf install -y libfido2 fuse3-libs gtk3
```

### Linux (Arch)

```bash
sudo pacman -S --needed libfido2 fuse3 gtk3
```

### macOS

If you installed via the **official .dmg release**, libfido2 is
bundled inside `LUKSbox.app/Contents/Frameworks/`. No `brew install`
required for the GUI / CLI to start.

If you grabbed the **portable .tar.gz** release
(`luksbox-vX.Y.Z-aarch64-macos-portable.tar.gz`), libfido2 + its
transitive deps are bundled under the extracted `Frameworks/`
directory next to `bin/`. Run from the extracted tree
(`./bin/luksbox`); no Homebrew install needed for FIDO2 to work.

For `luksbox mount` (either release flavor), you need **macFUSE**
installed system-wide:

```bash
brew install --cask macfuse
```

macFUSE installs a kernel extension. Approve it under **System
Settings -> Privacy & Security** on first prompt and reboot. Apple
Silicon also requires lowering the security policy to "Reduced
Security" via Recovery Mode -> Startup Security Utility first. One-
time per-machine setup; mount works after that.

If you built from source, or want the bare CLI on PATH:

```bash
brew install libfido2
brew install --cask macfuse        # only for `luksbox mount`
```

(FUSE-T is a kext-free alternative we'd love to use but the
underlying `fuser` Rust crate hard-requires macFUSE's libfuse2
ABI on macOS. See the build instructions for details.)

### Windows

- **libfido2**: bundled (statically linked when built via the official
  release workflow); no separate install.
- **WinFsp 2.x runtime**: install from <https://winfsp.dev/rel/>,
  required for the `mount` subcommand. Without it, `mount` returns a
  clear "WinFsp driver not present" error and every other subcommand
  works.

### Hardware (optional but recommended)

A FIDO2-capable security key with the **hmac-secret** extension,
YubiKey 5 series (USB-A, USB-C, NFC, Nano, Bio), SoloKey 2, OnlyKey,
Token2, Nitrokey 3 / FIDO2, etc. The CLI/GUI also works without one
(passphrase + optional PQ-KEM seed).

On Linux, plug-and-play udev rules ship with `libfido2`; on Wayland
desktops you typically also want:

```bash
sudo apt install -y fido2-tools          # `fido2-token -L` to list keys
```

---

## Verifying a build

Whichever path you used:

```bash
./luksbox --version
./luksbox info <vault.lbx>            # smoke test against a vault
cargo test --workspace                  # if you built from source
```

The full security-regression matrix runs as 10 named gate suites in
[`.github/workflows/ci.yml`](.github/workflows/ci.yml); see
[`TESTING.md`](TESTING.md) for instructions on running them locally.

---

## Troubleshooting

| Symptom | Cause / fix |
|---|---|
| `error: linking with cc failed: cannot find -lfido2` | libfido2 not installed for the build target. Linux: `apt install libfido2-dev`. macOS: `brew install libfido2` + export `PKG_CONFIG_PATH`. Windows: `vcpkg install libfido2:x64-windows-static-md` + set `VCPKG_ROOT`. |
| `bindgen ... cannot find libclang.so` | Install `clang`/LLVM: Linux `apt install clang`; Windows `winget install LLVM.LLVM` + `LIBCLANG_PATH=C:\Program Files\LLVM\bin`. |
| `no such file or directory: fuse3.h` | Linux: `apt install libfuse3-dev`. macOS: `brew install --cask macfuse` (build *and* runtime). |
| `the WinFsp driver is not present` at runtime | Install WinFsp 2.x from <https://winfsp.dev/rel/>. |
| Cross-build for arm64 errors `pkg-config has not been configured to support cross-compilation` | The build script handles this for you, set `PKG_CONFIG_ALLOW_CROSS=1` if invoking cargo by hand. |
| osxcross compile fails with `gen_sdk_package.sh` errors | You're missing the SDK tarball under `tarballs/`. Apple license forbids us from shipping it; see the macOS cross section. |
| `accesskit` crate not found when building the GUI | Stale `Cargo.lock`: `cargo update -p egui` or `rm Cargo.lock && cargo build`. |

For anything else, see [`DEVELOPMENT.md`](DEVELOPMENT.md) and
[`TESTING.md`](TESTING.md).
