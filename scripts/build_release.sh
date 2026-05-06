#!/usr/bin/env bash
#
# build_release.sh, cross-platform release builds of the luksbox CLI
# (and optionally the GUI) for:
#
#     linux-amd64    x86_64-unknown-linux-gnu
#     linux-arm64    aarch64-unknown-linux-gnu
#     macos-amd64    x86_64-apple-darwin
#     macos-arm64    aarch64-apple-darwin
#     windows-amd64  x86_64-pc-windows-gnu  (MinGW)
#
# Strategy
# --------
# Default: plain `rustup target add <triple>` + the matching linker /
# C toolchain. No Docker, no `cross`. Works for Linux ↔ Linux ↔ Windows.
# macOS targets still need a real Mac (Apple SDK is not redistributable).
#
# Per-target host prereqs on a Debian/Ubuntu Linux build host:
#
#   linux-amd64    (host build) - no extra deps if your host is already x86_64.
#
#   linux-arm64
#       sudo apt install gcc-aarch64-linux-gnu
#       For --features hardware (libfido2 link), also enable arm64
#       multiarch and install the cross-arch dev libs:
#           sudo dpkg --add-architecture arm64
#           sudo apt update
#           sudo apt install libfido2-dev:arm64 libssl-dev:arm64 \
#                            libudev-dev:arm64 zlib1g-dev:arm64
#       The script auto-sets PKG_CONFIG_ALLOW_CROSS / PKG_CONFIG_PATH
#       so the luksbox-fido2 build.rs probe finds the arm64 .pc files.
#
#   windows-amd64  (x86_64-pc-windows-gnu)
#       sudo apt install mingw-w64
#       libfido2 is not packaged for mingw on Debian, so the windows
#       target is built --no-default-features automatically. To ship a
#       Windows binary WITH libfido2 use the GitHub Actions release
#       workflow (vcpkg builds it on a real Windows runner), see
#       --gh-dispatch below.
#
#   macos-amd64 / macos-arm64
#       Two options:
#         (a) Build on a real Mac:
#             brew install libfido2 pkg-config
#             rustup target add x86_64-apple-darwin aarch64-apple-darwin
#         (b) Cross-compile from Linux via osxcross. The Apple SDK is
#             not redistributable, so you have to fetch it yourself
#             from Xcode (or Apple Developer Downloads) and build the
#             toolchain once:
#                 git clone https://github.com/tpoechtrager/osxcross
#                 # follow osxcross README to package the SDK and run
#                 # ./build.sh, produces target/bin/<triple>-cc etc.
#                 export OSXCROSS_ROOT=/path/to/osxcross/target
#             Then add libfido2 to the cross sysroot via osxcross's
#             MacPorts wrapper:
#                 $OSXCROSS_ROOT/bin/osxcross-macports install libfido2
#             This script auto-detects $OSXCROSS_ROOT and configures
#             the cargo linker + pkg-config sysroot.
#         (c) Or skip locally and let real Mac runners do it via:
#                 scripts/build_release.sh --gh-dispatch
#
# `cross` (Docker) is optional. Use --use-cross to route every non-host
# build through `cross` instead of rustup+linker, useful if your host
# is missing the per-arch C toolchain and you'd rather pull a Docker
# image than apt-install a multi-GB cross compiler.
#
# Outputs land in dist/<target>/ and dist/luksbox-<ver>-<target>.<ext>.
#
# Usage
# -----
#   scripts/build_release.sh                       # every applicable target
#   scripts/build_release.sh --targets linux-amd64,linux-arm64
#   scripts/build_release.sh --no-fido2            # skip libfido2 link
#   scripts/build_release.sh --gui                 # also build luksbox-gui
#   scripts/build_release.sh --profile release-hardened
#   scripts/build_release.sh --use-cross           # route via Docker/cross
#   scripts/build_release.sh --gh-dispatch         # trigger release.yml
#                                                   on GitHub instead
#   scripts/build_release.sh --with-winfsp         # opt in to WinFsp link
#                                                   on windows-* (does NOT
#                                                   work from Linux today,
#                                                   see winfsp_for_target)
#
# Exit codes
#   0   every requested target produced an archive (or was cleanly skipped)
#   1   one or more targets failed
#   2   pre-flight failure (missing rustup; missing tool when needed)

set -euo pipefail

# ---------------------------------------------------------------------------
# defaults

ALL_TARGETS=(linux-amd64 linux-arm64 macos-amd64 macos-arm64 windows-amd64)
SELECTED=("${ALL_TARGETS[@]}")
PROFILE="release"
WITH_FIDO2=1
WITH_GUI=0
WITH_WINFSP=0       # see winfsp_for_target() for why this is opt-in
USE_CROSS=0
GH_DISPATCH_ONLY=0

# ---------------------------------------------------------------------------
# argument parsing

usage() {
    sed -n '2,/^# Exit codes/p' "$0" | sed 's/^# \{0,1\}//'
    exit 0
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --targets)        IFS=',' read -r -a SELECTED <<< "$2"; shift 2 ;;
        --profile)        PROFILE="$2"; shift 2 ;;
        --no-fido2)       WITH_FIDO2=0; shift ;;
        --gui)            WITH_GUI=1; shift ;;
        --with-winfsp)    WITH_WINFSP=1; shift ;;
        --use-cross)      USE_CROSS=1; shift ;;
        --gh-dispatch)    GH_DISPATCH_ONLY=1; shift ;;
        -h|--help)        usage ;;
        *) echo "unknown flag: $1" >&2; echo "see --help" >&2; exit 2 ;;
    esac
done

# ---------------------------------------------------------------------------
# triple lookup

triple_of() {
    case "$1" in
        linux-amd64)   echo "x86_64-unknown-linux-gnu"  ;;
        linux-arm64)   echo "aarch64-unknown-linux-gnu" ;;
        macos-amd64)   echo "x86_64-apple-darwin"       ;;
        macos-arm64)   echo "aarch64-apple-darwin"      ;;
        windows-amd64) echo "x86_64-pc-windows-gnu"     ;;
        *) echo "unknown target: $1" >&2; return 1      ;;
    esac
}

archive_ext_of() {
    case "$1" in windows-*) echo zip ;; *) echo tar.gz ;; esac
}
exe_suffix_of() {
    case "$1" in windows-*) echo .exe ;; *) echo "" ;; esac
}

# ---------------------------------------------------------------------------
# pre-flight

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$REPO_ROOT"

if [[ "$GH_DISPATCH_ONLY" == "1" ]]; then
    if ! command -v gh >/dev/null 2>&1; then
        echo "error: --gh-dispatch needs the GitHub CLI (gh) installed" >&2
        exit 2
    fi
    echo "==> dispatching .github/workflows/release.yml on GitHub"
    gh workflow run release.yml
    echo "    follow with: gh run watch"
    exit 0
fi

if ! command -v rustup >/dev/null 2>&1; then
    echo "error: rustup not found, install from https://rustup.rs" >&2
    exit 2
fi

HOST_TRIPLE="$(rustc -vV | awk '/^host:/ {print $2}')"
HOST_OS="$(uname -s)"
echo "==> host triple: $HOST_TRIPLE  (os: $HOST_OS)"
echo "==> profile:     $PROFILE"
echo "==> fido2:       $([[ $WITH_FIDO2 == 1 ]] && echo on || echo off)"
echo "==> gui:         $([[ $WITH_GUI == 1 ]] && echo on || echo off)"
echo "==> use-cross:   $([[ $USE_CROSS == 1 ]] && echo yes || echo no)"
echo

VERSION="$(awk -F'"' '/^version =/ {print $2; exit}' Cargo.toml || true)"
[[ -z "$VERSION" ]] && VERSION="0.0.0"

mkdir -p dist
SUMMARY=()
FAILED=0

# ---------------------------------------------------------------------------
# per-target environment

# Set linker / pkg-config env for a given triple, when cross-compiling
# from a Linux host without `cross`. Returns 1 if a required tool is
# missing.
configure_target_env() {
    local triple="$1"
    local with_fido2="$2"

    case "$triple" in
        aarch64-unknown-linux-gnu)
            if ! command -v aarch64-linux-gnu-gcc >/dev/null 2>&1; then
                echo "    missing aarch64-linux-gnu-gcc, install with:"
                echo "        sudo apt install gcc-aarch64-linux-gnu"
                return 1
            fi
            export CARGO_TARGET_AARCH64_UNKNOWN_LINUX_GNU_LINKER=aarch64-linux-gnu-gcc
            export CC_aarch64_unknown_linux_gnu=aarch64-linux-gnu-gcc
            if [[ "$with_fido2" == "1" ]]; then
                # arm64 multiarch sysroot, set up by the user as
                # documented in the script header. We only point
                # pkg-config at it.
                export PKG_CONFIG_ALLOW_CROSS=1
                export PKG_CONFIG_PATH="/usr/lib/aarch64-linux-gnu/pkgconfig"
                export PKG_CONFIG_SYSROOT_DIR=/
                if ! pkg-config --exists libfido2 2>/dev/null; then
                    echo "    libfido2 (arm64) not found via pkg-config, install with:"
                    echo "        sudo dpkg --add-architecture arm64 && sudo apt update"
                    echo "        sudo apt install libfido2-dev:arm64 libssl-dev:arm64 \\"
                    echo "                         libudev-dev:arm64 zlib1g-dev:arm64"
                    echo "    (or re-run with --no-fido2 to skip the libfido2 link)"
                    return 1
                fi
            fi
            ;;
        x86_64-pc-windows-gnu)
            if ! command -v x86_64-w64-mingw32-gcc >/dev/null 2>&1; then
                echo "    missing x86_64-w64-mingw32-gcc, install with:"
                echo "        sudo apt install mingw-w64"
                return 1
            fi
            export CARGO_TARGET_X86_64_PC_WINDOWS_GNU_LINKER=x86_64-w64-mingw32-gcc
            ;;
        x86_64-apple-darwin|aarch64-apple-darwin)
            configure_osxcross_env "$triple" "$with_fido2" || return 1
            ;;
        x86_64-unknown-linux-gnu|"$HOST_TRIPLE")
            : # native, nothing to do
            ;;
    esac
    return 0
}

# Configure the environment to cross-compile to a macOS triple from a
# non-Darwin host using osxcross. Returns 1 if osxcross isn't set up
# (or if libfido2 is requested but missing from the cross sysroot).
configure_osxcross_env() {
    local triple="$1"
    local with_fido2="$2"

    if [[ -n "${OSXCROSS_ROOT:-}" ]]; then
        export PATH="$OSXCROSS_ROOT/bin:$PATH"
    fi

    # osxcross compilers are named like x86_64-apple-darwin22.4-cc
    # (or arm64-apple-darwin22.4-cc on the Apple Silicon side; some
    # builds use aarch64- as the prefix, so accept both).
    local cc=""
    case "$triple" in
        x86_64-apple-darwin)
            cc="$(compgen -c 2>/dev/null | grep -E '^x86_64-apple-darwin[0-9.]+-cc$'   | head -n1 || true)"
            ;;
        aarch64-apple-darwin)
            cc="$(compgen -c 2>/dev/null | grep -E '^(aarch64|arm64)-apple-darwin[0-9.]+-cc$' | head -n1 || true)"
            ;;
    esac

    if [[ -z "$cc" ]]; then
        echo "    osxcross not found for $triple. To enable macOS cross-builds:"
        echo "      1. Obtain the macOS SDK (from Xcode on a Mac, or Apple"
        echo "         Developer downloads, Apple's license forbids"
        echo "         redistribution)."
        echo "      2. git clone https://github.com/tpoechtrager/osxcross"
        echo "         and follow its README to build the toolchain."
        echo "      3. export OSXCROSS_ROOT=/path/to/osxcross/target"
        echo "      4. Re-run this script."
        echo "    Or run on a real Mac, or use --gh-dispatch."
        return 1
    fi

    case "$triple" in
        x86_64-apple-darwin)
            export CARGO_TARGET_X86_64_APPLE_DARWIN_LINKER="$cc"
            export CC_x86_64_apple_darwin="$cc"
            ;;
        aarch64-apple-darwin)
            export CARGO_TARGET_AARCH64_APPLE_DARWIN_LINKER="$cc"
            export CC_aarch64_apple_darwin="$cc"
            ;;
    esac

    if [[ "$with_fido2" == "1" ]]; then
        local mp_root="${OSXCROSS_ROOT:-}/macports/pkgs"
        local mp_pkgcfg="$mp_root/opt/local/lib/pkgconfig"
        if [[ -n "${OSXCROSS_ROOT:-}" ]] && [[ -f "$mp_pkgcfg/libfido2.pc" ]]; then
            export PKG_CONFIG_ALLOW_CROSS=1
            export PKG_CONFIG_PATH="$mp_pkgcfg"
            export PKG_CONFIG_SYSROOT_DIR="$mp_root"
        else
            echo "    libfido2 not found in osxcross-macports tree."
            echo "    Install with:"
            echo "        \"\$OSXCROSS_ROOT/bin/osxcross-macports\" install libfido2"
            echo "    Or re-run with --no-fido2 to skip the libfido2 link."
            return 1
        fi
    fi

    return 0
}

# Decide whether libfido2 can be linked for this target on the current
# host. Override with --no-fido2 to force off; --use-cross hands the
# decision to the cross image.
fido2_for_target() {
    local logical="$1"
    if [[ "$WITH_FIDO2" == "0" ]]; then echo 0; return; fi
    case "$logical" in
        windows-*)
            # MSYS2-extracted mingw libfido2 enables this when
            # LIBFIDO2_LIB_DIR is exported by setup_mingw_libfido2.sh.
            # Otherwise skip, no apt-installable mingw libfido2.
            if [[ -n "${LIBFIDO2_LIB_DIR:-}" ]]; then echo 1; else echo 0; fi
            ;;
        *)
            echo 1
            ;;
    esac
}

# Decide whether the WinFsp link can be enabled for this target.
#
# WinFsp from Linux MinGW cross does NOT work currently: winfsp_wrs_sys's
# build.rs is host-conditional (uses `cfg!(target_os = "windows")` which
# evaluates against the host running the build script, not the target).
# So even if you've extracted the SDK and exported WINFSP_INC / WINFSP_LIB,
# cargo emits no -L / -l directives and the link fails.
#
# We force winfsp OFF for windows-* unless the user explicitly opts in via
# --with-winfsp (escape hatch for someone who's patched winfsp_wrs_sys
# locally). For a working Windows mount build, use --gh-dispatch (real
# Windows runner) or build natively on Windows with vcpkg + WinFsp SDK.
winfsp_for_target() {
    local logical="$1"
    case "$logical" in
        windows-*)
            [[ "$WITH_WINFSP" == "1" ]] && echo 1 || echo 0
            ;;
        *)
            echo 0
            ;;
    esac
}

# Decide whether the FUSE link can be enabled for this target.
#
# - linux-*  : on (libfuse3 from apt, system-wide).
# - macos-*  : on iff a FUSE provider's fuse.pc is detectable on the
#              host. Two providers are recognized in priority order:
#                1. FUSE-T (https://www.fuse-t.org/), kext-free FUSE
#                   over NFS; the recommended modern path. Drops
#                   fuse.pc into Homebrew's standard pkgconfig dir.
#                2. macFUSE (legacy), drops fuse.pc into either
#                   Homebrew's pkgconfig or its own framework path.
#              fuser 0.17 with default-features=false spawns
#              `mount_macfuse` from PATH at runtime, both providers
#              ship a binary by that name so the built artifact is
#              identical either way.
# - windows-*: never (winfsp is the analogous feature, separately gated).
fuse_for_target() {
    local logical="$1"
    case "$logical" in
        linux-*)
            echo 1
            ;;
        macos-*)
            # Probe for macFUSE's pkg-config file. fuser 0.17's
            # build.rs hard-requires the libfuse2 ABI on macOS
            # (`pkg-config fuse >= 2.6.0`), which only macFUSE
            # provides. FUSE-T's libfuse3 API is NOT a drop-in here;
            # we'd have to swap fuser for a libfuse3-aware crate.
            for cand in /usr/local/lib/pkgconfig /opt/homebrew/lib/pkgconfig \
                        /Library/Frameworks/macFUSE.framework/Versions/A/lib/pkgconfig; do
                if [[ -f "$cand/fuse.pc" ]]; then echo 1; return; fi
            done
            echo 0
            ;;
        *)
            echo 0
            ;;
    esac
}

# ---------------------------------------------------------------------------
# bundle DLL closure for a Windows .exe
#
# Walks the import table of $1 with x86_64-w64-mingw32-objdump, copies any
# matching DLL from $2 (the sysroot bin/) into $3 (the stage dir), and
# recurses on each newly-copied DLL until the closure is complete.
# DLLs not present in the sysroot are assumed to be system libraries
# (kernel32, advapi32, ...) and ignored.

bundle_windows_dlls() {
    local exe="$1"
    local sysroot_bin="$2"
    local dest="$3"

    if ! command -v x86_64-w64-mingw32-objdump >/dev/null 2>&1; then
        log "    note: x86_64-w64-mingw32-objdump not found, skipping DLL bundle"
        log "          (install: sudo apt install mingw-w64-tools)"
        return 0
    fi

    local queue=("$exe")
    local seen=""

    while [[ "${#queue[@]}" -gt 0 ]]; do
        local cur="${queue[0]}"
        queue=("${queue[@]:1}")

        # Read import table. Lines look like:
        #   DLL Name: libfido2-1.dll
        local imports
        imports="$(x86_64-w64-mingw32-objdump -p "$cur" 2>/dev/null \
                   | awk '/DLL Name:/ {print $3}')"

        for dll in $imports; do
            # Skip if already processed.
            case " $seen " in *" $dll "*) continue ;; esac
            seen="$seen $dll"

            # Some sysroots use lower-case filenames, the import table
            # mixes cases (e.g. KERNEL32.DLL). Probe both as-is and lower.
            local src=""
            local lower
            lower="$(echo "$dll" | tr '[:upper:]' '[:lower:]')"
            if   [[ -f "$sysroot_bin/$dll"   ]]; then src="$sysroot_bin/$dll"
            elif [[ -f "$sysroot_bin/$lower" ]]; then src="$sysroot_bin/$lower"
            fi

            # Not in sysroot, system DLL we don't ship.
            [[ -z "$src" ]] && continue

            cp -n "$src" "$dest/"
            queue+=("$dest/$(basename "$src")")
        done
    done
}

log() { echo "$@" >&2; }

# ---------------------------------------------------------------------------
# build one target

build_one() {
    local logical="$1"
    local triple
    triple="$(triple_of "$logical")"
    local exe_suffix
    exe_suffix="$(exe_suffix_of "$logical")"
    local with_fido2_eff
    with_fido2_eff="$(fido2_for_target "$logical")"
    local with_winfsp_eff
    with_winfsp_eff="$(winfsp_for_target "$logical")"
    local with_fuse_eff
    with_fuse_eff="$(fuse_for_target "$logical")"

    # --- decide builder ----------------------------------------------------
    local builder="cargo"

    if [[ "$triple" != "$HOST_TRIPLE" ]]; then
        if [[ "$USE_CROSS" == "1" ]]; then
            builder="cross"
        else
            if ! configure_target_env "$triple" "$with_fido2_eff"; then
                # macOS without osxcross is a soft skip, not a failure,
                # the user gets a clear setup hint from
                # configure_osxcross_env above.
                case "$logical" in
                    macos-*) SUMMARY+=("$logical SKIP needs-osxcross-or-mac"); return 0 ;;
                    *)       SUMMARY+=("$logical FAIL missing-toolchain"); FAILED=1; return 0 ;;
                esac
            fi
        fi
    fi

    if [[ "$builder" == "cross" ]] && ! command -v cross >/dev/null 2>&1; then
        echo "    --use-cross set but \`cross\` not installed:"
        echo "        cargo install cross --git https://github.com/cross-rs/cross"
        SUMMARY+=("$logical FAIL no-cross")
        FAILED=1
        return 0
    fi

    # --- run cargo / cross --------------------------------------------------
    # Build a comma-separated feature list. We always opt out of defaults
    # so each feature is controlled per-target rather than inherited from
    # the workspace's default = ["hardware", "fuse", "winfsp"].
    local features=()
    [[ "$with_fido2_eff"  == "1" ]] && features+=("hardware")
    [[ "$with_fuse_eff"   == "1" ]] && features+=("fuse")
    [[ "$with_winfsp_eff" == "1" ]] && features+=("winfsp")
    local feat_flag="--no-default-features"
    if [[ "${#features[@]}" -gt 0 ]]; then
        local joined
        joined="$(IFS=,; echo "${features[*]}")"
        feat_flag="--no-default-features --features $joined"
    fi
    local cli_pkg="-p luksbox-cli"
    local gui_pkg=""
    [[ "$WITH_GUI" == "1" ]] && gui_pkg="-p luksbox-gui"

    # macOS host + fuse: feed macFUSE's pkg-config path to the
    # fuser crate (it hard-requires libfuse2 here, see
    # fuse_for_target() comment for why FUSE-T doesn't substitute).
    # Only takes effect on a native macOS host (cross builds use
    # osxcross's pkg-config setup elsewhere).
    if [[ "$with_fuse_eff" == "1" && "$logical" == macos-* && "$triple" == "$HOST_TRIPLE" ]]; then
        for cand in /usr/local/lib/pkgconfig /opt/homebrew/lib/pkgconfig \
                    /Library/Frameworks/macFUSE.framework/Versions/A/lib/pkgconfig; do
            if [[ -f "$cand/fuse.pc" ]]; then
                export PKG_CONFIG_PATH="$cand:${PKG_CONFIG_PATH:-}"
                break
            fi
        done
    fi

    echo "==> $logical ($triple) via $builder  fido2=$with_fido2_eff fuse=$with_fuse_eff winfsp=$with_winfsp_eff"
    rustup target add "$triple" >/dev/null 2>&1 || true

    if ! $builder build --profile "$PROFILE" --target "$triple" \
            $feat_flag $cli_pkg $gui_pkg; then
        echo "    build failed for $logical"
        SUMMARY+=("$logical FAIL build-error")
        FAILED=1
        return 0
    fi

    # --- stage + archive ----------------------------------------------------
    local stage="dist/${logical}"
    rm -rf "$stage"
    mkdir -p "$stage"

    local profile_dir="$PROFILE"
    [[ "$PROFILE" == "dev" ]] && profile_dir="debug"

    cp "target/${triple}/${profile_dir}/luksbox${exe_suffix}" "$stage/"
    if [[ "$WITH_GUI" == "1" ]]; then
        cp "target/${triple}/${profile_dir}/luksbox-gui${exe_suffix}" "$stage/" 2>/dev/null || true
    fi

    if [[ "$logical" != windows-* ]] && command -v strip >/dev/null 2>&1; then
        strip "$stage/luksbox${exe_suffix}" 2>/dev/null || true
        [[ -f "$stage/luksbox-gui${exe_suffix}" ]] && \
            strip "$stage/luksbox-gui${exe_suffix}" 2>/dev/null || true
    fi

    # Bundle runtime DLLs for windows-amd64 builds that linked against
    # the MSYS2 libfido2 sysroot. The MinGW build dynamically links
    # against ~6 DLLs (libfido2, libcbor, libcrypto, libssl, zlib,
    # hidapi) plus the mingw runtime (libwinpthread, libgcc_s_seh).
    # We copy whatever's actually referenced in luksbox.exe's import
    # table, which keeps the dist tarball minimal and avoids shipping
    # unrelated files from the sysroot.
    if [[ "$logical" == windows-* && "$with_fido2_eff" == "1" \
          && -n "${LIBFIDO2_LIB_DIR:-}" ]]; then
        local sysroot_bin="${LIBFIDO2_LIB_DIR%/lib}/bin"
        if [[ -d "$sysroot_bin" ]]; then
            bundle_windows_dlls "$stage/luksbox${exe_suffix}" "$sysroot_bin" "$stage"
            if [[ -f "$stage/luksbox-gui${exe_suffix}" ]]; then
                bundle_windows_dlls "$stage/luksbox-gui${exe_suffix}" "$sysroot_bin" "$stage"
            fi
            local n_dlls
            n_dlls="$(find "$stage" -maxdepth 1 -name '*.dll' | wc -l)"
            echo "    bundled $n_dlls runtime DLL(s) from $sysroot_bin"
        fi
    fi

    for f in README.md SECURITY.md LICENSE TUTORIAL.md; do
        [[ -f "$f" ]] && cp "$f" "$stage/"
    done

    local ext archive
    ext="$(archive_ext_of "$logical")"
    archive="dist/luksbox-${VERSION}-${logical}.${ext}"
    case "$ext" in
        zip)    (cd "$stage" && zip -qr "../$(basename "$archive")" .) ;;
        tar.gz) tar -C "$stage" -czf "$archive" . ;;
    esac

    local sha
    sha="$(sha256sum "$archive" | awk '{print $1}')"
    echo "    -> $archive  ($sha)"
    SUMMARY+=("$logical OK  $(basename "$archive")  ${sha:0:12}")
}

# ---------------------------------------------------------------------------
# build loop

for t in "${SELECTED[@]}"; do
    build_one "$t"
done

# ---------------------------------------------------------------------------
# summary

echo
echo "==================================================================="
echo "  build_release.sh, summary"
echo "==================================================================="
printf '%s\n' "${SUMMARY[@]}"
echo
echo "Artifacts in dist/. Generate checksums with:"
echo "    (cd dist && sha256sum luksbox-*.tar.gz luksbox-*.zip 2>/dev/null > SHA256SUMS.txt)"
echo

exit "$FAILED"
