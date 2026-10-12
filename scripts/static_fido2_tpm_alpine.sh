#!/bin/sh
#
# static_fido2_tpm_alpine.sh - build the static luksbox CLI WITH FIDO2 and
# TPM 2.0 support, inside an Alpine Linux container (GitHub issue #34).
#
# Called by `scripts/build_static_musl.sh --fido2-tpm`; not meant to be run
# by hand: it installs packages and writes to /opt, so it belongs in a
# throwaway container. Arguments:
#
#   $1  output directory; receives `luksbox` and `licenses/`
#
# Why Alpine and Alpine's own Rust: the C libraries below have to be
# compiled against musl, which Alpine is built on. Alpine's rustc also keeps
# build scripts dynamically linked (rustup's musl toolchain makes them
# static, and a static build script cannot dlopen libclang, which the
# luksbox-fido2 bindgen step needs); `+crt-static` still makes the final
# binary fully static.
#
# Bundled, built from pinned sources checked against SHA-256:
#   libudev-zero  daemonless libudev, so libfido2 finds /dev/hidraw* with
#                 no systemd-udevd and no host library
#   libcbor, libfido2
#   tpm2-tss      configured with --enable-nodl: the device / swtpm / mssim
#                 TCTIs are linked in instead of dlopen()ed, which a static
#                 binary cannot do
# OpenSSL (libcrypto) and zlib come from Alpine's -static packages.
#
# A security fix in any of these needs a LUKSbox rebuild: the binary does
# not pick up the host's copies.

set -eu

# Bundled library versions. When upstream ships a fix, bump the version
# and its SHA-256 pin below. scripts/check_static_deps.py, run on every
# release build, fails when a bundled library has a known vulnerability or
# a newer upstream release announces security fixes.
UDEV_ZERO_VERSION=1.0.4
LIBCBOR_VERSION=0.14.0
LIBFIDO2_VERSION=1.17.0
TPM2_TSS_VERSION=4.2.0

OUT="$1"
PREFIX=/opt/luksbox-static
SRC=/tmp/luksbox-static-src
JOBS="$(nproc)"

apk add --no-cache \
    build-base cmake pkgconf linux-headers curl \
    openssl-dev openssl-libs-static zlib-dev zlib-static \
    clang21-libclang rust cargo >/dev/null

mkdir -p "$SRC" "$PREFIX" "$OUT/licenses"

# fetch <url> <sha256> <file>: download, verify, unpack into $SRC.
fetch() {
    curl -fsSL --retry 3 -o "$SRC/$3" "$1"
    echo "$2  $SRC/$3" >"$SRC/$3.sha256"
    sha256sum -c "$SRC/$3.sha256" >/dev/null
    tar -xzf "$SRC/$3" -C "$SRC"
}

fetch "https://github.com/illiliti/libudev-zero/archive/refs/tags/$UDEV_ZERO_VERSION.tar.gz" \
    10148cfd6047d387bf71eca72cd19c177084224d96434a118d8def6e0a3d6316 \
    "libudev-zero-$UDEV_ZERO_VERSION.tar.gz"
fetch "https://github.com/PJK/libcbor/archive/refs/tags/v$LIBCBOR_VERSION.tar.gz" \
    a8c1516e741562cf95aa4479c64916c3d4d2623e24fdc35e414e2320e7300aae \
    "libcbor-$LIBCBOR_VERSION.tar.gz"
fetch "https://developers.yubico.com/libfido2/Releases/libfido2-$LIBFIDO2_VERSION.tar.gz" \
    c1012c8871d71b65872fd5ff1a9d6b0838a55683a03e85ba97479ce57129c736 \
    "libfido2-$LIBFIDO2_VERSION.tar.gz"
fetch "https://github.com/tpm2-software/tpm2-tss/releases/download/$TPM2_TSS_VERSION/tpm2-tss-$TPM2_TSS_VERSION.tar.gz" \
    b53f0c5c8c4ce17f05701a410ca9688f725ca380c9bc4640eacd0eadb1fea124 \
    "tpm2-tss-$TPM2_TSS_VERSION.tar.gz"

export PKG_CONFIG_PATH="$PREFIX/lib/pkgconfig"

# ---- libudev-zero -------------------------------------------------------
make -C "$SRC/libudev-zero-$UDEV_ZERO_VERSION" -j"$JOBS" PREFIX="$PREFIX" install-static >/dev/null

# ---- libcbor ------------------------------------------------------------
# CMAKE_POLICY_VERSION_MINIMUM: older libcbor releases declare CMake 3.0,
# which CMake 4 refuses outright; harmless for newer ones.
cmake -S "$SRC/libcbor-$LIBCBOR_VERSION" -B "$SRC/build-cbor" \
    -DCMAKE_BUILD_TYPE=Release -DCMAKE_POLICY_VERSION_MINIMUM=3.5 \
    -DCMAKE_INSTALL_PREFIX="$PREFIX" -DCMAKE_INSTALL_LIBDIR=lib \
    -DBUILD_SHARED_LIBS=OFF -DWITH_EXAMPLES=OFF >/dev/null
cmake --build "$SRC/build-cbor" -j "$JOBS" >/dev/null
cmake --install "$SRC/build-cbor" >/dev/null

# ---- libfido2 -----------------------------------------------------------
# libfido2 compiles with -Werror; a compiler newer than the one upstream
# tested with must not fail the build over a new warning.
sed -i 's/add_compile_options(-Werror)//' "$SRC/libfido2-$LIBFIDO2_VERSION/CMakeLists.txt"
cmake -S "$SRC/libfido2-$LIBFIDO2_VERSION" -B "$SRC/build-fido2" \
    -DCMAKE_BUILD_TYPE=Release -DCMAKE_POLICY_VERSION_MINIMUM=3.5 \
    -DCMAKE_INSTALL_PREFIX="$PREFIX" -DCMAKE_INSTALL_LIBDIR=lib \
    -DBUILD_SHARED_LIBS=OFF -DBUILD_STATIC_LIBS=ON -DBUILD_TOOLS=OFF \
    -DBUILD_EXAMPLES=OFF -DBUILD_MANPAGES=OFF -DBUILD_TESTS=OFF \
    -DNFC_LINUX=OFF -DUSE_PCSC=OFF >/dev/null
cmake --build "$SRC/build-fido2" -j "$JOBS" >/dev/null
cmake --install "$SRC/build-fido2" >/dev/null
# libfido2.pc only declares libcrypto; a static link also needs the rest.
echo "Requires.private: libcbor zlib libudev" >>"$PREFIX/lib/pkgconfig/libfido2.pc"

# ---- tpm2-tss -----------------------------------------------------------
(
    cd "$SRC/tpm2-tss-$TPM2_TSS_VERSION"
    ./configure --prefix="$PREFIX" --libdir="$PREFIX/lib" \
        --enable-static --disable-shared --enable-nodl \
        --disable-fapi --disable-policy --disable-weakcrypto \
        --disable-unit --disable-integration --disable-doxygen-doc \
        --disable-tcti-pcap --disable-tcti-libtpms --disable-tcti-null \
        --disable-tcti-spi-helper --disable-tcti-spi-ltt2go \
        --disable-tcti-spidev --disable-tcti-spi-ftdi \
        --disable-tcti-i2c-helper --disable-tcti-i2c-ftdi >/dev/null
    make -j"$JOBS" >/dev/null
    # Only the libraries, headers and .pc files: the full `make install`
    # also creates a `tss` user and runs systemd-sysusers / -tmpfiles.
    make install-libLTLIBRARIES install-pkgconfigDATA install-tss2HEADERS >/dev/null
)
# Every TCTI also exports the generic `Tss2_Tcti_Info` entry point that the
# dlopen() loader looks up, so linked statically side by side they collide
# ("multiple definition of `Tss2_Tcti_Info'"). The nodl loader calls each
# TCTI's *_Init function directly and never uses it: make those copies local.
for tcti in device swtpm mssim cmd; do
    objcopy --localize-symbol=Tss2_Tcti_Info "$PREFIX/lib/libtss2-tcti-$tcti.a"
    ranlib "$PREFIX/lib/libtss2-tcti-$tcti.a"
done
# With --enable-nodl the TCTI loader (built into both libtss2-esys and
# libtss2-tctildr) calls the device / swtpm / mssim TCTIs directly, but no
# .pc file lists them; add them so the static link pulls them in.
tctis="tss2-tcti-device tss2-tcti-swtpm tss2-tcti-mssim"
sed -i "s/^Requires.private:.*/& $tctis/" "$PREFIX/lib/pkgconfig/tss2-esys.pc"
echo "Requires.private: $tctis" >>"$PREFIX/lib/pkgconfig/tss2-tctildr.pc"

# ---- luksbox ------------------------------------------------------------
export PKG_CONFIG_ALL_STATIC=1
LIBCLANG="$(find /usr/lib -name 'libclang.so*' | head -n1)"
export LIBCLANG_PATH="${LIBCLANG%/*}"
export CARGO_TARGET_DIR=/tmp/target
TARGET="$(rustc -vV | sed -n 's/^host: //p')"
# What pkg-config hands the -sys build scripts, for the build log.
for pc in libfido2 tss2-esys tss2-tctildr; do
    echo "pkg-config --static --libs $pc: $(pkg-config --static --libs "$pc")"
done
# The build scripts emit each library's link flags separately (and the
# pkg-config crate only marks a library static when its -L came first,
# which tpm2-tss's .pc files do not do), while GNU ld resolves archives
# strictly left to right: an archive placed before the one that needs it
# (libtss2-sys before libtss2-esys, the TCTIs, libcbor) is never pulled
# in. List every bundled archive once more inside one --start-group /
# --end-group; rustc puts link-args after all libraries, and ld searches
# a group repeatedly until nothing new resolves.
group="-C link-arg=-Wl,--start-group"
for archive in "$PREFIX"/lib/*.a /usr/lib/libcrypto.a /usr/lib/libz.a; do
    group="$group -C link-arg=$archive"
done
group="$group -C link-arg=-Wl,--end-group"
RUSTFLAGS="-C target-feature=+crt-static $group" cargo build --locked \
    --profile release-hardened -p luksbox-cli \
    --no-default-features --features hardware,fuse --target "$TARGET"
install -m 0755 "$CARGO_TARGET_DIR/$TARGET/release-hardened/luksbox" "$OUT/luksbox"

# ---- third-party licenses and component list ---------------------------
cp "$SRC/libudev-zero-$UDEV_ZERO_VERSION/LICENSE" "$OUT/licenses/libudev-zero.txt"
cp "$SRC/libcbor-$LIBCBOR_VERSION/LICENSE.md" "$OUT/licenses/libcbor.txt"
cp "$SRC/libfido2-$LIBFIDO2_VERSION/LICENSE" "$OUT/licenses/libfido2.txt"
cp "$SRC/tpm2-tss-$TPM2_TSS_VERSION/LICENSE" "$OUT/licenses/tpm2-tss.txt"

# Exact versions of the Alpine packages linked in (with their -rN release,
# which is what Alpine's security fixes bump).
ALPINE_BRANCH="v$(cut -d. -f1,2 /etc/alpine-release)"
apk_version() {
    v="$(apk list --installed "$1" 2>/dev/null | sed -n "s/^$1-\([0-9][^ ]*\) .*/\1/p" | head -n1)"
    if [ -z "$v" ]; then
        echo "could not read the installed version of $1" >&2
        exit 1
    fi
    echo "$v"
}
OPENSSL_APK="$(apk_version openssl-libs-static)"
ZLIB_APK="$(apk_version zlib-static)"
MUSL_APK="$(apk_version musl-dev)"

# Machine-readable list for scripts/check_static_deps.py (and for anyone
# checking the binary against vulnerability databases): name, version,
# where it comes from.
{
    printf 'libudev-zero\t%s\tgithub:illiliti/libudev-zero\n' "$UDEV_ZERO_VERSION"
    printf 'libcbor\t%s\tgithub:PJK/libcbor\n' "$LIBCBOR_VERSION"
    printf 'libfido2\t%s\tgithub:Yubico/libfido2\n' "$LIBFIDO2_VERSION"
    printf 'tpm2-tss\t%s\tgithub:tpm2-software/tpm2-tss\n' "$TPM2_TSS_VERSION"
    printf 'openssl\t%s\talpine:%s\n' "$OPENSSL_APK" "$ALPINE_BRANCH"
    printf 'zlib\t%s\talpine:%s\n' "$ZLIB_APK" "$ALPINE_BRANCH"
    printf 'musl\t%s\talpine:%s\n' "$MUSL_APK" "$ALPINE_BRANCH"
} >"$OUT/licenses/components.tsv"

cat >"$OUT/licenses/README.txt" <<EOF
Libraries linked into this luksbox binary (machine-readable list:
components.tsv):

  libudev-zero $UDEV_ZERO_VERSION        ISC           libudev-zero.txt
  libcbor $LIBCBOR_VERSION             MIT           libcbor.txt
  libfido2 $LIBFIDO2_VERSION            BSD-2-Clause  libfido2.txt
  tpm2-tss $TPM2_TSS_VERSION             BSD-2-Clause  tpm2-tss.txt
  OpenSSL $OPENSSL_APK     Apache-2.0    same text as ../LICENSE
  zlib $ZLIB_APK          zlib          https://zlib.net/zlib_license.html
  musl libc $MUSL_APK     MIT           https://musl.libc.org/COPYRIGHT
  (OpenSSL, zlib and musl are Alpine Linux $ALPINE_BRANCH packages)
EOF

# The container runs as root; hand what it wrote back to the caller.
if [ -n "${HOST_IDS:-}" ]; then
    chown -R "$HOST_IDS" "$OUT/luksbox" "$OUT/licenses"
fi
