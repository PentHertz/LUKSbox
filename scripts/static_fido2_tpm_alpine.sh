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

fetch https://github.com/illiliti/libudev-zero/archive/refs/tags/1.0.3.tar.gz \
    0bd89b657d62d019598e6c7ed726ff8fed80e8ba092a83b484d66afb80b77da5 \
    libudev-zero-1.0.3.tar.gz
fetch https://github.com/PJK/libcbor/archive/refs/tags/v0.12.0.tar.gz \
    5368add109db559f546d7ed10f440f39a273b073daa8da4abffc83815069fa7f \
    libcbor-0.12.0.tar.gz
fetch https://developers.yubico.com/libfido2/Releases/libfido2-1.16.0.tar.gz \
    8c2b6fb279b5b42e9ac92ade71832e485852647b53607c43baaafbbcecea04e4 \
    libfido2-1.16.0.tar.gz
fetch https://github.com/tpm2-software/tpm2-tss/releases/download/4.1.3/tpm2-tss-4.1.3.tar.gz \
    37f1580200ab78305d1fc872d89241aaee0c93cbe85bc559bf332737a60d3be8 \
    tpm2-tss-4.1.3.tar.gz

export PKG_CONFIG_PATH="$PREFIX/lib/pkgconfig"

# ---- libudev-zero -------------------------------------------------------
make -C "$SRC/libudev-zero-1.0.3" -j"$JOBS" PREFIX="$PREFIX" install-static >/dev/null

# ---- libcbor ------------------------------------------------------------
# CMAKE_POLICY_VERSION_MINIMUM: libcbor declares CMake 3.0, which CMake 4
# refuses outright.
cmake -S "$SRC/libcbor-0.12.0" -B "$SRC/build-cbor" \
    -DCMAKE_BUILD_TYPE=Release -DCMAKE_POLICY_VERSION_MINIMUM=3.5 \
    -DCMAKE_INSTALL_PREFIX="$PREFIX" -DCMAKE_INSTALL_LIBDIR=lib \
    -DBUILD_SHARED_LIBS=OFF -DWITH_EXAMPLES=OFF >/dev/null
cmake --build "$SRC/build-cbor" -j "$JOBS" >/dev/null
cmake --install "$SRC/build-cbor" >/dev/null

# ---- libfido2 -----------------------------------------------------------
# libfido2 compiles with -Werror; a compiler newer than the one upstream
# tested with must not fail the build over a new warning.
sed -i 's/add_compile_options(-Werror)//' "$SRC/libfido2-1.16.0/CMakeLists.txt"
cmake -S "$SRC/libfido2-1.16.0" -B "$SRC/build-fido2" \
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
    cd "$SRC/tpm2-tss-4.1.3"
    ./configure --prefix="$PREFIX" --libdir="$PREFIX/lib" \
        --enable-static --disable-shared --enable-nodl \
        --disable-fapi --disable-policy --disable-weakcrypto \
        --disable-unit --disable-integration --disable-doxygen-doc \
        --disable-tcti-pcap --disable-tcti-libtpms \
        --disable-tcti-spi-helper --disable-tcti-spi-ltt2go \
        --disable-tcti-spidev --disable-tcti-spi-ftdi \
        --disable-tcti-i2c-helper --disable-tcti-i2c-ftdi >/dev/null
    make -j"$JOBS" >/dev/null
    # Only the libraries, headers and .pc files: the full `make install`
    # also creates a `tss` user and runs systemd-sysusers / -tmpfiles.
    make install-libLTLIBRARIES install-pkgconfigDATA install-tss2HEADERS >/dev/null
)
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
RUSTFLAGS="-C target-feature=+crt-static" cargo build --locked \
    --profile release-hardened -p luksbox-cli \
    --no-default-features --features hardware,fuse --target "$TARGET"
install -m 0755 "$CARGO_TARGET_DIR/$TARGET/release-hardened/luksbox" "$OUT/luksbox"

# ---- third-party licenses -----------------------------------------------
cp "$SRC/libudev-zero-1.0.3/LICENSE" "$OUT/licenses/libudev-zero.txt"
cp "$SRC/libcbor-0.12.0/LICENSE.md" "$OUT/licenses/libcbor.txt"
cp "$SRC/libfido2-1.16.0/LICENSE" "$OUT/licenses/libfido2.txt"
cp "$SRC/tpm2-tss-4.1.3/LICENSE" "$OUT/licenses/tpm2-tss.txt"
cat >"$OUT/licenses/README.txt" <<EOF
Libraries linked into this luksbox binary:

  libudev-zero 1.0.3   ISC           libudev-zero.txt
  libcbor 0.12.0       MIT           libcbor.txt
  libfido2 1.16.0      BSD-2-Clause  libfido2.txt
  tpm2-tss 4.1.3       BSD-2-Clause  tpm2-tss.txt
  OpenSSL $(pkg-config --modversion libcrypto)  Apache-2.0    same text as ../LICENSE
  zlib $(pkg-config --modversion zlib)          zlib          https://zlib.net/zlib_license.html
EOF

# The container runs as root; hand what it wrote back to the caller.
if [ -n "${HOST_IDS:-}" ]; then
    chown -R "$HOST_IDS" "$OUT/luksbox" "$OUT/licenses"
fi
