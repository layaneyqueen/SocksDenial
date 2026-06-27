#!/usr/bin/env bash
set -euo pipefail

echo "=== Installing cross-compilation toolchains ==="
echo ""

apt update

PKGS=(
    gcc-i686-linux-gnu
    gcc-aarch64-linux-gnu
    gcc-arm-linux-gnueabi
    gcc-arm-linux-gnueabihf
    gcc-mips-linux-gnu
    gcc-mipsel-linux-gnu
    gcc-mips64-linux-gnuabi64
    gcc-mips64el-linux-gnuabi64
    gcc-powerpc-linux-gnu
    gcc-powerpc64-linux-gnu
    gcc-powerpc64le-linux-gnu
    gcc-sh4-linux-gnu
    gcc-m68k-linux-gnu
    gcc-sparc64-linux-gnu
    gcc-s390x-linux-gnu
    gcc-riscv64-linux-gnu
    gcc-alpha-linux-gnu
    gcc-hppa-linux-gnu
    upx-ucl
)

for pkg in "${PKGS[@]}"; do
    if apt install -y "$pkg" 2>/dev/null; then
        echo "  [OK] $pkg"
    else
        echo "  [SKIP] $pkg (not available)"
    fi
done

# i586 symlink from i686
if ! command -v i586-linux-gnu-gcc &>/dev/null && command -v i686-linux-gnu-gcc &>/dev/null; then
    echo "  [SYMLINK] i586-linux-gnu-gcc -> i686-linux-gnu-gcc"
    ln -sf "$(command -v i686-linux-gnu-gcc)" "/usr/bin/i586-linux-gnu-gcc"
fi

echo ""
echo "=== Done ==="
echo "Run ./build.sh to compile for all architectures"
