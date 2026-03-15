#!/usr/bin/env bash
# fetch_kernel.sh VERSION CONFIG OUT
# Downloads Linux kernel source, configures with microvm.config, builds vmlinux.
# Used by: make kernel
# Output: build/vmlinux (ELF, not bzImage — required by cloud-hypervisor)
set -euo pipefail

if [ $# -ne 3 ]; then
    echo "Usage: $0 VERSION CONFIG OUT" >&2
    exit 1
fi

VERSION="$1"
CONFIG="$2"
OUT="$3"
BUILDDIR="build/linux-${VERSION}"
TARBALL="build/linux-${VERSION}.tar.xz"
URL="https://cdn.kernel.org/pub/linux/kernel/v6.x/linux-${VERSION}.tar.xz"

mkdir -p build

if [ ! -f "$TARBALL" ]; then
    echo "Downloading Linux ${VERSION}..." >&2
    curl -L --fail --progress-bar -o "$TARBALL" "$URL"
fi

if [ ! -d "$BUILDDIR" ]; then
    echo "Extracting..." >&2
    tar -C build -xf "$TARBALL"
fi

echo "Configuring..." >&2
cp "$CONFIG" "$BUILDDIR/.config"
make -C "$BUILDDIR" olddefconfig

JOBS=$(nproc 2>/dev/null || echo 4)
echo "Building vmlinux with ${JOBS} jobs..." >&2
make -C "$BUILDDIR" vmlinux -j"$JOBS"

cp "$BUILDDIR/vmlinux" "$OUT"
echo "vmlinux -> $OUT ($(du -sh "$OUT" | cut -f1))" >&2
