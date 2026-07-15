#!/bin/sh
# Build a bare-metal configuration, then strip the build directory down to
# the ELFs and .map files (all scaffolding is regenerated on the next run,
# at the cost of a full rebuild each time).
#
# Usage:
#   scripts/build_trimmed.sh build_m4                    # QEMU board (mps2-an386)
#   scripts/build_trimmed.sh build_m4_stm32f405 stm32f405
set -e

if [ -z "$1" ]; then
    echo "usage: $0 <builddir> [BOARD]" >&2
    exit 1
fi

cd "$(dirname "$0")/.."
BUILDDIR=$1
BOARD=$2

# A trimmed dir has no CMakeCache.txt; CMake refuses to configure into a
# non-empty dir without one, so clear leftover ELFs/maps first.
if [ -d "$BUILDDIR" ] && [ ! -f "$BUILDDIR/CMakeCache.txt" ]; then
    rm -f "$BUILDDIR"/*_m4 "$BUILDDIR"/*.map
fi

cmake -S . -B "$BUILDDIR" \
    -DCMAKE_TOOLCHAIN_FILE=cmake/toolchain-arm-none-eabi.cmake \
    ${BOARD:+-DBOARD=$BOARD}
cmake --build "$BUILDDIR" -j

rm -rf "$BUILDDIR/CMakeFiles" "$BUILDDIR/lib" "$BUILDDIR/CMakeCache.txt" \
    "$BUILDDIR/Makefile" "$BUILDDIR/cmake_install.cmake" "$BUILDDIR/libpairing.a"

echo
echo "Trimmed $BUILDDIR:"
ls -l "$BUILDDIR"
