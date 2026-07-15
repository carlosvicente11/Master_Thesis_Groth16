#!/bin/sh
# Build the host verifier, then strip the build directory down to the
# executables (all scaffolding is regenerated on the next run, at the cost
# of a full rebuild each time).
#
# Usage:
#   scripts/build_trimmed.sh [builddir]    # default: build
set -e

cd "$(dirname "$0")/.."
BUILDDIR=${1:-build}

# A trimmed dir has no CMakeCache.txt; CMake refuses to configure into a
# non-empty dir without one. Everything left in a trimmed dir is a product,
# so just start fresh.
if [ -d "$BUILDDIR" ] && [ ! -f "$BUILDDIR/CMakeCache.txt" ]; then
    rm -rf "$BUILDDIR"
fi

cmake -S . -B "$BUILDDIR"
cmake --build "$BUILDDIR" -j

rm -rf "$BUILDDIR/CMakeFiles" "$BUILDDIR/relic_build" "$BUILDDIR/CMakeCache.txt" \
    "$BUILDDIR/Makefile" "$BUILDDIR/cmake_install.cmake" "$BUILDDIR/libgroth16_verifier.a"

echo
echo "Trimmed $BUILDDIR:"
ls -l "$BUILDDIR"
