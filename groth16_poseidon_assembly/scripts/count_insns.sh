#!/usr/bin/env bash
#
# Count guest instructions executed by the ARM Groth16 verifier under QEMU.
#
# QEMU's SysTick read (bench_*_arm output) is a *modeled cycle* count and is not
# cycle-accurate. This script instead counts *retired instructions* via a tiny
# TCG plugin, which is the meaningful "work" metric.
#
# It reports two numbers:
#   1. Full verify   - whole bench_verifier_arm run (init + decode + verify)
#   2. Pairing only  - pp_map_sim_k12 in isolation, obtained by running
#                      bench_pairing_arm at PAIRING_ITERS=1 and =11 and taking
#                      the difference / 10 (cancels the fixed init+decode cost).
#
# Usage:  scripts/count_insns.sh
set -euo pipefail

PROJ="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BUILD="$PROJ/build_insn"
PLUGIN="$PROJ/scripts/libinsn.so"
TOOLCHAIN="$PROJ/cmake/toolchain-arm-none-eabi.cmake"
MACHINE="netduinoplus2"

BREW_PREFIX="$(brew --prefix)"
QEMU="$(command -v qemu-system-arm)"

# --- 1. Build the instruction-counter plugin if needed ---
if [[ ! -f "$PLUGIN" || "$PROJ/scripts/qemu_insn_count.c" -nt "$PLUGIN" ]]; then
    echo ">> Building instruction-counter plugin"
    GLIB="$(brew --prefix glib)"
    cc -shared -fPIC \
        -I"$GLIB/include/glib-2.0" -I"$GLIB/lib/glib-2.0/include" \
        -I"$BREW_PREFIX/include" \
        -Wl,-undefined,dynamic_lookup \
        "$PROJ/scripts/qemu_insn_count.c" -o "$PLUGIN"
fi

# Run a freshly-built bench binary under the plugin, echo the "insns:" total.
# QEMU returns exit code 1 on a normal semihosting exit, so ignore its status.
run_count() {
    local kernel="$1" out
    out="$("$QEMU" -machine "$MACHINE" -nographic -semihosting \
        -plugin "$PLUGIN" -d plugin \
        -kernel "$kernel" 2>&1)" || true
    printf '%s\n' "$out" | sed -n 's/^insns: \([0-9]*\)$/\1/p'
}

# (Re)configure + build a single target, optionally overriding PAIRING_ITERS.
build_target() {
    local target="$1"; local iters="${2:-}"
    local args=(-DCMAKE_TOOLCHAIN_FILE="$TOOLCHAIN" -DBOARD="$MACHINE")
    [[ -n "$iters" ]] && args+=(-DPAIRING_ITERS="$iters")
    cmake -S "$PROJ" -B "$BUILD" "${args[@]}" >/dev/null
    # CMake's Makefiles generator does not recompile on a -D define-only change,
    # so force the bench source to rebuild when PAIRING_ITERS varies.
    [[ -n "$iters" ]] && touch "$PROJ/test/bench_pairing_arm.c"
    cmake --build "$BUILD" --target "$target" >/dev/null
}

echo ">> Full verify (bench_verifier_arm)"
build_target bench_verifier_arm
FULL=$(run_count "$BUILD/bench_verifier_arm")
echo "   full verify: $FULL instructions"

echo ">> Pairing isolation (bench_pairing_arm, 1 vs 11 iters)"
build_target bench_pairing_arm 1
N1=$(run_count "$BUILD/bench_pairing_arm")
build_target bench_pairing_arm 11
N11=$(run_count "$BUILD/bench_pairing_arm")
PER=$(( (N11 - N1) / 10 ))

echo "   1 pairing  : $N1 instructions (incl. init+decode)"
echo "   11 pairings: $N11 instructions"
echo
echo "=== Results (retired guest instructions) ==="
echo "  Whole bench_verifier_arm (1 sanity + 3 verifies): $FULL"
echo "  Per single verify (FULL / 4)                    : $(( FULL / 4 ))"
echo "  Per pairing, isolated (pp_map_sim_k12, 3 pairs) : $PER"
