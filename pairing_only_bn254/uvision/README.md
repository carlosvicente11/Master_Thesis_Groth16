# Cortex-M4 / Keil µVision port

Bare-metal build of the BN254 Groth16 multi-pairing benchmark for the
Cortex-M4, aimed at the Keil µVision **cycle-accurate simulator**. QEMU is
used only as a functional gate (its timing is not cycle-accurate).

Configuration: `WSIZE=32`, `ARITH=easy` (pure C), `RAND=CALL` (no callback
registered — the pairing path is deterministic), `ALLOC=AUTO`, no OS, no timer
syscalls. Timing uses **SysTick** with an overflow interrupt (24-bit counter),
identical on the simulator, QEMU, and real silicon. Results also land in
volatile globals (`g_valid`, `g_ticks[]`, `g_done`) readable from the µVision
watch window.

## Contents

| File | Purpose |
|---|---|
| `main_m4.c` | Bare-metal benchmark: decode points, warm-up + correctness check vs `e(alpha,beta)`, then `PAIRING_ITERS` timed runs of `pp_map_sim_k12` |
| `clear_signing_m4.c` | Bare-metal clear-signing verify (two-hash): SysTick-times Poseidon(C), Poseidon(T), 2×`ep_mul` input prep, and the 3-pair multi-pairing separately; checks on-chip h_c/h_t vs the prover and the pairing product vs `e(alpha,beta)`. Watch-window globals: `g_hashes_ok`, `g_valid`, `g_cycles_{hc,ht,prep,pair,total}`, `g_done` |
| `startup.c` | Vector table, reset handler, BSS init, semihosting (BKPT 0xAB) console, minimal libc (printf subset, bump-allocator malloc/calloc) |
| `mps2_an386.ld` | Linker script for QEMU's MPS2-AN386 board (Cortex-M4, 4 MB flash @ 0x0, 4 MB SRAM @ 0x20000000) |
| `stm32f405.ld` | Linker script for an STM32F405-class part (1 MB flash, 128 KB SRAM) — realistic target footprint |
| `include/` | Freestanding libc headers (`-nostdinc` shims) so RELIC compiles without a hosted toolchain libc |
| `relic_conf.h` | Pre-generated RELIC config for WSIZE=32 / ARCH=NONE / RAND=CALL — for a native µVision project, which has no CMake to generate it |

## Cross-compile (arm-none-eabi-gcc)

```sh
cd thesis/pairing_only_bn254
cmake -S . -B build_m4 -DCMAKE_TOOLCHAIN_FILE=cmake/toolchain-arm-none-eabi.cmake
cmake --build build_m4
```

Produces `build_m4/multi_pairing_m4` and `build_m4/clear_signing_m4` (ELFs)
plus their `.map` files. Options: `-DBOARD=stm32f405` (default `mps2-an386`),
`-DPAIRING_ITERS=N` (default 3, `multi_pairing_m4` only).

`clear_signing_m4` compiles `../minimal_c_verifier`'s RELIC-independent
`fr.c`/`poseidon.c` (portable C99, no `__int128`) and its generated
clear-signing VK/vector headers; both µVision options below apply to it
unchanged (image: ~63 KB flash, ~19 KB RAM).

## Functional check under QEMU

```sh
qemu-system-arm -M mps2-an386 -cpu cortex-m4 -nographic \
    -semihosting -kernel build_m4/multi_pairing_m4
qemu-system-arm -M mps2-an386 -cpu cortex-m4 -nographic \
    -semihosting -kernel build_m4/clear_signing_m4
```

Expected output: `Correctness: PASS (equals e(alpha,beta))` (multi-pairing) /
`On-chip h_c/h_t match prover: YES` + `Proof: VALID` (clear-signing) plus tick
counts (QEMU ticks are NOT cycle-accurate — ignore the numbers, only the PASS
matters here).

## Keil µVision (cycle-accurate timing)

Two ways to get the benchmark into the simulator:

### Option A — debug the GCC-built ELF (fastest)

µVision's debugger can load an external ELF/DWARF image; no need to rebuild
inside the IDE.

1. Create a new µVision project targeting a Cortex-M4 device (e.g.
   STM32F405RG or the generic ARMCM4). Skip adding source files.
2. Options for Target → Debug → select **Use Simulator**.
3. Options for Target → Debug → Initialization file: none needed. Under
   "Load Application at Startup", point the debugger at the GCC-built ELF:
   Options → Utilities/Debug → or simply use the command
   `LOAD build_m4/multi_pairing_m4 INCREMENTAL` in the debugger command window.
4. Run. Read `g_valid` / `g_ticks[]` in a Watch window (or set a breakpoint on
   `g_done = 1`). The simulator's "States" counter and SysTick agree since
   SysTick runs on the core clock.

Note: the image was linked for MPS2 (flash at 0x0). For a device whose flash
is at 0x08000000 (STM32), rebuild with `-DBOARD=stm32f405` so the load regions
match the simulated memory map.

### Option B — native µVision project (armclang build)

If a native MDK build is preferred (e.g. for the assembly work later):

1. New project, Cortex-M4 device, **disable** MicroLIB or keep it — either
   works; the standard C library replaces our `startup.c` shims. Do NOT add
   `startup.c` or `include/` (those are for the GCC `-nostdlib` build); use
   the device's normal startup and scatter file instead.
2. Add sources:
   - all of `lib/relic/src/` **except** `arch/relic_arch_a64.c`,
     `arch/relic_arch_x64.c` (keep `relic_arch_none.c`; `rand/` files are
     self-guarded, add them all)
   - `lib/relic/src/low/easy/*.c`
   - `src/point_decode.c`, `src/crypto_init.c`
   - `uvision/main_m4.c`
3. Include paths (in this order):
   - `uvision/` (so the vendored `relic_conf.h` is found first)
   - `lib/relic/include`
   - `lib/relic/include/low`
   - `include/`
   - `test/`
4. Retarget `stdout` (Compiler → I/O → STDOUT via ITM or breakpoint-based
   semihosting), or skip printf entirely and read the volatile globals.
5. Run under the simulator as in Option A.

## Interpreting the numbers

`g_ticks[i]` = core cycles for one full multi-pairing (3 pairs, shared Miller
loop + final exponentiation). At a given core clock f, time = ticks / f.
Host reference points: ~1.27 ms (64-bit limbs) / ~4.0 ms (32-bit limbs) on a
~3.5 GHz superscalar host — expect substantially more cycles on the in-order
M4 with the pure-C `easy` backend. This baseline is what the supervisor's
UMAAL Montgomery assembly (`fp_mulm_low`/`fp_sqrm_low` hooks) will improve.
