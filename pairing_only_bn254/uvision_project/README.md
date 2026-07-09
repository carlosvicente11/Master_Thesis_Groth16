# Self-contained Keil µVision project sources

Everything needed for a **native µVision (armclang) build** of the BN254
verifier benchmarks — no CMake, no files outside this folder. Copy this
folder to the machine that has Keil MDK.

## Layout

| Path | Contents |
|---|---|
| `relic_conf.h` | Pre-generated RELIC config (WSIZE=32, ARCH=NONE, ARITH=easy, RAND=CALL) — must be found *before* `relic/include` |
| `app/` | Application sources: two alternative `main`s plus shared glue |
| `include/` | Project headers: `pairing.h`, VK constants, test vectors, Poseidon/Fr headers |
| `relic/include`, `relic/src` | The trimmed RELIC library (BN254 pairing only) |

`app/` files:

| File | Role |
|---|---|
| `clear_signing_m4.c` | **main #1** — full clear-signing verify: Poseidon(C), Poseidon(T), 2× `ep_mul`, 3-pair multi-pairing, each phase SysTick-timed |
| `main_m4.c` | **main #2** — multi-pairing-only benchmark (`PAIRING_ITERS` timed runs) |
| `single_pairing_m4.c` | **main #3** — single-pairing micro-benchmark: one `pp_map_k12(e, A, B)` per timed run; correctness via bilinearity `e([2]A,B) == e(A,B)^2`. Cleanest workload for measuring the Montgomery drop-in speedup |
| `crypto_init.c` | `pairing_init()`: core init + BN254 curve + D-type twist |
| `point_decode.c` | G1/G2/Fr decoders with on-curve checks |
| `fr.c`, `poseidon.c` | Scalar field + Poseidon (portable C99, RELIC-independent) |

Add **exactly one** of `clear_signing_m4.c` / `main_m4.c` /
`single_pairing_m4.c` to the build — each defines `main` and
`SysTick_Handler`.

## Keil project setup

0. For the assembly work, `app/single_pairing_m4.c` is the recommended main:
   one pairing per timed run, no Groth16 3-pair sharing, so the
   `fp_{mulm,sqrm,rdcn}_low` replacement shows up directly in `g_ticks[]`.
1. New project → device **STM32F405RG** (or generic ARMCM4) → compiler
   **armclang (AC6)**. Use the device's normal startup file and scatter file
   (the pack's defaults are fine). Do **not** add any startup of our own —
   `SysTick_Handler` in the app's main file overrides the pack startup's weak
   handler automatically.
2. Add sources:
   - one main: `app/clear_signing_m4.c`, `app/main_m4.c`, or
     `app/single_pairing_m4.c`
   - `app/crypto_init.c`, `app/point_decode.c`
   - `app/fr.c`, `app/poseidon.c` (only needed by `clear_signing_m4.c`, but
     harmless to keep in both configurations)
   - **all** `.c` files under `relic/src/` (recursively; already trimmed —
     the x86-64/AArch64 arch backends and the `/dev/urandom` rand backend
     have been removed from this copy)
3. Include paths, **in this order** (Options for Target → C/C++ → Include
   Paths):
   1. `.` (this folder — so the vendored `relic_conf.h` wins)
   2. `relic/include`
   3. `relic/include/low`
   4. `relic/src/tmpl`
   5. `include`
4. C settings: C99 or later; optimization `-Os` (matches the GCC reference
   build); no extra defines needed — `relic_conf.h` carries the whole
   configuration.
5. `printf`: either retarget STDOUT (Options → Target → use MicroLIB +
   Debug (printf) Viewer via ITM, or Compiler → I/O → STDOUT: ITM), or skip
   it entirely — all results land in volatile globals readable from a Watch
   window.
6. Debug: **Use Simulator**, core clock set to the frequency you want to
   report (e.g. 168 MHz — SysTick counts core cycles, so cycle counts are
   clock-independent; only the ms conversion uses the frequency).

## What to read in the Watch window

`clear_signing_m4.c` (break on `g_done == 1`):

| Global | Meaning |
|---|---|
| `g_hashes_ok` | 1 = on-chip Poseidon(C)/Poseidon(T) match the prover's public inputs |
| `g_valid` | 1 = 3-pair product equals cached e(alpha,beta) → proof VALID |
| `g_cycles_hc` / `g_cycles_ht` | cycles for Poseidon(C) / Poseidon(T) |
| `g_cycles_prep` | cycles for the 2 `ep_mul` public-input preparation |
| `g_cycles_pair` | cycles for the 3-pair multi-pairing |
| `g_cycles_total` | sum of the four phases |

`main_m4.c` / `single_pairing_m4.c`: `g_valid`, `g_ticks[]` (one entry per
iteration), `g_done`.

Expected functional result (already verified under QEMU with the identical
sources): `g_hashes_ok = 1`, `g_valid = 1`.

## Provenance / regeneration

This folder is assembled from the repo (do not edit here and there
divergently — the repo copies are authoritative):

- `app/clear_signing_m4.c`, `app/main_m4.c`, `app/single_pairing_m4.c` ← `../uvision/`
- `app/crypto_init.c`, `app/point_decode.c` ← `../src/`
- `app/fr.c`, `app/poseidon.c` ← `../../minimal_c_verifier/src/`
- `include/*` ← `../include/`, `../test/test_vectors.h`,
  `../../minimal_c_verifier/include/`,
  `../../minimal_c_verifier/test/clear_signing_vectors.h`
- `relic/` ← `../lib/relic/` (minus `arch/relic_arch_{a64,x64}.c`,
  `rand/relic_rand_udev.c`, CMake files)
- `relic_conf.h` ← `../uvision/relic_conf.h`

Self-containment check (all 123 sources compile against only these headers):

```sh
cd uvision_project
GCCINC=$(arm-none-eabi-gcc -mcpu=cortex-m4 -print-file-name=include)
for f in $(find app relic/src -name '*.c'); do
  arm-none-eabi-gcc -mcpu=cortex-m4 -mthumb -Os -nostdinc \
    -I. -I../uvision/include -isystem "$GCCINC" \
    -Irelic/include -Irelic/include/low -Irelic/src/tmpl -Iinclude \
    -c "$f" -o /tmp/$(basename $f .c).o || echo "FAIL: $f"
done
```

(The `../uvision/include` shims are only for this host-side GCC check —
Keil's armclang has a real C library; do not add them to the µVision
project.)
