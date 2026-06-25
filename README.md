# Groth16 BN254 Verifier for Clear Signing

This repository contains the implementation of a Groth16 zero-knowledge proof system for clear signing verification on a constrained ARM Cortex-M4 chip.

## Quick Start for Reviewers

The headline artifact is the ARM Cortex-M4 verifier in `groth16_poseidon_assembly/`. To build and run it from a fresh clone:

```bash
# 0. Tools needed: arm-none-eabi-gcc, cmake (3.14+), qemu-system-arm
#    (macOS: brew install --cask gcc-arm-embedded; brew install cmake qemu)

# 1. Reconstitute the RELIC library (NOT stored in git — shipped as lib.zip).
#    A bare clone will NOT build until you do this. The -o flag overwrites the
#    placeholder files git checked out; the archive already contains the
#    optimized kernels, so nothing is lost.
unzip -o lib.zip -d groth16_poseidon_assembly/lib/

# 2. Build (hand-tuned assembly backend, the default).
cd groth16_poseidon_assembly
mkdir -p build && cd build
cmake .. -DCMAKE_TOOLCHAIN_FILE=../cmake/toolchain-arm-none-eabi.cmake
cmake --build .

# 3. Run the verification test suite under QEMU (expect "All tests passed").
qemu-system-arm -machine netduinoplus2 -nographic -semihosting -kernel ./test_verifier_arm
```

This is a **bare-metal ARM** project: there is no native/desktop build of the assembly verifier (CMake errors out if not cross-compiling), and it executes under QEMU rather than on a host CPU. For a desktop C verifier that runs natively, see `groth16_poseidon_c/` below.

## Prerequisites

| Tool | Purpose |
|---|---|
| Rust stable (1.88+) | Build Rust provers |
| CMake (3.14+) | Build C projects |
| GCC or Clang | Desktop C compilation |
| arm-none-eabi-gcc | ARM cross-compilation (optional) |
| QEMU (qemu-system-arm) | ARM emulation (optional) |

## Project Structure

```
thesis/
├── report/                       # Thesis chapter drafts
├── groth16_poseidon_rust/       # Rust prover/verifier (basic preimage)
├── groth16_poseidon_c/          # C verifier (basic preimage, desktop)
├── groth16_poseidon_assembly/   # C verifier (ARM Cortex-M4 with assembly)
└── lib.zip                      # RELIC crypto library (vendored)
```

The benchmark methodology, results, and proof-system selection draft is in
[`report/BENCHMARK_EVALUATION_DRAFT.md`](report/BENCHMARK_EVALUATION_DRAFT.md).

## Setting Up the RELIC Library

The RELIC crypto library is not checked into the repository directly. Instead, it is distributed as `lib.zip` at the root of the project. After cloning, unzip it into the projects that need it:

```bash
# From the thesis/ root
unzip lib.zip -d groth16_poseidon_c/lib/
unzip lib.zip -d groth16_poseidon_assembly/lib/
```

This creates `groth16_poseidon_c/lib/relic/` and `groth16_poseidon_assembly/lib/relic/`, which CMake expects. The RELIC source includes a custom Ethereum BN254 curve (`BN_P254E`) that is required for Groth16 verification on this curve.

## ARM Assembly Files

The hand-tuned ARM Thumb-2 assembly for BN254 field arithmetic is located in the RELIC source tree at:

```
lib/relic/src/low/arm-asm-254e/
├── relic_fp_add_low.s    # Field addition and subtraction
├── relic_fp_add_low.c    # C wrappers for addition operations
├── relic_fp_mul_low.s    # Field multiplication (schoolbook, 256-bit)
├── relic_fp_mul_low.c    # C wrappers for multiplication operations
├── relic_fp_rdc_low.s    # Montgomery reduction (Ethereum BN254 prime hardcoded)
└── relic_fp_rdc_low.c    # C wrappers for reduction operations
```

The `.s` files contain the assembly routines. The `.c` files are thin wrappers that combine the assembly primitives into the higher-level operations RELIC expects. These files are only compiled when building with the assembly backend (`ARITH=arm-asm-254e`, which is the default for the ARM build). When building with `-DFORCE_ARITH=easy`, RELIC uses generic C implementations from `src/low/easy/` instead and these files are not used.

## Groth16 Poseidon — Rust

Basic preimage: proves knowledge of a value whose Poseidon hash equals a public input.

```bash
cd groth16_poseidon_rust

# Build
cargo build --release

# Trusted setup (generates proving key and verifying key)
cargo run --release --bin poseidon-preimage-groth16 -- setup

# Generate proof (default preimage: 12345)
cargo run --release --bin poseidon-preimage-groth16 -- prove

# Verify proof
cargo run --release --bin poseidon-preimage-groth16 -- verify
```

Pre-generated artifacts are included in `artifacts/`, so you can skip setup and prove and run verify directly.

**Build output:**
```
groth16_poseidon_rust/
└── target/release/
    ├── poseidon-preimage-groth16    # main binary (setup/prove/verify)
    ├── cross_validate               # dumps intermediate values for comparison with C
    └── profile_verify               # times each verification step
```

## Groth16 Poseidon — C (Desktop)

C verifier using RELIC library with generic C arithmetic backend.

```bash
cd groth16_poseidon_c

# Build
mkdir build && cd build
cmake ..
cmake --build .

# Run verification
./groth16_verifier_main

# Run test suite (valid proof, tampered proof, wrong lengths, etc.)
./test_verifier

# Dump intermediate values for cross-validation with Rust
./cross_validate

# Profile each verification step
./profile_verify
```

**Build output:**
```
groth16_poseidon_c/
└── build/
    ├── groth16_verifier_main    # simple verification
    ├── test_verifier            # test suite
    ├── cross_validate           # dumps intermediate values for comparison with Rust
    ├── profile_verify           # times each verification step
    └── lib/relic/
        └── lib/librelic_s.a     # compiled RELIC library
```

## Groth16 Poseidon — ARM Assembly (Cortex-M4)

C verifier cross-compiled for ARM Cortex-M4 bare-metal, using hand-tuned assembly for field arithmetic. Runs under QEMU emulating a Netduino Plus 2 (STM32F405: 1MB flash, 128KB SRAM, Cortex-M4).

Requires `arm-none-eabi-gcc` and `qemu-system-arm`.

```bash
cd groth16_poseidon_assembly

# Build (assembly backend)
mkdir build && cd build
cmake .. -DCMAKE_TOOLCHAIN_FILE=../cmake/toolchain-arm-none-eabi.cmake
cmake --build .

# Build (generic C backend, for comparison)
cmake .. -DCMAKE_TOOLCHAIN_FILE=../cmake/toolchain-arm-none-eabi.cmake -DFORCE_ARITH=easy
cmake --build .

# Run test suite under QEMU
qemu-system-arm -machine netduinoplus2 -nographic -semihosting -kernel ./test_verifier_arm

# Run benchmark (SysTick cycle count)
qemu-system-arm -machine netduinoplus2 -nographic -semihosting -kernel ./bench_verifier_arm

# Dump intermediate values for cross-validation
qemu-system-arm -machine netduinoplus2 -nographic -semihosting -kernel ./cross_validate_arm
```

**Build output:**
```
groth16_poseidon_assembly/
└── build/
    ├── test_verifier_arm        # test suite (ARM ELF)
    ├── bench_verifier_arm       # cycle benchmark (ARM ELF)
    ├── cross_validate_arm       # intermediate value dump (ARM ELF)
    └── lib/relic/
        └── lib/librelic_s.a     # RELIC with ARM assembly backend
```

**Memory usage (STM32F405):**

| Backend | Flash (baseline) | Flash (current, post-strip) | RAM | Budget |
|---|---|---|---|---|
| Assembly (`arm-asm-254e`) | 214 KB | 55.0 KB | 12.5 KB | 1 MB / 128 KB |
| Generic C (`easy`) | 211 KB | 53.2 KB | 12.5 KB | 1 MB / 128 KB |

The *baseline* column is the pre-strip footprint (full RELIC, all curves/towers). The *current* column is after the Phase 3 source-level strip of unused curves and field towers. Measured with `arm-none-eabi-size` on `test_verifier_arm` (flash = text+data, RAM = data+bss). Note the assembly backend is slightly larger in flash than generic C (its unrolled `UMAAL`/`LDM`/`STM` kernels are bigger code) despite being ~3.6× faster in retired instructions.

## Cleaning Build Artifacts

```bash
# Rust
cd groth16_poseidon_rust
cargo clean                      # removes target/ directory

# C (desktop)
cd groth16_poseidon_c
rm -rf build                     # removes build/ directory

# ARM assembly
cd groth16_poseidon_assembly
rm -rf build                     # removes build/ directory
```

After cleaning, rebuild with the same commands above. `cargo run` automatically rebuilds if needed. For C/ARM, you need to run `cmake` and `cmake --build .` again.
