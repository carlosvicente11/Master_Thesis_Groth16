# Groth16 BN254 Verifier for Clear Signing

Master's thesis implementation of zero-knowledge clear signing: a Groth16 (BN254)
proof that a human-readable display text is the canonical rendering of a
transaction's calldata, verified on a constrained ARM Cortex-M4
(emulated via QEMU / Keil µVision). Rust
produces the proofs and artifacts; a minimal C verifier (built on a trimmed
RELIC library) checks them on desktop and bare-metal ARM.

## Project Structure

```
thesis/
├── groth16_poseidon_rust/         # Rust prover: Poseidon-preimage statement
├── groth16_clear_signing_rust/    # Rust prover: two-hash clear-signing statement
├── device_verifier_bn254/         # Bare-metal Cortex-M4 verifier (trimmed RELIC, in-tree)
├── minimal_c_verifier/            # Desktop C verifier + test/CLI harness
├── groth16_poseidon_c/            # Earlier desktop C verifier (preimage)
├── groth16_poseidon_assembly/     # Earlier Cortex-M4 verifier with hand-tuned assembly
└── lib.zip                        # Full RELIC source (for the earlier projects only)
```

The four main projects are the first four. `device_verifier_bn254` ships its
own trimmed RELIC tree in-repo (`lib/relic/`), which `minimal_c_verifier`
also builds against.

## Prerequisites

| Tool | Version | Purpose |
|---|---|---|
| git | any | clone the repository |
| CMake | **3.14+** | build all C projects |
| make | any | CMake's build backend |
| GCC or Clang | any recent | desktop C builds (`minimal_c_verifier`) |
| Rust (rustup: stable + cargo) | 1.88+ | Rust provers and artifact exporters |
| arm-none-eabi-gcc | 10+ | ARM cross-compilation (`device_verifier_bn254`) |
| QEMU (qemu-system-arm) | any recent | running the ARM firmware in emulation |

All cryptographic libraries are vendored, RELIC ships in the repo and the
arkworks crates are fetched automatically by cargo. No system crypto or GMP
is required.

### macOS

```bash
xcode-select --install                       # clang + make (if not present)
brew install cmake qemu
brew install --cask gcc-arm-embedded         # arm-none-eabi-gcc
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh   # Rust
```

### Linux (Debian/Ubuntu; other distros have equivalent packages)

```bash
sudo apt update
sudo apt install git cmake make gcc gcc-arm-none-eabi qemu-system-arm
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh   # Rust
```

Note: CMake should be 3.14<; check with `cmake --version` and upgrade if needed (e.g. from [cmake.org](https://cmake.org/download/) or the Kitware apt repository).

### Windows

**Recommended: WSL2** (Ubuntu). All builds, scripts, and QEMU runs work
unchanged. Follow the Linux instructions inside WSL:

```powershell
wsl --install -d Ubuntu    # then use the Linux commands above inside WSL
```

The one native-Windows-only tool is **Keil µVision 5 / Arm MDK**, used optionally for cycle-accurate simulation; everything else is easier under WSL2.

## groth16_poseidon_rust (Poseidon preimage)

Statement: *"the prover knows x such that Poseidon(x) = h"*. The public input
is the hash `h`.

```bash
cd groth16_poseidon_rust

# Verify the pre-generated proof in artifacts/
cargo run --release --bin poseidon-preimage-groth16 -- verify

# Export the artifacts to the raw layout the C verifiers consume
cargo run --release --bin export_vk_raw      # -> artifacts/vk_raw.bin (768 B)
cargo run --release --bin export_proof_raw   # -> artifacts/proof_raw.bin (256 B),
                                             #    artifacts/public_input_raw.bin (32 B)

# Cross-validation / profiling helpers
cargo run --release --bin cross_validate     # dumps intermediates for comparison with C
cargo run --release --bin profile_verify     # times each verification step
```

> **Do not run `setup` or `prove`.** They perform a fresh random trusted
> setup and overwrite `artifacts/`. The pre-generated set is **frozen**: the
> C headers (`vk_constants.h`, `test_vectors.h`) compiled into the device
> firmware were generated from it and cannot be regenerated to match a new
> setup. `verify` and the exporters are read-only and always safe.

Clean:

```bash
cargo clean        # removes target/; artifacts/ is untouched
```

## groth16_clear_signing_rust (clear signing)

Statement: *"display text T is the canonical rendering of calldata C"*. The
public inputs are the two hashes `h_c = Poseidon(C)` and `h_t = Poseidon(T)`.

```bash
cd groth16_clear_signing_rust

# In-memory demo: build calldata + text, setup, prove, verify, tamper-check
cargo run --release --bin clear-signing-groth16

# Full artifact export: fresh trusted setup + proof + all raw files -> artifacts/
cargo run --release --bin export_artifacts

# VK-only raw conversion (reads the existing VK, no setup) -> artifacts/vk_raw.bin
cargo run --release --bin export_vk_raw
```

Clean:

```bash
cargo clean        # removes target/; artifacts/ is untouched
```

## device_verifier_bn254 (bare-metal Cortex-M4 verifier)

The headline artifact: verifies the clear-signing proof on an emulated
Cortex-M4, with the trimmed RELIC BN254 pairing stack in-tree (no setup
needed). Two board configurations, which must match the QEMU machine:

| Build dir | BOARD | Memory | QEMU machine |
|---|---|---|---|
| `build_m4` | `mps2-an386` (default) | 4 MB / 4 MB | `mps2-an386` |
| `build_m4_stm32f405` | `stm32f405` | 1 MB / 128 KB | `netduinoplus2` |

Build (trimmed, leaves only the ELFs and `.map` files):

```bash
cd device_verifier_bn254
scripts/build_trimmed.sh build_m4                        # default board
scripts/build_trimmed.sh build_m4_stm32f405 stm32f405    # STM32F405 board
```

Run under QEMU:

```bash
qemu-system-arm -machine mps2-an386 -nographic -semihosting \
    -kernel build_m4/clear_signing_m4

qemu-system-arm -machine netduinoplus2 -nographic -semihosting \
    -kernel build_m4_stm32f405/clear_signing_m4
```

Each build dir contains three firmwares: `clear_signing_m4` (full two-hash
verification), `multi_pairing_m4` and `single_pairing_m4` (pairing-only
benchmarks).

Clean:

```bash
rm -rf build_m4 build_m4_stm32f405
```

## minimal_c_verifier (desktop C verifier)

Host-side harness for the same verification engine (builds RELIC from the
`device_verifier_bn254` tree).

Build (trimmed, leaves only the executables):

```bash
cd minimal_c_verifier
scripts/build_trimmed.sh          # -> build/
```

Run:

```bash
# Test suite (run from test/ — it loads the raw proof files from the cwd)
cd test && ../build/test_verifier && cd ..

# Cross-validation against the Rust prover / profiling (compiled-in vectors)
build/cross_validate
build/profile_verify

cd ..   # thesis/

# File-driven CLIs: verify the Rust-exported artifacts directly
A=groth16_clear_signing_rust/artifacts
minimal_c_verifier/build/clear_signing_cli \
    $A/vk_raw.bin $A/proof_raw.bin $A/calldata.bin $A/text.bin

A=groth16_poseidon_rust/artifacts
minimal_c_verifier/build/poseidon_preimage_cli \
    $A/vk_raw.bin $A/proof_raw.bin $A/public_input_raw.bin
```

Both CLIs print the inputs and `VALID` / `INVALID`; exit code `0` = valid,
`1` = invalid, `2` = usage/IO error. Tampering with any input file flips the
result to INVALID.

Clean:

```bash
rm -rf build
```
