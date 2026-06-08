/// Poseidon parameters shared across implementations.
///
/// Both Groth16 (arkworks Poseidon sponge) and RISC0 (Plonky3 Poseidon2)
/// use these structural parameters over the BN254 scalar field.
///
/// The hash constructions differ — Groth16 uses sponge-based Poseidon,
/// RISC0 uses permutation-based Poseidon2 — so their outputs are not
/// compatible despite sharing parameters.
pub const WIDTH: usize = 3;
pub const SBOX_DEGREE: u64 = 5;
pub const FULL_ROUNDS: usize = 8;
pub const PARTIAL_ROUNDS: usize = 56;

pub const DEFAULT_PREIMAGE: u64 = 12345;
