// Dumps the arkworks Poseidon parameters used by the prover so the pure-C
// verifier can hardcode byte-identical constants. Field elements are printed
// as canonical (non-Montgomery) 32-byte big-endian hex, matching cross_validate.

use ark_bn254::Fr;
use ark_crypto_primitives::sponge::poseidon::PoseidonConfig;
use ark_ff::{BigInteger, PrimeField};

use common::{FULL_ROUNDS, PARTIAL_ROUNDS, SBOX_DEGREE, WIDTH};
use poseidon_preimage_groth16::params::{poseidon_hash, poseidon_params};

fn fr_to_be(elem: &Fr) -> [u8; 32] {
    let bigint = elem.into_bigint();
    let mut out = [0u8; 32];
    let le_bytes = bigint.to_bytes_le();
    for (i, &b) in le_bytes.iter().enumerate() {
        out[31 - i] = b;
    }
    out
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn main() {
    let params: PoseidonConfig<Fr> = poseidon_params();

    println!("=== Poseidon params (arkworks sponge, BN254 Fr) ===\n");
    println!("--- Structural ---");
    println!("width         = {WIDTH}");
    println!("rate          = {}", params.rate);
    println!("capacity      = {}", params.capacity);
    println!("alpha (S-box) = {SBOX_DEGREE}");
    println!("full_rounds   = {FULL_ROUNDS}");
    println!("partial_rounds= {PARTIAL_ROUNDS}");
    println!("total_rounds  = {}", FULL_ROUNDS + PARTIAL_ROUNDS);
    println!("Fr modulus bits = {}", Fr::MODULUS_BIT_SIZE);
    println!("ark dims      = {} x {}", params.ark.len(), params.ark[0].len());
    println!("mds dims      = {} x {}", params.mds.len(), params.mds[0].len());

    println!("\n--- ARK round constants (row-major, BE hex) ---");
    for (r, row) in params.ark.iter().enumerate() {
        for (c, val) in row.iter().enumerate() {
            println!("ark[{r}][{c}] = {}", hex(&fr_to_be(val)));
        }
    }

    println!("\n--- MDS matrix (BE hex) ---");
    for (r, row) in params.mds.iter().enumerate() {
        for (c, val) in row.iter().enumerate() {
            println!("mds[{r}][{c}] = {}", hex(&fr_to_be(val)));
        }
    }

    println!("\n--- Test vectors: poseidon_hash(absorb 1, squeeze 1) ---");
    for x in [0u64, 1, 2, 42, common::DEFAULT_PREIMAGE] {
        let h = poseidon_hash(&params, Fr::from(x));
        println!("H({x}) = {}", hex(&fr_to_be(&h)));
    }

    println!("\n=== END ===");
}
