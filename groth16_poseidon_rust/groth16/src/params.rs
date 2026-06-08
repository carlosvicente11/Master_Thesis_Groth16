use ark_bn254::Fr;
use ark_crypto_primitives::sponge::poseidon::traits::find_poseidon_ark_and_mds;
use ark_crypto_primitives::sponge::poseidon::PoseidonConfig;
use ark_ff::PrimeField;
use common::{FULL_ROUNDS, PARTIAL_ROUNDS, SBOX_DEGREE, WIDTH};

/// Poseidon parameters for BN254 scalar field.
///
/// Uses the Grain LFSR deterministic generation from the Poseidon paper.
/// Parameters chosen for 128-bit security:
/// - Rate: 2 (state width = rate + capacity = 3)
/// - Alpha: 5 (x^5 S-box, standard for BN254)
/// - Full rounds: 8
/// - Partial rounds: 56
pub fn poseidon_params() -> PoseidonConfig<Fr> {
    let rate = WIDTH - 1;
    let capacity = 1;

    let (ark, mds) = find_poseidon_ark_and_mds::<Fr>(
        Fr::MODULUS_BIT_SIZE as u64,
        rate,
        FULL_ROUNDS as u64,
        PARTIAL_ROUNDS as u64,
        0,
    );

    PoseidonConfig {
        full_rounds: FULL_ROUNDS,
        partial_rounds: PARTIAL_ROUNDS,
        alpha: SBOX_DEGREE,
        ark,
        mds,
        rate,
        capacity,
    }
}

/// Compute a single native Poseidon hash (no constraints).
pub fn poseidon_hash(params: &PoseidonConfig<Fr>, preimage: Fr) -> Fr {
    use ark_crypto_primitives::sponge::{
        poseidon::PoseidonSponge, CryptographicSponge, FieldBasedCryptographicSponge,
    };

    let mut sponge = PoseidonSponge::new(params);
    sponge.absorb(&preimage);
    let output: Vec<Fr> = sponge.squeeze_native_field_elements(1);
    output[0]
}

/// Compute N iterations of chained Poseidon hashing: Poseidon^N(preimage).
pub fn poseidon_hash_chain(params: &PoseidonConfig<Fr>, preimage: Fr, iterations: usize) -> Fr {
    let mut current = preimage;
    for _ in 0..iterations {
        current = poseidon_hash(params, current);
    }
    current
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn params_are_deterministic() {
        let p1 = poseidon_params();
        let p2 = poseidon_params();
        assert_eq!(p1.ark, p2.ark);
        assert_eq!(p1.mds, p2.mds);
    }

    #[test]
    fn hash_is_deterministic() {
        let params = poseidon_params();
        let preimage = Fr::from(42u64);
        let h1 = poseidon_hash(&params, preimage);
        let h2 = poseidon_hash(&params, preimage);
        assert_eq!(h1, h2);
    }

    #[test]
    fn different_preimages_different_hashes() {
        let params = poseidon_params();
        let h1 = poseidon_hash(&params, Fr::from(1u64));
        let h2 = poseidon_hash(&params, Fr::from(2u64));
        assert_ne!(h1, h2);
    }
}
