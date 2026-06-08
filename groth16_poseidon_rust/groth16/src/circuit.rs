use ark_bn254::Fr;
use ark_crypto_primitives::sponge::constraints::CryptographicSpongeVar;
use ark_crypto_primitives::sponge::poseidon::constraints::PoseidonSpongeVar;
use ark_crypto_primitives::sponge::poseidon::PoseidonConfig;
use ark_r1cs_std::fields::fp::FpVar;
use ark_r1cs_std::prelude::*;
use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError};

/// Circuit that proves knowledge of a preimage `x` such that `Poseidon^N(x) = h`.
///
/// - Private witness: `preimage` (the secret value)
/// - Public input: `hash` (the Poseidon hash after N iterations)
/// - Parameter: `iterations` (number of chained hash applications, baked into circuit structure)
///
/// The verifier only sees `h` and the proof; it does not learn `x`.
#[derive(Clone)]
pub struct PoseidonPreimageCircuit {
    pub params: PoseidonConfig<Fr>,
    pub iterations: usize,
    pub preimage: Option<Fr>,
    pub hash: Option<Fr>,
}

impl ConstraintSynthesizer<Fr> for PoseidonPreimageCircuit {
    fn generate_constraints(self, cs: ConstraintSystemRef<Fr>) -> Result<(), SynthesisError> {
        let preimage_val = self.preimage.unwrap_or(Fr::from(0u64));
        let mut current = FpVar::new_witness(cs.clone(), || Ok(preimage_val))?;

        let hash_val = self.hash.unwrap_or(Fr::from(0u64));
        let hash_var = FpVar::new_input(cs.clone(), || Ok(hash_val))?;

        for _ in 0..self.iterations {
            let mut sponge = PoseidonSpongeVar::new(cs.clone(), &self.params);
            sponge.absorb(&current)?;
            let output = sponge.squeeze_field_elements(1)?;
            current = output[0].clone();
        }

        current.enforce_equal(&hash_var)?;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::params::{poseidon_hash_chain, poseidon_params};
    use ark_relations::r1cs::ConstraintSystem;

    #[test]
    fn single_iteration_satisfies_constraints() {
        let params = poseidon_params();
        let preimage = Fr::from(42u64);
        let hash = poseidon_hash_chain(&params, preimage, 1);

        let circuit = PoseidonPreimageCircuit {
            params,
            iterations: 1,
            preimage: Some(preimage),
            hash: Some(hash),
        };

        let cs = ConstraintSystem::<Fr>::new_ref();
        circuit.generate_constraints(cs.clone()).unwrap();
        assert!(cs.is_satisfied().unwrap());
    }

    #[test]
    fn multiple_iterations_satisfies_constraints() {
        let params = poseidon_params();
        let preimage = Fr::from(42u64);
        let hash = poseidon_hash_chain(&params, preimage, 10);

        let circuit = PoseidonPreimageCircuit {
            params,
            iterations: 10,
            preimage: Some(preimage),
            hash: Some(hash),
        };

        let cs = ConstraintSystem::<Fr>::new_ref();
        circuit.generate_constraints(cs.clone()).unwrap();
        assert!(cs.is_satisfied().unwrap());
    }

    #[test]
    fn wrong_preimage_fails_constraints() {
        let params = poseidon_params();
        let preimage = Fr::from(42u64);
        let hash = poseidon_hash_chain(&params, preimage, 1);

        let wrong_preimage = Fr::from(99u64);
        let circuit = PoseidonPreimageCircuit {
            params,
            iterations: 1,
            preimage: Some(wrong_preimage),
            hash: Some(hash),
        };

        let cs = ConstraintSystem::<Fr>::new_ref();
        circuit.generate_constraints(cs.clone()).unwrap();
        assert!(!cs.is_satisfied().unwrap());
    }
}
