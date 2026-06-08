use ark_bn254::{Bn254, Fr};
use ark_crypto_primitives::sponge::poseidon::PoseidonConfig;
use ark_groth16::{
    prepare_verifying_key, Groth16, PreparedVerifyingKey, Proof, ProvingKey, VerifyingKey,
};
use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystem, SynthesisError};
use rand::rngs::OsRng;

use crate::circuit::PoseidonPreimageCircuit;
use crate::params::poseidon_hash_chain;

pub type E = Bn254;

pub struct Groth16Artifacts {
    pub pk: ProvingKey<E>,
    pub vk: VerifyingKey<E>,
    pub pvk: PreparedVerifyingKey<E>,
}

/// Run trusted setup (circuit-specific CRS generation).
pub fn setup(
    params: &PoseidonConfig<Fr>,
    iterations: usize,
) -> Result<Groth16Artifacts, SynthesisError> {
    let empty_circuit = PoseidonPreimageCircuit {
        params: params.clone(),
        iterations,
        preimage: None,
        hash: None,
    };

    let mut rng = OsRng;
    let pk = Groth16::<E>::generate_random_parameters_with_reduction(empty_circuit, &mut rng)?;
    let vk = pk.vk.clone();
    let pvk = prepare_verifying_key(&vk);

    Ok(Groth16Artifacts { pk, vk, pvk })
}

/// Generate a proof that the prover knows `preimage` such that `Poseidon^N(preimage) = hash`.
pub fn prove(
    pk: &ProvingKey<E>,
    params: &PoseidonConfig<Fr>,
    preimage: Fr,
    iterations: usize,
) -> Result<(Proof<E>, Vec<Fr>), SynthesisError> {
    let hash = poseidon_hash_chain(params, preimage, iterations);

    let circuit = PoseidonPreimageCircuit {
        params: params.clone(),
        iterations,
        preimage: Some(preimage),
        hash: Some(hash),
    };

    let mut rng = OsRng;
    let proof = Groth16::<E>::create_random_proof_with_reduction(circuit, pk, &mut rng)?;

    Ok((proof, vec![hash]))
}

/// Verify a Groth16 proof against the public inputs.
pub fn verify(pvk: &PreparedVerifyingKey<E>, public_inputs: &[Fr], proof: &Proof<E>) -> bool {
    Groth16::<E>::verify_proof(pvk, proof, public_inputs).unwrap_or(false)
}

/// Print circuit statistics (constraint count, variable counts).
pub fn print_circuit_stats(params: &PoseidonConfig<Fr>, iterations: usize) {
    let cs = ConstraintSystem::<Fr>::new_ref();
    let circuit = PoseidonPreimageCircuit {
        params: params.clone(),
        iterations,
        preimage: None,
        hash: None,
    };
    circuit.generate_constraints(cs.clone()).expect("synthesize");

    println!("Circuit statistics ({iterations} iterations):");
    println!("  Constraints:       {}", cs.num_constraints());
    println!(
        "  Public inputs:     {} (includes implicit 1)",
        cs.num_instance_variables()
    );
    println!("  Witness variables: {}", cs.num_witness_variables());
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::params::poseidon_params;

    #[test]
    fn full_round_trip() {
        let params = poseidon_params();
        let artifacts = setup(&params, 1).unwrap();

        let preimage = Fr::from(12345u64);
        let (proof, public_inputs) = prove(&artifacts.pk, &params, preimage, 1).unwrap();

        assert!(verify(&artifacts.pvk, &public_inputs, &proof));
    }

    #[test]
    fn multi_iteration_round_trip() {
        let params = poseidon_params();
        let artifacts = setup(&params, 5).unwrap();

        let preimage = Fr::from(12345u64);
        let (proof, public_inputs) = prove(&artifacts.pk, &params, preimage, 5).unwrap();

        assert!(verify(&artifacts.pvk, &public_inputs, &proof));
    }

    #[test]
    fn wrong_public_input_rejects() {
        let params = poseidon_params();
        let artifacts = setup(&params, 1).unwrap();

        let preimage = Fr::from(12345u64);
        let (proof, mut public_inputs) = prove(&artifacts.pk, &params, preimage, 1).unwrap();

        public_inputs[0] += Fr::from(1u64);
        assert!(!verify(&artifacts.pvk, &public_inputs, &proof));
    }
}
