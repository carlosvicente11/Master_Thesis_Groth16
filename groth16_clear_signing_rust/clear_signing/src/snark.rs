use ark_bn254::{Bn254, Fr};
use ark_crypto_primitives::sponge::poseidon::PoseidonConfig;
use ark_groth16::{
    prepare_verifying_key, Groth16, PreparedVerifyingKey, Proof, ProvingKey, VerifyingKey,
};
use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystem, SynthesisError};
use poseidon_preimage_groth16::pack::poseidon_hash_bytes;
use rand::rngs::OsRng;

use crate::circuit::TwoHashCircuit;

pub type E = Bn254;

pub struct Groth16Artifacts {
    pub pk: ProvingKey<E>,
    pub vk: VerifyingKey<E>,
    pub pvk: PreparedVerifyingKey<E>,
}

/// Circuit-specific trusted setup (single-party; see plan §8).
pub fn setup(params: &PoseidonConfig<Fr>) -> Result<Groth16Artifacts, SynthesisError> {
    let empty_circuit = TwoHashCircuit {
        params: params.clone(),
        calldata: None,
        text: None,
        h_c: None,
        h_t: None,
    };

    let mut rng = OsRng;
    let pk = Groth16::<E>::generate_random_parameters_with_reduction(empty_circuit, &mut rng)?;
    let vk = pk.vk.clone();
    let pvk = prepare_verifying_key(&vk);

    Ok(Groth16Artifacts { pk, vk, pvk })
}

/// Prove that `text` is bound to `calldata` under the circuit's relations.
/// Returns the proof and the public inputs [h_c, h_t].
pub fn prove(
    pk: &ProvingKey<E>,
    params: &PoseidonConfig<Fr>,
    calldata: &[u8],
    text: &[u8],
) -> Result<(Proof<E>, Vec<Fr>), SynthesisError> {
    let h_c = poseidon_hash_bytes(params, calldata);
    let h_t = poseidon_hash_bytes(params, text);

    let circuit = TwoHashCircuit {
        params: params.clone(),
        calldata: Some(calldata.to_vec()),
        text: Some(text.to_vec()),
        h_c: Some(h_c),
        h_t: Some(h_t),
    };

    let mut rng = OsRng;
    let proof = Groth16::<E>::create_random_proof_with_reduction(circuit, pk, &mut rng)?;

    Ok((proof, vec![h_c, h_t]))
}

pub fn verify(pvk: &PreparedVerifyingKey<E>, public_inputs: &[Fr], proof: &Proof<E>) -> bool {
    Groth16::<E>::verify_proof(pvk, proof, public_inputs).unwrap_or(false)
}

pub fn print_circuit_stats(params: &PoseidonConfig<Fr>) {
    let cs = ConstraintSystem::<Fr>::new_ref();
    let circuit = TwoHashCircuit {
        params: params.clone(),
        calldata: None,
        text: None,
        h_c: None,
        h_t: None,
    };
    circuit.generate_constraints(cs.clone()).expect("synthesize");

    println!("Circuit statistics (two-hash ERC-20 transfer v1):");
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
    use crate::template::{build_transfer_calldata, render_transfer_text};
    use poseidon_preimage_groth16::params::poseidon_params;

    fn sample_inputs() -> (Vec<u8>, Vec<u8>) {
        let calldata = build_transfer_calldata(&[0x11; 20], 12_500_000);
        let text = render_transfer_text(&calldata).unwrap();
        (calldata, text)
    }

    #[test]
    fn full_round_trip() {
        let params = poseidon_params();
        let artifacts = setup(&params).unwrap();

        let (calldata, text) = sample_inputs();
        let (proof, public_inputs) = prove(&artifacts.pk, &params, &calldata, &text).unwrap();

        assert_eq!(public_inputs.len(), 2);
        assert!(verify(&artifacts.pvk, &public_inputs, &proof));
    }

    #[test]
    fn wrong_public_input_rejects() {
        let params = poseidon_params();
        let artifacts = setup(&params).unwrap();

        let (calldata, text) = sample_inputs();
        let (proof, mut public_inputs) = prove(&artifacts.pk, &params, &calldata, &text).unwrap();

        public_inputs[1] += Fr::from(1u64); // h_t of a different text
        assert!(!verify(&artifacts.pvk, &public_inputs, &proof));
    }

    #[test]
    fn swapped_public_inputs_reject() {
        let params = poseidon_params();
        let artifacts = setup(&params).unwrap();

        let (calldata, text) = sample_inputs();
        let (proof, public_inputs) = prove(&artifacts.pk, &params, &calldata, &text).unwrap();

        let swapped = vec![public_inputs[1], public_inputs[0]];
        assert!(!verify(&artifacts.pvk, &swapped, &proof));
    }
}
