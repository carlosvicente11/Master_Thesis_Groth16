//! Two-hash clear-signing circuit, skeleton stage (plan step 3): only the two
//! hash bindings are constrained —
//!   1. Poseidon(pack(C)) == h_c
//!   4. Poseidon(pack(T)) == h_t
//! Parsing/formatting constraints (relations 2 and 3) come in step 4 and will
//! operate on the same byte witnesses allocated here.

use ark_bn254::Fr;
use ark_crypto_primitives::sponge::constraints::CryptographicSpongeVar;
use ark_crypto_primitives::sponge::poseidon::constraints::PoseidonSpongeVar;
use ark_crypto_primitives::sponge::poseidon::PoseidonConfig;
use ark_r1cs_std::fields::fp::FpVar;
use ark_r1cs_std::prelude::*;
use ark_r1cs_std::uint8::UInt8;
use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError};

/// ERC-20 transfer(address,uint256): selector + 2 static 32-byte slots.
pub const CALLDATA_BYTES: usize = 68;
/// Fixed rendered-text length; shorter texts are space-padded by the prover
/// and the chip hashes the same padded buffer.
pub const TEXT_BYTES: usize = 96;

const PACK_CHUNK_BYTES: usize = 31;

/// In-circuit mirror of the locked packing + sponge convention:
/// absorb Fr(len) then each 31-byte chunk as a big-endian integer.
/// Chunk recombination is linear (no constraints); the byte witnesses carry
/// the 8-bit range constraints from `UInt8` allocation.
fn poseidon_hash_bytes_gadget(
    cs: ConstraintSystemRef<Fr>,
    params: &PoseidonConfig<Fr>,
    bytes: &[UInt8<Fr>],
) -> Result<FpVar<Fr>, SynthesisError> {
    let mut sponge = PoseidonSpongeVar::new(cs, params);
    sponge.absorb(&FpVar::constant(Fr::from(bytes.len() as u64)))?;
    for chunk in bytes.chunks(PACK_CHUNK_BYTES) {
        let mut acc = FpVar::zero();
        for byte in chunk {
            acc = acc * Fr::from(256u64) + byte.to_fp()?;
        }
        sponge.absorb(&acc)?;
    }
    Ok(sponge.squeeze_field_elements(1)?[0].clone())
}

/// Public inputs (in IC order): [h_c, h_t]. Witness: calldata + text bytes.
#[derive(Clone)]
pub struct TwoHashCircuit {
    pub params: PoseidonConfig<Fr>,
    pub calldata: Option<Vec<u8>>,
    pub text: Option<Vec<u8>>,
    pub h_c: Option<Fr>,
    pub h_t: Option<Fr>,
}

impl ConstraintSynthesizer<Fr> for TwoHashCircuit {
    fn generate_constraints(self, cs: ConstraintSystemRef<Fr>) -> Result<(), SynthesisError> {
        let h_c_var = FpVar::new_input(cs.clone(), || Ok(self.h_c.unwrap_or_default()))?;
        let h_t_var = FpVar::new_input(cs.clone(), || Ok(self.h_t.unwrap_or_default()))?;

        let calldata = self.calldata.unwrap_or_else(|| vec![0u8; CALLDATA_BYTES]);
        let text = self.text.unwrap_or_else(|| vec![0u8; TEXT_BYTES]);
        assert_eq!(calldata.len(), CALLDATA_BYTES, "calldata must be padded");
        assert_eq!(text.len(), TEXT_BYTES, "text must be padded");

        let calldata_vars = UInt8::new_witness_vec(cs.clone(), &calldata)?;
        let text_vars = UInt8::new_witness_vec(cs.clone(), &text)?;

        // Relation 1: Poseidon(pack(C)) == h_c.
        let h_c_computed = poseidon_hash_bytes_gadget(cs.clone(), &self.params, &calldata_vars)?;
        h_c_computed.enforce_equal(&h_c_var)?;

        // Relation 4: Poseidon(pack(T)) == h_t.
        let h_t_computed = poseidon_hash_bytes_gadget(cs, &self.params, &text_vars)?;
        h_t_computed.enforce_equal(&h_t_var)?;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_relations::r1cs::ConstraintSystem;
    use poseidon_preimage_groth16::pack::poseidon_hash_bytes;
    use poseidon_preimage_groth16::params::poseidon_params;

    fn sample_inputs() -> (Vec<u8>, Vec<u8>) {
        let mut calldata = vec![0u8; CALLDATA_BYTES];
        calldata[..4].copy_from_slice(&[0xa9, 0x05, 0x9c, 0xbb]);
        calldata[16..36].fill(0x11);
        calldata[64..].copy_from_slice(&12_500_000u32.to_be_bytes());

        let mut text =
            b"Send 12.500000 USDC to 0x1111111111111111111111111111111111111111".to_vec();
        text.resize(TEXT_BYTES, b' ');
        (calldata, text)
    }

    fn circuit_with(calldata: Vec<u8>, text: Vec<u8>, h_c: Fr, h_t: Fr) -> TwoHashCircuit {
        TwoHashCircuit {
            params: poseidon_params(),
            calldata: Some(calldata),
            text: Some(text),
            h_c: Some(h_c),
            h_t: Some(h_t),
        }
    }

    #[test]
    fn good_witness_satisfies() {
        let params = poseidon_params();
        let (calldata, text) = sample_inputs();
        let h_c = poseidon_hash_bytes(&params, &calldata);
        let h_t = poseidon_hash_bytes(&params, &text);

        let cs = ConstraintSystem::<Fr>::new_ref();
        circuit_with(calldata, text, h_c, h_t)
            .generate_constraints(cs.clone())
            .unwrap();
        assert!(cs.is_satisfied().unwrap());
    }

    #[test]
    fn in_circuit_hash_matches_native_convention() {
        // The gadget must reproduce pack::poseidon_hash_bytes exactly (which is
        // itself cross-validated against the C poseidon_hash_bytes).
        let params = poseidon_params();
        let (calldata, text) = sample_inputs();
        let h_c = poseidon_hash_bytes(&params, &calldata);
        let h_t = poseidon_hash_bytes(&params, &text);

        let cs = ConstraintSystem::<Fr>::new_ref();
        let calldata_vars = UInt8::new_witness_vec(cs.clone(), &calldata).unwrap();
        let text_vars = UInt8::new_witness_vec(cs.clone(), &text).unwrap();
        let hc_var = poseidon_hash_bytes_gadget(cs.clone(), &params, &calldata_vars).unwrap();
        let ht_var = poseidon_hash_bytes_gadget(cs, &params, &text_vars).unwrap();
        assert_eq!(hc_var.value().unwrap(), h_c);
        assert_eq!(ht_var.value().unwrap(), h_t);
    }

    #[test]
    fn tampered_calldata_unsatisfied() {
        let params = poseidon_params();
        let (calldata, text) = sample_inputs();
        let h_c = poseidon_hash_bytes(&params, &calldata);
        let h_t = poseidon_hash_bytes(&params, &text);

        let mut bad = calldata.clone();
        bad[67] ^= 0x01; // amount off by one
        let cs = ConstraintSystem::<Fr>::new_ref();
        circuit_with(bad, text, h_c, h_t)
            .generate_constraints(cs.clone())
            .unwrap();
        assert!(!cs.is_satisfied().unwrap());
    }

    #[test]
    fn tampered_text_unsatisfied() {
        let params = poseidon_params();
        let (calldata, text) = sample_inputs();
        let h_c = poseidon_hash_bytes(&params, &calldata);
        let h_t = poseidon_hash_bytes(&params, &text);

        let mut bad = text.clone();
        bad[5] = b'9'; // displayed amount lies
        let cs = ConstraintSystem::<Fr>::new_ref();
        circuit_with(calldata, bad, h_c, h_t)
            .generate_constraints(cs.clone())
            .unwrap();
        assert!(!cs.is_satisfied().unwrap());
    }
}
