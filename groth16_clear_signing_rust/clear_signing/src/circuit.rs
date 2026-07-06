//! Two-hash clear-signing circuit, v1 (ERC-20 transfer). All four relations:
//!   1. Poseidon(pack(C)) == h_c
//!   2. parse(C) == params   (selector, zero paddings, to, amount)
//!   3. format(params) == T  (fixed template, decimal amount, hex address)
//!   4. Poseidon(pack(T)) == h_t
//! Relations 2 and 3 are merged: the constraints tie calldata bytes directly
//! to text bytes (both already witnessed for the hash bindings).

use ark_bn254::Fr;
use ark_crypto_primitives::sponge::constraints::CryptographicSpongeVar;
use ark_crypto_primitives::sponge::poseidon::constraints::PoseidonSpongeVar;
use ark_crypto_primitives::sponge::poseidon::PoseidonConfig;
use ark_r1cs_std::fields::fp::FpVar;
use ark_r1cs_std::prelude::*;
use ark_r1cs_std::uint8::UInt8;
use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError};

use crate::template::{
    AMOUNT_POS, DOT_POS, FRAC_POS, HEX_END, HEX_POS, INT_POS, MIDDLE, MIDDLE_POS, PREFIX,
    SELECTOR, TO_POS,
};

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

/// Value of a nibble from its little-endian bits (linear, no constraints).
fn nibble_value(bits: &[Boolean<Fr>]) -> FpVar<Fr> {
    let mut acc = FpVar::zero();
    let mut weight = Fr::from(1u64);
    for bit in bits {
        acc += FpVar::from(bit.clone()) * weight;
        weight += weight;
    }
    acc
}

/// n >= 10 for a 4-bit nibble: b3 AND (b2 OR b1). (10..15 = 1010..1111)
fn nibble_ge_ten(bits: &[Boolean<Fr>]) -> Boolean<Fr> {
    &bits[3] & (&bits[2] | &bits[1])
}

/// ASCII lowercase hex char of a nibble: '0'+n for n<10, 'a'+n-10 = '0'+n+39.
fn nibble_hex_char(bits: &[Boolean<Fr>]) -> FpVar<Fr> {
    FpVar::constant(Fr::from(u64::from(b'0')))
        + nibble_value(bits)
        + FpVar::from(nibble_ge_ten(bits)) * Fr::from(39u64)
}

/// Enforce that `byte` is an ASCII decimal digit and return its value.
/// '0'..'9' = 0b0011_0000..0b0011_1001: high nibble fixed, low nibble <= 9.
fn enforce_ascii_digit(byte: &UInt8<Fr>) -> Result<FpVar<Fr>, SynthesisError> {
    let bits = byte.to_bits_le()?;
    bits[7].enforce_equal(&Boolean::FALSE)?;
    bits[6].enforce_equal(&Boolean::FALSE)?;
    bits[5].enforce_equal(&Boolean::TRUE)?;
    bits[4].enforce_equal(&Boolean::TRUE)?;
    nibble_ge_ten(&bits[..4]).enforce_equal(&Boolean::FALSE)?;
    Ok(nibble_value(&bits[..4]))
}

/// Relations 2 + 3: the text is the canonical rendering of the calldata.
fn enforce_transfer_template(
    calldata: &[UInt8<Fr>],
    text: &[UInt8<Fr>],
) -> Result<(), SynthesisError> {
    let const_byte = |v: u8| FpVar::constant(Fr::from(u64::from(v)));

    // parse(C): selector, then zero padding above the address and the amount.
    for (byte, &v) in calldata[..4].iter().zip(SELECTOR.iter()) {
        byte.to_fp()?.enforce_equal(&const_byte(v))?;
    }
    for byte in calldata[4..TO_POS].iter().chain(&calldata[36..AMOUNT_POS]) {
        byte.to_fp()?.enforce_equal(&FpVar::zero())?;
    }

    // format: fixed template characters.
    for (byte, &v) in text[..INT_POS].iter().zip(PREFIX.iter()) {
        byte.to_fp()?.enforce_equal(&const_byte(v))?;
    }
    text[DOT_POS].to_fp()?.enforce_equal(&const_byte(b'.'))?;
    for (byte, &v) in text[MIDDLE_POS..].iter().zip(MIDDLE.iter()) {
        byte.to_fp()?.enforce_equal(&const_byte(v))?;
    }
    for byte in &text[HEX_END..] {
        byte.to_fp()?.enforce_equal(&const_byte(b' '))?;
    }

    // Amount: the 16 digit chars (int MSB..LSB then frac MSB..LSB) evaluate to
    // the same integer as the 8-byte big-endian amount in the calldata.
    let mut amount_from_text = FpVar::zero();
    for pos in (INT_POS..DOT_POS).chain(FRAC_POS..MIDDLE_POS) {
        let digit = enforce_ascii_digit(&text[pos])?;
        amount_from_text = amount_from_text * Fr::from(10u64) + digit;
    }
    let mut amount_from_calldata = FpVar::zero();
    for byte in &calldata[AMOUNT_POS..] {
        amount_from_calldata = amount_from_calldata * Fr::from(256u64) + byte.to_fp()?;
    }
    amount_from_text.enforce_equal(&amount_from_calldata)?;

    // Address: each of the 20 bytes renders as two lowercase hex chars.
    for (k, byte) in calldata[TO_POS..TO_POS + 20].iter().enumerate() {
        let bits = byte.to_bits_le()?;
        text[HEX_POS + 2 * k]
            .to_fp()?
            .enforce_equal(&nibble_hex_char(&bits[4..8]))?;
        text[HEX_POS + 2 * k + 1]
            .to_fp()?
            .enforce_equal(&nibble_hex_char(&bits[..4]))?;
    }

    Ok(())
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

        // Relations 2 + 3: T is the canonical rendering of C.
        enforce_transfer_template(&calldata_vars, &text_vars)?;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_relations::r1cs::ConstraintSystem;
    use poseidon_preimage_groth16::pack::poseidon_hash_bytes;
    use poseidon_preimage_groth16::params::poseidon_params;

    use crate::template::{build_transfer_calldata, render_transfer_text};

    fn sample_inputs() -> (Vec<u8>, Vec<u8>) {
        // 12.5 USDC to an address exercising all hex chars a-f and 0-9.
        let to: [u8; 20] = [
            0xde, 0xad, 0xbe, 0xef, 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0x11, 0x22,
            0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
        ];
        let calldata = build_transfer_calldata(&to, 12_500_000);
        let text = render_transfer_text(&calldata).unwrap();
        (calldata, text)
    }

    /// Circuit whose h_c/h_t are recomputed over the (possibly tampered)
    /// C and T, so the hash bindings hold and only relations 2/3 can fail.
    fn consistent_circuit(calldata: Vec<u8>, text: Vec<u8>) -> TwoHashCircuit {
        let params = poseidon_params();
        let h_c = poseidon_hash_bytes(&params, &calldata);
        let h_t = poseidon_hash_bytes(&params, &text);
        circuit_with(calldata, text, h_c, h_t)
    }

    fn assert_unsatisfied(circuit: TwoHashCircuit) {
        let cs = ConstraintSystem::<Fr>::new_ref();
        circuit.generate_constraints(cs.clone()).unwrap();
        assert!(!cs.is_satisfied().unwrap());
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

    // --- Relations 2/3 negatives: hashes recomputed over the tampered data,
    // --- so only the parse/format constraints can reject.

    #[test]
    fn lying_amount_digit_unsatisfied() {
        let (calldata, text) = sample_inputs();
        let mut bad = text;
        bad[crate::template::DOT_POS - 1] = b'3'; // "…12." -> "…13."
        assert_unsatisfied(consistent_circuit(calldata, bad));
    }

    #[test]
    fn lying_address_char_unsatisfied() {
        let (calldata, text) = sample_inputs();
        let mut bad = text;
        bad[crate::template::HEX_POS] = b'f'; // "de…" -> "fe…"
        assert_unsatisfied(consistent_circuit(calldata, bad));
    }

    #[test]
    fn non_digit_amount_char_unsatisfied() {
        let (calldata, text) = sample_inputs();
        let mut bad = text;
        // ':' is '9'+1; without the digit range check its nibble value (10)
        // could forge the decimal sum.
        bad[crate::template::MIDDLE_POS - 1] = b':';
        assert_unsatisfied(consistent_circuit(calldata, bad));
    }

    #[test]
    fn wrong_selector_unsatisfied() {
        let (calldata, text) = sample_inputs();
        let mut bad = calldata;
        bad[0] = 0x23; // approve() prefix instead of transfer()
        assert_unsatisfied(consistent_circuit(bad, text));
    }

    #[test]
    fn nonzero_amount_padding_unsatisfied() {
        let (calldata, text) = sample_inputs();
        let mut bad = calldata;
        bad[40] = 0x01; // amount slot high bytes must be zero (< 10^16 units)
        assert_unsatisfied(consistent_circuit(bad, text));
    }

    #[test]
    fn uppercase_hex_unsatisfied() {
        let (calldata, text) = sample_inputs();
        let mut bad = text;
        assert_eq!(bad[crate::template::HEX_POS + 1], b'e');
        bad[crate::template::HEX_POS + 1] = b'E'; // canonical rendering is lowercase
        assert_unsatisfied(consistent_circuit(calldata, bad));
    }
}
