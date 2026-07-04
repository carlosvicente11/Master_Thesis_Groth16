//! Byte-string packing + Poseidon sponge hashing convention for the two-hash
//! clear-signing statement (h_c = H(calldata), h_t = H(text)).
//!
//! Convention (must match `minimal_c_verifier`'s C `poseidon_hash_bytes` and
//! the future circuit gadget EXACTLY):
//! - pack(bytes) = [Fr(byte_len)] ++ one Fr per 31-byte chunk, each chunk read
//!   as a big-endian integer (`Fr::from_be_bytes_mod_order`; a chunk of 31
//!   bytes never exceeds the modulus, so no reduction actually occurs).
//! - The length prefix domain-separates inputs whose padded chunks collide
//!   (e.g. "\x00" vs "").
//! - hash = arkworks `PoseidonSponge` (width 3, rate 2, capacity 1) absorbing
//!   the packed vector, squeezing 1 native field element.

use ark_bn254::Fr;
use ark_crypto_primitives::sponge::poseidon::{PoseidonConfig, PoseidonSponge};
use ark_crypto_primitives::sponge::{CryptographicSponge, FieldBasedCryptographicSponge};
use ark_ff::PrimeField;

/// Bytes per field element: 31 bytes always fit below the ~254-bit BN254 r.
pub const PACK_CHUNK_BYTES: usize = 31;

/// pack(bytes) = [Fr(len)] ++ big-endian 31-byte chunks.
pub fn pack_bytes_to_fr_elements(data: &[u8]) -> Vec<Fr> {
    let mut out = Vec::with_capacity(1 + data.len().div_ceil(PACK_CHUNK_BYTES));
    out.push(Fr::from(data.len() as u64));
    for chunk in data.chunks(PACK_CHUNK_BYTES) {
        out.push(Fr::from_be_bytes_mod_order(chunk));
    }
    out
}

/// Poseidon sponge hash of a byte string under the packing convention above.
pub fn poseidon_hash_bytes(params: &PoseidonConfig<Fr>, data: &[u8]) -> Fr {
    let packed = pack_bytes_to_fr_elements(data);
    let mut sponge = PoseidonSponge::new(params);
    sponge.absorb(&packed);
    sponge.squeeze_native_field_elements(1)[0]
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::params::poseidon_params;

    #[test]
    fn packing_layout() {
        assert_eq!(pack_bytes_to_fr_elements(&[]), vec![Fr::from(0u64)]);

        let one = pack_bytes_to_fr_elements(&[0xab]);
        assert_eq!(one, vec![Fr::from(1u64), Fr::from(0xabu64)]);

        // 31 bytes -> exactly one chunk; 32 bytes -> two chunks.
        assert_eq!(pack_bytes_to_fr_elements(&[0u8; 31]).len(), 2);
        assert_eq!(pack_bytes_to_fr_elements(&[0u8; 32]).len(), 3);
        assert_eq!(pack_bytes_to_fr_elements(&[0u8; 62]).len(), 3);
        assert_eq!(pack_bytes_to_fr_elements(&[0u8; 63]).len(), 4);
    }

    #[test]
    fn hash_is_deterministic() {
        let params = poseidon_params();
        let data = b"Send 12.5 USDC to 0x1234";
        assert_eq!(
            poseidon_hash_bytes(&params, data),
            poseidon_hash_bytes(&params, data)
        );
    }

    #[test]
    fn length_prefix_separates_zero_padded_inputs() {
        let params = poseidon_params();
        // Same chunk value (0), different lengths.
        assert_ne!(
            poseidon_hash_bytes(&params, b""),
            poseidon_hash_bytes(&params, b"\x00")
        );
        assert_ne!(
            poseidon_hash_bytes(&params, b"\x00"),
            poseidon_hash_bytes(&params, b"\x00\x00")
        );
    }

    #[test]
    fn different_data_different_hashes() {
        let params = poseidon_params();
        assert_ne!(
            poseidon_hash_bytes(&params, b"hello"),
            poseidon_hash_bytes(&params, b"hellp")
        );
    }
}
