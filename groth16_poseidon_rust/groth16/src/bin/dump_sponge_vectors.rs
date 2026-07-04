// Dumps Poseidon byte-string sponge test vectors (the two-hash clear-signing
// packing convention) so the C mirror in minimal_c_verifier can cross-validate.
// Digests are printed as canonical (non-Montgomery) 32-byte big-endian hex.

use ark_bn254::Fr;
use ark_ff::{BigInteger, PrimeField};

use poseidon_preimage_groth16::pack::poseidon_hash_bytes;
use poseidon_preimage_groth16::params::poseidon_params;

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

/// ERC-20 transfer(address,uint256): selector a9059cbb + to + amount (68 B).
fn erc20_transfer_calldata() -> Vec<u8> {
    let mut c = vec![0xa9, 0x05, 0x9c, 0xbb];
    // to = 0x1111...1111 (20 bytes), left-padded to 32.
    c.extend_from_slice(&[0u8; 12]);
    c.extend_from_slice(&[0x11u8; 20]);
    // amount = 12_500_000 (12.5 USDC, 6 decimals), 32-byte BE.
    let mut amount = [0u8; 32];
    amount[28..].copy_from_slice(&12_500_000u32.to_be_bytes());
    c.extend_from_slice(&amount);
    c
}

fn main() {
    let params = poseidon_params();

    let calldata = erc20_transfer_calldata();
    let text = b"Send 12.500000 USDC to 0x1111111111111111111111111111111111111111";

    let vectors: Vec<(&str, Vec<u8>)> = vec![
        ("empty (len 0)", vec![]),
        ("single byte 0xab (len 1)", vec![0xab]),
        ("0x01..0x1f (len 31, one chunk)", (1..=31u8).collect()),
        ("0x01..0x20 (len 32, two chunks)", (1..=32u8).collect()),
        ("0x01..0x3e (len 62, two chunks)", (1..=62u8).collect()),
        ("0x01..0x3f (len 63, three chunks)", (1..=63u8).collect()),
        ("ERC-20 transfer calldata (len 68)", calldata),
        ("sample text (len 65)", text.to_vec()),
    ];

    println!("=== Poseidon byte-sponge vectors (pack = [len] ++ 31-B BE chunks) ===\n");
    for (label, data) in &vectors {
        let h = poseidon_hash_bytes(&params, data);
        println!("input: {label}");
        println!("bytes: {}", hex(data));
        println!("hash : {}\n", hex(&fr_to_be(&h)));
    }
    println!("=== END ===");
}
