// End-to-end demo of the two-hash clear-signing skeleton circuit:
// setup -> prove -> verify, plus circuit stats and the public-input digests
// (BE hex, comparable with the C verifier's poseidon_hash_bytes output).

use ark_ff::{BigInteger, PrimeField};
use clear_signing_groth16::circuit::{CALLDATA_BYTES, TEXT_BYTES};
use clear_signing_groth16::snark::{print_circuit_stats, prove, setup, verify};
use poseidon_preimage_groth16::params::poseidon_params;

fn fr_hex(elem: &ark_bn254::Fr) -> String {
    let le = elem.into_bigint().to_bytes_le();
    let mut be = [0u8; 32];
    for (i, &b) in le.iter().enumerate() {
        be[31 - i] = b;
    }
    be.iter().map(|b| format!("{b:02x}")).collect()
}

fn main() {
    let params = poseidon_params();
    print_circuit_stats(&params);

    // ERC-20 transfer(0x1111...1111, 12.5 USDC).
    let mut calldata = vec![0u8; CALLDATA_BYTES];
    calldata[..4].copy_from_slice(&[0xa9, 0x05, 0x9c, 0xbb]);
    calldata[16..36].fill(0x11);
    calldata[64..].copy_from_slice(&12_500_000u32.to_be_bytes());

    let mut text =
        b"Send 12.500000 USDC to 0x1111111111111111111111111111111111111111".to_vec();
    text.resize(TEXT_BYTES, b' ');

    println!("\nSetup (circuit-specific CRS)...");
    let artifacts = setup(&params).expect("setup");

    println!("Prove...");
    let start = std::time::Instant::now();
    let (proof, public_inputs) = prove(&artifacts.pk, &params, &calldata, &text).expect("prove");
    println!("  proving time: {:?}", start.elapsed());
    println!("  h_c = {}", fr_hex(&public_inputs[0]));
    println!("  h_t = {}", fr_hex(&public_inputs[1]));

    println!("Verify...");
    let ok = verify(&artifacts.pvk, &public_inputs, &proof);
    println!("  verification: {}", if ok { "PASS" } else { "FAIL" });
    std::process::exit(if ok { 0 } else { 1 });
}
