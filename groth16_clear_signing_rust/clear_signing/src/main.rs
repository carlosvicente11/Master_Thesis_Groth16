// End-to-end demo of the two-hash clear-signing skeleton circuit:
// setup -> prove -> verify, plus circuit stats and the public-input digests
// (BE hex, comparable with the C verifier's poseidon_hash_bytes output).

use ark_ff::{BigInteger, PrimeField};
use clear_signing_groth16::snark::{print_circuit_stats, prove, setup, verify};
use clear_signing_groth16::template::{build_transfer_calldata, render_transfer_text};
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
    let calldata = build_transfer_calldata(&[0x11; 20], 12_500_000);
    let text = render_transfer_text(&calldata).expect("render");
    println!("\ntext: \"{}\"", String::from_utf8_lossy(&text));

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
