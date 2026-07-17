// Converts the frozen ark-serialize proof and public inputs
// (artifacts/poseidon_preimage_1_{proof,public_inputs}.bin) into the raw
// byte layout the C verifier consumes. Read-only: no setup, no proving —
// the frozen artifact set is never touched.
//
//   proof_raw.bin        = A (G1, 64 B) || B (G2, 128 B) || C (G1, 64 B) = 256 B
//   public_input_raw.bin = h = Poseidon(x), one Fr, 32 B BE
//
// Encodings: G1 = BE x||y, G2 = x.c0||x.c1||y.c0||y.c1.

use std::fs;
use std::path::Path;

use ark_bn254::{Bn254, Fq, Fr, G1Affine, G2Affine};
use ark_ff::{BigInteger, PrimeField};
use ark_groth16::Proof;

use poseidon_preimage_groth16::serialize::from_bytes_compressed;

fn fq_be(e: &Fq) -> [u8; 32] {
    let le = e.into_bigint().to_bytes_le();
    let mut be = [0u8; 32];
    for (i, &b) in le.iter().enumerate() {
        be[31 - i] = b;
    }
    be
}

fn fr_be(e: &Fr) -> [u8; 32] {
    let le = e.into_bigint().to_bytes_le();
    let mut be = [0u8; 32];
    for (i, &b) in le.iter().enumerate() {
        be[31 - i] = b;
    }
    be
}

fn g1_raw(p: &G1Affine) -> Vec<u8> {
    [fq_be(&p.x).as_slice(), &fq_be(&p.y)].concat()
}

fn g2_raw(p: &G2Affine) -> Vec<u8> {
    [
        fq_be(&p.x.c0).as_slice(),
        &fq_be(&p.x.c1),
        &fq_be(&p.y.c0),
        &fq_be(&p.y.c1),
    ]
    .concat()
}

fn main() {
    let dir = std::env::args().nth(1).unwrap_or_else(|| "artifacts".into());
    let dir = Path::new(&dir);

    let proof_path = dir.join("poseidon_preimage_1_proof.bin");
    let pi_path = dir.join("poseidon_preimage_1_public_inputs.bin");

    let proof: Proof<Bn254> = from_bytes_compressed(
        &fs::read(&proof_path)
            .unwrap_or_else(|e| panic!("read {}: {e}", proof_path.display())),
    );
    let public_inputs: Vec<Fr> = from_bytes_compressed(
        &fs::read(&pi_path)
            .unwrap_or_else(|e| panic!("read {}: {e}", pi_path.display())),
    );
    assert_eq!(public_inputs.len(), 1, "expect 1 public input");

    let mut raw = g1_raw(&proof.a);
    raw.extend(g2_raw(&proof.b));
    raw.extend(g1_raw(&proof.c));
    assert_eq!(raw.len(), 256);

    let proof_out = dir.join("proof_raw.bin");
    fs::write(&proof_out, &raw).expect("write proof_raw.bin");
    println!("{}: {} bytes", proof_out.display(), raw.len());

    let pi_out = dir.join("public_input_raw.bin");
    fs::write(&pi_out, fr_be(&public_inputs[0])).expect("write public_input_raw.bin");
    println!("{}: 32 bytes", pi_out.display());
}
