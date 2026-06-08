use std::fs;
use std::path::PathBuf;

use ark_bn254::{Bn254, Fq, Fq12, Fr, G1Affine, G2Affine};
use ark_ec::{pairing::Pairing, AffineRepr, CurveGroup};
use ark_ff::{BigInteger, PrimeField};
use ark_groth16::{prepare_verifying_key, Groth16, Proof, VerifyingKey};
use core::ops::AddAssign;
use std::ops::Neg;

use poseidon_preimage_groth16::serialize::from_bytes_compressed;

type E = Bn254;

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn fq_to_be(elem: &Fq) -> [u8; 32] {
    let bigint = elem.into_bigint();
    let mut out = [0u8; 32];
    let le_bytes = bigint.to_bytes_le();
    for (i, &b) in le_bytes.iter().enumerate() {
        out[31 - i] = b;
    }
    out
}

fn g1_to_hex(p: &G1Affine) -> (String, String) {
    (hex(&fq_to_be(&p.x)), hex(&fq_to_be(&p.y)))
}

fn g2_to_hex(p: &G2Affine) -> (String, String, String, String) {
    (
        hex(&fq_to_be(&p.x.c0)),
        hex(&fq_to_be(&p.x.c1)),
        hex(&fq_to_be(&p.y.c0)),
        hex(&fq_to_be(&p.y.c1)),
    )
}

fn fp12_to_hex(f: &Fq12) -> Vec<(String, String)> {
    let coeffs = [
        ("c0.c0.c0", &f.c0.c0.c0),
        ("c0.c0.c1", &f.c0.c0.c1),
        ("c0.c1.c0", &f.c0.c1.c0),
        ("c0.c1.c1", &f.c0.c1.c1),
        ("c0.c2.c0", &f.c0.c2.c0),
        ("c0.c2.c1", &f.c0.c2.c1),
        ("c1.c0.c0", &f.c1.c0.c0),
        ("c1.c0.c1", &f.c1.c0.c1),
        ("c1.c1.c0", &f.c1.c1.c0),
        ("c1.c1.c1", &f.c1.c1.c1),
        ("c1.c2.c0", &f.c1.c2.c0),
        ("c1.c2.c1", &f.c1.c2.c1),
    ];
    coeffs
        .iter()
        .map(|(name, val)| (name.to_string(), hex(&fq_to_be(val))))
        .collect()
}

fn main() {
    let artifacts_dir = PathBuf::from("artifacts");

    let vk: VerifyingKey<E> = from_bytes_compressed(
        &fs::read(artifacts_dir.join("poseidon_preimage_1_vk.bin")).expect("read vk"),
    );
    let proof: Proof<E> = from_bytes_compressed(
        &fs::read(artifacts_dir.join("poseidon_preimage_1_proof.bin")).expect("read proof"),
    );
    let public_inputs: Vec<Fr> = from_bytes_compressed(
        &fs::read(artifacts_dir.join("poseidon_preimage_1_public_inputs.bin"))
            .expect("read public inputs"),
    );

    println!("=== Rust Cross-Validation Dump (Basic Preimage) ===\n");

    // Phase 1: Proof points
    let a = proof.a;
    let b = proof.b;
    let c = proof.c;

    println!("--- Phase 1: Decoded Proof ---");
    let (ax, ay) = g1_to_hex(&a);
    println!("A.x = {ax}");
    println!("A.y = {ay}");
    let (bx0, bx1, by0, by1) = g2_to_hex(&b);
    println!("B.x.c0 = {bx0}");
    println!("B.x.c1 = {bx1}");
    println!("B.y.c0 = {by0}");
    println!("B.y.c1 = {by1}");
    let (cx, cy) = g1_to_hex(&c);
    println!("C.x = {cx}");
    println!("C.y = {cy}");

    // Phase 2: VK points
    println!("\n--- Phase 2: VK Points ---");
    let pvk = prepare_verifying_key(&vk);

    let ic0 = vk.gamma_abc_g1[0];
    let ic1 = vk.gamma_abc_g1[1];
    let (ic0x, ic0y) = g1_to_hex(&ic0);
    println!("IC[0].x = {ic0x}");
    println!("IC[0].y = {ic0y}");
    let (ic1x, ic1y) = g1_to_hex(&ic1);
    println!("IC[1].x = {ic1x}");
    println!("IC[1].y = {ic1y}");

    let neg_gamma = vk.gamma_g2.into_group().neg().into_affine();
    let neg_delta = vk.delta_g2.into_group().neg().into_affine();
    let (ngx0, ngx1, ngy0, ngy1) = g2_to_hex(&neg_gamma);
    println!("neg_gamma.x.c0 = {ngx0}");
    println!("neg_gamma.x.c1 = {ngx1}");
    println!("neg_gamma.y.c0 = {ngy0}");
    println!("neg_gamma.y.c1 = {ngy1}");
    let (ndx0, ndx1, ndy0, ndy1) = g2_to_hex(&neg_delta);
    println!("neg_delta.x.c0 = {ndx0}");
    println!("neg_delta.x.c1 = {ndx1}");
    println!("neg_delta.y.c0 = {ndy0}");
    println!("neg_delta.y.c1 = {ndy1}");

    // Precomputed e(alpha, beta)
    let alpha_beta = pvk.alpha_g1_beta_g2;
    println!("\ne(alpha, beta) [precomputed]:");
    for (name, val) in fp12_to_hex(&alpha_beta) {
        println!("  {name} = {val}");
    }

    // Phase 3: prepare_inputs
    println!("\n--- Phase 3: prepare_inputs ---");
    let scalar = &public_inputs[0];
    let scalar_be = {
        let bigint = scalar.into_bigint();
        let le = bigint.to_bytes_le();
        let mut be = [0u8; 32];
        for (i, &b) in le.iter().enumerate() {
            be[31 - i] = b;
        }
        be
    };
    println!("public_input[0] = {}", hex(&scalar_be));

    let mut g_ic = ic0.into_group();
    g_ic.add_assign(&ic1.mul_bigint(scalar.into_bigint()));
    let l = g_ic.into_affine();
    let (lx, ly) = g1_to_hex(&l);
    println!("L.x = {lx}");
    println!("L.y = {ly}");

    // Phase 4: Multi-pairing (using prepared inputs like C does)
    println!("\n--- Phase 4: Multi-pairing ---");
    let qap = E::multi_miller_loop(
        [
            <_ as Into<<E as Pairing>::G1Prepared>>::into(a),
            l.into(),
            c.into(),
        ],
        [
            proof.b.into(),
            pvk.gamma_g2_neg_pc.clone(),
            pvk.delta_g2_neg_pc.clone(),
        ],
    );
    let pairing_result = E::final_exponentiation(qap).unwrap();

    println!("pairing result (after final exp):");
    for (name, val) in fp12_to_hex(&pairing_result.0) {
        println!("  {name} = {val}");
    }

    // Phase 5: Compare
    println!("\n--- Phase 5: Compare ---");
    let matches = pairing_result.0 == alpha_beta;
    println!("pairing_result == e(alpha,beta): {matches}");

    // Also verify with library
    let valid = Groth16::<E>::verify_proof(&pvk, &proof, &public_inputs).unwrap();
    println!("Groth16::verify_proof: {valid}");

    println!("\n=== END ===");
}
