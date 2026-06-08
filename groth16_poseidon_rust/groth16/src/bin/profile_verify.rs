use std::fs;
use std::path::PathBuf;
use std::time::Instant;

use ark_bn254::{Bn254, Fr};
use ark_ec::{pairing::Pairing, AffineRepr, CurveGroup};
use ark_ff::PrimeField;
use ark_groth16::{prepare_verifying_key, Groth16, PreparedVerifyingKey, Proof, VerifyingKey};
use core::ops::AddAssign;

use poseidon_preimage_groth16::serialize::from_bytes_compressed;

type E = Bn254;

const NUM_ITERS: usize = 1000;

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

    // Warmup
    let pvk = prepare_verifying_key(&vk);
    let valid = Groth16::<E>::verify_proof(&pvk, &proof, &public_inputs).unwrap();
    assert!(valid, "proof must verify");

    println!("=== Groth16 BN254 Verification Profile (native, {} iterations) ===", NUM_ITERS);
    println!("Protocol: Basic Preimage (1 public input)\n");

    // --- Phase 1: prepare_verifying_key (one-time precomputation) ---
    let t = Instant::now();
    for _ in 0..NUM_ITERS {
        let _ = prepare_verifying_key(&vk);
    }
    let pvk_us = t.elapsed().as_nanos() / NUM_ITERS as u128;
    let pvk = prepare_verifying_key(&vk);

    // --- Phase 2: prepare_inputs (scalar muls on G1) ---
    let t = Instant::now();
    for _ in 0..NUM_ITERS {
        let _ = prepare_inputs_manual(&pvk, &public_inputs);
    }
    let prepare_us = t.elapsed().as_nanos() / NUM_ITERS as u128;

    // --- Phase 3: multi_miller_loop ---
    let prepared_inputs = prepare_inputs_manual(&pvk, &public_inputs);
    let t = Instant::now();
    for _ in 0..NUM_ITERS {
        let _ = E::multi_miller_loop(
            [
                <_ as Into<<E as Pairing>::G1Prepared>>::into(proof.a),
                prepared_inputs.into_affine().into(),
                proof.c.into(),
            ],
            [
                proof.b.into(),
                pvk.gamma_g2_neg_pc.clone(),
                pvk.delta_g2_neg_pc.clone(),
            ],
        );
    }
    let miller_us = t.elapsed().as_nanos() / NUM_ITERS as u128;

    // --- Phase 4: final_exponentiation ---
    let qap = E::multi_miller_loop(
        [
            <_ as Into<<E as Pairing>::G1Prepared>>::into(proof.a),
            prepared_inputs.into_affine().into(),
            proof.c.into(),
        ],
        [
            proof.b.into(),
            pvk.gamma_g2_neg_pc.clone(),
            pvk.delta_g2_neg_pc.clone(),
        ],
    );
    let t = Instant::now();
    for _ in 0..NUM_ITERS {
        let _ = E::final_exponentiation(qap.clone());
    }
    let final_exp_us = t.elapsed().as_nanos() / NUM_ITERS as u128;

    // --- Phase 5: GT comparison ---
    let test = E::final_exponentiation(qap).unwrap();
    let t = Instant::now();
    for _ in 0..NUM_ITERS {
        let _ = std::hint::black_box(test.0 == pvk.alpha_g1_beta_g2);
    }
    let compare_us = t.elapsed().as_nanos() / NUM_ITERS as u128;

    // --- Full verify_proof (end-to-end) ---
    let t = Instant::now();
    for _ in 0..NUM_ITERS {
        let _ = Groth16::<E>::verify_proof(&pvk, &proof, &public_inputs);
    }
    let total_us = t.elapsed().as_nanos() / NUM_ITERS as u128;

    let pairing_us = miller_us + final_exp_us;
    let verify_core = prepare_us + pairing_us + compare_us;

    println!("=== Average time per verification (over {} iterations) ===", NUM_ITERS);
    println!("  prepare_verifying_key:   {:>8} ns  ({:.3} us)", pvk_us, pvk_us as f64 / 1000.0);
    println!("  prepare_inputs (1 mul):  {:>8} ns  ({:.3} us)", prepare_us, prepare_us as f64 / 1000.0);
    println!("  multi_miller_loop:       {:>8} ns  ({:.3} us)", miller_us, miller_us as f64 / 1000.0);
    println!("  final_exponentiation:    {:>8} ns  ({:.3} us)", final_exp_us, final_exp_us as f64 / 1000.0);
    println!("  GT comparison:           {:>8} ns  ({:.3} us)", compare_us, compare_us as f64 / 1000.0);
    println!("  ---");
    println!("  Pairing total:           {:>8} ns  ({:.3} us)", pairing_us, pairing_us as f64 / 1000.0);
    println!("  Sum of phases:           {:>8} ns  ({:.3} us)", verify_core, verify_core as f64 / 1000.0);
    println!("  verify_proof (measured):  {:>8} ns  ({:.3} us)", total_us, total_us as f64 / 1000.0);

    println!("\n=== Percentage breakdown ===");
    println!("  prepare_inputs:       {:>5.1}%", prepare_us as f64 / total_us as f64 * 100.0);
    println!("  multi_miller_loop:    {:>5.1}%", miller_us as f64 / total_us as f64 * 100.0);
    println!("  final_exponentiation: {:>5.1}%", final_exp_us as f64 / total_us as f64 * 100.0);
    println!("  Pairing total:        {:>5.1}%", pairing_us as f64 / total_us as f64 * 100.0);
    println!("  GT comparison:        {:>5.1}%", compare_us as f64 / total_us as f64 * 100.0);
}

fn prepare_inputs_manual(
    pvk: &PreparedVerifyingKey<E>,
    public_inputs: &[Fr],
) -> <E as Pairing>::G1 {
    let mut g_ic = pvk.vk.gamma_abc_g1[0].into_group();
    for (i, b) in public_inputs.iter().zip(pvk.vk.gamma_abc_g1.iter().skip(1)) {
        g_ic.add_assign(&b.mul_bigint(i.into_bigint()));
    }
    g_ic
}
