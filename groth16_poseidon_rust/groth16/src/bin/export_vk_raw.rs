// Converts the frozen ark-serialize verifying key
// (artifacts/poseidon_preimage_1_vk.bin) into the raw byte layout the C
// verifier consumes. Read-only: no setup, no proving — the frozen artifact
// set is never touched.
//
//   vk_raw.bin = IC[0..1] (2 x 64 B G1) || e(alpha,beta) (384 B GT)
//                || -gamma (128 B G2) || -delta (128 B G2)   = 768 B
//
// Encodings: G1 = BE x||y, G2 = x.c0||x.c1||y.c0||y.c1,
// GT = 12 BE Fq coefficients in tower order.

use std::fs;
use std::ops::Neg;
use std::path::Path;

use ark_bn254::{Bn254, Fq, Fq12, G1Affine, G2Affine};
use ark_ec::{AffineRepr, CurveGroup};
use ark_ff::{BigInteger, PrimeField};
use ark_groth16::{prepare_verifying_key, VerifyingKey};

use poseidon_preimage_groth16::serialize::from_bytes_compressed;

fn fq_be(e: &Fq) -> [u8; 32] {
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

fn gt_raw(f: &Fq12) -> Vec<u8> {
    [
        &f.c0.c0.c0, &f.c0.c0.c1, &f.c0.c1.c0, &f.c0.c1.c1, &f.c0.c2.c0, &f.c0.c2.c1,
        &f.c1.c0.c0, &f.c1.c0.c1, &f.c1.c1.c0, &f.c1.c1.c1, &f.c1.c2.c0, &f.c1.c2.c1,
    ]
    .iter()
    .flat_map(|c| fq_be(c))
    .collect()
}

fn main() {
    let dir = std::env::args().nth(1).unwrap_or_else(|| "artifacts".into());
    let dir = Path::new(&dir);
    let vk_path = dir.join("poseidon_preimage_1_vk.bin");

    let bytes = fs::read(&vk_path)
        .unwrap_or_else(|e| panic!("read {}: {e}", vk_path.display()));
    let vk: VerifyingKey<Bn254> = from_bytes_compressed(&bytes);
    assert_eq!(vk.gamma_abc_g1.len(), 2, "expect 1 public input");

    let pvk = prepare_verifying_key(&vk);
    let neg_gamma = vk.gamma_g2.into_group().neg().into_affine();
    let neg_delta = vk.delta_g2.into_group().neg().into_affine();

    let mut raw: Vec<u8> = vk.gamma_abc_g1.iter().flat_map(|p| g1_raw(p)).collect();
    raw.extend(gt_raw(&pvk.alpha_g1_beta_g2));
    raw.extend(g2_raw(&neg_gamma));
    raw.extend(g2_raw(&neg_delta));
    assert_eq!(raw.len(), 768);

    let out = dir.join("vk_raw.bin");
    fs::write(&out, &raw).expect("write vk_raw.bin");
    println!("{}: {} bytes", out.display(), raw.len());
}
