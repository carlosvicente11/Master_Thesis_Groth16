use std::fs;
use std::path::PathBuf;
use std::time::Instant;

use ark_bn254::Fr;
use ark_ec::{pairing::Pairing, CurveGroup};
use ark_ff::opcount::{self, Snapshot};
use ark_groth16::{prepare_verifying_key, Groth16, PreparedVerifyingKey, Proof, ProvingKey, VerifyingKey};
use clap::{Parser, Subcommand};

use poseidon_preimage_groth16::params::{poseidon_hash_chain, poseidon_params};
use poseidon_preimage_groth16::serialize::{from_bytes_compressed, to_bytes_compressed};
use poseidon_preimage_groth16::snark::{self, E};

#[derive(Parser)]
#[command(name = "poseidon-preimage-groth16")]
#[command(about = "Groth16 proof of knowledge of a Poseidon hash preimage")]
struct Cli {
    #[command(subcommand)]
    command: Commands,

    #[arg(long, default_value = "artifacts")]
    artifacts_dir: PathBuf,
}

#[derive(Subcommand)]
enum Commands {
    /// Run trusted setup (generate proving and verifying keys)
    Setup {
        #[arg(long, default_value = "1")]
        iterations: usize,
    },
    /// Generate a Groth16 proof for a given preimage
    Prove {
        #[arg(long, default_value = "1")]
        iterations: usize,
        #[arg(long, default_value_t = common::DEFAULT_PREIMAGE)]
        preimage: u64,
    },
    /// Verify a previously generated proof
    Verify {
        #[arg(long, default_value = "1")]
        iterations: usize,
        /// Report Fq/Fr field-operation counts for the runtime verify path
        #[arg(long, default_value_t = false)]
        count_ops: bool,
    },
}

fn artifact_path(dir: &PathBuf, iterations: usize, suffix: &str) -> PathBuf {
    dir.join(format!("poseidon_preimage_{iterations}_{suffix}"))
}

/// Run the runtime verify path phase-by-phase with the field-op counters on,
/// printing the Fq/Fr `mul`/`square`/`inverse` distribution per phase. This
/// replicates `Groth16::verify_proof` (prepare_inputs -> multi_miller_loop ->
/// final_exponentiation -> Gt compare) so each phase can be measured
/// separately. `prepare_verifying_key` is excluded on purpose: on-chip,
/// `e(alpha,beta)`/`-gamma`/`-delta` are baked into ROM.
fn verify_with_op_counts(
    pvk: &PreparedVerifyingKey<E>,
    public_inputs: &[Fr],
    proof: &Proof<E>,
) -> bool {
    fn phase<T>(label: &str, f: impl FnOnce() -> T) -> T {
        opcount::reset();
        opcount::set_enabled(true);
        let out = f();
        opcount::set_enabled(false);
        print_phase(label, &opcount::snapshot());
        out
    }

    println!("=== Field-operation counts per verify phase (Fq base field) ===");
    println!("phase                fq_mul (direct+sop)        fq_sqr   fq_inv");

    // Phase 1: prepare_inputs (public-input MSM: 1 scalar mul + 1 add here).
    let prepared = phase("prepare_inputs", || {
        Groth16::<E>::prepare_inputs(pvk, public_inputs).expect("prepare_inputs")
    });

    // Phase 2: affine conversion (one Fp inversion) + 3-pair multi-Miller loop.
    let qap = phase("affine+miller_loop", || {
        E::multi_miller_loop(
            [
                <<E as Pairing>::G1Affine as Into<<E as Pairing>::G1Prepared>>::into(proof.a),
                prepared.into_affine().into(),
                proof.c.into(),
            ],
            [
                proof.b.into(),
                pvk.gamma_g2_neg_pc.clone(),
                pvk.delta_g2_neg_pc.clone(),
            ],
        )
    });

    // Phase 3: final exponentiation (easy + hard part).
    let test = phase("final_exponentiation", || {
        E::final_exponentiation(qap).expect("final_exponentiation")
    });

    println!("==============================================================");
    println!("(Fr scalar-field ops are 0 across all phases for this circuit.)");

    test.0 == pvk.alpha_g1_beta_g2
}

fn print_phase(label: &str, s: &Snapshot) {
    let fq_mul = s.fq_mul + s.fq_sop;
    println!(
        "{label:<20} {fq_mul:>7} ({:>5}+{:>6})   {:>7}  {:>5}",
        s.fq_mul, s.fq_sop, s.fq_square, s.fq_inverse
    );
}

fn main() {
    let cli = Cli::parse();
    let params = poseidon_params();

    fs::create_dir_all(&cli.artifacts_dir).expect("create artifacts dir");

    match cli.command {
        Commands::Setup { iterations } => {
            snark::print_circuit_stats(&params, iterations);

            let t = Instant::now();
            let artifacts = snark::setup(&params, iterations).expect("setup failed");
            println!("Setup time: {} ms", t.elapsed().as_millis());

            let pk_path = artifact_path(&cli.artifacts_dir, iterations, "pk.bin");
            let vk_path = artifact_path(&cli.artifacts_dir, iterations, "vk.bin");

            let pk_bytes = to_bytes_compressed(&artifacts.pk);
            fs::write(&pk_path, &pk_bytes).expect("write pk");
            println!(
                "Proving key:   {} bytes -> {}",
                pk_bytes.len(),
                pk_path.display()
            );

            let vk_bytes = to_bytes_compressed(&artifacts.vk);
            fs::write(&vk_path, &vk_bytes).expect("write vk");
            println!(
                "Verifying key: {} bytes -> {}",
                vk_bytes.len(),
                vk_path.display()
            );
        }

        Commands::Prove {
            iterations,
            preimage,
        } => {
            let preimage_val = Fr::from(preimage);
            let hash = poseidon_hash_chain(&params, preimage_val, iterations);
            println!("Iterations: {iterations}");
            println!("Preimage:   {preimage}");
            println!("Hash:       {hash}");

            let pk_path = artifact_path(&cli.artifacts_dir, iterations, "pk.bin");
            let pk_bytes = fs::read(&pk_path).unwrap_or_else(|_| {
                panic!("read pk (run setup --iterations {iterations} first)")
            });
            let pk: ProvingKey<E> = from_bytes_compressed(&pk_bytes);

            let t = Instant::now();
            let (proof, public_inputs) =
                snark::prove(&pk, &params, preimage_val, iterations).expect("prove failed");
            println!("Prove time: {} ms", t.elapsed().as_millis());

            let proof_path = artifact_path(&cli.artifacts_dir, iterations, "proof.bin");
            let pi_path = artifact_path(&cli.artifacts_dir, iterations, "public_inputs.bin");

            let proof_bytes = to_bytes_compressed(&proof);
            fs::write(&proof_path, &proof_bytes).expect("write proof");
            println!(
                "Proof: {} bytes -> {}",
                proof_bytes.len(),
                proof_path.display()
            );

            let pi_bytes = to_bytes_compressed(&public_inputs);
            fs::write(&pi_path, &pi_bytes).expect("write public inputs");
        }

        Commands::Verify {
            iterations,
            count_ops,
        } => {
            let vk_path = artifact_path(&cli.artifacts_dir, iterations, "vk.bin");
            let proof_path = artifact_path(&cli.artifacts_dir, iterations, "proof.bin");
            let pi_path = artifact_path(&cli.artifacts_dir, iterations, "public_inputs.bin");

            let vk: VerifyingKey<E> =
                from_bytes_compressed(&fs::read(&vk_path).expect("read vk"));
            let pvk = prepare_verifying_key(&vk);
            let proof: Proof<E> =
                from_bytes_compressed(&fs::read(&proof_path).expect("read proof"));
            let public_inputs: Vec<Fr> =
                from_bytes_compressed(&fs::read(&pi_path).expect("read public inputs"));

            let t = Instant::now();
            let valid = if count_ops {
                verify_with_op_counts(&pvk, &public_inputs, &proof)
            } else {
                snark::verify(&pvk, &public_inputs, &proof)
            };
            let verify_us = t.elapsed().as_micros();

            println!("Verify time: {verify_us} us ({:.3} ms)", verify_us as f64 / 1000.0);
            println!(
                "Verification: {}",
                if valid { "VALID" } else { "INVALID" }
            );

            if !valid {
                std::process::exit(1);
            }
        }
    }
}
