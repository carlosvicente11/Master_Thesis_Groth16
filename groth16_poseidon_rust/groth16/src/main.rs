use std::fs;
use std::path::PathBuf;
use std::time::Instant;

use ark_bn254::Fr;
use ark_groth16::{prepare_verifying_key, Proof, ProvingKey, VerifyingKey};
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
    },
}

fn artifact_path(dir: &PathBuf, iterations: usize, suffix: &str) -> PathBuf {
    dir.join(format!("poseidon_preimage_{iterations}_{suffix}"))
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

        Commands::Verify { iterations } => {
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
            let valid = snark::verify(&pvk, &public_inputs, &proof);
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
