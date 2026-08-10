//! Command-line entry point for local Nitro attestation Groth16 proving.

use std::{env, fs, path::PathBuf, time::Instant};

use alloy_primitives::hex;
use base_proof_tee_nitro_attestation_prover::{AttestationProofProvider, DirectProver, Result};
use base_proof_tee_nitro_verifier::{VerificationResult, VerifierJournal};
use tokio_util::sync::CancellationToken;

const DEFAULT_TRUSTED_PREFIX: u8 = 1;
const GUEST_PROGRAM_ENV: &str = "NITRO_GUEST_PROGRAM";
const LEGACY_GUEST_ELF_ENV: &str = "NITRO_GUEST_ELF";
const ATTESTATION_ENV: &str = "NITRO_ATTESTATION";
const TEST_ATTESTATION_HEX: &str = include_str!("../verifier/testdata/attestation.hex");

#[tokio::main]
async fn main() -> Result<()> {
    let _ = tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .with_target(true)
        .try_init();

    assert_ne!(
        env::var("RISC0_DEV_MODE").as_deref(),
        Ok("1"),
        "RISC0_DEV_MODE=1 produces a fake receipt and cannot measure Groth16 performance"
    );

    let program_path = guest_program_path();
    let program = fs::read(&program_path)
        .unwrap_or_else(|error| panic!("failed to read {}: {error}", program_path.display()));
    let attestation = attestation_bytes();
    let prover = DirectProver::new(program, DEFAULT_TRUSTED_PREFIX)?;

    let started_at = Instant::now();
    eprintln!("\nStarting Groth16 proof generation...");

    let proof = prover
        .generate_proof(&attestation, &CancellationToken::new())
        .await?;
    let elapsed = started_at.elapsed();
    eprintln!("Groth16 proof generated in {:.3}s", elapsed.as_secs_f64());

    assert!(
        !proof.proof_bytes.is_empty(),
        "Groth16 seal should not be empty"
    );
    let journal = VerifierJournal::decode(&proof.output)
        .expect("prover output should contain a valid verifier journal");
    assert_eq!(journal.result, VerificationResult::Success);
    eprintln!(
        "Groth16 proof size: {} bytes (journal: {} bytes)",
        proof.proof_bytes.len(),
        proof.output.len()
    );

    Ok(())
}

fn guest_program_path() -> PathBuf {
    env::var_os(GUEST_PROGRAM_ENV)
        .or_else(|| env::var_os(LEGACY_GUEST_ELF_ENV))
        .map(PathBuf::from)
        .unwrap_or_else(|| {
            panic!(
                "{GUEST_PROGRAM_ENV} must point to an encoded R0BF program binary; raw guest ELF files are not supported"
            )
        })
}

fn attestation_bytes() -> Vec<u8> {
    env::var_os(ATTESTATION_ENV).map_or_else(
        || {
            hex::decode(TEST_ATTESTATION_HEX.trim())
                .expect("bundled Nitro attestation fixture should be valid hex")
        },
        |path| {
            let path = PathBuf::from(path);
            fs::read(&path)
                .unwrap_or_else(|error| panic!("failed to read {}: {error}", path.display()))
        },
    )
}
