//! Command-line entry point for local Nitro attestation Groth16 proving with SP1.

use std::{
    env, fs,
    path::{Path, PathBuf},
    time::Instant,
};

use alloy_primitives::hex;
use base_proof_tee_nitro_attestation_prover::{
    AttestationProof, AttestationProofProvider, DirectProver, ProverError,
};
use base_proof_tee_nitro_verifier::{VerificationResult, VerifierJournal};
use sp1_verifier::Groth16Verifier;
use tokio_util::sync::CancellationToken;

const DEFAULT_TRUSTED_PREFIX: u8 = 1;
const GUEST_PROGRAM_ENV: &str = "NITRO_GUEST_PROGRAM";
const DEFAULT_GUEST_PROGRAM: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/verifier/elf/nitro-verifier-guest"
);
const ATTESTATION_ENV: &str = "NITRO_ATTESTATION";
const TEST_ATTESTATION_HEX: &str = include_str!("../verifier/testdata/attestation.hex");
const PROOF_OUTPUT_DIR: &str = "./proof";

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let _ = tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .with_target(true)
        .try_init();

    let elf_path = env::var_os(GUEST_PROGRAM_ENV)
        .map_or_else(|| PathBuf::from(DEFAULT_GUEST_PROGRAM), PathBuf::from);
    let elf = fs::read(&elf_path)
        .unwrap_or_else(|error| panic!("failed to read {}: {error}", elf_path.display()));
    let attestation = attestation_bytes();

    let prover = DirectProver::new(elf, DEFAULT_TRUSTED_PREFIX).await?;
    let vkey = prover.vkey();
    eprintln!("=========> Guest program vkey: {vkey}");

    eprintln!("\nStarting Groth16 proof generation...");
    let started_at = Instant::now();
    let proof = prover
        .generate_proof(&attestation, &CancellationToken::new())
        .await?;
    let elapsed = started_at.elapsed();
    eprintln!(
        "==========> Groth16 proof generated in {:.3}s",
        elapsed.as_secs_f64()
    );
    save_proof_artifacts(Path::new(PROOF_OUTPUT_DIR), &proof, &vkey)?;
    eprintln!("Proof artifacts saved to {PROOF_OUTPUT_DIR}");

    assert!(
        !proof.proof_bytes.is_empty(),
        "Groth16 proof should not be empty"
    );
    let journal = VerifierJournal::decode(&proof.output)
        .expect("prover output should contain a valid verifier journal");
    assert_eq!(journal.result, VerificationResult::Success);
    eprintln!(
        "Groth16 proof size: {} bytes (public values: {} bytes)",
        proof.proof_bytes.len(),
        proof.output.len()
    );

    Groth16Verifier::verify(
        &proof.proof_bytes,
        &proof.output,
        &vkey,
        *sp1_verifier::GROTH16_VK_BYTES,
    )
    .map_err(|e| ProverError::Sp1(format!("local Groth16 verification failed: {e}")))?;
    eprintln!("Groth16 proof verified locally against the SP1 vkey");

    Ok(())
}

fn save_proof_artifacts(
    output_dir: &Path,
    proof: &AttestationProof,
    vkey: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    fs::create_dir_all(output_dir)?;

    let proof_json = serde_json::json!({
        "proof": hex::encode_prefixed(&proof.proof_bytes),
        "public_values": hex::encode_prefixed(&proof.output),
    });
    let vkey_json = serde_json::json!({ "vkey": vkey });

    fs::write(
        output_dir.join("proof.json"),
        serde_json::to_vec_pretty(&proof_json)?,
    )?;
    fs::write(
        output_dir.join("vkey.json"),
        serde_json::to_vec_pretty(&vkey_json)?,
    )?;

    Ok(())
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
