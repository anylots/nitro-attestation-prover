//! [`DirectProver`] — proving backend using `risc0_zkvm::default_prover()`.
//!
//! The default prover can use local proving, Bonsai, or development mode based
//! on the RISC Zero environment variables.

use std::sync::Arc;

use alloy_primitives::Bytes;
use base_proof_tee_nitro_verifier::VerifierInput;
use risc0_zkvm::{ExecutorEnv, ProverOpts, compute_image_id, default_prover};
use tokio_util::sync::CancellationToken;

use crate::{AttestationProof, AttestationProofProvider, ProverError, Result};

/// Attestation prover using the RISC Zero default prover.
///
/// The default prover routes to Bonsai remote proving or dev-mode depending
/// on environment variable configuration. Always requests Groth16 receipts
/// for on-chain verifiability.
///
/// Proving is offloaded to a blocking task via [`tokio::task::spawn_blocking`]
/// to avoid stalling the async executor.
#[derive(Debug)]
pub struct DirectProver {
    program: Arc<[u8]>,
    image_id: [u32; 8],
    trusted_certs_prefix_len: u8,
}

impl DirectProver {
    /// Creates a new [`DirectProver`] from an encoded R0BF program binary.
    ///
    /// The R0BF must bundle the guest ELF with its zkVM kernel. Computes the
    /// image ID from that program. The `trusted_certs_prefix_len` controls how
    /// many certificates in the chain are treated as trusted (typically 1 for
    /// root-only).
    pub fn new(program: Vec<u8>, trusted_certs_prefix_len: u8) -> Result<Self> {
        let digest = compute_image_id(&program)
            .map_err(|e| ProverError::ImageId(format!("failed to compute image ID: {e}")))?;
        let image_id: [u32; 8] = digest.into();

        Ok(Self {
            program: Arc::from(program),
            image_id,
            trusted_certs_prefix_len,
        })
    }

    /// Returns the computed image ID for this guest program.
    pub const fn image_id(&self) -> &[u32; 8] {
        &self.image_id
    }
}

#[async_trait::async_trait]
impl AttestationProofProvider for DirectProver {
    /// # Cancellation
    ///
    /// `DirectProver` honors the token only at the synchronous boundary
    /// *before* spawning the blocking prover task: if the token is
    /// already cancelled, the call returns early. Once the blocking
    /// task is in flight, dropping the returned future (e.g. via the
    /// registrar's outer `select!`) abandons the await but the
    /// underlying RISC Zero proof continues to completion on the
    /// blocking thread pool until the backend finishes — `spawn_blocking`
    /// has no abort signal. This is acceptable because the prover has
    /// no on-chain side effects.
    async fn generate_proof(
        &self,
        attestation_bytes: &[u8],
        cancel: &CancellationToken,
    ) -> Result<AttestationProof> {
        if cancel.is_cancelled() {
            return Err(ProverError::Risc0(
                "proof generation cancelled before start".into(),
            ));
        }
        let program = Arc::clone(&self.program);
        let trusted_certs_prefix_len = self.trusted_certs_prefix_len;
        let attestation_owned = attestation_bytes.to_vec();

        // Proving is synchronous and potentially long-running (Bonsai HTTP
        // polling or local CPU). Offload to a blocking thread so we don't
        // stall the async executor.
        let (journal_bytes, seal) = tokio::task::spawn_blocking(move || {
            let input = VerifierInput {
                trustedCertsPrefixLen: trusted_certs_prefix_len,
                attestationReport: Bytes::from(attestation_owned),
            };
            let input_bytes = input.encode();

            let env = ExecutorEnv::builder()
                .write_slice(&input_bytes)
                .build()
                .map_err(|e| ProverError::Risc0(format!("failed to build executor env: {e}")))?;

            let prover = default_prover();
            let prove_info = prover
                .prove_with_opts(env, &program, &ProverOpts::groth16())
                .map_err(|e| ProverError::Risc0(format!("proving failed: {e}")))?;

            let journal = prove_info.receipt.journal.bytes.clone();
            let seal = risc0_ethereum_contracts::encode_seal(&prove_info.receipt)
                .map_err(|e| ProverError::Risc0(format!("failed to encode seal: {e}")))?;

            Ok::<_, ProverError>((journal, seal))
        })
        .await
        .map_err(|e| ProverError::Risc0(format!("proving task panicked: {e}")))??;

        Ok(AttestationProof {
            output: Bytes::from(journal_bytes),
            proof_bytes: Bytes::from(seal),
        })
    }
}

#[cfg(test)]
mod tests {
    use std::{env, fs, path::PathBuf, time::Instant};

    use base_proof_tee_nitro_verifier::{AttestationVerifier, VerificationResult};
    use rstest::rstest;

    use super::*;

    /// Default trusted certificate prefix length (root-only).
    const DEFAULT_TRUSTED_PREFIX: u8 = 1;

    /// Path to a binary NSM attestation document used in place of the fixture.
    const ATTESTATION_ENV: &str = "NITRO_ATTESTATION";

    /// Valid Nitro attestation shared with the verifier's end-to-end test.
    const TEST_ATTESTATION_HEX: &str = include_str!("../verifier/testdata/attestation.hex");

    // ── DirectProver::new() error paths ─────────────────────────────────

    #[rstest]
    fn new_with_empty_program_returns_image_id_error() {
        let result = DirectProver::new(vec![], DEFAULT_TRUSTED_PREFIX);

        let err = result.unwrap_err();
        assert!(matches!(err, ProverError::ImageId(_)));
        assert!(
            err.to_string().contains("image ID"),
            "error message should mention image ID: {err}"
        );
    }

    #[rstest]
    fn new_with_garbage_program_returns_image_id_error() {
        let garbage = vec![0xDE, 0xAD, 0xBE, 0xEF];
        let result = DirectProver::new(garbage, DEFAULT_TRUSTED_PREFIX);

        let err = result.unwrap_err();
        assert!(matches!(err, ProverError::ImageId(_)));
    }

    #[rstest]
    #[case::single_zero(vec![0x00])]
    #[case::short_header(vec![0x7F, 0x45, 0x4C, 0x46])] // ELF magic without body
    #[case::random_noise(vec![0xFF; 64])]
    fn new_with_invalid_program_variants_rejected(#[case] bad_program: Vec<u8>) {
        let result = DirectProver::new(bad_program, DEFAULT_TRUSTED_PREFIX);
        assert!(result.is_err(), "invalid program should be rejected");
    }

    // ── DirectProver::new() with different trusted prefix lengths ───────

    #[rstest]
    fn new_rejects_invalid_program_regardless_of_prefix(#[values(0, 1, 2, 5)] trusted_prefix: u8) {
        let result = DirectProver::new(vec![], trusted_prefix);
        assert!(result.is_err());
    }

    /// Verifies the shared attestation directly on the host without generating a ZK proof.
    #[test]
    fn verifies_attestation_on_host() {
        let input = VerifierInput {
            trustedCertsPrefixLen: DEFAULT_TRUSTED_PREFIX,
            attestationReport: Bytes::from(attestation_bytes()),
        };

        let started_at = Instant::now();
        let journal = AttestationVerifier::verify(&input)
            .expect("host verifier should accept the Nitro attestation");
        let elapsed = started_at.elapsed();

        assert_eq!(journal.result, VerificationResult::Success);
        eprintln!(
            "Nitro attestation verified on host in {:.3}ms (PCRs: {}, certificates: {})",
            elapsed.as_secs_f64() * 1_000.0,
            journal.pcrs.len(),
            journal.certs.len()
        );
    }

    /// Loads the configured attestation or falls back to the shared valid fixture.
    fn attestation_bytes() -> Vec<u8> {
        env::var_os(ATTESTATION_ENV).map_or_else(
            || {
                alloy_primitives::hex::decode(TEST_ATTESTATION_HEX.trim())
                    .expect("bundled Nitro attestation fixture should be valid hex")
            },
            |path| {
                let path = PathBuf::from(path);
                fs::read(&path)
                    .unwrap_or_else(|error| panic!("failed to read {}: {error}", path.display()))
            },
        )
    }
}
