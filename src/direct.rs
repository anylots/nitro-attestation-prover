//! [`DirectProver`] — proving backend using a local SP1 [`CpuProver`].
//!
//! Always generates Groth16 proofs, the format the on-chain SP1 verifier
//! contracts accept.

use std::fmt;

use alloy_primitives::Bytes;
use base_proof_tee_nitro_verifier::VerifierInput;
use base_proof_tee_nitro_verifier::{AttestationVerifier, VerificationResult};
use sp1_sdk::{
    CpuProver, Elf, HashableKey, ProveRequest, Prover, ProverClient, ProvingKey, SP1ProvingKey,
    SP1Stdin,
};
use tokio_util::sync::CancellationToken;

use crate::{AttestationProof, AttestationProofProvider, ProverError, Result};

/// Attestation prover using a local SP1 CPU prover.
///
/// Proving runs on SP1's internal worker pool, so awaiting a proof does not
/// stall the async executor.
pub struct DirectProver {
    client: CpuProver,
    pk: SP1ProvingKey,
    trusted_certs_prefix_len: u8,
}

impl DirectProver {
    /// Creates a new [`DirectProver`] from an SP1 guest ELF binary.
    ///
    /// The `trusted_certs_prefix_len` controls how many certificates in the
    /// chain are treated as trusted (typically 1 for root-only).
    pub async fn new(elf: Vec<u8>, trusted_certs_prefix_len: u8) -> Result<Self> {
        let client = ProverClient::builder().cpu().build().await;
        let pk = client
            .setup(Elf::Dynamic(elf.into()))
            .await
            .map_err(|e| ProverError::Sp1(format!("failed to set up proving key: {e}")))?;

        Ok(Self {
            client,
            pk,
            trusted_certs_prefix_len,
        })
    }

    /// Returns the verifying key hash (`bytes32`) of the guest program — the
    /// SP1 equivalent of an image ID.
    pub fn vkey(&self) -> String {
        self.pk.verifying_key().bytes32()
    }
}

impl fmt::Debug for DirectProver {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DirectProver")
            .field("vkey", &self.vkey())
            .field("trusted_certs_prefix_len", &self.trusted_certs_prefix_len)
            .finish_non_exhaustive()
    }
}

#[async_trait::async_trait]
impl AttestationProofProvider for DirectProver {
    /// # Cancellation
    ///
    /// `DirectProver` honors the token only at the synchronous boundary
    /// *before* starting the proof: if the token is already cancelled, the
    /// call returns early. Once proving is in flight, dropping the returned
    /// future abandons the await but SP1's worker pool may keep the job
    /// running until it finishes. This is acceptable because the prover has
    /// no on-chain side effects.
    async fn generate_proof(
        &self,
        attestation_bytes: &[u8],
        cancel: &CancellationToken,
    ) -> Result<AttestationProof> {
        if cancel.is_cancelled() {
            return Err(ProverError::Sp1(
                "proof generation cancelled before start".into(),
            ));
        }

        let input = VerifierInput {
            trustedCertsPrefixLen: self.trusted_certs_prefix_len,
            attestationReport: Bytes::copy_from_slice(attestation_bytes),
        };

        let journal = AttestationVerifier::verify(&input)
            .expect("host verifier should accept the Nitro attestation");
        assert_eq!(journal.result, VerificationResult::Success);
        eprintln!("==========> attestation verified successfully on host");

        let mut stdin = SP1Stdin::new();
        stdin.write_vec(input.encode());

        let proof = self
            .client
            .prove(&self.pk, stdin)
            .groth16()
            .await
            .map_err(|e| ProverError::Sp1(format!("proving failed: {e}")))?;

        Ok(AttestationProof {
            output: Bytes::from(proof.public_values.to_vec()),
            proof_bytes: Bytes::from(proof.bytes()),
        })
    }
}

#[cfg(test)]
mod tests {
    use std::{env, fs, path::PathBuf, time::Instant};

    use base_proof_tee_nitro_verifier::{AttestationVerifier, VerificationResult};

    use super::*;

    /// Default trusted certificate prefix length (root-only).
    const DEFAULT_TRUSTED_PREFIX: u8 = 1;

    /// Path to a binary NSM attestation document used in place of the fixture.
    const ATTESTATION_ENV: &str = "NITRO_ATTESTATION";

    /// Valid Nitro attestation shared with the verifier's end-to-end test.
    const TEST_ATTESTATION_HEX: &str = include_str!("../verifier/testdata/attestation.hex");

    /// Verifies the shared attestation directly on the host without generating a ZK proof.
    /// cargo test verifies_attestation_on_host --nocapture
    #[test]
    fn verifies_attestation_on_host() {
        println!("verifying Nitro attestation on host without ZK proof...");
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
