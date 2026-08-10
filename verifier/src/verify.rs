//! Top-level attestation verification orchestrating COSE parsing, certificate
//! chain validation, signature verification, and content validation.
//!
//! [`AttestationVerifier::verify`] is the ZK guest entry point — called from the
//! RISC Zero guest program in CHAIN-3560. It must be deterministic with no
//! side effects.

use alloy_primitives::Bytes;
use p384::ecdsa::{Signature, VerifyingKey, signature::Verifier};
use serde_bytes::ByteBuf;

use crate::{
    Result, VerifierError, VerifierInput,
    attestation::{AttestationDocument, AttestationReport},
    types::{Bytes48, Pcr, VerificationResult, VerifierJournal},
    x509::CertChain,
};

/// Attestation report verifier.
///
/// Entry point for end-to-end Nitro attestation verification including
/// COSE parsing, M-02 content validation, x509 chain validation (M-01),
/// COSE signature verification, and journal construction.
#[derive(Debug)]
pub struct AttestationVerifier;

impl AttestationVerifier {
    /// Verifies a Nitro attestation report end-to-end.
    ///
    /// 1. Parses the `COSE_Sign1` envelope and attestation document
    /// 2. Validates attestation content (M-02 checks)
    /// 3. Verifies the x509 certificate chain (M-01 checks)
    /// 4. Verifies the COSE signature against the leaf certificate's public key
    /// 5. Extracts verified data into a `VerifierJournal`
    pub fn verify(input: &VerifierInput) -> Result<VerifierJournal> {
        // 1. Parse attestation report.
        let report = AttestationReport::parse(&input.attestationReport)?;

        // 2. Validate attestation content (M-02).
        Self::validate_attestation_content(&report.doc)?;

        // 3. Extract and verify certificate chain.
        let cert_chain_der = report.cert_chain_der();
        let chain = CertChain::from_der(&cert_chain_der)?;

        let trusted_prefix_len = input.trustedCertsPrefixLen as usize;
        let (certs, cert_expiries) =
            chain.verify_chain(trusted_prefix_len, report.doc.timestamp)?;

        // 4. Verify COSE signature against the leaf certificate's public key.
        let leaf_pk_bytes = chain.leaf_public_key()?;
        let sig_structure = report.cose.sig_structure()?;
        Self::verify_cose_signature(leaf_pk_bytes, &sig_structure, &report.cose.signature)?;

        // 5. Build the journal.
        let pcrs = report
            .doc
            .pcrs
            .iter()
            .map(|(&index, value)| Pcr {
                index,
                value: Bytes48::from(value),
            })
            .collect::<Vec<_>>();

        Ok(VerifierJournal {
            result: VerificationResult::Success,
            trustedCertsPrefixLen: input.trustedCertsPrefixLen,
            timestamp: report.doc.timestamp,
            certs,
            certExpiries: cert_expiries,
            userData: Self::optional_bytes(&report.doc.user_data),
            nonce: Self::optional_bytes(&report.doc.nonce),
            publicKey: Self::optional_bytes(&report.doc.public_key),
            pcrs,
            moduleId: report.doc.module_id,
        })
    }

    /// Verifies the COSE signature over the `Sig_structure` using the leaf cert's P384 key.
    fn verify_cose_signature(
        leaf_pk_bytes: &[u8],
        sig_structure: &[u8],
        signature_bytes: &[u8],
    ) -> Result<()> {
        let verifying_key = VerifyingKey::from_sec1_bytes(leaf_pk_bytes).map_err(|e| {
            VerifierError::SignatureVerification(format!("invalid leaf public key: {e}"))
        })?;

        let signature = Signature::from_slice(signature_bytes).map_err(|e| {
            VerifierError::SignatureVerification(format!("invalid COSE signature: {e}"))
        })?;

        verifying_key
            .verify(sig_structure, &signature)
            .map_err(|e| {
                VerifierError::SignatureVerification(format!(
                    "COSE signature verification failed: {e}"
                ))
            })
    }

    /// Converts an optional `ByteBuf` to `Bytes`, defaulting to empty.
    fn optional_bytes(opt: &Option<ByteBuf>) -> Bytes {
        opt.as_ref()
            .map_or_else(Bytes::new, |b| Bytes::copy_from_slice(b.as_ref()))
    }

    /// Validates attestation document content (M-02 audit checks).
    ///
    /// Per `NitroValidator.sol` reference:
    /// - `module_id` non-empty
    /// - `timestamp` non-zero
    /// - `digest` == `"SHA384"`
    /// - `cabundle` has >= 1 certificate
    /// - PCR count between 1 and 32, each index 0-31
    /// - PCRs are not all zero (AWS Nitro debug-mode attestations)
    /// - `public_key`: null or 1-1024 bytes (present-but-empty is rejected, matching Solidity)
    /// - `user_data`: null or <= 512 bytes
    /// - `nonce`: null or <= 512 bytes
    fn validate_attestation_content(doc: &AttestationDocument) -> Result<()> {
        if doc.module_id.is_empty() {
            return Err(VerifierError::ContentValidation(
                "module_id is empty".into(),
            ));
        }

        if doc.timestamp == 0 {
            return Err(VerifierError::ContentValidation("timestamp is zero".into()));
        }

        if doc.digest != "SHA384" {
            return Err(VerifierError::ContentValidation(format!(
                "unsupported digest algorithm: '{}' (expected 'SHA384')",
                doc.digest
            )));
        }

        if doc.cabundle.is_empty() {
            return Err(VerifierError::ContentValidation("cabundle is empty".into()));
        }

        // PCR count: 1-32, each index 0-31.
        // PCR sizes are statically enforced as 48 bytes by `ByteArray<48>`.
        let pcr_count = doc.pcrs.len();
        if pcr_count == 0 || pcr_count > 32 {
            return Err(VerifierError::ContentValidation(format!(
                "PCR count {pcr_count} out of range (must be 1-32)"
            )));
        }
        for &index in doc.pcrs.keys() {
            if index > 31 {
                return Err(VerifierError::ContentValidation(format!(
                    "PCR index {index} out of range (must be 0-31)"
                )));
            }
        }
        if doc
            .pcrs
            .values()
            .all(|pcr| pcr.iter().all(|&byte| byte == 0))
        {
            return Err(VerifierError::ContentValidation(
                "all PCRs are zero (Nitro debug mode)".into(),
            ));
        }

        // Optional field size limits. public_key min=1 means present-but-empty is
        // rejected, matching Solidity where `pubkeyLen == 0` means absent (null).
        if let Some(pk) = &doc.public_key
            && (pk.is_empty() || pk.len() > 1024)
        {
            return Err(VerifierError::ContentValidation(format!(
                "public_key length {} out of range (1-1024)",
                pk.len()
            )));
        }
        if let Some(ud) = &doc.user_data
            && ud.len() > 512
        {
            return Err(VerifierError::ContentValidation(format!(
                "user_data length {} exceeds maximum (512)",
                ud.len()
            )));
        }
        if let Some(n) = &doc.nonce
            && n.len() > 512
        {
            return Err(VerifierError::ContentValidation(format!(
                "nonce length {} exceeds maximum (512)",
                n.len()
            )));
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use alloy_sol_types::SolValue;
    use rstest::{fixture, rstest};
    use serde_bytes::{ByteArray, ByteBuf};

    use super::*;

    /// Full attestation `COSE_Sign1` from `NitroValidator.t.sol` `test_DecodeAttestationTbs`.
    const ATTESTATION_HEX: &str = include_str!("../testdata/attestation.hex");

    // ── Fixtures ────────────────────────────────────────────────────────

    #[fixture]
    fn attestation_input() -> VerifierInput {
        let bytes = hex::decode(ATTESTATION_HEX.trim()).unwrap();
        VerifierInput {
            trustedCertsPrefixLen: 1,
            attestationReport: Bytes::copy_from_slice(&bytes),
        }
    }

    /// A minimal valid `AttestationDocument` for M-02 unit tests.
    fn valid_doc() -> AttestationDocument {
        let mut pcrs = BTreeMap::new();
        pcrs.insert(0, ByteArray::new([1u8; 48]));
        AttestationDocument {
            module_id: "test-module".into(),
            timestamp: 1_700_000_000_000,
            digest: "SHA384".into(),
            pcrs,
            certificate: ByteBuf::from(vec![0x30]),
            cabundle: vec![ByteBuf::from(vec![0x30])],
            public_key: None,
            user_data: None,
            nonce: None,
        }
    }

    // ── End-to-end happy path ───────────────────────────────────────────

    #[rstest]
    fn verify_full_attestation_report(attestation_input: VerifierInput) {
        let journal = AttestationVerifier::verify(&attestation_input).unwrap();

        assert_eq!(journal.result, VerificationResult::Success);
        assert_eq!(journal.trustedCertsPrefixLen, 1);
        assert_eq!(journal.timestamp, 0x000001937de1c543);
        assert_eq!(journal.moduleId, "i-0de38b2b6853cc9e8-enc0193685e7fee7d85");
        assert_eq!(journal.certs.len(), 5);
        assert_eq!(journal.certExpiries.len(), journal.certs.len());
        // Spot-check first and last expiry against known cert validity periods.
        // Root CA notAfter: 2049-10-28T14:28:05Z
        assert_eq!(journal.certExpiries[0], 2519044085);
        // Leaf notAfter: 2024-11-30T19:22:48Z
        assert_eq!(journal.certExpiries[4], 1732994568);
        assert_eq!(journal.pcrs.len(), 16);
        assert!(journal.userData.is_empty());
        assert!(journal.nonce.is_empty());
        assert!(!journal.publicKey.is_empty());

        // ABI round-trip: verify all fields survive encode/decode.
        let encoded = SolValue::abi_encode(&journal);
        let decoded = VerifierJournal::decode(&encoded).unwrap();
        assert_eq!(decoded.moduleId, journal.moduleId);
        assert_eq!(decoded.timestamp, journal.timestamp);
        assert_eq!(decoded.certExpiries, journal.certExpiries);
        assert_eq!(decoded.certs, journal.certs);
    }

    #[rstest]
    fn verify_with_zero_trusted_prefix() {
        let bytes = hex::decode(ATTESTATION_HEX).unwrap();
        let input = VerifierInput {
            trustedCertsPrefixLen: 0,
            attestationReport: Bytes::copy_from_slice(&bytes),
        };
        let journal = AttestationVerifier::verify(&input).unwrap();
        assert_eq!(journal.result, VerificationResult::Success);
    }

    // ── End-to-end error tests ──────────────────────────────────────────

    #[rstest]
    fn corrupted_attestation_rejected() {
        let input = VerifierInput {
            trustedCertsPrefixLen: 0,
            attestationReport: Bytes::copy_from_slice(&[0xDE, 0xAD]),
        };
        assert!(AttestationVerifier::verify(&input).is_err());
    }

    // ── M-02: validate_attestation_content unit tests ───────────────────

    #[rstest]
    fn m02_valid_doc_passes() {
        assert!(AttestationVerifier::validate_attestation_content(&valid_doc()).is_ok());
    }

    #[rstest]
    fn m02_empty_module_id_rejected() {
        let mut doc = valid_doc();
        doc.module_id = String::new();
        let err = AttestationVerifier::validate_attestation_content(&doc).unwrap_err();
        assert!(err.to_string().contains("module_id"));
    }

    #[rstest]
    fn m02_zero_timestamp_rejected() {
        let mut doc = valid_doc();
        doc.timestamp = 0;
        let err = AttestationVerifier::validate_attestation_content(&doc).unwrap_err();
        assert!(err.to_string().contains("timestamp"));
    }

    #[rstest]
    fn m02_wrong_digest_rejected() {
        let mut doc = valid_doc();
        doc.digest = "SHA256".into();
        let err = AttestationVerifier::validate_attestation_content(&doc).unwrap_err();
        assert!(err.to_string().contains("SHA384"));
    }

    #[rstest]
    fn m02_empty_cabundle_rejected() {
        let mut doc = valid_doc();
        doc.cabundle.clear();
        let err = AttestationVerifier::validate_attestation_content(&doc).unwrap_err();
        assert!(err.to_string().contains("cabundle"));
    }

    #[rstest]
    fn m02_empty_pcrs_rejected() {
        let mut doc = valid_doc();
        doc.pcrs.clear();
        let err = AttestationVerifier::validate_attestation_content(&doc).unwrap_err();
        assert!(err.to_string().contains("PCR count"));
    }

    #[rstest]
    fn m02_all_zero_pcrs_rejected() {
        let mut doc = valid_doc();
        doc.pcrs.insert(0, ByteArray::new([0u8; 48]));
        doc.pcrs.insert(1, ByteArray::new([0u8; 48]));
        let err = AttestationVerifier::validate_attestation_content(&doc).unwrap_err();
        assert!(err.to_string().contains("debug mode"));
    }

    #[rstest]
    fn m02_pcr_index_out_of_range_rejected() {
        let mut doc = valid_doc();
        doc.pcrs.insert(32, ByteArray::new([0u8; 48]));
        let err = AttestationVerifier::validate_attestation_content(&doc).unwrap_err();
        assert!(err.to_string().contains("PCR index"));
    }

    #[rstest]
    fn m02_pcr_index_31_accepted() {
        let mut doc = valid_doc();
        doc.pcrs.insert(31, ByteArray::new([0u8; 48]));
        assert!(AttestationVerifier::validate_attestation_content(&doc).is_ok());
    }

    #[rstest]
    fn m02_public_key_empty_rejected() {
        let mut doc = valid_doc();
        doc.public_key = Some(ByteBuf::from(vec![]));
        let err = AttestationVerifier::validate_attestation_content(&doc).unwrap_err();
        assert!(err.to_string().contains("public_key"));
    }

    #[rstest]
    fn m02_public_key_too_large_rejected() {
        let mut doc = valid_doc();
        doc.public_key = Some(ByteBuf::from(vec![0u8; 1025]));
        let err = AttestationVerifier::validate_attestation_content(&doc).unwrap_err();
        assert!(err.to_string().contains("public_key"));
    }

    #[rstest]
    fn m02_user_data_too_large_rejected() {
        let mut doc = valid_doc();
        doc.user_data = Some(ByteBuf::from(vec![0u8; 513]));
        let err = AttestationVerifier::validate_attestation_content(&doc).unwrap_err();
        assert!(err.to_string().contains("user_data"));
    }

    #[rstest]
    fn m02_nonce_too_large_rejected() {
        let mut doc = valid_doc();
        doc.nonce = Some(ByteBuf::from(vec![0u8; 513]));
        let err = AttestationVerifier::validate_attestation_content(&doc).unwrap_err();
        assert!(err.to_string().contains("nonce"));
    }

    #[rstest]
    fn m02_valid_optional_fields_accepted() {
        let mut doc = valid_doc();
        doc.public_key = Some(ByteBuf::from(vec![0x04; 65]));
        doc.user_data = Some(ByteBuf::from(vec![0u8; 512]));
        doc.nonce = Some(ByteBuf::from(vec![0u8; 256]));
        assert!(AttestationVerifier::validate_attestation_content(&doc).is_ok());
    }
}
