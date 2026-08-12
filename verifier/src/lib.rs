#![doc = include_str!("../README.md")]
#![cfg_attr(not(test), warn(unused_crate_dependencies))]

// Only the guest binary uses `sp1-zkvm`; mark it used so the lint above stays
// quiet when compiling this lib for the zkvm target.
#[cfg(target_os = "zkvm")]
use sp1_zkvm as _;

mod attestation;
pub use attestation::{AttestationDocument, AttestationReport, CoseSign1};

mod error;
pub use error::{Result, VerifierError};

mod types;
pub use types::{
    BatchVerifierJournal, Bytes48, Pcr, VerificationResult, VerifierInput, VerifierJournal,
    ZkCoProcessorConfig, ZkCoProcessorType,
};

mod verify;
pub use verify::AttestationVerifier;

mod x509;
pub use x509::{CertChain, compute_path_digests};
