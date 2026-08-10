#![doc = include_str!("../README.md")]

mod error;
pub use error::{ProverError, Result};

mod types;
pub use types::{AttestationProof, AttestationProofProvider};

#[cfg(feature = "prove")]
mod direct;
#[cfg(feature = "prove")]
pub use direct::DirectProver;
