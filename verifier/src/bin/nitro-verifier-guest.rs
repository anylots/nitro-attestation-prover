//! SP1 guest program for AWS Nitro Enclave attestation verification.
//!
//! This binary is the ZK entry point, compiled to `riscv32im-succinct-zkvm-elf`
//! with `cargo prove build`. It reads an ABI-encoded [`VerifierInput`], runs
//! [`AttestationVerifier::verify`], and commits the ABI-encoded
//! [`VerifierJournal`] as public values.
//!
//! The library target stays zkVM-agnostic and usable from host code; only this
//! binary depends on `sp1-zkvm` (a target-gated dependency). When built for a
//! non-zkvm target (e.g. `cargo test` on the host) it compiles to a stub that
//! only prints a hint, so host builds keep working.

#![cfg_attr(target_os = "zkvm", no_main)]

#[cfg(target_os = "zkvm")]
use base_proof_tee_nitro_verifier::{AttestationVerifier, VerifierInput};

#[cfg(target_os = "zkvm")]
sp1_zkvm::entrypoint!(main);

/// Guest entry point: ABI bytes in, verified ABI journal out.
///
/// Panics on malformed input or failed verification (fail-closed: no proof is
/// generated for an attestation that does not verify).
#[cfg(target_os = "zkvm")]
pub fn main() {
    let input_bytes = sp1_zkvm::io::read_vec();
    let input = VerifierInput::decode(&input_bytes)
        .expect("guest input should be an ABI-encoded VerifierInput");

    let journal = AttestationVerifier::verify(&input).expect("attestation verification failed");

    sp1_zkvm::io::commit_slice(&journal.encode());
}

/// Host-side stub so off-zkvm builds link normally.
#[cfg(not(target_os = "zkvm"))]
fn main() {
    eprintln!(
        "nitro-verifier-guest is an SP1 guest program; build it with \
         `cargo prove build` (target riscv64im-succinct-zkvm-elf)"
    );
}
