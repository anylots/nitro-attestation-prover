# Standalone Nitro attestation prover

This workspace provides native verification of the bundled AWS Nitro
attestation as a test and local RISC Zero Groth16 proving as the main binary.
The required verifier source, attestation fixture, recursion archive, and
encoded R0BF guest program are all included, so it does not depend on the Base
monorepo.

Run the fast host verification test:

```sh
cargo test --features prove verifies_attestation_on_host -- --nocapture
```

Run the local Groth16 prover:

```sh
RUSTFLAGS="-C target-cpu=native" \
RUST_LOG="risc0_zkvm=info,risc0_zkp=debug,risc0_circuit_rv32im=info,risc0_circuit_recursion=info" \
RISC0_PROVER=local \
RECURSION_SRC_PATH="$PWD/744b999f0a35b3c86753311c7efb2a0054be21727095cf105af6ee7d3f4d8849.zip" \
NITRO_GUEST_PROGRAM="$PWD/nitro-verifier-guest.r0bf" \
cargo run --profile maxperf \
  -p base-proof-tee-nitro-attestation-prover \
  --features prove
```

Set `NITRO_ATTESTATION=/path/to/raw-attestation.bin` to replace the bundled
fixture.

### Run after disconnecting SSH

Use the helper scripts to keep the local prover running after the SSH session
ends:

```sh
./script/start-prover.sh
tail -f .run/prover.log
```

The start script records the process ID in `.run/prover.pid`. Stop the prover
gracefully with:

```sh
./script/stop-prover.sh
```

Environment variables can be supplied when starting it. For example, to use a
custom attestation and log location:

```sh
NITRO_ATTESTATION=/path/to/raw-attestation.bin \
LOG_FILE=/path/to/prover.log \
./script/start-prover.sh
```

## Run with Docker (Ubuntu 24.04)

Build the image on the server so that `target-cpu=native` is optimized for the
server CPU:

```sh
docker build --tag nitro-attestation-prover .
docker run --rm nitro-attestation-prover

docker run -d \
  --name nitro-attestation-prover-run \
  nitro-attestation-prover

docker logs -f nitro-attestation-prover-run
docker stop nitro-attestation-prover-run
docker rm nitro-attestation-prover-run
```

To prove a custom raw attestation document, mount it read-only and set
`NITRO_ATTESTATION` to its path inside the container:

```sh
docker run --rm \
  --volume /path/to/raw-attestation.bin:/data/attestation.bin:ro \
  --env NITRO_ATTESTATION=/data/attestation.bin \
  nitro-attestation-prover
```
