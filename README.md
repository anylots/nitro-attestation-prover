# Standalone Nitro attestation prover

This workspace provides native verification of the bundled AWS Nitro
attestation as a test and local SP1 Groth16 proving as the main binary.
The required verifier source, attestation fixture, and SP1 guest ELF
(`verifier/elf/nitro-verifier-guest`) are all included, so it does not depend
on the Base monorepo.

Run the fast host verification test:

```sh
cargo test --features prove verifies_attestation_on_host -- --nocapture
```

Run the local Groth16 prover:

```sh
RUSTFLAGS="-C target-cpu=native -C target-feature=+avx512f" \
RUST_LOG="info,sp1_sdk=info,sp1_prover=info" \
cargo run --release \
  -p base-proof-tee-nitro-attestation-prover \
  --features prove
```

The prover loads the bundled guest ELF from `verifier/elf/nitro-verifier-guest`;
set `NITRO_GUEST_PROGRAM=/path/to/guest-elf` to override it. On the first run
SP1 downloads the Groth16 circuit artifacts, which takes extra time.

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

  RUSTFLAGS="-C target-cpu=native -C target-feature=+avx512f" \
  RUST_LOG="info,sp1_sdk=info,sp1_prover=debug" \
  MEMORY_LIMIT=12589934592 \
  SHARD_SIZE=524288 \
  ELEMENT_THRESHOLD=87108864 \
  HEIGHT_THRESHOLD=624288 \
  TRACE_CHUNK_SLOTS=2 \
  RAYON_NUM_THREADS=8 \
  SP1_WORKER_NUM_SPLICING_WORKERS=1 \
  SP1_WORKER_SPLICING_BUFFER_SIZE=1 \
  SP1_WORKER_NUMBER_OF_SEND_SPLICE_WORKERS_PER_SPLICE=1 \
  SP1_WORKER_SEND_SPLICE_INPUT_BUFFER_SIZE_PER_SPLICE=1 \
  SP1_WORKER_GLOBAL_MEMORY_BUFFER_SIZE=1 \
  SP1_WORKER_NUM_CORE_WORKERS=2 \
  SP1_WORKER_CORE_BUFFER_SIZE=1 \
  SP1_WORKER_NUM_SETUP_WORKERS=1 \
  SP1_WORKER_SETUP_BUFFER_SIZE=1 \
  SP1_WORKER_NORMALIZE_PROGRAM_CACHE_SIZE=1 \
  SP1_WORKER_NUM_PREPARE_REDUCE_WORKERS=1 \
  SP1_WORKER_PREPARE_REDUCE_BUFFER_SIZE=1 \
  SP1_WORKER_NUM_RECURSION_EXECUTOR_WORKERS=2 \
  SP1_WORKER_RECURSION_EXECUTOR_BUFFER_SIZE=1 \
  SP1_WORKER_NUM_RECURSION_PROVER_WORKERS=2 \
  SP1_WORKER_RECURSION_PROVER_BUFFER_SIZE=1 \
  SP1_WORKER_NUM_DEFERRED_WORKERS=1 \
  SP1_WORKER_DEFERRED_BUFFER_SIZE=1 \
  cargo run --release \
    -p base-proof-tee-nitro-attestation-prover \
    --features prove

  RUSTFLAGS="-C target-cpu=native -C target-feature=+avx512f" \
  RUST_LOG="info,sp1_sdk=info,sp1_prover=debug" \
  MEMORY_LIMIT=12589934592 \
  SHARD_SIZE=524288 \
  ELEMENT_THRESHOLD=77108864 \
  HEIGHT_THRESHOLD=624288 \
  TRACE_CHUNK_SLOTS=1 \
  RAYON_NUM_THREADS=8 \
  SP1_WORKER_NUM_SPLICING_WORKERS=1 \
  SP1_WORKER_SPLICING_BUFFER_SIZE=1 \
  SP1_WORKER_NUMBER_OF_SEND_SPLICE_WORKERS_PER_SPLICE=1 \
  SP1_WORKER_SEND_SPLICE_INPUT_BUFFER_SIZE_PER_SPLICE=1 \
  SP1_WORKER_GLOBAL_MEMORY_BUFFER_SIZE=1 \
  SP1_WORKER_NUM_CORE_WORKERS=1 \
  SP1_WORKER_CORE_BUFFER_SIZE=1 \
  SP1_WORKER_NUM_SETUP_WORKERS=1 \
  SP1_WORKER_SETUP_BUFFER_SIZE=1 \
  SP1_WORKER_NORMALIZE_PROGRAM_CACHE_SIZE=1 \
  SP1_WORKER_NUM_PREPARE_REDUCE_WORKERS=1 \
  SP1_WORKER_PREPARE_REDUCE_BUFFER_SIZE=1 \
  SP1_WORKER_NUM_RECURSION_EXECUTOR_WORKERS=1 \
  SP1_WORKER_RECURSION_EXECUTOR_BUFFER_SIZE=1 \
  SP1_WORKER_NUM_RECURSION_PROVER_WORKERS=1 \
  SP1_WORKER_RECURSION_PROVER_BUFFER_SIZE=1 \
  SP1_WORKER_NUM_DEFERRED_WORKERS=1 \
  SP1_WORKER_DEFERRED_BUFFER_SIZE=1 \
  cargo run --release \
    -p base-proof-tee-nitro-attestation-prover \
    --features prove