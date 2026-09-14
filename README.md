# Standalone Nitro attestation prover

Run the local Groth16 prover:

```sh
  RUSTFLAGS="-C target-cpu=native -C target-feature=+avx512f" \
  RUST_LOG="info,sp1_sdk=info,sp1_prover=debug" \
  cargo run --release \
    -p base-proof-tee-nitro-attestation-prover \
    --features prove
```

## Run with Docker (Ubuntu 24.04)

Build the SP1 base image first, then build the prover image on the server so
that `target-cpu=native` is optimized for the server CPU:

```sh
docker build \
  --file Dockerfile.sp1-start \
  --tag sp1-start \
  .

docker build \
  --file Dockerfile.sp1-prover \
  --tag nitro-attestation-prover \
  .

# SP1's non-native Groth16 backend starts the Gnark container through the host
# Docker daemon. This shared directory must have the same absolute path on the
# host and in the prover container because the daemon resolves bind-mount source
# paths on the host.
sudo mkdir -p \
  /data/nitro-prover/circuits/groth16 \
  /data/nitro-prover/tmp

docker run --rm \
  --shm-size=4g \
  --volume /var/run/docker.sock:/var/run/docker.sock \
  --volume /data/nitro-prover:/data/nitro-prover \
  --env DOCKER_API_VERSION=1.41 \
  --env RUST_LOG="info,sp1_sdk=info,sp1_prover=debug" \
  nitro-attestation-prover

docker run -d \
  --name nitro-attestation-prover-run \
  --shm-size=4g \
  --volume /var/run/docker.sock:/var/run/docker.sock \
  --volume /data/nitro-prover:/data/nitro-prover \
  --env DOCKER_API_VERSION=1.41 \
  --env RUST_LOG="info,sp1_sdk=info,sp1_prover=debug" \
  nitro-attestation-prover

docker logs -f nitro-attestation-prover-run
docker stop nitro-attestation-prover-run
docker rm nitro-attestation-prover-run
```

To prove a custom raw attestation document, mount it read-only and set
`NITRO_ATTESTATION` to its path inside the container:

```sh
docker run --rm \
  --volume /var/run/docker.sock:/var/run/docker.sock \
  --volume /data/nitro-prover:/data/nitro-prover \
  --volume /path/to/raw-attestation.bin:/data/attestation.bin:ro \
  --env DOCKER_API_VERSION=1.41 \
  --env NITRO_ATTESTATION=/data/attestation.bin \
  nitro-attestation-prover
```

Mounting the Docker socket gives the prover container effective root-level
control of the host. Run only trusted prover images on a dedicated host. The
host daemon pulls `ghcr.io/succinctlabs/sp1-gnark:v6.1.0` on the first proof;
pre-pull that image if the runtime host has restricted network access.


## Hyperparameter Version 1
```sh
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
```
## Hyperparameter Version 2
```sh
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
```
