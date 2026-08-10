# syntax=docker/dockerfile:1

FROM ubuntu:24.04 AS builder

ARG DEBIAN_FRONTEND=noninteractive
ARG RUST_VERSION=1.93.0

RUN apt-get -o Acquire::Retries=3 update \
    && apt-get -o Acquire::Retries=3 install --yes --fix-missing --no-install-recommends \
        build-essential \
        ca-certificates \
        curl \
        pkg-config \
    && rm -rf /var/lib/apt/lists/*

ENV RUSTUP_HOME=/opt/rustup \
    CARGO_HOME=/opt/cargo \
    PATH=/opt/cargo/bin:$PATH

RUN curl --proto '=https' --tlsv1.2 --fail --silent --show-error https://sh.rustup.rs \
        | sh -s -- -y --default-toolchain "${RUST_VERSION}" --profile minimal --no-modify-path

WORKDIR /build

COPY Cargo.toml Cargo.lock ./
COPY verifier/Cargo.toml verifier/Cargo.toml
RUN mkdir --parents src verifier/src \
    && touch src/lib.rs src/main.rs verifier/src/lib.rs
RUN cargo fetch --locked

COPY src/ src/
COPY verifier/ verifier/
COPY README.md ./
COPY 744b999f0a35b3c86753311c7efb2a0054be21727095cf105af6ee7d3f4d8849.zip ./

ENV RUSTFLAGS="-C target-cpu=native" \
    RECURSION_SRC_PATH=/build/744b999f0a35b3c86753311c7efb2a0054be21727095cf105af6ee7d3f4d8849.zip

RUN --mount=type=cache,id=nitro-prover-target,target=/build/target,sharing=locked \
    cargo build --locked --profile maxperf \
        -p base-proof-tee-nitro-attestation-prover \
        --features prove \
    && install --directory /out \
    && install --mode=0755 \
        /build/target/maxperf/base-proof-tee-nitro-attestation-prover \
        /out/nitro-attestation-prover

FROM ubuntu:24.04 AS runtime

ARG DEBIAN_FRONTEND=noninteractive

RUN apt-get -o Acquire::Retries=3 update \
    && apt-get -o Acquire::Retries=3 install --yes --fix-missing --no-install-recommends \
        ca-certificates \
        libgcc-s1 \
        libstdc++6 \
    && rm -rf /var/lib/apt/lists/* \
    && useradd --create-home --uid 10001 prover

WORKDIR /app

COPY --from=builder /out/nitro-attestation-prover /usr/local/bin/nitro-attestation-prover
COPY --chown=prover:prover nitro-verifier-guest.r0bf /app/nitro-verifier-guest.r0bf

ENV RUST_LOG="risc0_zkvm=info,risc0_zkp=debug,risc0_circuit_rv32im=info,risc0_circuit_recursion=info" \
    RISC0_PROVER=local \
    NITRO_GUEST_PROGRAM=/app/nitro-verifier-guest.r0bf

USER prover

ENTRYPOINT ["/usr/local/bin/nitro-attestation-prover"]
