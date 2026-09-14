#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd -- "$SCRIPT_DIR/.." && pwd)"
RUN_DIR="${RUN_DIR:-$PROJECT_ROOT/.run}"
PID_FILE="$RUN_DIR/prover.pid"
LOG_FILE="${LOG_FILE:-$RUN_DIR/prover.log}"

mkdir -p -- "$RUN_DIR"

if [[ -f "$PID_FILE" ]]; then
    old_pid="$(<"$PID_FILE")"
    if [[ "$old_pid" =~ ^[0-9]+$ ]] && kill -0 "$old_pid" 2>/dev/null; then
        echo "Prover is already running (PID $old_pid)."
        echo "Log: $LOG_FILE"
        exit 1
    fi
    rm -f -- "$PID_FILE"
fi

export RUSTFLAGS="${RUSTFLAGS:--C target-cpu=native -C target-feature=+avx512f}"
export RUST_LOG="${RUST_LOG:-info,sp1_sdk=info,sp1_prover=info}"

cd -- "$PROJECT_ROOT"
nohup setsid cargo run --release \
    -p base-proof-tee-nitro-attestation-prover \
    --features prove \
    </dev/null >>"$LOG_FILE" 2>&1 &
prover_pid=$!
printf '%s\n' "$prover_pid" >"$PID_FILE"

# Catch immediate startup failures while still leaving the full error in the log.
sleep 1
if ! kill -0 "$prover_pid" 2>/dev/null; then
    rm -f -- "$PID_FILE"
    echo "Prover failed to start. Check the log: $LOG_FILE" >&2
    exit 1
fi

echo "Prover started (PID $prover_pid)."
echo "Log: $LOG_FILE"
echo "Follow: tail -f '$LOG_FILE'"
echo "Stop: $SCRIPT_DIR/stop-prover.sh"
