#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd -- "$SCRIPT_DIR/.." && pwd)"
RUN_DIR="${RUN_DIR:-$PROJECT_ROOT/.run}"
PID_FILE="$RUN_DIR/prover.pid"

if [[ ! -f "$PID_FILE" ]]; then
    echo "Prover is not running (no PID file)."
    exit 0
fi

prover_pid="$(<"$PID_FILE")"
if [[ ! "$prover_pid" =~ ^[0-9]+$ ]]; then
    echo "Invalid PID file: $PID_FILE" >&2
    exit 1
fi

if ! kill -0 "$prover_pid" 2>/dev/null; then
    rm -f -- "$PID_FILE"
    echo "Prover is no longer running; removed stale PID file."
    exit 0
fi

command_line="$(ps -o args= -p "$prover_pid")"
if [[ "$command_line" != *"base-proof-tee-nitro-attestation-prover"* ]]; then
    echo "PID $prover_pid does not look like this project's prover; refusing to stop it." >&2
    echo "Command: $command_line" >&2
    exit 1
fi

# start-prover.sh uses setsid, so the negative PID stops Cargo and its prover child.
kill -TERM -- "-$prover_pid"

for _ in {1..10}; do
    if ! kill -0 "$prover_pid" 2>/dev/null; then
        rm -f -- "$PID_FILE"
        echo "Prover stopped (PID $prover_pid)."
        exit 0
    fi
    sleep 1
done

echo "Prover did not stop within 10 seconds (PID $prover_pid)." >&2
echo "Inspect it before forcing termination: ps -fp $prover_pid" >&2
exit 1
