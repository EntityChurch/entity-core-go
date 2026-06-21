#!/usr/bin/env bash
# Validate remote Entity Core peers against the V7 spec.
#
# For each target peer, runs the full single+two-peer validation:
#   1. Responder-side checks (single-peer categories — peer answers requests).
#   2. Origination (A-role) checks — peer dispatches outbound EXECUTEs
#      against a known-good Go reference peer.
#
# This combined coverage is the standard pre-merge validation for a peer
# implementation. Three-peer merge/convergence behavior is a separate tool —
# see scripts/test-cross-peer.sh.
#
# Usage:
#   ./scripts/validate-peers.sh                    # validate rust + python
#   ./scripts/validate-peers.sh rust               # validate rust only
#   ./scripts/validate-peers.sh python             # validate python only
#   ./scripts/validate-peers.sh 127.0.0.1:9003     # validate arbitrary address
#
# Options (via env):
#   CATEGORY=encoding    Only run one category. "origination" requires reference peer.
#   JSON=1               Output raw JSON instead of human-readable.
#   SAVE=1               Save JSON reports to docs/validation/reports/.
#   NO_REFERENCE=1       Skip A-role checks (responder-side only — not recommended).
#   REFERENCE_ADDR=host:port   Use an externally-managed Go reference instead of starting one.
#
# Known peers:
#   rust   = 127.0.0.1:9000
#   python = 127.0.0.1:9001
#   go     = 127.0.0.1:9002

set -euo pipefail
cd "$(dirname "$0")/.."

# Default addresses for well-known fixed-port peers.
# Overridden by peer-manager if a managed peer with a matching name exists.
declare -A DEFAULT_PEERS=(
    [rust]="127.0.0.1:9000"
    [python]="127.0.0.1:9001"
    [go]="127.0.0.1:9002"
)

resolve_peer_addr() {
    local name="$1"
    # Try peer-manager first: look for "{name}", "{name}-peer", or type match.
    for candidate in "$name" "${name}-peer"; do
        local addr
        addr=$(go run ./cmd/peer-manager addrs "$candidate" 2>/dev/null) && [[ -n "$addr" ]] && {
            echo "$addr"
            return
        }
    done
    # Fall back to hardcoded defaults.
    if [[ -v "DEFAULT_PEERS[$name]" ]]; then
        echo "${DEFAULT_PEERS[$name]}"
        return
    fi
    # Assume it's a literal address.
    echo "$name"
}

declare -A PEERS

ARGS=()
[[ -n "${CATEGORY:-}" ]] && ARGS+=(-category "$CATEGORY")
[[ "${JSON:-}" == "1" ]] && ARGS+=(-json)

REF_ADDR=""
REF_NAME="validate-ref-$$"
STARTED_REF=0

start_reference_if_needed() {
    if [[ "${NO_REFERENCE:-}" == "1" ]]; then
        echo "NO_REFERENCE=1: skipping A-role checks (responder-side only)."
        return
    fi
    if [[ -n "${REFERENCE_ADDR:-}" ]]; then
        REF_ADDR="$REFERENCE_ADDR"
        echo "Using external reference peer at $REF_ADDR"
        return
    fi
    echo "Starting Go reference peer for A-role validation..."
    go run ./cmd/peer-manager start --name "$REF_NAME" --type go 2>&1 | sed 's/^/  /'
    REF_ADDR=$(go run ./cmd/peer-manager addrs "$REF_NAME")
    STARTED_REF=1
    echo "Reference peer ready at $REF_ADDR"
    echo
}

stop_reference() {
    if [[ "$STARTED_REF" == "1" ]]; then
        echo "Stopping reference peer $REF_NAME..."
        # `stop` takes a positional NAME (not --name); the flag form silently
        # matches no peer and leaks the reference peer on every run.
        go run ./cmd/peer-manager stop "$REF_NAME" 2>/dev/null || true
    fi
}

trap stop_reference EXIT

validate_peer() {
    local name="$1"
    local addr="$2"

    echo "=== Validating $name @ $addr ==="
    echo

    local peer_args=(-addr "$addr" "${ARGS[@]}")
    if [[ -n "$REF_ADDR" ]]; then
        peer_args+=(-reference-peer "$REF_ADDR")
    fi

    if [[ "${SAVE:-}" == "1" ]]; then
        mkdir -p docs/validation/reports
        local outfile="docs/validation/reports/${name}-validation-raw.json"
        # -json-out writes the JSON report AND prints the text summary to
        # stdout. One Go code path owns the schema — no inline-python reparse
        # that silently breaks (|| true + 2>/dev/null) when the schema changes.
        go run ./cmd/validate-peer "${peer_args[@]}" -json-out "$outfile" -failures-only || true
    else
        go run ./cmd/validate-peer "${peer_args[@]}" || true
    fi
    echo
}

targets=("$@")
if [[ ${#targets[@]} -eq 0 ]]; then
    targets=(rust python)
fi

start_reference_if_needed

for target in "${targets[@]}"; do
    addr=$(resolve_peer_addr "$target")
    validate_peer "$target" "$addr"
done
