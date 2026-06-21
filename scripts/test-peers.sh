#!/usr/bin/env bash
# Unified test runner for Entity Core peers.
#
# Takes peer specs as arguments. "go" spins up a managed Go peer (auto-teardown).
# "rust", "python" use known addresses. Raw addresses work too.
#
# Usage:
#   ./scripts/test.sh                          # Go-Go convergence (default)
#   ./scripts/test.sh go go go                 # 3 Go peers
#   ./scripts/test.sh rust go                  # Rust + Go convergence
#   ./scripts/test.sh go rust                  # Go + Rust convergence
#   ./scripts/test.sh rust                     # single-peer validation of Rust
#   ./scripts/test.sh rust python              # validate Rust, then Python (single-peer each)
#   ./scripts/test.sh 127.0.0.1:9003           # validate arbitrary address
#
# Options (via env):
#   KEEP=1              Keep managed Go peers running after test
#   CATEGORY=encoding   Only run one category
#   TIMEOUT=60s         Override timeout (default: 120s)
#   SAVE=1              Save JSON reports to docs/validation/reports/
#   DEBUG=1             Start managed Go peers with --debug
#
# Known peers:
#   rust   = 127.0.0.1:9000
#   python = 127.0.0.1:9001

set -euo pipefail
cd "$(dirname "$0")/.."

# --- Configuration ---

declare -A KNOWN_PEERS=(
    [rust]="127.0.0.1:9000"
    [python]="127.0.0.1:9001"
)

KEEP="${KEEP:-0}"
TIMEOUT="${TIMEOUT:-120s}"
CATEGORY="${CATEGORY:-}"
SAVE="${SAVE:-0}"
DEBUG="${DEBUG:-1}"

# --- Parse args ---

specs=("$@")
if [[ ${#specs[@]} -eq 0 ]]; then
    specs=(go go)
fi

# --- Resolve peers ---
# Each spec becomes an address. "go" specs get managed peers.

managed_peers=()
addrs=()
labels=()
go_count=0
rust_count=0

resolve_spec() {
    local spec="$1"
    if [[ "$spec" == "go" ]]; then
        go_count=$((go_count + 1))
        local name="test-go-$go_count"
        local debug_flag=""
        [[ "$DEBUG" == "1" ]] && debug_flag="--debug"
        echo "Starting managed Go peer: $name"
        go run ./cmd/peer-manager start --name "$name" --type go $debug_flag 2>/dev/null
        local addr
        addr=$(go run ./cmd/peer-manager addr "$name")
        managed_peers+=("$name")
        addrs+=("$addr")
        labels+=("go[$name]@$addr")
    elif [[ "$spec" == "rust" ]]; then
        rust_count=$((rust_count + 1))
        local name="test-rust-$rust_count"
        echo "Starting managed Rust peer: $name"
        go run ./cmd/peer-manager start --name "$name" --type rust --debug 2>/dev/null
        local addr
        addr=$(go run ./cmd/peer-manager addr "$name")
        managed_peers+=("$name")
        addrs+=("$addr")
        labels+=("rust[$name]@$addr")
    elif [[ -v "KNOWN_PEERS[$spec]" ]]; then
        local addr="${KNOWN_PEERS[$spec]}"
        # Verify reachable.
        if nc -z -w2 "${addr%%:*}" "${addr##*:}" 2>/dev/null; then
            addrs+=("$addr")
            labels+=("$spec@$addr")
        else
            echo "ERROR: $spec peer at $addr is not reachable"
            exit 1
        fi
    else
        # Raw address.
        addrs+=("$spec")
        labels+=("$spec")
    fi
}

# --- Cleanup ---

cleanup() {
    if [[ ${#managed_peers[@]} -eq 0 ]]; then
        return
    fi
    echo ""
    if [[ "$KEEP" == "1" ]]; then
        echo "KEEP=1: Managed peers left running."
        echo "  go run ./cmd/peer-manager list"
        echo "  go run ./cmd/peer-manager stop --all"
    else
        echo "Stopping managed peers..."
        for name in "${managed_peers[@]}"; do
            go run ./cmd/peer-manager stop "$name" 2>/dev/null || true
        done
    fi
}
trap cleanup EXIT

# Stop leftover managed peers from previous runs.
go run ./cmd/peer-manager stop --all 2>/dev/null || true

# Resolve all specs.
for spec in "${specs[@]}"; do
    resolve_spec "$spec"
done

echo ""
echo "Peers:"
for i in "${!addrs[@]}"; do
    echo "  ${labels[$i]}"
done
echo ""

# --- Build validator args ---

validator_args=(-identity framework-admin -timeout "$TIMEOUT")
[[ -n "$CATEGORY" ]] && validator_args+=(-category "$CATEGORY")

# --- Run tests ---

if [[ ${#addrs[@]} -eq 1 ]]; then
    # Single peer: validation only.
    echo "=== Single-Peer Validation ==="
    echo ""
    if [[ "$SAVE" == "1" ]]; then
        mkdir -p docs/validation/reports
        local_label="${labels[0]%%@*}"
        outfile="docs/validation/reports/${local_label}-validation-raw.json"
        go run ./cmd/validate-peer -addr "${addrs[0]}" -json-out "$outfile" -failures-only "${validator_args[@]}" || true
    else
        go run ./cmd/validate-peer -addr "${addrs[0]}" "${validator_args[@]}" || true
    fi

elif [[ ${#addrs[@]} -ge 2 ]]; then
    # Multi-peer: convergence.
    peer_csv=$(IFS=,; echo "${addrs[*]}")
    echo "=== Multi-Peer Convergence ==="
    echo "Peers: $peer_csv"
    echo ""
    if [[ "$SAVE" == "1" ]]; then
        mkdir -p docs/validation/reports
        name_parts=()
        for l in "${labels[@]}"; do name_parts+=("${l%%@*}"); done
        outfile="docs/validation/reports/convergence-$(IFS=-; echo "${name_parts[*]}")-raw.json"
        go run ./cmd/validate-peer -peers "$peer_csv" -json-out "$outfile" -failures-only "${validator_args[@]}" || true
    else
        go run ./cmd/validate-peer -peers "$peer_csv" "${validator_args[@]}" || true
    fi
fi

echo ""
echo "Done."
