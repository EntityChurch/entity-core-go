#!/usr/bin/env bash
# Test cross-peer operations using managed peers.
#
# Usage:
#   ./scripts/test-cross-peer.sh                        # convergence test with 2 Go peers
#   ./scripts/test-cross-peer.sh 3                       # convergence test with 3 Go peers
#   TYPES=go,python ./scripts/test-cross-peer.sh         # 1 Go + 1 Python peer
#   TYPES=go,rust,python ./scripts/test-cross-peer.sh    # all three implementations
#   TYPE=python ./scripts/test-cross-peer.sh             # 2 Python peers
#   TYPE=python ./scripts/test-cross-peer.sh 3           # 3 Python peers
#
# Options (via env):
#   TYPES=go,python,rust   Comma-separated list of peer types to start (one peer each)
#   TYPE=go                Default type for numbered peers (default: go)
#   KEEP=1                 Don't tear down peers after test
#   TIMEOUT=120s           Convergence test timeout (default: 120s)

# pipefail so a peer-manager start failure isn't masked by the `| sed` pipe
# (a peer that fails to launch would otherwise be silently skipped, then the
# convergence run fails confusingly against a missing peer). -u catches unset
# vars. Matches validate-peers.sh / test-peers.sh.
set -euo pipefail

NUM_PEERS="${1:-2}"
TYPE="${TYPE:-go}"
KEEP="${KEEP:-0}"
TIMEOUT="${TIMEOUT:-120s}"

# Cleanup handler.
cleanup() {
    if [ "$KEEP" = "1" ]; then
        echo ""
        echo "KEEP=1: Peers left running. Use 'go run ./cmd/peer-manager list' to see them."
        echo "Use 'go run ./cmd/peer-manager stop --all' to tear down."
    else
        echo ""
        echo "Stopping peers..."
        go run ./cmd/peer-manager stop --all 2>/dev/null || true
    fi
}
trap cleanup EXIT

# Stop any leftover peers from previous runs.
go run ./cmd/peer-manager stop --all 2>/dev/null || true

PEER_NAMES=()

if [ -n "${TYPES:-}" ]; then
    # Mixed-type mode: start one peer per type listed in TYPES.
    IFS=',' read -ra TYPE_LIST <<< "$TYPES"
    idx=0
    for ptype in "${TYPE_LIST[@]}"; do
        idx=$((idx + 1))
        name="cross-${ptype}-${idx}"
        echo "Starting $ptype peer '$name'..."
        go run ./cmd/peer-manager start --name "$name" --type "$ptype" --debug 2>&1 | sed 's/^/  /'
        PEER_NAMES+=("$name")
    done
else
    # Homogeneous mode: start N peers of the same type.
    for i in $(seq 1 "$NUM_PEERS"); do
        name="cross-$i"
        echo "Starting $TYPE peer '$name'..."
        go run ./cmd/peer-manager start --name "$name" --type "$TYPE" --debug 2>&1 | sed 's/^/  /'
        PEER_NAMES+=("$name")
    done
fi

echo ""
go run ./cmd/peer-manager list
echo ""

# Build addrs string.
ADDRS=$(go run ./cmd/peer-manager addrs "$(IFS=,; echo "${PEER_NAMES[*]}")")

echo "Running convergence tests against: $ADDRS"
echo "============================================"
echo ""

go run ./cmd/validate-peer -peers "$ADDRS" -identity framework-admin -timeout "$TIMEOUT"

echo ""
echo "Done."
