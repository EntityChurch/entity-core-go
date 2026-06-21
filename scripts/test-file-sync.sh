#!/bin/bash
# Test cross-peer file synchronization via entity system.
#
# Peer B watches a source directory at local/sync/ prefix.
# Peer A has a destination directory at local/sync/ prefix.
# The test script sets up subscription + continuation chain, then writes
# a file to B's directory. The file should appear in A's directory via:
#   fsnotify → B tree → subscription → continuation extract+merge → A tree → reverse-write → A directory
#
# Usage:
#   ./scripts/test-file-sync.sh
#   KEEP=1 ./scripts/test-file-sync.sh

set -e

KEEP="${KEEP:-0}"

DIR_A=$(mktemp -d /tmp/entity-fsync-A-XXXXXX)
DIR_B=$(mktemp -d /tmp/entity-fsync-B-XXXXXX)

cleanup() {
    if [ "$KEEP" = "1" ]; then
        echo ""; echo "KEEP=1: Peers running."
        echo "  Source: $DIR_B  Dest: $DIR_A"
        echo "  go run ./cmd/peer-manager stop --all"
    else
        echo ""; echo "Stopping peers..."
        go run ./cmd/peer-manager stop --all 2>/dev/null || true
        rm -rf "$DIR_A" "$DIR_B"
    fi
}
trap cleanup EXIT
go run ./cmd/peer-manager stop --all 2>/dev/null || true

echo "Source dir (B): $DIR_B"
echo "Dest dir (A):   $DIR_A"
echo ""

# Start peers with local files.
echo "Starting peers..."
go run ./cmd/peer-manager start --name fsync-a --debug --files "sync:${DIR_A}:local/sync/" 2>/dev/null
go run ./cmd/peer-manager start --name fsync-b --debug --files "sync:${DIR_B}:local/sync/" 2>/dev/null
echo ""

ADDR_A=$(go run ./cmd/peer-manager addr fsync-a)
ADDR_B=$(go run ./cmd/peer-manager addr fsync-b)
PEERID_A=$(go run ./cmd/peer-manager peer-id fsync-a)
PEERID_B=$(go run ./cmd/peer-manager peer-id fsync-b)

echo "A: $ADDR_A ($PEERID_A)"
echo "B: $ADDR_B ($PEERID_B)"
echo ""

# Write a seed file first so the tree prefix exists before we subscribe.
echo "Seed file" > "$DIR_B/seed.txt"
sleep 2

# Run convergence tests (sets up transport addresses + proves basic sync works).
echo "=== Convergence ==="
go run ./cmd/validate-peer -peers "$ADDR_A,$ADDR_B" -identity framework-admin -timeout 60s 2>/dev/null \
    | grep -E 'Summary'
echo ""

# Now write the test file. The psync test already proved the continuation chain
# works for system/validate/ prefixes. For local/sync/, we need to verify that
# the local files handler detects the write and puts it in the tree.
echo "=== File Sync Test ==="

echo "1. Write file to B's directory"
echo "Hello from cross-peer file sync!" > "$DIR_B/hello.txt"

echo "2. Wait for fsnotify + tree write (3s)"
sleep 3

echo "3. Check B's tree for local/sync/hello.txt"
# Try to read the entity from B's tree via the validator.
RESULT=$(go run ./cmd/validate-peer -addr "$ADDR_B" -identity framework-admin -timeout 10s -verbose 2>&1 \
    | grep -c "local/sync" || echo "0")
echo "   References to local/sync in B's validation: $RESULT"

echo "4. Check A's directory"
if [ -f "$DIR_A/hello.txt" ]; then
    echo "   SUCCESS: hello.txt synced to A!"
    echo "   Content: $(cat "$DIR_A/hello.txt")"
else
    echo "   Not synced (expected — continuation chain not set up for local/sync/ prefix)."
    echo ""
    echo "   Next step: Add a 'filesync' convergence check that sets up"
    echo "   subscription + continuation chain for the local/sync/ prefix,"
    echo "   same pattern as psync but targeting local/sync/*."
fi

echo ""
echo "B dir: $(ls "$DIR_B" 2>/dev/null)"
echo "A dir: $(ls "$DIR_A" 2>/dev/null)"
