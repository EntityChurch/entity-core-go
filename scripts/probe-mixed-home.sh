#!/usr/bin/env bash
# Probe the SPECIFICATION-FORMAT §8.4.6 cross-peer seam: two peers running
# DIFFERENT home content_hash_formats, meeting.
#
# Why this exists. Every HASH_TYPE=sha384 run this cohort has ever published
# sets EVERY peer to SHA-384 — a uniform network, just a different uniform.
# §8.4.6's whole point is that derive-to-meet and hold-and-fetch produce
# identical bytes on a single-format network and spring apart only at the
# cross-peer seam. That seam had never been exercised. This script exercises
# it, WITH A CONTROL, so a failure is attributable to the home format and not
# to the run being cross-peer at all.
#
# The control is the load-bearing half. A mixed-home failure means nothing on
# its own — the same probe must pass same-home in the same invocation, on the
# same build, or the result is unattributable.
#
# Usage:
#   ./scripts/probe-mixed-home.sh              # go/go, sha256 vs sha384
#   PEER_TYPE=rust ./scripts/probe-mixed-home.sh
#   KEEP=1 ./scripts/probe-mixed-home.sh       # leave peers up for -verbose follow-up
#
# Options (via env):
#   PEER_TYPE=go|rust|python   type for BOTH peers (default: go)
#   ALT_FORMAT=sha384          the non-floor home to probe (default: sha384)
#   CATEGORY=origination       validator category driving the seam (default: origination)
#   KEEP=1                     don't tear the peers down
#
# Exit status is DIAGNOSTIC, not a gate: 0 = the seam held, 1 = it diverged.
# §1.2a keeps the uniform network as the supported v1 deployment, so a
# divergence here is a finding to route, not a broken build. Do not wire this
# into validate-complete.sh.

set -euo pipefail

PEER_TYPE="${PEER_TYPE:-go}"
ALT_FORMAT="${ALT_FORMAT:-sha384}"
CATEGORY="${CATEGORY:-origination}"
KEEP="${KEEP:-0}"

cleanup() {
    if [ "$KEEP" != "1" ]; then
        go run ./cmd/peer-manager stop --all >/dev/null 2>&1 || true
    else
        echo "KEEP=1 — peers left running; stop with: go run ./cmd/peer-manager stop --all"
    fi
}
trap cleanup EXIT

# addr_of parses the "addr=host:port" field out of peer-manager's start line.
addr_of() { sed -n 's/.*addr=\([^ ]*\).*/\1/p' <<<"$1"; }

echo "=== §8.4.6 mixed-home probe — type=$PEER_TYPE, floor=sha256 vs alt=$ALT_FORMAT"
go run ./cmd/peer-manager stop --all >/dev/null 2>&1 || true

FLOOR_OUT=$(go run ./cmd/peer-manager start --name mh-floor  --type "$PEER_TYPE" --debug)
CTRL_OUT=$(go  run ./cmd/peer-manager start --name mh-ctrl   --type "$PEER_TYPE" --debug)
ALT_OUT=$(go   run ./cmd/peer-manager start --name mh-alt    --type "$PEER_TYPE" --debug --hash-type "$ALT_FORMAT")

FLOOR_ADDR=$(addr_of "$FLOOR_OUT")
CTRL_ADDR=$(addr_of "$CTRL_OUT")
ALT_ADDR=$(addr_of "$ALT_OUT")

if [ -z "$FLOOR_ADDR" ] || [ -z "$CTRL_ADDR" ] || [ -z "$ALT_ADDR" ]; then
    echo "FATAL: could not parse peer addresses from peer-manager output" >&2
    exit 2
fi

echo "  floor (sha256): $FLOOR_ADDR"
echo "  ctrl  (sha256): $CTRL_ADDR"
echo "  alt   ($ALT_FORMAT): $ALT_ADDR"
echo

# --- CONTROL: same home. Must pass, or nothing below is attributable. -----
echo "--- CONTROL  sha256 -> sha256  (category=$CATEGORY)"
set +e
go run ./cmd/validate-peer -addr "$FLOOR_ADDR" -reference-peer "$CTRL_ADDR" -category "$CATEGORY" >/tmp/mh-control.txt 2>&1
CONTROL_RC=$?
set -e
grep -E "^Summary:" /tmp/mh-control.txt || true

if [ "$CONTROL_RC" -ne 0 ]; then
    echo
    echo "CONTROL FAILED — the same-home run does not pass, so a mixed-home failure"
    echo "would be unattributable. Fix the control first; this probe measures nothing"
    echo "until it is green. Full output: /tmp/mh-control.txt"
    exit 2
fi
echo "  control green — a divergence below is attributable to the home format."
echo

# --- EXPERIMENT: differing homes. -----------------------------------------
echo "--- MIXED    sha256 -> $ALT_FORMAT  (category=$CATEGORY)"
set +e
go run ./cmd/validate-peer -addr "$FLOOR_ADDR" -reference-peer "$ALT_ADDR" -category "$CATEGORY" >/tmp/mh-mixed.txt 2>&1
MIXED_RC=$?
set -e
grep -E "^Summary:" /tmp/mh-mixed.txt || true
grep -E "^  (FAIL|SKIP) " -A 1 /tmp/mh-mixed.txt || true
echo

if [ "$MIXED_RC" -eq 0 ]; then
    echo "RESULT: the seam HELD. Same checks pass same-home and mixed-home."
    echo "        Full output: /tmp/mh-control.txt, /tmp/mh-mixed.txt"
    exit 0
fi

cat <<'EOF'
RESULT: the seam DIVERGED — checks that pass same-home fail mixed-home on the
        same build. This is the §8.4.6 cross-peer seam, and it is a finding to
        ROUTE, not a build break: §1.2a keeps the uniform network as the
        supported v1 deployment.

        Read the peers' own logs before theorizing — wire evidence is upstream
        of theory (USING-DIAGNOSTICS):
          ~/.entity/logs/mh-floor.log
          ~/.entity/logs/mh-alt.log
        and re-run one failing check with -verbose narrowed by -category.

        Full output: /tmp/mh-control.txt, /tmp/mh-mixed.txt
EOF
exit 1
