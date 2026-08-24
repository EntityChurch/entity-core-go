#!/usr/bin/env bash
# Full cross-impl signaling MEET matrix: every implementation as both initiator
# and responder, meeting live through one --open rendezvous node.
#
# This is the live half of the cross-impl signaling gate. Each impl ships a
# `signaling-meet` driver speaking one CLI+JSON+exit contract:
#
#   <driver> --node HOST:PORT --role initiator|responder \
#            --mode tag|secret|lobby|pair --input VALUE --timeout SECS
#   -> one JSON line on stdout; exit 0 iff met.
#
# The drivers (all on the SAME contract):
#   go   : entity-core-go   cmd/signaling-meet          (go run)
#   py   : entity-core-py   tests/interop/signaling_meet.py
#   rust : entity-core-rust cmd/signaling-meet          (cargo --release bin)
#
# Proof of a meet is the PAIR, not either process alone: the initiator exits 0
# AND its nonce appears in the responder's `answered` AND both derived the same
# 33-byte key AND the responder's peer_id is the one the initiator saw.
#
# Usage:
#   ./scripts/signaling-meet-matrix.sh
#
# Env overrides:
#   IMPLS="go py rust"          which impls to cross (space-separated)
#   MODES="tag secret lobby"    which shared-string modes (pair needs an
#                               out-of-band peer-id exchange — not scriptable here)
#   NODE_PORT=4050              --open node listen port
#   PY_REPO / RUST_REPO         sibling repo paths (default ../entity-core-{py,rust})
#   PY_PYTHON=3.11              interpreter uv selects for the Python driver
#   KEEP=1                      leave the node running after the run
set -uo pipefail

GO_REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PARENT="$(cd "$GO_REPO/.." && pwd)"
PY_REPO="${PY_REPO:-$PARENT/entity-core-py}"
RUST_REPO="${RUST_REPO:-$PARENT/entity-core-rust}"
NODE_PORT="${NODE_PORT:-4050}"
NODE="127.0.0.1:$NODE_PORT"
IMPLS="${IMPLS:-go py rust}"
MODES="${MODES:-tag secret lobby}"
PY_PYTHON="${PY_PYTHON:-3.11}"
WORK="$(mktemp -d)"
RUST_NODE="$RUST_REPO/target/release/entity-signaling-node"
RUST_MEET="$RUST_REPO/target/release/signaling-meet"

say() { printf '%s\n' "$*" >&2; }

# --- build any missing Rust binaries fresh from the committed tree ------------
if [ ! -x "$RUST_NODE" ] || [ ! -x "$RUST_MEET" ]; then
  say "building Rust node + meet driver (release)…"
  ( cd "$RUST_REPO" && cargo build --release -p entity-signaling-node -p signaling-meet ) \
    || { say "cargo build failed"; exit 2; }
fi

# --- start the --open node, clean up on exit ---------------------------------
"$RUST_NODE" --listen "$NODE" --endpoint node-a:"$NODE_PORT" --open >"$WORK/node.log" 2>&1 &
NODE_PID=$!
cleanup() {
  [ -n "${KEEP:-}" ] || kill "$NODE_PID" 2>/dev/null
  [ -n "${KEEP:-}" ] || say "node stopped (pid $NODE_PID); port $NODE_PORT $(ss -ltn 2>/dev/null | grep -q ":$NODE_PORT " && echo STILL-LISTENING || echo free)"
}
trap cleanup EXIT
sleep 2
ss -ltn 2>/dev/null | grep -q ":$NODE_PORT " || { say "node did not come up on $NODE — see $WORK/node.log"; exit 2; }

drive() { # <impl> <role> <mode> <input> <timeout>
  case "$1" in
    go)   ( cd "$GO_REPO"   && go run ./cmd/signaling-meet --node "$NODE" --role "$2" --mode "$3" --input "$4" --timeout "$5" ) ;;
    py)   ( cd "$PY_REPO"   && uv run --python "$PY_PYTHON" python tests/interop/signaling_meet.py --node "$NODE" --role "$2" --mode "$3" --input "$4" --timeout "$5" 2>/dev/null | tail -1 ) ;;
    rust) ( "$RUST_MEET" --node "$NODE" --role "$2" --mode "$3" --input "$4" --timeout "$5" ) ;;
  esac
}

PASS=0; FAIL=0
meet() { # <init> <resp> <mode> <input>
  local il=$1 rl=$2 mode=$3 input=$4
  drive "$rl" responder "$mode" "$input" 10 >"$WORK/r.json" &
  local rp=$!
  sleep 2
  local ij; ij=$(drive "$il" initiator "$mode" "$input" 6); local ix=$?
  wait "$rp"
  python3 - "$ij" "$(cat "$WORK/r.json")" "$ix" "$il" "$rl" "$mode" <<'PY'
import json,sys
ij,rj,ix,il,rl,mode=sys.argv[1:7]
try: I=json.loads(ij); R=json.loads(rj)
except Exception as e:
    print(f"FAIL {il:>4}->{rl:<4} {mode:<7} unparseable ({e})"); sys.exit(1)
good = bool(I.get("ok")) and bool(R.get("ok")) and int(ix)==0 \
   and I.get("key")==R.get("key") \
   and I.get("nonce") in (R.get("answered") or []) \
   and I.get("responder")==R.get("peer_id")
print(f"{'PASS' if good else 'FAIL'} {il:>4}->{rl:<4} {mode:<7} key={I.get('key','?')[:14]}…")
sys.exit(0 if good else 1)
PY
  if [ $? -eq 0 ]; then PASS=$((PASS+1)); else FAIL=$((FAIL+1)); fi
}

for il in $IMPLS; do for rl in $IMPLS; do for m in $MODES; do
  case "$m" in
    lobby) meet "$il" "$rl" lobby "lobby:default" ;;
    *)     meet "$il" "$rl" "$m" "m-$m-$il-$rl-$RANDOM" ;;
  esac
done; done; done

echo "================================================"
echo "TOTAL: $PASS passed, $FAIL failed (of $((PASS+FAIL)))"
[ "$FAIL" -eq 0 ]
