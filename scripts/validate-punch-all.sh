#!/usr/bin/env bash
# validate-punch-all.sh — the full punch validation suite in one command.
#
# Runs, in order: build+vet, unit+race, the G3 emulated dual-NAT harness, and the
# `signaling` validate-peer category against a live Go node. Reports one PASS/FAIL.
# Everything runs on one box (loopback + rootless emulated NAT); no sudo, no
# external network. This is the gate for the whole §7 punch stack short of G4.
set -uo pipefail
cd "$(dirname "$0")/.."

FAIL=0
NODE_NAME="punchsuite"
step() { echo; echo "======== $* ========"; }
mark() { if [ "$1" -ne 0 ]; then FAIL=1; echo ">> FAILED: $2"; else echo ">> ok: $2"; fi; }

# Stage 4 starts a peer. Without this, a Ctrl-C or an early exit leaks it and the
# NEXT run inherits a stale node (peer-manager rebuilds on start, so a leaked one
# is also a *stale-binary* hazard, not just a stray process).
cleanup() { go run ./cmd/peer-manager stop --all >/dev/null 2>&1 || true; }
trap cleanup EXIT INT TERM

step "1/5  build + vet (all three modules)"
go build ./core/... ./ext/... ./cmd/...; mark $? "build"
go vet ./core/... ./ext/... ./cmd/...;   mark $? "vet"

step "2/5  unit + race (signaling stack)"
go test ./core/... ./ext/... ./cmd/...;  mark $? "unit"
# Race the whole punch path, not just the library half: punchwire carries the
# candidate/SRFLX gathering and validate carries the signaling_punch check, and
# both are as concurrent as ext/signaling is.
go test -race ./ext/signaling/... ./cmd/internal/punchwire/... ./cmd/internal/validate/...
mark $? "race (signaling + punchwire + validate)"

step "3/5  G3 — emulated dual-NAT harness (positive traverses, negative control fails)"
bash scripts/punch-nat-harness.sh;        mark $? "G3 harness"

step "4/5  validate-peer signaling category (live Go node: meet x4 + signaling_punch)"
go run ./cmd/peer-manager stop --all >/dev/null 2>&1 || true
START="$(go run ./cmd/peer-manager start --name "$NODE_NAME" --type go --signaling-node --debug 2>&1)"
echo "$START"
ADDR="$(echo "$START" | grep -oE 'addr=[0-9.]+:[0-9]+' | head -1 | cut -d= -f2)"
if [ -n "$ADDR" ]; then
	go run ./cmd/validate-peer -addr "$ADDR" -category signaling; mark $? "validate-peer signaling @ $ADDR"
else
	echo ">> FAILED: could not determine node addr from peer-manager"; FAIL=1
fi
go run ./cmd/peer-manager stop --all >/dev/null 2>&1 || true

# Stage 5 is OPT-IN: point RUST_PUNCH at a built Rust `signaling-punch` and the
# cross-impl NAT crossing joins the gate. Left opt-in so the one-command suite
# stays hermetic — it must not fail on a box with no Rust toolchain, and the
# sibling's binary is not ours to keep current.
#   RUST_PUNCH=../entity-core-rust/target/release/signaling-punch bash scripts/validate-punch-all.sh
if [ -n "${RUST_PUNCH:-}" ]; then
	# --reflector: the cross-impl stage runs the HIGHER rung — both drivers discover
	# their mapping from the node's §6.7.1 responder instead of being handed it.
	# Stage 3 stays on the asserted mapping so the --srflx path keeps its coverage;
	# between them the suite exercises both mapping sources and both impl pairings.
	step "5/5  cross-impl — Go↔Rust, two NATs, reflector-discovered srflx (opt-in via RUST_PUNCH)"
	bash scripts/punch-nat-harness.sh --reflector --crossimpl "$RUST_PUNCH"; mark $? "cross-impl NAT harness (reflector)"
else
	step "5/5  cross-impl — SKIPPED (set RUST_PUNCH=<path to rust signaling-punch> to run it)"
fi

echo
if [ "$FAIL" -eq 0 ]; then
	echo "FULL PUNCH VALIDATION SUITE: PASS (G0–G3; G4 = real networks, operator infra)"
	[ -n "${RUST_PUNCH:-}" ] || echo "  (cross-impl stage skipped — this run gates Go only)"
	exit 0
fi
echo "FULL PUNCH VALIDATION SUITE: FAIL"
exit 1
