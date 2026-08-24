#!/usr/bin/env bash
# validate-punch-all.sh — the full punch validation suite in one command.
#
# Runs, in order: build+vet, unit+race, the G3 emulated dual-NAT harness, the
# §6.7.3 endpoint-binding rung, the §6.7.1 NAT-type detection rung, and the
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

step "1/6  build + vet (all three modules)"
go build ./core/... ./ext/... ./cmd/...; mark $? "build"
go vet ./core/... ./ext/... ./cmd/...;   mark $? "vet"

step "2/6  unit + race (signaling stack)"
go test ./core/... ./ext/... ./cmd/...;  mark $? "unit"
# Race the whole punch path, not just the library half: punchwire carries the
# candidate/SRFLX gathering and validate carries the signaling_punch check, and
# both are as concurrent as ext/signaling is.
go test -race ./ext/signaling/... ./cmd/internal/punchwire/... ./cmd/internal/validate/...
mark $? "race (signaling + punchwire + validate)"

step "3/6  G3 — emulated dual-NAT harness (positive traverses, negative control fails)"
bash scripts/punch-nat-harness.sh;        mark $? "G3 harness"

step "3b/6  endpoint binding — §6.7.3 violation: loopback certifies it, the NAT rung catches it"
bash scripts/punch-endpoint-binding.sh;   mark $? "endpoint-binding harness"

step "3c/6  NAT-type detection — §6.7.1/§11.2 multi-reflector: cone punchable, per-destination relay-only, one reflector refused"
# Cross-impl here is NOT a bonus lap: a classifier can be unit-tested against
# authored divergent vectors in either tree, but no unit test can PRODUCE a
# per-destination mapping. This is the only substrate in the cohort that can, so
# until a driver runs P2 here its endpoint-dependent verdict is an assertion
# about its own test data. Same reflectors, same NAT policies, both binaries.
if [ -n "${RUST_PUNCH:-}" ]; then
	bash scripts/punch-nat-type.sh --crossimpl "$RUST_PUNCH"; mark $? "nat-type harness (go + rust)"
else
	bash scripts/punch-nat-type.sh;       mark $? "nat-type harness (go only)"
fi

step "4/6  validate-peer signaling category (live Go node: meet x4 + signaling_punch)"
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
	step "5/6  cross-impl — Go↔Rust, two NATs, reflector-discovered srflx (opt-in via RUST_PUNCH)"
	bash scripts/punch-nat-harness.sh --reflector --crossimpl "$RUST_PUNCH"; mark $? "cross-impl NAT harness (reflector)"
	# Stage 6 moves ONE more variable: the §6.7.1 reflector becomes Rust's node, so
	# Go's observe-address CLIENT meets Rust's RESPONDER with a real NAT in between.
	# A wrong answer there is not a cosmetic mismatch — it advertises a hole that
	# never opens. Carrier stays Go's node so only the reflector changes.
	if [ -n "${RUST_NODE:-}" ]; then
		step "6/6  cross-impl — reflector is RUST's node (Go client × Rust responder, under NAT)"
		bash scripts/punch-nat-harness.sh --rust-reflector "$RUST_NODE" --crossimpl "$RUST_PUNCH"
		mark $? "cross-impl NAT harness (rust reflector)"
	else
		step "6/6  rust-reflector — SKIPPED (set RUST_NODE=<path to entity-signaling-node> to run it)"
	fi
else
	step "5/6  cross-impl — SKIPPED (set RUST_PUNCH=<path to rust signaling-punch> to run it)"
fi

echo
if [ "$FAIL" -eq 0 ]; then
	echo "FULL PUNCH VALIDATION SUITE: PASS (G0–G3; G4 = real networks, operator infra)"
	[ -n "${RUST_PUNCH:-}" ] || echo "  (cross-impl stage skipped — this run gates Go only)"
	exit 0
fi
echo "FULL PUNCH VALIDATION SUITE: FAIL"
exit 1
