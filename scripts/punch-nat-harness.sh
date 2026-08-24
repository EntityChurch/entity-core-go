#!/usr/bin/env bash
# punch-nat-harness.sh — G3: the emulated dual-NAT hole-punch gate.
#
# Validates the §7.1-step-4 dual-hole fix for real — the thing loopback CANNOT
# prove. Two peers sit behind independent stateful NATs; a peer's inbound SYN is
# delivered only if that peer has already dialed OUT (creating a conntrack entry —
# "opening its hole"). So:
#
#   - positive: both peers dial (G1) → both holes open → the punch traverses.
#   - negative: one peer is listen-only (--suppress-dial, the pre-G1 shape) → its
#     hole never opens → the counterpart's SYN is dropped → the punch MUST fail.
#
# The negative control is the load-bearing half: it proves the harness can tell a
# one-dials build from a two-dials build, which loopback (no NAT) never can.
#
# Rootless: runs under a user+net+mount namespace (unshare --map-root-user), so it
# needs NO sudo. Topology (all inside the unshared net ns):
#
#     peerA netns                 root netns (bridge)              peerB netns
#   dummy0 10.1.0.2/32   br0 10.0.0.254/24 == node/reflector   dummy0 10.2.0.2/32
#   vethA  10.0.0.1/24  <->      (10.0.0.0/24)      <->        vethB  10.0.0.2/24
#   SNAT 10.1.0.2->10.0.0.1                                    SNAT 10.2.0.2->10.0.0.2
#   app binds 10.1.0.2 (private); public 10.0.0.1 has no listener, so an
#   unsolicited inbound reaches the app ONLY via conntrack reverse-SNAT = the hole.
#
# The node (entity-peer --signaling-node) is BOTH the rendezvous lobby and the
# §6.7.1 observe-address reflector; it lives on the bridge, reachable by both.
# srflx is static here (SNAT preserves the port), so the driver advertises
# 10.0.0.N:PORT via --srflx; reflector-based gathering is a later refinement and
# does not change what the dual hole proves.
set -euo pipefail

# ---- cross-impl mode (`--crossimpl <path-to-rust-signaling-punch>`) ----------
#
# Same §3.1 CLI/JSON contract, a different binary in peerB — so peerB becomes a
# Rust peer and the crossing is Go↔Rust across the SAME two-NAT topology Go↔Go
# runs. Both drivers take the same flags (`--srflx`, `--suppress-dial`,
# `--debug`); the binary is the only difference left.
#
# Both role directions are gated, and so are BOTH negative controls — each impl
# gets a turn at being the listen-only side, because a suppressed Rust side only
# proves anything behind a NAT (on loopback it still completes: no hole is needed,
# so nothing can fail). Verification follows the §3.1 per-role `verified` pin —
# see xi_ok below.
PA_PORT=20001   # peerA punch port (preserved across its SNAT)
PB_PORT=20002
NODE_PORT=4050
LOBBY="g3-room"
# Survives the stage-1 re-exec via the environment: the flag parse below consumes
# "$@", so the namespace child would otherwise come up in Go↔Go mode.
CROSSIMPL="${_PUNCH_CROSSIMPL:-}"
# --reflector: both drivers DISCOVER their mapping from the node's §6.7.1
# observe-address responder instead of being handed it via --srflx. The node
# already sits on the bridge and sees each peer's post-SNAT source, so it is the
# reflector. This is the fidelity rung: with an asserted mapping the advertised
# candidate and the bind agree by construction even if the NAT disagrees with
# both, so a §6.7.3 violation is structurally undetectable. Discovered, it isn't.
REFLECT="${_PUNCH_REFLECT:-}"
# --rust-reflector <entity-signaling-node>: run RUST's node as the §6.7.1
# responder on the bridge, so the reflector is the OTHER implementation. Closes
# the client×responder matrix edge that only ever ran on loopback: Go's
# observe-address client vs Rust's responder, with a real NAT in between — the
# case where a wrong answer means advertising a hole that never opens. The
# carrier stays Go's node so exactly one variable moves.
RUST_REFLECTOR="${_PUNCH_RUST_REFLECTOR:-}"
REFLECTOR_ADDR="10.0.0.254:4050"
RNODE_PORT=4051

while [ $# -gt 0 ]; do
	case "$1" in
		--crossimpl) CROSSIMPL="$2"; shift 2 ;;
		--reflector) REFLECT=1; shift ;;
		--rust-reflector) REFLECT=1; RUST_REFLECTOR="$2"; shift 2 ;;
		-h|--help) sed -n '2,30p' "$0"; exit 0 ;;
		*) echo "unknown flag: $1" >&2; exit 2 ;;
	esac
done

# ---- stage 1: re-exec inside a rootless user+net+mount namespace -------------
if [ -z "${_PUNCH_NS:-}" ]; then
	# Build the binaries on the host (module cache, toolchain) BEFORE entering the
	# namespace, into a temp dir the inner run reads.
	REPO="$(cd "$(dirname "$0")/.." && pwd)"
	BIN="$(mktemp -d "${TMPDIR:-/tmp}/punch-nat-bin.XXXXXX")"
	echo "building signaling-punch + entity-peer -> $BIN"
	( cd "$REPO" && go build -o "$BIN/signaling-punch" ./cmd/signaling-punch && go build -o "$BIN/entity-peer" ./cmd/entity-peer )
	if [ -n "$CROSSIMPL" ]; then
		[ -x "$CROSSIMPL" ] || { echo "FAIL: --crossimpl binary not executable: $CROSSIMPL" >&2; exit 1; }
		# Copy it in: the namespace child re-reads by path, and a path under a
		# caller's tree can vanish or be rebuilt mid-run.
		cp "$CROSSIMPL" "$BIN/signaling-punch-rust"
		echo "cross-impl peer: $CROSSIMPL"
	fi
	if [ -n "$RUST_REFLECTOR" ]; then
		[ -x "$RUST_REFLECTOR" ] || { echo "FAIL: --rust-reflector binary not executable: $RUST_REFLECTOR" >&2; exit 1; }
		cp "$RUST_REFLECTOR" "$BIN/signaling-node-rust"
		echo "rust reflector: $RUST_REFLECTOR"
	fi
	export _PUNCH_NS=1 _PUNCH_BIN="$BIN" _PUNCH_CROSSIMPL="$CROSSIMPL" _PUNCH_REFLECT="$REFLECT" _PUNCH_RUST_REFLECTOR="$RUST_REFLECTOR"
	# --mount-proc keeps /proc sane; --fork so unshare waits for us.
	exec unshare --user --map-root-user --net --mount --fork "$0" "$@"
fi

BIN="$_PUNCH_BIN"
PUNCH="$BIN/signaling-punch"
PEER="$BIN/entity-peer"
WORK="$(mktemp -d "${TMPDIR:-/tmp}/punch-nat-run.XXXXXX")"
NODE_PID=""

cleanup() {
	[ -n "$NODE_PID" ] && kill "$NODE_PID" 2>/dev/null || true
	[ -n "${RNODE_PID:-}" ] && kill "$RNODE_PID" 2>/dev/null || true
	rm -rf "$WORK" 2>/dev/null || true
	# netns/bridge vanish with the namespace on exit.
}
trap cleanup EXIT

# ---- stage 2: build the topology --------------------------------------------
# `ip netns` bind-mounts under /run/netns, but /run is not writable even as
# userns-root. In our private mount ns, overlay a fresh tmpfs on /run (permitted
# for a user namespace since tmpfs backs no host device) so netns files land.
mount -t tmpfs tmpfs /run 2>/dev/null || mount -t tmpfs tmpfs /var/run 2>/dev/null || true
mkdir -p /run/netns

ip link set lo up
ip link add br0 type bridge
ip addr add 10.0.0.254/24 dev br0
ip link set br0 up

# make_peer <name> <ns> <pubip> <privip>
make_peer() {
	local ns="$1" pub="$2" priv="$3" veth="v_$1"
	ip netns add "$ns"
	ip link add "$veth" type veth peer name "${veth}p"
	ip link set "${veth}p" master br0
	ip link set "${veth}p" up
	ip link set "$veth" netns "$ns"
	ip -n "$ns" link set lo up
	ip -n "$ns" link add dummy0 type dummy
	ip -n "$ns" addr add "$priv/32" dev dummy0
	ip -n "$ns" link set dummy0 up
	ip -n "$ns" addr add "$pub/24" dev "$veth"
	ip -n "$ns" link set "$veth" up
	# rp_filter off: reverse-SNAT delivers a packet whose dst (private) lives on
	# dummy0 while it arrives on the veth — strict RPF would drop it.
	ip netns exec "$ns" sysctl -qw net.ipv4.conf.all.rp_filter=0
	ip netns exec "$ns" sysctl -qw net.ipv4.conf."$veth".rp_filter=0
	# The NAT: source-NAT the private app addr to the public veth addr, port
	# preserved. Stateful: inbound is delivered only via a matching conntrack
	# entry (ESTABLISHED); an unsolicited NEW inbound is dropped = a closed hole.
	ip netns exec "$ns" iptables -t nat -A POSTROUTING -s "$priv" -o "$veth" -j SNAT --to-source "$pub"
	ip netns exec "$ns" iptables -A INPUT -i "$veth" -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
	ip netns exec "$ns" iptables -A INPUT -i "$veth" -m conntrack --ctstate NEW -j DROP
}

# Both peers are NATted in BOTH modes. Cross-impl used to force peerB public
# because Rust's driver could not advertise a mapping other than its bind
# address; Rust landed --srflx (8f209aa), so that carve-out is deleted rather
# than left behind a flag — cross-impl is now the same two-NAT topology Go↔Go
# runs.
make_peer peerA 10.0.0.1 10.1.0.2
make_peer peerB 10.0.0.2 10.2.0.2

# ---- stage 3: the node (lobby + reflector) on the bridge --------------------
"$PEER" -addr 10.0.0.254:$NODE_PORT -signaling-node -open-access -storage memory \
	-ready-file "$WORK/node.ready" >"$WORK/node.log" 2>&1 &
NODE_PID=$!
for _ in $(seq 1 50); do [ -s "$WORK/node.ready" ] && break; sleep 0.1; done
if [ ! -s "$WORK/node.ready" ]; then echo "FAIL: node did not become ready"; cat "$WORK/node.log"; exit 1; fi
echo "node ready: $(cat "$WORK/node.ready")"

RNODE_PID=""
if [ -n "$RUST_REFLECTOR" ]; then
	# Second bridge address so the Rust reflector is a distinct peer from the Go
	# carrier — one variable moves, not two.
	ip addr add 10.0.0.253/24 dev br0
	"$BIN/signaling-node-rust" --listen 10.0.0.253:$RNODE_PORT --open >"$WORK/rnode.log" 2>&1 &
	RNODE_PID=$!
	for _ in $(seq 1 60); do
		timeout 1 bash -c ":</dev/tcp/10.0.0.253/$RNODE_PORT" 2>/dev/null && break
		sleep 0.25
	done
	if ! timeout 1 bash -c ":</dev/tcp/10.0.0.253/$RNODE_PORT" 2>/dev/null; then
		echo "FAIL: rust reflector did not come up"; cat "$WORK/rnode.log"; exit 1
	fi
	REFLECTOR_ADDR="10.0.0.253:$RNODE_PORT"
	echo "rust reflector ready on $REFLECTOR_ADDR"
fi

# run_punch <ns> <role> <priv> <pub> <port> [extra flags...]
# Uses the phase-local $INPUT lobby so each phase gets a CLEAN rendezvous bucket —
# reusing one bucket lets a prior phase's stale blobs muddy coordination (the §4.5
# stale-request hazard), which would make the negative control fail for the wrong
# reason instead of at the punch itself.
# How this side gets its srflx: discovered from the node-as-reflector, or asserted.
mapping_args() {
	if [ -n "$REFLECT" ]; then echo "--reflector $REFLECTOR_ADDR"; else echo "--srflx $1:$2"; fi
}

run_punch() {
	local ns="$1" role="$2" priv="$3" pub="$4" port="$5"; shift 5
	ip netns exec "$ns" "$PUNCH" \
		--node 10.0.0.254:$NODE_PORT --role "$role" --mode lobby --input "$INPUT" \
		--local-addr "$priv:$port" $(mapping_args "$pub" "$port") --timeout 25 "$@"
}

# run_punch_rust <ns> <role> <priv> <pub> <port> [extra flags...]
# Identical invocation to run_punch — same §3.1 CLI, same flags, same topology.
# The only difference left between the two drivers is the binary.
run_punch_rust() {
	local ns="$1" role="$2" priv="$3" pub="$4" port="$5"; shift 5
	ip netns exec "$ns" "$BIN/signaling-punch-rust" \
		--node 10.0.0.254:$NODE_PORT --role "$role" --mode lobby --input "$INPUT" \
		--local-addr "$priv:$port" $(mapping_args "$pub" "$port") --timeout 25 "$@"
}

verified() { echo "$1" | grep -q '"verified":true'; }
# `dialed_outbound` is what makes G1 checkable — "the punch worked" is NOT the
# claim, "BOTH sides dialed and it worked" is. A build where only one side dials
# can still traverse when a NAT is permissive, so assert the field, not just the
# outcome.
dialed() { echo "$1" | grep -q '"dialed_outbound":true'; }
# Pull a string field. Field values here are ids/addrs (no embedded quotes), and
# -f2- keeps the rest of an addr's own colons intact.
jstr() { echo "$1" | grep -oE "\"$2\":\"[^\"]*\"" | head -1 | cut -d: -f2- | tr -d '"'; }
# Each side must hold *the other's* peer-id: verified+verified is also what two
# peers that each punched something ELSE would report.
cross_held() {
	local a="$1" b="$2"
	local a_id b_id a_rem b_rem
	a_id="$(jstr "$a" peer_id)"; b_id="$(jstr "$b" peer_id)"
	a_rem="$(jstr "$a" remote_peer_id)"; b_rem="$(jstr "$b" remote_peer_id)"
	[ -n "$a_id" ] && [ -n "$b_id" ] && [ "$a_rem" = "$b_id" ] && [ "$b_rem" = "$a_id" ]
}

# ---- cross-impl mode: Go (behind NAT) <-> Rust (public) ---------------------
if [ -n "$CROSSIMPL" ]; then
	# Rust reports `remote_addr`, Go reports `remote_peer_id` — the drivers do NOT
	# emit the same identity field, so "each holds the other's peer-id" is only
	# checkable Go-side. Go-side we assert it; Rust-side we assert the next best
	# thing its JSON does carry: that it punched to peerA's *public* mapping,
	# which is reachable only through the hole peerA opened.
	# §3.1 per-role `verified` pin (agreed with Rust, c5fad76):
	#   initiator.verified — the client half completed over the direct path AND an
	#     ordinary operation round-tripped on it. Positive observation. GATES.
	#   responder.verified — served the handshake, connection closed clean.
	#     Corroborating, NEVER gating: a responder never observes its own reply
	#     landing, so anything stronger it reports (session registration, pool
	#     insertion) is a fact about its own internals, not about the round trip.
	# So this harness gates on the initiator and MUST NOT require agreement. Go's
	# responder says "registered for §6.11 reentry", Rust's says "served, clean
	# EOF" — both legal, and requiring them to match is what manufactured the
	# divergence reported in the 2026-08-01 cross-impl report.
	#
	# dialed_outbound still gates on BOTH sides: that is the §7.1-step-4 dual-hole
	# MUST, and it is independent of what either side can observe about the ping.
	xi_ok() {
		local init_out="$1" resp_out="$2" go_out="$3" rs_out="$4" label="$5"
		if ! verified "$init_out"; then
			echo "  => FAIL ($label): initiator did not verify — detail=$(jstr "$init_out" detail)$(jstr "$init_out" error)"; return 1
		elif ! { dialed "$init_out" && dialed "$resp_out"; }; then
			echo "  => FAIL ($label): a side reported dialed_outbound:false — the dual hole is not what carried this"; return 1
		elif [ "$(jstr "$go_out" remote_peer_id)" != "$(jstr "$rs_out" peer_id)" ]; then
			echo "  => FAIL ($label): Go did not hold the Rust peer's id"; return 1
		fi
		if [ -n "$REFLECT" ]; then
			# Both sides must report the higher rung, and the discovered mapping must
			# be the public one. If a side silently fell back to its bind address we
			# would be advertising a private addr and calling a lucky run a pass.
			local isrc rsrc
			isrc="$(jstr "$init_out" srflx_source)"; rsrc="$(jstr "$resp_out" srflx_source)"
			if [ "$isrc" != "reflector" ] || [ "$rsrc" != "reflector" ]; then
				echo "  => FAIL ($label): srflx_source is initiator=$isrc responder=$rsrc, expected reflector on both"; return 1
			fi
			case "$(jstr "$go_out" srflx)" in
				10.0.0.*) ;;
				*) echo "  => FAIL ($label): Go discovered srflx $(jstr "$go_out" srflx), not its public 10.0.0.x mapping"; return 1 ;;
			esac
		fi
		echo "  => PASS ($label): Go↔Rust traversed TWO NATs — initiator verified, both dialed${REFLECT:+, srflx DISCOVERED via reflector}"
		verified "$resp_out" || echo "     (responder did not corroborate — non-gating per the §3.1 pin; detail=$(jstr "$resp_out" detail)$(jstr "$resp_out" error))"
		return 0
	}

	# xi_neg <initiator json> <suppressed json> <label>
	# A negative control is only worth something if it fails for the RIGHT reason.
	xi_neg() {
		local init_out="$1" supp_out="$2" label="$3"
		if verified "$init_out"; then
			echo "  => FAIL ($label): initiator verified against a listen-only peer — the NAT is not enforcing the hole, or a one-dials build would pass G3"; return 1
		elif dialed "$supp_out"; then
			echo "  => FAIL ($label): --suppress-dial did not take (suppressed side reported dialed_outbound:true)"; return 1
		elif ! dialed "$init_out"; then
			echo "  => FAIL ($label): vacuous negative — the initiator never dialed, so the closed hole was not what stopped it"; return 1
		fi
		echo "  => PASS ($label): punch correctly FAILED at the crossing — no hole, no path"
		return 0
	}

	XI_A=0 XI_B=0 XI_NEG_GO=0 XI_NEG_RS=0

	INPUT="$LOBBY-xi-a"
	echo; echo "== cross-impl positive A: Go initiator <-> Rust responder (both behind their own NAT) =="
	run_punch_rust peerB responder 10.2.0.2 10.0.0.2 $PB_PORT >"$WORK/xa_rs.json" 2>"$WORK/xa_rs.err" &
	XPID=$!
	sleep 2
	XA_GO="$(run_punch peerA initiator 10.1.0.2 10.0.0.1 $PA_PORT || true)"
	wait $XPID || true
	XA_RS="$(cat "$WORK/xa_rs.json")"
	echo "  go   (initiator): $XA_GO"
	echo "  rust (responder): $XA_RS"
	xi_ok "$XA_GO" "$XA_RS" "$XA_GO" "$XA_RS" "go-init" && XI_A=1

	INPUT="$LOBBY-xi-b"
	echo; echo "== cross-impl positive B (reverse roles): Rust initiator <-> Go responder =="
	run_punch peerA responder 10.1.0.2 10.0.0.1 $PA_PORT >"$WORK/xb_go.json" 2>"$WORK/xb_go.err" &
	XPID=$!
	sleep 2
	XB_RS="$(run_punch_rust peerB initiator 10.2.0.2 10.0.0.2 $PB_PORT || true)"
	wait $XPID || true
	XB_GO="$(cat "$WORK/xb_go.json")"
	echo "  rust (initiator): $XB_RS"
	echo "  go   (responder): $XB_GO"
	xi_ok "$XB_RS" "$XB_GO" "$XB_GO" "$XB_RS" "rust-init" && XI_B=1

	# Negative control 1: the Go side is listen-only. Its hole never opens, so the
	# Rust initiator's SYN dies at peerA's NAT.
	INPUT="$LOBBY-xi-neg-go"
	echo; echo "== cross-impl negative control 1: Go side listen-only (--suppress-dial) =="
	run_punch peerA responder 10.1.0.2 10.0.0.1 $PA_PORT --suppress-dial >"$WORK/xn_go.json" 2>"$WORK/xn_go.err" &
	XPID=$!
	sleep 2
	XN_RS="$(run_punch_rust peerB initiator 10.2.0.2 10.0.0.2 $PB_PORT || true)"
	wait $XPID || true
	XN_GO="$(cat "$WORK/xn_go.json")"
	echo "  rust (initiator): $XN_RS"
	echo "  go   (responder): $XN_GO"
	xi_neg "$XN_RS" "$XN_GO" "go-suppressed" && XI_NEG_GO=1

	# Negative control 2 — the one Rust explicitly asked for. On loopback a
	# suppressed Rust side still completes (the pre-G1 shape; no NAT, so no hole is
	# needed and nothing can fail). Behind a real NAT it MUST fail. If this PASSES,
	# the harness is not testing what we think it is.
	INPUT="$LOBBY-xi-neg-rs"
	echo; echo "== cross-impl negative control 2: RUST side listen-only (--suppress-dial) =="
	run_punch_rust peerB responder 10.2.0.2 10.0.0.2 $PB_PORT --suppress-dial >"$WORK/xn_rs.json" 2>"$WORK/xn_rs.err" &
	XPID=$!
	sleep 2
	XNG_GO="$(run_punch peerA initiator 10.1.0.2 10.0.0.1 $PA_PORT || true)"
	wait $XPID || true
	XNR_RS="$(cat "$WORK/xn_rs.json")"
	echo "  go   (initiator): $XNG_GO"
	echo "  rust (responder): $XNR_RS"
	xi_neg "$XNG_GO" "$XNR_RS" "rust-suppressed" && XI_NEG_RS=1

	echo
	if [ "$XI_A" = 1 ] && [ "$XI_B" = 1 ] && [ "$XI_NEG_GO" = 1 ] && [ "$XI_NEG_RS" = 1 ]; then
		echo "CROSS-IMPL NAT RESULT: PASS — Go↔Rust traverses TWO NATs in BOTH role directions,"
		echo "  and BOTH negative controls fail as required (each impl's listen-only build is caught)."
		exit 0
	fi
	echo "CROSS-IMPL NAT RESULT: FAIL (go-init=$XI_A rust-init=$XI_B neg-go=$XI_NEG_GO neg-rust=$XI_NEG_RS)"
	exit 1
fi

# ---- stage 4: POSITIVE — both dial, the punch must traverse both NATs --------
INPUT="$LOBBY-pos"
echo; echo "== positive: both peers dial =="
run_punch peerB responder 10.2.0.2 10.0.0.2 $PB_PORT >"$WORK/b.json" 2>"$WORK/b.err" &
BPID=$!
sleep 2
A_OUT="$(run_punch peerA initiator 10.1.0.2 10.0.0.1 $PA_PORT || true)"
wait $BPID || true
B_OUT="$(cat "$WORK/b.json")"
echo "  initiator: $A_OUT"
echo "  responder: $B_OUT"

POS_OK=0
if ! { verified "$A_OUT" && verified "$B_OUT"; }; then
	echo "  => FAIL: expected both sides verified across the NATs"
elif ! { dialed "$A_OUT" && dialed "$B_OUT"; }; then
	# Traversed, but not by the dual hole — exactly the regression G1 fixed.
	echo "  => FAIL: both verified but a side reported dialed_outbound:false — the dual hole is NOT what carried this"
elif ! cross_held "$A_OUT" "$B_OUT"; then
	echo "  => FAIL: peers did not cross-hold ids (initiator.remote != responder.peer_id, or vice versa)"
else
	echo "  => PASS: punch traversed two NATs — both dialed, both verified, ids cross-held"
	POS_OK=1
fi

# ---- stage 5: NEGATIVE control — responder listen-only, punch MUST fail ------
INPUT="$LOBBY-neg"
echo; echo "== negative control: responder is listen-only (--suppress-dial) =="
run_punch peerB responder 10.2.0.2 10.0.0.2 $PB_PORT --suppress-dial >"$WORK/bn.json" 2>"$WORK/bn.err" &
BNPID=$!
sleep 2
AN_OUT="$(run_punch peerA initiator 10.1.0.2 10.0.0.1 $PA_PORT || true)"
wait $BNPID || true
BN_OUT="$(cat "$WORK/bn.json")"
echo "  initiator: $AN_OUT"
echo "  responder: $BN_OUT"

NEG_OK=0
# A negative control is only worth something if it fails for the RIGHT reason. A
# dead node, a bad lobby key, a crashed process — all make the punch "fail" too,
# and would hand back a green G3 that proves nothing. So three guards beyond
# not-verified: the initiator must have reached the crossing (it learned B's
# candidate through the node — its error names that exact public addr), it must
# actually have dialed, and suppression must demonstrably have taken.
if verified "$AN_OUT"; then
	echo "  => FAIL: initiator verified against a listen-only peer — the NAT is not enforcing the hole, or a one-dials build would pass G3"
elif ! echo "$AN_OUT" | grep -q "10.0.0.2:$PB_PORT"; then
	echo "  => FAIL: vacuous negative — initiator never learned the responder's candidate, so this failed at coordination, not at the hole"
elif ! dialed "$AN_OUT"; then
	echo "  => FAIL: vacuous negative — initiator never dialed, so the closed hole was not what stopped it"
elif dialed "$BN_OUT"; then
	echo "  => FAIL: --suppress-dial did not take (responder reported dialed_outbound:true) — this is not a listen-only build"
else
	echo "  => PASS: punch correctly FAILED at the crossing — a listen-only side never opens its hole (dual-hole MUST holds)"
	NEG_OK=1
fi

echo
if [ "$POS_OK" = 1 ] && [ "$NEG_OK" = 1 ]; then
	echo "G3 RESULT: PASS (positive traverses, negative control fails as required)"
	exit 0
fi
echo "G3 RESULT: FAIL (positive=$POS_OK negative=$NEG_OK)"
exit 1
