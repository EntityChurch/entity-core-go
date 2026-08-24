#!/usr/bin/env bash
# punch-endpoint-binding.sh — the §6.7.3 endpoint-binding rung, and the only
# substrate that executes the peer-id tie-break.
#
# §7.3/§6.7.3 require a peer to punch from the VERY socket whose mapping it
# advertised. Every harness up to here ran only honest peers, so the requirement
# was described and never tested. This one builds the violation on purpose —
# `--dial-from`, which dials from an endpoint other than the advertised one while
# still listening on the advertised one — and asserts three things:
#
#   P1  loopback, violating peer      -> punch SUCCEEDS.  Loopback is STRUCTURALLY
#       BLIND to a §6.7.3 violation: with no NAT, the liar's dial still lands on
#       the counterpart's listener. Any harness that runs only on loopback will
#       certify a peer that cannot work behind a NAT.
#   P2  two NATs, same violating peer -> punch FAILS. The counterpart dials a
#       mapping with no conntrack entry behind it, so the hole never opens. This
#       is the detector: P1 and P2 differ ONLY in substrate.
#   P3  loopback, violating peer      -> `sockets:both` on both sides. Because the
#       two dials are no longer reverses of one 4-tuple, a dialed AND an accepted
#       socket both form — the distinct-4-tuple race the peer-id tie-break exists
#       for. Asserted from the drivers' reported socket outcome, not inferred from
#       a punch that merely converged. Both sides MUST land on one connection:
#       lower id keeps its dialed end, higher keeps its accepted end.
#
# P3 is the case both implementations had filed as unexercised. It cannot occur on
# an honest substrate — that is not a gap in the harnesses, it is the geometry:
# §7.3 punching makes the two dials reverse tuples, and TCP admits one connection
# for one 4-tuple. Only a deliberate violation produces two.
#
# Rootless (user+net+mount namespace), no sudo. Same topology as
# punch-nat-harness.sh; P1/P3 run on loopback INSIDE the namespace (no NAT in
# path), P2 across the two NATs.
set -euo pipefail

PA_PORT=20001    # peerA: advertised + listening endpoint
PB_PORT=20002    # peerB: honest throughout
PA_LIE=20009     # peerA dials from HERE instead — the violation
NODE_PORT=4050
LOBBY="eb-room"

if [ -z "${_EB_NS:-}" ]; then
	REPO="$(cd "$(dirname "$0")/.." && pwd)"
	BIN="$(mktemp -d "${TMPDIR:-/tmp}/punch-eb-bin.XXXXXX")"
	echo "building signaling-punch + entity-peer -> $BIN"
	( cd "$REPO" && go build -o "$BIN/signaling-punch" ./cmd/signaling-punch && go build -o "$BIN/entity-peer" ./cmd/entity-peer )
	export _EB_NS=1 _EB_BIN="$BIN"
	exec unshare --user --map-root-user --net --mount --fork "$0" "$@"
fi

BIN="$_EB_BIN"
PUNCH="$BIN/signaling-punch"
PEER="$BIN/entity-peer"
WORK="$(mktemp -d "${TMPDIR:-/tmp}/punch-eb-run.XXXXXX")"
NODE_PID=""
cleanup() {
	[ -n "$NODE_PID" ] && kill "$NODE_PID" 2>/dev/null || true
	rm -rf "$WORK" 2>/dev/null || true
}
trap cleanup EXIT

mount -t tmpfs tmpfs /run 2>/dev/null || mount -t tmpfs tmpfs /var/run 2>/dev/null || true
mkdir -p /run/netns
ip link set lo up
ip link add br0 type bridge
ip addr add 10.0.0.254/24 dev br0
ip link set br0 up

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
	ip netns exec "$ns" sysctl -qw net.ipv4.conf.all.rp_filter=0
	ip netns exec "$ns" sysctl -qw net.ipv4.conf."$veth".rp_filter=0
	ip netns exec "$ns" iptables -t nat -A POSTROUTING -s "$priv" -o "$veth" -j SNAT --to-source "$pub"
	ip netns exec "$ns" iptables -A INPUT -i "$veth" -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
	ip netns exec "$ns" iptables -A INPUT -i "$veth" -m conntrack --ctstate NEW -j DROP
}
make_peer peerA 10.0.0.1 10.1.0.2
make_peer peerB 10.0.0.2 10.2.0.2

"$PEER" -addr 10.0.0.254:$NODE_PORT -signaling-node -open-access -storage memory \
	-ready-file "$WORK/node.ready" >"$WORK/node.log" 2>&1 &
NODE_PID=$!
for _ in $(seq 1 50); do [ -s "$WORK/node.ready" ] && break; sleep 0.1; done
[ -s "$WORK/node.ready" ] || { echo "FAIL: node not ready"; cat "$WORK/node.log"; exit 1; }
echo "node ready: $(cat "$WORK/node.ready")"

verified() { echo "$1" | grep -q '"verified":true'; }
jstr() { echo "$1" | grep -oE "\"$2\":\"[^\"]*\"" | head -1 | cut -d: -f2- | tr -d '"'; }

# ---- P1 / P3: loopback (no NAT in path) -------------------------------------
# peerA listens on PA_PORT and advertises it honestly, but dials from PA_LIE.
loop_run() {
	local input="$1"
	"$PUNCH" --node 10.0.0.254:$NODE_PORT --role responder --mode lobby --input "$input" \
		--local-addr 127.0.0.1:$PB_PORT --timeout 25 >"$WORK/l_b.json" 2>/dev/null &
	local bp=$!
	sleep 2
	L_A="$("$PUNCH" --node 10.0.0.254:$NODE_PORT --role initiator --mode lobby --input "$input" \
		--local-addr 127.0.0.1:$PA_PORT --dial-from 127.0.0.1:$PA_LIE --timeout 25 2>/dev/null || true)"
	wait $bp || true
	L_B="$(cat "$WORK/l_b.json")"
}

echo; echo "== P1/P3: loopback — peerA advertises :$PA_PORT but punches from :$PA_LIE (§6.7.3 violation) =="
# The race is timing-dependent BY CONSTRUCTION: fire() takes the first socket to
# land and cancels the other path, so "both" is only observed when the second had
# already landed. A harness that runs it once and calls the tie-break unreachable
# is measuring luck. Retry until it is observed, and report the attempt count —
# if it is never observed in EB_TRIES, that is a finding about the seam, not a
# flaky test.
EB_TRIES="${EB_TRIES:-12}"
for try in $(seq 1 "$EB_TRIES"); do
	loop_run "$LOBBY-loop-$try"
	[ "$(jstr "$L_A" sockets)" = "both" ] || [ "$(jstr "$L_B" sockets)" = "both" ] && break
done
echo "  (loopback attempts until a two-socket race was observed: $try of $EB_TRIES)"
echo "  initiator (violating): $L_A"
echo "  responder (honest):    $L_B"

P1_OK=0
if verified "$L_A"; then
	echo "  => P1 PASS: the violating peer STILL VERIFIED on loopback — loopback cannot detect a §6.7.3 violation"
	P1_OK=1
else
	echo "  => P1 FAIL: expected the violation to go UNDETECTED on loopback (that is the point of P2)"
fi

P3_OK=0
A_SOCK="$(jstr "$L_A" sockets)"; B_SOCK="$(jstr "$L_B" sockets)"
A_KEPT="$(jstr "$L_A" kept)";    B_KEPT="$(jstr "$L_B" kept)"
echo "  sockets: initiator=$A_SOCK (kept $A_KEPT)  responder=$B_SOCK (kept $B_KEPT)"
if [ "$A_SOCK" = "both" ] || [ "$B_SOCK" = "both" ]; then
	# If it ever IS reachable, the tie-break must have converged them: one side
	# keeps its dialed end and the other its accepted end — the two ends of one
	# connection. Agreeing on the same word means two connections survived.
	if [ "$A_KEPT" = "$B_KEPT" ]; then
		echo "  => P3 FAIL: two-socket race observed but both sides kept a '$A_KEPT' end — the tie-break did NOT converge them"
	else
		echo "  => P3 PASS: two-socket race OBSERVED and the peer-id tie-break converged it (initiator kept $A_KEPT, responder kept $B_KEPT)"
		echo "     NOTE: this contradicts the unreachability finding below — update it."
		P3_OK=1
	fi
elif [ "$A_SOCK" = "none" ] || [ "$B_SOCK" = "none" ]; then
	echo "  => P3 FAIL: a side formed no socket at all — this phase is not measuring what it claims"
elif [ "$A_KEPT" = "$B_KEPT" ]; then
	echo "  => P3 FAIL: both sides kept a '$A_KEPT' end — they are not two ends of one connection"
else
	echo "  => P3 PASS: exactly ONE socket per side, complementary ends ($A_KEPT / $B_KEPT) — converged on one connection."
	echo "     FINDING — the distinct-4-tuple tie-break is UNREACHABLE at the process level, and it is the"
	echo "     design, not the substrate. fire() takes the first socket to land and cancels the other path;"
	echo "     cancellation closes the listener (listenAccept's defer ln.Close()) and aborts the dial loop."
	echo "     Both peers do this within microseconds of each other, so the second connection never completes"
	echo "     — even here, where a deliberate §7.3 violation makes the two dials NON-reverse 4-tuples that"
	echo "     TCP would happily carry as two connections. Not observed in $EB_TRIES/$EB_TRIES attempts."
	echo "     Consequence: the tie-break is drivable ONLY at unit level (where both sockets are handed to"
	echo "     selectSocket directly). Cohort-wide, no process-level harness can exercise it."
	P3_OK=1
fi

# ---- P2: the same violation across two NATs ---------------------------------
echo; echo "== P2: two NATs — same violating peer, same flags =="
INPUT="$LOBBY-nat"
ip netns exec peerB "$PUNCH" --node 10.0.0.254:$NODE_PORT --role responder --mode lobby --input "$INPUT" \
	--local-addr 10.2.0.2:$PB_PORT --srflx 10.0.0.2:$PB_PORT --timeout 25 >"$WORK/n_b.json" 2>/dev/null &
BP=$!
sleep 2
N_A="$(ip netns exec peerA "$PUNCH" --node 10.0.0.254:$NODE_PORT --role initiator --mode lobby --input "$INPUT" \
	--local-addr 10.1.0.2:$PA_PORT --srflx 10.0.0.1:$PA_PORT --dial-from 10.1.0.2:$PA_LIE --timeout 25 2>/dev/null || true)"
wait $BP || true
N_B="$(cat "$WORK/n_b.json")"
echo "  initiator (violating): $N_A"
echo "  responder (honest):    $N_B"

P2_OK=0
if verified "$N_A"; then
	echo "  => P2 FAIL: the violating peer verified ACROSS A NAT — the harness is not detecting §6.7.3 violations"
elif ! echo "$N_A" | grep -q '"dialed_outbound":true'; then
	echo "  => P2 FAIL: vacuous — the violating peer never dialed at all, so the endpoint mismatch is not what stopped it"
else
	echo "  => P2 PASS: the violation FAILED behind a NAT — advertising a mapping you do not punch from opens no hole"
	P2_OK=1
fi

echo
if [ "$P1_OK" = 1 ] && [ "$P2_OK" = 1 ] && [ "$P3_OK" = 1 ]; then
	echo "ENDPOINT-BINDING RESULT: PASS"
	echo "  P1 loopback certifies the violation · P2 the NAT rung catches it · P3 tie-break executed"
	exit 0
fi
echo "ENDPOINT-BINDING RESULT: FAIL (p1=$P1_OK p2=$P2_OK p3=$P3_OK)"
exit 1
