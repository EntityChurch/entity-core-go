#!/usr/bin/env bash
# punch-nat-type.sh — the §6.7.1 / §11.2 NAT-type detection rung.
#
# EXTENSION-SIGNALING §11.2 SHOULDs — and §9.3 states as a MUST — that a peer
# consults SEVERAL reflectors and requires agreement before concluding a NAT
# type. §6.7.1: agreement ⇒ endpoint-independent mapping ⇒ punchable;
# disagreement ⇒ the mapping differs per destination ⇒ symmetric ⇒ prefer relay.
#
# This gates the detector against a NAT that really behaves each way. The three
# phases differ ONLY in the NAT's mapping policy — same driver, same flags, same
# socket discipline — so a green P1 next to a red P2 is a statement about the
# detector, not about the topology.
#
#   P1  port-preserving SNAT          -> class=endpoint-independent, punchable
#   P2  per-destination SNAT          -> class=endpoint-dependent,  relay-only
#   P3  one reflector, cone NAT       -> class=unknown, exit 1 (the §6.7.1 refusal)
#
# P3 is the load-bearing one. Without it the tool could "conclude" from a single
# reflector and P1 would still be green — the MUST would be a comment rather than
# behaviour. It asserts the detector REFUSES a verdict it is not entitled to.
#
# WHAT IS EMULATED, STATED PLAINLY (§11.5.1 — a claim is scoped by its
# substrate). P2 is not a carrier's symmetric NAT; it is iptables rules that map
# the same socket to a different public port per destination. That mapping policy
# IS the symmetric property, and it is what the detector reads — but it is
# deterministic and small, and it does not reproduce CGNAT allocation behaviour,
# port-preservation heuristics, or a real carrier's mapping lifetime. This rung
# proves the detector classifies each policy correctly. It does NOT prove any
# real network is one or the other; that is G4.
#
# Rootless — user+net+mount namespace, no sudo. Topology (all inside the ns):
#
#      probe netns                       root netns (bridge)
#   dummy0 10.1.0.2/32          br0 10.0.0.254/24 == reflector R1
#   veth   10.0.0.1/24   <->    br0 10.0.0.253/24 == reflector R2
#   SNAT policy per phase             (two INDEPENDENT reflectors, which is the
#                                      whole point: one cannot corroborate itself)
set -euo pipefail

# ---- cross-impl mode (`--crossimpl <path-to-rust-signaling-punch>`) ----------
#
# Runs the SAME three phases with the sibling's binary against the SAME two
# reflectors. This is the rung's whole point for the cohort: a classifier can be
# unit-tested against authored vectors in either tree, but no unit test can
# produce a per-destination mapping — only this substrate can. Until a driver has
# run here, its `endpoint-dependent` is an assertion about its own vectors.
CROSSIMPL="${_NATTYPE_CROSSIMPL:-}"

PRIV=10.1.0.2
PUB=10.0.0.1
R1_ADDR="10.0.0.254:4050"
R2_ADDR="10.0.0.253:4052"
# A fresh local port per phase, deliberately. The probe pins one socket and dials
# both reflectors from it (§6.7.3); conntrack entries from a previous phase
# outlive the connection, and reusing the port would let a stale mapping answer
# for the new NAT policy — P2 would inherit P1's verdict and look like a pass.
# The cross-impl driver gets its own port block for the same reason.
P1_PORT=20001
P2_PORT=20002
P3_PORT=20003
XI_OFFSET=10

while [ $# -gt 0 ]; do
	case "$1" in
		--crossimpl) CROSSIMPL="$2"; shift 2 ;;
		-h|--help) sed -n '2,40p' "$0"; exit 0 ;;
		*) echo "unknown flag: $1" >&2; exit 2 ;;
	esac
done

# ---- stage 1: re-exec inside a rootless user+net+mount namespace -------------
if [ -z "${_NATTYPE_NS:-}" ]; then
	REPO="$(cd "$(dirname "$0")/.." && pwd)"
	BIN="$(mktemp -d "${TMPDIR:-/tmp}/nat-type-bin.XXXXXX")"
	echo "building signaling-punch + entity-peer -> $BIN"
	( cd "$REPO" && go build -o "$BIN/signaling-punch" ./cmd/signaling-punch && go build -o "$BIN/entity-peer" ./cmd/entity-peer )
	if [ -n "$CROSSIMPL" ]; then
		[ -x "$CROSSIMPL" ] || { echo "FAIL: --crossimpl binary not executable: $CROSSIMPL" >&2; exit 1; }
		# Copied in: the namespace child re-reads by path, and a path under a
		# caller's tree can vanish or be rebuilt mid-run.
		cp "$CROSSIMPL" "$BIN/signaling-punch-rust"
		echo "cross-impl driver: $CROSSIMPL"
	fi
	export _NATTYPE_NS=1 _NATTYPE_BIN="$BIN" _NATTYPE_CROSSIMPL="$CROSSIMPL"
	exec unshare --user --map-root-user --net --mount --fork "$0" "$@"
fi

BIN="$_NATTYPE_BIN"
PUNCH="$BIN/signaling-punch"
PEER="$BIN/entity-peer"
WORK="$(mktemp -d "${TMPDIR:-/tmp}/nat-type-run.XXXXXX")"
R1_PID=""; R2_PID=""

cleanup() {
	[ -n "$R1_PID" ] && kill "$R1_PID" 2>/dev/null || true
	[ -n "$R2_PID" ] && kill "$R2_PID" 2>/dev/null || true
	rm -rf "$WORK" 2>/dev/null || true
}
trap cleanup EXIT

# ---- stage 2: topology -------------------------------------------------------
mount -t tmpfs tmpfs /run 2>/dev/null || mount -t tmpfs tmpfs /var/run 2>/dev/null || true
mkdir -p /run/netns

ip link set lo up
ip link add br0 type bridge
ip addr add 10.0.0.254/24 dev br0
# The second reflector is a second ADDRESS on the bridge, not a second interface:
# two independent responders the probe reaches by two distinct destinations,
# which is exactly what a destination-dependent mapping needs to be visible.
ip addr add 10.0.0.253/24 dev br0
ip link set br0 up

ip netns add probe
ip link add v_probe type veth peer name v_probep
ip link set v_probep master br0
ip link set v_probep up
ip link set v_probe netns probe
ip -n probe link set lo up
ip -n probe link add dummy0 type dummy
ip -n probe addr add "$PRIV/32" dev dummy0
ip -n probe link set dummy0 up
ip -n probe addr add "$PUB/24" dev v_probe
ip -n probe link set v_probe up
ip netns exec probe sysctl -qw net.ipv4.conf.all.rp_filter=0
ip netns exec probe sysctl -qw net.ipv4.conf.v_probe.rp_filter=0

# nat_cone: one mapping for every destination — port preserved. The punchable case.
nat_cone() {
	ip netns exec probe iptables -t nat -F POSTROUTING
	ip netns exec probe iptables -t nat -A POSTROUTING -s "$PRIV" -o v_probe -j SNAT --to-source "$PUB"
}

# nat_symmetric: the SAME socket gets a DIFFERENT public port depending on where
# it is going. That is the symmetric property in one sentence, and it is why a
# punch cannot work: whatever this peer advertises names a mapping created for
# the reflector, never for the counterpart.
nat_symmetric() {
	ip netns exec probe iptables -t nat -F POSTROUTING
	ip netns exec probe iptables -t nat -A POSTROUTING -s "$PRIV" -p tcp -d 10.0.0.254 -o v_probe -j SNAT --to-source "$PUB:41000-41000"
	ip netns exec probe iptables -t nat -A POSTROUTING -s "$PRIV" -p tcp -d 10.0.0.253 -o v_probe -j SNAT --to-source "$PUB:52000-52000"
}

# ---- stage 3: the two reflectors on the bridge -------------------------------
"$PEER" -addr "$R1_ADDR" -signaling-node -open-access -storage memory \
	-ready-file "$WORK/r1.ready" >"$WORK/r1.log" 2>&1 &
R1_PID=$!
"$PEER" -addr "$R2_ADDR" -signaling-node -open-access -storage memory \
	-ready-file "$WORK/r2.ready" >"$WORK/r2.log" 2>&1 &
R2_PID=$!
for _ in $(seq 1 60); do
	[ -s "$WORK/r1.ready" ] && [ -s "$WORK/r2.ready" ] && break
	sleep 0.1
done
for r in r1 r2; do
	if [ ! -s "$WORK/$r.ready" ]; then echo "FAIL: reflector $r did not become ready"; cat "$WORK/$r.log"; exit 1; fi
done
echo "reflectors ready: R1=$R1_ADDR R2=$R2_ADDR"

# probe_nat <driver> <port> <reflectors-csv>  -> JSON on stdout, exit code preserved
probe_nat() {
	ip netns exec probe "$1" --nat-type \
		--local-addr "$PRIV:$2" --reflectors "$3" --timeout 20
}

# Trailing `|| true`: a MISSING field is a legitimate answer here (P3's refusal
# carries no `class` at all), and under `set -euo pipefail` grep's exit 1 would
# otherwise kill the run at the exact moment the assertion was about to be made.
jstr() { echo "$1" | grep -oE "\"$2\":\"[^\"]*\"" | head -1 | cut -d: -f2- | tr -d '"' || true; }
jflag() { echo "$1" | grep -q "\"$2\":$3"; }

FAILED=0
report() { # <phase> <ok|fail> <detail>
	if [ "$2" = ok ]; then echo "  => PASS ($1): $3"; else echo "  => FAIL ($1): $3"; FAILED=1; fi
}

# run_phases <driver-binary> <label> <port-base-offset>
# The same three phases, driven by whichever binary is passed. Both impls answer
# on the SAME reflectors under the SAME NAT policies, so a divergence is the
# driver's and nothing else's.
run_phases() {
	local drv="$1" label="$2" off="$3"
	local p1=$((P1_PORT + off)) p2=$((P2_PORT + off)) p3=$((P3_PORT + off))
	local OUT CLASS MAP RC

	# ---- P1: port-preserving SNAT — the punchable case -----------------------
	echo
	echo "== [$label] P1: port-preserving SNAT, two reflectors =="
	nat_cone
	OUT="$(probe_nat "$drv" "$p1" "$R1_ADDR,$R2_ADDR" || true)"
	echo "  $OUT"
	CLASS="$(jstr "$OUT" class)"; MAP="$(jstr "$OUT" mapping)"
	if [ "$CLASS" = "endpoint-independent" ] && jflag "$OUT" punchable true && [ "$MAP" = "$PUB:$p1" ]; then
		report "$label/P1" ok "both reflectors observed $MAP — endpoint-independent, punchable"
	else
		report "$label/P1" fail "class=$CLASS mapping=$MAP, expected endpoint-independent at $PUB:$p1"
	fi

	# ---- P2: per-destination SNAT — the relay-only case ----------------------
	# The phase no unit test in ANY tree can substitute for: a classifier can be
	# fed authored divergent vectors in-process, but only a real NAT policy can
	# produce them. Until a driver has run this, its endpoint-dependent verdict
	# is an assertion about its own test data.
	echo
	echo "== [$label] P2: per-destination SNAT (the symmetric mapping policy), two reflectors =="
	nat_symmetric
	OUT="$(probe_nat "$drv" "$p2" "$R1_ADDR,$R2_ADDR" || true)"
	echo "  $OUT"
	CLASS="$(jstr "$OUT" class)"
	if [ "$CLASS" = "endpoint-dependent" ] && jflag "$OUT" punchable false; then
		report "$label/P2" ok "the mapping differed per destination and the detector said relay-only: $(jstr "$OUT" reason)"
	else
		report "$label/P2" fail "class=$CLASS, expected endpoint-dependent (punchable=false)"
	fi

	# ---- P3: one reflector — the refusal -------------------------------------
	# §6.7.1: "a single reflector is advisory, never trusted." The NAT here is the
	# cone from P1, so the observation is CORRECT and a tool that concluded from it
	# would even be right — and still wrong, because being right by luck on an
	# untrusted single source is the failure this MUST exists to prevent.
	#
	# The assertion is the FULL converged shape — class=="unknown" AND ok:false AND
	# a non-zero exit. It deliberately does NOT accept an error-text refusal: both
	# impls once refused correctly in different shapes (one rejected at the CLI
	# arity check with no `class` field at all, one probed and let the classifier
	# refuse), so a harness keying on either alone passed one binary and failed the
	# other. Gating all three is what keeps the shapes converged.
	echo
	echo "== [$label] P3: one reflector on the same cone NAT — must REFUSE to conclude =="
	nat_cone
	set +e
	OUT="$(probe_nat "$drv" "$p3" "$R1_ADDR" 2>&1)"
	RC=$?
	set -e
	echo "  $OUT"
	CLASS="$(jstr "$OUT" class)"
	if [ $RC -ne 0 ] && [ "$CLASS" = "unknown" ] && jflag "$OUT" ok false; then
		report "$label/P3" ok "probed the one reflector, reported the observation, refused the verdict (class=unknown, ok=false, exit $RC)"
	else
		report "$label/P3" fail "exit=$RC class=$CLASS, expected class=unknown + ok:false + non-zero exit"
	fi
}

run_phases "$PUNCH" go 0
if [ -n "$CROSSIMPL" ]; then
	run_phases "$BIN/signaling-punch-rust" rust "$XI_OFFSET"
fi

echo
if [ $FAILED -eq 0 ]; then
	echo -n "NAT-TYPE DETECTION (emulated): PASS — cone classified punchable, per-destination classified relay-only, single reflector refused"
	if [ -n "$CROSSIMPL" ]; then echo " [go + rust, same reflectors, same NAT policies]"; else echo " [go only]"; fi
	exit 0
fi
echo "NAT-TYPE DETECTION (emulated): FAIL"
exit 1
