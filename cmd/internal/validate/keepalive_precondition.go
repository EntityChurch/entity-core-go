package validate

import (
	"fmt"
	"sync"
	"time"
)

// Harness fail-closed for the keepalive precondition (arch ruling 2026-07-17 §4).
//
// > A probe MUST fail closed on its own misconfiguration. A validator that can
// > emit a *peer* FAIL when the *harness* is misconfigured is a false-report
// > generator. The peer verdict should be unreachable when the harness
// > precondition is unmet.
//
// The bug this closes, concretely: `-keepalive-envelope-ms 5000` is a CLAIM
// about how the target peer was started. The probes gated on the flag being
// *present* and then trusted its value. Start the peers without
// `--keepalive 2000,1000,2` and the target cannot notice a dead counterpart
// inside the window — so the probe reported "the disconnect was not detected"
// as a PEER FAIL, on all three seats at once, and nearly routed a cohort
// regression that did not exist.
//
// The flag-present gate was fail-closed against the flag being *forgotten* and
// wide open to it being *wrong*. Trusting an operator's assertion about the
// peer is the whole defect; the fix is to measure the peer instead.
//
// How: the target runs a §5.4 keepalive loop against the peers it MAINTAINS.
// The probe's own counterpart is one of them, so the target's real cadence is
// observable there via a dispatch hook — no impl internals, no target
// cooperation, nothing to keep in sync with a flag. If the pings the claimed
// envelope implies do not arrive, the harness is misconfigured and the peer is
// not judged.
//
// Measuring on the validator's own client connection does NOT work: the target
// does not ping a plain client, so every correctly-configured peer reads as
// misconfigured. That was this file's first cut, and the positive-case test
// caught it — a fail-closed check that fails closed on everything is just a
// broken probe with better manners.

// pingObservation records inbound §5.4 keepalive ping arrivals.
type pingObservation struct {
	mu    sync.Mutex
	times []time.Time
}

func (p *pingObservation) note() {
	p.mu.Lock()
	p.times = append(p.times, time.Now())
	p.mu.Unlock()
}

func (p *pingObservation) countSince(t time.Time) int {
	p.mu.Lock()
	defer p.mu.Unlock()
	n := 0
	for _, ts := range p.times {
		if ts.After(t) {
			n++
		}
	}
	return n
}

// RequireKeepaliveEnvelope verifies the harness precondition that
// -keepalive-envelope-ms asserts: that the TARGET is actually configured with a
// keepalive fast enough to notice a dead counterpart inside envelopeMs.
//
// MUST be called only after the target has been asked to maintain cp — the
// target pings peers it MAINTAINS, not every client that connects to it, so
// before the relationship exists there is nothing to observe. (The validator's
// own client connection sees no pings at all; measuring there reports every
// correctly-configured peer as misconfigured. Verified the hard way.)
//
// Returns nil when the precondition holds. Returns a CheckOutcome — always a
// SKIP, never a FAIL — when it does not. A skip still fails the run under
// ADR-0012 ("a skip counts as a failure"), so a misconfigured run is loudly
// red; what it does NOT do is emit a verdict about the peer. That is the
// distinction the ruling turns on: the operator learns they misconfigured the
// harness, and no false peer FAIL exists to be routed to a sibling.
//
// Cost is bounded by envelopeMs, paid once, and only on probes that depend on
// the envelope.
func RequireKeepaliveEnvelope(cp *networkCounterpart, envelopeMs int) *CheckOutcome {
	if envelopeMs <= 0 {
		out := SkipCheck("harness: pass -keepalive-envelope-ms matching the target's §2.3 envelope (interval_ms × max_missed + timeout_ms; spec defaults \u2248100000) — this probe needs the disconnect observable in seconds. Start the target with a short envelope: go run ./cmd/peer-manager start --name p1 --type go|rust|python --debug --keepalive 2000,1000,2")
		return &out
	}

	// Within one envelope (interval × max_missed + timeout) at least two pings
	// are due. Require two, so a single stray frame cannot satisfy the check.
	const wantPings = 2
	start := time.Now()
	deadline := start.Add(time.Duration(envelopeMs) * time.Millisecond)
	for time.Now().Before(deadline) {
		if cp.pings.countSince(start) >= wantPings {
			return nil
		}
		time.Sleep(50 * time.Millisecond)
	}

	// RE-COUNT AFTER THE LOOP, and it is not belt-and-braces — without it this
	// guard rejects a correctly-configured harness at the boundary.
	//
	// The loop polls every 50ms and exits on the deadline, so a ping landing
	// between the final poll and the deadline is never observed by the loop but
	// IS in the count afterwards. At the exact configuration the message asks
	// for — interval 1000ms inside a 2000ms envelope, where precisely two pings
	// are due — that window is hit routinely: measured against live rust and
	// python peers 2026-08-13, both reported `got=2 … at least 2 were due` and
	// skipped, a message that contradicts itself in the same sentence.
	//
	// The effect was that `network_reconnect_anchor` could not be driven against
	// ANY peer from a direct `validate-peer -addr` run: it skipped whatever the
	// operator did, and the skip blamed their configuration. A precondition that
	// cannot be satisfied is indistinguishable from an unimplemented surface,
	// which is the misattribution this whole file exists to prevent — one level
	// up, and pointed at the operator instead of the peer.
	if got := cp.pings.countSince(start); got >= wantPings {
		return nil
	}

	got := cp.pings.countSince(start)
	out := SkipCheck(fmt.Sprintf(
		"HARNESS MISCONFIGURED — peer verdict withheld. The target sent %d §5.4 keepalive ping(s) to the probe's counterpart in %dms; -keepalive-envelope-ms=%d claims at least %d were due. "+
			"The target is not configured with the envelope this run asserts, so it CANNOT notice a dead counterpart inside the probe window — a FAIL here would be this harness's bug reported as the peer's. "+
			"Restart the target with an envelope that fits at least %d pings — the interval MUST be at most -keepalive-envelope-ms/%d: "+
			"go run ./cmd/peer-manager start --name p1 --type go|rust|python --debug --keepalive 1000,500,2, and pass -keepalive-envelope-ms 2000. "+
			"(The advice here used to read `--keepalive 2000,1000,2` alongside a 2000ms envelope, which is interval=2000 — one ping per envelope, so following it exactly could never satisfy this guard.)",
		got, envelopeMs, envelopeMs, wantPings, wantPings, wantPings))
	return &out
}
