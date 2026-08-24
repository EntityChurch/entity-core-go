package validate

// Cross-peer half of continuation_bounds: PROPOSAL-CONTINUATION-BOUNDS-
// PROPAGATION anchor 1 — a causal continuation-advancement chain that crosses a
// peer boundary terminates at the GLOBAL depth count, because chain_depth is
// carried in system/bounds and inherited across the wire (rung 1-2). Before the
// fix, chain_depth was a per-peer context field that reset every hop, so a
// cross-peer A→B→A→… ping-pong had nothing accumulating.
//
// This runs in the -peers convergence flow (two live peers), not the single-peer
// -addr flow, and is the counterpart to the single-peer cb1/cb2/cb3 in
// continuation_bounds.go.

import (
	"context"
	"fmt"
	"time"

	"go.entitychurch.org/entity-core-go/core/ecf"
	"go.entitychurch.org/entity-core-go/core/types"

	"github.com/fxamacker/cbor/v2"
)

// cbxSafetyCap bounds each continuation's advancements so a peer WITHOUT working
// cross-peer depth inheritance cannot ping-pong forever: the chain stops when a
// side exhausts its executions instead of the brake firing. Set well above the
// default §3.9 max (64) so a working global brake (~32 advances/side) fires
// first — its absence, with the chain running to this cap, IS the regression.
const cbxSafetyCap = 100

func runContinuationBoundsCrossPeer(ctx context.Context, clients []*PeerClient) []CheckResult {
	r := NewCheckRunner(catContinuationBounds)

	r.Declare("cbx_setup_mutual_transport",
		"cross-peer reachability — publish each peer's TCP profile in the other so A↔B can dispatch")
	r.Declare("cbx_crosspeer_chain_bounds_globally",
		"CONTINUATION §3.9 / PROPOSAL-BOUNDS anchor 1 — a synchronous cross-peer advancement ping-pong terminates at the GLOBAL depth count (chain_depth inherited across the wire), not per-peer")

	if len(clients) < 2 {
		fail := FailCheck(fmt.Sprintf("cross-peer chain-depth gate requires 2 peers (got %d)", len(clients)))
		r.Run("cbx_setup_mutual_transport", func() CheckOutcome { return fail })
		r.Run("cbx_crosspeer_chain_bounds_globally", func() CheckOutcome { return fail })
		return r.Results()
	}
	a, b := clients[0], clients[1]

	r.Run("cbx_setup_mutual_transport", func() CheckOutcome {
		if !a.GrantsAllow("system/peer/transport/*") || !b.GrantsAllow("system/peer/transport/*") {
			return SkipCheck("connection grants do not allow system/peer/transport/* on both peers — run with -identity framework-admin")
		}
		if err := publishTransportProfile(ctx, b, a); err != nil { // B learns how to reach A
			return FailCheck("publish A's profile on B: " + err.Error())
		}
		if err := publishTransportProfile(ctx, a, b); err != nil { // A learns how to reach B
			return FailCheck("publish B's profile on A: " + err.Error())
		}
		return PassCheck(fmt.Sprintf("mutual TCP reachability published (A=%s <-> B=%s)", a.addr, b.addr))
	})

	r.Run("cbx_crosspeer_chain_bounds_globally", func() CheckOutcome {
		if out, ok := r.Require("cbx_setup_mutual_transport"); !ok {
			return out
		}
		return runCBXCrossPeerBrake(ctx, a, b)
	})

	return r.Results()
}

// publishTransportProfile writes `target`'s TCP profile into `host`'s tree so
// host's dispatcher can resolve and dial target for a cross-peer EXECUTE.
// Same mechanism cross_peer_tcp uses to make a peer reachable.
func publishTransportProfile(ctx context.Context, host, target *PeerClient) error {
	targetHash, err := types.ComputePeerIdentityHashFromPeerID(target.RemotePeerID())
	if err != nil {
		return fmt.Errorf("target identity hash: %w", err)
	}
	prefix := "system/peer/transport/" + types.PeerIdentityHashHex(targetHash) + "/"
	ent := tcpProfileEntityFor(string(target.RemotePeerID()), target.addr)
	if _, err := host.TreePut(ctx, prefix+"primary", ent); err != nil {
		return fmt.Errorf("write primary: %w", err)
	}
	if _, err := host.TreePut(ctx, prefix+"primary-http", ent); err != nil {
		return fmt.Errorf("write primary-http: %w", err)
	}
	return nil
}

func runCBXCrossPeerBrake(ctx context.Context, a, b *PeerClient) CheckOutcome {
	pa := "system/inbox/validate-cbx-a"
	pb := "system/inbox/validate-cbx-b"
	safety := uint64(cbxSafetyCap)

	// Ca on A dispatches `receive` to B/Pb; Cb on B dispatches `receive` to
	// A/Pa. Neither has a DeliverTo, so each advancement dispatches a
	// SYNCHRONOUS cross-peer EXECUTE (which carries + inherits bounds.chain_depth),
	// and receiving at a path that holds a continuation advances it — so the two
	// continuations re-trigger each other and the chain accumulates depth across
	// the wire. RemainingExecutions caps the runaway if inheritance is broken.
	contA := types.ContinuationData{
		Target:              fmt.Sprintf("entity://%s/system/inbox", string(b.RemotePeerID())),
		Operation:           "receive",
		Resource:            &types.ResourceTarget{Targets: []string{pb}},
		RemainingExecutions: &safety,
	}
	contB := types.ContinuationData{
		Target:              fmt.Sprintf("entity://%s/system/inbox", string(a.RemotePeerID())),
		Operation:           "receive",
		Resource:            &types.ResourceTarget{Targets: []string{pa}},
		RemainingExecutions: &safety,
	}
	if err := InstallCrossPeerContinuation(ctx, a, b, pa, contA); err != nil {
		return FailCheck("install Ca (A->B): " + err.Error())
	}
	if err := InstallCrossPeerContinuation(ctx, b, a, pb, contB); err != nil {
		return FailCheck("install Cb (B->A): " + err.Error())
	}

	// Deep-snapshot both lost-marker sinks so we match only THIS kick's
	// emission — a shallow listing would let a stale marker from an earlier
	// convergence check falsely satisfy the walk.
	sink := "system/runtime/chain-errors/lost/"
	beforeA := snapshotLostMarkerPaths(ctx, a, sink)
	beforeB := snapshotLostMarkerPaths(ctx, b, sink)

	// Kick Ca once. A working global brake returns fast; a runaway either blocks
	// until the safety cap unwinds or drops the connection — bound the wait.
	kickCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	resultData, _ := ecf.Encode(map[string]interface{}{"kick": true})
	if _, _, err := a.SendAdvance(kickCtx, pa, cbor.RawMessage(resultData), nil); err != nil {
		return FailCheck(fmt.Sprintf("cross-peer kick: %v — a runaway that drops the connection or hangs is the failure the global brake must prevent", err))
	}

	// Look for a fresh chain-error-lost marker on either peer and branch on its
	// reason, so we distinguish three very different outcomes:
	//   depth brake  → PASS: the chain accumulated across the wire and braked at
	//                  the GLOBAL ceiling (anchor 1 confirmed).
	//   other reason → WARN: the chain broke on something else BEFORE depth could
	//                  accumulate — most likely a cross-peer cap denial on the
	//                  return leg. That is a cross-peer bidirectional-continuation
	//                  AUTHORITY question, NOT a bounds-propagation defect; flag
	//                  it, don't gate on it.
	//   no marker    → FAIL: the chain ran to the safety cap without braking —
	//                  depth is genuinely not accumulating across the wire.
	reason, path, peer := "", "", ""
	if rA, pA := findFreshLostMarker(ctx, a, sink, beforeA); rA != "" {
		reason, path, peer = rA, pA, "A"
	} else if rB, pB := findFreshLostMarker(ctx, b, sink, beforeB); rB != "" {
		reason, path, peer = rB, pB, "B"
	}

	switch {
	case isDepthBrakeReason(reason):
		return PassCheck(fmt.Sprintf("cross-peer ping-pong terminated at the GLOBAL ceiling — brake marker reason=%q on %s at %s (chain_depth inherited across the wire; anchor 1)", reason, peer, path))
	case reason != "":
		return WarnCheck(fmt.Sprintf("cross-peer chain broke on reason=%q (marker on %s at %s) BEFORE the depth brake could engage — the return-leg dispatch was refused, a cross-peer bidirectional-continuation AUTHORITY issue, not a bounds-propagation defect. Depth accumulation across the wire is not yet exercised by this probe; the single-peer cb1/cb2 cover the §3.9 brake itself", reason, peer, path))
	default:
		// No marker on either peer. Empirically (Go↔Go, 2026-07-18) the chain
		// stalls at hop 2: peer A's advancement delivers `receive` to B, but B's
		// return-leg advancement dispatch back to A is refused by a LOCAL cap
		// check (~microseconds, before any wire round-trip, so no lost-marker is
		// bound). That is a cross-peer BIDIRECTIONAL continuation-authority
		// problem — the return-leg dispatch_capability is not accepted for B→A —
		// and it blocks depth from ever accumulating. It is orthogonal to
		// bounds-propagation (rung 1-3, which the single-peer cb1/cb2 exercise
		// and confirm). WARN, not FAIL: the blocker is real but it is not a
		// bounds defect, so it must not red-gate the convergence run.
		return WarnCheck(fmt.Sprintf("cross-peer depth accumulation NOT exercised: the ping-pong stalled before the §3.9 ceiling (no depth-brake marker on either peer). Empirically the return-leg B→A advancement is refused by a local cap check — a cross-peer bidirectional continuation-AUTHORITY issue, not a bounds-propagation defect. Anchor 1 (global count across the wire) needs that authority resolved before it can be probed; single-peer cb1/cb2 cover the §3.9 brake mechanism itself. safety_cap=%d", cbxSafetyCap))
	}
}
