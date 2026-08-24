package validate

// EXTENSION-CONTINUATION §3.9 chain_depth — the continuation-advancement depth
// brake, and PROPOSAL-CONTINUATION-BOUNDS-PROPAGATION's cross-impl convergence
// surface. This is the counter that bounds a *continuation advancement chain*
// (429 bounds_exceeded on Go / 429 + suspend on Python), distinct from the
// V7 §4.10(b) *capability-chain* depth counter (400 chain_depth_exceeded) that
// `resource_bounds.r2` already covers. Two different counters sharing a name;
// before this category NOTHING exercised the §3.9 one.
//
// The subtlety this category is built around is the O1 signal
// (PROPOSAL §5): depth accumulates only across a *causal, synchronous*
// advancement chain — advancement N dispatching advancement N+1 within one
// execution. A *fresh external trigger* (a separate EXECUTE, a timer, an inbox
// delivery) roots depth fresh at 0, which is what keeps retry-forever safe.
// So the two load-bearing checks are a mirror image:
//
//   cb1  standing continuation, K > max SEPARATE external advances  → never
//        suspends (fresh triggers root fresh; retry-forever stays unbounded)
//   cb2  one self-referential continuation whose advancement re-advances
//        ITSELF synchronously → terminates at the ceiling, does not run away
//   cb3  after the brake fires, the peer still serves (keeps-serving invariant)
//
// cb2 accepts BOTH terminal shapes — a 429 bounds_exceeded and a suspension
// carrying chain_depth_exceeded — because the §3.9 suspension handler is a MAY
// the cohort has not converged (Go returns 429; Python 429 + persists a
// resumable suspended entity). The probe gates ENFORCEMENT (the chain
// terminates and the peer survives), never which tolerated shape it takes.

import (
	"context"
	"fmt"
	"time"

	"go.entitychurch.org/entity-core-go/core/ecf"
	"go.entitychurch.org/entity-core-go/core/types"

	"github.com/fxamacker/cbor/v2"
)

const catContinuationBounds = "continuation_bounds"

// cbFreshTriggerCount is how many separate external advances cb1 fires. It must
// exceed any reasonable §3.9 maximum (default 64) so that, were depth wrongly
// accumulating across fresh triggers, the run would cross the ceiling and
// suspend — turning the O1 regression into an observable failure.
const cbFreshTriggerCount = 80

func runContinuationBounds(ctx context.Context, client *PeerClient) []CheckResult {
	r := NewCheckRunner(catContinuationBounds)

	r.Declare("cb1_fresh_triggers_root_fresh",
		"CONTINUATION §3.9 / PROPOSAL-CONTINUATION-BOUNDS-PROPAGATION §5 — a standing continuation advanced by K>max SEPARATE external triggers never accumulates depth (retry-forever stays unbounded)")
	r.Declare("cb2_self_referential_chain_brakes",
		"CONTINUATION §3.9 — a self-referential advancement chain terminates at the ceiling (429 bounds_exceeded or suspend), never runs away")
	r.Declare("cb3_keeps_serving_after_brake",
		"CONTINUATION §3.9 keeps-serving — the peer still serves a normal request after the depth brake fires")

	r.Run("cb1_fresh_triggers_root_fresh", func() CheckOutcome {
		return runCB1FreshTriggers(ctx, client)
	})
	r.Run("cb2_self_referential_chain_brakes", func() CheckOutcome {
		return runCB2SelfReferentialBrake(ctx, client)
	})
	r.Run("cb3_keeps_serving_after_brake", func() CheckOutcome {
		// Independent of cb2's PASS/WARN outcome — the point is that whatever
		// cb2's self-referential kick did to the peer, it is still serving.
		if _, _, err := client.TreeGet(ctx, "system/handler/system/tree"); err != nil {
			return FailCheck(fmt.Sprintf("post-brake tree.get failed: %v (peer degraded under the §3.9 brake)", err))
		}
		return PassCheck("post-brake tree.get succeeded (peer keeps serving)")
	})

	return r.Results()
}

// runCB1FreshTriggers installs a STANDING continuation (remaining_executions =
// null) and advances it K > max times, each via a separate external EXECUTE.
// Every advance is a fresh trigger, so depth roots at 0 each time and the chain
// never approaches the ceiling. All K advances MUST return 200. A suspension or
// 429 anywhere in the run is the O1 regression: depth leaking across triggers.
func runCB1FreshTriggers(ctx context.Context, client *PeerClient) CheckOutcome {
	peerID := string(client.RemotePeerID())
	contPath := "system/inbox/validate-cb-standing"
	targetPath := "system/inbox/validate-cb-standing-target"

	cont := types.ContinuationData{
		Target:              fmt.Sprintf("entity://%s/system/inbox", peerID),
		Operation:           "receive",
		Resource:            &types.ResourceTarget{Targets: []string{targetPath}},
		RemainingExecutions: nil, // standing — persists across advances
	}
	if err := installContinuationFromData(ctx, client, contPath, cont); err != nil {
		return FailCheck("install standing continuation: " + err.Error())
	}

	for i := 0; i < cbFreshTriggerCount; i++ {
		resultData, _ := ecf.Encode(map[string]interface{}{"tick": i})
		env, _, err := client.SendAdvance(ctx, contPath, cbor.RawMessage(resultData), nil)
		if err != nil {
			return FailCheck(fmt.Sprintf("fresh advance %d/%d: transport error %v", i+1, cbFreshTriggerCount, err))
		}
		respData, derr := types.ExecuteResponseDataFromEntity(env.Root)
		if derr != nil {
			return FailCheck(fmt.Sprintf("fresh advance %d/%d: decode response: %v", i+1, cbFreshTriggerCount, derr))
		}
		if respData.Status != 200 {
			code, _ := extractErrorCode(respData.Result)
			return FailCheck(fmt.Sprintf("fresh advance %d/%d returned status=%d code=%q — a fresh external trigger must root depth at 0 (§5); depth is leaking across triggers, which would wrongly bound retry-forever",
				i+1, cbFreshTriggerCount, respData.Status, code))
		}
	}
	return PassCheck(fmt.Sprintf("%d separate external advances of a standing continuation all returned 200 — fresh triggers root depth fresh (retry-forever stays unbounded, O1)", cbFreshTriggerCount))
}

// runCB2SelfReferentialBrake installs a STANDING continuation whose advancement
// dispatches an `advance` of ITSELF — a synchronous, zero-delay self-redispatch,
// the exact runaway PROPOSAL §5's corollary says the brake exists to catch.
// Kicked once, a peer WITHOUT a working §3.9 brake recurses until its stack
// dies (the connection drops); a peer WITH the brake terminates the chain at
// its ceiling and answers. We accept either 429 bounds_exceeded or a suspend.
func runCB2SelfReferentialBrake(ctx context.Context, client *PeerClient) CheckOutcome {
	peerID := string(client.RemotePeerID())
	contPath := "system/inbox/validate-cb-selfref"
	sinkPrefix := "system/runtime/chain-errors/lost/"

	// Deep-snapshot the lost-error sink so we match only THIS kick's emission.
	beforeMarkers := snapshotLostMarkerPaths(ctx, client, sinkPrefix)

	// Target = an inbox `receive` delivered to this continuation's OWN path.
	// Receiving at a path that holds a continuation advances it (synchronously —
	// the forward is in-dispatch, as cb1 relies on), so each advancement
	// re-delivers to itself and advances again: a causal, zero-delay
	// self-redispatch that accumulates chain_depth. `receive` takes an arbitrary
	// message entity, so (unlike `advance`) the primitive/any-wrapped forward
	// params are accepted and the loop actually runs to the ceiling.
	cont := types.ContinuationData{
		Target:              fmt.Sprintf("entity://%s/system/inbox", peerID),
		Operation:           "receive",
		Resource:            &types.ResourceTarget{Targets: []string{contPath}},
		RemainingExecutions: nil, // standing — so the self-delivery keeps finding it
	}
	if err := installContinuationFromData(ctx, client, contPath, cont); err != nil {
		return FailCheck("install self-referential continuation: " + err.Error())
	}

	// Kick once. Bound the wait: a working brake returns fast; a runaway either
	// hangs (caught by the deadline) or drops the connection (caught as error).
	kickCtx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	resultData, _ := ecf.Encode(map[string]interface{}{"kick": true})
	env, _, err := client.SendAdvance(kickCtx, contPath, cbor.RawMessage(resultData), nil)
	if err != nil {
		return FailCheck(fmt.Sprintf("self-referential kick: peer did not answer (%v) — a runaway that drops the connection or hangs is exactly the §3.9 failure the brake must prevent", err))
	}
	respData, derr := types.ExecuteResponseDataFromEntity(env.Root)
	if derr != nil {
		return FailCheck(fmt.Sprintf("self-referential kick: decode response: %v", derr))
	}
	kickCode, _ := extractErrorCode(respData.Result)

	// Positive confirmation the chain actually reached the ceiling (rather than
	// terminating benignly at hop 1): the §3.9 brake fires DEEP in the
	// recursion and surfaces as a chain-error-lost marker, so the outer kick
	// response is typically 200 even though 429 bounds_exceeded fired inside.
	// Walk the lost sink for a marker this kick bound, whose reason is the
	// depth-brake code. Without this, a 200 could not distinguish "braked at the
	// ceiling" from "never looped".
	reason, markerPath := findFreshLostMarker(ctx, client, sinkPrefix, beforeMarkers)
	if isDepthBrakeReason(reason) {
		return PassCheck(fmt.Sprintf("self-referential chain terminated at the §3.9 ceiling: chain-error-lost marker reason=%q at %s (kick returned status=%d code=%q; brake fired, no runaway)", reason, markerPath, respData.Status, kickCode))
	}

	// A direct 429/suspend on the outer response also confirms the brake.
	if respData.Status == 429 || kickCode == "bounds_exceeded" || kickCode == "chain_depth_exceeded" {
		return PassCheck(fmt.Sprintf("self-referential chain terminated at the ceiling (kick status=%d code=%q; brake fired)", respData.Status, kickCode))
	}

	// The peer answered and SURVIVED (cb3 confirms it keeps serving) — the
	// runaway WAS prevented — but no chain_depth brake marker surfaced, so the
	// §3.9 chain_depth brake *specifically* is not confirmed here. Observed
	// cross-impl (2026-07-18): Python brakes this same-peer synchronous loop via
	// ttl/budget exhaustion FIRST (it carries a peer_default_ttl; Go has none and
	// brakes on chain_depth), which masks the depth counter and leaves no tree
	// marker. An impl that SUSPENDS on depth would instead record it under
	// system/continuation/suspended/. WARN, not FAIL: the safety property (no
	// runaway) holds; only the brake MECHANISM diverges — the peer_default_ttl /
	// rung-4 question, in docs/validation/spec-issues/2026-07-18-*.
	return WarnCheck(fmt.Sprintf("self-referential kick returned cleanly (status=%d code=%q) and the peer SURVIVED (runaway prevented), but no chain_depth brake marker surfaced under %s — the §3.9 chain_depth brake is not confirmed on this peer, likely masked by ttl/budget exhaustion firing first (peer_default_ttl divergence: Python brakes via TTL, Go via chain_depth). Both prevent the runaway; the mechanism differs", respData.Status, kickCode, sinkPrefix))
}

// isDepthBrakeReason reports whether a chain-error-lost reason is a §3.9 depth
// brake (Go spells it bounds_exceeded; an impl MAY spell it chain_depth_exceeded).
func isDepthBrakeReason(r string) bool {
	return r == "bounds_exceeded" || r == "chain_depth_exceeded"
}

// snapshotLostMarkerPaths recursively collects the FULL leaf paths of every
// chain-error-lost marker currently under sinkPrefix (v1.20 4-segment scheme:
// chain / step / reason / marker_hash). findFreshLostMarker compares full paths
// against this set, so a stale marker from an earlier check in the same run
// cannot be mistaken for one THIS kick bound — the bug that made a cross-peer
// chain which never looped falsely PASS on an unrelated bounds_exceeded marker.
func snapshotLostMarkerPaths(ctx context.Context, client *PeerClient, sinkPrefix string) map[string]bool {
	seen := map[string]bool{}
	var walk func(prefix string, depth int)
	walk = func(prefix string, depth int) {
		if depth == 0 {
			seen[prefix] = true
			return
		}
		entries, _, err := client.TreeListing(ctx, prefix+"/")
		if err != nil {
			return
		}
		for seg := range entries {
			walk(prefix+"/"+seg, depth-1)
		}
	}
	entries, _, _ := client.TreeListing(ctx, sinkPrefix)
	for chainSeg := range entries {
		walk(sinkPrefix+chainSeg, 3)
	}
	return seen
}

// findFreshLostMarker walks the chain-error-lost sink for the first marker whose
// full path is NOT in `before` (a deep snapshot from snapshotLostMarkerPaths),
// returning its (reason, path) — ANY reason, so callers can distinguish a depth
// brake from a chain that broke on something else (e.g. a cross-peer cap
// denial). Returns ("", "") if none surfaced. Polls briefly — most impls bind
// synchronously, but tree-event fan-out can surface the listing slightly late.
func findFreshLostMarker(ctx context.Context, client *PeerClient, sinkPrefix string, before map[string]bool) (string, string) {
	var foundReason, foundPath string
	var walk func(prefix string, depth int) bool
	walk = func(prefix string, depth int) bool {
		if depth == 0 {
			if before[prefix] {
				return false
			}
			ent, _, gerr := client.TreeGet(ctx, prefix)
			if gerr != nil || ent.Type != types.TypeChainErrorLost {
				return false
			}
			var md types.ChainErrorLostData
			if derr := ecf.Decode(ent.Data, &md); derr != nil {
				return false
			}
			foundReason, foundPath = md.Reason, prefix
			return true
		}
		entries, _, err := client.TreeListing(ctx, prefix+"/")
		if err != nil {
			return false
		}
		for seg := range entries {
			if walk(prefix+"/"+seg, depth-1) {
				return true
			}
		}
		return false
	}
	for i := 0; i < 10; i++ {
		entries, _, _ := client.TreeListing(ctx, sinkPrefix)
		for chainSeg := range entries {
			if walk(sinkPrefix+chainSeg, 3) {
				return foundReason, foundPath
			}
		}
		time.Sleep(50 * time.Millisecond)
	}
	return "", ""
}
