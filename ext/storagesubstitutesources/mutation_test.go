package storagesubstitutesources

import (
	"context"
	"testing"

	"go.entitychurch.org/entity-core-go/core/store"
)

// The mutation arm behind the SUBSTITUTE declared exclusion
// (cmd/internal/validate/exclusions.go).
//
// WHY THIS FILE EXISTS. EXTENSION-SUBSTITUTE's §3 chain-consultation
// algorithm is not drivable by a conformance client in ANY of the three
// implementations — the chain fires only for a caller supplying
// `claimed_source_peer_id`, which per Ruling 4 is local dispatcher context and
// no production path in go, rust or py populates it (rust `handler.rs:164`
// binds `None`; py's content handler says it "does NOT auto-invoke"; go's
// `WithClaimedSource` has no production caller). So §8's fail-closed
// capability rule — the one that stops an arbitrary caller triggering an
// outbound fetch and a forced ingestion — is verified in-process and DECLARED
// as an exclusion rather than measured over the wire.
//
// GUIDE-CONFORMANCE §5.2b.1: a declared exclusion is honest only if the test
// standing in for the wire vector is shown capable of FAILING. The precedent
// this repo already holds is core-py's, and it is worth restating: their §5.5a
// control and its mutation both ran against a malformed probe, so neither
// could have failed, and the pair certified nothing for a full cycle.
//
// This test is that proof, EXECUTED — it runs in the ordinary unit suite on
// every commit, not described in a document.

// TestConsultFailClosedMutationHasTeeth removes the §8 consult gate and
// asserts the chain THEN consults. If this test ever fails, the gate is not
// what makes TestConsult_FailClosed_NoCallerCapability pass, and that test —
// plus every cap-scoping test beside it — has been passing for some other
// reason.
func TestConsultFailClosedMutationHasTeeth(t *testing.T) {
	consultGateDisabled = true
	t.Cleanup(func() { consultGateDisabled = false })

	// Byte-for-byte the setup of TestConsult_FailClosed_NoCallerCapability:
	// no CallerCapability on the context. With the gate in place that peer
	// answers Disabled and dispatches nothing.
	cs := store.NewMemoryContentStore()
	li := store.NewMemoryLocationIndex()
	claimed := peerID(0xab)
	publishSource(t, cs, li, mkSrc(t, "primary", claimed, 10))

	exec := &stubExecute{}
	hctx := mkHCtxNoCap(t, cs, li, exec)

	o := New()
	res := o.Consult(context.Background(), hctx, peerID(0xcd), claimed)

	if res.Outcome == OutcomeDisabled {
		t.Fatalf("mutation had no effect: outcome is still Disabled with the consult gate removed. " +
			"TestConsult_FailClosed_NoCallerCapability is therefore not proving the gate — something " +
			"else is short-circuiting the chain, and the declared exclusion that rests on it is void")
	}
	if len(exec.calls) == 0 {
		t.Fatal("mutation had no effect: no try-dispatch happened with the consult gate removed. " +
			"The fail-closed test cannot be attributing the absence of dispatch to the cap check")
	}
}

// TestChainIsNotWireReachable_ByConstruction pins the OTHER half of the
// exclusion's reasoning: that a request arriving with no claimed source
// bypasses the chain entirely, which is what every live content:get does today
// because nothing calls WithClaimedSource outside tests.
//
// It is deliberately an assertion about the ADAPTER rather than about the
// orchestrator: `Consult` refuses a zero claimed-source by its own §3-RES.2
// rule, but the wire-unreachability claim is about the miss-hook seam, and
// that is where a future dispatcher would wire the context in. **If someone
// populates the claimed source in production, this test still passes and the
// exclusion becomes void** — so the exclusion's `voids` clause names the
// condition explicitly rather than relying on a test to notice.
func TestChainIsNotWireReachable_ByConstruction(t *testing.T) {
	cs := store.NewMemoryContentStore()
	li := store.NewMemoryLocationIndex()
	claimed := peerID(0xab)
	publishSource(t, cs, li, mkSrc(t, "primary", claimed, 10))

	exec := &stubExecute{}
	hctx := mkHCtxNoCap(t, cs, li, exec)

	// A bare context — exactly what the content handler passes today.
	res := New().Resolve(context.Background(), hctx, peerID(0xcd))

	if res.Found || res.CapDenied {
		t.Fatalf("Resolve on a context with no claimed source returned %+v — it must be an empty "+
			"MissResult so the content handler reports the hash as missing (§3-RES.2)", res)
	}
	if len(exec.calls) != 0 {
		t.Fatalf("Resolve consulted the chain (%d dispatches) with no claimed source in context", len(exec.calls))
	}
}
