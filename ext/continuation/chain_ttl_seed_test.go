package continuation

import (
	"testing"

	"go.entitychurch.org/entity-core-go/core/types"
)

// The cross-peer TTL rule: a continuation chain carries a UNIFORM ttl, seeded
// when none is inherited, decremented exactly once per hop.
//
// Before this was pinned, Go seeded nothing — a root chain rode the wire with
// ttl absent, so whether TTL bounded the chain was decided by whichever peer it
// reached. Go and Rust (seed nothing) ran to the §3.9 depth ceiling; Python
// (seeds, decrements several times per hop) died on TTL around hop 9. Same
// chain, three terminations. That divergence is what made the anchor-1 probe
// (cbx_crosspeer_chain_bounds_globally) WARN Go<->Python while passing
// Go<->Rust: TTL was masking the depth brake the anchor exists to demonstrate.
//
// These are the invariants that keep it fixed. They are cheap and pure — no
// peers, no sockets — because the expensive way to learn a regression here is a
// cross-impl WARN three cycles later.

func TestDispatchBoundsSeedsUniformTTLOnRootChain(t *testing.T) {
	// A root chain: no parent bounds at all. Used to yield "chain id alone".
	child, err := dispatchBounds(nil, "chain-root", types.DefaultChainTTL)
	if err != nil {
		t.Fatalf("dispatchBounds(nil): %v", err)
	}
	if child.TTL == nil {
		t.Fatal("root chain has no ttl — Go is seeding nothing again, so the chain's bound is decided by whichever peer it reaches")
	}
	if *child.TTL != types.DefaultChainTTL {
		t.Errorf("root chain ttl = %d, want the uniform seed %d", *child.TTL, types.DefaultChainTTL)
	}

	// A parent that exists but carries no ttl is the same case: nothing to
	// inherit, so it must be seeded rather than left absent.
	child, err = dispatchBounds(&types.BoundsData{ChainID: "x"}, "chain-root", types.DefaultChainTTL)
	if err != nil {
		t.Fatalf("dispatchBounds(ttl-less parent): %v", err)
	}
	if child.TTL == nil || *child.TTL != types.DefaultChainTTL {
		t.Errorf("ttl-less parent did not get the uniform seed (got %v)", child.TTL)
	}
}

func TestDispatchBoundsDecrementsExactlyOncePerHop(t *testing.T) {
	// An inherited ttl is decremented by exactly 1 — never re-seeded (which
	// would make the chain unbounded) and never multi-decremented (the
	// observed non-conformant case that kills a chain early).
	ttl := uint64(10)
	child, err := dispatchBounds(&types.BoundsData{TTL: &ttl}, "chain-1", types.DefaultChainTTL)
	if err != nil {
		t.Fatalf("dispatchBounds: %v", err)
	}
	if child.TTL == nil || *child.TTL != 9 {
		t.Fatalf("inherited ttl 10 -> %v, want 9 (exactly one decrement per hop)", child.TTL)
	}

	// Walk several hops: strictly one per hop, no re-seed at any point.
	cur := &types.BoundsData{TTL: &ttl}
	for hop, want := 1, uint64(9); hop <= 5; hop, want = hop+1, want-1 {
		cur, err = dispatchBounds(cur, "chain-1", types.DefaultChainTTL)
		if err != nil {
			t.Fatalf("hop %d: %v", hop, err)
		}
		if *cur.TTL != want {
			t.Fatalf("hop %d: ttl = %d, want %d", hop, *cur.TTL, want)
		}
	}

	// Exhaustion is still an error, not a silent re-seed.
	zero := uint64(0)
	if _, err := dispatchBounds(&types.BoundsData{TTL: &zero}, "chain-1", types.DefaultChainTTL); err == nil {
		t.Error("ttl=0 did not error — an exhausted chain is being re-seeded instead of terminated")
	}
}

// PROPOSAL-CONTINUATION-BOUNDS-PROPAGATION §5 / §8 anchor 2: retry-forever MUST
// NOT be bounded. A standing continuation (NETWORK backoff against a down peer)
// re-fires for its lifetime, and seeding a ttl introduces a way for that to die
// that did not exist before — after N re-firings the chain would exhaust and a
// peer would silently stop retrying a neighbour that is merely away.
//
// It is safe because a standing re-fire is a NEW root flow, not a causal
// continuation of the previous one: both firing paths construct fresh bounds
// with no ttl (ext/network/wiring.go selfExecute, ext/subscription/delivery.go),
// so each firing re-seeds rather than inheriting a decremented value. This test
// pins that. It would only fail in production after ~DefaultChainTTL retries —
// far too late to notice.
func TestStandingRefireReseedsAndNeverDecaysAcrossFirings(t *testing.T) {
	// Mimic the firing paths exactly: fresh BoundsData carrying only a stable
	// chain id, as network/subscription construct on every firing.
	for firing := 1; firing <= 2000; firing++ {
		child, err := dispatchBounds(&types.BoundsData{ChainID: "network-maintain-s1"}, "network-maintain-s1", types.DefaultChainTTL)
		if err != nil {
			t.Fatalf("firing %d errored (%v) — retry-forever just became retry-until-%d", firing, err, firing)
		}
		if child.TTL == nil || *child.TTL != types.DefaultChainTTL {
			t.Fatalf("firing %d: ttl = %v, want a full re-seed of %d — ttl is decaying across standing firings, so a peer will stop retrying",
				firing, child.TTL, types.DefaultChainTTL)
		}
		// The chain id is the stable identity axis and must survive untouched.
		if child.ChainID != "network-maintain-s1" {
			t.Fatalf("firing %d: chain id mutated to %q", firing, child.ChainID)
		}
	}
}

func TestChainTTLSeedIsDeconfoundedFromDepthCeiling(t *testing.T) {
	// The magnitude confound: EXTENSION-CONTINUATION §3.9's depth ceiling
	// defaults to 64 (core/protocol.DefaultMaxChainDepth). If the ttl seed also
	// equals 64 and both step once per hop, the two brakes fire on the same hop
	// and no observer can say which bound the chain — which is exactly why the
	// global depth brake was undemonstrable cross-peer.
	//
	// The ceiling is asserted here as a literal rather than imported: this
	// package is ext/, the ceiling lives in core/protocol, and the invariant
	// that matters is the RELATIONSHIP between the two magnitudes. If the
	// ceiling default ever moves, this test should fail loudly and be
	// re-reconciled, not silently track it.
	const depthCeilingDefault = 64
	if types.DefaultChainTTL <= depthCeilingDefault {
		t.Fatalf("DefaultChainTTL=%d must exceed the §3.9 depth ceiling %d, or ttl masks the depth brake",
			types.DefaultChainTTL, depthCeilingDefault)
	}
	// The ratio is the meaningful quantity, not the seed alone. chain_depth
	// increments only on a continuation advancement; ttl is decremented by every
	// dispatch, including the internal sub-dispatches one advancement makes
	// (which inherit chain_depth unchanged). So seed/ceiling is the number of
	// dispatch operations one causal level may spend before ttl — rather than
	// the deterministic depth brake — becomes binding.
	//
	// Require real headroom: at ratio 1 the two race (the confound), and at a
	// ratio near 1 any chain doing more than trivial work per level trips the
	// resource backstop instead of the depth brake, which silently un-does
	// Ruling 2's intent that depth be the PRIMARY brake.
	const wantMinRatio = 4
	if ratio := types.DefaultChainTTL / depthCeilingDefault; ratio < wantMinRatio {
		t.Errorf("seed/ceiling ratio = %d (%d/%d), want >= %d — too little room for per-level sub-dispatch before ttl displaces depth as the binding brake",
			ratio, types.DefaultChainTTL, depthCeilingDefault, wantMinRatio)
	}
}
