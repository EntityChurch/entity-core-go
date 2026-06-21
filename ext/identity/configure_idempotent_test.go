package identity

import (
	"testing"

	"go.entitychurch.org/entity-core-go/core/crypto"
	"go.entitychurch.org/entity-core-go/core/types"
)

// TestIssueLocalPeerToControllerCap_Idempotent is the regression guard for the
// identity-bundle re-apply leak reported by workbench-go: the
// local-peer→controller cap was minted with CreatedAt: nowMillis(), so every
// configure / ApplyIdentityBundle re-apply produced a fresh cap content hash,
// leaking a cap entity + an invariant-pointer signature + a new signature path
// per restart. The cap has no TTL and is never time-validated, so re-issuing it
// from identical inputs MUST be a content-addressed no-op: same hash, no store
// growth, no new paths.
func TestIssueLocalPeerToControllerCap_Idempotent(t *testing.T) {
	f := newIFixture()
	w := &startupWriter{cs: f.cs, li: f.li}

	kp, err := crypto.Generate()
	if err != nil {
		t.Fatalf("crypto.Generate: %v", err)
	}
	localIdentity, err := kp.IdentityEntity()
	if err != nil {
		t.Fatalf("IdentityEntity: %v", err)
	}
	if _, err := f.cs.Put(localIdentity); err != nil {
		t.Fatalf("put local identity: %v", err)
	}

	controllerKey := makeFakeHash(0x42)
	grants := []types.GrantEntry{{
		Handlers:   types.CapabilityScope{Include: []string{"*"}},
		Resources:  types.CapabilityScope{Include: []string{"*"}},
		Operations: types.CapabilityScope{Include: []string{"*"}},
	}}

	cap1, err := issueLocalPeerToControllerCap(w, kp, localIdentity, controllerKey, grants)
	if err != nil {
		t.Fatalf("first issue: %v", err)
	}
	storeLen := f.cs.Len()
	pathLen := f.li.LenPrefix("")

	// Pin the actual contract directly: the cap must not fold wall-clock, so
	// CreatedAt is the fixed sentinel 0. This is timing-independent — the
	// no-growth checks below only catch the leak if two issues straddle a
	// millisecond boundary (nowMillis resolution), which a fast test won't.
	capEnt, ok := f.cs.Get(cap1)
	if !ok {
		t.Fatalf("minted cap %s not in store", cap1)
	}
	capData, err := types.CapabilityTokenDataFromEntity(capEnt)
	if err != nil {
		t.Fatalf("decode minted cap: %v", err)
	}
	if capData.CreatedAt != 0 {
		t.Errorf("cap CreatedAt = %d, want 0 (wall-clock folded into a content-addressed cap defeats re-apply idempotency)",
			capData.CreatedAt)
	}

	// Re-issue with identical inputs — this is the ApplyIdentityBundle re-apply
	// path. Must reproduce the prior cap hash and touch nothing new.
	cap2, err := issueLocalPeerToControllerCap(w, kp, localIdentity, controllerKey, grants)
	if err != nil {
		t.Fatalf("second issue: %v", err)
	}

	if cap1 != cap2 {
		t.Errorf("cap hash not deterministic across re-issue:\n  first  = %s\n  second = %s", cap1, cap2)
	}
	if got := f.cs.Len(); got != storeLen {
		t.Errorf("content store grew on re-issue: %d -> %d (Δ%+d) — leaked cap/signature entities",
			storeLen, got, got-storeLen)
	}
	if got := f.li.LenPrefix(""); got != pathLen {
		t.Errorf("location index grew on re-issue: %d -> %d (Δ%+d) — leaked a new signature path",
			pathLen, got, got-pathLen)
	}
}
