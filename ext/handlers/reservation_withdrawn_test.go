package handlers

import (
	"context"
	"testing"

	"go.entitychurch.org/entity-core-go/core/crypto"
	"go.entitychurch.org/entity-core-go/core/handler"
	"go.entitychurch.org/entity-core-go/core/store"
	"go.entitychurch.org/entity-core-go/core/types"
)

// TestSystemStarRegistrationIsPermitted is the F61 / 0.8.2.13 invariant: the
// `system/*` registration reservation is WITHDRAWN, so a register whose
// resource-derived pattern is under `system/` installs normally rather than
// being refused `403 forbidden_pattern`. §6.2/§3162: installation at any path
// is authorized by the dispatch capability check on `resource` (done by the
// dispatcher, above this handler), and refusing `system/*` is deployment
// policy, not a protocol constraint (§3164).
//
// Mutation witness: reintroducing the isReservedSystemPattern prefix refusal in
// handleRegister reddens this — the response flips to 403 forbidden_pattern.
// (The handler trusts the dispatcher authorized the call, so no cap is needed
// here; this asserts only that the handler itself imposes no system/* prefix
// constraint.)
func TestSystemStarRegistrationIsPermitted(t *testing.T) {
	kp, err := crypto.Generate()
	if err != nil {
		t.Fatal(err)
	}
	identity, err := kp.IdentityEntity()
	if err != nil {
		t.Fatal(err)
	}

	h := NewHandler()
	h.SetupAuthority(kp, identity)

	cs := store.NewMemoryContentStore()
	li := store.NewNamespacedIndex(store.NewMemoryLocationIndex(), string(kp.PeerID()))

	const pattern = "system/validate/reservation-withdrawn"
	manifest := types.HandlerManifestData{
		Pattern: pattern,
		Name:    pattern,
		Operations: map[string]types.HandlerOperationSpec{
			"go": {InputType: "primitive/any", OutputType: "primitive/any"},
		},
	}
	reqEnt, err := types.RegisterRequestData{Manifest: manifest}.ToEntity()
	if err != nil {
		t.Fatal(err)
	}
	hctx := &handler.HandlerContext{
		Store:         cs,
		LocationIndex: li,
		LocalPeerID:   kp.PeerID(),
		Resource:      &types.ResourceTarget{Targets: []string{"system/handler/" + pattern}},
	}
	req := &handler.Request{Operation: "register", Params: reqEnt, Context: hctx}

	resp, err := h.Handle(context.Background(), req)
	if err != nil {
		t.Fatalf("register at a system/* pattern errored: %v", err)
	}
	if resp.Status == 403 {
		t.Fatalf("register at a system/* pattern was refused (status 403) — the withdrawn §6.6 reservation has been reintroduced; 0.8.2.13 permits system/* installation (it is gated by the capability check at the dispatcher, not a prefix refusal here)")
	}
	if resp.Status != 200 {
		t.Fatalf("register at a system/* pattern returned status %d, want 200", resp.Status)
	}
	// The artifacts landed at the system/* path — installation really happened.
	if _, ok := li.Get("system/handler/" + pattern); !ok {
		t.Fatal("register returned 200 but bound no manifest at system/handler/" + pattern)
	}
	if _, ok := li.Get("system/capability/grants/" + pattern); !ok {
		t.Fatal("register returned 200 but bound no grant at system/capability/grants/" + pattern)
	}
}
