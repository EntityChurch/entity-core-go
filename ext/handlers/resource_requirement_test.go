package handlers

import (
	"context"
	"testing"

	"go.entitychurch.org/entity-core-go/core/crypto"
	"go.entitychurch.org/entity-core-go/core/ecf"
	"go.entitychurch.org/entity-core-go/core/handler"
	"go.entitychurch.org/entity-core-go/core/store"
	"go.entitychurch.org/entity-core-go/core/types"
)

// TestRegisterResourceRequirementSplitsAbsentFromAmbiguous pins §3245 / §3.3's
// 400 row as folded at 0.8.2.18: register and unregister derive their install
// path from EXECUTE.resource.targets[0], so they are operations "whose own
// specification requires a resource" — and the two malformed inputs carry
// different remedies, so they carry different codes:
//
//   - ABSENT resource (nil, or zero targets) → 400 path_required   (remedy: supply a resource)
//   - MORE THAN ONE target                   → 400 ambiguous_resource (remedy: disambiguate)
//
// The earlier text collapsed both into ambiguous_resource; §3.3 declares a
// handler that collapses them "non-conformant on the absent case." §3245 covers
// register and unregister in one sentence, so both must split identically.
//
// Mutation witness: reverting either handler to `len(Targets) != 1 →
// ambiguous_resource` reddens every absent row here (want path_required, got
// ambiguous_resource). The exactly-one (200) path is the positive control in
// TestSystemStarRegistrationIsPermitted, so this test asserts only the 400
// branch it governs.
func TestRegisterResourceRequirementSplitsAbsentFromAmbiguous(t *testing.T) {
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

	two := &types.ResourceTarget{Targets: []string{
		"system/handler/system/validate/a",
		"system/handler/system/validate/b",
	}}
	empty := &types.ResourceTarget{Targets: []string{}}

	// Params are irrelevant: the resource-count check precedes any param decode.
	// A well-formed register request keeps the test honest about what fails.
	reqEnt, err := types.RegisterRequestData{Manifest: types.HandlerManifestData{
		Pattern:    "system/validate/x",
		Name:       "system/validate/x",
		Operations: map[string]types.HandlerOperationSpec{"go": {InputType: "primitive/any", OutputType: "primitive/any"}},
	}}.ToEntity()
	if err != nil {
		t.Fatal(err)
	}

	cases := []struct {
		name     string
		op       string
		resource *types.ResourceTarget
		wantCode string
	}{
		{"register/nil-resource", "register", nil, "path_required"},
		{"register/zero-targets", "register", empty, "path_required"},
		{"register/two-targets", "register", two, "ambiguous_resource"},
		{"unregister/nil-resource", "unregister", nil, "path_required"},
		{"unregister/zero-targets", "unregister", empty, "path_required"},
		{"unregister/two-targets", "unregister", two, "ambiguous_resource"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			hctx := &handler.HandlerContext{
				Store:         cs,
				LocationIndex: li,
				LocalPeerID:   kp.PeerID(),
				Resource:      tc.resource,
			}
			req := &handler.Request{Operation: tc.op, Params: reqEnt, Context: hctx}

			resp, err := h.Handle(context.Background(), req)
			if err != nil {
				t.Fatalf("%s errored: %v", tc.op, err)
			}
			if resp.Status != 400 {
				t.Fatalf("%s with malformed resource returned status %d, want 400", tc.op, resp.Status)
			}
			var ed types.ErrorData
			if err := ecf.Decode(resp.Result.Data, &ed); err != nil {
				t.Fatalf("decode error entity: %v", err)
			}
			if ed.Code != tc.wantCode {
				t.Fatalf("%s: code = %q, want %q (§3245/§3.3 0.8.2.18: absent→path_required, >1→ambiguous_resource; collapsing them is non-conformant on the absent case)", tc.op, ed.Code, tc.wantCode)
			}
		})
	}
}
