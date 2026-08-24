package protocol

import (
	"context"
	"testing"

	"go.entitychurch.org/entity-core-go/core/crypto"
	"go.entitychurch.org/entity-core-go/core/entity"
	"go.entitychurch.org/entity-core-go/core/handler"
	"go.entitychurch.org/entity-core-go/core/store"
	"go.entitychurch.org/entity-core-go/core/types"
)

// arch ROUTING-2026-08-18-d §2 (SA-PY-9): §5.2's resource dimension binds every
// dispatch carrying a resource target, in-process sub-dispatch included. The
// condition is `resource_target is not null` — a test on the FIELD, not on any
// wire-entry door. makeLocalExecute used to compute the child's resource,
// propagate it as the child's authorization target, and yet hand the L1 check a
// literal that omitted it — moving the resource past its own scope check. §6.2
// pins `system/handler:register`'s install-path authorization to exactly this
// check, and register always carries a resource (the pattern), so the skip is a
// real authorization hole regardless of today's reachability.
//
// Teeth: the parent's grant covers the child handler pattern (Dimension 2) and
// the operation (Dimension 1), but its Resources scope is `app/*` and the
// sub-dispatch targets `pwn`. With the resource dimension checked this is 403;
// with it skipped (the pre-fix shape) the child runs and the parent returns 200.
// If this test reads 200 the fix has regressed.
func TestSubDispatchResourceDimensionIsChecked(t *testing.T) {
	kp, _ := crypto.Generate()
	cs := store.NewMemoryContentStore()
	li := store.NewNamespacedIndex(store.NewMemoryLocationIndex(), string(kp.PeerID()))

	const parentURI = "app/parent"
	const childURI = "app/child"

	childRan := false
	child := &fnHandler{name: "child", fn: func(ctx context.Context, req *handler.Request) (*handler.Response, error) {
		childRan = true
		return &handler.Response{Status: 200}, nil
	}}
	// The parent sub-dispatches to the child with a resource target OUTSIDE its
	// own grant's Resources scope, and returns whatever the sub-dispatch yields.
	parent := &fnHandler{name: "parent", fn: func(ctx context.Context, req *handler.Request) (*handler.Response, error) {
		return req.Context.Execute(ctx, childURI, "go", entity.Entity{},
			handler.WithResource(&types.ResourceTarget{Targets: []string{"pwn"}}))
	}}

	reg := handler.NewRegistry()
	reg.Register(parentURI, parent)
	reg.Register(childURI, child)
	if err := SeedHandlersFromRegistry(cs, li, reg); err != nil {
		t.Fatal(err)
	}

	// Grant: handlers=* (Dim 2 passes for the child pattern), operations cover
	// "go" (Dim 1 passes), resources=app/* (Dim 3 must REJECT "pwn"). Bound as
	// the handler grant for both patterns (§6.8: sub-dispatch gates on the
	// executing handler's grant, not the caller capability).
	identity, _ := kp.IdentityEntity()
	if _, err := cs.Put(identity); err != nil {
		t.Fatal(err)
	}
	capData := types.CapabilityTokenData{
		Grants: []types.GrantEntry{{
			Handlers:   types.CapabilityScope{Include: []string{"*"}},
			Resources:  types.CapabilityScope{Include: []string{"app/*"}},
			Operations: types.CapabilityScope{Include: []string{"go"}},
		}},
		Granter:   types.SingleSigGranter(identity.ContentHash),
		Grantee:   identity.ContentHash,
		CreatedAt: 1000,
	}
	capEntity, err := capData.ToEntity()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := cs.Put(capEntity); err != nil {
		t.Fatal(err)
	}
	for _, p := range []string{parentURI, childURI} {
		if err := li.Set("system/capability/grants/"+p, capEntity.ContentHash); err != nil {
			t.Fatal(err)
		}
	}

	d := NewDispatcher(reg, cs, li, kp, nil)
	resp, err := d.DispatchLocalExecute(context.Background(), LocalExecuteRequest{
		URI:              parentURI,
		Operation:        "go",
		Params:           entity.Entity{},
		CallerCapability: capEntity,
	})
	if err != nil {
		t.Fatalf("dispatch: %v", err)
	}
	if resp.Status != 403 {
		t.Fatalf("sub-dispatch to a resource outside the grant's Resources scope returned %d, want 403 — §5.2 Dimension 3 (resource) was skipped on the in-process path (SA-PY-9): the child's authorization target was computed and propagated but never scope-checked.", resp.Status)
	}
	if childRan {
		t.Fatalf("the child handler RAN despite the caller's grant not covering resource \"pwn\" — the resource dimension did not gate the sub-dispatch")
	}
}

// TestSubDispatchNoResourceDoesNotInherit pins the no-resource ruling
// (ENTITY-CORE-PROTOCOL §5.2, 0.8.2; arch ROUTING-2026-08-18-g §5): a sub-dispatch
// that names NO resource has NONE. The child MUST NOT inherit the parent's
// resource targets — not into the §5.2 check, and not into the child handler
// context. go, py and rust are aligned on this after go recommended against its
// own prior inheritance (spec-issue 2026-08-18-b).
//
// Teeth: the parent runs with an in-scope entry resource (app/parent-data) and
// sub-dispatches WITHOUT naming a resource. The child records its own
// ctx.Resource. Under the old inherit-from-parent behavior the child would see
// app/parent-data; under the ruling it MUST see nil. If this test observes a
// non-nil child resource, the inheritance has regressed.
func TestSubDispatchNoResourceDoesNotInherit(t *testing.T) {
	kp, _ := crypto.Generate()
	cs := store.NewMemoryContentStore()
	li := store.NewNamespacedIndex(store.NewMemoryLocationIndex(), string(kp.PeerID()))

	const parentURI = "app/parent"
	const childURI = "app/child"

	var childResourceSeen *types.ResourceTarget
	childRan := false
	child := &fnHandler{name: "child", fn: func(ctx context.Context, req *handler.Request) (*handler.Response, error) {
		childRan = true
		childResourceSeen = req.Context.Resource
		return &handler.Response{Status: 200}, nil
	}}
	// Parent sub-dispatches WITHOUT WithResource — it names no resource of its own.
	parent := &fnHandler{name: "parent", fn: func(ctx context.Context, req *handler.Request) (*handler.Response, error) {
		return req.Context.Execute(ctx, childURI, "go", entity.Entity{})
	}}

	reg := handler.NewRegistry()
	reg.Register(parentURI, parent)
	reg.Register(childURI, child)
	if err := SeedHandlersFromRegistry(cs, li, reg); err != nil {
		t.Fatal(err)
	}

	identity, _ := kp.IdentityEntity()
	if _, err := cs.Put(identity); err != nil {
		t.Fatal(err)
	}
	capData := types.CapabilityTokenData{
		Grants: []types.GrantEntry{{
			Handlers:   types.CapabilityScope{Include: []string{"*"}},
			Resources:  types.CapabilityScope{Include: []string{"app/*"}},
			Operations: types.CapabilityScope{Include: []string{"go"}},
		}},
		Granter:   types.SingleSigGranter(identity.ContentHash),
		Grantee:   identity.ContentHash,
		CreatedAt: 1000,
	}
	capEntity, err := capData.ToEntity()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := cs.Put(capEntity); err != nil {
		t.Fatal(err)
	}
	for _, p := range []string{parentURI, childURI} {
		if err := li.Set("system/capability/grants/"+p, capEntity.ContentHash); err != nil {
			t.Fatal(err)
		}
	}

	d := NewDispatcher(reg, cs, li, kp, nil)
	// Entry carries an in-scope resource so the parent's own ctx.Resource is
	// non-nil — the value the old code would have inherited into the child.
	resp, err := d.DispatchLocalExecute(context.Background(), LocalExecuteRequest{
		URI:              parentURI,
		Operation:        "go",
		Params:           entity.Entity{},
		Resource:         &types.ResourceTarget{Targets: []string{"app/parent-data"}},
		CallerCapability: capEntity,
	})
	if err != nil {
		t.Fatalf("dispatch: %v", err)
	}
	if resp.Status != 200 {
		t.Fatalf("no-resource sub-dispatch returned %d, want 200 — a sub-dispatch naming no resource has none, so §5.2 Dimension 3 is deferred to the handler and the child runs", resp.Status)
	}
	if !childRan {
		t.Fatal("child did not run")
	}
	if childResourceSeen != nil {
		t.Fatalf("child inherited the parent's resource %v — §5.2 (0.8.2) says a sub-dispatch naming no resource has none; the child MUST NOT inherit", childResourceSeen.Targets)
	}
}
