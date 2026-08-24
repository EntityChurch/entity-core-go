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

// selfDispatchHandler stands in for a self-referential continuation chain: each
// invocation dispatches back into itself at depth+1, exactly as a continuation
// whose advancement re-triggers its own inbox path would. Nothing else stops
// it — that is the point.
type selfDispatchHandler struct {
	uri    string
	calls  *int
	status *uint
}

// fnHandler adapts a func to handler.Handler (the package has no HandlerFunc).
type fnHandler struct {
	name string
	fn   func(ctx context.Context, req *handler.Request) (*handler.Response, error)
}

func (h *fnHandler) Name() string { return h.name }
func (h *fnHandler) Handle(ctx context.Context, req *handler.Request) (*handler.Response, error) {
	return h.fn(ctx, req)
}

func (h *selfDispatchHandler) Name() string { return "self-dispatch" }

func (h *selfDispatchHandler) Handle(ctx context.Context, req *handler.Request) (*handler.Response, error) {
	*h.calls++
	hctx := req.Context
	resp, err := hctx.Execute(ctx, h.uri, "loop", entity.Entity{},
		handler.WithChainDepth(hctx.ChainDepth+1))
	if err != nil {
		return nil, err
	}
	*h.status = resp.Status
	return resp, nil
}

// seedWildcardGrant mints a wildcard capability, stores it, and binds it as the
// handler grant for each pattern (V7 §6.8 gates sub-dispatch on the executing
// handler's grant). Returns the cap entity for use as the caller capability.
func seedWildcardGrant(t *testing.T, kp crypto.Keypair, cs store.ContentStore, li store.LocationIndex, ops []string, patterns ...string) entity.Entity {
	t.Helper()
	identity, _ := kp.IdentityEntity()
	if _, err := cs.Put(identity); err != nil { // the granter must be resolvable
		t.Fatal(err)
	}
	capData := types.CapabilityTokenData{
		Grants: []types.GrantEntry{{
			Handlers:   types.CapabilityScope{Include: []string{"*"}},
			Resources:  types.CapabilityScope{Include: []string{"*"}},
			Operations: types.CapabilityScope{Include: ops},
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
	for _, p := range patterns {
		if err := li.Set("system/capability/grants/"+p, capEntity.ContentHash); err != nil {
			t.Fatal(err)
		}
	}
	return capEntity
}

func newDepthTestDispatcher(t *testing.T, uri string, calls *int, last *uint) (*Dispatcher, entity.Entity) {
	t.Helper()
	kp, _ := crypto.Generate()
	reg := handler.NewRegistry()
	reg.Register(uri, &selfDispatchHandler{uri: uri, calls: calls, status: last})
	cs := store.NewMemoryContentStore()
	li := store.NewNamespacedIndex(store.NewMemoryLocationIndex(), string(kp.PeerID()))
	if err := SeedHandlersFromRegistry(cs, li, reg); err != nil {
		t.Fatal(err)
	}
	capEntity := seedWildcardGrant(t, kp, cs, li, []string{"loop"}, uri)
	return NewDispatcher(reg, cs, li, kp, nil), capEntity
}

// EXTENSION-CONTINUATION §3.9: the dispatch layer bounds continuation
// advancement depth and refuses past the maximum.
//
// This is the brake that makes step 6's fresh TTL/budget safe (arch ruling 15).
// A chain that dispatches back into its own trigger refills ttl at every hop,
// so ttl can never exhaust and cannot terminate it. Without this counter the
// call below does not return — it recurses until the goroutine stack dies.
// A passing run IS the termination proof.
func TestSelfReferentialChainTerminatesAtMaxDepth(t *testing.T) {
	const uri = "system/test/loop"
	calls := 0
	var last uint
	d, callerCap := newDepthTestDispatcher(t, uri, &calls, &last)
	d.MaxChainDepth = 8 // small, so the test is fast; the default is 64

	resp, err := d.DispatchLocalExecute(context.Background(), LocalExecuteRequest{
		URI:              uri,
		Operation:        "loop",
		Params:           entity.Entity{},
		CallerCapability: callerCap,
	})
	if err != nil {
		t.Fatalf("dispatch returned a Go error: %v", err)
	}
	if resp == nil {
		t.Fatal("nil response")
	}

	// Depth 0 (entry) then 1..8 are permitted; 9 is the first refusal, so the
	// handler runs 9 times and the innermost dispatch is refused.
	if want := 9; calls != want {
		t.Errorf("handler ran %d times, want %d — the ceiling is off by %d",
			calls, want, calls-want)
	}
	if last != 429 {
		t.Errorf("innermost dispatch returned %d, want 429 bounds_exceeded (§3.9 groups chain depth with ttl/budget exhaustion)", last)
	}
}

// The ceiling must not fire on ordinary traffic: a dispatch that does not
// advance a continuation inherits the caller's depth unchanged, so a handler
// calling a handler forever-wide (rather than deep) is unaffected.
func TestOrdinarySubDispatchDoesNotConsumeChainDepth(t *testing.T) {
	kp, _ := crypto.Generate()
	reg := handler.NewRegistry()

	var sawDepth uint64
	reg.Register("system/test/leaf", &fnHandler{name: "leaf", fn: func(ctx context.Context, req *handler.Request) (*handler.Response, error) {
		sawDepth = req.Context.ChainDepth
		return &handler.Response{Status: 200}, nil
	}})
	reg.Register("system/test/caller", &fnHandler{name: "caller", fn: func(ctx context.Context, req *handler.Request) (*handler.Response, error) {
		// No WithChainDepth — an ordinary sub-dispatch.
		return req.Context.Execute(ctx, "system/test/leaf", "go", entity.Entity{})
	}})

	cs := store.NewMemoryContentStore()
	li := store.NewNamespacedIndex(store.NewMemoryLocationIndex(), string(kp.PeerID()))
	if err := SeedHandlersFromRegistry(cs, li, reg); err != nil {
		t.Fatal(err)
	}
	callerCap := seedWildcardGrant(t, kp, cs, li, []string{"go"}, "system/test/caller", "system/test/leaf")
	d := NewDispatcher(reg, cs, li, kp, nil)
	d.MaxChainDepth = 2

	resp, err := d.DispatchLocalExecute(context.Background(), LocalExecuteRequest{
		URI:              "system/test/caller",
		Operation:        "go",
		Params:           entity.Entity{},
		CallerCapability: callerCap,
	})
	if err != nil {
		t.Fatalf("dispatch error: %v", err)
	}
	if resp.Status != 200 {
		t.Fatalf("ordinary sub-dispatch got %d, want 200 — the §3.9 ceiling must only count continuation advancements", resp.Status)
	}
	if sawDepth != 0 {
		t.Errorf("leaf saw chain depth %d, want 0 (an ordinary sub-dispatch inherits, it does not increment)", sawDepth)
	}
}

// §8.4: the maximum is implementation-defined and SHOULD default to 64.
func TestMaxChainDepthDefaultsTo64(t *testing.T) {
	d := &Dispatcher{}
	if got := d.maxChainDepth(); got != 64 {
		t.Errorf("unconfigured maxChainDepth() = %d, want 64 (§8.4 SHOULD default)", got)
	}
	d.MaxChainDepth = 5
	if got := d.maxChainDepth(); got != 5 {
		t.Errorf("configured maxChainDepth() = %d, want 5", got)
	}
}
