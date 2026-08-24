package protocol

import (
	"context"
	"testing"

	"github.com/fxamacker/cbor/v2"

	"go.entitychurch.org/entity-core-go/core/crypto"
	"go.entitychurch.org/entity-core-go/core/ecf"
	"go.entitychurch.org/entity-core-go/core/entity"
	"go.entitychurch.org/entity-core-go/core/handler"
	"go.entitychurch.org/entity-core-go/core/store"
	"go.entitychurch.org/entity-core-go/core/types"
)

// PROPOSAL-CONTINUATION-BOUNDS-PROPAGATION anchor 3: an originated cross-peer
// continuation advancement MUST carry system/bounds with chain_id, chain_depth,
// ttl (and budget) populated. Before this fix the remote branch of
// makeLocalExecute built a delivery carrier and dropped bounds, so the counter
// reset at every peer boundary and nothing globally bounded a cross-peer chain.
func TestChainDepthRidesCrossPeerBounds(t *testing.T) {
	kp, _ := crypto.Generate()
	remoteKP, _ := crypto.Generate()
	remoteURI := "entity://" + string(remoteKP.PeerID()) + "/system/test/target"

	reg := handler.NewRegistry()
	reg.Register("system/test/advance", &fnHandler{name: "advance", fn: func(ctx context.Context, req *handler.Request) (*handler.Response, error) {
		ttl := uint64(5)
		// A continuation advancement across the wire: caller+1, carrying its
		// resource bounds and correlation id (the shape ext/continuation
		// advanceForward produces).
		return req.Context.Execute(ctx, remoteURI, "loop", entity.Entity{},
			handler.WithChainDepth(req.Context.ChainDepth+1),
			handler.WithBounds(&types.BoundsData{ChainID: "chain-1", TTL: &ttl}))
	}})

	cs := store.NewMemoryContentStore()
	li := store.NewNamespacedIndex(store.NewMemoryLocationIndex(), string(kp.PeerID()))
	if err := SeedHandlersFromRegistry(cs, li, reg); err != nil {
		t.Fatal(err)
	}
	callerCap := seedWildcardGrant(t, kp, cs, li, []string{"loop"}, "system/test/advance")
	d := NewDispatcher(reg, cs, li, kp, nil)

	var captured *types.BoundsData
	var sawAsync int
	d.RemoteExecute = func(ctx context.Context, uri, op string, params entity.Entity, resource *types.ResourceTarget, async ...*AsyncDelivery) (*handler.Response, error) {
		sawAsync = len(async)
		if len(async) > 0 && async[0] != nil {
			captured = async[0].Bounds
		}
		return &handler.Response{Status: 200}, nil
	}

	resp, err := d.DispatchLocalExecute(context.Background(), LocalExecuteRequest{
		URI: "system/test/advance", Operation: "loop",
		Params: entity.Entity{}, CallerCapability: callerCap,
	})
	if err != nil {
		t.Fatalf("dispatch: %v", err)
	}
	if resp.Status != 200 {
		t.Fatalf("status %d, want 200", resp.Status)
	}
	if sawAsync == 0 || captured == nil {
		t.Fatal("cross-peer advancement carried no bounds — the remote branch dropped them (PROPOSAL §3 MUST NOT drop bounds)")
	}
	if captured.ChainDepth == nil || *captured.ChainDepth != 1 {
		t.Errorf("bounds.chain_depth = %v, want 1 (caller depth 0, advancement +1)", captured.ChainDepth)
	}
	if captured.ChainID != "chain-1" {
		t.Errorf("bounds.chain_id = %q, want \"chain-1\" (correlation must ride the wire)", captured.ChainID)
	}
	if captured.TTL == nil || *captured.TTL != 5 {
		t.Errorf("bounds.ttl = %v, want 5 (per-advancement resource bound must ride the wire)", captured.TTL)
	}
}

// The "ordinary remote dispatch, unchanged" invariant: a plain cross-peer call
// that is NOT within a chain (depth 0, no bounds) must invent no bounds — we do
// not add wire noise to every remote dispatch, only to chain-participating ones.
func TestOrdinaryRemoteDispatchAddsNoBounds(t *testing.T) {
	kp, _ := crypto.Generate()
	remoteKP, _ := crypto.Generate()
	remoteURI := "entity://" + string(remoteKP.PeerID()) + "/system/test/target"

	reg := handler.NewRegistry()
	reg.Register("system/test/plain", &fnHandler{name: "plain", fn: func(ctx context.Context, req *handler.Request) (*handler.Response, error) {
		return req.Context.Execute(ctx, remoteURI, "get", entity.Entity{})
	}})

	cs := store.NewMemoryContentStore()
	li := store.NewNamespacedIndex(store.NewMemoryLocationIndex(), string(kp.PeerID()))
	if err := SeedHandlersFromRegistry(cs, li, reg); err != nil {
		t.Fatal(err)
	}
	callerCap := seedWildcardGrant(t, kp, cs, li, []string{"get"}, "system/test/plain")
	d := NewDispatcher(reg, cs, li, kp, nil)

	sawAsync := -1
	d.RemoteExecute = func(ctx context.Context, uri, op string, params entity.Entity, resource *types.ResourceTarget, async ...*AsyncDelivery) (*handler.Response, error) {
		sawAsync = len(async)
		return &handler.Response{Status: 200}, nil
	}

	if _, err := d.DispatchLocalExecute(context.Background(), LocalExecuteRequest{
		URI: "system/test/plain", Operation: "get",
		Params: entity.Entity{}, CallerCapability: callerCap,
	}); err != nil {
		t.Fatalf("dispatch: %v", err)
	}
	if sawAsync != 0 {
		t.Errorf("ordinary remote dispatch attached %d async carriers, want 0 — bounds must not be invented for a non-chain dispatch", sawAsync)
	}
}

// Anchor 1 (the wire half): chain_depth is a real system/bounds member that
// survives the deterministic-CBOR wire encoding and is read back on ingress, so
// the value tested at the ceiling is the GLOBAL chain length, not per-peer. A
// bounds with no chain_depth — a fresh external trigger firing a standing
// continuation — roots fresh at 0 (§5).
func TestChainDepthSurvivesWireRoundTripAndInherits(t *testing.T) {
	enc, err := ecf.Encode(stampChainDepth(nil, 7))
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	var got types.BoundsData
	if err := cbor.Unmarshal(enc, &got); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if d := inheritedChainDepth(&got); d != 7 {
		t.Errorf("after wire round trip, inherited chain_depth = %d, want 7 — the field did not survive as a system/bounds member", d)
	}
	if d := inheritedChainDepth(&types.BoundsData{ChainID: "c"}); d != 0 {
		t.Errorf("bounds carrying no chain_depth inherited %d, want 0 (fresh external trigger roots fresh — §5)", d)
	}
	if d := inheritedChainDepth(nil); d != 0 {
		t.Errorf("nil bounds inherited %d, want 0", d)
	}
}

// stampChainDepth semantics: depth 0 is the root (top-level / fresh trigger /
// operator resume) and MUST carry no chain_depth — including stripping a stale
// one, which is how §7 resume roots fresh. A non-zero depth is stamped,
// materializing bounds when the dispatch had none.
func TestStampChainDepthRootAndStamp(t *testing.T) {
	if stampChainDepth(nil, 0) != nil {
		t.Error("depth-0 nil-bounds dispatch must stay nil (ordinary dispatch unchanged)")
	}
	stale := uint64(9)
	out := stampChainDepth(&types.BoundsData{ChainID: "c", ChainDepth: &stale}, 0)
	if out.ChainDepth != nil {
		t.Errorf("root dispatch (depth 0) left chain_depth = %d, want nil (§7 resume/root roots fresh)", *out.ChainDepth)
	}
	if out.ChainID != "c" {
		t.Errorf("root strip clobbered chain_id = %q, want \"c\"", out.ChainID)
	}
	got := stampChainDepth(nil, 3)
	if got == nil || got.ChainDepth == nil || *got.ChainDepth != 3 {
		t.Errorf("stampChainDepth(nil, 3) = %+v, want chain_depth 3 materialized", got)
	}
}
