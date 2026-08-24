package protocol

import (
	"context"
	"testing"

	"go.entitychurch.org/entity-core-go/core/crypto"
	"go.entitychurch.org/entity-core-go/core/ecf"
	"go.entitychurch.org/entity-core-go/core/entity"
	"go.entitychurch.org/entity-core-go/core/handler"
	"go.entitychurch.org/entity-core-go/core/store"
	"go.entitychurch.org/entity-core-go/core/types"

	"github.com/fxamacker/cbor/v2"
)

// resourceRecordingHandler runs at 200 and records the resource its context
// carried, so a test can assert the §5.2 Dimension-3 resource actually reached
// the handler rather than being dropped in the dispatch plumbing.
type resourceRecordingHandler struct {
	ran  bool
	seen *types.ResourceTarget
}

func (h *resourceRecordingHandler) Handle(_ context.Context, req *handler.Request) (*handler.Response, error) {
	h.ran = true
	h.seen = req.Context.Resource
	return &handler.Response{Status: 200, Result: req.Params}, nil
}

func (h *resourceRecordingHandler) Name() string { return "resource-record" }

// TestDispatchLocalExecute_CarriesResourceToHandler pins that the ENTRY-POINT
// in-process dispatch (DispatchLocalExecute — how every SDK consumer dispatches)
// delivers the caller-named resource to the handler's context, exactly as wire
// entry does (execute.go seeds hctx.Resource = normalizeResourceTargets(...)).
//
// This is the coverage gap workbench-go's packet named: subdispatch_resource_
// dimension_test.go exercises both sub-dispatch directions (via hctx.Execute) but
// never enters through DispatchLocalExecute, so the entry-point drop — rootCtx.Resource
// was set but never passed as the WithResource opt, and makeLocalExecute's child
// takes its resource from execOpts, not callerCtx — was invisible. Before the fix
// the handler runs at 200 and sees Resource == nil; after it, it sees the resource.
func TestDispatchLocalExecute_CarriesResourceToHandler(t *testing.T) {
	localKP, _ := crypto.Generate()
	localIdentity, _ := localKP.IdentityEntity()

	rec := &resourceRecordingHandler{}
	reg := handler.NewRegistry()
	reg.Register("test/resource-record", rec)

	cs := store.NewMemoryContentStore()
	li := store.NewNamespacedIndex(store.NewMemoryLocationIndex(), string(localKP.PeerID()))
	if err := SeedHandlersFromRegistry(cs, li, reg); err != nil {
		t.Fatal(err)
	}
	d := NewDispatcher(reg, cs, li, localKP, nil)
	if _, err := cs.Put(localIdentity); err != nil {
		t.Fatal(err)
	}

	// Wildcard caller cap — the L1 gate at entry. Resource wildcard so the
	// Dimension-3 check is not what would drop the request; the point is that the
	// resource reaches the handler, not whether it authorizes.
	capData := types.CapabilityTokenData{
		Grants: []types.GrantEntry{{
			Handlers:   types.CapabilityScope{Include: []string{"*"}},
			Resources:  types.CapabilityScope{Include: []string{"*"}},
			Operations: types.CapabilityScope{Include: []string{"*"}},
		}},
		Granter:   types.SingleSigGranter(localIdentity.ContentHash),
		Grantee:   localIdentity.ContentHash,
		CreatedAt: 1,
	}
	callerCap, _ := capData.ToEntity()
	if _, err := cs.Put(callerCap); err != nil {
		t.Fatal(err)
	}

	paramsRaw, _ := ecf.Encode("ignored")
	paramsEnt, _ := entity.NewEntity("test/params", cbor.RawMessage(paramsRaw))

	// A local-peer resource the wildcard cap covers (bare "*" canonicalizes to
	// /{localPeer}/*), and one normalization leaves unchanged (a bare absolute
	// path, not an entity://localPeer/ URI), so the expected value is exact and
	// the L1 Dimension-3 check — which now SEES the resource — authorizes it.
	wantTarget := "/" + string(localKP.PeerID()) + "/local/files/doc"
	resource := &types.ResourceTarget{Targets: []string{wantTarget}}

	resp, err := d.DispatchLocalExecute(context.Background(), LocalExecuteRequest{
		URI:              "test/resource-record",
		Operation:        "noop",
		Params:           paramsEnt,
		CallerCapability: callerCap,
		Resource:         resource,
		Author:           localKP.PeerID(),
		AuthorHash:       localIdentity.ContentHash,
	})
	if err != nil {
		t.Fatalf("dispatch: %v", err)
	}
	if resp.Status != 200 {
		t.Fatalf("dispatch status: %d (the handler must run — the drop is silent, at 200)", resp.Status)
	}
	if !rec.ran {
		t.Fatal("handler never ran")
	}
	// The bug: handler runs at 200 but sees Resource == nil.
	if rec.seen == nil {
		t.Fatal("handler saw Resource == nil — the entry-point dispatch dropped the caller-named resource (DispatchLocalExecute must pass WithResource, mirroring wire entry)")
	}
	if len(rec.seen.Targets) != 1 || rec.seen.Targets[0] != wantTarget {
		t.Fatalf("handler saw Resource targets %v, want [%q]", rec.seen.Targets, wantTarget)
	}
}
