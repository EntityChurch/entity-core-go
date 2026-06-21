package protocol

import (
	"context"
	"testing"

	"go.entitychurch.org/entity-core-go/core/crypto"
	"go.entitychurch.org/entity-core-go/core/ecf"
	"go.entitychurch.org/entity-core-go/core/entity"
	"go.entitychurch.org/entity-core-go/core/handler"
	"go.entitychurch.org/entity-core-go/core/hash"
	"go.entitychurch.org/entity-core-go/core/store"
	"go.entitychurch.org/entity-core-go/core/types"

	"github.com/fxamacker/cbor/v2"
)

// envelopeHandler returns a system/envelope result entity with a non-empty
// inner included map — exactly the shape V7 v7.49 §3.3 specifies for
// multi-entity results.
type envelopeHandler struct{}

func (h *envelopeHandler) Handle(ctx context.Context, req *handler.Request) (*handler.Response, error) {
	// Build two leaf entities.
	rawA, _ := ecf.Encode(map[string]string{"k": "a"})
	leafA, _ := entity.NewEntity("test/leaf", cbor.RawMessage(rawA))
	rawB, _ := ecf.Encode(map[string]string{"k": "b"})
	leafB, _ := entity.NewEntity("test/leaf", cbor.RawMessage(rawB))

	// Build a root entity that references both by hash.
	rootRaw, _ := ecf.Encode(map[string]interface{}{
		"a": leafA.ContentHash,
		"b": leafB.ContentHash,
	})
	rootEnt, _ := entity.NewEntity("test/root", cbor.RawMessage(rootRaw))

	env := entity.NewEnvelope(rootEnt, map[hash.Hash]entity.Entity{
		leafA.ContentHash: leafA,
		leafB.ContentHash: leafB,
	})
	envEntity, _ := env.ToEntity()
	return &handler.Response{Status: 200, Result: envEntity}, nil
}
func (h *envelopeHandler) Name() string { return "envelope" }

// V7 v7.49 §3.3 dispatch-surface result equivalence: a handler's result MUST
// be identical regardless of how the handler was dispatched. When the result
// is a system/envelope, that envelope's inner `included` subtree MUST be
// preserved on every dispatch surface. This test exercises both internal
// (hctx.Execute) and entry-point (DispatchLocalExecute) paths on the same op
// returning the same multi-entity envelope, and asserts Result content-hash
// equality (which entails byte equality of the envelope including `included`).
func TestDispatchSurfaceEquivalence_EnvelopeIncludedPreserved(t *testing.T) {
	localKP, _ := crypto.Generate()
	localIdentity, _ := localKP.IdentityEntity()

	reg := handler.NewRegistry()
	reg.Register("test/envelope", &envelopeHandler{})
	reg.Register("test/delegate-env", &delegatingHandler{targetURI: "test/envelope"})

	cs := store.NewMemoryContentStore()
	li := store.NewNamespacedIndex(store.NewMemoryLocationIndex(), string(localKP.PeerID()))
	if err := SeedHandlersFromRegistry(cs, li, reg); err != nil {
		t.Fatal(err)
	}
	d := NewDispatcher(reg, cs, li, localKP, nil)
	if _, err := cs.Put(localIdentity); err != nil {
		t.Fatal(err)
	}

	// Wildcard caller cap; also serves as placeholder grant entity for the
	// delegating handler (validation is skipped because LocalIdentityHash is
	// zero in this test context).
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
	// Seed test/delegate-env's handler grant (V7 v7.49 §6.8 — sub-dispatch
	// from inside a handler gates on the parent's HandlerGrant).
	if err := li.Set("system/capability/grants/test/delegate-env", callerCap.ContentHash); err != nil {
		t.Fatal(err)
	}

	paramsRaw, _ := ecf.Encode("ignored")
	paramsEnt, _ := entity.NewEntity("test/params", cbor.RawMessage(paramsRaw))

	// Entry-point dispatch directly to the envelope handler.
	respDirect, err := d.DispatchLocalExecute(context.Background(), LocalExecuteRequest{
		URI:              "test/envelope",
		Operation:        "build",
		Params:           paramsEnt,
		CallerCapability: callerCap,
		Author:           localKP.PeerID(),
		AuthorHash:       localIdentity.ContentHash,
	})
	if err != nil {
		t.Fatalf("direct dispatch: %v", err)
	}
	if respDirect.Status != 200 {
		t.Fatalf("direct dispatch status: %d", respDirect.Status)
	}
	if respDirect.Result.Type != "system/envelope" {
		t.Fatalf("direct dispatch result type: %s", respDirect.Result.Type)
	}

	// Dispatch through delegate: enters via the entry point, then the
	// delegating handler calls hctx.Execute → exercises the internal
	// sub-dispatch surface.
	respDelegated, err := d.DispatchLocalExecute(context.Background(), LocalExecuteRequest{
		URI:              "test/delegate-env",
		Operation:        "build",
		Params:           paramsEnt,
		CallerCapability: callerCap,
		Author:           localKP.PeerID(),
		AuthorHash:       localIdentity.ContentHash,
	})
	if err != nil {
		t.Fatalf("delegated dispatch: %v", err)
	}
	if respDelegated.Status != 200 {
		t.Fatalf("delegated dispatch status: %d", respDelegated.Status)
	}
	if respDelegated.Result.Type != "system/envelope" {
		t.Fatalf("delegated dispatch result type: %s", respDelegated.Result.Type)
	}

	// Result content-hash equality across surfaces. Hash is computed over
	// (type, data); data is RawMessage (the envelope's CBOR bytes including
	// `included`); equality of hash entails byte equality of the inner
	// included subtree.
	if respDirect.Result.ContentHash != respDelegated.Result.ContentHash {
		t.Fatalf("V7 v7.49 §3.3 violation: result hash differs across dispatch surfaces\n"+
			"  direct (entry-point):  %s\n"+
			"  via hctx.Execute:      %s",
			respDirect.Result.ContentHash, respDelegated.Result.ContentHash)
	}

	// Decode the envelope and assert inner Included is non-empty. Belt-and-
	// suspenders — the hash equality already implies this, but a future
	// regression that returned an empty envelope from both surfaces would
	// pass hash equality vacuously.
	var env entity.Envelope
	if err := ecf.Decode(respDirect.Result.Data, &env); err != nil {
		t.Fatalf("decode envelope: %v", err)
	}
	if len(env.Included) != 2 {
		t.Fatalf("expected 2 included entities, got %d", len(env.Included))
	}
}
