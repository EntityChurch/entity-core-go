package continuation

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"testing"

	"go.entitychurch.org/entity-core-go/core/ecf"
	"go.entitychurch.org/entity-core-go/core/entity"
	"go.entitychurch.org/entity-core-go/core/handler"
	"go.entitychurch.org/entity-core-go/core/store"
	"go.entitychurch.org/entity-core-go/core/types"
)

// mustCapEntity builds a real (decodable) system/capability/token entity
// and puts it in the store. The F2 vector needs typed caps, not the opaque
// testCapHash stub: selectCapability decodes the caller cap to decide
// whether it covers the write path.
func mustCapEntity(t *testing.T, cs store.ContentStore, grants []types.GrantEntry) entity.Entity {
	t.Helper()
	capData := types.CapabilityTokenData{Grants: grants}
	ent, err := capData.ToEntity()
	if err != nil {
		t.Fatalf("cap ToEntity: %v", err)
	}
	if _, err := cs.Put(ent); err != nil {
		t.Fatalf("cap store: %v", err)
	}
	return ent
}

// TestF2_BindUnderDenial_MarkerRidesHandlerAuthority is the Go reference
// shape for PROPOSAL-CONTINUATION-LOST-ERROR-MARKER-MUST §4 vector 1 — the
// F2 vector, option (ii) adopted:
//
// A chain whose dispatch_capability does NOT cover
// system/runtime/chain-errors/** suffers an on_error dispatch failure. The
// lost marker MUST land anyway — bound at the observing peer's own tree
// under the CONTINUATION HANDLER'S OWN authority (never the chain's
// propagated cap), keyed by the original request ID (F1 ratification), with
// the W6 attribution split recorded (handler cap authorized; caller cap
// noted). This is what makes MUST-bind unconditionally satisfiable: the
// backstop cannot be broken by the very misconfiguration it exists to
// observe.
//
// Mechanism under test: HandlerContext.TreeSet → selectCapability — the
// caller cap is used only when it covers the write path; here it covers
// system/inbox/* only, so the write attributes to hctx.HandlerGrant
// (Go's continuation handler grant covers the namespace — default
// full-scope grant per createHandlerGrants; a precision-scoped
// internal_scope would satisfy the proposal identically).
func TestF2_BindUnderDenial_MarkerRidesHandlerAuthority(t *testing.T) {
	h := NewHandler()
	hctx := newTestContext()
	hctx.RequestID = "req-f2"
	hctx.Bounds = &types.BoundsData{ChainID: "chain-f2"}

	// Observable attribution: wrap the index so mutation context surfaces
	// on the sync hook's TreeChangeEvent.
	events := make(chan store.TreeChangeEvent, 64)
	done := make(chan struct{})
	defer close(done)
	go func() {
		for {
			select {
			case <-events:
			case <-done:
				return
			}
		}
	}()
	nli := store.NewNotifyingLocationIndex(hctx.LocationIndex, events, done)

	var mu sync.Mutex
	var captured []store.TreeChangeEvent
	nli.AddNamedSyncHookWithPattern("f2-capture", "system/runtime/chain-errors/lost/*",
		func(evt store.TreeChangeEvent) *store.ConsumerResult {
			mu.Lock()
			captured = append(captured, evt)
			mu.Unlock()
			return nil
		})
	hctx.LocationIndex = nli

	// The chain's cap covers system/inbox/* ONLY — the marker namespace is
	// explicitly outside it (the F11 misconfiguration, reproduced).
	callerCap := mustCapEntity(t, hctx.Store, []types.GrantEntry{{
		Handlers:   types.CapabilityScope{Include: []string{"system/continuation"}},
		Resources:  types.CapabilityScope{Include: []string{"system/inbox/*"}},
		Operations: types.CapabilityScope{Include: []string{"*"}},
	}})
	hctx.CallerCapability = callerCap

	// The continuation handler's own grant (createHandlerGrants default:
	// full scope — covers the managed namespace).
	handlerGrant := mustCapEntity(t, hctx.Store, []types.GrantEntry{{
		Handlers:   types.CapabilityScope{Include: []string{"*"}},
		Resources:  types.CapabilityScope{Include: []string{"*"}},
		Operations: types.CapabilityScope{Include: []string{"*"}},
	}})
	hctx.HandlerGrant = handlerGrant

	// on_error dispatch fails — and count dispatches for the §4
	// non-reactivity assertion.
	var dispatches int
	hctx.Execute = func(ctx context.Context, uri, op string, params entity.Entity, opts ...handler.ExecuteOption) (*handler.Response, error) {
		dispatches++
		return nil, fmt.Errorf("simulated on_error delivery failure")
	}

	storeContinuation(t, hctx, "system/inbox/f2-cb", types.ContinuationData{
		Target:             "system/tree",
		Operation:          "put",
		OnError:            &types.DeliverySpec{URI: "system/tree/error-log", Operation: "put"},
		DispatchCapability: callerCap.ContentHash,
	})

	resp, err := h.Handle(context.Background(),
		makeAdvanceRequest(t, hctx, "system/inbox/f2-cb", 500, map[string]interface{}{"code": "boom"}))
	if err != nil {
		t.Fatal(err)
	}
	if resp.Status != 200 {
		t.Fatalf("marker path must stay best-effort/non-blocking (200), got %d", resp.Status)
	}

	// 1. The marker LANDED despite the cap not covering the namespace,
	//    keyed by the original request ID (F1).
	prefix := "system/runtime/chain-errors/lost/chain-f2/req-f2/on_error_dispatch_failed/"
	entries := hctx.LocationIndex.List(prefix)
	if len(entries) != 1 {
		t.Fatalf("bind-under-denial: expected exactly 1 marker under %s, got %d — MUST-bind is not satisfiable under handler authority", prefix, len(entries))
	}
	mEnt, ok := hctx.Store.Get(entries[0].Hash)
	if !ok {
		t.Fatal("marker entity not in store")
	}
	var md types.ChainErrorLostData
	if err := ecf.Decode(mEnt.Data, &md); err != nil {
		t.Fatalf("decode marker: %v", err)
	}
	if md.StepIndex != "req-f2" || md.ChainID != "chain-f2" {
		t.Fatalf("marker key: got (chain=%q, step=%q), want (chain-f2, req-f2) — F1 RequestID ratification", md.ChainID, md.StepIndex)
	}

	// 2. Authority attribution (W6 split): the write was authorized by the
	//    HANDLER's grant; the denied caller cap is recorded alongside, not
	//    used.
	mu.Lock()
	defer mu.Unlock()
	var markerEvt *store.TreeChangeEvent
	for i := range captured {
		if strings.HasPrefix(captured[i].Path, prefix) {
			markerEvt = &captured[i]
			break
		}
	}
	if markerEvt == nil {
		t.Fatalf("sync hook never saw the marker bind (captured %d events)", len(captured))
	}
	if markerEvt.Context == nil {
		t.Fatalf("marker bind carried no mutation context — attribution unobservable")
	}
	if markerEvt.Context.CapabilityHash != handlerGrant.ContentHash {
		t.Fatalf("marker bind attributed to %s, want the handler grant %s — substrate surface rides substrate authority",
			markerEvt.Context.CapabilityHash, handlerGrant.ContentHash)
	}
	if markerEvt.Context.CallerCapabilityHash != callerCap.ContentHash {
		t.Fatalf("W6 attribution split lost: caller cap %s not recorded (got %s)",
			callerCap.ContentHash, markerEvt.Context.CallerCapabilityHash)
	}

	// 3. Non-reactivity (§4): the marker bind triggered nothing — the only
	//    dispatch was the failed on_error delivery itself.
	if dispatches != 1 {
		t.Fatalf("expected exactly 1 dispatch (the failed on_error), got %d — marker MUST NOT trigger reactive behavior", dispatches)
	}
}
