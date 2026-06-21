package inbox

import (
	"context"
	"testing"
	"time"

	"go.entitychurch.org/entity-core-go/core/ecf"
	"go.entitychurch.org/entity-core-go/core/entity"
	"go.entitychurch.org/entity-core-go/core/handler"
	"go.entitychurch.org/entity-core-go/core/hash"
	"go.entitychurch.org/entity-core-go/core/store"
	"go.entitychurch.org/entity-core-go/core/types"

	"github.com/fxamacker/cbor/v2"
)

func newTestContext() *handler.HandlerContext {
	return &handler.HandlerContext{
		Store:          store.NewMemoryContentStore(),
		LocationIndex:  store.NewMemoryLocationIndex(),
		HandlerPattern: "system/inbox",
		RequestID:      "test-req-1",
		Included:       make(map[hash.Hash]entity.Entity),
	}
}

func TestReceiveStoresAtCorrectPath(t *testing.T) {
	h := NewHandler()

	msgData, _ := ecf.Encode(map[string]interface{}{"hello": "world"})
	params, err := entity.NewEntity("primitive/any", cbor.RawMessage(msgData))
	if err != nil {
		t.Fatal(err)
	}

	hctx := newTestContext()
	hctx.Resource = &types.ResourceTarget{Targets: []string{"system/inbox/my-results"}}

	req := &handler.Request{
		Path:      "system/inbox/my-results",
		Operation: "receive",
		Params:    params,
		Context:   hctx,
	}

	resp, err := h.Handle(context.Background(), req)
	if err != nil {
		t.Fatal(err)
	}
	if resp.Status != 200 {
		t.Fatalf("expected status 200, got %d", resp.Status)
	}

	expectedPath := "system/inbox/my-results/test-req-1"
	if !hctx.LocationIndex.Has(expectedPath) {
		t.Fatalf("expected entity at path %s", expectedPath)
	}
}

func TestReceiveWithContinuationDelegates(t *testing.T) {
	h := NewHandler()
	hctx := newTestContext()

	advanceCh := make(chan bool, 1)
	hctx.Execute = func(ctx context.Context, uri, op string, params entity.Entity, opts ...handler.ExecuteOption) (*handler.Response, error) {
		advanceCh <- true
		if op != "advance" {
			t.Fatalf("expected advance operation, got %s", op)
		}
		resultRaw, _ := ecf.Encode(map[string]interface{}{"advanced": true})
		resultEntity, _ := entity.NewEntity("system/continuation/advancement-result", cbor.RawMessage(resultRaw))
		return &handler.Response{Status: 200, Result: resultEntity}, nil
	}

	// Create a dummy capability entity for dispatch.
	capData, _ := ecf.Encode(map[string]interface{}{"scope": "test"})
	capEnt, _ := entity.NewEntity("system/capability/grant", cbor.RawMessage(capData))
	capHash, _ := hctx.Store.Put(capEnt)

	// Write a continuation at the inbox path.
	remaining := uint64(1)
	cont := types.ContinuationData{
		Target:              "system/tree",
		Operation:           "put",
		RemainingExecutions: &remaining,
		DispatchCapability:  capHash,
	}
	contEntity, _ := cont.ToEntity()
	contHash, _ := hctx.Store.Put(contEntity)
	hctx.LocationIndex.Set("system/inbox/with-cont", contHash)

	msgData, _ := ecf.Encode(map[string]interface{}{"value": 42})
	params, _ := entity.NewEntity("primitive/any", cbor.RawMessage(msgData))

	hctx.Resource = &types.ResourceTarget{Targets: []string{"system/inbox/with-cont"}}
	req := &handler.Request{
		Path:      "system/inbox/with-cont",
		Operation: "receive",
		Params:    params,
		Context:   hctx,
	}

	resp, err := h.Handle(context.Background(), req)
	if err != nil {
		t.Fatal(err)
	}
	if resp.Status != 200 {
		t.Fatalf("expected status 200, got %d", resp.Status)
	}
	// Advance runs async — wait for it with timeout.
	select {
	case <-advanceCh:
		// ok
	case <-time.After(2 * time.Second):
		t.Fatal("expected advance to be called")
	}

	// Cleanup runs in the goroutine after advance returns — give it time to complete.
	storagePath := "system/inbox/with-cont/test-req-1"
	deadline := time.After(2 * time.Second)
	for hctx.LocationIndex.Has(storagePath) {
		select {
		case <-deadline:
			t.Fatal("stored message should have been cleaned up after advancement")
		default:
			time.Sleep(time.Millisecond)
		}
	}
}

func TestReceiveNoContinuationStores(t *testing.T) {
	h := NewHandler()
	hctx := newTestContext()

	msgData, _ := ecf.Encode(map[string]interface{}{"data": "test"})
	params, _ := entity.NewEntity("primitive/any", cbor.RawMessage(msgData))

	hctx.Resource = &types.ResourceTarget{Targets: []string{"system/inbox/no-cont"}}
	req := &handler.Request{
		Path:      "system/inbox/no-cont",
		Operation: "receive",
		Params:    params,
		Context:   hctx,
	}

	resp, err := h.Handle(context.Background(), req)
	if err != nil {
		t.Fatal(err)
	}
	if resp.Status != 200 {
		t.Fatalf("expected status 200, got %d", resp.Status)
	}

	// Message should be stored.
	storagePath := "system/inbox/no-cont/test-req-1"
	if !hctx.LocationIndex.Has(storagePath) {
		t.Fatalf("expected message stored at %s", storagePath)
	}
}

func TestUnknownOperationReturns400(t *testing.T) {
	h := NewHandler()
	hctx := newTestContext()
	hctx.Resource = &types.ResourceTarget{Targets: []string{"system/inbox/test"}}

	req := &handler.Request{
		Path:      "system/inbox/test",
		Operation: "invalid",
		Params:    entity.Entity{},
		Context:   hctx,
	}

	resp, err := h.Handle(context.Background(), req)
	if err != nil {
		t.Fatal(err)
	}
	if resp.Status != 400 {
		t.Fatalf("expected status 400, got %d", resp.Status)
	}
}

func TestReceiveMissingResourceReturns400(t *testing.T) {
	h := NewHandler()
	hctx := newTestContext()
	// No resource target set.

	req := &handler.Request{
		Path:      "system/inbox/test",
		Operation: "receive",
		Params:    entity.Entity{},
		Context:   hctx,
	}

	resp, err := h.Handle(context.Background(), req)
	if err != nil {
		t.Fatal(err)
	}
	if resp.Status != 400 {
		t.Fatalf("expected status 400, got %d", resp.Status)
	}
}

func TestManifest(t *testing.T) {
	h := NewHandler()
	m := h.Manifest()
	if m.Pattern != "system/inbox" {
		t.Fatalf("expected pattern system/inbox, got %s", m.Pattern)
	}
	if m.Name != "inbox" {
		t.Fatalf("expected name inbox, got %s", m.Name)
	}
	if _, ok := m.Operations["receive"]; !ok {
		t.Fatal("missing receive operation")
	}
}
