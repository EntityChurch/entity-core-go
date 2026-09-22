package conformance

import (
	"context"
	"testing"

	"go.entitychurch.org/entity-core-go/core/ecf"
	"go.entitychurch.org/entity-core-go/core/entity"
	"go.entitychurch.org/entity-core-go/core/handler"

	"github.com/fxamacker/cbor/v2"
)

// TestDispatchOutboundManifestGrantIsNarrow pins the GUIDE-CONFORMANCE §7a.1 ⛔
// scaffold-contract requirement: the dispatch-outbound handler declares a NARROW
// InternalScope (echo only), NOT the wide default self-grant. This is the F63
// enabler — a wide grant makes the compose-vs-bypass wire discriminator vacuous
// (both readings return the same answer for every input). A regression that
// drops InternalScope silently restores the omnipotent default, so this guards
// it deterministically.
//
// Mutation witness: removing the InternalScope field falls back to the §6.9
// default self-grant (Handlers/Operations = "*"), and this reddens.
func TestDispatchOutboundManifestGrantIsNarrow(t *testing.T) {
	m := NewDispatchOutboundHandler().Manifest()
	if len(m.InternalScope) == 0 {
		t.Fatal("dispatch-outbound MUST declare a narrow InternalScope (§7a.1 ⛔) — an absent scope falls back to the wide default self-grant, which makes the F63 discriminator vacuous")
	}
	// Every declared grant must be operation-narrow: no "*" in Operations, and
	// the only operation is echo. A wildcard operation is exactly the wide grant
	// the requirement forbids.
	for i, g := range m.InternalScope {
		for _, op := range g.Operations.Include {
			if op == "*" {
				t.Fatalf("InternalScope[%d] includes operation \"*\" — the grant must be a fixed op set (§7a.1 ⛔), not a wildcard", i)
			}
			if op != "echo" {
				t.Fatalf("InternalScope[%d] includes unexpected operation %q — the declared minimum is echo only", i, op)
			}
		}
		for _, h := range g.Handlers.Include {
			if h == "*" {
				t.Fatalf("InternalScope[%d] includes handler \"*\" — the grant must be scoped to system/validate/echo, not a wildcard", i)
			}
			if h != PatternEcho {
				t.Fatalf("InternalScope[%d] includes unexpected handler %q — the declared minimum is %s only", i, h, PatternEcho)
			}
		}
	}
}

// recordingExecute returns a HandlerContext whose Execute records whether it was
// called and answers 200 with a zero result entity, so an ambient dispatch can
// proceed and a refused/rejected one can be observed as "never reached Execute".
func recordingExecute(called *bool) *handler.HandlerContext {
	return &handler.HandlerContext{
		Execute: func(ctx context.Context, uri, operation string, params entity.Entity, opts ...handler.ExecuteOption) (*handler.Response, error) {
			*called = true
			return &handler.Response{Status: 200, Result: entity.Entity{}}, nil
		},
	}
}

func mustDispatchParams(t *testing.T, m map[string]interface{}) entity.Entity {
	t.Helper()
	raw, err := ecf.Encode(m)
	if err != nil {
		t.Fatalf("encode params map: %v", err)
	}
	ent, err := entity.NewEntity("primitive/any", cbor.RawMessage(raw))
	if err != nil {
		t.Fatalf("build params entity: %v", err)
	}
	return ent
}

// TestDispatchOutboundPartialTripleRejected pins the §7a.1 all-or-none rule: a
// PARTIAL reentry authority set (credential present, granters/signatures absent)
// is malformed — 400 invalid_params — not silently treated as ambient. A partial
// credential that degraded to ambient would run the ambient authority arm with a
// caller who thinks they presented authority; the refusal must be explicit.
func TestDispatchOutboundPartialTripleRejected(t *testing.T) {
	h := NewDispatchOutboundHandler()
	dummy, err := ecf.Encode(map[string]interface{}{"placeholder": true})
	if err != nil {
		t.Fatal(err)
	}
	called := false
	req := &handler.Request{
		Operation: "dispatch",
		Params: mustDispatchParams(t, map[string]interface{}{
			"target":             "entity://peer/system/validate/echo",
			"operation":          "echo",
			"reentry_capability": cbor.RawMessage(dummy),
			// reentry_granters / reentry_cap_signatures deliberately omitted.
		}),
		Context: recordingExecute(&called),
	}
	resp, err := h.Handle(context.Background(), req)
	if err != nil {
		t.Fatalf("handle: %v", err)
	}
	if resp.Status != 400 {
		t.Fatalf("partial reentry triple: status %d, want 400 invalid_params (§7a.1 all-or-none)", resp.Status)
	}
	if called {
		t.Fatal("partial reentry triple reached Execute — a malformed credential must be refused at param validation, not dispatched")
	}
}

// TestDispatchOutboundAmbientProceeds is the control: with NO reentry authority
// at all (the ambient arm), the handler proceeds to the outbound sub-dispatch
// (which the peer's own §5.2/§6.8 gate then evaluates). Without this control the
// partial-rejection test would pass on a handler that refuses everything.
func TestDispatchOutboundAmbientProceeds(t *testing.T) {
	h := NewDispatchOutboundHandler()
	valueRaw, err := ecf.Encode(map[string]interface{}{"value": "x"})
	if err != nil {
		t.Fatal(err)
	}
	called := false
	req := &handler.Request{
		Operation: "dispatch",
		Params: mustDispatchParams(t, map[string]interface{}{
			"target":    "entity://peer/system/validate/echo",
			"operation": "echo",
			"value":     cbor.RawMessage(valueRaw),
			// no reentry_* fields → ambient arm.
		}),
		Context: recordingExecute(&called),
	}
	resp, err := h.Handle(context.Background(), req)
	if err != nil {
		t.Fatalf("handle: %v", err)
	}
	if !called {
		t.Fatalf("ambient dispatch did not reach Execute (status %d) — the ambient arm must proceed to the sub-dispatch so the outbound gate can evaluate it", resp.Status)
	}
}
