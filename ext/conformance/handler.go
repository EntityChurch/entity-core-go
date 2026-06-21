// Package conformance implements GUIDE-CONFORMANCE §7a — the two
// `system/validate/*` test handlers behind the runtime opt-in.
//
// The handlers are conformance scaffolding, not core protocol and not an
// extension. They expose two existing core capabilities (handler dispatch
// V7 §6.13(a); outbound seam §6.13(b)/§6.11) at well-known patterns so a
// black-box validator can probe them. In a core-only peer those
// capabilities have no other wire-reachable trigger (no compute, no
// continuation, no subscription) — that is the whole reason this exists.
//
// Both handlers are OFF by default. The wire-host opts in by passing
// WithConformanceHandlers() to the peer builder (typically driven from a
// host-level --validate flag). A peer without the opt-in 404s the two
// patterns — the validator SKIPs honestly per §7a.2.
//
// Wire contracts (§7a.1):
//   - system/validate/echo:echo  — params verbatim → result verbatim.
//   - system/validate/dispatch-outbound:dispatch — originate ONE outbound
//     EXECUTE via the §6.11 reentry seam back to the caller over the same
//     inbound connection; return {status, result}.
//
// Cap-passing convention (§7a.2a, ruled by Go): the three
// reentry-authority entities travel **in-band, nested in params**
// (reentry_capability / reentry_granter / reentry_cap_signature) — NOT
// via the envelope `included` set.
package conformance

import (
	"context"
	"fmt"

	"go.entitychurch.org/entity-core-go/core/ecf"
	"go.entitychurch.org/entity-core-go/core/entity"
	"go.entitychurch.org/entity-core-go/core/handler"
	"go.entitychurch.org/entity-core-go/core/types"

	"github.com/fxamacker/cbor/v2"
)

const (
	// PatternEcho — system/validate/echo:echo proves §6.13(a) resolve→dispatch.
	PatternEcho = "system/validate/echo"
	// PatternDispatchOutbound — system/validate/dispatch-outbound:dispatch
	// proves §6.13(b)/§6.11 outbound-seam-via-reentry.
	PatternDispatchOutbound = "system/validate/dispatch-outbound"
)

// EchoHandler implements system/validate/echo per §7a.1.
//
// Operation `echo` returns the params entity verbatim. The contract is
// byte-exact: result.value == params.value, for any ECF value the caller
// passes.
type EchoHandler struct{}

// NewEchoHandler creates the echo handler.
func NewEchoHandler() *EchoHandler { return &EchoHandler{} }

// Name reports the handler identity for diagnostics.
func (*EchoHandler) Name() string { return "validate/echo" }

// Manifest describes the handler for system/handler indexing.
func (*EchoHandler) Manifest() types.HandlerManifestData {
	return types.HandlerManifestData{
		Pattern: PatternEcho,
		Name:    "validate/echo",
		Operations: map[string]types.HandlerOperationSpec{
			"echo": {InputType: "primitive/any", OutputType: "primitive/any"},
		},
	}
}

// Handle dispatches to the echo operation.
func (h *EchoHandler) Handle(ctx context.Context, req *handler.Request) (*handler.Response, error) {
	if req.Operation != "echo" {
		resp, _ := handler.NewErrorResponse(501, "unsupported_operation",
			fmt.Sprintf("system/validate/echo: operation %q not supported", req.Operation))
		return resp, nil
	}
	// Verbatim echo: return the params entity as-is. §7a.1 contract is byte
	// equality between params.value and result.value, satisfied by returning
	// the params entity itself with no decode/re-encode roundtrip.
	return &handler.Response{Status: 200, Result: req.Params}, nil
}

// DispatchOutboundData is the §7a.1 dispatch-outbound params shape, with
// the three reentry-authority entities carried in-band per the §7a.2a
// Go ruling. Each authority field is a CBOR-encoded entity nested inside
// the primitive/any params object — decoded here as cbor.RawMessage so
// the entity round-trips byte-fidelity.
type DispatchOutboundData struct {
	Target              string          `cbor:"target"`
	Operation           string          `cbor:"operation"`
	Value               cbor.RawMessage `cbor:"value"`
	ReentryCapability   cbor.RawMessage `cbor:"reentry_capability"`
	ReentryGranter      cbor.RawMessage `cbor:"reentry_granter"`
	ReentryCapSignature cbor.RawMessage `cbor:"reentry_cap_signature"`
}

// DispatchOutboundResult is the §7a.1 result shape — the downstream
// EXECUTE_RESPONSE's status + result entity returned to the caller so a
// validator can assert end-to-end round-trip.
type DispatchOutboundResult struct {
	Status uint            `cbor:"status"`
	Result cbor.RawMessage `cbor:"result"`
}

// DispatchOutboundHandler implements system/validate/dispatch-outbound.
//
// On `dispatch`: originate exactly one outbound EXECUTE via hctx.Execute
// (the §6.13(b) seam routed through §6.11 reentry) to operation@target
// — which the validator sets to itself, so the EXECUTE travels back over
// the same inbound connection (B-role-same-connection per §7a.2a). The
// validator's system/validate/echo serves the reentrant call.
type DispatchOutboundHandler struct{}

// NewDispatchOutboundHandler creates the dispatch-outbound handler.
func NewDispatchOutboundHandler() *DispatchOutboundHandler {
	return &DispatchOutboundHandler{}
}

// Name reports the handler identity for diagnostics.
func (*DispatchOutboundHandler) Name() string { return "validate/dispatch-outbound" }

// Manifest describes the handler for system/handler indexing.
func (*DispatchOutboundHandler) Manifest() types.HandlerManifestData {
	return types.HandlerManifestData{
		Pattern: PatternDispatchOutbound,
		Name:    "validate/dispatch-outbound",
		Operations: map[string]types.HandlerOperationSpec{
			"dispatch": {InputType: "primitive/any", OutputType: "primitive/any"},
		},
	}
}

// Handle dispatches to the dispatch operation.
func (h *DispatchOutboundHandler) Handle(ctx context.Context, req *handler.Request) (*handler.Response, error) {
	if req.Operation != "dispatch" {
		resp, _ := handler.NewErrorResponse(501, "unsupported_operation",
			fmt.Sprintf("system/validate/dispatch-outbound: operation %q not supported", req.Operation))
		return resp, nil
	}

	if req.Context == nil || req.Context.Execute == nil {
		resp, _ := handler.NewErrorResponse(500, "internal",
			"dispatcher did not wire hctx.Execute (§6.13(b) seam missing)")
		return resp, nil
	}

	var d DispatchOutboundData
	if err := ecf.Decode(req.Params.Data, &d); err != nil {
		resp, _ := handler.NewErrorResponse(400, "invalid_params",
			"decode dispatch-outbound params: "+err.Error())
		return resp, nil
	}
	if d.Target == "" || d.Operation == "" {
		resp, _ := handler.NewErrorResponse(400, "invalid_params",
			"dispatch-outbound requires target and operation")
		return resp, nil
	}
	if len(d.ReentryCapability) == 0 || len(d.ReentryGranter) == 0 || len(d.ReentryCapSignature) == 0 {
		resp, _ := handler.NewErrorResponse(400, "invalid_params",
			"dispatch-outbound requires reentry_capability + reentry_granter + reentry_cap_signature in-band per §7a.2a")
		return resp, nil
	}

	// Decode the three in-band authority entities. Their byte fidelity is
	// preserved because each field rode as cbor.RawMessage.
	var capEnt, granterEnt, sigEnt entity.Entity
	if err := ecf.Decode(d.ReentryCapability, &capEnt); err != nil {
		resp, _ := handler.NewErrorResponse(400, "invalid_params",
			"decode reentry_capability: "+err.Error())
		return resp, nil
	}
	if err := ecf.Decode(d.ReentryGranter, &granterEnt); err != nil {
		resp, _ := handler.NewErrorResponse(400, "invalid_params",
			"decode reentry_granter: "+err.Error())
		return resp, nil
	}
	if err := ecf.Decode(d.ReentryCapSignature, &sigEnt); err != nil {
		resp, _ := handler.NewErrorResponse(400, "invalid_params",
			"decode reentry_cap_signature: "+err.Error())
		return resp, nil
	}

	// Re-canonicalize so each entity carries the right ContentHash before
	// dispatch — ECF decode populates type+data; NewEntity recomputes the
	// hash deterministically.
	cap, err := entity.NewEntity(capEnt.Type, capEnt.Data)
	if err != nil {
		resp, _ := handler.NewErrorResponse(400, "invalid_params",
			"rebuild reentry_capability entity: "+err.Error())
		return resp, nil
	}
	granter, err := entity.NewEntity(granterEnt.Type, granterEnt.Data)
	if err != nil {
		resp, _ := handler.NewErrorResponse(400, "invalid_params",
			"rebuild reentry_granter entity: "+err.Error())
		return resp, nil
	}
	sig, err := entity.NewEntity(sigEnt.Type, sigEnt.Data)
	if err != nil {
		resp, _ := handler.NewErrorResponse(400, "invalid_params",
			"rebuild reentry_cap_signature entity: "+err.Error())
		return resp, nil
	}

	// Build the outbound params entity. The caller passed `value` as a
	// raw-CBOR ECF blob; wrap it as a primitive/any entity for the §3.4
	// "params is an entity" requirement at the wire.
	outboundParams, err := entity.NewEntity("primitive/any", cbor.RawMessage(d.Value))
	if err != nil {
		resp, _ := handler.NewErrorResponse(400, "invalid_params",
			"build outbound params entity: "+err.Error())
		return resp, nil
	}

	// Originate one outbound EXECUTE through the §6.13(b) seam. hctx.Execute
	// routes cross-peer URIs through RemoteExecute (which, on the §6.11
	// reentry path, reuses the inbound connection — no fresh dial). The
	// reentry capability and its authority chain travel via
	// WithCapability + WithIncludedChain so the caller's verifier finds them
	// in the EXECUTE's included map.
	resp, err := req.Context.Execute(ctx, d.Target, d.Operation, outboundParams,
		handler.WithCapability(cap),
		handler.WithIncludedChain([]entity.Entity{granter, sig}),
	)
	if err != nil {
		errResp, _ := handler.NewErrorResponse(502, "reentry_dispatch_failed",
			"originate reentry EXECUTE: "+err.Error())
		return errResp, nil
	}

	// Pack the downstream EXECUTE_RESPONSE into the §7a.1 result shape.
	// resp.Result is the downstream result entity; encode it as raw CBOR so
	// byte fidelity survives back through this handler's primitive/any wrap.
	resultRaw, err := ecf.Encode(resp.Result)
	if err != nil {
		errResp, _ := handler.NewErrorResponse(500, "internal",
			"encode reentry result: "+err.Error())
		return errResp, nil
	}
	out, err := handler.NewResponse(200, "primitive/any", DispatchOutboundResult{
		Status: resp.Status,
		Result: cbor.RawMessage(resultRaw),
	})
	if err != nil {
		errResp, _ := handler.NewErrorResponse(500, "internal",
			"build dispatch-outbound result: "+err.Error())
		return errResp, nil
	}
	return out, nil
}
