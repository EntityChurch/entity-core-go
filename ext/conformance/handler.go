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
// Cap-passing convention (§7a.2a, ruled by Go — shape (a) in-band params):
// the reentry-authority entities travel **in-band, nested in params**
// (reentry_capability / reentry_granters / reentry_cap_signatures) — NOT
// via the envelope `included` set. The granter/signature carriers are
// plural arrays (0.8.2.19 §7a.1) so a K-of-2 multi-sig root can be driven.
package conformance

import (
	"context"
	"fmt"

	"go.entitychurch.org/entity-core-go/core/ecf"
	"go.entitychurch.org/entity-core-go/core/entity"
	"go.entitychurch.org/entity-core-go/core/handler"
	"go.entitychurch.org/entity-core-go/core/hash"
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
// the reentry-authority entities carried in-band per the §7a.2a Go ruling.
// Each authority entity is a CBOR-encoded entity nested inside the
// primitive/any params object — decoded here as cbor.RawMessage so the
// entity round-trips byte-fidelity.
//
// reentry_granters and reentry_cap_signatures are PLURAL carriers as of
// 0.8.2.19 (§7a.1): arrays, single-granter being an array of one. A K-of-2
// multi-sig root credential needs two granter identities and two signatures
// to drive the E3/F66 fail-closed rule; the singular carrier could not
// express that input, so every seat drove E3 in-process only. The
// reentry_capability stays singular — the credential is one entity; its ROOT
// granter is what may be multi-signed.
//
// All-or-none (§7a.1): supplying the credential + at least one granter + at
// least one signature selects the PRESENTED arm; omitting all three selects
// the AMBIENT arm; a partial set is malformed (400 invalid_params) — a
// partial credential is not "ambient", it is broken.
type DispatchOutboundData struct {
	Target               string            `cbor:"target"`
	Operation            string            `cbor:"operation"`
	Value                cbor.RawMessage   `cbor:"value"`
	ReentryCapability    cbor.RawMessage   `cbor:"reentry_capability"`
	ReentryGranters      []cbor.RawMessage `cbor:"reentry_granters"`
	ReentryCapSignatures []cbor.RawMessage `cbor:"reentry_cap_signatures"`
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
//
// InternalScope is NARROW, and this is a GUIDE-CONFORMANCE §7a.1 scaffold-
// contract REQUIREMENT, not a hardening choice. §7a.1's ⛔ block: the
// dispatch-outbound handler's own grant (the ceiling the §6.8/§5.2 outbound
// gate enforces on Dimensions 1-3) MUST be scoped to a fixed, declared
// operation set — NOT the peer's wide default self-grant (`/*/*`, ops `*`).
//
// Why it must be narrow: ENTITY-CORE-PROTOCOL §1.4's outbound gate admits two
// authority contributions — the executing handler's grant (Dims 1-3, always)
// and a target-minted credential (Dim 4 only, 0.8.2.19 E1). A check set must
// discriminate COMPOSE from BYPASS, and the discriminating vector is *a valid
// credential presented to a handler whose own grant does not cover the request
// → MUST refuse*. Against a WIDE grant that vector is unconstructible: the
// composed and bypassed readings return the same answer for every input, which
// is exactly how the F67 confused-deputy bypass passed two green wire vectors
// cohort-wide. The narrow grant is what makes the F63 discriminator observable
// on the wire (validate's dispatch_outbound_narrow_grant_refuses_out_of_scope).
//
// The declared minimum is `echo` on system/validate/echo — the only operation
// the §7a.2a reentry contract needs. The reentry (in-scope op=echo) still
// passes: Dims 1-2 covered here, Dim 3 skipped (echo carries no resource
// target), Dim 4 relaxed by the caller-minted reentry credential. An
// out-of-scope operation fails Dimension 1 unless the credential is (wrongly)
// treated as a standalone authorizer.
func (*DispatchOutboundHandler) Manifest() types.HandlerManifestData {
	return types.HandlerManifestData{
		Pattern: PatternDispatchOutbound,
		Name:    "validate/dispatch-outbound",
		Operations: map[string]types.HandlerOperationSpec{
			"dispatch": {InputType: "primitive/any", OutputType: "primitive/any"},
		},
		InternalScope: []types.GrantEntry{
			{
				Handlers:   types.CapabilityScope{Include: []string{PatternEcho}},
				Operations: types.CapabilityScope{Include: []string{"echo"}},
				Resources:  types.CapabilityScope{Include: []string{"/*/" + PatternEcho}},
			},
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
		resp, _ := handler.NewErrorResponse(500, "internal_error",
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
	// The §7a.2a authority set is optional as of the PD-2 (§5.2) check, and its
	// granter/signature carriers are PLURAL (§7a.1, 0.8.2.19).
	// PRESENTED: credential + ≥1 granter + ≥1 signature → the sub-dispatch
	// presents a target-minted capability (the reentry probe, and the E3
	// multi-sig probe). AMBIENT: all three omitted → the sub-dispatch rides only
	// the executing handler's grant, which is exactly the input the PD-2
	// negative-arm check needs. A PARTIAL set is malformed (a partial credential
	// is not "ambient" — it is broken).
	hasCap := len(d.ReentryCapability) > 0
	nGranters := len(d.ReentryGranters)
	nSigs := len(d.ReentryCapSignatures)
	present := hasCap || nGranters > 0 || nSigs > 0
	ambient := !present
	if present && (!hasCap || nGranters == 0 || nSigs == 0) {
		resp, _ := handler.NewErrorResponse(400, "invalid_params",
			"dispatch-outbound: reentry_capability + at least one reentry_granters + at least one reentry_cap_signatures must be supplied together (§7a.1) or all omitted (ambient PD-2 probe)")
		return resp, nil
	}

	// Build the outbound EXECUTE options. On the presented arm the reentry
	// capability + its authority chain (all granter identities + all signatures)
	// travel via WithCapability + WithIncludedChain so the far peer's verifier
	// (and the local PD-2 presented-arm check) find them. On the ambient arm no
	// capability is attached — the sub-dispatch rides the executing handler's
	// grant, which PD-2 (§5.2) evaluates on Dimension 4.
	var execOpts []handler.ExecuteOption
	if !ambient {
		// Re-canonicalize so each entity carries the right ContentHash before
		// dispatch — ECF decode populates type+data; NewEntity recomputes the
		// hash deterministically.
		var capEnt entity.Entity
		if err := ecf.Decode(d.ReentryCapability, &capEnt); err != nil {
			resp, _ := handler.NewErrorResponse(400, "invalid_params",
				"decode reentry_capability: "+err.Error())
			return resp, nil
		}
		cap, err := entity.NewEntity(capEnt.Type, capEnt.Data)
		if err != nil {
			resp, _ := handler.NewErrorResponse(400, "invalid_params",
				"rebuild reentry_capability entity: "+err.Error())
			return resp, nil
		}

		chain := make([]entity.Entity, 0, nGranters+nSigs)
		// Each granter is a `system/peer` identity, so it is rebuilt at the
		// ECFv1-SHA-256 FLOOR rather than under the process-global authoring
		// default: ENTITY-CORE-PROTOCOL §4.5a item 1a pins the identity entity
		// to the floor unconditionally, whatever this peer's home format.
		// NewEntity here was a latent defect on a `--hash-type sha384` peer — it
		// rebuilt the caller's identity under 0x01, manufacturing a second
		// content_hash for the one identity that item 1a exists to collapse, on
		// the exact surface where §5.2's grantee/granter equality is evaluated.
		// It never failed a check because both sides of every comparison
		// downstream were wrong the same way (the Go-on-Go deception AGENTS.md
		// warns about); core/entity now refuses the construction outright.
		for i, raw := range d.ReentryGranters {
			var granterEnt entity.Entity
			if err := ecf.Decode(raw, &granterEnt); err != nil {
				resp, _ := handler.NewErrorResponse(400, "invalid_params",
					fmt.Sprintf("decode reentry_granters[%d]: %v", i, err))
				return resp, nil
			}
			granter, err := entity.NewEntityFormat(hash.AlgorithmSHA256, granterEnt.Type, granterEnt.Data)
			if err != nil {
				resp, _ := handler.NewErrorResponse(400, "invalid_params",
					fmt.Sprintf("rebuild reentry_granters[%d] entity: %v", i, err))
				return resp, nil
			}
			chain = append(chain, granter)
		}
		for i, raw := range d.ReentryCapSignatures {
			var sigEnt entity.Entity
			if err := ecf.Decode(raw, &sigEnt); err != nil {
				resp, _ := handler.NewErrorResponse(400, "invalid_params",
					fmt.Sprintf("decode reentry_cap_signatures[%d]: %v", i, err))
				return resp, nil
			}
			sig, err := entity.NewEntity(sigEnt.Type, sigEnt.Data)
			if err != nil {
				resp, _ := handler.NewErrorResponse(400, "invalid_params",
					fmt.Sprintf("rebuild reentry_cap_signatures[%d] entity: %v", i, err))
				return resp, nil
			}
			chain = append(chain, sig)
		}

		execOpts = append(execOpts,
			handler.WithCapability(cap),
			handler.WithIncludedChain(chain),
		)
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
	// reentry path, reuses the inbound connection — no fresh dial).
	resp, err := req.Context.Execute(ctx, d.Target, d.Operation, outboundParams, execOpts...)
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
		errResp, _ := handler.NewErrorResponse(500, "internal_error",
			"encode reentry result: "+err.Error())
		return errResp, nil
	}
	out, err := handler.NewResponse(200, "primitive/any", DispatchOutboundResult{
		Status: resp.Status,
		Result: cbor.RawMessage(resultRaw),
	})
	if err != nil {
		errResp, _ := handler.NewErrorResponse(500, "internal_error",
			"build dispatch-outbound result: "+err.Error())
		return errResp, nil
	}
	return out, nil
}
