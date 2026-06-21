// Package handlers implements the system/handler handler — the handlers
// handler — per V7 §3.12 and §6.2. It exposes register and unregister
// operations that atomically install and remove handler manifests, their
// interface index entries, capability grants, and any associated types.
//
// All post-bootstrap handler installation flows through this handler; it is
// the spec-defined entrance. Bootstrap handlers (system/tree, system/handler,
// system/type, system/protocol/connect) are pre-loaded during peer
// initialization (V7 §6.9) without going through register.
package handlers

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"time"

	"go.entitychurch.org/entity-core-go/core/crypto"
	"go.entitychurch.org/entity-core-go/core/ecf"
	"go.entitychurch.org/entity-core-go/core/entity"
	"go.entitychurch.org/entity-core-go/core/handler"
	"go.entitychurch.org/entity-core-go/core/hash"
	"go.entitychurch.org/entity-core-go/core/types"
)

const handlerPattern = "system/handler"

// Handler implements the system/handler handler with register/unregister.
//
// Handler authority (peer keypair + identity) is wired in after peer
// construction via SetupAuthority. Without it, register fails closed —
// because it would otherwise produce unsigned grants, which dispatch-time
// validation per V7 §6.8 would reject anyway. See the handler-grant
// authority spec-gap notes for context.
type Handler struct {
	mu       sync.RWMutex
	keypair  crypto.Keypair
	identity entity.Entity // local peer's system/peer entity
	ready    bool
}

// NewHandler creates a new handlers handler.
func NewHandler() *Handler { return &Handler{} }

func (h *Handler) Name() string { return "handler" }

// SetupAuthority wires the peer's signing authority into the handlers handler.
// Called by the peer-construction code (e.g., cmd/entity-peer/main.go) after
// peer.New, when the peer's keypair and identity entity become available.
// Until SetupAuthority has been called, register returns 503 because we
// cannot produce signed grants per V7 §6.2 / §6.8.
func (h *Handler) SetupAuthority(kp crypto.Keypair, identityEnt entity.Entity) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.keypair = kp
	h.identity = identityEnt
	h.ready = true
}

// Manifest returns the handler's self-description (V7 §6.2).
func (h *Handler) Manifest() types.HandlerManifestData {
	return types.HandlerManifestData{
		Pattern: handlerPattern,
		Name:    "handler",
		Operations: map[string]types.HandlerOperationSpec{
			"register": {
				InputType:  types.TypeHandlerRegisterReq,
				OutputType: types.TypeHandlerRegisterRes,
			},
			"unregister": {
				InputType: "primitive/any", // empty-params per V7 §3.2
			},
		},
	}
}

// Handle dispatches to register or unregister.
func (h *Handler) Handle(ctx context.Context, req *handler.Request) (*handler.Response, error) {
	switch req.Operation {
	case "register":
		return h.handleRegister(ctx, req)
	case "unregister":
		return h.handleUnregister(ctx, req)
	default:
		return handler.NewErrorResponse(400, "unknown_operation",
			"system/handler does not support operation: "+req.Operation)
	}
}

// handleRegister atomically installs a new handler per V7 §6.2:
//   - manifest entity at the pattern path
//   - interface entity at system/handler/{pattern}
//   - signed capability grant at system/capability/grants/{pattern}
//   - signature entity at system/signature/{grant_hash} (v7.74 v0.4 §3.4
//     invariant-pointer convergence — same convention as every other
//     signature in the address space)
//   - any provided type definitions at system/type/{type_name}
//
// V7 §6.6: rejects user-installed handlers under system/* paths.
//
// V7 §3.12 / §6.2: grant scope comes from requested_scope, falling back to
// manifest.internal_scope. An empty scope is permitted — the handler is
// asserted pure-functional and its grant has authority to do nothing impure.
//
// V7 §6.2 / spec-gap-handler-grant-authority §S1: every grant emitted by
// register MUST have granter set to the local peer's identity, MUST be
// signed by the peer's keypair, and is verified at dispatch read.
func (h *Handler) handleRegister(ctx context.Context, req *handler.Request) (*handler.Response, error) {
	hctx := req.Context

	h.mu.RLock()
	ready := h.ready
	keypair := h.keypair
	identity := h.identity
	h.mu.RUnlock()
	if !ready {
		return handler.NewErrorResponse(503, "authority_not_ready",
			"handlers handler authority not yet wired (SetupAuthority pending)")
	}

	// V7 §3.2 path-as-resource: pattern derives from
	// EXECUTE.resource.targets[0] = system/handler/{pattern}.
	if hctx.Resource == nil || len(hctx.Resource.Targets) != 1 {
		return handler.NewErrorResponse(400, "ambiguous_resource",
			"register requires resource = system/handler/{pattern}")
	}
	pattern, ok := patternFromHandlerResource(hctx.Resource.Targets[0])
	if !ok {
		return handler.NewErrorResponse(400, "malformed_resource",
			"register resource must be system/handler/{pattern}: "+hctx.Resource.Targets[0])
	}
	if isReservedSystemPattern(pattern) {
		return handler.NewErrorResponse(403, "forbidden_pattern",
			"V7 §6.6: user-installed handlers MUST NOT register at system/* paths: "+pattern)
	}

	var rr types.RegisterRequestData
	if err := ecf.Decode(req.Params.Data, &rr); err != nil {
		return handler.NewErrorResponse(400, "invalid_params",
			"failed to decode register-request: "+err.Error())
	}

	// manifest.pattern policy (V7 §3.12): absent → derive; matches → use;
	// disagrees → reject. The resource-derived pattern is authoritative.
	if rr.Manifest.Pattern != "" && rr.Manifest.Pattern != pattern {
		return handler.NewErrorResponse(400, "manifest_pattern_mismatch",
			"manifest.pattern does not match resource-derived pattern")
	}
	rr.Manifest.Pattern = pattern

	// Refuse to clobber an existing registration. Unregister first, then re-register.
	if existing, ok := hctx.LocationIndex.Get(pattern); ok {
		if ent, ok := hctx.Store.Get(existing); ok && ent.Type == types.TypeHandler {
			return handler.NewErrorResponse(409, "already_registered",
				"handler already registered at pattern: "+pattern)
		}
	}

	// Build the grant scope: prefer explicit requested_scope, else manifest
	// internal_scope. Empty scope is permitted — produces a signed
	// zero-authority grant for a pure-functional handler.
	grantScope := rr.RequestedScope
	if len(grantScope) == 0 {
		grantScope = rr.Manifest.InternalScope
	}

	grantData := types.CapabilityTokenData{
		Grants:    grantScope, // may be empty — valid attenuation to "no impure authority"
		Granter:   types.SingleSigGranter(identity.ContentHash),
		Grantee:   identity.ContentHash, // peer is granting to itself for the handler context
		CreatedAt: uint64(time.Now().UnixMilli()),
	}
	grantEnt, err := grantData.ToEntity()
	if err != nil {
		return handler.NewErrorResponse(500, "internal",
			"failed to build grant entity: "+err.Error())
	}

	// Sign the grant's content hash. The signature entity references the
	// grant by its content hash and identifies the signer (granter).
	sigData := types.SignatureData{
		Target:    grantEnt.ContentHash,
		Signer:    identity.ContentHash,
		Algorithm: crypto.KeyTypeString(keypair.KeyType),
		Signature: keypair.Sign(grantEnt.ContentHash.Bytes()),
	}
	sigEnt, err := sigData.ToEntity()
	if err != nil {
		return handler.NewErrorResponse(500, "internal",
			"failed to build signature entity: "+err.Error())
	}

	// Interface entity (public contract).
	ifacePath := "system/handler/" + pattern
	ifaceData := types.HandlerInterfaceData{
		Pattern:    pattern,
		Name:       rr.Manifest.Name,
		Operations: rr.Manifest.Operations,
	}
	ifaceEnt, err := ifaceData.ToEntity()
	if err != nil {
		return handler.NewErrorResponse(500, "internal",
			"failed to build interface entity: "+err.Error())
	}

	// Handler entity (dispatch target — what tree-walk finds).
	handlerData := types.HandlerData{
		Interface:      ifacePath,
		MaxScope:       rr.Manifest.MaxScope,
		InternalScope:  rr.Manifest.InternalScope,
		ExpressionPath: rr.Manifest.ExpressionPath,
	}
	handlerEnt, err := handlerData.ToEntity()
	if err != nil {
		return handler.NewErrorResponse(500, "internal",
			"failed to build handler entity: "+err.Error())
	}

	// Ensure the granter identity is in the content store so dispatch-time
	// validation can resolve granter -> public key. The peer's identity is
	// usually already there; this is idempotent (content-addressed put).
	if _, err := hctx.Store.Put(identity); err != nil {
		return handler.NewErrorResponse(500, "internal",
			"failed to store granter identity: "+err.Error())
	}

	// Atomic install. Order: interface first (so the handler entity's interface
	// ref resolves immediately), then grant + signature, then handler entity
	// (which makes the pattern dispatch-resolvable last).
	if err := putAt(hctx, ifacePath, ifaceEnt, "register-interface"); err != nil {
		return handler.NewErrorResponse(500, "internal", err.Error())
	}
	grantPath := "system/capability/grants/" + pattern
	if err := putAt(hctx, grantPath, grantEnt, "register-grant"); err != nil {
		return handler.NewErrorResponse(500, "internal", err.Error())
	}
	signaturePath := types.LocalSignaturePath(grantEnt.ContentHash)
	if err := putAt(hctx, signaturePath, sigEnt, "register-grant-signature"); err != nil {
		return handler.NewErrorResponse(500, "internal", err.Error())
	}
	if err := putAt(hctx, pattern, handlerEnt, "register-handler"); err != nil {
		return handler.NewErrorResponse(500, "internal", err.Error())
	}

	// Optional type installation. Type definitions land at system/type/{name}.
	for typeName, typeDef := range rr.Types {
		typeEnt, err := typeDef.ToEntity()
		if err != nil {
			return handler.NewErrorResponse(500, "internal",
				"failed to build type entity for "+typeName+": "+err.Error())
		}
		if err := putAt(hctx, "system/type/"+typeName, typeEnt, "register-type"); err != nil {
			return handler.NewErrorResponse(500, "internal", err.Error())
		}
	}

	return handler.NewResponse(200, types.TypeHandlerRegisterRes, types.RegisterResultData{
		Pattern: pattern,
		Grant:   grantData,
	})
}

// handleUnregister removes a previously registered handler per V7 §6.2.
// Removes the handler entity, interface index entry, grant, and grant
// signature. Type definitions are left in place (they may be shared by
// other handlers).
func (h *Handler) handleUnregister(ctx context.Context, req *handler.Request) (*handler.Response, error) {
	hctx := req.Context

	// V7 §3.2 path-as-resource: pattern derives from
	// EXECUTE.resource.targets[0] = system/handler/{pattern}. Unregister
	// takes no params (empty primitive/any per the empty-params wire shape).
	if hctx.Resource == nil || len(hctx.Resource.Targets) != 1 {
		return handler.NewErrorResponse(400, "ambiguous_resource",
			"unregister requires resource = system/handler/{pattern}")
	}
	pattern, ok := patternFromHandlerResource(hctx.Resource.Targets[0])
	if !ok {
		return handler.NewErrorResponse(400, "malformed_resource",
			"unregister resource must be system/handler/{pattern}: "+hctx.Resource.Targets[0])
	}
	if isReservedSystemPattern(pattern) {
		return handler.NewErrorResponse(403, "forbidden_pattern",
			"V7 §6.6: cannot unregister system/* handlers: "+pattern)
	}

	existing, ok := hctx.LocationIndex.Get(pattern)
	if !ok {
		return handler.NewErrorResponse(404, "not_registered",
			"no handler registered at pattern: "+pattern)
	}
	ent, ok := hctx.Store.Get(existing)
	if !ok || ent.Type != types.TypeHandler {
		return handler.NewErrorResponse(404, "not_registered",
			"no handler entity at pattern: "+pattern)
	}

	// v7.74 v0.4 §3.4: signature lives at system/signature/{grant_hash}.
	// Resolve grant content_hash from the grant entity at the colocated grant
	// path so we can remove the signature at its invariant-pointer location.
	grantPath := "system/capability/grants/" + pattern
	if grantHash, ok := hctx.LocationIndex.Get(grantPath); ok {
		hctx.TreeRemove(types.LocalSignaturePath(grantHash), "unregister-grant-signature")
	}

	hctx.TreeRemove(pattern, "unregister-handler")
	hctx.TreeRemove("system/handler/"+pattern, "unregister-interface")
	hctx.TreeRemove(grantPath, "unregister-grant")

	return &handler.Response{Status: 200}, nil
}

// putAt stores ent in the content store and binds it at path with a
// MutationContext-carrying TreeSet (so emit consumers see the write).
func putAt(hctx *handler.HandlerContext, path string, ent entity.Entity, op string) error {
	h, err := hctx.Store.Put(ent)
	if err != nil {
		return fmt.Errorf("store %s entity: %w", path, err)
	}
	if _, err := hctx.TreeSet(path, h, op); err != nil {
		return fmt.Errorf("bind %s entity: %w", path, err)
	}
	return nil
}

// isReservedSystemPattern returns true for patterns the spec reserves for
// bootstrap installation. V7 §6.6: "Implementations MUST NOT allow user-
// installed handlers to register at system/* paths."
func isReservedSystemPattern(pattern string) bool {
	return pattern == "system" || strings.HasPrefix(pattern, "system/")
}

// patternFromHandlerResource extracts the user pattern from a register/unregister
// resource target of the form `system/handler/{pattern}` or
// `/{peer_id}/system/handler/{pattern}`. Returns ("", false) if the path
// doesn't match either shape or has an empty pattern segment.
func patternFromHandlerResource(resourcePath string) (string, bool) {
	bare := resourcePath
	if strings.HasPrefix(bare, "/") {
		rest := bare[1:]
		idx := strings.IndexByte(rest, '/')
		if idx < 0 {
			return "", false
		}
		bare = rest[idx+1:]
	}
	const prefix = "system/handler/"
	if !strings.HasPrefix(bare, prefix) {
		return "", false
	}
	pattern := bare[len(prefix):]
	if pattern == "" {
		return "", false
	}
	return pattern, true
}

// Suppress unused-import warning if hash package isn't directly referenced
// elsewhere in this file.
var _ = hash.Hash{}
