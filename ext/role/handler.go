package role

import (
	"context"
	"reflect"
	"sync"

	"go.entitychurch.org/entity-core-go/core/crypto"
	"go.entitychurch.org/entity-core-go/core/entity"
	"go.entitychurch.org/entity-core-go/core/handler"
	"go.entitychurch.org/entity-core-go/core/store"
	"go.entitychurch.org/entity-core-go/core/types"
)

const handlerPattern = "system/role"

// Handler implements the system/role handler per EXTENSION-ROLE v1.5.
// Provides seven operations — :define, :assign, :unassign, :exclude,
// :unexclude, :re-derive, :delegate — plus a sync hook that runs the
// fleet-wide reactive sweep (§6.5 IA8) when an exclusion entity arrives
// via tree-sync on a non-issuing runtime peer.
//
// Construction: NewHandler() then SetupStore(cs, li, peerID) to wire the
// content store, location index, and local peer ID. The handler is
// registered with the peer via peer.WithHandler("system/role", h) and
// peer.WithNamedSyncHook("role", h.OnTreeChange) per the conventions used
// by ext/attestation, ext/quorum, and ext/identity.
type Handler struct {
	mu       sync.RWMutex
	cs       store.ContentStore
	li       store.LocationIndex
	peerID   crypto.PeerID
	keypair  crypto.Keypair
	identity entity.Entity
	ready    bool
}

// NewHandler returns a new role handler. The content store, location
// index, local peer ID, and signing authority are wired post-construction
// via SetupStore and SetupAuthority.
func NewHandler() *Handler {
	return &Handler{}
}

func (h *Handler) Name() string { return "role" }

// SetupStore wires the content store, location index, and local peer ID.
// Required before any operation can run.
func (h *Handler) SetupStore(cs store.ContentStore, li store.LocationIndex, peerID crypto.PeerID) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.cs = cs
	h.li = li
	h.peerID = peerID
}

// SetupAuthority wires the peer's signing authority into the role
// handler. Called after peer construction with the local peer's keypair
// and identity entity. Required before assign / re-derive / delegate can
// issue role-derived capability tokens. Mirrors the identity / handlers
// extensions' SetupAuthority pattern.
func (h *Handler) SetupAuthority(kp crypto.Keypair, identityEnt entity.Entity) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.keypair = kp
	h.identity = identityEnt
	h.ready = true
}

// authority returns the wired keypair + identity, or a 503 response if
// SetupAuthority hasn't been called yet. Mirrors ext/identity/handler.go.
func (h *Handler) authority() (crypto.Keypair, entity.Entity, *handler.Response) {
	h.mu.RLock()
	defer h.mu.RUnlock()
	if !h.ready {
		resp, _ := handler.NewErrorResponse(503, "authority_not_ready",
			"role handler authority not yet wired (SetupAuthority pending)")
		return crypto.Keypair{}, entity.Entity{}, resp
	}
	return h.keypair, h.identity, nil
}

// Manifest returns the handler's self-description per V7 §6.
func (h *Handler) Manifest() types.HandlerManifestData {
	return types.HandlerManifestData{
		Pattern: handlerPattern,
		Name:    "role",
		Operations: map[string]types.HandlerOperationSpec{
			"define": {
				InputType:  types.TypeRoleDefineRequest,
				OutputType: types.TypeRoleDefineResult,
			},
			"assign": {
				InputType:  types.TypeRoleAssignRequest,
				OutputType: types.TypeRoleAssignResult,
			},
			"unassign": {
				InputType:  "primitive/any",
				OutputType: types.TypeRoleUnassignResult,
			},
			"exclude": {
				InputType:  "primitive/any",
				OutputType: types.TypeRoleExcludeResult,
			},
			"unexclude": {
				InputType:  "primitive/any",
				OutputType: types.TypeRoleUnexcludeResult,
			},
			"re-derive": {
				InputType:  types.TypeRoleReDeriveRequest,
				OutputType: types.TypeRoleReDeriveResult,
			},
			"delegate": {
				InputType:  types.TypeRoleDelegateRequest,
				OutputType: types.TypeRoleDelegateResult,
			},
		},
	}
}

// RegisterTypes registers the role extension's types with the registry.
// Four entity types (role / assignment / exclusion / derived-token-link)
// plus the eleven request/result types per core/types/role.go (v1.6).
func (h *Handler) RegisterTypes(r *types.TypeRegistry) {
	// Entity types (§2).
	r.ReflectType(types.TypeRole, reflect.TypeOf(types.RoleData{}))
	r.ReflectType(types.TypeRoleAssignment, reflect.TypeOf(types.RoleAssignmentData{}))
	r.ReflectType(types.TypeRoleExclusion, reflect.TypeOf(types.RoleExclusionData{}))
	r.ReflectType(types.TypeRoleDerivedTokenLink, reflect.TypeOf(types.RoleDerivedTokenLinkData{}))
	r.ReflectType(types.TypeRoleInitialGrantPolicy, reflect.TypeOf(types.RoleInitialGrantPolicyData{}))

	// Handler request/result types (§4.2).
	r.ReflectType(types.TypeRoleDefineRequest, reflect.TypeOf(types.RoleDefineRequestData{}))
	r.ReflectType(types.TypeRoleDefineResult, reflect.TypeOf(types.RoleDefineResultData{}))
	r.ReflectType(types.TypeRoleAssignRequest, reflect.TypeOf(types.RoleAssignRequestData{}))
	r.ReflectType(types.TypeRoleAssignResult, reflect.TypeOf(types.RoleAssignResultData{}))
	r.ReflectType(types.TypeRoleUnassignResult, reflect.TypeOf(types.RoleUnassignResultData{}))
	r.ReflectType(types.TypeRoleExcludeResult, reflect.TypeOf(types.RoleExcludeResultData{}))
	r.ReflectType(types.TypeRoleUnexcludeResult, reflect.TypeOf(types.RoleUnexcludeResultData{}))
	r.ReflectType(types.TypeRoleReDeriveRequest, reflect.TypeOf(types.RoleReDeriveRequestData{}))
	r.ReflectType(types.TypeRoleReDeriveResult, reflect.TypeOf(types.RoleReDeriveResultData{}))
	r.ReflectType(types.TypeRoleDelegateRequest, reflect.TypeOf(types.RoleDelegateRequestData{}))
	r.ReflectType(types.TypeRoleDelegateResult, reflect.TypeOf(types.RoleDelegateResultData{}))
}

// Handle dispatches to the appropriate operation. All seven operations
// are wired but the post-skeleton ones return 501 not_implemented until
// their phases land (see ext/role/doc.go for the phase plan).
func (h *Handler) Handle(ctx context.Context, req *handler.Request) (*handler.Response, error) {
	switch req.Operation {
	case "define":
		return h.handleDefine(ctx, req)
	case "assign":
		return h.handleAssign(ctx, req)
	case "unassign":
		return h.handleUnassign(ctx, req)
	case "exclude":
		return h.handleExclude(ctx, req)
	case "unexclude":
		return h.handleUnexclude(ctx, req)
	case "re-derive":
		return h.handleReDerive(ctx, req)
	case "delegate":
		return h.handleDelegate(ctx, req)
	default:
		return handler.NewErrorResponse(400, "unknown_operation",
			"system/role does not support operation: "+req.Operation)
	}
}

// OnTreeChange is the sync-hook for the role handler. Per §6.5 IA8: when
// an exclusion entity arrives at this peer via tree-sync, sweep the local
// role-derived subtree for the excluded peer in that context. This makes
// layer-1 enforcement actually fleet-wide rather than only catching the
// exclude-issuing peer's own subtree.
//
// The hook fires on any source — local handleExclude, cross-peer sync,
// L0 direct writes — so the sweep must be idempotent. Handleexclude has
// already swept by the time the hook fires for a local op; the second
// sweep finds an already-empty subtree. For sync-arrived exclusions this
// is the only sweep that runs, so it's load-bearing.
func (h *Handler) OnTreeChange(evt store.TreeChangeEvent) *store.ConsumerResult {
	if evt.ChangeType == store.ChangeDeleted {
		return nil
	}
	if evt.Hash.IsZero() {
		return nil
	}

	h.mu.RLock()
	cs := h.cs
	li := h.li
	h.mu.RUnlock()
	if cs == nil || li == nil {
		return nil
	}

	// Filter to exclusion paths: system/role/{context}/excluded/{peer_id_hex}
	bare := stripLocalNamespace(evt.Path)
	info, ok := ParseExclusionPath(bare)
	if !ok {
		return nil
	}

	// Confirm the bound entity is actually a role exclusion before
	// sweeping. Defends against a non-exclusion entity bound at this
	// path range.
	ent, ok := cs.Get(evt.Hash)
	if !ok || ent.Type != types.TypeRoleExclusion {
		return nil
	}

	// Sweep our own role-derived subtree for the excluded peer in the
	// given context. Direct LocationIndex mutation — no HandlerContext
	// in a sync hook — mirrors ext/identity/sync_hook.go's fail-closed
	// unbind pattern. Per v1.6 SI-7: broad sweep — every cap at the
	// subtree, regardless of original issuer.
	prefix := RoleDerivedPeerPrefix(info.Context, info.PeerHash)
	for _, e := range li.List(prefix) {
		li.Remove(e.Path)
	}
	return nil
}

// stripLocalNamespace returns the peer-relative form of an absolute
// path. Sync-hook events carry absolute paths (`/{peer_id}/...`); we
// strip the leading `/{peer_id}/` segment so ParseExclusionPath can
// match against its peer-relative grammar. For already-peer-relative
// paths (no leading "/") returns input unchanged.
func stripLocalNamespace(absPath string) string {
	return barePath(absPath)
}

// resourcePath extracts the canonical resource path from the request's
// resource target per V7 §3.2 (path-as-resource). Returns empty if no
// path is present.
func resourcePath(req *handler.Request) string {
	if req.Context == nil {
		return ""
	}
	return req.Context.ExtractResourcePath()
}

// barePath returns the peer-relative path for `absPath`. When the path is
// already peer-relative (no leading "/") it's returned unchanged. When
// it's absolute (`/{peer_id}/...`) the peer_id segment is stripped. This
// mirrors ext/attestation/handler.go:barePath so role and attestation
// share the same path-shape contract for handler-internal logic.
func barePath(absPath string) string {
	if len(absPath) == 0 || absPath[0] != '/' {
		return absPath
	}
	rest := absPath[1:]
	for i := 0; i < len(rest); i++ {
		if rest[i] == '/' {
			return rest[i+1:]
		}
	}
	return rest
}

type errString string

func (e errString) Error() string { return string(e) }
