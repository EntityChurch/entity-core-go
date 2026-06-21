// Package sdk wraps system/role EXECUTE operations behind a small Go API.
//
// This is the exploratory first cut surfaced by EXTENSION-ROLE v2.0
// cross-impl validation: the test harness's inline helpers
// (defineRole, assignRole, excludePeer, ...) had organically converged
// on application-shaped methods, and the architecture team's
// rulings approved promoting them into a shared package so larger
// fixtures (Tier 3 identity ceremony, Tier 4 multi-peer) and real
// applications speak the same surface.
//
// # Scope
//
// Happy-path operations only — Define / Assign / Unassign / Exclude /
// Unexclude / ReDerive. Adversarial cap-override flows (RL2 negative,
// nil-expiry chain rejection) belong inline in tests, not here.
//
// # Transport
//
// The client takes a small Transport interface that any peer-RPC client
// can implement. cmd/internal/validate.PeerClient satisfies it without
// modification — the SDK depends only on entity / types / hash, not on
// the wire layer.
package sdk

import (
	"context"
	"fmt"

	"github.com/fxamacker/cbor/v2"

	"go.entitychurch.org/entity-core-go/core/crypto"
	"go.entitychurch.org/entity-core-go/core/ecf"
	"go.entitychurch.org/entity-core-go/core/entity"
	"go.entitychurch.org/entity-core-go/core/hash"
	"go.entitychurch.org/entity-core-go/core/types"
	"go.entitychurch.org/entity-core-go/ext/role"
)

// Transport is the wire-side dependency the role SDK needs. Any RPC
// client that can dispatch authenticated EXECUTEs and report the remote
// peer's ID satisfies it. cmd/internal/validate.PeerClient satisfies
// this interface as-is.
type Transport interface {
	SendExecute(ctx context.Context, uri, operation string, params entity.Entity, resource *types.ResourceTarget) (entity.Envelope, []byte, error)
	RemotePeerID() crypto.PeerID
}

// Client wraps system/role EXECUTE operations behind typed Go methods.
// One Client targets one remote peer (the URI is computed once from
// Transport.RemotePeerID()).
type Client struct {
	t             Transport
	roleURI       string
	delegatorHash hash.Hash // optional override; see SetDelegator.
}

// NewClient constructs a role SDK client targeting the peer behind t.
func NewClient(t Transport) *Client {
	return &Client{
		t:       t,
		roleURI: fmt.Sprintf("entity://%s/system/role", t.RemotePeerID().String()),
	}
}

// Define writes or mutates a role definition at
// system/role/{context}/{roleName}. Triggers a re-derive cascade if the
// role already exists (§8.2 IA11). `metadata` is opaque CBOR; pass nil
// for a role with no metadata.
func (c *Client) Define(ctx context.Context, contextStr, roleName string, grants []types.GrantEntry, metadata cbor.RawMessage) (uint, types.RoleDefineResultData, error) {
	req := types.RoleDefineRequestData{Grants: grants, Metadata: metadata}
	ent, err := req.ToEntity()
	if err != nil {
		return 0, types.RoleDefineResultData{}, fmt.Errorf("encode RoleDefineRequest: %w", err)
	}
	path := role.RoleDefinitionPath(contextStr, roleName)
	status, resultEnt, err := c.execute(ctx, "define", path, ent)
	if err != nil || status != 200 {
		return status, types.RoleDefineResultData{}, err
	}
	result, err := types.RoleDefineResultDataFromEntity(resultEnt)
	if err != nil {
		return status, types.RoleDefineResultData{}, fmt.Errorf("decode RoleDefineResult: %w", err)
	}
	return status, result, nil
}

// Assign binds peerHash to roleName within contextStr and issues a
// role-derived capability token (§4.3 + §5.1). The minted cap inherits
// expiration per §5.3 v2.0 MIN_DEFINED(parent, role.ttl, caller_cap).
func (c *Client) Assign(ctx context.Context, contextStr string, peerHash hash.Hash, roleName string) (uint, types.RoleAssignResultData, error) {
	req := types.RoleAssignRequestData{Role: roleName}
	ent, err := req.ToEntity()
	if err != nil {
		return 0, types.RoleAssignResultData{}, fmt.Errorf("encode RoleAssignRequest: %w", err)
	}
	path := role.AssignmentPath(contextStr, peerHash, roleName)
	status, resultEnt, err := c.execute(ctx, "assign", path, ent)
	if err != nil || status != 200 {
		return status, types.RoleAssignResultData{}, err
	}
	result, err := types.RoleAssignResultDataFromEntity(resultEnt)
	if err != nil {
		return status, types.RoleAssignResultData{}, fmt.Errorf("decode RoleAssignResult: %w", err)
	}
	return status, result, nil
}

// Unassign removes the assignment for (peerHash, roleName) in contextStr.
// If roleName == "", uses the all-roles form: drops the trailing role
// segment per §4.4 to remove every role for the peer in the context.
func (c *Client) Unassign(ctx context.Context, contextStr string, peerHash hash.Hash, roleName string) (uint, types.RoleUnassignResultData, error) {
	var path string
	if roleName != "" {
		path = role.AssignmentPath(contextStr, peerHash, roleName)
	} else {
		path = "system/role/" + contextStr + "/assignment/" + role.HashHex(peerHash)
	}
	status, resultEnt, err := c.execute(ctx, "unassign", path, emptyParams())
	if err != nil || status != 200 {
		return status, types.RoleUnassignResultData{}, err
	}
	result, err := types.RoleUnassignResultDataFromEntity(resultEnt)
	if err != nil {
		return status, types.RoleUnassignResultData{}, fmt.Errorf("decode RoleUnassignResult: %w", err)
	}
	return status, result, nil
}

// Exclude writes an exclusion entity for peerHash in contextStr and
// triggers the layer-1 sweep (§6.1).
func (c *Client) Exclude(ctx context.Context, contextStr string, peerHash hash.Hash) (uint, types.RoleExcludeResultData, error) {
	path := role.ExclusionPath(contextStr, peerHash)
	status, resultEnt, err := c.execute(ctx, "exclude", path, emptyParams())
	if err != nil || status != 200 {
		return status, types.RoleExcludeResultData{}, err
	}
	result, err := types.RoleExcludeResultDataFromEntity(resultEnt)
	if err != nil {
		return status, types.RoleExcludeResultData{}, fmt.Errorf("decode RoleExcludeResult: %w", err)
	}
	return status, result, nil
}

// Unexclude removes the exclusion entity at the resource path. Per §6.4,
// removing an exclusion does NOT auto-restore role-derived caps —
// re-assignment is required.
func (c *Client) Unexclude(ctx context.Context, contextStr string, peerHash hash.Hash) (uint, types.RoleUnexcludeResultData, error) {
	path := role.ExclusionPath(contextStr, peerHash)
	status, resultEnt, err := c.execute(ctx, "unexclude", path, emptyParams())
	if err != nil || status != 200 {
		return status, types.RoleUnexcludeResultData{}, err
	}
	result, err := types.RoleUnexcludeResultDataFromEntity(resultEnt)
	if err != nil {
		return status, types.RoleUnexcludeResultData{}, fmt.Errorf("decode RoleUnexcludeResult: %w", err)
	}
	return status, result, nil
}

// Delegate is the IA22 member-to-member delegation op (§5.6, v1.6).
// The caller (delegator) delegates a role they hold (or a literal
// subset of its grants via `scope`) to `delegateHash`. Per SI-19
// `:delegate` MUST run on the delegator's own runtime peer; per SI-20
// `scope` MUST be literal (no template variables).
//
// expiresAt is optional — pass nil for no explicit bound. The minted
// delegation cap is rooted at the delegator's runtime peer (granter =
// delegator's identity) and persists at the role-derived storage path
// so layer-1 sweep / unassign / re-derive all reach it.
//
// Note: as of role v1.6 the Go handler returns 501 for :delegate; the
// SDK signature is the canonical shape that the impl will land into.
// Callers that need delegation today should detect the 501 and surface
// it; once the impl lands, no SDK callsite changes.
func (c *Client) Delegate(
	ctx context.Context,
	contextStr, roleName string,
	delegateHash hash.Hash,
	scope []types.GrantEntry,
	expiresAt *uint64,
) (uint, types.RoleDelegateResultData, error) {
	req := types.RoleDelegateRequestData{
		Delegate:  delegateHash,
		Context:   contextStr,
		Role:      roleName,
		Scope:     scope,
		ExpiresAt: expiresAt,
	}
	ent, err := req.ToEntity()
	if err != nil {
		return 0, types.RoleDelegateResultData{}, fmt.Errorf("encode RoleDelegateRequest: %w", err)
	}
	// Per §4.2 the resource target for :delegate is the role-derived
	// storage path where the delegation cap will land. Implementations
	// MAY accept the assignment path of the delegator's role and
	// synthesize the storage path internally; this SDK passes the
	// assignment-path form for ergonomic reasons (callers don't need
	// to know the future cap-hash).
	delegatorAssignmentPath := role.AssignmentPath(contextStr, c.callerHashFallback(), roleName)
	status, resultEnt, err := c.execute(ctx, "delegate", delegatorAssignmentPath, ent)
	if err != nil || status != 200 {
		return status, types.RoleDelegateResultData{}, err
	}
	result, err := types.RoleDelegateResultDataFromEntity(resultEnt)
	if err != nil {
		return status, types.RoleDelegateResultData{}, fmt.Errorf("decode RoleDelegateResult: %w", err)
	}
	return status, result, nil
}

// callerHashFallback returns the delegator's identity hash for use in
// the assignment-path resource target. This SDK is wire-side, so the
// caller's identity isn't directly known — but per SI-19 :delegate
// MUST run on the delegator's own peer, meaning the remote peer's
// identity-entity hash IS the delegator. Callers that need a
// different delegator (e.g., multi-tenant) should use SetDelegator.
func (c *Client) callerHashFallback() hash.Hash {
	return c.delegatorHash
}

// SetDelegator pins the delegator identity hash used to construct the
// resource path for :delegate. Optional — defaults to zero-hash, which
// produces the assignment-path form spec'd to be synthesized by the
// handler. Set this when the SDK is wrapping a multi-tenant flow where
// the caller identity is not the same as the transport's peer.
func (c *Client) SetDelegator(h hash.Hash) {
	c.delegatorHash = h
}

// ReDerive walks every assignment of roleName in contextStr and
// re-issues role-derived caps (§5.5 IA9). Per §5.5 SI-15, assignees
// that fail RL2 mid-cascade appear in the result's SkippedGrantees
// rather than aborting the cascade.
func (c *Client) ReDerive(ctx context.Context, contextStr, roleName string) (uint, types.RoleReDeriveResultData, error) {
	req := types.RoleReDeriveRequestData{Role: roleName}
	ent, err := req.ToEntity()
	if err != nil {
		return 0, types.RoleReDeriveResultData{}, fmt.Errorf("encode RoleReDeriveRequest: %w", err)
	}
	path := role.RoleDefinitionPath(contextStr, roleName)
	status, resultEnt, err := c.execute(ctx, "re-derive", path, ent)
	if err != nil || status != 200 {
		return status, types.RoleReDeriveResultData{}, err
	}
	result, err := types.RoleReDeriveResultDataFromEntity(resultEnt)
	if err != nil {
		return status, types.RoleReDeriveResultData{}, fmt.Errorf("decode RoleReDeriveResult: %w", err)
	}
	return status, result, nil
}

// execute is the shared EXECUTE-and-decode helper. Returns
// (status, result-entity-or-empty, err). Per V7 §3.2 all role ops use
// path-as-resource.
func (c *Client) execute(ctx context.Context, op, path string, params entity.Entity) (uint, entity.Entity, error) {
	resource := &types.ResourceTarget{Targets: []string{path}}
	respEnv, _, err := c.t.SendExecute(ctx, c.roleURI, op, params, resource)
	if err != nil {
		return 0, entity.Entity{}, err
	}
	respData, err := types.ExecuteResponseDataFromEntity(respEnv.Root)
	if err != nil {
		return 0, entity.Entity{}, fmt.Errorf("decode response: %w", err)
	}
	var resultEnt entity.Entity
	if len(respData.Result) > 0 {
		if err := ecf.Decode(respData.Result, &resultEnt); err != nil {
			return respData.Status, entity.Entity{}, fmt.Errorf("decode result entity: %w", err)
		}
	}
	return respData.Status, resultEnt, nil
}

func emptyParams() entity.Entity {
	raw, _ := ecf.Encode(map[string]interface{}{})
	ent, _ := entity.NewEntity("primitive/any", raw)
	return ent
}
