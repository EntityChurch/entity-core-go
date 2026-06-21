// Package sdk wraps system/identity EXECUTE operations behind a small
// Go API. Mirrors the role SDK's shape — Transport interface + Client
// struct — so applications and test fixtures share one calling
// convention across the identity stack (configure ceremony + role
// management).
//
// # Scope (first cut)
//
// Configure only — that's the §14.1 Acme onboarding entry point. The
// other identity ops (create_quorum, create_attestation,
// supersede_attestation, revoke_attestation, publish_attestation,
// process_attestation) follow the same pattern and can be added as
// fixtures need them.
//
// # Transport
//
// Same Transport interface as ext/role/sdk; cmd/internal/validate.PeerClient
// satisfies it without modification.
package sdk

import (
	"context"
	"fmt"

	"go.entitychurch.org/entity-core-go/core/crypto"
	"go.entitychurch.org/entity-core-go/core/ecf"
	"go.entitychurch.org/entity-core-go/core/entity"
	"go.entitychurch.org/entity-core-go/core/hash"
	"go.entitychurch.org/entity-core-go/core/types"
	"go.entitychurch.org/entity-core-go/ext/identity"
)

// Transport is the wire-side dependency the identity SDK needs. Same
// shape as ext/role/sdk.Transport — by design, so a single PeerClient
// instance satisfies both.
type Transport interface {
	SendExecute(ctx context.Context, uri, operation string, params entity.Entity, resource *types.ResourceTarget) (entity.Envelope, []byte, error)
	RemotePeerID() crypto.PeerID
}

// Client wraps system/identity EXECUTE operations behind typed Go
// methods. One Client targets one remote peer.
type Client struct {
	t           Transport
	identityURI string
}

// NewClient constructs an identity SDK client targeting the peer behind t.
func NewClient(t Transport) *Client {
	return &Client{
		t:           t,
		identityURI: fmt.Sprintf("entity://%s/system/identity", t.RemotePeerID().String()),
	}
}

// Configure runs the §6.1 configure ceremony on the remote peer:
// installs peer-config, locates live controller-cert attestations under
// the trusted quorum, and issues local peer→controller caps. Returns
// the peer-config path and the issued cap hashes.
//
// Startup flow: post-startup, configure must be authorized by the
// caller's local peer→controller cap (§6.1). Pre-startup, callers use
// identity.Startup(...) directly against the peer's store; that's an
// in-process path and lives in entity-peer wiring, not in this SDK.
func (c *Client) Configure(ctx context.Context, req types.IdentityConfigureRequestData) (uint, types.IdentityConfigureResultData, error) {
	ent, err := req.ToEntity()
	if err != nil {
		return 0, types.IdentityConfigureResultData{}, fmt.Errorf("encode IdentityConfigureRequest: %w", err)
	}
	resource := &types.ResourceTarget{Targets: []string{identity.PeerConfigPath}}
	status, resultEnt, err := c.execute(ctx, "configure", resource, ent)
	if err != nil || status != 200 {
		return status, types.IdentityConfigureResultData{}, err
	}
	result, err := types.IdentityConfigureResultDataFromEntity(resultEnt)
	if err != nil {
		return status, types.IdentityConfigureResultData{}, fmt.Errorf("decode IdentityConfigureResult: %w", err)
	}
	return status, result, nil
}

// CreateAttestation mints a system/attestation entity on the remote peer
// per §6. The attestation is bound at its canonical path (derived from
// kind/function/mode); the returned AttestationHash is the on-disk
// content hash. K-of-N signatures (where the attestation is anchored
// under a multi-sig quorum) are written separately as system/signature
// entities at /{signer_peer_id}/system/signature/{attestation_hex} per
// EXTENSION-ATTESTATION v1.1 §4.0.
func (c *Client) CreateAttestation(ctx context.Context, att types.AttestationData) (uint, types.IdentityCreateAttestationResultData, error) {
	req := types.IdentityCreateAttestationRequestData{AttestationData: att}
	ent, err := req.ToEntity()
	if err != nil {
		return 0, types.IdentityCreateAttestationResultData{}, fmt.Errorf("encode IdentityCreateAttestationRequest: %w", err)
	}
	// Path-as-resource per V7 §3.2 / EXTENSION-IDENTITY §6: caller supplies
	// the canonical tree-binding path. Embedded mode has no path; let
	// the handler short-circuit on nil resource for that case.
	var resource *types.ResourceTarget
	if path, perr := identity.CanonicalCertPath(att); perr == nil && path != "" {
		resource = &types.ResourceTarget{Targets: []string{path}}
	}
	status, resultEnt, err := c.execute(ctx, "create_attestation", resource, ent)
	if err != nil || status != 200 {
		return status, types.IdentityCreateAttestationResultData{}, err
	}
	result, err := types.IdentityCreateAttestationResultDataFromEntity(resultEnt)
	if err != nil {
		return status, types.IdentityCreateAttestationResultData{}, fmt.Errorf("decode IdentityCreateAttestationResult: %w", err)
	}
	return status, result, nil
}

// PublishAttestation promotes/demotes a kind=identity-cert function=agent
// attestation across publication modes per §6 / §4.2a. The on-disk entity
// is unchanged — only its tree binding moves between mode-specific paths
// (internal / public / per-relationship). ContactID is required when
// NewMode == "per-relationship". Returns the new tree path.
//
// Only applies to function=agent certs. Function=controller certs use
// :supersede_attestation for lifecycle changes; this op rejects them
// at handler validation.
func (c *Client) PublishAttestation(ctx context.Context, attHash hash.Hash, newMode string, contactID *hash.Hash) (uint, types.IdentityPublishAttestationResultData, error) {
	req := types.IdentityPublishAttestationRequestData{
		AttestationHash: attHash,
		NewMode:         newMode,
		ContactID:       contactID,
	}
	ent, err := req.ToEntity()
	if err != nil {
		return 0, types.IdentityPublishAttestationResultData{}, fmt.Errorf("encode IdentityPublishAttestationRequest: %w", err)
	}
	// Path-as-resource: the new tree-binding location for the agent-cert
	// after publish moves it. Mode determines path family.
	var resource *types.ResourceTarget
	switch newMode {
	case types.ModeInternal:
		resource = &types.ResourceTarget{Targets: []string{identity.InternalCertPath(attHash)}}
	case types.ModePublic:
		resource = &types.ResourceTarget{Targets: []string{identity.PublicCertPath(attHash)}}
	case types.ModePerRelationship:
		if contactID != nil && !contactID.IsZero() {
			resource = &types.ResourceTarget{Targets: []string{identity.RelationshipCertPath(*contactID, attHash)}}
		}
	}
	status, resultEnt, err := c.execute(ctx, "publish_attestation", resource, ent)
	if err != nil || status != 200 {
		return status, types.IdentityPublishAttestationResultData{}, err
	}
	result, err := types.IdentityPublishAttestationResultDataFromEntity(resultEnt)
	if err != nil {
		return status, types.IdentityPublishAttestationResultData{}, fmt.Errorf("decode IdentityPublishAttestationResult: %w", err)
	}
	return status, result, nil
}

// RevokeAttestation produces a revocation attestation targeting an
// identity-context attestation per §6. The revocation is itself an
// attestation entity (kind="revocation"), bound at the same tier as
// the target. The caller MUST K-of-N sign the revocation under the
// quorum's threshold for it to be "live"; an unsigned revocation
// has no effect on liveness.
func (c *Client) RevokeAttestation(ctx context.Context, targetHash hash.Hash, reason string) (uint, types.IdentityRevokeAttestationResultData, error) {
	req := types.IdentityRevokeAttestationRequestData{TargetHash: targetHash, Reason: reason}
	ent, err := req.ToEntity()
	if err != nil {
		return 0, types.IdentityRevokeAttestationResultData{}, fmt.Errorf("encode IdentityRevokeAttestationRequest: %w", err)
	}
	status, resultEnt, err := c.execute(ctx, "revoke_attestation", nil, ent)
	if err != nil || status != 200 {
		return status, types.IdentityRevokeAttestationResultData{}, err
	}
	result, err := types.IdentityRevokeAttestationResultDataFromEntity(resultEnt)
	if err != nil {
		return status, types.IdentityRevokeAttestationResultData{}, fmt.Errorf("decode IdentityRevokeAttestationResult: %w", err)
	}
	return status, result, nil
}

// SupersedeAttestation mints a successor identity-context attestation
// per §6. The new attestation MUST set Supersedes to the prior attestation's
// content hash; the handler validates the kind matches and binds the new
// attestation at its canonical path. The previous attestation remains in
// the tree but is no longer "live" — :configure's enumerator filters
// superseded chains and only issues caps for the live tip.
func (c *Client) SupersedeAttestation(ctx context.Context, newAtt types.AttestationData) (uint, types.IdentitySupersedeAttestationResultData, error) {
	req := types.IdentitySupersedeAttestationRequestData{AttestationData: newAtt}
	ent, err := req.ToEntity()
	if err != nil {
		return 0, types.IdentitySupersedeAttestationResultData{}, fmt.Errorf("encode IdentitySupersedeAttestationRequest: %w", err)
	}
	// Path-as-resource: the canonical tree-binding path of the new
	// successor attestation.
	var resource *types.ResourceTarget
	if path, perr := identity.CanonicalCertPath(newAtt); perr == nil && path != "" {
		resource = &types.ResourceTarget{Targets: []string{path}}
	}
	status, resultEnt, err := c.execute(ctx, "supersede_attestation", resource, ent)
	if err != nil || status != 200 {
		return status, types.IdentitySupersedeAttestationResultData{}, err
	}
	result, err := types.IdentitySupersedeAttestationResultDataFromEntity(resultEnt)
	if err != nil {
		return status, types.IdentitySupersedeAttestationResultData{}, fmt.Errorf("decode IdentitySupersedeAttestationResult: %w", err)
	}
	return status, result, nil
}

// CreateQuorum mints a system/quorum entity on the remote peer per §6.
// Delegates to system/quorum:create internally; returns the quorum's
// content hash. The quorum entity is structural and not itself signed —
// authorization for :create_quorum follows the standard caller-cap path.
//
// The §14.1 Acme deployment shape uses this to bind the founder K-of-N
// quorum that subsequently drives :assign via a multi-sig caller cap.
func (c *Client) CreateQuorum(ctx context.Context, signers []hash.Hash, threshold uint64, name string) (uint, types.IdentityCreateQuorumResultData, error) {
	q := types.QuorumData{
		Signers:   signers,
		Threshold: threshold,
		Name:      name,
	}
	req := types.IdentityCreateQuorumRequestData{QuorumData: q}
	ent, err := req.ToEntity()
	if err != nil {
		return 0, types.IdentityCreateQuorumResultData{}, fmt.Errorf("encode IdentityCreateQuorumRequest: %w", err)
	}
	// Path-as-resource: canonical quorum path is system/quorum/{q_hex}
	// where q_hex is the hash of the QuorumData entity. Compute locally
	// so the request satisfies V7 §3.2 / EXTENSION-QUORUM §6.1's MUST.
	qEnt, qerr := q.ToEntity()
	if qerr != nil {
		return 0, types.IdentityCreateQuorumResultData{}, fmt.Errorf("compute quorum hash: %w", qerr)
	}
	resource := &types.ResourceTarget{Targets: []string{identity.QuorumPathFor(qEnt.ContentHash)}}
	status, resultEnt, err := c.execute(ctx, "create_quorum", resource, ent)
	if err != nil || status != 200 {
		return status, types.IdentityCreateQuorumResultData{}, err
	}
	result, err := types.IdentityCreateQuorumResultDataFromEntity(resultEnt)
	if err != nil {
		return status, types.IdentityCreateQuorumResultData{}, fmt.Errorf("decode IdentityCreateQuorumResult: %w", err)
	}
	return status, result, nil
}

// execute is the shared EXECUTE-and-decode helper. resource may be nil
// for ops that take no resource target (configure, create_quorum).
func (c *Client) execute(ctx context.Context, op string, resource *types.ResourceTarget, params entity.Entity) (uint, entity.Entity, error) {
	respEnv, _, err := c.t.SendExecute(ctx, c.identityURI, op, params, resource)
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
