package attestation

import (
	"context"
	"fmt"

	"go.entitychurch.org/entity-core-go/core/handler"
	"go.entitychurch.org/entity-core-go/core/hash"
	"go.entitychurch.org/entity-core-go/core/types"
)

// Create writes a system/attestation entity at `path` and updates the index
// per §6.1. Validates structural invariants only — signature gathering and
// consumer authority are out of scope. Used by handleCreate (the EXECUTE
// dispatch path) and by consumer extensions (ext/quorum, ext/identity) that
// produce attestations directly via Go calls without an EXECUTE round-trip.
//
// Returns the new attestation's content hash.
func (h *Handler) Create(hctx *handler.HandlerContext, path string, att types.AttestationData) (hash.Hash, error) {
	if hctx == nil || hctx.Store == nil || hctx.LocationIndex == nil {
		return hash.Hash{}, errString("missing store or location index")
	}
	if path == "" {
		return hash.Hash{}, errString("create requires a resource path")
	}
	if err := validateStructure(att); err != nil {
		return hash.Hash{}, err
	}
	if att.Supersedes != nil {
		if _, err := loadAttestation(hctx.Store, *att.Supersedes); err != nil {
			return hash.Hash{}, errString("invalid supersedes: " + err.Error())
		}
	}
	ent, err := att.ToEntity()
	if err != nil {
		return hash.Hash{}, errString("encode attestation: " + err.Error())
	}
	if _, err := hctx.Store.Put(ent); err != nil {
		return hash.Hash{}, err
	}
	if _, err := hctx.TreeSet(path, ent.ContentHash, "attestation-create"); err != nil {
		return hash.Hash{}, fmt.Errorf("bind attestation: %w", err)
	}
	h.ix.Add(ent.ContentHash, att)
	return ent.ContentHash, nil
}

// handleCreate is the EXECUTE wrapper around Create. It decodes the request,
// reads the resource path from the handler context, and returns the result
// in V7 wire form.
func (h *Handler) handleCreate(ctx context.Context, req *handler.Request) (*handler.Response, error) {
	hctx := req.Context
	if hctx == nil || hctx.Store == nil || hctx.LocationIndex == nil {
		return handler.NewErrorResponse(500, "internal_error",
			"missing store or location index")
	}
	path := resourcePath(req)
	if path == "" {
		return handler.NewErrorResponse(400, "missing_resource_path",
			"system/attestation:create requires a resource target path")
	}
	body, err := types.AttestationCreateRequestDataFromEntity(req.Params)
	if err != nil {
		return handler.NewErrorResponse(400, "invalid_request",
			"decode AttestationCreateRequest: "+err.Error())
	}
	attHash, err := h.Create(hctx, path, body.AttestationData)
	if err != nil {
		return handler.NewErrorResponse(400, "invalid_attestation", err.Error())
	}
	return handler.NewResponse(200, types.TypeAttestationCreateResult,
		types.AttestationCreateResultData{AttestationHash: attHash})
}

// handleSupersede produces a successor attestation per §6.2. Looks up
// previous_hash, copies its attesting/attested into the new attestation, sets
// supersedes=previous_hash, applies the request's properties / time bounds,
// and stores at the resource path.
func (h *Handler) handleSupersede(ctx context.Context, req *handler.Request) (*handler.Response, error) {
	hctx := req.Context
	if hctx == nil || hctx.Store == nil || hctx.LocationIndex == nil {
		return handler.NewErrorResponse(500, "internal_error",
			"missing store or location index")
	}
	path := resourcePath(req)
	if path == "" {
		return handler.NewErrorResponse(400, "missing_resource_path",
			"system/attestation:supersede requires a resource target path")
	}
	body, err := types.AttestationSupersedeRequestDataFromEntity(req.Params)
	if err != nil {
		return handler.NewErrorResponse(400, "invalid_request",
			"decode AttestationSupersedeRequest: "+err.Error())
	}
	prev, err := loadAttestation(hctx.Store, body.PreviousHash)
	if err != nil {
		return handler.NewErrorResponse(404, "previous_not_found",
			"supersede previous_hash: "+err.Error())
	}
	prevHash := body.PreviousHash
	att := types.AttestationData{
		Attesting:  prev.Attesting,
		Attested:   prev.Attested,
		Properties: body.Properties,
		Supersedes: &prevHash,
		NotBefore:  body.NotBefore,
		ExpiresAt:  body.ExpiresAt,
	}
	if err := validateStructure(att); err != nil {
		return handler.NewErrorResponse(400, "invalid_attestation", err.Error())
	}
	ent, err := att.ToEntity()
	if err != nil {
		return handler.NewErrorResponse(500, "encode_failed", err.Error())
	}
	if _, err := hctx.Store.Put(ent); err != nil {
		return handler.NewErrorResponse(500, "store_put_failed", err.Error())
	}
	if _, err := hctx.TreeSet(path, ent.ContentHash, "attestation-supersede"); err != nil {
		return handler.NewErrorResponse(500, "storage_error", "bind attestation: "+err.Error())
	}
	h.ix.Add(ent.ContentHash, att)
	return handler.NewResponse(200, types.TypeAttestationSupersedeResult,
		types.AttestationSupersedeResultData{AttestationHash: ent.ContentHash})
}

// handleRevoke produces a revocation attestation per §6.3 — equivalent to
// :create with the universal kind="revocation" properties shape. The
// revocation's attesting / attested / properties are derived from the request
// body; the revocation itself is bound at the resource-target path.
func (h *Handler) handleRevoke(ctx context.Context, req *handler.Request) (*handler.Response, error) {
	hctx := req.Context
	if hctx == nil || hctx.Store == nil || hctx.LocationIndex == nil {
		return handler.NewErrorResponse(500, "internal_error",
			"missing store or location index")
	}
	path := resourcePath(req)
	if path == "" {
		return handler.NewErrorResponse(400, "missing_resource_path",
			"system/attestation:revoke requires a resource target path")
	}
	body, err := types.AttestationRevokeRequestDataFromEntity(req.Params)
	if err != nil {
		return handler.NewErrorResponse(400, "invalid_request",
			"decode AttestationRevokeRequest: "+err.Error())
	}
	if body.TargetHash.IsZero() || body.Attesting.IsZero() {
		return handler.NewErrorResponse(400, "invalid_attestation",
			"revoke requires non-zero target_hash and attesting")
	}
	props, err := types.EncodeProperties(types.RevocationProperties{
		Kind:   types.KindRevocation,
		Reason: body.Reason,
	})
	if err != nil {
		return handler.NewErrorResponse(500, "encode_failed", err.Error())
	}
	att := types.AttestationData{
		Attesting:  body.Attesting,
		Attested:   body.TargetHash,
		Properties: props,
	}
	ent, err := att.ToEntity()
	if err != nil {
		return handler.NewErrorResponse(500, "encode_failed", err.Error())
	}
	if _, err := hctx.Store.Put(ent); err != nil {
		return handler.NewErrorResponse(500, "store_put_failed", err.Error())
	}
	if _, err := hctx.TreeSet(path, ent.ContentHash, "attestation-revoke"); err != nil {
		return handler.NewErrorResponse(500, "storage_error", "bind revocation: "+err.Error())
	}
	h.ix.Add(ent.ContentHash, att)
	return handler.NewResponse(200, types.TypeAttestationRevokeResult,
		types.AttestationRevokeResultData{RevocationHash: ent.ContentHash})
}

// handleVerify wraps signature + liveness checks per §6.4. Looks up the
// attestation by hash, runs VerifyAttestationSignature + IsAttestationLive,
// returns {valid, reason}. Consumer-specific authority rules are NOT checked
// here — see consumer extensions.
func (h *Handler) handleVerify(ctx context.Context, req *handler.Request) (*handler.Response, error) {
	hctx := req.Context
	if hctx == nil || hctx.Store == nil || hctx.LocationIndex == nil {
		return handler.NewErrorResponse(500, "internal_error",
			"missing store or location index")
	}
	body, err := types.AttestationVerifyRequestDataFromEntity(req.Params)
	if err != nil {
		return handler.NewErrorResponse(400, "invalid_request",
			"decode AttestationVerifyRequest: "+err.Error())
	}
	att, err := loadAttestation(hctx.Store, body.AttestationHash)
	if err != nil {
		return handler.NewResponse(200, types.TypeAttestationVerifyResult,
			types.AttestationVerifyResultData{Valid: false, Reason: "not_found"})
	}
	if !VerifyAttestationSignature(hctx.Store, hctx.LocationIndex, body.AttestationHash, att) {
		return handler.NewResponse(200, types.TypeAttestationVerifyResult,
			types.AttestationVerifyResultData{Valid: false, Reason: "invalid_signature"})
	}
	asOf := uint64(0)
	if body.AsOf != nil {
		asOf = *body.AsOf
	}
	if !IsAttestationLive(hctx.Store, hctx.LocationIndex, h.ix, body.AttestationHash, att, asOf) {
		return handler.NewResponse(200, types.TypeAttestationVerifyResult,
			types.AttestationVerifyResultData{Valid: false, Reason: "not_live"})
	}
	return handler.NewResponse(200, types.TypeAttestationVerifyResult,
		types.AttestationVerifyResultData{Valid: true})
}

// validateStructure enforces the §3.1 / §6.1 structural invariants:
// attesting and attested are non-zero hashes; properties is a map (CBOR
// shape; we accept nil as empty); not_before <= expires_at when both set.
func validateStructure(att types.AttestationData) error {
	if att.Attesting.IsZero() {
		return errString("attesting must be a non-zero hash")
	}
	if att.Attested.IsZero() {
		return errString("attested must be a non-zero hash")
	}
	if att.NotBefore != nil && att.ExpiresAt != nil && *att.NotBefore > *att.ExpiresAt {
		return errString("not_before must be <= expires_at")
	}
	return nil
}

type errString string

func (e errString) Error() string { return string(e) }
