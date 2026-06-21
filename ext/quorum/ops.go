package quorum

import (
	"context"

	"go.entitychurch.org/entity-core-go/core/handler"
	"go.entitychurch.org/entity-core-go/core/hash"
	"go.entitychurch.org/entity-core-go/core/types"
)

// handleCreate writes a system/quorum entity at its canonical path
// system/quorum/{quorum_id_hex} per §6.1. The quorum entity is structural
// and not signed; authorization for :create is per coherent-capability §8.
func (h *Handler) handleCreate(ctx context.Context, req *handler.Request) (*handler.Response, error) {
	hctx := req.Context
	if hctx == nil || hctx.Store == nil || hctx.LocationIndex == nil {
		return handler.NewErrorResponse(500, "internal_error",
			"missing store or location index")
	}
	body, err := types.QuorumCreateRequestDataFromEntity(req.Params)
	if err != nil {
		return handler.NewErrorResponse(400, "invalid_request",
			"decode QuorumCreateRequest: "+err.Error())
	}
	q := body.QuorumData
	if err := validateQuorum(q); err != nil {
		return handler.NewErrorResponse(400, "invalid_quorum", err.Error())
	}
	ent, err := q.ToEntity()
	if err != nil {
		return handler.NewErrorResponse(500, "encode_failed", err.Error())
	}
	if _, err := hctx.Store.Put(ent); err != nil {
		return handler.NewErrorResponse(500, "store_put_failed", err.Error())
	}
	if _, err := hctx.TreeSet(QuorumPath(ent.ContentHash), ent.ContentHash, "create"); err != nil {
		return handler.NewErrorResponse(500, "storage_error", "bind quorum: "+err.Error())
	}
	return handler.NewResponse(200, types.TypeQuorumCreateResult,
		types.QuorumCreateResultData{QuorumID: ent.ContentHash})
}

// handleUpdate produces a quorum-update attestation per §6.2. Validates
// structural invariants, delegates to attestation:create with the
// quorum-update properties shape, binds at system/quorum/{q}/event/{h},
// and invalidates the signer-set cache on success.
func (h *Handler) handleUpdate(ctx context.Context, req *handler.Request) (*handler.Response, error) {
	hctx := req.Context
	if hctx == nil || hctx.Store == nil || hctx.LocationIndex == nil {
		return handler.NewErrorResponse(500, "internal_error",
			"missing store or location index")
	}
	h.mu.RLock()
	att := h.att
	h.mu.RUnlock()
	if att == nil {
		return handler.NewErrorResponse(503, "not_ready",
			"quorum handler attestation dependency not wired")
	}
	body, err := types.QuorumUpdateRequestDataFromEntity(req.Params)
	if err != nil {
		return handler.NewErrorResponse(400, "invalid_request",
			"decode QuorumUpdateRequest: "+err.Error())
	}
	if body.NewThreshold < 1 || body.NewThreshold > uint64(len(body.NewSigners)) {
		return handler.NewErrorResponse(400, "invalid_quorum_update",
			"new_threshold must be >= 1 and <= |new_signers|")
	}
	if !IsQuorumID(hctx.Store, hctx.LocationIndex, body.QuorumID) {
		return handler.NewErrorResponse(404, "quorum_not_found", body.QuorumID.String())
	}
	props, err := types.EncodeProperties(types.QuorumUpdateProperties{
		Kind:         types.KindQuorumUpdate,
		NewSigners:   body.NewSigners,
		NewThreshold: body.NewThreshold,
	})
	if err != nil {
		return handler.NewErrorResponse(500, "encode_failed", err.Error())
	}
	updateAtt := types.AttestationData{
		Attesting:  body.QuorumID,
		Attested:   body.QuorumID,
		Properties: props,
		Supersedes: body.Supersedes,
	}
	// Compute the binding path: system/quorum/{q}/event/{att_hash}.
	// Pre-compute the entity to know the hash for the path.
	ent, err := updateAtt.ToEntity()
	if err != nil {
		return handler.NewErrorResponse(500, "encode_failed", err.Error())
	}
	path := QuorumEventPath(body.QuorumID, ent.ContentHash)
	attHash, err := att.Create(hctx, path, updateAtt)
	if err != nil {
		return handler.NewErrorResponse(400, "create_failed", err.Error())
	}
	h.cache.invalidate(body.QuorumID)
	return handler.NewResponse(200, types.TypeQuorumUpdateResult,
		types.QuorumUpdateResultData{UpdateHash: attHash})
}

// handlePublish produces a quorum-publish attestation per §6.3. Validates
// signers / threshold match the current signer set on initial publish (no
// supersedes); supersedes-chain publishes are validated by the previous
// signer set per §3.3 (validation runs in the sync hook on arrival).
func (h *Handler) handlePublish(ctx context.Context, req *handler.Request) (*handler.Response, error) {
	hctx := req.Context
	if hctx == nil || hctx.Store == nil || hctx.LocationIndex == nil {
		return handler.NewErrorResponse(500, "internal_error",
			"missing store or location index")
	}
	h.mu.RLock()
	att := h.att
	h.mu.RUnlock()
	if att == nil {
		return handler.NewErrorResponse(503, "not_ready",
			"quorum handler attestation dependency not wired")
	}
	body, err := types.QuorumPublishRequestDataFromEntity(req.Params)
	if err != nil {
		return handler.NewErrorResponse(400, "invalid_request",
			"decode QuorumPublishRequest: "+err.Error())
	}
	if !IsQuorumID(hctx.Store, hctx.LocationIndex, body.QuorumID) {
		return handler.NewErrorResponse(404, "quorum_not_found", body.QuorumID.String())
	}
	if body.Threshold < 1 || body.Threshold > uint64(len(body.Signers)) {
		return handler.NewErrorResponse(400, "invalid_publish",
			"threshold must be >= 1 and <= |signers|")
	}
	// Initial publish: signers/threshold MUST match current_signer_set.
	// Subsequent publishes are signed by the previous quorum (per §3.3); the
	// caller is responsible for matching the supersedes-chain key.
	if body.Supersedes == nil {
		curSigners, curThreshold, err := h.CurrentSignerSet(body.QuorumID)
		if err != nil {
			return handler.NewErrorResponse(500, "signer_set_resolve", err.Error())
		}
		if !signerSetsEqual(body.Signers, curSigners) || body.Threshold != curThreshold {
			return handler.NewErrorResponse(400, "publish_mismatch",
				"initial publish signers/threshold MUST match current_signer_set")
		}
	}
	props, err := types.EncodeProperties(types.QuorumPublishProperties{
		Kind:            types.KindQuorumPublish,
		Signers:         body.Signers,
		Threshold:       body.Threshold,
		PublishedHandle: body.PublishedHandle,
	})
	if err != nil {
		return handler.NewErrorResponse(500, "encode_failed", err.Error())
	}
	merged := types.MergeProperties(props, body.ExtraProperties)
	publishAtt := types.AttestationData{
		Attesting:  body.QuorumID,
		Attested:   body.QuorumID,
		Properties: merged,
		Supersedes: body.Supersedes,
	}
	ent, err := publishAtt.ToEntity()
	if err != nil {
		return handler.NewErrorResponse(500, "encode_failed", err.Error())
	}
	path := QuorumEventPath(body.QuorumID, ent.ContentHash)
	attHash, err := att.Create(hctx, path, publishAtt)
	if err != nil {
		return handler.NewErrorResponse(400, "create_failed", err.Error())
	}
	h.cache.invalidate(body.QuorumID)
	return handler.NewResponse(200, types.TypeQuorumPublishResult,
		types.QuorumPublishResultData{PublishHash: attHash})
}

// handleVerify wraps current_signer_set + verify_k_of_n_signatures per §6.4.
// Returns the validation result and the set of constituents whose signatures
// were verified.
func (h *Handler) handleVerify(ctx context.Context, req *handler.Request) (*handler.Response, error) {
	hctx := req.Context
	if hctx == nil || hctx.Store == nil || hctx.LocationIndex == nil {
		return handler.NewErrorResponse(500, "internal_error",
			"missing store or location index")
	}
	body, err := types.QuorumVerifyRequestDataFromEntity(req.Params)
	if err != nil {
		return handler.NewErrorResponse(400, "invalid_request",
			"decode QuorumVerifyRequest: "+err.Error())
	}
	signers, threshold, err := h.CurrentSignerSet(body.QuorumID)
	if err != nil {
		return handler.NewErrorResponse(404, "quorum_not_found", err.Error())
	}
	signedBy, ok := VerifyKOfNSignatures(hctx.Store, hctx.LocationIndex, body.EntityHash, signers, threshold)
	return handler.NewResponse(200, types.TypeQuorumVerifyResult,
		types.QuorumVerifyResultData{Valid: ok, SignedBy: signedBy})
}

// validateQuorum enforces the §3.1 invariants: threshold >= 1; threshold
// <= |signers|; signers non-empty; all signer hashes non-zero.
func validateQuorum(q types.QuorumData) error {
	if len(q.Signers) == 0 {
		return errString("signers must be non-empty")
	}
	if q.Threshold < 1 || q.Threshold > uint64(len(q.Signers)) {
		return errString("threshold must be >= 1 and <= |signers|")
	}
	for _, s := range q.Signers {
		if s.IsZero() {
			return errString("signer hash must be non-zero")
		}
	}
	return nil
}

// signerSetsEqual returns true iff a and b contain the same signer hashes
// (order-sensitive — quorum signer order is significant for K-of-N
// verification ordering and impl test parity).
func signerSetsEqual(a, b []hash.Hash) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
