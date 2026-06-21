// adapter.go — bridges the chain-consult orchestrator to ext/content's
// MissResolver interface, plus the ctx-key plumbing for claimed
// source_peer_id (Ruling 4 — local context, NOT a wire field).

package storagesubstitutesources

import (
	"context"

	"go.entitychurch.org/entity-core-go/core/handler"
	"go.entitychurch.org/entity-core-go/core/hash"
	"go.entitychurch.org/entity-core-go/ext/content"
)

// claimedSourceKey is the context-key under which the dispatcher (or
// caller) stows the claimed source_peer_id for a content:get. The CONTENT
// miss-hook reads it via ClaimedSourceFromContext when invoking the
// orchestrator. Defining the key as an unexported struct type prevents
// accidental collision with other ctx-key consumers.
type claimedSourceKey struct{}

// WithClaimedSource returns a derived context carrying source_peer_id as
// the claimed source for any storage-substitute chain consultation
// downstream. Per Ruling 4 this stays local — never serialized into a
// get-request wire field.
func WithClaimedSource(ctx context.Context, sourcePeerID hash.Hash) context.Context {
	return context.WithValue(ctx, claimedSourceKey{}, sourcePeerID)
}

// ClaimedSourceFromContext returns the claimed source the dispatcher
// stowed via WithClaimedSource (zero hash + ok=false if absent).
func ClaimedSourceFromContext(ctx context.Context) (hash.Hash, bool) {
	v := ctx.Value(claimedSourceKey{})
	if v == nil {
		return hash.Hash{}, false
	}
	h, ok := v.(hash.Hash)
	return h, ok
}

// Resolve implements content.MissResolver. The CONTENT handler calls
// this from handleGet's miss branch (when WithMissResolver(o) was wired
// at peer construction). The claimed source comes from the ctx-key set
// by the caller (Ruling 4 — local plumbing, not a wire field).
func (o *Orchestrator) Resolve(ctx context.Context, hctx *handler.HandlerContext, target hash.Hash) content.MissResult {
	claimed, ok := ClaimedSourceFromContext(ctx)
	if !ok {
		// No claimed source → bare-hash query → never consult (§3-RES.2).
		// Return an empty MissResult so the content handler marks the
		// hash as missing.
		return content.MissResult{}
	}

	res := o.Consult(ctx, hctx, target, claimed)
	switch res.Outcome {
	case OutcomeBytes:
		return content.MissResult{Found: true, Entity: res.Bytes}
	case OutcomeCapDenied:
		return content.MissResult{CapDenied: true}
	default:
		// Disabled / NotFound → mark as missing without aborting.
		return content.MissResult{}
	}
}
