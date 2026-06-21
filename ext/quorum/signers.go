package quorum

import (
	"context"
	"encoding/hex"
	"fmt"
	"sync"

	"go.entitychurch.org/entity-core-go/core/hash"
	"go.entitychurch.org/entity-core-go/core/store"
	"go.entitychurch.org/entity-core-go/core/types"
	"go.entitychurch.org/entity-core-go/ext/attestation"
)

// IsQuorumID returns true iff `h` refers to a system/quorum entity bound at
// its canonical path system/quorum/{hex(h)} on the local peer's tree per
// §4.3. Path-based lookup is normative — the quorum is "known" only if it
// is bound at its canonical path on the local tree (TV-Q6, TV-Q8 type
// mismatch fails closed).
//
// Race semantics during bootstrap / sync catch-up: this function is
// stateless and re-evaluates at each call. If a cert validation runs before
// the relevant quorum entity has been written, the call returns false and
// dispatch falls through accordingly; subsequent calls after the quorum is
// written return true.
func IsQuorumID(cs store.ContentStore, li store.LocationIndex, h hash.Hash) bool {
	if h.IsZero() {
		return false
	}
	path := QuorumPath(h)
	entHash, ok := li.Get(path)
	if !ok {
		return false
	}
	ent, ok := cs.Get(entHash)
	if !ok {
		return false
	}
	return ent.Type == types.TypeQuorum
}

// QuorumPath returns the canonical storage path for a quorum entity per
// §7: system/quorum/{quorum_id_hex} (lowercase hex of the full 33-byte
// system/hash byte sequence).
func QuorumPath(quorumID hash.Hash) string {
	return "system/quorum/" + hex.EncodeToString(quorumID.Bytes())
}

// QuorumEventPath returns the canonical storage path for a quorum-update
// or quorum-publish attestation under quorumID per §7:
// system/quorum/{quorum_id_hex}/event/{hash_hex}.
func QuorumEventPath(quorumID, eventHash hash.Hash) string {
	return QuorumPath(quorumID) + "/event/" + hex.EncodeToString(eventHash.Bytes())
}

// signerSetCache maintains per-quorum (signers, threshold) snapshots for
// CurrentSignerSet per §4.2.1. The cache is per-peer; cross-peer sync
// invalidations apply at the receiving peer's cache.
type signerSetCache struct {
	mu      sync.RWMutex
	entries map[hash.Hash]signerSetEntry
}

type signerSetEntry struct {
	signers   []hash.Hash
	threshold uint64
}

func newSignerSetCache() *signerSetCache {
	return &signerSetCache{entries: make(map[hash.Hash]signerSetEntry)}
}

func (c *signerSetCache) get(quorumID hash.Hash) ([]hash.Hash, uint64, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	e, ok := c.entries[quorumID]
	if !ok {
		return nil, 0, false
	}
	out := make([]hash.Hash, len(e.signers))
	copy(out, e.signers)
	return out, e.threshold, true
}

func (c *signerSetCache) set(quorumID hash.Hash, signers []hash.Hash, threshold uint64) {
	stored := make([]hash.Hash, len(signers))
	copy(stored, signers)
	c.mu.Lock()
	c.entries[quorumID] = signerSetEntry{signers: stored, threshold: threshold}
	c.mu.Unlock()
}

// invalidate scopes the invalidation per §4.2.1: only the named quorum's
// entry is cleared (TV-QF15 — other quorums are independently scoped).
func (c *signerSetCache) invalidate(quorumID hash.Hash) {
	c.mu.Lock()
	delete(c.entries, quorumID)
	c.mu.Unlock()
}

// CurrentSignerSet walks the live quorum-update attestation chain to
// determine the effective signer set + threshold per §4.2. The walk uses
// ext/attestation's index lookups and find_live_head; no quorum-specific
// traversal logic. Resolution-mode dispatch (per §5.1, §5.2) maps each
// entry through its resolver if applicable.
//
// Returns the current effective signer set. Use CurrentSignerSetAt for a
// historical timestamp; use CurrentSignerSetCtx when a parent context
// carries resolver-chain state (depth/visited per IDENTITY-2).
//
// Cache (§4.2.1): if a cached entry exists for quorumID, it is returned
// directly. Misses recompute and populate the cache.
func (h *Handler) CurrentSignerSet(quorumID hash.Hash) ([]hash.Hash, uint64, error) {
	return h.CurrentSignerSetCtx(context.Background(), quorumID, 0)
}

// CurrentSignerSetAt returns the signer set + threshold that was live at
// the given epoch-millisecond timestamp per §4.2 / §5.2 (`as_of` parameter).
// When asOf is 0 the result equals CurrentSignerSet (current state, cached).
// When asOf is non-zero the cache is bypassed (cache holds current state
// only); the chain is walked fresh and resolved as of that timestamp.
//
// Historical resolution is normative per the v1.1 spec: a `quorum-update`
// signed before a controller rotation in an identity-resolved group
// quorum must validate against the controller live at the update's
// not_before time, not the current controller. `find_live_head` already
// accepts as_of (per EXTENSION-ATTESTATION §5.3); the historical walk
// reuses its existing semantics through IsAttestationLive.
func (h *Handler) CurrentSignerSetAt(quorumID hash.Hash, asOf uint64) ([]hash.Hash, uint64, error) {
	return h.CurrentSignerSetCtx(context.Background(), quorumID, asOf)
}

// CurrentSignerSetCtx is the full-control entry point. Carries
// resolver-chain state (depth + visited per IDENTITY-2) through the
// context so nested resolvers see the same bound. Top-level callers pass
// context.Background(); recursive resolvers (e.g., identity-resolved
// against a group-of-groups topology) thread the context they received.
//
// The cache is consulted only when asOf == 0 AND no parent resolver state
// is present (i.e., this is a fresh top-level call). Historical or
// nested-recursive calls bypass the cache.
func (h *Handler) CurrentSignerSetCtx(ctx context.Context, quorumID hash.Hash, asOf uint64) ([]hash.Hash, uint64, error) {
	parent, hasParent := getResolverState(ctx)
	useCache := asOf == 0 && !hasParent
	if useCache {
		if signers, threshold, ok := h.cache.get(quorumID); ok {
			return signers, threshold, nil
		}
	}
	if hasParent {
		// Nested call from a resolver — propagate cycle/depth bound.
		if _, seen := parent.visited[quorumID]; seen {
			return nil, 0, &ResolverCycleError{QuorumID: quorumID}
		}
		if parent.depth+1 > MaxResolverDepth {
			return nil, 0, &ResolverDepthExceededError{QuorumID: quorumID, Depth: parent.depth + 1}
		}
		parent.visited[quorumID] = struct{}{}
		parent.depth++
		defer func() { parent.depth-- }()
	} else {
		// Fresh top-level call — install resolver state for this invocation.
		ctx = withResolverState(ctx, quorumID)
	}
	signers, threshold, err := h.computeSignerSet(ctx, quorumID, asOf)
	if err != nil {
		return nil, 0, err
	}
	if useCache {
		h.cache.set(quorumID, signers, threshold)
	}
	return signers, threshold, nil
}

// computeSignerSet performs the chain walk + resolution dispatch at the
// given asOf timestamp. asOf == 0 means "current"; FindLiveHead and the
// resolver hook treat 0 as "use wall-clock now." The context carries
// resolver-chain state for nested cycle/depth detection.
func (h *Handler) computeSignerSet(ctx context.Context, quorumID hash.Hash, asOf uint64) ([]hash.Hash, uint64, error) {
	h.mu.RLock()
	cs := h.cs
	li := h.li
	att := h.att
	h.mu.RUnlock()
	if cs == nil || li == nil || att == nil {
		return nil, 0, fmt.Errorf("quorum handler not wired (SetupStore pending)")
	}

	quorumPath := QuorumPath(quorumID)
	entHash, ok := li.Get(quorumPath)
	if !ok {
		return nil, 0, fmt.Errorf("quorum_not_found: %s", quorumID)
	}
	ent, ok := cs.Get(entHash)
	if !ok || ent.Type != types.TypeQuorum {
		return nil, 0, fmt.Errorf("quorum_not_found: %s", quorumID)
	}
	q, err := types.QuorumDataFromEntity(ent)
	if err != nil {
		return nil, 0, fmt.Errorf("decode quorum: %w", err)
	}

	signers := q.Signers
	threshold := q.Threshold

	// Find the live quorum-update attestation head at asOf. quorum-update
	// attestations target the quorum_id (attesting=quorum_id, attested=
	// quorum_id) and carry kind="quorum-update" properties.
	updates := attestation.FindAttestationsTargeting(cs, att.Index(), quorumID, func(_ hash.Hash, a types.AttestationData) bool {
		return a.Kind() == types.KindQuorumUpdate
	})
	if len(updates) > 0 {
		// Find the live head of the supersedes chain at asOf. Multiple
		// top-level updates (no supersedes) → take any; FindLiveHead picks
		// the live head for each.
		var liveHead *attestation.AttestationRef
		for _, u := range updates {
			ref := u
			headHash, headData, ok := attestation.FindLiveHead(cs, li, att.Index(), ref.Hash, ref.Data, asOf)
			if !ok {
				continue
			}
			candidate := attestation.AttestationRef{Hash: headHash, Data: headData}
			if liveHead == nil || hashLess(candidate.Hash, liveHead.Hash) {
				liveHead = &candidate
			}
		}
		if liveHead != nil {
			var props types.QuorumUpdateProperties
			if err := types.DecodeProperties(liveHead.Data.Properties, &props); err == nil &&
				len(props.NewSigners) > 0 && props.NewThreshold > 0 {
				signers = props.NewSigners
				threshold = props.NewThreshold
			}
		}
	}

	// Resolution-mode dispatch.
	mode := q.SignerResolution
	if mode == "" || mode == types.SignerResolutionConcrete {
		// Concrete mode: signers are peer-identity hashes; nothing to resolve.
		return signers, threshold, nil
	}
	resolver, ok := h.resolvers.lookup(mode)
	if !ok {
		// Fail-closed per §5.3.1 cases C2/C3/C4.
		return nil, 0, &ResolverError{
			QuorumID:       quorumID,
			ModeName:       mode,
			AvailableModes: h.resolvers.availableModes(),
		}
	}
	resolved := make([]hash.Hash, len(signers))
	for i, s := range signers {
		r, err := resolver(ctx, s, cs, li, asOf)
		if err != nil {
			return nil, 0, fmt.Errorf("resolver %s failed for signer %s: %w", mode, s, err)
		}
		resolved[i] = r
	}
	return resolved, threshold, nil
}

// hashLess provides deterministic ordering for tie-break per §3.2 / §3.6
// (lowest content_hash). Identical to ext/attestation's hashLess; replicated
// here to avoid exporting a helper from the substrate package.
func hashLess(a, b hash.Hash) bool {
	ab := a.Bytes()
	bb := b.Bytes()
	for i := 0; i < len(ab) && i < len(bb); i++ {
		if ab[i] != bb[i] {
			return ab[i] < bb[i]
		}
	}
	return len(ab) < len(bb)
}
