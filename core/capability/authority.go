package capability

import (
	"fmt"

	"go.entitychurch.org/entity-core-go/core/crypto"
	"go.entitychurch.org/entity-core-go/core/entity"
	ecerrors "go.entitychurch.org/entity-core-go/core/errors"
	"go.entitychurch.org/entity-core-go/core/hash"
	"go.entitychurch.org/entity-core-go/core/types"
)

// EntityResolver looks up an entity by its content hash. Returns the entity
// and true on hit, zero value and false on miss.
type EntityResolver func(hash.Hash) (entity.Entity, bool)

// SignatureResolver looks up a signature entity by both target hash and
// signer identity hash. Used by CheckCreatorAuthority's multi-sig branch
// (M7) where multiple constituents sign the same target. Per
// PROPOSAL-MULTISIG-CORE-PRIMITIVE §4.0, signature scope is the envelope's
// `included` set only — signatures are wire artifacts, not persistent state.
type SignatureResolver func(target, signer hash.Hash) (entity.Entity, bool)

// IncludedResolver wraps a static included map as an EntityResolver. Useful
// when only the envelope's included set is in scope (e.g., dispatch chain
// validation that mirrors the wire-time resolution policy).
func IncludedResolver(included map[hash.Hash]entity.Entity) EntityResolver {
	return func(h hash.Hash) (entity.Entity, bool) {
		ent, ok := included[h]
		return ent, ok
	}
}

// IncludedSignatureResolver wraps an envelope's included map as a
// SignatureResolver, enumerating signature entities by (target, signer).
func IncludedSignatureResolver(included map[hash.Hash]entity.Entity) SignatureResolver {
	return func(target, signer hash.Hash) (entity.Entity, bool) {
		return findSignatureBySigner(target, signer, included)
	}
}

// CollectAuthorityChain walks a capability's authority chain from the given
// leaf to its root, returning the chain ordered leaf → root. This is the
// shared primitive backing R1 creator-authorization, dispatch-time chain
// validation, and revocation checks (PROPOSAL-UNIFIED-CHAIN-WALK-PRIMITIVE).
//
// The walk ALWAYS proceeds to root — there is no early return on any
// condition. Consumers filter, validate, or persist the returned chain
// without re-walking.
//
// Resolution policy is supplied by resolve. Different consumers prefer
// different sources (envelope-only, envelope-then-store, store-then-envelope);
// this primitive is policy-free.
//
// Errors:
//   - ecerrors.ErrChainUnreachable when a parent reference cannot be
//     resolved by the supplied resolver.
//   - ecerrors.ErrChainTooDeep when the chain exceeds maxChainDepth.
//
// Note that signatures, attenuation, and temporal validity are NOT checked
// by this primitive. Callers needing those run their own validation over
// the returned chain (see VerifyChain).
func CollectAuthorityChain(capEntity entity.Entity, resolve EntityResolver) ([]entity.Entity, error) {
	chain := make([]entity.Entity, 0, 4)
	current := capEntity
	depth := 0
	// v7.66 §5.3 cap-chain format-code freeze (Reading A): the chain's
	// format-code is the content_hash_format of its OWN links. All links
	// MUST share the same leading format-code byte; cross-format chain
	// extension is refused at the walker boundary. Today only 0x00 is
	// allocated so this is structurally a no-op, but the check enforces
	// that any future format transition cannot smuggle in mixed-format
	// chain links without an explicit signer-set re-signing event (which
	// is operator process — not protocol — and lives outside this walker).
	//
	// Signed targets (capData.Grantee, capData.Granter, capData.Parent's
	// own targets, signature.Signer/Target) MAY reference entities at a
	// different format-code than the chain; resolution of those uses §5.2
	// prefix-routing. The freeze applies only to the chain's own link
	// content_hashes, not to signed targets.
	chainFormatCode := capEntity.ContentHash.Algorithm
	for {
		if depth > maxChainDepth {
			return nil, fmt.Errorf("%w: depth exceeded %d", ecerrors.ErrChainTooDeep, maxChainDepth)
		}
		if current.ContentHash.Algorithm != chainFormatCode {
			return nil, fmt.Errorf("%w: v7.66 §5.3 cap-chain format-code freeze — link at depth %d has content_hash_format=0x%02x; chain's format-code is 0x%02x. Cross-format chain extension requires a continuous signer-set re-signing event",
				ecerrors.ErrCapabilityDenied, depth, current.ContentHash.Algorithm, chainFormatCode)
		}
		chain = append(chain, current)

		capData, err := types.CapabilityTokenDataFromEntity(current)
		if err != nil {
			return nil, fmt.Errorf("invalid capability data at depth %d: %w", depth, err)
		}

		if capData.Parent == nil {
			return chain, nil
		}

		parentEntity, ok := resolve(*capData.Parent)
		if !ok {
			return nil, ecerrors.ErrChainUnreachable
		}
		current = parentEntity
		depth++
	}
}

// CheckCreatorAuthority performs the R1 creator-authorization check: the
// writer's identity MUST appear as a granter somewhere in the embedded
// capability's authority chain.
//
// The full chain is collected via CollectAuthorityChain so chain
// reachability is enforced before identity matching. This makes the
// short-circuit class of bug structurally impossible.
//
// Per PROPOSAL-MULTISIG-CORE-PRIMITIVE §4.4 (M7), the chain-identity check
// uses the strict-with-signature rule:
//   - Single-sig granter: identity equals granter's identity hash.
//   - Multi-sig granter:  identity is in granter's signers AND has signed
//     the link (signature looked up via findSig).
//
// findSig MAY be nil for callers without envelope context; in that case
// multi-sig links never match and the function falls back to single-sig-only
// behavior. The signature resolution scope mirrors the proposal §4.0
// guidance — envelope `included` only.
//
// Returns:
//   - (true,  chain, nil)                 — writer authorized; chain available
//     for persistence by the caller
//   - (false, chain, nil)                 — chain valid but writer not in it;
//     caller surfaces 403 embedded_cap_unauthorized
//   - (false, nil,   ErrChainUnreachable) — chain incomplete; caller surfaces
//     404 chain_unreachable
//   - (false, nil,   ErrChainTooDeep)     — chain exceeds maxChainDepth
//
// Per the proposal: callers MUST NOT persist the collected chain when found
// is false — rejected requests do not contribute to local state.
//
// This is a creator-authorization check only — it does NOT verify
// attenuation or temporal validity. Multi-sig links DO verify the writer's
// signature here so the strict-with-signature rule is meaningful; full chain
// validation still requires VerifyChain.
func CheckCreatorAuthority(capEntity entity.Entity, identity hash.Hash, resolve EntityResolver, findSig SignatureResolver) (bool, []entity.Entity, error) {
	chain, err := CollectAuthorityChain(capEntity, resolve)
	if err != nil {
		return false, nil, err
	}

	for _, ent := range chain {
		capData, decodeErr := types.CapabilityTokenDataFromEntity(ent)
		if decodeErr != nil {
			return false, chain, fmt.Errorf("decode chain entry: %w", decodeErr)
		}
		// Within-cap precedence (PROPOSAL-MULTISIG-CORE-PRIMITIVE §3.3
		// amendment): M3 structural validity MUST be checked before
		// any signature verification on the same cap. A malformed cap can never
		// authorize, so its presence in the chain disqualifies the chain
		// regardless of whether the writer happened to also be a granter.
		if structErr := capData.ValidateStructure(); structErr != nil {
			return false, chain, fmt.Errorf("%w: %v", ecerrors.ErrCapabilityDenied, structErr)
		}
		if granterHash, single := capData.Granter.SingleHash(); single {
			if granterHash == identity {
				return true, chain, nil
			}
			continue
		}
		// Multi-sig: writer must be in signers AND have signed at this link.
		multi, _ := capData.Granter.Multi()
		if !multi.HasSigner(identity) {
			continue
		}
		if findSig == nil {
			continue
		}
		sigEntity, ok := findSig(ent.ContentHash, identity)
		if !ok {
			continue
		}
		sigData, sigErr := types.SignatureDataFromEntity(sigEntity)
		if sigErr != nil {
			continue
		}
		// Identity-entity lookup mirrors V7 line 1986–1988's dual-lookup
		// pattern (proposal §4.4): envelope-included first, then content store.
		writerIdentityEntity, found := resolve(identity)
		if !found {
			continue
		}
		writerIdentity, idErr := types.PeerDataFromEntity(writerIdentityEntity)
		if idErr != nil {
			continue
		}
		ktByte, ktOK := writerIdentity.KeyTypeByte()
		if !ktOK {
			continue
		}
		if crypto.Verify(ktByte, writerIdentity.PublicKey, ent.ContentHash.Bytes(), sigData.Signature) {
			return true, chain, nil
		}
	}
	return false, chain, nil
}
