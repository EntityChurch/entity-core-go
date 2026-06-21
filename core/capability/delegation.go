package capability

import (
	"bytes"
	"errors"
	"fmt"
	"time"

	"go.entitychurch.org/entity-core-go/core/crypto"
	"go.entitychurch.org/entity-core-go/core/entity"
	ecerrors "go.entitychurch.org/entity-core-go/core/errors"
	"go.entitychurch.org/entity-core-go/core/hash"
	"go.entitychurch.org/entity-core-go/core/types"

	"github.com/fxamacker/cbor/v2"
)

const maxChainDepth = 64

// granterPeerIDFromIncluded returns the namespace owner peer_id for a
// cap's resource canonicalization in chain validation (the chain-validation
// analogue of ResolveGranterPeerID).
//
// Per §PR-8 each cap's resource patterns canonicalize against ITS OWN
// granter's namespace, not the chain root's. A re-attenuated leaf's
// granter is the peer that did the delegation, distinct from the root
// granter (typically the local peer). The earlier implementation returned
// localPeerID unconditionally — that admitted attenuation cases where a
// foreign-granter leaf's bare-wildcard pattern was treated as covering
// the local peer's namespace, which is wrong per PR-8 chain semantics
// (the v7.73 V2(a) substrate-FAIL across Go / Rust / Py).
//
// Resolution algorithm mirrors verifyRootGranter / peerIDFromPeerEntity:
// single-sig → look up granter entity in `included` → derive peer_id from
// (key_type, public_key) per v7.65 §1.5. Multi-sig falls back to
// localPeerID (M3 root-only invariant).
func granterPeerIDFromIncluded(granter types.Granter, included map[hash.Hash]entity.Entity, localPeerID crypto.PeerID) (crypto.PeerID, error) {
	if granter.IsMulti() {
		return localPeerID, nil
	}
	granterHash, _ := granter.SingleHash()
	if granterHash.IsZero() {
		// See ResolveGranterPeerID for the zero-granter rationale.
		return localPeerID, nil
	}
	granterEnt, ok := included[granterHash]
	if !ok {
		return "", fmt.Errorf("granter identity %s not in envelope.included", granterHash)
	}
	return peerIDFromPeerEntity(granterEnt)
}

// VerifyChain validates a capability token's delegation chain end-to-end:
// signatures, temporal validity, grantee→granter linkage, attenuation,
// delegation caveats, and that the root cap's granter is the local peer.
//
// Per PROPOSAL-UNIFIED-CHAIN-WALK-PRIMITIVE §3.1, this delegates the chain
// walk to CollectAuthorityChain and validates each level over the returned
// chain. ChainUnreachable / ChainTooDeep errors take precedence over
// per-level validation errors when both apply (the walker errors before
// validation runs). Both fail closed; the difference is which error code
// fires for compound-failure cases.
func VerifyChain(capEntity entity.Entity, included map[hash.Hash]entity.Entity, localPeerID crypto.PeerID) error {
	chain, err := CollectAuthorityChain(capEntity, IncludedResolver(included))
	if err != nil {
		// V7 §4.10(b) (v7.75 §9.1 floor MUST): a chain that exceeds the impl's
		// max depth is a client-correctable structural excess, not an
		// authz verdict — preserve ErrChainTooDeep so execute.go can map
		// it to (400, chain_depth_exceeded) instead of collapsing it into
		// the (403, capability_denied) default. Keystone analysis caught
		// the 403/400 conflation: 403 would conflate "too deep" with
		// "you lack the capability", which a caller cannot distinguish.
		if errors.Is(err, ecerrors.ErrChainTooDeep) {
			return err
		}
		return fmt.Errorf("%w: %v", ecerrors.ErrCapabilityDenied, err)
	}

	// Per-level validation: signature, temporal, and (for non-root levels)
	// grantee→granter linkage + attenuation + delegation caveats.
	for i, current := range chain {
		capData, err := types.CapabilityTokenDataFromEntity(current)
		if err != nil {
			return fmt.Errorf("%w: invalid capability data: %v", ecerrors.ErrCapabilityDenied, err)
		}

		// M3 content validation MUST run at chain-walk entry per
		// PROPOSAL-MULTISIG-CORE-PRIMITIVE §3.3. Use double-%w so
		// callers can match either ErrCapabilityDenied (general
		// chain-rejection class) OR the specific structural-error
		// class returned by ValidateStructure (e.g.,
		// ErrUnresolvableGrantee for SEC-18 zero-grantee rejection).
		if err := capData.ValidateStructure(); err != nil {
			return fmt.Errorf("%w: %w", ecerrors.ErrCapabilityDenied, err)
		}

		// Per-link temporal validity (F3 / V7 §5.5). Every link in the chain
		// MUST be within its validity window — not just the leaf. The leaf-only
		// temporal check in FindMatchingGrant/CheckPathPermission left an
		// expired or not-yet-valid INTERMEDIATE cap unvalidated: a stale
		// delegated authority would still verify, a §5.10 verdict divergence
		// (Python checks every link; Go/Rust did not). Checked here so it
		// applies to root, intermediate, and leaf uniformly.
		now := uint64(time.Now().UnixMilli())
		if capData.NotBefore != nil && now < *capData.NotBefore {
			return fmt.Errorf("%w: cap %s is not yet valid (not_before)", ecerrors.ErrCapabilityDenied, current.ContentHash)
		}
		if capData.ExpiresAt != nil && *capData.ExpiresAt < now {
			return fmt.Errorf("%w: cap %s has expired (expires_at)", ecerrors.ErrCapabilityDenied, current.ContentHash)
		}

		// Site 1: per-link signature verification (V7 §5.5; M4).
		if err := verifyLinkSignatures(current, capData, included); err != nil {
			return err
		}

		// V7 v7.39 §3.6 + §5.5 (PROPOSAL-ROLE-V2.0 PR-3): grantee
		// resolution. The cap's `grantee` MUST resolve to a present
		// `system/peer` entity in either the local content store
		// or the wire envelope's `included` map. Per-link, not just at
		// the leaf — every cap in the chain has its own grantee, and
		// each MUST resolve. Closes the bearer-cap surface area:
		// without this check, a cap with `grantee = zero-hash` (or any
		// other unresolvable hash) would be honored as if any holder
		// could wield it. Self-caps (grantee == granter) pass naturally
		// because the granter's identity was already required for
		// signature verification above.
		if granteeEnt, ok := included[capData.Grantee]; !ok || granteeEnt.Type != crypto.TypePeer {
			return fmt.Errorf("%w: cap %s grantee %s does not resolve to a system/peer entity",
				ecerrors.ErrUnresolvableGrantee, current.ContentHash, capData.Grantee)
		}

		// Site 3: root granter identity check (V7 §5.5; M6).
		if i == len(chain)-1 {
			if err := verifyRootGranter(current, capData, included, localPeerID); err != nil {
				return err
			}
			continue
		}

		// Non-root: verify linkage and attenuation against the parent.
		// By M3, multi-sig caps cannot reach this branch — they're roots.
		parentEntity := chain[i+1]
		parentData, err := types.CapabilityTokenDataFromEntity(parentEntity)
		if err != nil {
			return fmt.Errorf("%w: invalid parent capability: %v", ecerrors.ErrCapabilityDenied, err)
		}
		// Site 2: chain linkage (V7 §5.5; M5 — code unchanged in form).
		// Defensive: if M3 was bypassed somehow, single-sig extraction below
		// fails closed.
		currentGranterHash, single := capData.Granter.SingleHash()
		if !single {
			return fmt.Errorf("%w: non-root capability has multi-sig granter (M3 violated)", ecerrors.ErrCapabilityDenied)
		}
		if parentData.Grantee != currentGranterHash {
			return fmt.Errorf("%w: parent grantee != current granter", ecerrors.ErrCapabilityDenied)
		}
		// Per §PR-8: each cap's resource patterns canonicalize against ITS
		// OWN granter's namespace. For attenuation (child ⊆ parent), resolve
		// each cap's granter peer_id and use them when comparing patterns.
		childGranterPeerID, err := granterPeerIDFromIncluded(capData.Granter, included, localPeerID)
		if err != nil {
			return fmt.Errorf("%w: child granter unresolvable: %v", ecerrors.ErrCapabilityDenied, err)
		}
		parentGranterPeerID, err := granterPeerIDFromIncluded(parentData.Granter, included, localPeerID)
		if err != nil {
			return fmt.Errorf("%w: parent granter unresolvable: %v", ecerrors.ErrCapabilityDenied, err)
		}
		if !IsAttenuated(capData, parentData, childGranterPeerID, parentGranterPeerID) {
			return fmt.Errorf("%w: capability not properly attenuated", ecerrors.ErrCapabilityDenied)
		}
		if err := checkDelegationCaveats(parentData, capData, i); err != nil {
			return err
		}
	}
	return nil
}

// verifyLinkSignatures runs Site 1: per-link signature verification (M4).
// For single-sig granters it finds the one signature and verifies it. For
// multi-sig granters it runs the K-of-N inner loop with deduplication and
// short-circuits at threshold.
func verifyLinkSignatures(current entity.Entity, capData types.CapabilityTokenData, included map[hash.Hash]entity.Entity) error {
	if granterHash, single := capData.Granter.SingleHash(); single {
		sigEntity, ok := findSignatureForTarget(current.ContentHash, included)
		if !ok {
			return fmt.Errorf("%w: no signature found for capability %s", ecerrors.ErrCapabilityDenied, current.ContentHash)
		}
		sigData, err := types.SignatureDataFromEntity(sigEntity)
		if err != nil {
			return fmt.Errorf("%w: invalid signature data: %v", ecerrors.ErrCapabilityDenied, err)
		}
		if sigData.Signer != granterHash {
			return fmt.Errorf("%w: signer %s != granter %s", ecerrors.ErrCapabilityDenied, sigData.Signer, granterHash)
		}
		granterEntity, ok := included[granterHash]
		if !ok {
			return fmt.Errorf("%w: granter identity not found", ecerrors.ErrCapabilityDenied)
		}
		granterData, err := types.PeerDataFromEntity(granterEntity)
		if err != nil {
			return fmt.Errorf("%w: invalid granter identity: %v", ecerrors.ErrCapabilityDenied, err)
		}
		ktByte, ktOK := granterData.KeyTypeByte()
		if !ktOK {
			return fmt.Errorf("%w: granter key_type %q not supported", ecerrors.ErrAuthenticationFailed, granterData.KeyType)
		}
		if !crypto.Verify(ktByte, granterData.PublicKey, current.ContentHash.Bytes(), sigData.Signature) {
			return fmt.Errorf("%w: signature verification failed", ecerrors.ErrAuthenticationFailed)
		}
		return nil
	}

	// Multi-sig path (M4).
	multi, _ := capData.Granter.Multi()
	// Defensive bound checks (already enforced by M3 at chain-walk entry).
	if len(multi.Signers) < 2 || multi.Threshold < 2 || multi.Threshold > uint64(len(multi.Signers)) {
		return fmt.Errorf("%w: malformed multi-granter", ecerrors.ErrCapabilityDenied)
	}
	seen := make(map[hash.Hash]struct{}, len(multi.Signers))
	var valid uint64
	for _, candidate := range multi.Signers {
		if _, dup := seen[candidate]; dup {
			continue
		}
		seen[candidate] = struct{}{}
		candidateIdentity, ok := included[candidate]
		if !ok {
			continue
		}
		idData, err := types.PeerDataFromEntity(candidateIdentity)
		if err != nil {
			continue
		}
		sigEntity, ok := findSignatureBySigner(current.ContentHash, candidate, included)
		if !ok {
			continue
		}
		sigData, err := types.SignatureDataFromEntity(sigEntity)
		if err != nil {
			continue
		}
		ktByte, ktOK := idData.KeyTypeByte()
		if !ktOK {
			continue
		}
		if !crypto.Verify(ktByte, idData.PublicKey, current.ContentHash.Bytes(), sigData.Signature) {
			continue
		}
		valid++
		if valid >= multi.Threshold {
			return nil
		}
	}
	return fmt.Errorf("%w: multi-sig threshold not met (got %d, need %d)", ecerrors.ErrCapabilityDenied, valid, multi.Threshold)
}

// verifyRootGranter runs Site 3: root granter identity check (M6).
// Single-sig: root granter peer_id must equal local peer. Multi-sig: local
// peer must be in signers AND must have signed.
func verifyRootGranter(root entity.Entity, capData types.CapabilityTokenData, included map[hash.Hash]entity.Entity, localPeerID crypto.PeerID) error {
	if granterHash, single := capData.Granter.SingleHash(); single {
		granterEntity, ok := included[granterHash]
		if !ok {
			return fmt.Errorf("%w: root granter identity not found", ecerrors.ErrCapabilityDenied)
		}
		granterData, err := types.PeerDataFromEntity(granterEntity)
		if err != nil {
			return fmt.Errorf("%w: invalid root granter identity: %v", ecerrors.ErrCapabilityDenied, err)
		}
		// v7.65 §1.5: derive peer_id from public_key (canonical form).
		// Previously read granterData.PeerID; v7.65 drops peer_id from data.
		ktByte, ktOK := granterData.KeyTypeByte()
		if !ktOK {
			return fmt.Errorf("%w: granter key_type %q not supported", ecerrors.ErrCapabilityDenied, granterData.KeyType)
		}
		granterPID, err := crypto.PeerIDFromPublicKey(granterData.PublicKey, ktByte)
		if err != nil {
			return fmt.Errorf("%w: derive granter peer_id: %v", ecerrors.ErrCapabilityDenied, err)
		}
		if string(granterPID) != string(localPeerID) {
			return fmt.Errorf("%w: root capability granter is not local peer", ecerrors.ErrCapabilityDenied)
		}
		return nil
	}

	// Multi-sig root: local peer must be in signers AND have signed.
	// Site 3 runs before Site 1 in V7 §5.5 ordering; this branch does its
	// own signature verification rather than depending on Site 1's loop.
	multi, _ := capData.Granter.Multi()
	for _, candidate := range multi.Signers {
		candidateIdentity, ok := included[candidate]
		if !ok {
			continue
		}
		idData, err := types.PeerDataFromEntity(candidateIdentity)
		if err != nil {
			continue
		}
		// v7.65 §1.5: derive peer_id from public_key.
		ktByte, ktOK := idData.KeyTypeByte()
		if !ktOK {
			continue
		}
		candPID, err := crypto.PeerIDFromPublicKey(idData.PublicKey, ktByte)
		if err != nil {
			continue
		}
		if string(candPID) != string(localPeerID) {
			continue
		}
		// This candidate is the local peer. Confirm they actually signed.
		sigEntity, ok := findSignatureBySigner(root.ContentHash, candidate, included)
		if !ok {
			continue
		}
		sigData, err := types.SignatureDataFromEntity(sigEntity)
		if err != nil {
			continue
		}
		if crypto.Verify(ktByte, idData.PublicKey, root.ContentHash.Bytes(), sigData.Signature) {
			return nil
		}
	}
	return fmt.Errorf("%w: multi-sig root requires local peer in signers AND signed", ecerrors.ErrCapabilityDenied)
}

// IsAttenuated checks that child's grants are a subset of parent's grants.
// Each cap's resource patterns canonicalize against ITS OWN granter's
// namespace per §PR-8 (V7 §5.5); pass the resolved granter peer_id for
// each cap.
func IsAttenuated(child, parent types.CapabilityTokenData, childGranterPeerID, parentGranterPeerID crypto.PeerID) bool {
	// Every child grant must be covered by some parent grant.
	for _, childGrant := range child.Grants {
		covered := false
		for _, parentGrant := range parent.Grants {
			if grantCovers(parentGrant, childGrant, parentGranterPeerID, childGranterPeerID) {
				covered = true
				break
			}
		}
		if !covered {
			return false
		}
	}

	// Child expiration must not exceed parent's.
	if parent.ExpiresAt != nil {
		if child.ExpiresAt == nil {
			return false
		}
		if *child.ExpiresAt > *parent.ExpiresAt {
			return false
		}
	}

	return true
}

// grantCovers checks if a parent grant covers a child grant. Resource
// pattern canonicalization uses the granter peer_id of each respective cap
// per §PR-8.
func grantCovers(parent, child types.GrantEntry, parentGranterPeerID, childGranterPeerID crypto.PeerID) bool {
	// All child handlers must be covered by some parent handler pattern.
	for _, childHandler := range child.Handlers.Include {
		matched := false
		for _, parentHandler := range parent.Handlers.Include {
			if MatchesPattern(childHandler, parentHandler) {
				matched = true
				break
			}
		}
		if !matched {
			return false
		}
	}

	// All child operations must be covered by some parent operation
	// pattern. V7 §3.6 line 836 + §5.4 line 1868 + §5.6 scope_subset
	// require matches_pattern for ALL grant dimensions including
	// operations — `{include: ["*"]}` matches any operation. Earlier
	// drafts of this code used literal set membership (containsString),
	// which silently rejected wildcard parent caps; fixed per
	// PROPOSAL-ROLE-V1.5-SPEC-FIXES SI-24.
	for _, childOp := range child.Operations.Include {
		matched := false
		for _, parentOp := range parent.Operations.Include {
			if MatchesPattern(childOp, parentOp) {
				matched = true
				break
			}
		}
		if !matched {
			return false
		}
	}

	// All child resources must match some parent resource. Each side
	// canonicalizes against its own granter's namespace per §PR-8.
	for _, childRes := range child.Resources.Include {
		canonChild := Canonicalize(childRes, childGranterPeerID)
		matched := false
		for _, parentRes := range parent.Resources.Include {
			canonParent := Canonicalize(parentRes, parentGranterPeerID)
			if MatchesPattern(canonChild, canonParent) {
				matched = true
				break
			}
		}
		if !matched {
			return false
		}
	}

	// Parent-exclude inheritance (F4 / V7 §5.6 scope_subset). A child grant
	// MUST inherit every exclude the parent carries, on each dimension. Without
	// this, a delegating peer could split a grant to DROP an exclude the parent
	// imposed — re-granting access to a region the parent explicitly denied
	// (the exact attenuation bypass §5.6 calls out, and a §5.10 verdict
	// divergence: Rust/Python enforce it, Go did not). Handlers/operations are
	// matched literally; resources canonicalize against each cap's own granter
	// namespace (PR-8).
	identity := func(s string) string { return s }
	canonChild := func(s string) string { return Canonicalize(s, childGranterPeerID) }
	canonParent := func(s string) string { return Canonicalize(s, parentGranterPeerID) }
	if !excludesInherited(parent.Handlers.Exclude, child.Handlers.Exclude, identity, identity) {
		return false
	}
	if !excludesInherited(parent.Operations.Exclude, child.Operations.Exclude, identity, identity) {
		return false
	}
	if !excludesInherited(parent.Resources.Exclude, child.Resources.Exclude, canonParent, canonChild) {
		return false
	}

	// Constraint attenuation (G3): child must retain all parent constraint
	// keys with byte-identical values. Child MAY add new constraint keys
	// (safe — adds restriction).
	if !checkMapAttenuation(parent.Constraints, child.Constraints, true) {
		return false
	}

	// Allowance attenuation (G3): child must not add keys the parent doesn't
	// have. Existing keys must be byte-identical. Child MAY remove allowance
	// keys (safe — removes privilege).
	if !checkMapAttenuation(parent.Allowances, child.Allowances, false) {
		return false
	}

	return true
}

// excludesInherited reports whether the child's exclude patterns cover every
// one of the parent's exclude patterns (F4 / V7 §5.6). For each parent exclude
// Pe, some child exclude Ce must deny at least everything Pe does — i.e. Pe (as
// a representative path) MUST match Ce (as a pattern). A broader child exclude
// (Ce="a/*") covers a narrower parent exclude (Pe="a/secret"); a narrower child
// exclude does not cover a broader parent one (the child would re-open paths
// the parent denied), so that case is correctly rejected. canonParent/canonChild
// canonicalize each side's patterns against its own granter namespace (PR-8);
// pass the identity function for non-path dimensions (handlers, operations).
func excludesInherited(parentExcludes, childExcludes []string, canonParent, canonChild func(string) string) bool {
	for _, pe := range parentExcludes {
		cpe := canonParent(pe)
		covered := false
		for _, ce := range childExcludes {
			if MatchesPattern(cpe, canonChild(ce)) {
				covered = true
				break
			}
		}
		if !covered {
			return false
		}
	}
	return true
}

// checkMapAttenuation checks key-level and byte-equality attenuation for
// constraints or allowances CBOR maps.
//
// For constraints (isConstraint=true): child must retain all parent keys.
//   - Parent has key, child doesn't → escalation (key dropped)
//   - Child has key parent doesn't → OK (key added = narrows)
//
// For allowances (isConstraint=false): child must not add keys.
//   - Child has key, parent doesn't → escalation (key added)
//   - Parent has key, child doesn't → OK (key removed = narrows)
//
// For all shared keys: values must be byte-identical.
func checkMapAttenuation(parentRaw, childRaw cbor.RawMessage, isConstraint bool) bool {
	parentMap := decodeCBORMap(parentRaw)
	childMap := decodeCBORMap(childRaw)

	if isConstraint {
		// Constraint: every parent key must exist in child with same value.
		for key, parentVal := range parentMap {
			childVal, ok := childMap[key]
			if !ok {
				return false // Key dropped — escalation.
			}
			if !bytes.Equal(parentVal, childVal) {
				return false // Value changed — deny by default.
			}
		}
	} else {
		// Allowance: every child key must exist in parent with same value.
		for key, childVal := range childMap {
			parentVal, ok := parentMap[key]
			if !ok {
				return false // Key added — escalation.
			}
			if !bytes.Equal(parentVal, childVal) {
				return false // Value changed — deny by default.
			}
		}
	}
	return true
}

// decodeCBORMap decodes a CBOR-encoded map into string→raw-value pairs.
// Returns empty map for nil, empty, or non-map inputs.
func decodeCBORMap(raw cbor.RawMessage) map[string]cbor.RawMessage {
	if len(raw) == 0 {
		return nil
	}
	var m map[string]cbor.RawMessage
	if err := cbor.Unmarshal(raw, &m); err != nil {
		return nil
	}
	return m
}

func checkDelegationCaveats(parent types.CapabilityTokenData, child types.CapabilityTokenData, depth int) error {
	if parent.DelegationCaveats == nil {
		return nil
	}
	caveats := parent.DelegationCaveats

	if caveats.NoDelegation != nil && *caveats.NoDelegation {
		return fmt.Errorf("%w: delegation not allowed", ecerrors.ErrCapabilityDenied)
	}

	if caveats.MaxDelegationDepth != nil {
		if uint64(depth) >= *caveats.MaxDelegationDepth {
			return fmt.Errorf("%w: max delegation depth exceeded", ecerrors.ErrCapabilityDenied)
		}
	}

	if caveats.MaxDelegationTTL != nil && child.ExpiresAt != nil {
		ttl := *child.ExpiresAt - child.CreatedAt
		if ttl > *caveats.MaxDelegationTTL {
			return fmt.Errorf("%w: delegation TTL exceeded", ecerrors.ErrCapabilityDenied)
		}
	}

	return nil
}

// findSignatureForTarget looks for a signature entity that targets the given hash.
func findSignatureForTarget(target hash.Hash, included map[hash.Hash]entity.Entity) (entity.Entity, bool) {
	for _, ent := range included {
		if ent.Type != types.TypeSignature {
			continue
		}
		sigData, err := types.SignatureDataFromEntity(ent)
		if err != nil {
			continue
		}
		if sigData.Target == target {
			return ent, true
		}
	}
	return entity.Entity{}, false
}

// findSignatureBySigner looks for a signature entity that targets the given
// hash AND was produced by the given signer identity. Used on the multi-sig
// path where multiple constituents sign the same target — see
// PROPOSAL-MULTISIG-CORE-PRIMITIVE §4.0.
func findSignatureBySigner(target hash.Hash, signer hash.Hash, included map[hash.Hash]entity.Entity) (entity.Entity, bool) {
	for _, ent := range included {
		if ent.Type != types.TypeSignature {
			continue
		}
		sigData, err := types.SignatureDataFromEntity(ent)
		if err != nil {
			continue
		}
		if sigData.Target == target && sigData.Signer == signer {
			return ent, true
		}
	}
	return entity.Entity{}, false
}
