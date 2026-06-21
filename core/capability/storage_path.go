package capability

import (
	"encoding/hex"

	"go.entitychurch.org/entity-core-go/core/entity"
	"go.entitychurch.org/entity-core-go/core/hash"
	"go.entitychurch.org/entity-core-go/core/types"
)

// Capability storage path conventions per V7 §5.1 + V7 §6.8 + role-spec
// alignment (PROPOSAL-MULTISIG-CORE-PRIMITIVE M12).
const (
	// CapabilityGrantsRoot is the tree prefix under which capability grants
	// are bound. Subcategories follow as `{root}/{category}/...`.
	CapabilityGrantsRoot = "system/capability/grants"

	// MultiSigRootGrantsPrefix is the storage prefix for multi-sig root caps,
	// per PROPOSAL-MULTISIG-CORE-PRIMITIVE M12. Caps live at
	// `system/capability/grants/multi-sig-root/{cap_hash}`.
	MultiSigRootGrantsPrefix = CapabilityGrantsRoot + "/multi-sig-root"

	// RevocationsRoot is the tree prefix under which capability revocation
	// markers are bound, per V7 §6.2:2544 ("revoke MAY write to a revocation
	// list at system/capability/revocations/*"). Pinned in entity-core-go
	// at `system/capability/revocations/{cap_hash}` per the resolved
	// capability-handler ambiguities — cross-impl convergence requires a
	// normative path; V7 leaves it "implementation-specific" today.
	RevocationsRoot = "system/capability/revocations"
)

// RevocationPathFor returns the canonical storage path for a revocation
// marker targeting the capability with the given content hash. Format:
// `system/capability/revocations/{algorithm-and-digest-hex}`, where the
// hex encodes the full 33-byte wire form (algorithm byte + digest) per
// V7 §3.5 invariant-pointer convention — same encoding as PathFor for
// multi-sig roots.
func RevocationPathFor(capHash hash.Hash) string {
	return RevocationsRoot + "/" + hex.EncodeToString(capHash.Bytes())
}

// CapabilityPathFor implements V7 v7.62 §5.1 `capability_path_for(hash)`:
// resolves a capability's content hash to its canonical storage path via the
// observational reverse index. Returns ("", false) for wire-only caps (no
// recorded binding) — the is_revoked algorithm then falls through to the
// marker check at system/capability/revocations/{root_hash_hex}.
//
// Per V7 v7.62 §5.1, the signature is (hash) → (path, bool). The index is
// scheme-agnostic by construction: the verifier need not know the
// extension's path scheme because it recorded where it bound things.
//
// Multi-sig roots are also covered by the index — they get recorded at
// their MultiSigRootGrantsPrefix path at bind time like every other cap.
// (The legacy PathFor entry-derived path remains as a fallback for
// callsites that have the entity in hand but not the index.)
func CapabilityPathFor(index CapabilityIndex, capHash hash.Hash) (string, bool) {
	if index == nil {
		return "", false
	}
	return index.PathFor(capHash)
}

// PathFor returns the canonical tree path where the given capability entity
// should be bound, per PROPOSAL-MULTISIG-CORE-PRIMITIVE M12.
//
// For single-sig caps no protocol-level path is mandated; callers that have
// a context-specific path (handler self-grants at
// `system/capability/grants/{pattern}`, role-derived tokens, etc.) bind
// where they choose. For multi-sig roots, the path is fixed at
// `system/capability/grants/multi-sig-root/{cap_hash}`.
//
// Returns ok=false when no protocol-mandated path applies (e.g., single-sig
// caps); the caller is responsible for choosing storage in that case.
func PathFor(capEntity entity.Entity) (string, bool, error) {
	tok, err := types.CapabilityTokenDataFromEntity(capEntity)
	if err != nil {
		return "", false, err
	}
	if tok.Granter.IsMulti() {
		// Path-segment hash uses lowercase hex of full system/hash bytes
		// (format byte + digest) per V7 §3.5 invariant pointer convention.
		// Earlier code used hash.Hash.String(), which returns the V7 §1.2
		// display form `ecf-sha256:<hex>` — that form is "UI only, never
		// on wire" per V7 §1.2 line 117. Fixed per
		// PROPOSAL-ROLE-V1.5-SPEC-FIXES SI-2 (same fix shape applies here).
		return MultiSigRootGrantsPrefix + "/" + hex.EncodeToString(capEntity.ContentHash.Bytes()), true, nil
	}
	return "", false, nil
}
