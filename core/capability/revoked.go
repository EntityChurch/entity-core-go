package capability

import (
	"encoding/hex"

	"go.entitychurch.org/entity-core-go/core/entity"
	"go.entitychurch.org/entity-core-go/core/hash"
	"go.entitychurch.org/entity-core-go/core/store"
	"go.entitychurch.org/entity-core-go/core/types"
)

// RevocationContext carries the resolvers is_revoked needs to walk the chain
// and look up bindings and markers per V7 v7.62 §5.1. It maps to the spec's
// context-field table:
//
//   - ContentStore: ctx.content_store — local content store.
//   - LocationIndex: ctx.entity_tree — local path → hash tree.
//   - Included: ctx.included — the EXECUTE/response envelope's `included`
//     map merged into the resolver, OR nil when no envelope context is
//     active (background validation jobs). Callers that have an envelope
//     MUST populate this so cross-peer chain walks succeed without round-
//     trip GETs.
//   - CapabilityIndex: ctx.capability_path_for(hash) — observational hash→
//     path index for cap bindings.
type RevocationContext struct {
	ContentStore     store.ContentStore
	LocationIndex    store.LocationIndex
	Included         map[hash.Hash]entity.Entity
	CapabilityIndex  CapabilityIndex
}

// IsRevoked implements V7 v7.62 §5.1 `is_revoked(capability, ctx)`.
//
// Algorithm:
//  1. Walk the delegation chain to the root cap. Any parent that cannot be
//     resolved → revoked (fail-closed). Cycle → revoked.
//  2. If capability_path_for(root) returns a path: read that path from the
//     entity tree; revoked iff missing OR bound entity != root (binding
//     check; defense-in-depth for path-bound caps).
//  3. Always: read system/capability/revocations/{root_hash_hex}. Revoked
//     iff a marker is present (covers wire-only caps; defense-in-depth
//     for path-bound caps).
//
// The previous "unknown root policy" branch is gone (v7.62) — a cap with no
// stored root path is no longer ambiguous; it's revoked iff a marker exists.
func IsRevoked(capEntity entity.Entity, rctx RevocationContext) bool {
	// Step 1: walk to root via the chain resolver (envelope + store).
	current := capEntity
	visited := make(map[hash.Hash]struct{}, 4)
	for {
		capData, err := types.CapabilityTokenDataFromEntity(current)
		if err != nil {
			return true
		}
		if capData.Parent == nil {
			break
		}
		if _, seen := visited[current.ContentHash]; seen {
			return true
		}
		visited[current.ContentHash] = struct{}{}
		parent, ok := resolveCapAncestor(*capData.Parent, rctx)
		if !ok {
			return true
		}
		current = parent
	}

	// Step 2: binding check via capability_path_for + entity_tree.
	if rctx.LocationIndex != nil && rctx.CapabilityIndex != nil {
		if path, ok := rctx.CapabilityIndex.PathFor(current.ContentHash); ok {
			stored, present := rctx.LocationIndex.Get(path)
			if !present {
				return true // root deleted from tree = revoked
			}
			if stored != current.ContentHash {
				return true // bound entity differs from expected root
			}
		}
		// path not recorded → wire-only cap. Fall through to marker check.
	}

	// Step 3: explicit revocation marker check.
	// Marker lives at system/capability/revocations/{root_hash_hex} where
	// the hex encodes the full 33-byte wire form (algorithm byte + digest).
	if rctx.LocationIndex != nil {
		markerPath := RevocationsRoot + "/" + hex.EncodeToString(current.ContentHash.Bytes())
		if _, ok := rctx.LocationIndex.Get(markerPath); ok {
			return true
		}
	}
	return false
}

// resolveCapAncestor looks up a parent capability by hash. Tries the local
// content store first, then the envelope's `included` map (the spec is
// store-then-included; the included map carries cross-peer chain links the
// receiver hasn't otherwise persisted).
func resolveCapAncestor(h hash.Hash, rctx RevocationContext) (entity.Entity, bool) {
	if rctx.ContentStore != nil {
		if ent, ok := rctx.ContentStore.Get(h); ok {
			return ent, true
		}
	}
	if rctx.Included != nil {
		if ent, ok := rctx.Included[h]; ok {
			return ent, true
		}
	}
	return entity.Entity{}, false
}
