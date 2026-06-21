package capability

import (
	"go.entitychurch.org/entity-core-go/core/crypto"
	"go.entitychurch.org/entity-core-go/core/entity"
	"go.entitychurch.org/entity-core-go/core/hash"
	"go.entitychurch.org/entity-core-go/core/store"
	"go.entitychurch.org/entity-core-go/core/types"
)

// StoreResolver wraps a content store as an EntityResolver for chain walks
// over locally-persisted entities (e.g. a continuation's dispatch_capability
// chain, persisted at install per §3.2 step 5).
func StoreResolver(cs store.ContentStore) EntityResolver {
	return func(h hash.Hash) (entity.Entity, bool) { return cs.Get(h) }
}

// CollectChainBundle gathers the full set of entities a remote verifier
// needs to validate leafCap's authority chain: every capability from the
// leaf up to its root, plus each link's granter identity entity and the
// granter's signature over that link (resolved from the V7 invariant
// pointer path /{signer_peer_id}/system/signature/{target_hex} that
// envelope ingest binds). This is the dispatch chain-walk + bundle helper
// of EXTENSION-CONTINUATION §4.3 / §8.2: the dispatching peer MUST place
// this whole set in the cross-peer EXECUTE envelope's `included` (the
// general V7 §3.1/§3.2 rule only carries the leaf cap, which is
// referenced from EXECUTE data; the transitive chain is referenced from
// *within* the cap entities and must be bundled explicitly).
//
// Over-inclusion is intentional and free: content-addressing dedups any
// entity the verifier already holds, eliminating the "verifier GC'd a
// parent → VerifyChain fails" failure mode at zero correctness cost
// (§4.2 "Chain transport"). Best-effort per link — a link whose signature
// or identity is not locally resolvable is simply omitted; the verifier
// fails closed if it actually needed it.
func CollectChainBundle(
	leafCap entity.Entity,
	cs store.ContentStore,
	li store.LocationIndex,
) (map[hash.Hash]entity.Entity, error) {
	chain, err := CollectAuthorityChain(leafCap, StoreResolver(cs))
	if err != nil {
		return nil, err
	}
	bundle := make(map[hash.Hash]entity.Entity, len(chain)*3)
	for _, capEnt := range chain {
		bundle[capEnt.ContentHash] = capEnt

		capData, derr := types.CapabilityTokenDataFromEntity(capEnt)
		if derr != nil {
			continue
		}
		// Resolve the granter identities for this link. Single-sig: one;
		// multi-sig: every constituent signer.
		var signers []hash.Hash
		if g, single := capData.Granter.SingleHash(); single {
			signers = append(signers, g)
		} else if m, multi := capData.Granter.Multi(); multi {
			signers = append(signers, m.Signers...)
		}
		for _, signer := range signers {
			if idEnt, ok := cs.Get(signer); ok && idEnt.Type == types.TypePeer {
				bundle[idEnt.ContentHash] = idEnt
				if sigEnt, ok := findBoundSignature(cs, li, capEnt.ContentHash, idEnt); ok {
					bundle[sigEnt.ContentHash] = sigEnt
				}
			}
		}
	}
	return bundle, nil
}

// findBoundSignature resolves the signature entity bound at the V7
// invariant pointer path for (target, signerIdentity), mirroring
// envelope_ingest's bind path so the bundle matches what the verifier's
// SignatureResolver expects.
func findBoundSignature(
	cs store.ContentStore,
	li store.LocationIndex,
	target hash.Hash,
	signerIdentity entity.Entity,
) (entity.Entity, bool) {
	idData, err := types.PeerDataFromEntity(signerIdentity)
	if err != nil {
		return entity.Entity{}, false
	}
	// v7.65 §1.5/§3.5: peer_id derives from (public_key, key_type) — canonical
	// form for Ed25519 is identity-multihash, for Ed448 SHA-256-form.
	ktByte, ktOK := idData.KeyTypeByte()
	if !ktOK {
		return entity.Entity{}, false
	}
	pid, err := crypto.PeerIDFromPublicKey(idData.PublicKey, ktByte)
	if err != nil {
		return entity.Entity{}, false
	}
	path := types.InvariantSignaturePath(string(pid), target)
	sigHash, ok := li.Get(path)
	if !ok {
		return entity.Entity{}, false
	}
	sigEnt, ok := cs.Get(sigHash)
	if !ok || sigEnt.Type != types.TypeSignature {
		return entity.Entity{}, false
	}
	return sigEnt, true
}
