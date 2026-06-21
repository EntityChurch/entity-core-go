package protocol

import (
	"fmt"

	"go.entitychurch.org/entity-core-go/core/crypto"
	"go.entitychurch.org/entity-core-go/core/entity"
	"go.entitychurch.org/entity-core-go/core/hash"
	"go.entitychurch.org/entity-core-go/core/store"
	"go.entitychurch.org/entity-core-go/core/types"
)

// ingestEnvelopeSignatures persists `system/signature` entities from an
// envelope's `included` map into the content store and binds them at
// their V7 invariant pointer paths per ENTITY-CORE-PROTOCOL-V7 v7.37
// §6.5 (dispatcher-level envelope.included signature ingestion;
// formerly EXTENSION-IDENTITY §6.2 SI-11, moved to V7 by Amendment 1
// of PROPOSAL-IDENTITY-V3.2-MIGRATION-FIXES.md / SPEC-25). Run before
// handler dispatch; required so identity / quorum / substrate
// validators can find signatures via `find_signature_by_signer`
// regardless of whether they arrived via cross-peer sync or
// `envelope.included`. The scope is universal — kernel ops
// (`tree:put`), substrate ops (attestation:verify, quorum:verify),
// identity ops, and any extension's handler ops all see ingested
// signatures already bound at their V7 paths.
//
// Mechanism:
//
//  1. Persist any `system/peer` entities referenced from signature
//     entities (so the signer's peer_id is recoverable).
//  2. Persist each `system/signature` entity.
//  3. Bind at /{signer_peer_id}/system/signature/{target_hash_hex}.
//
// Conflict policy (V7 §6.5): the V7 invariant pointer path is content-
// addressed by target_hash; identical signature entities at the same path
// produce no-ops. A different-hash collision indicates either a malformed
// envelope or storage corruption — returns "signature_path_conflict"
// error so the caller can reject the envelope.
//
// Returns nil on success or a wrapped error describing the first conflict
// or persist failure.
//
// Exported so non-dispatch envelope-handling paths (e.g. the connect
// handshake completion in `core/peer/connection.go::PerformConnect`)
// can invoke the same ingest behavior. Without this the connect
// handshake's AUTHENTICATE_RESPONSE envelope sigs (cap signature +
// granter identity sigs) never land in the local store, so any
// subsequent local code that needs to chain-walk the conferred cap
// (e.g. re-attenuation via `core/capability.MintReattenuated`) hits
// `chain_unreachable` immediately. The dispatch path used to be the
// only ingest call site; making it shared closes that gap.
func IngestEnvelopeSignatures(
	cs store.ContentStore,
	li store.LocationIndex,
	included map[hash.Hash]entity.Entity,
) error {
	if len(included) == 0 {
		return nil
	}
	// First pass: persist identity entities (signers may reference these).
	// Skip Put when the identity is already in the store — cross-peer
	// subscription delivery re-ships the same handful of identities on
	// every envelope; redundant Put goes through a SELECT + INSERT-OR-
	// REPLACE round-trip on SQLite that's pure overhead (H-G3 §1).
	for _, ent := range included {
		if ent.Type != types.TypePeer {
			continue
		}
		if cs.Has(ent.ContentHash) {
			continue
		}
		if _, err := cs.Put(ent); err != nil {
			return fmt.Errorf("ingest identity %s: %w", ent.ContentHash, err)
		}
	}
	// Second pass: persist + bind signature entities.
	for _, ent := range included {
		if ent.Type != types.TypeSignature {
			continue
		}
		sigData, err := types.SignatureDataFromEntity(ent)
		if err != nil {
			// Malformed signature in included — skip; downstream validation
			// fails closed if the signature was needed.
			continue
		}
		if sigData.Signer.IsZero() || sigData.Target.IsZero() {
			continue
		}
		// Resolve the signer's peer_id via the system/peer entity.
		signerEnt, ok := cs.Get(sigData.Signer)
		if !ok {
			// Identity not in local store and not in included — cannot bind.
			// Validators that rely on this signature will fail-closed.
			continue
		}
		if signerEnt.Type != types.TypePeer {
			continue
		}
		idData, err := types.PeerDataFromEntity(signerEnt)
		if err != nil {
			continue
		}
		// Check the V7 invariant pointer path FIRST. If already bound to
		// this same content hash, the entire ingest is a no-op for this
		// signature — no Put, no Set, no cascade walk (H-G3 §2). The
		// path-level check both catches the conflict case and tells us
		// whether the signature has already been ingested at this slot.
		//
		// v7.65 §1.5: peer_id derives from (public_key, key_type) — canonical
		// form per crypto.CanonicalHashType.
		ktByte, ktOK := idData.KeyTypeByte()
		if !ktOK {
			continue
		}
		signerPID, err := crypto.PeerIDFromPublicKey(idData.PublicKey, ktByte)
		if err != nil {
			continue
		}
		path := types.InvariantSignaturePath(string(signerPID), sigData.Target)
		if existing, present := li.Get(path); present {
			if existing != ent.ContentHash {
				return fmt.Errorf("signature_path_conflict: %s already bound to %s, envelope offers %s",
					path, existing, ent.ContentHash)
			}
			// Identical hash — no-op (idempotent).
			continue
		}
		// Path is empty — persist the signature unless cs already holds
		// it (orphaned-but-stored case after restart or partial ingest).
		if !cs.Has(ent.ContentHash) {
			if _, err := cs.Put(ent); err != nil {
				return fmt.Errorf("ingest signature %s: %w", ent.ContentHash, err)
			}
		}
		if err := li.Set(path, ent.ContentHash); err != nil {
			// Per V7 §2688: transient I/O during entity_tree.put MUST
			// short-circuit envelope processing and return status 500.
			return fmt.Errorf("ingest signature bind %s: %w", path, err)
		}
	}
	return nil
}
