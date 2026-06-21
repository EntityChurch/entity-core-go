// Package storagesubstitutesources hosts the §2 storage-substitute sources
// validator orchestrator + the §2.4 signature-trust verifier closure.
//
// Per CONTENT-3.5 (and the §2.4 cross-cut into V7 §3.5 invariant signature
// pointers), the validator runs every Put/SetReverseHash to check whether
// an entry's source_peer_id has produced a valid signature over the entry's
// content_hash, persisted at /{signer_peer_id}/system/signature/{target_hex}.
//
// V7.67 Phase 2 unification: NewSignatureVerifier returns a closure that
// dispatches on the source peer's declared key_type (Ed25519 / Ed448 /
// future allocations) rather than hard-coding Ed25519. See crypto.Verify
// for the dispatch table.
package storagesubstitutesources

import (
	"fmt"

	"go.entitychurch.org/entity-core-go/core/crypto"
	"go.entitychurch.org/entity-core-go/core/entity"
	"go.entitychurch.org/entity-core-go/core/handler"
	"go.entitychurch.org/entity-core-go/core/hash"
	"go.entitychurch.org/entity-core-go/core/types"
)

// NewSignatureVerifier returns the §2.4 verifier closure. It needs
// nothing from outside the HandlerContext — store + location index +
// content hashes are sufficient — so PeerBuilder integration is a one-
// liner: orchestrator := New(WithSignatureVerifier(NewSignatureVerifier())).
//
// On verification failure the returned error carries which axis failed
// (no system/peer entity for source / no signature entity / unsupported
// algorithm / pubkey-vs-peer-id mismatch / signature verify) — informative
// for diagnostics, descriptive enough that operators can audit chain
// rejections without leaking key material.
//
// V7.67 Phase 2: dispatches on source peer's PeerData.KeyType (Ed25519 or
// Ed448); previously hard-coded to Ed25519 (Ed25519SignatureVerifier alias
// retained for source-compat below).
func NewSignatureVerifier() SignatureVerifier {
	return func(hctx *handler.HandlerContext, entry entity.Entity, srcData types.SubstituteSourceData) error {
		if hctx == nil || hctx.Store == nil || hctx.LocationIndex == nil {
			return fmt.Errorf("verifier: hctx missing store/locationIndex")
		}

		// 1. Resolve the source peer's public key via the system/peer entity.
		peerEnt, ok := hctx.Store.Get(srcData.SourcePeerID)
		if !ok {
			return fmt.Errorf("verifier: system/peer entity not found for source_peer_id %s",
				srcData.SourcePeerID)
		}
		if peerEnt.Type != types.TypePeer {
			return fmt.Errorf("verifier: source_peer_id resolves to %q, not %s",
				peerEnt.Type, types.TypePeer)
		}
		peerData, err := types.PeerDataFromEntity(peerEnt)
		if err != nil {
			return fmt.Errorf("verifier: decode system/peer: %w", err)
		}
		ktByte, ktOK := peerData.KeyTypeByte()
		if !ktOK {
			return fmt.Errorf("verifier: unsupported key_type %q", peerData.KeyType)
		}
		expectedPubLen := 0
		switch ktByte {
		case crypto.KeyTypeEd25519:
			expectedPubLen = crypto.Ed25519PublicKeyLen
		case crypto.KeyTypeEd448:
			expectedPubLen = crypto.Ed448PublicKeyLen
		}
		if expectedPubLen > 0 && len(peerData.PublicKey) != expectedPubLen {
			return fmt.Errorf("verifier: malformed public_key for key_type %q (got %d bytes, want %d)",
				peerData.KeyType, len(peerData.PublicKey), expectedPubLen)
		}
		// v7.65 §1.5: peer_id derives from (public_key, key_type) — canonical
		// form per crypto.CanonicalHashType.
		signerPID, err := crypto.PeerIDFromPublicKey(peerData.PublicKey, ktByte)
		if err != nil {
			return fmt.Errorf("verifier: derive signer peer_id: %w", err)
		}

		// 2. Resolve the signature entity via the invariant signature path.
		sigPath := types.InvariantSignaturePath(string(signerPID), entry.ContentHash)
		sigHash, ok := hctx.LocationIndex.Get(sigPath)
		if !ok {
			return fmt.Errorf("verifier: no signature bound at %s", sigPath)
		}
		sigEnt, ok := hctx.Store.Get(sigHash)
		if !ok {
			return fmt.Errorf("verifier: signature hash %s not in store", sigHash)
		}
		if sigEnt.Type != types.TypeSignature {
			return fmt.Errorf("verifier: signature path resolves to %q, not %s",
				sigEnt.Type, types.TypeSignature)
		}
		sigData, err := types.SignatureDataFromEntity(sigEnt)
		if err != nil {
			return fmt.Errorf("verifier: decode system/signature: %w", err)
		}

		// 3. Cross-check the signature's claimed target/signer.
		if sigData.Target != entry.ContentHash {
			return fmt.Errorf("verifier: signature target mismatch (got %s, want %s)",
				sigData.Target, entry.ContentHash)
		}
		if sigData.Signer != srcData.SourcePeerID {
			return fmt.Errorf("verifier: signature signer mismatch (got %s, want %s)",
				sigData.Signer, srcData.SourcePeerID)
		}
		if sigData.Algorithm != "" && sigData.Algorithm != peerData.KeyType {
			return fmt.Errorf("verifier: signature algorithm %q does not match peer key_type %q",
				sigData.Algorithm, peerData.KeyType)
		}

		// 4. Verify the signature over the entry's content_hash bytes,
		// dispatching on the source peer's key_type. The signed message is
		// the canonical hash wire representation (algorithm byte || digest)
		// per ENTITY-CBOR-ENCODING — what every other signature site in the
		// codebase signs over.
		msg := canonicalHashBytes(entry.ContentHash)
		if !crypto.Verify(ktByte, peerData.PublicKey, msg, sigData.Signature) {
			return fmt.Errorf("verifier: signature verification failed (key_type=%q)", peerData.KeyType)
		}
		return nil
	}
}

// canonicalHashBytes returns the 33-byte canonical hash representation
// (algorithm byte || 32-byte digest) — the same bytes hash.Hash.Bytes()
// returns and the same bytes every other signature site in the codebase
// signs over.
func canonicalHashBytes(h hash.Hash) []byte {
	return h.Bytes()
}
