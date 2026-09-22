package protocol

import (
	"fmt"

	"go.entitychurch.org/entity-core-go/core/capability"
	"go.entitychurch.org/entity-core-go/core/crypto"
	"go.entitychurch.org/entity-core-go/core/entity"
	ecerrors "go.entitychurch.org/entity-core-go/core/errors"
	"go.entitychurch.org/entity-core-go/core/hash"
	"go.entitychurch.org/entity-core-go/core/types"
)

// IdentityBindingChecker is the optional cross-cut hook by which cap-chain
// verification (V7 §5.5) consults attestation state for grantee identity-
// binding lookup, per EXTENSION-IDENTITY §12.3 / IA23.
//
// The §3.10 invariant requires structural separation: cap-chain machinery
// MUST NOT process attestations as caps; attestation validation is performed
// entirely by the implementation's own logic (typically
// VerifyKOfNSignatures / verifySingleSigAt over the local tree). The
// interface is a one-way dependency: cap-chain calls into the checker;
// the checker never delegates back to cap-chain.
//
// Returning nil means the grantee binding is recognized. Returning a non-nil
// error rejects the cap (failing closed). Implementations are typically
// deployed by the identity extension; nil is permitted (no-op, V7-only).
type IdentityBindingChecker interface {
	CheckGranteeBinding(grantee hash.Hash, env entity.Envelope) error
}

// resolveAuthoredGrant is the receive half of EXTENSION-SIGNALING §6.5 (b)
// "Wielding" under the arch 977667f carriage ruling: the counterpart names the
// §7a.2a triple as references and we resolve it from our own side, "because we
// authored it."
//
// It supplies whatever part of the triple the frame did not carry, rather than
// triggering only on a fully-absent cap. That distinction is not cosmetic: a
// sender can omit the granter identity and the granter signature while still
// inlining the cap itself (Go's own CreateAuthenticatedExecute inlines the cap
// unconditionally), so "cap is missing" is the wrong trigger and would leave
// the partial case failing at the §5.5 walk with `no signature found`.
//
// It returns env unchanged unless an AuthoredGrantSupplier is installed and
// the EXECUTE names a capability THIS peer minted as a reciprocal grant — so
// wiring it up is a no-op for every frame that inlines its chain the shipped
// way, since every entity it would supply is already present.
//
// The merge builds a COPY of the included set. That matters: env.Included is
// the decoded wire map, and mutating it would make a verification-time
// resolution look, to anything downstream that re-reads the envelope, like
// something the counterpart sent.
//
// This widens what RESOLVES, never what PASSES. Grantee resolution,
// grantee == author, and the full §5.5 chain walk all run afterward against
// the augmented set exactly as before, so a supplied cap whose grantee is not
// the requester still fails closed.
func (d *Dispatcher) resolveAuthoredGrant(env entity.Envelope, execData types.ExecuteData) entity.Envelope {
	if d.AuthoredGrantSupplier == nil || execData.Capability.IsZero() {
		return env
	}
	supporting, authored := d.AuthoredGrantSupplier(execData.Capability)
	if !authored || len(supporting) == 0 {
		return env
	}

	// Counterpart-sent entities win on collision. A hash collision can only
	// mean identical content (entities are content-addressed), so this is a
	// tie-break for determinism, not a trust decision.
	var augmented map[hash.Hash]entity.Entity
	for h, ent := range supporting {
		if _, present := env.Included[h]; present {
			continue
		}
		if augmented == nil {
			augmented = make(map[hash.Hash]entity.Entity, len(env.Included)+len(supporting))
			for eh, eent := range env.Included {
				augmented[eh] = eent
			}
		}
		augmented[h] = ent
	}
	if augmented == nil {
		// Fully inlined — the shipped shape. Nothing to supply.
		return env
	}
	d.debugf("execute: supplied %d entity(s) for locally-authored reciprocal grant %s (§6.5 (b) wielding-by-reference)",
		len(augmented)-len(env.Included), execData.Capability)
	return entity.Envelope{Root: env.Root, Included: augmented}
}

// VerifyRequest verifies the integrity and authenticity of an EXECUTE envelope.
// It checks: content hashes, signature target-matching, Ed25519 signature,
// capability chain, and grantee == author.
func VerifyRequest(env entity.Envelope, localPeerID crypto.PeerID) error {
	// 0. Bind every included map key to the entity it addresses BEFORE any
	// authority lookup. Author identity (step 1), signature signer, capability,
	// grantee and the whole chain (step 5) all resolve BY HASH out of
	// env.Included; a mis-keyed entry is an identity/capability forgery (an
	// attacker files their own system/peer under a victim's identity hash, then
	// their own signature verifies against their own key while the peer
	// attributes it to the victim — core-rust routed 2026-09-13). Enforced here
	// as well as in VerifyChain because the author check at step 1 fires before
	// the chain walk (an author-identity forgery is an AUTHENTICATION failure,
	// hence the auth-class code), and because VerifyRequest is a standalone
	// verifier that may be reached without a prior ValidateAll.
	if err := entity.VerifyIncludedKeyBinding(env.Included); err != nil {
		return fmt.Errorf("%w: %v", ecerrors.ErrAuthenticationFailed, err)
	}

	execData, err := types.ExecuteDataFromEntity(env.Root)
	if err != nil {
		return fmt.Errorf("%w: invalid execute: %v", ecerrors.ErrAuthenticationFailed, err)
	}

	// 1. Find author identity.
	if execData.Author.IsZero() {
		return fmt.Errorf("%w: missing author", ecerrors.ErrAuthenticationFailed)
	}
	authorEntity, ok := env.FindIncluded(execData.Author)
	if !ok {
		return fmt.Errorf("%w: author identity not in included", ecerrors.ErrAuthenticationFailed)
	}
	authorData, err := types.PeerDataFromEntity(authorEntity)
	if err != nil {
		return fmt.Errorf("%w: invalid author identity: %v", ecerrors.ErrAuthenticationFailed, err)
	}

	// 2. Find signature via target-matching.
	sigEntity, ok := env.FindSignatureFor(env.Root.ContentHash)
	if !ok {
		return fmt.Errorf("%w: no signature found for execute", ecerrors.ErrAuthenticationFailed)
	}
	sigData, err := types.SignatureDataFromEntity(sigEntity)
	if err != nil {
		return fmt.Errorf("%w: invalid signature: %v", ecerrors.ErrAuthenticationFailed, err)
	}

	// Verify signer matches author.
	if sigData.Signer != execData.Author {
		return fmt.Errorf("%w: signer %s != author %s", ecerrors.ErrAuthenticationFailed, sigData.Signer, execData.Author)
	}

	// 3. Verify author signature over execute's content_hash bytes,
	// dispatching on author's declared key_type (v7.67 §3 crypto-agility).
	ktByte, ktOK := authorData.KeyTypeByte()
	if !ktOK {
		return fmt.Errorf("%w: author key_type %q not supported", ecerrors.ErrAuthenticationFailed, authorData.KeyType)
	}
	if !crypto.Verify(ktByte, authorData.PublicKey, env.Root.ContentHash.Bytes(), sigData.Signature) {
		return fmt.Errorf("%w: signature verification failed", ecerrors.ErrAuthenticationFailed)
	}

	// 4. Verify capability.
	if execData.Capability.IsZero() {
		return fmt.Errorf("%w: missing capability", ecerrors.ErrCapabilityDenied)
	}
	capEntity, ok := env.FindIncluded(execData.Capability)
	if !ok {
		return fmt.Errorf("%w: capability not in included", ecerrors.ErrCapabilityDenied)
	}
	capData, err := types.CapabilityTokenDataFromEntity(capEntity)
	if err != nil {
		return fmt.Errorf("%w: invalid capability: %v", ecerrors.ErrCapabilityDenied, err)
	}

	// V7 v7.71 §A4-AUTHZ (AUTHZ-GRANTEE-1) — pre-chain grantee resolution
	// pin (§5.2 / PR-3 single 401 carve-out). If the leaf cap's `grantee`
	// does not resolve to a present `system/peer` entity in the envelope's
	// included map, surface the §5.2 carve-out code BEFORE the structural
	// "grantee != author" check fires. The resolution gap is the v7.39 §3.6
	// PR-3 surface (closes the bearer-cap class); the grantee-vs-author
	// mismatch is a different self-attribution invariant that keeps its
	// `403 capability_denied` mapping. Order matters: a zero-hash grantee
	// (or any grantee absent from included) is *unresolvable*, not just
	// non-matching, and the §3.3 401 status is the load-bearing pin.
	if granteeEnt, ok := env.FindIncluded(capData.Grantee); !ok || granteeEnt.Type != crypto.TypePeer {
		return fmt.Errorf("%w: leaf cap %s grantee %s does not resolve to a system/peer entity",
			ecerrors.ErrUnresolvableGrantee, capEntity.ContentHash, capData.Grantee)
	}

	// Verify grantee == author. Both grantee + author have resolved above;
	// this check is the self-attribution invariant (V7 §5.2).
	if capData.Grantee != execData.Author {
		return fmt.Errorf("%w: grantee %s != author %s", ecerrors.ErrCapabilityDenied, capData.Grantee, execData.Author)
	}

	// 5. Verify capability chain.
	if err := capability.VerifyChain(capEntity, env.Included, localPeerID); err != nil {
		return err
	}

	return nil
}

// VerifyRequestWithBinding extends VerifyRequest with the cross-cut hook in
// §12.3. After the cap chain validates, the optional checker confirms the
// LEAF cap's grantee is bound to a recognized identity (typically via a
// runtime-peer-attestation cached locally or embedded in the envelope). A nil
// checker means binding-blind operation (V7-only deployments stay backward-
// compatible).
//
// EXTENSION-IDENTITY v3.9 verdict-determinism invariant: the cap-chain
// verdict that participates in cross-peer interaction MUST be determined by
// the cap layer alone (signatures / attenuation / revocation / TTL), uniformly
// across peers; the binding check is a local signal and MUST NOT change a
// cross-peer verdict. This function preserves the invariant by construction:
//
//  1. The chain verdict is VerifyRequest → capability.VerifyChain, which is
//     purely cap-layer (signatures, structure, grantee resolution, linkage,
//     attenuation, delegation caveats — see core/capability/delegation.go).
//     VerifyChain has zero binding/attestation consultation.
//  2. The binding check fires AFTER the chain verdict has already passed,
//     EXACTLY ONCE per request, on the LEAF cap's grantee (capData.Grantee
//     from env.FindIncluded(execData.Capability)). It never walks intermediate
//     chain members — those are owned by VerifyChain. So the X → agent(local-
//     to-X) → Y scenario v3.9 names cannot cause cross-peer divergence here:
//     X's binding state for `agent` is not consulted (agent is intermediate,
//     not leaf).
//
// Self-caps (grantee == local peer) skip the binding check — they are local
// caps the peer issued to itself; the V7 §5.5 root-grant-by-local-peer rule
// already covers them.
func VerifyRequestWithBinding(env entity.Envelope, localPeerID crypto.PeerID, localIdentityHash hash.Hash, checker IdentityBindingChecker) error {
	if err := VerifyRequest(env, localPeerID); err != nil {
		return err
	}
	if checker == nil {
		return nil
	}
	execData, err := types.ExecuteDataFromEntity(env.Root)
	if err != nil {
		return fmt.Errorf("%w: invalid execute: %v", ecerrors.ErrAuthenticationFailed, err)
	}
	capEntity, ok := env.FindIncluded(execData.Capability)
	if !ok {
		return fmt.Errorf("%w: capability not in included", ecerrors.ErrCapabilityDenied)
	}
	capData, err := types.CapabilityTokenDataFromEntity(capEntity)
	if err != nil {
		return fmt.Errorf("%w: invalid capability: %v", ecerrors.ErrCapabilityDenied, err)
	}
	// Self-cap: grantee is the local peer's identity. No binding lookup needed.
	if !localIdentityHash.IsZero() && capData.Grantee == localIdentityHash {
		return nil
	}
	return checker.CheckGranteeBinding(capData.Grantee, env)
}
