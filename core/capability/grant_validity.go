package capability

import (
	"errors"
	"fmt"
	"time"

	"go.entitychurch.org/entity-core-go/core/crypto"
	"go.entitychurch.org/entity-core-go/core/entity"
	"go.entitychurch.org/entity-core-go/core/hash"
	"go.entitychurch.org/entity-core-go/core/store"
	"go.entitychurch.org/entity-core-go/core/types"
)

// ErrGrantInvalid is returned by VerifyHandlerGrant for any failure shape.
// Callers translate this into the §7.1 fail-closed wire response. The Error()
// string carries a stable code ("missing_granter", "foreign_granter", etc.)
// that callers may inspect for diagnostics; the message is human-readable.
type ErrGrantInvalid struct {
	Code    string
	Message string
}

func (e *ErrGrantInvalid) Error() string {
	return e.Code + ": " + e.Message
}

func grantInvalid(code, message string) error {
	return &ErrGrantInvalid{Code: code, Message: message}
}

// VerifyHandlerGrant validates a handler grant entity per V7 §6.2 / §6.8 and
// PROPOSAL-ENTITY-NATIVE-HANDLER-DISPATCH §7.1 / spec-gap-handler-grant-
// authority §S2.
//
// A grant is valid iff:
//  1. The entity decodes as system/capability/token with a non-zero granter.
//  2. The granter equals the local peer's identity hash (chain-to-root via
//     parent is normative per §S1 but not yet implemented; this is the
//     direct-grant case sufficient to reject cross-peer grant transfer).
//  3. A system/signature entity exists at signaturePath.
//  4. The signature entity's Target == grant.ContentHash and Signer == granter.
//  5. The granter's identity entity is resolvable from the content store.
//  6. The signature verifies against the granter's public key.
//  7. Temporal validity holds (NotBefore/ExpiresAt).
//
// signaturePath is the tree path where the grant's signature entity lives.
// Per v7.74 v0.4 §3.4 (invariant-pointer convergence), grant signatures
// are stored at system/signature/{grant_hash}; callers derive the path via
// types.LocalSignaturePath(grantEnt.ContentHash).
//
// Returns nil on success, an *ErrGrantInvalid on validation failure, or a
// generic error for I/O / decode problems.
func VerifyHandlerGrant(
	grantEnt entity.Entity,
	signaturePath string,
	localIdentityHash hash.Hash,
	cs store.ContentStore,
	li store.LocationIndex,
) error {
	if grantEnt.Type != types.TypeCapToken {
		return grantInvalid("wrong_type",
			fmt.Sprintf("expected %s, got %s", types.TypeCapToken, grantEnt.Type))
	}
	tok, err := types.CapabilityTokenDataFromEntity(grantEnt)
	if err != nil {
		return grantInvalid("decode_failed", err.Error())
	}

	// (1) granter must be set
	if tok.Granter.IsZero() {
		return grantInvalid("missing_granter", "grant has no granter set")
	}

	// (2) granter must be the local peer (chain-to-root via parent: deferred).
	// Handler grants are issued by the local peer to itself; multi-sig grants
	// are root caps issued by a K-of-N group and don't fit this single-issuer
	// pattern. M3 root-only + the local-handler shape mean we reject multi-sig
	// here outright. (Future: handlers issued under a multi-sig root would
	// require a separate validation path.)
	granterHash, single := tok.Granter.SingleHash()
	if !single {
		return grantInvalid("multi_sig_granter_not_supported_here",
			"handler grants must be single-sig; multi-sig grants are root caps issued elsewhere")
	}
	if granterHash != localIdentityHash {
		return grantInvalid("foreign_granter",
			fmt.Sprintf("grant granter %s is not local peer %s",
				granterHash, localIdentityHash))
	}

	// (3-4) signature entity must exist alongside the grant.
	sigHash, ok := li.Get(signaturePath)
	if !ok {
		return grantInvalid("missing_signature",
			"no signature entity at "+signaturePath)
	}
	sigEnt, ok := cs.Get(sigHash)
	if !ok {
		return grantInvalid("missing_signature_entity",
			"signature path bound but content store has no entity")
	}
	if sigEnt.Type != types.TypeSignature {
		return grantInvalid("wrong_signature_type",
			fmt.Sprintf("expected %s, got %s", types.TypeSignature, sigEnt.Type))
	}
	sig, err := types.SignatureDataFromEntity(sigEnt)
	if err != nil {
		return grantInvalid("signature_decode_failed", err.Error())
	}
	if sig.Target != grantEnt.ContentHash {
		return grantInvalid("signature_target_mismatch",
			fmt.Sprintf("signature targets %s, grant content_hash is %s",
				sig.Target, grantEnt.ContentHash))
	}
	if sig.Signer != granterHash {
		return grantInvalid("signature_signer_mismatch",
			fmt.Sprintf("signature signer %s != grant granter %s",
				sig.Signer, granterHash))
	}

	// (5) granter identity entity (carries public key) must be resolvable.
	idEnt, ok := cs.Get(granterHash)
	if !ok {
		return grantInvalid("granter_identity_unresolvable",
			"granter identity entity not in content store: "+granterHash.String())
	}
	if idEnt.Type != types.TypePeer {
		return grantInvalid("granter_not_identity",
			fmt.Sprintf("granter resolves to %s, not %s", idEnt.Type, types.TypePeer))
	}
	idData, err := types.PeerDataFromEntity(idEnt)
	if err != nil {
		return grantInvalid("granter_identity_decode_failed", err.Error())
	}

	// (6) cryptographic signature verification — algorithm-agnostic dispatch
	// on granter's declared key_type (v7.67 §3 crypto-agility).
	ktByte, ktOK := idData.KeyTypeByte()
	if !ktOK {
		return grantInvalid("unsupported_key_type",
			"granter key type "+idData.KeyType+" is not supported")
	}
	if sig.Algorithm != "" && sig.Algorithm != idData.KeyType {
		return grantInvalid("unsupported_signature_algorithm",
			fmt.Sprintf("signature algorithm %q does not match granter key_type %q",
				sig.Algorithm, idData.KeyType))
	}
	expectedPubLen := 0
	switch ktByte {
	case crypto.KeyTypeEd25519:
		expectedPubLen = crypto.Ed25519PublicKeyLen
	case crypto.KeyTypeEd448:
		expectedPubLen = crypto.Ed448PublicKeyLen
	}
	if expectedPubLen > 0 && len(idData.PublicKey) != expectedPubLen {
		return grantInvalid("granter_public_key_invalid",
			fmt.Sprintf("granter public key length %d != %d (key_type %q)",
				len(idData.PublicKey), expectedPubLen, idData.KeyType))
	}
	if !crypto.Verify(ktByte, idData.PublicKey, grantEnt.ContentHash.Bytes(), sig.Signature) {
		return grantInvalid("signature_verification_failed",
			"granter public key did not verify the grant signature")
	}

	// (7) temporal validity.
	now := uint64(time.Now().UnixMilli())
	if tok.NotBefore != nil && now < *tok.NotBefore {
		return grantInvalid("grant_not_yet_valid",
			fmt.Sprintf("not_before=%d, now=%d", *tok.NotBefore, now))
	}
	if tok.ExpiresAt != nil && *tok.ExpiresAt < now {
		return grantInvalid("grant_expired",
			fmt.Sprintf("expires_at=%d, now=%d", *tok.ExpiresAt, now))
	}

	return nil
}

// IsGrantInvalid returns the *ErrGrantInvalid if err was produced by
// VerifyHandlerGrant; otherwise (false, nil).
func IsGrantInvalid(err error) (*ErrGrantInvalid, bool) {
	var gi *ErrGrantInvalid
	if errors.As(err, &gi) {
		return gi, true
	}
	return nil, false
}
