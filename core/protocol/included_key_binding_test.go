package protocol

import (
	"errors"
	"testing"

	"go.entitychurch.org/entity-core-go/core/crypto"
	"go.entitychurch.org/entity-core-go/core/ecf"
	"go.entitychurch.org/entity-core-go/core/entity"
	ecerrors "go.entitychurch.org/entity-core-go/core/errors"
	"go.entitychurch.org/entity-core-go/core/hash"
	"go.entitychurch.org/entity-core-go/core/types"

	"github.com/fxamacker/cbor/v2"
)

// TestVerifyRequest_IncludedMapKeyBindingForgery drives the capability/identity
// forgery core-rust routed on 2026-09-13 (their included_key_binding.rs): the
// `included` map is keyed by wire-supplied hashes, and nothing binds a map key
// to the entity it addresses. An attacker who KNOWS a victim's identity hash
// (the public grantee field of any capability the victim presents) can file
// THEIR OWN system/peer entity under the victim's hash key. Every authority
// lookup that resolves an identity BY HASH from `included` then reads the
// attacker's key under the victim's identity — so the attacker's own signature
// verifies against the attacker's own key while the peer attributes it to the
// victim.
//
// Concretely: the victim legitimately holds a cap granted by the local peer.
// The attacker replays that genuine cap, sets Author = victim, signs the
// EXECUTE with the ATTACKER's key, and includes the attacker's peer entity
// under the victim's hash. Pre-fix VerifyRequest returned nil — the local peer
// accepted a request authored by the attacker as if authored by the victim,
// wielding the victim's own capability. No key of the victim's is needed.
//
// Teeth: RED against the pre-binding tree (VerifyRequest returns nil); GREEN
// once the map-key binding is enforced. The positive control (the same envelope
// with the victim's REAL identity under the victim's hash, self-signed) MUST
// still verify, so the refusal is attributable to the key substitution and not
// to the cap or the chain.
func TestVerifyRequest_IncludedMapKeyBindingForgery(t *testing.T) {
	localKP, _ := crypto.Generate()
	victimKP, _ := crypto.Generate()
	attackerKP, _ := crypto.Generate()

	localIdentity, _ := localKP.IdentityEntity()
	victimIdentity, _ := victimKP.IdentityEntity()
	attackerIdentity, _ := attackerKP.IdentityEntity()

	// A genuine cap the local peer granted to the victim (grantee = victim).
	// The attacker observes it on the wire and replays it verbatim.
	capData := types.CapabilityTokenData{
		Grants: []types.GrantEntry{{
			Handlers:   types.CapabilityScope{Include: []string{"system/tree"}},
			Resources:  types.CapabilityScope{Include: []string{"system/tree/*"}},
			Operations: types.CapabilityScope{Include: []string{"get"}},
		}},
		Granter:   types.SingleSigGranter(localIdentity.ContentHash),
		Grantee:   victimIdentity.ContentHash,
		CreatedAt: 1000,
	}
	capEntity, _ := capData.ToEntity()
	capSig := localKP.Sign(capEntity.ContentHash.Bytes())
	capSigEntity, _ := types.SignatureData{
		Target:    capEntity.ContentHash,
		Signer:    localIdentity.ContentHash,
		Algorithm: "ed25519",
		Signature: capSig,
	}.ToEntity()

	paramsRaw, _ := ecf.Encode(map[string]string{"path": "system/tree/test"})
	paramsEntity, _ := entity.NewEntity("system/tree/get-request", cbor.RawMessage(paramsRaw))
	encodedParams, _ := ecf.Encode(paramsEntity)

	// EXECUTE authored AS the victim (Author = victim hash), under the victim's
	// genuine cap.
	execData := types.ExecuteData{
		RequestID:  "req-forge",
		URI:        "entity://" + string(localKP.PeerID()) + "/system/tree",
		Operation:  "get",
		Params:     cbor.RawMessage(encodedParams),
		Author:     victimIdentity.ContentHash,
		Capability: capEntity.ContentHash,
	}
	execEntity, _ := execData.ToEntity()

	// The attacker signs the EXECUTE with THEIR OWN key, and labels the
	// signature as the victim's (Signer = victim hash).
	forgedSig := attackerKP.Sign(execEntity.ContentHash.Bytes())
	forgedSigEntity, _ := types.SignatureData{
		Target:    execEntity.ContentHash,
		Signer:    victimIdentity.ContentHash,
		Algorithm: "ed25519",
		Signature: forgedSig,
	}.ToEntity()

	// The forgery: the attacker's peer entity filed under the VICTIM's hash.
	// attackerIdentity.ContentHash != victimIdentity.ContentHash, so this entry
	// is mis-keyed — the whole point of the map-key binding.
	forgedEnv := entity.NewEnvelope(execEntity, map[hash.Hash]entity.Entity{
		victimIdentity.ContentHash:  attackerIdentity, // <-- substitution
		localIdentity.ContentHash:   localIdentity,
		capEntity.ContentHash:       capEntity,
		capSigEntity.ContentHash:    capSigEntity,
		forgedSigEntity.ContentHash: forgedSigEntity,
	})

	err := VerifyRequest(forgedEnv, localKP.PeerID())
	if err == nil {
		t.Fatalf("FORGERY ACCEPTED: VerifyRequest returned nil for a request authored by the attacker but attributed to the victim (attacker key filed under victim's identity hash)")
	}
	// An author-identity forgery is an AUTHENTICATION failure, and the map-key
	// binding at VerifyRequest's entry produces exactly that class — BEFORE the
	// chain walk. Asserting the auth class (not merely "some error") is what
	// makes this probe pin the VerifyRequest guard specifically: remove that
	// guard and VerifyChain still catches the mis-key at step 5, but with
	// ErrCapabilityDenied, so this assertion reddens. (Two guards, each pinned
	// by the error class it is responsible for — per the "a negative security
	// test can pass for the wrong reason" rule.)
	if !errors.Is(err, ecerrors.ErrAuthenticationFailed) {
		t.Fatalf("expected an authentication-class rejection from VerifyRequest's map-key binding, got: %v", err)
	}

	// Positive control: the victim's REAL identity under the victim's hash,
	// self-signed. This MUST verify — proving the refusal above is attributable
	// to the key substitution, not to the cap, the chain, or the harness.
	realSig := victimKP.Sign(execEntity.ContentHash.Bytes())
	realSigEntity, _ := types.SignatureData{
		Target:    execEntity.ContentHash,
		Signer:    victimIdentity.ContentHash,
		Algorithm: "ed25519",
		Signature: realSig,
	}.ToEntity()
	honestEnv := entity.NewEnvelope(execEntity, map[hash.Hash]entity.Entity{
		victimIdentity.ContentHash: victimIdentity, // correct binding
		localIdentity.ContentHash:  localIdentity,
		capEntity.ContentHash:      capEntity,
		capSigEntity.ContentHash:   capSigEntity,
		realSigEntity.ContentHash:  realSigEntity,
	})
	if err := VerifyRequest(honestEnv, localKP.PeerID()); err != nil {
		t.Fatalf("positive control failed — the honest, correctly-keyed request must verify: %v", err)
	}
}
