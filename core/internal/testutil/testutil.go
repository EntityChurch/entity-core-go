package testutil

import (
	"testing"

	"go.entitychurch.org/entity-core-go/core/crypto"
	"go.entitychurch.org/entity-core-go/core/ecf"
	"go.entitychurch.org/entity-core-go/core/entity"
	"go.entitychurch.org/entity-core-go/core/hash"
	"go.entitychurch.org/entity-core-go/core/types"

	"github.com/fxamacker/cbor/v2"
)

// MakeEntity creates a test entity with the given type and data.
func MakeEntity(t *testing.T, entityType string, data interface{}) entity.Entity {
	t.Helper()
	raw, err := ecf.Encode(data)
	if err != nil {
		t.Fatal(err)
	}
	e, err := entity.NewEntity(entityType, cbor.RawMessage(raw))
	if err != nil {
		t.Fatal(err)
	}
	return e
}

// MakeHash computes a content hash for the given type and data.
func MakeHash(t *testing.T, entityType string, data interface{}) hash.Hash {
	t.Helper()
	raw, err := ecf.Encode(data)
	if err != nil {
		t.Fatal(err)
	}
	h, err := hash.Compute(entityType, cbor.RawMessage(raw))
	if err != nil {
		t.Fatal(err)
	}
	return h
}

// MakeKeypair creates a deterministic keypair from a fixed seed.
// The seed byte is used to differentiate multiple keypairs in the same test.
func MakeKeypair(t *testing.T, seedByte byte) crypto.Keypair {
	t.Helper()
	var seed [32]byte
	seed[0] = seedByte
	return crypto.FromSeed(seed)
}

// MakeCapability creates a test capability token entity.
func MakeCapability(t *testing.T, grants []types.GrantEntry, granter, grantee entity.Entity) entity.Entity {
	t.Helper()
	capData := types.CapabilityTokenData{
		Grants:    grants,
		Granter:   types.SingleSigGranter(granter.ContentHash),
		Grantee:   grantee.ContentHash,
		CreatedAt: 1000,
	}
	capEntity, err := capData.ToEntity()
	if err != nil {
		t.Fatal(err)
	}
	return capEntity
}

// MakeEnvelope creates a test envelope.
func MakeEnvelope(t *testing.T, root entity.Entity, included ...entity.Entity) entity.Envelope {
	t.Helper()
	inc := make(map[hash.Hash]entity.Entity)
	for _, e := range included {
		inc[e.ContentHash] = e
	}
	return entity.NewEnvelope(root, inc)
}

// MakeSignedCapability creates a capability token signed by the granter.
func MakeSignedCapability(t *testing.T, grants []types.GrantEntry, granterKP crypto.Keypair, granterIdentity, granteeIdentity entity.Entity) (entity.Entity, entity.Entity) {
	t.Helper()
	capEntity := MakeCapability(t, grants, granterIdentity, granteeIdentity)

	sig := granterKP.Sign(capEntity.ContentHash.Bytes())
	sigData := types.SignatureData{
		Target:    capEntity.ContentHash,
		Signer:    granterIdentity.ContentHash,
		Algorithm: "ed25519",
		Signature: sig,
	}
	sigEntity, err := sigData.ToEntity()
	if err != nil {
		t.Fatal(err)
	}
	return capEntity, sigEntity
}
