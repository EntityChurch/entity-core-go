package peer

import (
	"testing"

	"go.entitychurch.org/entity-core-go/core/crypto"
	"go.entitychurch.org/entity-core-go/core/entity"
	"go.entitychurch.org/entity-core-go/core/hash"
	"go.entitychurch.org/entity-core-go/core/store"
	"go.entitychurch.org/entity-core-go/core/types"
)

// TestDecodeExecuteResponse_IngestsIncludedSignatures pins E4 / F64 (0.8.2.19):
// a received EXECUTE_RESPONSE carrying `included` signatures/identities MUST have
// them ingested into the store so a later local chain-walk resolves — the same
// ingestion the inbound EXECUTE and connect-response paths already do. Before
// E4 the binding did not exist at all (rust's mutation: "left: None").
//
// Mutation witness: dropping the IngestEnvelopeSignatures call in
// decodeExecuteResponse leaves the signature unbound (li.Get → not present).
func TestDecodeExecuteResponse_IngestsIncludedSignatures(t *testing.T) {
	kp, err := crypto.Generate()
	if err != nil {
		t.Fatal(err)
	}
	ident, err := kp.IdentityEntity()
	if err != nil {
		t.Fatal(err)
	}

	// A signature entity over some target hash, signed by ident. Ingestion binds
	// it at its invariant path; it does not crypto-verify, so any well-formed
	// signature+identity pair is enough to observe the binding.
	targetHash := ident.ContentHash // any content hash serves as the signed target
	sigEnt, err := types.SignatureData{
		Target:    targetHash,
		Signer:    ident.ContentHash,
		Algorithm: "ed25519",
		Signature: kp.Sign(targetHash.Bytes()),
	}.ToEntity()
	if err != nil {
		t.Fatal(err)
	}

	respRoot, err := types.ExecuteResponseData{Status: 200, RequestID: "e4"}.ToEntity()
	if err != nil {
		t.Fatal(err)
	}
	env := entity.Envelope{
		Root: respRoot,
		Included: map[hash.Hash]entity.Entity{
			ident.ContentHash:  ident,
			sigEnt.ContentHash: sigEnt,
		},
	}

	cs := store.NewMemoryContentStore()
	li := store.NewMemoryLocationIndex()

	if _, err := decodeExecuteResponse(env, cs, li); err != nil {
		t.Fatalf("decode: %v", err)
	}

	ktByte, _ := func() (byte, bool) {
		d, _ := types.PeerDataFromEntity(ident)
		return d.KeyTypeByte()
	}()
	signerPID, err := crypto.PeerIDFromPublicKey(func() []byte {
		d, _ := types.PeerDataFromEntity(ident)
		return d.PublicKey
	}(), ktByte)
	if err != nil {
		t.Fatal(err)
	}
	path := types.InvariantSignaturePath(string(signerPID), targetHash)
	bound, ok := li.Get(path)
	if !ok {
		t.Fatal("E4: EXECUTE_RESPONSE included signature was not ingested — no binding at its invariant path (the binding did not exist)")
	}
	if bound != sigEnt.ContentHash {
		t.Fatalf("E4: signature bound to %s, want %s", bound, sigEnt.ContentHash)
	}
}
