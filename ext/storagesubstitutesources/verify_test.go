package storagesubstitutesources

import (
	"strings"
	"testing"

	"go.entitychurch.org/entity-core-go/core/crypto"
	"go.entitychurch.org/entity-core-go/core/entity"
	"go.entitychurch.org/entity-core-go/core/handler"
	"go.entitychurch.org/entity-core-go/core/hash"
	"go.entitychurch.org/entity-core-go/core/store"
	"go.entitychurch.org/entity-core-go/core/types"
)

// signedSrcSetup builds a real Ed25519-signed substitute-source entry +
// stages all the entities the verifier needs into a store/locationIndex:
//   - the system/peer entity for the source peer
//   - the system/signature entity signing the source-entry content hash
//   - the location binding at InvariantSignaturePath
//
// Returns the source entity (ready to feed the verifier) + the source
// data + a HandlerContext populated with the store/index.
func signedSrcSetup(t *testing.T) (entity.Entity, types.SubstituteSourceData, *handler.HandlerContext, crypto.Keypair) {
	t.Helper()

	cs := store.NewMemoryContentStore()
	li := store.NewMemoryLocationIndex()

	// 1. Source peer keypair + system/peer entity.
	kp, err := crypto.Generate()
	if err != nil {
		t.Fatalf("crypto.Generate: %v", err)
	}
	peerID := kp.PeerID()
	_ = peerID // v7.65: peer_id not in hashable basis
	peerData := types.PeerData{
		PublicKey: kp.PublicKey,
		KeyType:   "ed25519",
	}
	peerEnt, err := peerData.ToEntity()
	if err != nil {
		t.Fatalf("peer ToEntity: %v", err)
	}
	peerHash, err := cs.Put(peerEnt)
	if err != nil {
		t.Fatalf("Put peer: %v", err)
	}

	// 2. Construct the substitute-source entry with SourcePeerID = peerHash.
	srcData, err := types.NewHTTPSource("signed-source", peerHash,
		types.TransportEndpoint{
			TreeURLPrefix:    "https://signed.example.com",
			ContentURLPrefix: "https://signed.example.com/content",
			ContentLayout:    types.ContentLayoutFlat,
		}, 10)
	if err != nil {
		t.Fatalf("NewHTTPSource: %v", err)
	}
	srcEnt, err := srcData.ToEntity()
	if err != nil {
		t.Fatalf("src ToEntity: %v", err)
	}
	if _, err := cs.Put(srcEnt); err != nil {
		t.Fatalf("Put src: %v", err)
	}

	// 3. Sign the source-entry's content hash with the peer's private key.
	sig := kp.Sign(srcEnt.ContentHash.Bytes())

	// 4. Materialize the system/signature entity + bind at the §3.5 path.
	sigData := types.SignatureData{
		Target:    srcEnt.ContentHash,
		Signer:    peerHash,
		Algorithm: "ed25519",
		Signature: sig,
	}
	sigEnt, err := sigData.ToEntity()
	if err != nil {
		t.Fatalf("sig ToEntity: %v", err)
	}
	sigHash, err := cs.Put(sigEnt)
	if err != nil {
		t.Fatalf("Put sig: %v", err)
	}
	sigPath := types.InvariantSignaturePath(string(peerID), srcEnt.ContentHash)
	if err := li.Set(sigPath, sigHash); err != nil {
		t.Fatalf("Set sig binding: %v", err)
	}

	hctx := &handler.HandlerContext{Store: cs, LocationIndex: li}
	return srcEnt, srcData, hctx, kp
}

func TestEd25519SignatureVerifier_ValidSignature(t *testing.T) {
	srcEnt, srcData, hctx, _ := signedSrcSetup(t)
	v := NewSignatureVerifier()
	if err := v(hctx, srcEnt, srcData); err != nil {
		t.Fatalf("valid signature should verify, got: %v", err)
	}
}

func TestEd25519SignatureVerifier_MissingPeerEntity(t *testing.T) {
	// Build a srcData with a SourcePeerID that's not in the store.
	bogusPeer := hash.Hash{Algorithm: hash.AlgorithmSHA256}
	bogusPeer.Digest[0] = 0xff
	srcData, err := types.NewHTTPSource("no-peer", bogusPeer, types.TransportEndpoint{
		TreeURLPrefix: "https://x.example.com",
	}, 10)
	if err != nil {
		t.Fatal(err)
	}
	srcEnt, err := srcData.ToEntity()
	if err != nil {
		t.Fatal(err)
	}
	hctx := &handler.HandlerContext{
		Store:         store.NewMemoryContentStore(),
		LocationIndex: store.NewMemoryLocationIndex(),
	}
	v := NewSignatureVerifier()
	err = v(hctx, srcEnt, srcData)
	if err == nil || !strings.Contains(err.Error(), "system/peer entity not found") {
		t.Errorf("expected peer-not-found error, got %v", err)
	}
}

func TestEd25519SignatureVerifier_MissingSignatureBinding(t *testing.T) {
	srcEnt, srcData, hctx, _ := signedSrcSetup(t)
	// Wipe the location binding so the signature can't be resolved.
	peerEnt, _ := hctx.Store.Get(srcData.SourcePeerID)
	peerData, _ := types.PeerDataFromEntity(peerEnt)
	signerPID := crypto.PeerIDFromEd25519PublicKey(peerData.PublicKey) // v7.65 §1.5
	sigPath := types.InvariantSignaturePath(string(signerPID), srcEnt.ContentHash)
	hctx.LocationIndex.Remove(sigPath)

	v := NewSignatureVerifier()
	err := v(hctx, srcEnt, srcData)
	if err == nil || !strings.Contains(err.Error(), "no signature bound") {
		t.Errorf("expected missing-signature-binding error, got %v", err)
	}
}

func TestEd25519SignatureVerifier_TargetMismatch(t *testing.T) {
	// Sign a different hash, bind at this entry's path — verifier MUST
	// reject due to target mismatch.
	cs := store.NewMemoryContentStore()
	li := store.NewMemoryLocationIndex()

	kp, _ := crypto.Generate()
	peerData := types.PeerData{
		PublicKey: kp.PublicKey,
		KeyType:   "ed25519",
	}
	peerEnt, _ := peerData.ToEntity()
	peerHash, _ := cs.Put(peerEnt)

	srcData, _ := types.NewHTTPSource("mismatch", peerHash, types.TransportEndpoint{
		TreeURLPrefix: "https://x.example.com",
	}, 10)
	srcEnt, _ := srcData.ToEntity()
	cs.Put(srcEnt)

	wrongTarget := hash.Hash{Algorithm: hash.AlgorithmSHA256}
	wrongTarget.Digest[0] = 0xaa
	sig := kp.Sign(wrongTarget.Bytes())
	sigData := types.SignatureData{
		Target:    wrongTarget, // mismatch — should NOT equal srcEnt.ContentHash
		Signer:    peerHash,
		Algorithm: "ed25519",
		Signature: sig,
	}
	sigEnt, _ := sigData.ToEntity()
	sigHash, _ := cs.Put(sigEnt)
	sigPath := types.InvariantSignaturePath(string(kp.PeerID()), srcEnt.ContentHash)
	li.Set(sigPath, sigHash)

	hctx := &handler.HandlerContext{Store: cs, LocationIndex: li}
	v := NewSignatureVerifier()
	err := v(hctx, srcEnt, srcData)
	if err == nil || !strings.Contains(err.Error(), "signature target mismatch") {
		t.Errorf("expected target-mismatch error, got %v", err)
	}
}

func TestEd25519SignatureVerifier_BadSignature(t *testing.T) {
	srcEnt, srcData, hctx, _ := signedSrcSetup(t)
	// Corrupt the stored signature so ed25519.Verify fails.
	peerEnt, _ := hctx.Store.Get(srcData.SourcePeerID)
	peerData, _ := types.PeerDataFromEntity(peerEnt)
	signerPID := crypto.PeerIDFromEd25519PublicKey(peerData.PublicKey) // v7.65 §1.5
	sigPath := types.InvariantSignaturePath(string(signerPID), srcEnt.ContentHash)
	sigHash, _ := hctx.LocationIndex.Get(sigPath)
	sigEnt, _ := hctx.Store.Get(sigHash)
	sigData, _ := types.SignatureDataFromEntity(sigEnt)
	// Flip a byte in the signature.
	sigData.Signature[0] ^= 0xff
	corruptEnt, _ := sigData.ToEntity()
	corruptHash, _ := hctx.Store.Put(corruptEnt)
	hctx.LocationIndex.Set(sigPath, corruptHash)

	v := NewSignatureVerifier()
	err := v(hctx, srcEnt, srcData)
	if err == nil || !strings.Contains(err.Error(), "signature verification failed") {
		t.Errorf("expected signature-verification-failed error, got %v", err)
	}
}
