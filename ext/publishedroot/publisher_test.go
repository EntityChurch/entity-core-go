package publishedroot

import (
	"bytes"
	"crypto/ed25519"
	"strings"
	"testing"
	"time"

	"go.entitychurch.org/entity-core-go/core/crypto"
	"go.entitychurch.org/entity-core-go/core/entity"
	"go.entitychurch.org/entity-core-go/core/hash"
	"go.entitychurch.org/entity-core-go/core/store"
	"go.entitychurch.org/entity-core-go/core/tree"
	"go.entitychurch.org/entity-core-go/core/types"
)

func newTestPublisher(t *testing.T) (*Publisher, crypto.Keypair) {
	t.Helper()
	cs := store.NewMemoryContentStore()
	li := store.NewMemoryLocationIndex()
	kp, err := crypto.Generate()
	if err != nil {
		t.Fatalf("generate keypair: %v", err)
	}
	identity, err := kp.IdentityEntity()
	if err != nil {
		t.Fatalf("identity entity: %v", err)
	}
	if _, err := cs.Put(identity); err != nil {
		t.Fatalf("put identity: %v", err)
	}
	tracker := tree.NewRootTracker(cs, string(kp.PeerID()), nil)
	p := NewPublisher(cs, tracker, PrefixForLocalPeer, nil)
	if err := p.SetupAuthority(li, kp, identity, false); err != nil {
		t.Fatalf("setup authority: %v", err)
	}
	return p, kp
}

func fakeRoot(b byte) hash.Hash {
	var h hash.Hash
	h.Algorithm = hash.AlgorithmSHA256
	h.Digest[0] = b
	return h
}

func TestPublishMintsBindAndSignature(t *testing.T) {
	p, kp := newTestPublisher(t)
	root := fakeRoot(0xAB)

	ent, err := p.Publish(root)
	if err != nil {
		t.Fatalf("Publish: %v", err)
	}
	if ent.Type != types.TypePeerPublishedRoot {
		t.Fatalf("entity type: want %s got %s", types.TypePeerPublishedRoot, ent.Type)
	}

	// Decode the entity and check fields.
	pd, err := types.PublishedRootDataFromEntity(ent)
	if err != nil {
		t.Fatalf("decode published-root: %v", err)
	}
	if pd.RootHash != root {
		t.Fatalf("RootHash drift")
	}
	if pd.Seq != 1 {
		t.Fatalf("Seq want 1 got %d", pd.Seq)
	}
	if pd.Predecessor != nil {
		t.Fatalf("first publish should have nil Predecessor; got %+v", pd.Predecessor)
	}
	if pd.PublishedAt == 0 {
		t.Fatal("PublishedAt should be wall-clock millis, got 0")
	}

	// Ruling-1: pd.PeerID is the Base58 string per V7 §1.5.
	if pd.PeerID != string(kp.PeerID()) {
		t.Fatalf("PeerID Base58 drift: want %s got %s", kp.PeerID(), pd.PeerID)
	}

	// Storage path bound.
	storagePath := types.PublishedRootStoragePath(pd.PeerID)
	got, ok := p.li.Get(storagePath)
	if !ok {
		t.Fatalf("published-root not bound at %s", storagePath)
	}
	if got != ent.ContentHash {
		t.Fatalf("bound hash drift at %s", storagePath)
	}

	// Signature bound at invariant-pointer.
	sigPath := types.LocalSignaturePath(ent.ContentHash)
	sigHash, ok := p.li.Get(sigPath)
	if !ok {
		t.Fatalf("signature not bound at %s", sigPath)
	}
	sigEnt, ok := p.cs.Get(sigHash)
	if !ok {
		t.Fatal("signature entity missing from store")
	}
	sd, err := types.SignatureDataFromEntity(sigEnt)
	if err != nil {
		t.Fatalf("decode signature: %v", err)
	}
	if sd.Target != ent.ContentHash {
		t.Fatal("signature Target ≠ published-root content_hash")
	}
	// SignatureData.Signer is the content_hash of the publisher's system/peer
	// entity (V7 §5.2 — signature.signer is a hash). The pd.PeerID Base58 is
	// the V7 §1.5 derivation from that same key; distinct shapes.
	identity, _ := kp.IdentityEntity()
	if sd.Signer != identity.ContentHash {
		t.Fatal("signature Signer ≠ publisher's identity entity content_hash")
	}

	// Signature must verify against the publisher's public key (V7 §1.5:
	// pubkey IS identity; the published-root contract leans on this).
	if kp.KeyType != crypto.KeyTypeEd25519 {
		t.Skipf("default keypair is %s; verify path tested via Ed25519 below", crypto.KeyTypeString(kp.KeyType))
	}
	pub := ed25519.PublicKey(kp.PublicKey)
	if !ed25519.Verify(pub, ent.ContentHash.Bytes(), sd.Signature) {
		t.Fatal("signature does not verify against publisher's pubkey")
	}
}

func TestPublishSeqMonotonicAndPredecessorChain(t *testing.T) {
	p, _ := newTestPublisher(t)

	e1, err := p.Publish(fakeRoot(0x01))
	if err != nil {
		t.Fatalf("publish 1: %v", err)
	}
	e2, err := p.Publish(fakeRoot(0x02))
	if err != nil {
		t.Fatalf("publish 2: %v", err)
	}
	e3, err := p.Publish(fakeRoot(0x03))
	if err != nil {
		t.Fatalf("publish 3: %v", err)
	}

	d2, _ := types.PublishedRootDataFromEntity(e2)
	if d2.Seq != 2 {
		t.Fatalf("e2 Seq: want 2 got %d", d2.Seq)
	}
	if d2.Predecessor == nil || !bytes.Equal(d2.Predecessor.Bytes(), e1.ContentHash.Bytes()) {
		t.Fatalf("e2 Predecessor should chain to e1")
	}
	d3, _ := types.PublishedRootDataFromEntity(e3)
	if d3.Seq != 3 {
		t.Fatalf("e3 Seq: want 3 got %d", d3.Seq)
	}
	if d3.Predecessor == nil || !bytes.Equal(d3.Predecessor.Bytes(), e2.ContentHash.Bytes()) {
		t.Fatal("e3 Predecessor should chain to e2")
	}

	// Current() should reflect the latest publish.
	curr, ok := p.Current()
	if !ok {
		t.Fatal("Current() returned no published root")
	}
	if curr.ContentHash != e3.ContentHash {
		t.Fatal("Current() not pointing at the latest publish")
	}
}

func TestPublishWithoutAuthority(t *testing.T) {
	cs := store.NewMemoryContentStore()
	li := store.NewMemoryLocationIndex()
	tracker := tree.NewRootTracker(cs, "test", nil)
	_ = li
	p := NewPublisher(cs, tracker, PrefixForLocalPeer, nil)
	if _, err := p.Publish(fakeRoot(0xFF)); err == nil {
		t.Fatal("Publish without SetupAuthority must error")
	}
}

func TestOnTreeChangeFiltersUnrelatedPaths(t *testing.T) {
	p, _ := newTestPublisher(t)
	before, _ := p.Current()

	// An event for an unrelated path must not trigger a publish.
	p.OnTreeChange(store.TreeChangeEvent{
		Path:       "/some-peer/other/path",
		Hash:       fakeRoot(0xAA),
		ChangeType: store.ChangeCreated,
	})
	after, _ := p.Current()
	if (before == nil) != (after == nil) {
		t.Fatal("unrelated path triggered publish state change")
	}
}

func TestOnTreeChangeTriggersPublish(t *testing.T) {
	p, kp := newTestPublisher(t)
	root := fakeRoot(0xCC)

	// Synthesize what RootTracker would emit: a binding at the cleaned
	// tracked-root path for the publisher's prefix.
	p.OnTreeChange(store.TreeChangeEvent{
		Path:       "/" + string(kp.PeerID()) + "/system/tree/root/" + strings.TrimRight(PrefixForLocalPeer, "/"),
		Hash:       root,
		ChangeType: store.ChangeCreated,
	})

	// OnTreeChange spawns Publish on a goroutine to avoid deadlocking
	// against rootTracker's per-prefix mutex; poll briefly for the result.
	var curr *entity.Entity
	var ok bool
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		curr, ok = p.Current()
		if ok {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if !ok {
		t.Fatal("hook did not produce a published-root")
	}
	pd, _ := types.PublishedRootDataFromEntity(*curr)
	if pd.RootHash != root {
		t.Fatalf("published RootHash drift: %x vs %x", pd.RootHash.Bytes(), root.Bytes())
	}
}
