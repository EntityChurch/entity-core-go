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
	storagePath := types.PublishedRootStoragePath()
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

// TestSetupAuthorityRecoversSeqAcrossRestart pins the §6.5.3.1 rollback
// defense: a publisher constructed over a store that ALREADY carries a bound
// head must continue the monotonic seq chain, not restart at 1 from zeroed
// process memory. Teeth: without the recovery in SetupAuthority, p2's first
// publish is seq=1 with a nil predecessor and this fails at the seq==4 assert.
func TestSetupAuthorityRecoversSeqAcrossRestart(t *testing.T) {
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

	// First lifetime: publish three heads, seq reaches 3.
	tracker1 := tree.NewRootTracker(cs, string(kp.PeerID()), nil)
	p1 := NewPublisher(cs, tracker1, PrefixForLocalPeer, nil)
	if err := p1.SetupAuthority(li, kp, identity, false); err != nil {
		t.Fatalf("p1 setup: %v", err)
	}
	p1.Publish(fakeRoot(0x01))
	p1.Publish(fakeRoot(0x02))
	e3, err := p1.Publish(fakeRoot(0x03))
	if err != nil {
		t.Fatalf("p1 publish 3: %v", err)
	}

	// Restart: a NEW publisher over the SAME store + location index, as would
	// happen on process restart against persistent storage. Its lastSeq is
	// zero at construction; SetupAuthority must recover 3 from the bound head.
	tracker2 := tree.NewRootTracker(cs, string(kp.PeerID()), nil)
	p2 := NewPublisher(cs, tracker2, PrefixForLocalPeer, nil)
	if err := p2.SetupAuthority(li, kp, identity, false); err != nil {
		t.Fatalf("p2 setup: %v", err)
	}

	e4, err := p2.Publish(fakeRoot(0x04))
	if err != nil {
		t.Fatalf("p2 publish 4: %v", err)
	}
	d4, err := types.PublishedRootDataFromEntity(e4)
	if err != nil {
		t.Fatalf("decode e4: %v", err)
	}
	if d4.Seq != 4 {
		t.Fatalf("post-restart Seq: want 4 (continues the chain), got %d — SetupAuthority did not recover seq from the store", d4.Seq)
	}
	if d4.Predecessor == nil || !bytes.Equal(d4.Predecessor.Bytes(), e3.ContentHash.Bytes()) {
		t.Fatal("post-restart Predecessor should chain to the pre-restart head e3")
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

// TestOnTreeChangeRecordsNewestInSlot pins the convergence invariant behind
// TestRepublishConvergenceUndebounced, deterministically — without needing
// CPU starvation to surface the race.
//
// The undebounced hook path MUST route every tracked-root advance through the
// single newest-wins `dirty` slot, not spawn a per-event goroutine carrying a
// captured hash. This drives two advances (older then newer) while a publish
// is "in flight" (the guard held, exactly the window the lost update lived
// in), asserts the slot holds the NEWER root, then runs the drain and asserts
// the published root is the newer one — never the older midpoint.
//
// Teeth: reverting OnTreeChange to `go Publish(evt.Hash)` per event leaves
// `dirty` nil (that path never populated the slot), so the slot assertion
// fails; a drain that published a captured stale hash last would fail the
// RootHash assertion.
func TestOnTreeChangeRecordsNewestInSlot(t *testing.T) {
	p, kp := newTestPublisher(t)
	p.debounce = 0 // exercise the immediate (undebounced) path
	rootPath := "/" + string(kp.PeerID()) + "/system/tree/root/" + strings.TrimRight(PrefixForLocalPeer, "/")

	// Hold the publish guard so no flush can drain between the two events —
	// this is the "publish already in flight" window. With it held,
	// OnTreeChange records into the slot and returns without arming a flush.
	p.mu.Lock()
	p.publishing = true
	p.mu.Unlock()

	older := fakeRoot(0x10)
	newer := fakeRoot(0x20)
	p.OnTreeChange(store.TreeChangeEvent{Path: rootPath, Hash: older, ChangeType: store.ChangeCreated})
	p.OnTreeChange(store.TreeChangeEvent{Path: rootPath, Hash: newer, ChangeType: store.ChangeCreated})

	p.mu.Lock()
	slot := p.dirty
	p.mu.Unlock()
	if slot == nil || *slot != newer {
		t.Fatalf("coalescing slot must hold the NEWEST advance; want %x got %v", newer.Bytes(), slot)
	}

	// Release the guard and run the drain, as the in-flight publish would on
	// completion. The published root must converge to the newest advance.
	p.mu.Lock()
	p.publishing = false
	p.mu.Unlock()
	if _, err := p.publishPending(nil); err != nil {
		t.Fatalf("drain: %v", err)
	}
	curr, ok := p.Current()
	if !ok {
		t.Fatal("no published root after drain")
	}
	pd, _ := types.PublishedRootDataFromEntity(*curr)
	if pd.RootHash != newer {
		t.Fatalf("drain converged to a STALE root: want newer %x got %x", newer.Bytes(), pd.RootHash.Bytes())
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
