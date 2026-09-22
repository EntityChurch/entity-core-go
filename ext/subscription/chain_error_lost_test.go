package subscription

import (
	"encoding/hex"
	"testing"

	"go.entitychurch.org/entity-core-go/core/crypto"
	"go.entitychurch.org/entity-core-go/core/ecf"
	"go.entitychurch.org/entity-core-go/core/hash"
	"go.entitychurch.org/entity-core-go/core/protocol"
	"go.entitychurch.org/entity-core-go/core/store"
	"go.entitychurch.org/entity-core-go/core/types"
)

// TestBindLostMarkerRecordsTargetPeerID is the teeth for workbench-go tracker
// row 17: the §3.10.6 TargetPeerID field was reserved and no binder populated
// it, so a consumer could say "a transfer failed" but not "a transfer to THAT
// machine failed" — the field that decides which of two computers to look at.
//
// Mutation witness: drop the TargetPeerID assignment in bindLostMarker and the
// foreign-peer assertion reds. The bare-URI control pins that a path with no
// peer segment leaves the field absent (never the local peer).
func TestBindLostMarkerRecordsTargetPeerID(t *testing.T) {
	cs := store.NewMemoryContentStore()
	li := store.NewMemoryLocationIndex()
	e := NewEngine(cs, li, nil)

	foreignKP, err := crypto.Generate()
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	foreign := string(foreignKP.PeerID())

	// A delivery aimed at a foreign peer records that peer.
	h := e.bindLostMarker("chain1", "sub1", "delivery_failed",
		"entity://"+foreign+"/system/inbox/network/x", 502, "remote_fetch_failed")
	if h.IsZero() {
		t.Fatal("bindLostMarker returned zero hash")
	}
	got := readMarker(t, cs, h)
	if got.TargetPeerID != foreign {
		t.Fatalf("TargetPeerID = %q, want the foreign peer %q", got.TargetPeerID, foreign)
	}

	// A bare handler path names no peer — the field stays absent (a consumer
	// says "unknown" rather than the local peer being invented).
	h2 := e.bindLostMarker("chain2", "sub2", "delivery_failed", "system/network", 404, "not_found")
	if got2 := readMarker(t, cs, h2); got2.TargetPeerID != "" {
		t.Fatalf("bare-path marker TargetPeerID = %q, want empty", got2.TargetPeerID)
	}
}

// TestBindLostMarkerSelfReaps is the teeth for row 12: the subscription binder
// bound markers and never swept, so a peer whose only marker source is
// subscription delivery accumulated them until an unrelated dispatch happened
// to reap. The other two binders self-reap at bind time; this one now does too.
//
// Mutation witness: remove the `e.maybeCollectMarkers()` call in bindLostMarker
// and the expired seeded marker survives the assertion below.
func TestBindLostMarkerSelfReaps(t *testing.T) {
	cs := store.NewMemoryContentStore()
	li := store.NewMemoryLocationIndex()
	e := NewEngine(cs, li, nil)

	// Seed an already-expired marker (origination timestamp 1ms — far older
	// than the 24h retention window) directly under the marker root.
	old, err := types.ChainErrorLostData{
		Reason: "delivery_failed", Timestamp: 1, ChainID: "old", StepIndex: "subOld",
	}.ToEntity()
	if err != nil {
		t.Fatalf("build old marker: %v", err)
	}
	oldHash, err := cs.Put(old)
	if err != nil {
		t.Fatalf("put old marker: %v", err)
	}
	oldPath := protocol.MarkerRoot + "lost/old/subOld/delivery_failed/" + hex.EncodeToString(oldHash.Bytes())
	if err := li.Set(oldPath, oldHash); err != nil {
		t.Fatalf("set old marker path: %v", err)
	}

	// A fresh bind triggers the throttled sweep (lastMarkerCollect is zero, so
	// the first bind always sweeps).
	newHash := e.bindLostMarker("chain1", "sub1", "delivery_failed", "system/network", 404, "not_found")
	if newHash.IsZero() {
		t.Fatal("bind returned zero hash")
	}

	// The expired marker is reaped; the fresh one (now-timestamped) survives.
	if _, ok := li.Get(oldPath); ok {
		t.Fatal("expired marker was NOT reaped — the subscription binder does not self-reap (row 12)")
	}
}

func readMarker(t *testing.T, cs store.ContentStore, h hash.Hash) types.ChainErrorLostData {
	t.Helper()
	ent, ok := cs.Get(h)
	if !ok {
		t.Fatalf("marker %s not in store", h)
	}
	var d types.ChainErrorLostData
	if err := ecf.Decode(ent.Data, &d); err != nil {
		t.Fatalf("decode marker: %v", err)
	}
	return d
}
