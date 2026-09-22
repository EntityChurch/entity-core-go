package network

import (
	"testing"

	"go.entitychurch.org/entity-core-go/core/crypto"
	"go.entitychurch.org/entity-core-go/core/entity"
	"go.entitychurch.org/entity-core-go/core/store"
)

// TestRecoverSessionFromTreeResidentGraph is the teeth for workbench-go row 11:
// after a restart the in-memory session map is empty while the durable §4.1
// graph (the backoff continuation, on-disconnect/on-reconnect continuations)
// survives in the tree. recoverSession must rebuild the session from that
// evidence rather than return nil — which is what made handleReconnect /
// handleRestoreSubscriptions 404 into a restored continuation and bind a
// permanent lost marker per peer-status transition.
//
// Mutation witness: make recoverSession delegate to getSession (no tree
// rebuild) and the "graph present" case returns nil (the storm reopens).
func TestRecoverSessionFromTreeResidentGraph(t *testing.T) {
	kp, err := crypto.Generate()
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	peerID := kp.PeerID()

	li := store.NewMemoryLocationIndex()
	h := NewHandler()

	// No session in memory, no graph in tree → genuinely no relationship.
	if s := h.recoverSession(peerID, li); s != nil {
		t.Fatal("recoverSession must return nil when neither the map nor the tree has a relationship")
	}

	// Seed a tree-resident graph: a backoff continuation binding at the
	// peer-keyed managed path. (Any entity at that path is evidence of a prior
	// maintain relationship; recoverSession keys on presence, not content.)
	marker := entity.Entity{Type: "system/continuation"}
	if err := li.Set(backoffPath(peerID), marker.ContentHash); err != nil {
		t.Fatalf("seed backoff graph: %v", err)
	}

	// Now the map is still empty but the tree has the graph → recover it.
	s := h.recoverSession(peerID, li)
	if s == nil {
		t.Fatal("recoverSession must rebuild a session from the tree-resident graph (row 11 — else the marker storm reopens after restart)")
	}
	if !s.graphInstalled {
		t.Fatal("a recovered session must be marked graphInstalled so the reconnect path does not create duplicate lifecycle subscriptions")
	}

	// Idempotent: a second call returns the same session, not a duplicate.
	if s2 := h.recoverSession(peerID, li); s2 != s {
		t.Fatal("recoverSession must be idempotent — a second call returned a different session")
	}
}

// TestHasTreeResidentGraph pins the three durable-graph paths that count as a
// prior relationship.
func TestHasTreeResidentGraph(t *testing.T) {
	kp, _ := crypto.Generate()
	peerID := kp.PeerID()
	h := NewHandler()

	li := store.NewMemoryLocationIndex()
	if h.hasTreeResidentGraph(li, peerID) {
		t.Fatal("empty tree must report no graph")
	}
	for _, path := range []string{onDisconnectPath(peerID), onReconnectPath(peerID), backoffPath(peerID)} {
		fresh := store.NewMemoryLocationIndex()
		_ = fresh.Set(path, entity.Entity{Type: "system/continuation"}.ContentHash)
		if !h.hasTreeResidentGraph(fresh, peerID) {
			t.Fatalf("a binding at %s must count as a tree-resident graph", path)
		}
	}
}
