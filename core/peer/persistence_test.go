package peer

import (
	"sort"
	"testing"

	"go.entitychurch.org/entity-core-go/core/crypto"
	"go.entitychurch.org/entity-core-go/core/ecf"
	"go.entitychurch.org/entity-core-go/core/entity"
	"go.entitychurch.org/entity-core-go/core/hash"
	"go.entitychurch.org/entity-core-go/core/store"

	"github.com/fxamacker/cbor/v2"
)

// Persistence tests for the sqlite-backed peer.
//
// Group A pins state-stability invariants — tree state must be byte-stable
// across cold restarts so persistent stores don't accumulate stale entities
// or churn path bindings on every boot.
//
// Group B pins app-data lifecycle across restarts — the actual user
// expectation of "close it, reopen it, my data is still there".
//
// See docs/architecture/proposals/active/DESIGN-SQLITE-PERSISTENCE.md.

// openSqlitePeer opens a sqlite-backed peer at dbPath with the given keypair.
// Returns the peer and a closer that closes both the peer and the underlying
// SqliteStore. Test callers should defer the closer.
func openSqlitePeer(t *testing.T, dbPath string, kp crypto.Keypair) (*Peer, func()) {
	t.Helper()
	s, err := store.NewSqliteStore(dbPath)
	if err != nil {
		t.Fatalf("open sqlite at %s: %v", dbPath, err)
	}
	p, err := New(
		WithIdentity(kp),
		WithStore(s.ContentStore()),
		WithLocationIndex(s.LocationIndex()),
		WithCloseFunc(func() { _ = s.Close() }),
	)
	if err != nil {
		_ = s.Close()
		t.Fatalf("new peer: %v", err)
	}
	return p, func() { _ = p.Close() }
}

// snapshotTree returns a deterministic summary of the local peer's tree
// state: entity count + sorted path list. Two peers with identical state
// produce identical snapshots; any drift across restarts shows up here.
type treeSnapshot struct {
	entityCount int
	paths       []string
}

func snapshotTree(p *Peer) treeSnapshot {
	entries := p.LocationIndex().List("")
	paths := make([]string, len(entries))
	for i, e := range entries {
		paths[i] = e.Path
	}
	sort.Strings(paths)
	return treeSnapshot{
		entityCount: p.Store().(interface{ Len() int }).Len(),
		paths:       paths,
	}
}

func snapshotsEqual(a, b treeSnapshot) (bool, string) {
	if a.entityCount != b.entityCount {
		return false, "entity count drift"
	}
	if len(a.paths) != len(b.paths) {
		return false, "path-set size drift"
	}
	for i := range a.paths {
		if a.paths[i] != b.paths[i] {
			return false, "path drift at index " + a.paths[i] + " vs " + b.paths[i]
		}
	}
	return true, ""
}

// -----------------------------------------------------------------------------
// Group A — state-stability invariants
// -----------------------------------------------------------------------------

// TestPeerSqliteMultiRestartStable: N cold restarts with the same keypair
// must produce byte-identical tree state. This is the regression test for
// handler-grant determinism (DESIGN §4.1) and idempotent-Set (§4.2). If
// either drifts, this fails immediately.
func TestPeerSqliteMultiRestartStable(t *testing.T) {
	dir := t.TempDir()
	dbPath := dir + "/peer.db"

	kp, err := crypto.Generate()
	if err != nil {
		t.Fatal(err)
	}

	const restarts = 5

	var baseline treeSnapshot
	for i := 0; i <= restarts; i++ {
		p, closer := openSqlitePeer(t, dbPath, kp)
		got := snapshotTree(p)
		closer()

		if i == 0 {
			baseline = got
			t.Logf("baseline: entities=%d paths=%d", got.entityCount, len(got.paths))
			continue
		}
		if ok, why := snapshotsEqual(baseline, got); !ok {
			t.Errorf("restart %d: state drift (%s): baseline=%d/%d got=%d/%d",
				i, why,
				baseline.entityCount, len(baseline.paths),
				got.entityCount, len(got.paths))
		}
	}
}

// TestPeerSqliteIdentityInvariant: peer ID and identity-entity hash must be
// stable across restarts. If they drift, every peer who knew us before
// restart sees a "different" peer.
func TestPeerSqliteIdentityInvariant(t *testing.T) {
	dir := t.TempDir()
	dbPath := dir + "/peer.db"

	kp, err := crypto.Generate()
	if err != nil {
		t.Fatal(err)
	}

	p1, c1 := openSqlitePeer(t, dbPath, kp)
	id1 := p1.PeerID()
	h1 := p1.Identity().ContentHash
	c1()

	p2, c2 := openSqlitePeer(t, dbPath, kp)
	defer c2()
	if p2.PeerID() != id1 {
		t.Errorf("peer ID drift: %s → %s", id1, p2.PeerID())
	}
	if p2.Identity().ContentHash != h1 {
		t.Errorf("identity entity hash drift: %s → %s", h1, p2.Identity().ContentHash)
	}
}

// TestPeerSqliteHandlerGrantSurvivesRestart: handler-grant cap entity at
// system/capability/grants/system/tree has the same content hash before
// and after a sqlite-backed restart cycle. Companion to the in-memory
// TestHandlerGrantsAreDeterministic.
func TestPeerSqliteHandlerGrantSurvivesRestart(t *testing.T) {
	dir := t.TempDir()
	dbPath := dir + "/peer.db"

	kp, err := crypto.Generate()
	if err != nil {
		t.Fatal(err)
	}

	const grantPath = "system/capability/grants/system/tree"

	p1, c1 := openSqlitePeer(t, dbPath, kp)
	g1, ok := p1.LocationIndex().Get(grantPath)
	if !ok {
		t.Fatalf("grant missing on first peer at %s", grantPath)
	}
	c1()

	p2, c2 := openSqlitePeer(t, dbPath, kp)
	defer c2()
	g2, ok := p2.LocationIndex().Get(grantPath)
	if !ok {
		t.Fatalf("grant missing on restarted peer at %s", grantPath)
	}
	if g1 != g2 {
		t.Errorf("handler grant hash drifted across sqlite restart: %s → %s", g1, g2)
	}
}

// -----------------------------------------------------------------------------
// Group B — app-data lifecycle across restarts
// -----------------------------------------------------------------------------

// putAppEntity is a small helper: encode a string payload, store it, bind it
// at the given local-namespaced path, return the content hash.
func putAppEntity(t *testing.T, p *Peer, typ, path, payload string) hash.Hash {
	t.Helper()
	raw, err := ecf.Encode(payload)
	if err != nil {
		t.Fatalf("ecf encode: %v", err)
	}
	ent, err := entity.NewEntity(typ, cbor.RawMessage(raw))
	if err != nil {
		t.Fatalf("entity new: %v", err)
	}
	h, err := p.Store().Put(ent)
	if err != nil {
		t.Fatalf("store put: %v", err)
	}
	p.LocationIndex().Set(path, h)
	return h
}

// TestPeerSqliteWritesAccumulate: write across multiple restart sessions;
// every entity written in any prior session must be visible in the latest.
func TestPeerSqliteWritesAccumulate(t *testing.T) {
	dir := t.TempDir()
	dbPath := dir + "/peer.db"

	kp, err := crypto.Generate()
	if err != nil {
		t.Fatal(err)
	}

	type bind struct {
		path string
		hash hash.Hash
	}
	var bindings []bind

	// Three restart sessions, each writes one new entity.
	for i, payload := range []string{"alpha", "beta", "gamma"} {
		p, closer := openSqlitePeer(t, dbPath, kp)
		path := "app/data/" + payload
		h := putAppEntity(t, p, "test/app", path, payload)
		bindings = append(bindings, bind{path: path, hash: h})
		closer()
		t.Logf("session %d wrote %s = %s", i+1, path, h)
	}

	// Final session — verify all three writes are present.
	p, closer := openSqlitePeer(t, dbPath, kp)
	defer closer()
	for _, b := range bindings {
		got, ok := p.LocationIndex().Get(b.path)
		if !ok {
			t.Errorf("after restarts: binding lost at %s", b.path)
			continue
		}
		if got != b.hash {
			t.Errorf("after restarts: %s drifted: %s → %s", b.path, b.hash, got)
		}
		ent, ok := p.Store().Get(b.hash)
		if !ok {
			t.Errorf("after restarts: entity %s lost from store", b.hash)
			continue
		}
		if ent.Type != "test/app" {
			t.Errorf("entity type drift at %s: %q", b.path, ent.Type)
		}
	}
}

// TestPeerSqliteRemovesPersist: removes performed in one session must stay
// removed across restart. Writes don't resurrect from the dead.
func TestPeerSqliteRemovesPersist(t *testing.T) {
	dir := t.TempDir()
	dbPath := dir + "/peer.db"

	kp, err := crypto.Generate()
	if err != nil {
		t.Fatal(err)
	}

	// Session 1: write A.
	{
		p, closer := openSqlitePeer(t, dbPath, kp)
		putAppEntity(t, p, "test/app", "app/will-be-removed", "doomed")
		closer()
	}
	// Session 2: confirm present, remove.
	{
		p, closer := openSqlitePeer(t, dbPath, kp)
		if _, ok := p.LocationIndex().Get("app/will-be-removed"); !ok {
			t.Fatal("session 2: write didn't survive first restart")
		}
		if _, ok := p.LocationIndex().Remove("app/will-be-removed"); !ok {
			t.Fatal("remove returned false")
		}
		closer()
	}
	// Session 3: confirm gone.
	{
		p, closer := openSqlitePeer(t, dbPath, kp)
		defer closer()
		if _, ok := p.LocationIndex().Get("app/will-be-removed"); ok {
			t.Fatal("removed binding came back after restart")
		}
	}
}

// TestPeerSqliteOverwritePersists: overwriting a path with a new hash sticks
// across restart — the latest write wins, the prior binding is gone.
func TestPeerSqliteOverwritePersists(t *testing.T) {
	dir := t.TempDir()
	dbPath := dir + "/peer.db"

	kp, err := crypto.Generate()
	if err != nil {
		t.Fatal(err)
	}

	const path = "app/overwrite-me"

	var firstHash, secondHash hash.Hash
	{
		p, closer := openSqlitePeer(t, dbPath, kp)
		firstHash = putAppEntity(t, p, "test/app", path, "first")
		closer()
	}
	{
		p, closer := openSqlitePeer(t, dbPath, kp)
		secondHash = putAppEntity(t, p, "test/app", path, "second")
		closer()
	}
	if firstHash == secondHash {
		t.Fatalf("test setup: payloads chosen produce same hash %s", firstHash)
	}
	// Verify after restart: path → secondHash, and the second entity reads back.
	{
		p, closer := openSqlitePeer(t, dbPath, kp)
		defer closer()
		got, ok := p.LocationIndex().Get(path)
		if !ok {
			t.Fatal("binding lost")
		}
		if got != secondHash {
			t.Errorf("expected second hash %s, got %s", secondHash, got)
		}
		// First entity is still in the store (paths overwrite, content store
		// is content-addressed and append-only-by-default). Confirm at least
		// it's reachable; the *binding* points to the second.
		if !p.Store().Has(secondHash) {
			t.Fatal("second entity missing from store")
		}
	}
}
