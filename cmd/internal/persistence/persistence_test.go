// Package persistence holds in-process restart-survival tests for the
// sqlite-backed peer with extension wiring. They live here (cmd/internal/...)
// because they need to import both core/peer and ext/* — core/peer cannot
// import ext/* without creating a cycle.
//
// See docs/architecture/proposals/active/DESIGN-SQLITE-PERSISTENCE.md
// Group C tests (extension index rebuild correctness).
package persistence

import (
	"path/filepath"
	"testing"

	"go.entitychurch.org/entity-core-go/core/crypto"
	"go.entitychurch.org/entity-core-go/core/ecf"
	"go.entitychurch.org/entity-core-go/core/entity"
	"go.entitychurch.org/entity-core-go/core/hash"
	"go.entitychurch.org/entity-core-go/core/peer"
	"go.entitychurch.org/entity-core-go/core/store"
	"go.entitychurch.org/entity-core-go/core/types"

	"go.entitychurch.org/entity-core-go/ext/attestation"
	"go.entitychurch.org/entity-core-go/ext/query"
	"go.entitychurch.org/entity-core-go/ext/subscription"

	"github.com/fxamacker/cbor/v2"
)

// peerWithExtensions builds a sqlite-backed peer at dbPath with the
// extension wiring under test attached. The test-defined attestation handler
// and query maintainer are returned so tests can call their post-construction
// `Load()`/`Rebuild()` methods (matching what cmd/entity-peer/main.go does).
type extensionPeer struct {
	p             *peer.Peer
	attH          *attestation.Handler
	queryMaintain *query.IndexMaintainer
	subEngine     *subscription.Engine
	closeFn       func()
}

func openExtensionPeer(t *testing.T, dbPath string, kp crypto.Keypair) *extensionPeer {
	t.Helper()

	s, err := store.NewSqliteStore(dbPath)
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}

	cs := s.ContentStore()
	li := s.LocationIndex()

	queryMaintain := query.NewIndexMaintainer(cs)
	queryHandler := query.NewHandler(
		queryMaintain.TypeIndex(),
		queryMaintain.ReverseHashIndex(),
		queryMaintain.PathLinkIndex(),
		cs,
	)
	attH := attestation.NewHandler()
	subEngine := subscription.NewEngine(cs, li, nil)

	p, err := peer.New(
		peer.WithIdentity(kp),
		peer.WithStore(cs),
		peer.WithLocationIndex(li),
		peer.WithCloseFunc(func() { _ = s.Close() }),
		peer.WithNamedSyncHook("query/index-maintainer", queryMaintain.OnTreeChange),
		peer.WithNamedSyncHook("attestation/index-maintainer", attH.OnTreeChange),
		peer.WithNamedSyncHook("subscription/notification", subEngine.OnTreeChange),
		peer.WithHandler("system/query", queryHandler),
		peer.WithHandler("system/attestation", attH),
		peer.WithHandler("system/subscription", subscription.NewHandler(subEngine)),
	)
	if err != nil {
		_ = s.Close()
		t.Fatalf("new peer: %v", err)
	}

	// Post-construction wiring — same sequence as cmd/entity-peer/main.go.
	attH.SetupStore(p.Store(), p.LocationIndex(), p.PeerID())
	attH.Load()
	queryMaintain.Rebuild(p.LocationIndex())
	subEngine.SetLocationIndex(p.LocationIndex())
	subEngine.Load()

	return &extensionPeer{
		p:             p,
		attH:          attH,
		queryMaintain: queryMaintain,
		subEngine:     subEngine,
		closeFn:       func() { _ = p.Close() },
	}
}

// putAppEntity stores a payload string at the given path with the given type.
func putAppEntity(t *testing.T, p *peer.Peer, typ, path, payload string) {
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
}

// -----------------------------------------------------------------------------
// C: Attestation Load() rebuilds the in-memory graph after restart
// -----------------------------------------------------------------------------

// TestSqliteAttestationLoadAfterRestart writes attestation entities through
// session 1, closes, and verifies session 2's `attH.Load()` re-populates the
// in-memory `Index` so `FindByAttesting` returns the prior writes.
//
// This is the regression test for DESIGN §4.3: the attestation index is
// hydrated only via OnTreeChange at runtime, so a persistent-storage cold
// start would leave it empty without `Load()`.
func TestSqliteAttestationLoadAfterRestart(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "peer.db")

	kp, err := crypto.Generate()
	if err != nil {
		t.Fatal(err)
	}

	// Session 1: write two attestations through the local handler path.
	// Bind them at canonical attestation tree paths so session 2's Load()
	// will find them via li.List("").
	{
		ep := openExtensionPeer(t, dbPath, kp)
		// Build attestation entities by hand — handler-issuance has signature
		// requirements we don't need for index correctness. The Index only
		// requires (hash, AttestationData).
		attesting := ep.p.Identity().ContentHash
		attested := makeFakeIdentityHash(0xAA)
		// Encode kind as the well-known property — same shape attestation/index_test.go uses.
		kindRaw, err := ecf.Encode("test/binding")
		if err != nil {
			t.Fatalf("encode kind: %v", err)
		}
		att := types.AttestationData{
			Attesting:  attesting,
			Attested:   attested,
			Properties: map[string]cbor.RawMessage{"kind": cbor.RawMessage(kindRaw)},
		}
		ent, err := att.ToEntity()
		if err != nil {
			t.Fatalf("att toEntity: %v", err)
		}
		h, err := ep.p.Store().Put(ent)
		if err != nil {
			t.Fatalf("store put: %v", err)
		}
		ep.p.LocationIndex().Set("system/attestation/binding/sample", h)

		// Pre-restart sanity: index already has it (added via OnTreeChange).
		if got := ep.attH.Index().FindByAttesting(attesting); len(got) != 1 {
			t.Fatalf("session 1: expected 1 attestation pre-restart, got %d", len(got))
		}
		ep.closeFn()
	}

	// Session 2: open fresh peer at same path. Phase 2 calls attH.Load()
	// during construction (mirrored in openExtensionPeer); index must be
	// repopulated from the persisted tree.
	{
		ep := openExtensionPeer(t, dbPath, kp)
		defer ep.closeFn()

		attesting := ep.p.Identity().ContentHash
		got := ep.attH.Index().FindByAttesting(attesting)
		if len(got) != 1 {
			t.Fatalf("session 2 (post-restart Load): FindByAttesting got %d, want 1", len(got))
		}
		if k := ep.attH.Index().FindByKind("test/binding"); len(k) != 1 {
			t.Fatalf("session 2: FindByKind got %d, want 1", len(k))
		}
	}
}

// -----------------------------------------------------------------------------
// C: Query Rebuild() repopulates type/path indexes after restart
// -----------------------------------------------------------------------------

// TestSqliteQueryRebuildAfterRestart writes typed entities via session 1,
// closes, opens session 2 (which calls Rebuild), and verifies the query
// type-index returns the prior writes — i.e. Rebuild correctly reconstructs
// from persisted state. Companion to the attestation test above.
func TestSqliteQueryRebuildAfterRestart(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "peer.db")

	kp, err := crypto.Generate()
	if err != nil {
		t.Fatal(err)
	}

	const customType = "app/widget"

	// Session 1: write three "app/widget" entities at distinct paths.
	{
		ep := openExtensionPeer(t, dbPath, kp)
		for _, payload := range []string{"alpha", "beta", "gamma"} {
			putAppEntity(t, ep.p, customType, "app/widgets/"+payload, payload)
		}
		// Pre-restart sanity.
		got := ep.queryMaintain.TypeIndex().Lookup(customType)
		if len(got) != 3 {
			t.Fatalf("session 1: type index Lookup got %d, want 3", len(got))
		}
		ep.closeFn()
	}

	// Session 2: cold start, Rebuild called inside openExtensionPeer.
	{
		ep := openExtensionPeer(t, dbPath, kp)
		defer ep.closeFn()
		got := ep.queryMaintain.TypeIndex().Lookup(customType)
		if len(got) != 3 {
			t.Fatalf("session 2 (post-restart Rebuild): Lookup got %d, want 3", len(got))
		}
	}
}

// -----------------------------------------------------------------------------
// C: Subscription engine reloads registrations from tree after restart
// -----------------------------------------------------------------------------

// TestSqliteSubscriptionLoadAfterRestart writes subscription entities into
// the tree (as the handler would on subscribe), closes, and verifies that
// after restart the engine has them in its routing index — matchSubscriptions
// finds them and the engine.SubscriberCountForPrefix reflects the registered
// pattern.
//
// Without engine.Load() this test fails: subscription entities are in the
// tree but the engine is empty after restart, so deliveries silently stop.
func TestSqliteSubscriptionLoadAfterRestart(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "peer.db")

	kp, err := crypto.Generate()
	if err != nil {
		t.Fatal(err)
	}

	const subID = "sub-test-001"
	const pattern = "/peer/data/*"

	// Session 1: write a subscription entity directly into the tree (the
	// handler does the same via TreeSet on subscribe).
	{
		ep := openExtensionPeer(t, dbPath, kp)
		sub := types.SubscriptionData{
			SubscriptionID:     subID,
			SubscriberIdentity: ep.p.Identity().ContentHash,
			Pattern:            pattern,
			DeliverURI:         "entity:///peer/cb",
			CreatedAt:          1,
		}
		ent, err := sub.ToEntity()
		if err != nil {
			t.Fatalf("sub toEntity: %v", err)
		}
		h, err := ep.p.Store().Put(ent)
		if err != nil {
			t.Fatalf("store put: %v", err)
		}
		ep.p.LocationIndex().Set("system/subscription/"+subID, h)

		// Pre-restart: engine still doesn't know about this entity (it was
		// written directly, not via the handler). The engine.Load() call in
		// openExtensionPeer ran before the entity was written, so the index
		// is empty until we trigger via OnTreeChange. That's expected —
		// OnTreeChange would have routed the create event to engine.Register.
		// For this test we don't verify pre-restart state; we verify the
		// post-restart load.
		ep.closeFn()
	}

	// Session 2: cold start. engine.Load() fires inside openExtensionPeer
	// and rebuilds from persisted system/subscription/* entries.
	{
		ep := openExtensionPeer(t, dbPath, kp)
		defer ep.closeFn()
		count := ep.subEngine.SubscriberCountForPrefix(pattern)
		if count != 1 {
			t.Fatalf("post-restart subscriber count for %q: got %d, want 1", pattern, count)
		}
	}
}

// -----------------------------------------------------------------------------
// helpers
// -----------------------------------------------------------------------------

// makeFakeIdentityHash returns a deterministic hash.Hash to stand in for an
// identity entity hash. Tests don't need the real identity entity in the
// store for index correctness — the Index works on (attHash, AttestationData)
// regardless of whether the referenced entities exist.
func makeFakeIdentityHash(seed byte) hash.Hash {
	var h hash.Hash
	h.Algorithm = hash.AlgorithmSHA256
	h.Digest[0] = seed
	return h
}
