package tree

import (
	"context"
	"testing"

	"go.entitychurch.org/entity-core-go/core/crypto"
	"go.entitychurch.org/entity-core-go/core/ecf"
	"go.entitychurch.org/entity-core-go/core/entity"
	"go.entitychurch.org/entity-core-go/core/handler"
	"go.entitychurch.org/entity-core-go/core/store"
	"go.entitychurch.org/entity-core-go/core/types"
)

// Teeth for the EXTENSION-TREE §8.2 per-entry read filter (rust routed the gap
// 2026-09-11: handleListing / handleExtract shipped every entry under a covered
// prefix without checking each entry against the caller capability). A listing
// returns only entries the cap grants `get`, its `count` reflects the filtered
// visible count, and an extract re-roots over the filtered bindings so the
// envelope never carries an entity the cap forbids.
//
// The cap covers the whole prefix (so the prefix-level check passes) but
// EXCLUDES one child — the only shape that reaches the per-entry filter, since a
// prefix the cap does not cover is denied outright before any expansion.

func filterHarness(t *testing.T) (*Handler, store.ContentStore, store.LocationIndex, crypto.PeerID, entity.Entity) {
	t.Helper()
	cs := store.NewMemoryContentStore()
	rawLI := store.NewMemoryLocationIndex()
	h := NewHandler()
	kp, err := crypto.Generate()
	if err != nil {
		t.Fatal(err)
	}
	// The granter identity MUST be in the store so ResolveGranterPeerID resolves
	// it (single-sig granter → peer_id derivation); otherwise the check fails
	// closed on granter resolution and the filter never runs.
	identity, err := kp.IdentityEntity()
	if err != nil {
		t.Fatal(err)
	}
	cs.Put(identity)
	li := store.NewNamespacedIndex(rawLI, string(kp.PeerID()))
	return h, cs, li, kp.PeerID(), identity
}

func capWithExclude(identity entity.Entity, include, exclude []string) entity.Entity {
	capData := types.CapabilityTokenData{
		Grants: []types.GrantEntry{{
			Handlers:   types.CapabilityScope{Include: []string{"system/tree"}},
			Resources:  types.CapabilityScope{Include: include, Exclude: exclude},
			Operations: types.CapabilityScope{Include: []string{"get"}},
		}},
		Granter:   types.SingleSigGranter(identity.ContentHash),
		Grantee:   identity.ContentHash,
		CreatedAt: 1000,
	}
	capEntity, _ := capData.ToEntity()
	return capEntity
}

func TestListing_FiltersExcludedEntriesAndCount(t *testing.T) {
	h, cs, li, pid, identity := filterHarness(t)

	pub := makeEntity(t, "test/doc", "public")
	sec := makeEntity(t, "test/doc", "secret")
	cs.Put(pub)
	cs.Put(sec)
	li.Set("local/files/a.txt", pub.ContentHash)
	li.Set("local/files/secret", sec.ContentHash)

	list := func(capEntity entity.Entity) types.ListingData {
		getEntity, _ := types.GetRequestData{}.ToEntity()
		req := &handler.Request{
			Path: "system/tree", Operation: "get", Params: getEntity,
			Context: &handler.HandlerContext{
				LocalPeerID:      pid,
				Store:            cs,
				LocationIndex:    li,
				HandlerPattern:   "system/tree",
				CallerCapability: capEntity,
				Resource:         &types.ResourceTarget{Targets: []string{"local/files/"}},
			},
		}
		resp, err := h.Handle(context.Background(), req)
		if err != nil {
			t.Fatal(err)
		}
		if resp.Status != 200 {
			t.Fatalf("listing status: got %d want 200", resp.Status)
		}
		var l types.ListingData
		if err := ecf.Decode(resp.Result.Data, &l); err != nil {
			t.Fatal(err)
		}
		return l
	}

	// Cap covers the prefix but excludes the `secret` child.
	excl := list(capWithExclude(identity, []string{"local/files/*"}, []string{"local/files/secret"}))
	if _, ok := excl.Entries["secret"]; ok {
		t.Fatal("excluded child `secret` must not appear in the listing")
	}
	if _, ok := excl.Entries["a.txt"]; !ok {
		t.Fatalf("in-scope child `a.txt` must appear (entries=%v)", keysOf(excl.Entries))
	}
	if excl.Count != 1 {
		t.Fatalf("count must reflect filtered visible entries: got %d want 1", excl.Count)
	}

	// Discriminating control: a broad cap with NO exclude shows BOTH children and
	// count 2 — proving the filter is not over-aggressive (not a hide-everything).
	broad := list(capWithExclude(identity, []string{"local/files/*"}, nil))
	if _, ok := broad.Entries["secret"]; !ok {
		t.Fatal("control: broad cap must show the `secret` child")
	}
	if _, ok := broad.Entries["a.txt"]; !ok {
		t.Fatal("control: broad cap must show the `a.txt` child")
	}
	if broad.Count != 2 {
		t.Fatalf("control: broad cap count got %d want 2", broad.Count)
	}
}

// snapshot must filter too (py routed 2026-09-12): §11 exempts diff from path
// checks, sound only while a snapshot cannot commit to bindings the caller may
// not see. A scoped snapshot's root must be the trie over the VISIBLE bindings
// only — otherwise snapshot+diff-against-empty leaks the excluded key and hash.
func TestSnapshot_FiltersExcludedBindingsFromRoot(t *testing.T) {
	h, cs, li, pid, identity := filterHarness(t)

	pub := makeEntity(t, "test/doc", "public-snap")
	sec := makeEntity(t, "test/doc", "secret-snap")
	cs.Put(pub)
	cs.Put(sec)
	li.Set("local/files/a.txt", pub.ContentHash)
	li.Set("local/files/secret", sec.ContentHash)

	snapshot := func(capEntity entity.Entity) types.SnapshotData {
		snapReq, _ := types.SnapshotRequestData{}.ToEntity()
		req := &handler.Request{
			Path: "system/tree", Operation: "snapshot", Params: snapReq,
			Context: &handler.HandlerContext{
				LocalPeerID:      pid,
				Store:            cs,
				LocationIndex:    li,
				HandlerPattern:   "system/tree",
				CallerCapability: capEntity,
				Resource:         &types.ResourceTarget{Targets: []string{"local/files/"}},
			},
		}
		resp, err := h.Handle(context.Background(), req)
		if err != nil {
			t.Fatal(err)
		}
		if resp.Status != 200 {
			t.Fatalf("snapshot status: got %d want 200", resp.Status)
		}
		var s types.SnapshotData
		if err := ecf.Decode(resp.Result.Data, &s); err != nil {
			t.Fatal(err)
		}
		return s
	}

	// Expected roots computed directly: visible-only vs both. The snapshot
	// rebuild trims to the relative key under the qualified prefix.
	rootVisible, _ := BuildTrie(cs, []Binding{{Path: "a.txt", Hash: pub.ContentHash}})
	rootBoth, _ := BuildTrie(cs, []Binding{
		{Path: "a.txt", Hash: pub.ContentHash},
		{Path: "secret", Hash: sec.ContentHash},
	})
	if rootVisible == rootBoth {
		t.Fatal("test precondition: visible-only and full roots must differ")
	}

	// Scoped cap (excludes `secret`) → snapshot root commits to a.txt only.
	scoped := snapshot(capWithExclude(identity, []string{"local/files/*"}, []string{"local/files/secret"}))
	if scoped.Root != rootVisible {
		t.Fatalf("scoped snapshot root must be the visible-only trie root; got %s want %s",
			scoped.Root, rootVisible)
	}
	// Control: broad cap → snapshot commits to both (proves the filter, not a
	// blanket drop, moved the root).
	broad := snapshot(capWithExclude(identity, []string{"local/files/*"}, nil))
	if broad.Root != rootBoth {
		t.Fatalf("broad snapshot root must be the full trie root; got %s want %s",
			broad.Root, rootBoth)
	}
}

func TestExtract_FiltersExcludedBindings(t *testing.T) {
	h, cs, li, pid, identity := filterHarness(t)

	pub := makeEntity(t, "test/doc", "public-extract")
	sec := makeEntity(t, "test/doc", "secret-extract")
	cs.Put(pub)
	cs.Put(sec)
	li.Set("local/files/a.txt", pub.ContentHash)
	li.Set("local/files/secret", sec.ContentHash)

	extract := func(capEntity entity.Entity) entity.Envelope {
		req := &handler.Request{
			Path: "system/tree", Operation: "extract", Params: entity.Entity{},
			Context: &handler.HandlerContext{
				LocalPeerID:      pid,
				Store:            cs,
				LocationIndex:    li,
				HandlerPattern:   "system/tree",
				CallerCapability: capEntity,
				Resource:         &types.ResourceTarget{Targets: []string{"local/files/"}},
			},
		}
		resp, err := h.Handle(context.Background(), req)
		if err != nil {
			t.Fatal(err)
		}
		if resp.Status != 200 {
			t.Fatalf("extract status: got %d want 200", resp.Status)
		}
		var env entity.Envelope
		if err := ecf.Decode(resp.Result.Data, &env); err != nil {
			t.Fatal(err)
		}
		return env
	}

	// Excluded binding's data entity MUST NOT ride in the envelope; the in-scope
	// one MUST. Filtering before BuildTrie is re-rooting (§6.2), so the envelope
	// stays complete against its own filtered root.
	env := extract(capWithExclude(identity, []string{"local/files/*"}, []string{"local/files/secret"}))
	if _, ok := env.Included[sec.ContentHash]; ok {
		t.Fatal("excluded binding's entity must not appear in the extract envelope")
	}
	if _, ok := env.Included[pub.ContentHash]; !ok {
		t.Fatal("in-scope binding's entity must appear in the extract envelope")
	}

	// Control: a broad cap carries BOTH data entities.
	broad := extract(capWithExclude(identity, []string{"local/files/*"}, nil))
	if _, ok := broad.Included[sec.ContentHash]; !ok {
		t.Fatal("control: broad cap must carry the secret binding's entity")
	}
	if _, ok := broad.Included[pub.ContentHash]; !ok {
		t.Fatal("control: broad cap must carry the public binding's entity")
	}
}
