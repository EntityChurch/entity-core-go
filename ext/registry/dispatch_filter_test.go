package registry

import (
	"testing"

	"go.entitychurch.org/entity-core-go/core/crypto"
	"go.entitychurch.org/entity-core-go/core/handler"
	"go.entitychurch.org/entity-core-go/core/store"
	"go.entitychurch.org/entity-core-go/core/types"
)

// mockBackend is a resolver-chain backend that always resolves the queried
// name to a fixed peer-id — enough to observe whether the dispatch filter
// let the chain reach it.
type mockBackend struct {
	kind string
	id   string
}

func (m mockBackend) Kind() string { return m.kind }
func (m mockBackend) ID() string   { return m.id }
func (m mockBackend) Resolve(_ *handler.HandlerContext, name string, _ *uint64) (types.ResolveResultData, error) {
	return types.ResolveResultData{
		Status: types.ResolutionStatusResolved,
		PeerID: "resolved-by-" + m.kind,
	}, nil
}

func newFilterHctx(t *testing.T) *handler.HandlerContext {
	t.Helper()
	kp, err := crypto.Generate()
	if err != nil {
		t.Fatalf("generate peer: %v", err)
	}
	peer := kp.PeerID()
	return &handler.HandlerContext{
		Store:         store.NewMemoryContentStore(),
		LocationIndex: store.NewNamespacedIndex(store.NewMemoryLocationIndex(), string(peer)),
		LocalPeerID:   peer,
	}
}

func writeResolverConfig(t *testing.T, hctx *handler.HandlerContext, cfg types.ResolverConfigData) {
	t.Helper()
	ent, err := cfg.ToEntity()
	if err != nil {
		t.Fatalf("resolver-config ToEntity: %v", err)
	}
	h, err := hctx.Store.Put(ent)
	if err != nil {
		t.Fatalf("store resolver-config: %v", err)
	}
	if err := hctx.LocationIndex.Set(types.ResolverConfigStoragePath, h); err != nil {
		t.Fatalf("index resolver-config: %v", err)
	}
}

// TestDispatchFilterEligibilityIsPureFunctionOfName is the teeth for the
// §4.1 step 2 filter ruling [REGISTRY 1.14]: eligibility is the UNION of
// backend_kinds over the rules whose pattern matches the name, and a name
// matching NO rule yields the EMPTY set → chain_exhausted (fail-closed) —
// NOT an unfiltered chain.
//
// The TEETH row is "no rule matches the name": under the withdrawn `any`
// guard, a name matching no entry left `any=false`, the narrowing was
// skipped, and the chain fell through UNFILTERED and resolved. This test
// asserts chain_exhausted there, so it goes RED against that code. The other
// rows are regression guardrails — the "kind absent from the chain" mirror
// case already narrowed to empty under the old guard (its rule DID match, so
// `any=true`); it is kept to hold that invariant, not as a flip.
func TestDispatchFilterEligibilityIsPureFunctionOfName(t *testing.T) {
	chain := []types.ResolverChainEntry{
		{BackendKind: types.BackendKindLocalName, BackendID: "local", Priority: 0},
	}
	cases := []struct {
		name       string
		dispatch   []types.DispatchEntry
		query      string
		wantStatus string
		note       string
	}{
		{
			name:       "no rule matches the name -> empty set -> chain_exhausted",
			dispatch:   []types.DispatchEntry{{Pattern: "*.eth", BackendKinds: []string{types.BackendKindLocalName}}},
			query:      "alice", // matches neither "*.eth"
			wantStatus: types.ResolutionStatusChainExhausted,
			note:       "unmatched name is NOT 'no filtering' — the eligible set is empty (the flipped branch)",
		},
		{
			name:       "a rule matches and names local-name -> resolves",
			dispatch:   []types.DispatchEntry{{Pattern: "*", BackendKinds: []string{types.BackendKindLocalName}}},
			query:      "alice",
			wantStatus: types.ResolutionStatusResolved,
			note:       "catch-all names local-name; the one backend in the chain is eligible",
		},
		{
			name:       "matched rule names a kind absent from the chain -> chain_exhausted",
			dispatch:   []types.DispatchEntry{{Pattern: "*", BackendKinds: []string{types.BackendKindDIDWeb}}},
			query:      "alice",
			wantStatus: types.ResolutionStatusChainExhausted,
			note:       "eligible={did-web}; the chain holds only local-name -> narrows to empty (mirror case, §4.1a)",
		},
		{
			name:       "absent dispatch list disables the filter -> resolves",
			dispatch:   nil,
			query:      "alice",
			wantStatus: types.ResolutionStatusResolved,
			note:       "the ONLY place 'no filtering' is correct: absent/empty dispatch admits all kinds",
		},
		{
			name: "eligibility is the UNION over matching rules, order-free",
			dispatch: []types.DispatchEntry{
				{Pattern: "*.eth", BackendKinds: []string{types.BackendKindDIDWeb}},
				{Pattern: "*", BackendKinds: []string{types.BackendKindLocalName}},
			},
			query:      "alice",
			wantStatus: types.ResolutionStatusResolved,
			note:       "'*' contributes local-name to the union; '*.eth' does not match — still resolves",
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			h := NewHandler()
			h.RegisterBackend(mockBackend{kind: types.BackendKindLocalName, id: "local"})
			hctx := newFilterHctx(t)
			writeResolverConfig(t, hctx, types.ResolverConfigData{
				ResolverChain:      chain,
				NameFormatDispatch: c.dispatch,
			})
			got, _ := h.Resolve(hctx, c.query, false)
			if got.Status != c.wantStatus {
				t.Errorf("Resolve(%q) status = %q, want %q — %s",
					c.query, got.Status, c.wantStatus, c.note)
			}
		})
	}
}
