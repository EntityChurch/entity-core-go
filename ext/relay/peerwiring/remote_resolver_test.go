package peerwiring

import (
	"testing"

	"go.entitychurch.org/entity-core-go/core/types"
	"go.entitychurch.org/entity-core-go/ext/relay"
)

// fakeResolver returns a pre-canned (decl, ok) for a target peer, with a
// hit counter so chain-ordering tests can assert that later resolvers
// don't run after an earlier hit.
type fakeResolver struct {
	hits         int
	declarations map[string]types.InboxRelayData
}

func (f *fakeResolver) Resolve(dest string) (types.InboxRelayData, bool) {
	f.hits++
	d, ok := f.declarations[dest]
	return d, ok
}

var _ relay.InboxRelayResolver = (*fakeResolver)(nil)

func TestChain_FirstHitWins(t *testing.T) {
	wantNS := "registry-namespace"
	first := &fakeResolver{declarations: map[string]types.InboxRelayData{
		"dest1": {Relays: []types.InboxRelayEntry{{Relay: "B", Namespace: wantNS}}},
	}}
	second := &fakeResolver{declarations: map[string]types.InboxRelayData{
		"dest1": {Relays: []types.InboxRelayEntry{{Relay: "B", Namespace: "local-namespace"}}},
	}}

	got, ok := Chain(first, second).Resolve("dest1")
	if !ok {
		t.Fatal("chain returned no decl; expected first resolver to hit")
	}
	if got.Relays[0].Namespace != wantNS {
		t.Errorf("namespace = %q, want %q (first resolver should win)", got.Relays[0].Namespace, wantNS)
	}
	if first.hits != 1 {
		t.Errorf("first resolver hit %d times, want 1", first.hits)
	}
	if second.hits != 0 {
		t.Errorf("second resolver hit %d times, want 0 (short-circuit on first hit)", second.hits)
	}
}

func TestChain_FallsThroughOnMiss(t *testing.T) {
	wantNS := "local-namespace"
	first := &fakeResolver{declarations: map[string]types.InboxRelayData{}} // empty: misses
	second := &fakeResolver{declarations: map[string]types.InboxRelayData{
		"dest1": {Relays: []types.InboxRelayEntry{{Relay: "B", Namespace: wantNS}}},
	}}

	got, ok := Chain(first, second).Resolve("dest1")
	if !ok {
		t.Fatal("chain returned no decl; expected second resolver to hit")
	}
	if got.Relays[0].Namespace != wantNS {
		t.Errorf("namespace = %q, want %q", got.Relays[0].Namespace, wantNS)
	}
	if first.hits != 1 || second.hits != 1 {
		t.Errorf("hits = (%d, %d), want (1, 1)", first.hits, second.hits)
	}
}

func TestChain_EmptyReturnsNoDecl(t *testing.T) {
	if _, ok := Chain().Resolve("dest1"); ok {
		t.Error("empty chain returned a decl; expected false")
	}
}

func TestChain_AllMiss(t *testing.T) {
	first := &fakeResolver{declarations: map[string]types.InboxRelayData{}}
	second := &fakeResolver{declarations: map[string]types.InboxRelayData{}}
	if _, ok := Chain(first, second).Resolve("dest1"); ok {
		t.Error("all-miss chain returned a decl; expected false")
	}
	if first.hits != 1 || second.hits != 1 {
		t.Errorf("hits = (%d, %d), want (1, 1)", first.hits, second.hits)
	}
}

func TestChain_SkipsNil(t *testing.T) {
	wantNS := "ns"
	hit := &fakeResolver{declarations: map[string]types.InboxRelayData{
		"dest1": {Relays: []types.InboxRelayEntry{{Relay: "B", Namespace: wantNS}}},
	}}
	got, ok := Chain(nil, hit, nil).Resolve("dest1")
	if !ok {
		t.Fatal("expected hit through nil-padded chain")
	}
	if got.Relays[0].Namespace != wantNS {
		t.Errorf("namespace = %q, want %q", got.Relays[0].Namespace, wantNS)
	}
}

func TestRemoteResolver_NoRegistries_NoOp(t *testing.T) {
	// Sanity: with an empty registry list, Resolve must short-circuit to
	// (_, false) without dereferencing the (potentially nil) peer.
	r := &RemoteTreeInboxRelayResolver{}
	if _, ok := r.Resolve("dest1"); ok {
		t.Error("empty registry list returned a decl; expected false")
	}
}

func TestRemoteResolver_EmptyDest_NoOp(t *testing.T) {
	r := &RemoteTreeInboxRelayResolver{registryIDs: []string{"reg1"}}
	if _, ok := r.Resolve(""); ok {
		t.Error("empty destination returned a decl; expected false")
	}
}
