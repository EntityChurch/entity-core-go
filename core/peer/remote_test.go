package peer

import (
	"testing"

	"go.entitychurch.org/entity-core-go/core/ecf"
	"go.entitychurch.org/entity-core-go/core/entity"
	"go.entitychurch.org/entity-core-go/core/store"
	"go.entitychurch.org/entity-core-go/core/types"

	"github.com/fxamacker/cbor/v2"
)

// TestSortProfileEntriesD1 verifies D-1 selection rule: "primary" first,
// then remaining profile-ids in lexicographic order. Backend-native order
// of the input is irrelevant — selection must be deterministic across
// every LocationIndex impl.
//
// Per arch's Q2 ruling, profile-id is derived from the FINAL PATH SEGMENT
// (path.Base), not from a TrimPrefix against the caller-supplied prefix.
// This test confirms the rule holds for absolute paths (what
// NamespacedIndex.List actually returns) as well as bare relative ones.
// TestSortProfileEntriesD1_AbsolutePaths below pins the absolute case
// explicitly.
func TestSortProfileEntriesD1(t *testing.T) {
	prefix := "system/peer/transport/abcdef/"
	tests := []struct {
		name string
		in   []string // profile-ids (without prefix)
		want []string // expected order
	}{
		{
			name: "primary surfaces from middle",
			in:   []string{"zzz-backup", "cdn-mirror", "primary", "alpha"},
			want: []string{"primary", "alpha", "cdn-mirror", "zzz-backup"},
		},
		{
			name: "no primary — pure lex",
			in:   []string{"zzz-backup", "cdn-mirror", "alpha"},
			want: []string{"alpha", "cdn-mirror", "zzz-backup"},
		},
		{
			name: "only primary",
			in:   []string{"primary"},
			want: []string{"primary"},
		},
		{
			name: "already-ordered passes through",
			in:   []string{"primary", "a", "b"},
			want: []string{"primary", "a", "b"},
		},
		{
			name: "reverse-ordered gets sorted",
			in:   []string{"z", "primary", "a"},
			want: []string{"primary", "a", "z"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			entries := make([]store.LocationEntry, len(tt.in))
			for i, id := range tt.in {
				entries[i] = store.LocationEntry{Path: prefix + id}
			}
			sortProfileEntriesD1(entries, prefix)
			for i, want := range tt.want {
				gotID := entries[i].Path[len(prefix):]
				if gotID != want {
					t.Errorf("position %d: got %q, want %q (full result=%v)",
						i, gotID, want, paths(entries, prefix))
				}
			}
		})
	}
}

func paths(entries []store.LocationEntry, prefix string) []string {
	out := make([]string, len(entries))
	for i, e := range entries {
		out[i] = e.Path[len(prefix):]
	}
	return out
}

// TestEffectiveProfilePriority pins the Q1 default rule per arch §8.9:
// explicit Priority wins; absent Priority means "primary" → 0 and any
// other profile-id → 100.
func TestEffectiveProfilePriority(t *testing.T) {
	mkHTTP := func(priority *uint64) entity.Entity {
		data := types.HTTPProfileData{
			PeerID:        "p",
			TransportType: "http",
			Endpoint:      types.TransportEndpointURL{URL: "http://x/y"},
			SupportedOps:  []string{types.OpExecute},
			Priority:      priority,
		}
		raw, _ := ecf.Encode(data)
		ent, _ := entity.NewEntity(types.TypePeerTransportHTTP, cbor.RawMessage(raw))
		return ent
	}
	mkTCP := func(priority *uint64) entity.Entity {
		data := types.TCPProfileData{
			PeerID:        "p",
			TransportType: "tcp",
			Endpoint:      types.TransportEndpointURL{URL: "tcp://x:9"},
			SupportedOps:  []string{types.OpExecute},
			Priority:      priority,
		}
		raw, _ := ecf.Encode(data)
		ent, _ := entity.NewEntity(types.TypePeerTransportTCP, cbor.RawMessage(raw))
		return ent
	}
	p := func(v uint64) *uint64 { return &v }

	tests := []struct {
		name      string
		ent       entity.Entity
		profileID string
		want      uint64
	}{
		{name: "primary unset → 0", ent: mkTCP(nil), profileID: "primary", want: 0},
		{name: "other unset → 100", ent: mkHTTP(nil), profileID: "primary-http", want: 100},
		{name: "explicit on primary wins", ent: mkTCP(p(42)), profileID: "primary", want: 42},
		{name: "explicit zero on non-primary wins", ent: mkHTTP(p(0)), profileID: "cdn-mirror", want: 0},
		{name: "explicit 100 on primary wins", ent: mkTCP(p(100)), profileID: "primary", want: 100},
		{name: "explicit max on non-primary", ent: mkHTTP(p(65535)), profileID: "alpha", want: 65535},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := effectiveProfilePriority(tt.ent, tt.profileID)
			if got != tt.want {
				t.Errorf("effectivePriority(%s) = %d, want %d", tt.profileID, got, tt.want)
			}
		})
	}
}

// TestCollectProfileCandidates_PriorityWinsOverDefault pins the Q1
// selection rule end-to-end through collectProfileCandidates: an
// explicit low priority on a non-primary entry beats the reserved
// "primary"'s default (= 0 only because primary defaults so). Pre-Q1,
// "primary" always won; post-Q1 the lowest effective priority wins
// and lex is the tie-breaker.
func TestCollectProfileCandidates_PriorityWinsOverDefault(t *testing.T) {
	server := startPeer(t)
	client := startPeer(t)

	// Use a synthetic remote peer-id; we never dial it.
	syntheticID := server.PeerID() // any valid peer-id will do
	prefix := "system/peer/transport/" + string(syntheticID) + "/"

	// "primary" gets default priority 0; "cdn-mirror" gets explicit 0.
	// Tie-breaker is lex (cdn-mirror < primary alphabetically), so
	// cdn-mirror wins.
	mk := func(url string, priority *uint64) entity.Entity {
		data := types.HTTPProfileData{
			PeerID:        string(syntheticID),
			TransportType: "http",
			Endpoint:      types.TransportEndpointURL{URL: url},
			SupportedOps:  []string{types.OpExecute},
			Priority:      priority,
		}
		raw, _ := ecf.Encode(data)
		ent, _ := entity.NewEntity(types.TypePeerTransportHTTP, cbor.RawMessage(raw))
		return ent
	}
	zero := uint64(0)
	primaryEnt := mk("http://primary/", nil)              // default → 0
	cdnEnt := mk("http://cdn-mirror/", &zero)             // explicit 0
	hiPrioEnt := mk("http://hi/", func() *uint64 { v := uint64(50); return &v }())
	primaryHash, _ := client.Store().Put(primaryEnt)
	cdnHash, _ := client.Store().Put(cdnEnt)
	hiHash, _ := client.Store().Put(hiPrioEnt)
	if err := client.LocationIndex().Set(prefix+"primary", primaryHash); err != nil {
		t.Fatal(err)
	}
	if err := client.LocationIndex().Set(prefix+"cdn-mirror", cdnHash); err != nil {
		t.Fatal(err)
	}
	if err := client.LocationIndex().Set(prefix+"hi-prio", hiHash); err != nil {
		t.Fatal(err)
	}

	entries := client.LocationIndex().List(prefix)
	candidates := client.collectProfileCandidates(entries)

	if len(candidates) != 3 {
		t.Fatalf("got %d candidates, want 3", len(candidates))
	}
	wantOrder := []string{"cdn-mirror", "primary", "hi-prio"}
	for i, want := range wantOrder {
		if candidates[i].profileID != want {
			ids := make([]string, len(candidates))
			for j, c := range candidates {
				ids[j] = c.profileID
			}
			t.Errorf("position %d: got %q, want %q (full=%v)",
				i, candidates[i].profileID, want, ids)
		}
	}
}

// TestSortProfileEntriesD1_AbsolutePaths pins the arch Q2 ruling: profile-id
// is the FINAL PATH SEGMENT, not the result of a TrimPrefix against the
// caller's relative prefix. Production callers pass a relative prefix
// (system/peer/transport/{peer_id}/) but NamespacedIndex.List returns
// absolute paths (/{local_peer_id}/system/peer/transport/{peer_id}/{id}) —
// without the path.Base fix, the "primary" special case silently never
// fired in any real deployment because TrimPrefix never matched.
func TestSortProfileEntriesD1_AbsolutePaths(t *testing.T) {
	relPrefix := "system/peer/transport/abcdef/"
	absRoot := "/2KLocalPeerIDExample123/system/peer/transport/abcdef/"

	entries := []store.LocationEntry{
		{Path: absRoot + "zzz-backup"},
		{Path: absRoot + "cdn-mirror"},
		{Path: absRoot + "primary"},
		{Path: absRoot + "alpha"},
	}
	want := []string{"primary", "alpha", "cdn-mirror", "zzz-backup"}

	// The caller passes the same relative prefix it would in production
	// (the function ignores it post-Q2; we keep it in the API).
	sortProfileEntriesD1(entries, relPrefix)

	for i, w := range want {
		gotID := entries[i].Path[len(absRoot):]
		if gotID != w {
			t.Errorf("position %d: got %q, want %q (full result=%v)",
				i, gotID, w, entries)
		}
	}
}
