package role

import (
	"strings"
	"testing"

	"github.com/fxamacker/cbor/v2"

	"go.entitychurch.org/entity-core-go/core/hash"
	"go.entitychurch.org/entity-core-go/core/store"
	"go.entitychurch.org/entity-core-go/core/types"
)

func u64(v uint64) *uint64 { return &v }

func TestEffectiveExpiresAt_MinDefined(t *testing.T) {
	cases := []struct {
		name           string
		parent, ttl, c *uint64
		want           *uint64
	}{
		{"all nil", nil, nil, nil, nil},
		{"only parent", u64(100), nil, nil, u64(100)},
		{"only ttl", nil, u64(50), nil, u64(50)},
		{"only caller", nil, nil, u64(75), u64(75)},
		{"caller smallest", u64(100), u64(75), u64(50), u64(50)},
		{"ttl smallest", u64(100), u64(50), u64(75), u64(50)},
		{"parent smallest", u64(50), u64(75), u64(100), u64(50)},
		{"two finite, one nil", nil, u64(50), u64(75), u64(50)},
		{"caller bound when others nil — §5.3 v1.7 typical case", nil, nil, u64(60), u64(60)},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := effectiveExpiresAt(tc.parent, tc.ttl, tc.c)
			switch {
			case got == nil && tc.want == nil:
				return
			case got == nil || tc.want == nil:
				t.Fatalf("got %v, want %v", got, tc.want)
			case *got != *tc.want:
				t.Fatalf("got %d, want %d", *got, *tc.want)
			}
		})
	}
}

func TestRoleMetadataTTL(t *testing.T) {
	t.Run("nil metadata", func(t *testing.T) {
		if got := roleMetadataTTL(nil); got != nil {
			t.Errorf("expected nil for nil metadata, got %v", got)
		}
	})
	t.Run("empty map", func(t *testing.T) {
		raw, _ := cbor.Marshal(map[string]any{})
		if got := roleMetadataTTL(raw); got != nil {
			t.Errorf("expected nil for empty metadata, got %v", got)
		}
	})
	t.Run("ttl present", func(t *testing.T) {
		raw, _ := cbor.Marshal(map[string]any{"ttl": uint64(3600000)})
		got := roleMetadataTTL(raw)
		if got == nil || *got != 3600000 {
			t.Errorf("expected 3600000, got %v", got)
		}
	})
	t.Run("ttl with other fields", func(t *testing.T) {
		raw, _ := cbor.Marshal(map[string]any{"ttl": uint64(60000), "purpose": "test"})
		got := roleMetadataTTL(raw)
		if got == nil || *got != 60000 {
			t.Errorf("expected 60000, got %v", got)
		}
	})
	t.Run("garbage metadata returns nil", func(t *testing.T) {
		if got := roleMetadataTTL([]byte{0xff, 0xff, 0xff}); got != nil {
			t.Errorf("expected nil for garbage, got %v", got)
		}
	})
}

func TestResolveTemplates(t *testing.T) {
	g := types.GrantEntry{
		Handlers: types.CapabilityScope{Include: []string{"system/tree"}},
		Resources: types.CapabilityScope{
			Include: []string{"shared/{context}/*", "system/role/{context}/*"},
			Exclude: []string{"shared/{context}/secret"},
		},
		Operations: types.CapabilityScope{Include: []string{"get", "put"}},
	}
	peer := makeFakeHash(0xab)
	got := resolveTemplates(g, "group/team-alpha", peer)
	if len(got.Resources.Include) != 2 {
		t.Fatalf("expected 2 include entries, got %d", len(got.Resources.Include))
	}
	if got.Resources.Include[0] != "shared/group/team-alpha/*" {
		t.Errorf("include[0] = %q, want %q", got.Resources.Include[0], "shared/group/team-alpha/*")
	}
	if got.Resources.Include[1] != "system/role/group/team-alpha/*" {
		t.Errorf("include[1] = %q", got.Resources.Include[1])
	}
	if got.Resources.Exclude[0] != "shared/group/team-alpha/secret" {
		t.Errorf("exclude[0] = %q", got.Resources.Exclude[0])
	}
	if got.Handlers.Include[0] != "system/tree" {
		t.Errorf("handlers preserved: %v", got.Handlers.Include)
	}
}

func TestResolveTemplates_PeerIDSubstitution(t *testing.T) {
	g := types.GrantEntry{
		Resources: types.CapabilityScope{
			Include: []string{"private/{peer_id}/*"},
		},
	}
	peer := makeFakeHash(0xcd)
	got := resolveTemplates(g, "ctx", peer)
	wantHex := HashHex(peer)
	want := "private/" + wantHex + "/*"
	if got.Resources.Include[0] != want {
		t.Errorf("peer_id sub failed: got %q, want %q", got.Resources.Include[0], want)
	}
	// Per v1.6 SI-1, the substitution must be lowercase hex of the
	// system/hash (66 chars starting with 00), NOT a Base58 PeerID.
	if !strings.HasPrefix(wantHex, "00") {
		t.Errorf("expected sha256 hex starting with 00, got %q", wantHex)
	}
	if len(wantHex) != 66 {
		t.Errorf("expected 66-char hex (33 bytes), got %d chars", len(wantHex))
	}
}

func TestResolveTemplates_NoTemplates(t *testing.T) {
	g := types.GrantEntry{
		Resources: types.CapabilityScope{Include: []string{"public/*"}},
	}
	got := resolveTemplates(g, "ctx", makeFakeHash(0x01))
	if got.Resources.Include[0] != "public/*" {
		t.Errorf("untemplated path mutated: %q", got.Resources.Include[0])
	}
}

func TestResolveGrants_DeepCopy(t *testing.T) {
	in := []types.GrantEntry{{
		Resources: types.CapabilityScope{Include: []string{"shared/{context}/*"}},
	}}
	_ = resolveGrants(in, "g1", makeFakeHash(0x02))
	if in[0].Resources.Include[0] != "shared/{context}/*" {
		t.Errorf("input mutated: %q", in[0].Resources.Include[0])
	}
}

func TestIsExcluded(t *testing.T) {
	li := store.NewMemoryLocationIndex()
	peer := makeFakeHash(0x10)
	if isExcluded(li, "admin", peer) {
		t.Error("empty tree: must not be excluded")
	}
	dummy := makeFakeHash(0x42)
	li.Set(ExclusionPath("admin", peer), dummy)
	if !isExcluded(li, "admin", peer) {
		t.Error("after binding exclusion: must be excluded")
	}
	other := makeFakeHash(0x20)
	if isExcluded(li, "admin", other) {
		t.Error("non-bound peer must not be excluded")
	}
	if isExcluded(li, "service/api", peer) {
		t.Error("different context must not be excluded")
	}
}

func TestHashHexRoundTrip(t *testing.T) {
	h := makeFakeHash(0x55)
	hex := HashHex(h)
	if len(hex) != 66 {
		t.Errorf("hex length = %d, want 66 (33 bytes)", len(hex))
	}
	parsed, ok := HashFromHex(hex)
	if !ok {
		t.Fatalf("HashFromHex failed for %q", hex)
	}
	if parsed != h {
		t.Errorf("round-trip mismatch: %v -> %q -> %v", h, hex, parsed)
	}
}

func TestHashFromHex_Invalid(t *testing.T) {
	if _, ok := HashFromHex("not-hex"); ok {
		t.Error("expected failure on non-hex string")
	}
	if _, ok := HashFromHex("00ff"); ok {
		t.Error("expected failure on too-short hex")
	}
	if _, ok := HashFromHex(""); ok {
		t.Error("expected failure on empty string")
	}
}

// makeFakeHash produces a deterministic 33-byte hash with a single byte
// marker for tests. The first byte is the SHA-256 algorithm code (0x00);
// the remaining 32 bytes are filled with the marker byte.
func makeFakeHash(b byte) hash.Hash {
	bs := make([]byte, 33)
	bs[0] = hash.AlgorithmSHA256
	for i := 1; i < 33; i++ {
		bs[i] = b
	}
	out, _ := hash.FromBytes(bs)
	return out
}
