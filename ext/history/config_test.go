package history

import (
	"sort"
	"testing"

	"go.entitychurch.org/entity-core-go/core/types"
)

func TestCanonicalizePattern(t *testing.T) {
	pid := "peer123"
	tests := []struct {
		pattern string
		want    string
	}{
		{"project/*", "/" + pid + "/project/*"},
		{"/peerA/project/*", "/peerA/project/*"},
		{"*/project/*", "*/project/*"},
		{"*", "*"},
		{"docs/readme", "/" + pid + "/docs/readme"},
	}
	for _, tt := range tests {
		got := canonicalizePattern(tt.pattern, pid)
		if got != tt.want {
			t.Errorf("canonicalizePattern(%q, %q) = %q, want %q", tt.pattern, pid, got, tt.want)
		}
	}
}

func TestMatchHistoryPattern(t *testing.T) {
	tests := []struct {
		pattern string
		path    string
		want    bool
	}{
		// Exact match.
		{"/peerA/docs/readme", "/peerA/docs/readme", true},
		{"/peerA/docs/readme", "/peerA/docs/other", false},
		// Subtree wildcard.
		{"/peerA/project/*", "/peerA/project/file.txt", true},
		{"/peerA/project/*", "/peerA/project/sub/deep", true},
		{"/peerA/project/*", "/peerA/other/file.txt", false},
		// Full wildcard.
		{"*", "/peerA/anything", true},
		{"/*/*", "/peerA/anything", true},
		// Peer wildcard.
		{"*/project/*", "/peerA/project/file.txt", true},
		{"*/project/*", "/peerB/project/readme", true},
		{"*/project/*", "/peerA/other/file.txt", false},
		// Peer wildcard exact.
		{"*/readme", "/peerA/readme", true},
		{"*/readme", "/peerA/docs/readme", false},
	}
	for _, tt := range tests {
		got := matchHistoryPattern(tt.pattern, tt.path)
		if got != tt.want {
			t.Errorf("matchHistoryPattern(%q, %q) = %v, want %v", tt.pattern, tt.path, got, tt.want)
		}
	}
}

// entryOf builds a configEntry from a canonicalized pattern, as load() does.
func entryOf(canon string) configEntry {
	lit, depth := patternSpecificity(canon)
	return configEntry{canonicalizedPat: canon, literalSegs: lit, totalDepth: depth}
}

func TestPatternSpecificity(t *testing.T) {
	tests := []struct {
		a, b string
	}{
		// More literal segments = more specific.
		{"/peerA/project/*", "*"},
		{"/peerA/project/readme", "/peerA/project/*"},
		// Explicit peer > wildcard peer at same depth (key 1: explicit peer is literal).
		{"/peerA/project/*", "*/project/*"},
		// §6.2 worked pair: key 1 (literal count) outranks key 2 (depth). a/b/c/d
		// (4 literal, depth 4) beats a/*/c/*/e (3 literal, depth 5). A "2 per
		// literal, 1 per wildcard" scalar ties both at 8 and picks by store order.
		{"a/b/c/d", "a/*/c/*/e"},
	}
	for _, tt := range tests {
		if !moreSpecific(entryOf(tt.a), entryOf(tt.b)) {
			la, da := patternSpecificity(tt.a)
			lb, db := patternSpecificity(tt.b)
			t.Errorf("%q (lit=%d depth=%d) should outrank %q (lit=%d depth=%d)", tt.a, la, da, tt.b, lb, db)
		}
		// Antisymmetry — the reverse must not also hold (a total order).
		if moreSpecific(entryOf(tt.b), entryOf(tt.a)) {
			t.Errorf("ordering not antisymmetric: %q and %q both outrank each other", tt.a, tt.b)
		}
	}
}

// HIST-CONFIG-SPECIFICITY-1 (§6.2 v1.7, REQUIRED) — selection MUST NOT depend on
// enumeration order. Two configs both match one path; the more-specific one is
// selected regardless of the order they were listed into the cache. A peer that
// resolves ties by store order passes one order by luck and fails the other.
func TestConfigSelection_EnumerationOrderIndependent(t *testing.T) {
	// Both match /peerA/a/b/c/d; the exact pattern (5 literal, depth 5) outranks
	// the subtree (2 literal, depth 3). Distinguishable by MaxDepth.
	specificMax := uint64(99)
	generalMax := uint64(7)
	specific := configEntryFrom(types.HistoryConfigData{Pattern: "/peerA/a/b/c/d", Enabled: true, MaxDepth: &specificMax})
	general := configEntryFrom(types.HistoryConfigData{Pattern: "/peerA/a/*", Enabled: true, MaxDepth: &generalMax})

	for _, order := range [][]configEntry{{specific, general}, {general, specific}} {
		c := &configCache{entries: append([]configEntry(nil), order...)}
		sort.Slice(c.entries, func(i, j int) bool { return moreSpecific(c.entries[i], c.entries[j]) })
		got := c.find("/peerA/a/b/c/d")
		if got == nil {
			t.Fatalf("no config selected for a path both patterns match")
		}
		if got.MaxDepth == nil || *got.MaxDepth != specificMax {
			t.Errorf("insertion order %v: selected the wrong config (max_depth=%v, want the specific %d) — selection is enumeration-dependent", patternsOf(order), got.MaxDepth, specificMax)
		}
	}
}

// configEntryFrom mirrors load(): canonicalize the (already-absolute) pattern
// and compute its two keys.
func configEntryFrom(cfg types.HistoryConfigData) configEntry {
	canon := canonicalizePattern(cfg.Pattern, "peerA")
	lit, depth := patternSpecificity(canon)
	return configEntry{config: cfg, canonicalizedPat: canon, literalSegs: lit, totalDepth: depth}
}

func patternsOf(entries []configEntry) []string {
	out := make([]string, len(entries))
	for i, e := range entries {
		out[i] = e.canonicalizedPat
	}
	return out
}

// Key 3 (lexicographic byte order, lower wins) breaks a key-1/key-2 tie that
// keys 1–2 cannot: a/*/c and a/b/* are each 2 literal segments at depth 3.
func TestPatternSpecificity_Key3BreaksTie(t *testing.T) {
	a := entryOf("a/*/c")
	b := entryOf("a/b/*")
	if a.literalSegs != b.literalSegs || a.totalDepth != b.totalDepth {
		t.Fatalf("precondition: patterns should tie on keys 1-2 (a: %d/%d, b: %d/%d)", a.literalSegs, a.totalDepth, b.literalSegs, b.totalDepth)
	}
	// "a/*/c" < "a/b/*" lexicographically ('*' 0x2A < 'b' 0x62), so a wins, total.
	if !moreSpecific(a, b) || moreSpecific(b, a) {
		t.Errorf("key-3 tiebreak not total: expected %q < %q to decide", a.canonicalizedPat, b.canonicalizedPat)
	}
}
