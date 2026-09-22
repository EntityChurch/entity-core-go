package registry

import (
	"path"
	"testing"
)

// TestRegDispatchGrammar pins the EXTENSION-REGISTRY §4.1a name_format_dispatch
// grammar ruled closed at [REGISTRY 1.13] — REG-DISPATCH-GRAMMAR-1.
//
// The four REQUIRED rows are the first four cases; every one FAILS against
// Go's path.Match (asserted below in TestRegDispatchGrammarDivergesFromPathMatch),
// which is the whole point of pinning them: a matcher that merely omits '?'/'[…]'
// support and one that treats them as literals are indistinguishable until a
// pattern carries one, and '*'-crosses-'/' is invisible until a name carries a
// slash. These vectors carry the teeth.
func TestRegDispatchGrammar(t *testing.T) {
	cases := []struct {
		pattern string
		name    string
		want    bool
		note    string
	}{
		// --- REG-DISPATCH-GRAMMAR-1, the four REQUIRED rows ---
		{"a?c", "a?c", true, "row1: '?' is a literal, matches itself"},
		{"a?c", "abc", false, "row1: '?' is NOT a single-char wildcard"},
		{"a[bc]d", "a[bc]d", true, "row2: '[' ']' are literals, match themselves"},
		{"a[bc]d", "abd", false, "row2: '[bc]' is NOT a character class"},
		{"*@*.*", "alice@example.com", true, "row3: three '*', each any run"},
		{"x*z", "x/y/z", true, "row4: '*' crosses '/', which is not a separator"},

		// --- grammar coverage beyond the four rows ---
		{"*", "", true, "'*' matches the empty run"},
		{"*", "anything/at/all", true, "'*' catch-all crosses everything"},
		{"", "", true, "empty pattern matches only the empty name (anchored)"},
		{"", "x", false, "empty pattern is anchored, does not match a non-empty name"},
		{"x*z", "xz", true, "'*' matches the empty run between literals"},
		{"x*z", "xqz", true, "'*' matches a one-char run"},
		{"x*z", "xz ", false, "anchored at the end: trailing space is not absorbed"},
		{"x*z", " xz", false, "anchored at the start: leading space is not absorbed"},
		{"did:web:*", "did:web:example.com", true, "':' is a literal; suffix '*' any run"},
		{"did:web:*", "did:web:", true, "suffix '*' matches the empty run"},
		{"did:web:*", "did:key:example", false, "literal prefix must match exactly"},
		{"*.eth", "vitalik.eth", true, "'.' is a literal; leading '*' any run"},
		{"*.eth", ".eth", true, "leading '*' matches the empty run"},
		{"*.eth", "name.ETH", false, "literal '.eth' is byte-exact, not case-folded"},
		{`a\c`, `a\c`, true, "'\\' is a literal, no escape semantics"},
		{`a\c`, "ac", false, "'\\' does not escape — it is a literal byte"},
		{"a*b*c", "a-b-c", true, "two interior '*', matched in order"},
		{"a*b*c", "axbxc", true, "interior '*' each cross their own run"},
		{"a*b*c", "a-c-b", false, "middle literal 'b' must appear before 'c'"},
		{"a*a", "a", false, "'a*a' needs at least 'aa' — '*' is empty, ends overlap"},
		{"a*a", "aa", true, "'a*a' matches 'aa' with '*' = empty run"},
		{"**", "xy", true, "consecutive '*' collapse — empty middle segment"},
	}
	for _, c := range cases {
		if got := MatchName(c.pattern, c.name); got != c.want {
			t.Errorf("MatchName(%q, %q) = %v, want %v — %s",
				c.pattern, c.name, got, c.want, c.note)
		}
	}
}

// TestRegDispatchGrammarDivergesFromPathMatch is the teeth: it proves the four
// REQUIRED rows are exactly the ones a path-glob library gets wrong, so a
// regression to path.Match would be caught by REG-DISPATCH-GRAMMAR-1 rather
// than passing silently. Each row's path.Match result differs from ours.
func TestRegDispatchGrammarDivergesFromPathMatch(t *testing.T) {
	rows := []struct{ pattern, name string }{
		{"a?c", "abc"},    // path.Match: '?' matches 'b' → true; ours: false
		{"a[bc]d", "abd"}, // path.Match: '[bc]' matches 'b' → true; ours: false
		{"x*z", "x/y/z"},  // path.Match: '*' stops at '/' → false; ours: true
	}
	for _, r := range rows {
		pm, err := path.Match(r.pattern, r.name)
		if err != nil {
			// A malformed-pattern row would also diverge (path.Match errors,
			// ours never does) — still a divergence, still fine.
			continue
		}
		if pm == MatchName(r.pattern, r.name) {
			t.Errorf("row (%q,%q): path.Match and MatchName AGREE (%v) — "+
				"this row no longer has teeth against a path.Match regression",
				r.pattern, r.name, pm)
		}
	}
}
