package revision

import "testing"

// TestGlobMatchFourForms pins EXTENSION-REVISION §2.4's matcher to the exact
// REV-GLOB-* conformance vectors. This surface is hash-determining (it decides
// trie membership → version root → version identity), so the vectors are the
// contract, not prose. `**` must NOT behave as a wildcard.
func TestGlobMatchFourForms(t *testing.T) {
	cases := []struct {
		name             string
		pattern, subject string
		want             bool
	}{
		// REV-GLOB-PREFIX-1/2 — form 2 crosses / at any depth; retained / blocks siblings.
		{"prefix-deep", "system/revision/*", "system/revision/head/H/deep/x", true},
		{"prefix-sibling", "system/revision/*", "system/revisionary/x", false},
		{"prefix-immediate", "system/revision/*", "system/revision/head", true},
		// REV-GLOB-SUFFIX-1/2 — form 3 is a whole-subject byte suffix; / not special.
		{"suffix-nested", "*.cache", "a/b/foo.cache", true},
		{"suffix-bare", "*.cache", ".cache", true},
		{"suffix-segment-not-end", "*.cache", "a/cache/b", false},
		{"suffix-not-terminal", "*.cache", "foo.cache.tmp", false},
		// REV-GLOB-EXACT-1 — form 4 is exact, not a prefix.
		{"exact-match", "docs", "docs", true},
		{"exact-not-prefix", "docs", "docs/x", false},
		// REV-GLOB-ALL-1 — form 1.
		{"all", "*", "anything/at/any/depth", true},
		// `**` is not a form — under the matcher it can never behave as a crossing
		// wildcard (it would fall to form 3 with a literal "*" suffix, matching
		// nothing real). The write-time V6 check keeps it out entirely.
		{"doublestar-not-wildcard", "**", "docs/readme", false},
	}
	for _, tc := range cases {
		if got := globMatch(tc.pattern, tc.subject); got != tc.want {
			t.Errorf("%s: globMatch(%q, %q) = %v, want %v", tc.name, tc.pattern, tc.subject, got, tc.want)
		}
	}
}

// TestValidExcludePattern pins §4.4.17 V6 — the write-time gate that keeps the
// token out. A valid pattern has at most one *, positioned as the whole pattern,
// the final char after /, or the first char. REV-GLOB-REJECT-1/2.
func TestValidExcludePattern(t *testing.T) {
	valid := []string{"*", "system/revision/*", "*.cache", "docs", "app/*", "*-draft", "/*"}
	for _, p := range valid {
		if !validExcludePattern(p) {
			t.Errorf("validExcludePattern(%q) = false, want true", p)
		}
	}
	// REV-GLOB-REJECT-1 (`**`, load-bearing) and REV-GLOB-REJECT-2.
	invalid := []string{"**", "a/**/b", "a*b", "*a*", "docs/**", "*/*", "a*b*c"}
	for _, p := range invalid {
		if validExcludePattern(p) {
			t.Errorf("validExcludePattern(%q) = true, want false (rejected at config write)", p)
		}
	}
}
