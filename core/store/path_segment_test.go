package store

import (
	"path"
	"testing"
)

const testSentinel = "unspecified_test"

func TestIsSafePathSegment(t *testing.T) {
	cases := []struct {
		seg  string
		safe bool
	}{
		{"req-1", true},
		{"chain-4eaad964ccc6c275", true},
		{"handler_said_no", true},
		{".hidden", true}, // an interior dot is a valid component
		{"a.b", true},     // as is a dotted name
		{"ünïcode", true}, // §1.4 accepts Unicode segments
		{"", false},       // no segment at all
		{".", false},      // reserved
		{"..", false},     // reserved — the escape token
		{"a/b", false},    // forks the path into extra levels
		{"../x", false},   // escape with a suffix
		{"x/..", false},   // escape with a prefix
		{"/", false},      // bare separator
		{"a\x00b", false}, // NUL — V7 §1.4
		{"a\nb", false},   // control character
		{"a\x7fb", false}, // DEL
	}
	for _, tc := range cases {
		if got := IsSafePathSegment(tc.seg); got != tc.safe {
			t.Errorf("IsSafePathSegment(%q) = %v, want %v", tc.seg, got, tc.safe)
		}
	}
}

func TestSanitizePathSegmentPassesSafeValuesThrough(t *testing.T) {
	// Load-bearing for cohort convergence: every conformant value keeps its
	// exact spelling, so sanitizing changes no coordinate any peer observes.
	// Only hostile input is rewritten.
	for _, seg := range []string{"req-1", "chain-abc123", "capability_denied", "sub-99"} {
		if got := SanitizePathSegment(seg, testSentinel); got != seg {
			t.Errorf("SanitizePathSegment(%q) = %q — a safe value MUST pass through unchanged", seg, got)
		}
	}
}

// Unsafe values COLLAPSE to the sentinel — they are not hashed (arch ruling
// 2026-07-17 §1, amending 2026-07-16 §13).
//
// This assertion is the inverse of the one it replaces. The old test asserted
// that distinct hostile values keep distinct coordinates, on the theory that
// collapsing loses an occurrence. It does not: §3.10.1's terminal
// {marker_hash} segment gives every occurrence its own path regardless of what
// the intermediate segments do. The distinctness the hash was protecting was
// already carried one segment down.
func TestSanitizePathSegmentCollapsesUnsafeValuesToTheSentinel(t *testing.T) {
	unsafe := []string{"..", ".", "a/b", "../../../../authority/keys", "", "x/../../y", "a\x00b"}
	for _, seg := range unsafe {
		got := SanitizePathSegment(seg, testSentinel)
		if got != testSentinel {
			t.Errorf("SanitizePathSegment(%q) = %q, want the sentinel %q", seg, got, testSentinel)
		}
	}
}

// The security property the collapse exists for: an attacker CANNOT mint tree
// nodes. Hashing gave each distinct hostile value its own node, which re-opened
// the tree-pollution vector that sanitizing had just closed — one layer up, and
// bounded only by GC. Collapsing bounds it to a single quarantine node no
// matter how many distinct hostile values arrive.
func TestSanitizePathSegmentDoesNotLetAnAttackerMintNodes(t *testing.T) {
	nodes := map[string]struct{}{}
	for i := 0; i < 1000; i++ {
		// Every one distinct, every one hostile.
		seg := "../../../../attacker/" + string(rune('a'+i%26)) + string(rune(i))
		nodes[SanitizePathSegment(seg, testSentinel)] = struct{}{}
	}
	if len(nodes) != 1 {
		t.Errorf("1000 distinct hostile values produced %d distinct path nodes, want exactly 1 — an attacker can mint tree nodes", len(nodes))
	}
}

// A sentinel is only useful if it is itself a legal single segment: it has to
// survive normalization in place, or the collapse re-introduces the escape it
// was meant to stop.
func TestSentinelIsItselfASafeSegment(t *testing.T) {
	if !IsSafePathSegment(testSentinel) {
		t.Fatalf("sentinel %q is not a safe path segment", testSentinel)
	}
	joined := "system/runtime/chain-errors/lost/" + testSentinel + "/x"
	if path.Clean(joined) != joined {
		t.Errorf("sentinel %q does not survive path.Clean: %s", testSentinel, path.Clean(joined))
	}
}
