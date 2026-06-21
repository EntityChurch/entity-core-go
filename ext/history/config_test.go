package history

import (
	"testing"
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

func TestPatternSpecificity(t *testing.T) {
	tests := []struct {
		a, b string
	}{
		// More literal segments = more specific.
		{"/peerA/project/*", "*"},
		{"/peerA/project/readme", "/peerA/project/*"},
		// Explicit peer > wildcard peer at same depth.
		{"/peerA/project/*", "*/project/*"},
	}
	for _, tt := range tests {
		sa := patternSpecificity(tt.a)
		sb := patternSpecificity(tt.b)
		if sa <= sb {
			t.Errorf("specificity(%q)=%d should be > specificity(%q)=%d", tt.a, sa, tt.b, sb)
		}
	}
}
