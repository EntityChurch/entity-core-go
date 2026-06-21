package main

import "testing"

func TestResolve(t *testing.T) {
	tests := []struct {
		input string
		wd    Path
		want  Path
	}{
		// Empty input returns working directory.
		{"", "/", "/"},
		{"", "/abc123/system/", "/abc123/system/"},

		// Root.
		{"/", "/", "/"},
		{"/", "/abc123/system/", "/"},

		// Absolute paths.
		{"/abc123/system/handler/", "/", "/abc123/system/handler/"},
		{"/abc123/foo", "/xyz/bar/", "/abc123/foo"},

		// Relative from root.
		{"abc123", "/", "/abc123"},

		// Relative from peer root.
		{"system/", "/abc123/", "/abc123/system/"},
		{"system/handler/", "/abc123/", "/abc123/system/handler/"},

		// Relative from directory (with trailing slash).
		{"tree", "/abc123/system/handler/", "/abc123/system/handler/tree"},
		{"local/", "/abc123/system/handler/", "/abc123/system/handler/local/"},

		// Relative from non-directory (no trailing slash) — must insert "/".
		{"internal", "/abc123/system/inbox/target", "/abc123/system/inbox/target/internal"},
		{"foo", "/abc123/bar", "/abc123/bar/foo"},

		// Parent navigation.
		{"..", "/abc123/system/handler/", "/abc123/system/"},
		{"..", "/abc123/system/", "/abc123/"},
		{"..", "/abc123/", "/"},
		{"..", "/", "/"},

		// Parent + relative.
		{"../type/", "/abc123/system/handler/", "/abc123/system/type/"},
		{"../../", "/abc123/system/handler/", "/abc123/"},

		// Double slash normalization.
		{"//abc123//system//", "/", "/abc123/system/"},

		// Dot normalization.
		{"./system/", "/abc123/", "/abc123/system/"},
	}

	for _, tt := range tests {
		got := Resolve(tt.input, tt.wd)
		if got != tt.want {
			t.Errorf("Resolve(%q, %q) = %q, want %q", tt.input, tt.wd, got, tt.want)
		}
	}
}

func TestPathPeerID(t *testing.T) {
	tests := []struct {
		path Path
		want string
	}{
		{"/", ""},
		{"/abc123/", "abc123"},
		{"/abc123/system/handler/", "abc123"},
		{"/abc123", "abc123"},
	}
	for _, tt := range tests {
		got := tt.path.PeerID()
		if got != tt.want {
			t.Errorf("Path(%q).PeerID() = %q, want %q", tt.path, got, tt.want)
		}
	}
}

func TestPathBarePath(t *testing.T) {
	tests := []struct {
		path Path
		want string
	}{
		{"/", ""},
		{"/abc123/", ""},
		{"/abc123/system/handler/", "system/handler/"},
		{"/abc123/system/handler/tree", "system/handler/tree"},
		{"/abc123", ""},
	}
	for _, tt := range tests {
		got := tt.path.BarePath()
		if got != tt.want {
			t.Errorf("Path(%q).BarePath() = %q, want %q", tt.path, got, tt.want)
		}
	}
}

func TestPathParent(t *testing.T) {
	tests := []struct {
		path Path
		want Path
	}{
		{"/", "/"},
		{"/abc123/", "/"},
		{"/abc123/system/", "/abc123/"},
		{"/abc123/system/handler/", "/abc123/system/"},
		{"/abc123/system/handler/tree", "/abc123/system/handler/"},
	}
	for _, tt := range tests {
		got := tt.path.Parent()
		if got != tt.want {
			t.Errorf("Path(%q).Parent() = %q, want %q", tt.path, got, tt.want)
		}
	}
}

func TestPathIsRoot(t *testing.T) {
	if !Path("/").IsRoot() {
		t.Error("/ should be root")
	}
	if Path("/abc123/").IsRoot() {
		t.Error("/abc123/ should not be root")
	}
}
