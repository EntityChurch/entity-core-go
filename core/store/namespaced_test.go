package store

import (
	"strings"
	"testing"

	"go.entitychurch.org/entity-core-go/core/hash"
)

// Fake local peer ID (base58-like, >40 chars).
const testLocalNS = "2DRjqCz9DGeHZK8NqnpZ2q1ExFVjmJMAMSn5CPRcYcBq1a"
const testRemoteNS = "4FWkqP8mAHjZ7KNqrpR4s3GxHWkmKNCNTp7DQTdaCdSq2b"
const testRemoteNS2 = "5GqRgvNkBpJZHnLNAY3fS9P5MqaEbTnKpv2T8Fy3MdQt6c"

func makeHash(b byte) hash.Hash {
	h := hash.Hash{Algorithm: hash.AlgorithmSHA256}
	h.Digest[0] = b
	return h
}

func TestNamespacedIndex_LocalSetGet(t *testing.T) {
	inner := NewMemoryLocationIndex()
	ns := NewNamespacedIndex(inner, testLocalNS)

	h := makeHash(0x01)
	ns.Set("data/file1", h)

	// Get via NamespacedIndex (bare path).
	got, ok := ns.Get("data/file1")
	if !ok {
		t.Fatal("expected to find data/file1")
	}
	if got != h {
		t.Fatal("wrong hash")
	}

	// Underlying store has the absolute path.
	got2, ok := inner.Get("/" + testLocalNS + "/data/file1")
	if !ok {
		t.Fatal("expected absolute path in inner store")
	}
	if got2 != h {
		t.Fatal("wrong hash in inner store")
	}

	// Bare path does NOT exist in inner store.
	if inner.Has("data/file1") {
		t.Fatal("bare path should not exist in inner store")
	}
}

func TestNamespacedIndex_Has(t *testing.T) {
	inner := NewMemoryLocationIndex()
	ns := NewNamespacedIndex(inner, testLocalNS)

	h := makeHash(0x01)
	ns.Set("system/type/foo", h)

	if !ns.Has("system/type/foo") {
		t.Fatal("expected Has to return true")
	}
	if ns.Has("system/type/bar") {
		t.Fatal("expected Has to return false for nonexistent")
	}
}

func TestNamespacedIndex_Remove(t *testing.T) {
	inner := NewMemoryLocationIndex()
	ns := NewNamespacedIndex(inner, testLocalNS)

	h := makeHash(0x01)
	ns.Set("data/file1", h)

	removed, ok := ns.Remove("data/file1")
	if !ok {
		t.Fatal("expected remove to succeed")
	}
	if removed != h {
		t.Fatal("wrong removed hash")
	}
	if ns.Has("data/file1") {
		t.Fatal("should not have path after remove")
	}
	if inner.Has("/" + testLocalNS + "/data/file1") {
		t.Fatal("should not have absolute path in inner after remove")
	}
}

func TestNamespacedIndex_List(t *testing.T) {
	inner := NewMemoryLocationIndex()
	ns := NewNamespacedIndex(inner, testLocalNS)

	h1 := makeHash(0x01)
	h2 := makeHash(0x02)
	ns.Set("system/type/alpha", h1)
	ns.Set("system/type/beta", h2)
	ns.Set("data/other", h1)

	entries := ns.List("system/type/")
	if len(entries) != 2 {
		t.Fatalf("expected 2 entries, got %d", len(entries))
	}
	// List returns absolute paths.
	wantAlpha := "/" + testLocalNS + "/system/type/alpha"
	wantBeta := "/" + testLocalNS + "/system/type/beta"
	if entries[0].Path != wantAlpha {
		t.Fatalf("expected %s, got %s", wantAlpha, entries[0].Path)
	}
	if entries[1].Path != wantBeta {
		t.Fatalf("expected %s, got %s", wantBeta, entries[1].Path)
	}
}

func TestNamespacedIndex_ListEmpty(t *testing.T) {
	inner := NewMemoryLocationIndex()
	ns := NewNamespacedIndex(inner, testLocalNS)

	entries := ns.List("nonexistent/")
	if len(entries) != 0 {
		t.Fatalf("expected 0 entries, got %d", len(entries))
	}
}

// TestNamespacedIndex_List_HonorsInterfaceContract pins the LocationIndex
// contract (store.go:184) that "Empty prefix counts every binding in the
// index" on the namespaced wrapper. Pre-Amendment-5 the wrapper
// canonicalized "" to the local-peer namespace and silently returned
// local-only entries — a contract violation. List("") and List("/") MUST
// both return every binding regardless of which peer-id segment it lives
// under.
func TestNamespacedIndex_List_HonorsInterfaceContract(t *testing.T) {
	inner := NewMemoryLocationIndex()
	ns := NewNamespacedIndex(inner, testLocalNS)

	h := makeHash(0x01)
	// Seed bindings under three different peer-id top-level segments.
	if err := ns.Set("local/file", h); err != nil { // canonicalizes to /<localNS>/local/file
		t.Fatal(err)
	}
	if err := ns.Set("/"+testRemoteNS+"/data/x", h); err != nil { // absolute, passes through
		t.Fatal(err)
	}
	if err := ns.Set("/"+testRemoteNS2+"/data/y", h); err != nil {
		t.Fatal(err)
	}

	for _, p := range []string{"", "/"} {
		entries := ns.List(p)
		if len(entries) != 3 {
			t.Errorf("ns.List(%q): got %d entries, want 3 (interface contract: empty prefix lists everything)", p, len(entries))
		}
		// Confirm every top-level peer-id is reached.
		seen := map[string]bool{}
		for _, e := range entries {
			rest := strings.TrimPrefix(e.Path, "/")
			first, _, _ := strings.Cut(rest, "/")
			seen[first] = true
		}
		for _, want := range []string{testLocalNS, testRemoteNS, testRemoteNS2} {
			if !seen[want] {
				t.Errorf("ns.List(%q): missing top-level peer-id %s; got peers=%v", p, want, seen)
			}
		}
	}
}

// TestNamespacedIndex_LenPrefix_HonorsInterfaceContract pins the same
// contract for LenPrefix (store.go:184): empty or bare-root prefix counts
// every binding in the inner store, not just the local-peer ones.
func TestNamespacedIndex_LenPrefix_HonorsInterfaceContract(t *testing.T) {
	inner := NewMemoryLocationIndex()
	ns := NewNamespacedIndex(inner, testLocalNS)

	h := makeHash(0x01)
	if err := ns.Set("local/a", h); err != nil {
		t.Fatal(err)
	}
	if err := ns.Set("/"+testRemoteNS+"/remote/b", h); err != nil {
		t.Fatal(err)
	}

	for _, p := range []string{"", "/"} {
		if got := ns.LenPrefix(p); got != 2 {
			t.Errorf("ns.LenPrefix(%q): got %d, want 2 (empty/root counts all)", p, got)
		}
	}
}

func TestNamespacedIndex_RemoteNamespace(t *testing.T) {
	inner := NewMemoryLocationIndex()
	ns := NewNamespacedIndex(inner, testLocalNS)

	h := makeHash(0x42)
	ns.SetNS(testRemoteNS, "data/file1", h)

	got, ok := ns.GetNS(testRemoteNS, "data/file1")
	if !ok {
		t.Fatal("expected to find remote path")
	}
	if got != h {
		t.Fatal("wrong hash from remote NS")
	}

	if !ns.HasNS(testRemoteNS, "data/file1") {
		t.Fatal("expected HasNS to return true")
	}

	// Underlying store has the remote absolute path.
	if !inner.Has("/" + testRemoteNS + "/data/file1") {
		t.Fatal("expected remote absolute path in inner store")
	}
}

func TestNamespacedIndex_Isolation(t *testing.T) {
	inner := NewMemoryLocationIndex()
	ns := NewNamespacedIndex(inner, testLocalNS)

	hLocal := makeHash(0x01)
	hRemote := makeHash(0x02)

	ns.Set("data/file1", hLocal)
	ns.SetNS(testRemoteNS, "data/file1", hRemote)

	// Local get returns local hash.
	got, ok := ns.Get("data/file1")
	if !ok {
		t.Fatal("expected local path")
	}
	if got != hLocal {
		t.Fatalf("expected local hash, got remote")
	}

	// Remote get returns remote hash.
	got, ok = ns.GetNS(testRemoteNS, "data/file1")
	if !ok {
		t.Fatal("expected remote path")
	}
	if got != hRemote {
		t.Fatalf("expected remote hash, got local")
	}

	// Local doesn't see remote and vice versa via ListNS.
	localEntries := ns.List("data/")
	if len(localEntries) != 1 {
		t.Fatalf("expected 1 local entry, got %d", len(localEntries))
	}
	remoteEntries := ns.ListNS(testRemoteNS, "data/")
	if len(remoteEntries) != 1 {
		t.Fatalf("expected 1 remote entry, got %d", len(remoteEntries))
	}
}

func TestNamespacedIndex_ListNS(t *testing.T) {
	inner := NewMemoryLocationIndex()
	ns := NewNamespacedIndex(inner, testLocalNS)

	h1 := makeHash(0x01)
	h2 := makeHash(0x02)
	ns.SetNS(testRemoteNS, "data/alpha", h1)
	ns.SetNS(testRemoteNS, "data/beta", h2)
	ns.SetNS(testRemoteNS, "system/type/foo", h1)

	entries := ns.ListNS(testRemoteNS, "data/")
	if len(entries) != 2 {
		t.Fatalf("expected 2 entries, got %d", len(entries))
	}
	// ListNS returns absolute paths.
	wantAlpha := "/" + testRemoteNS + "/data/alpha"
	wantBeta := "/" + testRemoteNS + "/data/beta"
	if entries[0].Path != wantAlpha {
		t.Fatalf("expected %s, got %s", wantAlpha, entries[0].Path)
	}
	if entries[1].Path != wantBeta {
		t.Fatalf("expected %s, got %s", wantBeta, entries[1].Path)
	}
}

func TestNamespacedIndex_RemoveNS(t *testing.T) {
	inner := NewMemoryLocationIndex()
	ns := NewNamespacedIndex(inner, testLocalNS)

	h := makeHash(0x01)
	ns.SetNS(testRemoteNS, "data/file1", h)

	removed, ok := ns.RemoveNS(testRemoteNS, "data/file1")
	if !ok {
		t.Fatal("expected remove to succeed")
	}
	if removed != h {
		t.Fatal("wrong removed hash")
	}
	if ns.HasNS(testRemoteNS, "data/file1") {
		t.Fatal("should not have path after remove")
	}
}

func TestNamespacedIndex_Qualify(t *testing.T) {
	ns := NewNamespacedIndex(NewMemoryLocationIndex(), testLocalNS)

	got := ns.Qualify("data/file1")
	want := "/" + testLocalNS + "/data/file1"
	if got != want {
		t.Fatalf("Qualify: got %s, want %s", got, want)
	}

	got = ns.QualifyTo(testRemoteNS, "data/file1")
	want = "/" + testRemoteNS + "/data/file1"
	if got != want {
		t.Fatalf("QualifyTo: got %s, want %s", got, want)
	}
}

func TestNamespacedIndex_LocalNS(t *testing.T) {
	ns := NewNamespacedIndex(NewMemoryLocationIndex(), testLocalNS)
	if ns.LocalNS() != testLocalNS {
		t.Fatalf("expected %s, got %s", testLocalNS, ns.LocalNS())
	}
}

func TestNamespacedIndex_EventsLocal(t *testing.T) {
	inner := NewMemoryLocationIndex()
	events := make(chan TreeChangeEvent, 16)
	done := make(chan struct{})
	notifying := NewNotifyingLocationIndex(inner, events, done)
	ns := NewNamespacedIndex(notifying, testLocalNS)

	h := makeHash(0x01)
	ns.Set("data/file1", h)

	select {
	case evt := <-events:
		if evt.ChangeType != ChangeCreated {
			t.Fatalf("expected ChangeCreated, got %d", evt.ChangeType)
		}
		// Event path is the absolute path in the underlying store.
		want := "/" + testLocalNS + "/data/file1"
		if evt.Path != want {
			t.Fatalf("expected event path %s, got %s", want, evt.Path)
		}
	default:
		t.Fatal("expected event")
	}
}

func TestNamespacedIndex_EventsRemote(t *testing.T) {
	inner := NewMemoryLocationIndex()
	events := make(chan TreeChangeEvent, 16)
	done := make(chan struct{})
	notifying := NewNotifyingLocationIndex(inner, events, done)
	ns := NewNamespacedIndex(notifying, testLocalNS)

	h := makeHash(0x01)
	ns.SetNS(testRemoteNS, "data/file1", h)

	select {
	case evt := <-events:
		if evt.ChangeType != ChangeCreated {
			t.Fatalf("expected ChangeCreated, got %d", evt.ChangeType)
		}
		want := "/" + testRemoteNS + "/data/file1"
		if evt.Path != want {
			t.Fatalf("expected event path %s, got %s", want, evt.Path)
		}
	default:
		t.Fatal("expected event")
	}
}

func TestNamespacedIndex_Inner(t *testing.T) {
	inner := NewMemoryLocationIndex()
	ns := NewNamespacedIndex(inner, testLocalNS)

	if ns.Inner() != inner {
		t.Fatal("Inner() should return the wrapped LocationIndex")
	}
}

func TestNamespacedIndex_Canonicalize(t *testing.T) {
	inner := NewMemoryLocationIndex()
	ns := NewNamespacedIndex(inner, testLocalNS)

	h := makeHash(0x01)

	// Set via bare path.
	ns.Set("data/file1", h)

	// Get via absolute path — should NOT double-prefix.
	qualifiedPath := "/" + testLocalNS + "/data/file1"
	got, ok := ns.Get(qualifiedPath)
	if !ok {
		t.Fatal("Get with qualified path should find the entry")
	}
	if got != h {
		t.Fatal("wrong hash")
	}

	// Has via qualified path.
	if !ns.Has(qualifiedPath) {
		t.Fatal("Has with qualified path should return true")
	}

	// Remove via qualified path.
	removed, ok := ns.Remove(qualifiedPath)
	if !ok {
		t.Fatal("Remove with qualified path should succeed")
	}
	if removed != h {
		t.Fatal("wrong removed hash")
	}

	// Set via qualified path, get via bare path.
	ns.Set(qualifiedPath, h)
	got, ok = ns.Get("data/file1")
	if !ok {
		t.Fatal("Get with bare path should find entry set via qualified path")
	}
	if got != h {
		t.Fatal("wrong hash")
	}
}

// --- Path utility tests ---

func TestQualifyPath(t *testing.T) {
	got := QualifyPath(testLocalNS, "data/file1")
	want := "/" + testLocalNS + "/data/file1"
	if got != want {
		t.Fatalf("got %s, want %s", got, want)
	}
}

func TestSplitNamespace(t *testing.T) {
	tests := []struct {
		path   string
		wantNS string
		wantBP string
	}{
		{"/" + testLocalNS + "/data/file1", testLocalNS, "data/file1"},
		{"data/file1", "", "data/file1"},
		{"system/type/foo", "", "system/type/foo"},
		{"noSlash", "", "noSlash"},
		{"/" + testRemoteNS + "/system/tree", testRemoteNS, "system/tree"},
		{"/" + testLocalNS, testLocalNS, ""}, // just /{peerID} with no subpath
	}
	for _, tt := range tests {
		ns, bp := SplitNamespace(tt.path)
		if ns != tt.wantNS || bp != tt.wantBP {
			t.Errorf("SplitNamespace(%q) = (%q, %q), want (%q, %q)",
				tt.path, ns, bp, tt.wantNS, tt.wantBP)
		}
	}
}

func TestIsAbsolute(t *testing.T) {
	tests := []struct {
		path string
		want bool
	}{
		{"/" + testLocalNS + "/data/file1", true},
		{"/anything", true},
		{"data/file1", false},
		{"system/type/foo", false},
		{"noSlash", false},
		{"short/path", false},
	}
	for _, tt := range tests {
		got := IsAbsolute(tt.path)
		if got != tt.want {
			t.Errorf("IsAbsolute(%q) = %v, want %v", tt.path, got, tt.want)
		}
	}
}

func TestValidateAbsolutePath(t *testing.T) {
	tests := []struct {
		path    string
		wantErr bool
	}{
		{"/" + testLocalNS + "/data/file1", false},
		{"/" + testLocalNS, false}, // just /{peerID}
		{"/" + testRemoteNS + "/system/tree", false},
		{"data/file1", true},        // not absolute
		{"system/type/foo", true},   // not absolute
		{"/", true},                 // empty after /
		{"/short/path", true},       // first segment not a peer ID
		{"/ab/path", true},          // too short for peer ID
		{"/peer/path", true},        // "peer" is only 4 chars, not a valid ID
		{"/testpeer123/path", true}, // 11 chars, below 46 minimum
		{"/abcdefghijkABCDEFGHJKLMNPQRSTUVWXYZabcdefghijk/x", false},  // exactly 46 Base58 chars
		{"/contains0zero11111111111111111111111111111111111/x", true}, // '0' not in Base58
		{"/containsOcapital1111111111111111111111111111111/x", true},  // 'O' not in Base58
		{"/containslowerel111111111111111111111111111111111/x", true}, // 'l' not in Base58
		// Per NETWORK §6.4, the URL-layer reserved words content/manifest
		// MUST continue to fail this peer-ID-first check — that rejection
		// is what makes them collision-safe at the URL layer.
		{"/content/foo", true},
		{"/manifest", true},
	}
	for _, tt := range tests {
		err := ValidateAbsolutePath(tt.path)
		if (err != nil) != tt.wantErr {
			t.Errorf("ValidateAbsolutePath(%q) error=%v, wantErr=%v", tt.path, err, tt.wantErr)
		}
	}
}

func TestValidateURLPathXSegment(t *testing.T) {
	// Per NETWORK §6.4 D-12: peer-ID OR reserved word content|manifest.
	tests := []struct {
		seg     string
		wantErr bool
	}{
		{"content", false},
		{"manifest", false},
		{"abcdefghijkABCDEFGHJKLMNPQRSTUVWXYZabcdefghijk", false}, // 46-char Base58 peer-ID
		{"", true},
		{"random", true},
		{"foo", true},
		{"system", true},
		{"contents", true}, // exact-match only
		{"Manifest", true}, // case-sensitive
		{"short", true},
		// Reserved words must succeed even though they fail
		// looksLikePeerID — that's the whole point of the X validator.
	}
	for _, tt := range tests {
		err := ValidateURLPathXSegment(tt.seg)
		if (err != nil) != tt.wantErr {
			t.Errorf("ValidateURLPathXSegment(%q) error=%v, wantErr=%v", tt.seg, err, tt.wantErr)
		}
	}
}

func TestIsURLPathXReservedWord(t *testing.T) {
	tests := []struct {
		s    string
		want bool
	}{
		{"content", true},
		{"manifest", true},
		{"Content", false},
		{"MANIFEST", false},
		{"contents", false},
		{"", false},
		{"abcdefghijkABCDEFGHJKLMNPQRSTUVWXYZabcdefghijk", false},
	}
	for _, tt := range tests {
		if got := IsURLPathXReservedWord(tt.s); got != tt.want {
			t.Errorf("IsURLPathXReservedWord(%q) = %v, want %v", tt.s, got, tt.want)
		}
	}
}

func TestCleanPath(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		// Collapse double slashes.
		{"/" + testLocalNS + "//path", "/" + testLocalNS + "/path"},
		{"a//b//c", "a/b/c"},
		// Preserve leading slash.
		{"/" + testLocalNS + "/path", "/" + testLocalNS + "/path"},
		// Strip trailing slash.
		{"/" + testLocalNS + "/path/", "/" + testLocalNS + "/path"},
		{"data/file/", "data/file"},
		// No-op for clean paths.
		{"system/tree", "system/tree"},
		{"", ""},
		// Reserved prefixes pass through unchanged.
		{"./path", "./path"},
		{"../path", "../path"},
		// Entity URI: clean only the path portion.
		{"entity://" + testLocalNS + "/path", "entity://" + testLocalNS + "/path"},
		{"entity://" + testLocalNS + "//path/", "entity://" + testLocalNS + "/path"},
		// Dot segments in middle positions are valid (.gitignore, .env).
		{".gitignore", ".gitignore"},
		{"/" + testLocalNS + "/.hidden/config", "/" + testLocalNS + "/.hidden/config"},
	}
	for _, tt := range tests {
		got := CleanPath(tt.input)
		if got != tt.want {
			t.Errorf("CleanPath(%q) = %q, want %q", tt.input, got, tt.want)
		}
	}
}
