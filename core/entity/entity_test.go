package entity

import (
	"testing"

	"go.entitychurch.org/entity-core-go/core/ecf"
	"go.entitychurch.org/entity-core-go/core/hash"

	"github.com/fxamacker/cbor/v2"
)

// Test peer ID — proper 46-char Base58 format.
const testPeerID = "2KZFtestpeerAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"

func makeRawData(t *testing.T, v interface{}) cbor.RawMessage {
	t.Helper()
	b, err := ecf.Encode(v)
	if err != nil {
		t.Fatal(err)
	}
	return cbor.RawMessage(b)
}

func TestNewEntity(t *testing.T) {
	data := makeRawData(t, map[string]string{"key": "value"})
	e, err := NewEntity("test/type", data)
	if err != nil {
		t.Fatal(err)
	}

	if e.Type != "test/type" {
		t.Fatalf("expected type test/type, got %s", e.Type)
	}
	if e.ContentHash.IsZero() {
		t.Fatal("content hash should not be zero")
	}
	if e.ContentHash.Algorithm != hash.AlgorithmSHA256 {
		t.Fatalf("expected SHA256 algorithm, got 0x%02x", e.ContentHash.Algorithm)
	}
}

func TestNewEntityEmptyType(t *testing.T) {
	data := makeRawData(t, "hello")
	_, err := NewEntity("", data)
	if err == nil {
		t.Fatal("expected error for empty type")
	}
}

func TestNewEntityEmptyData(t *testing.T) {
	_, err := NewEntity("test", nil)
	if err == nil {
		t.Fatal("expected error for nil data")
	}

	_, err = NewEntity("test", cbor.RawMessage{})
	if err == nil {
		t.Fatal("expected error for empty data")
	}
}

func TestEntityValidate(t *testing.T) {
	data := makeRawData(t, map[string]string{"key": "value"})
	e, err := NewEntity("test/type", data)
	if err != nil {
		t.Fatal(err)
	}

	// Valid entity.
	if err := e.Validate(); err != nil {
		t.Fatalf("expected valid entity, got: %v", err)
	}

	// Tampered data.
	tampered := e
	tampered.Data = makeRawData(t, "tampered")
	if err := tampered.Validate(); err == nil {
		t.Fatal("expected validation error for tampered data")
	}
}

func TestEntityValidateHash(t *testing.T) {
	data := makeRawData(t, "test")
	e, err := NewEntity("test/type", data)
	if err != nil {
		t.Fatal(err)
	}

	if err := e.ValidateHash(); err != nil {
		t.Fatalf("ValidateHash failed: %v", err)
	}
}

func TestEntityDeterministicHash(t *testing.T) {
	data := makeRawData(t, map[string]int{"a": 1, "b": 2})

	e1, err := NewEntity("test", data)
	if err != nil {
		t.Fatal(err)
	}
	e2, err := NewEntity("test", data)
	if err != nil {
		t.Fatal(err)
	}

	if e1.ContentHash != e2.ContentHash {
		t.Fatalf("same input should produce same hash: %s != %s", e1.ContentHash, e2.ContentHash)
	}
}

// Envelope tests

func TestNewEnvelope(t *testing.T) {
	data := makeRawData(t, "root")
	root, err := NewEntity("test/root", data)
	if err != nil {
		t.Fatal(err)
	}

	env := NewEnvelope(root, nil)
	if env.Root.Type != "test/root" {
		t.Fatalf("expected root type test/root, got %s", env.Root.Type)
	}
}

func TestEnvelopeFindIncluded(t *testing.T) {
	data := makeRawData(t, "root")
	root, _ := NewEntity("test/root", data)

	incData := makeRawData(t, "included")
	inc, _ := NewEntity("test/included", incData)

	included := map[hash.Hash]Entity{
		inc.ContentHash: inc,
	}
	env := NewEnvelope(root, included)

	found, ok := env.FindIncluded(inc.ContentHash)
	if !ok {
		t.Fatal("expected to find included entity")
	}
	if found.Type != "test/included" {
		t.Fatalf("expected type test/included, got %s", found.Type)
	}

	// Not found.
	_, ok = env.FindIncluded(hash.Hash{})
	if ok {
		t.Fatal("expected not found for zero hash")
	}
}

func TestEnvelopeValidateAll(t *testing.T) {
	data := makeRawData(t, "root")
	root, _ := NewEntity("test/root", data)

	incData := makeRawData(t, "included")
	inc, _ := NewEntity("test/included", incData)

	included := map[hash.Hash]Entity{
		inc.ContentHash: inc,
	}
	env := NewEnvelope(root, included)

	if err := env.ValidateAll(); err != nil {
		t.Fatalf("expected valid envelope, got: %v", err)
	}

	// Tamper with an included entity.
	bad := inc
	bad.Data = makeRawData(t, "tampered")
	env.Included[inc.ContentHash] = bad

	if err := env.ValidateAll(); err == nil {
		t.Fatal("expected error for tampered included entity")
	}
}

func TestEnvelopeInclude(t *testing.T) {
	data := makeRawData(t, "root")
	root, _ := NewEntity("test/root", data)
	env := NewEnvelope(root, nil)

	incData := makeRawData(t, "included")
	inc, _ := NewEntity("test/included", incData)

	env.Include(inc)

	found, ok := env.FindIncluded(inc.ContentHash)
	if !ok {
		t.Fatal("expected to find included entity after Include")
	}
	if found.Type != "test/included" {
		t.Fatalf("unexpected type: %s", found.Type)
	}
}

// URI tests

func TestParseURI(t *testing.T) {
	tests := []struct {
		input   string
		peerID  string
		path    string
		wantErr bool
	}{
		{"entity://abc123/system/tree", "abc123", "system/tree", false},
		{"entity://abc123/local/files/readme.md", "abc123", "local/files/readme.md", false},
		{"entity://abc123", "abc123", "", false},
		{"not-entity://foo/bar", "", "", true},
		{"entity://", "", "", true},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			uri, err := ParseURI(tt.input)
			if tt.wantErr {
				if err == nil {
					t.Fatal("expected error")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if uri.PeerID != tt.peerID {
				t.Fatalf("PeerID: expected %q, got %q", tt.peerID, uri.PeerID)
			}
			if uri.Path != tt.path {
				t.Fatalf("Path: expected %q, got %q", tt.path, uri.Path)
			}
		})
	}
}

func TestURIString(t *testing.T) {
	u := URI{PeerID: "abc123", Path: "system/tree"}
	if s := u.String(); s != "entity://abc123/system/tree" {
		t.Fatalf("expected entity://abc123/system/tree, got %s", s)
	}

	u = URI{PeerID: "abc123"}
	if s := u.String(); s != "entity://abc123" {
		t.Fatalf("expected entity://abc123, got %s", s)
	}
}

func TestNormalizePath(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"entity://" + testPeerID + "/path", "/" + testPeerID + "/path"},
		{"system/tree", "system/tree"},
		{"entity://" + testPeerID, "/" + testPeerID},
	}

	for _, tt := range tests {
		result := NormalizePath(tt.input)
		if result != tt.expected {
			t.Fatalf("NormalizePath(%q): expected %q, got %q", tt.input, tt.expected, result)
		}
	}
}

func TestPathToURI(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"/" + testPeerID + "/system/tree", "entity://" + testPeerID + "/system/tree"},
		{"/" + testPeerID, "entity://" + testPeerID},
		{"system/tree", "entity://system/tree"}, // relative input (no leading /)
		{"/" + testPeerID + "/deep/nested/path", "entity://" + testPeerID + "/deep/nested/path"},
	}

	for _, tt := range tests {
		result := PathToURI(tt.input)
		if result != tt.expected {
			t.Fatalf("PathToURI(%q): expected %q, got %q", tt.input, tt.expected, result)
		}
	}
}

func TestExtractHandlerPath(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"entity://" + testPeerID + "/system/tree", "system/tree"},
		{"entity://" + testPeerID + "/local/files/readme.md", "local/files/readme.md"},
		{"system/tree", "system/tree"},
		{"local/files/readme.md", "local/files/readme.md"},
	}

	for _, tt := range tests {
		result := ExtractHandlerPath(tt.input)
		if result != tt.expected {
			t.Fatalf("ExtractHandlerPath(%q): expected %q, got %q", tt.input, tt.expected, result)
		}
	}
}
