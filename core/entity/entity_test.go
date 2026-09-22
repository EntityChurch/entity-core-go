package entity

import (
	"errors"
	"strings"
	"testing"

	"go.entitychurch.org/entity-core-go/core/ecf"
	ecerrors "go.entitychurch.org/entity-core-go/core/errors"
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

// K1 durable fix (§1.8 resolution integrity, 0.8.2.23): Include is the single
// site that keys the included map, so it recomputes the key from {type, data}
// and never trusts a caller-supplied (wire) ContentHash. This closes the four
// outbound re-key sites in core/peer at the constructor rather than relying on
// a non-local "the source map was already validated" argument at each. Mutation:
// revert Include to `e.Included[ent.ContentHash] = ent` → the mis-stamped entity
// files under the wrong key → the true-hash lookup below misses and this reds.
func TestEnvelopeInclude_ReKeysMisStampedEntityUnderTrueHash(t *testing.T) {
	root, _ := NewEntity("test/root", makeRawData(t, "root"))
	env := NewEnvelope(root, nil)

	// A genuine entity and its true hash.
	inc, _ := NewEntity("test/included", makeRawData(t, "included"))
	trueHash := inc.ContentHash

	// A DIFFERENT entity's hash, used as the attacker/wire key.
	other, _ := NewEntity("test/other", makeRawData(t, "other-decoy"))
	wireKey := other.ContentHash
	if wireKey == trueHash {
		t.Fatal("setup: decoy hash collided with the true hash")
	}

	// The re-key idiom: re-stamp the genuine entity's ContentHash with a foreign
	// wire key (exactly what the four core/peer sites used to do, and what a
	// forgery does — file an entity under a key that is not its content).
	misStamped := Entity{Type: inc.Type, Data: inc.Data, ContentHash: wireKey}
	env.Include(misStamped)

	// It MUST be filed under the true content hash, never the wire key.
	if _, ok := env.FindIncluded(wireKey); ok {
		t.Fatal("Include filed an entity under a caller-supplied wire key — resolution-integrity bypass")
	}
	found, ok := env.FindIncluded(trueHash)
	if !ok {
		t.Fatal("Include must key by recomputed content hash; true-hash lookup missed")
	}
	if found.ContentHash != trueHash {
		t.Fatalf("stored entity's ContentHash not normalized to the true hash: got %s", found.ContentHash)
	}
	// And the resulting map passes the receiver-side binding check.
	if err := VerifyIncludedKeyBinding(env.Included); err != nil {
		t.Fatalf("Include-built map must satisfy VerifyIncludedKeyBinding: %v", err)
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

		// The ABSOLUTE-path spelling. The contract has always named three
		// cases (URI, absolute, peer-relative) and this table covered two —
		// so the absolute case returned the path unchanged, peer_id still
		// attached, for as long as it has existed. Callers qualify the result
		// (store.QualifyPath prepends unconditionally), so the peer_id landed
		// twice: "/{peer}//{peer}/rest". The empty segment panicked
		// NamespacedIndex.canonicalize — and the path is reachable from the
		// WIRE, since core/protocol resolveHandler feeds an inbound EXECUTE's
		// `uri` straight through here. A remote peer could crash the peer
		// serving it just by spelling the uri as a path instead of a URI.
		{"/" + testPeerID + "/system/tree", "system/tree"},
		{"/" + testPeerID + "/system/protocol/connect", "system/protocol/connect"},
		{"/" + testPeerID + "/local/files/readme.md", "local/files/readme.md"},
		{"/" + testPeerID, testPeerID},
		{"entity://" + testPeerID, testPeerID},
	}

	for _, tt := range tests {
		result := ExtractHandlerPath(tt.input)
		if result != tt.expected {
			t.Fatalf("ExtractHandlerPath(%q): expected %q, got %q", tt.input, tt.expected, result)
		}
	}
}

// A URI and the equivalent absolute path are two spellings of ONE address
// (V7 §1.4), so they must reduce identically. Asserting the equivalence as a
// property — rather than case by case — is what keeps the two branches from
// drifting apart again.
func TestExtractHandlerPathSpellingsAgree(t *testing.T) {
	for _, rest := range []string{
		"system/tree",
		"system/protocol/connect",
		"system/network/peers/abc/on-reconnect-backoff",
		"a",
	} {
		fromURI := ExtractHandlerPath("entity://" + testPeerID + "/" + rest)
		fromPath := ExtractHandlerPath("/" + testPeerID + "/" + rest)
		if fromURI != fromPath {
			t.Fatalf("spellings disagree for %q: uri form -> %q, path form -> %q", rest, fromURI, fromPath)
		}
		if fromURI != rest {
			t.Fatalf("ExtractHandlerPath lost the handler path for %q: got %q", rest, fromURI)
		}
	}
}

// §4.5a item 1a (v7.77): `system/peer` is authored at the ECFv1-SHA-256 floor
// unconditionally. The rule was previously held only by the two pinned
// constructors, which meant a direct NewEntityFormat call — or NewEntity on a
// peer started --hash-type sha384 — could author an identity into the second
// address space item 1a exists to collapse. Both happened, in our own fixtures,
// and both PASSED, which is why the guard lives at the constructor rather than
// in the callers.
func TestFloorPinnedTypeRefusesNonFloorFormat(t *testing.T) {
	data := makeRawData(t, map[string]any{
		"public_key": make([]byte, 32),
		"key_type":   "ed25519",
	})

	if _, err := NewEntityFormat(hash.AlgorithmSHA256, typeFloorPinned, data); err != nil {
		t.Fatalf("the floor itself must still be authorable: %v", err)
	}

	_, err := NewEntityFormat(hash.AlgorithmSHA384, typeFloorPinned, data)
	if err == nil {
		t.Fatalf("NewEntityFormat authored %s under SHA-384 — §4.5a item 1a forbids it", typeFloorPinned)
	}
	if !errors.Is(err, ecerrors.ErrInvalidEntity) {
		t.Fatalf("want ErrInvalidEntity, got %v", err)
	}
	if !strings.Contains(err.Error(), "item 1a") {
		t.Fatalf("the refusal must name the rule it enforces, got %q", err.Error())
	}
}

// The process-global default is the other route in, and the one that is not a
// fixture problem: a peer started --hash-type sha384 calls SetDefaultHashAlgorithm,
// and every NewEntity after it picks 0x01 up implicitly.
func TestFloorPinnedTypeRefusesNonFloorProcessDefault(t *testing.T) {
	prev := DefaultHashAlgorithm()
	SetDefaultHashAlgorithm(hash.AlgorithmSHA384)
	defer SetDefaultHashAlgorithm(prev)

	data := makeRawData(t, map[string]any{
		"public_key": make([]byte, 32),
		"key_type":   "ed25519",
	})
	if _, err := NewEntity(typeFloorPinned, data); err == nil {
		t.Fatalf("NewEntity authored %s under the SHA-384 process default — §4.5a item 1a forbids it", typeFloorPinned)
	}

	// Every OTHER type still follows the home format — 1a is the single named
	// exception to §1.2, not a network-wide SHA-256 lock.
	ent, err := NewEntity("system/content/blob", data)
	if err != nil {
		t.Fatalf("non-pinned type under the SHA-384 default: %v", err)
	}
	if ent.ContentHash.Algorithm != hash.AlgorithmSHA384 {
		t.Fatalf("non-pinned type authored under 0x%02x, want the home format 0x%02x",
			ent.ContentHash.Algorithm, hash.AlgorithmSHA384)
	}
}

// TestValidateAll_BindsIncludedMapKey pins the decode/receive-path half of the
// map-key-binding fix (core-rust routed 2026-09-13). A mis-keyed included entry
// — an entity filed under a hash that is not its own — is an identity/capability
// forgery vector, because every authority lookup resolves BY HASH out of this
// map. ValidateAll (and VerifyIncludedKeyBinding beneath it) must reject it even
// though each entity is individually self-consistent.
func TestValidateAll_BindsIncludedMapKey(t *testing.T) {
	entA, err := NewEntity("system/note", makeRawData(t, map[string]string{"v": "a"}))
	if err != nil {
		t.Fatal(err)
	}
	entB, err := NewEntity("system/note", makeRawData(t, map[string]string{"v": "b"}))
	if err != nil {
		t.Fatal(err)
	}
	root, err := NewEntity("system/note", makeRawData(t, map[string]string{"v": "root"}))
	if err != nil {
		t.Fatal(err)
	}

	// Positive control: correctly keyed → passes.
	honest := NewEnvelope(root, map[hash.Hash]Entity{
		entA.ContentHash: entA,
		entB.ContentHash: entB,
	})
	if err := honest.ValidateAll(); err != nil {
		t.Fatalf("positive control failed — a correctly-keyed envelope must validate: %v", err)
	}

	// entB is self-consistent but filed under entA's hash: a mis-key.
	forged := NewEnvelope(root, map[hash.Hash]Entity{
		entA.ContentHash: entB, // <-- mis-keyed
	})
	if err := forged.ValidateAll(); err == nil {
		t.Fatalf("mis-keyed included entry ACCEPTED — ValidateAll does not bind the map key")
	} else if !errors.Is(err, ecerrors.ErrInvalidEntity) {
		t.Fatalf("expected ErrInvalidEntity for a mis-keyed entry, got: %v", err)
	}
}
