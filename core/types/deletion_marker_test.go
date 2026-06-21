package types

import (
	"bytes"
	"testing"

	"github.com/fxamacker/cbor/v2"

	"go.entitychurch.org/entity-core-go/core/entity"
)

// TestCanonicalDeletionMarkerHash is the cross-impl conformance regression
// test mandated by PROPOSAL-DELETION-MARKERS.md Amendment 1.
//
// Per the spec, every implementation that ships standard ECF encoding MUST
// produce the same content hash for the canonical deletion marker:
//
//	CANONICAL_DELETION_MARKER_HASH = ecf-sha256:689ae4679f69f006e4bf7cb7c7a9155d0de5fb9fe31e81692dca5769eda9e0a6
//
// This test is the local sentinel — if it ever fails, either the ECF encoder
// has changed (regression) or the canonical encoding has shifted (spec drift).
// Either way is a cross-impl interop hazard. Fail loudly.
const canonicalDeletionMarkerHashString = "ecf-sha256:689ae4679f69f006e4bf7cb7c7a9155d0de5fb9fe31e81692dca5769eda9e0a6"

func TestCanonicalDeletionMarkerHash(t *testing.T) {
	h := CanonicalDeletionMarkerHash()
	if got := h.String(); got != canonicalDeletionMarkerHashString {
		t.Fatalf("canonical deletion marker hash drift:\n  got:  %s\n  want: %s\nThis is a cross-impl interop hazard — investigate ECF encoding before merging.",
			got, canonicalDeletionMarkerHashString)
	}
}

// TestCanonicalDeletionMarkerEncoding pins the wire shape of the canonical
// marker. The data field MUST be the CBOR empty map (0xa0). Anything else
// (null, empty byte string, non-empty map) is a spec violation per
// Amendment 1.
func TestCanonicalDeletionMarkerEncoding(t *testing.T) {
	ent := CanonicalDeletionMarker()
	if ent.Type != TypeDeletionMarker {
		t.Fatalf("entity type = %q, want %q", ent.Type, TypeDeletionMarker)
	}
	if !bytes.Equal(ent.Data, cbor.RawMessage{0xa0}) {
		t.Fatalf("canonical data bytes = %x, want %x (CBOR empty map per Amendment 1)",
			[]byte(ent.Data), []byte{0xa0})
	}
}

// TestIsDeletionMarker covers the O(1) hash-equality identification path
// per Amendment 3.
func TestIsDeletionMarker(t *testing.T) {
	markerHash := CanonicalDeletionMarkerHash()
	if !IsDeletionMarker(markerHash) {
		t.Fatal("IsDeletionMarker(canonical hash) returned false")
	}

	// A non-marker hash MUST NOT be identified as a marker.
	other, err := entity.NewEntity("primitive/string", cbor.RawMessage{0x60}) // empty CBOR string
	if err != nil {
		t.Fatalf("build non-marker entity: %v", err)
	}
	if IsDeletionMarker(other.ContentHash) {
		t.Fatalf("IsDeletionMarker reported true for a non-marker hash %s", other.ContentHash)
	}
}

// TestCanonicalDeletionMarkerStability — re-constructing the marker
// produces byte-identical content and identical hash. Verifies the per-format
// cache doesn't drift across calls and confirms canonicality.
func TestCanonicalDeletionMarkerStability(t *testing.T) {
	first := CanonicalDeletionMarker()
	second := CanonicalDeletionMarker()
	if first.ContentHash != second.ContentHash {
		t.Fatalf("canonical marker not stable: %s vs %s", first.ContentHash, second.ContentHash)
	}
	if !bytes.Equal(first.Data, second.Data) {
		t.Fatalf("canonical marker data not stable")
	}

	// Re-building via NewEntity directly with the same inputs must produce
	// the same hash — canonicality is independent of the cache.
	rebuilt, err := entity.NewEntity(TypeDeletionMarker, cbor.RawMessage{0xa0})
	if err != nil {
		t.Fatalf("rebuild marker: %v", err)
	}
	if rebuilt.ContentHash != first.ContentHash {
		t.Fatalf("rebuilt marker hash differs from cached: rebuilt=%s cached=%s",
			rebuilt.ContentHash, first.ContentHash)
	}
}

// TestDeletionMarkerFormatRelative pins the V7 v7.70 §4.9 / EXTENSION-REVISION
// §766 ruling: the marker is a zero-field CONTENT entity, hashed under the
// trie's own home format. The SHA-256 instance is 689ae4…; the SHA-384 instance
// is a different hash; IsDeletionMarker recognizes both natively off the
// hash's algorithm byte (no content-store load). The SHA-256 constant is NOT a
// universal pin.
func TestDeletionMarkerFormatRelative(t *testing.T) {
	h256, err := DeletionMarkerHashForFormat(0x00) // SHA-256
	if err != nil {
		t.Fatalf("marker hash under SHA-256: %v", err)
	}
	if got := h256.String(); got != canonicalDeletionMarkerHashString {
		t.Fatalf("SHA-256 marker hash drift: got %s want %s", got, canonicalDeletionMarkerHashString)
	}

	h384, err := DeletionMarkerHashForFormat(0x01) // SHA-384
	if err != nil {
		t.Fatalf("marker hash under SHA-384: %v", err)
	}
	if h256 == h384 {
		t.Fatalf("SHA-256 and SHA-384 marker hashes must differ: both = %s", h256)
	}
	if h384.Algorithm != 0x01 {
		t.Fatalf("SHA-384 marker hash algorithm byte = 0x%02x, want 0x01", h384.Algorithm)
	}

	// IsDeletionMarker MUST recognize both natively (format-relative).
	if !IsDeletionMarker(h256) {
		t.Fatalf("IsDeletionMarker(SHA-256 marker) returned false")
	}
	if !IsDeletionMarker(h384) {
		t.Fatalf("IsDeletionMarker(SHA-384 marker) returned false — format-relative recognition broken")
	}
}
