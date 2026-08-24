package validate

import (
	"bytes"
	"testing"

	"go.entitychurch.org/entity-core-go/core/hash"

	"github.com/fxamacker/cbor/v2"
)

// TestCollectHashSizedByteStrings_StructuralNotOffsetScan pins the fix for the
// recurring `hash_wire_format` flake (python 2026-08-08, rust 2026-08-14): the
// collector must find hashes as CBOR byte-string ITEMS, never as byte patterns
// inside another item's content. The regression case (a long byte string whose
// payload embeds 0x58,0x21 — the header the old offset scanner matched) is the
// one that used to flake; it must surface ZERO hash-sized items now.
func TestCollectHashSizedByteStrings_StructuralNotOffsetScan(t *testing.T) {
	mustCBOR := func(v interface{}) []byte {
		b, err := cbor.Marshal(v)
		if err != nil {
			t.Fatalf("marshal: %v", err)
		}
		return b
	}

	sha256Hash := make([]byte, hash.HashWireSize(hash.AlgorithmSHA256)) // 33, [0]=0x00
	sha384Hash := make([]byte, hash.HashWireSize(hash.AlgorithmSHA384)) // 49, [0]=0x01
	sha384Hash[0] = hash.AlgorithmSHA384

	// A 64-byte payload (a digest/signature-sized blob) that CONTAINS the byte
	// pair 0x58,0x21 followed by a byte that is not a valid format code. The old
	// scanner read this as a phantom 33-byte hash with format 0xFF and FAILed.
	collisionBlob := make([]byte, 64)
	collisionBlob[10] = 0x58
	collisionBlob[11] = 0x21
	collisionBlob[12] = 0xFF

	// A genuinely malformed hash: a 33-byte byte-string ITEM whose leading
	// format byte is unallocated. This MUST still be surfaced (§8.4.5).
	badFormatHash := make([]byte, 33)
	badFormatHash[0] = 0xFF

	tests := []struct {
		name         string
		frame        []byte
		wantCount    int
		wantAllValid bool // every collected item's [0] matches its length
		wantAnyItem  []byte
	}{
		{
			name:      "content collision is not a phantom item",
			frame:     mustCBOR(map[string]interface{}{"sig": collisionBlob}),
			wantCount: 0,
		},
		{
			name:         "real sha256 hash item collected and valid",
			frame:        mustCBOR(map[string]interface{}{"content_hash": sha256Hash}),
			wantCount:    1,
			wantAllValid: true,
			wantAnyItem:  sha256Hash,
		},
		{
			name:         "real sha384 hash item collected and valid",
			frame:        mustCBOR(map[string]interface{}{"content_hash": sha384Hash}),
			wantCount:    1,
			wantAllValid: true,
			wantAnyItem:  sha384Hash,
		},
		{
			name:         "hash-sized item with bad format byte is still surfaced (invalid)",
			frame:        mustCBOR(map[string]interface{}{"content_hash": badFormatHash}),
			wantCount:    1,
			wantAllValid: false,
		},
		{
			name:         "hash nested in array-in-map is still found (structural recursion)",
			frame:        mustCBOR(map[string]interface{}{"included": []interface{}{map[string]interface{}{"h": sha256Hash}}}),
			wantCount:    1,
			wantAllValid: true,
		},
		{
			name:         "collision blob alongside a real hash: exactly one item, no phantom",
			frame:        mustCBOR(map[string]interface{}{"sig": collisionBlob, "content_hash": sha256Hash}),
			wantCount:    1,
			wantAllValid: true,
			wantAnyItem:  sha256Hash,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := collectHashSizedByteStrings(tc.frame)
			if len(got) != tc.wantCount {
				t.Fatalf("collected %d items, want %d: %x", len(got), tc.wantCount, got)
			}
			allValid := true
			for _, bs := range got {
				if hash.HashWireSize(bs[0]) != len(bs) {
					allValid = false
				}
			}
			if tc.wantCount > 0 && allValid != tc.wantAllValid {
				t.Fatalf("allValid=%v, want %v", allValid, tc.wantAllValid)
			}
			if tc.wantAnyItem != nil {
				found := false
				for _, bs := range got {
					if bytes.Equal(bs, tc.wantAnyItem) {
						found = true
					}
				}
				if !found {
					t.Fatalf("expected item %x not collected", tc.wantAnyItem)
				}
			}
		})
	}
}

// TestCollectHashSizedByteStrings_UndecodableFrameIsNil pins the WARN path: a
// frame that is not valid CBOR yields no items (the check then WARNs "could not
// locate" rather than silently passing).
func TestCollectHashSizedByteStrings_UndecodableFrameIsNil(t *testing.T) {
	if got := collectHashSizedByteStrings([]byte{0xFF, 0xFF, 0xFF}); got != nil {
		t.Fatalf("undecodable frame: got %x, want nil", got)
	}
}
