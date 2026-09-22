package tree

import (
	"testing"

	"github.com/fxamacker/cbor/v2"

	"go.entitychurch.org/entity-core-go/core/ecf"
)

// TestPut_AbsentContentHash_IsInvalidRequest pins EXTENSION-TREE Appendix A
// `put` row 1 (v4.5): content_hash is a required field of core/entity
// (ENTITY-NATIVE-TYPE-SYSTEM §8.1), so an ABSENT or null content_hash is a
// STRUCTURAL defect — step 1 of §6.3's admission ladder → 400 invalid_request —
// NOT a hash mismatch. Present-but-wrong is step 2 → 400 hash_mismatch.
//
// This is the exact wire shape rust/py SDKs currently send (a two-key
// {type, data} map). Before the fix go answered 400 hash_mismatch for BOTH
// absent and present-wrong (it could not distinguish them); the mutation
// witness is that absent now separates from present-wrong.
func TestPut_AbsentContentHash_IsInvalidRequest(t *testing.T) {
	data, err := ecf.Encode(map[string]string{"v": "1"})
	if err != nil {
		t.Fatal(err)
	}

	// 1. content_hash ABSENT (two-key map) → structural → invalid_request.
	twoKey, err := ecf.Encode(map[string]interface{}{
		"type": "test/doc",
		"data": cbor.RawMessage(data),
	})
	if err != nil {
		t.Fatal(err)
	}
	if st, code := putErrorCode(t, cbor.RawMessage(twoKey)); st != 400 || code != "invalid_request" {
		t.Errorf("absent content_hash: got %d/%q, want 400/invalid_request (v4.5 row 1, required field)", st, code)
	}

	// 2. content_hash present but NULL → also structural (a required field
	//    cannot be null) → invalid_request.
	nullHash, err := ecf.Encode(map[string]interface{}{
		"type":         "test/doc",
		"data":         cbor.RawMessage(data),
		"content_hash": nil,
	})
	if err != nil {
		t.Fatal(err)
	}
	if st, code := putErrorCode(t, cbor.RawMessage(nullHash)); st != 400 || code != "invalid_request" {
		t.Errorf("null content_hash: got %d/%q, want 400/invalid_request", st, code)
	}

	// 3. content_hash PRESENT but wrong → hash mismatch (step 2). This proves
	//    the absent case is distinguished from the mismatch case.
	e := makeEntity(t, "test/doc", map[string]string{"v": "1"})
	other := makeEntity(t, "test/doc", map[string]string{"v": "2"})
	e.ContentHash = other.ContentHash
	tampered, err := ecf.Encode(e)
	if err != nil {
		t.Fatal(err)
	}
	if st, code := putErrorCode(t, cbor.RawMessage(tampered)); st != 400 || code != "hash_mismatch" {
		t.Errorf("present-but-wrong content_hash: got %d/%q, want 400/hash_mismatch", st, code)
	}
}
