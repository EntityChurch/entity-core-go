package tree

import (
	"testing"

	"github.com/fxamacker/cbor/v2"

	"go.entitychurch.org/entity-core-go/core/ecf"
)

// TestPut_UnsupportedContentHashFormat pins EXTENSION-TREE Appendix A `put`
// row 4 (v4.5): a well-formed content_hash byte string whose leading format
// code the peer does not support → 400 unsupported_content_hash_format (the
// §1.2 ingest-dispatch case, ENTITY-CORE-PROTOCOL §4.7 row 5) — NOT the generic
// invalid_request row. A mis-sized hash under a KNOWN format stays
// invalid_request (structural), which is the mutation witness: the two must not
// collapse. rust and py both drove go into invalid_request here before the fix.
func TestPut_UnsupportedContentHashFormat(t *testing.T) {
	data, err := ecf.Encode(map[string]string{"v": "1"})
	if err != nil {
		t.Fatal(err)
	}
	put := func(ch []byte) (uint, string) {
		raw, err := ecf.Encode(map[string]interface{}{
			"type":         "test/doc",
			"data":         cbor.RawMessage(data),
			"content_hash": ch,
		})
		if err != nil {
			t.Fatal(err)
		}
		return putErrorCode(t, cbor.RawMessage(raw))
	}

	// 1. Unsupported format 0x02, plausible 64-byte digest → row 4.
	ch1 := make([]byte, 1+64)
	ch1[0] = 0x02
	if st, code := put(ch1); st != 400 || code != "unsupported_content_hash_format" {
		t.Errorf("0x02||64: got %d/%q, want 400/unsupported_content_hash_format (v4.5 row 4)", st, code)
	}

	// 2. Unsupported format 0x7f, 32-byte digest → row 4.
	ch2 := make([]byte, 1+32)
	ch2[0] = 0x7f
	if st, code := put(ch2); st != 400 || code != "unsupported_content_hash_format" {
		t.Errorf("0x7f||32: got %d/%q, want 400/unsupported_content_hash_format", st, code)
	}

	// 3. Mutation witness: KNOWN format 0x00 with the wrong length is mis-sized
	//    (structural) → invalid_request, NOT unsupported_content_hash_format.
	ch3 := make([]byte, 1+10)
	ch3[0] = 0x00
	if st, code := put(ch3); st != 400 || code != "invalid_request" {
		t.Errorf("0x00||10 (mis-sized known format): got %d/%q, want 400/invalid_request", st, code)
	}
}
