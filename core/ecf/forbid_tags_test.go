package ecf

import (
	"errors"
	"testing"

	ecerrors "go.entitychurch.org/entity-core-go/core/errors"
)

// TestForbidTags pins ENTITY-CBOR-ENCODING §6.3 (0.8.2.26 DR-3): a CBOR tag
// (major type 6) at ANY depth is non-canonical ECF and MUST be rejected; every
// tag-free canonical value passes. The tag-bearing rows are the check; the
// tag-free rows are the containment control — a walker that rejected an
// innocent value would red them.
func TestForbidTags(t *testing.T) {
	tagFree := []struct {
		name string
		data []byte
	}{
		{"int", []byte{0x01}},
		{"text_x", []byte{0x61, 0x78}},
		{"array_of_ints", []byte{0x83, 0x01, 0x02, 0x03}},
		// {"t":"y","marker":"x"} — canonical key order.
		{"map", []byte{0xA2, 0x61, 0x74, 0x61, 0x79, 0x66, 0x6d, 0x61, 0x72, 0x6b, 0x65, 0x72, 0x61, 0x78}},
		{"nested_map_in_array", []byte{0x81, 0xA1, 0x61, 0x74, 0x61, 0x79}},
		{"float", []byte{0xFA, 0x3F, 0x80, 0x00, 0x00}}, // 1.0
		{"simple_true", []byte{0xF5}},
	}
	for _, tc := range tagFree {
		t.Run("clean/"+tc.name, func(t *testing.T) {
			if err := ForbidTags(tc.data); err != nil {
				t.Fatalf("ForbidTags(%x) = %v; want nil (tag-free canonical value)", tc.data, err)
			}
		})
	}

	tagged := []struct {
		name string
		data []byte
	}{
		{"tag0_top", []byte{0xC0, 0x61, 0x78}},                           // 0("x")
		{"tag_in_array", []byte{0x81, 0xC0, 0x61, 0x78}},                 // [0("x")]
		{"tag_as_map_value", []byte{0xA1, 0x61, 0x74, 0xC0, 0x61, 0x78}}, // {"t":0("x")}
		{"tag_as_map_key", []byte{0xA1, 0xC0, 0x61, 0x74, 0x61, 0x79}},   // {0("t"):"y"}
		{"tag55799_wrapping", []byte{0xD9, 0xD9, 0xF7, 0x61, 0x78}},      // 55799("x")
		{"tag55799_deep", []byte{0x81, 0xD9, 0xD9, 0xF7, 0x01}},          // [55799(1)]
		{"tag1_uint", []byte{0xC1, 0x00}},                                // 1(0)
	}
	for _, tc := range tagged {
		t.Run("tagged/"+tc.name, func(t *testing.T) {
			err := ForbidTags(tc.data)
			if err == nil {
				t.Fatalf("ForbidTags(%x) = nil; want ErrNonCanonicalECF (tag present)", tc.data)
			}
			if !errors.Is(err, ecerrors.ErrNonCanonicalECF) {
				t.Fatalf("ForbidTags(%x) = %v; want it to wrap ErrNonCanonicalECF", tc.data, err)
			}
		})
	}
}
