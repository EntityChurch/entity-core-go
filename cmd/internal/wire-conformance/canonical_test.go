package main

import (
	"encoding/hex"
	"math"
	"testing"

	"github.com/fxamacker/cbor/v2"
)

// TestCanonicalEncoderSpotChecks: known canonical CBOR encodings for a
// small set of well-defined values. If these change, ECF correctness is
// broken.
func TestCanonicalEncoderSpotChecks(t *testing.T) {
	cases := []struct {
		name string
		in   interface{}
		want string
	}{
		{"uint_0", int64(0), "00"},
		{"uint_23", int64(23), "17"},
		{"uint_24", int64(24), "1818"},
		{"uint_255", int64(255), "18ff"},
		{"uint_256", int64(256), "190100"},
		{"nint_1", int64(-1), "20"},
		{"nint_24", int64(-24), "37"},
		{"nint_25", int64(-25), "3818"},
		{"f16_0", float64(0.0), "f90000"},
		{"f16_neg0", math.Copysign(0, -1), "f98000"},
		{"f16_1", float64(1.0), "f93c00"},
		{"f16_max", float64(65504.0), "f97bff"},
		{"empty_array", []interface{}{}, "80"},
		{"empty_map", map[interface{}]interface{}{}, "a0"},
		{"empty_tstr", "", "60"},
		{"empty_bstr", []byte{}, "40"},
		{"null", nil, "f6"},
		{"true", true, "f5"},
		{"false", false, "f4"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, err := encodeCanonical(c.in)
			if err != nil {
				t.Fatalf("encode: %v", err)
			}
			if hex.EncodeToString(got) != c.want {
				t.Fatalf("canonical mismatch: got %s want %s", hex.EncodeToString(got), c.want)
			}
		})
	}
}

// TestMapKeyOrdering: a map authored with keys in non-canonical source
// order must emit canonical-sorted bytes ("a" < "b" < "z" by length-
// then-lex per ECF §4.2.1).
func TestMapKeyOrdering(t *testing.T) {
	m := map[interface{}]interface{}{
		"z":  int64(1),
		"aa": int64(2),
	}
	got, err := encodeCanonical(m)
	if err != nil {
		t.Fatal(err)
	}
	// Canonical:
	//   a2     -- map(2)
	//   61 7a  -- "z" (1-char)
	//   01     -- 1
	//   62 6161 -- "aa" (2-char)
	//   02     -- 2
	want := "a2617a0162616102"
	if hex.EncodeToString(got) != want {
		t.Fatalf("map sort wrong: got %s want %s", hex.EncodeToString(got), want)
	}
}

// TestMixedKeyMap: text and byte keys in one map. ECF sorts by encoded
// key bytes. Encoded "key" (text) is 6b 6b 65 79 (text-3 + 'key').
// Encoded h'6b6579' (bytes) is 43 6b 65 79 (bstr-3 + bytes).
// Byte-key encoding (0x43...) < text-key encoding (0x6b...) bytewise,
// so the byte-keyed entry sorts first.
func TestMixedKeyMap(t *testing.T) {
	m := map[interface{}]interface{}{
		"text_key":         int64(1),
		byteKey("\x6b\x65\x79"): int64(2), // h'6b6579'
	}
	got, err := encodeCanonical(m)
	if err != nil {
		t.Fatal(err)
	}
	// a2                    -- map(2)
	//   43 6b6579           -- bstr(3) "key"
	//   02                  -- 2
	//   68 746578745f6b6579 -- tstr(8) "text_key"
	//   01                  -- 1
	want := "a2436b6579026874657874 5f6b657901"
	want = removeSpaces(want)
	if hex.EncodeToString(got) != want {
		t.Fatalf("mixed-key map wrong: got %s want %s", hex.EncodeToString(got), want)
	}
}

func removeSpaces(s string) string {
	out := make([]byte, 0, len(s))
	for i := 0; i < len(s); i++ {
		if s[i] != ' ' {
			out = append(out, s[i])
		}
	}
	return string(out)
}

// TestRoundTripAgainstCoreDet: for primitives the canonical encoder must
// agree byte-for-byte with fxamacker's CoreDetEncOptions (which we know
// has been validated through W2). This guards against drift between the
// two encoders we use together.
func TestRoundTripAgainstCoreDet(t *testing.T) {
	em, _ := cbor.CoreDetEncOptions().EncMode()
	cases := []interface{}{
		int64(0), int64(23), int64(24), int64(255), int64(256),
		int64(65535), int64(65536), int64(-1), int64(-256),
		float64(0.0), float64(1.5), float64(65504.0), float64(1.1),
		"", "hello",
		nil, true, false,
	}
	for _, c := range cases {
		ours, err := encodeCanonical(c)
		if err != nil {
			t.Fatalf("ours: %v", err)
		}
		theirs, err := em.Marshal(c)
		if err != nil {
			t.Fatalf("theirs: %v", err)
		}
		if hex.EncodeToString(ours) != hex.EncodeToString(theirs) {
			t.Fatalf("drift on %#v: ours=%s theirs=%s",
				c, hex.EncodeToString(ours), hex.EncodeToString(theirs))
		}
	}
}
