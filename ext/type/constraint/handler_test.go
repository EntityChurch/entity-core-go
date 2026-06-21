package constraint

import (
	"bytes"
	"testing"

	"go.entitychurch.org/entity-core-go/core/ecf"
	"go.entitychurch.org/entity-core-go/core/types"

	"github.com/fxamacker/cbor/v2"
)

// must encodes v via ECF and fails the test on error.
func must(t *testing.T, v interface{}) cbor.RawMessage {
	t.Helper()
	raw, err := ecf.Encode(v)
	if err != nil {
		t.Fatalf("ecf.Encode(%T): %v", v, err)
	}
	return cbor.RawMessage(raw)
}

// req builds a dispatch envelope for the per-kind evaluator.
func req(ct string, data, value interface{}) types.ConstraintValidateRequestData {
	return types.ConstraintValidateRequestData{
		Value:          mustNoT(value),
		ConstraintType: ct,
		ConstraintData: mustNoT(data),
	}
}

func mustNoT(v interface{}) cbor.RawMessage {
	raw, err := ecf.Encode(v)
	if err != nil {
		panic(err)
	}
	return cbor.RawMessage(raw)
}

func TestEvaluateMin(t *testing.T) {
	cases := []struct {
		name  string
		c     types.ConstraintMinData
		v     interface{}
		valid bool
	}{
		{"at-boundary", types.ConstraintMinData{Min: 0}, 0, true},
		{"above", types.ConstraintMinData{Min: 0}, 5, true},
		{"below", types.ConstraintMinData{Min: 10}, 5, false},
		{"float-above", types.ConstraintMinData{Min: 1.5}, 2.0, true},
		{"non-numeric", types.ConstraintMinData{Min: 0}, "abc", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := evaluate(nil, req(types.TypeConstraintMin, tc.c, tc.v))
			if r.Valid != tc.valid {
				t.Errorf("got valid=%v reason=%q, want %v", r.Valid, r.Reason, tc.valid)
			}
		})
	}
}

func TestEvaluateMax(t *testing.T) {
	cases := []struct {
		name  string
		c     types.ConstraintMaxData
		v     interface{}
		valid bool
	}{
		{"at-boundary", types.ConstraintMaxData{Max: 10}, 10, true},
		{"below", types.ConstraintMaxData{Max: 10}, 5, true},
		{"above", types.ConstraintMaxData{Max: 10}, 20, false},
		{"non-numeric", types.ConstraintMaxData{Max: 10}, "abc", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := evaluate(nil, req(types.TypeConstraintMax, tc.c, tc.v))
			if r.Valid != tc.valid {
				t.Errorf("got valid=%v reason=%q, want %v", r.Valid, r.Reason, tc.valid)
			}
		})
	}
}

func TestEvaluateMinLength(t *testing.T) {
	cases := []struct {
		name  string
		min   uint64
		v     interface{}
		valid bool
	}{
		{"empty-fails", 1, "", false},
		{"single-ok", 1, "x", true},
		{"unicode-codepoints", 2, "日本", true},
		{"unicode-too-short", 3, "日本", false},
		{"bytes-ok", 3, []byte{1, 2, 3}, true},
		{"bytes-fail", 4, []byte{1, 2, 3}, false},
		{"not-string-or-bytes", 1, 42, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := evaluate(nil, req(types.TypeConstraintMinLength,
				types.ConstraintMinLengthData{MinLength: tc.min}, tc.v))
			if r.Valid != tc.valid {
				t.Errorf("got valid=%v reason=%q, want %v", r.Valid, r.Reason, tc.valid)
			}
		})
	}
}

func TestEvaluateMaxLength(t *testing.T) {
	r := evaluate(nil, req(types.TypeConstraintMaxLength,
		types.ConstraintMaxLengthData{MaxLength: 2}, "abc"))
	if r.Valid {
		t.Error("'abc' should not satisfy max_length=2")
	}
	r = evaluate(nil, req(types.TypeConstraintMaxLength,
		types.ConstraintMaxLengthData{MaxLength: 5}, "abc"))
	if !r.Valid {
		t.Errorf("'abc' should satisfy max_length=5, got %q", r.Reason)
	}
}

func TestEvaluateMinCount(t *testing.T) {
	arr := []int{1, 2, 3}
	r := evaluate(nil, req(types.TypeConstraintMinCount,
		types.ConstraintMinCountData{MinCount: 2}, arr))
	if !r.Valid {
		t.Errorf("3-elem array should satisfy min_count=2, got %q", r.Reason)
	}
	r = evaluate(nil, req(types.TypeConstraintMinCount,
		types.ConstraintMinCountData{MinCount: 5}, arr))
	if r.Valid {
		t.Error("3-elem array should not satisfy min_count=5")
	}
}

func TestEvaluateMaxCount(t *testing.T) {
	m := map[string]int{"a": 1, "b": 2}
	r := evaluate(nil, req(types.TypeConstraintMaxCount,
		types.ConstraintMaxCountData{MaxCount: 3}, m))
	if !r.Valid {
		t.Errorf("2-key map should satisfy max_count=3, got %q", r.Reason)
	}
}

func TestEvaluatePattern(t *testing.T) {
	cases := []struct {
		name    string
		pattern string
		v       string
		valid   bool
	}{
		{"simple-match", "^foo$", "foo", true},
		{"unanchored-input-equivalent", "foo", "foo", true},
		{"full-match-rejects-substring", "foo", "foobar", false},
		{"email-ish", `[^@]+@[^@]+\.[^@]+`, "a@b.c", true},
		{"alpha-fails-digits", `[a-z]+`, "abc123", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := evaluate(nil, req(types.TypeConstraintPattern,
				types.ConstraintPatternData{Pattern: tc.pattern}, tc.v))
			if r.Valid != tc.valid {
				t.Errorf("pattern %q v=%q: got valid=%v reason=%q, want %v",
					tc.pattern, tc.v, r.Valid, r.Reason, tc.valid)
			}
		})
	}
}

// TestPatternPCREBackrefRejected — RE2 does not support backreferences. The
// §12.1 MUST: "RE2 or equivalent linear-time" — backtracking engines
// non-conformant. Pattern compilation MUST fail and the handler MUST report
// invalid; it MUST NOT silently fall back.
func TestPatternPCREBackrefRejected(t *testing.T) {
	r := evaluate(nil, req(types.TypeConstraintPattern,
		types.ConstraintPatternData{Pattern: `(a)\1`}, "aa"))
	if r.Valid {
		t.Error("PCRE backref pattern should be rejected at compile time")
	}
}

// TestEvaluateOneOfECFByteEquality is the load-bearing cross-impl gate per
// §5.5. Two values that decode to the same logical CBOR value MUST canonicalize
// to identical bytes and compare equal — regardless of incoming byte form.
func TestEvaluateOneOfECFByteEquality(t *testing.T) {
	// Allowed list contains the strings "alice" and "bob" and a small int.
	values := []cbor.RawMessage{
		must(t, "alice"),
		must(t, "bob"),
		must(t, 42),
	}
	c := types.ConstraintOneOfData{Values: values}

	cases := []struct {
		name  string
		v     interface{}
		valid bool
	}{
		{"string-match", "alice", true},
		{"int-match", 42, true},
		{"miss", "carol", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := evaluate(nil, req(types.TypeConstraintOneOf, c, tc.v))
			if r.Valid != tc.valid {
				t.Errorf("v=%v: got valid=%v reason=%q, want %v",
					tc.v, r.Valid, r.Reason, tc.valid)
			}
		})
	}

	// Direct byte-level check: ECF re-encoding of the same string from two
	// inputs MUST produce identical bytes. This is the substrate guarantee
	// the constraint relies on.
	a := mustNoT("alice")
	b := mustNoT("alice")
	ca, _ := canonicalize(a)
	cb, _ := canonicalize(b)
	if !bytes.Equal(ca, cb) {
		t.Fatalf("ECF canonicalization differs for identical inputs: %x vs %x", ca, cb)
	}
}

func TestEvaluateNotOneOf(t *testing.T) {
	values := []cbor.RawMessage{must(t, "x"), must(t, "y")}
	c := types.ConstraintNotOneOfData{Values: values}
	if r := evaluate(nil, req(types.TypeConstraintNotOneOf, c, "z")); !r.Valid {
		t.Errorf("'z' should pass not_one_of[x,y]: %q", r.Reason)
	}
	if r := evaluate(nil, req(types.TypeConstraintNotOneOf, c, "x")); r.Valid {
		t.Error("'x' should fail not_one_of[x,y]")
	}
}

func TestEvaluateFormat(t *testing.T) {
	cases := []struct {
		name   string
		format string
		v      string
		valid  bool
	}{
		{"uri-ok", types.FormatURI, "https://example.com/path", true},
		{"uri-no-scheme", types.FormatURI, "example.com/path", false},
		{"date-ok", types.FormatDate, "2026-05-28", true},
		{"date-bad", types.FormatDate, "2026-13-99", false},
		{"date-time-ok", types.FormatDateTime, "2026-05-28T12:34:56Z", true},
		{"date-time-bad", types.FormatDateTime, "yesterday", false},
		{"uuid-ok", types.FormatUUID, "12345678-1234-1234-1234-1234567890ab", true},
		{"uuid-bad", types.FormatUUID, "not-a-uuid", false},
		{"base58-ok", types.FormatBase58, "3MNQE1X", true},
		{"base58-bad", types.FormatBase58, "0OIl", false},
		{"re2-ok", types.FormatRE2, "^foo$", true},
		{"re2-bad-pcre", types.FormatRE2, `(a)\1`, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := evaluate(nil, req(types.TypeConstraintFormat,
				types.ConstraintFormatData{Format: tc.format}, tc.v))
			if r.Valid != tc.valid {
				t.Errorf("format=%s v=%q: got valid=%v reason=%q, want %v",
					tc.format, tc.v, r.Valid, r.Reason, tc.valid)
			}
		})
	}
}

// TestFormatUnknownFailsClosed — §4.5: unknown format names MUST fail closed
// (valid:false) so callers report kind=unknown_constraint instead of silent pass.
func TestFormatUnknownFailsClosed(t *testing.T) {
	r := evaluate(nil, req(types.TypeConstraintFormat,
		types.ConstraintFormatData{Format: "email"}, "a@b.c"))
	if r.Valid {
		t.Error("unknown format 'email' must fail closed")
	}
	if !bytes.Contains([]byte(r.Reason), []byte("unknown format")) {
		t.Errorf("expected 'unknown format' marker in reason, got %q", r.Reason)
	}
}

// TestUnknownConstraintFailsClosed — the §5.4 default arm. Unrecognized
// constraint type → valid:false.
func TestUnknownConstraintFailsClosed(t *testing.T) {
	r := evaluate(nil, req("system/type/constraint/email",
		map[string]string{}, "x@y.z"))
	if r.Valid {
		t.Error("unknown constraint must fail closed")
	}
	if !bytes.Contains([]byte(r.Reason), []byte("unknown constraint type")) {
		t.Errorf("expected 'unknown constraint type' marker, got %q", r.Reason)
	}
}

func TestGlobMatch(t *testing.T) {
	cases := []struct {
		pat, in string
		want    bool
	}{
		{"system/capability/*", "system/capability/grant-entry", true},
		{"system/capability/*", "system/capability/path-scope/foo", false},
		{"system/capability/**", "system/capability/path-scope/foo", true},
		{"system/capability/**", "system/capability", true},
		{"*/leaf", "ns/leaf", true},
		{"*/leaf", "leaf", false},
		{"app/user", "app/user", true},
		{"app/user", "app/admin", false},
	}
	for _, tc := range cases {
		t.Run(tc.pat+"_vs_"+tc.in, func(t *testing.T) {
			if got := globMatch(tc.pat, tc.in); got != tc.want {
				t.Errorf("globMatch(%q, %q) = %v, want %v", tc.pat, tc.in, got, tc.want)
			}
		})
	}
}
