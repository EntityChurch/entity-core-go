// Package constraint implements the standard constraint handler bound at
// pattern system/type/constraint/* per EXTENSION-TYPE v1.1 §5.
//
// The handler is a fixed evaluator for the 11 standard constraint types
// declared at system/type/constraint/{kind}. It is deterministic, bounded,
// always terminates (Class 1 convergence per §5.6).
package constraint

import (
	"bytes"
	"context"
	"fmt"
	"net/url"
	"regexp"
	"strings"
	"time"
	"unicode/utf8"

	"go.entitychurch.org/entity-core-go/core/ecf"
	"go.entitychurch.org/entity-core-go/core/entity"
	"go.entitychurch.org/entity-core-go/core/handler"
	"go.entitychurch.org/entity-core-go/core/hash"
	"go.entitychurch.org/entity-core-go/core/types"

	"github.com/fxamacker/cbor/v2"
	"github.com/mr-tron/base58"
)

// handlerPattern is the registration path. Per V7 §6.6 the dispatcher
// walks back through parent path segments looking for a system/handler
// entity, so binding the standard constraint handler at the prefix
// system/type/constraint catches all subpaths
// (system/type/constraint/min, .../pattern, etc.) — the spec's "pattern
// system/type/constraint/*" is the same semantic, expressed as a glob.
const handlerPattern = "system/type/constraint"

// Handler implements the standard constraint handler (§5.1).
type Handler struct{}

// NewHandler returns a stateless constraint-handler instance.
func NewHandler() *Handler { return &Handler{} }

func (h *Handler) Name() string { return "standard-constraints" }

// Manifest returns the handler's self-description per §5.1.
func (h *Handler) Manifest() types.HandlerManifestData {
	return types.HandlerManifestData{
		Pattern: handlerPattern,
		Name:    "standard-constraints",
		Operations: map[string]types.HandlerOperationSpec{
			"validate": {
				InputType:  types.TypeConstraintValidateReq,
				OutputType: types.TypeConstraintValidateResult,
			},
		},
	}
}

// RegisterTypes is a no-op — constraint types are registered in RegisterCoreTypes.
func (h *Handler) RegisterTypes(r *types.TypeRegistry) {}

// Handle dispatches per §5.4.
func (h *Handler) Handle(ctx context.Context, req *handler.Request) (*handler.Response, error) {
	if req.Operation != "validate" {
		return handler.NewErrorResponse(400, "unknown_operation",
			"standard constraint handler does not support operation: "+req.Operation)
	}

	var dispatch types.ConstraintValidateRequestData
	if err := ecf.Decode(req.Params.Data, &dispatch); err != nil {
		return handler.NewErrorResponse(400, "decode_error",
			"failed to decode validate-request: "+err.Error())
	}

	result := evaluate(req.Context, dispatch)
	return handler.NewResponse(200, types.TypeConstraintValidateResult, result)
}

// evaluate is the standard §5.4 dispatch. Exposed (lower-case) for testing.
func evaluate(hctx *handler.HandlerContext, req types.ConstraintValidateRequestData) types.ConstraintValidateResultData {
	switch req.ConstraintType {
	case types.TypeConstraintMin:
		var c types.ConstraintMinData
		if err := ecf.Decode(req.ConstraintData, &c); err != nil {
			return invalid("min: decode failed: " + err.Error())
		}
		v, ok := decodeNumeric(req.Value)
		if !ok {
			return invalid("min: not numeric")
		}
		if v != v { // NaN check (§4.1)
			return invalid(fmt.Sprintf("must be >= %v", c.Min))
		}
		if v >= c.Min {
			return valid()
		}
		return invalid(fmt.Sprintf("must be >= %v", c.Min))

	case types.TypeConstraintMax:
		var c types.ConstraintMaxData
		if err := ecf.Decode(req.ConstraintData, &c); err != nil {
			return invalid("max: decode failed: " + err.Error())
		}
		v, ok := decodeNumeric(req.Value)
		if !ok {
			return invalid("max: not numeric")
		}
		if v != v {
			return invalid(fmt.Sprintf("must be <= %v", c.Max))
		}
		if v <= c.Max {
			return valid()
		}
		return invalid(fmt.Sprintf("must be <= %v", c.Max))

	case types.TypeConstraintMinLength:
		var c types.ConstraintMinLengthData
		if err := ecf.Decode(req.ConstraintData, &c); err != nil {
			return invalid("min_length: decode failed: " + err.Error())
		}
		n, ok := measureLength(req.Value)
		if !ok {
			return invalid("min_length: not a string or bytes")
		}
		if uint64(n) >= c.MinLength {
			return valid()
		}
		return invalid(fmt.Sprintf("length must be >= %d", c.MinLength))

	case types.TypeConstraintMaxLength:
		var c types.ConstraintMaxLengthData
		if err := ecf.Decode(req.ConstraintData, &c); err != nil {
			return invalid("max_length: decode failed: " + err.Error())
		}
		n, ok := measureLength(req.Value)
		if !ok {
			return invalid("max_length: not a string or bytes")
		}
		if uint64(n) <= c.MaxLength {
			return valid()
		}
		return invalid(fmt.Sprintf("length must be <= %d", c.MaxLength))

	case types.TypeConstraintMinCount:
		var c types.ConstraintMinCountData
		if err := ecf.Decode(req.ConstraintData, &c); err != nil {
			return invalid("min_count: decode failed: " + err.Error())
		}
		n, ok := collectionSize(req.Value)
		if !ok {
			return invalid("min_count: not an array or map")
		}
		if uint64(n) >= c.MinCount {
			return valid()
		}
		return invalid(fmt.Sprintf("count must be >= %d", c.MinCount))

	case types.TypeConstraintMaxCount:
		var c types.ConstraintMaxCountData
		if err := ecf.Decode(req.ConstraintData, &c); err != nil {
			return invalid("max_count: decode failed: " + err.Error())
		}
		n, ok := collectionSize(req.Value)
		if !ok {
			return invalid("max_count: not an array or map")
		}
		if uint64(n) <= c.MaxCount {
			return valid()
		}
		return invalid(fmt.Sprintf("count must be <= %d", c.MaxCount))

	case types.TypeConstraintPattern:
		var c types.ConstraintPatternData
		if err := ecf.Decode(req.ConstraintData, &c); err != nil {
			return invalid("pattern: decode failed: " + err.Error())
		}
		s, ok := decodeString(req.Value)
		if !ok {
			return invalid("pattern: not a string")
		}
		re, err := compileFullMatch(c.Pattern)
		if err != nil {
			// Invalid pattern — fail closed per §1.2 / §12.1 (RE2-only).
			return types.ConstraintValidateResultData{
				Valid:  false,
				Reason: "pattern: invalid RE2 pattern: " + err.Error(),
			}
		}
		if re.MatchString(s) {
			return valid()
		}
		return invalid("must match pattern: " + c.Pattern)

	case types.TypeConstraintOneOf:
		var c types.ConstraintOneOfData
		if err := ecf.Decode(req.ConstraintData, &c); err != nil {
			return invalid("one_of: decode failed: " + err.Error())
		}
		ok, err := ecfByteEqualAny(req.Value, c.Values)
		if err != nil {
			return invalid("one_of: ECF canonicalization failed: " + err.Error())
		}
		if ok {
			return valid()
		}
		return invalid("must be one of the allowed values")

	case types.TypeConstraintNotOneOf:
		var c types.ConstraintNotOneOfData
		if err := ecf.Decode(req.ConstraintData, &c); err != nil {
			return invalid("not_one_of: decode failed: " + err.Error())
		}
		ok, err := ecfByteEqualAny(req.Value, c.Values)
		if err != nil {
			return invalid("not_one_of: ECF canonicalization failed: " + err.Error())
		}
		if !ok {
			return valid()
		}
		return invalid("must not be one of the disallowed values")

	case types.TypeConstraintFormat:
		var c types.ConstraintFormatData
		if err := ecf.Decode(req.ConstraintData, &c); err != nil {
			return invalid("format: decode failed: " + err.Error())
		}
		return validateFormat(req.Value, c.Format)

	case types.TypeConstraintTypePattern:
		var c types.ConstraintTypePatternData
		if err := ecf.Decode(req.ConstraintData, &c); err != nil {
			return invalid("type_pattern: decode failed: " + err.Error())
		}
		return validateTypePattern(hctx, req.Value, c.Pattern)

	default:
		// Standard handler does not recognize this constraint type — fail
		// closed (§1.2 / §5.4 default arm). The caller surfaces this as a
		// violation kind=unknown_constraint at the type-handler layer.
		return invalid("unknown constraint type: " + req.ConstraintType)
	}
}

func valid() types.ConstraintValidateResultData {
	return types.ConstraintValidateResultData{Valid: true}
}

func invalid(reason string) types.ConstraintValidateResultData {
	return types.ConstraintValidateResultData{Valid: false, Reason: reason}
}

// decodeNumeric tries to coerce a CBOR-encoded value into a float64. Returns
// (NaN, true) for actual numeric NaN to keep §4.1 semantics (NaN comparisons
// return false at the call site).
func decodeNumeric(raw cbor.RawMessage) (float64, bool) {
	var f float64
	if err := ecf.Decode(raw, &f); err == nil {
		return f, true
	}
	var u uint64
	if err := ecf.Decode(raw, &u); err == nil {
		return float64(u), true
	}
	var i int64
	if err := ecf.Decode(raw, &i); err == nil {
		return float64(i), true
	}
	return 0, false
}

// decodeString tries to coerce a CBOR-encoded value into a Go string.
func decodeString(raw cbor.RawMessage) (string, bool) {
	var s string
	if err := ecf.Decode(raw, &s); err == nil {
		return s, true
	}
	return "", false
}

// measureLength returns codepoint count for strings, byte count for byte
// strings (§4.2).
func measureLength(raw cbor.RawMessage) (int, bool) {
	var s string
	if err := ecf.Decode(raw, &s); err == nil {
		return utf8.RuneCountInString(s), true
	}
	var b []byte
	if err := ecf.Decode(raw, &b); err == nil {
		return len(b), true
	}
	return 0, false
}

// collectionSize returns element count for arrays / entry count for maps (§4.2).
func collectionSize(raw cbor.RawMessage) (int, bool) {
	var arr []cbor.RawMessage
	if err := ecf.Decode(raw, &arr); err == nil {
		return len(arr), true
	}
	var m map[interface{}]cbor.RawMessage
	if err := ecf.Decode(raw, &m); err == nil {
		return len(m), true
	}
	return 0, false
}

// compileFullMatch wraps the user RE2 pattern with ^...$ to enforce the §4.3
// full-match semantic.
func compileFullMatch(pattern string) (*regexp.Regexp, error) {
	// regexp.Compile already accepts RE2; backreferences and other PCRE-only
	// features fail compilation here, which is the correct fail-closed
	// behavior per §12.1.
	return regexp.Compile("^(?:" + pattern + ")$")
}

// ecfByteEqualAny canonicalizes the input value via ECF and compares against
// the same canonicalization of each list element. This is the §5.5
// normative byte-equality semantic; it is the load-bearing cross-impl gate
// for the standard constraint handler.
func ecfByteEqualAny(value cbor.RawMessage, list []cbor.RawMessage) (bool, error) {
	want, err := canonicalize(value)
	if err != nil {
		return false, fmt.Errorf("value: %w", err)
	}
	for i, elem := range list {
		got, err := canonicalize(elem)
		if err != nil {
			return false, fmt.Errorf("values[%d]: %w", i, err)
		}
		if bytes.Equal(want, got) {
			return true, nil
		}
	}
	return false, nil
}

// canonicalize decodes raw CBOR and re-encodes it via the ECF deterministic
// encoder. Two inputs that decode to the same logical value produce the same
// bytes regardless of incoming byte representation.
func canonicalize(raw cbor.RawMessage) ([]byte, error) {
	var v interface{}
	if err := ecf.Decode(raw, &v); err != nil {
		return nil, err
	}
	return ecf.Encode(v)
}

// validateFormat checks a string value against a named format per §4.5.
// Unknown format names fail closed.
func validateFormat(raw cbor.RawMessage, format string) types.ConstraintValidateResultData {
	s, ok := decodeString(raw)
	if !ok {
		return invalid("format: not a string")
	}
	switch format {
	case types.FormatURI:
		// RFC 3986. url.Parse is permissive; require an absolute form with a
		// scheme to avoid the empty-string and bare-fragment false positives.
		u, err := url.Parse(s)
		if err != nil || u.Scheme == "" {
			return invalid("format: not a valid URI")
		}
		return valid()

	case types.FormatDateTime:
		// RFC 3339 — try a few common shapes; time.RFC3339 / RFC3339Nano cover
		// the standard cases.
		layouts := []string{time.RFC3339, time.RFC3339Nano}
		for _, layout := range layouts {
			if _, err := time.Parse(layout, s); err == nil {
				return valid()
			}
		}
		return invalid("format: not a valid RFC 3339 date-time")

	case types.FormatDate:
		// RFC 3339 §5.6 full-date is YYYY-MM-DD.
		if _, err := time.Parse("2006-01-02", s); err == nil {
			return valid()
		}
		return invalid("format: not a valid RFC 3339 date")

	case types.FormatUUID:
		if isUUID(s) {
			return valid()
		}
		return invalid("format: not a valid UUID")

	case types.FormatBase58:
		// Empty string accepted as a degenerate valid input; non-empty input
		// must decode cleanly.
		if s == "" {
			return valid()
		}
		if _, err := base58.Decode(s); err != nil {
			return invalid("format: not a valid Base58 string")
		}
		return valid()

	case types.FormatRE2:
		if _, err := regexp.Compile(s); err != nil {
			return invalid("format: not a valid RE2 pattern: " + err.Error())
		}
		return valid()

	default:
		// Unknown format — fail closed (§4.5).
		return invalid("unknown format: " + format)
	}
}

// uuidRE matches the standard 8-4-4-4-12 hex form (case-insensitive). RFC
// 4122 permits but does not require uppercase; both are accepted.
var uuidRE = regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`)

func isUUID(s string) bool { return uuidRE.MatchString(s) }

// validateTypePattern resolves a hash or path reference and glob-matches the
// resolved entity's type field against the pattern per §4.6. Resolution
// failures pass with a warning embedded in the reason — §4.6 explicitly
// punts existence checking to a higher conformance level.
func validateTypePattern(hctx *handler.HandlerContext, raw cbor.RawMessage, pattern string) types.ConstraintValidateResultData {
	if hctx == nil || hctx.Store == nil {
		// No store wired (in-process eval) — same as "could not resolve",
		// pass with warning.
		return types.ConstraintValidateResultData{Valid: true, Reason: "type_pattern: no content store wired; resolution skipped"}
	}

	// Try hash form first.
	var h hash.Hash
	if err := ecf.Decode(raw, &h); err == nil {
		ent, ok := hctx.Store.Get(h)
		if !ok {
			return types.ConstraintValidateResultData{Valid: true, Reason: "type_pattern: hash not resolvable; pass-with-warning per §4.6"}
		}
		if globMatch(pattern, ent.Type) {
			return valid()
		}
		return invalid("type_pattern: entity type " + ent.Type + " does not match " + pattern)
	}

	// Otherwise try path.
	if s, ok := decodeString(raw); ok && hctx.LocationIndex != nil {
		// Path lookup uses absolute paths; for peer-relative input, canonicalize first.
		h, ok := hctx.LocationIndex.Get(s)
		if !ok {
			return types.ConstraintValidateResultData{Valid: true, Reason: "type_pattern: path not bound; pass-with-warning per §4.6"}
		}
		ent, ok := hctx.Store.Get(h)
		if !ok {
			return types.ConstraintValidateResultData{Valid: true, Reason: "type_pattern: path resolved but entity not in store; pass-with-warning per §4.6"}
		}
		if globMatch(pattern, ent.Type) {
			return valid()
		}
		return invalid("type_pattern: entity type " + ent.Type + " does not match " + pattern)
	}

	return invalid("type_pattern: value is neither a hash nor a path")
}

// globMatch implements the §4.6 glob semantics: `*` matches one path
// segment, `**` matches zero or more. Path segments are separated by `/`.
func globMatch(pattern, s string) bool {
	pp := strings.Split(pattern, "/")
	ss := strings.Split(s, "/")
	return globMatchSegments(pp, ss)
}

func globMatchSegments(pat, seg []string) bool {
	for pi, si := 0, 0; ; {
		if pi == len(pat) {
			return si == len(seg)
		}
		switch pat[pi] {
		case "**":
			// match zero or more segments — try every suffix
			for k := si; k <= len(seg); k++ {
				if globMatchSegments(pat[pi+1:], seg[k:]) {
					return true
				}
			}
			return false
		case "*":
			if si == len(seg) {
				return false
			}
			pi++
			si++
		default:
			if si == len(seg) || pat[pi] != seg[si] {
				return false
			}
			pi++
			si++
		}
	}
}

// Compile-time assertion: Handler satisfies the handler.Handler interface.
var _ handler.Handler = (*Handler)(nil)

// Ensure entity is referenced (used by validateTypePattern via Store.Get's
// return type, which is entity.Entity).
var _ = entity.Entity{}
