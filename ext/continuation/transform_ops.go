package continuation

import (
	"strconv"
	"strings"

	"go.entitychurch.org/entity-core-go/core/ecf"
	"go.entitychurch.org/entity-core-go/core/entity"
	"go.entitychurch.org/entity-core-go/core/hash"
	"go.entitychurch.org/entity-core-go/core/types"

	"github.com/fxamacker/cbor/v2"
)

// Bounded field operations for continuation transforms (EXTENSION-CONTINUATION
// §2.2, G1). The op set is closed, total, pure, and bounded — field plumbing,
// not a computation surface. Every op is total: a missing/non-string field is
// a documented no-op (or null result), never an error. Errors are surfaced
// only at install, where an unrecognized op is rejected fail-closed
// (validateTransformOps, §8.1) — apply never errors (§2.2 best-effort).
//
// transformOpKinds is the recognized set; install validation rejects any op
// not in it. Adding an op here is the only place the set grows (under the
// §2.2 admissibility contract: total / pure / bounded / statically analyzable).
var transformOpKinds = map[string]bool{
	"strip_prefix":    true,
	"prepend":         true,
	"append":          true,
	"join":            true,
	"replace_literal": true,
	"split":           true,
	"slice":           true,
	"collect_keys":    true,
	// deref_included: reads m[Field] as a system/hash and replaces with the
	// entity at that hash from the envelope's `included` map. Closes the
	// plain-continuation-chain gap in the cross-peer mirror recipe — see
	// EXTENSION-CONTINUATION §2.2 (v1.17) + the Boundary clarification that
	// envelope-included navigation is in-scope and distinct from tree
	// references. Pure (function of input + envelope), total (no-op on
	// miss), bounded (one lookup), statically analyzable (hash → entity).
	// Does not assume fixed hash length (system/hash is variable-length
	// per V7 §1.2 / crypto-agility). Requires V7 §3.3 v7.51 request-side
	// envelope-included preservation so `included` reaches the continuation.
	"deref_included": true,
}

// isKnownTransformOp reports whether op is in the recognized set.
func isKnownTransformOp(op string) bool { return transformOpKinds[op] }

// firstUnknownTransformOp returns the first transform_ops op name on the
// transform that is not in the recognized set, and true; ("", false) when
// every op is recognized (or there are no ops / no transform). Install uses
// this to reject an unrecognized op fail-closed (§2.2 / §8.1) — never
// silently skip it at advance.
func firstUnknownTransformOp(t *types.ContinuationTransformData) (string, bool) {
	if t == nil {
		return "", false
	}
	for _, op := range t.TransformOps {
		if !isKnownTransformOp(op.Op) {
			return op.Op, true
		}
	}
	return "", false
}

// firstInvalidTransformOpArgs returns a human-readable reason if any op on
// the transform is recognized but its argument shape is invalid (e.g.
// collect_keys carrying both `field` and `fields`). Returns ("", false) if
// every op's args are admissible. Install rejects with
// `400 unknown_transform_op` (current spec wording) but the proposal's
// minor item flags this as a candidate for `400 invalid_transform_args` —
// the message string makes the failure mode explicit until the code
// renames at ratification.
func firstInvalidTransformOpArgs(t *types.ContinuationTransformData) (string, bool) {
	if t == nil {
		return "", false
	}
	for _, op := range t.TransformOps {
		if op.Op == "collect_keys" {
			if op.Field != "" && len(op.Fields) > 0 {
				return "collect_keys: field and fields are mutually exclusive", true
			}
			if op.Into == "" {
				return "collect_keys: into is required", true
			}
		}
	}
	return "", false
}

// applyTransformOps runs the ordered op list against the post-extract/
// post-select value. Ops read and write named fields, so the value must be a
// string-keyed map; if it is not (e.g. extract produced a scalar), the ops
// are a total no-op and the value passes through unchanged. The returned
// value is the (possibly new) map. Pure and bounded: no clock/RNG/IO/tree.
func applyTransformOps(value interface{}, ops []types.ContinuationTransformOpData) interface{} {
	return applyTransformOpsWithIncluded(value, ops, nil)
}

// applyTransformOpsWithIncluded is applyTransformOps with envelope `included`
// access. Threaded by applyTransform so the deref_included op can resolve a
// hash field to the entity at that hash. Other ops ignore included. The two-
// arg applyTransformOps preserves the call shape used by existing tests of
// pure transforms (those never need deref_included).
func applyTransformOpsWithIncluded(value interface{}, ops []types.ContinuationTransformOpData, included map[hash.Hash]entity.Entity) interface{} {
	if len(ops) == 0 {
		return value
	}
	m := toStringMap(value)
	if m == nil {
		// Not a map — ops are field plumbing; nothing to plumb. Total no-op.
		return value
	}
	for _, op := range ops {
		applyOneTransformOp(m, op, included)
	}
	return m
}

// toStringMap returns a string-keyed view of value, converting a
// map[interface{}]interface{} (CBOR generic map) in place. Returns nil if
// value is not a map.
func toStringMap(value interface{}) map[string]interface{} {
	switch t := value.(type) {
	case map[string]interface{}:
		return t
	case map[interface{}]interface{}:
		out := make(map[string]interface{}, len(t))
		for k, v := range t {
			if ks, ok := k.(string); ok {
				out[ks] = v
			}
		}
		return out
	default:
		return nil
	}
}

// fieldString returns the string value of field m[name]: a string as-is,
// a []byte decoded, anything else (incl. absent) the empty string. This is
// the documented total behavior — a missing field is a no-op input.
func fieldString(m map[string]interface{}, name string) string {
	switch v := m[name].(type) {
	case string:
		return v
	case []byte:
		return string(v)
	default:
		return ""
	}
}

func applyOneTransformOp(m map[string]interface{}, op types.ContinuationTransformOpData, included map[hash.Hash]entity.Entity) {
	switch op.Op {
	case "strip_prefix":
		// TrimPrefix is already a no-op when the prefix is absent.
		m[op.Field] = strings.TrimPrefix(fieldString(m, op.Field), op.Prefix)
	case "prepend":
		m[op.Field] = op.Literal + fieldString(m, op.Field)
	case "append":
		m[op.Field] = fieldString(m, op.Field) + op.Literal
	case "join":
		parts := make([]string, 0, len(op.Fields))
		for _, f := range op.Fields {
			parts = append(parts, fieldString(m, f))
		}
		m[op.Into] = strings.Join(parts, op.Sep)
	case "replace_literal":
		// Literal (non-regex) replacement of every occurrence. An empty
		// `from` has no literal occurrence to replace — treat it as a
		// documented total no-op (Go's strings.ReplaceAll(s,"",to) would
		// otherwise splice `to` around every byte: pure but nonsensical
		// field plumbing, and a silent footgun).
		if op.From == "" {
			break
		}
		m[op.Field] = strings.ReplaceAll(fieldString(m, op.Field), op.From, op.To)
	case "split":
		s := fieldString(m, op.Field)
		var parts []string
		if op.Sep == "" {
			parts = []string{s}
		} else {
			parts = strings.Split(s, op.Sep)
		}
		arr := make([]interface{}, len(parts))
		for i, p := range parts {
			arr[i] = p
		}
		m[op.Into] = arr
	case "slice":
		m[op.Into] = sliceString(fieldString(m, op.Field), op.Range)
	case "collect_keys":
		// Project the keys of one or more map fields into an array, written
		// to `Into`. Singular `Field` reads one map; plural `Fields` reads
		// each and concatenates the keys in list order. Missing or non-map
		// fields are individually skipped (best-effort §2.2). Both `field`
		// and `fields` field navigation use the same dotted-path rules as
		// `extract` (e.g. "data.added"). Output is always written when
		// `Into` is set, even if empty — chains downstream observe `[]`
		// rather than an absent key.
		if op.Into == "" {
			break
		}
		out := []interface{}{}
		if len(op.Fields) > 0 {
			for _, f := range op.Fields {
				out = append(out, collectMapKeys(navigateMap(m, f))...)
			}
		} else if op.Field != "" {
			out = append(out, collectMapKeys(navigateMap(m, op.Field))...)
		}
		m[op.Into] = out
	case "deref_included":
		// EXTENSION-CONTINUATION v1.17 §2.2: reads m[op.Field] as a
		// system/hash and replaces it with the entity bound to that hash
		// in the envelope's `included` map. The replacement is a
		// cbor.RawMessage so the downstream CBOR encode embeds the
		// entity's representation verbatim — preserving entity fidelity
		// per V7 §1.8. Total: missing field, non-byte shape, unparseable
		// hash, unresolved hash, or nil included map each map to a no-op
		// per §2.2 best-effort. Pure: function of input + envelope (no
		// tree/IO/clock). Bounded: one lookup + one encode. Does not
		// assume fixed hash length — hash.FromBytes is the validator,
		// keeping the op crypto-agile per V7 §1.2.
		if op.Field == "" || included == nil {
			break
		}
		raw, ok := m[op.Field]
		if !ok {
			break
		}
		var hashBytes []byte
		switch v := raw.(type) {
		case []byte:
			hashBytes = v
		case cbor.RawMessage:
			// CBOR-encoded byte string; decode the byte string.
			var decoded []byte
			if err := cbor.Unmarshal(v, &decoded); err != nil {
				break
			}
			hashBytes = decoded
		default:
			break
		}
		h, err := hash.FromBytes(hashBytes)
		if err != nil {
			// Non-hash shape, wrong length, or unknown algorithm — no-op
			// per the §2.2 best-effort contract. hash.FromBytes owns the
			// length / algorithm validation so this op stays crypto-agile.
			break
		}
		ent, ok := included[h]
		if !ok {
			// Unresolved — total no-op. Downstream handler sees the
			// original hash and can fail per its own contract.
			break
		}
		encoded, err := ecf.Encode(ent)
		if err != nil {
			break
		}
		m[op.Field] = cbor.RawMessage(encoded)
	default:
		// Unreachable on the apply path: unknown ops are rejected
		// fail-closed at install (validateTransformOps). Total no-op here
		// preserves the §2.2 "transforms never error" contract even if a
		// non-validating call path ever reaches this.
	}
}

// sliceString returns a bounded substring of s selected by a Python-style
// "start:end" range (either side optional; e.g. "2:", ":4", "1:3"). Indices
// are byte offsets clamped to [0, len(s)] so the op is total and bounded for
// every input. A malformed range is a total no-op (returns s unchanged).
func sliceString(s, rng string) string {
	colon := strings.IndexByte(rng, ':')
	if colon < 0 {
		return s // no range separator — total no-op
	}
	n := len(s)
	start, end := 0, n
	if lhs := rng[:colon]; lhs != "" {
		v, err := strconv.Atoi(lhs)
		if err != nil {
			return s
		}
		start = clamp(v, 0, n)
	}
	if rhs := rng[colon+1:]; rhs != "" {
		v, err := strconv.Atoi(rhs)
		if err != nil {
			return s
		}
		end = clamp(v, 0, n)
	}
	if start > end {
		start = end
	}
	return s[start:end]
}

// navigateMap walks a dotted path into m and returns the resulting value, or
// nil if any segment misses or yields a non-map intermediate. Same semantics
// as the handler's navigate() helper but starting from a string-keyed map.
func navigateMap(m map[string]interface{}, dottedPath string) interface{} {
	if dottedPath == "" {
		return m
	}
	var current interface{} = m
	for _, seg := range strings.Split(dottedPath, ".") {
		switch v := current.(type) {
		case map[string]interface{}:
			current = v[seg]
		case map[interface{}]interface{}:
			current = v[seg]
		default:
			return nil
		}
		if current == nil {
			return nil
		}
	}
	return current
}

// collectMapKeys returns the keys of v if v is a map (string or CBOR-generic
// interface keys), otherwise an empty slice (best-effort, total). Keys are
// stringified so the output array is uniformly []interface{} of strings,
// regardless of source map shape — this matches the canonical
// system/tree/diff use (paths are strings) and keeps downstream
// tree:extract.paths typing trivial.
//
// Order: Go map iteration order is unspecified, but for the canonical
// chain shape (collect_keys -> tree:extract(paths)) order is irrelevant —
// extract de-dupes its paths set. If a future caller needs ordered keys,
// the proposal §2 contract is unchanged — sorting is an op variant, not a
// semantic change to this op.
func collectMapKeys(v interface{}) []interface{} {
	switch t := v.(type) {
	case map[string]interface{}:
		out := make([]interface{}, 0, len(t))
		for k := range t {
			out = append(out, k)
		}
		return out
	case map[interface{}]interface{}:
		out := make([]interface{}, 0, len(t))
		for k := range t {
			if ks, ok := k.(string); ok {
				out = append(out, ks)
			}
			// Non-string keys are silently skipped — the canonical
			// collect_keys input (system/tree/diff) is always
			// string-keyed (paths). Preserves totality without dragging
			// in a generic stringifier.
		}
		return out
	default:
		return nil
	}
}

func clamp(v, lo, hi int) int {
	if v < lo {
		return lo
	}
	if v > hi {
		return hi
	}
	return v
}
