package typeext

import (
	"bytes"
	"fmt"
	"sort"

	"go.entitychurch.org/entity-core-go/core/ecf"
	"go.entitychurch.org/entity-core-go/core/entity"
	"go.entitychurch.org/entity-core-go/core/handler"
	"go.entitychurch.org/entity-core-go/core/types"

	"github.com/fxamacker/cbor/v2"
)

// verifyNarrowing implements §6.4: when child has extends, walk the parent
// chain and verify per-field narrowing rules (§6.2). Returns one violation
// per rule failure, deterministic order. An empty slice means no
// narrowing problems.
//
// Resolution failures (parent not in tree) yield an unknown_constraint
// violation rather than silent pass — same fail-closed posture as the rest
// of v1.1.
func verifyNarrowing(hctx *handler.HandlerContext, child types.TypeDefinition) []types.Violation {
	if child.Extends == "" {
		return nil
	}
	parent, ok := resolveTypeDefinition(hctx, child.Extends)
	if !ok {
		return []types.Violation{{
			Field:  "extends",
			Kind:   types.ViolationKindStructural,
			Reason: fmt.Sprintf("parent type %q not resolvable for narrowing check", child.Extends),
		}}
	}

	var out []types.Violation
	names := make([]string, 0, len(parent.Fields))
	for n := range parent.Fields {
		names = append(names, n)
	}
	sort.Strings(names)

	for _, fname := range names {
		parentSpec := parent.Fields[fname]
		if len(parentSpec.Constraints) == 0 {
			continue
		}
		childSpec, present := child.Fields[fname]
		if !present {
			// Child inherits the parent's field — the parent's
			// constraints continue to apply unchanged. That is
			// trivially narrower. No violation.
			continue
		}

		for _, pc := range parentSpec.Constraints {
			cc, found := findConstraint(childSpec.Constraints, pc.Type)
			if !found {
				out = append(out, types.Violation{
					Field:      fname,
					Kind:       types.ViolationKindConstraint,
					Constraint: pc.Type,
					Reason:     "narrowing violation: child removed parent constraint",
				})
				continue
			}
			if v := checkNarrower(fname, cc, pc); v != nil {
				out = append(out, *v)
			}
		}
	}

	// Recurse up the chain — Liskov substitution is transitive.
	out = append(out, verifyNarrowing(hctx, parent)...)
	return out
}

// findConstraint returns the first constraint in cs whose Type matches t.
func findConstraint(cs []entity.Entity, t string) (entity.Entity, bool) {
	for _, c := range cs {
		if c.Type == t {
			return c, true
		}
	}
	return entity.Entity{}, false
}

// checkNarrower verifies that the child constraint is equal-to-or-narrower
// than the parent per §6.2. Returns nil on narrowing OK, a violation on
// widening.
func checkNarrower(field string, child, parent entity.Entity) *types.Violation {
	switch child.Type {
	case types.TypeConstraintMin:
		var c, p types.ConstraintMinData
		if err := ecf.Decode(child.Data, &c); err != nil {
			return decodeViolation(field, child.Type, err)
		}
		if err := ecf.Decode(parent.Data, &p); err != nil {
			return decodeViolation(field, child.Type, err)
		}
		if c.Min >= p.Min {
			return nil
		}
		return widening(field, child.Type, fmt.Sprintf("child.min %v < parent.min %v", c.Min, p.Min))

	case types.TypeConstraintMax:
		var c, p types.ConstraintMaxData
		if err := ecf.Decode(child.Data, &c); err != nil {
			return decodeViolation(field, child.Type, err)
		}
		if err := ecf.Decode(parent.Data, &p); err != nil {
			return decodeViolation(field, child.Type, err)
		}
		if c.Max <= p.Max {
			return nil
		}
		return widening(field, child.Type, fmt.Sprintf("child.max %v > parent.max %v", c.Max, p.Max))

	case types.TypeConstraintMinLength:
		var c, p types.ConstraintMinLengthData
		if err := ecf.Decode(child.Data, &c); err != nil {
			return decodeViolation(field, child.Type, err)
		}
		if err := ecf.Decode(parent.Data, &p); err != nil {
			return decodeViolation(field, child.Type, err)
		}
		if c.MinLength >= p.MinLength {
			return nil
		}
		return widening(field, child.Type, fmt.Sprintf("child.min_length %d < parent.min_length %d", c.MinLength, p.MinLength))

	case types.TypeConstraintMaxLength:
		var c, p types.ConstraintMaxLengthData
		if err := ecf.Decode(child.Data, &c); err != nil {
			return decodeViolation(field, child.Type, err)
		}
		if err := ecf.Decode(parent.Data, &p); err != nil {
			return decodeViolation(field, child.Type, err)
		}
		if c.MaxLength <= p.MaxLength {
			return nil
		}
		return widening(field, child.Type, fmt.Sprintf("child.max_length %d > parent.max_length %d", c.MaxLength, p.MaxLength))

	case types.TypeConstraintMinCount:
		var c, p types.ConstraintMinCountData
		if err := ecf.Decode(child.Data, &c); err != nil {
			return decodeViolation(field, child.Type, err)
		}
		if err := ecf.Decode(parent.Data, &p); err != nil {
			return decodeViolation(field, child.Type, err)
		}
		if c.MinCount >= p.MinCount {
			return nil
		}
		return widening(field, child.Type, fmt.Sprintf("child.min_count %d < parent.min_count %d", c.MinCount, p.MinCount))

	case types.TypeConstraintMaxCount:
		var c, p types.ConstraintMaxCountData
		if err := ecf.Decode(child.Data, &c); err != nil {
			return decodeViolation(field, child.Type, err)
		}
		if err := ecf.Decode(parent.Data, &p); err != nil {
			return decodeViolation(field, child.Type, err)
		}
		if c.MaxCount <= p.MaxCount {
			return nil
		}
		return widening(field, child.Type, fmt.Sprintf("child.max_count %d > parent.max_count %d", c.MaxCount, p.MaxCount))

	case types.TypeConstraintPattern:
		// §6.2 v1.1: equal-only. Byte-identical pattern strings narrow
		// trivially; non-equal patterns default to incomparable. No
		// speculative regex-subset recognition.
		var c, p types.ConstraintPatternData
		if err := ecf.Decode(child.Data, &c); err != nil {
			return decodeViolation(field, child.Type, err)
		}
		if err := ecf.Decode(parent.Data, &p); err != nil {
			return decodeViolation(field, child.Type, err)
		}
		if c.Pattern == p.Pattern {
			return nil
		}
		return widening(field, child.Type, "patterns differ — incomparable by default per v1.1 §6.2")

	case types.TypeConstraintFormat:
		// §6.2 v1.1: equal-only. Equal format names narrow trivially;
		// sub-format relationships default to incomparable.
		var c, p types.ConstraintFormatData
		if err := ecf.Decode(child.Data, &c); err != nil {
			return decodeViolation(field, child.Type, err)
		}
		if err := ecf.Decode(parent.Data, &p); err != nil {
			return decodeViolation(field, child.Type, err)
		}
		if c.Format == p.Format {
			return nil
		}
		return widening(field, child.Type, "format names differ — incomparable by default per v1.1 §6.2")

	case types.TypeConstraintOneOf:
		// §6.2: child.values ⊆ parent.values (ECF byte equality per element).
		var c, p types.ConstraintOneOfData
		if err := ecf.Decode(child.Data, &c); err != nil {
			return decodeViolation(field, child.Type, err)
		}
		if err := ecf.Decode(parent.Data, &p); err != nil {
			return decodeViolation(field, child.Type, err)
		}
		if isCanonicalSubset(c.Values, p.Values) {
			return nil
		}
		return widening(field, child.Type, "child one_of values are not a subset of parent values")

	case types.TypeConstraintNotOneOf:
		// §6.2: child.values ⊇ parent.values.
		var c, p types.ConstraintNotOneOfData
		if err := ecf.Decode(child.Data, &c); err != nil {
			return decodeViolation(field, child.Type, err)
		}
		if err := ecf.Decode(parent.Data, &p); err != nil {
			return decodeViolation(field, child.Type, err)
		}
		if isCanonicalSubset(p.Values, c.Values) {
			return nil
		}
		return widening(field, child.Type, "child not_one_of values are not a superset of parent values")

	case types.TypeConstraintTypePattern:
		// §6.2: child pattern is more specific (longer prefix or exact
		// match). Concrete reading: child.pattern equals parent.pattern,
		// or child.pattern is a more specific glob (no wildcards at
		// positions where parent uses a literal).
		var c, p types.ConstraintTypePatternData
		if err := ecf.Decode(child.Data, &c); err != nil {
			return decodeViolation(field, child.Type, err)
		}
		if err := ecf.Decode(parent.Data, &p); err != nil {
			return decodeViolation(field, child.Type, err)
		}
		if typePatternNarrower(c.Pattern, p.Pattern) {
			return nil
		}
		return widening(field, child.Type, fmt.Sprintf("child type_pattern %q not narrower than parent %q", c.Pattern, p.Pattern))

	default:
		// Unknown constraint type — can't compare narrowing. Per the
		// fail-closed posture, surface as unknown_constraint.
		return &types.Violation{
			Field:      field,
			Kind:       types.ViolationKindUnknownConstraint,
			Constraint: child.Type,
			Reason:     "cannot verify narrowing for unknown constraint type",
		}
	}
}

func widening(field, ctype, detail string) *types.Violation {
	return &types.Violation{
		Field:      field,
		Kind:       types.ViolationKindConstraint,
		Constraint: ctype,
		Reason:     "narrowing violation: " + detail,
	}
}

func decodeViolation(field, ctype string, err error) *types.Violation {
	return &types.Violation{
		Field:      field,
		Kind:       types.ViolationKindConstraint,
		Constraint: ctype,
		Reason:     "decode failure during narrowing check: " + err.Error(),
	}
}

// isCanonicalSubset reports whether every element of `sub` ECF-byte-equals
// some element of `sup`. Used for one_of (sub ⊆ sup) and inverted for
// not_one_of.
func isCanonicalSubset(sub, sup []cbor.RawMessage) bool {
	supCanon := make([][]byte, len(sup))
	for i, e := range sup {
		c, err := canonicalizeRaw(e)
		if err != nil {
			return false
		}
		supCanon[i] = c
	}
	for _, e := range sub {
		c, err := canonicalizeRaw(e)
		if err != nil {
			return false
		}
		matched := false
		for _, s := range supCanon {
			if bytes.Equal(c, s) {
				matched = true
				break
			}
		}
		if !matched {
			return false
		}
	}
	return true
}

func canonicalizeRaw(raw cbor.RawMessage) ([]byte, error) {
	var v interface{}
	if err := ecf.Decode(raw, &v); err != nil {
		return nil, err
	}
	return ecf.Encode(v)
}

// typePatternNarrower reports whether the child glob is at-least-as-specific
// as the parent glob. Equal patterns narrow trivially. The minimal
// "more specific" rule pinned in v1.1 §6.2 is: at every position, the child
// is no less specific than the parent — i.e., if the parent has `*` or `**`
// the child may have a literal, but if the parent has a literal the child
// must have the same literal.
func typePatternNarrower(child, parent string) bool {
	if child == parent {
		return true
	}
	// Decompose both globs into segments. The narrowing relation is: for
	// each position the child's segment must be more-or-equally specific.
	c, p := splitGlob(child), splitGlob(parent)
	return narrowerSegments(c, p)
}

func splitGlob(s string) []string {
	if s == "" {
		return nil
	}
	out := []string{}
	start := 0
	for i := 0; i < len(s); i++ {
		if s[i] == '/' {
			out = append(out, s[start:i])
			start = i + 1
		}
	}
	out = append(out, s[start:])
	return out
}

func narrowerSegments(child, parent []string) bool {
	for ci, pi := 0, 0; ; {
		if pi == len(parent) {
			return ci == len(child)
		}
		switch parent[pi] {
		case "**":
			// Parent matches zero or more — try every suffix.
			for k := ci; k <= len(child); k++ {
				if narrowerSegments(child[k:], parent[pi+1:]) {
					return true
				}
			}
			return false
		case "*":
			if ci == len(child) {
				return false
			}
			// `*` in parent matches any single segment — child can be
			// anything at this position. Both must consume one.
			pi++
			ci++
		default:
			if ci == len(child) {
				return false
			}
			// Parent literal — child MUST be the same literal.
			if child[ci] != parent[pi] {
				return false
			}
			pi++
			ci++
		}
	}
}
