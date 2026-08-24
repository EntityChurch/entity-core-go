package main

// The v3.25 corner vectors — CV-1…CV-6, arch-authored in GUIDE-CONFORMANCE
// §7c.6 for EXTENSION-COMPUTE v3.25's four corner rulings (C-1…C-4).
//
// Arch supplies the IR + the expected outcome; the boundary hashes are the
// emit stage's output (§7c.4(3): no impl is privileged). These are IR-only, as
// every corpus vector is — go's emission produces the outcomes, which are then
// cross-blessed against rust/py once they land v3.25.
//
// Seeded into the corpus per §7c.6 ("seed them in; do not score them
// separately") — on their own they carry only two distinct error codes, below
// §7c.4(2)'s ≥3 anti-vacuity guard, so they are counted as corpus members, not
// a standalone tranche.
//
// Multi-arm vectors (CV-2, CV-3, CV-4) become one Vector per arm, each with its
// own outcome — the corpus format is one IR per Vector.

import (
	"go.entitychurch.org/entity-core-go/core/hash"
	"go.entitychurch.org/entity-core-go/core/types"
	"go.entitychurch.org/entity-core-go/ext/compute"
)

// seededError returns the hash of a fixed compute/error VALUE E, shared across
// CV-4/CV-5/CV-6 (arch's table uses one "E"). It is referenced by hash and
// resolves via SA-1 to the live value form — it CANNOT be embedded in frozen
// CBOR data (a literal/binding round-trips it to a bare map), so every corner
// that needs E injects it as an entity operand.
func seededError(b *irBuilder) hash.Hash {
	ent, err := (types.ComputeErrorData{Code: "seeded_error", Message: "corner-vector seed E"}).ToEntity()
	if err != nil {
		if b.err == nil {
			b.err = err
		}
		return hash.Hash{}
	}
	return b.addRaw(ent)
}

var v325CornerVectors = []workedVector{
	{
		// CV-1 (C-1): group-by result shape is system/compute/group{key,members};
		// group order = first appearance, member order = input order.
		id:       "worked/v325-corner/cv1-group-by-shape",
		bindings: map[string]interface{}{},
		build: func(b *irBuilder) hash.Hash {
			b.feature("v325-corner", "closure", "group-by")
			coll := b.lit([]interface{}{int64(1), int64(2), int64(3), int64(4)})
			fn := b.lambda([]string{"x"}, b.arith("mod", b.lookupScope("x"), b.lit(int64(2))))
			return probe(b, b.builtin(compute.BuiltinGroupBy, map[string]hash.Hash{"collection": coll, "fn": fn}))
		},
	},
	{
		// CV-2 arm a (C-2): assoc negative index → index_out_of_range.
		id:       "worked/v325-corner/cv2-assoc-oob-negative",
		bindings: map[string]interface{}{},
		build: func(b *irBuilder) hash.Hash {
			b.feature("v325-corner", "assoc", "error-path")
			coll := b.lit([]interface{}{int64(10), int64(20), int64(30)})
			return probe(b, b.builtin(compute.BuiltinAssoc, map[string]hash.Hash{
				"collection": coll, "index": b.lit(int64(-1)), "value": b.lit(int64(99)),
			}))
		},
	},
	{
		// CV-2 arm b (C-2): assoc index ≥ length → index_out_of_range. Both arms
		// required — an impl special-casing one magnitude passes a single-arm test.
		id:       "worked/v325-corner/cv2-assoc-oob-overflow",
		bindings: map[string]interface{}{},
		build: func(b *irBuilder) hash.Hash {
			b.feature("v325-corner", "assoc", "error-path")
			coll := b.lit([]interface{}{int64(10), int64(20), int64(30)})
			return probe(b, b.builtin(compute.BuiltinAssoc, map[string]hash.Hash{
				"collection": coll, "index": b.lit(int64(3)), "value": b.lit(int64(99)),
			}))
		},
	},
	{
		// CV-3 arm a (C-3): range(-1) → count_out_of_range.
		id:       "worked/v325-corner/cv3-range-negative",
		bindings: map[string]interface{}{},
		build: func(b *irBuilder) hash.Hash {
			b.feature("v325-corner", "range", "error-path")
			return probe(b, b.builtin(compute.BuiltinRange, map[string]hash.Hash{"n": b.lit(int64(-1))}))
		},
	},
	{
		// CV-3 arm b (C-3): range(0) → value []. The anti-vacuity partner — without
		// it a peer that errors on every range scores green on CV-3.
		id:       "worked/v325-corner/cv3-range-zero",
		bindings: map[string]interface{}{},
		build: func(b *irBuilder) hash.Hash {
			b.feature("v325-corner", "range")
			return probe(b, b.builtin(compute.BuiltinRange, map[string]hash.Hash{"n": b.lit(int64(0))}))
		},
	},
	{
		// CV-4 arm b (C-4, THE discriminator): assoc index = E → CONSUMED →
		// short-circuit to E. Same op, different position, opposite outcome —
		// a uniform rule fails exactly one of the two arms.
		id:       "worked/v325-corner/cv4b-assoc-index-error-shortcircuit",
		bindings: map[string]interface{}{},
		build: func(b *irBuilder) hash.Hash {
			b.feature("v325-corner", "assoc", "error-value")
			coll := b.lit([]interface{}{int64(1), int64(2), int64(3)})
			return probe(b, b.builtin(compute.BuiltinAssoc, map[string]hash.Hash{
				"collection": coll, "index": seededError(b), "value": b.lit(int64(9)),
			}))
		},
	},
	{
		// CV-6 (C-4): group-by derived key = E → CONSUMED (compared to assign a
		// group) → short-circuit to E, even though the key now has an output
		// position (system/compute/group.key).
		id:       "worked/v325-corner/cv6-group-by-error-key",
		bindings: map[string]interface{}{},
		build: func(b *irBuilder) hash.Hash {
			b.feature("v325-corner", "closure", "group-by", "error-value")
			coll := b.lit([]interface{}{int64(1), int64(2)})
			fn := b.lambda([]string{"x"}, seededError(b))
			return probe(b, b.builtin(compute.BuiltinGroupBy, map[string]hash.Hash{"collection": coll, "fn": fn}))
		},
	},
	{
		// CV-4 arm a (C-4, THE discriminator's contain half): assoc value = E →
		// CONTAINED → [1,E,3], with E present in the output array code-only (§3.5,
		// v3.26). Same op as CV-4b, different position, opposite outcome — CV-4b's
		// index=E short-circuits, this value=E contains. Seeded once COMPUTE v3.26
		// ruled the containment boundary (spec-issue 2026-08-20-f) and go's
		// materialize() gained the array-element carve-out.
		id:       "worked/v325-corner/cv4a-assoc-value-error-contained",
		bindings: map[string]interface{}{},
		build: func(b *irBuilder) hash.Hash {
			b.feature("v325-corner", "assoc", "error-value")
			coll := b.lit([]interface{}{int64(1), int64(2), int64(3)})
			return probe(b, b.builtin(compute.BuiltinAssoc, map[string]hash.Hash{
				"collection": coll, "index": b.lit(int64(1)), "value": seededError(b),
			}))
		},
	},
	{
		// CV-5 (C-4): concat type-transparency → [1,2,E], not type_mismatch — the
		// error element flows through untouched and materializes code-only in the
		// joined array (§3.5, v3.26). The collections arg [[1,2],[E]] is built as
		// an expression (a frozen literal would degrade E to a bare map): assoc a
		// live [E] into slot 1 of [[1,2],[0]].
		id:       "worked/v325-corner/cv5-concat-error-transparent",
		bindings: map[string]interface{}{},
		build: func(b *irBuilder) hash.Hash {
			b.feature("v325-corner", "concat", "error-value")
			placeholder := b.lit([]interface{}{
				[]interface{}{int64(1), int64(2)},
				[]interface{}{int64(0)},
			})
			liveErrArr := b.builtin(compute.BuiltinAssoc, map[string]hash.Hash{
				"collection": b.lit([]interface{}{int64(0)}), "index": b.lit(int64(0)), "value": seededError(b),
			})
			collections := b.builtin(compute.BuiltinAssoc, map[string]hash.Hash{
				"collection": placeholder, "index": b.lit(int64(1)), "value": liveErrArr,
			})
			return probe(b, b.builtin(compute.BuiltinConcat, map[string]hash.Hash{"collections": collections}))
		},
	},
	{
		// CV-7a — the COLLECTION operand short-circuit (§7.2 consumed position).
		// assoc(collection=E, …) short-circuits to E, the same as CV-4b's index=E
		// but on the collection operand. Added 2026-08-21 after core-rust + core-py
		// traced go answering type_mismatch here to resolveCollection's
		// Evaluate-vs-evalOperand slip — a discriminator the 350→352 corpus lacked,
		// which is why go LOCKED three-way with the bug live (no fixture put an
		// error in the collection operand). Seeds it so the case is guarded on the wire.
		id:       "worked/v325-corner/cv7a-assoc-collection-error-shortcircuit",
		bindings: map[string]interface{}{},
		build: func(b *irBuilder) hash.Hash {
			b.feature("v325-corner", "assoc", "error-value")
			return probe(b, b.builtin(compute.BuiltinAssoc, map[string]hash.Hash{
				"collection": seededError(b), "index": b.lit(int64(0)), "value": b.lit(int64(9)),
			}))
		},
	},
	{
		// CV-7b — group-by(collection=E, fn) short-circuits to E. Shares
		// resolveCollection with assoc/map/filter/fold, so one wire vector on that
		// path plus concat's (CV-7c, a separate code path) discriminates the fix.
		id:       "worked/v325-corner/cv7b-group-by-collection-error-shortcircuit",
		bindings: map[string]interface{}{},
		build: func(b *irBuilder) hash.Hash {
			b.feature("v325-corner", "closure", "group-by", "error-value")
			fn := b.lambda([]string{"x"}, b.lookupScope("x"))
			return probe(b, b.builtin(compute.BuiltinGroupBy, map[string]hash.Hash{
				"collection": seededError(b), "fn": fn,
			}))
		},
	},
	{
		// CV-7c — concat with an error SUB-collection short-circuits (§7.2: each
		// `collection` is consumed). Distinct from CV-5, where an error ELEMENT of a
		// VALID sub-collection is CONTAINED. collections = assoc([0],0,E) → [E], a
		// single live error sub-collection; concat consumes it → E. go typed the
		// sub-collection via c.([]interface{}) and reported type_mismatch — a
		// separate code path from resolveCollection, so it needs its own vector.
		id:       "worked/v325-corner/cv7c-concat-sub-collection-error-shortcircuit",
		bindings: map[string]interface{}{},
		build: func(b *irBuilder) hash.Hash {
			b.feature("v325-corner", "concat", "error-value")
			collections := b.builtin(compute.BuiltinAssoc, map[string]hash.Hash{
				"collection": b.lit([]interface{}{int64(0)}), "index": b.lit(int64(0)), "value": seededError(b),
			})
			return probe(b, b.builtin(compute.BuiltinConcat, map[string]hash.Hash{"collections": collections}))
		},
	},
	{
		// CV-8a — map CONTAINS a produced (MINTED) closure error as an output
		// element (arch C-8 ruling 172589e: "map never reads it; §1.5 NaN model
		// element-wise"). fn = λx. div(1,0) over [1,2] → [error{division_by_zero},
		// error{division_by_zero}], each contained CODE-ONLY, NOT a short-circuit.
		// go used to short-circuit the minted form (a single error) where the value
		// form was contained — the §2.4 provenance asymmetry rust+py flagged. Two
		// elements so a contained array (len 2) is unambiguous vs a short-circuit.
		// NOT budget/depth/cascade — those propagate, and are deliberately kept OUT
		// of the corpus until the limit-set is cross-blessed (spec-issue 2026-08-21-b).
		id:       "worked/v325-corner/cv8a-map-contains-minted-error",
		bindings: map[string]interface{}{},
		build: func(b *irBuilder) hash.Hash {
			b.feature("v325-corner", "closure", "map", "error-value")
			coll := b.lit([]interface{}{int64(1), int64(2)})
			fn := b.lambda([]string{"x"}, b.arith("div", b.lit(int64(1)), b.lit(int64(0))))
			return probe(b, b.mapB(coll, fn))
		},
	},
	{
		// CV-8b — map CONTAINS a VALUE-FORM closure error as an output element. Same
		// shape as CV-8a with the error arriving as a stored compute/error (SA-1,
		// nil Go-error) rather than minted. THE PAIR IS THE POINT (arch §6): a
		// provenance-dependent impl gives two different answers and fails exactly one
		// arm — CV-8a/CV-8b must produce byte-identical boundaries (code-only
		// containment), which is the §2.4 provenance-independence [MUST].
		id:       "worked/v325-corner/cv8b-map-contains-valueform-error",
		bindings: map[string]interface{}{},
		build: func(b *irBuilder) hash.Hash {
			b.feature("v325-corner", "closure", "map", "error-value")
			coll := b.lit([]interface{}{int64(1), int64(2)})
			fn := b.lambda([]string{"x"}, seededError(b))
			return probe(b, b.mapB(coll, fn))
		},
	},
	{
		// CV-8c — filter SHORT-CIRCUITS a value-form predicate error (arch C-8:
		// "filter's predicate result short-circuits" — it is read for truthiness, a
		// consumed position). fn = λx. E over [1] → E. go used to run truthy(E),
		// which hits the default true and SILENTLY KEPT the element; now it
		// short-circuits, matching the already-correct minted form.
		id:       "worked/v325-corner/cv8c-filter-predicate-error-shortcircuit",
		bindings: map[string]interface{}{},
		build: func(b *irBuilder) hash.Hash {
			b.feature("v325-corner", "closure", "filter", "error-value")
			coll := b.lit([]interface{}{int64(1)})
			fn := b.lambda([]string{"x"}, seededError(b))
			return probe(b, b.filterB(coll, fn))
		},
	},
	{
		// CV-8d — fold RECOVERS: its accumulator is CONTAINED, not short-circuited
		// (arch C-8: "fold binds it into the next closure invocation and never reads
		// it, so a closure that ignores its accumulator recovers"). fn = λacc x. x
		// ignores the accumulator; initial is a value-form error E; over [1,2] the
		// error is threaded in as acc, ignored each step, and the fold returns the
		// last element (2). THIS IS THE DISCRIMINATOR THAT WAS MISSING at go's 358
		// freeze — it is deliberately the shape where contain and short-circuit
		// produce DIFFERENT VALUES (2 vs error{code}), so a fold that short-circuits
		// (go's earlier defect, corrected here) forks the boundary. Two elements so
		// the per-iteration recovery — ignoring an error acc on step 2 — is exercised.
		id:       "worked/v325-corner/cv8d-fold-ignores-accumulator-recovers",
		bindings: map[string]interface{}{},
		build: func(b *irBuilder) hash.Hash {
			b.feature("v325-corner", "closure", "fold", "error-value")
			coll := b.lit([]interface{}{int64(1), int64(2)})
			fn := b.lambda([]string{"acc", "x"}, b.lookupScope("x"))
			return probe(b, b.foldB(coll, seededError(b), fn))
		},
	},
}
