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
}

// v325BlockedOnMaterialization holds CV-4a and CV-5 — arch-authored, correct as
// IR, but NOT YET SEEDED because go cannot emit them. Both put a compute/error
// in a DATA position that v3.25 C-4 rules "contained" (assoc value; concat
// element), so the error flows INTO the output array and is present when that
// array materializes at the boundary. go's materialize() rejects any
// compute/error reaching it — the v3.23 ruling-B guard ("an error propagates
// from a consumption site, it never materializes there"), written before v3.25
// created data-positions that legitimately carry an error into a materialized
// value. Measured: both fail `capture scope: internal: compute/error reached
// materialize()`. This is CV-4 (the discriminator) finding exactly the gap a
// uniform rule misses.
//
// Routed as spec-issue 2026-08-20-f: how does a CONTAINED compute/error
// materialize at the boundary — code-only per §7c.3, inside the array — and how
// is that reconciled with the v3.23 guard? Seeding these two + the go
// materialize() fix are gated on that ruling (and cross-verification once rust/py
// land v3.25), so they are held here rather than seeded and left as a go RED.
var v325BlockedOnMaterialization = []workedVector{
	{
		// CV-4 arm a (C-4): assoc value = E → CONTAINED → [1,E,3] (value, code-only E).
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
		// CV-5 (C-4): concat type-transparency → [1,2,E], not type_mismatch. The
		// collections arg [[1,2],[E]] is built as an expression (a frozen literal
		// would degrade E to a bare map): assoc a live [E] into slot 1 of [[1,2],[0]].
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
}

// Referenced so the blocked authoring is compiled and stays valid IR (it will be
// moved into v325CornerVectors when spec-issue 2026-08-20-f rules the boundary).
var _ = v325BlockedOnMaterialization
