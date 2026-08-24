package main

// The worked-lowering vectors — the first tranche of the corpus.
//
// GUIDE-CONFORMANCE §7c.5(a) says to start here, before the random sweep:
// "start with the nine lowering-toolkit worked lowerings
// (PROPOSAL-COMPUTE-LOWERING-TOOLKIT §5), then the random sweep."
//
// §5 of that proposal is the worked-vector contract; §3 is the table of nine
// decompositions (arithmetic, compare, fold, filter, map, recurse, match,
// record, numeric-intent) and §4 is the invariant catalog each decomposition
// MUST encode. Every vector below names the §4 invariant it pins, because a
// vector that does not pin an invariant is a vector nobody can act on when it
// goes red.
//
// (The 2026-07-21 cohort handoff cites "§2.3" for these. There is no §2.3
// worked-vector section; §7c's own pointer to §5 is the correct one.)
//
// WHY THE ORDER MATTERS. The sweep is broad and shallow: it finds divergences
// but describes them as "case 137 disagreed." A worked vector is narrow and
// named — "unsigned div reverts to signed when the cast is let-bound" — so it
// arrives with its own diagnosis. Landing these first means the sweep's failures
// have somewhere to be triaged against.

import (
	"go.entitychurch.org/entity-core-go/core/ecf"
	"go.entitychurch.org/entity-core-go/core/entity"
	"go.entitychurch.org/entity-core-go/core/hash"
	"go.entitychurch.org/entity-core-go/core/types"
	"go.entitychurch.org/entity-core-go/ext/compute"

	"github.com/fxamacker/cbor/v2"
)

// Standard budget for vectors that are not probing budget behavior. Written as
// literals rather than compute.DefaultMaxOps: the corpus is a cross-impl
// artifact, and pinning it to a Go constant would mean a Go-side retune
// silently changes what every other impl is asked to run.
var stdBudget = VecBudget{Operations: 100000, Depth: 1024}

// stdBindings is the root scope most worked vectors evaluate against.
//
// Both a signed-negative (m) and a small unsigned (u) are present on purpose:
// the numeric-intent decomposition turns on telling int64(-3) from uint64(3),
// and a bindings set with only non-negative signed integers cannot express the
// difference the whole Rule-11 family is about.
func stdBindings() map[string]interface{} {
	return map[string]interface{}{
		"n":   int64(7),
		"m":   int64(-3),
		"u":   uint64(3),
		"arr": []interface{}{int64(1), int64(2), int64(3), int64(4)},
	}
}

// workedVector is one authored case.
type workedVector struct {
	id       string
	bindings map[string]interface{}
	budget   VecBudget
	build    func(b *irBuilder) hash.Hash
	// boundaryPath sets Vector.BoundaryPath: the boundary is the entity WRITTEN to
	// this tree path, not the eval result. Set on the store-crossing vectors, whose
	// point is the written error's BYTES (§2.4 code-only), not the eval result.
	boundaryPath string
}

// buildWorked constructs all worked vectors in declaration order.
//
// In the `wire` profile the root bindings are inlined into the IR and the
// vector's own bindings map is emptied — the expression is closed, so a peer
// evaluating it from an empty scope sees the same program.
func buildWorked(profile string) ([]Vector, error) {
	out := make([]Vector, 0, len(workedVectors))
	for _, wv := range workedVectors {
		bindings := wv.bindings
		if bindings == nil {
			bindings = stdBindings()
		}
		b := newIRBuilder(inlineRootsFor(profile, bindings))
		root := wv.build(b)
		budget := wv.budget
		if budget.Operations == 0 {
			budget = stdBudget
		}
		v, err := b.freeze(wv.id, 0, root, emittedBindings(profile, bindings), budget)
		if err != nil {
			return nil, err
		}
		v.BoundaryPath = wv.boundaryPath
		out = append(out, v)
	}
	return out, nil
}

// The two corpus profiles.
const (
	// profileInproc matches §7c.3's vector shape exactly: root bindings are
	// supplied alongside the IR and the harness binds them before evaluating.
	profileInproc = "inproc"
	// profileWire closes every expression by inlining the root bindings, so the
	// corpus can be driven against a live peer through system/compute:eval,
	// whose scope is empty by §3.2.
	profileWire = "wire"
)

func inlineRootsFor(profile string, bindings map[string]interface{}) map[string]interface{} {
	if profile == profileWire {
		return bindings
	}
	return nil
}

func emittedBindings(profile string, bindings map[string]interface{}) map[string]interface{} {
	if profile == profileWire {
		return map[string]interface{}{}
	}
	return bindings
}

// probe wraps an expression in a compute/construct so the result crosses the
// materialized boundary — the only surface AE-1 binds. An unwrapped expression
// yielding an in-flight value would be compared at a shape the contract does
// not pin.
func probe(b *irBuilder, value hash.Hash) hash.Hash {
	return b.construct("app/corpus/probe", map[string]hash.Hash{"value": value})
}

var workedVectors = []workedVector{
	// --- 1. arithmetic (§3 row 1; §4a) -------------------------------------

	{
		// Signed arithmetic over the sign-agnostic ops. §3: add/sub/mul emit
		// bare IR with no cast — a toolkit that wraps these in casts anyway is
		// producing hash-divergent IR for identical source.
		id: "worked/arithmetic/signed-agnostic",
		build: func(b *irBuilder) hash.Hash {
			sum := b.arith("add", b.lookupScope("n"), b.lookupScope("m"))
			diff := b.arith("sub", b.lookupScope("n"), b.lookupScope("m"))
			return probe(b, b.arith("mul", sum, diff))
		},
	},
	{
		// §4a, the positive case: unsigned div reached ONLY by a numeric-cast
		// as the DIRECT operand. Both operands cast; the result is unsigned.
		id: "worked/arithmetic/unsigned-div-at-use-site",
		build: func(b *irBuilder) hash.Hash {
			b.feature("unsigned-at-use-site")
			l := b.cast(b.lookupScope("n"), "primitive/uint")
			r := b.cast(b.lit(int64(2)), "primitive/uint")
			return probe(b, b.arith("div", l, r))
		},
	},
	{
		// §4a, the footgun, and the highest-value vector in this file.
		//
		// The SAME cast, bound in a let instead of inlined, silently reverts to
		// signed-default. Go's builder rejects this at build time, so Go can
		// only reach it by authoring IR directly — which is exactly what a
		// second impl's toolkit will do by accident. If Rust or Python treats a
		// let-bound cast as carrying unsigned intent, this vector is the only
		// thing in the corpus that catches it, and it catches it as a named
		// invariant rather than as an unexplained hash mismatch.
		//
		// m = -3, so the two readings are far apart: signed div gives -1;
		// unsigned would give a value near 2^64/3. No chance of a coincidental
		// agreement masking the divergence.
		id: "worked/arithmetic/rule11-let-bound-cast-reverts-to-signed",
		build: func(b *irBuilder) hash.Hash {
			b.feature("unsigned-at-use-site", "rule11-negative")
			castM := b.cast(b.lookupScope("m"), "primitive/uint")
			body := b.arith("div", b.lookupScope("cm"), b.lit(int64(2)))
			return probe(b, b.letE(map[string]hash.Hash{"cm": castM}, body))
		},
	},
	{
		// Error path: division_by_zero. Errors are part of the contract, not an
		// absence of one (§7c.4(2) requires error outcomes in the corpus).
		id: "worked/arithmetic/division-by-zero",
		build: func(b *irBuilder) hash.Hash {
			b.feature("error-path")
			return probe(b, b.arith("div", b.lookupScope("n"), b.lit(int64(0))))
		},
	},

	// --- 2. compare (§3 row 2; §4a) ----------------------------------------

	{
		// Signed-default ordered compare: -3 < 7 is true.
		id: "worked/compare/signed-default",
		build: func(b *irBuilder) hash.Hash {
			return probe(b, b.compare("lt", b.lookupScope("m"), b.lookupScope("n")))
		},
	},
	{
		// The discriminator. Identical operands, identical op, cast inlined at
		// the operand site: -3 reinterpreted unsigned is ~1.8e19, so `lt` flips
		// from true to false. An impl that ignores operand-site cast intent on
		// compare produces `true` here and `true` above, and the two vectors
		// together localize the bug to intent propagation rather than to
		// comparison itself.
		id: "worked/compare/unsigned-at-use-site-flips",
		build: func(b *irBuilder) hash.Hash {
			b.feature("unsigned-at-use-site")
			l := b.cast(b.lookupScope("m"), "primitive/uint")
			r := b.cast(b.lookupScope("n"), "primitive/uint")
			return probe(b, b.compare("lt", l, r))
		},
	},

	{
		// The operand's CBOR major type MUST NOT steer evaluation.
		//
		// §2.2 rule 9 is explicit: "The primitive/int / primitive/uint
		// distinction is a TYPE-SYSTEM ANNOTATION: a value's classification
		// follows its CBOR major type (non-negative → uint, negative → int) for
		// typing/constraints, but IT DOES NOT STEER EVALUATION." Unsigned
		// compare is reached only by an operand-site numeric-cast (rule 11).
		//
		// So `gte(-7i, 4u)` is signed-default and false, even though the right
		// operand encodes as CBOR major type 0. An impl that reads the major
		// type as intent evaluates -7 as ~1.8e19 and answers true.
		//
		// Value-kind boundary, no construct wrapper: the answer is one byte
		// (0xf4 / 0xf5), so a divergence report shows the disagreement itself
		// rather than two entity hashes.
		//
		// Found by the corpus: the seeded sweep diverged at case 124, where this
		// comparison sat in an `if` condition 28 nodes deep and flipped the whole
		// expression onto the other branch. Minimized to the comparison alone.
		id: "worked/compare/uint-literal-does-not-steer-evaluation",
		build: func(b *irBuilder) hash.Hash {
			b.feature("major-type-is-not-intent")
			return b.compare("gte", b.lit(int64(-7)), b.lit(uint64(4)))
		},
	},
	{
		// The positive control for the vector above, and the reason the pair has
		// to travel together: the SAME comparison with an operand-site cast IS
		// unsigned, so `gte` becomes true. One vector alone cannot tell "reads
		// the major type as intent" from "never does unsigned compare at all" —
		// an impl that always answers signed passes the first and fails this one.
		id: "worked/compare/cast-at-operand-site-does-steer",
		build: func(b *irBuilder) hash.Hash {
			b.feature("unsigned-at-use-site", "major-type-is-not-intent")
			return b.compare("gte",
				b.cast(b.lit(int64(-7)), "primitive/uint"),
				b.cast(b.lit(int64(4)), "primitive/uint"))
		},
	},

	// --- 3. fold (§3 row 3; §4b) -------------------------------------------

	{
		// Lambda lowers to a compute/lambda EXPRESSION passed by hash, never to
		// a pre-evaluated compute/closure value (§4b) — a closure is a runtime
		// artifact and is not portable as a builtin argument.
		id: "worked/fold/sum",
		build: func(b *irBuilder) hash.Hash {
			fn := b.lambda([]string{"acc", "e"},
				b.arith("add", b.lookupScope("acc"), b.lookupScope("e")))
			return probe(b, b.foldB(b.lookupScope("arr"), b.lit(int64(0)), fn))
		},
	},
	{
		// Empty collection — the §5 edge case. fold over nothing must return
		// the initial value, and it is the shape where an impl that special-
		// cases the first element instead of threading the accumulator breaks.
		id: "worked/fold/empty-collection",
		build: func(b *irBuilder) hash.Hash {
			b.feature("empty-collection")
			fn := b.lambda([]string{"acc", "e"},
				b.arith("add", b.lookupScope("acc"), b.lookupScope("e")))
			empty := b.lit([]interface{}{})
			return probe(b, b.foldB(empty, b.lit(int64(41)), fn))
		},
	},

	// --- 4. filter (§3 row 4; §4b) -----------------------------------------

	{
		id: "worked/filter/predicate",
		build: func(b *irBuilder) hash.Hash {
			fn := b.lambda([]string{"e"}, b.compare("gt", b.lookupScope("e"), b.lit(int64(2))))
			return probe(b, b.filterB(b.lookupScope("arr"), fn))
		},
	},

	// --- 5. map (§3 row 5; §4b) --------------------------------------------

	{
		// The closure captures `n` from the ENCLOSING scope, not from its own
		// parameters. This is the live-frame path: an engine holding
		// environments as pointers and one materializing them through
		// CaptureScope/LoadScope diverge here first, and it is the single
		// feature the workbench guards insist must appear at least once.
		id: "worked/map/closure-captures-enclosing",
		build: func(b *irBuilder) hash.Hash {
			fn := b.lambda([]string{"e"},
				b.arith("add", b.lookupScope("e"), b.lookupScope("n")))
			return probe(b, b.mapB(b.lookupScope("arr"), fn))
		},
	},
	{
		// Nested collections + a map over a map — §5's "nested arrays". The
		// inner lambda's capture must not leak into the outer frame.
		id: "worked/map/nested-collections",
		build: func(b *irBuilder) hash.Hash {
			b.feature("nested-collection")
			inner := b.lambda([]string{"e"}, b.arith("mul", b.lookupScope("e"), b.lit(int64(2))))
			doubled := b.mapB(b.lookupScope("arr"), inner)
			outer := b.lambda([]string{"e"}, b.arith("add", b.lookupScope("e"), b.lookupScope("m")))
			return probe(b, b.mapB(doubled, outer))
		},
	},

	// --- 6. recurse (§3 row 6; §4c) ----------------------------------------

	{
		// The fixpoint bootstrap: a lambda stored at a tree path, referencing
		// ITSELF through compute/lookup/tree, invoked by compute/apply. The knot
		// (needing the body's hash to build the body) is resolved by indirecting
		// through the path — the toolkit's job per §4c.
		//
		// The self-call is in TAIL position, so §4c's "tail calls iterate
		// without stack growth" is observable: the depth budget is deliberately
		// set to 16 while the recursion runs 5 levels deep. An impl that grows
		// the stack per call fails with depth_exceeded instead of the value, and
		// that is the point — a depth budget large enough to hide the difference
		// would make this vector prove nothing.
		id:     "worked/recurse/tail-sum",
		budget: VecBudget{Operations: 100000, Depth: 16},
		build: func(b *irBuilder) hash.Hash {
			b.feature("tail-recursion", "tree-lookup", "closure")
			const path = "corpus/fn/sum"

			self := b.lookupTree(path)
			recur := b.applyClosure(self, map[string]hash.Hash{
				"k":   b.arith("sub", b.lookupScope("k"), b.lit(int64(1))),
				"acc": b.arith("add", b.lookupScope("acc"), b.lookupScope("k")),
			})
			done := b.lookupScope("acc")
			guard := b.compare("lte", b.lookupScope("k"), b.lit(int64(0)))
			body := b.ifE(guard, done, &recur)
			fn := b.lambda([]string{"acc", "k"}, body)
			b.at(path, fn)

			return probe(b, b.applyClosure(b.lookupTree(path), map[string]hash.Hash{
				"k":   b.lit(int64(5)),
				"acc": b.lit(int64(0)),
			}))
		},
	},

	// --- 7. match (§3 row 7; §4d) ------------------------------------------

	{
		// Sum-type discrimination by a `.data` tag read with compute/field,
		// branched with if/eq (§4d). There is no union_of and no runtime
		// compute/match; an impl that invents one produces IR nothing else can
		// evaluate. Two vectors, one per arm, so a stuck branch is visible: a
		// single-arm vector passes even against an impl that always takes
		// `then`.
		id: "worked/match/tag-dispatch-arm-a",
		build: func(b *irBuilder) hash.Hash {
			return matchVariant(b, "circle")
		},
	},
	{
		id: "worked/match/tag-dispatch-arm-b",
		build: func(b *irBuilder) hash.Hash {
			return matchVariant(b, "square")
		},
	},

	// --- 8. record (§3 row 8; §4e, §4f) ------------------------------------

	{
		// §4e: a compute/construct leaving compute materializes to a bare entity
		// byte-identical to a hand-built one — entity-kind fields become bare
		// system/hash refs, value-kind fields inline. The nested construct is
		// what makes this non-trivial: `inner` must be materialized and STORED
		// first, then referenced by hash from `outer`.
		id: "worked/record/nested-construct-materializes-bare",
		build: func(b *irBuilder) hash.Hash {
			b.feature("nested-construct")
			inner := b.construct("app/corpus/inner", map[string]hash.Hash{
				"total": b.arith("add", b.lookupScope("n"), b.lookupScope("m")),
				"label": b.lit("inner"),
			})
			return b.construct("app/corpus/outer", map[string]hash.Hash{
				"child": inner,
				"count": b.length(b.lookupScope("arr")),
			})
		},
	},
	{
		// §4f: reading a system/hash field back out of a MATERIALIZED entity
		// returns the hash itself — the impl MUST NOT auto-resolve it.
		//
		// The distinction is invisible in Go-on-Go if both writer and reader
		// auto-resolve, which is why the vector is pinned at a value-kind
		// boundary: the expected bytes are a 33-byte CBOR byte string
		// (algorithm || digest). An impl that auto-resolves emits the target's
		// contents instead and the divergence is unmistakable.
		//
		// The tree carries a hand-built parent/child pair rather than a
		// constructed one, because construct's in-flight form is navigated by
		// typed field access — only a genuinely materialized entity exercises
		// the read-back path.
		id: "worked/record/materialized-hash-readback",
		build: func(b *irBuilder) hash.Hash {
			b.feature("materialized-hash-readback", "tree-lookup")
			const path = "corpus/record/node"
			child := b.addRaw(rawEntity("app/corpus/leaf", map[string]interface{}{
				"n": int64(41),
			}))
			parent := b.addRaw(rawEntity("app/corpus/node", map[string]interface{}{
				"child": child,
				"label": "node",
			}))
			b.at(path, parent)
			return b.field("child", b.lookupTree(path))
		},
	},
	{
		// Deep navigation — §5's "deep field/index chains". field → index →
		// length composed over a heterogeneous array, which is also §5's
		// "heterogeneous inputs": an impl that types an array by its first
		// element mis-handles the mixed literal.
		id: "worked/record/deep-navigation-heterogeneous",
		build: func(b *irBuilder) hash.Hash {
			b.feature("deep-navigation", "heterogeneous-array")
			mixed := b.lit([]interface{}{int64(10), "two", true, []interface{}{int64(1), int64(2)}})
			nested := b.index(mixed, b.lit(int64(3)))
			rec := b.construct("app/corpus/deep", map[string]hash.Hash{
				"items": mixed,
				"tail":  b.length(nested),
			})
			return probe(b, b.field("tail", rec))
		},
	},
	{
		// Error path: index_out_of_range. Ragged access on a known-length array.
		id: "worked/record/index-out-of-range",
		build: func(b *irBuilder) hash.Hash {
			b.feature("error-path")
			return probe(b, b.index(b.lookupScope("arr"), b.lit(int64(99))))
		},
	},
	{
		// F-2, the ruled case (ARCH-RESPONSE R3, §9.1): an out-of-range index
		// whose magnitude exceeds int64 is index_out_of_range, NOT type_mismatch.
		// int/uint are annotations, not distinct value types (§2.2), so any
		// integer bit-pattern is a valid index argument; out-of-bounds magnitude
		// — read signed (negative) or unsigned (≥ length) — is index_out_of_range.
		//
		// cast(-4, uint) = 2⁶⁴−4: a well-formed unsigned index, far past the
		// array length. This is the named version of the divergence the sweep
		// found at case 93, where Go answered type_mismatch and Rust
		// index_out_of_range; Rust was ruled correct and Go's evaluator fixed.
		id: "worked/record/index-out-of-range-uint",
		build: func(b *irBuilder) hash.Hash {
			b.feature("error-path", "unsigned-at-use-site")
			idx := b.cast(b.lit(int64(-4)), "primitive/uint")
			return probe(b, b.index(b.lookupScope("arr"), idx))
		},
	},

	// --- 9. numeric-intent (§3 row 9; §4a) ---------------------------------

	{
		// The ninth row is not a graph — it is the parameter that selects signed
		// vs unsigned across div/mod/compare. This vector holds mod, the member
		// the arithmetic and compare vectors above do not cover, at both
		// readings in one expression: signed mod of -3 and the same operand
		// cast at the use site. Constructing both in one probe means a single
		// boundary hash pins the pair, so an impl cannot pass by getting one
		// reading right twice.
		id: "worked/numeric-intent/mod-signed-vs-unsigned",
		build: func(b *irBuilder) hash.Hash {
			b.feature("unsigned-at-use-site")
			signed := b.arith("mod", b.lookupScope("m"), b.lit(int64(5)))
			unsigned := b.arith("mod",
				b.cast(b.lookupScope("m"), "primitive/uint"),
				b.cast(b.lit(int64(5)), "primitive/uint"))
			return b.construct("app/corpus/intent", map[string]hash.Hash{
				"signed":   signed,
				"unsigned": unsigned,
			})
		},
	},
	{
		// A STANDALONE cast of a negative int to primitive/uint. §2.2 rule 11's
		// parenthetical pins this exactly, and names the vector that pins it:
		//
		//   "A standalone or indirected numeric-cast → uint reinterprets the
		//    bits and yields the non-negative MAGNITUDE — CBOR major type 0, per
		//    rule 10's exception, not signed-canonical (the
		//    v314_cast_int_to_uint_negative vector confirms cast(-1, uint) →
		//    2⁶⁴−1)."
		//
		// So cast(-1, uint) is 18446744073709551615 encoded as major type 0, not
		// -1, and not a cast_out_of_range error. Two things make this the single
		// most divergence-prone cast in the surface: the conversion is a
		// reinterpretation rather than a value-preserving conversion, and a
		// language whose native uint cast saturates, panics, or rejects negatives
		// will disagree without its authors noticing.
		//
		// Deliberately NOT construct-wrapped. Every other vector hides its answer
		// inside an entity hash, which is right for the AE-1 boundary and useless
		// for triage — a divergence report can only say "two hashes differ." At a
		// value-kind boundary the emission carries the canonical CBOR bytes
		// themselves, so the report shows what each impl actually computed.
		//
		// Found by the corpus: the seeded sweep hit this at case 124, where it
		// was buried under a 28-node expression. This is the same finding with a
		// name attached.
		id: "worked/numeric-intent/cast-negative-int-to-uint",
		build: func(b *irBuilder) hash.Hash {
			b.feature("unsigned-at-use-site", "bit-reinterpretation")
			return b.cast(b.lit(int64(-1)), "primitive/uint")
		},
	},
	{
		// The same cast, now MATERIALIZED as a construct field — and the vector
		// that localizes the sweep/0124 divergence.
		//
		// Two rules meet here and only one can win:
		//
		//   rule 10: "A 64-bit integer result MUST be canonically encoded by its
		//            SIGNED two's-complement interpretation: ... bit 63 set →
		//            CBOR major type 1 (the negative two's-complement value)."
		//   rule 11: "A standalone or indirected numeric-cast → uint ... yields
		//            the non-negative magnitude — CBOR major type 0, PER RULE
		//            10'S EXCEPTION ... The cast's value-conversion and its
		//            major-0 encoding ALWAYS APPLY."
		//
		// cast(-1, uint) has bit 63 set, so rule 10 alone would encode it as
		// major type 1 and rule 11's exception says major type 0. The standalone
		// vector above shows Go and Rust agree at a bare value boundary. This one
		// asks whether the exception survives materialization into an entity —
		// where the answer becomes a content hash, and a divergence is a silent
		// hash mismatch rather than a visibly different number.
		//
		// Paired with the standalone deliberately: standalone agreeing while this
		// one differs localizes the divergence to the materialization encoding
		// rather than to the cast, which is a different bug in a different file.
		id: "worked/numeric-intent/cast-negative-to-uint-materialized",
		build: func(b *irBuilder) hash.Hash {
			b.feature("unsigned-at-use-site", "bit-reinterpretation", "nested-construct")
			return b.construct("app/corpus/cast", map[string]hash.Hash{
				"v": b.cast(b.lit(int64(-1)), "primitive/uint"),
			})
		},
	},
	{
		// The SAME materialized cast, but reached THROUGH an if-branch — the
		// residual F-1 path the direct vector above does not cover.
		//
		// §2.2 rule 11 is precise about what indirection drops: "what indirection
		// drops is only the OPERATION-LEVEL unsigned intent for a consuming
		// div/mod/compare. The cast's value-conversion and its major-0 encoding
		// ALWAYS APPLY." There is no consuming op here — the cast result flows
		// through if→then straight into a construct field — so the major-0
		// magnitude MUST survive. The `if` selects the cast (condition is 1u==1u,
		// true), so the materialized entity is IDENTICAL to the direct vector's:
		// app/corpus/cast{v: uint 2⁶⁴−1} = the same 5243d277… hash.
		//
		// Why it earns its own name: the first three-way run (2026-07-23) had the
		// direct vector GREEN in all three impls while sweep/0124 — which reaches
		// the cast through an if — was ONE-DIFFERS (Rust materialized the value as
		// signed −3). So an impl can fix the direct construct-field encoder and
		// still collapse the cast on the through-indirection path, conflating "drop
		// the op-intent tag" (rule 11, correct) with "drop the major-0 encoding"
		// (never). This vector pins the two paths apart; direct-green + this-red is
		// the exact signature of that conflation.
		id: "worked/numeric-intent/cast-negative-to-uint-through-if-materialized",
		build: func(b *irBuilder) hash.Hash {
			b.feature("unsigned-at-use-site", "bit-reinterpretation", "nested-construct")
			cond := b.compare("eq", b.lit(uint64(1)), b.lit(uint64(1)))
			castV := b.cast(b.lit(int64(-1)), "primitive/uint")
			zero := b.lit(int64(0))
			return b.construct("app/corpus/cast", map[string]hash.Hash{
				"v": b.ifE(cond, castV, &zero),
			})
		},
	},
	{
		// The control for the vector above: the same construct with the negative
		// literal and NO cast.
		//
		// This is what makes the previous vector diagnosable rather than merely
		// red. Two impls disagreeing on a content hash tells you nothing about
		// which encoding either chose — the hash is opaque. But if an impl's
		// answer to `construct{v: cast(-1, uint)}` equals ITS OWN answer to
		// `construct{v: -1}`, then its cast is a no-op at the materialization
		// boundary: rule 10's signed-canonical encoding was applied and rule 11's
		// major-0 exception was dropped. The comparison is within one impl, so it
		// works without privileging anyone's bytes — which is the whole
		// constraint cross-bless operates under.
		id: "worked/numeric-intent/negative-literal-materialized-control",
		build: func(b *irBuilder) hash.Hash {
			b.feature("bit-reinterpretation", "nested-construct")
			return b.construct("app/corpus/cast", map[string]hash.Hash{
				"v": b.lit(int64(-1)),
			})
		},
	},
	{
		// Error path: cast_out_of_range, the third distinct code the guards
		// require. A float literal beyond int64 range — deterministic, and it
		// exercises the cast's range check rather than its type check.
		//
		// Sits next to the vector above on purpose: the pair separates "a cast
		// that reinterprets" from "a cast that legitimately fails," which is the
		// distinction an impl conflates when it rejects negative→uint.
		id: "worked/numeric-intent/cast-out-of-range",
		build: func(b *irBuilder) hash.Hash {
			b.feature("error-path")
			return probe(b, b.cast(b.lit(float64(1e30)), "primitive/int"))
		},
	},
	{
		// Error path: type_mismatch. Casting a non-numeric is a different code
		// from casting an out-of-range numeric, and impls conflate the two.
		id: "worked/numeric-intent/cast-type-mismatch",
		build: func(b *irBuilder) hash.Hash {
			b.feature("error-path")
			return probe(b, b.cast(b.lit("not a number"), "primitive/uint"))
		},
	},

	// --- Budget surface (BP-1 / W-BUDGET preemption determinism) ------------

	{
		// budget_exhausted must be DETERMINISTIC: the same expression under the
		// same operation budget must stop at the same place in every impl, or
		// W-BUDGET preemption is unimplementable. The budget is set low enough
		// that the fold cannot complete, so the vector pins the failure rather
		// than the result.
		//
		// This is the vector most likely to diverge first, because nothing in
		// the spec forces two impls to charge the same number of operations for
		// the same node. If it goes red cross-impl, the finding is a spec
		// ambiguity (all differ) and not an impl bug — §4's routing rule.
		//
		// The collection is a 32-element literal against a 24-operation budget,
		// which puts the cut well inside the fold. Sizing matters in both
		// directions: a budget the workload can finish under makes the vector
		// silently assert a value (it did, at 24 ops over the 4-element `arr`),
		// while one so small that evaluation dies on the first node would be
		// satisfied by any impl that counts operations at all. Stopping partway
		// through a loop is the only shape that pins WHERE an impl stops.
		id:     "worked/budget/exhausted-deterministic",
		budget: VecBudget{Operations: 24, Depth: 1024},
		build: func(b *irBuilder) hash.Hash {
			b.feature("error-path", "budget")
			fn := b.lambda([]string{"acc", "e"},
				b.arith("add", b.lookupScope("acc"), b.lookupScope("e")))
			long := make([]interface{}, 32)
			for i := range long {
				long[i] = int64(i)
			}
			return probe(b, b.foldB(b.lit(long), b.lit(int64(0)), fn))
		},
	},
	{
		// not_found: a free variable with no root binding. Cheap, and it pins
		// that an unbound name is an error rather than a null.
		id: "worked/scope/unbound-name",
		build: func(b *irBuilder) hash.Hash {
			b.feature("error-path")
			return probe(b, b.lookupScope("nope"))
		},
	},
	{
		// The vector that forced COMPUTE-ERROR-MATERIALIZATION open, and the one
		// arch's v3.23 ruling closed. A compute/error is a value-type (SA-1): a
		// LITERAL error, evaluated, returns as-is rather than propagating on its
		// own, so it LANDS in a compute/construct FIELD — the only vector that
		// reaches an error across the construct boundary at all (every other error
		// vector here propagates out of its `probe` before any construct sees it).
		// That is what made this the instrument for the embed-vs-propagate question
		// the §2.4 gate presupposed away.
		//
		// Run three-way (report 2026-08-15-d) it did NOT lock: go embedded +
		// materialized code-only (A), rust propagated (B), py crashed. Routed, not
		// voted (GUIDE-CONFORMANCE §4 — all three differ, tighten the spec).
		//
		// arch RULED (B), COMPUTE v3.23: is_error is kind-based (§4.1 [MUST]), so an
		// error reaching a construct field SHORT-CIRCUITS — the construct evaluation
		// yields the error. N1 was corrected to drop compute/error from the three
		// consumption sites; an error materializes only where it is WRITTEN (§7.2
		// result_path / SA-9 store). So this vector's outcome is now ERROR-KIND (code
		// `corpus_materialized_error`), matching rust's original result. go flipped
		// to (B) — eval_construct.go short-circuits and materialize() now REJECTS an
		// error; the loud `message` below proves the outcome turns on `code` and is
		// blind to prose. §2.4 ratification waits on this re-running three-way under
		// (B): go + rust agree; py owes its crash fix.
		id: "worked/error/materialized-into-construct",
		build: func(b *irBuilder) hash.Hash {
			b.feature("error-path", "propagated-error")
			errLit := errorValue(b, "corpus_materialized_error",
				"DIAGNOSTIC PROSE — v3.23 ruling (B): this error PROPAGATES from the construct field; the outcome is error-kind and turns on `code` alone, never on this message")
			return probe(b, errLit)
		},
	},

	// --- §2131 value-form error family (arch ROUTING-2026-08-16-b, item 1) ----
	//
	// A compute/error is a value (SA-1), and is_error is KIND-based (§4.1
	// [MUST]), so a value-form error MUST short-circuit at every consumer exactly
	// as a minted one does — the outcome is error-kind, turning on `code` alone.
	// The pre-existing worked/error/materialized-into-construct vector exercises
	// the value form at ONE consumer (a construct field); this family covers the
	// rest of §2148's short-circuit list — arithmetic, compare, logic, field,
	// index, if-condition, apply — the consumers a three-green board sat on top
	// of while two impls independently reached 0% value-form coverage (AP-14).
	//
	// Each vector's root IS the consumer (no `probe` wrapper): wrapping would add
	// a construct consumer and test that instead of the one named. The loud
	// `message` proves the outcome is blind to prose — cross-bless keys error
	// outcomes on `code` alone (crossbless.go signature()).

	{
		id: "worked/value-error/arithmetic-short-circuits",
		build: func(b *irBuilder) hash.Hash {
			b.feature("error-path", "value-form-error")
			return b.arith("add", vfErrorLit(b), b.lit(int64(1)))
		},
	},
	{
		id: "worked/value-error/compare-short-circuits",
		build: func(b *irBuilder) hash.Hash {
			b.feature("error-path", "value-form-error")
			return b.compare("lt", vfErrorLit(b), b.lit(int64(1)))
		},
	},
	{
		id: "worked/value-error/logic-short-circuits",
		build: func(b *irBuilder) hash.Hash {
			b.feature("error-path", "value-form-error")
			t := b.lit(true)
			return b.logic("and", vfErrorLit(b), &t)
		},
	},
	{
		id: "worked/value-error/field-short-circuits",
		build: func(b *irBuilder) hash.Hash {
			b.feature("error-path", "value-form-error")
			// The trap this pins: a field consumer that reads `.code` off the error
			// instead of short-circuiting would return "value_form_error" as a value.
			return b.field("code", vfErrorLit(b))
		},
	},
	{
		id: "worked/value-error/index-short-circuits",
		build: func(b *irBuilder) hash.Hash {
			b.feature("error-path", "value-form-error")
			return b.index(vfErrorLit(b), b.lit(int64(0)))
		},
	},
	{
		id: "worked/value-error/if-condition-short-circuits",
		build: func(b *irBuilder) hash.Hash {
			b.feature("error-path", "value-form-error")
			then := b.lit(int64(1))
			els := b.lit(int64(2))
			return b.ifE(vfErrorLit(b), then, &els)
		},
	},
	{
		id: "worked/value-error/apply-fn-short-circuits",
		build: func(b *irBuilder) hash.Hash {
			b.feature("error-path", "value-form-error")
			// The apply target (fn) is an error — the closure-mode apply MUST
			// short-circuit before attempting to load a scope from it.
			return b.applyClosure(vfErrorLit(b), map[string]hash.Hash{"x": b.lit(int64(1))})
		},
	},
	{
		// The SECOND SA-1 form arch named: not a literal, but a lookup/tree
		// resolving to a STORED compute/error. It must short-circuit identically —
		// a literal that works and a lookup that doesn't would be the same
		// two-representation split one indirection deeper.
		id: "worked/value-error/lookup-tree-short-circuits",
		build: func(b *irBuilder) hash.Hash {
			b.feature("error-path", "value-form-error", "tree-lookup")
			errH := errorValue(b, "stored_value_form_error",
				"PROSE from a STORED error resolved via lookup/tree — the outcome is code-only")
			b.at("corpus/value-error/stored", errH)
			return b.arith("mul", b.lookupTree("corpus/value-error/stored"), b.lit(int64(2)))
		},
	},

	// --- SA-9 store crossing materializes code-only (§2.4 write-site gate) -----
	//
	// The store crossing, and the §2.4 code-only property ON it — item 2 of arch's
	// ROUTING-2026-08-16-b, the half the proposal waits on. Store an error, read it
	// back; the read-back IS the written entity. §2.4 requires that entity be
	// content-hashed over `code` ALONE — message/at MUST NOT enter the bytes, or
	// two peers writing the same error to the same path get different hashes
	// (breaking AE-1, dedup, cross-peer sync).
	//
	// These carry boundaryPath: the boundary is the entity actually WRITTEN to the
	// store path, read back out of band (not the eval result). That is what makes
	// code-only gateable. Reading the eval result cannot: over the wire an error
	// result is re-wrapped by F10 with a fresh message (so it is NOT the stored
	// entity), and under the error-kind reduction cross-bless keys on `code` and is
	// blind to `message` anyway — which is how the 2026-08-16 three-way reported
	// LOCKED while go stored code-only and rust/py stored with-message. Hashing the
	// stored entity turns a message-leaking store into a hard divergence from a
	// code-only one.
	//
	// Two vectors = the two-representation pair at the crossing (AP-14): the minted
	// form (division_by_zero) and the value form. Both go through builtinStore's
	// write, which 61b431c fixed to materialize code-only for either form. The root
	// is just the store — the write is the whole point; the boundary is its result.
	{
		id:           "worked/error/store-materializes-code-only-minted",
		boundaryPath: "corpus/error/store-minted",
		build: func(b *irBuilder) hash.Hash {
			b.feature("error-path", "store-crossing", "materialized-error")
			minted := b.arith("div", b.lookupScope("n"), b.lit(int64(0)))
			return b.storeB(b.lit("corpus/error/store-minted"), minted)
		},
	},
	{
		id:           "worked/error/store-materializes-code-only-value-form",
		boundaryPath: "corpus/error/store-vf",
		build: func(b *irBuilder) hash.Hash {
			b.feature("error-path", "store-crossing", "materialized-error", "value-form-error")
			verr := errorValue(b, "stored_before_write",
				"LOUD PROSE that MUST NOT survive the SA-9 store write — §2.4 code-only")
			return b.storeB(b.lit("corpus/error/store-vf"), verr)
		},
	},

	// Q23 (§2.1, arch 7fdeea7 / ROUTING-2026-08-16-i): a builtin-path compute/apply
	// carrying capability or resource is invalid_expression — the fields are
	// parameters of the dispatched EXECUTE, which a builtin (inline, §3.5) never
	// dispatches. Two representatives: a PURE builtin rejecting on `resource`, and
	// the security-critical `store` rejecting on `capability` (the field arch's
	// fail-closed argument turns on). Both carry a benign literal, so they lock the
	// same under either rejection ordering — the ordering-sensitive case is
	// spec-issue 2026-08-16-d, deliberately NOT vectored until arch rules it.
	{
		id: "worked/error/builtin-apply-carrying-resource-is-invalid",
		build: func(b *irBuilder) hash.Hash {
			b.feature("error-path", "builtin-alias", "invalid-expression")
			res := b.lit("app/corpus/benign-resource")
			return b.builtinCarrying(compute.BuiltinArithmetic,
				map[string]hash.Hash{"op": b.lit("add"), "left": b.lit(int64(3)), "right": b.lit(int64(4))},
				nil, &res)
		},
	},
	{
		id: "worked/error/builtin-store-apply-carrying-capability-is-invalid",
		build: func(b *irBuilder) hash.Hash {
			b.feature("error-path", "builtin-alias", "invalid-expression", "store-crossing")
			cap := b.lit("app/corpus/benign-capability")
			return b.builtinCarrying(compute.BuiltinStore,
				map[string]hash.Hash{"path": b.lit("corpus/error/q23-store"), "value": b.lit(int64(1))},
				&cap, nil)
		},
	},
}

// vfErrorLit records one value-form compute/error literal (SA-1) carrying loud
// diagnostic prose, and returns its hash. The prose is really in the artifact
// bytes so that "the outcome turns on code alone" is a claim the corpus can
// actually falsify — an artifact carrying only the code could not tell a
// short-circuiting impl from one that leaks the message.
func vfErrorLit(b *irBuilder) hash.Hash {
	return errorValue(b, "value_form_error",
		"LOUD PROSE — a value-form compute/error (SA-1) MUST short-circuit at this consumer; the outcome is error-kind and turns on `code` alone, never on this message")
}

// matchVariant builds the §4d match decomposition for a given tag: construct a
// variant carrying the tag in .data, then discriminate with if/eq over
// field(value, "tag").
func matchVariant(b *irBuilder, tag string) hash.Hash {
	variant := b.construct("app/corpus/shape", map[string]hash.Hash{
		"tag":  b.lit(tag),
		"size": b.lookupScope("n"),
	})
	tagOf := b.field("tag", b.lookupScope("v"))
	sizeOf := b.field("size", b.lookupScope("v"))
	circle := b.arith("mul", sizeOf, b.lit(int64(3)))
	square := b.arith("mul", sizeOf, sizeOf)
	isCircle := b.compare("eq", tagOf, b.lit("circle"))
	body := b.ifE(isCircle, circle, &square)
	return probe(b, b.letE(map[string]hash.Hash{"v": variant}, body))
}

// errorValue records a compute/error VALUE literal in the closure and returns
// its hash. This is the in-flight form (§2.4: {code, message, at?, expression?}),
// so the `message` is REALLY in the artifact bytes — which is the whole point of
// the materialized-into-construct vector: the materialized boundary MUST strip it
// to `code` alone, and an artifact that carried only the code could not tell a
// stripping impl from a non-stripping one. A compute/error is a value-type (SA-1),
// so evaluating this literal returns it as-is rather than propagating, letting it
// be placed into a compute/construct field. Panics on encode failure — the inputs
// are literals here, so a failure is a corpus-build programming error.
func errorValue(b *irBuilder, code, message string) hash.Hash {
	ent, err := types.ComputeErrorData{Code: code, Message: message}.ToEntity()
	if err != nil {
		panic("corpus: build compute/error literal " + code + ": " + err.Error())
	}
	return b.addRaw(ent)
}

// rawEntity hand-builds a non-compute entity for tree preconditions. Panics on
// encode failure: the inputs are literals in this file, so a failure is a
// programming error at corpus-build time, not a runtime condition.
func rawEntity(entityType string, data map[string]interface{}) entity.Entity {
	raw, err := ecf.Encode(data)
	if err != nil {
		panic("corpus: encode raw entity " + entityType + ": " + err.Error())
	}
	ent, err := entity.NewEntity(entityType, cbor.RawMessage(raw))
	if err != nil {
		panic("corpus: build raw entity " + entityType + ": " + err.Error())
	}
	return ent
}
