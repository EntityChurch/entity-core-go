package main

// The seeded sweep generator — ported from entity-workbench-go's
// entitysdk/axis1_equivalence_test.go (exprGen, seed 20260716, 300 cases).
//
// GUIDE-CONFORMANCE §7c.2 names that harness "the thing to port cross-impl,"
// and §7c.4(1) is specific about what porting means: "port the generator, not a
// static dump," because a dump alone freezes Go's coverage. So the grammar
// below is a faithful port of the workbench typed grammar, and the artifact it
// produces is the frozen output every impl runs.
//
// TWO DELIBERATE DEPARTURES FROM THE WORKBENCH ORIGINAL
//
//  1. The PRNG. math/rand is not reproducible outside Go, which would make
//     "run the generator with seed S" mean three different corpora. See prng.go.
//     Consequence: the sweep is NOT the same 300 shapes the workbench sees, and
//     that is fine — the two harnesses prove different claims (§7c.4(4)).
//
//  2. An unsigned root binding (`u`). The workbench bindings are n=7, m=-3,
//     arr=[1,2,3,4] — all signed. That is the right set for an intra-Go engine
//     comparison, where the risk is Axis-1 re-deriving Stage-1's arithmetic. It
//     is the wrong set for a cross-impl corpus, where the risk is a language
//     whose integers are not natively two's-complement 64-bit disagreeing about
//     mixed signed/unsigned operands. Mixed-mode arithmetic never occurs in the
//     original sweep; here it occurs constantly.
//
// The grammar keeps every property the original was built for: it is TYPED
// (int / bool / array), so cases are mostly meaningful rather than degenerating
// into a type_mismatch corpus, while still emitting div/mod, index, and casts so
// the error paths are covered on purpose rather than by accident.

import (
	"fmt"

	"go.entitychurch.org/entity-core-go/core/hash"
)

// defaultSeed selects the published sweep stream.
//
// It is the workbench harness's seed carried forward. Under a different PRNG it
// selects an entirely different stream, so it is not continuity of coverage —
// it is continuity of provenance: anyone tracing this corpus back finds the
// harness it was ported from.
const defaultSeed uint64 = 20260716

// defaultCases matches the workbench sweep's case count. Kept identical so a
// coverage comparison between the two harnesses is like-for-like on N even
// though the shapes differ.
const defaultCases = 300

// exprGen builds random well-formed expression graphs over the typed grammar.
type exprGen struct {
	b   *irBuilder
	rnd *rng
}

// intExpr generates an integer-valued expression.
func (g *exprGen) intExpr(depth int) hash.Hash {
	return g.intExprOpt(depth, true)
}

// intExprOpt generates an integer-valued expression; allowCast=false forbids a
// bare numeric-cast at the ROOT of the generated expression.
//
// That restriction is not a generator convenience — it is Rule 11 (§4a) as a
// build-time constraint. A cast bound in a `let` silently reverts to
// signed-default, so the toolkit contract says a conformant lowering MUST
// inline the cast at the use site and never bind it. The workbench builder
// enforces this by rejecting the binding outright; this generator has no
// builder to enforce it, so the grammar respects it explicitly.
//
// The bound case is not thereby lost: `worked/arithmetic/rule11-let-bound-cast-
// reverts-to-signed` pins it as a named vector, which is where a footgun
// belongs — with a diagnosis attached, not scattered through a random sweep.
func (g *exprGen) intExprOpt(depth int, allowCast bool) hash.Hash {
	b := g.b
	if depth <= 0 {
		switch g.rnd.intn(5) {
		case 0:
			return b.lit(int64(g.rnd.intn(21) - 10))
		case 1:
			return b.lit(uint64(g.rnd.intn(10)))
		case 2:
			return b.lookupScope("n")
		case 3:
			return b.lookupScope("m")
		default:
			// The mixed-mode operand: a uint64 root binding meeting signed
			// literals under every arithmetic and comparison op in the grammar.
			return b.lookupScope("u")
		}
	}
	n := 8
	if !allowCast {
		n = 7
	}
	switch g.rnd.intn(n) {
	case 0, 1, 2:
		ops := []string{"add", "sub", "mul", "div", "mod"}
		op := ops[g.rnd.intn(len(ops))]
		return b.arith(op, g.intExpr(depth-1), g.intExpr(depth-1))
	case 3:
		return b.ifE(g.boolExpr(depth-1), g.intExpr(depth-1), ptr(g.intExpr(depth-1)))
	case 4:
		// Names chosen to sort in dependency order: let bindings are evaluated
		// in sorted name order, so "a" is visible to "b" but not the reverse.
		// The asymmetry is exercised on purpose — it is where an impl that
		// evaluates bindings in wire order or in parallel diverges.
		a := g.intExprOpt(depth-1, false)
		bb := b.arith("add", b.lookupScope("a"), g.intExpr(depth-1))
		body := b.arith("mul", b.lookupScope("a"), b.lookupScope("b"))
		return b.letE(map[string]hash.Hash{"a": a, "b": bb}, body)
	case 5:
		return b.index(g.arrExpr(depth-1), g.intExpr(depth-1))
	case 6:
		return b.length(g.arrExpr(depth - 1))
	default:
		// Rule 11 positive: an eager cast at the operand position flips
		// div/mod/compare unsigned. Generated directly under an op so the hint
		// is actually consumed — that is the semantic an impl's decoder must
		// hoist, and the position where it is observable.
		g.b.feature("unsigned-at-use-site")
		t := []string{"primitive/int", "primitive/uint", "primitive/float"}[g.rnd.intn(3)]
		return b.cast(g.intExpr(depth-1), t)
	}
}

func (g *exprGen) boolExpr(depth int) hash.Hash {
	b := g.b
	cmpOps := []string{"eq", "neq", "lt", "gt", "lte", "gte"}
	if depth <= 0 {
		return b.compare(cmpOps[g.rnd.intn(6)], g.intExpr(0), g.intExpr(0))
	}
	switch g.rnd.intn(3) {
	case 0:
		return b.compare(cmpOps[g.rnd.intn(6)], g.intExpr(depth-1), g.intExpr(depth-1))
	case 1:
		return b.logic([]string{"and", "or"}[g.rnd.intn(2)],
			g.boolExpr(depth-1), ptr(g.boolExpr(depth-1)))
	default:
		return b.logic("not", g.boolExpr(depth-1), nil)
	}
}

func (g *exprGen) arrExpr(depth int) hash.Hash {
	b := g.b
	if depth <= 0 {
		n := g.rnd.intn(4)
		vals := make([]interface{}, n)
		for i := range vals {
			vals[i] = int64(g.rnd.intn(10))
		}
		return b.lit(vals)
	}
	switch g.rnd.intn(3) {
	case 0:
		// map with a closure capturing an enclosing binding — the live-frame
		// path, and where an engine holding environments as pointers diverges
		// most from one materializing them through capture/load.
		fn := b.lambda([]string{"e"},
			b.arith("add", b.lookupScope("e"), g.intExpr(depth-1)))
		return b.mapB(g.arrExpr(depth-1), fn)
	case 1:
		fn := b.lambda([]string{"e"},
			b.compare("gt", b.lookupScope("e"), g.intExpr(0)))
		return b.filterB(g.arrExpr(depth-1), fn)
	default:
		return b.lookupScope("arr")
	}
}

// buildSweep generates the seeded sweep.
//
// Every case is wrapped in a construct: it forces the result across the
// materialized boundary (the only surface the contract binds) and it is the
// shape every real program's step ends in. The case index rides in a `tag`
// field so two cases that happen to compute the same value still produce
// distinct boundary hashes — otherwise a collapsed corpus would look like
// coverage it does not have.
func buildSweep(seed uint64, cases int, profile string) ([]Vector, error) {
	rnd := newRNG(seed)
	out := make([]Vector, 0, cases)
	for i := 0; i < cases; i++ {
		bindings := stdBindings()
		b := newIRBuilder(inlineRootsFor(profile, bindings))
		g := &exprGen{b: b, rnd: rnd}
		root := b.construct("app/corpus/probe", map[string]hash.Hash{
			"value": g.intExpr(3),
			"tag":   b.lit(int64(i)),
		})
		v, err := b.freeze(fmt.Sprintf("sweep/%04d", i), i, root,
			emittedBindings(profile, bindings), stdBudget)
		if err != nil {
			return nil, fmt.Errorf("sweep case %d (seed %d): %w", i, seed, err)
		}
		out = append(out, v)
	}
	return out, nil
}

// ptr is the address-of helper the optional-hash fields need.
func ptr(h hash.Hash) *hash.Hash { return &h }
