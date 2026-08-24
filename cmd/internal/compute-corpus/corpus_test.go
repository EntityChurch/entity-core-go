package main

// These tests do NOT assert what the boundary hashes are.
//
// That distinction is the whole discipline of §7c.5(b): Go is the
// fixture-builder, not the oracle. Pinning core-go's answers here would make
// this file a golden-master of Go's evaluator, and the first time a cross-impl
// divergence turned out to be Go's bug, the test suite would defend the bug.
//
// What they DO assert is that each vector pins the invariant it claims to. A
// vector whose two readings produce the same boundary discriminates nothing,
// and would sail through cross-bless green while proving nothing — the
// ECF-F30 "vacuous pass" failure mode, aimed at the corpus itself rather than
// at an impl. So the tests below check discrimination, reachability, and
// reproducibility, and stay silent about values.

import (
	"bytes"
	"testing"

	"go.entitychurch.org/entity-core-go/core/ecf"
	"go.entitychurch.org/entity-core-go/core/hash"
)

// buildTestCorpus builds the full corpus once for the tests that need it.
func buildTestCorpus(t *testing.T) *Corpus {
	t.Helper()
	return buildTestCorpusProfile(t, profileInproc)
}

func buildTestCorpusProfile(t *testing.T, profile string) *Corpus {
	t.Helper()
	worked, err := buildWorked(profile)
	if err != nil {
		t.Fatalf("build worked: %v", err)
	}
	sweep, err := buildSweep(defaultSeed, defaultCases, profile)
	if err != nil {
		t.Fatalf("build sweep: %v", err)
	}
	c := &Corpus{
		CorpusVersion:    corpusVersion,
		GeneratorVersion: generatorVersion,
		PRNG:             prngName,
		Seed:             defaultSeed,
		SweepCases:       defaultCases,
		Profile:          profile,
		SpecVersion:      specVersion,
		Vectors:          append(worked, sweep...),
	}
	if err := checkVectorIDsUnique(c.Vectors); err != nil {
		t.Fatal(err)
	}
	return c
}

// outcomes evaluates every vector and returns the results by ID.
func outcomes(t *testing.T, c *Corpus) map[string]Outcome {
	t.Helper()
	out := make(map[string]Outcome, len(c.Vectors))
	for _, v := range c.Vectors {
		o, err := evalVector(v)
		if err != nil {
			t.Fatalf("vector %s: %v", v.ID, err)
		}
		out[v.ID] = o
	}
	return out
}

func mustOutcome(t *testing.T, os map[string]Outcome, id string) Outcome {
	t.Helper()
	o, ok := os[id]
	if !ok {
		t.Fatalf("vector %s missing from results", id)
	}
	return o
}

// TestCorpusIsReproducible is the §7c.4(6) contract: the artifact must be
// byte-identical across builds, or "hash-pin the frozen corpus in a MANIFEST"
// pins nothing and no impl can be sure it ran what Go ran.
//
// It is a live risk rather than a formality: the builder holds its closure in a
// map and Go randomizes map iteration per process, so an ordering mistake
// anywhere in freeze() surfaces as a corpus whose SHA changes every run.
func TestCorpusIsReproducible(t *testing.T) {
	a := buildTestCorpus(t)
	b := buildTestCorpus(t)

	rawA, sumA, err := encodeCorpus(a)
	if err != nil {
		t.Fatal(err)
	}
	rawB, sumB, err := encodeCorpus(b)
	if err != nil {
		t.Fatal(err)
	}
	if sumA != sumB {
		t.Fatalf("corpus is not reproducible: %x != %x (%d vs %d bytes)",
			sumA, sumB, len(rawA), len(rawB))
	}
	if _, err := decodeCorpus(rawA); err != nil {
		t.Fatalf("corpus fails its own round-trip: %v", err)
	}
}

// TestSeedSelectsAStream guards the reproducibility triple from the other
// direction: if a different seed produced the same corpus, the seed would be
// decorative and "reproduce from (seed, case-index)" would be meaningless.
func TestSeedSelectsAStream(t *testing.T) {
	a, err := buildSweep(defaultSeed, 32, profileInproc)
	if err != nil {
		t.Fatal(err)
	}
	b, err := buildSweep(defaultSeed+1, 32, profileInproc)
	if err != nil {
		t.Fatal(err)
	}
	same := 0
	for i := range a {
		if a[i].Root == b[i].Root {
			same++
		}
	}
	if same == len(a) {
		t.Fatal("two different seeds produced identical shapes — the seed is not reaching the generator")
	}
}

// TestWireProfileIsClosedButStillUsesScope is the contract of the `wire`
// profile, in both directions.
//
// EXTENSION-COMPUTE §3.2 is normative that explicit eval over the wire starts
// from `scope = empty_scope()`, so a vector referencing a root binding cannot be
// evaluated by a live peer at all. The wire profile inlines those bindings.
//
// The risk in doing that is over-correcting: inline every scope lookup and the
// corpus stops exercising compute/lookup/scope, closures, and the let* ordering
// rule — a wire-drivable corpus that has quietly dropped four of the eight
// MUST-implement core expression types. So the test asserts BOTH halves: no
// vector still depends on a root binding, AND scope lookups are still plentiful
// because let- and lambda-bound names were left alone.
func TestWireProfileIsClosedButStillUsesScope(t *testing.T) {
	c := buildTestCorpusProfile(t, profileWire)

	rootNames := map[string]bool{}
	for k := range stdBindings() {
		rootNames[k] = true
	}

	scopeLookups := 0
	for _, v := range c.Vectors {
		var bindings map[string]interface{}
		if err := ecf.Decode(v.Bindings, &bindings); err != nil {
			t.Fatalf("%s: decode bindings: %v", v.ID, err)
		}
		if len(bindings) != 0 {
			t.Errorf("%s: wire profile must emit no root bindings, got %d", v.ID, len(bindings))
		}
		for _, ve := range v.Entities {
			if ve.Type != "compute/lookup/scope" {
				continue
			}
			scopeLookups++
			var d struct {
				Name string `cbor:"name"`
			}
			if err := ecf.Decode(ve.Data, &d); err != nil {
				t.Fatalf("%s: decode lookup/scope: %v", v.ID, err)
			}
			if rootNames[d.Name] {
				t.Errorf("%s: still looks up root binding %q, which a peer's empty eval scope cannot supply",
					v.ID, d.Name)
			}
		}
	}
	if scopeLookups == 0 {
		t.Fatal("the wire profile inlined every scope lookup — let/lambda binding, " +
			"closure capture, and compute/lookup/scope itself all went untested")
	}

	// And it must still evaluate to something worth comparing.
	em := &Emission{Impl: implName, Engine: "stage1", EngineRole: RoleReference,
		CorpusVersion: c.CorpusVersion, Results: outcomes(t, c)}
	if rep := runGuards(c, em, false); rep.Failed() {
		t.Fatalf("wire-profile corpus fails the anti-vacuity guards:\n%s", rep.String())
	}
}

// TestWireAndInprocAreDifferentArtifacts: the two profiles are different
// corpora, and an emission from one must never be compared against the other.
// The SHA-pin enforces that mechanically — this checks the SHAs actually differ.
func TestWireAndInprocAreDifferentArtifacts(t *testing.T) {
	_, inproc, err := encodeCorpus(buildTestCorpusProfile(t, profileInproc))
	if err != nil {
		t.Fatal(err)
	}
	_, wire, err := encodeCorpus(buildTestCorpusProfile(t, profileWire))
	if err != nil {
		t.Fatal(err)
	}
	if inproc == wire {
		t.Fatal("the two profiles produced an identical artifact — root-binding inlining did not happen")
	}
}

// TestWorkedVectorsDiscriminate is the anti-vacuity check aimed at the AUTHORED
// vectors. Each pair below exists to separate two readings of the same source;
// if both readings land on the same boundary, the vector cannot detect the
// divergence it was written for, and would pass cross-bless while blind.
func TestWorkedVectorsDiscriminate(t *testing.T) {
	c := buildTestCorpus(t)
	os := outcomes(t, c)

	pairs := []struct {
		name, a, b, why string
	}{
		{
			name: "rule11-cast-position",
			a:    "worked/arithmetic/unsigned-div-at-use-site",
			b:    "worked/arithmetic/rule11-let-bound-cast-reverts-to-signed",
			why:  "an operand-site cast means unsigned; the same cast let-bound reverts to signed (§4a)",
		},
		{
			name: "compare-intent",
			a:    "worked/compare/signed-default",
			b:    "worked/compare/unsigned-at-use-site-flips",
			why:  "-3 < 7 signed is true; reinterpreted unsigned it is false",
		},
		{
			name: "match-arms",
			a:    "worked/match/tag-dispatch-arm-a",
			b:    "worked/match/tag-dispatch-arm-b",
			why:  "the two arms must reach different branches, or a stuck `then` passes both",
		},
	}
	for _, p := range pairs {
		oa := mustOutcome(t, os, p.a)
		ob := mustOutcome(t, os, p.b)
		if canonicalOutcome(oa) == canonicalOutcome(ob) {
			t.Errorf("%s: %s and %s produce the identical boundary %s — the pair discriminates nothing.\n  %s",
				p.name, p.a, p.b, canonicalOutcome(oa), p.why)
		}
	}
}

// TestCastThroughIfEqualsDirect locks the intent of the through-if F-1 vector:
// reaching the cast through an if-branch must not change its materialized value.
//
// §2.2 rule 11 — indirection drops only the operation-level unsigned intent, not
// the cast's major-0 value-conversion — so `construct{v: if(true, cast(-1,uint),
// 0)}` must materialize identically to `construct{v: cast(-1,uint)}`. If a future
// change to Go's evaluator made them differ, this vector would stop pinning the
// Rust residual it was authored for (direct-green + through-if-red), so guard the
// equality in the reference impl.
func TestCastThroughIfEqualsDirect(t *testing.T) {
	c := buildTestCorpus(t)
	os := outcomes(t, c)
	direct := mustOutcome(t, os, "worked/numeric-intent/cast-negative-to-uint-materialized")
	throughIf := mustOutcome(t, os, "worked/numeric-intent/cast-negative-to-uint-through-if-materialized")
	if canonicalOutcome(direct) != canonicalOutcome(throughIf) {
		t.Errorf("through-if cast must equal direct cast (rule 11: indirection drops op-intent, "+
			"not the major-0 encoding):\n  direct:    %s\n  through-if: %s", direct, throughIf)
	}
}

// TestWorkedErrorVectorsRaiseTheirCode checks that each error vector reaches
// the code it was written for. An error vector that raises a DIFFERENT code
// still looks like an error outcome to the guards — it would satisfy
// "distinct-error-codes>=3" while silently testing something else.
func TestWorkedErrorVectorsRaiseTheirCode(t *testing.T) {
	c := buildTestCorpus(t)
	os := outcomes(t, c)

	want := map[string]string{
		"worked/arithmetic/division-by-zero":       "division_by_zero",
		"worked/record/index-out-of-range":         "index_out_of_range",
		"worked/record/index-out-of-range-uint":    "index_out_of_range",
		"worked/numeric-intent/cast-out-of-range":  "cast_out_of_range",
		"worked/numeric-intent/cast-type-mismatch": "type_mismatch",
		"worked/scope/unbound-name":                "not_found",
		"worked/budget/exhausted-deterministic":    "budget_exhausted",
	}
	for id, code := range want {
		o := mustOutcome(t, os, id)
		if o.Kind != OutcomeError {
			t.Errorf("%s: expected an error outcome, got %s", id, o)
			continue
		}
		if o.Code != code {
			t.Errorf("%s: expected code %q, got %q (%q)", id, code, o.Code, o.Message)
		}
	}
}

// TestMaterializedErrorIsCodeOnly is §2.4 as an executable claim, and the
// invariant the worked/error/materialized-into-construct vector carries into the
// cross-impl corpus. A compute/error materialized into a construct field is
// content-hashed over `code` ALONE (PROPOSAL-COMPUTE-ERROR-MATERIALIZATION-
// DETERMINISM). So the construct's entity-kind boundary must turn on the error's
// CODE and be blind to its (in-flight-only) `message`.
//
// This is what makes the corpus vector load-bearing rather than decorative: it
// asserts, from both directions, exactly the divergence the vector exists to
// catch three-way — an impl that folds `message` into the materialized hash fails
// the same-code half; an impl that hashes a constant regardless of code fails the
// different-code half.
func TestMaterializedErrorIsCodeOnly(t *testing.T) {
	boundary := func(code, message string) []byte {
		b := newIRBuilder(nil)
		root := probe(b, errorValue(b, code, message))
		v, err := b.freeze("test/materialized-error", 0, root, map[string]interface{}{}, stdBudget)
		if err != nil {
			t.Fatalf("freeze(%q): %v", code, err)
		}
		o, err := evalVector(v)
		if err != nil {
			t.Fatalf("eval(%q): %v", code, err)
		}
		if o.Kind != OutcomeEntity {
			t.Fatalf("code %q: expected an entity-kind boundary (a materialized error is a bare entity), got %s", code, o)
		}
		return o.Boundary
	}

	sameCodeA := boundary("materialized_code", "message ALPHA — this prose is in-flight only and MUST NOT be hashed")
	sameCodeB := boundary("materialized_code", "an entirely different message, beta, of a different length")
	diffCode := boundary("other_code", "message ALPHA — this prose is in-flight only and MUST NOT be hashed")

	if !bytes.Equal(sameCodeA, sameCodeB) {
		t.Errorf("same code + different message produced DIFFERENT boundaries — `message` leaked into the materialized hash (§2.4 code-only violated):\n  A: %x\n  B: %x", sameCodeA, sameCodeB)
	}
	if bytes.Equal(sameCodeA, diffCode) {
		t.Errorf("different code produced the SAME boundary — the materialized error is not discriminating on `code` (§2.4):\n  both: %x", sameCodeA)
	}
}

// TestTailRecursionIterates is §4c as an executable claim.
//
// The vector runs 5 levels of self-call under a depth budget of 16. An engine
// that grows evaluation depth per tail call fails with depth_exceeded; one that
// trampolines returns a value. The narrow budget is the instrument — widen it
// and the vector stops distinguishing the two.
func TestTailRecursionIterates(t *testing.T) {
	c := buildTestCorpus(t)
	os := outcomes(t, c)

	o := mustOutcome(t, os, "worked/recurse/tail-sum")
	if o.Kind == OutcomeError {
		t.Fatalf("tail recursion did not iterate: %s (%s). Either TCO regressed or the "+
			"vector's depth budget is too tight to be a fair test", o, o.Message)
	}
}

// TestMaterializedHashReadbackReturnsTheHash is §4f.
//
// Reading a system/hash field out of a materialized entity must yield THE HASH,
// not the entity it points at. The assertion is deliberately structural rather
// than a pinned hex string: it checks that the boundary bytes are the canonical
// encoding of the child's 33-byte content hash, computed from the corpus itself.
// That holds no matter what the child entity's content happens to be, so the
// test does not have to be edited every time the fixture changes — and it would
// fail loudly against an impl that auto-resolved the reference.
func TestMaterializedHashReadbackReturnsTheHash(t *testing.T) {
	c := buildTestCorpus(t)
	os := outcomes(t, c)

	const id = "worked/record/materialized-hash-readback"
	o := mustOutcome(t, os, id)
	if o.Kind != OutcomeValue {
		t.Fatalf("%s: expected a value-kind boundary (the hash itself), got %s", id, o)
	}

	// Recover the child hash from the vector: the parent entity at the tree
	// path carries it in its `child` field.
	var vec *Vector
	for i := range c.Vectors {
		if c.Vectors[i].ID == id {
			vec = &c.Vectors[i]
			break
		}
	}
	if vec == nil {
		t.Fatalf("%s not in corpus", id)
	}
	var parentHash hash.Hash
	for _, h := range vec.Tree {
		parentHash = h
	}
	var parentData map[string]interface{}
	for _, ve := range vec.Entities {
		h, err := hash.Compute(ve.Type, ve.Data)
		if err != nil {
			t.Fatal(err)
		}
		if h == parentHash {
			if err := ecf.Decode(ve.Data, &parentData); err != nil {
				t.Fatal(err)
			}
		}
	}
	childRef, ok := parentData["child"].([]byte)
	if !ok {
		t.Fatalf("parent's child field is not a byte string: %T", parentData["child"])
	}
	wantBytes, err := ecf.Encode(childRef)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(o.Boundary, wantBytes) {
		t.Errorf("%s: boundary is not the child hash.\n  got  %x\n  want %x\n"+
			"An impl that auto-resolves the reference instead of returning it fails exactly here (§4f).",
			id, o.Boundary, wantBytes)
	}
}

// TestGuardsPassOnGoEmission runs the anti-vacuity gate over core-go's own
// emission. If the guards cannot pass against the impl that BUILT the corpus,
// the corpus is vacuous before any other impl sees it.
func TestGuardsPassOnGoEmission(t *testing.T) {
	c := buildTestCorpus(t)
	_, sum, err := encodeCorpus(c)
	if err != nil {
		t.Fatal(err)
	}
	em := &Emission{
		Impl: implName, ImplVersion: "test", Engine: "stage1", EngineRole: RoleReference,
		CorpusSHA256: sum[:], CorpusVersion: c.CorpusVersion, SpecVersion: specVersion,
		Results: outcomes(t, c),
	}
	rep := runGuards(c, em, false)
	if rep.Failed() {
		t.Fatalf("guards failed on core-go's own emission:\n%s", rep.String())
	}
	t.Logf("guards:\n%s", rep.String())
}

// TestGuardSixRejectsAReferenceEmission proves the guard added by §7c.4(2)
// actually bites. A guard that never fires is decoration, and this one is the
// only thing standing between the corpus and circular cross-impl agreement.
func TestGuardSixRejectsAReferenceEmission(t *testing.T) {
	c := buildTestCorpus(t)
	em := &Emission{
		Impl: implName, Engine: "stage1", EngineRole: RoleReference,
		CorpusVersion: c.CorpusVersion, Results: outcomes(t, c),
	}
	if rep := runGuards(c, em, true); !rep.Failed() {
		t.Fatal("guard 6 passed a reference-engine emission under --require-alternate; " +
			"an AE-1 admission run could then compare Stage-1 against itself")
	}
	// And it must not fire when the gate was not requested — otherwise
	// fixture-building runs are permanently red and the signal is ignored.
	if rep := runGuards(c, em, false); rep.Failed() {
		t.Fatalf("guard 6 fired without --require-alternate:\n%s", rep.String())
	}
}

// TestCrossBlessRoutesDivergence checks the §4 classifier, including the rule
// it must NOT implement: no voting. A 2-vs-1 split is reported as the outlier's
// bug; a 3-way split is reported as a spec ambiguity; neither picks a winner.
func TestCrossBlessRoutesDivergence(t *testing.T) {
	c := buildTestCorpus(t)
	base := outcomes(t, c)
	_, sum, err := encodeCorpus(c)
	if err != nil {
		t.Fatal(err)
	}
	mk := func(impl string, mutate func(map[string]Outcome)) *Emission {
		r := make(map[string]Outcome, len(base))
		for k, v := range base {
			r[k] = v
		}
		if mutate != nil {
			mutate(r)
		}
		return &Emission{
			Impl: impl, Engine: "e", EngineRole: RoleReference,
			CorpusSHA256: sum[:], CorpusVersion: c.CorpusVersion, Results: r,
		}
	}

	const oneOff = "worked/fold/sum"
	const threeWay = "worked/map/closure-captures-enclosing"

	go1 := mk("go", nil)
	rs := mk("rust", func(r map[string]Outcome) {
		r[oneOff] = Outcome{Kind: OutcomeValue, Boundary: []byte{0x01}}
		r[threeWay] = Outcome{Kind: OutcomeValue, Boundary: []byte{0x02}}
	})
	py := mk("py", func(r map[string]Outcome) {
		r[threeWay] = Outcome{Kind: OutcomeValue, Boundary: []byte{0x03}}
	})

	verdicts, err := crossBless(c, []*Emission{go1, rs, py}, sum[:])
	if err != nil {
		t.Fatal(err)
	}
	byID := map[string]vectorVerdict{}
	for _, v := range verdicts {
		byID[v.id] = v
	}
	if got := byID[oneOff].kind; got != verdictOneDiffers {
		t.Errorf("%s: expected ONE-DIFFERS, got %s", oneOff, got)
	}
	if got := byID[oneOff].outlier; got != "rust/e" {
		t.Errorf("%s: expected outlier rust/e, got %q", oneOff, got)
	}
	if got := byID[threeWay].kind; got != verdictAllDiffer {
		t.Errorf("%s: expected ALL-DIFFER (spec ambiguity), got %s", threeWay, got)
	}
	if _, locked := summarize(verdicts); locked {
		t.Error("summarize reported LOCKED despite divergence")
	}

	// Agreement on everything must lock.
	verdicts, err = crossBless(c, []*Emission{mk("go", nil), mk("rust", nil)}, sum[:])
	if err != nil {
		t.Fatal(err)
	}
	if _, locked := summarize(verdicts); !locked {
		t.Error("identical emissions did not lock")
	}
}

// TestTwoImplDisagreementIsNotRoutable guards the distinction that a real
// Go-vs-Rust run exposed on 2026-07-22.
//
// §4 routes "one impl differs" to that impl and "all differ" to arch as a spec
// ambiguity. With two emissions those are the same observation, and the
// classifier originally reported such a case as ALL-DIFFER — which would have
// sent a plain impl bug to arch labelled a spec ambiguity. Two impls disagreeing
// is a real divergence and an unroutable one; it must say so.
func TestTwoImplDisagreementIsNotRoutable(t *testing.T) {
	c := buildTestCorpus(t)
	base := outcomes(t, c)
	_, sum, err := encodeCorpus(c)
	if err != nil {
		t.Fatal(err)
	}
	const id = "worked/fold/sum"
	other := make(map[string]Outcome, len(base))
	for k, v := range base {
		other[k] = v
	}
	other[id] = Outcome{Kind: OutcomeValue, Boundary: []byte{0x7f}}

	a := &Emission{Impl: "go", Engine: "e", CorpusSHA256: sum[:], Results: base}
	b := &Emission{Impl: "rust", Engine: "e", CorpusSHA256: sum[:], Results: other}

	verdicts, err := crossBless(c, []*Emission{a, b}, sum[:])
	if err != nil {
		t.Fatal(err)
	}
	for _, v := range verdicts {
		if v.id != id {
			continue
		}
		if v.kind == verdictAllDiffer {
			t.Fatal("a 1-vs-1 disagreement was routed as ALL-DIFFER — that sends an impl bug " +
				"to arch as a spec ambiguity")
		}
		if v.kind != verdictTwoWay {
			t.Fatalf("expected TWO-WAY, got %s", v.kind)
		}
		if v.outlier != "" {
			t.Errorf("TWO-WAY named an outlier (%q); two impls cannot identify a culprit", v.outlier)
		}
	}
}

// TestCrossBlessRejectsAStaleEmission: an emission built against a different
// artifact must be refused outright. Comparing it would produce agreement on
// whichever IDs happen to coincide, which is worse than no comparison.
func TestCrossBlessRejectsAStaleEmission(t *testing.T) {
	c := buildTestCorpus(t)
	_, sum, err := encodeCorpus(c)
	if err != nil {
		t.Fatal(err)
	}
	good := &Emission{Impl: "go", Engine: "e", CorpusSHA256: sum[:], Results: outcomes(t, c)}
	stale := &Emission{Impl: "rust", Engine: "e", CorpusSHA256: []byte{0xde, 0xad}, Results: good.Results}

	if _, err := crossBless(c, []*Emission{good, stale}, sum[:]); err == nil {
		t.Fatal("cross-bless accepted an emission built against a different corpus")
	}
}

// TestSkipIsNotAgreement: §3.1(2) says a skip counts as a failure. A vector one
// impl did not answer must classify INCOMPLETE, never AGREE-by-omission.
func TestSkipIsNotAgreement(t *testing.T) {
	c := buildTestCorpus(t)
	base := outcomes(t, c)
	_, sum, err := encodeCorpus(c)
	if err != nil {
		t.Fatal(err)
	}
	const dropped = "worked/filter/predicate"
	partial := make(map[string]Outcome, len(base))
	for k, v := range base {
		if k == dropped {
			continue
		}
		partial[k] = v
	}
	a := &Emission{Impl: "go", Engine: "e", CorpusSHA256: sum[:], Results: base}
	b := &Emission{Impl: "rust", Engine: "e", CorpusSHA256: sum[:], Results: partial,
		Skipped: map[string]string{dropped: "unimplemented"}}

	verdicts, err := crossBless(c, []*Emission{a, b}, sum[:])
	if err != nil {
		t.Fatal(err)
	}
	for _, v := range verdicts {
		if v.id == dropped && v.kind != verdictIncomplete {
			t.Fatalf("%s: a skipped vector classified %s, not INCOMPLETE", dropped, v.kind)
		}
	}
	if _, locked := summarize(verdicts); locked {
		t.Error("a corpus with an unanswered vector reported LOCKED")
	}
}
