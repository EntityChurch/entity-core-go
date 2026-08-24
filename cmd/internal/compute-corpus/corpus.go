package main

// The portable compute conformance corpus — the on-disk artifact shape.
//
// GUIDE-CONFORMANCE §7c.3 pins the vector CONTRACT and explicitly leaves the
// serialization to the cohort:
//
//	(IR entity, root bindings, budget) → { boundary-hash | error{code, message} }
//
// This file is that choice. Canonical CBOR, not a .diag analog — the ECF corpus
// uses .diag because its vectors are hand-authored and a human edits them; these
// vectors are generator-produced content-addressed entity graphs, so a text
// source buys nothing and a hand-edit would silently break the root hash.
//
// WHAT IS AND IS NOT IN THE ARTIFACT
//
// The corpus carries ONLY inputs — the IR closure, the root bindings, the tree
// preconditions, and the budget. It deliberately does NOT carry expected
// outcomes. §7c.5(b) is explicit that "Go is the fixture-builder, NOT the
// oracle"; baking Go's answers into the corpus would make every other impl
// validate against Go rather than against the spec, which is exactly defect S3
// (the privileged-encoder anti-pattern) in a new place. Expectations live in
// per-impl emission files and are settled by cross-bless (§7c.5(d)).
//
// PORTABILITY OF EVERY FIELD
//
//   - entities   — (type, data) pairs. Hash input is {type, data} ONLY, so any
//     impl recomputes every content hash from the artifact alone.
//   - bindings   — one canonical-CBOR map. CBOR major types carry the
//     signed/unsigned distinction that the value model turns on, so a decoder
//     reconstructs int64(-3) vs uint64(3) without an out-of-band type note.
//   - tree       — path → hash, for the vectors that need `lookup/tree`
//     preconditions (the `recurse` decomposition stores its own lambda).
//   - budget     — explicit operations/depth, never "the default": a default is
//     an impl constant, and the budget-exhausted vectors need it pinned.

import (
	"crypto/sha256"
	"fmt"

	"go.entitychurch.org/entity-core-go/core/ecf"
	"go.entitychurch.org/entity-core-go/core/entity"
	"go.entitychurch.org/entity-core-go/core/hash"

	"github.com/fxamacker/cbor/v2"
)

const (
	corpusVersion = "v1"
	// generatorVersion is bumped whenever the grammar, the PRNG, or the root
	// bindings change — §7c.4(6) requires (seed, case-count, generator-version)
	// to reproduce a failure, and a seed alone does not pin the grammar.
	generatorVersion = "1"
	// specVersion tracks the compute semantics the vectors were built against.
	specVersion = "3.20"
	implName    = "core-go"
)

// VecEntity is one IR entity in a vector's closure, in the only form the
// protocol actually hashes: {type, data}. No content_hash field — carrying it
// would let a corrupt artifact assert its own hash, and every impl must
// recompute it anyway.
type VecEntity struct {
	Type string          `cbor:"type"`
	Data cbor.RawMessage `cbor:"data"`
}

// VecBudget is the evaluation budget, always explicit (never "the default").
type VecBudget struct {
	Operations int `cbor:"operations"`
	Depth      int `cbor:"depth"`
}

// Vector is one conformance case: inputs only.
type Vector struct {
	// ID is stable and human-legible: "worked/<decomposition>[/<edge>]" or
	// "sweep/<case-index>". Cross-bless reports divergence by ID.
	ID string `cbor:"id"`
	// CaseIndex is the generator index for sweep vectors, so a failure
	// reproduces from (seed, case_index) per §7c.4(6). Absent for worked ones.
	CaseIndex int `cbor:"case_index,omitempty"`
	// Entities is the full IR closure reachable from Root, in a deterministic
	// order (see freeze): the artifact must be byte-stable across builds.
	Entities []VecEntity `cbor:"entities"`
	// Root is the content hash of the expression to evaluate.
	Root hash.Hash `cbor:"root"`
	// Bindings is a canonical-CBOR map of the free variables (the root scope).
	Bindings cbor.RawMessage `cbor:"bindings"`
	// Tree maps paths to entity hashes that MUST be resolvable via
	// compute/lookup/tree before evaluation. Empty for most vectors.
	//
	// Paths are PEER-RELATIVE (no leading slash), not absolute, and that is
	// load-bearing rather than a style choice. An absolute path is
	// `/{peer_id}/rest` — but the corpus is frozen long before anyone knows
	// which peer will run it, so a baked-in `/corpus/fn/sum` would be read as
	// peer_id "corpus" by any peer evaluating it. A bare path resolves verbatim
	// in an in-process harness (no local peer id) and is qualified to
	// `/{peer_id}/corpus/fn/sum` by a live peer, so the same frozen vector works
	// in both.
	Tree map[string]hash.Hash `cbor:"tree,omitempty"`
	// Budget is the evaluation ceiling for this vector.
	Budget VecBudget `cbor:"budget"`
	// Requires are feature tags the vector exercises ("closure",
	// "unsigned-at-use-site", "tail-recursion", ...). The guards read these to
	// prove the corpus is non-vacuous BEFORE anyone runs it, and an impl can
	// report an honest skip against a named tag instead of a bare failure.
	Requires []string `cbor:"requires,omitempty"`
	// BoundaryPath makes the boundary the content hash of the entity WRITTEN to
	// this tree path after evaluation, instead of the evaluation result. Set it on
	// the SA-9 store vectors: §2.4 requires the written error be content-hashed
	// over `code` alone, and that is a property of the STORED entity, not the eval
	// result. Reading the eval result cannot see it — over the wire an error result
	// is re-wrapped by F10 (a fresh diagnostic message), and under the default
	// error-kind reduction cross-bless keys on `code` and is blind to `message`
	// either way. Reading the stored entity directly (in-process: the location
	// index; wire: a tree GET) observes exactly the bytes §2.4 governs, so a
	// message-leaking store is a hard divergence from a code-only one. The path is
	// peer-relative like Tree (qualified to /{peer_id}/… by a live peer). If the
	// store did not write (an impl that propagates instead of materializing), the
	// path is empty and the boundary falls back to the eval result — still a
	// divergence from a writer, surfaced not masked.
	BoundaryPath string `cbor:"boundary_path,omitempty"`
}

// Corpus is the frozen artifact. Its SHA-256 is the MANIFEST hash-pin
// (§7c.5(e)) and every emission carries it, so an emission can never be
// silently compared against a corpus it was not produced from.
type Corpus struct {
	CorpusVersion    string `cbor:"corpus_version"`
	GeneratorVersion string `cbor:"generator_version"`
	// PRNG names the algorithm, not just the seed. A seed is meaningless
	// cross-impl without it — see prng.go for why this is not math/rand.
	PRNG       string `cbor:"prng"`
	Seed       uint64 `cbor:"seed"`
	SweepCases int    `cbor:"sweep_cases"`
	// Profile is "inproc" or "wire". It rides in the artifact because the two
	// are genuinely different corpora — the wire profile inlines root bindings
	// to close every expression — and an emission produced against one must
	// never be compared against the other. The SHA-pin already prevents that
	// mechanically; the field makes the reason legible.
	Profile     string   `cbor:"profile"`
	SpecVersion string   `cbor:"spec_version"`
	Vectors     []Vector `cbor:"vectors"`
}

// Outcome is one impl's answer at the AE-1 boundary for one vector.
//
// Kind is the discriminator; the workbench harness's `value:%T:<hex>` form is
// deliberately NOT reproduced here — the Go type name is not portable, and the
// canonical CBOR bytes already carry the signed/unsigned distinction it was
// standing in for (int64(5) and uint64(5) differ by major type).
type Outcome struct {
	Kind     string `cbor:"kind"` // "entity" | "value" | "error"
	Boundary []byte `cbor:"boundary,omitempty"`
	Code     string `cbor:"code,omitempty"`
	Message  string `cbor:"message,omitempty"`
}

const (
	OutcomeEntity = "entity"
	OutcomeValue  = "value"
	OutcomeError  = "error"
)

// String renders an outcome for divergence reports. Not a wire form.
func (o Outcome) String() string {
	switch o.Kind {
	case OutcomeError:
		return fmt.Sprintf("error(%s)", o.Code)
	case OutcomeEntity:
		h, err := hash.FromBytes(o.Boundary)
		if err != nil {
			return fmt.Sprintf("entity(<malformed %x>)", o.Boundary)
		}
		return "entity(" + h.String() + ")"
	case OutcomeValue:
		return fmt.Sprintf("value(%x)", o.Boundary)
	default:
		return "unknown(" + o.Kind + ")"
	}
}

// EngineRole records whether the emitting engine is the impl's reference
// evaluator or an alternate one. This exists because of §7c.4(2)'s sixth
// guard: cross-impl agreement is circular if a side silently fell back to its
// reference engine, so the role and the fallback count are part of the
// emission rather than a claim made in prose.
const (
	RoleReference = "reference"
	RoleAlternate = "alternate"
)

// Emission is one impl's run over one corpus.
type Emission struct {
	Impl        string `cbor:"impl"`
	ImplVersion string `cbor:"impl_version"`
	// GitCommit is the source revision the emission was produced at. ADR-0012:
	// a published conformance number cites `N·0F @ <oracle-commit>`, so a lock is
	// not publishable without pinning the commit each emission was run at — a
	// tree-state pin (which the first three-way lock fell back to) is not a
	// citable revision. For a wire-driven emission this is the DRIVER's commit,
	// not the peer's; the peer's revision must be recorded alongside separately.
	GitCommit string `cbor:"git_commit,omitempty"`
	// Engine names the evaluator (e.g. "stage1", "axis1"); EngineRole says
	// whether it is the reference or the engine under test.
	Engine     string `cbor:"engine"`
	EngineRole string `cbor:"engine_role"`
	// Fallbacks is how many vectors routed to the reference engine instead of
	// the named one. MUST be 0 for an alternate-engine emission to count.
	Fallbacks int `cbor:"fallbacks"`
	// CorpusSHA256 pins which artifact this emission answers.
	CorpusSHA256  []byte             `cbor:"corpus_sha256"`
	CorpusVersion string             `cbor:"corpus_version"`
	SpecVersion   string             `cbor:"spec_version"`
	Results       map[string]Outcome `cbor:"results"`
	// Skipped records vectors the impl declined, keyed by ID with a reason.
	// §3.1(2): a skip counts as a failure — it is recorded, never elided.
	Skipped map[string]string `cbor:"skipped,omitempty"`
}

// encodeCorpus serializes a corpus through the canonical encoder and returns
// the bytes plus their SHA-256 (the MANIFEST pin).
func encodeCorpus(c *Corpus) ([]byte, [32]byte, error) {
	raw, err := ecf.Encode(c)
	if err != nil {
		return nil, [32]byte{}, fmt.Errorf("encode corpus: %w", err)
	}
	return raw, sha256.Sum256(raw), nil
}

// decodeCorpus parses a corpus artifact and re-verifies every vector's root
// hash against the entities it carries.
//
// §3.1(6) is explicit: decode the artifact, not just its SHA. A SHA match only
// proves the file is the one that was pinned; it says nothing about whether the
// bytes inside are a coherent expression graph. This catches a truncated or
// hand-edited corpus at load rather than as a mystery divergence later.
func decodeCorpus(raw []byte) (*Corpus, error) {
	var c Corpus
	if err := ecf.Decode(raw, &c); err != nil {
		return nil, fmt.Errorf("decode corpus: %w", err)
	}
	if len(c.Vectors) == 0 {
		return nil, fmt.Errorf("corpus carries no vectors")
	}
	for _, v := range c.Vectors {
		if err := v.verifyClosure(); err != nil {
			return nil, fmt.Errorf("vector %s: %w", v.ID, err)
		}
	}
	return &c, nil
}

// verifyClosure recomputes every entity's content hash from (type, data) and
// checks that the root resolves within the closure. A vector whose root is not
// present is unrunnable, and one whose entities do not hash as claimed would
// make an impl's "divergence" a corpus bug.
func (v Vector) verifyClosure() error {
	if len(v.Entities) == 0 {
		return fmt.Errorf("empty entity closure")
	}
	seen := make(map[hash.Hash]bool, len(v.Entities))
	for i, ve := range v.Entities {
		ent, err := entity.NewEntity(ve.Type, ve.Data)
		if err != nil {
			return fmt.Errorf("entity %d (%s): %w", i, ve.Type, err)
		}
		if seen[ent.ContentHash] {
			return fmt.Errorf("entity %d (%s): duplicate in closure", i, ve.Type)
		}
		seen[ent.ContentHash] = true
	}
	if !seen[v.Root] {
		return fmt.Errorf("root %s not present in closure", v.Root)
	}
	for path, h := range v.Tree {
		if !seen[h] {
			return fmt.Errorf("tree precondition %q → %s not present in closure", path, h)
		}
	}
	if v.Budget.Operations <= 0 || v.Budget.Depth <= 0 {
		return fmt.Errorf("budget must be positive, got %+v", v.Budget)
	}
	return nil
}
