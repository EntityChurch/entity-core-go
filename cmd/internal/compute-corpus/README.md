# compute-corpus — the portable cross-impl compute conformance corpus

The third conformance modality. Wire ECF is enumerable golden fixtures; concurrency is behavioral
probes; **compute is differential over a combinatorial input space** — so the corpus is
generator-seeded, then frozen, and the frozen vectors are the cross-impl gate.

Authoritative guidance: **`entity-system-architecture/guides/GUIDE-CONFORMANCE.md` §7c**. Vector
contract: **`PROPOSAL-COMPUTE-LOWERING-TOOLKIT §3/§4/§5`** (the nine decompositions, the invariants
each MUST encode, and the worked-vector contract — note it is **§5**, not the "§2.3" a prior handoff
cites; §7c's own pointer to §5 is the correct one).

## What this gates

AE-1 admission (an alternate engine is conformant iff materialized-boundary-equivalent), the
lowering-toolkit vectors, W-BUDGET preemption determinism, W-HOSTING transferable compute. Before it
existed, the entire cross-impl compute-evidence base was one `compute/scope` hash-equality point plus
Go-internal differential tests — "Rust eval == Go eval" was assumed, not verified.

## Running it

```bash
go run ./cmd/internal/compute-corpus generate --out ./compute-corpus-v1.cbor
go run ./cmd/internal/compute-corpus emit     --corpus ./compute-corpus-v1.cbor --out ./emit-go.cbor
go run ./cmd/internal/compute-corpus verify   --corpus ./compute-corpus-v1.cbor --emission ./emit-go.cbor
go run ./cmd/internal/compute-corpus cross-bless --corpus ./compute-corpus-v1.cbor \
    --emission ./emit-go.cbor --emission ./emit-rust.cbor --emission ./emit-py.cbor
```

`generate` writes the artifact plus a `.MANIFEST` carrying the hash-pin and the reproducibility
triple `(seed, case-count, generator-version)`.

## Two ways an impl produces an emission

**A — its own harness (the §7c.5 shape).** Read the artifact, evaluate in-process, emit. This is what
the porting contract below describes, and it is the only route that can satisfy guard 6, because only
the impl itself can attest which engine ran.

**B — driven over the wire, with no code on its side.**

```bash
go run ./cmd/internal/compute-corpus generate --profile wire --out ./corpus-wire.cbor
go run ./cmd/internal/compute-corpus emit --corpus ./corpus-wire.cbor --out ./emit-rust.cbor \
    --peer 127.0.0.1:PORT --impl rust
```

A peer already speaks `system/compute:eval`, so core-go can drive the corpus against any conformant
peer and produce that peer's emission. Same artifact, same cross-bless. This exists because the
corpus's reason to be is that "Rust eval == Go eval" is *assumed*, and route A means no evidence until
two other teams write harness code.

What route B costs, all of it real:

- **It needs `--profile wire`.** `EXTENSION-COMPUTE §3.2` is normative that explicit eval begins from
  `scope = empty_scope()` — there is no request field carrying root bindings to a peer. The wire
  profile inlines the root bindings so every expression is closed. Let- and lambda-bound names are
  untouched, so `compute/lookup/scope`, closure capture, and the let\* ordering rule are still
  exercised; what is given up is the root-binding half of §7c.3's `(IR, root bindings, budget)` shape.
  It is therefore a **second artifact with its own SHA**, not a replacement — `emit --peer` refuses an
  `inproc` corpus rather than returning `not_found` 323 times and calling it a divergence.
- **It measures the peer's handler path**, not its evaluator in isolation: dispatch, capability
  checks, and result wrapping are in the loop. A divergence found this way is real but needs
  localizing before it is filed against an impl.
- **It cannot satisfy guard 6.** The emission records `engine: "wire:<addr>"` so this is visible in
  the artifact rather than inferable from context. Route B finds divergence; AE-1 admission needs
  route A.

Validated end-to-end against a live Go peer: 323/323 answered, and cross-blessing the wire-driven
emission against the in-process one locks byte-identically — including the tree-precondition vectors
and the budget-edge vector.

## The discipline, in three rules

1. **Go is the fixture-builder, not the oracle.** `generate` freezes **inputs only** — no expected
   answers. Baking Go's outputs into the artifact would make every other impl validate against Go
   rather than against the spec (defect S3, the privileged-encoder anti-pattern). Expectations are
   whatever the impls agree on; the spec arbitrates.
2. **Lock only when byte-identical, and never vote.** `cross-bless` classifies — one impl differs =
   its bug; all differ = spec ambiguity, the round's work product — and refuses to pick a majority
   answer. A cohort agreeing is cohort-consistent, not correct.
3. **The guards are gates, not decoration.** A green run that proves nothing is the failure mode
   these exist for. `verify` fails the run, not warns.

## Intra-Go green is not cross-impl evidence

Running `cross-bless` over two core-go emissions reports LOCKED. That is a **pipeline smoke test**
and nothing more. The corpus's claim — Go == Rust == Py at the boundary — is unproven until emissions
from other impls exist. State the two separately whenever this is reported.

## Porting contract — what a second impl must implement

Everything below is derivable from the artifact alone; there is no Go in the wire format.

**1. Read the corpus.** Canonical CBOR. `Corpus{corpus_version, generator_version, prng, seed,
sweep_cases, spec_version, vectors[]}`, and each vector:

| Field | Meaning |
|---|---|
| `id` | stable identifier; cross-bless reports by it |
| `case_index` | generator index (sweep only) — a failure reproduces from `(seed, case_index)` |
| `entities[]` | the IR closure as `{type, data}` pairs. Hash input is `{type, data}` ONLY, so every content hash recomputes from the artifact |
| `root` | 33-byte content hash of the expression to evaluate |
| `bindings` | canonical-CBOR map of the root scope. CBOR major types carry the signed/unsigned distinction — decode without an out-of-band type note |
| `tree` | absolute path → hash; these MUST be resolvable via `compute/lookup/tree` before evaluation |
| `budget` | `{operations, depth}` — always explicit, never "the default" |
| `requires[]` | feature tags; also what the guards read to prove non-vacuity |

**2. Evaluate and reduce to the boundary.** Load every entity into a content store, install the tree
preconditions, bind the root scope, evaluate the root under the vector's budget. Then reduce:

> **The `worked/error/store-materializes-code-only-*` vectors need a `system/tree:put` dispatcher AND
> a tree GET.** They call the SA-9 `store` builtin, which dispatches its write via `system/tree:put`
> (wire a minimal in-process handler — the Go harness's `corpusTreePut` is the reference), and they
> carry `Vector.BoundaryPath`: the boundary is the content hash of the entity WRITTEN to that path,
> read out of band (in-process: the location index; wire: a `TreeGet`), **not the eval result.**
>
> That indirection is the whole point. §2.4 requires the *written* error be content-hashed over `code`
> alone, and that is a property of the stored bytes — invisible in the eval result, which reduces a
> `compute/error` to error-kind (keyed on `code`, blind to `message`) and which F10 re-wraps with a
> fresh message over the wire. Reading the stored entity makes a non-code-only or non-materializing
> store a hard divergence. The 2026-08-16 three-way proved it: go wrote the code-only entity; rust and
> py wrote nothing (they propagate the error), and the vector went RED (`ONE-DIFFERS`) — where the
> older result-reading form had reported LOCKED because the codes agreed.

| Result | Emit |
|---|---|
| entity-kind | `{kind: "entity", boundary: <33-byte content hash, algorithm byte included>}` |
| value-kind | `{kind: "value", boundary: <canonical CBOR of the value>}` |
| error | `{kind: "error", code, message}` |

Reduce through your own `capture_scope` equivalent rather than re-deriving the materialization — the
reference's own path is what makes the boundary authoritative instead of a second opinion.

**Do not emit a language type name** alongside the value bytes. The Go harness this was ported from
renders `value:%T:<hex>`; that field is not portable and is redundant, since the canonical bytes
already carry the distinction it stood in for.

**3. Emit.** `Emission{impl, impl_version, git_commit, engine, engine_role, fallbacks, corpus_sha256,
corpus_version, spec_version, results{id → outcome}, skipped{id → reason}}`. `corpus_sha256` is the
SHA-256 of the artifact bytes and is checked — an emission cannot be compared against a corpus it was
not produced from. A vector your impl declines goes in `skipped` with a reason, never omitted: a skip
counts as a failure. **`git_commit` stamps the source revision the emission ran at (ADR-0012):** a
published lock cites `N·0F @ <oracle-commit>`, so a lock over unstamped emissions is not publishable —
`cross-bless` prints each emission's `impl/engine @ commit` and flags any that is `UNSTAMPED`. For a
wire-driven emission the stamp is the *driver's* commit; record the peer's revision separately.

**4. (Optional) Run the generator.** §7c.4(1) asks that each impl be able to run the seeded generator,
not merely replay the frozen output. The PRNG is **SplitMix64**, specified in `prng.go` — six lines of
wrapping 64-bit arithmetic, chosen precisely because Go's `math/rand` is not reproducible outside Go.
`intn(n)` is `next() % n`, plain modulo, no rejection loop.

## The six guards

Five are ported verbatim from the workbench harness; the sixth is the cross-impl addition §7c.4(2)
names. All are gates.

| Guard | Why |
|---|---|
| ≥25% non-error outcomes | else the corpus is mostly agreeing about errors — vacuous |
| ≥1 error outcome | error-as-value propagation is part of the contract |
| ≥1 closure exercised | else `map`/`filter`/`fold` never ran and the live-frame path went untested |
| 0 fallbacks | a fallback compares an engine to itself — circular |
| ≥3 distinct error codes | one code repeated 140 times is coverage on paper only |
| engine role == alternate | **cross-impl addition**: an engine that fell back to its reference makes the agreement circular too. Enforced only under `--require-alternate` (AE-1 admission runs); core-go's Stage-1 emission legitimately declares `reference` |

The closure guard is restated from the original: the workbench reads it off engine instrumentation
(`Stats().Closures`), which core-go's Stage-1 does not have. Here it is "at least one vector tagged
`closure` completed without error" — weaker, because it does not count closures; stronger in one
respect, because every impl can check it from the artifact with no instrumentation to port.

## Known limits — read before reporting results

- **The sweep's error distribution is skewed.** Of 138 error outcomes, 108 are `index_out_of_range`.
  That is inherited from the ported grammar (indices are drawn from [-10,10] against arrays of length
  0–4), and the guards pass on distinctness, not balance. Six codes appear; three of them appear once
  or twice. Do not read "6 distinct codes" as even coverage.
- **Wire-driven emissions are not AE-1 evidence.** See route B above — they exercise the handler path
  and cannot attest which engine ran.
- **`params.budget` had to be implemented first.** §5.2 makes `request_budget = params.budget or
  infinity` normative, and core-go silently ignored it until 2026-07-22 — invisible in ordinary use,
  because ignoring a voluntary self-restriction never denies anything, but it meant every wire-driven
  vector ran at the peer default and the budget-edge vectors asserted nothing. Another impl driven
  over the wire will show the same symptom if it has the same gap: the budget vector returns a value
  where the in-process run returns `budget_exhausted`. Check that before filing it as a semantic
  divergence.
- **Two spec questions, both RESOLVED 2026-07-23** (arch, `ARCH-RESPONSE-COMPUTE-CORPUS-FIRST-RUN`):
  a **materialized `compute/error` is content-hashed over `code` alone** (§2.4), so comparing `code`
  strictly IS the materialized-boundary comparison — not a deviation from §7c.3 but its resolution;
  and the **observable budget charges `evaluate()` steps only** (§4.2), making `budget_exhausted` a
  deterministic, gated outcome with budget-edge vectors kept in. The corpus already compared `code`
  strictly, so no gate change was needed; Go absorbed the materialization side (see
  `docs/validation/reports/2026-07-23-arch-rulings-absorbed.md`). The two spec-issue docs are marked
  RESOLVED with pointers to the ruling.

## Where the artifact lands

§7c.5 puts the frozen corpus and MANIFEST in
`entity-core-protocol/specs/test-vectors/compute-conformance/`, vendored into keystone. That repo is
operator-coordinated and not writable from here — the expected split, per §7c.5's own note that "arch
guides; the impl work lands in the cohort repos." Build and pin here; route the artifact.

## Frozen artifact + the C-8 drift guard (2026-08-20)

C-8 was filed because the corpus was *regenerable but never frozen*: `TestCorpusIsReproducible` only
proves same-process determinism (two builds in one run agree — it cannot see a `gen.go` change that
shifts both), and the SHA that *would* catch a shift lived in a spec header, not beside the bytes.
Nothing noticed the corpus had already drifted **330 → 343** since the 2026-07-23 cross-bless.

Now pinned:

- **Frozen artifact:** `testdata/compute-corpus-v1.cbor` (+ `.MANIFEST`) — regenerate with
  `generate --out testdata/compute-corpus-v1.cbor`.
- **Mechanical guard:** `frozen_test.go` `TestFrozenCorpusSHAPinned` — regeneration MUST hash to the
  pinned `goldenCorpusSHA256`, and the committed bytes MUST match it. A generator change that shifts
  the corpus now fails a test, deliberately; re-freeze + re-pin + re-cross-bless is the required
  ritual, not a silent regeneration.

**Honest scope of this freeze — read before treating it as complete:**

- Pinned state: **352 vectors, SHA `7d09f108…`, `spec_version 3.20`.**
- **The v3.25/v3.26 corner vectors CV-1…CV-6 (C-5) are FULLY seeded:** **all 9 arms** are in the
  corpus (`worked/v325-corner/*`) and verified against arch's §7c.6 outcomes (`TestV325CornerOutcomes`).
  **CV-4a and CV-5 joined** once COMPUTE v3.26 ruled the contained-error boundary (**spec-issue
  2026-08-20-f**, RESOLVED) and go's `materialize()` gained the array-element carve-out: a contained
  `compute/error` now materializes code-only in the output array. `TestV325ContainedErrorBoundaryIsCodeOnly`
  is the positive teeth (message-independence) that replaced the old blocked-pin.
- The broader **sweep** still does not cover the v3.24/v3.25 primitives beyond these corners, and
  `spec_version` is still `3.20` — extending the sweep re-freezes under the guard.
- The last **three-way cross-bless** was at the older 330-vector corpus; a fresh three-way bless at
  352 is gated on `entity-core-rust` / `entity-core-py` building v3.26 (C-6) — and the two newly-seeded
  CV-4a/CV-5 have **never** been three-way'd. The frozen artifact is **inputs only** — freezing it does
  not bless outcomes.
- **Vendor** into `entity-core-protocol/specs/test-vectors/compute-conformance/` routes out (boundary
  repo); the frozen bytes + MANIFEST here are what gets vendored.
