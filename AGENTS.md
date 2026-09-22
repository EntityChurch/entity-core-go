# entity-core-go

Read **AGENTS-STANDARD.md** first (ecosystem conventions). This file adds entity-core-go specifics.

## Overview

Go implementation of the Entity Core Protocol v7 — the third ground-up reference implementation (after Python and Rust), and the SDK prototype: **Go leads on new features**, cross-impl convergence is downstream feedback, not a gate.

**Our addressable name is `entity-core-go`** (this repo's directory name) — that is what a routing
packet's `To:` / `cc:` / `From:` names us as. Packets we send live in `docs/outbox/`; dated working
memory in `docs/status/`; durable engineering memory in `docs/agents/memory/` (entered through its
`INDEX.md`).

## How we work here — tier **CORE**

This repo runs the entity-OS methodology at the **Core** tier — the framework is
`METHODOLOGY.md` (injected, identical everywhere; read it once). Conformance gates the wire
here. It does **not** catch process drift, stale build-state claims, unaccounted accumulation,
or a discipline quietly eaten by a competing legitimate pressure. Those need the ratchet.

**This repo diagnosed the reason the tier exists.** `docs/reviews/2026-08-12-discipline-audit-are-we-still-following-our-own-rules.md`
found the rules living in a sibling's guide, an ADR in a third repo, and this file — and named
the consequence: *"An audit should not have to assemble its own standard first. That is
plausibly the root cause of drift being invisible."* It also found the mechanism, which is the
part worth carrying: *"A legitimate pressure ate a discipline, and nothing in the process
noticed."* Reducing cross-repo round trips is a real constraint; it cannibalised *spec
arbitrates ambiguity, do not vote* because both point at the same act.

What binds today:

- **Universal disciplines D1–D12** (`METHODOLOGY.md` §4) — apply as written; nothing to re-derive.
- **The review questions** (§6) — run on every diff.
- **The Audit Doctrine A0–A12** (§7.2) — open it for *"Y is broken"* or *"something feels
  wrong,"* including when the thing that feels wrong is our own process. **A1 is the prime:
  trace a value before you theorize.**
- **The ratchet** — every audit ends by syncing what it taught into this file, same session.
  **If it didn't land here, it didn't land.**
- **The promotion ladder** (§3) — bit us once → an anti-pattern entry; a second time in a
  different shape → a ratified discipline. Candidates are applied, not yet claimed to generalize.
- **The divergence rule, as a standing discipline.** When a cross-impl divergence is measured,
  the response is chosen from `GUIDE-CONFORMANCE` §4's table **before** a fix is written, and
  the row is named in the commit. **A fix whose justification includes a count of
  implementations is the smell.** All-three-differ = spec ambiguity, tighten the spec; two-and-two
  = spec arbitrates, do not vote.

> Worked examples — the routed-recommendation smell, and why a close-out that only re-applied
> existing disciplines does not owe a new rule — are in
> `docs/agents/memory/THE-RATCHET-AND-DIVERGENCE-RULE.md`.

**Owed** (from the 2026-08-12 audit, promoted here so it stops being invisible): a standing
`DISCIPLINE-*` doc assembling this repo's own rules with an anti-pattern catalog; G-7, the
re-verification of the 20 build-state assertions in `cmd/peer-manager` flag help pinned to 18
stale sibling commits; and the five domains its §5 named as unaudited (§2.4a negative halves ·
§5.2/§5.2a label correctness · the ~25 dated ROUTING/HANDOFF docs for the same stale-claim
defect class applied to prose · whether the volume of cross-repo routing is itself a process
defect).

## Setup / environment

- **Go**, `go.work` multi-module workspace — three modules, all under `go.entitychurch.org/entity-core-go/`: **`core`** (protocol library), **`ext`** (system extensions), **`cmd`** (CLIs / validation / interop). Import paths always carry the module prefix, e.g. `go.entitychurch.org/entity-core-go/core/hash`.
- **External deps (two):** `github.com/fxamacker/cbor/v2` (CBOR / ECF — `CoreDetEncOptions()`), `github.com/mr-tron/base58` (PeerID encoding). Dep gate: stable + predictable + 30+ days old, and prefer the library that drops in **without an adapter** — a "small adapter layer" is a sign of shape mismatch. When a handoff already names a lean pick that clears the bar, take it; don't re-litigate an obvious call.
- **Spec is upstream, and the V8 split moved it — there are now TWO spec repos, both siblings:**
  - **`../entity-core-protocol/specs/`** — the core protocol floor: `ENTITY-CORE-PROTOCOL.md`, `ENTITY-CBOR-ENCODING.md`, `ENTITY-NATIVE-TYPE-SYSTEM.md`. No `EXTENSION-*` lives here.
  - **`../entity-system-architecture/`** — everything else: `specs/extensions/EXTENSION-*.md` (all 25, incl. `EXTENSION-CONTINUATION.md`, `EXTENSION-NETWORK.md`), plus **`docs/proposals/PROPOSAL-*.md`** (where handed proposals actually land), `docs/status/` (arch handoffs, `WORKSTREAMS.md`), `docs/research/`.

  **`entity-core-architecture` is the pre-split repo — STALE. Do not read specs or proposals from it.** It still exists on disk and still contains an old `v7.0-core-revision/` tree, so a search there returns plausible-looking but outdated hits, and a search for a *new* proposal returns nothing at all. That cost a full cycle on 2026-07-19: a rebuilt `PROPOSAL-CONTINUATION-BOUNDS-PROPAGATION` was reported "not on disk" because only the dead repo was searched. **If a handed doc seems missing, you are in the wrong repo — check `../entity-system-architecture/docs/proposals/` before concluding anything is absent.** **A second manifestation, 2026-08-20: a CODE PATH pointing at the dead repo doesn't error — it silently degrades.** `cmd/internal/validate/profile_v9_drift_test.go`'s core-profile drift gate `Skipf`s when its spec path is missing, and its path pointed at `../entity-core-architecture/...ENTITY-CORE-PROTOCOL-V7.md` (never present since the split), so **the guard silently skipped for its entire existence — a drift gate that never once fired.** Repointed to `../entity-core-protocol/specs/ENTITY-CORE-PROTOCOL.md` (where §9.0/§9.5 live) at `<this commit>` and it now PASSes (fires). The rule this earns: **a Skip-on-missing-file guard is only a guard if its path is live — grep the tree for `entity-core-architecture` in any non-comment path (test fixtures, tool inputs, spec-derivation guards), because a dead path turns a green gate vacuous and no failing run ever reveals it.** (Same STALE-repo trap, new surface: a search miss vs a silent guard.)
- Other impls: `../entity-core-py/`, `../entity-core-rust/` (note: **`entity-core-rust`, never `entity-core-rs`**). All siblings sit beside this repo in the same parent dir — read from disk, don't interrogate.

## Build & test

```bash
go test ./core/... ./ext/... ./cmd/...        # full suite (all three modules)
go vet  ./core/... ./ext/... ./cmd/...         # vet all packages
go test -race ./core/... ./ext/... ./cmd/...   # race detector
go test -run TestName ./core/ecf/...           # single / targeted (stdlib testing, table-driven, no assertion lib)
go build ./...                                  # verify compilation
```

**Peers & validation — use the purpose-built tooling, the documented way.** No `go install`, no custom env, no one-off compiles, no backgrounding `entity-peer` with `&`, no building to `/tmp`. If a peer seems stale, stop and restart it — `peer-manager` rebuilds fresh on start.

> **You own your peer lifecycle. NEVER ask the operator to kill a process (earned 2026-09-09 — the operator's standing instruction, after repeated `pkill` asks).** Every peer you start goes through `peer-manager` (which tracks it), and you end a session by tearing your own down: `go run ./cmd/peer-manager stop --all`. The golden rule is *you do not kill processes* — that means you do not `pkill`/`kill` AND you do not push the kill onto the operator; the two are the same failure wearing different clothes. **A stray raw peer from another session is a PORT COLLISION to route around, not a kill to request:** it is not `peer-manager`-managed (so `stop --all` won't touch it, and that is correct — it is not yours), so run on free ports (`POLL_PORT=<free> PI_PORT=<free>`, `validate-complete.sh` already pre-flights both and aborts exit 2 with the free-port re-run line). Asking the operator to `pkill` a container/peer so your ports are clear is banned; pick free ports instead. If a genuinely un-routable-around collision exists, say so once and move on — do not block the work on it and do not hand him a kill command.

```bash
go run ./cmd/peer-manager start --name p1 --type go|python|rust --debug   # ALWAYS --debug
go run ./cmd/peer-manager list | stop --all                              # (Go = host build; Rust/Python via podman)
go run ./cmd/validate-peer -addr host:port [-identity NAME] [-category NAME] [-failures-only] [-exclude c1,c2] [-json] [-verbose]
go run ./cmd/validate-peer -peers h1:p,h2:p -identity NAME                # multi-peer convergence
go run ./cmd/validate-peer -list-categories                              # live ~60-category set (from validate.AllCategories())
./scripts/validate-peers.sh [python]                                     # scripted (SAVE=1 to save JSON)
TYPES=go,rust,python ./scripts/test-cross-peer.sh                        # convergence test
```

- `--profile core` scores the **16** core-profile categories (V7 §9.0); `--profile full` (default) runs all. It read **14** until 2026-08-12 — stale since v7.75 folded `concurrency` and `resource_bounds` into §9.0. Don't hand-count it: `coreProfileCategories` (`cmd/internal/validate/profile.go`) is the set, and `TestCoreProfileCategoriesMatchSpec` re-derives it from the spec text.
- **A bare `validate-peer` run is NOT the release gate — surface-gated categories FAIL as peer-POSTURE artifacts, not defects (learned 2026-08-18, cost a chunk of a session).** `registry_issuer` returns `501 unsupported_operation` and `serving_mode` returns `404` against a peer started with a plain `peer-manager start`, because those categories require the peer to be started IN a posture (an armed issuer policy; a converged closure/namespace serving root). The release gate is `scripts/validate-complete.sh`, which starts the peer with every surface armed and scores each posture-gated category in its OWN pass (registry_issuer 31/31 in pass 3 as of 2bd2380 — the v1.11 TTL-ceiling vectors added three, serving_mode 55/55 in pass 2). **Before routing a raw-run FAIL as a sibling's — or our own — conformance defect, classify it against peer posture: a category that needs a startup flag the bare run didn't pass is an unwired surface, and its FAIL/501/404 is the artifact of that, provable by re-running under `validate-complete.sh` (or a targeted repro with a settle).** Same family as ADR-0012 green≠correct, inverted: red≠defect when the harness never armed the surface. (I nearly filed go's own `registry_issuer` 501s and `serving_mode` 404s as regressions; both were posture/timing, the peer was conformant.)
- **Diagnostics first** (`docs/architecture/guides/USING-DIAGNOSTICS.md`): when something fails, reach for `validate-peer -category $CAT -verbose 2>trace.log` + the peers' `~/.entity/logs/{name}.log` **before** reading code or writing analysis. Wire evidence is upstream of theory. Never `-verbose` the full suite to a TTY (~130 MB) — always narrow with `-category` first. For in-process Go work, use `peer.WithDispatchHook` / `WithWireHook` / `WithBindingHook` for tap observability without rebuild churn. (Negative-path tests like `security`/`multisig.escalation_*` legitimately emit 403s in the responder log — map `request_id` → test name.)
- **Never ad-hoc-filter validate-peer output.** Use `-failures-only`, `-exclude`, `-category`, `-json` — never a throwaway `python3 -c` / shell script to tally or "confirm" the tool's own output. The summary table already gives per-category P/W/F counts; to compare peers, run it N times and read the tables. (Corrected repeatedly — don't reach for `json.load` to re-verify what `-failures-only` already shows.)

> **Running the gate to a true exit 0, and authoring wire/oracle checks that discriminate** —
> reading the gate's real exit (a pipe masks it), pass-0b baseline drift, the `POLL_PORT`/`PI_PORT`
> collisions, `make test-starved`, carry-the-teeth, and the rest of the hard-won check-authoring
> lore — are in `docs/agents/memory/CONFORMANCE-GATE-AND-ORACLE-AUTHORING.md`.

## Code style & conventions

- Idiomatic Go: `sync.RWMutex` + goroutines; sentinel errors + `errors.Is/As`; functional options (`PeerOption`) for builders; `context.Context` on every I/O op; small provider-defined interfaces (`ContentStore`, `LocationIndex`, `Handler`).
- **No backward-compat shims.** Pre-1.0 takes clean breaks: remove conventions not in the current spec; convert removed-convention asserts into negative/invariant tests rather than leaving them green.

## Project structure

- **`core/`** — protocol library; **13 packages in a strict DAG** (no import cycles): `errors → ecf → hash → entity, crypto, store, types, wire → capability → handler → protocol, tree → peer`. **A package may only import packages to its left.** (`ls core/` shows 14 dirs — the fourteenth is `internal/testutil`, a test helper outside the DAG. This line said "14 packages" until 2026-08-12 while drawing a 13-package chain beside it.)
- **`ext/`** — system extensions, each depending only on `core`. **28 packages** — `ls ext/` is the source of truth, not this list, but the set is large enough that "is there an `ext/X`?" should be answered by looking, never from memory:
  `attestation`, `capability`, `clock`, `compute`, `conformance`, `content`, `continuation`, `discovery`, `encryption`, `handlers`, `history`, `httplive`, `identity`, `inbox`, `localfiles`, `network`, `publishedroot`, `query`, `quorum`, `registry`, `relay`, `revision`, `role`, `signaling`, `storagesubstitutehttp`, `storagesubstitutesources`, `subscription`, `type` (+ `type/constraint`).
  > This line read `clock, inbox, continuation, subscription, revision, role, type, localfiles` until 2026-08-11 — **eight of the twenty-eight.** It understated our own tree by twenty packages, including `identity`, and is exactly the shape that produces a confident false negative about what this repo has built. Re-check it when adding a package.
- **`cmd/`** — CLIs / validation / interop (full inventory in `cmd/README.md`): `entity-peer`, `validate-peer`, `peer-manager`, `entity-sync`, `probe-peer`, `compare-types`, plus `cmd/internal/` (`validate`, `interop`, `config` — not importable outside `cmd`).
- **`docs/`** — `architecture/` (specs, guides), `agents/memory/` (durable engineering memory), `validation/` (conformance reports, spec-issues), `reviews/`, `status/` (dated snapshots + trackers), `outbox/` (routing packets we have sent).
- **Module direction: `core ← ext ← cmd`.** Core never imports ext or cmd.

## Versioning — our number is ours ([ADR-0002])

**Canonical statement + the reasoning: `CHANGELOG.md` §Versioning.** Enforced by
`cmd/internal/hygiene/version_test.go`. The short form:

- **`0.y.z` is this repo's own 3-field SemVer**, forward-only from the published
  `v0.8.0`. **`v7.NN` is the protocol revision we implement** and rides out-of-band.
  **`N · 0F · 0S · 0W @ <commit>`** is what we measured. Three numbers, three jobs —
  ADR-0002 separated them on purpose, and conflating them is the failure it names.
- **Never adopt a sibling's release number.** `entity-core-protocol`'s `0.8.x` is the
  *spec repo's* version. The fleet shares a cut **date**, not a **number**, and the
  numbers are expected to diverge. This is not theoretical: on 2026-08-23 a
  coordination pass wrote `## [0.8.2]` — the protocol's number — into our CHANGELOG,
  and nothing in the tree contradicted it because nothing in the tree had ever said
  what our number was. **A convention that is not written down gets decided by
  whoever asks last.**
- **A cut is ONE edit across every declaration site** — the CHANGELOG heading,
  `ext/go.mod`, `cmd/go.mod`, README §Module paths. The trap is go-specific and
  silent: a sibling-path `replace` hides a stale `require` from *us* and from nobody
  else, because a consumer resolving `.../cmd@vX` gets the requires **without** the
  replaces. A `cmd` cut that still requires the previous `core` publishes a build
  reproducible only inside this workspace. `TestModuleRequiresMatchTheLatestRelease`
  is the gate; it goes RED the moment a release heading lands unaccompanied.
- **The next cut is `0.9.0`** (breaking pre-1.0 changes → MINOR: the §5.4 matcher, the
  `assoc`/`fold` corner rulings, the widened default self-grant, `ext/` 8 → 28).

## Citations on the PUBLISHED surface: name the finding, not the hash

Published history is re-authored at the release boundary, so an internal `dev` SHA in a file
that ships resolves to nothing for a public reader; a sibling's SHA is worse. **In anything that
ships, cite the SYMBOL and the finding, not a `dev` commit.** A *receipt* SHA (recording the
state a claim was verified against) is required by ADR-0012 and stays — mark it so the next
sweep does not "fix" it. The pointer-vs-receipt distinction and the worked case:
`docs/agents/memory/PUBLISHED-SURFACE-CITATIONS.md`.

## Boundaries — do NOT modify

- **Cross-repo git:** git in `entity-core-go` is in scope — commit/push freely, no per-commit asking (don't force-push or rewrite published history). **Never run git in `entity-core-py`, `entity-core-rust`, `entity-core-protocol`, or `entity-system-architecture`** — those are coordinated through the operator.
- **Spec is the upstream source of truth.** Don't edit `../entity-core-protocol/...` or `../entity-system-architecture/...` from here, and don't write implementation reviews/reports there — those go in `entity-core-go/docs/`. A handed `PROPOSAL-*.md` is **already merged** on the arch side: do the Go impl, don't ask whether to also update the spec or whether to proceed. Spec ambiguities and corrections **to** a proposal go in `docs/validation/spec-issues/` here, and get routed.
- **`EXTENSION-DURABILITY`** is **exploratory / optional / not actively developed** — implemented only as a reference; absence of the surface is conformant; no deployment depends on it (the `durability` validation category reflects this).

## Protocol / interop invariants agents repeatedly get wrong

These broke Python/Rust interop before. Treat them as load-bearing — a regression here is a silent hash mismatch, not a test you'll notice:

- **Hash wire format = a 33-byte CBOR byte string** (`algorithm || digest`), **NOT a CBOR map.** The `Hash` type carries custom CBOR marshal/unmarshal. In-memory it's `Algorithm byte` + `Digest [32]byte` (comparable → usable as a map key); the algorithm byte stays with the hash everywhere, validated once on receipt.
- **Entity `data` stays `cbor.RawMessage`.** Never decode it into a Go map and re-encode — the roundtrip loses byte fidelity → hash mismatch. Byte fidelity is the whole point.
- **ECF must use `CoreDetEncOptions()`.** Any non-deterministic CBOR output breaks hashes.
- **Hash input is `{type, data}` ONLY** — never URI, never content_hash.
- **All paths are absolute, `/{peer_id}/rest`.** Detection is `HasPrefix("/")` (absolute → pass through), not a heuristic; qualify peer-relative paths via `QualifyPath`, and `CleanPath` after any prefix concatenation. **Build URIs with `entity.PathToURI()`** (strips the leading `/` to avoid triple-slash). Reserved `./` / `../` / bare `*/rest` are rejected; there is no `self` token. Path bugs here are coding-discipline failures, not spec gaps — don't file a spec ambiguity for a self-inflicted one.
- **Invariant-pointer paths use 66-char hex with the format byte included** (`00…` for ECFv1-SHA-256 — lowercase hex, format code included; ENTITY-CORE-PROTOCOL "Hex encoding convention" under the invariant-pointer pattern, **normative for chain-participating capabilities** — a cap that travels in a transported/re-verified authority chain MUST bind its signature at the invariant-pointer path or it's untransportable cross-peer), NOT the 64-char digest-only form — every invariant-pointer path (signature / namespace / descriptor) MUST go through `h.Bytes()`, not `EffectiveDigest()`. Watch the trap: if Go's writer and reader share the same wrong form, Go-on-Go PASSes deceptively — the **cross-impl FAIL is the true signal**, so before routing a path-divergence as a sibling's bug, grep Go's own `Bytes()`/`EffectiveDigest()` uses for internal consistency.
- **§4.4 `default_connection_grants` are load-bearing.** When a handler is advertised in the default grants and the spec says peers "depend on" it, the disposition is **implement the handler** — never drop the advertised grant. Spec is contract, not aspiration.
- **An entity resolved from a wire-supplied `included` map BY HASH for an authority decision MUST have its map key bound to its recomputed content hash at the trust boundary** — self-consistency (`Validate`) is NOT that binding, and skipping it is a capability/identity FORGERY. Bind at the boundary (`entity.VerifyIncludedKeyBinding`: each entry self-consistent AND `key == ContentHash`), not per-call-site. The attack, the sites, and the teeth: `docs/agents/memory/CAPABILITY-AUTHORIZATION.md`.
- **A presented/delegated capability’s "granter = X" test is on the chain ROOT granter — enforce it via `VerifyChain(cap, included, X)`, never a leaf-granter equality check** (a re-attenuated credential’s leaf granter is the delegator, not the minter). The confused-deputy oracle class (PD-2 E1/E3/F70): `docs/agents/memory/CAPABILITY-AUTHORIZATION.md`.

> **The lessons behind these invariants** — the DR-3 raw-message blindness, the byte-identity
> decisions, the `included`-map key-binding forgery, the shared-matcher and sentinel traps, and
> the `compute/error` two-form rule — live in `docs/agents/memory/`
> (`PROTOCOL-WIRE-INVARIANTS.md`, `CAPABILITY-AUTHORIZATION.md`, `COMPUTE-ERROR-SEMANTICS.md`).

### Posture on protocol work (Go leads)

- **A PROPOSAL is the floor for implementation; a FOLD is not — and "implement against the landed spec, wait for the fold" is a leak, not the method.** We are the trailblazers. We implement from a landed proposal or a draft and do **not** wait for arch to fold it into the core spec. Implementing is *how* a proposal gets validated — the wire feedback is what lets arch fold **once**, instead of the merge→amend→re-merge churn that happens when a spec is folded before anyone has built against it. How arch knows what to fold is that we built it first. The bar is: (1) there is a proposal/draft behind the change — do not invent semantics from nothing; (2) the reading has **low degrees of freedom** and the impl cohort basically agrees. Clear the bar → implement now, hand arch the **result** (and the feedback to clean up the fold), do not ask a question. A **genuine** ambiguity — the analysis is open, the cohort splits, a value judgment is in play — is the exception you route (`docs/validation/spec-issues/`), while still implementing the unambiguous rest. This kept re-appearing as "implement against the landed spec, not in-flight proposals" in the shared `AGENTS-STANDARD.md`; that line was corrected in this repo's copy on 2026-09-04 (operator ruling) to "implement against a landed proposal or draft; you do not wait for the fold." **Owed:** the same edit to meta's master + a fleet re-inject (coordinate with DevOps at the next overlay reset) — until then the corrected text holds only here. Never re-derive the old gate.
- **Defer the GATE, never the IMPLEMENTATION.** The wire-conformance-check-deferral discipline (a check must not ride an unruled / cross-impl-divergent discriminator) is about not shipping a *conformance gate* that encodes a contested reading — it is **not** license to withhold the *behavior*. Build the behavior from the proposal now; hold only the specific gate whose PASS/FAIL turns on a genuinely open semantic, and while it is held, cite the **proposal** (not a not-yet-folded or colliding §number) at the impl site.
- **Don't defer on "implementation-defined" or "Rust/Python don't have it yet."** We are the impl team — implementation-defined means *we* define it; multi-Go-peer validation is real validation; cross-impl is downstream feedback.
- **Don't gate a merged spec on "hot path / blast radius."** The hot path is the system. Make the change additive (opt-in, nil-default) so there's no blast radius to agonize over, then implement it. Reserve questions for genuine value judgments; for a real **spec ambiguity**, write it up under `docs/validation/spec-issues/` and keep implementing the unambiguous parts.
- **On a fresh probe that FAILs one cohort sibling on a wire-shape detail:** check whether adjacent categories already tolerate that shape (reuse their extractor, e.g. `extractStatusAndCode`) before calling it a peer bug — a too-strict probe FAILs a tolerated divergence. Flag the divergence in writing; don't gate the cycle on it. (This is *not* "permissive forever," and never relabel a real FAIL "pre-existing" without bisecting.)

## Verify build state before you assert it — READ THE LIVE WORKTREE

Any claim about what another repo *has built* — a flag it honors, a surface it lacks, a seam that
is unbuilt — is a **build-state claim**, and it decays the moment that repo commits. Before making
one:

- **Open the tree.** `git status` + HEAD + **read the actual source**. A report, a handoff, or
  `git log` alone is not sufficient; run `git log --since` on every sibling the claim touches.
- **Cite `(repo, commit, date)` at the point of the claim**, not in a preamble.
- **Never carry a dated measurement across a commit change.** If the target moved, re-measure or
  re-pin — a number is only true of the commit it was taken at (ADR-0012).
- **A peer's correction outranks our inference, immediately.** They can read their own tree.

**The shape, so it is recognizable:** a stale build-state claim is always *plausible* — it was
true when written and reads fine forever after. Review does not catch it; only opening the tree
does. It has been caught four times, every time by a peer, never by us re-reading our own text.

The accumulated instances of this class — build-state staleness, the sibling-negative miss,
"filed not yours", the contradiction and over-broad-spec-text rules, the routing-and-census
discipline — are in `docs/agents/memory/SPEC-READING-AND-CROSS-IMPL-ROUTING.md`.

## Cross-impl validation deliverable

When validating Python/Rust against a spec change, the deliverable is a **written per-peer report under `docs/validation/reports/`** (dated filename, matching prior reports: headline pass/partial/blocked, category table, each gap with spec requirement + probed request shape + peer response + why it matters + suggested fix/test, repro steps) — not chat output that evaporates. Run the validator, report what you observed, and stop: don't dig through the sibling's git history or internals to root-cause — that's a separate job.

## Memory — what this repo has learned, by topic

The hard-won lessons that used to live in this file — every "earned/ratified/candidate" narrative
behind the terse rules above — now live under **`docs/agents/memory/`, entered through its
`INDEX.md`**. They are durable and published; findable **by symptom**. Load one by trigger, never
all at once:

- **`CONFORMANCE-GATE-AND-ORACLE-AUTHORING.md`** — running `validate-complete.sh` to a true exit 0; writing wire/oracle checks that discriminate.
- **`PROTOCOL-WIRE-INVARIANTS.md`** — receive-boundary / hash / ECF / dispatch traps that fail silently.
- **`CAPABILITY-AUTHORIZATION.md`** — grants, matchers, exclude semantics, presented authority (PD-2).
- **`COMPUTE-ERROR-SEMANTICS.md`** — the `compute/error` two-form rule.
- **`SPEC-READING-AND-CROSS-IMPL-ROUTING.md`** — build-state claims, sibling claims, routing, census.
- **`PUBLISHED-SURFACE-CITATIONS.md`** — pointer-vs-receipt citation on files that ship.
- **`THE-RATCHET-AND-DIVERGENCE-RULE.md`** — worked examples of the methodology in this repo.

**When a session ends holding something durable, put it in the right home** (`AGENTS-STANDARD.md`
§Documentation): *how do I work here today?* → this file, kept small; *what would I otherwise
rediscover the hard way?* → `docs/agents/memory/`; *where are we this week?* → `docs/status/`. And
**an entry that could become a test, a lint rule or a gate SHOULD become one** — then it leaves
memory.
