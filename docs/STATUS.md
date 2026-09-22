# entity-core-go — status

_Updated: 2026-09-14 · released version: the newest git tag on `master` (authoritative in `CHANGELOG.md` + `go.mod`) — deliberately not restated here, so it cannot go stale on a cut_

**This file is the canonical rolling log for this repo** — one file, re-measured
rather than appended to, and the only status document that publishes. The dated
snapshots beside it in `docs/status/` (`HANDOFF-`, `CHECKPOINT-`, `ROUTING-`,
`TRACKER-`, `PEER-PACKET-`) are internal working memory and publish nothing;
they are immutable once written, and nothing here should be inferred from them.
The same holds for `docs/reviews/`, `docs/validation/reports/` and
`docs/validation/spec-issues/`. **So the citations below that name a file under
one of those directories will not resolve in the published source mirror** — the
release filter drops non-canonical prose, deliberately. Each is cited for
provenance, and every claim it supports is stated here in full; nothing in this
file depends on opening one.

## Where it is

Go reference implementation of the Entity Core Protocol v7 — the third
ground-up reference implementation (after Python and Rust), and the project's
SDK prototype + interop oracle. Because Go **leads on new protocol features**,
cross-implementation convergence is downstream feedback here, not a gate, and
the other implementations validate against this one as the interop baseline.
The codebase is a three-module `go.work` workspace — `core` (the protocol
library, a strict 13-package DAG: `errors → ecf → hash → entity, crypto,
store, types, wire → capability → handler → protocol, tree → peer`), `ext`
(system extensions, each depending only on `core` — **28 packages**), and `cmd`
(CLIs, the **67-category** validation suite, and cross-impl interop tooling). Go 1.25, only
two external dependencies (`fxamacker/cbor` for ECF, `mr-tron/base58` for
PeerID), pure-Go/no-CGo. The build is fully containerized (`make` + `podman`,
per-invocation resource caps in the `Makefile` / `RESOURCE-CAPS.md`); a fresh
clone with no sibling repos present builds and tests standalone. Maturity:
**pre-1.0 research-preview** — publicly released and tagged (the released
version is the newest git tag; see `CHANGELOG.md`). The extension
surface is broad and landed: `inbox`, `subscription`, `continuation`,
`revision`, `role`, `type` (+`constraint`), `localfiles`, `content`,
`identity`/`attestation`/`quorum`, `registry`, `relay`, `discovery`,
`publishedroot`, `encryption`, `compute`, plus the HTTP storage-substitute and
live-HTTP transport surfaces.

## Where we left off

> **2026-09-14 — the 0.8.2.24 cohort round landed, and it was mostly arch retracting
> its own recent text.** Two behaviours changed here. **A frame that fails validation the moment
> it is decoded — a mis-keyed supporting entity, the impersonation vector closed on 2026-09-13 —
> now gets an explicit coded error on the wire before the connection is closed**, rather than the
> bare close it used to get: dropping a request with no answer at all is non-conformant, whether
> or not the connection then closes. **And `system/tree:get` now distinguishes the two ways a
> request can name no path**: a genuinely absent resource still asks for the root listing, but a
> request that names a path and then excludes exactly that path is refused (`400 path_required`)
> rather than answered with a listing of the whole tree — serving the listing there answers a
> request for one excluded path with everything. Both were implemented against the landed
> specification; a third change the whole cohort had agreed on (that a certain ceiling could be
> checked once instead of twice) was withdrawn upstream — the two implementations we thought
> collapsed do not, and this repo had flagged the agreement as thin in advance. An unrelated data
> race in a test-only liveness flag, present before this round, was fixed in passing; the race
> detector is clean across all three modules. Full conformance suite a true green on every pass
> (`1656 · 0F · 0S`). The one item the whole cohort still owes — a peer whose own handler grant is
> narrower than the caller's, which three separate findings all need and none ships — is tracked,
> not built.
>
> **2026-09-13 — the capability-forgery close and two path-scope corrections landed.** A
> capability presented on the wire carries its supporting entities — identities, capability
> chains, signatures — in a map addressed by content hash, and every authority decision looks
> an entity up by that address. The address is now bound to the entity it names on receipt: an
> entry whose key is not the hash of its own contents is rejected, closing an impersonation in
> which an attacker files their own identity under a victim's address and has their signature
> verified against their own key while the request is attributed to the victim. The single place
> that builds that map now recomputes each address from the entity's contents, so no code path
> can file an entity under an address that is not its own. A wire probe drives the impersonation
> directly and confirms it is refused (verified by disabling the check and watching the forgery
> succeed). Separately, two capability-scope checks that exclude paths by pattern were corrected
> to honour an unmatchable exclusion — a mis-spelled exclusion pattern that matches nothing now
> denies everything (fail-closed) rather than silently widening the grant — at evaluation, not
> only when the capability is minted. Every derived path a bulk read or a merge produces is
> authorized against the caller's own capability, so a narrow caller cannot reach paths its
> capability does not cover. Full conformance suite green across all profiles.
>
> **2026-09-09 (b) — the 0.8.2.17 set converged three ways.** All three reference
> implementations (Go, Rust, Python) landed the outbound sub-dispatch authorization
> and the id-scope delegation-subset, and drove them against each other: the outbound
> check refuses a foreign sub-dispatch on an unscoped handler grant and accepts a
> target-minted credential, agreeing on reading that credential's authority from the
> chain's root rather than its leaf (a re-attenuated credential the target delegated is
> still the target's). The `system/*` registration reservation is withdrawn — any path
> is gated by the capability check, not a prefix rule — so its conformance check was
> re-based onto that capability refusal. A handful of small questions the specification
> leaves open (which error code a few operations return for a missing resource; whether
> the outbound check also binds a request a peer originates purely as itself) are raised
> upstream rather than decided unilaterally; behaviour is correct and identical across
> the three implementations on everything that is settled.
>
> **2026-09-09 — outbound sub-dispatch authorization and the id-scope delegation-subset
> both landed (§5.2 / §5.5a).** Before a locally-originated sub-dispatch leaves the peer,
> the four-dimension permission check now runs against the authority the sub-dispatch spends:
> a capability the target peer minted for this peer (its own dimensions authorize it), or —
> absent one — the executing handler's own grant, whose `peers` dimension binds it, so a
> handler with no peers scope covering the target cannot reach a foreign peer. A top-level
> request the peer originates as itself is authorized by the target on receipt, not pre-gated.
> Separately, the delegation subset check (child capability ⊆ parent) now matches the
> `operations` and `peers` dimensions as literal identifiers (bare `*` / trailing `/*`), never
> the tree-path matcher, and checks the `peers` dimension at all — closing a path by which a
> child grant could widen the peers it applies to past its parent's. The full conformance
> suite is green across all profiles. The `path_required` code question for the tree / inbox /
> subscription / continuation operations (whose specifications do not state whether a missing
> resource is that specific code or a generic structural one) is raised upstream rather than
> decided unilaterally; the behaviour (a 400 on a missing resource) is correct either way.
>
> **2026-09-04: §3.3 error-code convergence is CLOSED at the
> reference-implementation tier; a scoped follow-on backlog is analysed and reconciled.**
>
> **§3.3 (0.8.2.7) error codes — done, cross-impl clean.** go/rust/py are zero-FAIL on every
> §3.3 error-code row (501 slot `unsupported_operation`; 404 `handler_not_found`; generic 500
> `internal_error`; the code carried in the `code` field). Two harness surfaces the slot sweep
> had missed were fixed (`c2ff3a2`): `checkOptionalOp` now WARNs an unimplemented optional TYPE
> op at `501/unsupported_operation` (was: only the retired 400), and `handler_not_found_on_
> unregistered_path` SKIPs a catch-all peer (the 404 row is not drivable there — §3.3
> satisfaction-mode). Correcting the first surfaced a real core-rust defect (type-handler error
> code under key `type`, not `code`) — rust fixed it (`f0a399b`), wire-confirmed. Arch ruled the
> field layer 2026-09-04: the requirement already bound (§3.3 descriptor); the genuine gap (how a
> conformance test asserts a code) landed in GUIDE-CONFORMANCE §5.2b.1. No core bump.
>
> **The follow-on backlog is analysed, not vague.** Four threads separate "landed" from "fully
> converged + spec-complete" — the single reconciled board is
> `docs/status/HANDOFF-2026-09-04-post-3.3-open-items-ledger.md`. go is conformant on every row
> today; nothing blocks a release. In short:
> - **Type-op 404** (`converge`/`adopt`/`reconcile` → `404 type_not_found`): go conformant; the
>   ruling is still a DRAFT proposal with a §8.5 numbering collision, so the go wire gate is
>   staged, not landed. py diverges on all three (two at the wrong *status*, 400 — bigger than
>   arch's table shows).
> - **`unsupported_mode`**: the 400 slot is cohort-aligned (needs a REGISTRY code-table row); the
>   501 slot is a real §9.1-vs-§6a.9.2 spec-conflict — go+rust emit `unsupported_operation`, py
>   holds `unsupported_mode` — **needs an arch ruling**.
> - **SA-PY-35** (half-open `hello`-before-`authenticate` `ping`): unruled spec silence; go
>   answers `409` (aligned with py). **Needs an arch ruling**; go acts only if arch says "serve 200".
> - **Domain 500 codes**: 2 already conformant; 3 undefined tokens are **go-closeable** →
>   `internal_error` (next session); `remote_empty` (status question) + discovery `backend_error`
>   (spec owes a table row) route to arch.
>
> **Next session drives, in order:** (1) converge the 3 undefined domain-500 codes; (2) stage the
> type-op 404 wire gate behind the arch fold; (3) send ONE consolidated arch packet (not tile-by-
> tile) covering the type-op fold + py `×3` undercount, the 501 `unsupported_mode` conflict, the
> owed code-tables, SA-PY-35, and `remote_empty`. Full detail + file:line pins in the ledger.
>
> ---
>
> **2026-08-22 (c): SIGNED OFF for publish. §5.2 compute depth-budget
> fixed; the compute corpus LOCKs 362/362 go-on-go.** The 362-vector compute cross-bless had read
> `361/362` for a week (`cv9a-map-depth-exceeded-contains`, `recurse/tail-sum` forked) — root cause was
> the DEPTH limit reaching the peer through the wrong channel, on both sides: EXTENSION-COMPUTE §5.2
> sources depth from the capability's **grant-level** `constraints["system/compute"]["max_compute_depth"]`
> (ENTITY-CORE-PROTOCOL §5), and (1) the handler read it off the capability TOKEN top level (`grants[]`
> is where it lives → it reached the evaluator *nowhere* since v0.8.0; `MatchingGrant` existed for exactly
> this and was unused), and (2) the corpus wire driver sent only `params.budget` (operations), never depth.
> Invisible go-on-go (both sides defaulted to depth 1024 → agreed); only the cross-impl fork showed it.
> Fixed `0e34e3e`: read the matching grant (`computeConstraintsOfGrant`/`OfToken`), transmit depth via a
> constraint-bearing cap in `peeremit.go` (`constrainedComputeCap`, absolute `/peer/*` resource so §PR-8
> canonicalization holds and internal tree lookups stay authorized). **Proof: go-in-process vs
> go-over-wire LOCKs 362/362 byte-identical.** Teeth `ext/compute/depth_constraint_test.go` (grant
> constraint lowers depth + mutation). Release gate `validate-complete.sh` (PI_PORT=9411) **exit 0, all
> six passes, read UNPIPED** (compute 128·0F); full suite 65 pkgs 0 fail; frozen corpus SHA unchanged.
>
> **SIGNED OFF — go publishes as-is.** **Owed to arch (WIP):** spec-issue `2026-08-22-a` — §5.2's
> pseudocode `capability.data.constraints` reads as token-top-level and misled the impl; arch tightens the
> wording to name the matching grant's constraints. **Owed cross-impl (rust/py, NOT go):** re-drive the
> 362 corpus now that the harness transmits the limit — a peer that reads §5.2 literally has the same
> silent default. `0e34e3e` (fix) + `93ca425` (CHANGELOG) on `dev`, pushed.
>
> ---
>
> **PRIOR — 2026-08-22 (b): the corpus de-version fold is LANDED and the
> release gate is verified exit 0 UNPIPED.** `f884538` closes arch's `ROUTING-2026-08-22-a`
> (C-1..C-4): arch executed `PROPOSAL-DEVERSION-TEST-VECTOR-CORPUS` on the crypto-agility half
> (protocol `b4ea610` — `test-vectors/v767/` deleted, `agility-vectors-v1.*` → `agility-vectors.*`),
> and go was the only tree that read the path. **C-1** collapsed the corpus to its one surviving copy
> and repointed the PASS 0 guard at the `test-vectors` parent (it had gone *silent*, not red — the
> `[ -d …/v767 ]` guard + `corpus.Check()` `ErrAbsent` both skip on an absent path). **C-2** re-verified:
> corpus re-encodes to `b5484e84…` (13 vec), `agility-corpus-verify` 63 PASS/0 FAIL, frozen legacy pair
> still reproduces `8e7c5232…` @ 9236 B (not re-pinned). **C-3** renamed the three `v767-*` command dirs
> → `agility-*` (last live v767 path token; dated snapshots keep the historical name). **C-4** re-cited
> the two conformance metadata checks off the revised §5.1 (still NON_NORMATIVE; register `-check` green).
>
> **Release gate: `validate-complete.sh` (PI_PORT=9411) exits 0 on all six passes — REAL exit read UNPIPED.**
> This session corrected a masking bite: a `validate-complete.sh | tail` reports tail's `0`, not the gate's
> exit, so the prior block's "exit 0, all six passes at b1c65e7" was made over a summary that read
> `PASS 1 exit 1` (the failure was environmental — a sibling's leftover py peer squatting PI_PORT 9401 —
> not a code defect, but the *reading* was masked). New ratchet in `AGENTS.md`: read the gate's exit from
> the gate (`>log; echo $?` or `pipefail`), and quote the six per-pass `exit N` values. **No new discipline
> in the corpus work itself** — it re-applied the standing "a Skip-on-missing-file guard is only a guard if
> its path is live" rule. The go repo is green + clean; nothing blocks its GitHub publish.
>
> ---
>
> **PRIOR — 2026-08-22 (a): arch's `ROUTING-2026-08-21-h` worklist is CLOSED and
> the go repo is release-ready.** Live state is in **`docs/status/TRACKER-RELEASE-PUSH-2026-08-20.md`**
> and **`docs/status/WORK-STATUS.md`** (this STATUS.md's narrative below is older context).
>
> All five go-owed items landed this session — **C-14** (eval-limit carve-out keyed on code both arms +
> `depth_exceeded` contains, a provenance defect go shipped, fixed), **C-15** (D3 concat-args scalar),
> **C-18** (CV-9a/b/c corpus 359→362, SHA `8d2f55c8`), **C-17** (D8 walk-completeness wire checks,
> compute 126→128, GREEN three-way), and **B5** (cross-impl naming-leg driver over browser-rust's
> committed federation — the last registry-v1 clause, MET). Release gate `validate-complete.sh` **exit 0,
> all six passes** at `b1c65e7`. **No new discipline earned** (recorded per the close-out floor).
>
> **The go repo is green + clean; nothing blocks its GitHub publish.** Compute is on the operator-DEFERRED
> T5 track, so the compute items are cohort-convergence, not release-blocking. **Owed by OTHERS:** rust/py
> cross-bless the compute corpus at `8d2f55c8`; rust lands D3 (closes the transient `type_system`
> divergence); rust/py seed the C-12 check
> (`docs/validation/reports/2026-08-22-compute-v327-landed-and-what-rust-py-owe.md`). Publication-gate
> blockers B-1/B-2/B-3 are core-rust/browser-rust/devops, not go. **Post-release go-internal residuals**
> (off the cohort path): WS-C S2 client `request_id` demux, S4 revocation vectors.
>
> ---
>
> **PRIOR — 2026-08-14 (c): the board is clear. One build owed, and it is
> a rare one — the spec is ahead of every implementation.**
> **Read this first:**
> `docs/status/HANDOFF-2026-08-14-b-the-board-is-clear-and-what-each-seat-owes.md`
> — measured state, what each seat owes, and two single-item packets ready to send.
>
> **Everything routed to us this cycle is implemented and measured.**
> `convergence` is **99 P / 0 F in ALL THREE pairings** (go→go, go→rust, go→python) — closing
> `rexec_delivered`, open across three sessions and ours all along. Gate
> `1574 · 0F · 0S · 0W / 636 / 55 / 27 / 8`, six passes exit 0. rust `cc6cb56` **0 F** full
> surface; py `808d9e6` **1 F**, which is a *code* not a behaviour (§5 of the handoff).
>
> **The one build we owe: `strategy: "handler"` (REVISION §5.3, G-18).** v3.10 says it outright
> — *implementation gap, not a spec gap.* §5.3 fully specifies the delegation, §5.2 has always
> carried the dispatch arm, and **nothing in the cohort has built it**. All three degrade to a
> conflict entity, which is safe and not conformant.
>
> **Two defects we found in our OWN oracle this cycle, and they are one shape:** a rule that is
> pinned but asserted by nothing. The supersession vector asserted the `pending_hash` *changed*
> — which R4 forbids, and which FAILed conformant peers on clock resolution. And
> `wrong_substitute_type` was pinned by us one day and gated on `status != 400` the next, so the
> code was a value nothing asserted — hiding python's `invalid_entry` divergence until v1.2
> forced the assertion.
>
> **PRIOR — 2026-08-14 (b): CONTINUATION v1.22 is implemented and the
> cross-impl seam is CLOSED — 99 P / 0 F in all three pairings.**
>
> Arch landed **CONTINUATION v1.22**, **REGISTRY v1.4**, SUBSTITUTE v1.1, REVISION v3.9.
> **Read the text, not the summary:** §3.6a and §3.6b are **new normative subsections**, not
> rulings we had overlooked — and §3.6a's `mint_result_deliver_token` matches the shape we had
> already built at `3c13009` **slot for slot**. Implemented all four v1.22 MUSTs (`26675e9`):
> the mint is **on**; the advance re-roots the chain initiator at its own `dispatch_capability`
> (§3.6b — the advance is a **new chain root**); the connection-authority fallback is **removed**
> (§3.6a MUST NOT); and `CollectChainBundle` now collects **grantee** identities — it never did —
> failing `ErrChainUnreachable` rather than omitting silently (**§4.3 — rust's ask 5, ruled their
> way**).
>
> **Both of our "blocking" asks resolved against the FIXTURES, not the rule**, and §3.6b says so
> outright: *"fix the fixture, not the rule."* It is right. The validator's dispatch capabilities
> were scoped **peer-relative**, so §PR-8 canonicalized them against the *validator's* namespace
> rather than the executing peer's — they only ever matched because the advance ran under the
> delivery's broader capability. **The vectors were asserting the escalation.**
>
> **Measured: `convergence` 99 P / 0 F — go→go, go→rust AND go→python.** Gate
> `1574 · 0F · 0S · 0W / 636 / 55 / 27 / 8`, six passes exit 0. Only residue is `odr2`, an
> unconfigured `--inbox-relay-registry` surface that fails go-against-go.
>
> **Already conformant, verified not assumed:** REVISION's merge-strategy vocabulary (arch found
> the corpus declared it three incompatible ways) — we read the §2.2 table, carry all five values
> incl. `manual`, and have no `field-level` anywhere. REGISTRY v1.4's `"denied"` branch — we emit
> `{status: "denied"}` with **neither** hash, which is what v1.4 pins.
>
> **PRIOR — 2026-08-14: the rexec seam was OURS, and the fix has two halves.**
> **To arch (send this):**
> `docs/status/ROUTING-2026-08-14-the-rexec-seam-was-ours-and-fixing-it-exposed-what-was-holding-it-up.md`
> — three numbered asks in §2a, plus the §6a.9.3 four still unruled.
>
> **`convergence.rexec_delivered` failed go→rust for three sessions and we routed it at rust
> twice. It was ours.** Ran rust's own discriminator probe: `UnresolvableGrantee` **0**,
> `operation permission denied` **1 — and that one is the C-3 negative control**. Neither of
> their candidates fires. **rust's B served the `tree:get` 200 and dispatched the result back;
> the 403 is at A — us**, `grantee <A> != author <B>`.
> **`EXTENSION-CONTINUATION` §4.2 Step 4 is two lines and go implemented one.**
> `execute.deliver_token = generate_internal_deliver_token(...)` was never built — there was no
> `WithDeliverToken` in `core/handler` at all. So the EXECUTE named a delivery it never
> authorized, and each impl improvised: **go's B fell back to connection authority — which is the
> only reason go→go ever passed**, and `async.go`'s own comment already called that *"works by
> accident."*
>
> **Built (`3c13009`): `Dispatcher.mintDeliverToken`. ENABLED NOWHERE, and that is the finding.**
> The switch makes rexec pass go→rust in 201 ms. With the **second half** (re-root the chain
> initiator at the `dispatch_capability`, which §4.2's table and our own `ReactiveTrigger` note
> already describe), **`convergence` is 99 P / 0 F in BOTH pairings — go→go and go→rust.** It
> costs two local vectors (`deref_included_resolves`, `request_side_included_preserved`), because
> **Level 2 (`CheckPathCapability`) consults the chain initiator** and these fixtures'
> `dispatch_capability`s cover handler+operation but not resource. §6.8 answers Level 1 and is
> **silent on Level 2** — that silence is where both defects live. Not shipped: we do not buy a
> cross-impl fix with a local regression.
>
> **A claim withdrawn before it was routed.** An earlier draft listed "six go↔rust sync
> divergences." **There are none.** Switch off, they all report `blocked: depends on
> rexec_delivered`; switch on, the go→rust failing set is a **strict subset** of go→go
> (`comm -13` empty). One go-internal defect, both pairings, no cross-impl gap.
>
> **Siblings re-measured from live trees: rust `cc6cb56` and py `808d9e6` are BOTH
> `registry_issuer` 27/27 and 0 F on the full surface** (rust was 9 F, py 7 F — every
> `pending_hash` failure closed; rust's ask 7 confirmed). **Containment closed in all three
> seats**, so the meta's one open security item is answerable.
> **Gate: `1574 · 0F · 0S · 0W / 636 / 55 / 27 / 8`, six passes exit 0.**
>
> **PRIOR — 2026-08-12 (c): the new MUST fails in BOTH siblings, and R-6
> found a row nothing measured.**
> **To arch (send this):**
> `docs/status/ROUTING-2026-08-12-c-r6-found-an-unmeasured-row-and-the-new-must-fails-in-both-siblings.md`
> — one ask, in
> `docs/validation/spec-issues/2026-08-12-c-the-202-pending-review-carrier-is-unpinned-and-all-three-differ.md`.
> **To rust + py (send this):** `docs/status/PEER-PACKET-2026-08-12-c-rust-and-py-the-escalation-fails-in-both.md`,
> evidence in `docs/validation/reports/2026-08-12-c-rust-and-py-measured-the-5-4a-escalation-fails-in-both.md`.
>
> **The headline: we ran rust `21eb223` and py `2c1aa1b` ourselves.**
> `liveness_escalate_after_eviction` (§5.4a `[MUST]`, ratified this morning) **FAILs in both** —
> the same defect go carried until `b55101f`, so it was the **cohort's**, not ours. Consequence in
> both: no `disconnected` write ⇒ **§4.1 reconnect never fires on a transport-error-first path.**
> **A-6 is answered by measurement, not by asking two teams.** py additionally fails the three
> §6a.9 layer-1 rows (**R-3**, previously arch's source read, now probed); rust is converged there.
> **Gate: 1571 · 0F · 0S · 0W / 633 core / 55 / 19, three consecutive runs** (pass 3 18 → 19 —
> `409 name_taken`, a pinned row that had **no check at all**).
>
> **PRIOR (2026-08-12): the cohort is aligned and F-1 is closed.**
> `docs/status/ROUTING-2026-08-12-full-status-to-arch-one-real-defect-and-two-gaps-of-the-same-shape.md`
> — full status plus **two small asks**, both in
> `docs/validation/spec-issues/2026-08-12-a1-eviction-orphans-the-5-4-escalation.md`.
> **Live tracker:** `docs/status/WORK-STATUS.md` (the *state*; dated ROUTING-*/HANDOFF-*
> docs are the *record*).
>
> **GATE: 1570 · 0F · 0S · 0W / 633 · 0F · 0W (core profile) / 55 / 18 at `dfaebfe`,
> four consecutive runs** — **four** passes now, all exit 0, and **zero WARNs for the
> first time.** The F-1 flake caveat is retired — not by re-running until green, but
> because F-1 was diagnosed and fixed.
>
> **Every open item in WORK-STATUS §2 is closed** (G-1a, N-2, G-2a, W-1), and three of
> them changed what the numbers mean rather than just adding coverage:
> **`--profile core` now runs in the gate** as pass 1b (it was invoked by nothing);
> **both standing WARNs were checks measuring the wrong thing** — `eval_depth_limit` was
> measuring tail-call optimization, and `r3_connection_flood` scored a close-based
> refusal as no refusal at all, so **implementing §4.10(c) turned its WARN into a FAIL.**
> Go now bounds inbound admission (`WithMaxInboundConnections`, default 128).
> **`validate-peer` scores all three impls — re-run `resource_bounds` against this build
> before trusting an older number for any peer.**
>
> **F-1 was a real conformance defect, not a flaky check.** The §A1 transport-error
> demotion **evicts the pooled binding as it writes `suspect`** (`demotePeer`) and the
> keepalive loop **exits when unbound** (`exitKeepaliveIfUnbound`) — the same event on the
> pooled path, so the §5.4 `suspect → disconnected` escalation was **structurally
> unreachable**. The peer stayed `suspect` forever, the disconnect subscription never
> fired, and **§4.1 reconnect never triggered**. Fixed at `b55101f` by taking §5.4's own
> grace step before exiting; pinned by a deterministic in-process test (failed 100 %
> pre-fix) and a mutation-tested negative half guarding the evict-without-demote paths.
>
> **The cohort packet is fully discharged and both peers pushed** — rust `21eb223`
> (0 unpushed, incl. the `revoke`/`renew` security fix), py `2c1aa1b` (18 commits,
> 0 unpushed, incl. the `system/*` reservation hole our new check found on their first
> run). **§5.5a is settled three ways by measurement; our delegated-cap finding was
> retracted** — no ruling needed.
>
> **The open asks are arch's:** A-5 (the §A1/§5.4 composition + the §A2 reason + the
> vector gap) and **A-2**, the v767 M3/M6 re-stamp, still unratified and still blocking
> A-3. **Nothing in WORK-STATUS §2 is open** — the next session picks up from §3
> (blocked/awaiting) or starts something new.
>
> **Do NOT start `ext/identity` pre-rotation** (§4 gated on §6.1, §6.1 on a matrix that
> does not exist). **Before anything else: check every sibling's `git log` including
> `origin/`.** A ruling that is not pushed has not been made.

> **[SUPERSEDED by the 2026-08-12 block above — the packet was carried, both peers
> discharged it, and the F-1 caveat is retired.]**
> `docs/status/HANDOFF-2026-08-12-clean-foundation-and-what-to-build-next.md`
> — the foundation is clean and measured; that doc carries what to build on it,
> what NOT to start, and the reconnect criteria for arch/browser-rust.
> **Was ready to send, since carried:**
> `docs/status/PEER-PACKET-2026-08-12-rust-and-py-restart-here.md` — one packet
> consolidating everything rust and py owe, superseding the 08-11 handoffs neither read.
> rust was carrying a **live security hole** (unauthenticated `revoke`/`renew`) — **fixed
> at rust `0caf911`.**
>
> **GATE: 1569 · 0F · 0S / 55 · 0F · 0S / 18 · 0F · 0S**, measured 2026-08-11 (f), all
> three passes exit 0. **1567 → 1569** because the §2.4a register negative half had been
> landing in a profile *nothing invokes* and now runs in the standing gate.
>
> **§2.4a is closed structurally:** the state probe lives in the shared deny helper
> (`denyStateProbe` / `sendAndExpectAuthzDenyProbed`), so callers inherit conjuncts 2+3
> by construction. Both probe modes mutation-tested. **One row is deliberately
> unasserted** — `handler_scope_denied_core_1`, whose write location was not established;
> a guessed probe would pass for the wrong reason. That is **G-1a**, the top next item.
>
> **Do NOT start `ext/identity` pre-rotation** (§4 gated on §6.1, §6.1 on a matrix that
> does not exist), and do not re-open arch/browser-rust until the reconnect criteria in
> §7 of the handoff are met.
>
> **Before anything else: check every sibling's `git log` including `origin/`.** A ruling
> that is not pushed has not been made.

> **[SUPERSEDED by the 1569 measurement above.]** GATE RE-MEASURED 2026-08-11 (e) at
> `cf99a59`: **1567 · 0F · 0S / 55 · 0F · 0S / 18 · 0F · 0S**, all three passes exit 0. This supersedes every carried instance of
> that triple below. Two standing WARNs the carried number never mentioned —
> `compute.eval_depth_limit` (COMPUTE §5.4) and `resource_bounds.r3_connection_flood`
> (V7 §4.10(c) SHOULD) — both pre-existing, tracked as W-1 in WORK-STATUS.

> **As of 2026-08-11 (b) — arch ruled everything routed in the last two cycles.
> Nothing is frozen; two rulings are coordinated cohort cuts.** Gate at
> `1745f16`: **1567 · 0F · 0S / 55 · 0F · 0S / 18 · 0F · 0S** (1566 → 1567 = the
> new announce-stop negative half). Peer handoff:
> `docs/status/HANDOFF-2026-08-11-b-…`. Arch pins: `4dd07f5`, `03ba755`.
>
> - **`{peer_id_hex}` is UNFROZEN — §4.5a item 1a (v7.77)** (`d7e44f6`).
>   `system/peer` is authored at the ECFv1-SHA-256 floor **unconditionally**,
>   whatever the home or negotiated active format. Our preferred resolution was
>   **rejected**: promoting §8.4.6's prose to a peer-level MUST would retire
>   `hash_formats` negotiation and make our own SHA-384 gate arm illegal by
>   construction. Implemented at two choke points; the format **parameter** is
>   deleted, not defaulted, because §4.5a item 4 now says two derivation
>   functions is the defect.
> - **The mixed-home seam HOLDS: 35/35 both arms**, control green in the same
>   invocation, from 2 FAIL + 3 SKIP. The `401 invalid_nonce` at
>   `connect:authenticate` is gone — arch declined to claim 1a would fix it and
>   was right not to; measured, it does. Still diagnostic, not a gate.
> - **`notification` cut** (`d7e44f6`) — RATIFIED; the banner we declined to cut
>   against was stripped in `03ba755`. `system/protocol/inbox/notification` →
>   **`system/subscription/notification`**, re-homed INBOX → SUBSCRIPTION. One
>   round with `delivery`, no dual-kind window, drain undelivered mail first.
> - **DISCOVERY §3.3 is a TWO-case rule** (`1745f16`) — ruled reading (b). Go
>   failed the half nobody had stated: `announce-stop` returned success for any
>   ref not currently announced, which is idempotency applied to a question it
>   never asked. Fixed, plus `v7c_announce_stop_unknown_profile_ref`. Our
>   `v7_announce_stop_idempotent` was scoring the wrong case and would have
>   failed a conformant peer.
> - **`issuerNoParams` sent `primitive/map`** where §3.2 pins `primitive/any` +
>   canonical `a0` — arch caught it reviewing the instrument. Would have surfaced
>   as a rust/py FAIL that was ours.
> - **Cohort state:** rust owes `revoke`/`renew` layer 1 (its 16/16 was scored
>   against the checks that certified the hole and will drop to 16/18); py's two
>   failures go green unchanged. Both owe the `notification` cut.
> - **[SUPERSEDED 2026-08-11 (e) — the corpus LANDED at
>   `entity-core-protocol/specs/test-vectors/v767/` (core-protocol `56d4de4`),
>   verbatim, pin unchanged and re-verified. The legacy path below is where it
>   *was*. The six M3/M6 assertions are now a written re-stamp proposal with full
>   derived values: `spec-issues/2026-08-11-d-*`. `core_register_gate`'s negative
>   half has shipped. Snapshot kept as authored per the immutability rule.]**
> - **Owed to arch: migrate the `v767` corpus.** It is **not** missing — it is at
>   `entity-core-architecture/docs/architecture/v7.0-core-revision/…/test-vectors/v767/`,
>   in the archived pre-V8 architecture repository,
>   sha `8e7c5232…` matching the pin exactly. The V8 split carried its two
>   siblings (`ecf-conformance`, `crypto-agility`) into `entity-core-protocol`
>   and left `v767` behind — visible even in the legacy repo's own `V8/` staging
>   subtree. **Measured, not predicted:** running it against item 1a gives
>   **49 PASS / 6 FAIL**, one root cause — M3/M6 pin peer A's `system/peer` hash
>   under SHA-384 and the root cap embeds it as `Granter`, so the cap hash and
>   its signature move too. Those six need re-stamping. Separately,
>   `hash-format-sha-384.2.rehash` **passes** while asserting a construction the
>   ruling forbids, because that vector builds the entity by hand and bypasses
>   the pinned constructor. Also: `core_register_gate` is ten positive checks
>   with no negative half — recorded as a §2.4a candidate, not claimed as a
>   defect.
> - **Correction, same day:** the first version of that spec-issue claimed the
>   corpus "exists nowhere." Wrong, and wrong because the search was insufficient
>   — `find -maxdepth 6` against a path 8 levels deep, over the church-meta
>   — `find -maxdepth 6` against a path 8 levels deep, over the church-meta
>   siblings only. `entity-core-architecture` is the **pre-V8 arch repo and is
>   build-state claim from here in two days; both were caught by a person, not by
>   the process.
> - **Correction to our 08-11 packet.** It claimed EXTENSION-SUBSCRIPTION §2.2's
>   banner "still reads not ratified, untouched since `4fe5348`." False when
>   written — stripped in `03ba755`, on disk at the time. We carried a prior
>   session's measurement across a commit change without reopening the file,
>   which is the exact failure `AGENTS.md` names. Arch's 08-10 (f) packet was
>   also committed-but-unpushed for a cycle, and the rule they recorded from it
>   stands on its own: **a ruling that is not pushed has not been made.**

> **As of 2026-08-11 — the cohort caught up, and two authorization holes came
> back with it. In both cases our own conformance check was certifying the
> hole.** Read this block first. Gate at `e91817f`: **1566 · 0F · 0S / 55 · 0F ·
> 0S / 18 · 0F · 0S** (`/18` was `/16` — two new §6a.9 layer-1 checks), three
> consecutive clean runs. Full routing:
> `docs/status/ROUTING-2026-08-11-the-checks-were-certifying-the-holes.md`.
>
> - **REGISTRY §6a.9 `revoke` + `renew` verified NOTHING** (`e91817f`). Any peer
>   that could reach the registry could **permanently revoke any binding in it**
>   — revocation is monotonic, there is no undo — or extend any binding past its
>   registrant's intended lapse. `verifyOwnershipProof` existed and was called
>   from exactly one place: register. Renew's nonce discipline reads as
>   authorization and is not; it stops a *captured* request being re-run while
>   leaving a fresh unsigned one accepted. Fixed for the pinned `target_peer_id`
>   half; the **"or the operator" half has no proof shape anywhere in the corpus**
>   and is routed.
> - **Our two checks certified it** — they dispatched revoke/renew with no proof
>   and asserted 200/202, so a *correctly implemented* peer failed them. **core-py
>   refused to match and reported it instead, which is the only reason it was
>   found.** Now they prove ownership, plus the two negative halves
>   (`layer1_unsigned_revoke_rejected` asserts 401 **and** that nothing was
>   published). `registry_issuer` 16 → 18.
> - **LOCAL-FILES §8.3 containment had no component boundary** (`e91817f`) —
>   root `/srv/peerroot` "contained" `/srv/peerroot-backup`, with **both**
>   §8.3-named defenses fully satisfied. Found by auditing what rust's V4a report
>   pointed at, not by the report; **neither sibling reported this one.** Third
>   distinct member of one defect family, each missed by a different impl, none
>   visible to the shared V4/V4a probe.
> - **`validate-peer`: an excluded check's live FAIL now says so.** py's
>   `serving_mode.content_get_out_of_scope_404` report was right — reporting
>   artifact in our tool. Annotated `[excluded from scoring]` rather than
>   suppressed; a dropped line would hide a real failure when someone excludes a
>   whole category.
> - **Cohort effect to announce:** rust's `registry_issuer` 16/16 was scored
>   against the checks that certified the hole and **will drop** until rust
>   implements layer 1 on both ops — correct outcome, not a rust regression.
>   **py's two pass-3 failures should go green unchanged.**
> - **Owed to arch, none blocking except the first:** `{peer_id_hex}` (carried,
>   still frozen for everyone); the operator proof shape; **DISCOVERY §3.3
>   `profile_ref`, now corroborated 3/3** — and Go's `v7_announce_stop_idempotent`
>   asserts the *opposite* of the ratified sentence, so the cohort's shared
>   instrument and the spec disagree; §6a.9's unpinned status codes (rust and py
>   both converged to Go's 401/202 with no MUST to point at); the `notification`
>   half-cut round, now 3/3 holding the old string on purpose.

> **As of 2026-08-10 (e) — the 08-10 packet's four items are through, and the two
> that did NOT land as scoped are the useful ones.** Read this block first.
> Gate at `4fb3c1b`: **1566 · 0F · 0S / 55 / 16**, identical under both
> content_hash_formats (`/16` was `/12` — four new §6a.9.2 checks).
> Full routing: `docs/status/ROUTING-2026-08-10-e-…`.
>
> - **Landed: the `system/inbox/delivery` cut** (`927070c`). Go has cut; **rust
>   and py have not**, and §2.1's one-round `[MUST]` means the delivery type is a
>   known cohort divergence until they do — expected at the next cross-impl run,
>   not news. **It may be a two-string round — see the `notification` question below.**
> - **Landed: REGISTRY §6a.9.2** (`8d3a6d4`) — `set-issuer-policy` /
>   `get-issuer-policy`, plus two behaviours that were non-conformant: the CLI
>   flag was a request-time parallel source (now a startup **seed** of the policy
>   entity), and an absent policy defaulted to `open` (now curated-only —
>   "unset is not a mode"). Four validate-peer checks are the cross-impl
>   instrument; `registry_issuer` is 16/16 on Go.
> - **Routed, NOT landed: the `{peer_id_hex}` pin** (`a2a4ccf`). The prescribed
>   one-line fix breaks capability-grant and ownership-proof equality in `core/`
>   on any non-floor home. `{peer_id_hex}` is not separable: one hash per
>   connection is both a path key and an identity-reference equality operand, and
>   §8.4.6 / §514 / §1772 rule those two roles in opposite directions. Two green
>   tests measure it. **Awaiting one ruling from arch; nothing else is blocked.**
> - **Landed: the mixed-home probe** (`4fb3c1b`) — and **the seam diverges.**
>   `scripts/probe-mixed-home.sh` runs it with a control in ~30s. Two Go peers on
>   different homes fail cross-peer rexec + subscription delivery on checks that
>   pass 35/35 same-home. Proximate cause `401 invalid_nonce` at
>   `connect:authenticate`; **not bisected.** Deliberately not in the gate —
>   §1.2a keeps the uniform network as the supported v1 deployment.
>
> **Owed to arch:** whether `system/subscription/notification` is in the delivery
> cut round (its spec banner still says unratified while the delivery ruling cites
> it as settled), and the machine spec's two stale type strings. Neither blocks us.

> **As of 2026-08-10 — ENCRYPTION v1.0's vector set is closed, and the open finding
> is hash agility.** Read this block first; everything below it is the connectivity
> narrative it superseded, kept because the substrate it describes is still the
> substrate.
>
> **Connectivity is parked at its hardware boundary, not stalled.** G3 — the emulated
> dual-NAT crossing — **ran and closed 2026-08-08 at 12/12 across 3 rungs, gate 6/6**,
> which retires the `EXTENSION-SIGNALING` §11.5.1 loopback-blindness class for the
> punch. The only remaining connectivity gates are **G4** (two real independent NATs,
> for NAT *diversity*) and **S5** (two real browsers) — both lead time, not work.
> Python's punch is the largest M-level gap in the corpus and is **python's**, not ours.
>
> **ENCRYPTION v1.0 (M2→M3): 11 of 12 §16 vectors built, and the 12th is not v1
> work.** `ENC-ROUNDTRIP-FORMAT-1` landed 2026-08-10 — the last substantive gap.
> `ENC-PEER-KAT-2` is the hybrid-PQ slot that §16 itself marks *"validate slot, no
> impl required v1."* BLOCK-0 is locked three-way; BLOCK-1 is built at all three
> tiers plus cross-tier interop, multi-device Tier C, and `ENC-RESOLVE-ORDER-1`
> (27 rows, now including the mixed-content_hash_format rows that make arch's Q2
> tie-break ruling falsifiable at all). The encryption category is **22 · 0F · 0S
> under both SHA-256 and SHA-384**.
>
> **The open finding is not encryption's.** Building that vector meant turning
> `--hash-type sha384` on for the first time — `validate-complete.sh` had no way to
> pass it, so every conformance number this project has published was measured under
> exactly one content_hash_format. Under SHA-384, **31 distinct checks fail and 30 are
> one spec rule**: `EXTENSION-NETWORK` §6.5.3.1 pins the served hash hex at 66 chars
> while justifying the format byte as crypto-agility, so a SHA-384 peer `400`s on its
> own content route. The 31st is `EXTENSION-SIGNALING` §6.3's `inner_content_hash(33)`.
> **Our peer is conformant in failing both** — they are arch's, and are filed in
> `docs/validation/spec-issues/2026-08-10-*`. The SHA-384 run is a **diagnostic**; the
> gate remains the default SHA-256 run at **1551 · 0F · 0S** (pass 2: 54 · 0F · 0S).
>
> **Routed to arch 2026-08-10** —
> `ROUTING-2026-08-10-sha-384-does-not-work-and-the-cohort-already-disagrees.md`,
> with the per-peer measurement in
> `docs/validation/reports/2026-08-10-sha384-home-format-cohort.md`. The cohort is
> already split on it: go and rust `400`, **python `200`** — letter vs intent, and
> nothing caught it because no run ever produced a hash that was not 66 chars.
>
> **We own exactly one substantial unblocked item:** REGISTRY §6a.9
> live-registration is fully built (`ext/registry/peerissued`, three ops × three
> policy modes) and has **zero** validator coverage — because `peer-manager` has no
> `--issuer-policy-mode` passthrough, so the suite cannot start the surface. That is
> the same shape as the SHA-384 gap: a real, correct, default-off surface with no way
> to turn it on.
>
> Entry points for the current cycle:
> `HANDOFF-2026-08-10-encryption-v1-0-is-closed-and-sha-384-is-not-runnable.md`
> (position), then
> `HANDOFF-2026-08-10-b-the-blocker-review-and-what-closes-each-one.md`
> (every open blocker, verified, with what closes it).

**The connectivity cycle — EXTENSION-SIGNALING — was the live work** from early July
through 2026-08-08. It is a cohort effort with `entity-core-rust`,
`entity-system-architecture` (spec) and `entity-browser-rust` (the browser leg),
routed through dated `ROUTING-*` / `HANDOFF-*` docs in this directory.

Landed here: the §4 rendezvous node + client, the §3 key derivation and pool
selection, the §7 NAT-punch choreography (gather → carrier exchange →
measure-and-schedule → simultaneous open over a shared SO_REUSEPORT socket →
§7.4 identity check), wired to a live peer through `ext/signaling/peerwiring`
behind EXTENSION-NETWORK §10.3's `establish_live` seam. The §6.5 WebRTC
coordination layer is implemented as coordination RULES ONLY — Go has no ICE
stack, terminates no data channel, and publishes no WebRTC transport profile.

**The §6.3 coordination envelope is folded** (arch `b99304d`) after crossing
both ways: Go `38·0F` verified by rust, rust `36·0F` verified by us. Every
correction this repo routed is in the normative text — the derived-and-compared
peer-id, the two hash axes, and the four-disposition anti-downgrade rule.

**The flag day is CLOSED.** Both implementations read, seal, and now refuse.
§6.1 sealing landed Go-side at `d56a690` and rust-side shortly after; rust ran
a live cross-impl sealed punch and raised their `PUNCH_TRUST` to `Require` on
the strength of it; our collector was then proven to enforce from our own seat
(Go↔Go completes under require, and a bare depositor built from our pre-flip
commit is refused by name, not by timeout). `peerwiring.DefaultTrust` is now
`VerifyRequire` — verified after the flip with no `--trust` flag passed at all,
so it is the default posture that was measured: `verified:true` on both seats
over a live node, `signaling` 7/7.

`entity-core-py` is unaffected: it has the §4 signaling client but does not
punch and has no signed-blob support, so it never enters the path this
governs. When Python builds the punch it seals from the start — there is no
tolerant window left to arrive into.

**The live arc is now the symmetric-reentry proposal**
(`PROPOSAL-SYMMETRIC-REENTRY-MUTUAL-MINTING.md`, arch DRAFT rev 2), reviewed
here against Go's code and routed back at
`ROUTING-2026-08-05-symmetric-reentry-reviewed-and-our-row-2-was-bare.md`. Its
§7 "no fourth row" ruling holds in Go: one resolution funnel
(`getRemoteConnection`), every dispatch site mapping to a row-1 dial, a row-2
trigger, or verbatim relay pass-through. Enumerating that found a defect of our
own — `deliverToInbox` built a fully-authorized envelope from the
`deliver_token` and then discarded it on the remote branch, so INBOX async
delivery rode the connection's session capability instead. Invisible on a
dialed connection, `401 unresolvable_grantee` on the §6.11 reentry path.
Fixed with two regression tests. A second site with the same shape —
`DispatchLocalEnvelope` dropping the envelope's capability, which is how
cross-peer subscription notify authorizes — is routed, not fixed: it needs a
taxonomy answer first, and the gate that covers notify publishes a dialable
profile as its setup step, so it cannot observe the profile-less case.
Arch answered at rev 3 (`5f62374`), folding both of our findings as validated
behavior: the §4.4 discriminator moved **onto the key** (*was a §3 rendezvous
key mutually brought?* — a co-occurring profile resolution does not demote it),
and §9 Q2 gained the precedence pin (connection-scoped originating authority is
a **distinct slot** from the durable `held_capability`, consulted in addition to
it). **Both are ACKed and built here** — `MarkEstablishedViaRendezvousKey` on
all three symmetric establishment paths, and a connection-scoped authority slot
with one shared selector for `Execute` / `ExecuteWithIncluded`; three tests,
`signaling` 7/7 with the classification on the live punch path. **Go still
mints nothing** — the mechanism (mint, §7a.2a carriage, acceptance check,
bounded wait) waits for FOLDED, which now gates on core-rust's ack, not ours.
Routed at `ROUTING-2026-08-05-b-ack-rev3-discriminator-and-precedence-both-built.md`.
(Arch's fold answered the ordering question in the normative text — the
connection-scoped grant wins, "a durable cap can predate the live
establishment and MUST NOT shadow it." Our implementation matched.)

**§6.5 (b) is FOLDED (arch `c8c7bc8`) and Go's mint is built.** The loop runs
end to end: mint at the handshake's tail gated on the local classification,
acceptance checking only the legs the frame carries, installation into the
connection-scoped slot, and a bounded wait so an acceptor that never receives a
grant fails closed instead of blocking. Proven **cross-process over a real
punched connection through a live signaling node** (both seats `verified:true`
under `trust:require`), plus three regression tests including the §8.2
asymmetric non-regression vector. `signaling` 7/7 with the mint in path.

**One spec issue, and it is load-bearing for py and browser-rust:** the folded
**Carriage** sentence (§7a.2a in-band params, no intercept lane) **has no
construction** — a proactive establishment-time grant has no authorized carrier,
because §4.4's `default_connection_grants` reach no deposit handler, and the
sentence names no URI or operation at all. Both shipped impls independently
built a self-verifying connect-phase frame instead. Filed at
`docs/validation/spec-issues/2026-08-05-reciprocal-grant-carriage-is-unimplementable-as-folded.md`,
routed with a proposed replacement at
`ROUTING-2026-08-05-c-the-mint-is-built-and-the-carriage-has-no-construction.md`.
Go matched core-rust's shipped wire shape deliberately so the cross-impl vector
is runnable.

**Building the §8.1 vector then found a gap that was ours, not the spec's.** The
acceptor's origination timed out — Go's client-side reader treated every inbound
frame as a response to something we sent, so an inbound EXECUTE on an *outbound*
connection (the counterpart originating to us) was dropped as an orphan. That is
V7 §6.11(b) dialer-side reentry, and Go had none; our server side has always
served both directions. Fixed at `8f6da60`, and the §8.1 vector now passes —
the acceptor dispatches under the grant and the dialer's `verify_request`
accepts it. **Authority without a serving path is not reach-back**, and a peer
can pass every grant-shaped test without noticing.

**All four rulings landed (arch `f8f736a`) and Go has folded them.** The packet
we held V3 on — `ROUTING-2026-08-06-decision-packet-four-rulings-before-the-cross-impl-run.md`
— came back ruled and folded in place, with a new MUST attached: **reach-back
serving**, generalized from Go's dialer-reentry gap and tagged
single-impl-invisible so py builds both halves from the start.

- **Q2 (the load-bearing one) — the reciprocal grant is the ASSEMBLED
  inbound-dialer grant**, not the flat §4.4 floor: floor ∪ policy,
  advertisement-filtered. Go's mint now runs the *same* assembly the §6.6
  handshake runs, extracted as `ConnectHandler.AssembleInboundGrants` and called
  from both sites — one assembly, not a second copy that drifts. Advertisement
  discipline (Q2a) binds the mint too; the "MAY narrow by policy" third
  direction (Q2b) is gone.
- **Q3 — a floor, not a value.** Our 2s stays implementation-local; the
  conformance-vector floor is named separately as
  `peer.ReciprocalGrantVectorFloor`, with the distinction spelled out at both
  constants so a future edit can't quietly merge them.
- **Q1 / Q4** need no Go code change: the carriage shape stands, and the
  reciprocal `capability:request` widening is the same §4.4 op (in v1, separate
  vector, not gating S5).

The pin test flipped rather than being deleted, and it no longer hardcodes a
grant list: it dials the same peer the ordinary way and asserts the reciprocal
grant is **byte-identical to what that peer hands an inbound dialer** — the
ruling itself, measured on both directions.

**V3 is CLOSED on the crossing — `8·0F`, four per direction.**
`docs/validation/reports/2026-08-05-v3-reciprocal-grant-crossing-rust.md`.
The first run was partial (direction A 4/4, direction B 0/4). Rust bisected
direction B to their own punch driver — the initiator handed the socket to a
bare `perform_connect` with the rendezvous flag and the dispatch context both
dropped, so the mint's guards were never reached — fixed it, and folded Q2 in
the same commit. Re-run against `6bf8f19`: **both directions mint and accept,
4/4 each.** Their `reciprocal_grant_sent` and our new
`reciprocal_grant_received` now appear on the same crossing, which is what makes
"their minter declined" and "our acceptor dropped it" separable from the JSON
alone.

**Oracle-pinned: `8·0F @ e968ed1`.** Rust pushed, so `origin/dev` now carries
the §6.5 (b) work and the provisional caveat that rode both earlier runs is
discharged. Re-run from a read-only extraction of the published commit: no
outcome changed, which is the only interesting thing a re-pin could find.

**REACH is the open edge now, and we built our half of it.** The first run's
stated limit was that V3 proved installation, not reach — a cap that verifies
and authorizes nothing is exactly the failure the mechanism exists to prevent.
`cmd/signaling-punch`'s responder now originates one dispatch back under the
installed grant and reports `reciprocal_grant_received` /
`reciprocal_reach_status`. **Go↔Go control: 200.** Against a Rust dialer the
grant installs and the dispatch does not land — *not* an authority failure (no
401, no 403) but a **lifetime** one: their initiator tears the connection down
**~1.4 ms after its pong**, leaving no window to reach back. Checked both ways
before routing it: our processing of their grant frame took 0.2 ms, and the same
code path returns 200 Go↔Go.

That is the precise **mirror** of the defect Go fixed on 2026-08-01, when our
responder returned on first observation and dropped the socket under an
initiator still waiting on its pong. The fix then was `lingerAfterVerify`; the
ask now is the same linger on their initiator. A symmetric establishment needs a
symmetric linger — and the reach leg in direction A is theirs to build, since
there they are the acceptor.

Re-checked at `e968ed1`: the linger is not in their driver yet (our routing and
their status note crossed), so direction-B reach is a **held** measurement, not
a failure — `reciprocal_grant_received:true` 4/4, never a 401 or 403. It becomes
measurable the moment that linger exists. **Their note that Go still owes the
reach leg is stale** — it landed in `26fd7b7`; what direction B waits on is the
counterpart linger, not our leg.

**Arch closed both owed items (`977667f`), and two Go deltas fell out — not one.**

**The advertisement-filter matching rule is built.** Go's filter was the
namespace-prefix-match the ruling names non-conformant (strip a trailing `/*`,
ask the registry, handlers axis only); it now compares the four named axes with
the chain's own pattern semantics, and the ruling's own `foo/*`-vs-`foo/bar`
example drops and is pinned. Two decisions came with it, both routed rather than
buried (`docs/validation/spec-issues/2026-08-05-drop-not-narrow-deletes-wildcard-grants.md`):
"drop, not narrow" deletes every wildcard grant — including `OpenAccessGrants()`,
i.e. every test peer and driver we have — so the pre-ruling universal carve-out
stands until arch rules; and "the same relation the chain uses" is a trap we fell
into for one build, because `IsAttenuated` is more than four axes and its
allowance-attenuation rule took out the **entire `query` category, 6 FAIL**
(v7.14 requires allowances on query grants). Four axes means four.

**The carriage closure is a wire change to Go and Rust, not just a shape for py.**
The ruling is a better answer than either option we offered — delivery is the
cap's content hash, wielding is the §7a.2a triple as references the dialer
resolves because it authored them, so nothing in the delivery frame conveys
authority and nothing needs to authorize it. But both shipped impls send the full
cap entity plus chain at delivery and re-inline the chain on every origination;
both halves are now wrong on the wire. **V3 is `8·0F` under the old shape, and the
first impl to flip alone turns it red.** We are not flipping unilaterally — that
is a call, not a deferral. Proposed: both impls accept both shapes (additive,
independently landable), then flip senders in one window and re-pin; py builds
only the new shape. Routed at
`ROUTING-2026-08-05-g-the-filter-is-built-and-the-carriage-is-a-flag-day.md`.

One ordering lesson worth carrying to the py driver: the reach must be triggered
by **the grant landing**, not by the establishment poll. Sequenced after
`verified` it sits behind the initiator's own round trip, and we first saw it
fail as `no transport profile` — the §6.11 registration already torn down — which
reads like a resolution bug and is a lifetime bug.

**Where this is NOT.** Coordination-green is not transport-works. §11.5.1's S5
gate — two real browser peers establishing a real data channel over a real
signaling node — has not been run, and nothing in this arc moved it. The
browser leg is one box and it is `entity-browser-rust`'s.

The v1.x protocol cycle (Tier-2 dispatch-fallback to the byte-identical-envelope
bar, paired with the encrypted-relay boundary) is queued behind this and
unstarted.

### 2026-08-07 — obligation 5, and two bugs that were ours

**NETWORK §10.3 obligation 5 (single-flight establishment per peer) is built —
and it was NOT the no-op it was routed to us as.** `entity-browser-rust` found
the fan-in gap on the WebRTC leg (~470 deposits/side → 4) and arch folded it as a
general MUST; the baton note asked us to "confirm `EnsureConnected` is
single-flight, likely no-op." **Go had no fan-in gate at all.**
`getRemoteConnection` double-checked the pool only *after* dialing, and the §10.3
seam was consulted from three separate call sites downstream of it — so N
concurrent dispatches to one unpooled peer meant N coordination exchanges against
the shared node, each individually obligation-4-conformant. The exposure was
never about ICE; it is a property of the connection pool, not the transport.

Landed at `2c56da9`: one funnel (`establishRemote`) with the gate spanning **pool
check → dial → seam**, because gating only the dial leaves N callers to fan into
the seam the instant it fails. Waiters take the leader's result rather than
re-establishing; the leader drops the map entry on publish, so the gate is
bounded with no refcount. A pooled hit and §6.11 reentry reuse stay **outside**
the gate deliberately — reentry establishes nothing, and its bounded §6.5 (b)
grant wait would otherwise serialize concurrent originations. Six vectors in
`core/peer/single_flight_test.go`, all `-race` clean, including the
per-peer-not-global one that deadlocks if the gate is ever made global.

**The §11.5 deposit-bound teeth are adopted** (the cohort S5 item browser-rust
left to Go). `signaling_punch` counts offer deposits per side and FAILs above a
fixed O(1) bound of 8 **even when a channel opened**. Go measures **2/1 per
side** (node log corroborates: 3 `op=offer` total for one establishment) — below
browser-rust's ~4/side because TCP simultaneous-open has no ICE restart or glare
rollback. Fail path proven by driving the bound to 0.

**Then the cross-impl sweep found two bugs, both Go's** (`72001f5`). Four
descriptors had been reporting *"content hash mismatch with no structural
differences — likely a CBOR encoding edge"* against both siblings. There is no
encoding edge: `validate-peer`'s differ compared field **shape** only and never
compared `FieldSpec.Constraints`, which are part of the descriptor and its hash.
Our own oracle was telling the cohort to hunt an encoder bug that does not exist.
Fixing the differ then exposed the second: `OverrideField` replaces the whole
`FieldSpec`, and converge-request/reconcile-request `.type_paths` were registered
with `min_count(2)` and then re-overridden constraint-free — **Go declared a
constraint and published a descriptor without it.** Bug 2 hid bug 1, and no
Go-only run could have caught either; it took **py publishing the constraint Go
did not**. Two cross-impl divergences with py closed on our side; one *new*
warning against rust appeared because Go's bug had been masking rust's identical
gap.

**Cross-impl state, all figures from freshly-started peers:**

| Peer | Full profile | Excl. the Go-only signaling-node role |
|---|---|---|
| Go `72001f5` | **1406 P / 7 W / 0 F / 16 S** (baseline held) | — |
| rust `e17c2ad` | 1381 P / 19 W / 13 F / 16 S | **6 F** — all §6.7 `check-reachability` + its 2 descriptors |
| py `68c2faa` | 1376 P / 15 W / 22 F / 16 S | **15 F** — §6.7 both halves + 3 descriptors, and QUERY §5.5 grant narrowing |

Reports: `docs/validation/reports/2026-08-07-{obligation-5-single-flight-go-confirmed-and-gate-teeth,crossimpl-full-suite-rust,crossimpl-full-suite-py}.md`.
**py is not "unstarted" or far behind** — it trails rust by two well-defined
additive features, neither touching the wire core. V3 Go↔Rust carriage re-crossed
**6/6 cells both directions, reach 200**, against a `signaling-punch` rebuilt
from rust's own `dev` (the on-disk binary predated their `f227df8`).

**A harness finding worth acting on:** repeat validation runs against one live
peer degrade it. On py the **test count itself shrinks** (1429 → 1309 → 1136) as
categories bail; on Go elapsed climbs 8 s → 43 s over eight runs. A fresh peer
restores it exactly. **Every published figure must come from a freshly-started
peer** — every figure above does. One transient Go failure (run 4 of 8, `1405 P /
1 F`) was not captured before it stopped reproducing; recorded rather than
rounded away.

### 2026-08-07 (b) — core-rust reviewed the above and 16 of those failures were ours

**The sibling numbers in the section above are wrong and are superseded.**
core-rust caught `reachability_dialback_posture` asserting "nothing else is
conformant" besides 200/403 when **NETWORK §12.3 says a peer MAY offer
`observe-address`, `check-reachability`, both, or neither, and an unimplemented
response is fully conformant.** They were right, and checking whether it was one
check or a class found the larger instance: **SIGNALING §2.1 — "the server role
is OPTIONAL for a conformant implementation; the client role is the conformance
surface"** — while `signaling_authority` FAILed on 404 and cascaded 6 dependents.
Our own report called the node role optional *in prose while the tool emitted
FAIL*; the prose does not travel, the number does.

Fixed at `26c4332`: a §6.7 decline and a missing node role are now **SKIP** (not
Pass — nothing was exercised, and a 200 → 501 regression must not read as green);
every §6.7 MUST still binds a peer that answers (§12.1).

| Peer | Published | Corrected | Whose |
|---|---|---|---|
| rust | 13 F | **0 F** (`1393 P / 13 W / 0 F / 23 S`) | 7 ours, 6 rust's real gaps — **which rust closed** |
| py (tree unchanged — a pure oracle A/B) | 22 F | **13 F** (`1376 P / 15 W / 13 F / 25 S`) | all 9 ours |

**35 failures published, 16 of them this validator.** rust's `check-reachability`
now passes **on merit**, their six field constraints are adopted, and
`durability/result.handle` matches at `system/tree/path?` — we were right, they
corrected it. py's only *undisputed* remaining gap is the QUERY §5.5 grant
narrowing (6); the other 7 are the §6.7 type descriptors, pending the ruling
rust routed and we seconded at
`docs/validation/spec-issues/2026-08-07-are-optional-section-types-owed.md` — if
types follow their section, py drops to 6 F with no code change.

**The bias, named so it recurs less.** This validator encodes *Go's* reading, Go
implements both §6.7 ops and the node role, and a check written from a feature
you already have quietly promotes "I implement this" into "you must" — invisible
from our own seat because we pass it. Third oracle defect this cycle, and **all
three were found by a sibling disagreeing with us**, not by our tests. Rule going
forward: **a check may FAIL only on a MUST** — a SHOULD is a WARN, a MAY is a
PASS or SKIP — and a FAIL against a surface Go implements must cite the MUST in
its declaration string.

Correction report:
`docs/validation/reports/2026-08-07-b-correction-sixteen-of-those-failures-were-ours.md`.

### 2026-08-07 (c) — the suite was not validating the full system

Operator ruling, and it resets the bar: **this project implements everything.
There is no luxury of a MAY.** An unimplemented surface is an untested surface,
so optional-surface absence must never be waved through — it is a gap to close,
not an exemption to take. The `-allow-skip` invitations the (b) cycle put into
those messages are removed; the skips stay skips (honest: not exercised) and
still count toward the FAIL gate.

Auditing for other leaks found a much bigger one, and then its root cause.

**1. The default invocation never ran ~113 checks.** `validate-peer -addr <a>`
exercises **1429**; a fully-configured run exercises **1542**. The difference is
whole surfaces — the LOCAL-FILES round-trip and frame-budget chunking, the
published-root / manifest / HTTP-poll face, origination (the peer *dispatching*),
§7a concurrent-reentry, and the §5.4/§4.1 liveness+reconnect vectors — each gated
on a peer flag *and* a matching validator flag. Landed
**`scripts/validate-complete.sh`**, which configures every surface in one command,
plus a **COVERAGE** roll-up in the summary naming each unexercised surface and the
switch that closes it. The per-check gate was already honest; nothing told you
*what* never ran.

**2. Root cause of the "instability" — and (b)'s harness finding was misdiagnosed.**
`-timeout` defaulted to **60 s, less than a full run takes**. Past the window every
remaining category was recorded `budget_exhausted` and skipped, so a slower peer
tested *less* and printed a smaller total. That is the whole explanation for the
totals wandering (1542 / 1494 / 1443 / 1297) and for py's 1429 → 1309 → 1136 — **not**
peer state accumulation, which is what the (b) cycle published. Default raised to
10 minutes; `RuntimeBudgetMs` still warns on a slow run without dropping coverage.
Totals are now bit-stable across repeat runs. The py report's §5 carries the
correction.

**3. Two configuration findings the newly-run checks caught immediately.**
`--serve-namespace` alongside `--publish-root` is **non-conformant** — §6.5.6
Amendment 10 makes the closure of the signed root the serving floor once
`signed_pointer` is advertised, and trie nodes are hash-linked not path-bound
(V7 §1.7), so `v5_outbound_dial` and `v7_trie_closure_content_get` 404. And
Amendment 10 and the §6.5.6 **T4 out-of-scope** checks cannot both be satisfied by
one peer: closure scope leaves nothing out of scope to probe. That is a property
of the spec surfaces, not a Go defect — so the script runs **two passes**
(everything under `--serve-closure-root`, then `serving_mode` against a
namespace-scoped peer) and every check runs where it means something.

**Standing full-coverage result, reproducible and bit-stable:**

| Pass | Result |
|---|---|
| 1 — all surfaces, closure scope | **1489 total — 1480 P / 3 W / 0 F / 6 S** |
| 2 — `serving_mode`, namespace scope | **53 total — 53 P / 0 W / 0 F / 0 S** |
| **Union** | **1542 checks, 0 failures** |

The 7 registry failures seen mid-investigation were budget-exhaustion cascade, not
defects — they pass under the corrected timeout. **The one real remaining gap is
the 6 `peer_issued` wire vectors**, which need a fixture-pinned registry
(`--peer-issued-registry <pid>@<url>`); the backend is unit-tested in
`ext/registry/peerissued` (8 vectors) but the fixture wiring is the deferred
Keystone leg. That is now the only thing standing between us and a run that
exercises every surface — and it is named in COVERAGE on every run rather than
sitting silent.

### 2026-08-07 (d) — the signaling/network set is closed out

**The §6.7.5 gate has run** — the one arch records as *"a cross-impl reflect plus
a dial-back… has not run"* — and the Amendment 13 build-state note is stale twice
over. The **client-side srflx gatherer** is present in **both** Go
(`--reflector` → `punchwire.ObserveSRFLXFrom` → `signaling.DialReflector`) and
Rust, not "absent in every tree." But it had **never been exercised**: every V3
crossing this cohort published, including yesterday's 6/6, reported
`srflx_source: "bind"`. Built, then never put in the path — a capability that is
never exercised is indistinguishable from one that does not exist.

Now green, with a Go peer doubling as the reflector:

| Cell | Acceptor | Initiator | `srflx_source` | `reciprocal_reach_status` |
|---|---|---|---|---|
| Go↔Go | Go | Go | `reflector` both seats | **200** |
| B, B2 | Go | **Rust** | `reflector` both seats | **200** |
| A, A2 | **Rust** | Go | `reflector` both seats | **200** |

Corroborated at the reflector's vantage: **10 `op=observe-address` executes**
across five cells, two per cell. The full §6.7.1 → §6.7.3 → §7 chain runs end to
end and interoperates.

**Honest limit:** loopback, so observed == bind. The *mechanism* is proven; the
case it exists for — mapping differs from bind — still needs a real NAT. §6.7.5 is
**partially** discharged, not closed.

**What remains open in this set is one thing in three costumes: nobody has run it
across a real NAT.** The §6.7.5 dial-back half, the §10.3 seam gate (two NAT'd
peers, direct transport surviving idle), and §11.5.1 S5 (two real browsers) are
all blocked on the same missing infrastructure, not on any implementation's code.
That is cohort infrastructure and is the next thing worth building.

Everything else in the arc is landed: §4 node+client, §3 derivation/pool, §7
choreography + §7.4, §6.1 sealing (flag day closed, `VerifyRequire` default), §6.3
envelope, §6.5 (b) carriage (Go+Rust, 200 both directions incl. under
reflector-gathered srflx), §10.3 obligation 5, §11.5 teeth, §6.7.1/§6.7.2/§6.7.3.

Report:
`docs/validation/reports/2026-08-07-c-signaling-network-closeout-full-coverage.md`.

Superseded by 2026-08-07 (f) below — Track 2 is finished and the `serving_mode`
question is settled.

Superseded: `HANDOFF-2026-08-07-full-coverage-and-the-open-queue.md`. Its queue is
largely resolved — arch ruled all five open questions (`c78b3dc`), the 42 serving
failures were withdrawn as **our** harness defect, and the
`type/violation.kind` item in it was based on an inverted sentence (Go was never
the outlier). Real-NAT remains open and remains **infrastructure, not
implementation debt** — recorded as such in the spec now.

Current cross-impl state (oracle `2305008`, full coverage, both passes):
**Go 0 F / 6 S · rust 0 F / 40 S · py 8 F / 42 S**, pass 2 54/54 on all three.
Report: `docs/validation/reports/2026-08-07-e-remeasure-under-the-ruled-oracle.md`.
Superseded for Go by 2026-08-07 (f) — Go is now **0 F / 0 S**.

### 2026-08-07 (f) — Track 2 finished: Go is at ZERO SKIPS · and the `serving_mode` question is settled

**Go: 1539 total — 1537 P / 2 W / 0 F / 0 S**, pass 2 54/54. First peer in the
cohort at zero skips. Oracle `76b5a79`.

**1. The six `peer_issued` wire vectors now run against a live peer.** The
validator serves the `-wire` fixture bundle as a static peer-issued registry
(`-peer-issued-bundle` / `-peer-issued-addr`) and the target is started pinned
to it (`--peer-issued-registry`, now a `peer-manager` passthrough);
`validate-complete.sh` does all three steps. Report this as a **REGISTRY
conformance-completeness milestone, non-gating for S5** — it is a real cohort
first, and it is *not* an S5 or connectivity claim.

Two things the wire genuinely cannot see, handled rather than papered over:

- The meta-resolver advances past a backend that errors (§2.2) and **drops the
  reason**, so VERIFY-FAIL-1 / REVOKED-1 / EXPIRED-1 all surface the *same*
  status as a peer with no backend at all: `chain_exhausted`. Status alone
  would pass against a peer that never looked. So the fixture origin records
  every request and each vector asserts the **fetch pattern**. Proven by
  negative control: all six FAIL against an unpinned peer.
- OFFLINE-NOTFOUND-1's `neg_ttl` is backend-level and the chain loop discards
  it; the wire assertion is the surviving pair — the name does not resolve AND
  the fixture answered its by-name probe with a 404.

Found the honest way: **registering a backend is not the same as consulting
one.** With no `resolver-config` installed the §4 chain is empty and the pinned
registry is never dialed — the first armed run failed all six with "fixture saw
0 requests." The category now installs a chain naming only the fixture
registry, so a rejected name cannot be rescued by a second backend.

**2. `--publish-root` does NOT republish on rust or python — answer (a).** The
27+27 `serving_mode` skips were masking a real defect, and it is a bigger one
than the 42 we withdrew. Both siblings mint `system/peer/published-root` **once
at startup and never again**; a `tree:put` that changes the tree root triggers
no republish at 10 s or at **6 minutes**. Go republishes within seconds — the
control proving the harness detects one when it happens.

Timing-independent corroboration, so this is **not** a debounce: rust/py
manifests are 216 B with **no `predecessor`** while Go's is 263 B and carries
one; `published_root.seq` is `0` and stays `0`; rust's log shows a single mint,
`change=Created`, never `Updated`. Confounder ruled out — `seed_in_scope`
PASSes, so the binding landed and the root did change.

Why it bites: under §6.5.6 Amendment 10 the served closure tracks the *current*
`published-root.root_hash`, so a peer that advertises a signed root and never
republishes serves a closure **frozen at boot** — every entity written after
startup is permanently outside the served set. For a static-origin publisher,
that is a publisher that can never publish.

The 27 dependent checks stay **UNEXERCISED, not failed**: under a frozen
closure a 404 would be conformant and a 200 would not prove recomputation. The
finding is about the republish, not the serve. **Routed, not fixed from here.**

`--publish-root`'s own help text claimed *"Honored by all three impls"* without
qualification — corrected. That claim is what made "all three peers are
configured identically" look true while the behavior differed.

Report:
`docs/validation/reports/2026-08-07-f-publish-root-republish-contract-rust-py.md`.

**→ NEXT SESSION STARTS HERE:**
`docs/status/HANDOFF-2026-08-07-c-go-is-at-zero-and-the-rest-is-sibling-work.md`.
Superseded: `HANDOFF-2026-08-07-b-finish-track-2-then-kill-every-skip.md` (both
its jobs are done).

## Backlog

Ranked roughly by readiness to pick up.

**Tier-2 async delivery (next protocol cycle).**
- Implement the **dispatch-fallback seam** end to end. The seam is wired
  (`*peer.Peer` carries a `DispatchFallbackFunc`, consulted at the remote-EXECUTE
  caller that holds both `peer_id` and the EXECUTE envelope — not inside
  connection resolution) and the happy-path build-test passes (sender →
  inbox-relay store-and-forward → offline target polls on reconnect → verifies
  the sender signature exactly as a direct dispatch would). The remaining work
  is the v1.x cycle: prove the **byte-identical-envelope** guarantee (a peer
  with the seam unset is byte-for-byte identical to one without it) and pair the
  implementation with encryption at the encrypted-relay boundary.

**Encryption beyond the first block.**
- ENCRYPTION v1.0 self/peer/group end-to-end is landed with byte-pinned
  known-answer tests. The forward work is the **encrypted-inner-over-relay**
  case (gift-wrap / WRAP model for the relay path, with the inside-envelope
  form retained for at-rest `self` mode) and continuing the cohort's
  follow-on findings to a full cross-impl close.

**Routing / reachability (parked until there's a driver).**
- **ROUTE auto-population (GOSSIP / adaptive routing).** Storage plane is green;
  tables are hand-populated today, which already expresses the VPN/gateway
  case correctly (`system/route` entry with `action="forward", via=<gateway>`).
  Adaptive multi-hop convergence (anti-entropy gossip is the natural fit) is
  deferred until a real adaptive-routing need appears.
- ~~**NAT traversal.** Proposal-grade analysis exists; it is Tier-3 territory
  and deferred.~~ **Superseded** — EXTENSION-SIGNALING §7 is implemented and
  wired (see "Where we left off"). What remains unproven is traversal under
  REAL NAT: the punch is validated on loopback, which has no mapping to punch,
  so both-fire correctness is asserted at the `DialFunc` seam rather than
  observed. That is the §7.5-class gate and it has not been run.

**Demos / reach (stretch).**
- **Phone-browser → desktop-native (WebSocket) demo.** The transport substrate
  is in place on Go; the remaining piece is a minimal HTML page that dials the
  `ws://` endpoint. Stretch goal, downstream of the substrate.
- **Browser ↔ browser (WebRTC).** No longer deferred and no longer Go's:
  the signaling substrate is built (that was the blocker), and the browser leg
  is `entity-core-rust`'s wasm32 transport (S3) → `entity-browser-rust` (S4) →
  S5. Go's part is the §6.5 coordination rules as a second independent
  implementation of the conventions, which is done.

**Cross-impl conformance & quality.**
- **Published-root §6.5.6 convergence: validate Rust and Python under starvation
  (pick up after the py/rust release cut).** Go carried a scheduling race in the
  undebounced publisher — one goroutine per tracked-root advance, each with a
  CAPTURED root hash, so under CPU contention a late goroutine could publish a
  STALE root last and strand the published root behind the tracked root (a
  §6.5.6 convergence failure). It is fixed: the undebounced path now routes
  every advance through a single newest-wins coalescing slot (see
  `ext/publishedroot.Publisher` `dirty` / `publishPending`), with deterministic
  teeth `TestOnTreeChangeRecordsNewestInSlot` and a general scheduling-race net
  `make test-starved`. The sibling question is open and worth a measured answer,
  not an inference: **Python looks structurally immune** (boolean `_dirty` +
  live-root read on a single-threaded asyncio loop), but **Rust's
  `core/peer/src/published_root.rs` `guarded_publish` DROPS a concurrent
  republish with no `dirty`/`pending` recovery slot** — structurally the
  pre-drain-fix "dropped tail" shape Go already fixed, so it is the one to
  probe. Deliverable: a burst-then-stop convergence stress under
  `GOMAXPROCS`-starvation (or `--cpus<1`) against live rust + py peers, checking
  the published root actually catches up to the tracked root, written up as
  dated per-peer reports under `docs/validation/reports/`. Do NOT root-cause a
  sibling's internals — measure, report, route. Full account: the
  `test-starved` candidate discipline in `AGENTS.md`.
- Stand up dated, oracle-pinned **per-peer conformance reports** for the Rust
  and Python implementations (the local `docs/validation/` reporting tier is
  not part of the published surface yet). Every published number must be
  reproducible and oracle-pinned (P/W/F/S breakdown, not a bare percentage).
- **Expand the behavioral wire harness.** Some v3.3 conformance vectors
  (transitive supersession / predecessor revival) already drive over the wire;
  the remaining v3.3 vectors run only as in-process unit tests. Promoting them
  to wire-driven cohort vectors is optional follow-up.

**Exploratory (not on any critical path).**
- EXTENSION-DURABILITY is implemented only as a reference surface — exploratory
  / optional, absence is conformant, no deployment depends on it.

## Waiting on

- **Spec (upstream).** The canonical protocol spec is owned by the architecture
  repo; normative/protocol changes flow from there. Implementations implement
  the landed spec and route gaps/ambiguities upstream rather than inventing wire
  shapes locally.
- **Sibling implementations present on disk.** Cross-impl interop validation
  (`make validate-rust` / `make validate-python`, the convergence harness)
  drives live peers and needs the Rust and Python repos available alongside
  this one.

## Done recently

- **`HASH_TYPE=sha384` is a GATE, not a diagnostic** (go peer). Arch ruled both
  blocking gaps on 2026-08-10 — NETWORK §6.5.3.1's hex length follows its own
  format byte, SIGNALING §6.3 drops the fixed-33 on `inner_content_hash` — and
  both landed with the three validator SHA-256 assumptions sequenced behind
  them. **1566 · 0F · 0S / 55 / 12, identical under both content_hash_formats.**
  Still a diagnostic against rust, which has not landed the width ruling (rust
  `b8e0ae2`: `content/{hex33}` route, `hex.len() != 66` in the FFI parse).
- **Two validation categories were never reachable, and one was failing.**
  `peer_id_form` (4) and `policy_dual_form` (5) were registered, dispatchable
  and advertised, and never called by the full run — nine checks outside every
  number this repo has published, with one FAILING under SHA-384 throughout.
  Now wired in, and the class is a test
  (`TestEveryCategoryIsReachableFromARun`) rather than a discipline, per
  GUIDE-CONFORMANCE §5.2b. It found two further categories, both genuine and
  both now declared exclusions. This is why the gate moved 1557 → 1566.
- **The `--open-access` + `--issuer-policy-mode` footgun is closed.** A policy
  entry is a request-time ceiling (V7 v7.62 §4), so two flags that each grant
  combined to grant less than either alone. `entity-peer` unions them, guarded
  by a monotonicity test; one peer with both flags now scores capability 13/13,
  authz 11/11, registry_issuer 12/12.
- **EXTENSION-SIGNALING §4 node + client, §3 keys/pool, §7 punch**, wired to a
  live peer via `ext/signaling/peerwiring` behind NETWORK §10.3's
  `establish_live` seam. Validated over a live node (`signaling_punch`
  category) and Go↔Go end to end on loopback.
- **§6.5 WebRTC coordination rules** — the offerer/glare resolution, session
  correlation, the trickle-settled gate, and the channel-identity guard, as a
  second independent implementation of conventions the S5 gate cannot validate
  (two browser peers likely run the SAME WebRTC stack). Coordination crossed
  both ways with rust at `21·0F`/`23·0F`.
- **§6.3 coordination envelope — built, crossed both ways, FOLDED into the
  spec** (arch `b99304d`). Go `38·0F` verified by rust, rust `36·0F` verified
  by us. Two blocking corrections this repo raised are in the normative text:
  the peer-id is derived-and-compared in full (a wire `signer` is forgeable,
  and a non-canonical `hash_type` would let one key present two ids and choose
  its own glare role), and the two hash axes are distinguished.
- **The §6.1 flag day, Go's half** — §6.3 step 3 wired into the read path (it
  can only live where the claim is known, which is why the API had no caller
  and the gap survived the crossing), skip-own moved onto the verified signer,
  and all three §6.1 deposits sealed as bucket-bound containers. `SelfID` is
  gone: the party derives its id from the key it signs with, so the id/key skew
  rust refuses at runtime is unrepresentable here. Vector file re-emitted at
  `42·0F @ 204e1d9` with four §6.1 rows, closing the same-side-tested limit
  rust flagged on their own read side.
- **v0.8.0 initial public research-preview** — first public release, tagged.
- **Network/relay release-readiness milestone closed.** Relay substrate (single-
  hop, source-routed multi-hop, Mode-S queued fallback, Mode-F over any
  transport) plus the ROUTE storage plane green three-way; publish→fetch end-to-
  end over `http-poll` (the Tier-1 publish gate) closed three-way, with a
  cross-impl wire-drive of Go-publish → Rust/Python-consume confirming byte-equal
  contract over real HTTP; the HTTP-transport relay coverage gate closed
  three-way after the Python `send_raw_frame` substrate gap was filled.
- **WebSocket transport on Go.** Ships a `-ws-addr` listener + outbound dialer
  (via `coder/websocket`); Go-self three-way green and a Go→Go(WS)→Rust(WS)
  terminal-hop leg byte-equal cross-impl. Unblocks the phone-browser →
  desktop-native (M2) demo substrate.
- **ENCRYPTION v1.0 (first block).** self / peer / group end-to-end with
  byte-pinned KATs; registered as a validation category; cohort wire surface
  brought to three-way green.
- **Peer-issued registry path.** Live registration (replay defense + peer-id
  allowlist) plus a self-verified fixture bundle (resolve / expired / revoked /
  precede / verify-fail / offline-not-found vectors).
- **Containerized bare-box build.** `make` + `podman` build/test/vet/race with
  the repo mounted directly, per-invocation memory/CPU/pids caps, Go 1.25, and
  vanity module paths (`go.entitychurch.org/entity-core-go/{core,ext,cmd}`);
  `peer-manager` launches Rust/Python peers via podman to match.

## Next

1. ~~**Close the §6.1 flag day.**~~ **DONE** — both impls seal, read, and now
   refuse. Nothing in the signaling security arc is open on either side.
2. **Cross-verify the §6.1 rows.** Crossed one way: rust reads our file at
   `42·0F`. We read theirs at `40·1W·0F` — their false-claim row's payload
   names its own signer, so only the row field is false and the row cannot
   catch a read path with step 3 unwired on the payload side. Routed; one
   field on their end closes it.
3. ~~**Two real machines.**~~ **PARTLY DONE, and the rest is lead time.** This
   item asserted that "the §7.5 emulated-NAT rung and §11.5.1's S5 are both
   unrun." **The emulated rung (G3) ran on 2026-08-08 and closed 12/12 across
   3 rungs, gate 6/6**, retiring the loopback-blindness class for the punch.
   *(Left visible rather than edited away: a durable doc asserting an unrun
   gate that has since run and passed is the stale-build-state defect this
   repo keeps catching in other people's text — worth one instance of catching
   it in our own.)* What remains is **G4** (two real independent NATs, for NAT
   diversity) and **S5** (two real browsers). Python's punch is queued behind
   neither and is python's to build.
4. ~~**Close ENCRYPTION v1.0.**~~ **DONE.** `ENC-ROUNDTRIP-FORMAT-1` landed and
   the §16 vector set is closed; encryption is 22 · 0F · 0S under both
   content_hash_formats. `ENC-PEER-KAT-2` is the hybrid-PQ slot §16 itself marks
   *"validate slot, no impl required v1."*

**The live work list is arch's 2026-08-10 answer packet (arch `ed3de7a`), and
all four items are shovel-ready** — full scoping, call-site surveys and ordering
in `HANDOFF-2026-08-10-c-arch-answered-everything-and-four-items-are-shovel-ready.md`:

5. **Cut `system/inbox/delivery`.** Arch granted the sequencing; Go's half is one
   constant (`core/types/delivery.go:14`) plus three comments. The MUST is that
   the cohort not be left half-cut, so say so when we cut.
6. **`{peer_id_hex}` must pin to the SHA-256 floor** — the one place we are
   non-conformant under the new `SPECIFICATION-FORMAT` §8.4.6 derive-to-meet
   rule. `types.ComputePeerIdentityHash` follows the home format today;
   `PeerData.ToEntity()` must keep it. `prefix_hash` and the rendezvous key
   already match.
7. **REGISTRY §6a.9.2** — build `set-issuer-policy` / `get-issuer-policy`
   (replace-whole, 404-on-unset, `domain-control` → 400), and convert
   `--issuer-policy-mode` from a request-time fallback into a startup **seed of
   the policy entity**, which store-first-as-a-MUST now requires.
8. **The mixed-home probe.** Unblocked and explicitly not urgent, but it is the
   only thing that can *prove* §8.4.6 rather than assert it: every
   `HASH_TYPE=sha384` run to date sets every peer to SHA-384, so the cross-peer
   seam where the rule bites has never been exercised.

9. Open the v1.x cycle: implement Tier-2 dispatch-fallback to the
   byte-identical-envelope bar, paired with the encrypted-relay boundary, and
   stand up dated, oracle-pinned cross-impl conformance reports for Rust and
   Python once the sibling repos are available.

**The honesty line, unchanged.** No number in this document is a WebRTC
transport claim. Coordination-green means two implementations agree about
coordination bytes; §11.5.1's S5 — two real browser peers, a real data channel,
a real signaling node — remains the only evidence that the browser leg works,
and it has not been run.
