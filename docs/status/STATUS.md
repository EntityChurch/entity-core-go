# entity-core-go — status

_Updated: 2026-08-07 · public: v0.8.0 (master)_

## Where it is

Go reference implementation of the Entity Core Protocol v7 — the third
ground-up reference implementation (after Python and Rust), and the project's
SDK prototype + interop oracle. Because Go **leads on new protocol features**,
cross-implementation convergence is downstream feedback here, not a gate, and
the other implementations validate against this one as the interop baseline.
The codebase is a three-module `go.work` workspace — `core` (the protocol
library, a strict 14-package DAG: `errors → ecf → hash → entity, crypto,
store, types, wire → capability → handler → protocol, tree → peer`), `ext`
(system extensions, each depending only on `core`), and `cmd` (CLIs, the
~60-category validation suite, and cross-impl interop tooling). Go 1.25, only
two external dependencies (`fxamacker/cbor` for ECF, `mr-tron/base58` for
PeerID), pure-Go/no-CGo. The build is fully containerized (`make` + `podman`,
per-invocation resource caps in the `Makefile` / `RESOURCE-CAPS.md`); a fresh
clone with no sibling repos present builds and tests standalone. Maturity:
**v0.8.0 research-preview** — publicly released and tagged. The extension
surface is broad and landed: `inbox`, `subscription`, `continuation`,
`revision`, `role`, `type` (+`constraint`), `localfiles`, `content`,
`identity`/`attestation`/`quorum`, `registry`, `relay`, `discovery`,
`publishedroot`, `encryption`, `compute`, plus the HTTP storage-substitute and
live-HTTP transport surfaces.

## Where we left off

**The connectivity cycle — EXTENSION-SIGNALING — is the live work**, and has
been since early July. It is a cohort effort with `entity-core-rust`,
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
3. **Two real machines.** This is the gap that matters and it is not blocked
   on code. Everything above is loopback, where there is no NAT to punch —
   so both implementations agreeing proves they wrote the same code, not that
   traversal works. The §7.5 emulated-NAT rung and §11.5.1's S5 are both
   unrun, and Python catching up to the punch is queued behind neither.
3. Open the v1.x cycle: implement Tier-2 dispatch-fallback to the
   byte-identical-envelope bar, paired with the encrypted-relay boundary, and
   stand up dated, oracle-pinned cross-impl conformance reports for Rust and
   Python once the sibling repos are available.

**The honesty line, unchanged.** No number in this document is a WebRTC
transport claim. Coordination-green means two implementations agree about
coordination bytes; §11.5.1's S5 — two real browser peers, a real data channel,
a real signaling node — remains the only evidence that the browser leg works,
and it has not been run.
