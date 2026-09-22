# Changelog

All notable changes to this project are documented here.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project aims to follow [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

A **tag is a release** ([ADR-0015]) — a docs or `AGENTS.md` change does not get
one. Conformance, not the version number, is the contract ([ADR-0012]): every
number below is pinned to the commit it was measured at.

## Versioning — three numbers, three jobs

Read this before writing a version anywhere in this repo.

| Number | What it is | Where it lives |
|---|---|---|
| **`0.y.z`** | **This module's own release.** 3-field SemVer, forward-only from the published `v0.8.0`. | the git tag, the headings below, `ext/go.mod`, `cmd/go.mod`, README §Module paths |
| **`v7.NN`** | **The protocol revision we implement.** Carried out-of-band, never in the version. | README, `--profile core`, flag help, `docs/STATUS.md` |
| **`N · 0F · 0S · 0W @ <commit>`** | **What we measured.** Conformance is the contract, not the version ([ADR-0012]). | `docs/STATUS.md`, README |

[ADR-0002] (accepted ecosystem-wide 2026-06-16) chose 3-field SemVer and put the
spec/conformance level out-of-band **specifically so these cannot be conflated**:
a version that encodes the spec level confuses *which spec level an implementation
targets* with *the implementation's own release*. So:

- **We do not adopt another repo's number.** `entity-core-protocol` cuts its own
  releases; those are the spec's version, not ours. Our repos share a fleet cut
  *date*, not a fleet *number*, and the numbers are expected to diverge.
- **There is no 4th digit.** Go enforces this for us — the module resolver parses
  `vMAJOR.MINOR.PATCH` and nothing else, so `v0.8.2.1` is not a resolvable module
  version at all.
- **A cut is one edit across every site**, because a `replace` hides a stale
  `require` from us and from nobody else: an external consumer resolves
  `.../cmd@vX` and gets its `require` lines *without* its `replace` lines, so a
  `cmd` cut that still requires the previous `core` publishes a build that only
  works inside this workspace. `cmd/internal/hygiene/version_test.go` gates both
  halves — the SemVer shape, and lockstep between the newest heading here and
  every module declaration.

**Why each cut picked its field, on the record rather than in someone's head.**
Pre-1.0 SemVer puts breaking changes in the MINOR field, so every release so far
has moved the MINOR: `0.9.0` because the §5.4 matcher stopped self-matching a bare
prefix, `assoc` began answering `index_out_of_range` where it answered
`type_mismatch`, `fold` gained an error accumulator instead of short-circuiting,
the default per-handler self-grant widened to the peer-wildcard form, and `ext/`
grew from 8 packages to 28; `0.10.0` for the reasons its own section states.
A PATCH would claim backward-compatible fixes only, which in both cases is false.
(`entity-core-py` independently reached `0.9.0` for an unrelated reason — a fourth
workspace package. Same number, different derivation; do not read either as a
fleet version. The fleet shares a cut **date**, never a number.)

## [Unreleased]

Development lands on `dev`; `master` carries the last release.

## [0.10.0] — 2026-09-20

_Protocol: Entity Core Protocol **V7**, carried out-of-band per [ADR-0002]. The
revision each claim was measured against is named at its own site. Conformance
gate green at `1666 · 0F · 0S · 0W` over 68 categories, measured 2026-09-15._

**A MINOR, not a patch.** Pre-1.0 SemVer puts breaking changes in the MINOR field,
and this span moved error codes, statuses and authorization outcomes that an
existing caller can observe. *Breaking* is measured against what this project
promises to keep: **the wire** — the status and error code a peer emits for a
given request, and whether that request is admitted at all — and **the exported
Go API of `core` and `ext`**. Internal packages, log prose, and the validator's
own output shapes are outside that line.

### Changed in ways that can break an existing caller

- **A registered handler that does not implement the named operation answers
  `501 unsupported_operation`, not `400 unknown_operation`**
  (`ENTITY-CORE-PROTOCOL` §3.3 / §6.2). `unknown_operation` is retired as a
  synonym that MUST NOT be emitted, and the sweep covered all 26 emit sites: the
  25 handler `default:` arms across `core/tree` and `ext/*`, plus the connect
  path, where an unrecognized connect operation is §4.7's `400 invalid_request`
  rather than the 501 case. A client branching on that pair sees neither the
  status nor the code it used to. The spelling is now absent from the tree.
- **`system/tree:put` error codes moved to EXTENSION-TREE Appendix A.** `put`
  answered `400 invalid_entity` — a code defined in no specification — at both
  its decode and its validate site. The validate site now branches, because
  `Validate` checks empty type/data before the hash: a decode failure or a
  structural defect is `400 invalid_request`, a content-hash mismatch is
  `400 hash_mismatch`. The 409 CAS-race `hash_mismatch` rows were already
  conformant and are untouched.
- **`system/tree:put` rejects an absent `content_hash` as `400 invalid_request`,
  not `400 hash_mismatch`** (EXTENSION-TREE Appendix A `put` row 1, v4.5;
  `ENTITY-NATIVE-TYPE-SYSTEM` §8.1 — content_hash is a required field of
  `core/entity`). An absent required field is a structural defect decided in
  step 1 of the §6.3 admission ladder, ahead of the step-2 hash-value compare;
  a present-but-mismatching hash stays `hash_mismatch`. Previously go conflated
  the two (both `hash_mismatch`). `put` is a receipt path: the hash is authored
  by the SDK, never by the peer.
- **`system/tree:put` answers a `content_hash` naming an unsupported format code
  with `400 unsupported_content_hash_format`, not `400 invalid_request`**
  (EXTENSION-TREE Appendix A `put` row 4, v4.5; `ENTITY-CORE-PROTOCOL` §4.7 row 5
  / §1.2 ingest-dispatch). A well-formed hash byte string the peer cannot verify
  by format is distinct from a structurally-malformed one; a mis-sized hash under
  a *known* format stays `invalid_request`. Previously go flattened the
  unknown-format decode error into `invalid_request`.
- **A grant-exclude that cannot match anything now excludes everything, and a
  capability carrying an unmatchable scope pattern is refused as invalid.** The
  never-match sentinel is directional: fail-closed in an include (covers nothing)
  but fail-**open** in an exclude (carves out nothing), which made a grant
  silently wider than its author wrote. Evaluation now denies; authoring and
  verification refuse — `400 invalid_path` at
  `system/capability:{request,delegate}` (§6.2), `capability_denied` at chain
  verification (§5.5). A request such a capability used to authorize is now
  refused, and the capability itself no longer mints.
- **An outbound sub-dispatch is authorized before it leaves the peer (§5.2).**
  A handler dispatching to a foreign peer must now present a capability rooted at
  that target, or hold a grant whose **peers** scope covers it; with neither, the
  dispatch is `403` instead of going out. The peers dimension was not previously
  enforced on this path, so a handler that reached a foreign peer on ambient
  authority alone stops doing so. `operations` and `peers` are matched as
  id-scopes — literally, bare `*` and trailing `/*` — never through the §5.4 path
  matcher.
- **An advertised served scope names `/*/*` on its resources axis, not a bare
  `*`.** Canonicalization (§5.5) resolves a bare `*` to the local namespace only,
  so as the parent of the advertisement subset check it **dropped** — not narrowed
  — any grant whose resource names a foreign namespace, meaning an operator
  widening a grant silently deleted it. Advertisements a consumer has pinned will
  differ. `operations` stays bare `*`; it is not a path axis. A declared
  `MaxScope` is untouched.
- **A peers pattern is canonicalized at comparison, and an unresolvable exclude
  fails closed** (rule 4). Previously an exclude that could not be resolved was
  ignored, so a child grant could widen the peers it applies to past its parent's.
- **A malformed frame gets a coded error on the wire before the connection
  closes, and a whole-decoded refusal keeps the connection open** (§4.11). A peer
  used to answer an undecodable frame, or one that is not a recognized message
  type, by simply hanging up — indistinguishable from the network failing, and
  destructive of the unrelated requests multiplexed on the same connection. It
  now answers `400 invalid_request` first, and where the frame decoded whole it
  keeps serving. A caller that treated a silent hang-up as the signal must read
  the error instead. A genuine network drop — a reset, a broken pipe, a timeout —
  is told apart from a malformed frame and stays silent, rather than blaming the
  caller for the network.
- **A read that excludes exactly the path it named is refused, not answered with
  everything.** `system/tree:get` in its widest listing form now returns
  `400 path_required` for a request that resolves to nothing, matching the
  disposition the two narrower read operations already drew; it previously
  exported every entity in the tree. A malformed entry anywhere in
  `extract.paths[]` is `400 invalid_path` for the **whole** request, validated
  before any read, rather than being skipped per entry.
- **Connect-handshake refusals were brought to §4.6 / §4.7.** An absent or empty
  `protocols` list is `400 invalid_request`; a `peer_id` that does not equal the
  authenticated identity is refused; out-of-order handshake messages answer `409`;
  a non-connect operation before the handshake completes is
  `401 authentication_failed`. Each of these answered differently before.
- **`system/handlers:{register,unregister}` with an absent resource is
  `400 path_required`, and the reservation refusing registration under `system/*`
  is withdrawn** — a registration the peer used to reject now succeeds.
- **A frame carrying a CBOR tag at any depth is refused at the receive
  boundary** (`ENTITY-CBOR-ENCODING` §6.3 — tags are non-canonical in ECF and
  MUST NOT be accepted, forwarded, or silently stripped). Such a frame used to be
  admitted: the package decoder runs with tags allowed, an entity's `data` is
  held raw to preserve byte fidelity for hashing, and a tagged entity
  self-verifies because the sender hashed the same tagged bytes — so nothing
  short of an explicit walk could see it. `Envelope.ValidateAll` now walks every
  `data` field, including nested ones, and rejects definite- and
  indefinite-length non-canonical items alike.
- **`capability.IsAttenuated` takes a fifth parameter**, `localPeerID
  crypto.PeerID`, required to canonicalize a peers-scope pattern at the point of
  comparison. This is a compile break for an external caller; it is the only
  exported signature in `core`/`ext` that changed.
- **`history` `max_depth` no longer prunes, and is documented RESERVED.** It
  enforced nothing: prune walked head→`max_depth` and returned without mutating,
  so the head still reached every transition, and there is no garbage collector
  anywhere in the cohort to reclaim an unlinked tail. The walk — an
  `O(max_depth)` content-store read after every recorded write, achieving nothing
  — is removed, and the field's type doc says it is not enforced, so nothing
  sizes a retention plan against it as a guarantee. A caller that believed it
  bounded a chain never had that bound; a real bound needs a rewrite cascade, a
  head-side counter, a segmented chain or a reclaim pass, and that design call is
  deferred rather than invented.

### Added

- **The §4.11 pre-admission refusal conformance class**, five arms driven over
  raw sockets, including the one the specification calls out as never previously
  exercised: a garbled frame arriving on a connection already carrying an active
  request must not disturb it, and the connection must keep serving new work
  afterward. Every arm is mutation-verified — reverting to the old bare hang-up
  turns it red.
- **An entity resolved by hash from a wire-supplied `included` map has its map
  key bound to its recomputed content hash at the trust boundary.** Self
  consistency is not that binding, and its absence was a capability/identity
  forgery. Closed at the boundary, not per call site.
- **`Connection.IsOutbound()` / `Connection.Direction()`** — connection direction
  is now observable rather than inferred.
- **`peerissued.NormalizeName`** is exported as a cross-implementation contract,
  so the name a registry issues normalizes identically in every implementation.
- **Relay §8 store bounds (EXTENSION-RELAY v1.3)** — the retention clamp (§8.1)
  and storage refusal (§8.2), `expires_at` on forward-request clamped on the
  §6.2.1 fallback, and a self-advertise seam that publishes the bounds so a peer
  can see them before it relies on them.
- **Peer-wiring advertisement** (`ext/relay/peerwiring`) and maintain-peer
  relationship existence derived from the tree rather than a process-scoped map,
  so it survives a restart.
- **`corpus-sig-verify`** — a standing verifier for the ECF conformance signature
  vectors, which were recomputed under the §7.3 rules.
- **The validation suite is 68 categories**, up from 66, adding the exclude
  matrix, effective-resource, resolution-integrity, serving-capability-scope,
  origination, connect-error and `tree:put` error-code families. `-list-categories`
  prints the live set.

### Fixed

- **A published root recovers rather than stalling**: local-files rehydration
  restarts, the loop guard keys on content rather than a clock, and watcher
  liveness is a fact in the tree instead of process state.
- **The last-burst write loss was a stale tracked-root read, not the CAS loop** —
  auto-versioning re-reads the tracked root inside the loop.
- **A chain-error lost marker carries its `TargetPeerID`**, and a subscription
  binder reaps itself; a pull failure carries the downstream error code on its
  `502` rather than flattening it.
- **A remote denial-of-service in the store-path boundary** — the path check is
  total, not an assert.

## [0.9.0] — 2026-08-24

_Protocol: Entity Core Protocol **V7**, carried out-of-band per [ADR-0002]. The
revision each claim was measured against is named at its own site — README
(`--profile core`, V7 §9.0 as folded at v7.75), `docs/STATUS.md`, and the
entries below._

Highlights since `v0.8.0`, all measured in-tree:

- **Published-root convergence holds under load (§6.5.6).** The undebounced
  publisher spawned one goroutine per tracked-root advance, each carrying a
  captured root hash; under CPU contention a late goroutine could publish a
  **stale** root last, leaving the published root behind the tracked root
  indefinitely — a convergence failure, not a slow one (the tell was
  `seq > writes` with `converged=false`: work done, wrong root landed). Fixed by
  routing every advance through a single newest-wins coalescing slot, the same
  path the debounced mode always used. `TestRepublishConvergenceUndebounced`
  now converges in ~1 ms at `GOMAXPROCS=1` (0/8 failures, was reproducible ~3/8
  before); `TestOnTreeChangeRecordsNewestInSlot` pins the invariant
  deterministically; race-clean. Measured 2026-08-24.
- **Compute budget: the `depth` limit is honored end-to-end (§5.2).** The eval
  depth limit is sourced from the capability's **grant-level**
  `constraints["system/compute"]["max_compute_depth"]` (ENTITY-CORE-PROTOCOL §5),
  not the token top level and not a param — the reader was corrected, and the
  compute-corpus wire driver now transmits it through a constraint-bearing
  capability. Result: the 362-vector compute corpus **LOCKs 362/362** go-in-process
  vs go-over-wire (the depth-sensitive vectors `cv9a-map-depth-exceeded-contains`
  and `recurse/tail-sum` previously forked at the peer default depth). Spec-issue
  `2026-08-22-a` routes the §5.2 pseudocode wording upstream. Measured @ `0e34e3e`.
- **Conformance gate at 1572 · 0F · 0S · 0W** across six passes — four scoring
  passes (all surfaces, core profile, `serving_mode`, `registry_issuer`) behind
  two static peer-free ones that fail fast (the v767 corpus, and the conformance
  register ratchet). Reproduces identically under the non-floor `sha384` home
  format. Measured 2026-08-13.
- **`conformance-register`**: emits the conformance category register — every
  check the oracle declares, its citation, its profile membership, whether it
  contacts the peer at all, and which tier its requirement lives in — resolving
  each citation against the live spec trees. 1165 checks across 66 categories.
  `-boundary` reports the adoption line: the core floor binds every peer, an
  extension is adopted and its absence is a SKIP, never a FAIL.
- **`corpus-check`**: one contract over every conformance corpus — the committed
  artifact matches its pinned sha, the committed source still re-encodes to it,
  and multiple copies agree byte for byte. Replaces a per-corpus process under
  which the 71-vector ECF corpus had neither assertion.
- **`ext/` grown to 28 system extensions**, including `attestation`, `compute`,
  `continuation`, `network`, `quorum`, `registry`, `relay`, `revision`,
  `signaling`, and the storage-substitute pair.
- **Cross-implementation validation tooling**: `validate-peer` — 66 categories
  at `3cfec93` (`-list-categories` prints the live set), core/full profiles,
  JSON output — plus `peer-manager` (orchestrates Go, Rust, and Python peers,
  the latter two containerized) and the six-pass
  `scripts/validate-complete.sh` gate.
- **Local-files containment hardened** — the §8.3 rule has three parts and the
  spec enumerated two; the component-boundary defense is now implemented and
  regression-tested, and the spec gained vector `LF-CONTAIN-BOUNDARY-1`.
- **v767 conformance corpus tooling**: `agility-corpus-verify` and
  `agility-corpus-build`, the latter self-checked by re-encoding an already-pinned
  artifact byte-for-byte before it is trusted to write one.

## [0.8.0] — 2026-06-21

- Initial public research-preview release.
