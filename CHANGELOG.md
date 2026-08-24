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

**The next cut is `0.9.0`**, and the reasoning belongs on the record rather than in
someone's head. Pre-1.0 SemVer puts breaking changes in the MINOR field, and the
work below is breaking for a consumer of `core`/`ext`: the §5.4 matcher no longer
self-matches a bare prefix, `assoc` answers `index_out_of_range` where it answered
`type_mismatch`, `fold` contains an error accumulator instead of short-circuiting,
the default per-handler self-grant widened to the peer-wildcard form, and `ext/`
grew from 8 packages to 28. `0.8.1` would claim backward-compatible fixes only,
which is false. (`entity-core-py` independently reached `0.9.0` for an unrelated
reason — a fourth workspace package. Same number, different derivation; do not
read it as a fleet version.)

## [Unreleased]

Development lands on `dev`; `master` carries the last release. **Will be cut as
`0.9.0`** — see Versioning above. Highlights since `v0.8.0`, all measured in-tree:

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
