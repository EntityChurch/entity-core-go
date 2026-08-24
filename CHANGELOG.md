# Changelog

All notable changes to this project are documented here.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project aims to follow [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

A **tag is a release** ([ADR-0015]) — a docs or `AGENTS.md` change does not get
one. Conformance, not the version number, is the contract ([ADR-0012]): every
number below is pinned to the commit it was measured at.

## [Unreleased]

Development lands on `dev`; `master` carries the last release. Highlights since
`v0.8.0`, all measured in-tree:

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
