# `cmd/` — CLIs, validation suite, and interop tooling

The `cmd` module (`go.entitychurch.org/entity-core-go/cmd`) holds every
executable in this repo: the peer server, the conformance validator, the
process manager, and a long tail of diagnostic, fixture, and interop tools.

Run any tool with `go run ./cmd/<name> [flags]`, or build them all into
`/out` with `make build`. The tools split into the groups below.

`cmd/internal/` is shared, non-importable library code:
- `internal/validate/` — the validation suite (all categories) + `PeerClient`.
- `internal/interop/` — cross-implementation interop tests.
- `internal/config/` — identity, grant, and config loading.

`cmd/internal/` also holds two conformance-harness binaries (`package main`, run with `go run`):
- `internal/wire-conformance/` — the ECF corpus pipeline (`.diag → .cbor → per-impl emit → cross-bless`).
- `internal/compute-corpus/` — the compute differential corpus (GUIDE-CONFORMANCE §7c); see its README.

---

## Peer + operations

| Tool | Purpose |
|------|---------|
| **entity-peer** | The peer server. Wires `core` + every `ext` handler and listens for EXECUTE traffic (TCP, plus optional HTTP-live, WebSocket, and HTTP-poll serving listeners). The thing you actually run to be a peer. |
| **peer-manager** | Start/stop/list managed peers — Go (host build), Rust + Python (podman images via their `make build`). The orchestration layer the validation scripts drive. See `peer-manager` help for the full flag set. |

```bash
go run ./cmd/entity-peer -addr :9002 --name my-peer --debug
go run ./cmd/peer-manager start --name p1 --type go --debug
go run ./cmd/peer-manager start --name p2 --type rust          # podman container
go run ./cmd/peer-manager list
go run ./cmd/peer-manager stop --all
```

## Conformance & interop validation

| Tool | Purpose |
|------|---------|
| **validate-peer** | The conformance validator. Runs the V7 spec suite against a live peer, single-peer or multi-peer convergence. `validate-peer -list-categories` prints every category; see CLAUDE.md for the full flag reference. The primary gate for any implementation. |
| **compare-types** | Connects to two peers, fetches all type definitions from each, and diffs them field-by-field (also against locally-generated types). |
| **entity-sync** | Sets up cross-peer sync (continuation chains + subscriptions) so one peer's subtree mirrors onto another. |
| **corpus-check** | Holds every registered conformance corpus to one contract — artifact-is-expected (pinned sha), source-produces-artifact (re-encode), and copies-agree. Registry: `cmd/internal/corpus`. Writes nothing. Wired into `validate-complete.sh` PASS 0. |
| **conformance-register** | Emits the conformance category register — every check `validate-peer` declares, its citation, its profile membership, and whether it contacts the peer at all — and resolves each citation against the live spec trees. Static: no peer, no network. `-check` is a baseline ratchet wired into `validate-complete.sh` as PASS 0b. |

```bash
go run ./cmd/validate-peer -addr host:port -identity framework-admin
go run ./cmd/conformance-register            # summary; -md, -findings, -json, -check
go run ./cmd/validate-peer -peers h1:p,h2:p -identity framework-admin   # convergence
go run ./cmd/compare-types host1:port host2:port
go run ./cmd/entity-sync -from host:port -to host:port -source-prefix local/files/
```

## Interactive exploration

| Tool | Purpose |
|------|---------|
| **entity-shell** | Interactive REPL against peers — connect, browse, and issue operations by hand. `-identity` selects a named identity. |
| **probe-peer** | Tree explorer: connect, walk `system/tree`, and print entities at given paths. `probe-peer -addr host:port [-identity name] [paths...]`. |

## Diagnostic probes (dev tools — not part of the conformance gate)

These are small, single-purpose tools for investigating wire behavior during
development. Several were written for a specific cross-impl bug hunt and are
kept as reproductions; they are intentionally minimal.

| Tool | Purpose |
|------|---------|
| **probe-hello** | Connect, send hello, dump the raw CBOR of the response result field. |
| **probe-grant** | Register a minimal handler, read back the installed grant entity, and dump its decoded `CapabilityTokenData` — for comparing what each impl emits. |
| **probe-files** | One-shot `local/files` op: `probe-files <addr> <operation> <tree-path> [content]`. |
| **probe-ingest** | Ingest a chunk under a content-namespace and print the resulting hex hash — seeds cohort cross-impl HTTP-poll serving tests. |
| **scan-probe** | Dispatch `system/discovery:scan(mdns)` against a peer and print the decoded candidate snapshot (LAN discovery smoke test). |
| **dump-messages** | Build real protocol messages and render them with full type annotations showing how entity types nest. |
| **dump-types** | Fetch a set of type defs from Go + Rust peers and dump them side-by-side (one-off hash-divergence diagnostic). |
| **bench-localfiles** | Measure `local/files:write`/`:read` latency + throughput against a peer (`-addr`, `-prefix`, `-label`). Reliability benchmark, not a gate. |

## Registry operator tools (peer-issued REGISTRY backend)

| Tool | Purpose |
|------|---------|
| **registry-issue-binding** | Operator signing tool (Part B.curated): the registry operator, holding the registry peer's key, signs a `name → target_peer_id` binding and publishes the body + signature + by-name pointer. |
| **registry-request-binding** | Publisher self-service request (Part B.live, EXTENSION-REGISTRY §6a.9): a publisher holding `target_peer_id`'s key asks a registry (running with `--issuer-policy-mode`) to sign + publish a binding. |

## Cross-impl fixtures & corpus gates

Deterministic generators and verifiers for cross-implementation byte-equality.
The cohort rule: Rust + Python re-deriving from the same seeds/inputs MUST
produce byte-equal CBOR and identical content hashes.

| Tool | Purpose |
|------|---------|
| **publish-fixture** | Spins up a deterministic HTTP-poll publisher (real listener) for publish→fetch interop drives; prints the reproducible contract (peer-id, root hash, leaf hashes) to stdout. |
| **fetch-published-fixture** | Go-side consumer that drives the Tier-1 published-root read flow (MANIFEST_GET → verify → TREE_GET → CONTENT_GET → byte-equality) against a publisher URL. |
| **peerissued-fixtures** | Emits the `REG-PEERISSUED-*` byte-equal fixture bundle (`-out <dir>`) for the peer-issued REGISTRY backend. |
| **relay-fixtures** | Emits the EXTENSION-RELAY v1.0 byte-equal fixtures for the R5 cohort handoff. |
| **internal/compute-corpus** | The compute differential corpus (GUIDE-CONFORMANCE §7c): `generate` a seeded frozen `(IR, bindings, budget)` set, `emit` boundary outcomes through core-go, `verify` the six anti-vacuity guards, `cross-bless` 2+ impls. Inputs only — Go is the fixture-builder, not the oracle. |
| **webrtc-vectors** | Emits and verifies the §6.5 WebRTC-coordination differential vectors (`-emit` / `-verify`, CBOR). Four surfaces crossable with no browser, ICE stack, socket or NAT: entity wire shape, offerer/glare decisions, the `session_id` floor, and §6.3 verification. Files live in `docs/validation/vectors/`. A green run crosses the **coordination** layer only — never evidence that WebRTC transport works (§11.5.1: S5 is). |
| **encryption-vectors** | Emits and verifies `ENC-RESOLVE-ORDER-1` (EXTENSION-ENCRYPTION §16.1, defined by §16.6) for §4.4's recipient-key resolution (`-emit` / `-verify`, CBOR; rows in `cmd/internal/encvectors`). §4.4 is a cross-peer-seam MUST with **no wire surface** — resolution is sender-side and ENCRYPTION exposes no peer-facing encrypt op — so a pinned-input vector each impl runs in its own suite is the only crossing available. §16.6 makes the *coverage* normative, not any repo's file: ladder precedence, the total order, carrier→pubkey projection + dedup, revocation at both granularities, `expires`, both step-4 errors, order-independence on every row, and negative controls that each fire on a named row. |
| **agility-corpus-verify** | Decodes the v7.67 agility conformance corpus and asserts file hash + structural invariants + cryptographic re-derivation. |
| **agility-phase2-pins** | Derives the v7.67 Phase-2 matrix (M2/M3/M6) byte tuples from the pinned seeds and prints them as JSON per vector. |
