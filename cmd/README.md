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

```bash
go run ./cmd/validate-peer -addr host:port -identity framework-admin
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
| **v767-corpus-verify** | Decodes the v7.67 agility conformance corpus and asserts file hash + structural invariants + cryptographic re-derivation. |
| **v767-phase2-pins** | Derives the v7.67 Phase-2 matrix (M2/M3/M6) byte tuples from the pinned seeds and prints them as JSON per vector. |
