# Entity Core Go

Go reference implementation of Entity Core Protocol v7 — one of three
independent ground-up implementations (with `entity-core-rust` and
`entity-core-py`), and the repo that hosts the cross-implementation
conformance validator the three are measured with.

Agent and contributor orientation lives in **[`AGENTS.md`](AGENTS.md)** (this
repo) and **[`AGENTS-STANDARD.md`](AGENTS-STANDARD.md)** (ecosystem-wide
conventions). `CLAUDE.md` is a shim to those two, per ADR-0016.

**The spec is upstream and lives in two sibling repos**, not here:

| Repo | Carries |
|---|---|
| `entity-core-protocol` | the core floor — `ENTITY-CORE-PROTOCOL.md`, `ENTITY-CBOR-ENCODING.md`, `ENTITY-NATIVE-TYPE-SYSTEM.md`, and the conformance vectors |
| `entity-system-architecture` | every `EXTENSION-*.md`, the guides, and the proposal record |

Implementations implement the spec; they do not define it. When this repo hits
a gap or an ambiguity it writes it up as a spec issue and routes it upstream to
whichever of those two repos owns the text, rather than papering over it
locally — the ruling comes back as spec text, and only then does it get
implemented here. The write-ups themselves are working notes kept in this
repo's internal `docs/validation/` tier; the outcome that matters to a reader
is in the spec.

---

## Conformance

Conformance to the spec is the contract — not the version number, and not a
green unit suite. Every published number here is pinned to the commit it was
measured at, per ADR-0012.

Measured at `3cfec93` (2026-08-12), `./scripts/validate-complete.sh`:

| Pass | Result |
|---|---|
| All surfaces, closure scope | **1571 · 0F · 0S · 0W** |
| Core profile (V7 §9.0), same target | **633 · 0F · 0W** |
| `serving_mode`, namespace scope | **55 · 0F · 0S** |
| `registry_issuer`, registry posture | **19 · 0F · 0S** |

All four passes exit 0, and the same four reproduce identically under
`HASH_TYPE=sha384` — the non-floor home format is a separate gate, because it
is the only run in which a home-format defect is reachable at all.

The living measurement is [`docs/STATUS.md`](docs/STATUS.md), which is
re-measured rather than carried forward. A skip counts as a failure.

---

## Build & test — `make` + `podman` only

The build is fully containerized: a host with only **`make`** and **`podman`**
can build and test everything. No host Go toolchain is required.

```bash
make build      # compile every cmd/ binary in-container (multistage Dockerfile)
make test       # go test ./... across all three workspace modules
make lint       # go vet ./... (alias: vet)
make fmt        # gofmt -w across all modules (writes)
make check      # lint + test — the green gate
make race       # tests under -race
make clean      # remove the build image
make help       # the full verb list
```

The verbs follow the ecosystem's standard vocabulary (ADR-0019). `dist` and
`publish` are **reserved** verbs with fixed meanings and are deliberately not
defined here — this repo has no binary-release target, and defining the verb
for anything else would break the contract.

A fresh clone — with no sibling repositories present — passes `make build` and
`make test` standalone. The repository is self-contained: the committed
`go.work` plus intra-repo `replace` directives tie `core`, `ext`, and `cmd`
together so nothing external is fetched to build.

Dependencies are kept deliberately few. The protocol library `core/` has
**exactly two** direct external dependencies — `github.com/fxamacker/cbor/v2`
(CBOR/ECF) and `github.com/mr-tron/base58` (PeerID encoding). `ext/` adds
`fsnotify`, `zeroconf`, and `golang.org/x/{crypto,sys,text}`; `cmd/` adds
`BurntSushi/toml`. A new dependency must be stable, predictable, 30+ days old,
and drop in without an adapter layer.

Every podman invocation is capped (memory/CPU/pids) so a build can't take the
host down. Defaults are committed in the `Makefile`; override per-machine via
env vars or an untracked `caps.local.mk`. See
[`RESOURCE-CAPS.md`](RESOURCE-CAPS.md).

### Optional: a host Go toolchain

To build and test with a local Go directly, the toolchain is Go **1.25** —
each `go.mod` carries the `go 1.25.0` directive. Install it however your system
installs Go; this repo pins no toolchain manager. The default build path is
pure Go, no CGo.

```bash
go build ./...
go test  ./core/... ./ext/... ./cmd/...
go vet   ./core/... ./ext/... ./cmd/...
```

---

## Repository layout

Three Go modules in a workspace (`go.work`), with a strict dependency
direction — **`core ← ext ← cmd`**. Core never imports ext or cmd.

```
entity-core-go/
├── core/   # protocol library — 13 packages in a strict DAG, no import cycles
│           #   (plus internal/testutil, a test helper outside the DAG):
│           #   errors → ecf → hash → entity, crypto, store, types, wire
│           #     → capability → handler → protocol, tree → peer
├── ext/    # 28 system extensions, each depending only on core
└── cmd/    # CLIs, the conformance validator, and interop tooling
```

`ext/` is large enough that "is there an `ext/X`?" should be answered by
looking rather than from memory — `ls ext/` is the source of truth:

```
attestation  capability  clock      compute    conformance  content
continuation discovery   encryption handlers   history      httplive
identity     inbox       localfiles network    publishedroot query
quorum       registry    relay      revision   role         signaling
storagesubstitutehttp    storagesubstitutesources           subscription
type
```

Full `cmd/` inventory is in [`cmd/README.md`](cmd/README.md); the principal
entry points are `entity-peer` (the peer), `validate-peer` (the conformance
validator), and `peer-manager` (peer orchestration, including containerized
Rust and Python peers).

### Sibling repos

Sibling repos are referenced for spec text and interop validation only —
**building this repo never requires them.** They are expected as siblings in
the same parent directory:

```
../entity-core-protocol/        ← core spec + conformance vectors
../entity-system-architecture/  ← extension specs, guides, proposals
../entity-core-rust/            ← Rust implementation (interop target)
../entity-core-py/              ← Python implementation (interop target)
```

---

## Module paths

The three modules publish under the project vanity domain:

```
go.entitychurch.org/entity-core-go/core
go.entitychurch.org/entity-core-go/ext
go.entitychurch.org/entity-core-go/cmd
```

Downstream consumers (e.g. `entity-workbench-go`) pin the versioned module —
for example `require go.entitychurch.org/entity-core-go/core v0.10.0` — and
resolve it through the vanity domain. Published manifests never carry a
sibling-path `replace`.

---

## Validation & interop

Single-peer conformance against the spec, and cross-peer convergence:

```bash
# start peers (Go builds on the host; Rust and Python run via podman)
go run ./cmd/peer-manager start --name p1 --type go|rust|python --debug
go run ./cmd/peer-manager list
go run ./cmd/peer-manager stop --all          # owner-scoped: only this session's peers

# score one peer
go run ./cmd/validate-peer -addr host:port [-category NAME] [-failures-only] [-json]
go run ./cmd/validate-peer -list-categories   # the live category set
go run ./cmd/validate-peer -peers h1:p,h2:p -identity NAME   # multi-peer convergence
```

`--profile core` scores the 16 core-profile categories (V7 §9.0, as folded at
v7.75); `--profile full` is the default. The category set is re-derived from
the spec text by a drift test rather than hand-maintained. Scripted entry
points:

```bash
make validate           # validate against all available implementations
make validate-rust      # requires ../entity-core-rust/
make validate-python    # requires ../entity-core-py/
./scripts/validate-complete.sh                # the four-pass gate
TYPES=go,rust,python ./scripts/test-cross-peer.sh
```

Cross-implementation results are written up per peer, dated and pinned to the
commit each peer was measured at, because a conformance number is only true of
the commit it was taken at. Those write-ups are working notes in this repo's
internal `docs/validation/` tier rather than published documentation — they go
stale the moment the peer they measure commits again. What a reader should take
from them is the current headline, which is in [`docs/STATUS.md`](docs/STATUS.md),
and anything they turned up about the spec, which is routed upstream.

**On what the validator is.** It scores against the spec, and it has itself
been the defect. A 2026-08-07 re-measure under a corrected oracle withdrew
**all 42** serving failures this repo had reported against the Rust and Python
peers — 39 from a single harness defect, and the remaining 3 also ours. Go's
writer and reader share the same assumptions, so a wrong assumption is
unfalsifiable in-tree; every oracle defect that cycle was found from outside
this repo. Read validator output accordingly, and note that a cohort of
implementations passing one author's vectors is cohort-consistent, not
independent convergence.

---

## Contributing

Contributions welcome — see [CONTRIBUTING.md](CONTRIBUTING.md). In short:
DCO sign-off (`git commit -s`) from an accountable human, no CLA, code under
Apache-2.0, and AI-assisted work is welcome and unrestricted — the gate is the
accountable human and the quality bar, applied equally however much tooling was
used. The default branch is `master`; development lands on `dev`.

Security reports: [SECURITY.md](SECURITY.md).

---

## Supporting the project

This project is developed in the open. If it's useful to you, the best support
is to use it, report issues, and contribute back.

To support the work directly, see the project's funding page.
