# Entity Core Go

Go reference implementation of Entity Core Protocol v7. Used as the
interop baseline (oracle) for the Rust and Python implementations.

See `CLAUDE.md` for architecture orientation and the strict 14-package
DAG. The protocol spec lives in the `entity-core-architecture` repo.

---

## Build & test — `make` + `podman` only

The build is fully containerized: a host with only **`make`** and
**`podman`** can build and test everything. No host Go toolchain is
required.

```bash
make build      # compile every cmd/ binary in-container (multistage Dockerfile)
make test       # run the full test suite across core/ext/cmd inside the toolchain image
make vet        # go vet across all modules
make race       # tests under -race
```

A fresh clone — with no sibling repositories present — passes `make build`
and `make test` standalone. The repository is self-contained: the committed
`go.work` plus intra-repo `replace` directives tie the `core`, `ext`, and
`cmd` modules together so nothing external is fetched to build.

Every podman invocation is capped (memory/CPU/pids) so a build can't take the
host down. Defaults are committed in the `Makefile`; override per-machine via
env vars or an untracked `caps.local.mk`. See
[`RESOURCE-CAPS.md`](RESOURCE-CAPS.md).

### Optional: a host Go toolchain

If you prefer to build/test with a local Go directly, the toolchain is Go
**1.25** (`mise.toml` pins it; `mise install` will fetch it). Each `go.mod`
carries the `go 1.25.0` directive. The default build path is pure Go — no CGo.

---

## Module paths

The three modules publish under the project vanity domain:

```
go.entitychurch.org/entity-core-go/core
go.entitychurch.org/entity-core-go/ext
go.entitychurch.org/entity-core-go/cmd
```

Downstream consumers (e.g. `entity-workbench-go`) pin the versioned module,
for example `require go.entitychurch.org/entity-core-go/core v0.8.0`, and
resolve it through the vanity domain. Sibling-directory development uses a
local, gitignored `go.work`; published manifests never carry a sibling-path
`replace`.

---

## Repository layout

Three Go modules in a workspace (`go.work`):

```
entity-core-go/
├── core/   # protocol library (entities, ECF, crypto, store, wire, tree, peer)
├── ext/    # system extensions (inbox, subscription, revision, role, type, …)
└── cmd/    # CLIs, the validation suite, and cross-impl interop tests
```

Sibling repos under the `entity-systems/` parent are referenced for
documentation and interop validation only — building this repo never
requires them:

```
entity-systems/
├── entity-core-go/               ← this repo
├── entity-core-architecture/     ← protocol spec
├── entity-core-rust/             ← Rust impl (interop target)
└── entity-core-py/               ← Python impl (interop target)
```

---

## Interop validation

Cross-implementation conformance tests drive live peers and require the
sibling impl repos to be present:

```bash
make validate           # validate against all available implementations
make validate-rust      # requires ../entity-core-rust/
make validate-python    # requires ../entity-core-py/
```

For single-peer conformance against the spec, see the `validate-peer` CLI
documented in `CLAUDE.md`.

---

## Supporting the project

This project is developed in the open. If it's useful to you, the best support is
to use it, report issues, and contribute back — see
[CONTRIBUTING.md](CONTRIBUTING.md).

To support the work directly, see the project's funding page.
