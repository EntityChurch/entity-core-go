
# entity-core-go

Read **AGENTS-STANDARD.md** first (ecosystem conventions). This file adds entity-core-go specifics.

## Overview

Go implementation of the Entity Core Protocol v7 — the third ground-up reference implementation (after Python and Rust), and the SDK prototype: **Go leads on new features**, cross-impl convergence is downstream feedback, not a gate.

## Setup / environment

- **Go**, `go.work` multi-module workspace — three modules, all under `go.entitychurch.org/entity-core-go/`: **`core`** (protocol library), **`ext`** (system extensions), **`cmd`** (CLIs / validation / interop). Import paths always carry the module prefix, e.g. `go.entitychurch.org/entity-core-go/core/hash`.
- **External deps (two):** `github.com/fxamacker/cbor/v2` (CBOR / ECF — `CoreDetEncOptions()`), `github.com/mr-tron/base58` (PeerID encoding). Dep gate: stable + predictable + 30+ days old, and prefer the library that drops in **without an adapter** — a "small adapter layer" is a sign of shape mismatch. When a handoff already names a lean pick that clears the bar, take it; don't re-litigate an obvious call.
- **Spec is upstream**, in sibling `../entity-core-architecture/docs/architecture/v7.0-core-revision/specs/` (`ENTITY-CORE-PROTOCOL-V7.md`, `ENTITY-CBOR-ENCODING.md`, `ENTITY-NATIVE-TYPE-SYSTEM.md`, the `EXTENSION-*.md` set). Other impls: `../entity-core-py/`, `../entity-core-rust/` (note: **`entity-core-rust`, never `entity-core-rs`**). Siblings live under `~/projects/entity-systems/` — read from disk, don't interrogate.

## Build & test

```bash
go test ./core/... ./ext/... ./cmd/...        # full suite (all three modules)
go vet  ./core/... ./ext/... ./cmd/...         # vet all packages
go test -race ./core/... ./ext/... ./cmd/...   # race detector
go test -run TestName ./core/ecf/...           # single / targeted (stdlib testing, table-driven, no assertion lib)
go build ./...                                  # verify compilation
```

**Peers & validation — use the purpose-built tooling, the documented way.** No `go install`, no custom env, no one-off compiles, no backgrounding `entity-peer` with `&`, no building to `/tmp`. If a peer seems stale, stop and restart it — `peer-manager` rebuilds fresh on start.

```bash
go run ./cmd/peer-manager start --name p1 --type go|python|rust --debug   # ALWAYS --debug
go run ./cmd/peer-manager list | stop --all                              # (Go = host build; Rust/Python via podman)
go run ./cmd/validate-peer -addr host:port [-identity NAME] [-category NAME] [-failures-only] [-exclude c1,c2] [-json] [-verbose]
go run ./cmd/validate-peer -peers h1:p,h2:p -identity NAME                # multi-peer convergence
go run ./cmd/validate-peer -list-categories                              # live ~60-category set (from validate.AllCategories())
./scripts/validate-peers.sh [python]                                     # scripted (SAVE=1 to save JSON)
TYPES=go,rust,python ./scripts/test-cross-peer.sh                        # convergence test
```

- `--profile core` scores the 14 core-profile categories (V7 §9.0); `--profile full` (default) runs all.
- **Diagnostics first** (`docs/architecture/guides/USING-DIAGNOSTICS.md`): when something fails, reach for `validate-peer -category $CAT -verbose 2>trace.log` + the peers' `~/.entity/logs/{name}.log` **before** reading code or writing analysis. Wire evidence is upstream of theory. Never `-verbose` the full suite to a TTY (~130 MB) — always narrow with `-category` first. For in-process Go work, use `peer.WithDispatchHook` / `WithWireHook` / `WithBindingHook` for tap observability without rebuild churn. (Negative-path tests like `security`/`multisig.escalation_*` legitimately emit 403s in the responder log — map `request_id` → test name.)
- **Never ad-hoc-filter validate-peer output.** Use `-failures-only`, `-exclude`, `-category`, `-json` — never a throwaway `python3 -c` / shell script to tally or "confirm" the tool's own output. The summary table already gives per-category P/W/F counts; to compare peers, run it N times and read the tables. (Corrected repeatedly — don't reach for `json.load` to re-verify what `-failures-only` already shows.)

## Code style & conventions

- Idiomatic Go: `sync.RWMutex` + goroutines; sentinel errors + `errors.Is/As`; functional options (`PeerOption`) for builders; `context.Context` on every I/O op; small provider-defined interfaces (`ContentStore`, `LocationIndex`, `Handler`).
- **No backward-compat shims.** Pre-1.0 takes clean breaks: remove conventions not in the current spec; convert removed-convention asserts into negative/invariant tests rather than leaving them green.

## Project structure

- **`core/`** — protocol library; **14 packages in a strict DAG** (no import cycles): `errors → ecf → hash → entity, crypto, store, types, wire → capability → handler → protocol, tree → peer`. **A package may only import packages to its left.**
- **`ext/`** — system extensions, each depending only on `core`: `clock`, `inbox`, `continuation`, `subscription`, `revision`, `role`, `type` (+ `type/constraint`), `localfiles`.
- **`cmd/`** — CLIs / validation / interop (full inventory in `cmd/README.md`): `entity-peer`, `validate-peer`, `peer-manager`, `entity-sync`, `probe-peer`, `compare-types`, plus `cmd/internal/` (`validate`, `interop`, `config` — not importable outside `cmd`).
- **`docs/`** — `architecture/`, `validation/` (conformance reports, spec-issues), `reviews/`, `legacy/`.
- **Module direction: `core ← ext ← cmd`.** Core never imports ext or cmd.

## Boundaries — do NOT modify

- **Cross-repo git:** git in `entity-core-go` is in scope — commit/push freely, no per-commit asking (don't force-push or rewrite published history). **Never run git in `entity-core-py`, `entity-core-rust`, or `entity-core-architecture`** — those are coordinated through the operator.
- **Spec is the upstream source of truth.** Don't edit `../entity-core-architecture/...` from here, and don't write implementation reviews/reports there — those go in `entity-core-go/docs/`. A handed `PROPOSAL-*.md` is **already merged** on the arch side: do the Go impl, don't ask whether to also update the spec or whether to proceed.
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

### Posture on protocol work (Go leads)

- **Don't defer on "implementation-defined" or "Rust/Python don't have it yet."** We are the impl team — implementation-defined means *we* define it; multi-Go-peer validation is real validation; cross-impl is downstream feedback.
- **Don't gate a merged spec on "hot path / blast radius."** The hot path is the system. Make the change additive (opt-in, nil-default) so there's no blast radius to agonize over, then implement it. Reserve questions for genuine value judgments; for a real **spec ambiguity**, write it up under `docs/validation/spec-issues/` and keep implementing the unambiguous parts.
- **On a fresh probe that FAILs one cohort sibling on a wire-shape detail:** check whether adjacent categories already tolerate that shape (reuse their extractor, e.g. `extractStatusAndCode`) before calling it a peer bug — a too-strict probe FAILs a tolerated divergence. Flag the divergence in writing; don't gate the cycle on it. (This is *not* "permissive forever," and never relabel a real FAIL "pre-existing" without bisecting.)

## Cross-impl validation deliverable

When validating Python/Rust against a spec change, the deliverable is a **written per-peer report under `docs/validation/reports/`** (dated filename, matching prior reports: headline pass/partial/blocked, category table, each gap with spec requirement + probed request shape + peer response + why it matters + suggested fix/test, repro steps) — not chat output that evaporates. Run the validator, report what you observed, and stop: don't dig through the sibling's git history or internals to root-cause — that's a separate job.
