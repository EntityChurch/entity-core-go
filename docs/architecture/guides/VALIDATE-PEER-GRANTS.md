# Validate-Peer Capability Standards

How `validate-peer` decides what to test, what grants each category needs, and how to wire identities so a fresh peer passes the full suite.

## Why a peer can score "39 of 466 fail" without anything being broken

`cmd/internal/validate/suite.go` is grant-gated: each category checks the connecting client's capability scope before running. If the client doesn't hold grants for the operations a category needs, that whole category is **skipped** — and the skip counts as a fail in the suite's exit code. This is the suite signaling "you wanted full coverage, you got partial — that's meaningful." It is **not** the peer failing the test.

When you see a numerically large failure count on a fresh peer, the first question is "did the client receive the grants the categories require?" The answer is usually no — because the default connection grant is intentionally narrow.

## The connect-grant baseline

When a client connects via `system/protocol/connect:authenticate`, the peer hands it a capability token. The grants in that token are determined by this chain (in `core/protocol/connect.go:181-194`):

1. **Dynamic grant resolver** (`grantResolver` — wired by extensions like `ext/role/policy.go` when a peer is named and has a `grants.toml`). If it returns non-nil, those grants are used.
2. **Static connection grants** (`connectionGrants` — set by `peer.WithConnectionGrants(...)`). Used if the resolver returned nil.
3. **`DefaultConnectionGrants()`** — used if neither of the above provided grants.

`DefaultConnectionGrants()` (`core/protocol/connect.go:337`):
```
[handlers=[system/tree],       resources=[system/type/*, system/handler/*], operations=[get]]
[handlers=[system/capability], resources=[],                                operations=[request]]
```

Just enough to discover the peer's shape (read its types and handler manifests) and request additional capabilities. That's it. No subscription, no inbox, no clock, no compute, no tree mutation. Most of `validate-peer`'s categories require more.

## Category-by-category grant requirements

From `cmd/internal/validate/suite.go`, with gate line numbers:

| Category | Gate | Minimal grant tuple (handler, resource, operation) | Why |
|---|---|---|---|
| `connectivity` | always runs | — | Establishes the handshake itself |
| `encoding` | always runs | — | Wire-shape checks on the handshake response |
| `type_system` | L84: `GrantsAllow("system/type/system/peer")` | `(system/tree, system/type/*, get)` | Reads type defs via tree handler |
| `handlers` | L91: `GrantsAllow("system/handler/system/tree")` | `(system/tree, system/handler/*, get)` | Reads handler manifests via tree handler |
| `tree_operations` | L98: `GrantsAllow("system/validate/test-1")` | `(system/tree, system/validate/*, get)` | Snapshot/diff/merge/extract on validation paths |
| `subscriptions` | L105: `grantsAllow(grants, "system/subscription", "system/validate/sub-test/*", "subscribe")` | `(system/subscription, system/validate/sub-test/*, subscribe)` | Subscribe/notify/unsubscribe |
| `continuations` | L112: `grantsAllow(grants, "system/inbox", "system/inbox/*", "receive")` | `(system/inbox, system/inbox/*, receive)` | Forward/resume/abandon via inbox |
| `revision` | L119: `GrantsAllow("system/validate/revision-main-0/")` | `(system/tree, system/validate/revision-*, get)` | Commit/log/branch/merge wire ops |
| `auto_version` | L126: `GrantsAllow("system/validate/auto-version-0/")` | `(system/tree, system/validate/auto-version-*, get)` | CRDT per-write tracking |
| `clock` | L133: `grantsAllow(grants, "system/clock", "system/clock/*", "now")` | `(system/clock, system/clock/*, now)` | Now/compare/tick |
| `history` | L140: `grantsAllow(grants, "system/history", "system/history", "query")` | `(system/history, system/history, query)` | Recording/query/rollback |
| `security` | always runs | — | Capability enforcement checks (need no extra surface) |
| `multisig` | always runs | — | Negative-only wire-level tests |
| `query` | L155: `grantsAllow(grants, "system/query", "system/validate/query/*", "find")` | `(system/query, system/validate/query/*, find)` | Find/count/index ops |
| `local_files` | L162: `grantsAllow(grants, "local/files", "local/files/*", "read")` | `(local/files, local/files/*, read)` | Domain handler file ops |
| `compute` | L169: `GrantsAllow("system/validate/compute-test")` | `(system/tree, system/validate/compute-*, get)` | Eval / install / reactive |
| `entity_native` | L176: `GrantsAllow("app/validate/entity-native")` | `(system/tree, app/validate/entity-native, get)` | Entity-native dispatch |
| `origination` | L186: requires `-reference-peer` | (separate peer) | A-role tests need a B-role peer to relay to |
| `attestation` | always runs | — | Substrate primitive; ambient access |
| `quorum` | always runs | — | K-of-N primitive; ambient access |
| `identity` | always runs | — | Convention layer; ambient tree access |
| `role` | always runs | — | Structural conformance |
| `behavioral_role` | always runs | — | Role lifecycle via ambient access |
| `behavioral_v33` | always runs | — | TV test vectors via ambient access |
| `durability` | always runs | — | Probes baseline-covered ops |

**Note**: `GrantsAllow(resource)` is a convenience that expands to `grantsAllow(grants, "system/tree", resource, "get")` (see `client.go:760`). Categories using bare `GrantsAllow(...)` only need tree:get on a validation path; the more explicit `grantsAllow(grants, handler, resource, op)` calls are needed when the category dispatches to a non-tree handler.

## Two ways to make the suite pass

### A. `--open-access` (development / quick test)

`go run ./cmd/entity-peer -addr :9900 --open-access`

Wires `peer.WithConnectionGrants(peer.OpenAccessGrants())` (`cmd/entity-peer/main.go:128`). Every connecting client receives:

```
[handlers=[system/query], resources=[*],     operations=[find, count]]   (query-specific, exercises Constraints + Allowances)
[handlers=[*],            resources=[*, /*/*], operations=[*]]            (wildcard general)
```

All categories' gates pass. No identity setup required. **Do not use in production** — the warning at peer startup says so explicitly. Use for local dev, CI smoke tests, and quick regression runs.

### B. Identity-based authorization (canonical / production-shaped)

The spec-correct path: the peer is configured with a named identity, and clients authenticate as named identities with grants assigned by an admin policy. This matches how a deployed peer behaves and exercises the full grant-resolution chain.

**One-time setup for a fresh validator identity** (the recipe from `core/protocol/connect.go` + `cmd/internal/config/grants.go`):

1. Create a fresh validator identity. `~/.entity/identities/validator-admin` with a keypair (any name; the file holds an ed25519 keypair).
2. Create a fresh peer config. `~/.entity/peers/test-peer/keypair` (the peer's own identity).
3. Author the peer's `grants.toml` at `~/.entity/peers/test-peer/grants.toml`:
   ```toml
   [groups.admin]
   members = ["<validator-admin's peer ID>"]
   resources = ["*"]
   operations = ["*"]
   description = "Full admin access for validation"
   ```
4. Optionally start a second peer (`ref-peer`) for `origination` tests; same recipe with its own identity.

**Run the validator**:

```bash
go run ./cmd/entity-peer -name test-peer -addr :9900
go run ./cmd/entity-peer -name ref-peer -addr :9901   # in parallel
go run ./cmd/validate-peer -addr :9900 -identity validator-admin -reference-peer :9901
```

The validator client authenticates as `validator-admin` → peer recognizes its peer ID in `grants.toml`'s admin group → returns wildcard grants → all categories pass their gates.

### What about `framework-admin`?

CLAUDE.md mentions `framework-admin` in example commands. It's a **placeholder identity name** — not a magic identifier, not a built-in role, not a special peer. It's the name a previous operator picked for "the identity I use to validate my peers." Use whatever name you like; the convention is just to pick one and reuse it.

## Identity vs. role

Two distinct mechanisms, easy to confuse:

- **Identity** is a keypair + the peer-ID derived from it. Identities are loaded from `~/.entity/identities/<name>`. A client authenticates AS an identity; the peer can identify the connecting party by their peer ID.

- **Role** is a named bundle of grants defined via `ext/role`'s `system/role:define` operation. Roles are assigned to identities. The peer's grant resolver (when wired via `role.NewPolicyGrantResolver`) consults role assignments to decide what grants to return for a connecting identity.

The `grants.toml` model in `cmd/internal/config/grants.go` is a simpler static alternative — `[groups.admin]` is functionally a role assignment but configured statically rather than via the role extension. For validation purposes static groups are usually sufficient and easier to reason about.

When the role extension is active AND `grants.toml` is configured, both are consulted: static grants resolve first (per-peer overrides), then role policy (for un-configured peers per `system/role/initial-grant-policy`). See `cmd/entity-peer/main.go:329-339`.

## Debugging grant issues

`validate-peer -verbose` now prints the grants the client receives during the handshake (`cmd/internal/validate/client.go`):

```
[VERBOSE] received 2 connection grants:
  [0] handlers=[system/query] resources=[*] operations=[find count]
  [1] handlers=[*] resources=[* /*/*] operations=[*]
```

If the suite shows lots of "category skipped: connection grants do not cover X" failures, run with `-verbose` first. The grants printed there tell you exactly what the peer is handing out, which lets you diagnose whether:

- The peer wasn't started with `--open-access` (use `-open-access` for quick tests)
- The identity you authenticated as doesn't have the right grants assigned (check the peer's `grants.toml`)
- A `grantResolver` extension is overriding what you expected (role policy, etc.)

## Common confusions (notes from investigation)

- **"`--open-access` doesn't seem to work."** Almost always a stale peer process on the same port. The new peer fails to bind silently (`bind: address already in use`) and the old peer (without `--open-access`) keeps serving. Check `pgrep -af entity-peer` and `ss -tln | grep <port>` before assuming a wiring bug.
- **"The default grant should be wider."** No — the narrow default is by design. Capabilities are explicit, not implicit. The default grant lets a fresh client discover the peer; broader access requires authentication or `--open-access`.
- **"Why does the static `connectionGrants` lose to `grantResolver`?"** Because the resolver represents per-peer-ID policy decisions (role assignments, identity recognition); static grants are the fallback for un-configured peers. If you want `--open-access` to win unconditionally, you would have to either not wire a resolver or invert the ordering — but that breaks the per-identity grant model the role/identity extensions depend on.
- **"What about the remaining 39 fails after `--open-access` works?"** Those are real test failures in `history` (23/34) and `local_files` (15/32), plus the expected `origination` skip when no `-reference-peer` is provided. They are NOT grant-gating artifacts. Investigate as you would any test failure.

## Reference: file:line index

- Grant gates: `cmd/internal/validate/suite.go:84-219`
- `grantsAllow()` matcher: `cmd/internal/validate/client.go:764-795`
- Verbose grants print: `cmd/internal/validate/client.go:389-396`
- Connect handler grant resolution: `core/protocol/connect.go:181-194`
- `DefaultConnectionGrants()`: `core/protocol/connect.go:340-355`
- `OpenAccessGrants()`: `core/peer/builder.go:249-290`
- `--open-access` flag wiring: `cmd/entity-peer/main.go:127-130`
- Role policy resolver: `ext/role/policy.go:362-380` + chain composition at `cmd/entity-peer/main.go:329-339`
- Static `grants.toml` parser: `cmd/internal/config/grants.go:29-92`
