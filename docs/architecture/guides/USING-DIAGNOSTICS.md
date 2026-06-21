# Using diagnostics — operational guide

**Audience:** anyone debugging the substrate, writing a new validate-peer check, or instrumenting an L2 tool.

The diagnostics surface only pays off when you reach for it. This guide is the reach-for-it reference: when to flip which knob, what volume to expect, how to hone in, and where the foot-guns are.

## TL;DR

| You want… | Use… |
|---|---|
| Just narrow what got run | `validate-peer -category X` |
| See *exactly* what went over the wire in a failure | `validate-peer -verbose 2>trace.log` then `grep` |
| Process the result programmatically | `validate-peer -json-out report.json` |
| In-process observation from Go | `peer.WithDispatchHook` / `WithWireHook` / `WithBindingHook` or `Engine.AddEmitHook` / `AddDeliverHook` |
| Suppress noise | `-failures-only`, `-exclude cat1,cat2` |

Never write ad-hoc scripts to filter `validate-peer` output — there's already a flag.

## When to use what

### 1. "validate-peer says FAIL, no idea why"

```bash
# Step 1: narrow scope.
validate-peer -addr host:port -identity framework-admin -category $CAT -failures-only

# Step 2: get the wire trace for that category only (small, parseable).
validate-peer ... -category $CAT -verbose 2>/tmp/trace.log

# Step 3: search the trace.
strings /tmp/trace.log | grep "code:"             # all error responses
strings /tmp/trace.log | grep "op=$OP"            # all calls for an op
strings /tmp/trace.log | grep "$PATH"             # everything touching a path
```

In a recent debug session this surfaced two distinct failures in 30 seconds:
- `{code: "no_root_mapping", message: "no root mapping for path: local/files/test/..."}` → peer was misconfigured, not buggy.
- `{status: "no_change", hash: ..., path: ...}` returned on a first-`set` → revealed cross-invocation test-state leakage.

Neither would have been findable from just `status 404` / `status 200`.

### 2. "I'm writing a new validate-peer check that hits a tricky wire path"

Use `-verbose` while iterating. Verify each EXECUTE goes where you expect by reading the trace. Once it's stable, commit without -verbose.

### 3. "I'm writing an L2 tool that needs to observe the substrate"

Programmatic hooks. See *Hook surface* below.

### 4. "I want to know if a chain completed end-to-end"

Either:
- Subscribe to the relevant content/binding hook and watch for the chain's success entity (`system/inbox/v1/data`, etc.), or
- Watch `system/runtime/chain-errors/lost/{chain_id}/{subscription_id}/{reason}/{marker_hash}` for the §9 #8 LOST marker (cf. `ext/subscription/chain_error_lost.go`).

The marker is the conformance lever — its absence + absence of a success entity = silent failure.

## CLI surface — `validate-peer`

| Flag | What it does | When you reach for it |
|---|---|---|
| `-category $CAT` | runs only one category | always start here when debugging one thing |
| `-exclude cat1,cat2` | hide passing/failing categories from output (still runs) | when you want a focused summary |
| `-failures-only` | suppress PASS lines in stdout | always, unless you're debugging the suite itself |
| `-verbose` | wire trace to stderr | only with `-category` (volume — see below) |
| `-json-out FILE` | structured report to file + text summary to stdout | when you want to compare runs or post-process |
| `-reference-peer host:port` | enable origination + cross-peer convergence categories | always, for a complete pass; without it the suite reports many tests as "skipped" or "blocked" |
| `-identity NAME` | use a named identity from `~/.entity/identities/` | always — without `framework-admin` (or equivalent) you'll get capability_denied on test paths |

**Mandatory pairing**: `-verbose 2>file` because stderr is unbuffered and very large.

## Verbose output volume (measured)

Plain UTF-8 with unicode box-drawing for separators. Every consumer is grep/awk/strings.

| Scope | Lines | Bytes |
|---|---|---|
| `-category revision -verbose` | ~830 | ~75 KB |
| `-verbose` (full suite, with reference) | ~30,000 | **~130 MB** |

Rule: don't `-verbose` the full suite unless you're collecting bulk data. Narrow with `-category` first.

## Honing patterns (recipes)

```bash
# All error responses
strings trace.log | grep "code:" | sort -u

# All wire calls touching a path
strings trace.log | grep "path.*$PATH_PREFIX"

# All EXECUTE invocations
strings trace.log | grep "EXECUTE entity://"

# Count operations
strings trace.log | awk '/op=/{n=NR; for(i=1;i<=NF;i++)if($i~/^op=/)print $i}' | sort | uniq -c

# PASS/FAIL/RUN counts
awk '/^RUN /{r++} /^PASS /{p++} /^FAIL /{f++} END{print "RUN:",r,"PASS:",p,"FAIL:",f}' trace.log
```

The trace is "data" to `file(1)` because of the unicode box chars, but every Unix text tool treats it correctly. `file` is wrong here; `strings` and `grep` both work.

## Hook surface — programmatic (in-process Go)

For L2 tools (workbench inspect, custom observability):

```go
// Wire — every framed envelope crossing the network boundary.
peer.WithWireHook("recorder", func(evt peer.WireEvent) {
    // evt.Direction, evt.FrameBytes, evt.RequestID, evt.RootType, evt.Timestamp
})

// Dispatch — invoke{entry,exit} at the dispatcher↔handler boundary.
peer.WithDispatchHook("tap", func(evt handler.DispatchEvent) {
    // evt.Phase, evt.TargetURI, evt.Operation, evt.ParamsHash,
    // evt.RequestID, evt.ResponseStatus, evt.ResponseHash (exit only)
})

// Binding — every tree write. Observe-only alias for WithNamedSyncHook
// that can't accidentally halt the cascade.
peer.WithBindingHook("watch", func(evt store.TreeChangeEvent) {
    // evt.Path, evt.Hash, evt.PreviousHash, evt.ChangeType, evt.Context.CascadeDepth
})

// Binding with path filter at registration. Engine skips the fn entirely
// for non-matching paths — no per-event string-compare inside the hook.
//
// Grammar — three coordinate-space cases for the multi-peer tree shape:
//
//   ""                              match all (legacy no-pattern API)
//   "*"                             match all
//
//   peer-relative — ANY peer namespace, suffix match (the default for
//   observers; gives full cross-peer visibility):
//     "system/attestation/*"        any peer's attestation subtree
//     "system/clock/now"            any peer's clock/now (exact suffix)
//
//   absolute, specific peer — matches that peer only:
//     "/PID_A/system/attestation/*" peer A's attestation subtree
//     "/PID_A/system/exact/path"    peer A, exact path
//
//   absolute, any peer (explicit) — same semantics as peer-relative:
//     "/*/system/attestation/*"     any peer's attestation subtree
//
// Why peer-relative defaults to namespace-agnostic: tree storage is
// peer-namespaced (/{peer_id}/...), but the logical content shape is
// peer-namespace agnostic — a write at PeerA's "system/attestation/x" and
// PeerB's "system/attestation/x" are the same kind of event from an
// observer's perspective. Local-only auto-scoping would silently lose
// every event from remote-peer namespaces (sync/revision/cache populates
// the local tree under those PIDs). Scope to one peer explicitly when
// that's what you actually want.

// Cross-peer visibility — fires for events under any peer in the tree:
peer.WithBindingHookPattern("att-watch", "system/attestation/*", ...)

// Local peer only (explicit):
peer.WithBindingHookPattern("local-att", "/"+localPID+"/system/attestation/*", ...)

// Specific remote peer:
peer.WithBindingHookPattern("remote-att", "/"+remotePID+"/system/attestation/*", ...)

// Cascade-participating variant (can halt with non-200):
peer.WithNamedSyncHookPattern("att-index", "system/attestation/*", fn)

// Content — every new content put.
peer.WithNamedContentHook("seen", func(evt store.ContentStoreEvent) *store.ContentConsumerResult {
    // evt.Hash, evt.Entity, evt.IsNew (always true today; documents the contract)
    return nil // observe-only; return non-nil only to halt cascade
})

// Subscription emit (matcher decided to notify).
engine.AddEmitHook("emit-tap", func(evt subscription.EmitEvent) { /* ... */ })

// Subscription deliver (wire attempt completed).
engine.AddDeliverHook("deliver-tap", func(evt subscription.DeliverEvent) { /* ... */ })
```

**Discipline (load-bearing):**
- All hooks fire on the hot path. Snapshot fact-tuple, return. Don't block.
- Hooks receive events **by value**. Don't retain pointers to mutable handler-owned objects past return.
- Static-at-construction: all hooks must be registered before the peer starts accepting traffic. There is no wire-installable hook at L0/L1 — that's the security primitive (operator-bounded by construction).

**Sensitive material**: `WireEvent.FrameBytes` is the raw envelope — caps, signatures, identities. A wire recorder's sink is a privileged artifact. Treat it as such.

### Sync vs async

- Dispatch, wire, subscription emit/deliver hooks: **sync inline**. Ordered, fast, no buffering.
- Binding events: also available as async fan-out via `peer.WithTreeEventSink(chan<- store.TreeChangeEvent)`. Per-sink isolation: a slow sink drops only its own events, others continue. Monitor via `peer.Stats().FanOutSinks`.

If you need async for the other event classes today, you have to wrap them yourself. Not built in.

## Writing new validate-peer checks — pitfalls

The two we've actually hit:

### 1. Cross-invocation test-state leakage

If your check writes to a path the peer persists across invocations, your test will pass the first time and fail the second. The classic shape:

```go
// BAD — assumes clean state.
r.Run("foo_idempotent", func() CheckOutcome {
    // First call writes to path P; expects "set".
    // Second call writes same content to P; expects "no_change".
    // BUT: re-run against same peer ⇒ first call already sees "no_change".
})
```

Two acceptable patterns:

**Pattern A — precondition cleanup (best when the op has a delete):**
```go
r.Run("foo_idempotent", func() CheckOutcome {
    _, _ = sendDelete(name) // ignore error; absent is fine
    // ... rest of test
})
```

**Pattern B — unique name per invocation (when no clean delete exists):**
```go
name := fmt.Sprintf("test-foo-%d", time.Now().UnixNano())
```

`merge_config_set_idempotent` (cmd/internal/validate/revision.go) is the precedent for Pattern A.

### 2. Wire trace is the source of truth, not the test message

When a check fails with a vague message, don't add more prints to the test — run with `-verbose`. The wire trace shows exactly what the peer returned. The test message is downstream of that.

## Cross-impl matrix debugging — workflow

A representative lesson from cross-impl matrix debugging: a handoff cycle was spent on a misdiagnosed bug because nobody actually ran the failing scenario under instrumentation. The first version of the handoff hypothesized three Ed448 verify-side root causes from static code reading; running the diagnostics took twenty minutes and showed the bug was on the *outbound* side (Rust transport-profile lookup), not verify, and the "403 invalid_signature" entries cited as evidence were validate-peer's own negative-path probes.

The pattern of failure was: speculation → memo → cross-team code review → guess what to instrument → maybe never run it. This section is how to skip that loop.

### Before you write a memo, run the scenario

Cross-impl peers (Go, Rust, Python) all start through the same harness:

```bash
go run ./cmd/peer-manager start --name dg48  --type go     --key-type ed448 --debug
go run ./cmd/peer-manager start --name drs48 --type rust   --key-type ed448 --debug
go run ./cmd/peer-manager start --name dpy48 --type python --key-type ed448 --debug
go run ./cmd/peer-manager list
```

Each peer's stderr is piped to `~/.entity/logs/{name}.log`. Rust runs under `RUST_LOG=debug` (set by peer-manager); Python and Go honor `--debug`. **All three logs are immediately readable** — Rust's tracing format is ANSI-decorated but `grep -a` works.

Drive the failing scenario through `validate-peer -peers` or `validate-peer -addr` and read **both** sides. Most cross-impl bugs leave a clear marker in one peer's log:

```bash
# After running the failing scenario:
grep -aE "ERROR|WARN|invalid|reject|fail|cannot|denied" ~/.entity/logs/drs48.log | head
```

That one line in this case surfaced the actual error in 30 seconds: `async delivery: SHA-256-form PID — cannot derive {peer_id_hex} locally`. No verify-side bug at all.

### Negative-path tests look like bugs in the responding peer's log

`validate-peer`'s `security` category runs the `sendTamperedExecute` family (`cmd/internal/validate/security.go:131`) — `tampered_signature`, `signer_author_mismatch`, `author_not_in_included`, etc. The responding peer SHOULD log `403 invalid signature` (or similar) for each. Reading those entries as evidence of a bug is the trap that broke the V7.67 cycle.

Disambiguate by mapping `request_id` → test name:

```bash
# In the same run, capture the validate-peer wire trace and the responding peer's log.
# Then grep for the request_id in both:
grep "request_id=validate-87" ~/.entity/logs/drs48.log
grep -B 2 "validate-87" /tmp/wire-trace.log    # shows the test that issued it
```

If the `request_id` belongs to `security.*` or `multisig.escalation_*` or anything sourced through `sendTamperedExecute`, the 403 is a PASS for the test, not a bug. The catalog of negative-path tests: `grep -rn "sendTamperedExecute\|expectsFailure\|expects_403" cmd/internal/validate/`.

### One-off in-process instrumentation beats memos

When you need the actual bytes (sig/pubkey/message) for cross-impl byte-level disagreement debugging, drop a temporary env-gated dump in the producing impl. The discipline:

1. **Gate behind an env var** — `if os.Getenv("ECG_DUMP_X") != ""` so it's a no-op for everyone else and you can toggle without rebuild discipline.
2. **Dump hex, not pretty-print** — comparable across impls.
3. **Include a self-verify** — `crypto.Verify(...)` on the dump path immediately tells you whether the bug is on the producing side or downstream. In the V7.67 case, `SELF_VERIFY=OK` on every dispatch killed every verify-side hypothesis in one line.
4. **Revert before commit** — `git diff` to confirm the working tree is back where it started.

This is faster than the alternative ("ask the other team to add a log line, wait for their build, read their output, ask them to add another log line") and removes the cross-repo build dependency entirely. The producing-side dump is enough to falsify "the receiver is wrong" if self-verify passes.

### The failure matrix is itself data — pattern-match it

A 9-row matrix with 4 failures is a fingerprint, not a list. Before writing any code, write down the candidate mechanism and check whether it predicts *every* failing row and *no* passing row.

V7.67 Phase 2 example:

| Failing pair | The §3.2 hypothesis predicted (verify-side Ed448 bug) | The actual mechanism (Rust outbound to SHA-256-form PID) |
|---|---|---|
| go-48 × rs-25 | ✓ rs-25 verifying foreign Ed448 sig | ✓ rs-25 async-delivers result back to go-48 (SHA-256) |
| go-48 × rs-48 | ✓ rs-48 verifying foreign Ed448 sig | ✓ rs-48 async-delivers result back to go-48 (SHA-256) |
| rs-25 × rs-48 | ✗ rs-48 verifying rs-25 Ed25519 sig (works in standalone) | ✓ rs-25 dispatches forward to rs-48 (SHA-256) |
| rs-48 × py-48 | ✗ py-48 verifying rs-48 Ed448 sig (Python verifies fine elsewhere) | ✓ rs-48 dispatches forward to py-48 (SHA-256) |

The verify-side hypothesis explains 2 of 4 rows. The transport-profile hypothesis explains 4 of 4. If a hypothesis doesn't fit the matrix, don't ship it as a memo — go find one that does.

### Standalone vs cross-impl signal

A category passing in single-peer mode but failing in multi-peer mode is information: the bug is in the cross-peer path. Categories like `convergence`, `convergent_mirror`, and `cross_peer_*` exist precisely to expose this gap. The Phase 1 byte-equality gate (Go × Rust × Python at fixed Ed448 seed) is a separate confirmation that locks the *unit*-level surface — if a unit-level claim is already byte-locked across impls, the bug is not at the unit level. Re-read the lock state before hypothesizing about it.

## Pitfalls (general)

- **Don't `-verbose` the full suite to a TTY.** 130 MB will hang your terminal. Always `2>file`.
- **`file(1)` reports the trace as "data".** It isn't — unicode box chars confuse it. Use any text tool.
- **`-failures-only` filters stdout only.** The wire trace on stderr is independent — it always contains everything.
- **`-reference-peer` enables 34 additional tests.** A "passing" run without it isn't a full pass; convergence and origination silently skip.

## References

- Validate-peer overview: `AGENTS.md` § Validate-peer CLI
- Peer setup for conformance: `docs/architecture/guides/PEER-VALIDATION-WORKFLOW.md`
- Grants required by the suite: `docs/architecture/guides/VALIDATE-PEER-GRANTS.md`
