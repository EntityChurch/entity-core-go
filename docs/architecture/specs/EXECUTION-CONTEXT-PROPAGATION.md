# Execution Context Propagation

**Status**: Architecture review — documenting current behavior, identified gaps, fix direction
**Scope**: All three implementations (Go, Rust, Python)

---

## 1. The Principle

**Every operation in the system operates under authority.** There are no anonymous mutations, no context-free writes, no optimizations that bypass the capability system.

The authority model is structural and exhaustive:

1. **Peer startup** — the peer creates its own identity and issues a **peer grant** — the root authority from which all handler grants are delegated. Every handler gets its own grant stored at `system/capability/grants/{handler_pattern}`. Even startup seeding (types, manifests, grants) operates under the peer's own authority.

2. **External calls** — the dispatcher verifies the caller's identity and capability token from the wire envelope. The `HandlerContext` carries the caller's `AuthorHash` and `CallerCapability`.

3. **Handler-to-handler calls** — `hctx.Execute()` creates a child `HandlerContext` that inherits `Author` and `CallerCapability` from the parent. The child gets its own `HandlerGrant` and `HandlerPattern`. Authority chains through.

4. **Autonomous operations** — subscription delivery, clock advancement, file watchers — the peer acts as its own author using the relevant handler grant. The peer has decided that this operation runs on its own accord. That IS the authority — the handler grant.

5. **Background goroutines** — any code that writes to the tree outside the dispatch pipeline is still operating under the peer's authority. If a background goroutine bypasses the dispatcher, the context is the peer's identity + the relevant handler grant. There is no "no context" case — there is only "context not yet wired."

The goal is **strict mode**: every write carries a `MutationContext` with author + capability + handler + operation. If we later want to relax this for performance (e.g., skip recording for system-internal paths), we can — but the context is still present, just not persisted. The optimization is in what we do with the context, not in whether it exists.

---

## 2. What the History Spec Requires

EXTENSION-HISTORY v1.2 §2.1 defines the transition entity:

```
system/history/transition := {
  author:        {type_ref: "system/hash"}       ; MUST (§9.1)
  capability:    {type_ref: "system/hash"}       ; MUST (§9.1)
  handler:       {type_ref: "system/tree/path"}  ; SHOULD (§9.1)
  operation:     {type_ref: "primitive/string"}   ; SHOULD (§9.1)
  chain_id:      {type_ref: "primitive/string", optional: true}
}
```

§5.1 says the emit pathway is triggered by "any tree mutation — put, merge, delete, or any handler operation that writes to the location index." The `execution_context` parameter is always present.

The spec does not distinguish between "tree handler writes" and "extension handler writes." All mutations carry context.

---

## 3. The Mechanism (Go Implementation)

### 3.1 MutationContext

Every tree write flows through `MutationContext`, which carries execution metadata from the handler that triggered the mutation:

```go
// core/store/event.go
type MutationContext struct {
    AuthorHash     hash.Hash   // Content hash of the caller's identity entity
    CapabilityHash hash.Hash   // Content hash of the capability token used
    HandlerPattern string      // Handler that processed the operation
    Operation      string      // Operation name (e.g., "put", "merge", "commit")
    ChainID        string      // Causal correlation from bounds context
}
```

This is attached to `TreeChangeEvent.Context` and available to all sync hooks and event consumers.

### 3.2 TreeSet / TreeRemove

All handler writes go through `HandlerContext.TreeSet()` and `HandlerContext.TreeRemove()`:

```go
// core/handler/handler.go
func (hctx *HandlerContext) TreeSet(path string, h hash.Hash, operation string)
func (hctx *HandlerContext) TreeRemove(path string, operation string) (hash.Hash, bool)
```

These build a `MutationContext` from the handler context and delegate to `SetWithContext` / `RemoveWithContext` on the location index. No handler should call `LocationIndex.Set()` or `LocationIndex.Remove()` directly.

### 3.3 Capability Selection

The `mutationContext()` method selects the capability hash:

```go
func (hctx *HandlerContext) mutationContext(operation string) *store.MutationContext {
    ctx := &store.MutationContext{
        AuthorHash:     hctx.AuthorHash,
        HandlerPattern: hctx.HandlerPattern,
        Operation:      operation,
    }
    if !hctx.CallerCapability.ContentHash.IsZero() {
        ctx.CapabilityHash = hctx.CallerCapability.ContentHash
    } else if !hctx.HandlerGrant.ContentHash.IsZero() {
        ctx.CapabilityHash = hctx.HandlerGrant.ContentHash
    }
    if hctx.Bounds != nil {
        ctx.ChainID = hctx.Bounds.ChainID
    }
    return ctx
}
```

**Priority**: CallerCapability (the grant that entered the chain) > HandlerGrant (the handler's own self-issued grant).

This means the recorded capability traces back to the original authority that started the handler chain, not the intermediate handler machinery.

---

## 4. Handler Chain Context Propagation

### 4.1 Direct External Call

```
Remote caller → Dispatcher → Tree Handler → TreeSet
```

| Field | Value |
|-------|-------|
| Author | Remote peer's identity hash |
| Capability | Remote peer's connection grant |
| Handler | `system/tree` |
| Operation | `put` |

The dispatcher builds the HandlerContext from the wire envelope. The tree handler calls `hctx.TreeSet()`.

### 4.2 Handler-to-Handler (via hctx.Execute)

```
Remote caller → Dispatcher → Revision Handler → hctx.Execute("system/tree", "merge")
```

| Step | Author | Capability | Handler | Operation |
|------|--------|------------|---------|-----------|
| Revision handler writes | Remote peer | Remote grant (inherited) | system/revision | commit |
| Tree handler writes (if dispatched via Execute) | Remote peer | Remote grant (inherited) | system/tree | merge |

`makeLocalExecute` inherits `Author` and `CallerCapability` from the parent context. The child gets a new `HandlerPattern` and `HandlerGrant` for the target handler.

### 4.3 Autonomous Chain (Subscription → Inbox → Continuation → Tree)

```
Subscription engine → DispatchLocalEnvelope → Inbox → hctx.Execute → Continuation → hctx.Execute → Tree
```

| Step | Author | Capability | Handler | Operation |
|------|--------|------------|---------|-----------|
| Subscription delivers to inbox | Local peer | Inbox handler grant | system/inbox | receive |
| Inbox delegates to continuation | Local peer | Inbox handler grant (inherited) | system/continuation | advance |
| Continuation dispatches to tree | Local peer | Inbox handler grant (inherited) | system/tree | put |

The subscription engine creates an authenticated EXECUTE envelope using `MakeDeliveryFunc`:
- Author = local peer's identity
- Capability = inbox handler grant (looked up from `system/capability/grants/system/inbox`)

This envelope goes through `DispatchLocalEnvelope` → normal dispatch pipeline. The dispatcher builds a HandlerContext with these values. The inbox handler's `hctx.Execute()` inherits them into child contexts.

**Key insight**: The capability recorded throughout the chain is the **inbox handler grant** — the grant that authorized entry into the autonomous pipeline. This correctly answers "under what authority was this change made?"

### 4.4 Clock Advancement

```
Tree change event → Clock handler (async goroutine) → LocationIndex.Set
```

Clock advancement runs outside the handler dispatch pipeline. It processes tree change events asynchronously and writes clock state directly.

**Current gap**: Clock advancement does NOT go through `HandlerContext.TreeSet()`. It writes via a raw `LocationIndex.Set()` call because it runs in a background goroutine, not inside a dispatched handler request.

```go
// ext/clock/handler.go — StartAdvancement goroutine
li.Set(clockPath, clockHash)  // No execution context
```

This needs review. The clock handler should either:
- Use a synthetic HandlerContext with the peer's identity and clock handler grant, or
- Accept that clock writes are system-internal and exempt from context tracking (they're at `system/clock/*` which is excluded from history recording via recursion prevention anyway)

### 4.5 File Watcher (Reverse Write)

```
fsnotify event → localfiles.StartReverseWrite goroutine → LocationIndex.Set
```

Similar to clock: reverse write runs outside the dispatch pipeline. It writes file entities to the tree when filesystem changes are detected.

**Current gap**: Reverse write uses raw `LocationIndex.Set()`, not `HandlerContext.TreeSet()`. It has no HandlerContext because it runs in a background goroutine.

Unlike clock, these writes ARE at user-visible paths (e.g., `local/files/docs/readme`) and SHOULD be tracked by history. The author is the local peer, the capability is the localfiles handler grant.

---

## 5. Startup / Initialization Writes

During peer construction, before any handler is registered:

```go
// core/peer/peer.go
li.Set(td.TreePath(), h)                         // Type definitions
li.Set("system/handler/"+pattern, hh)             // Handler manifests
li.Set("system/capability/grants/"+pattern, capHash) // Handler grants
```

These use raw `li.Set()` with no context. They happen before the history recorder is initialized, and seed events are drained before the peer starts serving.

**Assessment**: These are deterministic initialization writes. They produce the same result on every peer startup. Recording them in history would add noise without audit value. The current behavior (no context, events drained) is acceptable.

---

## 6. Extension-by-Extension Audit

### Core Tree Handler (`core/tree/`)
- **put**: `hctx.TreeSet(path, storedHash, "put")` ✓
- **delete** (put with nil entity): `hctx.TreeRemove(path, "delete")` ✓
- **merge**: `hctx.TreeSet(targetPath, incomingHash, "merge")` ✓
- All write paths use TreeSet/TreeRemove.

### Revision (`ext/revision/`)
- **commit**: `hctx.TreeSet(headPath, versionHash, "commit")` ✓
- **merge**: `hctx.TreeSet(...)` / `hctx.TreeRemove(...)` with "merge" ✓
- **checkout**: `hctx.TreeSet(...)` / `hctx.TreeRemove(...)` with "checkout" ✓
- **branch**: `hctx.TreeSet(bp, ..., "branch")` / `hctx.TreeRemove(bp, "delete-branch")` ✓
- **tag**: `hctx.TreeSet(tp, ..., "tag")` / `hctx.TreeRemove(tp, "delete-tag")` ✓
- **cherry-pick**: `hctx.TreeSet(...)` / `hctx.TreeRemove(...)` with "cherry-pick" ✓
- **revert**: `hctx.TreeSet(...)` / `hctx.TreeRemove(...)` with "revert" ✓
- **resolve**: `hctx.TreeSet(...)` / `hctx.TreeRemove(...)` with "resolve" ✓
- **push**: `hctx.TreeSet(remotePath, ..., "push")` ✓
- All 37 write sites use TreeSet/TreeRemove.

### Subscription (`ext/subscription/`)
- **subscribe**: `hctx.TreeSet("system/subscription/"+id, ..., "subscribe")` ✓
- **renewal**: `hctx.TreeSet(subPath, ..., "subscribe")` ✓
- **unsubscribe**: `hctx.TreeRemove(subPath, "unsubscribe")` ✓

### Inbox (`ext/inbox/`)
- **receive** (write-ahead): `hctx.TreeSet(storagePath, ..., "receive")` ✓
- **receive** (cleanup after advance): `hctx.TreeRemove(storagePath, "receive")` ✓

### Continuation (`ext/continuation/`)
- **advance** (join update): `hctx.TreeSet(joinPath, ..., "advance")` ✓
- **advance** (exhausted delete): `hctx.TreeRemove(path, "advance")` ✓
- **advance** (remaining_executions update): `hctx.TreeSet(path, ..., "advance")` ✓
- **advance** (join reset): `hctx.TreeSet(joinPath, ..., "advance")` ✓
- **resume**: `hctx.TreeRemove(path, "resume")` ✓
- **abandon**: `hctx.TreeRemove(path, "abandon")` ✓

### Local Files (`ext/localfiles/`)
- **read**: `hctx.TreeSet(treePath, fh, "read")` ✓
- **write**: `hctx.TreeSet(treePath, fh, "write")` ✓
- **delete**: `hctx.TreeRemove(treePath, "delete")` ✓
- **watch**: `hctx.TreeSet(watcherPath, wh, "watch")` ✓
- **Reverse write (background)**: uses raw `li.Set()` ✗ — see §4.5

### History (`ext/history/`)
- **rollback**: `hctx.TreeSet(path, params.TargetHash, "rollback")` ✓
- **recorder** (head pointer): `SetWithContext` with peer identity + history handler grant, operation="record" ✓
  - Recursion prevention excludes these paths from history recording, but context is still present for other consumers

### Clock (`ext/clock/`)
- **Handler operations** (now, compare, tick): read-only, no writes ✓
- **Advancement (background)**: uses raw `li.Set()` ✗ — see §4.4 (but `system/clock/` is excluded from history)

### Query (`ext/query/`)
- Read-only handler (find, count). No tree writes. ✓

---

## 7. Identified Gaps and Fix Direction

Every gap here represents a place where we prematurely optimized by bypassing the capability system. The fix direction is the same in all cases: wire the context through, don't skip it.

### 7.1 Clock Advancement — MUST FIX

Clock advancement writes to `system/clock/*` via raw `h.li.Set()` without context.

Even though these paths are excluded from history recording, the principle is that every write operates under authority. The clock handler has a grant at `system/capability/grants/system/clock`. The advancement goroutine should use it.

**Fix**: Look up the clock handler grant once at `StartAdvancement` time. Build a `MutationContext` with author=peer identity, capability=clock handler grant, handler="system/clock", operation="advance". Use `SetWithContext` in the advancement loop.

### 7.2 Local Files Reverse Write — MUST FIX

Reverse write runs in a background goroutine with no context. It writes to user-visible paths (`local/files/docs/readme`) that history should track.

The localfiles handler has a grant at `system/capability/grants/local/files`. The peer has decided that filesystem changes should be reflected in the tree — that's the peer acting under its own authority via the localfiles handler grant.

**Fix**: Same pattern as clock. Look up the localfiles handler grant once at `StartReverseWrite` time. Build a reusable `MutationContext`. Use `SetWithContext` in the reverse write loop.

### 7.3 Startup Writes — SHOULD FIX (Phase 2)

Startup seeding (types, manifests, grants) uses raw `li.Set()` before handlers are registered. These writes happen before the history recorder is active and events are drained.

Even so, the peer IS the author. The peer's own identity exists at this point. What's missing is a "peer startup grant" — the root authority from which handler grants are delegated.

**Fix direction**: Create a peer-level grant (or use the peer's identity as implicit authority) for startup writes. Pass a startup `MutationContext` to `seedFromRegistries` and `createHandlerGrants`. Events are still drained (history doesn't record them), but the context is present in the event pipeline for any consumer that cares.

This is lower priority because the events are drained and the writes are deterministic. But architecturally, the context should be there.

---

## 8. Cross-Implementation Comparison

### 8.1 What We Validated

History validation (27 checks) includes 4 context checks:
- `context_author_present` — MUST per §9.1
- `context_capability_present` — MUST per §9.1
- `context_handler_present` — SHOULD per §9.1
- `context_operation_present` — SHOULD per §9.1

Results for a simple tree put (remote caller → tree handler):

| Field | Go | Rust | Python |
|-------|-----|------|--------|
| Author | Remote peer identity hash | Remote peer identity hash | Remote peer identity hash |
| Capability | Remote peer's connection grant | Remote peer's connection grant | Remote peer's connection grant |
| Handler | `system/tree` | `/{peerID}/system/tree` | `system/tree` |
| Operation | `put` | `put` | `put` |

All three implementations correctly record the remote caller's identity and grant for direct tree puts.

### 8.2 Minor Divergence: Handler Path Format

Rust records the handler as an absolute path (`/{peerID}/system/tree`) while Go and Python use the bare handler pattern (`system/tree`). The spec says the field type_ref is `system/tree/path` but doesn't specify absolute vs relative format.

**Recommendation**: Clarify in the spec. Both formats identify the handler. The bare pattern is more portable (doesn't embed a specific peer ID). Suggest standardizing on bare pattern.

### 8.3 What Needs Cross-Implementation Testing

The simple case (remote → tree put) is validated. The following scenarios need validation across all implementations:

1. **Handler chain**: Does revision commit record context on its internal writes?
2. **Autonomous delivery**: Does subscription → inbox → continuation chain propagate the local peer's identity and inbox handler grant?
3. **Multi-hop**: In a chain A → B → C, does the final write record A's identity and grant (the chain originator)?

These are harder to validate remotely because they require setting up subscriptions, continuations, and observing the resulting history transitions. The current validation suite tests direct tree puts; extending it to test handler chains would require a dedicated convergence test.

---

## 9. Open Questions for Architecture Review

1. **Which capability should be recorded in the transition — CallerCapability or HandlerGrant?** Currently Go records CallerCapability (the grant that entered the handler chain). This answers "under whose authority was this initiated?" The HandlerGrant would answer "which handler's own authority performed this specific write?" For a remote caller → tree put, they're different grants. For autonomous operations, they may be the same. The spec should prescribe this. Our current behavior (CallerCapability, fall back to HandlerGrant) seems right — it traces the chain of authority.

2. **Handler path format — absolute or bare pattern?** Rust records `/{peerID}/system/tree`, Go/Python record `system/tree`. Bare pattern is more portable. Recommend standardizing on bare pattern.

3. **Should the spec define a peer startup grant?** Currently handler grants are self-issued by the peer with wildcard scope. A formal "peer grant" as the root of the delegation chain would make the authority model explicit: peer grant → handler grants → connection grants. This is how the system actually works — making it formal helps cross-implementation alignment.

4. **What should the spec say about context and optimization?** Proposed: the spec should state that every tree mutation has an execution context (author + capability). Implementations MAY choose not to persist the context for certain system-internal paths (e.g., `system/history/`, `system/clock/`), but the context MUST be available in the event pipeline. The optimization is in persistence, not in context existence.
