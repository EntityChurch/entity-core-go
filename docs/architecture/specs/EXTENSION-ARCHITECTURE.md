# Extension Architecture

## Extension Layers

Extensions operate at three distinct levels, and almost everything lives at the top:

```
Layer 0: Raw tree events (core — NotifyingLocationIndex)
            ↓
Layer 1: Subscription engine (bridges events → protocol callbacks)
            ↓ capability-gated callbacks
Layer 2: Everything else (normal handlers — subscribe + receive callbacks)
```

**Layer 0** is core infrastructure. The NotifyingLocationIndex emits raw tree change events (path, hash, change type) on every location index mutation.

**Layer 1** is the subscription engine — the single extension that requires direct access to the event stream. It watches raw tree events, matches them against active subscriptions, and delivers notifications via the callback protocol. It is the bridge between the core event system and the protocol-level callback mechanism.

**Layer 2** is every other extension. History, sync, compute, query, relay — they all subscribe to paths via the protocol, receive capability-gated callback notifications, and do their work. They don't need raw event access. They're just handlers.

The subscription engine is the only extension that needs privileged access to the emit pathway (`WithTreeEventSink`). Every other extension is a handler that subscribes to changes and receives callbacks through the normal protocol. This is by design — the subscription/callback mechanism exists precisely so that extensions don't need to reach into core internals.

## Core vs Extension Boundary

The `core/` module contains the protocol library — types, encoding, dispatch, handlers, peer lifecycle. Extensions live in `ext/` and use the same handler interface as domain-specific handlers.

**Rule**: If it's in the protocol spec's core sections (EXECUTE, connect, capability, tree), it belongs in `core/`. If it's a system extension spec (callback, subscription, history, sync, compute) or a domain handler, it belongs in `ext/` or the application.

### What belongs in core

- Entity/envelope types and encoding (`entity`, `ecf`, `hash`, `wire`)
- Protocol dispatch and authentication (`protocol`)
- Capability checking (`capability`)
- Handler interface and registry (`handler`)
- Tree handler with get/put/snapshot/diff/merge/extract (`tree`)
- Type system and type registry (`types`)
- Storage interfaces (`store`)
- Identity and crypto (`crypto`)
- Peer lifecycle and builder (`peer`)
- The `SubscriptionEngine` interface in `tree/` (DI point for the Layer 1 bridge)
- Callback fields on `ExecuteData` (core protocol per spec §3.2)

### What belongs in ext

- Callback handler (`ext/callback`) — stores delivery/notification results
- Subscription engine (`ext/subscription`) — the Layer 1 bridge from events to callbacks
- Future: history, sync, compute, query, relay (all Layer 2 — handler + subscribe)

## The Three Peer Configurations

**Minimal peer** — `peer.New()` with no options:
- Connect + tree handlers only
- No callback storage, no subscriptions
- Can store entities, serve tree get/put, establish connections

**Callback peer** — adds `WithHandler("system/callback", ...)`:
- Can receive and store callback deliveries/notifications
- Other peers or handlers can dispatch async results to it
- Still no subscription support

**Standard peer** — adds callback + subscription engine:
- Full subscription support (subscribe, notify, unsubscribe)
- Extensions above this (history, sync, etc.) just subscribe and receive callbacks
- This is what `cmd/entity-peer` assembles

## Handler Interface

What every handler (core or extension) gets access to:

- `Handle(ctx, req)` — operation, params, resource target
- `HandlerContext` — store, location index, caller capability, handler grant, included entities, author
- `Execute()` — dispatch to any other handler (local or remote)
- `ManifestProvider` — declare operations, types, internal scope
- `TypeProvider` — contribute types to the registry

A handler can read/write the store, read/write the location index, and call other handlers via Execute. That's the full extent of its system access — capability-gated by the caller's token and the handler's own grant.

## How to Add a New Extension

Most extensions are Layer 2 — they're just handlers:

1. Create a package in `ext/`, e.g., `ext/history/`
2. Implement `handler.Handler` with `Manifest()` and `RegisterTypes()`
3. Register via `peer.WithHandler("system/history", history.NewHandler())`
4. Subscribe to tree paths via the protocol to receive change notifications
5. If it needs cleanup on shutdown, use `peer.WithCloseFunc(cancelFn)`

Only the subscription engine (Layer 1) uses `WithTreeEventSink` for raw event access. New extensions should not need it — they should subscribe via callbacks instead.

## Integration Points

| Mechanism | Purpose | Who uses it |
|-----------|---------|-------------|
| `WithHandler` | Register handler at a pattern | All extensions |
| `WithSubscriptionEngine` | Wire subscription into tree handler | Subscription engine only |
| `WithTreeEventSink` | Raw tree event access | Subscription engine only |
| `WithCloseFunc` | Cleanup on peer shutdown | Extensions with background goroutines |

## Standard Peer Assembly

The `cmd/entity-peer` binary assembles a standard peer with all system extensions:

```go
engine := subscription.NewEngine(cs, li, debugLog)
engineEvents := make(chan store.TreeChangeEvent, 256)
engineCtx, cancelEngine := context.WithCancel(context.Background())

opts = append(opts,
    peer.WithHandler("system/callback", callback.NewHandler()),
    peer.WithSubscriptionEngine(engine),
    peer.WithTreeEventSink(engineEvents),
    peer.WithCloseFunc(cancelEngine),
)

p, err := peer.New(opts...)

engine.Deliver = subscription.MakeDeliveryFunc(
    p.Keypair(), p.Identity(), p.Store(), p.LocationIndex(), p.Dispatcher(),
)
engine.Start(engineCtx, engineEvents)
```

## When to Cross the Core Boundary

Move something from ext to core only if:

- [ ] It's referenced by the core EXECUTE dispatch path
- [ ] It's a field on a core protocol message (ExecuteData, etc.)
- [ ] Other core packages need to import it (would create ext→core→ext cycle)
- [ ] The protocol spec's core sections require it

If none apply, it belongs in ext.
