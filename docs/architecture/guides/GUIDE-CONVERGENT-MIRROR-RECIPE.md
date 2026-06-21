# Guide — Convergent-Mirror Recipe (Go)

**Status:** Implementation guide for the EXTENSION-SUBSCRIPTION v3.14 + V7 v7.50 cross-peer mirror recipe in Go. Follows the design in `entity-core-architecture/.../proposals/PROPOSAL-CONVERGENT-MIRRORING.md`.

This guide covers:
- The common-case recipe (single continuation; relies on `include_payload` + `deref_included`)
- The drop-tolerant variant (composed local handler)
- Bootstrap behavior (CAS-create on first write)
- Validation: cycle test + `convergent_mirror` validate-peer category

## 1. The bug this recipe fixes

"Follow another peer's tree" was implemented as: `subscription → cont1(cross-peer GET upstream) → cont2(unconditional tree:put local)`. Two problems:

1. **Unbounded amplification under concurrency.** A stale lap arriving at a peer that's already advanced silently rolls state back; the rollback is itself a tree change that re-fires forward; the ring never quiesces. Go's `cmd/internal/interop/cycle_test.go` reproduced this — 20 writes produced ~87 laps/peer instead of ~20.
2. **Three cross-peer hops per notification** (notification + GET request + GET response), plus a race window where the GET can return newer source state than the notification announced.

The fix is two orthogonal pieces: CAS on the local PUT terminates the amplification; `include_payload` collapses the recipe to one hop and one continuation.

## 2. The recipe (common case)

The receiver installs a single continuation at an inbox path:

```go
mirror := types.ContinuationData{
    Target:    "system/tree",
    Operation: "put",
    Resource:  &types.ResourceTarget{Targets: []string{mirrorPath}},
    ResultTransform: &types.ContinuationTransformData{
        Select: map[string]string{
            "entity":        "hash",          // notification.hash → put.entity
            "expected_hash": "previous_hash", // notification.previous_hash → put.expected_hash
        },
        TransformOps: []types.ContinuationTransformOpData{
            {Op: "deref_included", Field: "entity"}, // hash → entity from envelope.included
        },
    },
    // No Params / ResultField — pass-through: the post-transform value IS params.
}
// Install on receiver:
validate.InstallCrossPeerContinuation(ctx, receiverClient, receiverClient, mirrorInbox, mirror)
```

The source subscribes with `include_payload=true`:

```go
token, tokenSig, _ := sourceClient.CreateDeliveryToken(deliverURI, "receive")
sourceClient.SubscribeWithPayload(ctx, mirrorPattern, deliverURI, "receive",
    token, tokenSig, []string{"created", "updated"}, nil, /*includePayload*/ true)
```

That's it. The source bundles the changed entity in the delivery envelope's `included`; the receiver's continuation extracts both the hash and the previous-state anchor from the notification, derefs the hash into the entity bytes from `included`, and CAS-PUTs locally.

### Why this works

- Notification fires at source. Source resolves the new entity from its content store; attaches to the delivery envelope's `included` (`ext/subscription/engine.go:371-394`).
- Envelope crosses the wire to the receiver. `core/protocol/local.go:DispatchLocalEnvelope` threads `env.Included` through `AsyncDelivery.Extras` so it survives the local→remote routing boundary. (Without this, the included payload is silently lost — that was the §7 gap caught during impl.)
- Receiver's inbox handler dispatches `continuation/advance`; `hctx.Included` flows through the existing sub-dispatch propagation.
- The continuation's `ResultTransform` runs:
  - `Select` maps `notification.hash → entity`, `notification.previous_hash → expected_hash`.
  - `deref_included {field: "entity"}` looks up the hash in `hctx.Included` and replaces the field with the full entity bytes (as `cbor.RawMessage`).
- Pass-through assembly turns the post-transform map into the put-request params.
- `tree:put` decodes `entity` as the inline payload; CAS-checks `expected_hash` against the local binding.

### Bootstrap (first write to a fresh mirror path)

The first notification at a fresh receiver path is a `created` event with `previous_hash` absent (or zero, depending on impl). The recipe handles this via V7 §3.9 v7.50 CAS-create semantics:

- `expected_hash` absent ⇒ unconditional write (used when notifications omit `previous_hash` per the CBOR `omitzero` convention).
- `expected_hash` non-zero ⇒ CAS-replace (succeeds iff current binding equals it).
- `expected_hash = zero hash` ⇒ CAS-create (succeeds iff path is unbound).

For one-way single-writer mirrors (the cycle test pattern), the bootstrap proceeds as an unconditional write because the notification omits `previous_hash`. For multi-writer convergent mirrors where the bootstrap-race matters, sources should emit `previous_hash` as the zero hash on `created` events (cross-impl coordination pending).

### Stale-lap termination

A stale lap carries `previous_hash = old_state_hash` but arrives at a receiver whose current binding is a newer hash. The CAS check fails with `409 hash_mismatch`; `tree:put` does nothing; the chain ends. No tree change ⇒ no forward propagation ⇒ amplification terminates. This is exactly what `cycle_test.go` observes: 19 stale laps fail CAS cleanly while the single in-order lap per write succeeds. Net amplification ratio: 1.00 laps/peer/write.

## 3. The drop-tolerant variant (optional)

If notifications can be dropped (unreliable subscription transport) and the receiver still needs to converge to source's latest state, compose a thin local handler:

```go
type mirrorHandler struct{ /* ... */ }

func (h *mirrorHandler) Handle(ctx, req *handler.Request) (*handler.Response, error) {
    // Decode notification (req.Params is the InboxNotificationData entity).
    // Read receiver's current head locally via hctx.LocationIndex.Get(mirrorPath).
    // Decide: apply if newer; reconcile via tree:get to source if local head is stale and
    // notification.previous_hash doesn't match.
    // Dispatch tree:put with appropriate CAS via hctx.Execute.
    return ...
}
```

Per `PROPOSAL-CONVERGENT-MIRRORING §2`, this is the "compose more when you need more" path. It's a local handler (not a protocol op) and not a cross-peer call. The common-case recipe should be the documented default; drop-tolerance is a deliberate composition.

## 4. Spec dependencies

The recipe needs:

| Spec / mechanism | Version | Site |
|---|---|---|
| `tree:put` CAS-create variant | V7 v7.50 §3.9 | `core/tree/handler.go:341-355` |
| `include_payload` opt-in subscription option | EXTENSION-SUBSCRIPTION v3.12/v3.13/v3.14 | `ext/subscription/engine.go:371-394` |
| `deref_included` transform_op | DOUBTS §9b (pending arch ratification) | `ext/continuation/transform_ops.go` |
| Envelope `Included` cross-peer preservation | DOUBTS §7 (pending arch ratification as normative invariant) | `core/protocol/local.go:DispatchLocalEnvelope` |

All four are implemented in Go (commits `5591ad9`, `5239ff3`, `8e7b6cc`, `2c3a976`). The latter two are open doubts for arch ratification — Go's posture is "land ahead, rebase to ratified spelling."

## 5. Validation

Two layers:

**Go-internal (cycle test):** `cmd/internal/interop/cycle_test.go::TestCrossPeerCycle` spins up four networked peers in a ring, exercises the recipe, and asserts the convergent-mirror canonical gate (laps per peer ≤ 1.5 × N). After the v3.14 rewire, observed amplification is 1.00 laps/peer/write (was ~87 pre-fix).

**Cross-impl (validate-peer):** the `convergent_mirror` category exercises the recipe end-to-end against two live peers and asserts:

- `recipe_install` — receiver installs the mirror continuation
- `recipe_subscribe` — source subscribes with `include_payload=true`
- `writes_driven` — source drives N writes
- `converges_to_latest` — receiver reaches source's final state within the time bound
- `entity_fidelity` — mirrored entity validates and preserves type
- `bounded_amplification` — receiver's mirror prefix has ≤ 1.5 × N bindings

Run via:

```bash
go run ./cmd/validate-peer -peers host1:port,host2:port -category convergent_mirror
```

Or as part of the full multi-peer suite:

```bash
go run ./cmd/validate-peer -peers host1:port,host2:port
```

Any V7-conformant peer that supports v3.14 `include_payload`, v7.50 CAS-create, and the `deref_included` transform_op MUST pass these six checks. Cross-impl divergence on any single check is a conformance gap.

## 6. What this recipe is NOT

- **Not a `tree:mirror` op.** Mirroring is "apply this transition with CAS"; `tree:put` already does that. The earlier draft of `PROPOSAL-CONVERGENT-MIRRORING` invented a `tree:mirror` op and a cross-peer fetch-on-reconcile — both wrong, both withdrawn.
- **Not a `revision:diff-since-local-head` reshape.** The deferred proposal stays deferred; the convergent-mirror is a different problem (apply-with-CAS) than versioned incremental diff.
- **No cross-peer fetch on reconcile.** Source pushes the entity in the delivery envelope; receiver applies locally. The receiver-local invariant is trivially satisfied because there is no cross-peer step in the reconcile path.

## 7. References

- Authoritative design: `entity-core-architecture/.../proposals/PROPOSAL-CONVERGENT-MIRRORING.md`
- Background (analytical core): `entity-core-architecture/.../core-protocol-domain/explorations/EXPLORATION-CAS-AND-CONVERGENT-MIRRORING.md`
- Implementation:
  - V7 v7.50 CAS-create: `core/tree/handler.go:341-355`
  - `include_payload` engine + handler + types: `ext/subscription/engine.go`, `ext/subscription/handler.go`, `core/types/delivery.go`
  - `deref_included` transform_op: `ext/continuation/transform_ops.go`
  - Envelope `Included` cross-peer preservation: `core/protocol/local.go:DispatchLocalEnvelope`
  - Cycle test: `cmd/internal/interop/cycle_test.go::TestCrossPeerCycle`
  - Validate-peer category: `cmd/internal/validate/convergent_mirror.go`
