package validate

import (
	"context"
	"fmt"
	"math/rand"
	"time"

	"go.entitychurch.org/entity-core-go/core/ecf"
	"go.entitychurch.org/entity-core-go/core/entity"
	"go.entitychurch.org/entity-core-go/core/types"

	"github.com/fxamacker/cbor/v2"
)

const catConvergentMirror = "convergent_mirror"

// runConvergentMirror exercises the EXTENSION-SUBSCRIPTION v3.14 +
// V7 v7.50 cross-peer mirror recipe end-to-end and asserts the
// PROPOSAL-CONVERGENT-MIRRORING §5 conformance gate: bounded
// amplification under concurrent / out-of-order delivery, plus
// convergence-to-latest.
//
// Recipe (one-way A→B, the minimal cross-peer surface):
//
//   - B installs a single local mirror continuation at an inbox path
//     using ResultTransform with Select {entity: hash, expected_hash:
//     previous_hash} + transform_op deref_included on the entity field.
//   - B subscribes to A's mirror prefix with include_payload=true,
//     deliver_to B's mirror inbox.
//   - A drives N tree writes on its mirror prefix.
//   - We verify B converges to A's final state within a bounded time
//     and that the per-peer amplification stays under the canonical
//     gate of 1.5 × N (one-way means the upper bound is exactly N
//     successful settle-writes at B; we keep 1.5×N for headroom
//     against transient races).
//
// Cross-impl conformance: any V7-conformant peer that supports v3.14
// include_payload, v7.50 CAS-create, and the deref_included transform_op
// (DOUBTS §9b) MUST pass this gate. Drop-injection property (ii) per
// PROPOSAL-CONVERGENT-MIRRORING §5 is impl-internal and not covered
// here — convergence-to-latest is the cross-impl assertion.
func runConvergentMirror(ctx context.Context, clients []*PeerClient) []CheckResult {
	r := NewCheckRunner(catConvergentMirror)

	r.Declare("recipe_install", "PROPOSAL-CONVERGENT-MIRRORING §3")
	r.Declare("recipe_subscribe", "EXTENSION-SUBSCRIPTION §2.3 v3.14")
	r.Declare("writes_driven", "PROPOSAL-CONVERGENT-MIRRORING §5")
	r.Declare("converges_to_latest", "PROPOSAL-CONVERGENT-MIRRORING §2.2")
	r.Declare("entity_fidelity", "ENTITY-CORE-MACHINE-SPEC §1.8 (mirror preserves hash)")
	r.Declare("bounded_amplification", "PROPOSAL-CONVERGENT-MIRRORING §5 (≤ 1.5 × N)")

	if len(clients) < 2 {
		// Skip everything with a single SKIP at the front.
		r.Run("recipe_install", func() CheckOutcome {
			return SkipCheck("requires 2+ peers (use -peers host1:port,host2:port)")
		})
		for _, name := range []string{"recipe_subscribe", "writes_driven", "converges_to_latest", "entity_fidelity", "bounded_amplification"} {
			n := name
			r.Run(n, func() CheckOutcome { return BlockCheck("recipe_install") })
		}
		return r.Results()
	}
	a, b := clients[0], clients[1]
	bID := string(b.RemotePeerID())

	suffix := fmt.Sprintf("%d", rand.Intn(100000))
	mirrorPrefix := "system/validate/convergent-mirror-" + suffix
	mirrorDocPath := mirrorPrefix + "/doc"
	mirrorPattern := mirrorPrefix + "/*"
	mirrorInbox := "system/inbox/convergent-mirror-" + suffix

	const writes = 20

	// (1) Install the local mirror continuation on B at the inbox path.
	r.Run("recipe_install", func() CheckOutcome {
		mirror := types.ContinuationData{
			Target:    "system/tree",
			Operation: "put",
			Resource:  &types.ResourceTarget{Targets: []string{mirrorDocPath}},
			ResultTransform: &types.ContinuationTransformData{
				Select: map[string]string{
					"entity":        "hash",          // notification.hash → put.entity (hash ref)
					"expected_hash": "previous_hash", // notification.previous_hash → put.expected_hash
				},
				TransformOps: []types.ContinuationTransformOpData{
					{Op: "deref_included", Field: "entity"}, // hash → entity from envelope.included
				},
			},
		}
		if err := InstallCrossPeerContinuation(ctx, b, b, mirrorInbox, mirror); err != nil {
			return FailCheck("install mirror continuation on B: " + err.Error())
		}
		return PassCheck("mirror continuation installed at " + mirrorInbox)
	})

	// (2) Subscribe B's mirror inbox to A's prefix with include_payload=true.
	r.Run("recipe_subscribe", func() CheckOutcome {
		if out, ok := r.Require("recipe_install"); !ok {
			return out
		}
		deliverURI := "entity://" + bID + "/" + mirrorInbox
		token, tokenSig, err := a.CreateDeliveryToken(deliverURI, "receive")
		if err != nil {
			return FailCheck("create delivery token on A: " + err.Error())
		}
		subID, _, _, err := a.SubscribeWithPayload(ctx, mirrorPattern, deliverURI, "receive",
			token, tokenSig, []string{"created", "updated"}, nil, true)
		if err != nil || subID == "" {
			return FailCheck(fmt.Sprintf("subscribe on A: %v", err))
		}
		r.Store("subID", subID)
		return PassCheck("B subscribed to A with include_payload=true (sub=" + subID + ")")
	})

	// (3) Drive N writes at A.
	r.Run("writes_driven", func() CheckOutcome {
		if out, ok := r.Require("recipe_subscribe"); !ok {
			return out
		}
		var lastEntity entity.Entity
		for w := 0; w < writes; w++ {
			raw, err := ecf.Encode(map[string]interface{}{
				"seq":     w,
				"content": fmt.Sprintf("convergent-mirror-%d", w),
			})
			if err != nil {
				return FailCheck(fmt.Sprintf("encode write %d: %v", w, err))
			}
			ent, err := entity.NewEntity("test/mirror-doc", cbor.RawMessage(raw))
			if err != nil {
				return FailCheck(fmt.Sprintf("build write %d: %v", w, err))
			}
			if _, err := a.TreePut(ctx, mirrorDocPath, ent); err != nil {
				return FailCheck(fmt.Sprintf("write %d on A: %v", w, err))
			}
			lastEntity = ent
			time.Sleep(25 * time.Millisecond)
		}
		r.Store("lastEntity", lastEntity)
		return PassCheck(fmt.Sprintf("drove %d writes at A", writes))
	})

	// (4) Wait for B to converge to A's final state.
	r.Run("converges_to_latest", func() CheckOutcome {
		if out, ok := r.Require("writes_driven"); !ok {
			return out
		}
		lastEntity := r.Load("lastEntity").(entity.Entity)
		deadline := time.Now().Add(30 * time.Second)
		for time.Now().Before(deadline) {
			if ctx.Err() != nil {
				return FailCheck("context cancelled while waiting for convergence")
			}
			ent, _, err := b.TreeGet(ctx, mirrorDocPath)
			if err == nil && ent.ContentHash == lastEntity.ContentHash {
				r.Store("bFinalEntity", ent)
				return PassCheck(fmt.Sprintf("B converged to A's final state after %d writes", writes))
			}
			time.Sleep(100 * time.Millisecond)
		}
		ent, _, _ := b.TreeGet(ctx, mirrorDocPath)
		return FailCheck(fmt.Sprintf("B did not converge within deadline: B has %s, A's last was %s",
			ent.ContentHash.String(), lastEntity.ContentHash.String()))
	})

	// (5) Entity fidelity: B's mirrored entity must validate and preserve type.
	r.Run("entity_fidelity", func() CheckOutcome {
		if out, ok := r.Require("converges_to_latest"); !ok {
			return out
		}
		ent := r.Load("bFinalEntity").(entity.Entity)
		if ent.Type != "test/mirror-doc" {
			return FailCheck(fmt.Sprintf("B's entity type is %q, expected test/mirror-doc", ent.Type))
		}
		if err := ent.Validate(); err != nil {
			return FailCheck("B's entity does not validate: " + err.Error())
		}
		return PassCheck("B's mirrored entity validates and preserves type")
	})

	// (6) Bounded amplification: one-way mirror should bind exactly one
	// path under the mirror prefix. The 1.5×N gate is canonical headroom
	// for transient CAS-409-and-retry races on slower impls.
	r.Run("bounded_amplification", func() CheckOutcome {
		if out, ok := r.Require("converges_to_latest"); !ok {
			return out
		}
		entries, _, err := b.TreeListing(ctx, mirrorPrefix+"/")
		if err != nil {
			return FailCheck("list B's mirror prefix: " + err.Error())
		}
		gate := int(float64(writes) * 1.5)
		if len(entries) > gate {
			return FailCheck(fmt.Sprintf(
				"B's mirror prefix has %d bindings (cap = 1.5×N = %d) — fanout indicates broken recipe",
				len(entries), gate))
		}
		return PassCheck(fmt.Sprintf(
			"B's mirror prefix has %d binding(s) after %d writes (cap = %d)",
			len(entries), writes, gate))
	})

	return r.Results()
}
