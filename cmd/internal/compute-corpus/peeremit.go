package main

// Driving the corpus against a LIVE PEER over the wire.
//
// This is what makes the corpus reachable for Rust and Python this cycle. §7c.5
// assumes each impl builds its own harness — reads the artifact, evaluates
// in-process, emits. That is the right long-term shape and it is what the README's
// porting contract describes. But it means no cross-impl evidence exists until two
// other teams write harness code, and the corpus's whole reason to exist is that
// "Rust eval == Go eval" is currently assumed rather than verified.
//
// A peer already speaks `system/compute:eval` over the wire. So core-go can drive
// the corpus against any conformant peer and produce that peer's emission with no
// code written on its side. Same artifact, same comparison, same cross-bless — the
// difference is only who runs the evaluator.
//
// THREE THINGS THIS COSTS, ALL OF THEM REAL
//
//  1. It requires the `wire` profile. EXTENSION-COMPUTE §3.2 is normative that
//     explicit eval begins from `scope = empty_scope()`, so root bindings cannot
//     reach a peer. The wire profile inlines them (see builder.go::lookupScope).
//
//  2. It measures the peer's HANDLER path, not its evaluator in isolation —
//     dispatch, capability checks, and result wrapping are all in the loop. A
//     divergence found here is real but needs localizing before it is filed.
//
//  3. It is not a substitute for an impl running the corpus itself. An impl's own
//     harness can emit `engine_role: "alternate"` and satisfy guard 6; a
//     wire-driven emission never can, because the peer runs whatever engine it
//     runs and cannot attest to which. Wire-driven emissions are for FINDING
//     divergence, not for AE-1 admission.
//
// The emission records `engine: "wire:<addr>"` so none of this is inferable only
// from context — a reader can see it was driven, not self-reported.

import (
	"context"
	"fmt"
	"strings"

	"go.entitychurch.org/entity-core-go/cmd/internal/validate"
	"go.entitychurch.org/entity-core-go/core/ecf"
	"go.entitychurch.org/entity-core-go/core/entity"
	"go.entitychurch.org/entity-core-go/core/hash"
	"go.entitychurch.org/entity-core-go/core/types"
	"go.entitychurch.org/entity-core-go/ext/compute"

	"github.com/fxamacker/cbor/v2"
)

// corpusTreePrefix namespaces everything this driver writes into a peer's tree,
// so a run is identifiable and removable and cannot collide with the peer's own
// content.
const corpusTreePrefix = "corpus/run"

// peerDriver holds a connected client for the duration of a run.
type peerDriver struct {
	client *validate.PeerClient
	peerID string
}

func newPeerDriver(ctx context.Context, addr, identity string) (*peerDriver, error) {
	var c *validate.PeerClient
	var err error
	if identity != "" {
		c, err = validate.NewPeerClientWithIdentity(addr, identity)
	} else {
		c, err = validate.NewPeerClient(addr)
	}
	if err != nil {
		return nil, fmt.Errorf("create client: %w", err)
	}
	if err := c.Connect(ctx); err != nil {
		return nil, fmt.Errorf("connect %s: %w", addr, err)
	}
	for _, r := range c.PerformHandshake(ctx) {
		if r.Severity == validate.Fail {
			c.Close()
			return nil, fmt.Errorf("handshake failed at %q: %s", r.Name, r.Message)
		}
	}
	return &peerDriver{client: c, peerID: string(c.RemotePeerID())}, nil
}

func (d *peerDriver) Close() { d.client.Close() }

// evalVectorOnPeer runs one vector against the peer and reduces the response to
// a boundary outcome.
func (d *peerDriver) evalVectorOnPeer(ctx context.Context, v Vector) (Outcome, error) {
	byHash := make(map[hash.Hash]entity.Entity, len(v.Entities))
	for i, ve := range v.Entities {
		ent, err := entity.NewEntity(ve.Type, ve.Data)
		if err != nil {
			return Outcome{}, fmt.Errorf("entity %d (%s): %w", i, ve.Type, err)
		}
		byHash[ent.ContentHash] = ent
	}
	root, ok := byHash[v.Root]
	if !ok {
		return Outcome{}, fmt.Errorf("root %s not in closure", v.Root)
	}

	// Tree preconditions first — the recurse vector's lambda must be resolvable
	// at its path before the expression referencing it is evaluated.
	for path, h := range v.Tree {
		ent, ok := byHash[h]
		if !ok {
			return Outcome{}, fmt.Errorf("tree precondition %q → %s not in closure", path, h)
		}
		if _, err := d.client.TreePut(ctx, path, ent); err != nil {
			return Outcome{}, fmt.Errorf("put tree precondition %q: %w", path, err)
		}
	}

	// The root has to live at a tree path: §3.2 resolves the expression from
	// EXECUTE.resource, so there is no way to hand a peer an expression inline.
	rootPath := corpusTreePrefix + "/" + strings.ReplaceAll(v.ID, ".", "-")
	if _, err := d.client.TreePut(ctx, rootPath, root); err != nil {
		return Outcome{}, fmt.Errorf("put root at %q: %w", rootPath, err)
	}

	// Everything else rides in the envelope's `included` map — Tier 1 of the
	// §4.2 resolution model. One tree write per vector instead of one per
	// entity: the closures run to dozens of nodes, and writing each to its own
	// path would both flood the peer's tree and test tree writes rather than
	// evaluation.
	extras := make(map[hash.Hash]entity.Entity, len(byHash))
	for h, ent := range byHash {
		if h == v.Root {
			continue
		}
		extras[h] = ent
	}

	// §5.2: params.budget is a voluntary self-restriction entering a min. It is
	// how a vector's frozen budget reaches the peer at all — the alternative is
	// the peer default, under which the budget-edge vectors assert nothing.
	rawParams, err := ecf.Encode(map[string]interface{}{"budget": uint64(v.Budget.Operations)})
	if err != nil {
		return Outcome{}, err
	}
	params, err := entity.NewEntity("primitive/any", cbor.RawMessage(rawParams))
	if err != nil {
		return Outcome{}, err
	}

	uri := fmt.Sprintf("entity://%s/system/compute", d.peerID)
	resource := &types.ResourceTarget{Targets: []string{"/" + d.peerID + "/" + rootPath}}

	// §5.2 sources the operations budget from params.budget (above) but the DEPTH
	// budget from the capability's grant-level constraints — never from params
	// (ENTITY-CORE-PROTOCOL §5). A vector whose depth is below the peer default
	// (the depth_exceeded corner CV-9a, the tail-recursion vector) therefore only
	// reproduces on the wire through a constraint-bearing cap; without it the peer
	// runs at its default depth and forks the boundary from the in-process eval —
	// the divergence the 362-vector cross-bless surfaced. Vectors at the default
	// depth take the unchanged connection-cap path.
	var env entity.Envelope
	if v.Budget.Depth > 0 && v.Budget.Depth < compute.DefaultMaxDepth {
		capEnt, capSig, cerr := d.constrainedComputeCap(v.Budget)
		if cerr != nil {
			return Outcome{}, fmt.Errorf("mint depth-constrained cap: %w", cerr)
		}
		env, _, err = d.client.SendExecuteWithCap(ctx, uri, "eval", params, resource, capEnt, capSig, extras)
	} else {
		env, _, err = d.client.SendExecuteWithIncluded(ctx, uri, "eval", params, resource, extras)
	}
	if err != nil {
		return Outcome{}, fmt.Errorf("eval: %w", err)
	}
	respData, err := types.ExecuteResponseDataFromEntity(env.Root)
	if err != nil {
		return Outcome{}, fmt.Errorf("decode execute response: %w", err)
	}

	// BoundaryPath (SA-9 store vectors): the boundary is the entity the peer WROTE
	// to that path, read back with a tree GET — not the eval result, which F10
	// re-wraps into a fresh diagnostic error and which the error-kind reduction
	// keys on `code` regardless. A tree GET sees the exact stored bytes §2.4
	// governs. Fall through to the result reduction if the peer wrote nothing (it
	// propagated instead of materializing) — still a divergence from a writer.
	if v.BoundaryPath != "" {
		qualified := "/" + d.peerID + "/" + v.BoundaryPath
		ent, _, gerr := d.client.TreeGet(ctx, qualified)
		if gerr == nil && !ent.ContentHash.IsZero() {
			h, herr := hash.Compute(ent.Type, ent.Data)
			if herr != nil {
				return Outcome{}, fmt.Errorf("hash written entity at %q: %w", qualified, herr)
			}
			return Outcome{Kind: OutcomeEntity, Boundary: h.Bytes()}, nil
		}
	}

	return outcomeFromEvalResponse(respData)
}

// constrainedComputeCap mints a self-cap — chained from the connection cap —
// carrying the vector's frozen budget as grant-level constraints["system/compute"]
// (ENTITY-CORE-PROTOCOL §5 / EXTENSION-COMPUTE §5.2). This is the only channel
// through which a vector's DEPTH budget reaches a peer: §5.2 sources depth from
// constraints["system/compute"]["max_compute_depth"], never from params.
// Operations is carried too so the one cap reproduces the whole budget.
//
// The grant is broad but ABSOLUTE: the evaluator's internal sub-dispatches
// (compute/lookup/tree over the closure's tree preconditions at /peer/corpus/…)
// run under this same capability, so it must authorize every path the eval reads,
// not just the root resource, or those lookups 403. Resources are qualified with
// the SERVER peer id: §PR-8 canonicalizes each cap's resource patterns against
// its OWN granter's namespace, and this self-cap's granter is the CLIENT — so a
// bare "*" would canonicalize to the client namespace and fail to be covered by
// the connection cap's server-namespaced grant. An absolute /server/* path
// canonicalizes to itself and is covered by the parent's "*". Adding the compute
// budget as a grant-level constraint is a valid attenuation (a constraint only
// narrows, §5.6; grantCovers explicitly permits added keys).
func (d *peerDriver) constrainedComputeCap(budget VecBudget) (entity.Entity, entity.Entity, error) {
	limits := map[string]interface{}{
		"max_compute_depth": uint64(budget.Depth),
	}
	if budget.Operations > 0 {
		limits["max_compute_operations"] = uint64(budget.Operations)
	}
	rawConstraints, err := ecf.Encode(map[string]interface{}{"system/compute": limits})
	if err != nil {
		return entity.Entity{}, entity.Entity{}, err
	}
	grant := types.GrantEntry{
		Handlers:    types.CapabilityScope{Include: []string{"*"}},
		Resources:   types.CapabilityScope{Include: []string{"/" + d.peerID + "/*"}},
		Operations:  types.CapabilityScope{Include: []string{"*"}},
		Constraints: cbor.RawMessage(rawConstraints),
	}
	return d.client.CreateDispatchCapabilityWithGrants([]types.GrantEntry{grant})
}

// outcomeFromEvalResponse reduces an eval response to a boundary outcome.
//
// The mapping is exactly the handler's own result-wrapping rule read backwards
// (§3.2 + the F10 error-as-value clause), which is what makes a wire-driven
// emission comparable to an in-process one:
//
//	entity result   → returned as-is        → entity-kind boundary (its hash)
//	non-entity      → wrapped compute/result → value-kind boundary (canonical bytes)
//	evaluation error → compute/error at 200  → error outcome
//
// A non-200 is NOT an error outcome. Per F10 an evaluation error arrives at 200
// carrying a compute/error, so a 4xx/5xx means dispatch, authorization, or
// transport failed — the vector never ran. Recording that as an outcome would
// make an unauthorized run look like a semantic divergence; it is returned as an
// error so the caller records a skip, and a skip counts as a failure.
func outcomeFromEvalResponse(resp types.ExecuteResponseData) (Outcome, error) {
	if resp.Status != 200 {
		return Outcome{}, fmt.Errorf("eval returned status %d (not an evaluation outcome — "+
			"F10 puts compute errors at 200; this is a dispatch/auth/transport failure)", resp.Status)
	}
	var resultEnt entity.Entity
	if err := ecf.Decode(resp.Result, &resultEnt); err != nil {
		return Outcome{}, fmt.Errorf("decode result entity: %w", err)
	}

	switch resultEnt.Type {
	case types.TypeComputeError:
		var d types.ComputeErrorData
		if err := ecf.Decode(resultEnt.Data, &d); err != nil {
			return Outcome{}, fmt.Errorf("decode compute/error: %w", err)
		}
		return Outcome{Kind: OutcomeError, Code: d.Code, Message: d.Message}, nil

	case types.TypeComputeResult:
		var d types.ComputeResultData
		if err := ecf.Decode(resultEnt.Data, &d); err != nil {
			return Outcome{}, fmt.Errorf("decode compute/result: %w", err)
		}
		raw, err := ecf.Encode(d.Value)
		if err != nil {
			return Outcome{}, fmt.Errorf("re-encode result value: %w", err)
		}
		return Outcome{Kind: OutcomeValue, Boundary: raw}, nil

	default:
		// A materialized entity — the construct-wrapped vectors land here, which
		// is the AE-1 boundary proper. Recompute the hash from (type, data)
		// rather than trusting the claimed content_hash: the whole point is that
		// the bytes hash to what the peer says they do.
		h, err := hash.Compute(resultEnt.Type, resultEnt.Data)
		if err != nil {
			return Outcome{}, fmt.Errorf("recompute result hash: %w", err)
		}
		if !resultEnt.ContentHash.IsZero() && h != resultEnt.ContentHash {
			return Outcome{}, fmt.Errorf("peer's claimed content_hash %s does not match its own bytes (%s)",
				resultEnt.ContentHash, h)
		}
		return Outcome{Kind: OutcomeEntity, Boundary: h.Bytes()}, nil
	}
}
