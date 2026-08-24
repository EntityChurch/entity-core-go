package peer

import (
	"context"
	"testing"

	"go.entitychurch.org/entity-core-go/core/capability"
	"go.entitychurch.org/entity-core-go/core/crypto"
	"go.entitychurch.org/entity-core-go/core/ecf"
	"go.entitychurch.org/entity-core-go/core/entity"
	"go.entitychurch.org/entity-core-go/core/handler"
	"go.entitychurch.org/entity-core-go/core/protocol"
	"go.entitychurch.org/entity-core-go/core/tree"
	"go.entitychurch.org/entity-core-go/core/types"

	"github.com/fxamacker/cbor/v2"
)

// mirrorHandler sub-dispatches a system/tree put at whatever path it is given.
// scope is its manifest InternalScope; empty means it runs under the §6.9
// default self-grant (defaultHandlerSelfGrant), which is what these tests pin.
type mirrorHandler struct {
	target string
	scope  []types.GrantEntry

	sawResources []string // Resources.Include of the ceiling it actually ran under
	sawPeersNil  bool     // whether the ceiling's Peers dimension was absent
}

func (h *mirrorHandler) Name() string { return "ceiling-mirror" }

func (h *mirrorHandler) Manifest() types.HandlerManifestData {
	return types.HandlerManifestData{
		Pattern:       "app/ceiling-mirror",
		Name:          "ceiling-mirror",
		Operations:    map[string]types.HandlerOperationSpec{"sync": {}},
		InternalScope: h.scope,
	}
}

func (h *mirrorHandler) RegisterTypes(r *types.TypeRegistry) {}

func (h *mirrorHandler) Handle(ctx context.Context, req *handler.Request) (*handler.Response, error) {
	hctx := req.Context

	// Record the ceiling this sub-dispatch will be gated on, so a failure
	// reports the actual grant rather than an inferred one.
	if capData, err := types.CapabilityTokenDataFromEntity(hctx.HandlerGrant); err == nil && len(capData.Grants) > 0 {
		h.sawResources = capData.Grants[0].Resources.Include
		h.sawPeersNil = capData.Grants[0].Peers == nil
	}

	raw, _ := ecf.Encode(map[string]string{"content": "mirrored"})
	doc, err := entity.NewEntity("test/doc", cbor.RawMessage(raw))
	if err != nil {
		return nil, err
	}
	if _, err := hctx.Store.Put(doc); err != nil {
		return nil, err
	}
	putReq, putRes, err := tree.CreatePutRequest(h.target, &doc)
	if err != nil {
		return nil, err
	}
	return hctx.Execute(ctx, "system/tree", "put", putReq, handler.WithResource(putRes))
}

// openEntryCap mints a wide, self-signed capability for the ENTRY dispatch, so
// that what these tests measure is the handler-grant ceiling on the sub-dispatch
// and never the entry check. Resources use the cross-peer "/*/*" form
// deliberately (bare "*" is peer-local; §5.5 / PR-8).
func openEntryCap(t *testing.T, p *Peer) entity.Entity {
	t.Helper()
	identity := p.Identity()
	capData := types.CapabilityTokenData{
		Grants: []types.GrantEntry{{
			Handlers:   types.CapabilityScope{Include: []string{"*"}},
			Resources:  types.CapabilityScope{Include: []string{"/*/*"}},
			Operations: types.CapabilityScope{Include: []string{"*"}},
			Peers:      &types.CapabilityScope{Include: []string{"*"}},
		}},
		Granter:   types.SingleSigGranter(identity.ContentHash),
		Grantee:   identity.ContentHash,
		CreatedAt: 1,
	}
	ent, err := capData.ToEntity()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := p.Store().Put(ent); err != nil {
		t.Fatal(err)
	}
	return ent
}

// TestDefaultHandlerGrantCeilingReachesForeignNamespace pins the V7 §6.9
// default per-handler self-grant against the §5.2 Dimension 3 ceiling that
// 49d4a03 gave the in-process sub-dispatch path.
//
// §6.9 describes the default as "all resources" and it was encoded as bare "*".
// Inert, that is a harmless spelling — nothing read the field, because before
// 49d4a03 makeLocalExecute handed the L1 check an ExecuteData with a nil
// Resource and CheckResourceScope never ran. As a CEILING, bare "*" resolves
// through capability.Canonicalize to "/{granter}/*" — OWN NAMESPACE ONLY — so
// the peer's own engine could no longer write the foreign-namespace subtrees
// its store legitimately holds under V7 §1.4's universal address space
// (Category A: a `follow` mirror at /{them}/app/..., a cached foreign content
// site). entity-core-rust hit exactly this at c484fa6.
//
// Teeth: this test goes 403 capability_denied against the pre-fix bare-"*"
// spelling. The CONTROL below — the identical binding written through the
// bootstrap LocationIndex path — proves the store does hold the foreign
// namespace, so a 403 is the authorization encoding and not a store refusal.
func TestDefaultHandlerGrantCeilingReachesForeignNamespace(t *testing.T) {
	localKP, _ := crypto.Generate()
	remoteKP, _ := crypto.Generate()
	remoteID := remoteKP.PeerID()

	target := "/" + string(remoteID) + "/app/test/ceiling-mirror/doc"
	mirror := &mirrorHandler{target: target} // empty scope -> default self-grant

	p, err := New(WithIdentity(localKP), WithHandler("app/ceiling-mirror", mirror))
	if err != nil {
		t.Fatal(err)
	}
	defer p.Close()

	// CONTROL: the store legitimately HOLDS foreign-namespace subtrees. The
	// identical write two paths over — through the bootstrap location index,
	// which runs no capability check — succeeds. If this control ever fails,
	// the assertion below is measuring the store, not the ceiling.
	rawC, _ := ecf.Encode(map[string]string{"content": "bootstrap"})
	ctl, _ := entity.NewEntity("test/doc", cbor.RawMessage(rawC))
	if _, err := p.Store().Put(ctl); err != nil {
		t.Fatal(err)
	}
	ctlPath := "/" + string(remoteID) + "/app/test/ceiling-mirror/bootstrap"
	if err := p.LocationIndex().Set(ctlPath, ctl.ContentHash); err != nil {
		t.Fatalf("CONTROL failed: the bootstrap path could not bind a foreign-namespace entity at %s: %v — this test can say nothing about the ceiling until the control passes", ctlPath, err)
	}
	if _, ok := p.LocationIndex().Get(ctlPath); !ok {
		t.Fatalf("CONTROL failed: foreign-namespace binding not readable at %s", ctlPath)
	}

	resp, err := p.Dispatcher().DispatchLocalExecute(context.Background(), protocol.LocalExecuteRequest{
		URI:              "app/ceiling-mirror",
		Operation:        "sync",
		Params:           entity.Entity{},
		CallerCapability: openEntryCap(t, p),
	})
	if err != nil {
		t.Fatalf("dispatch: %v", err)
	}

	if resp.Status != 200 {
		canon := "<no ceiling observed>"
		if len(mirror.sawResources) > 0 {
			canon = capability.Canonicalize(mirror.sawResources[0], p.PeerID())
		}
		t.Fatalf("default-scope handler sub-dispatching system/tree:put at a FOREIGN-namespace path returned %d, want 200.\n"+
			"  ceiling Resources.Include = %v (first pattern canonicalizes to %q)\n"+
			"  target                    = %q\n"+
			"§6.9's \"all resources\" must be encoded as the cross-peer peer-wildcard \"/*/*\"; bare \"*\" canonicalizes to /{granter}/* (own namespace only) per §5.5/PR-8, and since 49d4a03 that spelling is an enforcement input, not documentation. The bootstrap-path control above proves the store holds this namespace.",
			resp.Status, mirror.sawResources, canon, target)
	}
	if _, ok := p.LocationIndex().Get(target); !ok {
		t.Fatalf("dispatch returned 200 but no binding landed at %s", target)
	}

	// Pin the encoding directly, not just its effect.
	if len(mirror.sawResources) != 1 || mirror.sawResources[0] != "/*/*" {
		t.Fatalf("default self-grant Resources.Include = %v, want [\"/*/*\"] — the cross-peer universal form", mirror.sawResources)
	}
	// Peers stays ABSENT on purpose. §5.2 Dimension 4 defaults an absent peers
	// field to {include:[local_peer_id]} and still checks it (acca9e8), but the
	// peer under test is extract_peer of the dispatch TARGET — which handler am
	// I invoking — not the namespace being written. Local is exactly right for
	// a self-grant; widening it to "*" would authorize dispatch at FOREIGN
	// peers' handlers, which is a real escalation and is not what "all
	// resources" means. This assertion exists so that "completing" the fix by
	// widening Peers has to argue with a test first.
	//
	// It IS a measured cross-impl divergence — rust (default_handler_self_grant,
	// peers = IdScope::all()) and py (create_full_access_grant, peers = ["*"])
	// both widen it — and go is deliberately not converging by counting
	// implementations (GUIDE-CONFORMANCE §4: one-differs, spec arbitrates).
	// Routed as docs/validation/spec-issues/2026-08-23-a-default-handler-self-
	// grant-peers-dimension.md. If arch rules the other way, this is the edit.
	if !mirror.sawPeersNil {
		t.Fatal("default self-grant now carries an explicit Peers scope — §5.2 Dimension 4's absent-defaults-to-local is CORRECT for a self-grant (the peer under test is the dispatch target, not the written namespace); widening it authorizes dispatch at foreign peers' handlers")
	}
}

// TestNarrowHandlerScopeStillBoundsForeignNamespace is the narrow-deputy
// control for the test above. Widening the DEFAULT and putting a hole in D1
// (§5.2 Dimension 3 on the in-process path) are one edit apart, so both
// directions are pinned: a handler that declares its own NARROW InternalScope
// must still be refused a write outside it, foreign namespace or not.
//
// Teeth: this goes 200 if the D1 resource check is neutered (revert
// makeLocalExecute's ExecuteData to omit Resource, as it was before 49d4a03),
// and it goes 200 if someone "fixes" the ceiling by widening every grant rather
// than only the default.
func TestNarrowHandlerScopeStillBoundsForeignNamespace(t *testing.T) {
	localKP, _ := crypto.Generate()
	remoteKP, _ := crypto.Generate()
	remoteID := remoteKP.PeerID()

	target := "/" + string(remoteID) + "/app/test/ceiling-mirror/doc"
	mirror := &mirrorHandler{
		target: target,
		// Narrow, and peer-relative on purpose: this handler asked to be
		// confined to its own namespace under app/mine/*.
		scope: []types.GrantEntry{{
			Handlers:   types.CapabilityScope{Include: []string{"system/tree"}},
			Resources:  types.CapabilityScope{Include: []string{"app/mine/*"}},
			Operations: types.CapabilityScope{Include: []string{"put", "get"}},
		}},
	}

	p, err := New(WithIdentity(localKP), WithHandler("app/ceiling-mirror", mirror))
	if err != nil {
		t.Fatal(err)
	}
	defer p.Close()

	resp, err := p.Dispatcher().DispatchLocalExecute(context.Background(), protocol.LocalExecuteRequest{
		URI:              "app/ceiling-mirror",
		Operation:        "sync",
		Params:           entity.Entity{},
		CallerCapability: openEntryCap(t, p),
	})
	if err != nil {
		t.Fatalf("dispatch: %v", err)
	}
	if resp.Status != 403 {
		t.Fatalf("a handler whose declared InternalScope is Resources=[app/mine/*] sub-dispatched system/tree:put at %q and got %d, want 403 — §5.2 Dimension 3 no longer bounds the in-process path (that is D1, 49d4a03), or the default-grant widening leaked onto declared scopes",
			target, resp.Status)
	}
	if _, ok := p.LocationIndex().Get(target); ok {
		t.Fatalf("the refused write LANDED at %s", target)
	}
}

// TestNarrowHandlerScopeStillBoundsOwnNamespace is the second half of the
// narrow-deputy control: the same declared scope must also refuse an
// out-of-scope write inside the peer's OWN namespace. Without this row a
// "fix" that special-cased foreign namespaces would pass the row above.
func TestNarrowHandlerScopeStillBoundsOwnNamespace(t *testing.T) {
	localKP, _ := crypto.Generate()

	mirror := &mirrorHandler{
		target: "app/yours/doc", // peer-relative -> /{local}/app/yours/doc
		scope: []types.GrantEntry{{
			Handlers:   types.CapabilityScope{Include: []string{"system/tree"}},
			Resources:  types.CapabilityScope{Include: []string{"app/mine/*"}},
			Operations: types.CapabilityScope{Include: []string{"put", "get"}},
		}},
	}

	p, err := New(WithIdentity(localKP), WithHandler("app/ceiling-mirror", mirror))
	if err != nil {
		t.Fatal(err)
	}
	defer p.Close()

	resp, err := p.Dispatcher().DispatchLocalExecute(context.Background(), protocol.LocalExecuteRequest{
		URI:              "app/ceiling-mirror",
		Operation:        "sync",
		Params:           entity.Entity{},
		CallerCapability: openEntryCap(t, p),
	})
	if err != nil {
		t.Fatalf("dispatch: %v", err)
	}
	if resp.Status != 403 {
		t.Fatalf("a handler scoped to app/mine/* wrote app/yours/doc in its OWN namespace and got %d, want 403 — §5.2 Dimension 3 is not bounding the in-process path", resp.Status)
	}
}

// TestDefaultHandlerGrantStillCoversOwnNamespace guards the other direction of
// the encoding change: "/*/*" must not have lost the local namespace that bare
// "*" covered. A regression here would break every default-scope handler that
// writes peer-relative paths, which is most of them.
func TestDefaultHandlerGrantStillCoversOwnNamespace(t *testing.T) {
	localKP, _ := crypto.Generate()

	mirror := &mirrorHandler{target: "app/test/ceiling-mirror/local-doc"}
	p, err := New(WithIdentity(localKP), WithHandler("app/ceiling-mirror", mirror))
	if err != nil {
		t.Fatal(err)
	}
	defer p.Close()

	resp, err := p.Dispatcher().DispatchLocalExecute(context.Background(), protocol.LocalExecuteRequest{
		URI:              "app/ceiling-mirror",
		Operation:        "sync",
		Params:           entity.Entity{},
		CallerCapability: openEntryCap(t, p),
	})
	if err != nil {
		t.Fatalf("dispatch: %v", err)
	}
	if resp.Status != 200 {
		t.Fatalf("default-scope handler writing its OWN peer-relative path got %d, want 200 — the /*/* encoding must still cover /{local}/...", resp.Status)
	}
	if _, ok := p.LocationIndex().Get("app/test/ceiling-mirror/local-doc"); !ok {
		t.Fatal("dispatch returned 200 but no local binding landed")
	}
}
