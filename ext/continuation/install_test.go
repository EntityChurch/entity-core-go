package continuation

import (
	"context"
	"strings"
	"testing"

	"go.entitychurch.org/entity-core-go/core/crypto"
	"go.entitychurch.org/entity-core-go/core/entity"
	"go.entitychurch.org/entity-core-go/core/handler"
	"go.entitychurch.org/entity-core-go/core/hash"
	"go.entitychurch.org/entity-core-go/core/types"
)

// installTestEnv holds the identities and the handler/context needed for
// install tests. writer is the EXECUTE author (who sees their identity hash
// threaded into hctx.AuthorHash).
type installTestEnv struct {
	h       *Handler
	hctx    *handler.HandlerContext
	writer  entity.Entity // identity entity for the writer
	other   entity.Entity // a separate identity (for adversary scenarios)
	handler entity.Entity // identity for the handler-wielder grantee
}

func newInstallEnv(t *testing.T) *installTestEnv {
	t.Helper()
	writerKP, _ := crypto.Generate()
	otherKP, _ := crypto.Generate()
	handlerKP, _ := crypto.Generate()
	writerID, _ := writerKP.IdentityEntity()
	otherID, _ := otherKP.IdentityEntity()
	handlerID, _ := handlerKP.IdentityEntity()

	hctx := newTestContext()
	hctx.AuthorHash = writerID.ContentHash
	hctx.LocalPeerID = writerKP.PeerID()
	hctx.Included[writerID.ContentHash] = writerID
	hctx.Included[otherID.ContentHash] = otherID
	hctx.Included[handlerID.ContentHash] = handlerID

	return &installTestEnv{
		h:       NewHandler(),
		hctx:    hctx,
		writer:  writerID,
		other:   otherID,
		handler: handlerID,
	}
}

// makeCap builds a cap entity with the given granter/grantee and optional parent,
// puts it in the envelope's Included map, and returns the entity.
func (env *installTestEnv) makeCap(t *testing.T, granter, grantee hash.Hash, parent *hash.Hash) entity.Entity {
	t.Helper()
	capData := types.CapabilityTokenData{
		Grants: []types.GrantEntry{
			{
				Handlers:   types.CapabilityScope{Include: []string{"*"}},
				Resources:  types.CapabilityScope{Include: []string{"*"}},
				Operations: types.CapabilityScope{Include: []string{"put"}},
			},
		},
		Granter:   types.SingleSigGranter(granter),
		Grantee:   grantee,
		Parent:    parent,
		CreatedAt: 1000,
	}
	capEnt, err := capData.ToEntity()
	if err != nil {
		t.Fatal(err)
	}
	env.hctx.Included[capEnt.ContentHash] = capEnt
	return capEnt
}

// makeInstallRequest builds an install handler.Request. installPath is set
// in hctx.Resource per V7 §3.2 path-as-resource; contEnt is a
// system/continuation or system/continuation/join entity passed as params
// (one op, two accepted entity types — discriminated on params.type).
func makeInstallRequest(t *testing.T, hctx *handler.HandlerContext, installPath string, contEnt entity.Entity) *handler.Request {
	t.Helper()
	hctx.Resource = &types.ResourceTarget{Targets: []string{installPath}}
	return &handler.Request{
		Path:      "system/continuation",
		Operation: "install",
		Params:    contEnt,
		Context:   hctx,
	}
}

// makeForward builds a system/continuation entity with the given fields.
func makeForward(t *testing.T, target, op string, dispatchCap hash.Hash) entity.Entity {
	t.Helper()
	ent, err := types.ContinuationData{
		Target:             target,
		Operation:          op,
		DispatchCapability: dispatchCap,
	}.ToEntity()
	if err != nil {
		t.Fatal(err)
	}
	return ent
}

// makeJoin builds a system/continuation/join entity with the given fields.
func makeJoin(t *testing.T, target, op string, dispatchCap hash.Hash, expected []string) entity.Entity {
	t.Helper()
	ent, err := types.ContinuationJoinData{
		Expected:           expected,
		Target:             target,
		Operation:          op,
		DispatchCapability: dispatchCap,
	}.ToEntity()
	if err != nil {
		t.Fatal(err)
	}
	return ent
}

func TestInstallForwardWriterIsRootGranter(t *testing.T) {
	// System-handler-equivalent case: writer (local peer) is the granter
	// of the embedded cap. Should succeed.
	env := newInstallEnv(t)
	cap := env.makeCap(t, env.writer.ContentHash, env.handler.ContentHash, nil)

	cont := makeForward(t, "/peer/system/tree", "put", cap.ContentHash)
	resp, err := env.h.handleInstall(context.Background(),
		makeInstallRequest(t, env.hctx, "/peer/system/continuation/test1", cont))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp.Status != 200 {
		t.Fatalf("expected 200, got %d (result type %s)", resp.Status, resp.Result.Type)
	}

	// Verify the continuation entity landed at the path.
	storedHash, ok := env.hctx.LocationIndex.Get("/peer/system/continuation/test1")
	if !ok {
		t.Fatal("install did not write to tree")
	}
	storedEnt, ok := env.hctx.Store.Get(storedHash)
	if !ok {
		t.Fatal("continuation entity not in store")
	}
	if storedEnt.Type != types.TypeContinuation {
		t.Fatalf("expected stored type %s, got %s", types.TypeContinuation, storedEnt.Type)
	}
}

func TestInstallForwardAdversaryRejected(t *testing.T) {
	// Finding 3 case: cap has granter=other, grantee=handler. Writer is not
	// in the granter chain. R1 rejects with 403 embedded_cap_unauthorized.
	env := newInstallEnv(t)
	cap := env.makeCap(t, env.other.ContentHash, env.handler.ContentHash, nil)

	cont := makeForward(t, "/peer/system/tree", "put", cap.ContentHash)
	resp, err := env.h.handleInstall(context.Background(),
		makeInstallRequest(t, env.hctx, "/peer/system/continuation/finding3", cont))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp.Status != 403 {
		t.Fatalf("expected 403, got %d", resp.Status)
	}
	errData, _ := types.ErrorDataFromEntity(resp.Result)
	if errData.Code != "embedded_cap_unauthorized" {
		t.Fatalf("expected embedded_cap_unauthorized, got %q", errData.Code)
	}

	// Tree should not have been written.
	if _, ok := env.hctx.LocationIndex.Get("/peer/system/continuation/finding3"); ok {
		t.Fatal("install should not have written to tree on rejection")
	}
}

func TestInstallForwardAttenuatedChainAccepted(t *testing.T) {
	// Re-attenuation pattern: root issued by other to writer, leaf issued by
	// writer to handler. Writer is leaf granter → R1 passes.
	env := newInstallEnv(t)
	root := env.makeCap(t, env.other.ContentHash, env.writer.ContentHash, nil)
	rootHash := root.ContentHash
	leaf := env.makeCap(t, env.writer.ContentHash, env.handler.ContentHash, &rootHash)

	cont := makeForward(t, "/peer/system/tree", "put", leaf.ContentHash)
	resp, err := env.h.handleInstall(context.Background(),
		makeInstallRequest(t, env.hctx, "/peer/system/continuation/atten", cont))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp.Status != 200 {
		t.Fatalf("expected 200, got %d", resp.Status)
	}
}

// TestInstallInChainNotRootGranter is the N1 regression guard
// (EXTENSION-CONTINUATION §3.1a / §8.1, v1.9). The writer is a STRICT
// middle granter — neither the chain root nor the leaf granter. A
// chain-*root* check (the pre-correction reading) would reject this
// because the root granter is `other`, not the writer; the required
// in-chain check accepts it because the writer appears as a granter
// somewhere in the chain. This is exactly the cross-peer shape
// (B-rooted, installer in-chain as a re-attenuation granter): if this
// test ever fails, the install check has regressed to a root check and
// every cross-peer continuation is broken.
func TestInstallInChainNotRootGranter(t *testing.T) {
	env := newInstallEnv(t)

	interKP, _ := crypto.Generate()
	interID, _ := interKP.IdentityEntity()
	env.hctx.Included[interID.ContentHash] = interID

	// root:  other  -> writer        (root granter = other, NOT writer)
	// mid:   writer -> intermediate  (writer is a strict middle granter)
	// leaf:  inter  -> handler       (leaf granter = intermediate)
	root := env.makeCap(t, env.other.ContentHash, env.writer.ContentHash, nil)
	rootHash := root.ContentHash
	mid := env.makeCap(t, env.writer.ContentHash, interID.ContentHash, &rootHash)
	midHash := mid.ContentHash
	leaf := env.makeCap(t, interID.ContentHash, env.handler.ContentHash, &midHash)

	cont := makeForward(t, "/peer/system/tree", "put", leaf.ContentHash)
	resp, err := env.h.handleInstall(context.Background(),
		makeInstallRequest(t, env.hctx, "/peer/system/continuation/midchain", cont))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp.Status != 200 {
		errData, _ := types.ErrorDataFromEntity(resp.Result)
		t.Fatalf("in-chain (mid-granter) install must succeed, got %d %q — install check regressed to a chain-ROOT check, which breaks cross-peer continuations (§3.1a)",
			resp.Status, errData.Code)
	}
}

func TestInstallChainUnreachable(t *testing.T) {
	// Leaf cap references a parent that's not in envelope or store. Helper
	// returns ErrChainUnreachable; handler surfaces 404 chain_unreachable.
	env := newInstallEnv(t)
	missingParent := hash.Hash{Algorithm: hash.AlgorithmSHA256}
	for i := 0; i < hash.SHA256DigestSize; i++ {
		missingParent.Digest[i] = byte(i + 1)
	}
	leaf := env.makeCap(t, env.other.ContentHash, env.handler.ContentHash, &missingParent)

	cont := makeForward(t, "/peer/system/tree", "put", leaf.ContentHash)
	resp, err := env.h.handleInstall(context.Background(),
		makeInstallRequest(t, env.hctx, "/peer/system/continuation/unreach", cont))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp.Status != 404 {
		t.Fatalf("expected 404, got %d", resp.Status)
	}
	errData, _ := types.ErrorDataFromEntity(resp.Result)
	if errData.Code != "chain_unreachable" {
		t.Fatalf("expected chain_unreachable, got %q", errData.Code)
	}
}

func TestInstallDispatchCapNotFound(t *testing.T) {
	// Install request references a cap hash that's not in envelope or store.
	env := newInstallEnv(t)
	bogus := hash.Hash{Algorithm: hash.AlgorithmSHA256}
	for i := 0; i < hash.SHA256DigestSize; i++ {
		bogus.Digest[i] = byte(i + 7)
	}

	cont := makeForward(t, "/peer/system/tree", "put", bogus)
	resp, err := env.h.handleInstall(context.Background(),
		makeInstallRequest(t, env.hctx, "/peer/system/continuation/missing", cont))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp.Status != 404 {
		t.Fatalf("expected 404, got %d", resp.Status)
	}
	errData, _ := types.ErrorDataFromEntity(resp.Result)
	if errData.Code != "dispatch_capability_not_found" {
		t.Fatalf("expected dispatch_capability_not_found, got %q", errData.Code)
	}
}

func TestInstallJoinAccepted(t *testing.T) {
	// Join continuation install with writer-issued cap. Should produce a
	// system/continuation/join entity at the path.
	env := newInstallEnv(t)
	cap := env.makeCap(t, env.writer.ContentHash, env.handler.ContentHash, nil)

	join := makeJoin(t, "/peer/system/tree", "put", cap.ContentHash, []string{"a", "b"})
	resp, err := env.h.handleInstall(context.Background(),
		makeInstallRequest(t, env.hctx, "/peer/system/continuation/join1", join))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp.Status != 200 {
		t.Fatalf("expected 200, got %d", resp.Status)
	}

	storedHash, _ := env.hctx.LocationIndex.Get("/peer/system/continuation/join1")
	storedEnt, _ := env.hctx.Store.Get(storedHash)
	if storedEnt.Type != types.TypeContinuationJoin {
		t.Fatalf("expected join type, got %s", storedEnt.Type)
	}
}

func TestInstallJoinAdversaryRejected(t *testing.T) {
	// Join variant of Finding 3 (proposal §10 row 10).
	env := newInstallEnv(t)
	cap := env.makeCap(t, env.other.ContentHash, env.handler.ContentHash, nil)

	join := makeJoin(t, "/peer/system/tree", "put", cap.ContentHash, []string{"a", "b"})
	resp, err := env.h.handleInstall(context.Background(),
		makeInstallRequest(t, env.hctx, "/peer/system/continuation/join-adv", join))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp.Status != 403 {
		t.Fatalf("expected 403, got %d", resp.Status)
	}
}

func TestInstallMissingFields(t *testing.T) {
	env := newInstallEnv(t)
	cap := env.makeCap(t, env.writer.ContentHash, env.handler.ContentHash, nil)
	tests := []struct {
		name    string
		cont    types.ContinuationData
		wantMsg string
	}{
		{
			"no target",
			types.ContinuationData{Operation: "put", DispatchCapability: cap.ContentHash},
			"forward continuation requires target and operation",
		},
		{
			"no operation",
			types.ContinuationData{Target: "x", DispatchCapability: cap.ContentHash},
			"forward continuation requires target and operation",
		},
		{
			"no dispatch_capability",
			types.ContinuationData{Target: "x", Operation: "put"},
			"continuation requires dispatch_capability",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ent, err := tt.cont.ToEntity()
			if err != nil {
				t.Fatalf("build continuation: %v", err)
			}
			resp, err := env.h.handleInstall(context.Background(),
				makeInstallRequest(t, env.hctx, "/p/x", ent))
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if resp.Status != 400 {
				t.Fatalf("expected 400, got %d", resp.Status)
			}
			errData, _ := types.ErrorDataFromEntity(resp.Result)
			if !strings.Contains(errData.Message, tt.wantMsg) {
				t.Fatalf("expected message to contain %q, got %q", tt.wantMsg, errData.Message)
			}
		})
	}
}

func TestInstallAmbiguousResource(t *testing.T) {
	env := newInstallEnv(t)
	cap := env.makeCap(t, env.writer.ContentHash, env.handler.ContentHash, nil)
	cont := makeForward(t, "/peer/system/tree", "put", cap.ContentHash)
	req := &handler.Request{
		Path:      "system/continuation",
		Operation: "install",
		Params:    cont,
		Context:   env.hctx,
	}
	// hctx.Resource left nil — should reject 400 ambiguous_resource.
	resp, err := env.h.handleInstall(context.Background(), req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp.Status != 400 {
		t.Fatalf("expected 400, got %d", resp.Status)
	}
	errData, _ := types.ErrorDataFromEntity(resp.Result)
	if errData.Code != "ambiguous_resource" {
		t.Fatalf("expected ambiguous_resource, got %q", errData.Code)
	}
}

func TestInstallInvalidParamsType(t *testing.T) {
	env := newInstallEnv(t)
	// Pass a non-continuation entity as params — should reject 400 invalid_params.
	bogus, _ := types.ContinuationAdvanceRequestData{}.ToEntity()
	resp, err := env.h.handleInstall(context.Background(),
		makeInstallRequest(t, env.hctx, "/peer/system/continuation/bogus", bogus))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp.Status != 400 {
		t.Fatalf("expected 400, got %d", resp.Status)
	}
	errData, _ := types.ErrorDataFromEntity(resp.Result)
	if errData.Code != "invalid_params" {
		t.Fatalf("expected invalid_params, got %q", errData.Code)
	}
}

// Note: the prior TestInstallJoinWithResultTransformRejected case is
// structurally impossible after the wrapper elimination —
// system/continuation/join has no result_transform field, so a join entity
// can never carry one.

func TestInstallPersistsChainToStore(t *testing.T) {
	// After successful install, the embedded cap and its full chain MUST be
	// in the local store (proposal §2 chain-entity persistence).
	env := newInstallEnv(t)
	root := env.makeCap(t, env.other.ContentHash, env.writer.ContentHash, nil)
	rootHash := root.ContentHash
	leaf := env.makeCap(t, env.writer.ContentHash, env.handler.ContentHash, &rootHash)

	cont := makeForward(t, "/peer/system/tree", "put", leaf.ContentHash)
	resp, err := env.h.handleInstall(context.Background(),
		makeInstallRequest(t, env.hctx, "/peer/system/continuation/persist", cont))
	if err != nil || resp.Status != 200 {
		t.Fatalf("install failed: status=%d err=%v", resp.Status, err)
	}
	if _, ok := env.hctx.Store.Get(leaf.ContentHash); !ok {
		t.Fatal("leaf cap not persisted to local store")
	}
	if _, ok := env.hctx.Store.Get(rootHash); !ok {
		t.Fatal("root cap not persisted to local store")
	}
}
