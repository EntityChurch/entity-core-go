package protocol

import (
	"context"
	"fmt"
	"testing"
	"time"

	"go.entitychurch.org/entity-core-go/core/crypto"
	"go.entitychurch.org/entity-core-go/core/ecf"
	"go.entitychurch.org/entity-core-go/core/entity"
	"go.entitychurch.org/entity-core-go/core/handler"
	"go.entitychurch.org/entity-core-go/core/hash"
	"go.entitychurch.org/entity-core-go/core/store"
	"go.entitychurch.org/entity-core-go/core/types"

	"github.com/fxamacker/cbor/v2"
)

func TestVerifyRequest(t *testing.T) {
	// Set up local and remote keypairs.
	localKP, _ := crypto.Generate()
	remoteKP, _ := crypto.Generate()

	localIdentity, _ := localKP.IdentityEntity()
	remoteIdentity, _ := remoteKP.IdentityEntity()

	// Create a root capability granted by local to remote.
	capData := types.CapabilityTokenData{
		Grants: []types.GrantEntry{
			{Handlers: types.CapabilityScope{Include: []string{"system/tree"}}, Resources: types.CapabilityScope{Include: []string{"system/tree/*"}}, Operations: types.CapabilityScope{Include: []string{"get"}}},
		},
		Granter:   types.SingleSigGranter(localIdentity.ContentHash),
		Grantee:   remoteIdentity.ContentHash,
		CreatedAt: 1000,
	}
	capEntity, _ := capData.ToEntity()

	// Sign the capability with local keypair.
	capSig := localKP.Sign(capEntity.ContentHash.Bytes())
	capSigData := types.SignatureData{
		Target:    capEntity.ContentHash,
		Signer:    localIdentity.ContentHash,
		Algorithm: "ed25519",
		Signature: capSig,
	}
	capSigEntity, _ := capSigData.ToEntity()

	// Create params entity.
	paramsRaw, _ := ecf.Encode(map[string]string{"path": "system/tree/test"})
	paramsEntity, _ := entity.NewEntity("system/tree/get-request", cbor.RawMessage(paramsRaw))
	encodedParams, _ := ecf.Encode(paramsEntity)

	// Create execute message.
	execData := types.ExecuteData{
		RequestID:  "req-1",
		URI:        "entity://" + string(localKP.PeerID()) + "/system/tree",
		Operation:  "get",
		Params:     cbor.RawMessage(encodedParams),
		Author:     remoteIdentity.ContentHash,
		Capability: capEntity.ContentHash,
	}
	execEntity, _ := execData.ToEntity()

	// Sign the execute with remote keypair.
	execSig := remoteKP.Sign(execEntity.ContentHash.Bytes())
	execSigData := types.SignatureData{
		Target:    execEntity.ContentHash,
		Signer:    remoteIdentity.ContentHash,
		Algorithm: "ed25519",
		Signature: execSig,
	}
	execSigEntity, _ := execSigData.ToEntity()

	// Build envelope.
	env := entity.NewEnvelope(execEntity, map[hash.Hash]entity.Entity{
		remoteIdentity.ContentHash: remoteIdentity,
		localIdentity.ContentHash:  localIdentity,
		capEntity.ContentHash:      capEntity,
		capSigEntity.ContentHash:   capSigEntity,
		execSigEntity.ContentHash:  execSigEntity,
	})

	// Verify.
	err := VerifyRequest(env, localKP.PeerID())
	if err != nil {
		t.Fatalf("expected valid request, got: %v", err)
	}
}

func TestVerifyRequestBadSignature(t *testing.T) {
	localKP, _ := crypto.Generate()
	remoteKP, _ := crypto.Generate()

	localIdentity, _ := localKP.IdentityEntity()
	remoteIdentity, _ := remoteKP.IdentityEntity()

	capData := types.CapabilityTokenData{
		Grants: []types.GrantEntry{
			{Handlers: types.CapabilityScope{Include: []string{"*"}}, Resources: types.CapabilityScope{Include: []string{"*"}}, Operations: types.CapabilityScope{Include: []string{"get"}}},
		},
		Granter:   types.SingleSigGranter(localIdentity.ContentHash),
		Grantee:   remoteIdentity.ContentHash,
		CreatedAt: 1000,
	}
	capEntity, _ := capData.ToEntity()

	capSig := localKP.Sign(capEntity.ContentHash.Bytes())
	capSigEntity, _ := types.SignatureData{
		Target: capEntity.ContentHash, Signer: localIdentity.ContentHash,
		Algorithm: "ed25519", Signature: capSig,
	}.ToEntity()

	paramsRaw, _ := ecf.Encode("test")
	execData := types.ExecuteData{
		RequestID: "req-1", URI: "system/tree", Operation: "get",
		Params: cbor.RawMessage(paramsRaw), Author: remoteIdentity.ContentHash,
		Capability: capEntity.ContentHash,
	}
	execEntity, _ := execData.ToEntity()

	// Bad signature (all zeros).
	badSig := make([]byte, 64)
	badSigEntity, _ := types.SignatureData{
		Target: execEntity.ContentHash, Signer: remoteIdentity.ContentHash,
		Algorithm: "ed25519", Signature: badSig,
	}.ToEntity()

	env := entity.NewEnvelope(execEntity, map[hash.Hash]entity.Entity{
		remoteIdentity.ContentHash: remoteIdentity,
		localIdentity.ContentHash:  localIdentity,
		capEntity.ContentHash:      capEntity,
		capSigEntity.ContentHash:   capSigEntity,
		badSigEntity.ContentHash:   badSigEntity,
	})

	err := VerifyRequest(env, localKP.PeerID())
	if err == nil {
		t.Fatal("expected error for bad signature")
	}
}

func TestConnectHelloAuthenticate(t *testing.T) {
	localKP, _ := crypto.Generate()
	remoteKP, _ := crypto.Generate()

	ch, err := NewConnectHandler(localKP, nil)
	if err != nil {
		t.Fatal(err)
	}

	reg := handler.NewRegistry()
	reg.Register("system/protocol/connect", ch)

	cs := store.NewMemoryContentStore()
	li := store.NewNamespacedIndex(store.NewMemoryLocationIndex(), string(localKP.PeerID()))
	if err := SeedHandlersFromRegistry(cs, li, reg); err != nil {
		t.Fatal(err)
	}

	d := NewDispatcher(reg, cs, li, localKP, nil)

	// Create hello from remote.
	helloEnv, _, err := CreateHelloExecute(remoteKP, nil)
	if err != nil {
		t.Fatal(err)
	}

	cs2 := NewConnectionState()
	respEnv, err := d.DispatchEnvelope(context.Background(), helloEnv, cs2)
	if err != nil {
		t.Fatalf("hello dispatch failed: %v", err)
	}

	// Verify response is an execute response.
	if respEnv.Root.Type != types.TypeExecuteResponse {
		t.Fatalf("expected execute response, got %s", respEnv.Root.Type)
	}

	respData, err := types.ExecuteResponseDataFromEntity(respEnv.Root)
	if err != nil {
		t.Fatal(err)
	}
	if respData.Status != 200 {
		t.Fatalf("expected status 200, got %d", respData.Status)
	}
}

func TestCreateHelloExecute(t *testing.T) {
	kp, _ := crypto.Generate()
	env, nonce, err := CreateHelloExecute(kp, nil)
	if err != nil {
		t.Fatal(err)
	}

	if env.Root.Type != types.TypeExecute {
		t.Fatalf("expected execute type, got %s", env.Root.Type)
	}
	if len(nonce) != 32 {
		t.Fatalf("expected 32-byte nonce, got %d", len(nonce))
	}

	execData, _ := types.ExecuteDataFromEntity(env.Root)
	if execData.Operation != "hello" {
		t.Fatalf("expected hello operation, got %s", execData.Operation)
	}
}

func TestCreateAuthenticateExecute(t *testing.T) {
	kp, _ := crypto.Generate()
	theirNonce := make([]byte, 32)

	env, err := CreateAuthenticateExecute(kp, theirNonce)
	if err != nil {
		t.Fatal(err)
	}

	if env.Root.Type != types.TypeExecute {
		t.Fatalf("expected execute type, got %s", env.Root.Type)
	}
	if len(env.Included) < 2 {
		t.Fatalf("expected at least 2 included entities, got %d", len(env.Included))
	}
}

func TestConnectionSequenceValidation(t *testing.T) {
	state := NewConnectionState()

	// Hello should work first.
	if err := ValidateConnectionSequence(state, "hello"); err != nil {
		t.Fatalf("hello should be valid: %v", err)
	}

	// Authenticate before hello should fail.
	if err := ValidateConnectionSequence(state, "authenticate"); err == nil {
		t.Fatal("authenticate before hello should fail")
	}

	// Set state to awaiting authenticate.
	state.Phase = "awaiting_authenticate"
	if err := ValidateConnectionSequence(state, "authenticate"); err != nil {
		t.Fatalf("authenticate should be valid after hello: %v", err)
	}

	// Complete connection.
	state.Completed = true
	if err := ValidateConnectionSequence(state, "hello"); err == nil {
		t.Fatal("hello after completion should fail")
	}
}

// echoHandler echoes the request operation back as a response.
type echoHandler struct{}

func (h *echoHandler) Handle(ctx context.Context, req *handler.Request) (*handler.Response, error) {
	return handler.NewResponse(200, "test/echo-result", map[string]string{"echoed": req.Operation})
}
func (h *echoHandler) Name() string { return "echo" }

// delegatingHandler calls ctx.Execute to invoke another handler, then returns its result.
type delegatingHandler struct {
	targetURI string
}

func (h *delegatingHandler) Handle(ctx context.Context, req *handler.Request) (*handler.Response, error) {
	if req.Context.Execute == nil {
		return nil, fmt.Errorf("Execute not available")
	}
	return req.Context.Execute(ctx, h.targetURI, req.Operation, req.Params)
}
func (h *delegatingHandler) Name() string { return "delegator" }

func TestHandlerToHandlerExecute(t *testing.T) {
	localKP, _ := crypto.Generate()
	remoteKP, _ := crypto.Generate()

	localIdentity, _ := localKP.IdentityEntity()
	remoteIdentity, _ := remoteKP.IdentityEntity()

	reg := handler.NewRegistry()
	reg.Register("test/echo", &echoHandler{})
	reg.Register("test/delegate", &delegatingHandler{targetURI: "test/echo"})

	cs := store.NewMemoryContentStore()
	li := store.NewNamespacedIndex(store.NewMemoryLocationIndex(), string(localKP.PeerID()))
	if err := SeedHandlersFromRegistry(cs, li, reg); err != nil {
		t.Fatal(err)
	}
	d := NewDispatcher(reg, cs, li, localKP, nil)

	// Create a wildcard capability (handlers/resources) with explicit operations.
	capData := types.CapabilityTokenData{
		Grants: []types.GrantEntry{
			{Handlers: types.CapabilityScope{Include: []string{"*"}}, Resources: types.CapabilityScope{Include: []string{"*"}}, Operations: types.CapabilityScope{Include: []string{"ping", "get"}}},
		},
		Granter:   types.SingleSigGranter(localIdentity.ContentHash),
		Grantee:   remoteIdentity.ContentHash,
		CreatedAt: 1000,
	}
	capEntity, _ := capData.ToEntity()
	capSig := localKP.Sign(capEntity.ContentHash.Bytes())
	capSigEntity, _ := types.SignatureData{
		Target: capEntity.ContentHash, Signer: localIdentity.ContentHash,
		Algorithm: "ed25519", Signature: capSig,
	}.ToEntity()

	// Seed test/delegate's handler grant. V7 v7.49 §6.8: sub-dispatch is
	// gated on the executing handler's grant, with no fallback. test/delegate
	// dispatches test/echo via hctx.Execute — the L1 check uses delegate's
	// HandlerGrant. (LocalIdentityHash is zero in test ctx → validation
	// skipped, the placeholder grant entity is sufficient.)
	if _, err := cs.Put(capEntity); err != nil {
		t.Fatalf("put placeholder grant entity: %v", err)
	}
	if err := li.Set("system/capability/grants/test/delegate", capEntity.ContentHash); err != nil {
		t.Fatalf("bind placeholder grant for test/delegate: %v", err)
	}

	// Build an authenticated execute to test/delegate.
	paramsRaw, _ := ecf.Encode("test-params")
	paramsEntity, _ := entity.NewEntity("test/params", cbor.RawMessage(paramsRaw))
	encodedParams, _ := ecf.Encode(paramsEntity)

	execData := types.ExecuteData{
		RequestID:  "req-delegate",
		URI:        "entity://" + string(localKP.PeerID()) + "/test/delegate",
		Operation:  "ping",
		Params:     cbor.RawMessage(encodedParams),
		Author:     remoteIdentity.ContentHash,
		Capability: capEntity.ContentHash,
	}
	execEntity, _ := execData.ToEntity()
	execSig := remoteKP.Sign(execEntity.ContentHash.Bytes())
	execSigEntity, _ := types.SignatureData{
		Target: execEntity.ContentHash, Signer: remoteIdentity.ContentHash,
		Algorithm: "ed25519", Signature: execSig,
	}.ToEntity()

	env := entity.NewEnvelope(execEntity, map[hash.Hash]entity.Entity{
		remoteIdentity.ContentHash: remoteIdentity,
		localIdentity.ContentHash:  localIdentity,
		capEntity.ContentHash:      capEntity,
		capSigEntity.ContentHash:   capSigEntity,
		execSigEntity.ContentHash:  execSigEntity,
	})

	respEnv, err := d.DispatchEnvelope(context.Background(), env, nil)
	if err != nil {
		t.Fatalf("dispatch failed: %v", err)
	}

	respData, err := types.ExecuteResponseDataFromEntity(respEnv.Root)
	if err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if respData.Status != 200 {
		t.Fatalf("expected status 200, got %d", respData.Status)
	}
}

// TestDispatchLocalExecuteEntityNative verifies the full V7 §6.6 entity-native
// dispatch chain end-to-end in-process via the DispatchLocalExecute helper.
//
// Coverage that didn't exist before: tree-walk finds a system/handler entity
// with ExpressionPath set; the dispatcher routes to the EvaluateExpression
// hook with the resolved expression path; the hook's response flows back to
// the caller. Previously the chain was tested only over TCP via the validate
// suite — no in-process caller exercised it.
//
// The hook is a stub (the test verifies the dispatcher's contract with it,
// not the compute extension's correctness — that lives in ext/compute_test).
func TestDispatchLocalExecuteEntityNative(t *testing.T) {
	localKP, _ := crypto.Generate()
	localIdentity, _ := localKP.IdentityEntity()

	reg := handler.NewRegistry()
	cs := store.NewMemoryContentStore()
	li := store.NewNamespacedIndex(store.NewMemoryLocationIndex(), string(localKP.PeerID()))
	d := NewDispatcher(reg, cs, li, localKP, nil)

	// Stub the EvaluateExpression hook to record inputs and return a known
	// result. This is the wiring entity-native dispatch needs (the real
	// hook is compute.Handler.EvaluateAtPath in the production wire-up).
	var calledExprPath string
	var calledOp string
	d.EvaluateExpression = func(ctx context.Context, exprPath string, req *handler.Request) (*handler.Response, error) {
		calledExprPath = exprPath
		calledOp = req.Operation
		raw, _ := ecf.Encode(map[string]any{"value": uint64(42)})
		result, _ := entity.NewEntity("primitive/any", cbor.RawMessage(raw))
		return &handler.Response{Status: 200, Result: result}, nil
	}

	// Persist the local identity so granter-resolution sees it as a known
	// peer-id (handlers' RL1 path uses ResolveGranterPeerID on the cap).
	if _, err := cs.Put(localIdentity); err != nil {
		t.Fatalf("put local identity: %v", err)
	}

	// Mint a wildcard self-cap so the makeLocalExecute RL1 scope check passes.
	capData := types.CapabilityTokenData{
		Grants: []types.GrantEntry{{
			Handlers:   types.CapabilityScope{Include: []string{"*"}},
			Resources:  types.CapabilityScope{Include: []string{"*"}},
			Operations: types.CapabilityScope{Include: []string{"*"}},
		}},
		Granter:   types.SingleSigGranter(localIdentity.ContentHash),
		Grantee:   localIdentity.ContentHash,
		CreatedAt: 1,
	}
	callerCap, _ := capData.ToEntity()
	if _, err := cs.Put(callerCap); err != nil {
		t.Fatalf("put caller cap: %v", err)
	}

	// Write the entity-native system/handler entity at the pattern path.
	// ExpressionPath points at where the compute expression *would* live;
	// the stub above ignores it but records what the dispatcher passed.
	const pattern = "test/entity-native"
	const exprPath = pattern + "/expr"
	hd := types.HandlerData{
		Interface:      "system/handler/" + pattern,
		ExpressionPath: exprPath,
	}
	hEnt, err := hd.ToEntity()
	if err != nil {
		t.Fatalf("build handler entity: %v", err)
	}
	hHash, err := cs.Put(hEnt)
	if err != nil {
		t.Fatalf("put handler entity: %v", err)
	}
	if err := li.Set(pattern, hHash); err != nil {
		t.Fatalf("bind handler entity at pattern: %v", err)
	}

	// Entity-native dispatch fails closed without a handler grant entity
	// (dispatch.go:341). Validation is skipped here because d.LocalIdentityHash
	// is zero (test context), so any entity at the grant path is sufficient.
	grantPath := "system/capability/grants/" + pattern
	if _, err := cs.Put(callerCap); err != nil {
		t.Fatalf("put placeholder grant entity: %v", err)
	}
	if err := li.Set(grantPath, callerCap.ContentHash); err != nil {
		t.Fatalf("bind placeholder grant: %v", err)
	}

	// Build params.
	paramsRaw, _ := ecf.Encode(map[string]any{"x": uint64(1)})
	paramsEnt, _ := entity.NewEntity("primitive/any", cbor.RawMessage(paramsRaw))

	// Dispatch in-process via the new helper. This is the path the SDK
	// Executor takes — same code that wire-receive dispatch reaches after
	// envelope verification.
	resp, err := d.DispatchLocalExecute(context.Background(), LocalExecuteRequest{
		URI:              "entity://" + string(localKP.PeerID()) + "/" + pattern,
		Operation:        "run",
		Params:           paramsEnt,
		CallerCapability: callerCap,
		Author:           localKP.PeerID(),
		AuthorHash:       localIdentity.ContentHash,
	})
	if err != nil {
		t.Fatalf("DispatchLocalExecute: %v", err)
	}
	if resp == nil {
		t.Fatal("nil response")
	}
	if resp.Status != 200 {
		t.Fatalf("status: got %d (type=%s), want 200", resp.Status, resp.Result.Type)
	}

	// Verify the hook was invoked with the qualified expression path. The
	// dispatcher qualifies relative paths via qualifyIfRelative — proves
	// the entity-native branch executed, not the compiled-handler fallback.
	wantQualifiedExpr := "/" + string(localKP.PeerID()) + "/" + exprPath
	if calledExprPath != wantQualifiedExpr {
		t.Fatalf("EvaluateExpression got exprPath=%q, want %q", calledExprPath, wantQualifiedExpr)
	}
	if calledOp != "run" {
		t.Fatalf("EvaluateExpression got op=%q, want %q", calledOp, "run")
	}

	// Verify result flows back.
	if resp.Result.Type != "primitive/any" {
		t.Fatalf("result type: got %q, want primitive/any", resp.Result.Type)
	}
}

// TestMakeLocalExecuteEntityNativeWithDeliverTo verifies that the dispatcher
// honors deliver_to uniformly for entity-native handlers — same async-
// delivery semantics as compiled handlers. The handler runs in a goroutine,
// returns 202 immediately, and the result is routed through deliverToInbox
// to the deliver_to URI.
//
// Before the unification fix, this combination either silently dropped the
// delivery (makeLocalExecute pre-F7) or returned 400 async_unsupported
// (handleExecute, and the conservative version of the F7 fix). The
// dispatcher's contract is "dispatch and deliver" — handler shape is
// internal. V7 §6.6 makes the tree the source of truth for what binds at a
// pattern; the deliver_to flow operates above that and doesn't branch on
// implementation shape.
func TestMakeLocalExecuteEntityNativeWithDeliverTo(t *testing.T) {
	localKP, _ := crypto.Generate()
	localIdentity, _ := localKP.IdentityEntity()

	reg := handler.NewRegistry()
	cs := store.NewMemoryContentStore()
	li := store.NewNamespacedIndex(store.NewMemoryLocationIndex(), string(localKP.PeerID()))
	d := NewDispatcher(reg, cs, li, localKP, nil)

	// EvaluateExpression stub records the invocation so the test can
	// verify the goroutine actually ran the entity-native handler.
	invoked := make(chan string, 1)
	d.EvaluateExpression = func(ctx context.Context, exprPath string, req *handler.Request) (*handler.Response, error) {
		invoked <- exprPath
		raw, _ := ecf.Encode(map[string]any{"ok": true})
		result, _ := entity.NewEntity("primitive/any", cbor.RawMessage(raw))
		return &handler.Response{Status: 200, Result: result}, nil
	}

	if _, err := cs.Put(localIdentity); err != nil {
		t.Fatalf("put local identity: %v", err)
	}

	capData := types.CapabilityTokenData{
		Grants: []types.GrantEntry{{
			Handlers:   types.CapabilityScope{Include: []string{"*"}},
			Resources:  types.CapabilityScope{Include: []string{"*"}},
			Operations: types.CapabilityScope{Include: []string{"*"}},
		}},
		Granter:   types.SingleSigGranter(localIdentity.ContentHash),
		Grantee:   localIdentity.ContentHash,
		CreatedAt: 1,
	}
	callerCap, _ := capData.ToEntity()
	if _, err := cs.Put(callerCap); err != nil {
		t.Fatalf("put caller cap: %v", err)
	}

	const pattern = "test/entity-native-delivery"
	hd := types.HandlerData{
		Interface:      "system/handler/" + pattern,
		ExpressionPath: pattern + "/expr",
	}
	hEnt, err := hd.ToEntity()
	if err != nil {
		t.Fatalf("build handler entity: %v", err)
	}
	hHash, err := cs.Put(hEnt)
	if err != nil {
		t.Fatalf("put handler entity: %v", err)
	}
	if err := li.Set(pattern, hHash); err != nil {
		t.Fatalf("bind handler entity: %v", err)
	}
	grantPath := "system/capability/grants/" + pattern
	if err := li.Set(grantPath, callerCap.ContentHash); err != nil {
		t.Fatalf("bind placeholder grant: %v", err)
	}

	parentCtx := &handler.HandlerContext{
		LocalPeerID:      d.LocalPeerID,
		Store:            d.Store,
		LocationIndex:    d.LocationIndex,
		CallerCapability: callerCap,
		HandlerGrant:     callerCap, // non-zero — used as deliver_token
		AuthorHash:       localIdentity.ContentHash,
	}
	execute := d.makeLocalExecute(context.Background(), parentCtx)

	// Use a non-existent local URI for deliver_to — deliverToInbox will
	// log and fail, which is fine; we're testing that the async path
	// fires and the handler is invoked. deliverToInbox correctness is
	// covered by its own tests.
	deliverSpec := &types.DeliverySpec{URI: "test/recording-handler"}
	resp, err := execute(context.Background(), pattern, "compute", entity.Entity{},
		handler.WithDeliverTo(deliverSpec))
	if err != nil {
		t.Fatalf("execute closure returned error: %v", err)
	}
	if resp.Status != 202 {
		t.Fatalf("status: got %d (want 202 Accepted — entity-native + deliver_to is just another handler call)", resp.Status)
	}

	// Confirm the goroutine actually invoked EvaluateExpression. The
	// 202 alone doesn't prove the dispatch happened (we'd also get 202
	// if the async pool silently dropped the work), so verify the
	// invocation reached the entity-native branch.
	select {
	case exprPath := <-invoked:
		wantQualified := "/" + string(localKP.PeerID()) + "/" + pattern + "/expr"
		if exprPath != wantQualified {
			t.Fatalf("EvaluateExpression got exprPath=%q, want %q", exprPath, wantQualified)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("EvaluateExpression was not invoked — async delivery path didn't reach the handler")
	}
}

// TestDispatchLocalExecuteCompiled verifies DispatchLocalExecute reaches
// language-native (compiled) handlers via the same tree-walk path. A
// regression here would mean the SDK's local dispatch path stopped working
// for the registry-resident handler case.
func TestDispatchLocalExecuteCompiled(t *testing.T) {
	localKP, _ := crypto.Generate()
	localIdentity, _ := localKP.IdentityEntity()

	reg := handler.NewRegistry()
	reg.Register("test/echo", &echoHandler{})

	cs := store.NewMemoryContentStore()
	li := store.NewNamespacedIndex(store.NewMemoryLocationIndex(), string(localKP.PeerID()))
	if err := SeedHandlersFromRegistry(cs, li, reg); err != nil {
		t.Fatalf("seed handlers: %v", err)
	}
	d := NewDispatcher(reg, cs, li, localKP, nil)

	if _, err := cs.Put(localIdentity); err != nil {
		t.Fatalf("put local identity: %v", err)
	}

	capData := types.CapabilityTokenData{
		Grants: []types.GrantEntry{{
			Handlers:   types.CapabilityScope{Include: []string{"*"}},
			Resources:  types.CapabilityScope{Include: []string{"*"}},
			Operations: types.CapabilityScope{Include: []string{"*"}},
		}},
		Granter:   types.SingleSigGranter(localIdentity.ContentHash),
		Grantee:   localIdentity.ContentHash,
		CreatedAt: 1,
	}
	callerCap, _ := capData.ToEntity()
	if _, err := cs.Put(callerCap); err != nil {
		t.Fatalf("put caller cap: %v", err)
	}

	paramsRaw, _ := ecf.Encode("hello")
	paramsEnt, _ := entity.NewEntity("test/params", cbor.RawMessage(paramsRaw))

	resp, err := d.DispatchLocalExecute(context.Background(), LocalExecuteRequest{
		URI:              "test/echo",
		Operation:        "ping",
		Params:           paramsEnt,
		CallerCapability: callerCap,
		Author:           localKP.PeerID(),
		AuthorHash:       localIdentity.ContentHash,
	})
	if err != nil {
		t.Fatalf("DispatchLocalExecute: %v", err)
	}
	if resp.Status != 200 {
		t.Fatalf("status: got %d, want 200", resp.Status)
	}
}

func TestExecuteTTLDecrement(t *testing.T) {
	ttl := uint64(1)
	bounds := &types.BoundsData{TTL: &ttl}

	child, err := decrementBounds(bounds)
	if err != nil {
		t.Fatal(err)
	}
	if *child.TTL != 0 {
		t.Fatalf("expected TTL 0, got %d", *child.TTL)
	}

	// Original should be unchanged.
	if *bounds.TTL != 1 {
		t.Fatalf("original TTL should be 1, got %d", *bounds.TTL)
	}
}

func TestExecuteTTLExhausted(t *testing.T) {
	ttl := uint64(0)
	bounds := &types.BoundsData{TTL: &ttl}

	_, err := decrementBounds(bounds)
	if err == nil {
		t.Fatal("expected error for exhausted TTL")
	}
}

func TestExecuteNilBounds(t *testing.T) {
	child, err := decrementBounds(nil)
	if err != nil {
		t.Fatal(err)
	}
	if child != nil {
		t.Fatal("expected nil bounds")
	}
}
