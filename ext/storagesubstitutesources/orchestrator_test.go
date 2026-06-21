package storagesubstitutesources

import (
	"context"
	"errors"
	"testing"
	"time"

	"go.entitychurch.org/entity-core-go/core/crypto"
	"go.entitychurch.org/entity-core-go/core/ecf"
	"go.entitychurch.org/entity-core-go/core/entity"
	"go.entitychurch.org/entity-core-go/core/handler"
	"go.entitychurch.org/entity-core-go/core/hash"
	"go.entitychurch.org/entity-core-go/core/store"
	"go.entitychurch.org/entity-core-go/core/types"
)

// stubExecute is a recordable Execute function — captures calls + returns
// a programmed response. It's plugged into HandlerContext.Execute so the
// orchestrator's dispatch calls flow through it without needing a real
// dispatcher.
type stubExecute struct {
	calls []stubCall
	// responder maps "<uri>" → response (status + body entity). Default is
	// 404. CapDeniedHandlers returns 403 instead.
	responder func(uri, op string, params entity.Entity) (*handler.Response, error)
}

type stubCall struct {
	uri    string
	op     string
	params entity.Entity
}

func (s *stubExecute) fn(ctx context.Context, uri, op string, params entity.Entity, opts ...handler.ExecuteOption) (*handler.Response, error) {
	s.calls = append(s.calls, stubCall{uri: uri, op: op, params: params})
	if s.responder == nil {
		return &handler.Response{Status: 404}, nil
	}
	return s.responder(uri, op, params)
}

// publishSource puts a substitute-source entity into the store + binds it
// at SubstituteSourcePathPrefix/{hash} so the orchestrator's listEntries
// scan finds it.
func publishSource(t *testing.T, cs store.ContentStore, li store.LocationIndex, src types.SubstituteSourceData) hash.Hash {
	t.Helper()
	ent, err := src.ToEntity()
	if err != nil {
		t.Fatalf("ToEntity: %v", err)
	}
	h, err := cs.Put(ent)
	if err != nil {
		t.Fatalf("Put: %v", err)
	}
	if err := li.Set(types.SubstituteSourcePathPrefix+h.String(), h); err != nil {
		t.Fatalf("Set: %v", err)
	}
	return h
}

// mkSrc builds an HTTP substitute source for the given claimed peer with
// the given priority.
func mkSrc(t *testing.T, name string, claimed hash.Hash, priority int64) types.SubstituteSourceData {
	t.Helper()
	src, err := types.NewHTTPSource(name, claimed, types.TransportEndpoint{
		TreeURLPrefix:    "https://" + name + ".example.com",
		ContentURLPrefix: "https://" + name + ".example.com/content",
		ContentLayout:    types.ContentLayoutFlat,
	}, priority)
	if err != nil {
		t.Fatalf("NewHTTPSource: %v", err)
	}
	return src
}

// mkPayloadEntity returns an entity with hash-stable test bytes.
func mkPayloadEntity(t *testing.T, payload string) entity.Entity {
	t.Helper()
	dataBytes, err := ecf.Encode(payload)
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	ent, err := entity.NewEntity("test/payload", dataBytes)
	if err != nil {
		t.Fatalf("NewEntity: %v", err)
	}
	return ent
}

// testLocalPeerID is the local peer ID used for canonicalizing both the
// request resource and the cap resource pattern in tests (V7 §5.5 / PR-8).
// 46+ Base58 chars so it satisfies looksLikePeerID.
const testLocalPeerID = crypto.PeerID("2KZFtestSubstituteSourcesLocalPeerIDAAAAAAAAAA")

// testConsultResource is the namespace-shaped target the test inbound
// content:get reads into, used as the consult gate's resource axis
// per D-2. Grants in mkConsultCap are scoped to a matching pattern
// ("system/validate/*") so the default-permit case actually permits.
const testConsultResource = "system/validate/things"

// testConsultResourcePattern is the cap-resource pattern that covers
// testConsultResource — wildcarded so a single grant covers a namespace.
const testConsultResourcePattern = "system/validate/*"

// mkConsultCap builds an entity.Entity holding a token that permits the
// consult gate per RULING-NAMED-CAPABILITY-MAPPING §4 +
// PROPOSAL-TRANSPORT-FAMILY-CHUNK-C-AMENDMENTS D-2 (resource
// axis = the triggering CONTENT request's namespace, not a static
// chain-namespace).
// Pass extraGrantTweak to adjust the grant (narrow handler/op/resource,
// add constraints, etc.) for targeted gate-failure tests; nil for the
// default permit-consult shape.
func mkConsultCap(t *testing.T, extraGrantTweak func(*types.GrantEntry)) entity.Entity {
	t.Helper()
	g := types.GrantEntry{
		Handlers:   types.CapabilityScope{Include: []string{HandlerPatternSources}},
		Resources:  types.CapabilityScope{Include: []string{testConsultResourcePattern}},
		Operations: types.CapabilityScope{Include: []string{OperationConsult}},
	}
	if extraGrantTweak != nil {
		extraGrantTweak(&g)
	}
	granterHash := hash.Hash{Algorithm: hash.AlgorithmSHA256}
	granterHash.Digest[0] = 0xa1
	tokenData := types.CapabilityTokenData{
		Grants:    []types.GrantEntry{g},
		Granter:   types.SingleSigGranter(granterHash),
		Grantee:   peerID(0xa2),
		CreatedAt: 1,
	}
	ent, err := tokenData.ToEntity()
	if err != nil {
		t.Fatalf("token ToEntity: %v", err)
	}
	// CallerCapability needs a non-zero ContentHash for the gate to
	// recognize it as present (zero hash trips the fail-closed branch).
	cs := store.NewMemoryContentStore()
	h, err := cs.Put(ent)
	if err != nil {
		t.Fatalf("Put: %v", err)
	}
	ent.ContentHash = h
	return ent
}

// defaultConsultResourceTarget is the Resource the inbound content:get
// is read with — supplied to the orchestrator via hctx.Resource per D-2.
func defaultConsultResourceTarget() *types.ResourceTarget {
	return &types.ResourceTarget{Targets: []string{testConsultResource}}
}

// mkHCtx assembles a HandlerContext with a stub Execute, store, and index.
// The default CallerCapability permits the consult gate; tests that need
// to exercise gate failure use mkHCtxNoCap or mkHCtxWithCap.
func mkHCtx(t *testing.T, cs store.ContentStore, li store.LocationIndex, exec *stubExecute) *handler.HandlerContext {
	t.Helper()
	return &handler.HandlerContext{
		Store:            cs,
		LocationIndex:    li,
		Execute:          exec.fn,
		LocalPeerID:      testLocalPeerID,
		CallerCapability: mkConsultCap(t, nil),
		Resource:         defaultConsultResourceTarget(),
	}
}

// mkHCtxNoCap returns a HandlerContext with no CallerCapability — the
// fail-closed default-deny path.
func mkHCtxNoCap(t *testing.T, cs store.ContentStore, li store.LocationIndex, exec *stubExecute) *handler.HandlerContext {
	t.Helper()
	return &handler.HandlerContext{
		Store:         cs,
		LocationIndex: li,
		Execute:       exec.fn,
		LocalPeerID:   testLocalPeerID,
		Resource:      defaultConsultResourceTarget(),
	}
}

// mkHCtxWithCap returns a HandlerContext with the supplied cap entity.
func mkHCtxWithCap(t *testing.T, cs store.ContentStore, li store.LocationIndex, exec *stubExecute, cap entity.Entity) *handler.HandlerContext {
	t.Helper()
	return &handler.HandlerContext{
		Store:            cs,
		LocationIndex:    li,
		Execute:          exec.fn,
		LocalPeerID:      testLocalPeerID,
		CallerCapability: cap,
		Resource:         defaultConsultResourceTarget(),
	}
}

// peerID returns a non-zero hash distinguishable by its first byte.
func peerID(b byte) hash.Hash {
	h := hash.Hash{Algorithm: hash.AlgorithmSHA256}
	h.Digest[0] = b
	return h
}

func TestConsult_BareHashShortCircuit(t *testing.T) {
	// claimedSourcePeerID is the zero hash → orchestrator returns
	// OutcomeDisabled without consulting any entries.
	cs := store.NewMemoryContentStore()
	li := store.NewMemoryLocationIndex()
	exec := &stubExecute{}
	hctx := mkHCtx(t, cs, li, exec)

	o := New()
	res := o.Consult(context.Background(), hctx, peerID(0xff), hash.Hash{})

	if res.Outcome != OutcomeDisabled {
		t.Errorf("outcome: got %v want Disabled", res.Outcome)
	}
	if len(exec.calls) != 0 {
		t.Errorf("should not have dispatched any try calls, got %d", len(exec.calls))
	}
}

func TestConsult_EmptyChain(t *testing.T) {
	// claimedSourcePeerID is set but no substitute-source entries exist →
	// OutcomeNotFound.
	cs := store.NewMemoryContentStore()
	li := store.NewMemoryLocationIndex()
	exec := &stubExecute{}
	hctx := mkHCtx(t, cs, li, exec)

	o := New()
	res := o.Consult(context.Background(), hctx, peerID(0x01), peerID(0xab))

	if res.Outcome != OutcomeNotFound {
		t.Errorf("outcome: got %v want NotFound", res.Outcome)
	}
	if res.AttemptedCount != 0 {
		t.Errorf("attempted: got %d want 0", res.AttemptedCount)
	}
}

func TestConsult_Success_FirstEntryReturnsBytes(t *testing.T) {
	cs := store.NewMemoryContentStore()
	li := store.NewMemoryLocationIndex()
	claimed := peerID(0xab)
	target := peerID(0xcd) // the hash we're fetching

	publishSource(t, cs, li, mkSrc(t, "primary", claimed, 10))

	payload := mkPayloadEntity(t, "the fetched bytes")
	// Need the payload's hash to equal target. Build target = payload.hash.
	target = payload.ContentHash

	exec := &stubExecute{
		responder: func(uri, op string, params entity.Entity) (*handler.Response, error) {
			// Sanity: orchestrator dispatched to system/substitute/http
			if uri != "system/substitute/http" {
				return nil, errors.New("unexpected uri " + uri)
			}
			if op != types.OpSubstituteTry {
				return nil, errors.New("unexpected op " + op)
			}
			return &handler.Response{Status: 200, Result: payload}, nil
		},
	}
	hctx := mkHCtx(t, cs, li, exec)

	o := New()
	res := o.Consult(context.Background(), hctx, target, claimed)
	if res.Outcome != OutcomeBytes {
		t.Fatalf("outcome: got %v (last_error=%q) want Bytes", res.Outcome, res.LastError)
	}
	if res.Bytes.ContentHash != target {
		t.Errorf("returned hash mismatch: got %s want %s", res.Bytes.ContentHash, target)
	}
	if res.AttemptedCount != 1 {
		t.Errorf("attempted: got %d want 1", res.AttemptedCount)
	}
	if len(exec.calls) != 1 {
		t.Errorf("dispatch calls: got %d want 1", len(exec.calls))
	}
}

func TestConsult_AdvanceOnNotFound(t *testing.T) {
	// First entry returns 404; second returns 200. Orchestrator advances
	// past the first and succeeds on the second.
	cs := store.NewMemoryContentStore()
	li := store.NewMemoryLocationIndex()
	claimed := peerID(0xab)

	payload := mkPayloadEntity(t, "the fetched bytes")
	target := payload.ContentHash

	publishSource(t, cs, li, mkSrc(t, "primary", claimed, 10))
	publishSource(t, cs, li, mkSrc(t, "fallback", claimed, 20))

	calls := 0
	exec := &stubExecute{
		responder: func(uri, op string, params entity.Entity) (*handler.Response, error) {
			calls++
			if calls == 1 {
				return &handler.Response{Status: 404}, nil
			}
			return &handler.Response{Status: 200, Result: payload}, nil
		},
	}
	hctx := mkHCtx(t, cs, li, exec)

	o := New()
	res := o.Consult(context.Background(), hctx, target, claimed)
	if res.Outcome != OutcomeBytes {
		t.Fatalf("outcome: got %v want Bytes", res.Outcome)
	}
	if res.AttemptedCount != 2 {
		t.Errorf("attempted: got %d want 2", res.AttemptedCount)
	}
}

func TestConsult_AdvanceOnHashMismatch(t *testing.T) {
	// First entry returns 200 with the wrong hash; orchestrator advances.
	cs := store.NewMemoryContentStore()
	li := store.NewMemoryLocationIndex()
	claimed := peerID(0xab)

	wrongPayload := mkPayloadEntity(t, "wrong bytes")
	rightPayload := mkPayloadEntity(t, "right bytes")
	target := rightPayload.ContentHash

	publishSource(t, cs, li, mkSrc(t, "buggy", claimed, 10))
	publishSource(t, cs, li, mkSrc(t, "correct", claimed, 20))

	calls := 0
	exec := &stubExecute{
		responder: func(uri, op string, params entity.Entity) (*handler.Response, error) {
			calls++
			if calls == 1 {
				return &handler.Response{Status: 200, Result: wrongPayload}, nil
			}
			return &handler.Response{Status: 200, Result: rightPayload}, nil
		},
	}
	hctx := mkHCtx(t, cs, li, exec)

	o := New()
	res := o.Consult(context.Background(), hctx, target, claimed)
	if res.Outcome != OutcomeBytes {
		t.Fatalf("outcome: got %v want Bytes (last_error=%q)", res.Outcome, res.LastError)
	}
	if res.Bytes.ContentHash != target {
		t.Errorf("returned wrong entity: %s", res.Bytes.ContentHash)
	}
}

func TestConsult_AbortOnCapDenied(t *testing.T) {
	// First entry returns 403 — orchestrator aborts the whole chain.
	cs := store.NewMemoryContentStore()
	li := store.NewMemoryLocationIndex()
	claimed := peerID(0xab)

	publishSource(t, cs, li, mkSrc(t, "primary", claimed, 10))
	publishSource(t, cs, li, mkSrc(t, "fallback", claimed, 20))

	exec := &stubExecute{
		responder: func(uri, op string, params entity.Entity) (*handler.Response, error) {
			return &handler.Response{Status: 403}, nil
		},
	}
	hctx := mkHCtx(t, cs, li, exec)

	o := New()
	res := o.Consult(context.Background(), hctx, peerID(0xcd), claimed)
	if res.Outcome != OutcomeCapDenied {
		t.Fatalf("outcome: got %v want CapDenied", res.Outcome)
	}
	if res.AttemptedCount != 1 {
		t.Errorf("attempted: got %d want 1 (chain MUST abort on first 403)", res.AttemptedCount)
	}
}

func TestConsult_PriorityOrdering(t *testing.T) {
	// Sources at priority 50, 10, 30; orchestrator dispatches in 10, 30, 50.
	cs := store.NewMemoryContentStore()
	li := store.NewMemoryLocationIndex()
	claimed := peerID(0xab)

	publishSource(t, cs, li, mkSrc(t, "slow", claimed, 50))
	publishSource(t, cs, li, mkSrc(t, "fast", claimed, 10))
	publishSource(t, cs, li, mkSrc(t, "medium", claimed, 30))

	exec := &stubExecute{
		responder: func(uri, op string, params entity.Entity) (*handler.Response, error) {
			// Pull entry name out of try-request to assert order.
			return &handler.Response{Status: 404}, nil
		},
	}
	hctx := mkHCtx(t, cs, li, exec)

	o := New()
	res := o.Consult(context.Background(), hctx, peerID(0xcd), claimed)
	if res.Outcome != OutcomeNotFound {
		t.Fatalf("outcome: got %v want NotFound", res.Outcome)
	}
	if res.AttemptedCount != 3 {
		t.Errorf("attempted: got %d want 3", res.AttemptedCount)
	}

	// Decode each call's try-request and confirm the entry-name order.
	wantOrder := []string{"fast", "medium", "slow"}
	for i, call := range exec.calls {
		req, err := types.SubstituteTryRequestDataFromEntity(call.params)
		if err != nil {
			t.Fatalf("decode call %d: %v", i, err)
		}
		src, err := types.SubstituteSourceDataFromEntity(req.Entry)
		if err != nil {
			t.Fatalf("decode src %d: %v", i, err)
		}
		if src.Name != wantOrder[i] {
			t.Errorf("call %d: dispatched %q, want %q", i, src.Name, wantOrder[i])
		}
	}
}

func TestConsult_SkipsDisabledEntries(t *testing.T) {
	cs := store.NewMemoryContentStore()
	li := store.NewMemoryLocationIndex()
	claimed := peerID(0xab)

	enabled := mkSrc(t, "enabled", claimed, 10)
	disabled := mkSrc(t, "disabled", claimed, 5)
	disabled.Enabled = false
	publishSource(t, cs, li, enabled)
	publishSource(t, cs, li, disabled)

	exec := &stubExecute{
		responder: func(uri, op string, params entity.Entity) (*handler.Response, error) {
			return &handler.Response{Status: 404}, nil
		},
	}
	hctx := mkHCtx(t, cs, li, exec)

	o := New()
	res := o.Consult(context.Background(), hctx, peerID(0xcd), claimed)
	if res.AttemptedCount != 1 {
		t.Errorf("attempted: got %d want 1 (disabled entry must be skipped)", res.AttemptedCount)
	}
}

func TestConsult_SkipsWrongSourcePeerID(t *testing.T) {
	cs := store.NewMemoryContentStore()
	li := store.NewMemoryLocationIndex()
	wantedPeer := peerID(0xab)
	otherPeer := peerID(0xcd)

	publishSource(t, cs, li, mkSrc(t, "wrong-peer", otherPeer, 10))
	publishSource(t, cs, li, mkSrc(t, "right-peer", wantedPeer, 20))

	exec := &stubExecute{
		responder: func(uri, op string, params entity.Entity) (*handler.Response, error) {
			return &handler.Response{Status: 404}, nil
		},
	}
	hctx := mkHCtx(t, cs, li, exec)

	o := New()
	res := o.Consult(context.Background(), hctx, peerID(0xee), wantedPeer)
	if res.AttemptedCount != 1 {
		t.Errorf("attempted: got %d want 1 (only the matching-peer entry should dispatch)", res.AttemptedCount)
	}
}

func TestConsult_SkipsExpiredEntries(t *testing.T) {
	cs := store.NewMemoryContentStore()
	li := store.NewMemoryLocationIndex()
	claimed := peerID(0xab)

	live := mkSrc(t, "live", claimed, 10)
	expired := mkSrc(t, "expired", claimed, 5)
	expired.ExpiresAt = 1000 // long-past timestamp
	publishSource(t, cs, li, live)
	publishSource(t, cs, li, expired)

	exec := &stubExecute{
		responder: func(uri, op string, params entity.Entity) (*handler.Response, error) {
			return &handler.Response{Status: 404}, nil
		},
	}
	hctx := mkHCtx(t, cs, li, exec)

	// Pin the orchestrator's clock to "now" = 2000 so expired entry is past.
	o := New(WithNow(func() time.Time { return time.Unix(2000, 0) }))
	res := o.Consult(context.Background(), hctx, peerID(0xcd), claimed)
	if res.AttemptedCount != 1 {
		t.Errorf("attempted: got %d want 1 (expired entry must be skipped)", res.AttemptedCount)
	}
}

func TestConsult_SkipsRejectedSignature(t *testing.T) {
	// Signature verifier rejects all → no entries dispatch.
	cs := store.NewMemoryContentStore()
	li := store.NewMemoryLocationIndex()
	claimed := peerID(0xab)

	publishSource(t, cs, li, mkSrc(t, "primary", claimed, 10))

	exec := &stubExecute{
		responder: func(uri, op string, params entity.Entity) (*handler.Response, error) {
			return &handler.Response{Status: 404}, nil
		},
	}
	hctx := mkHCtx(t, cs, li, exec)

	rejectAll := func(_ *handler.HandlerContext, _ entity.Entity, _ types.SubstituteSourceData) error {
		return errors.New("signature_invalid")
	}
	o := New(WithSignatureVerifier(rejectAll))
	res := o.Consult(context.Background(), hctx, peerID(0xcd), claimed)
	if res.AttemptedCount != 0 {
		t.Errorf("attempted: got %d want 0 (signature rejection must skip)", res.AttemptedCount)
	}
	if res.Outcome != OutcomeNotFound {
		t.Errorf("outcome: got %v want NotFound", res.Outcome)
	}
}

// --- Cap-axis ruling conformance tests
// RULING-NAMED-CAPABILITY-MAPPING §4 maps the consult gate to
// (HandlerPatternSources, OperationConsult) checked via check_permission;
// §6 mandates fail-closed default — "any token" is NOT a grant match.

func TestConsult_FailClosed_NoCallerCapability(t *testing.T) {
	// No CallerCapability on the context — the gate MUST deny.
	cs := store.NewMemoryContentStore()
	li := store.NewMemoryLocationIndex()
	claimed := peerID(0xab)
	publishSource(t, cs, li, mkSrc(t, "primary", claimed, 10))

	exec := &stubExecute{}
	hctx := mkHCtxNoCap(t, cs, li, exec)

	o := New()
	res := o.Consult(context.Background(), hctx, peerID(0xcd), claimed)
	if res.Outcome != OutcomeDisabled {
		t.Errorf("outcome: got %v want Disabled (fail-closed: no cap)", res.Outcome)
	}
	if len(exec.calls) != 0 {
		t.Errorf("no try dispatch expected when cap denies, got %d", len(exec.calls))
	}
}

func TestConsult_DeniesWrongHandlerPattern(t *testing.T) {
	// Cap scoped to a different handler — gate MUST deny.
	cs := store.NewMemoryContentStore()
	li := store.NewMemoryLocationIndex()
	claimed := peerID(0xab)
	publishSource(t, cs, li, mkSrc(t, "primary", claimed, 10))

	wrongHandlerCap := mkConsultCap(t, func(g *types.GrantEntry) {
		g.Handlers = types.CapabilityScope{Include: []string{"system/somewhere-else"}}
	})
	exec := &stubExecute{}
	hctx := mkHCtxWithCap(t, cs, li, exec, wrongHandlerCap)

	o := New()
	res := o.Consult(context.Background(), hctx, peerID(0xcd), claimed)
	if res.Outcome != OutcomeDisabled {
		t.Errorf("outcome: got %v want Disabled (wrong handler)", res.Outcome)
	}
}

func TestConsult_DeniesWrongOperation(t *testing.T) {
	cs := store.NewMemoryContentStore()
	li := store.NewMemoryLocationIndex()
	claimed := peerID(0xab)
	publishSource(t, cs, li, mkSrc(t, "primary", claimed, 10))

	wrongOpCap := mkConsultCap(t, func(g *types.GrantEntry) {
		g.Operations = types.CapabilityScope{Include: []string{"some-other-op"}}
	})
	exec := &stubExecute{}
	hctx := mkHCtxWithCap(t, cs, li, exec, wrongOpCap)

	o := New()
	res := o.Consult(context.Background(), hctx, peerID(0xcd), claimed)
	if res.Outcome != OutcomeDisabled {
		t.Errorf("outcome: got %v want Disabled (wrong operation)", res.Outcome)
	}
}

func TestConsult_DeniesWrongResource(t *testing.T) {
	cs := store.NewMemoryContentStore()
	li := store.NewMemoryLocationIndex()
	claimed := peerID(0xab)
	publishSource(t, cs, li, mkSrc(t, "primary", claimed, 10))

	wrongResourceCap := mkConsultCap(t, func(g *types.GrantEntry) {
		g.Resources = types.CapabilityScope{Include: []string{"system/somewhere-else/*"}}
	})
	exec := &stubExecute{}
	hctx := mkHCtxWithCap(t, cs, li, exec, wrongResourceCap)

	o := New()
	res := o.Consult(context.Background(), hctx, peerID(0xcd), claimed)
	if res.Outcome != OutcomeDisabled {
		t.Errorf("outcome: got %v want Disabled (wrong resource)", res.Outcome)
	}
}

func TestConsult_SourcePeerIDConstraint_Matches_Permits(t *testing.T) {
	// Grant has source_peer_id constraint matching the claimed source → permits.
	cs := store.NewMemoryContentStore()
	li := store.NewMemoryLocationIndex()
	claimed := peerID(0xab)
	publishSource(t, cs, li, mkSrc(t, "primary", claimed, 10))

	constraintBytes, err := ecf.Encode(consultConstraints{SourcePeerID: &claimed})
	if err != nil {
		t.Fatalf("encode constraints: %v", err)
	}
	constrainedCap := mkConsultCap(t, func(g *types.GrantEntry) {
		g.Constraints = constraintBytes
	})

	// Stub returns the payload bytes so we know the chain walked through.
	payload := mkPayloadEntity(t, "via-constraint-match")
	exec := &stubExecute{
		responder: func(uri, op string, params entity.Entity) (*handler.Response, error) {
			return &handler.Response{Status: 200, Result: payload}, nil
		},
	}
	hctx := mkHCtxWithCap(t, cs, li, exec, constrainedCap)

	o := New()
	res := o.Consult(context.Background(), hctx, payload.ContentHash, claimed)
	if res.Outcome != OutcomeBytes {
		t.Errorf("outcome: got %v want Bytes (matching constraint should permit)", res.Outcome)
	}
}

func TestConsult_SourcePeerIDConstraint_Mismatch_Denies(t *testing.T) {
	// Grant constrains source_peer_id to peerID(0x99); claimed is 0xab → deny.
	cs := store.NewMemoryContentStore()
	li := store.NewMemoryLocationIndex()
	claimed := peerID(0xab)
	publishSource(t, cs, li, mkSrc(t, "primary", claimed, 10))

	differentSource := peerID(0x99)
	constraintBytes, err := ecf.Encode(consultConstraints{SourcePeerID: &differentSource})
	if err != nil {
		t.Fatalf("encode constraints: %v", err)
	}
	constrainedCap := mkConsultCap(t, func(g *types.GrantEntry) {
		g.Constraints = constraintBytes
	})

	exec := &stubExecute{}
	hctx := mkHCtxWithCap(t, cs, li, exec, constrainedCap)

	o := New()
	res := o.Consult(context.Background(), hctx, peerID(0xcd), claimed)
	if res.Outcome != OutcomeDisabled {
		t.Errorf("outcome: got %v want Disabled (constraint mismatch)", res.Outcome)
	}
	if len(exec.calls) != 0 {
		t.Errorf("no try dispatch expected when constraint denies, got %d", len(exec.calls))
	}
}
