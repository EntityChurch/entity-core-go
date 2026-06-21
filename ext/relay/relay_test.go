package relay

import (
	"bytes"
	"context"
	"encoding/binary"
	"testing"

	"go.entitychurch.org/entity-core-go/core/crypto"
	"go.entitychurch.org/entity-core-go/core/ecf"
	"go.entitychurch.org/entity-core-go/core/entity"
	"go.entitychurch.org/entity-core-go/core/handler"
	"go.entitychurch.org/entity-core-go/core/hash"
	"go.entitychurch.org/entity-core-go/core/store"
	"go.entitychurch.org/entity-core-go/core/types"

	"github.com/fxamacker/cbor/v2"
)

// Fixture Base58-shaped peer-ids (mirrors core/types/relay_test.go).
const (
	tFakeSender = "2KSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSS"
	tFakeRelay  = "2KRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRR"
	tFakeDest   = "2KDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDD"
)

// newTestHandler returns a handler with SetupStore already called + a
// frozen clock for deterministic expires_at handling.
func newTestHandler(t *testing.T) *Handler {
	t.Helper()
	h := NewHandler()
	h.SetClock(func() uint64 { return 1_730_000_000_000 })
	h.SetupStore(tFakeRelay)
	return h
}

func newTestContext() *handler.HandlerContext {
	return &handler.HandlerContext{
		Store:          store.NewMemoryContentStore(),
		LocationIndex:  store.NewMemoryLocationIndex(),
		HandlerPattern: HandlerPattern,
		RequestID:      "test-req-1",
		Included:       make(map[hash.Hash]entity.Entity),
	}
}

// sharedStores builds a single Store + LocationIndex pair that multiple
// per-request contexts share — modeling the peer-level state production
// uses (one ContentStore + one LocationIndex per peer; per-request hctxs
// project onto them). RULING-RELAY-RECEIVE-SIDE-FETCH-SURFACE
// made handlePoll consult the tree, so put + poll on disjoint
// LocationIndexes no longer cross-link — tests using both paths must
// share the index.
func sharedStores() (store.ContentStore, store.LocationIndex) {
	return store.NewMemoryContentStore(), store.NewMemoryLocationIndex()
}

// newSharedContext returns a fresh handler context that reads/writes
// through the SHARED store/index. Per-request fields (Included, RequestID)
// stay per-context; the peer-level state stays shared.
func newSharedContext(cs store.ContentStore, li store.LocationIndex) *handler.HandlerContext {
	return &handler.HandlerContext{
		Store:          cs,
		LocationIndex:  li,
		HandlerPattern: HandlerPattern,
		RequestID:      "test-req-1",
		Included:       make(map[hash.Hash]entity.Entity),
	}
}

// makeInnerEnvelope returns an opaque entity standing in for the inner
// envelope (§9 — relay never decodes; tests just need byte-stable bytes).
func makeInnerEnvelope(t *testing.T, payload string) entity.Entity {
	t.Helper()
	raw, _ := ecf.Encode(map[string]any{"payload": payload})
	ent, err := entity.NewEntity("primitive/any", cbor.RawMessage(raw))
	if err != nil {
		t.Fatalf("makeInnerEnvelope: %v", err)
	}
	return ent
}

// -----------------------------------------------------------------------
// Handle dispatch + readiness
// -----------------------------------------------------------------------

func TestHandle_NotReadyReturns503(t *testing.T) {
	h := NewHandler() // no SetupStore call
	hctx := newTestContext()
	rd := types.PollRequestData{Namespace: tFakeDest}
	params, _ := rd.ToEntity()
	resp, err := h.Handle(context.Background(), &handler.Request{
		Path:      HandlerPattern,
		Operation: OpPoll,
		Params:    params,
		Context:   hctx,
	})
	if err != nil {
		t.Fatalf("Handle: %v", err)
	}
	if resp.Status != 503 {
		t.Fatalf("status: want 503, got %d", resp.Status)
	}
}

func TestHandle_UnknownOperation(t *testing.T) {
	h := newTestHandler(t)
	hctx := newTestContext()
	resp, err := h.Handle(context.Background(), &handler.Request{
		Path:      HandlerPattern,
		Operation: "bogus",
		Context:   hctx,
	})
	if err != nil {
		t.Fatalf("Handle: %v", err)
	}
	if resp.Status != 400 {
		t.Fatalf("status: want 400, got %d", resp.Status)
	}
}

// -----------------------------------------------------------------------
// :advertise
// -----------------------------------------------------------------------

func TestAdvertise_Happy(t *testing.T) {
	h := newTestHandler(t)
	hctx := newTestContext()
	adv := types.AdvertiseData{
		Modes: []string{types.RelayModeForward, types.RelayModeStorePoll},
		Endpoints: []cbor.RawMessage{
			mustEnc(t, map[string]any{"transport": "tcp", "addr": "192.0.2.7", "port": uint64(9002)}),
		},
		Limits:       types.AdvertiseLimits{MaxEnvelopeSize: 1 << 20},
		CapsRequired: []string{types.CapRelayForward},
	}
	params, _ := adv.ToEntity()
	resp, err := h.Handle(context.Background(), &handler.Request{
		Path:      HandlerPattern,
		Operation: OpAdvertise,
		Params:    params,
		Context:   hctx,
	})
	if err != nil {
		t.Fatalf("Handle: %v", err)
	}
	if resp.Status != 200 {
		t.Fatalf("status: want 200, got %d", resp.Status)
	}
	// §4.1: advertise lives at system/relay/advertise/{relay_peer_id}.
	wantPath := types.RelayAdvertisePath(tFakeRelay)
	if !hctx.LocationIndex.Has(wantPath) {
		t.Fatalf("advertise not bound at %s", wantPath)
	}
}

func TestAdvertise_RejectsEmptyModes(t *testing.T) {
	h := newTestHandler(t)
	hctx := newTestContext()
	params, _ := types.AdvertiseData{Modes: []string{}}.ToEntity()
	resp, _ := h.Handle(context.Background(), &handler.Request{
		Path:      HandlerPattern,
		Operation: OpAdvertise,
		Params:    params,
		Context:   hctx,
	})
	if resp.Status != 400 {
		t.Fatalf("status: want 400, got %d", resp.Status)
	}
}

// -----------------------------------------------------------------------
// :put
// -----------------------------------------------------------------------

func TestPut_Happy(t *testing.T) {
	h := newTestHandler(t)
	hctx := newTestContext()
	inner := makeInnerEnvelope(t, "hello")
	hctx.Included[inner.ContentHash] = inner

	se := types.StoreEntryData{
		Namespace:     tFakeDest,
		PutBy:         tFakeRelay,
		EnvelopeInner: inner.ContentHash,
	}
	params, _ := se.ToEntity()
	resp, err := h.Handle(context.Background(), &handler.Request{
		Path:      HandlerPattern,
		Operation: OpPut,
		Params:    params,
		Context:   hctx,
	})
	if err != nil {
		t.Fatalf("Handle: %v", err)
	}
	if resp.Status != 200 {
		t.Fatalf("status: want 200, got %d", resp.Status)
	}
	res, err := types.PutResultDataFromEntity(resp.Result)
	if err != nil {
		t.Fatalf("decode put-result: %v", err)
	}
	if res.Status != types.PutStatusStored {
		t.Fatalf("Status: want %q, got %q", types.PutStatusStored, res.Status)
	}
	entryEnt, _ := se.ToEntity()
	if !bytes.Equal(res.EntryHash.Bytes(), entryEnt.ContentHash.Bytes()) {
		t.Fatal("EntryHash drift")
	}
	wantPath := types.RelayStorePath(tFakeDest, entryEnt.ContentHash)
	if res.StoredAt != wantPath {
		t.Fatalf("StoredAt: want %q, got %q", wantPath, res.StoredAt)
	}
}

func TestPut_MissingNamespace(t *testing.T) {
	h := newTestHandler(t)
	hctx := newTestContext()
	inner := makeInnerEnvelope(t, "x")
	hctx.Included[inner.ContentHash] = inner
	params, _ := types.StoreEntryData{
		PutBy:         tFakeRelay,
		EnvelopeInner: inner.ContentHash,
	}.ToEntity()
	resp, _ := h.Handle(context.Background(), &handler.Request{
		Operation: OpPut, Params: params, Context: hctx,
	})
	if resp.Status != 400 {
		t.Fatalf("status: want 400, got %d", resp.Status)
	}
	code := decodeErrCode(t, resp)
	if code != types.RelayErrNamespaceInvalid {
		t.Fatalf("code: want %q, got %q", types.RelayErrNamespaceInvalid, code)
	}
}

func TestPut_ExpiredOnArrival(t *testing.T) {
	h := newTestHandler(t)
	hctx := newTestContext()
	inner := makeInnerEnvelope(t, "x")
	hctx.Included[inner.ContentHash] = inner
	// frozen clock = 1_730_000_000_000; an expires_at *equal to* now is past
	// per §4.3 (the relay-clock pass-through is fail-closed at the boundary).
	params, _ := types.StoreEntryData{
		Namespace:     tFakeDest,
		PutBy:         tFakeRelay,
		ExpiresAt:     1_730_000_000_000,
		EnvelopeInner: inner.ContentHash,
	}.ToEntity()
	resp, _ := h.Handle(context.Background(), &handler.Request{
		Operation: OpPut, Params: params, Context: hctx,
	})
	if resp.Status != 400 || decodeErrCode(t, resp) != types.RelayErrExpiredOnArrival {
		t.Fatalf("want 400 expired_on_arrival, got %d %q", resp.Status, decodeErrCode(t, resp))
	}
}

func TestPut_RejectsMissingInner(t *testing.T) {
	// §9: relay MUST reject when envelope_inner is not in included set (the
	// caller never attached the inner envelope; v1 relay does NOT lazy-fetch).
	h := newTestHandler(t)
	hctx := newTestContext()
	params, _ := types.StoreEntryData{
		Namespace:     tFakeDest,
		PutBy:         tFakeRelay,
		EnvelopeInner: relayFakeContentHash(0xAB), // not in included
	}.ToEntity()
	resp, _ := h.Handle(context.Background(), &handler.Request{
		Operation: OpPut, Params: params, Context: hctx,
	})
	if resp.Status != 400 {
		t.Fatalf("status: want 400, got %d", resp.Status)
	}
}

// §3.2 (post-Go-pre-impl-review): the relay MUST verify put_by ==
// authenticated wire caller. R3a gate.
func TestPut_PutByMismatchRejected(t *testing.T) {
	h := newTestHandler(t)
	hctx := newTestContext()
	hctx.SessionPeerID = crypto.PeerID(tFakeSender) // wire caller is Sender
	inner := makeInnerEnvelope(t, "x")
	hctx.Included[inner.ContentHash] = inner
	// PutBy claims to be the Relay, but the authenticated caller is Sender.
	params, _ := types.StoreEntryData{
		Namespace:     tFakeDest,
		PutBy:         tFakeRelay, // mismatch
		EnvelopeInner: inner.ContentHash,
	}.ToEntity()
	resp, _ := h.Handle(context.Background(), &handler.Request{
		Operation: OpPut, Params: params, Context: hctx,
	})
	if resp.Status != 400 {
		t.Fatalf("status: want 400, got %d", resp.Status)
	}
	if code := decodeErrCode(t, resp); code != types.RelayErrPutByMismatch {
		t.Fatalf("code: want %q, got %q", types.RelayErrPutByMismatch, code)
	}
}

func TestPut_PutByMatchesCallerAccepts(t *testing.T) {
	// On the wire happy path put_by == authenticated caller is the
	// trustworthy "placement identity" gate that makes put_by useful for
	// abuse attribution / rate limiting / GC.
	h := newTestHandler(t)
	hctx := newTestContext()
	hctx.SessionPeerID = crypto.PeerID(tFakeSender)
	inner := makeInnerEnvelope(t, "x")
	hctx.Included[inner.ContentHash] = inner
	params, _ := types.StoreEntryData{
		Namespace:     tFakeDest,
		PutBy:         tFakeSender, // matches Author
		EnvelopeInner: inner.ContentHash,
	}.ToEntity()
	resp, _ := h.Handle(context.Background(), &handler.Request{
		Operation: OpPut, Params: params, Context: hctx,
	})
	if resp.Status != 200 {
		t.Fatalf("happy put_by==caller: want 200, got %d (code=%q)",
			resp.Status, decodeErrCode(t, resp))
	}
}

func TestPut_InternalEmptyAuthorSkipsCheck(t *testing.T) {
	// The §6.2.1 fallback path dispatches an internal :put under the
	// relay's own authority — Author is empty in that internal context, and
	// PutBy intentionally diverges from caller authorship (it's the relay's
	// placement, not the origin's). The check skips when Author is empty.
	h := newTestHandler(t)
	hctx := newTestContext() // hctx.SessionPeerID = "" (zero value)
	inner := makeInnerEnvelope(t, "x")
	hctx.Included[inner.ContentHash] = inner
	params, _ := types.StoreEntryData{
		Namespace:     tFakeDest,
		PutBy:         tFakeRelay, // relay placing on origin's behalf
		EnvelopeInner: inner.ContentHash,
	}.ToEntity()
	resp, _ := h.Handle(context.Background(), &handler.Request{
		Operation: OpPut, Params: params, Context: hctx,
	})
	if resp.Status != 200 {
		t.Fatalf("internal :put (empty Author) want 200, got %d (code=%q)",
			resp.Status, decodeErrCode(t, resp))
	}
}

func TestPut_DedupByContentHash(t *testing.T) {
	// Same store-entry put twice is idempotent — the second put MUST NOT
	// surface as a new entry on a later poll (otherwise the seq counter
	// double-increments and cross-impl cursor advance drifts).
	h := newTestHandler(t)
	cs, li := sharedStores()
	hctx := newSharedContext(cs, li)
	inner := makeInnerEnvelope(t, "dup-payload")
	hctx.Included[inner.ContentHash] = inner

	se := types.StoreEntryData{
		Namespace:     tFakeDest,
		PutBy:         tFakeRelay,
		EnvelopeInner: inner.ContentHash,
	}
	params, _ := se.ToEntity()
	for i := 0; i < 3; i++ {
		// Reuse the same hctx so the inner envelope stays in Included for
		// every put — production wire wraps each put in its own envelope
		// carrying the same inner, which is what's modeled here.
		resp, _ := h.Handle(context.Background(), &handler.Request{
			Operation: OpPut, Params: params, Context: hctx,
		})
		if resp.Status != 200 {
			t.Fatalf("put #%d: status %d", i, resp.Status)
		}
	}
	// Poll: must see exactly one entry. Shared LocationIndex so the
	// tree-bound entries from put are visible to poll's tree enumeration.
	pollParams, _ := types.PollRequestData{Namespace: tFakeDest}.ToEntity()
	pollResp, _ := h.Handle(context.Background(), &handler.Request{
		Operation: OpPoll, Params: pollParams, Context: newSharedContext(cs, li),
	})
	pr, _ := types.PollResultDataFromEntity(pollResp.Result)
	if len(pr.Entries) != 1 {
		t.Fatalf("dedup failed: want 1 entry across 3 identical puts, got %d", len(pr.Entries))
	}
}

// -----------------------------------------------------------------------
// :poll
// -----------------------------------------------------------------------

func TestPoll_EmptyNamespaceReturnsEmptyNot404(t *testing.T) {
	// §4.2 + landing-pass finding #1: authorized-but-empty MUST be
	// {entries: [], has_more: false} at 200, NOT namespace_not_found/404.
	h := newTestHandler(t)
	hctx := newTestContext()
	params, _ := types.PollRequestData{Namespace: tFakeDest}.ToEntity()
	resp, err := h.Handle(context.Background(), &handler.Request{
		Operation: OpPoll, Params: params, Context: hctx,
	})
	if err != nil {
		t.Fatalf("Handle: %v", err)
	}
	if resp.Status != 200 {
		t.Fatalf("empty namespace must be 200, got %d", resp.Status)
	}
	pr, err := types.PollResultDataFromEntity(resp.Result)
	if err != nil {
		t.Fatalf("decode poll-result: %v", err)
	}
	if len(pr.Entries) != 0 {
		t.Fatalf("Entries: want empty, got %d", len(pr.Entries))
	}
	if pr.HasMore {
		t.Fatal("HasMore: want false on empty namespace")
	}
}

func TestPoll_AdvancesCursor(t *testing.T) {
	h := newTestHandler(t)
	cs, li := sharedStores()
	// Pre-populate three entries.
	hashes := make([]hash.Hash, 3)
	for i := 0; i < 3; i++ {
		hctx := newSharedContext(cs, li)
		inner := makeInnerEnvelope(t, "p"+string(rune('A'+i)))
		hctx.Included[inner.ContentHash] = inner
		se := types.StoreEntryData{
			Namespace:     tFakeDest,
			PutBy:         tFakeRelay,
			EnvelopeInner: inner.ContentHash,
		}
		seEnt, _ := se.ToEntity()
		hashes[i] = seEnt.ContentHash
		params, _ := se.ToEntity()
		resp, _ := h.Handle(context.Background(), &handler.Request{
			Operation: OpPut, Params: params, Context: hctx,
		})
		if resp.Status != 200 {
			t.Fatalf("put #%d failed: %d", i, resp.Status)
		}
	}

	// First poll with limit=2 → entries[0..1], has_more=true.
	params, _ := types.PollRequestData{Namespace: tFakeDest, Limit: 2}.ToEntity()
	resp, _ := h.Handle(context.Background(), &handler.Request{
		Operation: OpPoll, Params: params, Context: newSharedContext(cs, li),
	})
	pr, _ := types.PollResultDataFromEntity(resp.Result)
	if len(pr.Entries) != 2 {
		t.Fatalf("first poll: want 2 entries, got %d", len(pr.Entries))
	}
	if !pr.HasMore {
		t.Fatal("first poll: want HasMore=true")
	}
	if !bytes.Equal(pr.Entries[0].Bytes(), hashes[0].Bytes()) ||
		!bytes.Equal(pr.Entries[1].Bytes(), hashes[1].Bytes()) {
		t.Fatal("first poll: entry order drift")
	}

	// Second poll with the returned cursor → entries[2], has_more=false.
	params2, _ := types.PollRequestData{Namespace: tFakeDest, Since: pr.Cursor, Limit: 2}.ToEntity()
	resp2, _ := h.Handle(context.Background(), &handler.Request{
		Operation: OpPoll, Params: params2, Context: newSharedContext(cs, li),
	})
	pr2, _ := types.PollResultDataFromEntity(resp2.Result)
	if len(pr2.Entries) != 1 {
		t.Fatalf("second poll: want 1 entry, got %d", len(pr2.Entries))
	}
	if pr2.HasMore {
		t.Fatal("second poll: want HasMore=false")
	}
	if !bytes.Equal(pr2.Entries[0].Bytes(), hashes[2].Bytes()) {
		t.Fatal("second poll: tail entry drift")
	}
}

func TestPoll_InvalidCursorRejected(t *testing.T) {
	h := newTestHandler(t)
	params, _ := types.PollRequestData{
		Namespace: tFakeDest,
		Since:     []byte{0x01, 0x02}, // not 8 bytes
	}.ToEntity()
	resp, _ := h.Handle(context.Background(), &handler.Request{
		Operation: OpPoll, Params: params, Context: newTestContext(),
	})
	if resp.Status != 400 {
		t.Fatalf("status: want 400, got %d", resp.Status)
	}
}

func TestPoll_ExpiredEntriesNotSurfaced(t *testing.T) {
	// §8 GC posture: expired entries MUST NOT surface on poll.
	h := NewHandler()
	now := uint64(1_730_000_000_000)
	current := now
	h.SetClock(func() uint64 { return current })
	h.SetupStore(tFakeRelay)

	hctx := newTestContext()
	inner := makeInnerEnvelope(t, "soon-dead")
	hctx.Included[inner.ContentHash] = inner
	se := types.StoreEntryData{
		Namespace:     tFakeDest,
		PutBy:         tFakeRelay,
		ExpiresAt:     now + 1000, // 1 second from now
		EnvelopeInner: inner.ContentHash,
	}
	params, _ := se.ToEntity()
	resp, _ := h.Handle(context.Background(), &handler.Request{
		Operation: OpPut, Params: params, Context: hctx,
	})
	if resp.Status != 200 {
		t.Fatalf("put failed: %d", resp.Status)
	}

	// Advance the clock past expiry.
	current = now + 2000

	pollParams, _ := types.PollRequestData{Namespace: tFakeDest}.ToEntity()
	pollResp, _ := h.Handle(context.Background(), &handler.Request{
		Operation: OpPoll, Params: pollParams, Context: newTestContext(),
	})
	pr, _ := types.PollResultDataFromEntity(pollResp.Result)
	if len(pr.Entries) != 0 {
		t.Fatalf("expired entries surfaced: %d", len(pr.Entries))
	}
}

// -----------------------------------------------------------------------
// :forward (R2 partial gate — TTL + opacity; full dispatch in R3)
// -----------------------------------------------------------------------

func TestForward_TTLExhausted(t *testing.T) {
	h := newTestHandler(t)
	hctx := newTestContext()
	inner := makeInnerEnvelope(t, "x")
	hctx.Included[inner.ContentHash] = inner
	params, _ := types.ForwardRequestData{
		Destination:   tFakeDest,
		NextHop:       tFakeRelay,
		TTLHops:       0,
		EnvelopeInner: inner.ContentHash,
	}.ToEntity()
	resp, _ := h.Handle(context.Background(), &handler.Request{
		Operation: OpForward, Params: params, Context: hctx,
	})
	if resp.Status != 400 || decodeErrCode(t, resp) != types.RelayErrTTLExhausted {
		t.Fatalf("want 400 ttl_exhausted, got %d %q", resp.Status, decodeErrCode(t, resp))
	}
}

func TestForward_NoRoute(t *testing.T) {
	// v1 §13 Q3: explicit next_hop required, else no_route/502.
	h := newTestHandler(t)
	hctx := newTestContext()
	inner := makeInnerEnvelope(t, "x")
	hctx.Included[inner.ContentHash] = inner
	params, _ := types.ForwardRequestData{
		Destination:   tFakeDest,
		TTLHops:       3,
		EnvelopeInner: inner.ContentHash,
	}.ToEntity()
	resp, _ := h.Handle(context.Background(), &handler.Request{
		Operation: OpForward, Params: params, Context: hctx,
	})
	if resp.Status != 502 || decodeErrCode(t, resp) != types.RelayErrNoRoute {
		t.Fatalf("want 502 no_route, got %d %q", resp.Status, decodeErrCode(t, resp))
	}
}

func TestForward_RejectsMissingInner(t *testing.T) {
	h := newTestHandler(t)
	hctx := newTestContext()
	params, _ := types.ForwardRequestData{
		Destination:   tFakeDest,
		NextHop:       tFakeRelay,
		TTLHops:       3,
		EnvelopeInner: relayFakeContentHash(0xCC), // not in included
	}.ToEntity()
	resp, _ := h.Handle(context.Background(), &handler.Request{
		Operation: OpForward, Params: params, Context: hctx,
	})
	if resp.Status != 400 {
		t.Fatalf("status: want 400, got %d", resp.Status)
	}
}

// fakeDispatcher is a tunable OutboundDispatcher for testing the §3.1.1
// routing decisions + §6.2.1 fallback path. Set deliverErr / forwardErr
// to ErrDestinationUnreachable to exercise fallback; nil for happy path.
type fakeDispatcher struct {
	deliverErr error
	forwardErr error

	deliveredTo   string
	deliveredInner entity.Entity
	forwardedTo    string
	forwardedReq   types.ForwardRequestData
	forwardedInner entity.Entity
}

func (f *fakeDispatcher) DeliverInner(ctx context.Context, dest string, inner entity.Entity) (*handler.Response, error) {
	f.deliveredTo = dest
	f.deliveredInner = inner
	if f.deliverErr != nil {
		return nil, f.deliverErr
	}
	return &handler.Response{Status: 200}, nil
}

func (f *fakeDispatcher) ForwardToNextHop(ctx context.Context, next string, req types.ForwardRequestData, inner entity.Entity) (*handler.Response, error) {
	f.forwardedTo = next
	f.forwardedReq = req
	f.forwardedInner = inner
	if f.forwardErr != nil {
		return nil, f.forwardErr
	}
	return &handler.Response{Status: 200}, nil
}

// §3.1.1 terminal hop: next_hop == destination, dispatcher reaches the
// destination, handler dispatches the bare inner envelope and returns
// forwarded. The destination receives byte-identical-to-direct.
func TestForward_TerminalHop_DeliversInnerByteIdentical(t *testing.T) {
	h := newTestHandler(t)
	disp := &fakeDispatcher{}
	h.SetDispatcher(disp)

	hctx := newTestContext()
	inner := makeInnerEnvelope(t, "terminal-payload")
	hctx.Included[inner.ContentHash] = inner

	params, _ := types.ForwardRequestData{
		Destination:   tFakeDest,
		NextHop:       tFakeDest, // terminal — next_hop == destination
		TTLHops:       3,
		EnvelopeInner: inner.ContentHash,
	}.ToEntity()
	resp, _ := h.Handle(context.Background(), &handler.Request{
		Operation: OpForward, Params: params, Context: hctx,
	})
	if resp.Status != 200 {
		t.Fatalf("status: want 200, got %d (code=%q)", resp.Status, decodeErrCode(t, resp))
	}
	fr, _ := types.ForwardResultDataFromEntity(resp.Result)
	if fr.Status != types.ForwardStatusForwarded {
		t.Fatalf("status: want %q, got %q", types.ForwardStatusForwarded, fr.Status)
	}
	if disp.deliveredTo != tFakeDest {
		t.Fatalf("deliveredTo: want %q, got %q", tFakeDest, disp.deliveredTo)
	}
	// §9 envelope opacity: byte-identical. We compare the entity surface
	// (Type, Data, ContentHash) — not just the hash — to guard against an
	// impl that recomputes the hash but mangled the bytes.
	if disp.deliveredInner.ContentHash != inner.ContentHash {
		t.Fatal("delivered inner hash drift (§9 opacity broken)")
	}
	if !bytes.Equal(disp.deliveredInner.Data, inner.Data) {
		t.Fatal("delivered inner BYTES drift — §9 byte-identical-to-direct broken")
	}
	if disp.deliveredInner.Type != inner.Type {
		t.Fatal("delivered inner Type drift")
	}
}

// §3.1.1 intermediate hop: next_hop != destination, dispatcher forwards a
// (TTL-decremented) forward-request to next_hop relay. The inner stays
// byte-identical end-to-end.
func TestForward_IntermediateHop_DecrementsTTL(t *testing.T) {
	h := newTestHandler(t)
	disp := &fakeDispatcher{}
	h.SetDispatcher(disp)

	hctx := newTestContext()
	inner := makeInnerEnvelope(t, "intermediate-payload")
	hctx.Included[inner.ContentHash] = inner

	params, _ := types.ForwardRequestData{
		Destination:   tFakeDest,
		NextHop:       tFakeRelay, // intermediate — next_hop != destination
		TTLHops:       5,
		EnvelopeInner: inner.ContentHash,
	}.ToEntity()
	resp, _ := h.Handle(context.Background(), &handler.Request{
		Operation: OpForward, Params: params, Context: hctx,
	})
	if resp.Status != 200 {
		t.Fatalf("status: want 200, got %d (code=%q)", resp.Status, decodeErrCode(t, resp))
	}
	if disp.forwardedTo != tFakeRelay {
		t.Fatalf("forwardedTo: want %q, got %q", tFakeRelay, disp.forwardedTo)
	}
	// TTL decremented before forward.
	if disp.forwardedReq.TTLHops != 4 {
		t.Fatalf("TTLHops on forwarded req: want 4 (5-1), got %d", disp.forwardedReq.TTLHops)
	}
	// Destination + envelope_inner preserved.
	if disp.forwardedReq.Destination != tFakeDest {
		t.Fatalf("Destination drift: %q", disp.forwardedReq.Destination)
	}
	if disp.forwardedReq.EnvelopeInner != inner.ContentHash {
		t.Fatal("EnvelopeInner drift in forwarded req")
	}
	// Inner envelope identity preserved.
	if !bytes.Equal(disp.forwardedInner.Data, inner.Data) {
		t.Fatal("forwarded inner bytes drift")
	}
}

// bindRoute persists a route entity and binds it under the local route
// subtree at RoutePath(hash). Used by the table-read resolver tests to
// hand-populate the table (EXTENSION-ROUTE producers are deferred per the
// proposal §4 design-space framing — tests fill the table directly).
//
// Binds at the relative path types.RoutePath(hash) so the raw
// MemoryLocationIndex test fixture (no NamespacedIndex canonicalization)
// surfaces the entry under types.RoutePrefix during List. Production
// peers wire a NamespacedIndex, which canonicalizes both sides
// transparently.
func bindRoute(t *testing.T, hctx *handler.HandlerContext, rd types.RouteData) types.RouteData {
	t.Helper()
	ent, err := rd.ToEntity()
	if err != nil {
		t.Fatalf("RouteData.ToEntity: %v", err)
	}
	if _, err := hctx.Store.Put(ent); err != nil {
		t.Fatalf("Store.Put route: %v", err)
	}
	rel := types.RoutePath(ent.ContentHash)
	if err := hctx.LocationIndex.Set(rel, ent.ContentHash); err != nil {
		t.Fatalf("LocationIndex.Set %s: %v", rel, err)
	}
	return rd
}

// TestResolveFromTable_ExactForward_NamespacedIndex reproduces the
// production wiring: the relay handler receives a hctx with a
// NamespacedIndex; route entities bound via the standard tree:put
// canonicalize via the namespace prefix. The resolver MUST find them
// via List even under canonicalization. If this test FAILs but the
// raw-MemoryLocationIndex sibling passes, it means resolveFromTable's
// List/Get pair doesn't compose cleanly with NamespacedIndex.
func TestResolveFromTable_ExactForward_NamespacedIndex(t *testing.T) {
	h := newTestHandler(t)
	disp := &fakeDispatcher{}
	h.SetDispatcher(disp)

	// Wire a NamespacedIndex around the raw memory index so the test
	// mirrors how a real peer's tree-binding canonicalizes.
	raw := store.NewMemoryLocationIndex()
	nsIdx := store.NewNamespacedIndex(raw, tFakeRelay)
	cs := store.NewMemoryContentStore()
	hctx := &handler.HandlerContext{
		Store:          cs,
		LocationIndex:  nsIdx,
		HandlerPattern: HandlerPattern,
		RequestID:      "test-ns",
		Included:       make(map[hash.Hash]entity.Entity),
	}
	inner := makeInnerEnvelope(t, "ns-exact-forward")
	hctx.Included[inner.ContentHash] = inner

	// Tree-style binding — relative path through the NamespacedIndex,
	// which canonicalizes to /{tFakeRelay}/system/route/{hex}.
	rd := types.RouteData{
		Match: tFakeDest, Action: types.RouteActionForward, Via: tFakeSender,
	}
	ent, _ := rd.ToEntity()
	if _, err := cs.Put(ent); err != nil {
		t.Fatalf("Store.Put: %v", err)
	}
	if err := nsIdx.Set(types.RoutePath(ent.ContentHash), ent.ContentHash); err != nil {
		t.Fatalf("NamespacedIndex.Set: %v", err)
	}

	params, _ := types.ForwardRequestData{
		Destination:   tFakeDest,
		TTLHops:       4,
		EnvelopeInner: inner.ContentHash,
	}.ToEntity()
	resp, _ := h.Handle(context.Background(), &handler.Request{
		Operation: OpForward, Params: params, Context: hctx,
	})
	if resp.Status != 200 {
		t.Fatalf("status: want 200 (NamespacedIndex List/Set composes), got %d (code=%q)",
			resp.Status, decodeErrCode(t, resp))
	}
	if disp.forwardedTo != tFakeSender {
		t.Fatalf("forwardedTo: want %q, got %q", tFakeSender, disp.forwardedTo)
	}
}

// EXTENSION-ROUTE §3 — exact-match `forward` route resolves next-hop = Via.
// Routes hand-populated (the v1 deferral: producers are out of scope; tests
// configure the table directly).
func TestResolveFromTable_ExactForwardRoute(t *testing.T) {
	h := newTestHandler(t)
	disp := &fakeDispatcher{}
	h.SetDispatcher(disp)
	hctx := newTestContext()
	inner := makeInnerEnvelope(t, "table-exact-forward")
	hctx.Included[inner.ContentHash] = inner

	// Exact route: dest tFakeDest → forward via tFakeRelay.
	bindRoute(t, hctx, types.RouteData{
		Match:  tFakeDest,
		Action: types.RouteActionForward,
		Via:    tFakeSender, // pretend tFakeSender is the next-hop relay
	})

	// No Route, no NextHop — handler MUST consult the table.
	params, _ := types.ForwardRequestData{
		Destination:   tFakeDest,
		TTLHops:       4,
		EnvelopeInner: inner.ContentHash,
	}.ToEntity()
	resp, _ := h.Handle(context.Background(), &handler.Request{
		Operation: OpForward, Params: params, Context: hctx,
	})
	if resp.Status != 200 {
		t.Fatalf("status: want 200 (table hit → forward), got %d (code=%q)", resp.Status, decodeErrCode(t, resp))
	}
	if disp.forwardedTo != tFakeSender {
		t.Fatalf("forwardedTo: want %q (table route's Via), got %q", tFakeSender, disp.forwardedTo)
	}
	if disp.forwardedReq.TTLHops != 3 {
		t.Fatalf("TTLHops: want 3 (4-1), got %d", disp.forwardedReq.TTLHops)
	}
}

// EXTENSION-ROUTE §3 — `*` default route resolves when no exact match.
func TestResolveFromTable_DefaultRoute(t *testing.T) {
	h := newTestHandler(t)
	disp := &fakeDispatcher{}
	h.SetDispatcher(disp)
	hctx := newTestContext()
	inner := makeInnerEnvelope(t, "table-default-route")
	hctx.Included[inner.ContentHash] = inner

	bindRoute(t, hctx, types.RouteData{
		Match:  types.RouteMatchDefault, // "*"
		Action: types.RouteActionForward,
		Via:    tFakeSender,
	})
	params, _ := types.ForwardRequestData{
		Destination:   tFakeDest,
		TTLHops:       4,
		EnvelopeInner: inner.ContentHash,
	}.ToEntity()
	resp, _ := h.Handle(context.Background(), &handler.Request{
		Operation: OpForward, Params: params, Context: hctx,
	})
	if resp.Status != 200 {
		t.Fatalf("status: want 200 (default route hit), got %d (code=%q)", resp.Status, decodeErrCode(t, resp))
	}
	if disp.forwardedTo != tFakeSender {
		t.Fatalf("forwardedTo: want %q (default route's Via), got %q", tFakeSender, disp.forwardedTo)
	}
}

// EXTENSION-ROUTE §3 — exact match outranks default on the table read.
func TestResolveFromTable_ExactBeatsDefault(t *testing.T) {
	h := newTestHandler(t)
	disp := &fakeDispatcher{}
	h.SetDispatcher(disp)
	hctx := newTestContext()
	inner := makeInnerEnvelope(t, "table-exact-beats-default")
	hctx.Included[inner.ContentHash] = inner

	// Default route to tFakeRelay; exact route for tFakeDest to tFakeSender.
	bindRoute(t, hctx, types.RouteData{
		Match: types.RouteMatchDefault, Action: types.RouteActionForward, Via: tFakeRelay,
	})
	bindRoute(t, hctx, types.RouteData{
		Match: tFakeDest, Action: types.RouteActionForward, Via: tFakeSender,
	})
	params, _ := types.ForwardRequestData{
		Destination:   tFakeDest,
		TTLHops:       4,
		EnvelopeInner: inner.ContentHash,
	}.ToEntity()
	resp, _ := h.Handle(context.Background(), &handler.Request{
		Operation: OpForward, Params: params, Context: hctx,
	})
	if resp.Status != 200 {
		t.Fatalf("status: %d (code=%q)", resp.Status, decodeErrCode(t, resp))
	}
	if disp.forwardedTo != tFakeSender {
		t.Fatalf("forwardedTo: want %q (exact match wins over `*`), got %q", tFakeSender, disp.forwardedTo)
	}
}

// EXTENSION-ROUTE §3 — lower metric wins on tie (within exact-match cohort).
func TestResolveFromTable_LowestMetricWins(t *testing.T) {
	h := newTestHandler(t)
	disp := &fakeDispatcher{}
	h.SetDispatcher(disp)
	hctx := newTestContext()
	inner := makeInnerEnvelope(t, "table-lowest-metric")
	hctx.Included[inner.ContentHash] = inner

	bindRoute(t, hctx, types.RouteData{
		Match: tFakeDest, Action: types.RouteActionForward, Via: tFakeRelay, Metric: 20,
	})
	bindRoute(t, hctx, types.RouteData{
		Match: tFakeDest, Action: types.RouteActionForward, Via: tFakeSender, Metric: 5,
	})
	params, _ := types.ForwardRequestData{
		Destination:   tFakeDest,
		TTLHops:       4,
		EnvelopeInner: inner.ContentHash,
	}.ToEntity()
	resp, _ := h.Handle(context.Background(), &handler.Request{
		Operation: OpForward, Params: params, Context: hctx,
	})
	if resp.Status != 200 {
		t.Fatalf("status: %d (code=%q)", resp.Status, decodeErrCode(t, resp))
	}
	if disp.forwardedTo != tFakeSender {
		t.Fatalf("forwardedTo: want %q (Metric=5 < 20), got %q", tFakeSender, disp.forwardedTo)
	}
}

// EXTENSION-ROUTE §3 — expired routes are silently skipped (filtered before
// match), not surfaced as match-with-bad-action.
func TestResolveFromTable_ExpiredSkipped(t *testing.T) {
	h := newTestHandler(t)
	disp := &fakeDispatcher{}
	h.SetDispatcher(disp)
	hctx := newTestContext()
	inner := makeInnerEnvelope(t, "table-expired-skipped")
	hctx.Included[inner.ContentHash] = inner

	// h's clock = 1_730_000_000_000. Use an ExpiresAt strictly before that.
	bindRoute(t, hctx, types.RouteData{
		Match: tFakeDest, Action: types.RouteActionForward, Via: tFakeRelay,
		ExpiresAt: 1_000_000_000_000, // long expired
	})
	params, _ := types.ForwardRequestData{
		Destination:   tFakeDest,
		TTLHops:       4,
		EnvelopeInner: inner.ContentHash,
	}.ToEntity()
	resp, _ := h.Handle(context.Background(), &handler.Request{
		Operation: OpForward, Params: params, Context: hctx,
	})
	if resp.Status != 502 {
		t.Fatalf("status: want 502 (no usable route after expiry filter), got %d (code=%q)", resp.Status, decodeErrCode(t, resp))
	}
	if decodeErrCode(t, resp) != types.RelayErrNoRoute {
		t.Fatalf("code: want %q, got %q", types.RelayErrNoRoute, decodeErrCode(t, resp))
	}
	if disp.forwardedTo != "" {
		t.Fatal("expired route MUST NOT reach dispatcher")
	}
}

// EXTENSION-ROUTE §3 — `action: deliver` route → terminal hop at this relay.
func TestResolveFromTable_DeliverAction(t *testing.T) {
	h := newTestHandler(t)
	disp := &fakeDispatcher{}
	h.SetDispatcher(disp)
	hctx := newTestContext()
	inner := makeInnerEnvelope(t, "table-deliver-action")
	hctx.Included[inner.ContentHash] = inner

	bindRoute(t, hctx, types.RouteData{
		Match:  tFakeDest,
		Action: types.RouteActionDeliver,
	})
	params, _ := types.ForwardRequestData{
		Destination:   tFakeDest,
		TTLHops:       4,
		EnvelopeInner: inner.ContentHash,
	}.ToEntity()
	resp, _ := h.Handle(context.Background(), &handler.Request{
		Operation: OpForward, Params: params, Context: hctx,
	})
	if resp.Status != 200 {
		t.Fatalf("status: want 200, got %d (code=%q)", resp.Status, decodeErrCode(t, resp))
	}
	if disp.deliveredTo != tFakeDest {
		t.Fatalf("deliveredTo: want %q (action=deliver → terminal), got %q", tFakeDest, disp.deliveredTo)
	}
	if disp.forwardedTo != "" {
		t.Fatalf("forwardedTo unexpectedly populated (%q) on deliver action — terminal hop must not forward", disp.forwardedTo)
	}
}

// EXTENSION-ROUTE §7 ROUTE-ABSENT-TABLE-1 — no routes published → falls
// through to no_route/502 (trivial direct-or-no_route default).
func TestResolveFromTable_AbsentTableFallsThrough(t *testing.T) {
	h := newTestHandler(t)
	disp := &fakeDispatcher{}
	h.SetDispatcher(disp)
	hctx := newTestContext()
	inner := makeInnerEnvelope(t, "table-absent")
	hctx.Included[inner.ContentHash] = inner

	// No bindRoute calls — table is empty.
	params, _ := types.ForwardRequestData{
		Destination:   tFakeDest,
		TTLHops:       4,
		EnvelopeInner: inner.ContentHash,
	}.ToEntity()
	resp, _ := h.Handle(context.Background(), &handler.Request{
		Operation: OpForward, Params: params, Context: hctx,
	})
	if resp.Status != 502 {
		t.Fatalf("status: want 502 (no route in empty table), got %d", resp.Status)
	}
	if decodeErrCode(t, resp) != types.RelayErrNoRoute {
		t.Fatalf("code: want %q, got %q", types.RelayErrNoRoute, decodeErrCode(t, resp))
	}
}

// PROPOSAL §3 PRECEDENCE GATE — explicit source route MUST win over the
// table even when a matching table entry exists. Ensures the resolver
// doesn't override the originator's path.
func TestResolveFromTable_SourceRoutePrecedence(t *testing.T) {
	h := newTestHandler(t)
	disp := &fakeDispatcher{}
	h.SetDispatcher(disp)
	hctx := newTestContext()
	inner := makeInnerEnvelope(t, "table-precedence")
	hctx.Included[inner.ContentHash] = inner

	// Table says: forward to tFakeRelay for tFakeDest.
	bindRoute(t, hctx, types.RouteData{
		Match: tFakeDest, Action: types.RouteActionForward, Via: tFakeRelay,
	})
	// Source route says: go via tFakeSender first.
	params, _ := types.ForwardRequestData{
		Destination:   tFakeDest,
		Route:         []string{tFakeSender, tFakeDest},
		NextHop:       tFakeSender,
		TTLHops:       4,
		EnvelopeInner: inner.ContentHash,
	}.ToEntity()
	resp, _ := h.Handle(context.Background(), &handler.Request{
		Operation: OpForward, Params: params, Context: hctx,
	})
	if resp.Status != 200 {
		t.Fatalf("status: %d (code=%q)", resp.Status, decodeErrCode(t, resp))
	}
	// Source route's first hop wins, NOT the table entry.
	if disp.forwardedTo != tFakeSender {
		t.Fatalf("forwardedTo: want %q (source route wins over table), got %q",
			tFakeSender, disp.forwardedTo)
	}
}

// PROPOSAL-RELAY-SOURCE-ROUTED-MULTIHOP §2.2 — intermediate hop with a
// source route: a relay at the head of `route` pops the head, forwards
// `route[1:]` with ttl-1 to the popped peer. The destination + inner
// stay byte-identical through the hop.
func TestForward_SourceRouteIntermediateHop_PopsHead(t *testing.T) {
	h := newTestHandler(t)
	disp := &fakeDispatcher{}
	h.SetDispatcher(disp)

	hctx := newTestContext()
	inner := makeInnerEnvelope(t, "src-route-intermediate")
	hctx.Included[inner.ContentHash] = inner

	// route = [tFakeRelay, tFakeDest]; first hop is tFakeRelay; remaining = [tFakeDest].
	params, _ := types.ForwardRequestData{
		Destination:   tFakeDest,
		Route:         []string{tFakeRelay, tFakeDest},
		NextHop:       tFakeRelay, // must equal Route[0] per §2.1
		TTLHops:       8,
		EnvelopeInner: inner.ContentHash,
	}.ToEntity()
	resp, _ := h.Handle(context.Background(), &handler.Request{
		Operation: OpForward, Params: params, Context: hctx,
	})
	if resp.Status != 200 {
		t.Fatalf("status: want 200, got %d (code=%q)", resp.Status, decodeErrCode(t, resp))
	}
	if disp.forwardedTo != tFakeRelay {
		t.Fatalf("forwardedTo: want %q, got %q", tFakeRelay, disp.forwardedTo)
	}
	// Route popped: [tFakeDest].
	if len(disp.forwardedReq.Route) != 1 || disp.forwardedReq.Route[0] != tFakeDest {
		t.Fatalf("Route on forwarded req: want [%q], got %v", tFakeDest, disp.forwardedReq.Route)
	}
	// NextHop updated to head of remaining route (so single-hop receivers can also read it).
	if disp.forwardedReq.NextHop != tFakeDest {
		t.Fatalf("NextHop on forwarded req: want %q (head of remaining), got %q", tFakeDest, disp.forwardedReq.NextHop)
	}
	// TTL decremented.
	if disp.forwardedReq.TTLHops != 7 {
		t.Fatalf("TTLHops: want 7 (8-1), got %d", disp.forwardedReq.TTLHops)
	}
	if disp.forwardedReq.Destination != tFakeDest {
		t.Fatalf("Destination drift: %q", disp.forwardedReq.Destination)
	}
	// §9 envelope opacity: inner bytes byte-identical across the hop.
	if !bytes.Equal(disp.forwardedInner.Data, inner.Data) {
		t.Fatal("forwarded inner bytes drift (§9 opacity broken across source-route hop)")
	}
}

// SRCROUTE-TERMINAL-EQUIV — route:[D] (single-element) behaves identically
// to next_hop:D (proposal §4 case 3).
func TestForward_SourceRouteSingleElement_Terminal(t *testing.T) {
	h := newTestHandler(t)
	disp := &fakeDispatcher{}
	h.SetDispatcher(disp)

	hctx := newTestContext()
	inner := makeInnerEnvelope(t, "src-route-terminal-equiv")
	hctx.Included[inner.ContentHash] = inner

	params, _ := types.ForwardRequestData{
		Destination:   tFakeDest,
		Route:         []string{tFakeDest}, // single-element route → terminal
		// NextHop intentionally empty — Route alone is sufficient.
		TTLHops:       2,
		EnvelopeInner: inner.ContentHash,
	}.ToEntity()
	resp, _ := h.Handle(context.Background(), &handler.Request{
		Operation: OpForward, Params: params, Context: hctx,
	})
	if resp.Status != 200 {
		t.Fatalf("status: want 200, got %d (code=%q)", resp.Status, decodeErrCode(t, resp))
	}
	fr, _ := types.ForwardResultDataFromEntity(resp.Result)
	if fr.Status != types.ForwardStatusForwarded {
		t.Fatalf("status: want %q, got %q", types.ForwardStatusForwarded, fr.Status)
	}
	if disp.deliveredTo != tFakeDest {
		t.Fatalf("deliveredTo: want %q (terminal hop), got %q", tFakeDest, disp.deliveredTo)
	}
	// Must NOT have forwarded to a next relay.
	if disp.forwardedTo != "" {
		t.Fatalf("unexpected ForwardToNextHop call to %q on single-element route", disp.forwardedTo)
	}
}

// SRCROUTE-CONSISTENCY — Route[0] + NextHop both set, but disagree:
// invalid_request/400 per proposal §2.1 cross-field invariant.
func TestForward_SourceRouteNextHopMismatch_Rejects(t *testing.T) {
	h := newTestHandler(t)
	disp := &fakeDispatcher{}
	h.SetDispatcher(disp)

	hctx := newTestContext()
	inner := makeInnerEnvelope(t, "src-route-mismatch")
	hctx.Included[inner.ContentHash] = inner

	params, _ := types.ForwardRequestData{
		Destination:   tFakeDest,
		Route:         []string{tFakeRelay, tFakeDest},
		NextHop:       tFakeSender, // does NOT equal Route[0] — invariant violation
		TTLHops:       8,
		EnvelopeInner: inner.ContentHash,
	}.ToEntity()
	resp, _ := h.Handle(context.Background(), &handler.Request{
		Operation: OpForward, Params: params, Context: hctx,
	})
	if resp.Status != 400 {
		t.Fatalf("status: want 400, got %d", resp.Status)
	}
	if decodeErrCode(t, resp) != "invalid_request" {
		t.Fatalf("code: want invalid_request, got %q", decodeErrCode(t, resp))
	}
	// MUST NOT have called dispatcher at all.
	if disp.forwardedTo != "" || disp.deliveredTo != "" {
		t.Fatal("rejected request still reached dispatcher (cross-field invariant must fire pre-dispatch)")
	}
}

// SRCROUTE-TTL-EXHAUST — route longer than ttl_hops causes ttl_exhausted at
// the hop where TTL hits 0; no partial/silent delivery (proposal §4 case 4).
func TestForward_SourceRouteTTLExhaust(t *testing.T) {
	h := newTestHandler(t)
	disp := &fakeDispatcher{}
	h.SetDispatcher(disp)

	hctx := newTestContext()
	inner := makeInnerEnvelope(t, "src-route-ttl-exhaust")
	hctx.Included[inner.ContentHash] = inner

	// route length 3, ttl_hops = 1 — first hop decrements to 0, the second
	// hop receives ttl=0 and fails ttl_exhausted/400. To exercise the
	// receive-side gate directly, send ttl_hops=0 in the inbound (TTL
	// already exhausted on arrival per §3.1).
	params, _ := types.ForwardRequestData{
		Destination:   tFakeDest,
		Route:         []string{tFakeRelay, tFakeSender, tFakeDest},
		NextHop:       tFakeRelay,
		TTLHops:       0,
		EnvelopeInner: inner.ContentHash,
	}.ToEntity()
	resp, _ := h.Handle(context.Background(), &handler.Request{
		Operation: OpForward, Params: params, Context: hctx,
	})
	if resp.Status != 400 {
		t.Fatalf("status: want 400, got %d", resp.Status)
	}
	if decodeErrCode(t, resp) != types.RelayErrTTLExhausted {
		t.Fatalf("code: want %q, got %q", types.RelayErrTTLExhausted, decodeErrCode(t, resp))
	}
}

// §6.2.1 fallback path: terminal hop, destination unreachable, relay
// stores the inner envelope at namespace = destination peer_id under its
// own authority. PutBy on the fallback entry = the relay (NOT the original
// caller — §6.2.1 + §3.2 distinction).
func TestForward_TerminalUnreachable_QueuesFallback(t *testing.T) {
	h := newTestHandler(t)
	disp := &fakeDispatcher{deliverErr: ErrDestinationUnreachable}
	h.SetDispatcher(disp)

	hctx := newTestContext()
	inner := makeInnerEnvelope(t, "fallback-payload")
	hctx.Included[inner.ContentHash] = inner

	params, _ := types.ForwardRequestData{
		Destination:   tFakeDest,
		NextHop:       tFakeDest,
		TTLHops:       3,
		EnvelopeInner: inner.ContentHash,
	}.ToEntity()
	resp, _ := h.Handle(context.Background(), &handler.Request{
		Operation: OpForward, Params: params, Context: hctx,
	})
	if resp.Status != 200 {
		t.Fatalf("status: want 200 (queued-fallback is success), got %d", resp.Status)
	}
	fr, _ := types.ForwardResultDataFromEntity(resp.Result)
	if fr.Status != types.ForwardStatusQueuedFallback {
		t.Fatalf("status: want %q, got %q", types.ForwardStatusQueuedFallback, fr.Status)
	}
	// §4.2 + §6.2.1 (Rust R6 catch): forward-result.stored_at is the bare
	// NAMESPACE (= destination peer_id), NOT the full store path. The
	// destination uses this as the :poll namespace argument; the specific
	// entry hash is discovered via poll cursor advance.
	if fr.StoredAt != tFakeDest {
		t.Fatalf("StoredAt %q: want bare namespace %q (§4.2 spec comment 'namespace, if queued-fallback')", fr.StoredAt, tFakeDest)
	}
}

// The fallback entry is pollable by the destination: it lands at
// namespace=destination peer_id with the same inner envelope, and the
// destination's :poll surfaces it.
func TestForward_FallbackQueuedEntry_PolledByDestination(t *testing.T) {
	h := newTestHandler(t)
	h.SetDispatcher(&fakeDispatcher{deliverErr: ErrDestinationUnreachable})

	// Forward fails over → fallback. Shared peer-level state across the
	// forward + poll requests (production wire pattern).
	cs, li := sharedStores()
	hctx := newSharedContext(cs, li)
	inner := makeInnerEnvelope(t, "queued-payload")
	hctx.Included[inner.ContentHash] = inner

	params, _ := types.ForwardRequestData{
		Destination:   tFakeDest,
		NextHop:       tFakeDest,
		TTLHops:       3,
		EnvelopeInner: inner.ContentHash,
	}.ToEntity()
	if resp, _ := h.Handle(context.Background(), &handler.Request{
		Operation: OpForward, Params: params, Context: hctx,
	}); resp.Status != 200 {
		t.Fatalf("forward setup: %d", resp.Status)
	}

	// Destination polls its own namespace → sees the fallback entry.
	pollParams, _ := types.PollRequestData{Namespace: tFakeDest}.ToEntity()
	pollResp, _ := h.Handle(context.Background(), &handler.Request{
		Operation: OpPoll, Params: pollParams, Context: newSharedContext(cs, li),
	})
	pr, _ := types.PollResultDataFromEntity(pollResp.Result)
	if len(pr.Entries) != 1 {
		t.Fatalf("destination poll: want 1 entry, got %d", len(pr.Entries))
	}
	// And the entry resolves to the same byte-identical inner envelope.
	_, gotInner, ok := h.EntryByHash(tFakeDest, pr.Entries[0])
	if !ok {
		t.Fatal("EntryByHash: fallback entry not resolvable")
	}
	if gotInner.ContentHash != inner.ContentHash {
		t.Fatal("fallback inner hash drift")
	}
	if !bytes.Equal(gotInner.Data, inner.Data) {
		t.Fatal("fallback inner BYTES drift — §9 broken end-to-end across fallback")
	}
	// PutBy on the fallback entry == the relay's local peer-id (NOT the
	// caller — §6.2.1 + §3.2 distinction).
	entryEnt, _, _ := h.EntryByHash(tFakeDest, pr.Entries[0])
	se, _ := types.StoreEntryDataFromEntity(entryEnt)
	if se.PutBy != tFakeRelay {
		t.Fatalf("fallback PutBy: want relay %q, got %q", tFakeRelay, se.PutBy)
	}
}

// §6.2.1 fallback also fires on intermediate-hop unreachable next_hop.
// The spec doesn't distinguish hop-kind — fallback rendezvous stays at
// destination peer_id.
func TestForward_IntermediateUnreachable_QueuesFallback(t *testing.T) {
	h := newTestHandler(t)
	h.SetDispatcher(&fakeDispatcher{forwardErr: ErrDestinationUnreachable})

	hctx := newTestContext()
	inner := makeInnerEnvelope(t, "x")
	hctx.Included[inner.ContentHash] = inner
	params, _ := types.ForwardRequestData{
		Destination:   tFakeDest,
		NextHop:       tFakeRelay, // intermediate
		TTLHops:       3,
		EnvelopeInner: inner.ContentHash,
	}.ToEntity()
	resp, _ := h.Handle(context.Background(), &handler.Request{
		Operation: OpForward, Params: params, Context: hctx,
	})
	if resp.Status != 200 {
		t.Fatalf("status: want 200, got %d", resp.Status)
	}
	fr, _ := types.ForwardResultDataFromEntity(resp.Result)
	if fr.Status != types.ForwardStatusQueuedFallback {
		t.Fatalf("intermediate-unreachable: want queued-fallback, got %q", fr.Status)
	}
	// Rendezvous = destination peer_id namespace (NOT next_hop's, NOT a
	// full path). Bare namespace per §4.2 (Rust R6 catch).
	if fr.StoredAt != tFakeDest {
		t.Fatalf("StoredAt %q intermediate-fallback rendezvous wrong: want bare namespace %q", fr.StoredAt, tFakeDest)
	}
}

// Default (no-dispatcher) handler exercises the §6.2.1 path naturally.
// This is the conservative posture documented on NewHandler — every
// :forward without an explicit SetDispatcher goes straight to fallback.
func TestForward_NoDispatcherDefaultsToFallback(t *testing.T) {
	h := newTestHandler(t) // never calls SetDispatcher
	hctx := newTestContext()
	inner := makeInnerEnvelope(t, "x")
	hctx.Included[inner.ContentHash] = inner
	params, _ := types.ForwardRequestData{
		Destination:   tFakeDest,
		NextHop:       tFakeDest,
		TTLHops:       3,
		EnvelopeInner: inner.ContentHash,
	}.ToEntity()
	resp, _ := h.Handle(context.Background(), &handler.Request{
		Operation: OpForward, Params: params, Context: hctx,
	})
	fr, _ := types.ForwardResultDataFromEntity(resp.Result)
	if fr.Status != types.ForwardStatusQueuedFallback {
		t.Fatalf("default-dispatcher: want queued-fallback, got %q", fr.Status)
	}
}

// -----------------------------------------------------------------------
// §3.5 inbox-relay resolution + §6.2.1 fallback paths
// -----------------------------------------------------------------------

// fakeInboxResolver returns a pre-canned declaration for a target peer.
type fakeInboxResolver struct {
	declarations map[string]types.InboxRelayData
}

func (f *fakeInboxResolver) Resolve(dest string) (types.InboxRelayData, bool) {
	d, ok := f.declarations[dest]
	return d, ok
}

// §3.5 + §6.2.1: when the destination's declared inbox-relay names US as
// the holder, the fallback honors the declaration's namespace.
func TestForward_FallbackHonorsDeclaration(t *testing.T) {
	h := newTestHandler(t)
	h.SetDispatcher(&fakeDispatcher{deliverErr: ErrDestinationUnreachable})
	// Destination declares THIS relay (tFakeRelay) as the inbox-relay holder,
	// with a custom namespace.
	declaredNamespace := "custom-inbox"
	h.SetInboxRelayResolver(&fakeInboxResolver{
		declarations: map[string]types.InboxRelayData{
			tFakeDest: {
				Relays: []types.InboxRelayEntry{
					{Relay: tFakeRelay, Namespace: declaredNamespace, Priority: 10},
				},
			},
		},
	})

	hctx := newTestContext()
	inner := makeInnerEnvelope(t, "x")
	hctx.Included[inner.ContentHash] = inner
	params, _ := types.ForwardRequestData{
		Destination:   tFakeDest,
		NextHop:       tFakeDest,
		TTLHops:       3,
		EnvelopeInner: inner.ContentHash,
	}.ToEntity()
	resp, _ := h.Handle(context.Background(), &handler.Request{
		Operation: OpForward, Params: params, Context: hctx,
	})
	if resp.Status != 200 {
		t.Fatalf("status: want 200, got %d (code=%q)", resp.Status, decodeErrCode(t, resp))
	}
	fr, _ := types.ForwardResultDataFromEntity(resp.Result)
	if fr.StoredAt != declaredNamespace {
		t.Fatalf("StoredAt: want declared namespace %q, got %q", declaredNamespace, fr.StoredAt)
	}
}

// Default convention applies when no declaration is found.
func TestForward_FallbackDefaultConventionNoDeclaration(t *testing.T) {
	h := newTestHandler(t)
	h.SetDispatcher(&fakeDispatcher{deliverErr: ErrDestinationUnreachable})
	// No resolver injected → NopInboxRelayResolver default.

	hctx := newTestContext()
	inner := makeInnerEnvelope(t, "x")
	hctx.Included[inner.ContentHash] = inner
	params, _ := types.ForwardRequestData{
		Destination:   tFakeDest,
		NextHop:       tFakeDest,
		TTLHops:       3,
		EnvelopeInner: inner.ContentHash,
	}.ToEntity()
	resp, _ := h.Handle(context.Background(), &handler.Request{
		Operation: OpForward, Params: params, Context: hctx,
	})
	if resp.Status != 200 {
		t.Fatalf("status: want 200, got %d", resp.Status)
	}
	fr, _ := types.ForwardResultDataFromEntity(resp.Result)
	// Default convention: namespace == destination peer_id.
	if fr.StoredAt != tFakeDest {
		t.Fatalf("StoredAt: want default %q, got %q", tFakeDest, fr.StoredAt)
	}
}

// §3.5 + §4.3: no_inbox_relay/502 when destination has no declaration AND
// default convention is disabled. Never a silent drop.
func TestForward_NoInboxRelay(t *testing.T) {
	h := newTestHandler(t)
	h.SetDispatcher(&fakeDispatcher{deliverErr: ErrDestinationUnreachable})
	h.SetDisableDefaultFallback(true) // "MX-required" posture

	hctx := newTestContext()
	inner := makeInnerEnvelope(t, "x")
	hctx.Included[inner.ContentHash] = inner
	params, _ := types.ForwardRequestData{
		Destination:   tFakeDest,
		NextHop:       tFakeDest,
		TTLHops:       3,
		EnvelopeInner: inner.ContentHash,
	}.ToEntity()
	resp, _ := h.Handle(context.Background(), &handler.Request{
		Operation: OpForward, Params: params, Context: hctx,
	})
	if resp.Status != 502 {
		t.Fatalf("status: want 502, got %d", resp.Status)
	}
	if code := decodeErrCode(t, resp); code != types.RelayErrNoInboxRelay {
		t.Fatalf("code: want %q, got %q", types.RelayErrNoInboxRelay, code)
	}
}

// §3.5: when the declaration targets a DIFFERENT relay (not us) and
// default convention is on, we fall through to default convention
// (cross-relay store is v1-deferred; OutboundDispatcher seam isn't wired
// to relay-to-relay :put yet).
func TestForward_FallbackDeclarationTargetsOtherRelay(t *testing.T) {
	h := newTestHandler(t)
	h.SetDispatcher(&fakeDispatcher{deliverErr: ErrDestinationUnreachable})
	otherRelay := "2KOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOO"
	h.SetInboxRelayResolver(&fakeInboxResolver{
		declarations: map[string]types.InboxRelayData{
			tFakeDest: {
				Relays: []types.InboxRelayEntry{
					{Relay: otherRelay, Namespace: tFakeDest, Priority: 10}, // not us
				},
			},
		},
	})

	hctx := newTestContext()
	inner := makeInnerEnvelope(t, "x")
	hctx.Included[inner.ContentHash] = inner
	params, _ := types.ForwardRequestData{
		Destination:   tFakeDest,
		NextHop:       tFakeDest,
		TTLHops:       3,
		EnvelopeInner: inner.ContentHash,
	}.ToEntity()
	resp, _ := h.Handle(context.Background(), &handler.Request{
		Operation: OpForward, Params: params, Context: hctx,
	})
	// v1 falls through to default convention; cross-relay store is
	// deferred until OutboundDispatcher wires relay-to-relay :put.
	if resp.Status != 200 {
		t.Fatalf("status: want 200 (default-convention fallback), got %d (code=%q)", resp.Status, decodeErrCode(t, resp))
	}
	fr, _ := types.ForwardResultDataFromEntity(resp.Result)
	if fr.StoredAt != tFakeDest {
		t.Fatalf("StoredAt: want default %q (cross-relay store deferred), got %q", tFakeDest, fr.StoredAt)
	}
}

// Priority ordering: a declaration's highest-priority (= lowest number)
// entry targeting us wins over a lower-priority one.
func TestForward_FallbackHonorsPriority(t *testing.T) {
	h := newTestHandler(t)
	h.SetDispatcher(&fakeDispatcher{deliverErr: ErrDestinationUnreachable})
	primaryNamespace := "primary-inbox"
	backupNamespace := "backup-inbox"
	h.SetInboxRelayResolver(&fakeInboxResolver{
		declarations: map[string]types.InboxRelayData{
			tFakeDest: {
				Relays: []types.InboxRelayEntry{
					// Order intentionally backwards — sortByPriority must fix it.
					{Relay: tFakeRelay, Namespace: backupNamespace, Priority: 50},
					{Relay: tFakeRelay, Namespace: primaryNamespace, Priority: 10},
				},
			},
		},
	})

	hctx := newTestContext()
	inner := makeInnerEnvelope(t, "x")
	hctx.Included[inner.ContentHash] = inner
	params, _ := types.ForwardRequestData{
		Destination:   tFakeDest,
		NextHop:       tFakeDest,
		TTLHops:       3,
		EnvelopeInner: inner.ContentHash,
	}.ToEntity()
	resp, _ := h.Handle(context.Background(), &handler.Request{
		Operation: OpForward, Params: params, Context: hctx,
	})
	fr, _ := types.ForwardResultDataFromEntity(resp.Result)
	if fr.StoredAt != primaryNamespace {
		t.Fatalf("priority: want primary %q, got %q (sortByPriority broken)", primaryNamespace, fr.StoredAt)
	}
}

// §5.5 default-grant helper: returns the narrow per-peer relay-poll grant.
func TestSelfPollSeedGrants_ShapeAndScope(t *testing.T) {
	grants := SelfPollSeedGrants(crypto.PeerID(tFakeDest))
	if len(grants) != 1 {
		t.Fatalf("want 1 grant entry, got %d", len(grants))
	}
	g := grants[0]
	// Handlers: system/relay only.
	if len(g.Handlers.Include) != 1 || g.Handlers.Include[0] != HandlerPattern {
		t.Fatalf("Handlers scope wrong: %+v", g.Handlers)
	}
	// Operations: poll only (NOT put / forward / advertise).
	if len(g.Operations.Include) != 1 || g.Operations.Include[0] != OpPoll {
		t.Fatalf("Operations scope wrong: %+v (must be poll-only per §5.5 narrow grant)", g.Operations)
	}
	// Resources: scoped to system/relay/store/{peer-id}/*.
	wantRes := types.RelayStorePrefix(tFakeDest) + "*"
	if len(g.Resources.Include) != 1 || g.Resources.Include[0] != wantRes {
		t.Fatalf("Resources scope wrong: %+v (want %q)", g.Resources, wantRes)
	}
}

// -----------------------------------------------------------------------
// Cursor helpers
// -----------------------------------------------------------------------

func TestCursor_EncodeDecodeRoundtrip(t *testing.T) {
	for _, want := range []uint64{0, 1, 42, 1 << 30, ^uint64(0)} {
		got, err := decodeCursor(encodeCursor(want))
		if err != nil {
			t.Fatalf("decode round-trip: %v", err)
		}
		if got != want {
			t.Fatalf("roundtrip: want %d, got %d", want, got)
		}
	}
}

func TestCursor_RejectsMalformedBstr(t *testing.T) {
	// A CBOR bstr(3) = 0x43 + 3 bytes. Go's cursor is bstr(8); 3-byte bstr
	// is malformed for Go's own emit. Other-shape cursors (text strings
	// from a foreign impl) are pass-through; decode returns (0, nil) so
	// the foreign cursor just round-trips through Go without advancing
	// our store.
	malformed := cbor.RawMessage{0x43, 0x01, 0x02, 0x03}
	if _, err := decodeCursor(malformed); err == nil {
		t.Fatal("decodeCursor: want error on 3-byte bstr (Go's own format is bstr(8))")
	}
	// Empty/nil is fresh start (seq=0) — not an error.
	if seq, err := decodeCursor(nil); err != nil || seq != 0 {
		t.Fatalf("decodeCursor(nil): want (0, nil), got (%d, %v)", seq, err)
	}
	// Foreign-shape cursor (text string) → pass-through; (0, nil), not error.
	foreign := cbor.RawMessage{0x65, 'h', 'e', 'l', 'l', 'o'} // CBOR text(5)
	if seq, err := decodeCursor(foreign); err != nil || seq != 0 {
		t.Fatalf("decodeCursor(foreign text): want (0, nil) pass-through, got (%d, %v)", seq, err)
	}
}

func TestEncodeCursor_CBORBstrEightBytes(t *testing.T) {
	c := encodeCursor(0x0102030405060708)
	// CBOR-encoded: bstr(8) header (0x48) + 8 BE bytes.
	want := []byte{0x48, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08}
	if !bytes.Equal(c, want) {
		t.Fatalf("encodeCursor: want %x, got %x", want, c)
	}
	// Sanity: big-endian round-trip via the standard pkg, skipping bstr header.
	if binary.BigEndian.Uint64(c[1:]) != 0x0102030405060708 {
		t.Fatal("big-endian round-trip")
	}
}

// -----------------------------------------------------------------------
// EntryByHash exposure (R4 needs this for post-poll fetch)
// -----------------------------------------------------------------------

func TestEntryByHash_ResolvesStored(t *testing.T) {
	h := newTestHandler(t)
	hctx := newTestContext()
	inner := makeInnerEnvelope(t, "hello")
	hctx.Included[inner.ContentHash] = inner
	se := types.StoreEntryData{
		Namespace:     tFakeDest,
		PutBy:         tFakeRelay,
		EnvelopeInner: inner.ContentHash,
	}
	seEnt, _ := se.ToEntity()
	params, _ := se.ToEntity()
	if resp, _ := h.Handle(context.Background(), &handler.Request{
		Operation: OpPut, Params: params, Context: hctx,
	}); resp.Status != 200 {
		t.Fatalf("put: %d", resp.Status)
	}

	gotEntry, gotInner, ok := h.EntryByHash(tFakeDest, seEnt.ContentHash)
	if !ok {
		t.Fatal("EntryByHash: lookup miss after put")
	}
	if gotEntry.ContentHash != seEnt.ContentHash {
		t.Fatal("EntryByHash: entry hash drift")
	}
	if gotInner.ContentHash != inner.ContentHash {
		t.Fatal("EntryByHash: inner hash drift (§9 opacity — byte-identical preserved)")
	}
}

func TestEntryByHash_MissOnUnknown(t *testing.T) {
	h := newTestHandler(t)
	_, _, ok := h.EntryByHash(tFakeDest, relayFakeContentHash(0xFF))
	if ok {
		t.Fatal("EntryByHash: spurious hit")
	}
}

// -----------------------------------------------------------------------
// Helpers
// -----------------------------------------------------------------------

func must(t *testing.T, raw []byte, err error) cbor.RawMessage {
	t.Helper()
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	return cbor.RawMessage(raw)
}

// mustEnc wraps ecf.Encode so callers don't have to split (raw, err) at the
// must() call-site; works around Go's lack of multi-value spread in calls.
func mustEnc(t *testing.T, v any) cbor.RawMessage {
	t.Helper()
	raw, err := ecf.Encode(v)
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	return cbor.RawMessage(raw)
}

func relayFakeContentHash(b byte) hash.Hash {
	var h hash.Hash
	h.Algorithm = hash.AlgorithmSHA256
	h.Digest[0] = b
	return h
}

func decodeErrCode(t *testing.T, resp *handler.Response) string {
	t.Helper()
	var ed types.ErrorData
	if err := ecf.Decode(resp.Result.Data, &ed); err != nil {
		t.Fatalf("decode error: %v", err)
	}
	return ed.Code
}
