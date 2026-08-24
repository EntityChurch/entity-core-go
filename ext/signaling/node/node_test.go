package node

import (
	"bytes"
	"context"
	"fmt"
	"testing"
	"time"

	"go.entitychurch.org/entity-core-go/core/entity"
	"go.entitychurch.org/entity-core-go/core/handler"
	"go.entitychurch.org/entity-core-go/core/types"
	"go.entitychurch.org/entity-core-go/ext/signaling"
)

// key33 returns a distinct valid 33-byte rendezvous key (first byte = seed).
func key33(seed byte) []byte {
	k := make([]byte, keyLen)
	k[0] = seed
	return k
}

func offerReq(t *testing.T, key, msg []byte) *handler.Request {
	t.Helper()
	ent, err := types.OfferRequestData{RendezvousKey: key, Message: msg}.ToEntity()
	if err != nil {
		t.Fatalf("build offer-request: %v", err)
	}
	return &handler.Request{Operation: signaling.OpOffer, Params: ent}
}

func collectReq(t *testing.T, key []byte) *handler.Request {
	t.Helper()
	ent, err := types.CollectRequestData{RendezvousKey: key}.ToEntity()
	if err != nil {
		t.Fatalf("build collect-request: %v", err)
	}
	return &handler.Request{Operation: signaling.OpCollect, Params: ent}
}

func mustHandle(t *testing.T, h *Handler, req *handler.Request) *handler.Response {
	t.Helper()
	resp, err := h.Handle(context.Background(), req)
	if err != nil {
		t.Fatalf("Handle(%s): %v", req.Operation, err)
	}
	return resp
}

func collectMessages(t *testing.T, h *Handler, key []byte) [][]byte {
	t.Helper()
	resp := mustHandle(t, h, collectReq(t, key))
	if resp.Status != 200 {
		t.Fatalf("collect status=%d, want 200", resp.Status)
	}
	d, err := types.CollectResultDataFromEntity(resp.Result)
	if err != nil {
		t.Fatalf("decode collect-result: %v", err)
	}
	return d.Messages
}

// TestOfferCollectRoundTrip is the core §4.1 path: an offered blob is collected
// back verbatim, and an unknown key yields an empty list with a 200 (§4.4).
func TestOfferCollectRoundTrip(t *testing.T) {
	h := New()
	key := key33(1)

	if got := collectMessages(t, h, key33(9)); len(got) != 0 {
		t.Fatalf("unknown key returned %d messages, want 0 (§4.4)", len(got))
	}

	msg := []byte("blob-one")
	if resp := mustHandle(t, h, offerReq(t, key, msg)); resp.Status != 200 {
		t.Fatalf("offer status=%d, want 200", resp.Status)
	}
	got := collectMessages(t, h, key)
	if len(got) != 1 || !bytes.Equal(got[0], msg) {
		t.Fatalf("collect returned %v, want [%q]", got, msg)
	}
}

// TestOfferAppendsOldestFirst covers §5 pin 2 (append) and pin 4 (oldest-first).
func TestOfferAppendsOldestFirst(t *testing.T) {
	h := New()
	key := key33(2)
	for _, m := range []string{"first", "second", "third"} {
		mustHandle(t, h, offerReq(t, key, []byte(m)))
	}
	got := collectMessages(t, h, key)
	want := []string{"first", "second", "third"}
	if len(got) != len(want) {
		t.Fatalf("collected %d, want %d", len(got), len(want))
	}
	for i, w := range want {
		if string(got[i]) != w {
			t.Errorf("message[%d]=%q, want %q (oldest-first)", i, got[i], w)
		}
	}
}

// TestOfferIdempotentDedup covers §5 pin 1/2: re-offering identical bytes is a
// no-op success, so a retry never accumulates.
func TestOfferIdempotentDedup(t *testing.T) {
	h := New()
	key := key33(3)
	msg := []byte("same-bytes")
	for i := 0; i < 5; i++ {
		if resp := mustHandle(t, h, offerReq(t, key, msg)); resp.Status != 200 {
			t.Fatalf("re-offer %d status=%d, want 200 (idempotent)", i, resp.Status)
		}
	}
	if got := collectMessages(t, h, key); len(got) != 1 {
		t.Fatalf("bucket holds %d copies of an identical blob, want 1 (dedup by content hash)", len(got))
	}
	// A DIFFERENT blob at the same key still appends.
	mustHandle(t, h, offerReq(t, key, []byte("other-bytes")))
	if got := collectMessages(t, h, key); len(got) != 2 {
		t.Fatalf("bucket holds %d after a distinct offer, want 2", len(got))
	}
}

// TestOfferBucketFullRefuses covers §8 bucket_full: at max_bucket_blobs the node
// refuses (never evicts) with a non-200 and the bucket_full code.
func TestOfferBucketFullRefuses(t *testing.T) {
	h := New(WithLimits(0, 3, 0)) // max_bucket_blobs = 3, others default
	key := key33(4)
	for i := 0; i < 3; i++ {
		if resp := mustHandle(t, h, offerReq(t, key, []byte(fmt.Sprintf("m%d", i)))); resp.Status != 200 {
			t.Fatalf("offer %d status=%d, want 200", i, resp.Status)
		}
	}
	resp := mustHandle(t, h, offerReq(t, key, []byte("overflow")))
	if resp.Status != 429 {
		t.Fatalf("overflow offer status=%d, want 429 (bucket_full)", resp.Status)
	}
	assertErrorCode(t, resp, "bucket_full")
	// Nothing evicted: still exactly 3, and the overflow blob is absent.
	if got := collectMessages(t, h, key); len(got) != 3 {
		t.Fatalf("bucket holds %d after refused overflow, want 3 (never evicts)", len(got))
	}
}

// TestOfferMessageTooLargeRefuses covers §8 message_too_large.
func TestOfferMessageTooLargeRefuses(t *testing.T) {
	h := New(WithLimits(16, 0, 0)) // max_blob_bytes = 16
	key := key33(5)
	resp := mustHandle(t, h, offerReq(t, key, bytes.Repeat([]byte("x"), 17)))
	if resp.Status != 413 {
		t.Fatalf("oversized offer status=%d, want 413 (message_too_large)", resp.Status)
	}
	assertErrorCode(t, resp, "message_too_large")
	if got := collectMessages(t, h, key); len(got) != 0 {
		t.Fatalf("oversized blob was stored (%d) — must be refused, never truncated", len(got))
	}
	// A blob exactly at the limit is accepted.
	if resp := mustHandle(t, h, offerReq(t, key, bytes.Repeat([]byte("x"), 16))); resp.Status != 200 {
		t.Fatalf("at-limit offer status=%d, want 200", resp.Status)
	}
}

// TestBadKeyLength covers §8: any key length other than 33 is bad_request, for
// both offer and collect.
func TestBadKeyLength(t *testing.T) {
	h := New()
	short := make([]byte, 32)
	if resp := mustHandle(t, h, offerReq(t, short, []byte("x"))); resp.Status != 400 {
		t.Errorf("offer with 32-byte key status=%d, want 400", resp.Status)
	} else {
		assertErrorCode(t, resp, "bad_request")
	}
	if resp := mustHandle(t, h, collectReq(t, short)); resp.Status != 400 {
		t.Errorf("collect with 32-byte key status=%d, want 400", resp.Status)
	}
}

// TestUnknownOperation covers the closed-enum default: an unknown op is
// bad_request, not a panic or a 500.
func TestUnknownOperation(t *testing.T) {
	h := New()
	ent, _ := types.OfferRequestData{RendezvousKey: key33(7), Message: []byte("x")}.ToEntity()
	resp := mustHandle(t, h, &handler.Request{Operation: "bogus", Params: ent})
	if resp.Status != 400 {
		t.Fatalf("unknown op status=%d, want 400", resp.Status)
	}
	assertErrorCode(t, resp, "bad_request")
}

// TestTTLReaping covers §5 pin 3/6: an entry past ttl_seconds is reaped, so a
// later collect does not see it. Driven by an injected clock, no sleeping.
func TestTTLReaping(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	h := New(WithLimits(0, 0, 10), WithClock(func() time.Time { return now }))
	key := key33(8)
	mustHandle(t, h, offerReq(t, key, []byte("ephemeral")))
	if got := collectMessages(t, h, key); len(got) != 1 {
		t.Fatalf("pre-expiry collect returned %d, want 1", len(got))
	}
	now = now.Add(11 * time.Second) // past the 10s TTL
	if got := collectMessages(t, h, key); len(got) != 0 {
		t.Fatalf("post-expiry collect returned %d, want 0 (TTL binding on the service)", len(got))
	}
}

// TestAdvertiseLimits covers §4.5: advertise returns the endpoint and the exact
// limits block clients read instead of assuming.
func TestAdvertiseLimits(t *testing.T) {
	h := New(WithEndpoint("127.0.0.1:4050"), WithLimits(4096, 16, 30))
	resp, err := h.Handle(context.Background(), &handler.Request{Operation: signaling.OpAdvertise})
	if err != nil {
		t.Fatalf("advertise: %v", err)
	}
	if resp.Status != 200 {
		t.Fatalf("advertise status=%d, want 200", resp.Status)
	}
	adv, err := types.AdvertiseResultDataFromEntity(resp.Result)
	if err != nil {
		t.Fatalf("decode advertise-result: %v", err)
	}
	if adv.Endpoint != "127.0.0.1:4050" {
		t.Errorf("endpoint=%q, want 127.0.0.1:4050", adv.Endpoint)
	}
	if adv.Limits.MaxBlobBytes != 4096 || adv.Limits.MaxBucketBlobs != 16 || adv.Limits.TTLSeconds != 30 {
		t.Errorf("limits=%+v, want {4096 16 30 ...}", adv.Limits)
	}
	// Defaults surface when unset (§5 pin 5/6).
	def, _ := New().Handle(context.Background(), &handler.Request{Operation: signaling.OpAdvertise})
	dadv, _ := types.AdvertiseResultDataFromEntity(def.Result)
	if dadv.Limits.MaxBlobBytes != DefaultMaxBlobBytes || dadv.Limits.MaxBucketBlobs != DefaultMaxBucketBlobs || dadv.Limits.TTLSeconds != DefaultTTLSeconds {
		t.Errorf("default limits=%+v, want {%d %d %d}", dadv.Limits, DefaultMaxBlobBytes, DefaultMaxBucketBlobs, DefaultTTLSeconds)
	}
}

// assertErrorCode checks the response carries an ErrorData with the given §8
// closed-enum code.
func assertErrorCode(t *testing.T, resp *handler.Response, code string) {
	t.Helper()
	if resp.Result.Type != types.TypeError {
		t.Fatalf("result type=%q, want %q", resp.Result.Type, types.TypeError)
	}
	ed, err := errorDataFrom(resp.Result)
	if err != nil {
		t.Fatalf("decode error-data: %v", err)
	}
	if ed.Code != code {
		t.Fatalf("error code=%q, want %q", ed.Code, code)
	}
}

func errorDataFrom(e entity.Entity) (types.ErrorData, error) {
	return types.ErrorDataFromEntity(e)
}
