package content

import (
	"context"
	"encoding/hex"
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

type testEnv struct {
	cs      store.ContentStore
	nsLI    *store.NamespacedIndex
	peerID  crypto.PeerID
	handler *Handler
}

func newTestEnv(t *testing.T) *testEnv {
	t.Helper()
	kp, _ := crypto.Generate()
	cs := store.NewMemoryContentStore()
	raw := store.NewMemoryLocationIndex()
	nsLI := store.NewNamespacedIndex(raw, string(kp.PeerID()))
	return &testEnv{
		cs:      cs,
		nsLI:    nsLI,
		peerID:  kp.PeerID(),
		handler: NewHandler(),
	}
}

func (e *testEnv) hctx() *handler.HandlerContext {
	return &handler.HandlerContext{
		Store:          e.cs,
		LocationIndex:  e.nsLI,
		LocalPeerID:    e.peerID,
		HandlerPattern: handlerPattern,
		Resource:       &types.ResourceTarget{Targets: []string{"system/content"}},
	}
}

// hctxNoResource returns a context with no resource, for path_required tests.
func (e *testEnv) hctxNoResource() *handler.HandlerContext {
	hctx := e.hctx()
	hctx.Resource = nil
	return hctx
}

// TestGetReturnsPathRequiredWhenResourceAbsent — §6.2 v3.4 → v3.5
// behavior reversal. The MUST: missing resource on a system/content:get
// EXECUTE returns path_required.
func TestGetReturnsPathRequiredWhenResourceAbsent(t *testing.T) {
	env := newTestEnv(t)
	req := &handler.Request{
		Operation: "get",
		Context:   env.hctxNoResource(),
	}
	resp, err := env.handler.Handle(context.Background(), req)
	if err != nil {
		t.Fatalf("Handle: %v", err)
	}
	if resp.Status != 400 {
		t.Fatalf("status = %d, want 400", resp.Status)
	}
	var errData types.ErrorData
	if err := ecf.Decode(resp.Result.Data, &errData); err != nil {
		t.Fatalf("decode error: %v", err)
	}
	if errData.Code != "path_required" {
		t.Errorf("error code = %q, want path_required", errData.Code)
	}
}

// TestIngestReturnsPathRequiredWhenResourceAbsent — §6.3 v3.4 → v3.5
// behavior reversal. Same MUST as get.
func TestIngestReturnsPathRequiredWhenResourceAbsent(t *testing.T) {
	env := newTestEnv(t)
	req := &handler.Request{
		Operation: "ingest",
		Context:   env.hctxNoResource(),
	}
	resp, err := env.handler.Handle(context.Background(), req)
	if err != nil {
		t.Fatalf("Handle: %v", err)
	}
	if resp.Status != 400 {
		t.Fatalf("status = %d, want 400", resp.Status)
	}
	var errData types.ErrorData
	if err := ecf.Decode(resp.Result.Data, &errData); err != nil {
		t.Fatalf("decode error: %v", err)
	}
	if errData.Code != "path_required" {
		t.Errorf("error code = %q, want path_required", errData.Code)
	}
}

// putKnownEntity stores a known entity and returns its hash. Used in get
// tests to seed the store.
func (e *testEnv) putKnownEntity(t *testing.T) hash.Hash {
	t.Helper()
	ent, err := entity.NewEntity("test/marker", cbor.RawMessage{0xa0})
	if err != nil {
		t.Fatalf("NewEntity: %v", err)
	}
	h, err := e.cs.Put(ent)
	if err != nil {
		t.Fatalf("Put: %v", err)
	}
	return h
}

// TestGetResolvesKnownHash — smoke. With a resource present, get reads
// the known hash from the content store and returns it in the included
// map.
func TestGetResolvesKnownHash(t *testing.T) {
	env := newTestEnv(t)
	h := env.putKnownEntity(t)

	getReq := types.ContentGetRequestData{Hashes: []hash.Hash{h}}
	paramEnt, err := getReq.ToEntity()
	if err != nil {
		t.Fatalf("encode params: %v", err)
	}
	req := &handler.Request{
		Operation: "get",
		Params:    paramEnt,
		Context:   env.hctx(),
	}
	resp, err := env.handler.Handle(context.Background(), req)
	if err != nil {
		t.Fatalf("Handle: %v", err)
	}
	if resp.Status != 200 {
		t.Fatalf("status = %d, want 200", resp.Status)
	}
	if _, ok := resp.Included[h]; !ok {
		t.Errorf("included map missing the resolved hash")
	}
}

// makeBlobWithSize seeds the store with a blob whose total_size matches
// the requested size, plus a single chunk entity covering all of it.
// Returns the blob hash.
func (e *testEnv) makeBlobWithSize(t *testing.T, size uint64) hash.Hash {
	t.Helper()
	payload := make([]byte, size)
	for i := range payload {
		payload[i] = byte(i % 256)
	}
	chunkEnt, err := types.ContentChunkData{Payload: payload}.ToEntity()
	if err != nil {
		t.Fatalf("chunk ToEntity: %v", err)
	}
	chunkHash, err := e.cs.Put(chunkEnt)
	if err != nil {
		t.Fatalf("Put chunk: %v", err)
	}
	blobEnt, err := types.ContentBlobData{
		TotalSize: size,
		ChunkSize: size,
		Chunking:  types.ChunkingFixed,
		Chunks:    []hash.Hash{chunkHash},
	}.ToEntity()
	if err != nil {
		t.Fatalf("blob ToEntity: %v", err)
	}
	blobHash, err := e.cs.Put(blobEnt)
	if err != nil {
		t.Fatalf("Put blob: %v", err)
	}
	return blobHash
}

// TestInlineIncludeAtThreshold — §4.3 boundary. Total_size = 65,536
// (exactly MIN_CHUNK_SIZE) MUST inline-include the chunks.
func TestInlineIncludeAtThreshold(t *testing.T) {
	env := newTestEnv(t)
	blobHash := env.makeBlobWithSize(t, types.MinChunkSize) // 65,536

	getReq := types.ContentGetRequestData{Hashes: []hash.Hash{blobHash}}
	paramEnt, _ := getReq.ToEntity()
	req := &handler.Request{
		Operation: "get",
		Params:    paramEnt,
		Context:   env.hctx(),
	}
	resp, err := env.handler.Handle(context.Background(), req)
	if err != nil {
		t.Fatalf("Handle: %v", err)
	}
	if len(resp.Included) != 2 {
		t.Errorf("included entries = %d, want 2 (blob + chunk)", len(resp.Included))
	}
}

// TestInlineIncludeAboveThreshold — §4.3 boundary regression. Total_size
// = 65,537 MUST NOT inline-include the chunks (the receiver must follow
// up with get-request).
func TestInlineIncludeAboveThreshold(t *testing.T) {
	env := newTestEnv(t)
	blobHash := env.makeBlobWithSize(t, types.MinChunkSize+1) // 65,537

	getReq := types.ContentGetRequestData{Hashes: []hash.Hash{blobHash}}
	paramEnt, _ := getReq.ToEntity()
	req := &handler.Request{
		Operation: "get",
		Params:    paramEnt,
		Context:   env.hctx(),
	}
	resp, err := env.handler.Handle(context.Background(), req)
	if err != nil {
		t.Fatalf("Handle: %v", err)
	}
	if len(resp.Included) != 1 {
		t.Errorf("included entries = %d, want 1 (blob only)", len(resp.Included))
	}
}

// TestIngestEntityMode — smoke for the existing entity-mode ingest with
// a resource present.
func TestIngestEntityMode(t *testing.T) {
	env := newTestEnv(t)

	target, err := entity.NewEntity("test/marker", cbor.RawMessage{0xa0})
	if err != nil {
		t.Fatalf("NewEntity: %v", err)
	}
	targetBytes, err := ecf.Encode(target)
	if err != nil {
		t.Fatalf("encode target: %v", err)
	}
	targetRaw := cbor.RawMessage(targetBytes)

	ingestReq := types.ContentIngestRequestData{Entity: &targetRaw}
	paramEnt, _ := ingestReq.ToEntity()
	req := &handler.Request{
		Operation: "ingest",
		Params:    paramEnt,
		Context:   env.hctx(),
	}
	resp, err := env.handler.Handle(context.Background(), req)
	if err != nil {
		t.Fatalf("Handle: %v", err)
	}
	if resp.Status != 200 {
		t.Fatalf("status = %d, want 200", resp.Status)
	}
	var result types.ContentIngestResultData
	if err := ecf.Decode(resp.Result.Data, &result); err != nil {
		t.Fatalf("decode result: %v", err)
	}
	if result.IngestedCount != 1 {
		t.Errorf("ingested_count = %d, want 1", result.IngestedCount)
	}
	if !env.cs.Has(result.RootHash) {
		t.Errorf("ingested entity not in content store")
	}
}

// TestIngestEntity_WritesHashTreePresenceBinding asserts the CONTENT
// §6.4.1/§6.4.2 MUST: ingest into namespace P writes the entity to the
// content store AND binds at {namespace}/{hex(H)} in the tree. The
// binding is what NamespaceScope reads in serving-mode (Chunk E ruling
// RULING-SERVING-MODE-CONTENT-BODY-SHAPE §2).
//
// Cross-impl run 0c989fd surfaced this gap cohort-wide; this test
// guards Go from regressing once Rust + Python also land the fix.
func TestIngestEntity_WritesHashTreePresenceBinding(t *testing.T) {
	cases := []struct {
		name      string
		namespace string
	}{
		{"default namespace", "system/content"},
		{"sub namespace", "system/content/public"},
		{"nested sub namespace", "system/content/orgs/foo"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			env := newTestEnv(t)
			hctx := env.hctx()
			hctx.Resource = &types.ResourceTarget{Targets: []string{c.namespace}}

			target, _ := entity.NewEntity("test/marker", cbor.RawMessage{0xa0})
			targetBytes, _ := ecf.Encode(target)
			targetRaw := cbor.RawMessage(targetBytes)
			ingestReq := types.ContentIngestRequestData{Entity: &targetRaw}
			paramEnt, _ := ingestReq.ToEntity()

			resp, err := env.handler.Handle(context.Background(), &handler.Request{
				Operation: "ingest",
				Params:    paramEnt,
				Context:   hctx,
			})
			if err != nil || resp.Status != 200 {
				t.Fatalf("ingest: err=%v status=%d", err, resp.Status)
			}
			var result types.ContentIngestResultData
			if err := ecf.Decode(resp.Result.Data, &result); err != nil {
				t.Fatalf("decode result: %v", err)
			}

			// Expect the §6.4.2 binding at {namespace}/{hex33(H)} → H
			// per V7 §3.5 — 66 hex chars including the algorithm byte.
			wantPath := c.namespace + "/" + hex.EncodeToString(result.RootHash.Bytes())
			got, ok := env.nsLI.Get(wantPath)
			if !ok {
				t.Fatalf("no binding at %q — CONTENT §6.4.2 Hash Tree Presence missing (must be 66-hex per V7 §3.5)", wantPath)
			}
			if got != result.RootHash {
				t.Errorf("binding at %q resolves to %s, want %s", wantPath, got, result.RootHash)
			}
			if len(hex.EncodeToString(result.RootHash.Bytes())) != 66 {
				t.Errorf("hex33(H) wrong length: got %d, want 66", len(hex.EncodeToString(result.RootHash.Bytes())))
			}
		})
	}
}

