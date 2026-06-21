package content

import (
	"context"
	"testing"

	"go.entitychurch.org/entity-core-go/core/handler"
	"go.entitychurch.org/entity-core-go/core/hash"
	"go.entitychurch.org/entity-core-go/core/store"
	"go.entitychurch.org/entity-core-go/core/types"
	"go.entitychurch.org/entity-core-go/ext/content/chunker"
)

// fakeConnState satisfies the structural interface frameBudget looks for.
type fakeConnState struct{ budget uint64 }

func (f fakeConnState) EffectiveFrameBudget() uint64 { return f.budget }

// TestHandleGet_FrameBudgetChunksResponse_AndRemainderMovesToMissing
// drives the F8 receiver-side MUST directly through the content
// handler. Seed enough 1 MiB chunks to overflow a tight 4 MiB budget;
// confirm `found` is a strict subset and the remainder lands in
// `missing` while the budget is honored.
func TestHandleGet_FrameBudgetChunksResponse_AndRemainderMovesToMissing(t *testing.T) {
	cs := store.NewMemoryContentStore()

	// Seed 8 chunks of ~1 MiB each = ~8 MiB total. With a 4 MiB
	// budget (minus 64 KiB safety margin → ~3.94 MiB), only ~3
	// chunks should fit; the rest land in missing.
	chunkHashes := make([]hash.Hash, 0, 8)
	for i := 0; i < 8; i++ {
		body := make([]byte, 1024*1024)
		for j := range body {
			body[j] = byte(i ^ (j & 0xFF))
		}
		blobHash, err := IngestBlob(body, []chunker.ChunkRange{{Start: 0, End: uint64(len(body))}}, types.ChunkingFastCDC, types.DefaultChunkSize, cs)
		if err != nil {
			t.Fatalf("ingest %d: %v", i, err)
		}
		blobEnt, _ := cs.Get(blobHash)
		chunks, err := blobChunkHashes(blobEnt)
		if err != nil {
			t.Fatalf("decode blob %d: %v", i, err)
		}
		chunkHashes = append(chunkHashes, chunks...)
	}

	if len(chunkHashes) < 4 {
		t.Fatalf("seeded too few chunks (%d) — bump fixture or check chunker", len(chunkHashes))
	}

	h := NewHandler()
	getReq, err := types.ContentGetRequestData{Hashes: chunkHashes}.ToEntity()
	if err != nil {
		t.Fatalf("encode req: %v", err)
	}
	req := &handler.Request{
		Operation: "get",
		Params:    getReq,
		Context: &handler.HandlerContext{
			Store:           cs,
			HandlerPattern:  "system/content",
			Resource:        &types.ResourceTarget{Targets: []string{"system/content"}},
			ConnectionState: fakeConnState{budget: 4 * 1024 * 1024},
		},
	}
	resp, err := h.Handle(context.Background(), req)
	if err != nil {
		t.Fatalf("handle: %v", err)
	}
	if resp.Status != 200 {
		t.Fatalf("status %d, want 200", resp.Status)
	}
	var respData types.ContentGetResponseData
	if derr := decodeEntityData(resp.Result, &respData); derr != nil {
		t.Fatalf("decode resp: %v", derr)
	}
	if len(respData.Found) == 0 {
		t.Fatalf("found empty — handler returned zero entities")
	}
	if len(respData.Found) == len(chunkHashes) {
		t.Fatalf("F8 NOT enforced: found=%d equals requested=%d (no `missing`); response would exceed budget by ~%d MiB",
			len(respData.Found), len(chunkHashes), (len(chunkHashes)-len(respData.Found)))
	}
	if len(respData.Missing) == 0 {
		t.Fatalf("missing empty when budget would overflow — F8 not triggering")
	}
	if len(respData.Found)+len(respData.Missing) != len(chunkHashes) {
		t.Fatalf("found(%d) + missing(%d) ≠ requested(%d)", len(respData.Found), len(respData.Missing), len(chunkHashes))
	}
}
