package content

import (
	"context"
	"errors"
	"strings"
	"testing"

	"go.entitychurch.org/entity-core-go/core/handler"
	"go.entitychurch.org/entity-core-go/core/hash"
	"go.entitychurch.org/entity-core-go/core/store"
	"go.entitychurch.org/entity-core-go/core/types"
	"go.entitychurch.org/entity-core-go/ext/content/chunker"
)

// pendingThenServeDispatcher returns 503 for the first `pendingAttempts`
// calls, then serves from `remote`. Models a peer that's catching up.
type pendingThenServeDispatcher struct {
	cs              store.ContentStore
	remote          store.ContentStore
	pendingAttempts int
	calls           int
}

func (d *pendingThenServeDispatcher) Store() store.ContentStore { return d.cs }

func (d *pendingThenServeDispatcher) Execute(ctx context.Context, req handler.ExecuteRequest) (handler.ExecuteResponse, error) {
	d.calls++
	if d.calls <= d.pendingAttempts {
		errEnt, _ := types.ErrorData{Code: "blob_pending_sync", Message: "pending"}.ToEntity()
		return handler.ExecuteResponse{Status: 503, Result: errEnt}, nil
	}
	return fakeContentGet(d.remote, req)
}

// TestEnsureClosure_NoOpWhenClosureAlreadyLocal verifies that
// EnsureClosure issues zero dispatches when the blob + every chunk are
// already in the local content store.
func TestEnsureClosure_NoOpWhenClosureAlreadyLocal(t *testing.T) {
	cs := store.NewMemoryContentStore()
	body := []byte("complete-closure-already-local")
	blobHash, err := IngestBlob(body, []chunker.ChunkRange{{Start: 0, End: uint64(len(body))}}, types.ChunkingFastCDC, types.DefaultChunkSize, cs)
	if err != nil {
		t.Fatalf("ingest: %v", err)
	}

	d := &countingDispatcher{cs: cs}
	if err := EnsureClosure(context.Background(), d, blobHash, "system/content"); err != nil {
		t.Fatalf("EnsureClosure on locally-complete closure: %v", err)
	}
	if d.calls != 0 {
		t.Errorf("expected zero dispatches when closure local; got %d", d.calls)
	}
}

// TestEnsureClosure_FetchesMissingBlobAndChunks drives EnsureClosure
// against a remote store; verifies blob + chunks land locally.
func TestEnsureClosure_FetchesMissingBlobAndChunks(t *testing.T) {
	remote := store.NewMemoryContentStore()
	body := []byte("requires-fetch-blob-and-chunks-from-remote")
	blobHash, err := IngestBlob(body, []chunker.ChunkRange{{Start: 0, End: uint64(len(body))}}, types.ChunkingFastCDC, types.DefaultChunkSize, remote)
	if err != nil {
		t.Fatalf("seed remote: %v", err)
	}

	local := store.NewMemoryContentStore()
	d := &countingDispatcher{cs: local, remote: remote}
	if err := EnsureClosure(context.Background(), d, blobHash, "system/content"); err != nil {
		t.Fatalf("EnsureClosure: %v", err)
	}
	if _, ok := local.Get(blobHash); !ok {
		t.Fatalf("blob not local after EnsureClosure")
	}
	got, err := Reassemble(local, blobHash)
	if err != nil {
		t.Fatalf("Reassemble: %v", err)
	}
	if string(got) != string(body) {
		t.Errorf("Reassemble round-trip mismatch: got %q want %q", got, body)
	}
}

// TestEnsureClosure_RetriesMissingFromResponse simulates a responder
// that frame-budget-caps the response (returns blob in `found` but
// chunks in `missing`); EnsureClosure must retry until closure complete.
func TestEnsureClosure_RetriesMissingFromResponse(t *testing.T) {
	remote := store.NewMemoryContentStore()
	body := make([]byte, 0, 4096)
	for i := 0; i < 4096; i++ {
		body = append(body, byte(i))
	}
	ranges := chunker.ChunkFastCDC(body, types.DefaultChunkSize)
	if len(ranges) == 0 {
		ranges = []chunker.ChunkRange{{Start: 0, End: uint64(len(body))}}
	}
	blobHash, err := IngestBlob(body, ranges, types.ChunkingFastCDC, types.DefaultChunkSize, remote)
	if err != nil {
		t.Fatalf("seed remote: %v", err)
	}

	local := store.NewMemoryContentStore()
	d := &cappingDispatcher{cs: local, remote: remote, perCallCap: 1}
	if err := EnsureClosure(context.Background(), d, blobHash, "system/content"); err != nil {
		t.Fatalf("EnsureClosure: %v", err)
	}
	if _, ok := local.Get(blobHash); !ok {
		t.Fatalf("blob not local after EnsureClosure")
	}
}

// TestEnsureClosure_ReturnsStatusErrorOnDenial confirms 403/404 from
// a sub-dispatch propagates as StatusError with the correct status.
func TestEnsureClosure_ReturnsStatusErrorOnDenial(t *testing.T) {
	local := store.NewMemoryContentStore()
	nonZeroDigest := make([]byte, 32)
	for i := range nonZeroDigest {
		nonZeroDigest[i] = 0xAA
	}
	someHash, _ := hash.FromBytes(append([]byte{hash.AlgorithmSHA256}, nonZeroDigest...))
	d := &denyingDispatcher{cs: local, status: 403, code: "forbidden", message: "cap denied"}
	err := EnsureClosure(context.Background(), d, someHash, "system/content")
	if err == nil {
		t.Fatalf("expected StatusError, got nil")
	}
	var se *StatusError
	if !errors.As(err, &se) {
		t.Fatalf("expected *StatusError; got %T (%v)", err, err)
	}
	if se.Status != 403 {
		t.Errorf("status = %d, want 403", se.Status)
	}
}

// TestEnsureClosure_Retries503OnBlobFetch confirms a 503 response on
// the blob fetch path is retried up to MaxPendingSyncRetries (matching
// Rust's catch — Go originally had the same gap where 503 on blob
// fell through as a fatal error).
func TestEnsureClosure_Retries503OnBlobFetch(t *testing.T) {
	remote := store.NewMemoryContentStore()
	body := []byte("retry-on-503-blob-fetch")
	blobHash, err := IngestBlob(body, []chunker.ChunkRange{{Start: 0, End: uint64(len(body))}}, types.ChunkingFastCDC, types.DefaultChunkSize, remote)
	if err != nil {
		t.Fatalf("seed remote: %v", err)
	}
	local := store.NewMemoryContentStore()
	d := &pendingThenServeDispatcher{cs: local, remote: remote, pendingAttempts: 2}
	if err := EnsureClosure(context.Background(), d, blobHash, "system/content"); err != nil {
		t.Fatalf("EnsureClosure: %v", err)
	}
	if _, ok := local.Get(blobHash); !ok {
		t.Fatalf("blob not local after 503 retries succeeded")
	}
	if d.calls != 3 {
		t.Errorf("expected 3 dispatches (2 pending + 1 served); got %d", d.calls)
	}
}

// TestEnsureClosure_503ExhaustsRetries confirms a peer that keeps
// returning 503 eventually surfaces the error rather than looping
// forever.
func TestEnsureClosure_503ExhaustsRetries(t *testing.T) {
	local := store.NewMemoryContentStore()
	someHash, _ := hash.FromBytes(append([]byte{hash.AlgorithmSHA256}, makeNonZeroDigest()...))
	d := &denyingDispatcher{cs: local, status: 503, code: "blob_pending_sync", message: "still pending"}
	err := EnsureClosure(context.Background(), d, someHash, "system/content")
	if err == nil {
		t.Fatalf("expected error after MaxPendingSyncRetries exhausted; got nil")
	}
	var se *StatusError
	if !errors.As(err, &se) {
		t.Fatalf("expected *StatusError; got %T (%v)", err, err)
	}
	if se.Status != 503 {
		t.Errorf("status = %d, want 503", se.Status)
	}
}

// TestEnsureClosure_CancelsOnContextDeadline confirms ctx cancellation
// propagates without first running another fetch round — i.e., the
// drain loop and the retry loop both observe ctx.Err().
func TestEnsureClosure_CancelsOnContextDeadline(t *testing.T) {
	remote := store.NewMemoryContentStore()
	body := []byte("ctx-cancel-mid-loop")
	blobHash, err := IngestBlob(body, []chunker.ChunkRange{{Start: 0, End: uint64(len(body))}}, types.ChunkingFastCDC, types.DefaultChunkSize, remote)
	if err != nil {
		t.Fatalf("seed: %v", err)
	}
	local := store.NewMemoryContentStore()
	d := &countingDispatcher{cs: local, remote: remote}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	err = EnsureClosure(ctx, d, blobHash, "system/content")
	if err == nil || !errors.Is(err, context.Canceled) {
		t.Fatalf("expected context.Canceled; got %v", err)
	}
}

// TestEnsureClosure_RejectsNonBlobHash confirms passing a chunk hash
// (or any non-blob entity) cleanly errors instead of looping forever.
func TestEnsureClosure_RejectsNonBlobHash(t *testing.T) {
	cs := store.NewMemoryContentStore()
	chunkEnt, _ := types.ContentChunkData{Payload: []byte("not-a-blob")}.ToEntity()
	chunkHash, _ := cs.Put(chunkEnt)

	d := &countingDispatcher{cs: cs}
	err := EnsureClosure(context.Background(), d, chunkHash, "system/content")
	if err == nil {
		t.Fatalf("expected error when hash refers to a non-blob entity; got nil")
	}
	if !strings.Contains(err.Error(), "not a blob") {
		t.Errorf("error message should mention non-blob; got %q", err.Error())
	}
}

// TestAtPeer_MultiHopRespectsExistingAuthority confirms wrapping
// AtPeer(AtPeer(hctx, B), C) leaves an already-authority-qualified URI
// targeting B unchanged — the OUTER wrapper only rewrites URIs without
// authority. This matches V7 §1.4 absolute-path discipline.
func TestAtPeer_MultiHopRespectsExistingAuthority(t *testing.T) {
	const peerB = "2KpeerB"
	const peerC = "2KpeerC"
	// URI pre-qualified for B; AtPeer(C) wrapper must leave it alone.
	got := qualifyURIWithPeer("entity://"+peerB+"/system/content", peerC)
	want := "entity://" + peerB + "/system/content"
	if got != want {
		t.Errorf("AtPeer(C) over qualified-B URI: got %q, want %q (must not rewrite already-qualified authority)", got, want)
	}
}

func makeNonZeroDigest() []byte {
	out := make([]byte, 32)
	for i := range out {
		out[i] = 0xAA
	}
	return out
}

// TestQualifyURIWithPeer ensures AtPeer rewrites bare URIs and leaves
// already-qualified URIs alone.
func TestQualifyURIWithPeer(t *testing.T) {
	const peer = "2KTargetPeerID"
	tests := []struct {
		in, want string
	}{
		{"system/content", "entity://" + peer + "/system/content"},
		{"/system/content", "entity://" + peer + "/system/content"},
		{"entity://" + peer + "/system/content", "entity://" + peer + "/system/content"},
		{"entity://other-peer/system/content", "entity://other-peer/system/content"},
	}
	for _, tc := range tests {
		got := qualifyURIWithPeer(tc.in, peer)
		if got != tc.want {
			t.Errorf("qualifyURIWithPeer(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

// --- Test dispatchers ---

// countingDispatcher routes Execute through a fake handler reading from
// `remote` (if set) and writing to `cs`. Counts calls.
type countingDispatcher struct {
	cs     store.ContentStore
	remote store.ContentStore
	calls  int
}

func (d *countingDispatcher) Store() store.ContentStore { return d.cs }

func (d *countingDispatcher) Execute(ctx context.Context, req handler.ExecuteRequest) (handler.ExecuteResponse, error) {
	d.calls++
	if d.remote == nil {
		return handler.ExecuteResponse{Status: 404}, nil
	}
	return fakeContentGet(d.remote, req)
}

// cappingDispatcher returns only `perCallCap` entities per call; the
// rest go into `missing` (simulates responder frame-budget chunking).
type cappingDispatcher struct {
	cs         store.ContentStore
	remote     store.ContentStore
	perCallCap int
}

func (d *cappingDispatcher) Store() store.ContentStore { return d.cs }

func (d *cappingDispatcher) Execute(ctx context.Context, req handler.ExecuteRequest) (handler.ExecuteResponse, error) {
	return fakeContentGetCapped(d.remote, req, d.perCallCap)
}

// denyingDispatcher always returns the configured status with an error
// result entity, simulating a cap denial / not-found / etc.
type denyingDispatcher struct {
	cs                   store.ContentStore
	status               uint
	code, message        string
}

func (d *denyingDispatcher) Store() store.ContentStore { return d.cs }

func (d *denyingDispatcher) Execute(ctx context.Context, req handler.ExecuteRequest) (handler.ExecuteResponse, error) {
	errEnt, _ := types.ErrorData{Code: d.code, Message: d.message}.ToEntity()
	return handler.ExecuteResponse{Status: d.status, Result: errEnt}, nil
}

func fakeContentGet(remote store.ContentStore, req handler.ExecuteRequest) (handler.ExecuteResponse, error) {
	var getReq types.ContentGetRequestData
	if err := decodeRequestParams(req, &getReq); err != nil {
		return handler.ExecuteResponse{Status: 400}, nil
	}
	found := make([]hash.Hash, 0)
	missing := make([]hash.Hash, 0)
	included := make(map[hash.Hash]any)
	for _, h := range getReq.Hashes {
		ent, ok := remote.Get(h)
		if !ok {
			missing = append(missing, h)
			continue
		}
		found = append(found, h)
		included[h] = ent
		// §4.3 inline-include for small blobs.
		if ent.Type == types.TypeContentBlob {
			var blob types.ContentBlobData
			if err := decodeEntityData(ent, &blob); err == nil && blob.TotalSize <= types.MinChunkSize {
				for _, ch := range blob.Chunks {
					if chEnt, ok := remote.Get(ch); ok {
						included[ch] = chEnt
					}
				}
			}
		}
	}
	return buildExecuteResponse(found, missing, included), nil
}

func fakeContentGetCapped(remote store.ContentStore, req handler.ExecuteRequest, perCallCap int) (handler.ExecuteResponse, error) {
	var getReq types.ContentGetRequestData
	if err := decodeRequestParams(req, &getReq); err != nil {
		return handler.ExecuteResponse{Status: 400}, nil
	}
	found := make([]hash.Hash, 0)
	missing := make([]hash.Hash, 0)
	included := make(map[hash.Hash]any)
	added := 0
	for _, h := range getReq.Hashes {
		if added >= perCallCap {
			missing = append(missing, h)
			continue
		}
		ent, ok := remote.Get(h)
		if !ok {
			missing = append(missing, h)
			continue
		}
		found = append(found, h)
		included[h] = ent
		added++
	}
	return buildExecuteResponse(found, missing, included), nil
}
