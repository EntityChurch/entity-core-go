package storagesubstitutehttp

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"go.entitychurch.org/entity-core-go/core/ecf"
	"go.entitychurch.org/entity-core-go/core/entity"
	"go.entitychurch.org/entity-core-go/core/handler"
	"go.entitychurch.org/entity-core-go/core/hash"
	"go.entitychurch.org/entity-core-go/core/types"
)

// mkTryRequest builds a try-request entity wrapping the given source +
// target hash, suitable for passing into Handler.Handle as req.Params.
func mkTryRequest(t *testing.T, src types.SubstituteSourceData, target hash.Hash) entity.Entity {
	t.Helper()
	entryEnt, err := src.ToEntity()
	if err != nil {
		t.Fatalf("src.ToEntity: %v", err)
	}
	req := types.SubstituteTryRequestData{
		Entry: entryEnt,
		Hash:  target,
	}
	ent, err := req.ToEntity()
	if err != nil {
		t.Fatalf("req.ToEntity: %v", err)
	}
	return ent
}

// mkSourceEntity builds a substitute-source entity advertising a single
// HTTP endpoint at the given URL prefix.
func mkSourceEntity(t *testing.T, contentURLPrefix string) types.SubstituteSourceData {
	t.Helper()
	peerID := hash.Hash{Algorithm: hash.AlgorithmSHA256}
	peerID.Digest[0] = 0xab

	src, err := types.NewHTTPSource("test-mirror", peerID, types.TransportEndpoint{
		TreeURLPrefix:    contentURLPrefix,
		ContentURLPrefix: contentURLPrefix,
		ContentLayout:    types.ContentLayoutFlat,
	}, 10)
	if err != nil {
		t.Fatalf("NewHTTPSource: %v", err)
	}
	return src
}

// mkContentEntity builds a small entity, encodes it to wire bytes (the
// shape an http origin would serve), and returns the encoded bytes + the
// computed content hash.
func mkContentEntity(t *testing.T, payload string) ([]byte, hash.Hash) {
	t.Helper()
	dataBytes, err := ecf.Encode(payload)
	if err != nil {
		t.Fatalf("encode payload: %v", err)
	}
	ent, err := entity.NewEntity("test/payload", dataBytes)
	if err != nil {
		t.Fatalf("NewEntity: %v", err)
	}
	wire, err := ecf.Encode(ent)
	if err != nil {
		t.Fatalf("encode entity: %v", err)
	}
	return wire, ent.ContentHash
}

func TestHandler_Try_Success(t *testing.T) {
	// Mock CDN origin serving a hash-addressed entity wire bytes.
	wire, contentHash := mkContentEntity(t, "hello world")
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Layout=flat → {prefix}/{hash-hex}; the path is the hex of the digest.
		if !strings.Contains(r.URL.Path, "/") {
			http.Error(w, "no hash", http.StatusBadRequest)
			return
		}
		w.Header().Set("Content-Type", "application/cbor")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(wire)
	}))
	defer server.Close()

	src := mkSourceEntity(t, server.URL)
	req := mkTryRequest(t, src, contentHash)

	h := NewHandler(WithHTTPClient(server.Client()), WithAllowHTTP(true))
	resp, err := h.Handle(context.Background(), &handler.Request{
		Operation: types.OpSubstituteTry,
		Params:    req,
	})
	if err != nil {
		t.Fatalf("Handle: %v", err)
	}
	if resp.Status != 200 {
		t.Fatalf("expected 200, got %d (result type %q)", resp.Status, resp.Result.Type)
	}
	if resp.Result.ContentHash != contentHash {
		t.Errorf("hash mismatch: result=%s expected=%s", resp.Result.ContentHash, contentHash)
	}
}

func TestHandler_Try_HashMismatch(t *testing.T) {
	// Serve an entity whose hash does NOT match what the client requests.
	wire, actualHash := mkContentEntity(t, "what the publisher served")
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(wire)
	}))
	defer server.Close()

	// Build a target hash that differs from actualHash.
	wrongHash := actualHash
	wrongHash.Digest[0] ^= 0xff

	src := mkSourceEntity(t, server.URL)
	req := mkTryRequest(t, src, wrongHash)

	h := NewHandler(WithHTTPClient(server.Client()), WithAllowHTTP(true))
	resp, err := h.Handle(context.Background(), &handler.Request{
		Operation: types.OpSubstituteTry,
		Params:    req,
	})
	if err != nil {
		t.Fatalf("Handle: %v", err)
	}
	if resp.Status != 502 {
		t.Fatalf("expected 502 bad_gateway on hash mismatch, got %d", resp.Status)
	}
}

func TestHandler_Try_Upstream404(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.NotFound(w, r)
	}))
	defer server.Close()

	_, target := mkContentEntity(t, "anything")
	src := mkSourceEntity(t, server.URL)
	req := mkTryRequest(t, src, target)

	h := NewHandler(WithHTTPClient(server.Client()), WithAllowHTTP(true))
	resp, err := h.Handle(context.Background(), &handler.Request{
		Operation: types.OpSubstituteTry,
		Params:    req,
	})
	if err != nil {
		t.Fatalf("Handle: %v", err)
	}
	if resp.Status != 404 {
		t.Fatalf("expected 404 not_found, got %d", resp.Status)
	}
}

func TestHandler_Try_HTTPSRequiredByDefault(t *testing.T) {
	// Build a source advertising an http:// URL; default handler should reject.
	src := mkSourceEntity(t, "http://insecure.example.com/content")
	_, target := mkContentEntity(t, "anything")
	req := mkTryRequest(t, src, target)

	h := NewHandler() // defaults: HTTPS-only
	resp, err := h.Handle(context.Background(), &handler.Request{
		Operation: types.OpSubstituteTry,
		Params:    req,
	})
	if err != nil {
		t.Fatalf("Handle: %v", err)
	}
	if resp.Status != 403 {
		t.Fatalf("expected 403 https_required, got %d", resp.Status)
	}
}

func TestHandler_Try_WrongSubstituteType(t *testing.T) {
	// Build a source advertising a non-http substitute_type; handler should reject.
	peerID := hash.Hash{Algorithm: hash.AlgorithmSHA256}
	peerID.Digest[0] = 0xab
	src := types.SubstituteSourceData{
		Name:           "wrong-kind",
		SubstituteType: types.SubstituteTypePeerToPeer,
		SourcePeerID:   peerID,
		Priority:       10,
		Enabled:        true,
	}
	_, target := mkContentEntity(t, "anything")
	req := mkTryRequest(t, src, target)

	h := NewHandler(WithAllowHTTP(true))
	resp, err := h.Handle(context.Background(), &handler.Request{
		Operation: types.OpSubstituteTry,
		Params:    req,
	})
	if err != nil {
		t.Fatalf("Handle: %v", err)
	}
	if resp.Status != 400 {
		t.Fatalf("expected 400 wrong_substitute_type, got %d", resp.Status)
	}
}

func TestHandler_Try_UnknownOperation(t *testing.T) {
	h := NewHandler()
	resp, err := h.Handle(context.Background(), &handler.Request{
		Operation: "definitely-not-an-op",
	})
	if err != nil {
		t.Fatalf("Handle: %v", err)
	}
	if resp.Status != 400 {
		t.Fatalf("expected 400, got %d", resp.Status)
	}
}

func TestHandler_Manifest(t *testing.T) {
	h := NewHandler()
	m := h.Manifest()
	if m.Pattern != HandlerPattern {
		t.Errorf("pattern: got %q want %q", m.Pattern, HandlerPattern)
	}
	tryOp, ok := m.Operations[types.OpSubstituteTry]
	if !ok {
		t.Fatalf("missing %q op in manifest", types.OpSubstituteTry)
	}
	if tryOp.InputType != types.TypeSubstituteTryRequest {
		t.Errorf("input type: got %q want %q", tryOp.InputType, types.TypeSubstituteTryRequest)
	}
	// Ruling 3 — no output wrapper type.
	if tryOp.OutputType != "" {
		t.Errorf("output type: got %q want empty (raw entity per Ruling 3)", tryOp.OutputType)
	}
}
