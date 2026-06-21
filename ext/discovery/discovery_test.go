package discovery

import (
	"context"
	"strings"
	"sync"
	"testing"

	"go.entitychurch.org/entity-core-go/core/entity"
	"go.entitychurch.org/entity-core-go/core/handler"
	"go.entitychurch.org/entity-core-go/core/hash"
	"go.entitychurch.org/entity-core-go/core/types"

	"github.com/fxamacker/cbor/v2"
)

// stubBackend is a minimal Backend impl test-driven by injected slices.
type stubBackend struct {
	mu sync.Mutex

	kind             string
	candidates       []types.CandidateData
	scanErr          error
	announceCalls    []string
	stopCalls        []string
	announceErr      error
	stopErr          error
	observe          func(types.CandidateData)
	reap             func(hash.Hash)
}

func newStubBackend(kind string, candidates []types.CandidateData) *stubBackend {
	return &stubBackend{kind: kind, candidates: candidates}
}

func (s *stubBackend) Kind() string { return s.kind }

func (s *stubBackend) Scan(ctx context.Context, filter map[string]cbor.RawMessage) ([]types.CandidateData, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.scanErr != nil {
		return nil, s.scanErr
	}
	out := make([]types.CandidateData, len(s.candidates))
	copy(out, s.candidates)
	return out, nil
}

func (s *stubBackend) Announce(ctx context.Context, profileRef string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.announceCalls = append(s.announceCalls, profileRef)
	return s.announceErr
}

func (s *stubBackend) AnnounceStop(ctx context.Context, profileRef string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.stopCalls = append(s.stopCalls, profileRef)
	return s.stopErr
}

func (s *stubBackend) SetObserveCallback(observe func(types.CandidateData), reap func(hash.Hash)) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.observe = observe
	s.reap = reap
}

func (s *stubBackend) pushObserve(cd types.CandidateData) {
	s.mu.Lock()
	cb := s.observe
	s.mu.Unlock()
	if cb != nil {
		cb(cd)
	}
}

func (s *stubBackend) pushReap(h hash.Hash) {
	s.mu.Lock()
	cb := s.reap
	s.mu.Unlock()
	if cb != nil {
		cb(h)
	}
}

// makeScanReq builds a Request with a scan-request params entity.
func makeScanReq(t *testing.T, backend string) *handler.Request {
	t.Helper()
	rd := types.ScanRequestData{Backend: backend}
	ent, err := rd.ToEntity()
	if err != nil {
		t.Fatalf("build scan-request entity: %v", err)
	}
	return &handler.Request{
		Path:      HandlerPattern,
		Operation: OpScan,
		Params:    ent,
		Context:   &handler.HandlerContext{HandlerPattern: HandlerPattern},
	}
}

func dxFakeHashLocal(b byte) hash.Hash {
	var h hash.Hash
	h.Algorithm = hash.AlgorithmSHA256
	h.Digest[0] = b
	return h
}

// -----------------------------------------------------------------------
// 503 before SetupStore (lifecycle gate)
// -----------------------------------------------------------------------

func TestHandleReturns503BeforeSetupStore(t *testing.T) {
	h := NewHandler()
	resp, err := h.Handle(context.Background(), makeScanReq(t, "mdns"))
	if err != nil {
		t.Fatalf("Handle: %v", err)
	}
	if resp.Status != 503 {
		t.Fatalf("status: want 503 (authority_not_ready), got %d", resp.Status)
	}
}

// -----------------------------------------------------------------------
// :scan happy path — snapshot + watchable-prefix write
// -----------------------------------------------------------------------

func TestScanReturnsSnapshotAndBindsWatchablePrefix(t *testing.T) {
	h := NewHandler()
	binder := newMemBinder()
	h.SetupStore(binder)
	stub := newStubBackend("mdns", []types.CandidateData{
		{Backend: "mdns", ObservedAt: 1_730_000_000_000},
		{Backend: "mdns", ObservedAt: 1_730_000_000_001, PeerID: "2Kpeer1"},
	})
	h.RegisterBackend(stub)

	resp, err := h.Handle(context.Background(), makeScanReq(t, "mdns"))
	if err != nil {
		t.Fatalf("Handle: %v", err)
	}
	if resp.Status != 200 {
		t.Fatalf("status: want 200 got %d (result=%+v)", resp.Status, resp.Result)
	}

	result, err := types.ScanResultDataFromEntity(resp.Result)
	if err != nil {
		t.Fatalf("decode scan-result: %v", err)
	}
	if len(result.Candidates) != 2 {
		t.Fatalf("candidates: want 2 got %d", len(result.Candidates))
	}
	if result.Truncated {
		t.Fatal("Truncated must be false on under-ceiling")
	}
	if result.Code != nil {
		t.Fatalf("Code must be nil on non-truncated, got %+v", result.Code)
	}

	// Watchable prefix bindings present.
	paths := binder.boundPaths("mdns")
	if len(paths) != 2 {
		t.Fatalf("expected 2 watchable bindings, got %d (paths=%v)", len(paths), paths)
	}
	for _, p := range paths {
		if !strings.HasPrefix(p, "system/discovery/candidate/mdns/") {
			t.Fatalf("binding path %q not under watchable prefix", p)
		}
	}
}

// -----------------------------------------------------------------------
// :scan §3.1 truncation — MUST surface, NOT silent (§8.4 MUST NOT)
// -----------------------------------------------------------------------

func TestScanOverflowSurfacesTruncatedAndCode(t *testing.T) {
	h := NewHandler()
	h.SetupStore(newMemBinder())
	h.SetScanCeiling(3)
	// 5 candidates > 3 ceiling.
	stub := newStubBackend("mdns", []types.CandidateData{
		{Backend: "mdns", ObservedAt: 1},
		{Backend: "mdns", ObservedAt: 2},
		{Backend: "mdns", ObservedAt: 3},
		{Backend: "mdns", ObservedAt: 4},
		{Backend: "mdns", ObservedAt: 5},
	})
	h.RegisterBackend(stub)

	resp, err := h.Handle(context.Background(), makeScanReq(t, "mdns"))
	if err != nil || resp.Status != 200 {
		t.Fatalf("Handle: err=%v status=%d", err, resp.Status)
	}
	result, _ := types.ScanResultDataFromEntity(resp.Result)
	if !result.Truncated {
		t.Fatal("§3.1 MUST surface truncated: true on over-ceiling")
	}
	if result.Code == nil || *result.Code != types.DiscoveryErrScanOverflow {
		t.Fatalf("Code: want %q got %+v", types.DiscoveryErrScanOverflow, result.Code)
	}
	if len(result.Candidates) != 3 {
		t.Fatalf("snapshot truncated to ceiling: want 3 got %d", len(result.Candidates))
	}
}

// -----------------------------------------------------------------------
// :scan unknown-backend → 400 unknown_backend (§3.3 Ruling-5 erratum:
// V7 §3.3 maps unknown enum value to 400; backend is a
// parameter value, not a resource path)
// -----------------------------------------------------------------------

func TestScanUnknownBackendIs400(t *testing.T) {
	h := NewHandler()
	h.SetupStore(newMemBinder())
	resp, err := h.Handle(context.Background(), makeScanReq(t, "qr"))
	if err != nil {
		t.Fatalf("Handle: %v", err)
	}
	if resp.Status != 400 {
		t.Fatalf("status: want 400 (unknown_backend), got %d", resp.Status)
	}
}

// -----------------------------------------------------------------------
// :announce + :announce-stop symmetric lifecycle
// -----------------------------------------------------------------------

func TestAnnounceAndAnnounceStop(t *testing.T) {
	h := NewHandler()
	h.SetupStore(newMemBinder())
	stub := newStubBackend("mdns", nil)
	h.RegisterBackend(stub)

	// announce
	annData := types.AnnounceRequestData{Backend: "mdns", ProfileRef: "profile-http-poll"}
	annEnt, _ := annData.ToEntity()
	resp, err := h.Handle(context.Background(), &handler.Request{
		Operation: OpAnnounce,
		Params:    annEnt,
		Context:   &handler.HandlerContext{HandlerPattern: HandlerPattern},
	})
	if err != nil || resp.Status != 200 {
		t.Fatalf("announce: err=%v status=%d", err, resp.Status)
	}
	if len(stub.announceCalls) != 1 || stub.announceCalls[0] != "profile-http-poll" {
		t.Fatalf("backend.Announce not invoked: %v", stub.announceCalls)
	}

	// announce-stop
	stopData := types.AnnounceStopRequestData{Backend: "mdns", ProfileRef: "profile-http-poll"}
	stopEnt, _ := stopData.ToEntity()
	resp, err = h.Handle(context.Background(), &handler.Request{
		Operation: OpAnnounceStop,
		Params:    stopEnt,
		Context:   &handler.HandlerContext{HandlerPattern: HandlerPattern},
	})
	if err != nil || resp.Status != 200 {
		t.Fatalf("announce-stop: err=%v status=%d", err, resp.Status)
	}
	if len(stub.stopCalls) != 1 || stub.stopCalls[0] != "profile-http-poll" {
		t.Fatalf("backend.AnnounceStop not invoked: %v", stub.stopCalls)
	}
}

// -----------------------------------------------------------------------
// observe/reap callbacks — §3.0 reactive-default watchable prefix
// -----------------------------------------------------------------------

func TestObserveAndReapCallbacksPushToWatchablePrefix(t *testing.T) {
	h := NewHandler()
	binder := newMemBinder()
	h.SetupStore(binder)
	stub := newStubBackend("mdns", nil)
	h.RegisterBackend(stub)

	cd := types.CandidateData{Backend: "mdns", ObservedAt: 1_730_000_000_000}
	stub.pushObserve(cd)

	ent, _ := cd.ToEntity()
	paths := binder.boundPaths("mdns")
	if len(paths) != 1 {
		t.Fatalf("observe → expected 1 watchable binding, got %d", len(paths))
	}
	want := types.CandidateStoragePath("mdns", ent.ContentHash)
	if paths[0] != want {
		t.Fatalf("binding path: want %q got %q", want, paths[0])
	}

	// reap removes from watchable prefix (store entity retained per §7).
	stub.pushReap(ent.ContentHash)
	if got := binder.boundPaths("mdns"); len(got) != 0 {
		t.Fatalf("reap → expected 0 watchable bindings, got %d (%v)", len(got), got)
	}
	if _, ok := binder.Get(ent.ContentHash); !ok {
		t.Fatal("§7: historical candidate entity must be retained in store after reap")
	}
}

// -----------------------------------------------------------------------
// PromoteSuccessor — §2.2 successor candidate pattern
// -----------------------------------------------------------------------

func TestPromoteSuccessorTOFUPath(t *testing.T) {
	h := NewHandler()
	binder := newMemBinder()
	h.SetupStore(binder)
	h.RegisterBackend(newStubBackend("mdns", nil))

	// Original: TOFU (no identity_hint).
	original := types.CandidateData{Backend: "mdns", ObservedAt: 1_730_000_000_000}
	originalEnt, _ := original.ToEntity()
	if err := binder.Bind("mdns", originalEnt); err != nil {
		t.Fatalf("seed original: %v", err)
	}

	// IDENTIFY came back with a peer-id; supply the claim.
	claim := types.IdentityClaimData{
		PeerID:          "2KAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
		KeyType:         1,
		HashType:        0,
		PublicKeyDigest: []byte{0x01, 0x02, 0x03, 0x04},
	}
	successorHash, err := h.PromoteSuccessor(originalEnt.ContentHash, claim.PeerID, claim)
	if err != nil {
		t.Fatalf("PromoteSuccessor (TOFU): %v", err)
	}

	successorEnt, ok := binder.Get(successorHash)
	if !ok {
		t.Fatal("successor entity not in store")
	}
	successor, _ := types.CandidateDataFromEntity(successorEnt)
	if successor.PeerID != claim.PeerID {
		t.Fatalf("successor peer_id: want %q got %q", claim.PeerID, successor.PeerID)
	}
	if successor.Supersedes == nil || *successor.Supersedes != originalEnt.ContentHash {
		t.Fatalf("successor must supersede original (%x), got %+v", originalEnt.ContentHash.Bytes(), successor.Supersedes)
	}
	if successor.IdentityHint != nil {
		t.Fatal("TOFU successor must preserve nil identity_hint")
	}

	// Both bound under watchable prefix (original retained as observation
	// record per §2.2; successor is chain head).
	paths := binder.boundPaths("mdns")
	if len(paths) != 2 {
		t.Fatalf("expected original + successor both bound, got %d paths: %v", len(paths), paths)
	}
}

func TestPromoteSuccessorIdentityHintMatch(t *testing.T) {
	h := NewHandler()
	binder := newMemBinder()
	h.SetupStore(binder)
	h.RegisterBackend(newStubBackend("mdns", nil))

	// Compute the expected hint by building the claim first.
	claim := types.IdentityClaimData{
		PeerID:          "2KBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB",
		KeyType:         1,
		HashType:        0,
		PublicKeyDigest: []byte{0xAA, 0xBB, 0xCC, 0xDD},
	}
	claimEnt, _ := claim.ToEntity()
	hint := claimEnt.ContentHash

	original := types.CandidateData{
		Backend:      "mdns",
		ObservedAt:   1_730_000_000_000,
		IdentityHint: &hint,
	}
	originalEnt, _ := original.ToEntity()
	if err := binder.Bind("mdns", originalEnt); err != nil {
		t.Fatalf("seed: %v", err)
	}

	if _, err := h.PromoteSuccessor(originalEnt.ContentHash, claim.PeerID, claim); err != nil {
		t.Fatalf("PromoteSuccessor (matching hint): %v", err)
	}
}

func TestPromoteSuccessorIdentityHintMismatchFailsClosed(t *testing.T) {
	h := NewHandler()
	binder := newMemBinder()
	h.SetupStore(binder)
	h.RegisterBackend(newStubBackend("mdns", nil))

	// Candidate advertised a hint that does NOT match the actual claim's
	// content_hash — §2.2.1 + §8.4 require fail-closed.
	advertised := dxFakeHashLocal(0xFE)
	original := types.CandidateData{
		Backend:      "mdns",
		ObservedAt:   1_730_000_000_000,
		IdentityHint: &advertised,
	}
	originalEnt, _ := original.ToEntity()
	binder.Bind("mdns", originalEnt)

	actualClaim := types.IdentityClaimData{
		PeerID:          "2KCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC",
		KeyType:         1,
		HashType:        0,
		PublicKeyDigest: []byte{0x11, 0x22}, // hash will not match `advertised`.
	}

	_, err := h.PromoteSuccessor(originalEnt.ContentHash, actualClaim.PeerID, actualClaim)
	if err == nil {
		t.Fatal("§2.2.1 + §8.4: identity_hint mismatch MUST fail closed; got nil error")
	}
	if !strings.Contains(err.Error(), "identity_hint mismatch") {
		t.Fatalf("expected fail-closed error to surface mismatch, got: %v", err)
	}

	// Watchable prefix has ONLY the original (no successor was minted).
	paths := binder.boundPaths("mdns")
	if len(paths) != 1 {
		t.Fatalf("fail-closed: successor MUST NOT have been bound; paths=%v", paths)
	}
}

// -----------------------------------------------------------------------
// Manifest shape gate
// -----------------------------------------------------------------------

func TestManifestShape(t *testing.T) {
	h := NewHandler()
	m := h.Manifest()
	if m.Pattern != HandlerPattern {
		t.Fatalf("manifest pattern: want %q got %q", HandlerPattern, m.Pattern)
	}
	for _, op := range []string{OpScan, OpAnnounce, OpAnnounceStop} {
		if _, ok := m.Operations[op]; !ok {
			t.Errorf("manifest missing op %q", op)
		}
	}
	if m.Operations[OpScan].InputType != types.TypeDiscoveryScanRequest {
		t.Errorf("scan input_type: want %q got %q",
			types.TypeDiscoveryScanRequest, m.Operations[OpScan].InputType)
	}
	if m.Operations[OpScan].OutputType != types.TypeDiscoveryScanResult {
		t.Errorf("scan output_type: want %q got %q",
			types.TypeDiscoveryScanResult, m.Operations[OpScan].OutputType)
	}
}

// keep the entity import live (used in binder_test.go).
var _ entity.Entity
