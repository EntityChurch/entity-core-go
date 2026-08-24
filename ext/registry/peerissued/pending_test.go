package peerissued

import (
	"context"
	"testing"

	"go.entitychurch.org/entity-core-go/core/crypto"
	"go.entitychurch.org/entity-core-go/core/entity"
	"go.entitychurch.org/entity-core-go/core/handler"
	"go.entitychurch.org/entity-core-go/core/hash"
	"go.entitychurch.org/entity-core-go/core/types"
)

// EXTENSION-REGISTRY v1.3 §6a.9.3 — the manual-approval path.
//
// Vectors: REG-PENDING-HANDLE-1 (the 202's handle resolves, and the
// by-request pointer resolves to the same body) and REG-PENDING-DECIDE-1
// (approve issues + leaves an `approved` head; deny leaves a `denied` head
// and publishes NOTHING; a second decision is 409 already_decided; a
// superseding request leaves exactly one head).
//
// GUIDE-CONFORMANCE §2.4a: the NEGATIVE half is the load-bearing one in every
// pair below. A deny that silently issued the binding passes an outcome-only
// check, which is exactly why `deny_publishes_nothing` asserts that the name
// does not resolve rather than asserting the response body.

// --- helpers -------------------------------------------------------------

// manualIssuer builds an Issuer armed in `manual` mode with a fixed clock, so
// queued_at is deterministic and the retention window is testable without
// sleeping.
func manualIssuer(t *testing.T, now *uint64, opts ...IssuerOption) (*Issuer, *handler.HandlerContext) {
	t.Helper()
	registryKP, _, _ := newRegistry(t)
	opts = append([]IssuerOption{WithIssuerClock(func() uint64 { return *now })}, opts...)
	iss, hctx := newIssuer(t, registryKP, opts...)
	installPolicy(t, hctx, types.IssuerPolicyData{Mode: types.IssuerPolicyModeManual})
	return iss, hctx
}

// queue drives one manual-mode register-request through to its 202 and
// returns the pending_hash it handed back.
func queue(t *testing.T, iss *Issuer, hctx *handler.HandlerContext,
	publisher crypto.Keypair, name string, nonce []byte, issuedAt uint64) hash.Hash {
	t.Helper()
	reqEnt := stageRequest(t, hctx, publisher, types.RegistryRegisterRequestData{
		Name:         name,
		TargetPeerID: string(publisher.PeerID()),
		Nonce:        nonce,
		IssuedAt:     issuedAt,
	})
	resp := dispatchRegister(t, iss, hctx, reqEnt)
	if resp.Status != 202 {
		t.Fatalf("manual-mode register: want 202 got %d", resp.Status)
	}
	result, err := types.RegistryRegisterResultDataFromEntity(resp.Result)
	if err != nil {
		t.Fatalf("decode register-result: %v", err)
	}
	if result.Status != types.RegisterStatusPendingReview {
		t.Fatalf("202 status: want %q got %q", types.RegisterStatusPendingReview, result.Status)
	}
	if result.PendingHash == nil {
		t.Fatal("202 carried no pending_hash — §6a.9 MUST")
	}
	// The distinctness half of REG-PENDING-HANDLE-1, asserted at the source:
	// a handle the client computed before dispatching is not a handle.
	if *result.PendingHash == reqEnt.ContentHash {
		t.Fatal("pending_hash equals the request's own content_hash — names nothing fetchable")
	}
	return *result.PendingHash
}

func dispatchDecision(t *testing.T, iss *Issuer, hctx *handler.HandlerContext,
	op string, ph hash.Hash, reason *string) *handler.Response {
	t.Helper()
	d := types.RegistryDecisionRequestData{PendingHash: ph, Reason: reason}
	var (
		ent entity.Entity
		err error
	)
	if op == OpApproveRequest {
		ent, err = d.ToApproveEntity()
	} else {
		ent, err = d.ToDenyEntity()
	}
	if err != nil {
		t.Fatalf("encode %s: %v", op, err)
	}
	resp, err := iss.Handle(context.Background(), &handler.Request{
		Path:      IssuerHandlerPattern,
		Operation: op,
		Params:    ent,
		Context:   hctx,
	})
	if err != nil {
		t.Fatalf("Handle %s: %v", op, err)
	}
	if resp == nil {
		t.Fatalf("Handle %s: nil response", op)
	}
	return resp
}

// readPending fetches the pending-binding a hash names, through the body
// pointer — the same indirection the handler uses.
func readPending(t *testing.T, hctx *handler.HandlerContext, ph hash.Hash) types.PendingBindingData {
	t.Helper()
	stored, ok := hctx.LocationIndex.Get(types.PendingBindingPath(ph))
	if !ok {
		t.Fatalf("no pending-binding published at %s", types.PendingBindingPath(ph))
	}
	if stored != ph {
		t.Fatalf("body path %s resolves to a different hash", types.PendingBindingPath(ph))
	}
	ent, ok := hctx.Store.Get(ph)
	if !ok {
		t.Fatalf("pending-binding body is dangling at %s", types.PendingBindingPath(ph))
	}
	if ent.Type != types.TypeRegistryPendingBinding {
		t.Fatalf("pending-binding type: want %q got %q", types.TypeRegistryPendingBinding, ent.Type)
	}
	d, err := types.PendingBindingDataFromEntity(ent)
	if err != nil {
		t.Fatalf("decode pending-binding: %v", err)
	}
	return d
}

func newPublisher(t *testing.T) crypto.Keypair {
	t.Helper()
	kp, err := crypto.Generate()
	if err != nil {
		t.Fatalf("publisher keypair: %v", err)
	}
	return kp
}

// --- REG-PENDING-HANDLE-1 ------------------------------------------------

// The 202's pending_hash MUST resolve to a system/registry/pending-binding
// whose status is pending_review, and the by-request pointer MUST resolve to
// the SAME body.
//
// The resolvability half is what §6a.9.3 made assertable and is the reason
// the section exists: before it, a handle naming nothing fetchable was
// indistinguishable from a conformant one.
func TestPendingHandle_ResolvesAndPointerAgrees(t *testing.T) {
	now := uint64(1_700_000_000_000)
	iss, hctx := manualIssuer(t, &now)
	publisher := newPublisher(t)

	ph := queue(t, iss, hctx, publisher, "billslab.com", []byte{1, 2, 3, 4}, now)

	pending := readPending(t, hctx, ph)
	if pending.Status != types.PendingStatusPendingReview {
		t.Fatalf("queued status: want %q got %q", types.PendingStatusPendingReview, pending.Status)
	}
	if pending.Name != "billslab.com" {
		t.Fatalf("queued name: want billslab.com got %q", pending.Name)
	}
	if pending.TargetPeerID != string(publisher.PeerID()) {
		t.Fatalf("queued target_peer_id: want %s got %s", publisher.PeerID(), pending.TargetPeerID)
	}
	if pending.QueuedAt != now {
		t.Fatalf("queued_at: want %d got %d", now, pending.QueuedAt)
	}
	if pending.BindingHash != nil {
		t.Fatal("a pending_review head must not carry binding_hash")
	}

	// The pointer half — a requester that no longer holds the 202 finds its
	// own queued request by (target_peer_id, name) and lands on the same body.
	pointerPath := types.PendingBindingByRequestPath(string(publisher.PeerID()), "billslab.com")
	head, ok := hctx.LocationIndex.Get(pointerPath)
	if !ok {
		t.Fatalf("no by-request pointer at %s — a requester that lost the 202 cannot poll", pointerPath)
	}
	if head != ph {
		t.Fatalf("by-request pointer names %v, 202 handed back %v — they must be the same body", head, ph)
	}

	// Negative half: queueing publishes NO binding. The whole point of manual
	// mode is that nothing was signed.
	if _, exists := hctx.LocationIndex.Get(types.PeerIssuedByNamePath("billslab.com")); exists {
		t.Fatal("manual-mode queue published a binding — mode defeated")
	}
}

// The pointer path puts target_peer_id BEFORE name, normatively, so that
// `pending/by-request/{peer}/` stays enumerable at a fixed depth even when a
// name carries slashes. Asserted rather than assumed: a multi-segment name in
// a non-terminal position is the exact defect EXTENSION-NETWORK §4.1 was
// corrected for the same day, and it is invisible until a name has a slash.
func TestPendingPointer_PeerFirstKeepsPrefixEnumerable(t *testing.T) {
	peerID := "z6MkExamplePeerIdSingleSegment"
	got := types.PendingBindingByRequestPath(peerID, "deep/multi/segment.name")
	want := "system/registry/pending/by-request/" + peerID + "/deep/multi/segment.name"
	if got != want {
		t.Fatalf("pointer path: want %q got %q", want, got)
	}
	if prefix := types.PendingBindingByPeerPrefix(peerID); len(got) <= len(prefix) || got[:len(prefix)] != prefix {
		t.Fatalf("multi-segment name broke the per-peer prefix %q out of %q", prefix, got)
	}
}

// --- REG-PENDING-DECIDE-1 ------------------------------------------------

// Approve issues a binding resolvable by name AND leaves an `approved` head
// carrying the binding_hash.
func TestPendingDecide_ApproveIssuesAndLeavesApprovedHead(t *testing.T) {
	now := uint64(1_700_000_000_000)
	iss, hctx := manualIssuer(t, &now)
	publisher := newPublisher(t)

	ph := queue(t, iss, hctx, publisher, "billslab.com", []byte{1, 2, 3, 4}, now)

	resp := dispatchDecision(t, iss, hctx, OpApproveRequest, ph, nil)
	if resp.Status != 200 {
		t.Fatalf("approve status: want 200 got %d (%s)", resp.Status, decodeErrorCode(t, resp))
	}
	result, err := types.RegistryRegisterResultDataFromEntity(resp.Result)
	if err != nil {
		t.Fatalf("decode approve result: %v", err)
	}
	if result.Status != types.RegisterStatusBound {
		t.Fatalf("approve result status: want %q got %q", types.RegisterStatusBound, result.Status)
	}
	if result.BindingHash == nil {
		t.Fatal("approve returned no binding_hash")
	}

	// The binding resolves by name.
	bound, ok := hctx.LocationIndex.Get(types.PeerIssuedByNamePath("billslab.com"))
	if !ok {
		t.Fatal("approve did not publish a by-name binding")
	}
	if bound != *result.BindingHash {
		t.Fatalf("by-name pointer names %v, result said %v", bound, *result.BindingHash)
	}

	// And the head persists as `approved`, reachable through the pointer —
	// deny-is-not-a-delete's positive twin. py removes the entry here
	// (registry.py:1325, py d6cfbda); the ruling names that as the one place
	// its shape is not ratified.
	pointerPath := types.PendingBindingByRequestPath(string(publisher.PeerID()), "billslab.com")
	head, ok := hctx.LocationIndex.Get(pointerPath)
	if !ok {
		t.Fatal("approve removed the by-request pointer — the requester can no longer learn the outcome")
	}
	decided := readPending(t, hctx, head)
	if decided.Status != types.PendingStatusApproved {
		t.Fatalf("head status after approve: want %q got %q", types.PendingStatusApproved, decided.Status)
	}
	if decided.BindingHash == nil || *decided.BindingHash != *result.BindingHash {
		t.Fatal("approved head must carry the binding_hash it issued")
	}
}

// Deny leaves a `denied` head AND publishes nothing.
//
// The publishes-nothing half is the load-bearing assertion: a deny that
// silently issued the binding returns an identical response body, so an
// outcome-only check certifies the hole.
func TestPendingDecide_DenyLeavesHeadAndPublishesNothing(t *testing.T) {
	now := uint64(1_700_000_000_000)
	iss, hctx := manualIssuer(t, &now)
	publisher := newPublisher(t)

	ph := queue(t, iss, hctx, publisher, "billslab.com", []byte{1, 2, 3, 4}, now)

	reason := "not on the operator's roster"
	resp := dispatchDecision(t, iss, hctx, OpDenyRequest, ph, &reason)
	if resp.Status != 200 {
		t.Fatalf("deny status: want 200 got %d (%s)", resp.Status, decodeErrorCode(t, resp))
	}
	result, err := types.RegistryRegisterResultDataFromEntity(resp.Result)
	if err != nil {
		t.Fatalf("decode deny result: %v", err)
	}
	if result.Status != types.RegisterStatusDenied {
		t.Fatalf("deny result status: want %q got %q", types.RegisterStatusDenied, result.Status)
	}
	if result.BindingHash != nil {
		t.Fatal("deny returned a binding_hash — nothing was signed")
	}

	// NOTHING published.
	if _, exists := hctx.LocationIndex.Get(types.PeerIssuedByNamePath("billslab.com")); exists {
		t.Fatal("deny published a binding — the name resolves after a refusal")
	}

	// Deny is NOT a delete: the head persists with status denied, or a
	// requester polling a vanished pointer cannot tell `denied` from `never
	// received` — a silent drop.
	pointerPath := types.PendingBindingByRequestPath(string(publisher.PeerID()), "billslab.com")
	head, ok := hctx.LocationIndex.Get(pointerPath)
	if !ok {
		t.Fatal("deny removed the by-request pointer — denied is now indistinguishable from never-received")
	}
	decided := readPending(t, hctx, head)
	if decided.Status != types.PendingStatusDenied {
		t.Fatalf("head status after deny: want %q got %q", types.PendingStatusDenied, decided.Status)
	}
	if decided.Reason == nil || *decided.Reason != reason {
		t.Fatal("denied head dropped the operator's reason")
	}
}

// A second decision on either outcome returns 409 already_decided — approve
// and deny are not idempotent-by-replay, and re-approving would mint a SECOND
// binding for one request.
func TestPendingDecide_SecondDecisionIsAlreadyDecided(t *testing.T) {
	for _, tc := range []struct{ first, second string }{
		{OpApproveRequest, OpApproveRequest},
		{OpApproveRequest, OpDenyRequest},
		{OpDenyRequest, OpDenyRequest},
		{OpDenyRequest, OpApproveRequest},
	} {
		t.Run(tc.first+"_then_"+tc.second, func(t *testing.T) {
			now := uint64(1_700_000_000_000)
			iss, hctx := manualIssuer(t, &now)
			publisher := newPublisher(t)
			ph := queue(t, iss, hctx, publisher, "billslab.com", []byte{1, 2, 3, 4}, now)

			if resp := dispatchDecision(t, iss, hctx, tc.first, ph, nil); resp.Status != 200 {
				t.Fatalf("first decision (%s): want 200 got %d", tc.first, resp.Status)
			}
			// The head moved, so the replayed decision names a superseded
			// hash. Re-read the current head and decide THAT — otherwise this
			// test would be measuring supersession, not already-decided.
			pointerPath := types.PendingBindingByRequestPath(string(publisher.PeerID()), "billslab.com")
			head, ok := hctx.LocationIndex.Get(pointerPath)
			if !ok {
				t.Fatal("head vanished after the first decision")
			}
			resp := dispatchDecision(t, iss, hctx, tc.second, head, nil)
			if resp.Status != 409 {
				t.Fatalf("second decision (%s): want 409 got %d", tc.second, resp.Status)
			}
			if code := decodeErrorCode(t, resp); code != types.RegistryErrAlreadyDecided {
				t.Fatalf("second decision code: want %q got %q", types.RegistryErrAlreadyDecided, code)
			}
		})
	}
}

// A superseding request leaves exactly ONE head for the pair, and the 202
// carries the NEW pending_hash.
func TestPendingDecide_SupersessionLeavesOneHead(t *testing.T) {
	now := uint64(1_700_000_000_000)
	iss, hctx := manualIssuer(t, &now)
	publisher := newPublisher(t)

	first := queue(t, iss, hctx, publisher, "billslab.com", []byte{1, 2, 3, 4}, now)
	now += 5_000
	second := queue(t, iss, hctx, publisher, "billslab.com", []byte{5, 6, 7, 8}, now)

	if first == second {
		t.Fatal("a superseding request returned the same pending_hash — queued_at should differ")
	}

	pointerPath := types.PendingBindingByRequestPath(string(publisher.PeerID()), "billslab.com")
	head, ok := hctx.LocationIndex.Get(pointerPath)
	if !ok {
		t.Fatal("no by-request head after supersession")
	}
	if head != second {
		t.Fatalf("by-request head names %v, want the newer %v", head, second)
	}

	// Exactly one head for the pair — a retry (fresh nonce, so a distinct
	// request by construction) must not fill the operator's queue with
	// duplicates of one intent.
	if n := hctx.LocationIndex.LenPrefix(types.PendingBindingByPeerPrefix(string(publisher.PeerID()))); n != 1 {
		t.Fatalf("by-request heads for the pair: want 1 got %d", n)
	}
}

// A superseded head is NOT decidable. Its body stays fetchable forever (it is
// content-addressed and kept for audit), so without this the operator could
// approve stale terms and leave the pointer naming a different head than the
// one that was decided.
func TestPendingDecide_SupersededHeadIsNotDecidable(t *testing.T) {
	now := uint64(1_700_000_000_000)
	iss, hctx := manualIssuer(t, &now)
	publisher := newPublisher(t)

	stale := queue(t, iss, hctx, publisher, "billslab.com", []byte{1, 2, 3, 4}, now)
	now += 5_000
	queue(t, iss, hctx, publisher, "billslab.com", []byte{5, 6, 7, 8}, now)

	// The stale body is still fetchable — that is what makes this reachable.
	if _, ok := hctx.LocationIndex.Get(types.PendingBindingPath(stale)); !ok {
		t.Fatal("superseded body was removed — supersession must move only the pointer")
	}

	resp := dispatchDecision(t, iss, hctx, OpApproveRequest, stale, nil)
	if resp.Status != 404 {
		t.Fatalf("approving a superseded head: want 404 got %d", resp.Status)
	}
	if _, exists := hctx.LocationIndex.Get(types.PeerIssuedByNamePath("billslab.com")); exists {
		t.Fatal("approving a superseded head issued a binding")
	}
}

// The queue is not a reservation: if the name was bound by someone else
// between queue and approval, approve MUST answer 409 name_taken rather than
// silently overwriting a live binding.
func TestPendingDecide_ApproveNameTakenSinceQueue(t *testing.T) {
	now := uint64(1_700_000_000_000)
	iss, hctx := manualIssuer(t, &now)
	publisher := newPublisher(t)

	ph := queue(t, iss, hctx, publisher, "billslab.com", []byte{1, 2, 3, 4}, now)

	// Someone else's binding lands on the name while the request sits in the
	// queue. Simulated by publishing the by-name pointer directly — the mode
	// under test is the approval path, not how the competing binding arrived.
	other := newPublisher(t)
	if _, err := iss.issueBinding(hctx, "billslab.com", string(other.PeerID()), nil, nil); err != nil {
		t.Fatalf("stage competing binding: %v", err)
	}
	winner, _ := hctx.LocationIndex.Get(types.PeerIssuedByNamePath("billslab.com"))

	resp := dispatchDecision(t, iss, hctx, OpApproveRequest, ph, nil)
	if resp.Status != 409 {
		t.Fatalf("approve into a taken name: want 409 got %d", resp.Status)
	}
	if code := decodeErrorCode(t, resp); code != types.RegistryErrNameTaken {
		t.Fatalf("code: want %q got %q", types.RegistryErrNameTaken, code)
	}
	// The live binding is untouched.
	if got, _ := hctx.LocationIndex.Get(types.PeerIssuedByNamePath("billslab.com")); got != winner {
		t.Fatal("a refused approval overwrote the live binding")
	}
}

// A decision on a hash that names no published pending-binding is 404.
func TestPendingDecide_UnknownHandleIsNotFound(t *testing.T) {
	now := uint64(1_700_000_000_000)
	iss, hctx := manualIssuer(t, &now)

	bogus, err := types.PendingBindingData{
		Name: "never.queued", TargetPeerID: "zNobody", QueuedAt: now,
		Status: types.PendingStatusPendingReview,
	}.ToEntity()
	if err != nil {
		t.Fatalf("encode unqueued pending: %v", err)
	}
	// In the STORE but never PUBLISHED — a well-formed body this registry
	// never minted (an ingested envelope, a body copied from another peer's
	// tree). A store-only lookup would happily approve it, which is why the
	// handler resolves through the published body pointer instead.
	if _, err := hctx.Store.Put(bogus); err != nil {
		t.Fatalf("stage unpublished body: %v", err)
	}
	resp := dispatchDecision(t, iss, hctx, OpApproveRequest, bogus.ContentHash, nil)
	if resp.Status != 404 {
		t.Fatalf("unknown pending_hash: want 404 got %d", resp.Status)
	}
	if code := decodeErrorCode(t, resp); code != types.RegistryErrNotFound {
		t.Fatalf("code: want %q got %q", types.RegistryErrNotFound, code)
	}
}

// --- retention (§6a.9.3 [SHOULD]) ----------------------------------------

// A DECIDED head becomes GC-eligible after the retention window; the body
// survives (content-addressed and auditable independently of the pointer).
// A pending_review head is NEVER eligible — expiring live queue state would
// silently drop a request no operator has seen.
func TestPendingRetention_CollectsDecidedNotPending(t *testing.T) {
	now := uint64(1_700_000_000_000)
	const window = uint64(60_000)
	iss, hctx := manualIssuer(t, &now, WithPendingRetention(window))

	decidedPub := newPublisher(t)
	ph := queue(t, iss, hctx, decidedPub, "decided.example", []byte{1, 1, 1, 1}, now)
	if resp := dispatchDecision(t, iss, hctx, OpDenyRequest, ph, nil); resp.Status != 200 {
		t.Fatalf("deny: want 200 got %d", resp.Status)
	}
	decidedHead, _ := hctx.LocationIndex.Get(
		types.PendingBindingByRequestPath(string(decidedPub.PeerID()), "decided.example"))

	livePub := newPublisher(t)
	liveHash := queue(t, iss, hctx, livePub, "live.example", []byte{2, 2, 2, 2}, now)

	// Past the window, and drive the opportunistic sweep with a third queue.
	now += window + 1
	sweepPub := newPublisher(t)
	queue(t, iss, hctx, sweepPub, "sweep.example", []byte{3, 3, 3, 3}, now)

	if _, ok := hctx.LocationIndex.Get(
		types.PendingBindingByRequestPath(string(decidedPub.PeerID()), "decided.example")); ok {
		t.Fatal("a decided head outlived its retention window")
	}
	// The body survives the pointer.
	if _, ok := hctx.Store.Get(decidedHead); !ok {
		t.Fatal("retention GC destroyed the decided body — it must stay auditable")
	}
	// Live queue state is untouched, even though it is older than the window.
	if head, ok := hctx.LocationIndex.Get(
		types.PendingBindingByRequestPath(string(livePub.PeerID()), "live.example")); !ok || head != liveHash {
		t.Fatal("retention GC collected a pending_review head — live queue state is never GC-eligible")
	}
}

// --- capability separation ------------------------------------------------

// A publisher that can call register-request MUST NOT be able to approve its
// own queued request — that turns `manual` into `open` with extra steps.
func TestPendingDecide_GrantsAreSeparate(t *testing.T) {
	for _, g := range RequestBindingSeedGrants() {
		for _, op := range g.Operations.Include {
			if op == OpApproveRequest || op == OpDenyRequest {
				t.Fatalf("RequestBindingSeedGrants grants %q to publishers — §6a.9.3 gates it "+
					"behind registry-issue-binding (operator-only)", op)
			}
		}
	}
	found := map[string]bool{}
	for _, g := range IssueBindingSeedGrants() {
		for _, op := range g.Operations.Include {
			found[op] = true
		}
	}
	if !found[OpApproveRequest] || !found[OpDenyRequest] {
		t.Fatalf("IssueBindingSeedGrants must cover both decision ops, got %v", found)
	}
}
