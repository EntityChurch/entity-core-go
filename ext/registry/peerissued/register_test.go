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

// Per EXTENSION-REGISTRY §6a.9 conformance vectors:
//   REG-REGISTER-PROOF-1   — signature not by target_peer_id → rejected.
//   REG-REGISTER-POLICY-1  — allowlist reject → not_entitled; allow-listed →
//                            issued + resolvable through the same registry.
//   REG-REGISTER-REPLAY-1  — same nonce twice → rejected.
// Domain-control (REG-REGISTER-DOMAINCTRL-1) is DEFERRED per §6a.10 — the
// v1 issuer rejects the mode itself.

// --- helpers -------------------------------------------------------------

// newIssuer builds an Issuer and a HandlerContext whose store/index the
// registry will publish into.
func newIssuer(t *testing.T, kp crypto.Keypair, opts ...IssuerOption) (*Issuer, *handler.HandlerContext) {
	t.Helper()
	iss, err := NewIssuer(kp, opts...)
	if err != nil {
		t.Fatalf("NewIssuer: %v", err)
	}
	hctx := newHctx(t, kp.PeerID())
	return iss, hctx
}

// stageRequest builds a register-request entity, signs it with `signerKP`,
// and seeds the registry's hctx with both (so the §6a.9 layer-1 lookup
// finds the ownership-proof signature at the invariant pointer). Returns
// the request entity for handler dispatch.
//
// signerKP is whose key signs the request — REG-REGISTER-PROOF-1 passes a
// DIFFERENT keypair than the request's target_peer_id to assert rejection.
func stageRequest(
	t *testing.T,
	hctx *handler.HandlerContext,
	signerKP crypto.Keypair,
	body types.RegistryRegisterRequestData,
) entity.Entity {
	t.Helper()
	reqEnt, err := body.ToEntity()
	if err != nil {
		t.Fatalf("encode register-request: %v", err)
	}
	if _, err := hctx.Store.Put(reqEnt); err != nil {
		t.Fatalf("store register-request: %v", err)
	}
	sigBytes := signerKP.Sign(reqEnt.ContentHash.Bytes())
	signerIdentity, err := signerKP.IdentityEntity()
	if err != nil {
		t.Fatalf("signer identity: %v", err)
	}
	sigData := types.SignatureData{
		Target:    reqEnt.ContentHash,
		Signer:    signerIdentity.ContentHash,
		Algorithm: signerIdentity.Type,
		Signature: sigBytes,
	}
	sigEnt, err := sigData.ToEntity()
	if err != nil {
		t.Fatalf("encode register-request signature: %v", err)
	}
	if _, err := hctx.Store.Put(sigEnt); err != nil {
		t.Fatalf("store register-request signature: %v", err)
	}
	if err := hctx.LocationIndex.Set(types.LocalSignaturePath(reqEnt.ContentHash), sigEnt.ContentHash); err != nil {
		t.Fatalf("set signature pointer: %v", err)
	}
	return reqEnt
}

func dispatchRegister(t *testing.T, iss *Issuer, hctx *handler.HandlerContext, reqEnt entity.Entity) *handler.Response {
	t.Helper()
	resp, err := iss.Handle(context.Background(), &handler.Request{
		Path:      IssuerHandlerPattern,
		Operation: OpRegisterRequest,
		Params:    reqEnt,
		Context:   hctx,
	})
	if err != nil {
		t.Fatalf("Handle: %v", err)
	}
	if resp == nil {
		t.Fatalf("Handle: nil response")
	}
	return resp
}

func decodeErrorCode(t *testing.T, resp *handler.Response) string {
	t.Helper()
	if resp.Result.Type != types.TypeError {
		t.Fatalf("expected error result type %q, got %q", types.TypeError, resp.Result.Type)
	}
	ed, err := types.ErrorDataFromEntity(resp.Result)
	if err != nil {
		t.Fatalf("decode error: %v", err)
	}
	return ed.Code
}

// installPolicy writes an issuer-policy entity at the canonical store path
// so the Issuer's loadPolicy picks it up.
func installPolicy(t *testing.T, hctx *handler.HandlerContext, p types.IssuerPolicyData) {
	t.Helper()
	ent, err := p.ToEntity()
	if err != nil {
		t.Fatalf("encode issuer-policy: %v", err)
	}
	if _, err := hctx.Store.Put(ent); err != nil {
		t.Fatalf("store issuer-policy: %v", err)
	}
	if err := hctx.LocationIndex.Set(types.IssuerPolicyStoragePath, ent.ContentHash); err != nil {
		t.Fatalf("set issuer-policy: %v", err)
	}
}

// --- REG-REGISTER-PROOF-1 ------------------------------------------------

// Layer-1 ownership-proof failure: the request is signed by a key that is
// NOT the request's declared target_peer_id. The issuer MUST reject with
// signature_invalid; no binding is published.
func TestRegister_ProofFailure_SignerNotTarget(t *testing.T) {
	registryKP, _, _ := newRegistry(t)
	iss, hctx := newIssuer(t, registryKP)

	// Two distinct publisher identities: the request's target_peer_id is
	// publisherA, but the request is signed by publisherB.
	publisherA, err := crypto.Generate()
	if err != nil {
		t.Fatalf("publisherA: %v", err)
	}
	publisherB, err := crypto.Generate()
	if err != nil {
		t.Fatalf("publisherB: %v", err)
	}

	body := types.RegistryRegisterRequestData{
		Name:         "billslab.com",
		TargetPeerID: string(publisherA.PeerID()),
		Nonce:        []byte{0x01, 0x02, 0x03, 0x04},
		IssuedAt:     1_000_000,
	}
	reqEnt := stageRequest(t, hctx, publisherB, body) // wrong signer

	resp := dispatchRegister(t, iss, hctx, reqEnt)
	if resp.Status != 401 {
		t.Fatalf("status: want 401 got %d", resp.Status)
	}
	if code := decodeErrorCode(t, resp); code != types.RegistryErrSignatureInvalid {
		t.Fatalf("error code: want %s got %s", types.RegistryErrSignatureInvalid, code)
	}
	// No binding published.
	if _, exists := hctx.LocationIndex.Get(types.PeerIssuedByNamePath("billslab.com")); exists {
		t.Fatalf("by-name pointer published on layer-1 failure")
	}
}

// --- REG-REGISTER-POLICY-1 -----------------------------------------------

// Allowlist mode: a non-allow-listed publisher is rejected (not_entitled),
// then the same registry+name+allow-listed publisher succeeds and the
// binding is resolvable through the peer-issued backend's offline path.
func TestRegister_AllowlistMode_DenyThenAllow(t *testing.T) {
	registryKP, registryEnt, registryPID := newRegistry(t)
	iss, hctx := newIssuer(t, registryKP,
		WithIssuerClock(func() uint64 { return 1_000_000 }))

	denied, _ := crypto.Generate()
	allowed, _ := crypto.Generate()

	installPolicy(t, hctx, types.IssuerPolicyData{
		Mode:      types.IssuerPolicyModeAllowlist,
		Allowlist: []string{string(allowed.PeerID())},
	})

	// (a) denied publisher → not_entitled.
	bodyDenied := types.RegistryRegisterRequestData{
		Name:         "billslab.com",
		TargetPeerID: string(denied.PeerID()),
		Nonce:        []byte{0xDE, 0xAD, 0xBE, 0xEF},
		IssuedAt:     1_000_000,
	}
	resp := dispatchRegister(t, iss, hctx, stageRequest(t, hctx, denied, bodyDenied))
	if resp.Status != 403 {
		t.Fatalf("denied: status want 403 got %d", resp.Status)
	}
	if code := decodeErrorCode(t, resp); code != types.RegistryErrNotEntitled {
		t.Fatalf("denied: code want %s got %s", types.RegistryErrNotEntitled, code)
	}
	if _, exists := hctx.LocationIndex.Get(types.PeerIssuedByNamePath("billslab.com")); exists {
		t.Fatalf("denied: by-name pointer published")
	}

	// (b) allow-listed publisher → 200 + binding hash returned + resolvable.
	bodyAllowed := types.RegistryRegisterRequestData{
		Name:         "billslab.com",
		TargetPeerID: string(allowed.PeerID()),
		Nonce:        []byte{0xCA, 0xFE, 0xBA, 0xBE},
		IssuedAt:     1_000_001,
	}
	resp = dispatchRegister(t, iss, hctx, stageRequest(t, hctx, allowed, bodyAllowed))
	if resp.Status != 200 {
		t.Fatalf("allowed: status want 200 got %d", resp.Status)
	}
	bindRes, err := types.LocalNameBindResultDataFromEntity(resp.Result)
	if err != nil {
		t.Fatalf("decode bind result: %v", err)
	}
	if (bindRes.BindingHash == hash.Hash{}) {
		t.Fatalf("bind result: zero binding_hash")
	}

	// Resolvable via the peer-issued backend with empty Reader (offline /
	// precedes path) — the registry's own publish wrote into the local
	// store, which IS the registry peer's store in this test.
	backend, err := New(registryEnt, registryPID, newFakeReader(),
		WithClock(func() uint64 { return 1_000_010 }))
	if err != nil {
		t.Fatalf("backend New: %v", err)
	}
	res, err := backend.Resolve(hctx, "billslab.com")
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if res.Status != types.ResolutionStatusResolved {
		t.Fatalf("resolve status: want resolved got %s", res.Status)
	}
	if res.PeerID != string(allowed.PeerID()) {
		t.Fatalf("resolved peer_id: want %s got %s", string(allowed.PeerID()), res.PeerID)
	}
	if res.Binding == nil || *res.Binding != bindRes.BindingHash {
		t.Fatalf("resolved binding: want %s got %v", bindRes.BindingHash, res.Binding)
	}
}

// --- REG-REGISTER-REPLAY-1 -----------------------------------------------

// Same (target_peer_id, nonce) pair issued twice within the replay window
// → second call rejected with replay_detected.
func TestRegister_ReplayDetected_SameNonceTwice(t *testing.T) {
	registryKP, _, _ := newRegistry(t)
	clk := uint64(1_000_000)
	iss, hctx := newIssuer(t, registryKP,
		WithIssuerClock(func() uint64 { return clk }))

	publisher, _ := crypto.Generate()
	body := types.RegistryRegisterRequestData{
		Name:         "billslab.com",
		TargetPeerID: string(publisher.PeerID()),
		Nonce:        []byte{0xAA, 0xBB, 0xCC, 0xDD},
		IssuedAt:     1_000_000,
	}

	resp := dispatchRegister(t, iss, hctx, stageRequest(t, hctx, publisher, body))
	if resp.Status != 200 {
		t.Fatalf("first call: status want 200 got %d", resp.Status)
	}

	// Re-stage with a fresh request entity (different content_hash via a
	// different name) but reuse the (target, nonce) pair. The §6a.9
	// replay-defense rule is keyed on (target, nonce), independent of the
	// rest of the request body — a second request reusing the pair MUST
	// be rejected even if it requests a different name.
	body2 := body
	body2.Name = "otherslab.com"
	resp2 := dispatchRegister(t, iss, hctx, stageRequest(t, hctx, publisher, body2))
	if resp2.Status != 409 {
		t.Fatalf("replay: status want 409 got %d", resp2.Status)
	}
	if code := decodeErrorCode(t, resp2); code != types.RegistryErrReplayDetected {
		t.Fatalf("replay: code want %s got %s", types.RegistryErrReplayDetected, code)
	}
}

// Bonus — REG-REGISTER-DOMAINCTRL-1 stub: requesting under domain-control
// mode MUST be rejected as not_implemented per §6a.10 (the format is
// deferred to the web-native domain-proof co-design).
func TestRegister_DomainControlMode_Deferred(t *testing.T) {
	registryKP, _, _ := newRegistry(t)
	iss, hctx := newIssuer(t, registryKP,
		WithIssuerClock(func() uint64 { return 1_000_000 }))

	installPolicy(t, hctx, types.IssuerPolicyData{
		Mode: types.IssuerPolicyModeDomainControl,
	})

	publisher, _ := crypto.Generate()
	body := types.RegistryRegisterRequestData{
		Name:         "billslab.com",
		TargetPeerID: string(publisher.PeerID()),
		Nonce:        []byte{0x01},
		IssuedAt:     1_000_000,
	}
	resp := dispatchRegister(t, iss, hctx, stageRequest(t, hctx, publisher, body))
	if resp.Status != 501 {
		t.Fatalf("domain-control: status want 501 got %d", resp.Status)
	}
	if code := decodeErrorCode(t, resp); code != "not_implemented" {
		t.Fatalf("domain-control: code want not_implemented got %s", code)
	}
}

// Open mode: the trivial default — any layer-1-valid request gets a binding.
func TestRegister_OpenMode_HappyPath(t *testing.T) {
	registryKP, _, _ := newRegistry(t)
	iss, hctx := newIssuer(t, registryKP,
		WithIssuerClock(func() uint64 { return 1_000_000 }))

	// No policy entity installed → defaults to open.
	publisher, _ := crypto.Generate()
	body := types.RegistryRegisterRequestData{
		Name:         "billslab.com",
		TargetPeerID: string(publisher.PeerID()),
		Nonce:        []byte{0x42},
		IssuedAt:     1_000_000,
	}
	resp := dispatchRegister(t, iss, hctx, stageRequest(t, hctx, publisher, body))
	if resp.Status != 200 {
		t.Fatalf("open mode: status want 200 got %d", resp.Status)
	}
}

// --- REG-RENEW-REPLAY-1 --------------------------------------------------

// Same (target_peer_id, nonce) pair issued twice on renew within the
// replay window → second call rejected with replay_detected. Validates
// the v1.2 ruling that renew is a non-idempotent state effect (replay
// extends expiry past intended lapse) and so the same nonce + issued_at
// discipline as register applies.
func TestRenew_ReplayDetected_SameNonceTwice(t *testing.T) {
	registryKP, _, _ := newRegistry(t)
	clk := uint64(1_000_000)
	iss, hctx := newIssuer(t, registryKP,
		WithIssuerClock(func() uint64 { return clk }))

	// Establish a binding to renew.
	publisher, _ := crypto.Generate()
	resp := dispatchRegister(t, iss, hctx, stageRequest(t, hctx, publisher,
		types.RegistryRegisterRequestData{
			Name:         "billslab.com",
			TargetPeerID: string(publisher.PeerID()),
			Nonce:        []byte{0x01},
			IssuedAt:     1_000_000,
		}))
	if resp.Status != 200 {
		t.Fatalf("seed register: status want 200 got %d", resp.Status)
	}
	bindRes, err := types.LocalNameBindResultDataFromEntity(resp.Result)
	if err != nil {
		t.Fatalf("decode bind-result: %v", err)
	}
	bindingHash := bindRes.BindingHash

	dispatchRenew := func(t *testing.T, body types.RegistryRenewRequestData) *handler.Response {
		t.Helper()
		ent, err := body.ToEntity()
		if err != nil {
			t.Fatalf("encode renew-request: %v", err)
		}
		r, err := iss.Handle(context.Background(), &handler.Request{
			Path:      IssuerHandlerPattern,
			Operation: OpRenewRequest,
			Params:    ent,
			Context:   hctx,
		})
		if err != nil {
			t.Fatalf("Handle renew: %v", err)
		}
		if r == nil {
			t.Fatalf("Handle renew: nil response")
		}
		return r
	}

	// First renew with a fresh nonce: 200, produces a successor binding.
	ttl := uint64(86_400_000)
	body := types.RegistryRenewRequestData{
		BindingHash: bindingHash,
		TTL:         &ttl,
		Nonce:       []byte{0xAA, 0xBB, 0xCC, 0xDD},
		IssuedAt:    1_000_001,
	}
	r1 := dispatchRenew(t, body)
	if r1.Status != 200 {
		t.Fatalf("first renew: status want 200 got %d", r1.Status)
	}
	bindRes2, err := types.LocalNameBindResultDataFromEntity(r1.Result)
	if err != nil {
		t.Fatalf("decode renew result: %v", err)
	}

	// Re-renew with the SAME (target_peer_id, nonce) pair — still inside
	// the issued_at window — must be rejected as replay even when targeting
	// a different binding_hash (the successor) and using a slightly later
	// issued_at. The replay key is (target, nonce), not the full body.
	body2 := body
	body2.BindingHash = bindRes2.BindingHash
	body2.IssuedAt = 1_000_002
	r2 := dispatchRenew(t, body2)
	if r2.Status != 409 {
		t.Fatalf("renew replay: status want 409 got %d", r2.Status)
	}
	if code := decodeErrorCode(t, r2); code != types.RegistryErrReplayDetected {
		t.Fatalf("renew replay: code want %s got %s", types.RegistryErrReplayDetected, code)
	}
}

// name_taken: a second registration under the same name MUST be rejected,
// even when both the first and second publishers are layer-1-valid.
func TestRegister_NameTaken(t *testing.T) {
	registryKP, _, _ := newRegistry(t)
	iss, hctx := newIssuer(t, registryKP,
		WithIssuerClock(func() uint64 { return 1_000_000 }))

	first, _ := crypto.Generate()
	resp := dispatchRegister(t, iss, hctx, stageRequest(t, hctx, first, types.RegistryRegisterRequestData{
		Name:         "billslab.com",
		TargetPeerID: string(first.PeerID()),
		Nonce:        []byte{0x01},
		IssuedAt:     1_000_000,
	}))
	if resp.Status != 200 {
		t.Fatalf("first: status want 200 got %d", resp.Status)
	}

	second, _ := crypto.Generate()
	resp2 := dispatchRegister(t, iss, hctx, stageRequest(t, hctx, second, types.RegistryRegisterRequestData{
		Name:         "billslab.com",
		TargetPeerID: string(second.PeerID()),
		Nonce:        []byte{0x02},
		IssuedAt:     1_000_001,
	}))
	if resp2.Status != 409 {
		t.Fatalf("name_taken: status want 409 got %d", resp2.Status)
	}
	if code := decodeErrorCode(t, resp2); code != types.RegistryErrNameTaken {
		t.Fatalf("name_taken: code want %s got %s", types.RegistryErrNameTaken, code)
	}
}
