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
	return stageProof(t, hctx, signerKP, reqEnt)
}

// stageProof is stageRequest's body, generalized over the request type.
// §6a.9 layer 1 binds all three write ops — register, renew and revoke —
// so the proof-staging step cannot stay specific to register-request.
func stageProof(
	t *testing.T,
	hctx *handler.HandlerContext,
	signerKP crypto.Keypair,
	reqEnt entity.Entity,
) entity.Entity {
	t.Helper()
	if _, err := hctx.Store.Put(reqEnt); err != nil {
		t.Fatalf("store request: %v", err)
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
	// CAP registry D11/D12: a live-registration policy MUST define default_ttl,
	// else a request omitting requested_ttl resolves to a null ttl and register
	// fails closed (403 policy_rejected). These fixtures are not about ttl, so
	// default one when the caller left it nil. The D11/D12 negative cases seed
	// their null-default_ttl policy directly (not through this helper).
	if p.DefaultTTL == nil {
		d := uint64(1_000_000_000)
		p.DefaultTTL = &d
	}
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
	// RequestedTTL is set because this policy defines no DefaultTTL, and CAP
	// registry D3 makes a null-ttl peer-issued binding unresolvable — this test
	// is about the allowlist gate, not ttl.
	reqTTL := uint64(1_000_000)
	bodyAllowed := types.RegistryRegisterRequestData{
		Name:         "billslab.com",
		TargetPeerID: string(allowed.PeerID()),
		Nonce:        []byte{0xCA, 0xFE, 0xBA, 0xBE},
		IssuedAt:     1_000_001,
		RequestedTTL: &reqTTL,
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
	installPolicy(t, hctx, types.IssuerPolicyData{Mode: types.IssuerPolicyModeOpen})

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

	// §6a.9.2: the policy entity is the ONLY source. An unarmed registry is
	// curated-only, not implicitly open — so open mode must be armed.
	installPolicy(t, hctx, types.IssuerPolicyData{Mode: types.IssuerPolicyModeOpen})

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

	installPolicy(t, hctx, types.IssuerPolicyData{Mode: types.IssuerPolicyModeOpen})

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
		// Renew is layer-1 signed by the binding's target_peer_id, so the
		// replay probe has to clear authorization first — otherwise it
		// measures the 401 and never reaches the nonce logic.
		ent = stageProof(t, hctx, publisher, ent)
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

	installPolicy(t, hctx, types.IssuerPolicyData{Mode: types.IssuerPolicyModeOpen})

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

// --- §6a.9 layer 1 on the follow-on ops -----------------------------------
//
// revoke-request and renew-request verified NOTHING. Any peer that could
// reach the registry could permanently revoke any binding in it, or extend
// any binding past its registrant's intended lapse. The validator's own
// checks certified this: they asserted 200/202 with no proof attached, so a
// peer that enforced authorization FAILED them and a peer that skipped it
// passed. Python refused to match and reported it instead — go-on-go was
// green the whole time, which is precisely why the shared probe could not
// see it.

// seedBinding registers one name and returns its binding hash, so the
// layer-1 tests below have something real to aim at.
func seedBinding(t *testing.T, iss *Issuer, hctx *handler.HandlerContext, owner crypto.Keypair, name string) hash.Hash {
	t.Helper()
	installPolicy(t, hctx, types.IssuerPolicyData{Mode: types.IssuerPolicyModeOpen})
	resp := dispatchRegister(t, iss, hctx, stageRequest(t, hctx, owner,
		types.RegistryRegisterRequestData{
			Name:         name,
			TargetPeerID: string(owner.PeerID()),
			Nonce:        []byte{0x01},
			IssuedAt:     1_000_000,
		}))
	if resp.Status != 200 {
		t.Fatalf("seed register: status want 200 got %d", resp.Status)
	}
	res, err := types.LocalNameBindResultDataFromEntity(resp.Result)
	if err != nil {
		t.Fatalf("decode bind-result: %v", err)
	}
	return res.BindingHash
}

func dispatchOp(t *testing.T, iss *Issuer, hctx *handler.HandlerContext, op string, params entity.Entity) *handler.Response {
	t.Helper()
	resp, err := iss.Handle(context.Background(), &handler.Request{
		Path:      IssuerHandlerPattern,
		Operation: op,
		Params:    params,
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

// An unsigned revoke is a permanent, un-undoable denial-of-name against a
// binding the caller does not own. It MUST be refused — and MUST NOT
// publish a revocation, since a 401 that revoked anyway is worse than an
// honest 200: it reports refusal while acting.
func TestRevoke_Unsigned_Rejected(t *testing.T) {
	registryKP, _, _ := newRegistry(t)
	iss, hctx := newIssuer(t, registryKP,
		WithIssuerClock(func() uint64 { return 1_000_000 }))
	owner, _ := crypto.Generate()
	bindingHash := seedBinding(t, iss, hctx, owner, "unsigned-revoke.com")

	revEnt, err := types.RegistryRevokeRequestData{BindingHash: bindingHash}.ToEntity()
	if err != nil {
		t.Fatalf("encode revoke-request: %v", err)
	}
	resp := dispatchOp(t, iss, hctx, OpRevokeRequest, revEnt)
	if resp.Status != 401 {
		t.Fatalf("unsigned revoke: status want 401 got %d", resp.Status)
	}
	if code := decodeErrorCode(t, resp); code != types.RegistryErrSignatureInvalid {
		t.Fatalf("unsigned revoke: code want %s got %s", types.RegistryErrSignatureInvalid, code)
	}
	if _, ok := hctx.LocationIndex.Get(types.PeerIssuedRevocationByTargetPath(bindingHash)); ok {
		t.Fatal("unsigned revoke was refused 401 but published a revocation at the by-target index anyway")
	}
}

// The proof must be by the BINDING's target_peer_id, not merely by someone.
// A well-formed signature from an unrelated peer is the realistic attack:
// every attacker has a key of their own.
func TestRevoke_SignedByStranger_Rejected(t *testing.T) {
	registryKP, _, _ := newRegistry(t)
	iss, hctx := newIssuer(t, registryKP,
		WithIssuerClock(func() uint64 { return 1_000_000 }))
	owner, _ := crypto.Generate()
	stranger, _ := crypto.Generate()
	bindingHash := seedBinding(t, iss, hctx, owner, "stranger-revoke.com")

	revEnt, err := types.RegistryRevokeRequestData{BindingHash: bindingHash}.ToEntity()
	if err != nil {
		t.Fatalf("encode revoke-request: %v", err)
	}
	revEnt = stageProof(t, hctx, stranger, revEnt)

	resp := dispatchOp(t, iss, hctx, OpRevokeRequest, revEnt)
	if resp.Status != 401 {
		t.Fatalf("stranger-signed revoke: status want 401 got %d", resp.Status)
	}
	if _, ok := hctx.LocationIndex.Get(types.PeerIssuedRevocationByTargetPath(bindingHash)); ok {
		t.Fatal("stranger-signed revoke published a revocation")
	}
}

// The positive direction, so the fix cannot be "refuse everything": the
// registrant revoking their own binding still works.
func TestRevoke_SignedByTarget_Accepted(t *testing.T) {
	registryKP, _, _ := newRegistry(t)
	iss, hctx := newIssuer(t, registryKP,
		WithIssuerClock(func() uint64 { return 1_000_000 }))
	owner, _ := crypto.Generate()
	bindingHash := seedBinding(t, iss, hctx, owner, "owner-revoke.com")

	revEnt, err := types.RegistryRevokeRequestData{BindingHash: bindingHash}.ToEntity()
	if err != nil {
		t.Fatalf("encode revoke-request: %v", err)
	}
	revEnt = stageProof(t, hctx, owner, revEnt)

	resp := dispatchOp(t, iss, hctx, OpRevokeRequest, revEnt)
	if resp.Status != 200 {
		t.Fatalf("owner revoke: status want 200 got %d", resp.Status)
	}
	if _, ok := hctx.LocationIndex.Get(types.PeerIssuedRevocationByTargetPath(bindingHash)); !ok {
		t.Fatal("owner revoke answered 200 but published no revocation at the by-target index")
	}
}

// Renew's replay defense is not authorization — it stops a CAPTURED request
// being re-run while leaving a fresh unsigned one accepted. A fresh nonce is
// exactly what an attacker supplies.
func TestRenew_Unsigned_Rejected(t *testing.T) {
	registryKP, _, _ := newRegistry(t)
	iss, hctx := newIssuer(t, registryKP,
		WithIssuerClock(func() uint64 { return 1_000_000 }))
	owner, _ := crypto.Generate()
	bindingHash := seedBinding(t, iss, hctx, owner, "unsigned-renew.com")

	renewEnt, err := types.RegistryRenewRequestData{
		BindingHash: bindingHash,
		Nonce:       []byte{0xDE, 0xAD, 0xBE, 0xEF},
		IssuedAt:    1_000_001,
	}.ToEntity()
	if err != nil {
		t.Fatalf("encode renew-request: %v", err)
	}
	resp := dispatchOp(t, iss, hctx, OpRenewRequest, renewEnt)
	if resp.Status != 401 {
		t.Fatalf("unsigned renew: status want 401 got %d", resp.Status)
	}
	if code := decodeErrorCode(t, resp); code != types.RegistryErrSignatureInvalid {
		t.Fatalf("unsigned renew: code want %s got %s", types.RegistryErrSignatureInvalid, code)
	}
}

// --- CAP registry D11 / D12: the issuer must not mint a null-ttl binding ------
//
// REG-ISSUER-NULLTTL-POLICY-1 (arch ROUTING-2026-08-18-d §1), two-stage, same
// shape as the domain-control pair: D11 refuses the policy at set-issuer-policy,
// and D12 fails closed for a policy that reached the tree out of band.

// D11 — set-issuer-policy MUST refuse a live-registration policy with no
// default_ttl (it can only mint bindings D3 makes unresolvable), and store
// nothing. Mirrors TestSetIssuerPolicy_DomainControl_400UnsupportedMode.
func TestSetIssuerPolicy_NullDefaultTTL_Refused(t *testing.T) {
	registryKP, _, _ := newRegistry(t)
	iss, hctx := newIssuer(t, registryKP)

	// dispatchSet goes through the handler (unlike installPolicy, which seeds
	// directly), so D11 gates it. Open mode, no default_ttl.
	resp := dispatchSet(t, iss, hctx, types.IssuerPolicyData{Mode: types.IssuerPolicyModeOpen})
	if resp.Status != 400 {
		t.Fatalf("null-default_ttl policy set: status want 400 got %d", resp.Status)
	}
	// Nothing stored — the registry is still unarmed.
	if getResp := dispatchGet(t, iss, hctx); getResp.Status != 404 {
		t.Fatalf("null-default_ttl policy was rejected but something was stored (get → %d)", getResp.Status)
	}
}

// D12 — a null-default_ttl policy seeded OUT OF BAND (CLI flag / direct tree
// write / predating D11) must fail register closed: a request omitting
// requested_ttl resolves to a null ttl, and the issuer refuses 403
// policy_rejected, mints nothing, and does not substitute a default.
func TestRegister_NullResolvedTTL_FailsClosed(t *testing.T) {
	registryKP, _, _ := newRegistry(t)
	iss, hctx := newIssuer(t, registryKP,
		WithIssuerClock(func() uint64 { return 1_000_000 }))

	// Seed a null-default_ttl open policy directly, bypassing D11 (this is the
	// exact path D12 exists to backstop).
	polEnt, err := types.IssuerPolicyData{Mode: types.IssuerPolicyModeOpen}.ToEntity()
	if err != nil {
		t.Fatalf("encode null-ttl policy: %v", err)
	}
	if _, err := hctx.Store.Put(polEnt); err != nil {
		t.Fatalf("store null-ttl policy: %v", err)
	}
	if err := hctx.LocationIndex.Set(types.IssuerPolicyStoragePath, polEnt.ContentHash); err != nil {
		t.Fatalf("bind null-ttl policy: %v", err)
	}

	// A request that omits requested_ttl → resolved ttl is null.
	publisher, _ := crypto.Generate()
	body := types.RegistryRegisterRequestData{
		Name:         "billslab.com",
		TargetPeerID: string(publisher.PeerID()),
		Nonce:        []byte{0x01, 0x02, 0x03, 0x04},
		IssuedAt:     1_000_000,
		// no RequestedTTL
	}
	resp := dispatchRegister(t, iss, hctx, stageRequest(t, hctx, publisher, body))
	if resp.Status != 403 {
		t.Fatalf("register against a null-ttl policy: status want 403 got %d", resp.Status)
	}
	if code := decodeErrorCode(t, resp); code != types.RegistryErrPolicyRejected {
		t.Fatalf("code want %q got %q", types.RegistryErrPolicyRejected, code)
	}
	// Nothing minted — no by-name pointer published.
	if _, exists := hctx.LocationIndex.Get(types.PeerIssuedByNamePath("billslab.com")); exists {
		t.Fatalf("a binding was published despite the null-ttl refusal (D12 must mint nothing)")
	}
}

// REG-RENEW-TTL-CASCADE-1 (REGISTRY §6a.9, v1.9; ruled from go spec-issue
// 2026-08-18-c / SA-PY-13). renew resolves ttl by a three-step cascade —
// request ttl > policy default_ttl > the superseded binding's OWN ttl (non-null
// by §6a.3) — and NEVER refuses. Three rows:
//
//	(a) explicit ttl          → successor carries it
//	(b) omit, null-default    → successor carries the PREDECESSOR's ttl (step 3)
//	(c) omit, policy default  → successor carries the POLICY's ttl, not (b)'s
//
// Row (b) fails against a null-minting peer AND a refusing peer (go's own prior
// disposition); row (c) fails against a peer that wired inherit ABOVE the policy.
// Mutation control: delete step 3 (the `existing.TTL != nil` branch in
// handleRenewRequest) → row (b) mints a null ttl and this test fails.
func TestRenew_TTLCascade(t *testing.T) {
	const predTTL = uint64(1_000_000_000) // seedBinding's defaulted policy → the predecessor's ttl

	// setPolicy overwrites the armed issuer policy directly (store-first, the
	// curated-registry path); defaultTTL==nil seeds a null-default policy.
	setPolicy := func(t *testing.T, hctx *handler.HandlerContext, defaultTTL *uint64) {
		t.Helper()
		ent, err := types.IssuerPolicyData{Mode: types.IssuerPolicyModeOpen, DefaultTTL: defaultTTL}.ToEntity()
		if err != nil {
			t.Fatalf("encode policy: %v", err)
		}
		if _, err := hctx.Store.Put(ent); err != nil {
			t.Fatalf("store policy: %v", err)
		}
		if err := hctx.LocationIndex.Set(types.IssuerPolicyStoragePath, ent.ContentHash); err != nil {
			t.Fatalf("bind policy: %v", err)
		}
	}

	successorTTL := func(t *testing.T, hctx *handler.HandlerContext, r *handler.Response) *uint64 {
		t.Helper()
		if r.Status != 200 {
			t.Fatalf("renew: status want 200 got %d (%s)", r.Status, decodeErrorCode(t, r))
		}
		res, err := types.LocalNameBindResultDataFromEntity(r.Result)
		if err != nil {
			t.Fatalf("decode renew result: %v", err)
		}
		ent, ok := hctx.Store.Get(res.BindingHash)
		if !ok {
			t.Fatalf("successor binding not in store")
		}
		bd, err := types.BindingDataFromEntity(ent)
		if err != nil {
			t.Fatalf("decode successor binding: %v", err)
		}
		return bd.TTL
	}

	seed := func(t *testing.T) (*handler.HandlerContext, func(*testing.T, *uint64, []byte) *handler.Response) {
		registryKP, _, _ := newRegistry(t)
		iss, hctx := newIssuer(t, registryKP, WithIssuerClock(func() uint64 { return 1_000_000 }))
		owner, _ := crypto.Generate()
		bindingHash := seedBinding(t, iss, hctx, owner, "renew-cascade.com")
		renew := func(t *testing.T, ttl *uint64, nonce []byte) *handler.Response {
			t.Helper()
			ent, err := types.RegistryRenewRequestData{BindingHash: bindingHash, TTL: ttl, Nonce: nonce, IssuedAt: 1_000_001}.ToEntity()
			if err != nil {
				t.Fatalf("encode renew: %v", err)
			}
			ent = stageProof(t, hctx, owner, ent)
			r, err := iss.Handle(context.Background(), &handler.Request{Path: IssuerHandlerPattern, Operation: OpRenewRequest, Params: ent, Context: hctx})
			if err != nil || r == nil {
				t.Fatalf("Handle renew: r=%v err=%v", r, err)
			}
			return r
		}
		return hctx, renew
	}

	t.Run("a_explicit_ttl_carried", func(t *testing.T) {
		hctx, renew := seed(t)
		explicit := uint64(86_400_000)
		if got := successorTTL(t, hctx, renew(t, &explicit, []byte{0x0A})); got == nil || *got != explicit {
			t.Fatalf("explicit renew: successor ttl want %d got %v", explicit, got)
		}
	})

	t.Run("b_omit_null_default_inherits_predecessor", func(t *testing.T) {
		hctx, renew := seed(t)
		setPolicy(t, hctx, nil) // null-default policy, store-first — step 2 yields nothing
		if got := successorTTL(t, hctx, renew(t, nil, []byte{0x0B})); got == nil || *got != predTTL {
			t.Fatalf("null-default renew: successor ttl want predecessor %d got %v", predTTL, got)
		}
	})

	t.Run("c_omit_policy_default_outranks_predecessor", func(t *testing.T) {
		hctx, renew := seed(t)
		policyTTL := uint64(500_000_000) // deliberately != predTTL, so step 2 vs step 3 is observable
		setPolicy(t, hctx, &policyTTL)
		if got := successorTTL(t, hctx, renew(t, nil, []byte{0x0C})); got == nil || *got != policyTTL {
			t.Fatalf("policy-default renew: successor ttl want policy %d got %v (predecessor is %d)", policyTTL, got, predTTL)
		}
	})
}

// REG-RENEW-TTL-NULLPRED-1 (REGISTRY §6a.9, v1.10; the terminal refusal restored
// per ROUTING-2026-08-18-{n,o} §3). The three-step cascade is NOT total: v1.9
// asserted step 3 is non-null *because* §6a.3 guarantees it, but that reads an
// invariant as a fact about stored bytes. A predecessor carrying ttl:null can be
// ALREADY there — seeded out-of-band, written directly to the tree, or predating
// the rules. A renew omitting ttl, against a policy with no default_ttl, whose
// predecessor is itself null-ttl, resolves all three steps to null and MUST
// refuse 403 policy_rejected and publish nothing — never mint a null-ttl
// successor via a deref-guard fallthrough. The CONTROL is TestRenew_TTLCascade
// row (b): a non-null predecessor + the same renew returns 200.
//
// Mutation control: drop the `if ttlPtr == nil` terminal refusal in
// handleRenewRequest and the fallthrough mints a null-ttl successor → this fails.
func TestRenew_NullPredecessorTTL_FailsClosed(t *testing.T) {
	registryKP, _, _ := newRegistry(t)
	iss, hctx := newIssuer(t, registryKP, WithIssuerClock(func() uint64 { return 1_000_000 }))
	owner, _ := crypto.Generate()

	// Null-default policy, store-first — step 2 yields nothing.
	polEnt, err := types.IssuerPolicyData{Mode: types.IssuerPolicyModeOpen}.ToEntity()
	if err != nil {
		t.Fatalf("encode null-default policy: %v", err)
	}
	if _, err := hctx.Store.Put(polEnt); err != nil {
		t.Fatalf("store policy: %v", err)
	}
	if err := hctx.LocationIndex.Set(types.IssuerPolicyStoragePath, polEnt.ContentHash); err != nil {
		t.Fatalf("bind policy: %v", err)
	}

	// A null-ttl predecessor written DIRECTLY to the tree — the shape §6a.3 forbids
	// on any conformant mint path but that an out-of-band write can produce.
	pred := types.BindingData{
		Name:         "nullpred.com",
		Kind:         types.BindingKindPeerIssued,
		TargetPeerID: string(owner.PeerID()),
		IssuedAt:     1_000_000,
		TTL:          nil, // step 3 yields nothing
	}
	predEnt, err := pred.ToEntity()
	if err != nil {
		t.Fatalf("encode null-ttl predecessor: %v", err)
	}
	if _, err := hctx.Store.Put(predEnt); err != nil {
		t.Fatalf("store predecessor: %v", err)
	}
	if _, err := hctx.TreeSet(types.PeerIssuedByNamePath("nullpred.com"), predEnt.ContentHash, "test-nullpred"); err != nil {
		t.Fatalf("bind by-name: %v", err)
	}

	// Renew omitting ttl → all three cascade steps null.
	renewEnt, err := types.RegistryRenewRequestData{
		BindingHash: predEnt.ContentHash, TTL: nil, Nonce: []byte{0x0D}, IssuedAt: 1_000_001,
	}.ToEntity()
	if err != nil {
		t.Fatalf("encode renew: %v", err)
	}
	renewEnt = stageProof(t, hctx, owner, renewEnt)
	r, err := iss.Handle(context.Background(), &handler.Request{Path: IssuerHandlerPattern, Operation: OpRenewRequest, Params: renewEnt, Context: hctx})
	if err != nil || r == nil {
		t.Fatalf("Handle renew: r=%v err=%v", r, err)
	}
	if r.Status != 403 {
		t.Fatalf("renew of a null-ttl predecessor with no default_ttl: status want 403 got %d (%s) — the cascade terminal refusal is missing; a deref-guard fallthrough would mint a null-ttl successor", r.Status, decodeErrorCode(t, r))
	}
	if code := decodeErrorCode(t, r); code != types.RegistryErrPolicyRejected {
		t.Fatalf("renew null-pred: code want %q got %q", types.RegistryErrPolicyRejected, code)
	}
	// Publish nothing: the by-name pointer still names the predecessor, no successor.
	if h, ok := hctx.LocationIndex.Get(types.PeerIssuedByNamePath("nullpred.com")); !ok || h != predEnt.ContentHash {
		t.Fatalf("by-name pointer moved despite the 403 — a successor was published (must mint nothing)")
	}
}

// REG-TTL-CLAMP-1 (register half) — REGISTRY §6a.9, v1.11. A register-request
// carrying requested_ttl ABOVE the policy max_ttl is CLAMPED, not refused: the
// call returns 200 and the issued binding carries EXACTLY max_ttl. The clamp is
// asserted on the binding's value, not the status, because a peer that refuses
// instead of clamping also returns non-200 and is otherwise indistinguishable.
func TestRegister_TTLClampedToMax(t *testing.T) {
	registryKP, _, _ := newRegistry(t)
	iss, hctx := newIssuer(t, registryKP, WithIssuerClock(func() uint64 { return 1_000_000 }))
	owner, _ := crypto.Generate()

	defTTL := uint64(1_000_000)
	maxTTL := uint64(10_000_000)
	installPolicy(t, hctx, types.IssuerPolicyData{Mode: types.IssuerPolicyModeOpen, DefaultTTL: &defTTL, MaxTTL: &maxTTL})

	reqTTL := uint64(999_999_999) // far above max_ttl
	resp := dispatchRegister(t, iss, hctx, stageRequest(t, hctx, owner,
		types.RegistryRegisterRequestData{
			Name:         "clamp-me.com",
			TargetPeerID: string(owner.PeerID()),
			Nonce:        []byte{0x21},
			IssuedAt:     1_000_000,
			RequestedTTL: &reqTTL,
		}))
	if resp.Status != 200 {
		t.Fatalf("register above ceiling: status want 200 (clamp, not refuse) got %d (%s)", resp.Status, decodeErrorCode(t, resp))
	}
	res, err := types.LocalNameBindResultDataFromEntity(resp.Result)
	if err != nil {
		t.Fatalf("decode bind result: %v", err)
	}
	ent, ok := hctx.Store.Get(res.BindingHash)
	if !ok {
		t.Fatalf("issued binding not in store")
	}
	bd, err := types.BindingDataFromEntity(ent)
	if err != nil {
		t.Fatalf("decode binding: %v", err)
	}
	if bd.TTL == nil || *bd.TTL != maxTTL {
		t.Fatalf("register clamp: binding ttl want max_ttl %d got %v (requested %d)", maxTTL, bd.TTL, reqTTL)
	}
}

// REG-TTL-CLAMP-1 (renew half) — a renew carrying ttl above max_ttl is likewise
// clamped: 200, successor carries exactly max_ttl.
func TestRenew_TTLClampedToMax(t *testing.T) {
	registryKP, _, _ := newRegistry(t)
	iss, hctx := newIssuer(t, registryKP, WithIssuerClock(func() uint64 { return 1_000_000 }))
	owner, _ := crypto.Generate()

	// seedBinding installs a plain open policy (max_ttl nil); re-install one WITH a
	// ceiling before the renew so the clamp has something to bite.
	bindingHash := seedBinding(t, iss, hctx, owner, "renew-clamp.com")
	defTTL := uint64(1_000_000)
	maxTTL := uint64(10_000_000)
	installPolicy(t, hctx, types.IssuerPolicyData{Mode: types.IssuerPolicyModeOpen, DefaultTTL: &defTTL, MaxTTL: &maxTTL})

	reqTTL := uint64(999_999_999)
	renewEnt, err := types.RegistryRenewRequestData{
		BindingHash: bindingHash, TTL: &reqTTL, Nonce: []byte{0x22}, IssuedAt: 1_000_001,
	}.ToEntity()
	if err != nil {
		t.Fatalf("encode renew: %v", err)
	}
	renewEnt = stageProof(t, hctx, owner, renewEnt)
	r, err := iss.Handle(context.Background(), &handler.Request{Path: IssuerHandlerPattern, Operation: OpRenewRequest, Params: renewEnt, Context: hctx})
	if err != nil || r == nil {
		t.Fatalf("Handle renew: r=%v err=%v", r, err)
	}
	if r.Status != 200 {
		t.Fatalf("renew above ceiling: status want 200 (clamp) got %d (%s)", r.Status, decodeErrorCode(t, r))
	}
	res, err := types.LocalNameBindResultDataFromEntity(r.Result)
	if err != nil {
		t.Fatalf("decode renew result: %v", err)
	}
	ent, ok := hctx.Store.Get(res.BindingHash)
	if !ok {
		t.Fatalf("successor not in store")
	}
	bd, err := types.BindingDataFromEntity(ent)
	if err != nil {
		t.Fatalf("decode successor: %v", err)
	}
	if bd.TTL == nil || *bd.TTL != maxTTL {
		t.Fatalf("renew clamp: successor ttl want max_ttl %d got %v (requested %d)", maxTTL, bd.TTL, reqTTL)
	}
}
