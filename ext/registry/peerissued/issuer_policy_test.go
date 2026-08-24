package peerissued

import (
	"context"
	"testing"

	"go.entitychurch.org/entity-core-go/core/crypto"
	"go.entitychurch.org/entity-core-go/core/handler"
	"go.entitychurch.org/entity-core-go/core/types"
)

// EXTENSION-REGISTRY §6a.9.2 (RATIFIED 2026-08-10) — set-issuer-policy /
// get-issuer-policy. One test per normative point, plus the round-trip.
//
// The four points, and why each has its own test: every one of them closes a
// hole a status-only check would walk straight past.
//
//  1. set replaces the policy WHOLE [MUST] — an absent optional field is
//     *unset*, not *unchanged*.
//  2. resolution is store-first [MUST]; out-of-band arming seeds the entity
//     and is never a parallel request-time source.
//  3. unset is not a mode — get returns 404 and MUST NOT synthesize `open`.
//  4. mode "domain-control" → 400 unsupported_mode on set.

// dispatchSet is the typed set-issuer-policy call.
func dispatchSet(t *testing.T, iss *Issuer, hctx *handler.HandlerContext, p types.IssuerPolicyData) *handler.Response {
	t.Helper()
	ent, err := p.ToEntity()
	if err != nil {
		t.Fatalf("encode issuer-policy: %v", err)
	}
	resp, err := iss.Handle(context.Background(), &handler.Request{
		Path:      IssuerHandlerPattern,
		Operation: OpSetIssuerPolicy,
		Params:    ent,
		Context:   hctx,
	})
	if err != nil {
		t.Fatalf("set-issuer-policy: %v", err)
	}
	return resp
}

// dispatchGet is the typed get-issuer-policy call (no params).
func dispatchGet(t *testing.T, iss *Issuer, hctx *handler.HandlerContext) *handler.Response {
	t.Helper()
	resp, err := iss.Handle(context.Background(), &handler.Request{
		Path:      IssuerHandlerPattern,
		Operation: OpGetIssuerPolicy,
		Context:   hctx,
	})
	if err != nil {
		t.Fatalf("get-issuer-policy: %v", err)
	}
	return resp
}

// Point 3 — unset is not a mode. The single most consequential of the four:
// synthesizing `open` here would silently turn a curated registry into a
// first-come-first-serve one.
func TestGetIssuerPolicy_Unset_404NotFound(t *testing.T) {
	registryKP, _, _ := newRegistry(t)
	iss, hctx := newIssuer(t, registryKP)

	resp := dispatchGet(t, iss, hctx)
	if resp.Status != 404 {
		t.Fatalf("unset get: status want 404 got %d", resp.Status)
	}
	if code := decodeErrorCode(t, resp); code != types.RegistryErrNotFound {
		t.Fatalf("unset get: code want %q got %q", types.RegistryErrNotFound, code)
	}
}

// Point 3, the other half — an unarmed registry does not run live
// registration at all (§6a.9.2 / §6a.8 curated-only). Before this ruling Go
// defaulted an absent policy to `open`, which is the exact silent
// first-come-first-serve failure the point exists to prevent.
func TestRegisterRequest_UnarmedRegistry_IsCuratedOnly(t *testing.T) {
	registryKP, _, _ := newRegistry(t)
	iss, hctx := newIssuer(t, registryKP,
		WithIssuerClock(func() uint64 { return 1_000_000 }))

	publisher, _ := crypto.Generate()
	resp := dispatchRegister(t, iss, hctx, stageRequest(t, hctx, publisher,
		types.RegistryRegisterRequestData{
			Name:         "unarmed.example",
			TargetPeerID: string(publisher.PeerID()),
			Nonce:        []byte{0x01},
			IssuedAt:     1_000_000,
		}))
	if resp.Status == 200 {
		t.Fatalf("unarmed registry issued a binding — an absent policy must NOT mean open")
	}
	if resp.Status != 404 {
		t.Fatalf("unarmed register: status want 404 got %d", resp.Status)
	}
}

// Round-trip: set then get returns the policy as written, byte-exact.
func TestSetThenGetIssuerPolicy_RoundTrip(t *testing.T) {
	registryKP, _, _ := newRegistry(t)
	iss, hctx := newIssuer(t, registryKP)

	ttl := uint64(3600_000)
	want := types.IssuerPolicyData{
		Mode:       types.IssuerPolicyModeAllowlist,
		Allowlist:  []string{"peer-a", "peer-b"},
		DefaultTTL: &ttl,
	}

	setResp := dispatchSet(t, iss, hctx, want)
	if setResp.Status != 200 {
		t.Fatalf("set: status want 200 got %d (%s)", setResp.Status, decodeErrorCode(t, setResp))
	}
	if setResp.Result.Type != types.TypeRegistryIssuerPolicy {
		t.Fatalf("set: result type want %q got %q", types.TypeRegistryIssuerPolicy, setResp.Result.Type)
	}

	getResp := dispatchGet(t, iss, hctx)
	if getResp.Status != 200 {
		t.Fatalf("get: status want 200 got %d", getResp.Status)
	}
	// §6a.9.2 output is "the stored policy, as written" — byte-exact, which
	// is why set stores the submitted entity rather than re-encoding it.
	if getResp.Result.ContentHash != setResp.Result.ContentHash {
		t.Fatalf("get returned a different entity than set stored: %s != %s",
			getResp.Result.ContentHash, setResp.Result.ContentHash)
	}
	got, err := types.IssuerPolicyDataFromEntity(getResp.Result)
	if err != nil {
		t.Fatalf("decode policy: %v", err)
	}
	if got.Mode != want.Mode || len(got.Allowlist) != 2 || got.DefaultTTL == nil || *got.DefaultTTL != ttl {
		t.Fatalf("round-trip mismatch: got %+v want %+v", got, want)
	}
}

// Point 1 — replace whole, not merge. Set a policy carrying optional fields,
// then set one without them: the optional fields must be GONE, not inherited.
// A merge would make the result depend on write order.
func TestSetIssuerPolicy_ReplacesWhole_DoesNotMerge(t *testing.T) {
	registryKP, _, _ := newRegistry(t)
	iss, hctx := newIssuer(t, registryKP)

	ttl := uint64(3600_000)
	constraints := "*.example"
	first := types.IssuerPolicyData{
		Mode:            types.IssuerPolicyModeAllowlist,
		Allowlist:       []string{"peer-a"},
		DefaultTTL:      &ttl,
		NameConstraints: &constraints,
	}
	if resp := dispatchSet(t, iss, hctx, first); resp.Status != 200 {
		t.Fatalf("first set: status want 200 got %d", resp.Status)
	}

	// Second write carries mode only. Every optional field is absent —
	// which §6a.9.2 defines as *unset*, not *unchanged*.
	second := types.IssuerPolicyData{Mode: types.IssuerPolicyModeOpen}
	if resp := dispatchSet(t, iss, hctx, second); resp.Status != 200 {
		t.Fatalf("second set: status want 200 got %d", resp.Status)
	}

	got, err := types.IssuerPolicyDataFromEntity(dispatchGet(t, iss, hctx).Result)
	if err != nil {
		t.Fatalf("decode policy: %v", err)
	}
	if got.Mode != types.IssuerPolicyModeOpen {
		t.Fatalf("mode want %q got %q", types.IssuerPolicyModeOpen, got.Mode)
	}
	if len(got.Allowlist) != 0 {
		t.Fatalf("allowlist survived a whole-replace: %v — this is merge semantics", got.Allowlist)
	}
	if got.DefaultTTL != nil {
		t.Fatalf("default_ttl survived a whole-replace: %d — this is merge semantics", *got.DefaultTTL)
	}
	if got.NameConstraints != nil {
		t.Fatalf("name_constraints survived a whole-replace: %q — this is merge semantics", *got.NameConstraints)
	}
}

// Point 4 — domain-control is refused at the door with 400 unsupported_mode,
// "rather than storing a policy it cannot enforce." The second half matters
// as much as the status: the store must be left untouched.
func TestSetIssuerPolicy_DomainControl_400UnsupportedMode(t *testing.T) {
	registryKP, _, _ := newRegistry(t)
	iss, hctx := newIssuer(t, registryKP)

	resp := dispatchSet(t, iss, hctx, types.IssuerPolicyData{
		Mode: types.IssuerPolicyModeDomainControl,
	})
	if resp.Status != 400 {
		t.Fatalf("domain-control set: status want 400 got %d", resp.Status)
	}
	if code := decodeErrorCode(t, resp); code != types.RegistryErrUnsupportedMode {
		t.Fatalf("domain-control set: code want %q got %q", types.RegistryErrUnsupportedMode, code)
	}
	// Nothing stored — the registry is still unarmed.
	if getResp := dispatchGet(t, iss, hctx); getResp.Status != 404 {
		t.Fatalf("domain-control was rejected but something was stored (get → %d)", getResp.Status)
	}
}

// Point 2 — store-first, and the flag is a SEED. SeedPolicy writes the
// entity so get-issuer-policy reports the mode the peer is actually running;
// before this, a flag-armed registry had no policy entity at all and would
// have answered 404 while demonstrably enforcing a mode.
func TestSeedPolicy_WritesTheEntity_AndDoesNotOverwrite(t *testing.T) {
	registryKP, _, _ := newRegistry(t)
	iss, hctx := newIssuer(t, registryKP,
		WithSeedPolicy(types.IssuerPolicyData{Mode: types.IssuerPolicyModeManual}))

	if err := iss.SeedPolicy(hctx.Store, hctx.LocationIndex); err != nil {
		t.Fatalf("SeedPolicy: %v", err)
	}
	resp := dispatchGet(t, iss, hctx)
	if resp.Status != 200 {
		t.Fatalf("after seed: get status want 200 got %d — the flag did not reach the tree", resp.Status)
	}
	got, err := types.IssuerPolicyDataFromEntity(resp.Result)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if got.Mode != types.IssuerPolicyModeManual {
		t.Fatalf("seeded mode want %q got %q", types.IssuerPolicyModeManual, got.Mode)
	}

	// An operator-set policy outranks the flag: seeding again must not
	// revert it. A flag arms an unarmed registry; it does not silently
	// undo a set-issuer-policy call.
	if r := dispatchSet(t, iss, hctx, types.IssuerPolicyData{Mode: types.IssuerPolicyModeOpen}); r.Status != 200 {
		t.Fatalf("set over seed: status want 200 got %d", r.Status)
	}
	if err := iss.SeedPolicy(hctx.Store, hctx.LocationIndex); err != nil {
		t.Fatalf("re-seed: %v", err)
	}
	after, err := types.IssuerPolicyDataFromEntity(dispatchGet(t, iss, hctx).Result)
	if err != nil {
		t.Fatalf("decode after re-seed: %v", err)
	}
	if after.Mode != types.IssuerPolicyModeOpen {
		t.Fatalf("re-seeding reverted an operator-set policy to %q — the seed is overwriting", after.Mode)
	}
}

// Point 2, the negative half — there is no request-time parallel source. A
// seed that was never written to the tree must NOT be consulted by
// register-request. This is the property that lets a conformance run drive
// all three modes against a single peer by writing the entity, which is how
// registry_issuer reached 12 checks.
func TestSeedPolicy_NotConsultedAtRequestTime(t *testing.T) {
	registryKP, _, _ := newRegistry(t)
	iss, hctx := newIssuer(t, registryKP,
		WithIssuerClock(func() uint64 { return 1_000_000 }),
		WithSeedPolicy(types.IssuerPolicyData{Mode: types.IssuerPolicyModeOpen}))
	// Deliberately do NOT call SeedPolicy.

	publisher, _ := crypto.Generate()
	resp := dispatchRegister(t, iss, hctx, stageRequest(t, hctx, publisher,
		types.RegistryRegisterRequestData{
			Name:         "unseeded.example",
			TargetPeerID: string(publisher.PeerID()),
			Nonce:        []byte{0x09},
			IssuedAt:     1_000_000,
		}))
	if resp.Status == 200 {
		t.Fatalf("an unwritten seed admitted a registration — the seed is being read " +
			"at request time, which §6a.9.2 bars")
	}
}

// Guard: the store-first order itself. With a policy entity present, that
// entity decides — even when a seed carrying a different mode is configured.
func TestLoadPolicy_StoreWinsOverSeed(t *testing.T) {
	registryKP, _, _ := newRegistry(t)
	iss, hctx := newIssuer(t, registryKP,
		WithSeedPolicy(types.IssuerPolicyData{Mode: types.IssuerPolicyModeManual}))
	installPolicy(t, hctx, types.IssuerPolicyData{Mode: types.IssuerPolicyModeOpen})

	got, armed := iss.loadPolicy(hctx)
	if !armed {
		t.Fatalf("loadPolicy: want armed with a stored policy")
	}
	if got.Mode != types.IssuerPolicyModeOpen {
		t.Fatalf("store-first violated: want %q got %q", types.IssuerPolicyModeOpen, got.Mode)
	}
}

// An unknown mode is refused rather than stored — same reasoning as
// domain-control: a policy the issuer cannot enforce must not be armed.
func TestSetIssuerPolicy_UnknownMode_Rejected(t *testing.T) {
	registryKP, _, _ := newRegistry(t)
	iss, hctx := newIssuer(t, registryKP)

	resp := dispatchSet(t, iss, hctx, types.IssuerPolicyData{Mode: "first-come-first-serve"})
	if resp.Status != 400 {
		t.Fatalf("unknown mode: status want 400 got %d", resp.Status)
	}
	if code := decodeErrorCode(t, resp); code != types.RegistryErrUnsupportedMode {
		t.Fatalf("unknown mode: code want %q got %q", types.RegistryErrUnsupportedMode, code)
	}
}

// The two management ops are absent from the publisher seed grants. A peer
// that may call register-request must not be able to rewrite the policy that
// admits it.
func TestManageOps_NotInPublisherSeedGrants(t *testing.T) {
	for _, g := range RequestBindingSeedGrants() {
		for _, op := range g.Operations.Include {
			if op == OpSetIssuerPolicy || op == OpGetIssuerPolicy {
				t.Fatalf("RequestBindingSeedGrants grants %q to publishers — §6a.9.2 gates it "+
					"behind %s", op, types.CapRegistryManageIssuerPolicy)
			}
		}
	}
	// And they ARE in the operator grant set.
	found := map[string]bool{}
	for _, g := range ManageIssuerPolicySeedGrants() {
		for _, op := range g.Operations.Include {
			found[op] = true
		}
	}
	if !found[OpSetIssuerPolicy] || !found[OpGetIssuerPolicy] {
		t.Fatalf("ManageIssuerPolicySeedGrants must cover both ops, got %v", found)
	}
}
