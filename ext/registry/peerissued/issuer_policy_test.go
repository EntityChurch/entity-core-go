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
	maxTTL := uint64(86_400_000)
	want := types.IssuerPolicyData{
		Mode:       types.IssuerPolicyModeAllowlist,
		Allowlist:  []string{"peer-a", "peer-b"},
		DefaultTTL: &ttl,
		MaxTTL:     &maxTTL, // v1.11: REQUIRED on a live policy through set-issuer-policy
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
	ttl2 := uint64(7200_000)
	maxTTL := uint64(86_400_000)
	constraints := "*.example"
	first := types.IssuerPolicyData{
		Mode:            types.IssuerPolicyModeAllowlist,
		Allowlist:       []string{"peer-a"},
		DefaultTTL:      &ttl,
		MaxTTL:          &maxTTL,
		NameConstraints: &constraints,
	}
	if resp := dispatchSet(t, iss, hctx, first); resp.Status != 200 {
		t.Fatalf("first set: status want 200 got %d", resp.Status)
	}

	// Second write carries mode + the mandatory default_ttl (CAP registry D11 —
	// a live policy MUST define it), with a DIFFERENT value to prove replace not
	// merge, and DROPS the other optional fields. Absent optional fields are
	// *unset*, not *unchanged* (§6a.9.2); default_ttl is no longer optional, so
	// the replace property is shown by its value changing rather than clearing.
	second := types.IssuerPolicyData{Mode: types.IssuerPolicyModeOpen, DefaultTTL: &ttl2, MaxTTL: &maxTTL}
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
	if got.DefaultTTL == nil || *got.DefaultTTL != ttl2 {
		t.Fatalf("default_ttl not replaced whole: got %v want %d — a merge would keep the first value or two would appear", got.DefaultTTL, ttl2)
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
	setTTL := uint64(3600_000)
	setMaxTTL := uint64(86_400_000)
	if r := dispatchSet(t, iss, hctx, types.IssuerPolicyData{Mode: types.IssuerPolicyModeOpen, DefaultTTL: &setTTL, MaxTTL: &setMaxTTL}); r.Status != 200 {
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

// REG-TTL-CEILING-1 (REGISTRY §6a.9, v1.11) — set-issuer-policy MUST reject a
// live-registration policy whose max_ttl is absent (400), and one whose
// default_ttl exceeds max_ttl (400); the control is a policy with both, where
// default_ttl <= max_ttl, which is accepted 200. Same trigger and site as the
// default_ttl gate: max_ttl is the operator's field, and this is where it lives.
func TestSetIssuerPolicy_MaxTTL_Ceiling(t *testing.T) {
	registryKP, _, _ := newRegistry(t)
	iss, hctx := newIssuer(t, registryKP)

	def := uint64(3_600_000)
	big := uint64(7_200_000)
	small := uint64(1_800_000)

	// (1) live mode, default_ttl present but max_ttl ABSENT → 400.
	if resp := dispatchSet(t, iss, hctx, types.IssuerPolicyData{
		Mode: types.IssuerPolicyModeOpen, DefaultTTL: &def,
	}); resp.Status != 400 {
		t.Fatalf("absent max_ttl: status want 400 got %d (%s) — v1.11 makes max_ttl REQUIRED on a live policy", resp.Status, decodeErrorCode(t, resp))
	}

	// (2) default_ttl > max_ttl → 400.
	if resp := dispatchSet(t, iss, hctx, types.IssuerPolicyData{
		Mode: types.IssuerPolicyModeOpen, DefaultTTL: &big, MaxTTL: &small,
	}); resp.Status != 400 {
		t.Fatalf("default_ttl > max_ttl: status want 400 got %d (%s)", resp.Status, decodeErrorCode(t, resp))
	}

	// Negative half of (1)+(2): neither rejected policy was stored — get is still
	// 404 (nothing armed yet).
	if resp := dispatchGet(t, iss, hctx); resp.Status != 404 {
		t.Fatalf("a rejected ceiling policy was stored anyway: get status %d, want 404", resp.Status)
	}

	// (3) control — both present, default_ttl <= max_ttl → 200.
	if resp := dispatchSet(t, iss, hctx, types.IssuerPolicyData{
		Mode: types.IssuerPolicyModeOpen, DefaultTTL: &def, MaxTTL: &big,
	}); resp.Status != 200 {
		t.Fatalf("control (default_ttl <= max_ttl): status want 200 got %d (%s)", resp.Status, decodeErrorCode(t, resp))
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
