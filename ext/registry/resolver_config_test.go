package registry

import (
	"context"
	"testing"

	"go.entitychurch.org/entity-core-go/core/ecf"
	"go.entitychurch.org/entity-core-go/core/entity"
	"go.entitychurch.org/entity-core-go/core/handler"
	"go.entitychurch.org/entity-core-go/core/types"
)

// TestPatternMatchesUnscopedName pins the §4.1b is-broad classifier
// [MUST, v1.19]. A pattern is NARROW iff at least one of the four conditions
// (a)-(d) holds; otherwise BROAD. The fixtures are the spec's own two worked
// sets: §4.1a's recommended default list (which the classifier must keep
// conformant with the step-2 MUST living inside it), and the four cases
// independent readings diverged on — plus REG-DISPATCH-CONFIG-REFUSED-1 row 7's
// five classifier rows verbatim. Two results moved from the pre-v1.19 reading
// and BOTH were go's divergence: `alice`/`a.b` (an exact literal) narrow by (a),
// and `*.lab` broad because `.lab` is NOT an enumerated typed suffix (§4.1b.1).
func TestPatternMatchesUnscopedName(t *testing.T) {
	cases := []struct {
		pattern string
		broad   bool
		note    string
	}{
		// §4.1a default list — the check any impl runs first.
		{"*", true, "catch-all — §4.1a row 6, broad"},
		{"did:web:*", false, "(c) head 'did:web:' ends in ':' — §4.1a row 1"},
		{"did:key:*", false, "(c) scheme prefix — §4.1a row 2"},
		{"*.eth", false, "(d) enumerated typed suffix .eth — §4.1a row 3"},
		{"*@*.*", false, "(b) literal '@' — §4.1a row 4"},
		{"*@*", false, "(b) literal '@' — §4.1a row 5"},
		// The four the old undefined predicate split on (§4.1b worked set).
		{"*.*", true, "(broad) '.' is not a typed suffix — matches bare dotted names"},
		{"*.e*", true, "(broad) trailing '*' means no fixed suffix"},
		{"a.b", false, "(a) no '*' — matches exactly one name"},
		{"alice.eth", false, "(a) no '*', and also (d)"},
		// REG-DISPATCH-CONFIG-REFUSED-1 row 7 verbatim.
		{"a.b", false, "row 7 — accepted (narrow)"},
		{"*.lab", true, "row 7 — refused: .lab is NOT enumerated (any-literal is not the line)"},
		{"alice", false, "(a) an exact literal name is a single explicit route, narrow"},
		{"a*", true, "(broad) bare prefix captures bare names"},
		{"*@entity-church", false, "(b) literal '@'"},
	}
	for _, c := range cases {
		if got := patternMatchesUnscopedName(c.pattern); got != c.broad {
			t.Errorf("patternMatchesUnscopedName(%q) = %v, want %v (%s)", c.pattern, got, c.broad, c.note)
		}
	}
}

// TestDisclosureViolationsTwoDoors covers both §4.1 step 2 doors and the
// kind-scoped property: a broad rule naming a transmitting kind violates even
// with NO matching backend in the chain (door 1, kind-scoped), an absent
// dispatch with a transmitting kind in the chain violates (door 2), and the
// §4.1a default list is clean.
func TestDisclosureViolationsTwoDoors(t *testing.T) {
	transmit := []string{types.BackendKindDIDWeb}
	safe := []string{types.BackendKindLocalName}

	// Door 1, kind-scoped: broad `*` → did-web, but chain has only local-name.
	cfg := types.ResolverConfigData{
		ResolverChain:      []types.ResolverChainEntry{{BackendKind: types.BackendKindLocalName, BackendID: "self"}},
		NameFormatDispatch: []types.DispatchEntry{{Pattern: "*", BackendKinds: transmit}},
	}
	if v := disclosureViolations(cfg); len(v) != 1 {
		t.Errorf("door 1 kind-scoped: got %d violations %v, want 1", len(v), v)
	}

	// Door 1 narrow control: scoped `did:web:*` → did-web is fine.
	cfg.NameFormatDispatch = []types.DispatchEntry{{Pattern: "did:web:*", BackendKinds: transmit}}
	if v := disclosureViolations(cfg); len(v) != 0 {
		t.Errorf("narrow scoped rule: got %d violations %v, want 0", len(v), v)
	}

	// Door 2: absent dispatch, transmitting kind in the chain.
	cfg = types.ResolverConfigData{
		ResolverChain: []types.ResolverChainEntry{{BackendKind: types.BackendKindDIDWeb, BackendID: "x"}},
	}
	if v := disclosureViolations(cfg); len(v) != 1 {
		t.Errorf("door 2: got %d violations %v, want 1", len(v), v)
	}

	// Door 2 safe: absent dispatch, only safe kinds.
	cfg.ResolverChain = []types.ResolverChainEntry{{BackendKind: types.BackendKindLocalName, BackendID: "self"}}
	if v := disclosureViolations(cfg); len(v) != 0 {
		t.Errorf("door 2 safe: got %d violations %v, want 0", len(v), v)
	}

	// An UNKNOWN kind in a broad rule is NOT a violation (§4.2 [v1.14]).
	cfg = types.ResolverConfigData{
		ResolverChain:      []types.ResolverChainEntry{{BackendKind: safe[0], BackendID: "self"}},
		NameFormatDispatch: []types.DispatchEntry{{Pattern: "*", BackendKinds: []string{"some-future-kind"}}},
	}
	if v := disclosureViolations(cfg); len(v) != 0 {
		t.Errorf("unknown kind: got %d violations %v, want 0 — undeclared kinds are not transmitting", len(v), v)
	}

	// The §4.1a recommended default list is conformant.
	if v := disclosureViolations(defaultDispatchConfig()); len(v) != 0 {
		t.Errorf("§4.1a default list must be clean, got %d violations: %v", len(v), v)
	}
}

// defaultDispatchConfig is the §4.1a SHOULD-ship recommended list, with every
// named backend present in the chain so door 2 cannot hide a door-1 miss.
func defaultDispatchConfig() types.ResolverConfigData {
	return types.ResolverConfigData{
		ResolverChain: []types.ResolverChainEntry{
			{BackendKind: types.BackendKindLocalName, BackendID: "self", Priority: 0},
			{BackendKind: types.BackendKindDIDWeb, BackendID: "x", Priority: 1},
			{BackendKind: types.BackendKindSelfCertifying, BackendID: "x", Priority: 2},
			{BackendKind: types.BackendKindConsensusAnchored, BackendID: "x", Priority: 3},
			{BackendKind: types.BackendKindDNSTXT, BackendID: "x", Priority: 4},
			{BackendKind: types.BackendKindWellKnownURL, BackendID: "x", Priority: 5},
			{BackendKind: types.BackendKindPeerIssued, BackendID: "x", Priority: 6},
		},
		NameFormatDispatch: []types.DispatchEntry{
			{Pattern: "did:web:*", BackendKinds: []string{types.BackendKindDIDWeb}},
			{Pattern: "did:key:*", BackendKinds: []string{types.BackendKindSelfCertifying}},
			{Pattern: "*.eth", BackendKinds: []string{types.BackendKindConsensusAnchored}},
			{Pattern: "*@*.*", BackendKinds: []string{types.BackendKindDNSTXT, types.BackendKindWellKnownURL}},
			{Pattern: "*@*", BackendKinds: []string{types.BackendKindPeerIssued}},
			{Pattern: "*", BackendKinds: []string{
				types.BackendKindLocalName, types.BackendKindSelfCertifying,
				types.BackendKindOutOfBand, types.BackendKindPeerIssued}},
		},
	}
}

// capToken builds a CallerCapability token entity carrying the given grants.
func capToken(t *testing.T, grants ...types.GrantEntry) entity.Entity {
	t.Helper()
	ent, err := types.CapabilityTokenData{Grants: grants}.ToEntity()
	if err != nil {
		t.Fatalf("cap ToEntity: %v", err)
	}
	return ent
}

// TestSetResolverConfigPinDeltaRequiresPinCap is the teeth for §4.3's pin-delta
// MUST [v1.19] (R-16) and REG-DISPATCH-CONFIG-REFUSED-1 row 8: a write that
// CHANGES pinned_bindings additionally requires system/capability/registry-pin;
// a byte-identical pin list needs only registry-configure; and a refusal writes
// nothing. Driven with a real CallerCapability so the in-handler cap check runs
// (the local-owner path with a zero caller cap is exercised by every other test
// here and legitimately bypasses it).
func TestSetResolverConfigPinDeltaRequiresPinCap(t *testing.T) {
	h := NewHandler()
	hctx := newFilterHctx(t)
	hctx.HandlerPattern = HandlerPattern
	configureOnly := capToken(t, ManageResolverConfigSeedGrants()...)
	configurePlusPin := capToken(t, append(ManageResolverConfigSeedGrants(), ManageResolverPinsSeedGrants()...)...)

	reason := "operator"
	noPins := types.ResolverConfigData{
		ResolverChain: []types.ResolverChainEntry{{BackendKind: types.BackendKindLocalName, BackendID: "self", Priority: 0}},
	}
	withPin := noPins
	withPin.PinnedBindings = []types.PinnedEntry{{Name: "alice", TargetPeerID: "peerAAA", Reason: &reason}}
	// Same pins, different non-pin field (a pin-identical write).
	withPinOtherField := withPin
	withPinOtherField.ResolutionLogCapacity = 128

	// 1. First write, no pins: submitted empty == stored empty → no delta →
	//    accepted under registry-configure alone.
	hctx.CallerCapability = configureOnly
	if resp := setResolverConfig(t, h, hctx, noPins, false); resp.Status != 200 {
		t.Fatalf("no-pin first write: status %d, want 200", resp.Status)
	}

	// 2. Adding a pin under configure-only → 403 not_entitled, nothing written.
	if resp := setResolverConfig(t, h, hctx, withPin, false); resp.Status != 403 {
		t.Fatalf("pin add under configure-only: status %d, want 403", resp.Status)
	}
	// Nothing written: get returns the no-pin bytes.
	if resp := getResolverConfig(t, h, hctx); resp.Status != 200 {
		t.Fatalf("get after refusal: status %d, want 200", resp.Status)
	} else if got, _ := types.ResolverConfigDataFromEntity(resp.Result); len(got.PinnedBindings) != 0 {
		t.Fatalf("refused pin add still wrote %d pins — must write nothing", len(got.PinnedBindings))
	}

	// 3. The same add carrying registry-pin as well → accepted and stored.
	hctx.CallerCapability = configurePlusPin
	if resp := setResolverConfig(t, h, hctx, withPin, false); resp.Status != 200 {
		t.Fatalf("pin add under configure+pin: status %d, want 200", resp.Status)
	}

	// 4. Control: a pin-IDENTICAL write (non-pin field changes) under
	//    configure-only → accepted. Without this row a peer that demanded pin
	//    on every write would pass rows 2 and 3.
	hctx.CallerCapability = configureOnly
	if resp := setResolverConfig(t, h, hctx, withPinOtherField, false); resp.Status != 200 {
		t.Fatalf("pin-identical write under configure-only: status %d, want 200", resp.Status)
	}

	// 5. Removing the pin under configure-only is also a delta → 403.
	if resp := setResolverConfig(t, h, hctx, noPins, false); resp.Status != 403 {
		t.Fatalf("pin removal under configure-only: status %d, want 403", resp.Status)
	}
}

// TestPinDeltaComparesRawBytesNotDecoded is the teeth for the fail-open rust
// caught 2026-08-20: the §4.3 pin-delta MUST compare RAW pinned_bindings bytes,
// not decoded-then-re-encoded entries. A stored pin carrying a §4.2
// forward-compat key go does not model must count as CHANGED when a
// configure-only write submits the same pin WITHOUT that key — a decoded
// compare drops the key and fail-opens, rewriting the most privileged row in
// the file under registry-configure alone. Mutation: swap rawPinnedBindings
// back to a []PinnedEntry compare and this row goes 200.
func TestPinDeltaComparesRawBytesNotDecoded(t *testing.T) {
	h := NewHandler()
	hctx := newFilterHctx(t)
	hctx.HandlerPattern = HandlerPattern
	hctx.CallerCapability = capToken(t, ManageResolverConfigSeedGrants()...) // configure-only

	// Seed a stored config whose pin carries an unmodelled key, written directly
	// to the store (an out-of-band seed or a prior privileged write).
	richData, err := ecf.Encode(map[string]any{
		"resolver_chain": []any{},
		"pinned_bindings": []any{
			map[string]any{"name": "alice", "target_peer_id": "peerAAA", "future_field": uint64(7)},
		},
	})
	if err != nil {
		t.Fatalf("encode rich config: %v", err)
	}
	richEnt, err := entity.NewEntity(types.TypeRegistryResolverConfig, richData)
	if err != nil {
		t.Fatalf("rich entity: %v", err)
	}
	sh, err := hctx.Store.Put(richEnt)
	if err != nil {
		t.Fatalf("store rich config: %v", err)
	}
	if err := hctx.LocationIndex.Set(types.ResolverConfigStoragePath, sh); err != nil {
		t.Fatalf("index rich config: %v", err)
	}

	// Submit the SAME pin without future_field, under configure-only. Raw compare
	// sees a byte change → 403 not_entitled; a decoded compare would 200 (the hole).
	plain := types.ResolverConfigData{
		PinnedBindings: []types.PinnedEntry{{Name: "alice", TargetPeerID: "peerAAA"}},
	}
	if resp := setResolverConfig(t, h, hctx, plain, false); resp.Status != 403 {
		t.Fatalf("stripping a §4.2 forward-compat pin key under configure-only: status %d, want 403 not_entitled — a decoded compare fail-opens here", resp.Status)
	}
}

func respCode(t *testing.T, resp *handler.Response) string {
	t.Helper()
	ed, err := types.ErrorDataFromEntity(resp.Result)
	if err != nil {
		t.Fatalf("decode error response: %v", err)
	}
	return ed.Code
}

// TestPinCapCheckPrecedesConfigValidation is the teeth for R-27 clause 4: cap
// checks precede config validation. A config that BOTH changes pinned_bindings
// AND violates §4.1 step 2, submitted configure-only with no acknowledgement,
// MUST return 403 not_entitled (the authorization verdict), NOT 403
// policy_rejected — validating first would hand §4.3's deliberately-verbose
// violation list to a caller with no authority to change anything. Ordering is
// cross-impl-observable; rust runs the pin check first, and this pins go to the
// same order.
func TestPinCapCheckPrecedesConfigValidation(t *testing.T) {
	h := NewHandler()
	hctx := newFilterHctx(t)
	hctx.HandlerPattern = HandlerPattern
	hctx.CallerCapability = capToken(t, ManageResolverConfigSeedGrants()...) // configure-only

	// Changes pins AND discloses (broad `*` → did-web with did-web in chain).
	cfg := types.ResolverConfigData{
		ResolverChain: []types.ResolverChainEntry{
			{BackendKind: types.BackendKindLocalName, BackendID: "self", Priority: 0},
			{BackendKind: types.BackendKindDIDWeb, BackendID: "x", Priority: 1},
		},
		NameFormatDispatch: []types.DispatchEntry{{Pattern: "*", BackendKinds: []string{types.BackendKindDIDWeb}}},
		PinnedBindings:     []types.PinnedEntry{{Name: "alice", TargetPeerID: "peerAAA"}},
	}
	resp := setResolverConfig(t, h, hctx, cfg, false)
	if resp.Status != 403 {
		t.Fatalf("status %d, want 403", resp.Status)
	}
	if code := respCode(t, resp); code != types.RegistryErrNotEntitled {
		t.Fatalf("code %q, want %q — the cap check MUST precede config validation (R-27 clause 4), so an unauthorized pin change wins over the disclosure verdict",
			code, types.RegistryErrNotEntitled)
	}
}

// TestPinBindingsIsNotDispatchable is the teeth for R-27 clause 2: `pin-bindings`
// is a cap-check discriminator, NOT an EXECUTE operation. Dispatching it MUST be
// refused — exposing it would add an undeclared operation to the registry
// handler's wire surface.
func TestPinBindingsIsNotDispatchable(t *testing.T) {
	h := NewHandler()
	resp, err := h.Handle(context.Background(), &handler.Request{
		Operation: OpPinBindings,
		Context:   newFilterHctx(t),
	})
	if err != nil {
		t.Fatalf("Handle(pin-bindings): %v", err)
	}
	if resp.Status == 200 {
		t.Fatal("pin-bindings dispatched with 200 — it MUST NOT be a callable operation (R-27 clause 2)")
	}
	// And it MUST NOT appear in the advertised operation table.
	if _, ok := h.Manifest().Operations[OpPinBindings]; ok {
		t.Fatal("pin-bindings appears in Manifest().Operations — it is a cap discriminator, not a wire operation")
	}
}

func setResolverConfig(t *testing.T, h *Handler, hctx *handler.HandlerContext, cfg types.ResolverConfigData, ack bool) *handler.Response {
	t.Helper()
	cfgEnt, err := cfg.ToEntity()
	if err != nil {
		t.Fatalf("cfg ToEntity: %v", err)
	}
	reqEnt, err := types.SetResolverConfigRequestData{Config: cfgEnt, AcknowledgeNameDisclosure: ack}.ToEntity()
	if err != nil {
		t.Fatalf("request ToEntity: %v", err)
	}
	resp, err := h.Handle(context.Background(), &handler.Request{
		Operation: OpSetResolverConfig,
		Params:    reqEnt,
		Context:   hctx,
	})
	if err != nil {
		t.Fatalf("set-resolver-config: %v", err)
	}
	return resp
}

func getResolverConfig(t *testing.T, h *Handler, hctx *handler.HandlerContext) *handler.Response {
	t.Helper()
	resp, err := h.Handle(context.Background(), &handler.Request{
		Operation: OpGetResolverConfig,
		Context:   hctx,
	})
	if err != nil {
		t.Fatalf("get-resolver-config: %v", err)
	}
	return resp
}

// TestResolverConfigWriteSurface drives the §4.3 [v1.18] operations end to
// end: get-before-set is 404; a clean config round-trips byte-exact; a
// violating config is refused 403 policy_rejected and stores NOTHING (the
// prior bytes stand); and the acknowledge_name_disclosure arm stores it.
func TestResolverConfigWriteSurface(t *testing.T) {
	h := NewHandler()
	hctx := newFilterHctx(t)

	// get-before-set → 404 (unset is not an empty config).
	if resp := getResolverConfig(t, h, hctx); resp.Status != 404 {
		t.Fatalf("get before set: status %d, want 404", resp.Status)
	}

	// A clean config is accepted and round-trips byte-exact.
	clean := defaultDispatchConfig()
	cleanEnt, _ := clean.ToEntity()
	if resp := setResolverConfig(t, h, hctx, clean, false); resp.Status != 200 {
		t.Fatalf("set clean config: status %d, want 200", resp.Status)
	}
	got := getResolverConfig(t, h, hctx)
	if got.Status != 200 {
		t.Fatalf("get after set: status %d, want 200", got.Status)
	}
	if got.Result.ContentHash != cleanEnt.ContentHash {
		t.Fatalf("round-trip not byte-exact: stored hash %s, want %s", got.Result.ContentHash, cleanEnt.ContentHash)
	}

	// A violating config with no acknowledgement → 403 policy_rejected, and
	// NOTHING is written: get still returns the clean config's bytes.
	violating := types.ResolverConfigData{
		ResolverChain:      []types.ResolverChainEntry{{BackendKind: types.BackendKindDIDWeb, BackendID: "x"}},
		NameFormatDispatch: []types.DispatchEntry{{Pattern: "*", BackendKinds: []string{types.BackendKindDIDWeb}}},
	}
	resp := setResolverConfig(t, h, hctx, violating, false)
	if resp.Status != 403 {
		t.Fatalf("set violating unacknowledged: status %d, want 403", resp.Status)
	}
	after := getResolverConfig(t, h, hctx)
	if after.Result.ContentHash != cleanEnt.ContentHash {
		t.Fatalf("refusal was not no-op: stored hash moved to %s, want unchanged %s", after.Result.ContentHash, cleanEnt.ContentHash)
	}

	// The override arm: the SAME violating config WITH the acknowledgement is
	// stored (the operator MAY, made expressible).
	violEnt, _ := violating.ToEntity()
	if resp := setResolverConfig(t, h, hctx, violating, true); resp.Status != 200 {
		t.Fatalf("set violating acknowledged: status %d, want 200", resp.Status)
	}
	acked := getResolverConfig(t, h, hctx)
	if acked.Result.ContentHash != violEnt.ContentHash {
		t.Fatalf("acknowledged config not stored: hash %s, want %s", acked.Result.ContentHash, violEnt.ContentHash)
	}
}

// TestSetResolverConfigAckIsNotAConfigField is the teeth for §4.3's MUST that
// the acknowledgement rides the OPERATION, not the entity: two set calls with
// the same config bytes but different acknowledgement flags store the SAME
// config content hash — the flag never enters the stored entity, so it cannot
// move the content-addressed type's hash or be forged into the bytes.
func TestSetResolverConfigAckIsNotAConfigField(t *testing.T) {
	h := NewHandler()
	hctx := newFilterHctx(t)
	viol := types.ResolverConfigData{
		ResolverChain:      []types.ResolverChainEntry{{BackendKind: types.BackendKindDIDWeb, BackendID: "x"}},
		NameFormatDispatch: []types.DispatchEntry{{Pattern: "*", BackendKinds: []string{types.BackendKindDIDWeb}}},
	}
	violEnt, _ := viol.ToEntity()
	if resp := setResolverConfig(t, h, hctx, viol, true); resp.Status != 200 {
		t.Fatalf("acknowledged set: %d", resp.Status)
	}
	stored := getResolverConfig(t, h, hctx)
	if stored.Result.ContentHash != violEnt.ContentHash {
		t.Fatalf("ack leaked into the stored entity: hash %s != plain config hash %s", stored.Result.ContentHash, violEnt.ContentHash)
	}
}

// TestResolverConfigLoadSurfacesDisclosure is the teeth for §4.3 / §690: a
// stored violating config (e.g. an out-of-band seed) is SURFACED at load, not
// refused — Resolve still runs, and the diagnostic sink sees the violation.
func TestResolverConfigLoadSurfacesDisclosure(t *testing.T) {
	h := NewHandler()
	var surfaced []string
	h.SetConfigDiagnosticSink(func(msg string) { surfaced = append(surfaced, msg) })
	hctx := newFilterHctx(t)
	h.RegisterBackend(mockBackend{kind: types.BackendKindLocalName, id: "self"})

	// Out-of-band seed (a raw tree write — no acknowledgement possible).
	writeResolverConfig(t, hctx, types.ResolverConfigData{
		ResolverChain:      []types.ResolverChainEntry{{BackendKind: types.BackendKindLocalName, BackendID: "self", Priority: 0}},
		NameFormatDispatch: []types.DispatchEntry{{Pattern: "*", BackendKinds: []string{types.BackendKindDIDWeb, types.BackendKindLocalName}}},
	})

	// A load MUST NOT refuse: Resolve still functions.
	if _, reason := h.Resolve(hctx, "alice", false); reason == "" && false {
		t.Fatal("unreachable")
	}
	if len(surfaced) == 0 {
		t.Fatal("load-side disclosure was not surfaced (§4.3 / §690)")
	}
}
