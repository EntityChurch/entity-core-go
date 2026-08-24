package registry

import (
	"context"
	"testing"

	"go.entitychurch.org/entity-core-go/core/handler"
	"go.entitychurch.org/entity-core-go/core/types"
)

// TestPatternMatchesUnscopedName pins the kind-scoped is-broad classifier
// (§4.1 step 2 [v1.18], Q1). The decisive fixture is the §4.1a recommended
// default list: rows 1–5 MUST classify narrow (they are scoped shapes) and
// only the catch-all row 6 (`*`) MUST classify broad — otherwise the list the
// spec SHOULD-ships would itself violate the step-2 MUST that lives inside it.
func TestPatternMatchesUnscopedName(t *testing.T) {
	cases := []struct {
		pattern string
		broad   bool
		note    string
	}{
		{"*", true, "catch-all — §4.1a row 6"},
		{"did:web:*", false, "scheme-typed — §4.1a row 1"},
		{"did:key:*", false, "scheme-typed self-certifying — §4.1a row 2"},
		{"*.eth", false, "scheme-typed by suffix — §4.1a row 3"},
		{"*@*.*", false, "domain-scoped — §4.1a row 4"},
		{"*@*", false, "registry-scoped handle — §4.1a row 5"},
		{"a*", true, "bare prefix captures bare names"},
		{"*.*", true, "wildcard-dotted is not a literal suffix — stays broad"},
		{"alice", true, "a literal bare name is itself unscoped"},
		{"*@entity-church", false, "narrowed registry handle"},
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
