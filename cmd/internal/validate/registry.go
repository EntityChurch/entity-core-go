// Category: registry. Probes the EXTENSION-REGISTRY v1.0 surface — the
// meta-resolver + local-name backend + binding/revocation entities — over the
// wire. 14 vectors per the cohort strategy doc, each exercising one
// invariant of the spec:
//
//   v1  bind_round_trip                   — :bind round-trips; entity decodes
//   v2  resolver_config_round_trip        — resolver-config entity decodes
//   v3  meta_resolver_pin_precedence      — pinned binding short-circuits chain
//   v4  meta_resolver_dispatch_filter     — name_format_dispatch narrows chain
//   v5  meta_resolver_chain_exhaustion    — fail-closed when nothing matches
//   v6  meta_resolver_revocation_honored  — revoked binding excluded
//   v7  local-name_bind_invalid_name         — '/' / control chars rejected
//   v8  local-name_bind_already_exists       — 409 when allow_supersede=false
//   v9  local-name_supersedes_chain          — rebind links via Supersedes
//   v10 local-name_list_reads_index          — :list returns live tree pointers
//   v11 unknown_backend_kind_skip         — chain entry with unknown kind skipped
//   v12 unknown_binding_kind_skip         — unknown kind value still decodes
//   v13 invalidate_cache                  — :invalidate-cache returns 200
//   v14 resolution_log_shape              — log entry decodes per §11.2

package validate

import (
	"context"
	"fmt"
	"strings"

	"go.entitychurch.org/entity-core-go/core/ecf"
	"go.entitychurch.org/entity-core-go/core/entity"
	"go.entitychurch.org/entity-core-go/core/hash"
	"go.entitychurch.org/entity-core-go/core/types"
)

const catRegistry = "registry"

func runRegistry(ctx context.Context, client *PeerClient) []CheckResult {
	r := NewCheckRunner(catRegistry)

	r.Declare("v1_bind_round_trip", "REGISTRY §6.5 — :bind succeeds + binding entity decodes")
	r.Declare("v2_resolver_config_round_trip", "REGISTRY §4 — resolver-config entity decodes")
	r.Declare("v3_meta_resolver_pin_precedence", "REGISTRY §4.1.2 — pinned binding short-circuits chain")
	r.Declare("v4_meta_resolver_dispatch_filter", "REGISTRY §4.1 — name_format_dispatch narrows chain")
	r.Declare("v5_meta_resolver_chain_exhaustion", "REGISTRY §4.1 — fail-closed when nothing matches")
	r.Declare("v6_meta_resolver_revocation_honored", "REGISTRY §3.1 — revoked binding excluded")
	r.Declare("v7_local-name_bind_invalid_name", "REGISTRY §6.3 — '/' / control chars rejected with bind_invalid_name")
	r.Declare("v8_local-name_bind_already_exists", "REGISTRY §6.5 — 409 bind_already_exists when allow_supersede=false")
	r.Declare("v9_local-name_supersedes_chain", "REGISTRY §6.5 — rebind links via Supersedes hash")
	r.Declare("v10_local-name_list_reads_index", "REGISTRY §6.5 — :list returns one entry per live pointer")
	r.Declare("v11_unknown_backend_kind_skip", "REGISTRY §4.2 — unknown backend_kind skipped, no crash")
	r.Declare("v12_unknown_binding_kind_skip", "REGISTRY §3.0a — unknown binding kind still decodes")
	r.Declare("v13_invalidate_cache", "REGISTRY §2.1 — :invalidate-cache returns 200")
	r.Declare("v14_resolution_log_shape", "REGISTRY §11.2 — log entry decodes")

	r.Run("v1_bind_round_trip", func() CheckOutcome { return runRegBindRoundTrip(ctx, client) })
	r.Run("v2_resolver_config_round_trip", runRegResolverConfigRoundTrip)
	r.Run("v3_meta_resolver_pin_precedence", func() CheckOutcome { return runRegPinPrecedence(ctx, client) })
	r.Run("v4_meta_resolver_dispatch_filter", func() CheckOutcome { return runRegDispatchFilter(ctx, client) })
	r.Run("v5_meta_resolver_chain_exhaustion", func() CheckOutcome { return runRegChainExhaustion(ctx, client) })
	r.Run("v6_meta_resolver_revocation_honored", func() CheckOutcome { return runRegRevocationHonored(ctx, client) })
	r.Run("v7_local-name_bind_invalid_name", func() CheckOutcome { return runRegBindInvalidName(ctx, client) })
	r.Run("v8_local-name_bind_already_exists", func() CheckOutcome { return runRegBindAlreadyExists(ctx, client) })
	r.Run("v9_local-name_supersedes_chain", func() CheckOutcome { return runRegSupersedesChain(ctx, client) })
	r.Run("v10_local-name_list_reads_index", func() CheckOutcome { return runRegListReadsIndex(ctx, client) })
	r.Run("v11_unknown_backend_kind_skip", func() CheckOutcome { return runRegUnknownBackendKindSkip(ctx, client) })
	r.Run("v12_unknown_binding_kind_skip", runRegUnknownBindingKindSkip)
	r.Run("v13_invalidate_cache", func() CheckOutcome { return runRegInvalidateCache(ctx, client) })
	r.Run("v14_resolution_log_shape", runRegResolutionLogShape)

	return r.Results()
}

// regExecute runs an EXECUTE against the target peer's registry handler.
func regExecute(ctx context.Context, client *PeerClient, handlerURI, op string, params entity.Entity) (uint, entity.Entity, error) {
	uri := fmt.Sprintf("entity://%s/%s", client.RemotePeerID(), handlerURI)
	env, _, err := client.SendExecute(ctx, uri, op, params, nil)
	if err != nil {
		return 0, entity.Entity{}, err
	}
	resp, err := types.ExecuteResponseDataFromEntity(env.Root)
	if err != nil {
		return 0, entity.Entity{}, fmt.Errorf("decode execute-response: %w", err)
	}
	if len(resp.Result) == 0 {
		return resp.Status, entity.Entity{}, nil
	}
	var result entity.Entity
	if err := ecf.Decode(resp.Result, &result); err != nil {
		return resp.Status, entity.Entity{}, fmt.Errorf("decode result entity: %w", err)
	}
	return resp.Status, result, nil
}

// regBind issues a :bind. Returns the resulting binding hash (or zero +
// status when the bind errors).
func regBind(ctx context.Context, client *PeerClient, name, targetPeerID string, notes string) (hash.Hash, uint, error) {
	req := types.LocalNameBindRequestData{
		Name:         name,
		TargetPeerID: targetPeerID,
	}
	if notes != "" {
		req.Notes = &notes
	}
	ent, err := req.ToEntity()
	if err != nil {
		return hash.Hash{}, 0, err
	}
	status, result, err := regExecute(ctx, client, "system/registry/local-name", "bind", ent)
	if err != nil {
		return hash.Hash{}, status, err
	}
	if status != 200 {
		return hash.Hash{}, status, nil
	}
	res, err := types.LocalNameBindResultDataFromEntity(result)
	if err != nil {
		return hash.Hash{}, status, fmt.Errorf("decode bind result: %w", err)
	}
	return res.BindingHash, status, nil
}

func regUnbind(ctx context.Context, client *PeerClient, name string) (uint, error) {
	ent, _ := types.LocalNameUnbindRequestData{Name: name}.ToEntity()
	status, _, err := regExecute(ctx, client, "system/registry/local-name", "unbind", ent)
	return status, err
}

func regResolve(ctx context.Context, client *PeerClient, name string) (types.ResolveResultData, uint, error) {
	ent, _ := types.ResolveRequestData{Name: name}.ToEntity()
	status, result, err := regExecute(ctx, client, "system/registry", "resolve", ent)
	if err != nil {
		return types.ResolveResultData{}, status, err
	}
	if status != 200 {
		return types.ResolveResultData{}, status, nil
	}
	r, err := types.ResolveResultDataFromEntity(result)
	if err != nil {
		return types.ResolveResultData{}, status, fmt.Errorf("decode resolve result: %w", err)
	}
	return r, status, nil
}

// --- Vector implementations -----------------------------------------------

const regSamplePeerID = "2K6kyaA9UNaHHXKUV8cq5GLgc7XJDyVxH8EKiFQnMWeGZY"

func runRegBindRoundTrip(ctx context.Context, client *PeerClient) CheckOutcome {
	name := "validate-bind-rt"
	defer regUnbind(ctx, client, name)
	h, status, err := regBind(ctx, client, name, regSamplePeerID, "round-trip test")
	if err != nil {
		return FailCheck("bind: " + err.Error())
	}
	if status != 200 {
		return FailCheck(fmt.Sprintf("bind status %d, want 200", status))
	}
	if h.IsZero() {
		return FailCheck("bind succeeded but returned zero hash")
	}
	// Round-trip the entity by fetching it via TreeGet at the universal
	// binding path system/registry/binding/{hex}.
	bindPath := types.BindingStoragePath(h)
	ent, _, err := client.TreeGet(ctx, bindPath)
	if err != nil {
		return FailCheck("TreeGet bound binding: " + err.Error())
	}
	bd, err := types.BindingDataFromEntity(ent)
	if err != nil {
		return FailCheck("decode binding: " + err.Error())
	}
	if bd.Name != name || bd.Kind != types.BindingKindLocalName {
		return FailCheck(fmt.Sprintf("binding fields drift: name=%s kind=%s", bd.Name, bd.Kind))
	}
	if bd.TargetPeerID != regSamplePeerID {
		return FailCheck("target_peer_id drift")
	}
	return PassCheck("binding round-trips at " + bindPath)
}

func runRegResolverConfigRoundTrip() CheckOutcome {
	// Pure-Go round-trip — exercises the type without needing wire dispatch
	// (the peer-side resolver-config is operator-installed; not all peers
	// have one bound at this category's start time, so we verify the type
	// surface independently of the live tree state).
	cfg := types.ResolverConfigData{
		ResolverChain: []types.ResolverChainEntry{
			{BackendKind: types.BackendKindLocalName, BackendID: "local", Priority: 0},
		},
		PinnedBindings:        []types.PinnedEntry{{Name: "rt-pin", TargetPeerID: regSamplePeerID}},
		NameFormatDispatch:    []types.DispatchEntry{{Pattern: "*", BackendKinds: []string{types.BackendKindLocalName}}},
		LogCacheHits:          true,
		ResolutionLogCapacity: 256,
	}
	ent, err := cfg.ToEntity()
	if err != nil {
		return FailCheck("encode: " + err.Error())
	}
	if err := ent.Validate(); err != nil {
		return FailCheck("hash validate: " + err.Error())
	}
	dec, err := types.ResolverConfigDataFromEntity(ent)
	if err != nil {
		return FailCheck("decode: " + err.Error())
	}
	if len(dec.ResolverChain) != 1 || len(dec.PinnedBindings) != 1 {
		return FailCheck("fields drift")
	}
	return PassCheck("resolver-config round-trips")
}

func runRegPinPrecedence(ctx context.Context, client *PeerClient) CheckOutcome {
	// Install a resolver-config with one pin, then resolve the pinned name.
	// Result MUST be status=resolved, trust_anchor=out_of_band, backend_id=pinned.
	cfgPath := types.ResolverConfigStoragePath
	pinName := "validate-pin-precedence"
	cfg := types.ResolverConfigData{
		ResolverChain: []types.ResolverChainEntry{
			{BackendKind: types.BackendKindLocalName, BackendID: "local", Priority: 0},
		},
		PinnedBindings: []types.PinnedEntry{{Name: pinName, TargetPeerID: regSamplePeerID}},
	}
	cfgEnt, _ := cfg.ToEntity()
	if _, err := client.TreePut(ctx, cfgPath, cfgEnt); err != nil {
		return FailCheck("install resolver-config: " + err.Error())
	}
	defer client.SendExecute(ctx, fmt.Sprintf("entity://%s/%s", client.RemotePeerID(), cfgPath), "", entity.Entity{}, nil)

	r, status, err := regResolve(ctx, client, pinName)
	if err != nil {
		return FailCheck("resolve: " + err.Error())
	}
	if status != 200 {
		return FailCheck(fmt.Sprintf("resolve status %d", status))
	}
	if r.Status != types.ResolutionStatusResolved {
		return FailCheck("pinned name did not resolve: " + r.Status)
	}
	if r.TrustAnchor != types.TrustAnchorOutOfBand {
		return FailCheck(fmt.Sprintf("trust_anchor %q; want out_of_band", r.TrustAnchor))
	}
	if r.BackendID != "pinned" {
		return FailCheck(fmt.Sprintf("backend_id %q; want pinned", r.BackendID))
	}
	if r.PeerID != regSamplePeerID {
		return FailCheck("peer_id drift")
	}
	return PassCheck("pin short-circuits chain")
}

func runRegDispatchFilter(ctx context.Context, client *PeerClient) CheckOutcome {
	// Install a config where the only chain backend is local-name but the
	// dispatch table routes "did:web:*" exclusively to a (non-existent)
	// did-web backend. Querying a name matching "did:web:*" should yield
	// chain_exhausted (filter narrowed to a backend the peer doesn't have).
	cfg := types.ResolverConfigData{
		ResolverChain: []types.ResolverChainEntry{
			{BackendKind: types.BackendKindLocalName, BackendID: "local", Priority: 0},
		},
		NameFormatDispatch: []types.DispatchEntry{
			{Pattern: "did:web:*", BackendKinds: []string{types.BackendKindDIDWeb}},
		},
	}
	cfgEnt, _ := cfg.ToEntity()
	if _, err := client.TreePut(ctx, types.ResolverConfigStoragePath, cfgEnt); err != nil {
		return FailCheck("install resolver-config: " + err.Error())
	}
	r, _, err := regResolve(ctx, client, "did:web:example.com")
	if err != nil {
		return FailCheck("resolve: " + err.Error())
	}
	if r.Status != types.ResolutionStatusChainExhausted {
		return FailCheck("dispatch did not narrow chain: status=" + r.Status)
	}
	return PassCheck("dispatch filter narrowed local-name out of chain")
}

func runRegChainExhaustion(ctx context.Context, client *PeerClient) CheckOutcome {
	// Install a config with local-name backend only; resolve an unbound name.
	cfg := types.ResolverConfigData{
		ResolverChain: []types.ResolverChainEntry{
			{BackendKind: types.BackendKindLocalName, BackendID: "local", Priority: 0},
		},
	}
	cfgEnt, _ := cfg.ToEntity()
	if _, err := client.TreePut(ctx, types.ResolverConfigStoragePath, cfgEnt); err != nil {
		return FailCheck("install resolver-config: " + err.Error())
	}
	r, _, err := regResolve(ctx, client, "definitely-not-bound-"+randomSuffix())
	if err != nil {
		return FailCheck("resolve: " + err.Error())
	}
	// LocalName returns not_found internally; meta-resolver converts to
	// chain_exhausted when all backends fail.
	if r.Status != types.ResolutionStatusChainExhausted {
		return FailCheck("chain didn't exhaust: " + r.Status)
	}
	return PassCheck("unbound name → chain_exhausted")
}

func runRegRevocationHonored(ctx context.Context, client *PeerClient) CheckOutcome {
	// Bind a local-name, then write a revocation entity that targets the
	// binding. :resolve must NOT return the revoked binding.
	name := "validate-revocation-target"
	defer regUnbind(ctx, client, name)
	bindingHash, status, err := regBind(ctx, client, name, regSamplePeerID, "")
	if err != nil || status != 200 {
		return FailCheck(fmt.Sprintf("setup bind: status=%d err=%v", status, err))
	}
	// Install a chain that just has local-name.
	cfg := types.ResolverConfigData{
		ResolverChain: []types.ResolverChainEntry{
			{BackendKind: types.BackendKindLocalName, BackendID: "local", Priority: 0},
		},
	}
	cfgEnt, _ := cfg.ToEntity()
	client.TreePut(ctx, types.ResolverConfigStoragePath, cfgEnt)

	revocation := types.RevocationData{
		Revokes:   bindingHash,
		RevokedAt: 1_730_000_000_000,
	}
	revEnt, _ := revocation.ToEntity()
	revPath := types.RevocationStoragePath(revEnt.ContentHash)
	if _, err := client.TreePut(ctx, revPath, revEnt); err != nil {
		return FailCheck("install revocation: " + err.Error())
	}
	r, _, err := regResolve(ctx, client, name)
	if err != nil {
		return FailCheck("resolve after revocation: " + err.Error())
	}
	if r.Status == types.ResolutionStatusResolved {
		return FailCheck("revoked binding still resolved")
	}
	return PassCheck("revoked binding excluded; status=" + r.Status)
}

func runRegBindInvalidName(ctx context.Context, client *PeerClient) CheckOutcome {
	// Names with '/' must reject with status=400 bind_invalid_name per §6.5.
	_, status, err := regBind(ctx, client, "has/slash", regSamplePeerID, "")
	if err == nil && status != 400 {
		return FailCheck(fmt.Sprintf("'/' name accepted (status=%d)", status))
	}
	if status != 400 {
		return FailCheck(fmt.Sprintf("status %d, want 400", status))
	}
	// Control char.
	_, status, _ = regBind(ctx, client, "has\x01control", regSamplePeerID, "")
	if status != 400 {
		return FailCheck(fmt.Sprintf("control char accepted (status=%d)", status))
	}
	return PassCheck("invalid names rejected with 400")
}

func runRegBindAlreadyExists(ctx context.Context, client *PeerClient) CheckOutcome {
	name := "validate-bae-" + randomSuffix()
	defer regUnbind(ctx, client, name)
	// Install a local-name-config that disables supersede. The handler reads
	// local-name-config fresh on every op, so the second :bind sees this
	// config and returns 409.
	pc := types.LocalNameConfigData{
		DefaultPinned:     true,
		AllowSupersede:    false,
		CaseNormalization: types.CaseNormalizationNone,
	}
	pcEnt, _ := pc.ToEntity()
	if _, err := client.TreePut(ctx, types.LocalNameConfigStoragePath, pcEnt); err != nil {
		return FailCheck("install local-name-config: " + err.Error())
	}
	defer func() {
		// restore default to leave the peer in a sane state for later tests.
		restore := types.LocalNameConfigData{
			DefaultPinned:     true,
			AllowSupersede:    true,
			CaseNormalization: types.CaseNormalizationNone,
		}
		rEnt, _ := restore.ToEntity()
		client.TreePut(ctx, types.LocalNameConfigStoragePath, rEnt)
	}()
	_, status, err := regBind(ctx, client, name, regSamplePeerID, "")
	if err != nil || status != 200 {
		return FailCheck(fmt.Sprintf("first bind: status=%d err=%v", status, err))
	}
	_, status, _ = regBind(ctx, client, name, regSamplePeerID, "")
	if status != 409 {
		return FailCheck(fmt.Sprintf("second bind with allow_supersede=false: status=%d, want 409", status))
	}
	return PassCheck("bind_already_exists 409 fired with allow_supersede=false")
}

func runRegSupersedesChain(ctx context.Context, client *PeerClient) CheckOutcome {
	name := "validate-supersede-" + randomSuffix()
	defer regUnbind(ctx, client, name)
	h1, _, _ := regBind(ctx, client, name, regSamplePeerID, "")
	h2, _, _ := regBind(ctx, client, name, regSamplePeerID, "")
	if h1.IsZero() || h2.IsZero() || h1 == h2 {
		return FailCheck("rebind did not produce distinct hashes")
	}
	// Fetch the head binding (h2); its Supersedes must point to h1.
	ent, _, err := client.TreeGet(ctx, types.BindingStoragePath(h2))
	if err != nil {
		return FailCheck("fetch head: " + err.Error())
	}
	bd, _ := types.BindingDataFromEntity(ent)
	if bd.Supersedes == nil || *bd.Supersedes != h1 {
		return FailCheck("Supersedes does not chain to prior binding")
	}
	return PassCheck("supersedes chain links rebinds")
}

func runRegListReadsIndex(ctx context.Context, client *PeerClient) CheckOutcome {
	n1 := "validate-list-a-" + randomSuffix()
	n2 := "validate-list-b-" + randomSuffix()
	defer regUnbind(ctx, client, n1)
	defer regUnbind(ctx, client, n2)
	if _, _, err := regBind(ctx, client, n1, regSamplePeerID, ""); err != nil {
		return FailCheck("setup bind 1: " + err.Error())
	}
	if _, _, err := regBind(ctx, client, n2, regSamplePeerID, ""); err != nil {
		return FailCheck("setup bind 2: " + err.Error())
	}
	listReq, _ := types.LocalNameListRequestData{}.ToEntity()
	status, result, err := regExecute(ctx, client, "system/registry/local-name", "list", listReq)
	if err != nil {
		return FailCheck("list: " + err.Error())
	}
	if status != 200 {
		return FailCheck(fmt.Sprintf("list status %d", status))
	}
	res, err := types.LocalNameListResultDataFromEntity(result)
	if err != nil {
		return FailCheck("decode list result: " + err.Error())
	}
	seen := map[string]bool{}
	for _, e := range res.Entries {
		seen[e.Name] = true
	}
	if !seen[n1] || !seen[n2] {
		return FailCheck(fmt.Sprintf("list missing entries: have %d, want both %s + %s", len(res.Entries), n1, n2))
	}
	return PassCheck(fmt.Sprintf("list returned %d entries including both bindings", len(res.Entries)))
}

func runRegUnknownBackendKindSkip(ctx context.Context, client *PeerClient) CheckOutcome {
	// Install a chain with TWO entries: an unknown backend first (priority 0),
	// local-name second (priority 10). The unknown MUST be skipped and the
	// resolve must reach local-name (which then returns not_found → chain_exhausted).
	cfg := types.ResolverConfigData{
		ResolverChain: []types.ResolverChainEntry{
			{BackendKind: "wakanda-unknown-2026", BackendID: "any", Priority: 0},
			{BackendKind: types.BackendKindLocalName, BackendID: "local", Priority: 10},
		},
	}
	cfgEnt, _ := cfg.ToEntity()
	client.TreePut(ctx, types.ResolverConfigStoragePath, cfgEnt)
	r, _, err := regResolve(ctx, client, "validate-unknown-backend-skip-"+randomSuffix())
	if err != nil {
		return FailCheck("resolve: " + err.Error())
	}
	if r.Status != types.ResolutionStatusChainExhausted {
		return FailCheck("expected chain_exhausted after unknown-skip; got " + r.Status)
	}
	return PassCheck("unknown backend_kind skipped; chain advanced to local-name")
}

func runRegUnknownBindingKindSkip() CheckOutcome {
	// Pure-Go: a binding entity with an unknown `kind` MUST still decode
	// without error per §3.0a (forward-compat). The meta_resolve filter is
	// what excludes it from results.
	d := types.BindingData{
		Name:         "future-kind",
		Kind:         "alien-2030",
		TargetPeerID: regSamplePeerID,
		IssuedAt:     1_730_000_000_000,
	}
	ent, err := d.ToEntity()
	if err != nil {
		return FailCheck("encode: " + err.Error())
	}
	if err := ent.Validate(); err != nil {
		return FailCheck("validate: " + err.Error())
	}
	dec, err := types.BindingDataFromEntity(ent)
	if err != nil {
		return FailCheck("decode: " + err.Error())
	}
	if dec.Kind != "alien-2030" {
		return FailCheck("kind drift on round-trip")
	}
	return PassCheck("forward-compat unknown binding kind decodes")
}

func runRegInvalidateCache(ctx context.Context, client *PeerClient) CheckOutcome {
	req, _ := types.InvalidateCacheRequestData{}.ToEntity()
	status, _, err := regExecute(ctx, client, "system/registry", "invalidate-cache", req)
	if err != nil {
		return FailCheck("invalidate-cache: " + err.Error())
	}
	if status != 200 {
		return FailCheck(fmt.Sprintf("status %d", status))
	}
	return PassCheck("invalidate-cache 200")
}

func runRegResolutionLogShape() CheckOutcome {
	// Pure-Go round-trip of a resolution-log entry per §11.2 shape.
	bid := "local"
	reason := "pin_short_circuit"
	bindingHash := hash.Hash{Algorithm: hash.AlgorithmSHA256}
	bindingHash.Digest[0] = 0x77
	d := types.ResolutionLogData{
		Seq:                 42,
		Name:                "alice",
		BackendID:           &bid,
		Status:              types.ResolutionStatusResolved,
		Reason:              &reason,
		Binding:             &bindingHash,
		AttemptedAt:         1_730_000_000_000,
		IsFallbackReresolve: false,
	}
	ent, err := d.ToEntity()
	if err != nil {
		return FailCheck("encode: " + err.Error())
	}
	if err := ent.Validate(); err != nil {
		return FailCheck("hash validate: " + err.Error())
	}
	dec, err := types.ResolutionLogDataFromEntity(ent)
	if err != nil {
		return FailCheck("decode: " + err.Error())
	}
	if dec.Seq != 42 || dec.Status != types.ResolutionStatusResolved {
		return FailCheck("fields drift")
	}
	if dec.BackendID == nil || *dec.BackendID != "local" {
		return FailCheck("backend_id drift")
	}
	return PassCheck("resolution-log shape round-trips")
}

// --- Helpers --------------------------------------------------------------

var regRandSeed = uint64(1)

// randomSuffix returns a short ASCII suffix unique per call within this
// process. Avoids stdlib `math/rand` to keep the import set narrow and to
// ensure test-name uniqueness without seeding.
func randomSuffix() string {
	regRandSeed = regRandSeed*6364136223846793005 + 1442695040888963407 // splitmix-style
	v := regRandSeed >> 32
	const base = "abcdefghjklmnpqrstuvwxyz23456789"
	var buf [6]byte
	for i := range buf {
		buf[i] = base[v%uint64(len(base))]
		v /= uint64(len(base))
	}
	return string(buf[:])
}

// keep strings import in case the test grows
var _ = strings.HasPrefix
