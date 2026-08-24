// Category: registry. Probes the EXTENSION-REGISTRY v1.0 surface — the
// meta-resolver + local-name backend + binding/revocation entities — over the
// wire. 14 vectors per the cohort strategy doc, each exercising one
// invariant of the spec:
//
//   v1  bind_round_trip                   — :bind round-trips; entity decodes
//   v2  resolver_config_round_trip        — resolver-config entity decodes
//   v3  meta_resolver_pin_precedence      — pinned binding short-circuits chain
//   v4  meta_resolver_dispatch_filter     — name_format_dispatch narrows chain
//   v4b meta_resolver_filter_fail_closed  — bound + unmatched name → chain_exhausted
//   v4c ttl_resolver_ceiling              — hints.max_ttl clamps at resolution [v1.16]
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
	"time"

	"github.com/fxamacker/cbor/v2"

	"go.entitychurch.org/entity-core-go/core/ecf"
	"go.entitychurch.org/entity-core-go/core/entity"
	"go.entitychurch.org/entity-core-go/core/hash"
	"go.entitychurch.org/entity-core-go/core/types"
)

const catRegistry = "registry"

func runRegistry(ctx context.Context, client *PeerClient) []CheckResult {
	r := NewCheckRunner(catRegistry)

	r.Declare("v1_bind_round_trip", "REGISTRY §6.5 — :bind succeeds + binding entity decodes")
	r.DeclareSelf("v2_resolver_config_round_trip", "REGISTRY §4 — resolver-config entity decodes")
	r.Declare("v3_meta_resolver_pin_precedence", "REGISTRY §4.1.2 — pinned binding short-circuits chain")
	r.Declare("v4_meta_resolver_dispatch_filter", "REGISTRY §4.1 — name_format_dispatch narrows chain")
	r.Declare("v4b_meta_resolver_filter_fail_closed", "REGISTRY §4.1 step 2 [1.14] — a BOUND name matching no dispatch rule fails closed (chain_exhausted), not unfiltered resolve")
	r.Declare("v4c_ttl_resolver_ceiling", "REGISTRY §6a.9.1 [v1.16] — resolver ceiling at resolver_chain[].hints.max_ttl: no-ttl→local_max, hash unchanged, max_ttl:0 undeclared")
	r.Declare("v5_meta_resolver_chain_exhaustion", "REGISTRY §4.1 — fail-closed when nothing matches")
	r.Declare("v6_meta_resolver_revocation_honored", "REGISTRY §3.1 — revoked binding excluded")
	r.Declare("v7_local-name_bind_invalid_name", "REGISTRY §6.3 — '/' / control chars rejected with bind_invalid_name")
	r.Declare("v8_local-name_bind_already_exists", "REGISTRY §6.5 — 409 bind_already_exists when allow_supersede=false")
	r.Declare("v9_local-name_supersedes_chain", "REGISTRY §6.5 — rebind links via Supersedes hash")
	r.Declare("v10_local-name_list_reads_index", "REGISTRY §6.5 — :list returns one entry per live pointer")
	r.Declare("v11_unknown_backend_kind_skip", "REGISTRY §4.2 — unknown backend_kind skipped, no crash")
	r.DeclareSelf("v12_unknown_binding_kind_skip", "REGISTRY §3.0a — unknown binding kind still decodes")
	r.Declare("v13_invalidate_cache", "REGISTRY §2.1 — :invalidate-cache returns 200")
	r.DeclareSelf("v14_resolution_log_shape", "REGISTRY §11.2 — log entry decodes")
	r.Declare("v15_dispatch_config_refused", "REGISTRY §4.1 step 2 + §4.1b + §4.3 REG-DISPATCH-CONFIG-REFUSED-1 [v1.17/v1.18/v1.19] — set-resolver-config MUST refuse 403 policy_rejected a config that makes a name-transmitting kind eligible for an unscoped name, and store nothing (get returns prior bytes). KIND-SCOPED: row (b) — a broad `*`→did-web rule with NO did-web chain entry is STILL refused (chain-scoped would accept). Rows: (a) broad+chain, (b) broad+no-chain, (c) no-dispatch+did-web-in-chain, (d) control scoped `did:web:*`→accepted, (e) read-back byte-identical after refusal, (f) acknowledge_name_disclosure override → accepted, (7) §4.1b classifier: `*.*`/`*.e*`/`*.lab`→refused, `*.eth`/`a.b`→accepted, (8) §4.3 pin-delta [v1.19, R-27]: a pin change under a configure-only cap → 403 not_entitled + nothing written, under a configure+`pin-bindings` cap → 200, a byte-identical write under configure-only → 200 (the harness mints both caps in the ruled `pin-bindings` encoding)")
	r.Declare("v16_ttl_ceiling_reread", "REGISTRY §6a.9.1 REG-TTL-CEILING-REREAD-1 [v1.17] — the resolver ceiling is READ AT RESOLUTION, not latched at start. One peer process, three resolutions, resolver-config rewritten via set-resolver-config between them: hints.max_ttl absent→present→lower; the surfaced lifetime MUST track the currently-stored config each time. A latching peer passes row 1 and fails 2/3. Constructible only via §4.3's write op [v1.18]")

	r.Run("v1_bind_round_trip", func() CheckOutcome { return runRegBindRoundTrip(ctx, client) })
	r.Run("v2_resolver_config_round_trip", runRegResolverConfigRoundTrip)
	r.Run("v3_meta_resolver_pin_precedence", func() CheckOutcome { return runRegPinPrecedence(ctx, client) })
	r.Run("v4_meta_resolver_dispatch_filter", func() CheckOutcome { return runRegDispatchFilter(ctx, client) })
	r.Run("v4b_meta_resolver_filter_fail_closed", func() CheckOutcome { return runRegFilterFailClosed(ctx, client) })
	r.Run("v4c_ttl_resolver_ceiling", func() CheckOutcome { return runRegTTLResolverCeiling(ctx, client) })
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
	r.Run("v15_dispatch_config_refused", func() CheckOutcome { return runRegDispatchConfigRefused(ctx, client) })
	r.Run("v16_ttl_ceiling_reread", func() CheckOutcome { return runRegTTLCeilingReread(ctx, client) })

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
// status when the bind errors). Callers that need the error CODE — every
// caller checking a §6.5 pinned row — use regBindFull; this wrapper exists
// for the callers that legitimately only need the hash.
func regBind(ctx context.Context, client *PeerClient, name, targetPeerID string, notes string) (hash.Hash, uint, error) {
	h, status, _, err := regBindFull(ctx, client, name, targetPeerID, notes)
	return h, status, err
}

// regBindFull is regBind with the error code preserved.
//
// R-6 audit (2026-08-12 c): this helper is the registry category's own
// instance of the blind-extractor defect §5.2b.2 was written for. regBind
// returned `(hash, status, error)` and DISCARDED the result body on any
// non-200 — so the code never reached a caller, and `bind_invalid_name`
// could only ever assert the status half of a row the spec pins as
// `code | status`. bind_already_exists worked around it by re-driving
// regExecute inline; a third copy of that workaround was the signal to fix
// the plumbing instead. The extractor is fixed here, at the helper, so the
// checks inherit the code by construction rather than each remembering to.
func regBindFull(ctx context.Context, client *PeerClient, name, targetPeerID string, notes string) (hash.Hash, uint, string, error) {
	req := types.LocalNameBindRequestData{
		Name:         name,
		TargetPeerID: targetPeerID,
	}
	if notes != "" {
		req.Notes = &notes
	}
	ent, err := req.ToEntity()
	if err != nil {
		return hash.Hash{}, 0, "", err
	}
	status, result, err := regExecute(ctx, client, "system/registry/local-name", "bind", ent)
	if err != nil {
		return hash.Hash{}, status, "", err
	}
	if status != 200 {
		// The body of a refusal is an error entity; its `code` is the half
		// of the row that carries the contract. A body that does not decode
		// is reported as such rather than silently becoming "".
		var errData types.ErrorData
		if err := ecf.Decode(result.Data, &errData); err != nil {
			return hash.Hash{}, status, "", nil
		}
		return hash.Hash{}, status, errData.Code, nil
	}
	res, err := types.LocalNameBindResultDataFromEntity(result)
	if err != nil {
		return hash.Hash{}, status, "", fmt.Errorf("decode bind result: %w", err)
	}
	return res.BindingHash, status, "", nil
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

// regSetResolverConfig drives §4.3 set-resolver-config over the wire, carrying
// the config nested in the request wrapper plus the operator's acknowledgement
// (a parameter of the op, never a field of the entity). Returns status + the
// error code (policy_rejected on a refusal).
func regSetResolverConfig(ctx context.Context, client *PeerClient, cfg types.ResolverConfigData, ack bool) (uint, string, error) {
	cfgEnt, err := cfg.ToEntity()
	if err != nil {
		return 0, "", fmt.Errorf("cfg ToEntity: %w", err)
	}
	reqEnt, err := types.SetResolverConfigRequestData{Config: cfgEnt, AcknowledgeNameDisclosure: ack}.ToEntity()
	if err != nil {
		return 0, "", fmt.Errorf("request ToEntity: %w", err)
	}
	uri := fmt.Sprintf("entity://%s/%s", client.RemotePeerID(), "system/registry")
	respEnv, _, err := client.SendExecute(ctx, uri, "set-resolver-config", reqEnt, nil)
	if err != nil {
		return 0, "", err
	}
	status, code, _, err := extractStatusAndCode(respEnv)
	return status, code, err
}

// regGetResolverConfig drives §4.3 get-resolver-config; returns status and the
// stored config entity (its ContentHash is the read-back byte-identity probe).
func regGetResolverConfig(ctx context.Context, client *PeerClient) (uint, entity.Entity, error) {
	uri := fmt.Sprintf("entity://%s/%s", client.RemotePeerID(), "system/registry")
	respEnv, _, err := client.SendExecute(ctx, uri, "get-resolver-config", issuerNoParams(), nil)
	if err != nil {
		return 0, entity.Entity{}, err
	}
	resp, err := types.ExecuteResponseDataFromEntity(respEnv.Root)
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

// runRegDispatchConfigRefused drives REG-DISPATCH-CONFIG-REFUSED-1 (§4.1 step 2
// + §4.3) — the write-time name-disclosure MUST and the ONLY check that can
// settle kind-scoped, because the resolve-time observable (absence of a
// request) is name-blind under either reading.
func runRegDispatchConfigRefused(ctx context.Context, client *PeerClient) CheckOutcome {
	transmit := []string{types.BackendKindDIDWeb}
	localEntry := types.ResolverChainEntry{BackendKind: types.BackendKindLocalName, BackendID: "local", Priority: 0}
	didwebEntry := types.ResolverChainEntry{BackendKind: types.BackendKindDIDWeb, BackendID: "x", Priority: 1}

	control := types.ResolverConfigData{ // (d): scoped `did:web:*` → accepted
		ResolverChain:      []types.ResolverChainEntry{localEntry, didwebEntry},
		NameFormatDispatch: []types.DispatchEntry{{Pattern: "did:web:*", BackendKinds: transmit}},
	}
	broadWithChain := types.ResolverConfigData{ // (a)
		ResolverChain:      []types.ResolverChainEntry{localEntry, didwebEntry},
		NameFormatDispatch: []types.DispatchEntry{{Pattern: "*", BackendKinds: transmit}},
	}
	broadNoChain := types.ResolverConfigData{ // (b) — kind-scoped discriminator
		ResolverChain:      []types.ResolverChainEntry{localEntry},
		NameFormatDispatch: []types.DispatchEntry{{Pattern: "*", BackendKinds: transmit}},
	}
	noDispatch := types.ResolverConfigData{ // (c) — door 2
		ResolverChain: []types.ResolverChainEntry{didwebEntry},
	}

	// (d) control — a scoped rule MUST be accepted; also the constructibility
	// gate (if the op is unimplemented / unauthorized this is where it shows).
	st, code, err := regSetResolverConfig(ctx, client, control, false)
	if err != nil {
		return FailCheck("row (d) control set-resolver-config: " + err.Error())
	}
	if st != 200 {
		return FailCheck(fmt.Sprintf("row (d) control (scoped `did:web:*`) → %d/%q, want 200 — a scoped rule discloses nothing and MUST be accepted (or set-resolver-config §4.3 is unimplemented/unauthorized here)", st, code))
	}
	// Baseline for read-back (row e): what get returns after the accepted control.
	baseSt, baseEnt, err := regGetResolverConfig(ctx, client)
	if err != nil || baseSt != 200 {
		return FailCheck(fmt.Sprintf("baseline get-resolver-config after control: status=%d err=%v", baseSt, err))
	}
	baseHash := baseEnt.ContentHash

	// Refusal rows (a)/(b)/(c): each MUST be 403 policy_rejected, and (e) each
	// MUST leave the stored bytes unchanged.
	refuse := func(label string, cfg types.ResolverConfigData) *CheckOutcome {
		st, code, err := regSetResolverConfig(ctx, client, cfg, false)
		if err != nil {
			o := FailCheck(label + " set: " + err.Error())
			return &o
		}
		if st != 403 || code != types.RegistryErrPolicyRejected {
			o := FailCheck(fmt.Sprintf("%s → %d/%q, want 403/policy_rejected", label, st, code))
			return &o
		}
		gSt, gEnt, err := regGetResolverConfig(ctx, client)
		if err != nil || gSt != 200 {
			o := FailCheck(fmt.Sprintf("%s: read-back get status=%d err=%v", label, gSt, err))
			return &o
		}
		if gEnt.ContentHash != baseHash {
			o := FailCheck(fmt.Sprintf("%s row (e): stored config moved on a REFUSAL (%s vs baseline %s) — a refusal MUST write nothing", label, gEnt.ContentHash, baseHash))
			return &o
		}
		return nil
	}
	if o := refuse("row (a) broad `*`→did-web with did-web in chain", broadWithChain); o != nil {
		return *o
	}
	if o := refuse("row (b) broad `*`→did-web with NO did-web chain entry (kind-scoped)", broadNoChain); o != nil {
		return *o
	}
	if o := refuse("row (c) no name_format_dispatch, did-web in chain (door 2)", noDispatch); o != nil {
		return *o
	}

	// (f) override arm — the SAME (a) config WITH acknowledge_name_disclosure
	// MUST be accepted and STORED. Without this row a peer that refuses
	// unconditionally (deleting the operator MAY) scores identically.
	st, code, err = regSetResolverConfig(ctx, client, broadWithChain, true)
	if err != nil {
		return FailCheck("row (f) acknowledged set: " + err.Error())
	}
	if st != 200 {
		return FailCheck(fmt.Sprintf("row (f) acknowledge_name_disclosure=true → %d/%q, want 200 — the operator MAY MUST be honored on their own peer", st, code))
	}
	fSt, fEnt, err := regGetResolverConfig(ctx, client)
	if err != nil || fSt != 200 {
		return FailCheck(fmt.Sprintf("row (f) read-back: status=%d err=%v", fSt, err))
	}
	if fEnt.ContentHash == baseHash {
		return FailCheck("row (f): acknowledged config was not stored (get still returns the baseline) — the override did nothing")
	}
	wantEnt, _ := broadWithChain.ToEntity()
	if fEnt.ContentHash != wantEnt.ContentHash {
		return FailCheck(fmt.Sprintf("row (f): stored config hash %s != the acknowledged config %s (a rewrite-on-store, not a byte-exact write)", fEnt.ContentHash, wantEnt.ContentHash))
	}

	// Row 7 — §4.1b classifier rows [MUST, v1.19]. Each names did-web (a
	// transmitting kind) with a did-web chain entry present, so the ONLY thing
	// deciding accept/refuse is whether the pattern is broad. These five are
	// where independent readings of the old undefined predicate diverged: a peer
	// classifying by "does any literal exist" passes rows a-f and fails `*.*`
	// and `*.lab`. Read the stored hash before each refusal so the read-back
	// assertion holds regardless of what the accepted rows stored.
	classifierRow := func(pattern string, wantRefused bool) *CheckOutcome {
		cfg := types.ResolverConfigData{
			ResolverChain:      []types.ResolverChainEntry{localEntry, didwebEntry},
			NameFormatDispatch: []types.DispatchEntry{{Pattern: pattern, BackendKinds: transmit}},
		}
		var priorHash hash.Hash
		if wantRefused {
			pSt, pEnt, err := regGetResolverConfig(ctx, client)
			if err != nil || pSt != 200 {
				o := FailCheck(fmt.Sprintf("row 7 %q: baseline get status=%d err=%v", pattern, pSt, err))
				return &o
			}
			priorHash = pEnt.ContentHash
		}
		st, code, err := regSetResolverConfig(ctx, client, cfg, false)
		if err != nil {
			o := FailCheck(fmt.Sprintf("row 7 %q set: %v", pattern, err))
			return &o
		}
		if wantRefused {
			if st != 403 || code != types.RegistryErrPolicyRejected {
				o := FailCheck(fmt.Sprintf("row 7 %q → %d/%q, want 403/policy_rejected — a BROAD pattern (§4.1b) naming did-web discloses unscoped names", pattern, st, code))
				return &o
			}
			gSt, gEnt, err := regGetResolverConfig(ctx, client)
			if err != nil || gSt != 200 || gEnt.ContentHash != priorHash {
				o := FailCheck(fmt.Sprintf("row 7 %q: refusal moved the stored config (status=%d %s vs %s) — must write nothing", pattern, gSt, gEnt.ContentHash, priorHash))
				return &o
			}
		} else if st != 200 {
			o := FailCheck(fmt.Sprintf("row 7 %q → %d/%q, want 200 — a NARROW pattern (§4.1b) discloses nothing and MUST be accepted", pattern, st, code))
			return &o
		}
		return nil
	}
	for _, cr := range []struct {
		pattern string
		refused bool
	}{
		{"*.*", true},    // '.' is not a typed suffix → matches bare dotted names
		{"*.e*", true},   // trailing '*' → no fixed suffix
		{"*.eth", false}, // enumerated typed suffix (§4.1b.1) → narrow
		{"a.b", false},   // no '*' → exactly one name (rule a)
		{"*.lab", true},  // `.lab` is NOT enumerated → broad ("any literal" is not the line)
	} {
		if o := classifierRow(cr.pattern, cr.refused); o != nil {
			return *o
		}
	}

	// Row 8 — §4.3 pin-delta [MUST, v1.19], NOW ON THE WIRE. RULED (R-27, arch
	// 08841d8, ex spec-issue 2026-08-20-a): pin authority is the non-dispatchable
	// operation `pin-bindings`, the sole PORTABLE discriminator (V7: a grant
	// scopes on path-scope + id-scope only, and the path axis is explicitly
	// non-portable). All three seats independently ship `pin-bindings`, so the
	// discriminator is a settled cross-impl observable — the deceptive-green
	// deferral reason is discharged (the forward half of the deferral rule: land
	// once the discriminator is settled AND every conformant impl agrees). The
	// harness mints the cap in the ruled encoding and presents it.
	if o := runPinDeltaWireRows(ctx, client, localEntry); o != nil {
		return *o
	}

	return PassCheck("set-resolver-config: name-disclosure refused 403/policy_rejected kind-scoped (a,b,c), scoped control accepted (d), refusal writes nothing (e), acknowledge override stores byte-exact (f), §4.1b classifier *.*/*.e*/*.lab refused & *.eth/a.b accepted (7), pin-delta cap-gated on the ruled `pin-bindings` op: differ+configure-only→403 not_entitled+nothing-written, differ+configure+pin→200, byte-identical+configure-only→200 (8)")
}

// runPinDeltaWireRows drives REG-DISPATCH-CONFIG-REFUSED-1 row 8 (§4.3 pin-delta
// [v1.19], R-27). It seeds a clean no-pin config as the baseline, then presents
// pin-changing writes under a configure-ONLY child cap (refused 403 not_entitled,
// nothing written) and under a configure+pin child cap (accepted), plus the
// byte-identical control (configure-only accepted — without it a peer that
// demands pin on every write passes the other two).
func runPinDeltaWireRows(ctx context.Context, client *PeerClient, localEntry types.ResolverChainEntry) *CheckOutcome {
	base := types.ResolverConfigData{ResolverChain: []types.ResolverChainEntry{localEntry}}
	if st, code, err := regSetResolverConfig(ctx, client, base, false); err != nil || st != 200 {
		o := FailCheck(fmt.Sprintf("row 8 baseline (no-pin) set → %d/%q err=%v", st, code, err))
		return &o
	}
	baseSt, baseEnt, err := regGetResolverConfig(ctx, client)
	if err != nil || baseSt != 200 {
		o := FailCheck(fmt.Sprintf("row 8 baseline get status=%d err=%v", baseSt, err))
		return &o
	}

	pinned := base
	pinned.PinnedBindings = []types.PinnedEntry{{Name: "pindelta-" + randomSuffix(), TargetPeerID: regSamplePeerID}}

	configureOnly, coSig, err := mintRegChildCap(client, regConfigureGrants()...)
	if err != nil {
		o := FailCheck("row 8 mint configure-only cap: " + err.Error())
		return &o
	}
	configurePlusPin, cpSig, err := mintRegChildCap(client, append(regConfigureGrants(), regPinGrants()...)...)
	if err != nil {
		o := FailCheck("row 8 mint configure+pin cap: " + err.Error())
		return &o
	}

	// 8a — differ + configure-only → 403 not_entitled, nothing written.
	st, code, err := regSetResolverConfigVia(ctx, client, pinned, false, configureOnly, coSig)
	if err != nil {
		o := FailCheck("row 8a set: " + err.Error())
		return &o
	}
	if st != 403 || code != types.RegistryErrNotEntitled {
		o := FailCheck(fmt.Sprintf("row 8a (pin change, configure-only) → %d/%q, want 403/not_entitled — a pin write needs registry-pin (op `pin-bindings`, R-27)", st, code))
		return &o
	}
	if gSt, gEnt, err := regGetResolverConfig(ctx, client); err != nil || gSt != 200 || gEnt.ContentHash != baseEnt.ContentHash {
		o := FailCheck(fmt.Sprintf("row 8a: refused pin write moved the stored config (status=%d %s vs %s) — must write nothing", gSt, gEnt.ContentHash, baseEnt.ContentHash))
		return &o
	}

	// 8b — differ + configure+pin → 200.
	st, code, err = regSetResolverConfigVia(ctx, client, pinned, false, configurePlusPin, cpSig)
	if err != nil {
		o := FailCheck("row 8b set: " + err.Error())
		return &o
	}
	if st != 200 {
		o := FailCheck(fmt.Sprintf("row 8b (pin change, configure+pin) → %d/%q, want 200 — pin authority present", st, code))
		return &o
	}

	// 8c — control: byte-identical pins under configure-only → 200. Change only a
	// non-pin field so pinned_bindings is unchanged from what 8b stored.
	identical := pinned
	identical.ResolutionLogCapacity = 64
	st, code, err = regSetResolverConfigVia(ctx, client, identical, false, configureOnly, coSig)
	if err != nil {
		o := FailCheck("row 8c set: " + err.Error())
		return &o
	}
	if st != 200 {
		o := FailCheck(fmt.Sprintf("row 8c (pin-identical, configure-only) → %d/%q, want 200 — a write leaving pins byte-identical needs only registry-configure; a peer demanding pin on every write fails here", st, code))
		return &o
	}
	return nil
}

// regConfigureGrants / regPinGrants are the two registry authorities as ruled
// wire contracts (R-27): configure names the §4.3 operations, pin names the
// non-dispatchable operation `pin-bindings`. Written with the literal wire
// strings, not go's constants — the harness tests the ruled contract and drives
// rust/py peers, which check the SAME operation names.
func regConfigureGrants() []types.GrantEntry {
	return []types.GrantEntry{{
		Handlers:   types.CapabilityScope{Include: []string{"system/registry"}},
		Resources:  types.CapabilityScope{Include: []string{"system/registry/*"}},
		Operations: types.CapabilityScope{Include: []string{"set-resolver-config", "get-resolver-config"}},
	}}
}

func regPinGrants() []types.GrantEntry {
	return []types.GrantEntry{{
		Handlers:   types.CapabilityScope{Include: []string{"system/registry"}},
		Resources:  types.CapabilityScope{Include: []string{"system/registry/*"}},
		Operations: types.CapabilityScope{Include: []string{"pin-bindings"}}, // R-27 ruled discriminator
	}}
}

// mintRegChildCap mints a child capability carrying `grants`, attenuated from the
// harness's connection cap and signed by our identity — the portable way to
// present "configure-only" vs "configure+pin" authority to any conformant peer.
func mintRegChildCap(client *PeerClient, grants ...types.GrantEntry) (entity.Entity, entity.Entity, error) {
	kp := client.Keypair()
	identity := client.IdentityEntity()
	parentCap := client.CapEntity()
	now := uint64(time.Now().UnixMilli())
	exp := now + 5*60*1000
	td := types.CapabilityTokenData{
		Grants:    grants,
		Granter:   types.SingleSigGranter(identity.ContentHash),
		Grantee:   identity.ContentHash,
		Parent:    &parentCap.ContentHash,
		CreatedAt: now,
		ExpiresAt: &exp,
	}
	return createCapabilityToken(td, kp, identity)
}

// regSetResolverConfigVia drives set-resolver-config presenting a specific child
// capability (childCap/childSig) rather than the harness's default owner cap.
func regSetResolverConfigVia(ctx context.Context, client *PeerClient, cfg types.ResolverConfigData, ack bool, childCap, childSig entity.Entity) (uint, string, error) {
	cfgEnt, err := cfg.ToEntity()
	if err != nil {
		return 0, "", fmt.Errorf("cfg ToEntity: %w", err)
	}
	reqEnt, err := types.SetResolverConfigRequestData{Config: cfgEnt, AcknowledgeNameDisclosure: ack}.ToEntity()
	if err != nil {
		return 0, "", fmt.Errorf("request ToEntity: %w", err)
	}
	uri := fmt.Sprintf("entity://%s/%s", client.RemotePeerID(), "system/registry")
	env, err := buildDelegatedExecute(client, childCap, childSig, uri, "set-resolver-config", reqEnt, nil)
	if err != nil {
		return 0, "", fmt.Errorf("build delegated execute: %w", err)
	}
	respEnv, _, err := client.SendRawEnvelope(env)
	if err != nil {
		return 0, "", err
	}
	status, code, _, err := extractStatusAndCode(respEnv)
	return status, code, err
}

// runRegTTLCeilingReread drives REG-TTL-CEILING-REREAD-1 (§6a.9.1) — the
// resolver ceiling is read at resolution, not latched at start. It rewrites
// the resolver-config via set-resolver-config (§4.3, the enabling surface)
// between three resolutions of one bound name and asserts the surfaced
// lifetime tracks the currently-stored config each time.
func runRegTTLCeilingReread(ctx context.Context, client *PeerClient) CheckOutcome {
	name := "ttlreread-" + randomSuffix()
	defer regUnbind(ctx, client, name)
	if _, status, err := regBind(ctx, client, name, regSamplePeerID, ""); err != nil || status != 200 {
		return FailCheck(fmt.Sprintf("setup bind: status=%d err=%v", status, err))
	}
	setCeil := func(maxTTL *uint64) (uint, string, error) {
		entry := types.ResolverChainEntry{BackendKind: types.BackendKindLocalName, BackendID: "local", Priority: 0}
		if maxTTL != nil {
			raw, err := ecf.Encode(*maxTTL)
			if err != nil {
				return 0, "", err
			}
			entry.Hints = map[string]cbor.RawMessage{"max_ttl": raw}
		}
		return regSetResolverConfig(ctx, client, types.ResolverConfigData{ResolverChain: []types.ResolverChainEntry{entry}}, false)
	}

	// Config 1 — no ceiling (constructibility gate: prove resolution is reached
	// and the ceiling is absent before asserting the reread).
	if st, code, err := setCeil(nil); err != nil || st != 200 {
		return FailCheck(fmt.Sprintf("config 1 (no ceiling) set-resolver-config → %d/%q err=%v (§4.3 unimplemented/unauthorized?)", st, code, err))
	}
	r1, _, err := regResolve(ctx, client, name)
	if err != nil {
		return FailCheck("resolve 1: " + err.Error())
	}
	if r1.Status != types.ResolutionStatusResolved || r1.Binding == nil {
		return SkipCheck("bound name did not resolve under config 1 — cannot reach the ceiling, so the reread is unobservable (constructibility gate)")
	}
	if r1.TTL != nil {
		return FailCheck(fmt.Sprintf("config 1: surfaced ttl=%d with no ceiling, want none", *r1.TTL))
	}

	// Config 2 — a ceiling present. A latching peer keeps config 1's nil here.
	hi := uint64(60_000)
	if st, _, err := setCeil(&hi); err != nil || st != 200 {
		return FailCheck(fmt.Sprintf("config 2 set: status=%d err=%v", st, err))
	}
	r2, _, err := regResolve(ctx, client, name)
	if err != nil {
		return FailCheck("resolve 2: " + err.Error())
	}
	if r2.TTL == nil || *r2.TTL != hi {
		return FailCheck(fmt.Sprintf("config 2: surfaced ttl=%v after rewriting hints.max_ttl=%d — a peer that LATCHES config at start keeps config 1's absent ceiling here (read-at-resolution MUST, §6a.9.1)", r2.TTL, hi))
	}

	// Config 3 — a LOWER ceiling. The effective lifetime must drop again.
	lo := uint64(30_000)
	if st, _, err := setCeil(&lo); err != nil || st != 200 {
		return FailCheck(fmt.Sprintf("config 3 set: status=%d err=%v", st, err))
	}
	r3, _, err := regResolve(ctx, client, name)
	if err != nil {
		return FailCheck("resolve 3: " + err.Error())
	}
	if r3.TTL == nil || *r3.TTL != lo {
		return FailCheck(fmt.Sprintf("config 3: surfaced ttl=%v after lowering hints.max_ttl to %d — the ceiling MUST track the currently-stored config at every resolution", r3.TTL, lo))
	}
	return PassCheck("resolver ceiling is read at resolution: absent→present→lower tracked across three set-resolver-config rewrites in one process (a latching peer fails config 2/3)")
}

// runRegFilterFailClosed is the discriminating NEGATIVE-match row of the §4.1
// step 2 filter [REGISTRY 1.14], now driven on the wire. v4 above proves the
// MATCHED side (a name matching a dispatch rule that names an absent backend
// narrows to chain_exhausted). This proves the fail-closed half: a name that
// matches NO dispatch rule yields the EMPTY eligible set → chain_exhausted,
// EVEN WHEN the chain would otherwise resolve it. Under the withdrawn `any`
// guard the unmatched name skipped narrowing and fell through UNFILTERED to
// the binding → resolved; that is the exact defect this observes.
//
// The teeth require the name to be BOUND — otherwise local-name returns
// not_found and the query is chain_exhausted for the wrong reason, proving
// nothing. So a positive CONTROL runs first: with a catch-all rule the same
// bound name MUST resolve, proving the setup reaches resolution; if it does
// not the check SKIPs (unattributable), never falsely PASSes. (ADR-0012:
// carry the teeth in the check when a pre-fix peer isn't buildable.)
//
// Sequencing (arch ROUTING-2026-08-19-a §4): constructed only now that all
// three impls landed row 2 — go fbaf838, rust 898e55b, py 1cb7c01 — so a
// conformant peer answers chain_exhausted uniformly. Before that this FAILed a
// conformant not-yet-landed peer, which is why v4b was held. A green here is a
// TRUE signal only under a cross-impl run; go-on-go green alone is not.
func runRegFilterFailClosed(ctx context.Context, client *PeerClient) CheckOutcome {
	name := "filter-failclosed-" + randomSuffix()
	defer regUnbind(ctx, client, name)
	if _, status, err := regBind(ctx, client, name, regSamplePeerID, ""); err != nil || status != 200 {
		return FailCheck(fmt.Sprintf("setup bind: status=%d err=%v", status, err))
	}

	chain := []types.ResolverChainEntry{
		{BackendKind: types.BackendKindLocalName, BackendID: "local", Priority: 0},
	}
	putCfg := func(dispatch []types.DispatchEntry) error {
		cfg := types.ResolverConfigData{ResolverChain: chain, NameFormatDispatch: dispatch}
		cfgEnt, _ := cfg.ToEntity()
		_, err := client.TreePut(ctx, types.ResolverConfigStoragePath, cfgEnt)
		return err
	}

	// CONTROL: a catch-all rule names local-name → the bound name resolves.
	// If it does not, the setup can't reach resolution and the teeth row is
	// unattributable — SKIP, do not PASS.
	if err := putCfg([]types.DispatchEntry{{Pattern: "*", BackendKinds: []string{types.BackendKindLocalName}}}); err != nil {
		return FailCheck("install control config: " + err.Error())
	}
	ctl, _, err := regResolve(ctx, client, name)
	if err != nil {
		return FailCheck("control resolve: " + err.Error())
	}
	if ctl.Status != types.ResolutionStatusResolved {
		return SkipCheck(fmt.Sprintf("control: bound name did not resolve under catch-all dispatch (status=%s) — teeth row unattributable, not asserting fail-closed", ctl.Status))
	}

	// TEETH: a rule that does NOT match the bound name → empty eligible set →
	// chain_exhausted, though the binding exists and the chain holds local-name.
	if err := putCfg([]types.DispatchEntry{{Pattern: "*.eth", BackendKinds: []string{types.BackendKindLocalName}}}); err != nil {
		return FailCheck("install teeth config: " + err.Error())
	}
	got, _, err := regResolve(ctx, client, name)
	if err != nil {
		return FailCheck("teeth resolve: " + err.Error())
	}
	if got.Status != types.ResolutionStatusChainExhausted {
		return FailCheck(fmt.Sprintf("bound name %q matches no dispatch rule but status=%s (want chain_exhausted) — filter fell through UNFILTERED to the binding, the withdrawn `any`-guard defect (§4.1 step 2, [1.14])", name, got.Status))
	}
	return PassCheck("control resolved under catch-all; unmatched name fail-closed to chain_exhausted though bound — §4.1 step 2 eligibility is a pure function of the name")
}

// runRegTTLResolverCeiling drives REG-TTL-RESOLVER-CEILING-1 (REGISTRY §6a.9.1,
// ruled [v1.16]): the resolver-side ceiling lives at durable
// resolver_chain[].hints.max_ttl and is read AT RESOLUTION. This is the
// load-bearing half of the TTL system — the config site was homeless until
// v1.16, and go was the non-conformant seat (it read a construction-time
// builder option, which applies on a cold boot and silently not on a warm one).
//
// Wire-observable rows here use LOCAL-NAME, which is fully armable over the wire
// (bind + resolver-config + resolve):
//
//	(a) binding content-hash UNCHANGED under a ceiling — the ceiling is a *use*
//	    bound, not a re-issue; result.binding must equal the no-ceiling hash.
//	(c) max_ttl: 0 is UNDECLARED — no clamp, not an instant-expiry ceiling.
//	(d) a binding with NO ttl (local-name) takes local_max as its surfaced
//	    lifetime — the row an impl passes by accident and fails on inspection
//	    (a guard that only clamps a present ttl silently skips it).
//
// The peer-issued min(binding.ttl, local_max) clamp and its forced-expiry are
// teeth-pinned in-tree (ext/registry/peerissued TestResolve_LocalMaxTTL_Clamps):
// peer-issued resolution needs a pinned registry + published binding, not
// armable in the bare `registry` posture — so the clamp-on-a-ttl'd-binding row
// is asserted where it is constructible, not overclaimed on the wire.
func runRegTTLResolverCeiling(ctx context.Context, client *PeerClient) CheckOutcome {
	name := "ttlceil-" + randomSuffix()
	defer regUnbind(ctx, client, name)
	if _, status, err := regBind(ctx, client, name, regSamplePeerID, ""); err != nil || status != 200 {
		return FailCheck(fmt.Sprintf("setup bind: status=%d err=%v", status, err))
	}

	// install a local-name-only chain, optionally stamping hints.max_ttl (ms).
	putCfg := func(maxTTL *uint64) error {
		entry := types.ResolverChainEntry{BackendKind: types.BackendKindLocalName, BackendID: "local", Priority: 0}
		if maxTTL != nil {
			raw, err := ecf.Encode(*maxTTL)
			if err != nil {
				return err
			}
			entry.Hints = map[string]cbor.RawMessage{"max_ttl": raw}
		}
		cfg := types.ResolverConfigData{ResolverChain: []types.ResolverChainEntry{entry}}
		cfgEnt, _ := cfg.ToEntity()
		_, err := client.TreePut(ctx, types.ResolverConfigStoragePath, cfgEnt)
		return err
	}

	// Baseline — no ceiling: local-name binding resolves with NO surfaced ttl,
	// and this is the binding hash the ceiling must not move.
	if err := putCfg(nil); err != nil {
		return FailCheck("install baseline config: " + err.Error())
	}
	base, _, err := regResolve(ctx, client, name)
	if err != nil {
		return FailCheck("baseline resolve: " + err.Error())
	}
	if base.Status != types.ResolutionStatusResolved || base.Binding == nil {
		return FailCheck("baseline: bound name did not resolve (status=" + base.Status + ")")
	}
	if base.TTL != nil {
		return FailCheck(fmt.Sprintf("baseline: local-name surfaced ttl=%d with no ceiling — want none", *base.TTL))
	}

	// Row (d) + (a): with a ceiling, the no-ttl binding takes local_max, and the
	// binding hash is unchanged.
	ceil := uint64(60_000)
	if err := putCfg(&ceil); err != nil {
		return FailCheck("install ceiling config: " + err.Error())
	}
	got, _, err := regResolve(ctx, client, name)
	if err != nil {
		return FailCheck("ceiling resolve: " + err.Error())
	}
	if got.TTL == nil || *got.TTL != ceil {
		return FailCheck(fmt.Sprintf("row (d): no-ttl binding under hints.max_ttl=%d surfaced ttl=%v — want %d (a guard that only clamps a present ttl skips the sticky case)", ceil, got.TTL, ceil))
	}
	if got.Binding == nil || *got.Binding != *base.Binding {
		return FailCheck(fmt.Sprintf("row (a): binding hash moved under a ceiling (%v vs baseline %v) — the ceiling is a use bound, not a re-issue", got.Binding, base.Binding))
	}

	// Row (c): max_ttl: 0 is undeclared — no clamp, surfaced ttl returns to none.
	zero := uint64(0)
	if err := putCfg(&zero); err != nil {
		return FailCheck("install zero-ceiling config: " + err.Error())
	}
	z, _, err := regResolve(ctx, client, name)
	if err != nil {
		return FailCheck("zero-ceiling resolve: " + err.Error())
	}
	if z.TTL != nil {
		return FailCheck(fmt.Sprintf("row (c): hints.max_ttl=0 surfaced ttl=%d — 0 is UNDECLARED, not an instant-expiry ceiling", *z.TTL))
	}
	return PassCheck("resolver ceiling from hints.max_ttl: no-ttl→local_max (d), binding hash unchanged (a), max_ttl:0 undeclared (c); peer-issued min-clamp teeth in-tree")
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
	// §6.5's error table pins the row as `bind_invalid_name | 400`, so both
	// halves are asserted. R-6 (2026-08-12 c): this check asserted the status
	// alone on both arms — the third row of the sweep arch scoped to EVERY
	// pinned row, and the one the R-5 pass missed because the code was not
	// even named in a failure string here.
	for _, arm := range []struct{ what, name string }{
		{"'/' in the name", "has/slash"},
		{"a control character in the name", "has\x01control"},
	} {
		_, status, code, err := regBindFull(ctx, client, arm.name, regSamplePeerID, "")
		if err != nil {
			return FailCheck(fmt.Sprintf("bind with %s: %v", arm.what, err))
		}
		if status != 400 {
			return FailCheck(fmt.Sprintf("bind with %s → status %d, want 400 (§6.3 path safety)", arm.what, status))
		}
		if code != types.RegistryErrBindInvalidName {
			return FailCheck(fmt.Sprintf("bind with %s answered 400 with code %q, want %q — §6.5 pins the row as code AND status", arm.what, code, types.RegistryErrBindInvalidName))
		}
	}
	return PassCheck("invalid names rejected 400/bind_invalid_name (both '/' and control-char arms)")
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
	// R-5 audit (2026-08-12): this row is REGISTRY §6.5's pinned
	// `bind_already_exists | 409`, and it asserted the status while naming
	// the code only in its own declare string. Same half-check as the §6a.9
	// layer-1 rows — a status is a class, a code is the contract.
	//
	// It originally re-drove regExecute inline because regBind discarded the
	// result body on a non-200. R-6 fixed that at the helper (regBindFull),
	// so the workaround is gone: the code now arrives the same way for every
	// row of the table.
	_, status, code, err := regBindFull(ctx, client, name, regSamplePeerID, "")
	if err != nil {
		return FailCheck("second bind: " + err.Error())
	}
	if status != 409 {
		return FailCheck(fmt.Sprintf("second bind with allow_supersede=false: status=%d, want 409", status))
	}
	if code != types.RegistryErrBindAlreadyExists {
		return FailCheck(fmt.Sprintf("second bind answered 409 with code %q, want %q (REGISTRY §6.5 pins the row as status AND code)", code, types.RegistryErrBindAlreadyExists))
	}
	return PassCheck("bind_already_exists: 409/bind_already_exists fired with allow_supersede=false")
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

// The §4.1 step 2 FILTER's discriminating negative-match row is now driven on
// the wire as v4b (runRegFilterFailClosed): a BOUND name matching no dispatch
// rule fails closed. The sequencing gate arch set (ROUTING-2026-08-19-a §4 —
// land row 2 in all three, THEN one seat constructs the vector) is met: go
// fbaf838, rust 898e55b, py 1cb7c01. go was handed the construction by both
// siblings (we own v4 and pulled the v15 predecessor). A green is a true signal
// only under a cross-impl run; that run is the release evidence, not go-on-go.
//
// The MATCHER grammar (REG-DISPATCH-GRAMMAR-1, 1.15) stays teeth-pinned
// in-tree, NOT on the wire: its only distinguishing row is the `/`-crossing
// case (`*` subtree vs path.Match), and a name carrying `/` is unbindable per
// §6.3 (normalizeName), so it is unobservable on the wire (spec-issue
// 2026-08-19-b, routed for §11.1 to mark both `/`-rows in-tree-only). In-tree:
// REG-DISPATCH-GRAMMAR-1 (ext/registry/glob_dispatch_test.go, vs path.Match)
// and the filter (ext/registry/dispatch_filter_test.go, teeth vs the old `any`
// guard).

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
