package validate

import (
	"context"
	"fmt"
	"time"

	"go.entitychurch.org/entity-core-go/core/crypto"
	"go.entitychurch.org/entity-core-go/core/ecf"
	"go.entitychurch.org/entity-core-go/core/entity"
	"go.entitychurch.org/entity-core-go/core/hash"
	"go.entitychurch.org/entity-core-go/core/types"
)

// This file adds the capability chain / attenuation negative probes specified
// in SECURITY-FINDINGS-CHAIN-ATTENUATION-CROSS-IMPL §3. The legacy
// `security` category tested only single-link forgery and a single child
// overshooting scope; it was blind to the entire multi-link chain/attenuation
// surface where the cross-impl divergences F1–F6 live. Each probe here is a
// cross-impl-deterministic negative: a chain that MUST be denied at dispatch,
// pinning a §5.5/§5.6/§5.7 check that the cohort enforced inconsistently.
//
// Status discipline: these assert DENY (non-2xx) and report the observed
// status — they do NOT hard-pin 403. The request-time DENY→403 mapping is the
// settled-but-unratified D-A1 boundary (PROPOSAL-HANDSHAKE-POP §2); until it
// lands, rejection-only is correct (same discipline as the F12 connectivity
// probes). A peer that ALLOWS (2xx) fails; a peer that crashes/closes the
// connection fails (and that is itself the F5 fail-closed signal).
//
// Revocation (register §3 item 7) is intentionally NOT added here: it is gated
// on arch decision D-VOC (V-1 tree-unbind vs V-2 list) and no impl yet
// implements is_revoked. Adding a probe before the mechanism is pinned would
// assert a behavior the spec has not settled. Tracked in the handoff doc.

// runSecurityChain runs the chain/attenuation probes and returns their results.
// Called from runSecurity so they join the `security` category.
func runSecurityChain(client *PeerClient) []CheckResult {
	r := NewCheckRunner(catSecurity)

	r.Declare("chain_no_delegation_denied", "V7 §5.7 (delegation caveats)")
	r.Declare("chain_max_delegation_ttl_denied", "V7 §5.7 (delegation caveats)")
	r.Declare("chain_operation_exclude_denied", "V7 §5.2/§5.6 (F2)")
	r.Declare("chain_per_link_temporal_denied", "V7 §5.5 (F3)")
	r.Declare("chain_mid_link_expiry_denied", "V7 §5.5 (per-link expiry walk, V1)")
	r.Declare("chain_parent_exclude_drop_denied", "V7 §5.6 (F4)")
	r.Declare("chain_malformed_resource_pattern", "V7 §1.11 fail-closed (F5)")
	r.Declare("chain_content_hash_substitution", "V7 §5.2 (F6)")
	r.Declare("captok_form_dispatch_minted_pl_presented_xpeer", "V7 §3.6 / §5.2 PR-8 / §5.5 (V2a peer-local mint, cross-peer presentation)")
	r.Declare("captok_form_dispatch_minted_xpeer_presented_pl", "V7 §3.6 / §5.2 PR-8 / §4.5a (V2b cross-peer mint, peer-local presentation — informative)")
	r.Declare("authz_attenuation_foreign_granter_1", "V7 §5.5a (Amendment 1, per-link chain-walk granter frame, V1')")
	r.Declare("authz_attenuation_foreign_granter_deep", "V7 §5.5a (Amendment 1, multi-level chain-walk granter frame)")
	r.Declare("authz_attenuation_foreign_granter_wildcard_leaf", "V7 §5.5a (Amendment 1, chain-walk subset-check with wildcard suffix leaf)")

	r.Run("chain_no_delegation_denied", func() CheckOutcome {
		return toOutcome(probeNoDelegation(client))
	})
	r.Run("chain_max_delegation_ttl_denied", func() CheckOutcome {
		return toOutcome(probeMaxDelegationTTL(client))
	})
	r.Run("chain_operation_exclude_denied", func() CheckOutcome {
		return toOutcome(probeOperationExclude(client))
	})
	r.Run("chain_per_link_temporal_denied", func() CheckOutcome {
		return toOutcome(probePerLinkTemporal(client))
	})
	r.Run("chain_mid_link_expiry_denied", func() CheckOutcome {
		return toOutcome(probeChainMidLinkExpiryDenied(client))
	})
	r.Run("chain_parent_exclude_drop_denied", func() CheckOutcome {
		return toOutcome(probeParentExcludeDrop(client))
	})
	r.Run("chain_malformed_resource_pattern", func() CheckOutcome {
		return toOutcome(probeMalformedResourcePattern(client))
	})
	r.Run("chain_content_hash_substitution", func() CheckOutcome {
		return toOutcome(probeContentHashSubstitution(client))
	})
	r.Run("captok_form_dispatch_minted_pl_presented_xpeer", func() CheckOutcome {
		return toOutcome(probeCaptokFormDispatchMintedPLPresentedXpeer(client))
	})
	r.Run("captok_form_dispatch_minted_xpeer_presented_pl", func() CheckOutcome {
		return toOutcome(probeCaptokFormDispatchMintedXpeerPresentedPL(client))
	})
	r.Run("authz_attenuation_foreign_granter_1", func() CheckOutcome {
		return toOutcome(probeAuthzAttenuationForeignGranter1(client))
	})
	r.Run("authz_attenuation_foreign_granter_deep", func() CheckOutcome {
		return toOutcome(probeAuthzAttenuationForeignGranterDeep(client))
	})
	r.Run("authz_attenuation_foreign_granter_wildcard_leaf", func() CheckOutcome {
		return toOutcome(probeAuthzAttenuationForeignGranterWildcardLeaf(client))
	})

	return r.Results()
}

// buildAttenuatedChildCap delegates a single narrow child cap from the
// connection cap (granter=grantee=our identity, parent=connection cap, signed
// by us) and returns the cap entity + its signature. Used by probes that need
// to present a narrow authority (e.g. the capability scope-widening check).
func buildAttenuatedChildCap(client *PeerClient, grant types.GrantEntry) (entity.Entity, entity.Entity, error) {
	kp := client.Keypair()
	identity := client.IdentityEntity()
	parentCap := client.CapEntity()
	now := uint64(time.Now().UnixMilli())
	fiveMin := now + 5*60*1000
	td := types.CapabilityTokenData{
		Grants:    []types.GrantEntry{grant},
		Granter:   types.SingleSigGranter(identity.ContentHash),
		Grantee:   identity.ContentHash,
		Parent:    &parentCap.ContentHash,
		CreatedAt: now,
		ExpiresAt: &fiveMin,
	}
	return createCapabilityToken(td, kp, identity)
}

// chainCap describes one cap in a self-delegated chain (granter=grantee=us),
// delegated from the cap before it (the first from the connection cap).
type chainCap struct {
	grant     types.GrantEntry
	caveats   *types.DelegationCaveats
	notBefore *uint64
	expiresAt *uint64 // nil → default ~5 min from now
}

// buildSelfChainExecute builds an EXECUTE whose capability is the leaf of a
// chain of self-delegated caps rooted at the connection cap. caps[0] is
// delegated from the connection cap; each subsequent cap from the previous.
// All caps are granter=grantee=our identity, signed by us. The full chain
// (every cap + its signature + our identity + the connection cap chain) is
// placed in `included` so the responder can walk it to the local-peer root.
func buildSelfChainExecute(client *PeerClient, caps []chainCap, uri, operation string, resource *types.ResourceTarget) (entity.Envelope, hash.Hash, error) {
	kp := client.Keypair()
	identity := client.IdentityEntity()
	now := uint64(time.Now().UnixMilli())
	defaultExp := now + 5*60*1000

	parentHash := client.CapEntity().ContentHash
	chainIncluded := map[hash.Hash]entity.Entity{}
	var leafCap entity.Entity
	for _, c := range caps {
		ph := parentHash
		exp := c.expiresAt
		if exp == nil {
			e := defaultExp
			exp = &e
		}
		td := types.CapabilityTokenData{
			Grants:            []types.GrantEntry{c.grant},
			Granter:           types.SingleSigGranter(identity.ContentHash),
			Grantee:           identity.ContentHash,
			Parent:            &ph,
			CreatedAt:         now - 2000,
			NotBefore:         c.notBefore,
			ExpiresAt:         exp,
			DelegationCaveats: c.caveats,
		}
		capEnt, sigEnt, err := createCapabilityToken(td, kp, identity)
		if err != nil {
			return entity.Envelope{}, hash.Hash{}, err
		}
		chainIncluded[capEnt.ContentHash] = capEnt
		chainIncluded[sigEnt.ContentHash] = sigEnt
		parentHash = capEnt.ContentHash
		leafCap = capEnt
	}

	params, _, err := buildSimpleGetParams()
	if err != nil {
		return entity.Envelope{}, hash.Hash{}, err
	}
	rawParams, err := ecf.Encode(params)
	if err != nil {
		return entity.Envelope{}, hash.Hash{}, err
	}

	execData := types.ExecuteData{
		RequestID:  client.NextRequestID(),
		URI:        uri,
		Operation:  operation,
		Params:     rawParams,
		Author:     identity.ContentHash,
		Capability: leafCap.ContentHash,
		Resource:   resource,
	}
	execEntity, err := execData.ToEntity()
	if err != nil {
		return entity.Envelope{}, hash.Hash{}, err
	}
	execSig, err := signEntity(execEntity.ContentHash, kp, identity)
	if err != nil {
		return entity.Envelope{}, hash.Hash{}, err
	}

	included := map[hash.Hash]entity.Entity{
		identity.ContentHash: identity,
		execSig.ContentHash:  execSig,
	}
	for h, e := range chainIncluded {
		included[h] = e
	}
	// Connection cap + its chain (server identity + connection cap signature).
	parentCap := client.CapEntity()
	included[parentCap.ContentHash] = parentCap
	for h, ent := range client.AuthenticateIncluded() {
		included[h] = entity.Entity{Type: ent.Type, Data: ent.Data, ContentHash: h}
	}

	return entity.NewEnvelope(execEntity, included), leafCap.ContentHash, nil
}

// denyOutcome sends env and classifies the result as a security outcome.
// PASS: a decodable EXECUTE_RESPONSE with a non-2xx (DENY) status.
// FAIL: a 2xx (the forbidden chain was ALLOWED).
//
// A connection close with no response is classified by closeIsDeny. For a
// structurally valid but unauthorized chain the peer MUST answer with a DENY
// (§4.1 "every EXECUTE receives a response"), so a close is a FAIL. For an
// intentionally corrupt frame (the content-hash-substitution probe) a clean
// close is an acceptable fail-closed rejection — the security property (no
// access) holds — so closeIsDeny is true; the graceful-response-vs-close
// distinction there is the decision-gated D-R / §4.1 robustness question,
// flagged separately rather than failed here.
func denyOutcome(client *PeerClient, env entity.Envelope, desc string, closeIsDeny bool) CheckResult {
	respEnv, _, err := client.SendRawEnvelope(env)
	if err != nil {
		if closeIsDeny {
			return pass(catSecurity, "", "",
				fmt.Sprintf("%s: rejected (connection closed; fail-closed — access denied). Note: closed without a DENY response (§4.1 robustness / D-R)", desc))
		}
		return fail(catSecurity, "", "",
			fmt.Sprintf("%s: peer crashed or closed the connection instead of returning a DENY response (not fail-closed): %v", desc, err))
	}
	respData, derr := types.ExecuteResponseDataFromEntity(respEnv.Root)
	if derr != nil {
		return fail(catSecurity, "", "", fmt.Sprintf("%s: could not decode response: %v", desc, derr))
	}
	if respData.Status >= 200 && respData.Status < 300 {
		return fail(catSecurity, "", "",
			fmt.Sprintf("%s: ACCEPTED with status %d — MUST be denied", desc, respData.Status))
	}
	return pass(catSecurity, "", "", fmt.Sprintf("%s: correctly denied (status %d)", desc, respData.Status))
}

// withCheck stamps a check name + spec ref onto a denyOutcome result (denyOutcome
// is name-agnostic so it can be reused across probes).
func withCheck(cr CheckResult, name, ref string) CheckResult {
	cr.Name = name
	cr.SpecRef = ref
	return cr
}

func serverTreeURI(client *PeerClient) string {
	return fmt.Sprintf("entity://%s/system/tree", client.RemotePeerID())
}

// probeNoDelegation (F1, §5.7): an intermediate cap carries no_delegation:true;
// a leaf delegated from it MUST be denied — the intermediate forbade further
// delegation. Catches an impl that defines but never calls the caveat check.
func probeNoDelegation(client *PeerClient) CheckResult {
	no := true
	wildcard := types.GrantEntry{
		Handlers:   types.CapabilityScope{Include: []string{"system/tree"}},
		Resources:  types.CapabilityScope{Include: []string{"*"}},
		Operations: types.CapabilityScope{Include: []string{"*"}},
	}
	env, _, err := buildSelfChainExecute(client, []chainCap{
		{grant: wildcard, caveats: &types.DelegationCaveats{NoDelegation: &no}},
		{grant: wildcard}, // leaf — delegated despite no_delegation
	}, serverTreeURI(client), "get", &types.ResourceTarget{Targets: []string{"system/type/system/peer"}})
	if err != nil {
		return fail(catSecurity, "chain_no_delegation_denied", "V7 §5.7", "build: "+err.Error())
	}
	return withCheck(denyOutcome(client, env, "child delegated from a no_delegation:true parent", false),
		"chain_no_delegation_denied", "V7 §5.7 (delegation caveats)")
}

// probeMaxDelegationTTL (F1, §5.7): an intermediate caps max_delegation_ttl to
// a tiny value; a leaf whose lifetime exceeds it MUST be denied.
func probeMaxDelegationTTL(client *PeerClient) CheckResult {
	maxTTL := uint64(1000) // 1 second
	wildcard := types.GrantEntry{
		Handlers:   types.CapabilityScope{Include: []string{"system/tree"}},
		Resources:  types.CapabilityScope{Include: []string{"*"}},
		Operations: types.CapabilityScope{Include: []string{"*"}},
	}
	env, _, err := buildSelfChainExecute(client, []chainCap{
		{grant: wildcard, caveats: &types.DelegationCaveats{MaxDelegationTTL: &maxTTL}},
		{grant: wildcard}, // leaf default ~5min lifetime >> 1s cap
	}, serverTreeURI(client), "get", &types.ResourceTarget{Targets: []string{"system/type/system/peer"}})
	if err != nil {
		return fail(catSecurity, "chain_max_delegation_ttl_denied", "V7 §5.7", "build: "+err.Error())
	}
	return withCheck(denyOutcome(client, env, "child whose lifetime exceeds parent max_delegation_ttl", false),
		"chain_max_delegation_ttl_denied", "V7 §5.7 (delegation caveats)")
}

// probeOperationExclude (F2, §5.2/§5.6): a cap granting operations
// {include:["*"], exclude:["delete"]} MUST deny a delete. Catches a permission
// check that consults Operations.Include only.
func probeOperationExclude(client *PeerClient) CheckResult {
	env, _, err := buildSelfChainExecute(client, []chainCap{{
		grant: types.GrantEntry{
			Handlers:   types.CapabilityScope{Include: []string{"system/tree"}},
			Resources:  types.CapabilityScope{Include: []string{"*"}},
			Operations: types.CapabilityScope{Include: []string{"*"}, Exclude: []string{"delete"}},
		},
	}}, serverTreeURI(client), "delete", &types.ResourceTarget{Targets: []string{"system/validate/op-exclude-probe"}})
	if err != nil {
		return fail(catSecurity, "chain_operation_exclude_denied", "V7 §5.2/§5.6", "build: "+err.Error())
	}
	return withCheck(denyOutcome(client, env, "delete under a grant that excludes the delete operation", false),
		"chain_operation_exclude_denied", "V7 §5.2/§5.6 (F2)")
}

// probePerLinkTemporal (F3, §5.5): a 2-link chain whose INTERMEDIATE link is
// not-yet-valid (not_before in the future) while the leaf is valid now. The
// leaf alone passes a leaf-only temporal check; only a per-link chain temporal
// check catches the stale-authority window. not_before (not expiry) isolates
// F3: attenuation already forbids a leaf outliving its parent's expiry, so an
// expired-parent/valid-leaf chain is unreachable — but attenuation never
// checks not_before, so a not-yet-valid intermediate is the clean isolation.
func probePerLinkTemporal(client *PeerClient) CheckResult {
	now := uint64(time.Now().UnixMilli())
	future := now + 60*60*1000   // intermediate becomes valid in 1 hour
	leafExp := now + 5*60*1000   // leaf valid now, expires before parent's window even opens
	wildcard := types.GrantEntry{
		Handlers:   types.CapabilityScope{Include: []string{"system/tree"}},
		Resources:  types.CapabilityScope{Include: []string{"*"}},
		Operations: types.CapabilityScope{Include: []string{"*"}},
	}
	env, _, err := buildSelfChainExecute(client, []chainCap{
		{grant: wildcard, notBefore: &future}, // intermediate: not yet valid
		{grant: wildcard, expiresAt: &leafExp}, // leaf: valid now
	}, serverTreeURI(client), "get", &types.ResourceTarget{Targets: []string{"system/type/system/peer"}})
	if err != nil {
		return fail(catSecurity, "chain_per_link_temporal_denied", "V7 §5.5", "build: "+err.Error())
	}
	return withCheck(denyOutcome(client, env, "chain with a not-yet-valid intermediate link", false),
		"chain_per_link_temporal_denied", "V7 §5.5 (F3)")
}

// probeParentExcludeDrop (F4, §5.6): an intermediate excludes a subtree; the
// leaf delegated from it drops that exclude (re-opening the denied region).
// The chain MUST be denied at attenuation. Catches a grantCovers that ignores
// parent excludes.
func probeParentExcludeDrop(client *PeerClient) CheckResult {
	env, _, err := buildSelfChainExecute(client, []chainCap{
		{grant: types.GrantEntry{
			Handlers:   types.CapabilityScope{Include: []string{"system/tree"}},
			Resources:  types.CapabilityScope{Include: []string{"system/tree/*"}, Exclude: []string{"system/tree/secret/*"}},
			Operations: types.CapabilityScope{Include: []string{"*"}},
		}},
		{grant: types.GrantEntry{ // leaf drops the parent's exclude
			Handlers:   types.CapabilityScope{Include: []string{"system/tree"}},
			Resources:  types.CapabilityScope{Include: []string{"system/tree/*"}},
			Operations: types.CapabilityScope{Include: []string{"*"}},
		}},
	}, serverTreeURI(client), "get", &types.ResourceTarget{Targets: []string{"system/tree/foo"}})
	if err != nil {
		return fail(catSecurity, "chain_parent_exclude_drop_denied", "V7 §5.6", "build: "+err.Error())
	}
	return withCheck(denyOutcome(client, env, "leaf that drops its parent's resource exclude", false),
		"chain_parent_exclude_drop_denied", "V7 §5.6 (F4)")
}

// probeMalformedResourcePattern (F5, §1.11): a cap resource pattern with a
// reserved/malformed prefix (./, ../, */). It MUST be rejected cleanly — the
// peer MUST NOT crash or hang on attacker-controlled wire input. A
// crash/connection-close is the fail-closed violation (Rust panicked on these).
func probeMalformedResourcePattern(client *PeerClient) CheckResult {
	env, _, err := buildSelfChainExecute(client, []chainCap{{
		grant: types.GrantEntry{
			Handlers:   types.CapabilityScope{Include: []string{"system/tree"}},
			Resources:  types.CapabilityScope{Include: []string{"../etc/secret", "*/secret"}},
			Operations: types.CapabilityScope{Include: []string{"*"}},
		},
	}}, serverTreeURI(client), "get", &types.ResourceTarget{Targets: []string{"system/type/system/peer"}})
	if err != nil {
		return fail(catSecurity, "chain_malformed_resource_pattern", "V7 §1.11", "build: "+err.Error())
	}
	return withCheck(denyOutcome(client, env, "cap with a malformed resource pattern (../, */)", false),
		"chain_malformed_resource_pattern", "V7 §1.11 fail-closed (F5)")
}

// probeContentHashSubstitution (F6/§5.2 first gate): a delegated child cap
// whose entity bytes are mutated after signing, while the EXECUTE still
// references the original content hash. The responder MUST validate the
// included entity's hash before trusting it (recompute from {type,data}); the
// mutated bytes no longer hash to the referenced capability, so the request
// MUST be denied. Catches an impl that trusts the wire content_hash.
func probeContentHashSubstitution(client *PeerClient) CheckResult {
	// Run on a FRESH connection built with the same keypair. A hash-mismatched
	// included entity makes the responder reject at the wire/ingress layer,
	// which on the Go peer closes the connection (rather than returning a DENY
	// — a decision-gated D-R / §4.1 "every EXECUTE gets a response" observation,
	// flagged in the handoff, not failed here). Isolating it on a throwaway
	// connection keeps that close from poisoning the rest of the run.
	probe, err := NewPeerClientWithKeypair(client.Addr(), client.Keypair())
	if err != nil {
		return fail(catSecurity, "chain_content_hash_substitution", "V7 §5.2", "create probe client: "+err.Error())
	}
	defer probe.Close()
	if err := probe.Connect(context.Background()); err != nil {
		return fail(catSecurity, "chain_content_hash_substitution", "V7 §5.2", "probe connect: "+err.Error())
	}

	kp := probe.Keypair()
	identity := probe.IdentityEntity()
	parentCap := probe.CapEntity()
	now := uint64(time.Now().UnixMilli())
	fiveMin := now + 5*60*1000

	childData := types.CapabilityTokenData{
		Grants: []types.GrantEntry{{
			Handlers:   types.CapabilityScope{Include: []string{"system/tree"}},
			Resources:  types.CapabilityScope{Include: []string{"*"}},
			Operations: types.CapabilityScope{Include: []string{"*"}},
		}},
		Granter:   types.SingleSigGranter(identity.ContentHash),
		Grantee:   identity.ContentHash,
		Parent:    &parentCap.ContentHash,
		CreatedAt: now,
		ExpiresAt: &fiveMin,
	}
	childCap, childCapSig, err := createCapabilityToken(childData, kp, identity)
	if err != nil {
		return fail(catSecurity, "chain_content_hash_substitution", "V7 §5.2", "create cap: "+err.Error())
	}

	params, resource, err := buildSimpleGetParams()
	if err != nil {
		return fail(catSecurity, "chain_content_hash_substitution", "V7 §5.2", "setup: "+err.Error())
	}
	env, err := buildDelegatedExecute(probe, childCap, childCapSig, serverTreeURI(probe), "get", params, resource)
	if err != nil {
		return fail(catSecurity, "chain_content_hash_substitution", "V7 §5.2", "build: "+err.Error())
	}

	// Substitute the capability's bytes while the EXECUTE (and the cap's
	// signature) still reference the original content hash. We decode, mutate a
	// field, and re-encode to VALID CBOR. On a recompute-on-receipt wire (entity
	// content_hash is never transmitted — it is recomputed from {type,data}),
	// the mutated bytes hash to a different value, so the capability the EXECUTE
	// references is no longer present: the responder MUST deny
	// (validate-before-trust, §5.2 first gate). NB: the deeper F6 case (an impl
	// trusting a wire-supplied content_hash on an in-process path) is not
	// wire-observable here precisely because the hash is recomputed; this probe
	// pins the wire-observable half. A connection close counts as a (fail-closed)
	// deny — access is denied either way; the close-vs-DENY-response distinction
	// is the decision-gated D-R / §4.1 robustness question.
	orig, ok := env.Included[childCap.ContentHash]
	if !ok {
		return fail(catSecurity, "chain_content_hash_substitution", "V7 §5.2", "child cap not present in envelope")
	}
	var decoded types.CapabilityTokenData
	if err := ecf.Decode(orig.Data, &decoded); err != nil {
		return fail(catSecurity, "chain_content_hash_substitution", "V7 §5.2", "decode child cap: "+err.Error())
	}
	decoded.CreatedAt++ // mutate a field → different bytes → different hash, still valid CBOR
	mutatedData, err := ecf.Encode(decoded)
	if err != nil {
		return fail(catSecurity, "chain_content_hash_substitution", "V7 §5.2", "re-encode mutated cap: "+err.Error())
	}
	env.Included[childCap.ContentHash] = entity.Entity{Type: orig.Type, Data: mutatedData, ContentHash: childCap.ContentHash}

	return withCheck(denyOutcome(probe, env, "capability whose bytes were substituted after signing", true),
		"chain_content_hash_substitution", "V7 §5.2 (F6)")
}

// probeChainMidLinkExpiryDenied (V1, V7 §5.5 per-link temporal):
// 3-link self-delegated chain whose MIDDLE link expired 1ms ago while the
// leaf is still valid (expires_at = now + 1h). A chain walk that only
// validates the leaf's temporal window — or that re-checks expiry at
// delegation time but not at request time — will accept this; a per-link
// expiry walk at request-validation time MUST deny.
//
// Sibling to probePerLinkTemporal (F3, not_before case). F3 isolated stale
// future authority; V1 isolates stale past authority on an intermediate link.
// Arch capability-coverage audit flagged this as gated only
// transitively by verify_cap_chain; this vector pins it directly.
func probeChainMidLinkExpiryDenied(client *PeerClient) CheckResult {
	now := uint64(time.Now().UnixMilli())
	middleExpired := now - 1                    // middle: expired 1ms ago
	leafValid := now + 60*60*1000               // leaf: valid for another hour
	wildcard := types.GrantEntry{
		Handlers:   types.CapabilityScope{Include: []string{"system/tree"}},
		Resources:  types.CapabilityScope{Include: []string{"*"}},
		Operations: types.CapabilityScope{Include: []string{"*"}},
	}
	// Three-link chain: connection cap → root (valid) → middle (expired) → leaf (valid).
	// buildSelfChainExecute roots at the connection cap; the slice below is everything
	// downstream of it. Three caps in the slice = three-link delegated chain.
	env, _, err := buildSelfChainExecute(client, []chainCap{
		{grant: wildcard},                              // root of the self-chain
		{grant: wildcard, expiresAt: &middleExpired},   // middle: expired
		{grant: wildcard, expiresAt: &leafValid},       // leaf: valid now
	}, serverTreeURI(client), "get", &types.ResourceTarget{Targets: []string{"system/type/system/peer"}})
	if err != nil {
		return fail(catSecurity, "chain_mid_link_expiry_denied", "V7 §5.5", "build: "+err.Error())
	}
	return withCheck(denyOutcome(client, env, "3-link chain with an expired middle link (leaf still valid)", false),
		"chain_mid_link_expiry_denied", "V7 §5.5 (per-link expiry walk, V1)")
}

// probeCaptokFormDispatchMintedPLPresentedXpeer (V2a, V7 §3.6 / §5.2 PR-8 /
// §5.5):
// A child capability minted by the validator (granter = validator's identity)
// uses a peer-local resource pattern — bare "*", which per §PR-8
// canonicalizes against the GRANTER's peer_id to `/{validator}/*`. The
// EXECUTE then targets the server's namespace (`/{server}/system/type/...`).
// A correct granter-aware canonicalization rejects: the validator's peer-local
// authority cannot reach the server's namespace. A check that canonicalizes
// against the local checker (`localPeerID` = the server) instead of the
// granter would (incorrectly) admit the request — exactly the gap noted at
// `core/capability/check.go:296` ("Foreign-granter caps and the
// granter-aware canonicalization plumbing are follow-up work").
//
// V1 of this vector is allowed to surface a real bug per proposal §5.Q4. If
// the Go peer (or any impl) admits the request, the validator is doing its
// job — the FAIL is the signal to plumb granter-aware canonicalization.
func probeCaptokFormDispatchMintedPLPresentedXpeer(client *PeerClient) CheckResult {
	// Bare "*" in Resources canonicalizes against the granter's peer_id per
	// §PR-8. Here the granter is the validator (we sign the child), so the
	// pattern resolves to `/{validator}/*` — peer-local-of-validator. The
	// EXECUTE below targets `/{server}/...`, which is NOT in the
	// validator's namespace; the cap MUST NOT cover it.
	peerLocalGrant := types.GrantEntry{
		Handlers:   types.CapabilityScope{Include: []string{"system/tree"}},
		Resources:  types.CapabilityScope{Include: []string{"*"}}, // peer-local-of-granter
		Operations: types.CapabilityScope{Include: []string{"*"}},
	}
	env, _, err := buildSelfChainExecute(client, []chainCap{
		{grant: peerLocalGrant},
	}, serverTreeURI(client), "get", &types.ResourceTarget{Targets: []string{"system/type/system/peer"}})
	if err != nil {
		return fail(catSecurity, "captok_form_dispatch_minted_pl_presented_xpeer", "V7 §3.6", "build: "+err.Error())
	}
	return withCheck(denyOutcome(client, env, "cap with peer-local resource pattern (bare *) presented cross-peer", false),
		"captok_form_dispatch_minted_pl_presented_xpeer", "V7 §3.6 / §5.2 PR-8 / §5.5 (V2a)")
}

// probeCaptokFormDispatchMintedXpeerPresentedPL (V2b, V7 §3.6 / §5.2 PR-8 /
// §4.5a):
// Reverse direction: a child capability uses the explicit cross-peer form
// (`/*/*` — all peers, all paths). Per §3.6 / §5.5 cross-peer authority is
// expressed in absolute form; presented against the server's namespace, the
// cap's `/*/*` covers `/{server}/...`, so the dispatch should ALLOW (200).
//
// Per proposal §3.2: "expect 200 (or 403 if scope-walk rejects per v7.70
// §4.5a — informative on this branch)." 200 and 403 are both PASS;
// crash / 500 / undecodable response is FAIL. This is the informative half
// of V2.
//
// NB: this probe self-delegates via buildSelfChainExecute; the parent
// (connection cap) was issued by the server with peer-local form
// (server-canonicalized as `/{server}/*`). A strict attenuation that
// compares granter-aware canonicalized forms across granters could legitimately
// reject child `/*/*` as wider than parent — this is the v7.70 §4.5a
// active-format / scope-walk branch that the proposal flags as informative.
func probeCaptokFormDispatchMintedXpeerPresentedPL(client *PeerClient) CheckResult {
	crossPeerGrant := types.GrantEntry{
		Handlers:   types.CapabilityScope{Include: []string{"system/tree"}},
		Resources:  types.CapabilityScope{Include: []string{"/*/*"}}, // explicit cross-peer form
		Operations: types.CapabilityScope{Include: []string{"*"}},
	}
	env, _, err := buildSelfChainExecute(client, []chainCap{
		{grant: crossPeerGrant},
	}, serverTreeURI(client), "get", &types.ResourceTarget{Targets: []string{"system/type/system/peer"}})
	if err != nil {
		return fail(catSecurity, "captok_form_dispatch_minted_xpeer_presented_pl", "V7 §3.6", "build: "+err.Error())
	}
	// Informative: 200 or 403 both PASS. denyOutcome PASSes any non-2xx and
	// FAILs 2xx. For this informative-allow case we accept BOTH branches and
	// classify by raw status rather than reusing denyOutcome.
	respEnv, _, sendErr := client.SendRawEnvelope(env)
	if sendErr != nil {
		return fail(catSecurity, "captok_form_dispatch_minted_xpeer_presented_pl", "V7 §3.6",
			fmt.Sprintf("peer crashed or closed the connection on a structurally valid cross-peer cap: %v", sendErr))
	}
	respData, derr := types.ExecuteResponseDataFromEntity(respEnv.Root)
	if derr != nil {
		return fail(catSecurity, "captok_form_dispatch_minted_xpeer_presented_pl", "V7 §3.6",
			fmt.Sprintf("could not decode response: %v", derr))
	}
	switch {
	case respData.Status >= 200 && respData.Status < 300:
		return pass(catSecurity, "captok_form_dispatch_minted_xpeer_presented_pl", "V7 §3.6 / §5.2 PR-8 (V2b)",
			fmt.Sprintf("cross-peer cap (/*/*) presented peer-local — ALLOWED (status %d), per §5.5 cross-peer-is-superset", respData.Status))
	case respData.Status == 403:
		return pass(catSecurity, "captok_form_dispatch_minted_xpeer_presented_pl", "V7 §3.6 / §4.5a (V2b informative)",
			"cross-peer cap (/*/*) presented peer-local — DENIED 403 by scope-walk (v7.70 §4.5a active-format branch); informative-PASS per proposal §3.2")
	default:
		return fail(catSecurity, "captok_form_dispatch_minted_xpeer_presented_pl", "V7 §3.6",
			fmt.Sprintf("expected 200 or 403, got %d", respData.Status))
	}
}

// probeAuthzAttenuationForeignGranter1 (V7 v7.73 Amendment 1, §5.5a per-link
// chain-walk granter frame — V1' reconstruction per arch route-back):
//
// 3-link self-anchored chain (cap_root → cap_mid → cap_leaf):
//   - cap_root:  granter=us (validator), grantee=A, resources=/*/*    (frame-invariant)
//   - cap_mid:   granter=A (foreign),     grantee=B, resources="*"    (FRAME-DEPENDENT
//                — per §PR-8 canonicalizes against A → /{A}/*; under buggy
//                local_peer_id frame would canonicalize to /{verifier}/*)
//   - cap_leaf:  granter=B (foreign),     grantee=us, resources=/{verifier}/system/type/system/peer
//                (FRAME-INVARIANT — already absolute; canonicalization is a no-op)
//
// EXECUTE target = /{verifier}/system/type/system/peer (peer-relative `system/type/system/peer`
// canonicalizes against the verifier to the absolute form). The leaf's explicit cross-peer
// path covers the target at dispatch regardless of frame — dispatch ADMITS. The chain-walk
// subset-check is then the only remaining gate.
//
// Chain-walk subset-check on cap_leaf ⊆ cap_mid:
//   - CORRECT (§PR-8 granter frame): cap_mid → /{A}/*. Is /{verifier}/system/type/system/peer
//     ⊆ /{A}/*? No (different peer namespaces) → DENY 403.
//   - BUGGY local_peer_id frame:    cap_mid → /{verifier}/*. Is /{verifier}/system/type/system/peer
//     ⊆ /{verifier}/*? YES (subpath) → ADMIT 200. Authority escalation:
//     A's peer-local authority is read as authorizing the verifier's namespace.
//
// V1 → V1' construction change (per the V7.73 Amendment 1 V1-prime
// reconstruction handoff): the V1 original used bare "*" at
// BOTH mid + leaf. That construction was admitted at dispatch by V2(a)'s
// plumbing alone — the leaf's bare * canon /{B}/* never covered the
// verifier's namespace, so the chain-walk site was shadowed and the 3-way
// PASS on V1 reported the dispatch boundary, not chain-walk. V1' makes
// the leaf frame-invariant so dispatch admits unconditionally and the
// chain-walk subset-check is the sole disposition site.
//
// Go's `3aaa0c9` plumbs per-link granter frame via
// `granterPeerIDFromIncluded` / `IsAttenuated` through the attenuation
// subset-check (core/capability/delegation.go).
func probeAuthzAttenuationForeignGranter1(client *PeerClient) CheckResult {
	const checkName = "authz_attenuation_foreign_granter_1"
	const specRef = "V7 §5.5a (Amendment 1, per-link granter frame, V1')"

	// Foreign granters A (mid signer) + B (leaf signer). Fresh keypairs so
	// their peer_ids differ from validator's and verifier's.
	aKP, err := crypto.Generate()
	if err != nil {
		return fail(catSecurity, checkName, specRef, "generate A keypair: "+err.Error())
	}
	aIdentity, err := aKP.IdentityEntity()
	if err != nil {
		return fail(catSecurity, checkName, specRef, "build A identity: "+err.Error())
	}
	bKP, err := crypto.Generate()
	if err != nil {
		return fail(catSecurity, checkName, specRef, "generate B keypair: "+err.Error())
	}
	bIdentity, err := bKP.IdentityEntity()
	if err != nil {
		return fail(catSecurity, checkName, specRef, "build B identity: "+err.Error())
	}

	kp := client.Keypair()
	identity := client.IdentityEntity()
	parentCap := client.CapEntity()
	now := uint64(time.Now().UnixMilli())
	fiveMin := now + 5*60*1000

	// Frame-invariant explicit cross-peer path the leaf grants AND target hits.
	leafExplicitPath := fmt.Sprintf("/%s/system/type/system/peer", client.RemotePeerID())

	// cap_root: granter=us, grantee=A, /*/* (frame-invariant wide).
	rootData := types.CapabilityTokenData{
		Grants: []types.GrantEntry{{
			Handlers:   types.CapabilityScope{Include: []string{"system/tree"}},
			Resources:  types.CapabilityScope{Include: []string{"/*/*"}},
			Operations: types.CapabilityScope{Include: []string{"*"}},
		}},
		Granter:   types.SingleSigGranter(identity.ContentHash),
		Grantee:   aIdentity.ContentHash,
		Parent:    &parentCap.ContentHash,
		CreatedAt: now,
		ExpiresAt: &fiveMin,
	}
	capRoot, capRootSig, err := createCapabilityToken(rootData, kp, identity)
	if err != nil {
		return fail(catSecurity, checkName, specRef, "create cap_root: "+err.Error())
	}

	// cap_mid: granter=A, grantee=B, bare "*" (FRAME-DEPENDENT — the surface
	// under test). SIGNED BY A.
	midData := types.CapabilityTokenData{
		Grants: []types.GrantEntry{{
			Handlers:   types.CapabilityScope{Include: []string{"system/tree"}},
			Resources:  types.CapabilityScope{Include: []string{"*"}},
			Operations: types.CapabilityScope{Include: []string{"*"}},
		}},
		Granter:   types.SingleSigGranter(aIdentity.ContentHash),
		Grantee:   bIdentity.ContentHash,
		Parent:    &capRoot.ContentHash,
		CreatedAt: now,
		ExpiresAt: &fiveMin,
	}
	capMid, capMidSig, err := createCapabilityToken(midData, aKP, aIdentity)
	if err != nil {
		return fail(catSecurity, checkName, specRef, "create cap_mid: "+err.Error())
	}

	// cap_leaf: granter=B, grantee=us, EXPLICIT cross-peer to verifier
	// (frame-invariant). SIGNED BY B.
	leafData := types.CapabilityTokenData{
		Grants: []types.GrantEntry{{
			Handlers:   types.CapabilityScope{Include: []string{"system/tree"}},
			Resources:  types.CapabilityScope{Include: []string{leafExplicitPath}},
			Operations: types.CapabilityScope{Include: []string{"*"}},
		}},
		Granter:   types.SingleSigGranter(bIdentity.ContentHash),
		Grantee:   identity.ContentHash,
		Parent:    &capMid.ContentHash,
		CreatedAt: now,
		ExpiresAt: &fiveMin,
	}
	capLeaf, capLeafSig, err := createCapabilityToken(leafData, bKP, bIdentity)
	if err != nil {
		return fail(catSecurity, checkName, specRef, "create cap_leaf: "+err.Error())
	}

	// EXECUTE: target = leaf's explicit path. Dispatch admits via leaf
	// (frame-invariant); chain-walk subset-check is the disposition site.
	params, resource, err := buildSimpleGetParams()
	if err != nil {
		return fail(catSecurity, checkName, specRef, "setup: "+err.Error())
	}
	env, err := buildDelegatedExecute(client, capLeaf, capLeafSig, serverTreeURI(client), "get", params, resource)
	if err != nil {
		return fail(catSecurity, checkName, specRef, "build execute: "+err.Error())
	}
	env.Include(capRoot)
	env.Include(capRootSig)
	env.Include(capMid)
	env.Include(capMidSig)
	env.Include(aIdentity)
	env.Include(bIdentity)

	desc := "3-link chain, foreign-granter mid (bare *) + explicit cross-peer leaf — chain-walk frame isolation (V1')"
	return withCheck(denyOutcome(client, env, desc, false), checkName, specRef)
}

// probeAuthzAttenuationForeignGranterDeep (V7 v7.73 Amendment 1, §5.5a
// multi-level chain-walk granter frame):
//
// 4-link self-anchored chain stressing per-link frame plumbing at TWO
// intermediate sites simultaneously:
//   - cap_root:  granter=us, grantee=A, resources=/*/*           (frame-invariant)
//   - cap_mid1:  granter=A,  grantee=B, resources="*"            (frame-dependent: /{A}/* correct, /{verifier}/* buggy)
//   - cap_mid2:  granter=B,  grantee=C, resources="*"            (frame-dependent: /{B}/* correct, /{verifier}/* buggy)
//   - cap_leaf:  granter=C,  grantee=us, resources=/{verifier}/system/type/system/peer (frame-invariant)
//
// EXECUTE target = /{verifier}/system/type/system/peer.
//
// Chain-walk subset-checks under CORRECT §PR-8 per-link frame:
//   - leaf /{verifier}/system/type/system/peer ⊆ mid2 /{B}/*? No  → DENY (and mid2 /{B}/* ⊆ mid1 /{A}/*? also No).
// Under BUGGY local_peer_id frame at BOTH mids:
//   - leaf ⊆ mid2 /{verifier}/*? Yes. mid2 /{verifier}/* ⊆ mid1 /{verifier}/*? Yes (equal). → ADMIT.
//
// An impl that plumbed granter-frame at ONE level but not another would
// surface a partial fix; this catches that class.
func probeAuthzAttenuationForeignGranterDeep(client *PeerClient) CheckResult {
	const checkName = "authz_attenuation_foreign_granter_deep"
	const specRef = "V7 §5.5a (Amendment 1, multi-level chain-walk granter frame)"

	aKP, err := crypto.Generate()
	if err != nil {
		return fail(catSecurity, checkName, specRef, "generate A keypair: "+err.Error())
	}
	aIdentity, err := aKP.IdentityEntity()
	if err != nil {
		return fail(catSecurity, checkName, specRef, "build A identity: "+err.Error())
	}
	bKP, err := crypto.Generate()
	if err != nil {
		return fail(catSecurity, checkName, specRef, "generate B keypair: "+err.Error())
	}
	bIdentity, err := bKP.IdentityEntity()
	if err != nil {
		return fail(catSecurity, checkName, specRef, "build B identity: "+err.Error())
	}
	cKP, err := crypto.Generate()
	if err != nil {
		return fail(catSecurity, checkName, specRef, "generate C keypair: "+err.Error())
	}
	cIdentity, err := cKP.IdentityEntity()
	if err != nil {
		return fail(catSecurity, checkName, specRef, "build C identity: "+err.Error())
	}

	kp := client.Keypair()
	identity := client.IdentityEntity()
	parentCap := client.CapEntity()
	now := uint64(time.Now().UnixMilli())
	fiveMin := now + 5*60*1000

	leafExplicitPath := fmt.Sprintf("/%s/system/type/system/peer", client.RemotePeerID())

	// cap_root: granter=us, grantee=A, /*/*.
	rootData := types.CapabilityTokenData{
		Grants: []types.GrantEntry{{
			Handlers:   types.CapabilityScope{Include: []string{"system/tree"}},
			Resources:  types.CapabilityScope{Include: []string{"/*/*"}},
			Operations: types.CapabilityScope{Include: []string{"*"}},
		}},
		Granter:   types.SingleSigGranter(identity.ContentHash),
		Grantee:   aIdentity.ContentHash,
		Parent:    &parentCap.ContentHash,
		CreatedAt: now,
		ExpiresAt: &fiveMin,
	}
	capRoot, capRootSig, err := createCapabilityToken(rootData, kp, identity)
	if err != nil {
		return fail(catSecurity, checkName, specRef, "create cap_root: "+err.Error())
	}

	// cap_mid1: granter=A, grantee=B, bare "*". SIGNED BY A.
	mid1Data := types.CapabilityTokenData{
		Grants: []types.GrantEntry{{
			Handlers:   types.CapabilityScope{Include: []string{"system/tree"}},
			Resources:  types.CapabilityScope{Include: []string{"*"}},
			Operations: types.CapabilityScope{Include: []string{"*"}},
		}},
		Granter:   types.SingleSigGranter(aIdentity.ContentHash),
		Grantee:   bIdentity.ContentHash,
		Parent:    &capRoot.ContentHash,
		CreatedAt: now,
		ExpiresAt: &fiveMin,
	}
	capMid1, capMid1Sig, err := createCapabilityToken(mid1Data, aKP, aIdentity)
	if err != nil {
		return fail(catSecurity, checkName, specRef, "create cap_mid1: "+err.Error())
	}

	// cap_mid2: granter=B, grantee=C, bare "*". SIGNED BY B.
	mid2Data := types.CapabilityTokenData{
		Grants: []types.GrantEntry{{
			Handlers:   types.CapabilityScope{Include: []string{"system/tree"}},
			Resources:  types.CapabilityScope{Include: []string{"*"}},
			Operations: types.CapabilityScope{Include: []string{"*"}},
		}},
		Granter:   types.SingleSigGranter(bIdentity.ContentHash),
		Grantee:   cIdentity.ContentHash,
		Parent:    &capMid1.ContentHash,
		CreatedAt: now,
		ExpiresAt: &fiveMin,
	}
	capMid2, capMid2Sig, err := createCapabilityToken(mid2Data, bKP, bIdentity)
	if err != nil {
		return fail(catSecurity, checkName, specRef, "create cap_mid2: "+err.Error())
	}

	// cap_leaf: granter=C, grantee=us, explicit cross-peer. SIGNED BY C.
	leafData := types.CapabilityTokenData{
		Grants: []types.GrantEntry{{
			Handlers:   types.CapabilityScope{Include: []string{"system/tree"}},
			Resources:  types.CapabilityScope{Include: []string{leafExplicitPath}},
			Operations: types.CapabilityScope{Include: []string{"*"}},
		}},
		Granter:   types.SingleSigGranter(cIdentity.ContentHash),
		Grantee:   identity.ContentHash,
		Parent:    &capMid2.ContentHash,
		CreatedAt: now,
		ExpiresAt: &fiveMin,
	}
	capLeaf, capLeafSig, err := createCapabilityToken(leafData, cKP, cIdentity)
	if err != nil {
		return fail(catSecurity, checkName, specRef, "create cap_leaf: "+err.Error())
	}

	params, resource, err := buildSimpleGetParams()
	if err != nil {
		return fail(catSecurity, checkName, specRef, "setup: "+err.Error())
	}
	env, err := buildDelegatedExecute(client, capLeaf, capLeafSig, serverTreeURI(client), "get", params, resource)
	if err != nil {
		return fail(catSecurity, checkName, specRef, "build execute: "+err.Error())
	}
	env.Include(capRoot)
	env.Include(capRootSig)
	env.Include(capMid1)
	env.Include(capMid1Sig)
	env.Include(capMid2)
	env.Include(capMid2Sig)
	env.Include(aIdentity)
	env.Include(bIdentity)
	env.Include(cIdentity)

	desc := "4-link chain, TWO foreign-granter mid links (A→B, B→C) bare * + explicit cross-peer leaf — multi-level frame plumbing"
	return withCheck(denyOutcome(client, env, desc, false), checkName, specRef)
}

// probeAuthzAttenuationForeignGranterWildcardLeaf (V7 v7.73 Amendment 1,
// §5.5a — chain-walk subset-check with wildcard suffix on the leaf):
//
// Variant of V1' where the leaf pattern carries a wildcard suffix instead
// of an exact path. Tests that the chain-walk subset-check correctly
// handles wildcard-vs-wildcard comparison when the wildcards belong to
// different peer namespaces under §PR-8.
//
//   - cap_root: granter=us, grantee=A, /*/*               (frame-invariant)
//   - cap_mid:  granter=A,  grantee=B, "*"                (frame-dependent)
//   - cap_leaf: granter=B,  grantee=us, /{verifier}/system/*  (frame-invariant, wildcard suffix)
//
// EXECUTE target = /{verifier}/system/type/system/peer (covered by leaf's /{verifier}/system/*).
//
// Dispatch: leaf /{verifier}/system/* covers target → admits.
// Chain-walk leaf ⊆ mid:
//   - CORRECT: mid → /{A}/*. /{verifier}/system/* ⊆ /{A}/*? No → DENY.
//   - BUGGY:   mid → /{verifier}/*. /{verifier}/system/* ⊆ /{verifier}/*? Yes (more specific) → ADMIT.
//
// Wildcard-suffix surface: an impl that string-compares full patterns
// (e.g., exact-prefix or pattern-equality) instead of doing proper
// subset analysis could pass V1' but fail this one.
func probeAuthzAttenuationForeignGranterWildcardLeaf(client *PeerClient) CheckResult {
	const checkName = "authz_attenuation_foreign_granter_wildcard_leaf"
	const specRef = "V7 §5.5a (Amendment 1, chain-walk subset-check with wildcard suffix leaf)"

	aKP, err := crypto.Generate()
	if err != nil {
		return fail(catSecurity, checkName, specRef, "generate A keypair: "+err.Error())
	}
	aIdentity, err := aKP.IdentityEntity()
	if err != nil {
		return fail(catSecurity, checkName, specRef, "build A identity: "+err.Error())
	}
	bKP, err := crypto.Generate()
	if err != nil {
		return fail(catSecurity, checkName, specRef, "generate B keypair: "+err.Error())
	}
	bIdentity, err := bKP.IdentityEntity()
	if err != nil {
		return fail(catSecurity, checkName, specRef, "build B identity: "+err.Error())
	}

	kp := client.Keypair()
	identity := client.IdentityEntity()
	parentCap := client.CapEntity()
	now := uint64(time.Now().UnixMilli())
	fiveMin := now + 5*60*1000

	leafWildcardPath := fmt.Sprintf("/%s/system/*", client.RemotePeerID())

	rootData := types.CapabilityTokenData{
		Grants: []types.GrantEntry{{
			Handlers:   types.CapabilityScope{Include: []string{"system/tree"}},
			Resources:  types.CapabilityScope{Include: []string{"/*/*"}},
			Operations: types.CapabilityScope{Include: []string{"*"}},
		}},
		Granter:   types.SingleSigGranter(identity.ContentHash),
		Grantee:   aIdentity.ContentHash,
		Parent:    &parentCap.ContentHash,
		CreatedAt: now,
		ExpiresAt: &fiveMin,
	}
	capRoot, capRootSig, err := createCapabilityToken(rootData, kp, identity)
	if err != nil {
		return fail(catSecurity, checkName, specRef, "create cap_root: "+err.Error())
	}

	midData := types.CapabilityTokenData{
		Grants: []types.GrantEntry{{
			Handlers:   types.CapabilityScope{Include: []string{"system/tree"}},
			Resources:  types.CapabilityScope{Include: []string{"*"}},
			Operations: types.CapabilityScope{Include: []string{"*"}},
		}},
		Granter:   types.SingleSigGranter(aIdentity.ContentHash),
		Grantee:   bIdentity.ContentHash,
		Parent:    &capRoot.ContentHash,
		CreatedAt: now,
		ExpiresAt: &fiveMin,
	}
	capMid, capMidSig, err := createCapabilityToken(midData, aKP, aIdentity)
	if err != nil {
		return fail(catSecurity, checkName, specRef, "create cap_mid: "+err.Error())
	}

	leafData := types.CapabilityTokenData{
		Grants: []types.GrantEntry{{
			Handlers:   types.CapabilityScope{Include: []string{"system/tree"}},
			Resources:  types.CapabilityScope{Include: []string{leafWildcardPath}},
			Operations: types.CapabilityScope{Include: []string{"*"}},
		}},
		Granter:   types.SingleSigGranter(bIdentity.ContentHash),
		Grantee:   identity.ContentHash,
		Parent:    &capMid.ContentHash,
		CreatedAt: now,
		ExpiresAt: &fiveMin,
	}
	capLeaf, capLeafSig, err := createCapabilityToken(leafData, bKP, bIdentity)
	if err != nil {
		return fail(catSecurity, checkName, specRef, "create cap_leaf: "+err.Error())
	}

	params, resource, err := buildSimpleGetParams()
	if err != nil {
		return fail(catSecurity, checkName, specRef, "setup: "+err.Error())
	}
	env, err := buildDelegatedExecute(client, capLeaf, capLeafSig, serverTreeURI(client), "get", params, resource)
	if err != nil {
		return fail(catSecurity, checkName, specRef, "build execute: "+err.Error())
	}
	env.Include(capRoot)
	env.Include(capRootSig)
	env.Include(capMid)
	env.Include(capMidSig)
	env.Include(aIdentity)
	env.Include(bIdentity)

	desc := "3-link chain, foreign-granter mid (bare *) + explicit-cross-peer leaf with wildcard suffix /{verifier}/system/*"
	return withCheck(denyOutcome(client, env, desc, false), checkName, specRef)
}
