package validate

import (
	"context"
	"encoding/hex"
	"fmt"
	"strings"

	"go.entitychurch.org/entity-core-go/core/crypto"
	"go.entitychurch.org/entity-core-go/core/types"
)

// catPolicyDualForm validates V7 v7.65 §3.6 cap-pattern peer-reference
// canonicalization (including the rule 3 lazy-canonicalization path for
// Base58 mint without prior pubkey contact). Lineage: v7.64 dual-form
// policy was the original surface (POL-DF-1..POL-DF-6); v7.65 §9.2 directs
// Go-owned restructuring to reframe POL-DF-2 against §3.6 rule 3.
//
// Restructure scope (v7.65 §9.2):
//   - poldf_configure_hex_form_accepted (canonical) — KEEP, reframe to §3.6 rule 1+2
//   - poldf_lazy_canon_mint_accepts_base58_form_for_unknown_peer — RESCOPED from poldf_configure_base58_form_accepted to §3.6 rule 3
//   - poldf_configure_default_accepted — KEEP
//   - poldf_configure_garbage_rejected — KEEP
//   - poldf_configure_wildcard_rejected — KEEP
const catPolicyDualForm = "policy_dual_form"

// runPolicyDualForm asserts the live peer's capability handler accepts hex
// (canonical) and Base58 (lazy-canonicalization pending state) peer_patterns
// at configure, accepts "default", and rejects garbage and wildcards.
//
// Under v7.65 §3.6, the Base58 acceptance path is now the rule 3 lazy-canon
// mint surface — the configure succeeds with the pattern stored in pending
// state; canonicalization happens at first cap-match (lookupPolicy +
// canonicalizePolicyEntry). The configure-side acceptance is what this
// category exercises; the canonicalize-on-match behavior is exercised in
// the PEER-PATTERN-2 conformance vector.
func runPolicyDualForm(ctx context.Context, client *PeerClient) []CheckResult {
	r := NewCheckRunner(catPolicyDualForm)

	r.Declare("poldf_configure_hex_form_accepted", "V7 §3.6 v7.65 rule 1+2 (canonical hex peer_pattern)")
	r.Declare("poldf_lazy_canon_mint_accepts_base58_form_for_unknown_peer", "V7 §3.6 v7.65 rule 3 (lazy-canon: Base58 mint for unknown peer accepted with pending-canonicalization state)")
	r.Declare("poldf_configure_default_accepted", "V7 §3.6 v7.65 (default literal fallback)")
	r.Declare("poldf_configure_garbage_rejected", "V7 §3.6 v7.65 (MUST validation; garbage rejected)")
	r.Declare("poldf_configure_wildcard_rejected", "V7 §3.6 v7.65 (no globs in peer_pattern)")

	if !client.GrantsAllow("system/capability/policy/*") {
		skip := SkipCheck("connection grants do not allow writes under system/capability/policy/* — run with -identity framework-admin")
		for _, n := range []string{
			"poldf_configure_hex_form_accepted",
			"poldf_lazy_canon_mint_accepts_base58_form_for_unknown_peer",
			"poldf_configure_default_accepted",
			"poldf_configure_garbage_rejected",
			"poldf_configure_wildcard_rejected",
		} {
			r.Run(n, func() CheckOutcome { return skip })
		}
		return r.Results()
	}

	// Synthetic peer for the dual-form pattern; never dialed.
	synthKP, _ := crypto.Generate()
	synthPid := synthKP.PeerID()
	synthHash, _ := types.ComputePeerIdentityHashFromPeerID(synthPid)
	synthHex := hex.EncodeToString(synthHash.Bytes())

	// For the literal "default" peer_pattern, write a policy entry whose
	// grants mirror the validator's own connection-time cap. The "default"
	// segment is the fallback ceiling for ANY peer without an explicit
	// hex/Base58 entry — writing a NARROW grant there would poison every
	// downstream test that hits the default fallback (e.g.
	// capability.request_returns_grant, where the policy ceiling check
	// (handler.go:200) rejects 403 "scope_exceeds_authority" when the
	// request's grant — derived from the validator's connection grants —
	// adds Allowances/Constraints keys the policy entry doesn't list).
	//
	// By writing the validator's OWN connection grants under "default",
	// any request the validator can issue against its own cap is byte-for-
	// byte coverable by the policy ceiling. checkMapAttenuation
	// (core/capability/delegation.go:436) requires byte-identical
	// allowances/constraints values, which mirroring guarantees.
	//
	// The non-default patterns continue to write a narrow synthesis grant —
	// they're keyed to a synthetic Base58/hex peer that doesn't match
	// the validator's identity hash, so their policy entries never gate
	// the validator's own requests.
	mirrorGrants := append([]types.GrantEntry(nil), client.Grants()...)
	configure := func(pattern string) error {
		safeSuffix := pattern
		if len(safeSuffix) > 6 {
			safeSuffix = safeSuffix[:6]
		}
		var grants []types.GrantEntry
		if pattern == "default" {
			grants = mirrorGrants
		} else {
			grants = []types.GrantEntry{{
				Handlers:   types.CapabilityScope{Include: []string{"system/tree"}},
				Resources:  types.CapabilityScope{Include: []string{"system/validate/poldf/" + safeSuffix + "/"}},
				Operations: types.CapabilityScope{Include: []string{"get"}},
			}}
		}
		pe := types.CapabilityPolicyEntryData{
			PeerPattern: pattern,
			Grants:      grants,
		}
		ent, err := pe.ToEntity()
		if err != nil {
			return err
		}
		uri := fmt.Sprintf("entity://%s/system/capability", client.RemotePeerID())
		respEnv, _, err := client.SendExecute(ctx, uri, "configure", ent, nil)
		if err != nil {
			return err
		}
		// Decode the EXECUTE_RESPONSE envelope's root to get status.
		resp, err := types.ExecuteResponseDataFromEntity(respEnv.Root)
		if err != nil {
			return fmt.Errorf("decode execute response: %w", err)
		}
		if resp.Status >= 400 {
			return fmt.Errorf("status %d", resp.Status)
		}
		return nil
	}

	r.Run("poldf_configure_hex_form_accepted", func() CheckOutcome {
		// v7.65 §3.6 rule 1: pattern-write with canonical hex content_hash —
		// stored as-is; no canonicalization event needed.
		if err := configure(synthHex); err != nil {
			return FailCheck(fmt.Sprintf("configure with canonical hex peer_pattern %s rejected: %v", synthHex[:12]+"…", err))
		}
		return PassCheck(fmt.Sprintf("canonical hex peer_pattern (%s…) accepted per v7.65 §3.6 rule 1", synthHex[:12]))
	})

	r.Run("poldf_lazy_canon_mint_accepts_base58_form_for_unknown_peer", func() CheckOutcome {
		// v7.65 §3.6 rule 3: operator mints a cap pattern using a Base58
		// (wire-form) peer reference for a peer the impl has not previously
		// contacted. Impl MUST accept the mint with pattern stored in
		// pending-canonicalization state. Canonicalization happens at first
		// cap-match (verified separately in PEER-PATTERN-2 vector).
		//
		// The synthetic peer here is freshly generated and never dialed by
		// the target; its pubkey is not in the target's known set, so this
		// is the rule 3 unknown-peer path.
		if err := configure(string(synthPid)); err != nil {
			return FailCheck(fmt.Sprintf("configure with Base58 peer_pattern %s for unknown peer rejected: %v — v7.65 §3.6 rule 3 expects lazy-canon mint to succeed", string(synthPid), err))
		}
		return PassCheck(fmt.Sprintf("v7.65 §3.6 rule 3: Base58 peer_pattern (%s) accepted in pending-canonicalization state for unknown peer", string(synthPid)))
	})

	r.Run("poldf_configure_default_accepted", func() CheckOutcome {
		if err := configure("default"); err != nil {
			return FailCheck(fmt.Sprintf("configure with peer_pattern=default rejected: %v", err))
		}
		return PassCheck("default literal accepted per v7.65 §3.6")
	})

	r.Run("poldf_configure_garbage_rejected", func() CheckOutcome {
		// Invalid: wrong length, not Base58 or hex.
		err := configure("not-a-valid-peer-pattern-garbage")
		if err == nil {
			return FailCheck("configure with garbage peer_pattern accepted; v7.65 §3.6 MUST validation expects 400 invalid_peer_pattern")
		}
		if !strings.Contains(err.Error(), "400") && !strings.Contains(err.Error(), "invalid") {
			return FailCheck(fmt.Sprintf("configure rejected garbage but error %q does not look like a 400 invalid_peer_pattern", err.Error()))
		}
		return PassCheck("garbage peer_pattern rejected (v7.65 §3.6 MUST validation)")
	})

	r.Run("poldf_configure_wildcard_rejected", func() CheckOutcome {
		err := configure("*")
		if err == nil {
			return FailCheck("configure with peer_pattern=\"*\" accepted; v7.65 §3.6 expects rejection (use \"default\" instead)")
		}
		return PassCheck("wildcard peer_pattern rejected per v7.65 §3.6")
	})

	return r.Results()
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
