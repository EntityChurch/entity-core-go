package identity

import (
	"fmt"
	"time"

	"go.entitychurch.org/entity-core-go/core/hash"
	"go.entitychurch.org/entity-core-go/core/store"
	"go.entitychurch.org/entity-core-go/core/types"
	"go.entitychurch.org/entity-core-go/ext/attestation"
	"go.entitychurch.org/entity-core-go/ext/quorum"
)

// IdentityVerifyCert is the orchestration entry point per §3.6. Composes
// EXTENSION-ATTESTATION helpers + EXTENSION-QUORUM K-of-N + identity-
// specific predicates to validate an identity-context attestation.
//
// Returns nil on success or an error naming the failing predicate
// (invalid_signature, not_live, authority_revoked, k_of_n_failed,
// wrong_signer, missing_dual_sig, chain_to_quorum_not_found, chain_link_invalid).
//
// Operational invariant per §3.6 / §2.2: identity attestations are NEVER
// routed through V7's verify_capability_chain. This routine is the SOLE
// validator for identity attestations.
func IdentityVerifyCert(
	cs store.ContentStore,
	li store.LocationIndex,
	ix *attestation.Index,
	q *quorum.Handler,
	attHash hash.Hash,
	att types.AttestationData,
) error {
	kind := att.Kind()

	// Identity-specific structural validation.
	if !isIdentityKind(kind) {
		return fmt.Errorf("not_identity_attestation: kind=%q", kind)
	}
	if kind == types.KindIdentityCert {
		var props types.IdentityCertProperties
		if err := types.DecodeProperties(att.Properties, &props); err != nil {
			return fmt.Errorf("decode identity-cert properties: %w", err)
		}
		if !isValidFunction(props.Function) {
			return fmt.Errorf("invalid_function: %q", props.Function)
		}
		if !isValidMode(props.Mode) {
			return fmt.Errorf("invalid_mode: %q", props.Mode)
		}
	}

	// Generic liveness check (expiration / supersession / self-revocation).
	if !attestation.IsAttestationLive(cs, li, ix, attHash, att, 0) {
		return fmt.Errorf("not_live")
	}

	// Authority-revocation check (identity-specific).
	revocations := attestation.FindRevocationsFor(ix, attHash)
	for _, revHash := range revocations {
		revRef, err := loadAttestationRef(cs, revHash)
		if err != nil {
			continue
		}
		if !attestation.IsAttestationLive(cs, li, ix, revRef.Hash, revRef.Data, 0) {
			continue
		}
		if IdentityIsAuthorizedRevoker(cs, li, ix, q, revRef.Data.Attesting, attHash, att) {
			return fmt.Errorf("authority_revoked")
		}
	}

	// Topology dispatch + signature verification.
	topology, err := IdentityTopologyFor(cs, li, q, att)
	if err != nil {
		return fmt.Errorf("topology: %w", err)
	}
	switch topology.Mode {
	case TopologyKOfN:
		if _, ok := quorum.VerifyKOfNSignatures(cs, li, attHash, topology.Signers, topology.Threshold); !ok {
			return fmt.Errorf("k_of_n_failed")
		}
	case TopologySingle:
		if att.Attesting != topology.ExpectedSigner {
			return fmt.Errorf("wrong_signer")
		}
		if !attestation.VerifyAttestationSignature(cs, li, attHash, att) {
			return fmt.Errorf("invalid_signature")
		}
	case TopologyDual:
		for _, signer := range topology.Signers {
			if !attestation.VerifySpecificSigner(cs, li, attHash, signer) {
				return fmt.Errorf("missing_dual_sig: %s", signer)
			}
		}
	}

	// Chain walk back to quorum (for non-top-level certs).
	if !quorum.IsQuorumID(cs, li, att.Attesting) {
		terminate := IdentityIsQuorumLink(cs, li)
		find := attestation.DefaultFindAuthorizing(cs, li, ix, 0)
		chain, ok := attestation.WalkAttestingChain(attHash, att, terminate, find, 0)
		if !ok {
			return fmt.Errorf("chain_to_quorum_not_found")
		}
		// Validate each link in the chain (excluding self).
		for i := 1; i < len(chain); i++ {
			link := chain[i]
			if err := IdentityVerifyCert(cs, li, ix, q, link.Hash, link.Data); err != nil {
				return fmt.Errorf("chain_link_invalid: %w", err)
			}
		}
	}

	return nil
}

// isIdentityKind returns true for the four kinds identity owns plus the
// universal "revocation" kind (which identity processes via authority-
// revocation rules per §3.6).
func isIdentityKind(kind string) bool {
	switch kind {
	case types.KindIdentityCert,
		types.KindIdentityRotationHandoff,
		types.KindIdentityRotationRecovery,
		types.KindIdentityRetirement,
		types.KindRevocation:
		return true
	}
	return false
}

// isValidFunction returns true for standard cert functions defined by
// identity. App-defined functions are accepted via the "any string"
// fallback per §3.6 valid_functions; identity_verify_cert's check is
// "function is in valid_functions() OR function is an app-defined string"
// — apps that ship custom functions declare them in their own validator.
//
// For now we accept any non-empty string; future tightening can plug an
// app-defined-function registry here.
func isValidFunction(function string) bool {
	if function == "" {
		return false
	}
	switch function {
	case types.FunctionController, types.FunctionAgent, types.FunctionIdentifier:
		return true
	}
	// App-defined: accepted by default.
	return true
}

// isValidMode returns true for the four standard publication modes.
func isValidMode(mode string) bool {
	switch mode {
	case types.ModeInternal, types.ModePublic, types.ModePerRelationship, types.ModeEmbedded:
		return true
	}
	return false
}

// validModesForFunction returns the spec §4.2 per-function valid-modes list
// for an identity-cert. attestingIsQuorum is true when properties.attesting
// resolves to a system/quorum entity (top-level controller); false when it
// resolves to another controller's peer key (sub-controller chain).
//
//	controller (top-level):  {public, internal}
//	controller (sub):        {internal}
//	agent:                   {internal, public, per-relationship, embedded}
//	identifier:              {internal}    (4-key advanced only)
//	app-defined:             nil  (caller accepts any; apps document their own)
//
// Per PROPOSAL-IDENTITY-COMPOSITION-CLEANUP §PI-11. Returns nil for
// app-defined functions to signal "no enforcement here".
func validModesForFunction(function string, attestingIsQuorum bool) []string {
	switch function {
	case types.FunctionController:
		if attestingIsQuorum {
			return []string{types.ModePublic, types.ModeInternal}
		}
		return []string{types.ModeInternal}
	case types.FunctionAgent:
		return []string{types.ModeInternal, types.ModePublic, types.ModePerRelationship, types.ModeEmbedded}
	case types.FunctionIdentifier:
		return []string{types.ModeInternal}
	}
	// App-defined function: no enforcement.
	return nil
}

// modeAllowedForFunction reports whether mode is in validModesForFunction.
// Returns true unconditionally for app-defined functions (whose valid-modes
// list is nil).
func modeAllowedForFunction(mode, function string, attestingIsQuorum bool) bool {
	allowed := validModesForFunction(function, attestingIsQuorum)
	if allowed == nil {
		return true
	}
	for _, m := range allowed {
		if m == mode {
			return true
		}
	}
	return false
}

// loadAttestationRef fetches an attestation entity by hash and returns it
// paired with its content hash.
func loadAttestationRef(cs store.ContentStore, h hash.Hash) (attestation.AttestationRef, error) {
	ent, ok := cs.Get(h)
	if !ok {
		return attestation.AttestationRef{}, fmt.Errorf("attestation not found: %s", h)
	}
	if ent.Type != types.TypeAttestation {
		return attestation.AttestationRef{}, fmt.Errorf("not a system/attestation: %s", h)
	}
	att, err := types.AttestationDataFromEntity(ent)
	if err != nil {
		return attestation.AttestationRef{}, err
	}
	return attestation.AttestationRef{Hash: h, Data: att}, nil
}

// nowMillis returns the current epoch-millisecond timestamp. Used by
// liveness predicates that don't take an as_of parameter.
func nowMillis() uint64 {
	return uint64(time.Now().UnixMilli())
}
