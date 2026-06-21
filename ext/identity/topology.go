package identity

import (
	"go.entitychurch.org/entity-core-go/core/hash"
	"go.entitychurch.org/entity-core-go/core/store"
	"go.entitychurch.org/entity-core-go/core/types"
	"go.entitychurch.org/entity-core-go/ext/attestation"
	"go.entitychurch.org/entity-core-go/ext/quorum"
)

// TopologyMode names the signature topology a particular identity-context
// attestation requires per §3.6 identity_topology_for.
type TopologyMode int

const (
	TopologyKOfN   TopologyMode = iota // K-of-N from quorum
	TopologySingle                     // single-sig from a specific signer
	TopologyDual                       // dual-sig from old + new keys
)

// Topology describes the signature requirements for an identity-context
// attestation. KOfN sets {Signers, Threshold}; Single sets {ExpectedSigner};
// Dual sets {Signers}.
type Topology struct {
	Mode           TopologyMode
	Signers        []hash.Hash
	Threshold      uint64
	ExpectedSigner hash.Hash
}

// IdentityTopologyFor dispatches on properties.kind, properties.function,
// and is_quorum_id(att.attesting) to determine the signature topology
// requirements per §3.6.
//
// The result drives identity_verify_cert's topology dispatch; verification
// invokes the appropriate primitive (verify_k_of_n_signatures from
// EXTENSION-QUORUM, verify_specific_signer from EXTENSION-ATTESTATION,
// or both for dual-sig).
func IdentityTopologyFor(
	cs store.ContentStore,
	li store.LocationIndex,
	q *quorum.Handler,
	att types.AttestationData,
) (Topology, error) {
	kind := att.Kind()
	switch kind {
	case types.KindIdentityCert:
		var props types.IdentityCertProperties
		if err := types.DecodeProperties(att.Properties, &props); err != nil {
			return Topology{}, errString("decode identity-cert properties: " + err.Error())
		}
		isQuorum := quorum.IsQuorumID(cs, li, att.Attesting)
		switch props.Function {
		case types.FunctionController:
			if isQuorum {
				// Top-level controller cert: K-of-N from quorum.
				signers, threshold, err := q.CurrentSignerSet(att.Attesting)
				if err != nil {
					return Topology{}, err
				}
				return Topology{Mode: TopologyKOfN, Signers: signers, Threshold: threshold}, nil
			}
			// Sub-controller cert: single-sig from issuing controller.
			return Topology{Mode: TopologySingle, ExpectedSigner: att.Attesting}, nil
		case types.FunctionAgent, types.FunctionIdentifier:
			return Topology{Mode: TopologySingle, ExpectedSigner: att.Attesting}, nil
		default:
			// App-defined function: pinned single-sig from attesting per v3.3
			// SI-14. v3.3 does NOT specify an in-spec topology override hook
			// for app-defined functions; applications requiring custom
			// topology wrap IdentityVerifyCert with a pre-validator that runs
			// their topology check before delegating to the standard rules.
			return Topology{Mode: TopologySingle, ExpectedSigner: att.Attesting}, nil
		}

	case types.KindIdentityRotationHandoff:
		// Dual-sig: old key (att.attesting) + new key (att.attested).
		return Topology{Mode: TopologyDual, Signers: []hash.Hash{att.Attesting, att.Attested}}, nil

	case types.KindIdentityRotationRecovery, types.KindIdentityRetirement:
		// K-of-N from quorum. att.Attesting is the quorum_id.
		signers, threshold, err := q.CurrentSignerSet(att.Attesting)
		if err != nil {
			return Topology{}, err
		}
		return Topology{Mode: TopologyKOfN, Signers: signers, Threshold: threshold}, nil

	case types.KindRevocation:
		// Revocations are single-sig from the revoker (att.Attesting).
		return Topology{Mode: TopologySingle, ExpectedSigner: att.Attesting}, nil

	default:
		return Topology{}, errString("identity_topology_for: unknown kind " + kind)
	}
}

// IdentityIsQuorumLink is the terminate predicate for chain walks per §3.6.
// Returns true iff att is a top-level cert (its attesting is a known
// quorum_id on the local tree).
func IdentityIsQuorumLink(cs store.ContentStore, li store.LocationIndex) attestation.TerminatePredicate {
	return func(att attestation.AttestationRef) bool {
		return quorum.IsQuorumID(cs, li, att.Data.Attesting)
	}
}

// IdentityConfersFunction returns true iff `att` confers `functionName`
// on `att.Attested`. Per EXTENSION-IDENTITY v3.3 §3.6 (SI-13), chain walks
// looking for "the controller for this identity" must include lifecycle
// kinds — `identity-rotation-handoff` and `identity-rotation-recovery`
// inherit the function from their `target_cert`. `identity-retirement`
// terminates the chain (the function is retired; the chain ends as dead).
//
// Recursion handles handoff-of-handoff / recovery-of-handoff cases. The
// content store is bounded; no special depth limit needed (chain depth is
// bounded by `attestation.DefaultMaxChainDepth`).
//
// Used by chain-walk predicates (e.g., walk_cert_chain_to_current_controller)
// and other consumers that filter by function in the v3.3 cert chain.
func IdentityConfersFunction(
	cs store.ContentStore,
	att types.AttestationData,
	functionName string,
) bool {
	switch att.Kind() {
	case types.KindIdentityCert:
		var props types.IdentityCertProperties
		if err := types.DecodeProperties(att.Properties, &props); err != nil {
			return false
		}
		return props.Function == functionName
	case types.KindIdentityRotationHandoff,
		types.KindIdentityRotationRecovery:
		// Inherit function from target_cert.
		var common struct {
			TargetCert hash.Hash `cbor:"target_cert"`
		}
		if err := types.DecodeProperties(att.Properties, &common); err != nil {
			return false
		}
		if common.TargetCert.IsZero() {
			return false
		}
		ent, ok := cs.Get(common.TargetCert)
		if !ok || ent.Type != types.TypeAttestation {
			return false
		}
		target, err := types.AttestationDataFromEntity(ent)
		if err != nil {
			return false
		}
		return IdentityConfersFunction(cs, target, functionName)
	case types.KindIdentityRetirement:
		// Retirement RETIRES the function; the chain ends here as dead.
		// Returns false: a retired cert does not confer the function.
		return false
	}
	return false
}

// IdentityIsAuthorizedRevoker returns true if `revoker` has authority to
// revoke `targetCert` per identity's rules (§3.6). Identity rule: only the
// quorum at the root of target_cert's chain may revoke it. Plus self-
// revocation, handled at the primitive layer (IsAttestationLive).
func IdentityIsAuthorizedRevoker(
	cs store.ContentStore,
	li store.LocationIndex,
	ix *attestation.Index,
	q *quorum.Handler,
	revoker hash.Hash,
	targetCertHash hash.Hash,
	targetCert types.AttestationData,
) bool {
	// Walk targetCert's chain via attesting until we hit a quorum link.
	terminate := IdentityIsQuorumLink(cs, li)
	find := attestation.DefaultFindAuthorizing(cs, li, ix, 0)
	chain, ok := attestation.WalkAttestingChain(targetCertHash, targetCert, terminate, find, 0)
	if !ok {
		return false
	}
	if len(chain) == 0 {
		return false
	}
	quorumID := chain[len(chain)-1].Data.Attesting
	return revoker == quorumID
}

type errString string

func (e errString) Error() string { return string(e) }
