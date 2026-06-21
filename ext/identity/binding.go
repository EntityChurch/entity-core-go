package identity

import (
	"fmt"

	"go.entitychurch.org/entity-core-go/core/entity"
	"go.entitychurch.org/entity-core-go/core/hash"
	"go.entitychurch.org/entity-core-go/core/store"
	"go.entitychurch.org/entity-core-go/core/types"
	"go.entitychurch.org/entity-core-go/ext/attestation"
)

// BindingPolicy controls how strict the IdentityBindingChecker is on
// grantee identity-binding lookup per EXTENSION-IDENTITY §12.3.
//
// Per v3.8 the scope is pinned: the hook applies ONLY to caps whose
// grantee is a local identity (agent / sub-controller tracked in the
// local identity tree). A cap whose grantee is a remote peer
// (authenticated by the V7 §4.1 handshake + signed cap chain, e.g. a
// cross-peer dispatch_capability per EXTENSION-CONTINUATION §4.2) is
// out of scope regardless of policy — see CheckGranteeBinding.
type BindingPolicy int

const (
	// PolicyAllowAnyAttestedAgent runs a liveness/revocation check on
	// grantees that ARE local identities (identity-cert function=agent
	// or function=controller). Per v3.8 the check is silent when the
	// grantee has no identity-cert binding at all — that grantee is not
	// a local identity and thus out of scope. The default policy.
	PolicyAllowAnyAttestedAgent BindingPolicy = iota
	// PolicyDisabled accepts all grantees unconditionally — useful for
	// open-access peers where identity binding is not enforced even
	// for local-identity grantees.
	PolicyDisabled
)

// BindingChecker implements protocol.IdentityBindingChecker for v3.2 per
// the §12.3 / IA23 cross-cut. Cap-chain verification calls
// CheckGranteeBinding to confirm the grantee is bound to a live identity-
// cert attestation on the local tree.
//
// The check uses the attestation index (FindAttestationsTargeting on
// `attested`) to enumerate candidates, then filters to live identity-cert
// attestations. No tree walk needed — the index is the authoritative
// store-of-record per EXTENSION-ATTESTATION §5.7.
type BindingChecker struct {
	cs     store.ContentStore
	li     store.LocationIndex
	att    *attestation.Handler
	policy BindingPolicy
}

// NewBindingChecker constructs a BindingChecker using the provided store,
// location index, attestation handler, and policy. A nil attestation
// handler returns a checker that always rejects (fail-closed before
// substrate is wired); the entity-peer wiring should pass a real handler.
func NewBindingChecker(
	cs store.ContentStore,
	li store.LocationIndex,
	att *attestation.Handler,
	policy BindingPolicy,
) *BindingChecker {
	return &BindingChecker{cs: cs, li: li, att: att, policy: policy}
}

// CheckGranteeBinding implements protocol.IdentityBindingChecker. Returns
// nil iff the grantee hash is the attested peer of at least one live
// identity-cert attestation in the local tree, or iff the policy is
// PolicyDisabled, or iff the local peer has no peer-config bound (i.e.,
// has not yet been "configured" — until the first identity.Startup or
// configure call lands a peer-config, the binding check is a no-op for
// V7-only deployments and ephemeral testing peers).
func (b *BindingChecker) CheckGranteeBinding(grantee hash.Hash, env entity.Envelope) error {
	if b.policy == PolicyDisabled {
		return nil
	}
	if b.att == nil {
		return fmt.Errorf("identity binding checker: substrate not wired")
	}
	if grantee.IsZero() {
		return fmt.Errorf("identity binding checker: grantee is zero hash")
	}
	// Unconfigured peer fall-through: when no peer-config exists, treat the
	// peer as V7-only and skip the binding check. Once configure runs, the
	// peer-config is bound and this branch stops applying.
	if _, ok := b.li.Get(identityPeerConfigPath); !ok {
		return nil
	}
	candidates := attestation.FindAttestationsTargeting(b.cs, b.att.Index(), grantee, func(_ hash.Hash, a types.AttestationData) bool {
		if a.Kind() != types.KindIdentityCert {
			return false
		}
		var props types.IdentityCertProperties
		if err := types.DecodeProperties(a.Properties, &props); err != nil {
			return false
		}
		return props.Function == types.FunctionAgent || props.Function == types.FunctionController
	})
	// v3.8 §12.3 scope: the hook applies only to caps whose grantee is a
	// local identity (agent / sub-controller tracked in the local identity
	// tree). Absent any identity-cert binding for the grantee, this grantee
	// is NOT a local identity — it's a remote peer (authenticated by §4.1
	// handshake + signed cap chain, e.g. a cross-peer dispatch_capability
	// grantee per CONTINUATION §4.2) or an external party. Out of scope —
	// silent. Without this scope, a strict peer rejects already-authenticated
	// cross-peer dispatch caps, which both defeats cross-peer dispatch and
	// adds no security (the connection + chain already authenticate the
	// grantee). Resolved the four §12.3-rooted failures in the round-2
	// cross-impl convergent_mirror matrix.
	if len(candidates) == 0 {
		return nil
	}
	// At least one identity-cert binding exists for this grantee — it IS a
	// local identity. v3.8's MAY for local grantees then requires at least
	// one of those bindings to be live (the liveness/revocation check).
	for _, c := range candidates {
		if attestation.IsAttestationLive(b.cs, b.li, b.att.Index(), c.Hash, c.Data, 0) {
			return nil
		}
	}
	return fmt.Errorf("identity binding checker: local identity-cert binding for grantee %s exists but no live attestation (revoked or expired)", grantee)
}
