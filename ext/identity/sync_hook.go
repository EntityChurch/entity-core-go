package identity

import (
	"strings"

	"go.entitychurch.org/entity-core-go/core/store"
	"go.entitychurch.org/entity-core-go/core/types"
)

// OnTreeChange is the sync-hook for the identity handler per §6.8 / I4. It
// is the convergence point for any identity-context attestation entering
// the local tree at the named subtrees, regardless of source (incoming
// sync, local create_attestation, application-level direct writes via L0).
//
// The hook filters events to attestation-bearing paths under
// system/identity/{public/cert,internal/cert,relationships/*/cert} and
// dispatches IdentityVerifyCert. Validation failures unbind the path
// (fail-closed) per §6.8 / §9.4.
//
// Returns nil for events that don't apply, or that pass validation. The
// hook never returns a halt — fail-closed validation rejection is
// expressed as path-unbind, not cascade-halt, per
// PROPOSAL-CASCADE-SEMANTICS §4.2.
func (h *Handler) OnTreeChange(evt store.TreeChangeEvent) *store.ConsumerResult {
	if evt.ChangeType == store.ChangeDeleted {
		return nil
	}
	_, barePath := store.SplitNamespace(evt.Path)
	if !isIdentityCertPath(barePath) {
		return nil
	}

	h.mu.RLock()
	cs := h.cs
	li := h.li
	att := h.att
	q := h.q
	h.mu.RUnlock()
	if cs == nil || li == nil || att == nil || q == nil {
		// Substrate not yet wired — skip; the post-state will reconverge
		// when local writes from configure / create_attestation re-fire
		// process_attestation.
		return nil
	}

	// Skip events the hook itself induced (fail-closed unbind, etc.) to
	// prevent re-entrant validation loops.
	if evt.Context != nil && isInternalProcessAttestationOp(evt.Context.Operation) {
		return nil
	}

	if evt.Hash.IsZero() {
		return nil
	}
	ent, ok := cs.Get(evt.Hash)
	if !ok || ent.Type != types.TypeAttestation {
		// Path falls under cert/ but the binding is something else — skip.
		return nil
	}
	a, err := types.AttestationDataFromEntity(ent)
	if err != nil {
		return nil
	}
	if !isIdentityKind(a.Kind()) {
		return nil
	}

	if err := IdentityVerifyCert(cs, li, att.Index(), q, ent.ContentHash, a); err != nil {
		// Fail-closed: remove the binding directly via the index. No
		// HandlerContext is available in the hook.
		li.Remove(barePath)
		return nil
	}
	// TODO(side-effects): cache contacts/{handle}/quorum-publish updates;
	// cap issuance/revocation for agent certs and retirements.
	return nil
}

// isIdentityCertPath returns true when the peer-relative path is one of
// the §5.1 identity-cert-bearing paths the sync hook covers:
//
//   - system/identity/internal/cert/{hash_hex}
//   - system/identity/public/cert/{hash_hex}
//   - system/identity/relationships/{contact_hex}/cert/{hash_hex}
//
// Excludes signature siblings (paths under .../signature*).
func isIdentityCertPath(barePath string) bool {
	if !strings.HasPrefix(barePath, "system/identity/") {
		return false
	}
	if strings.Contains(barePath, "/signature") {
		return false
	}
	switch {
	case strings.HasPrefix(barePath, "system/identity/internal/cert/"):
		return true
	case strings.HasPrefix(barePath, "system/identity/public/cert/"):
		return true
	case strings.HasPrefix(barePath, "system/identity/relationships/"):
		return strings.Contains(barePath, "/cert/")
	}
	return false
}

// isInternalProcessAttestationOp identifies operations the hook should
// skip. Two categories:
//
//   - Re-entrant operations the hook itself (or :process_attestation)
//     induced; skipped to prevent validation loops.
//   - Local attestation-creation operations (attestation-create /
//     -supersede / -revoke). Per PR-8.3 / TV-IF-INTERNAL-CERT-READABLE,
//     locally-created identity-certs MUST remain tree-gettable from the
//     local peer; fail-closed unbind at create time would tear down the
//     binding before signatures (which are written separately, after
//     the cert hash is known) have a chance to land. The structural
//     validation in att.Create is sufficient at the create site;
//     signature-graph validation runs explicitly via :process_attestation
//     or implicitly when consumers call IdentityVerifyCert
//     (e.g., :configure's enumerateLiveControllerCerts). Cross-peer
//     arrivals come through different op strings (subscription deliver,
//     continuation advance) and remain fail-closed.
func isInternalProcessAttestationOp(op string) bool {
	switch op {
	case "process_attestation-failed",
		"process_attestation-cache-quorum-publish",
		"process_attestation-issue-cap",
		"process_attestation-revoke-cap",
		"create_attestation-rollback",
		"supersede_attestation-rollback",
		"attestation-create",
		"attestation-supersede",
		"attestation-revoke",
		// PI-5 (Rev 3) controller-events emit op — internal write that
		// MUST NOT trigger re-entrant validation. Events are bound at
		// system/identity/events/... not in cert subtrees, so they
		// wouldn't match isProcessableIdentityCertPath anyway, but list
		// for clarity.
		"controller-event-emit":
		return true
	}
	return false
}
