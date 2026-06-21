package identity

import (
	"fmt"

	"go.entitychurch.org/entity-core-go/core/handler"
	"go.entitychurch.org/entity-core-go/core/hash"
	"go.entitychurch.org/entity-core-go/core/types"
)

// Controller-event handler IDs per PI-5 (Rev 3) §6.3 dispatch table.
// Each (kind, function) handler registers under one of these IDs.
const (
	HandlerIDIssueLocalCap           = "maybe_issue_local_cap"
	HandlerIDIssueLocalControllerCap = "maybe_issue_local_controller_cap"
	HandlerIDUpdateIdentifierHandle  = "maybe_update_identifier_handle"
	HandlerIDDualSigHandoff          = "handle_dual_sig_handoff"
	HandlerIDUpdateHandleCacheTo     = "update_handle_cache_to"
	HandlerIDRevokeLocalCaps         = "revoke_local_caps_for_attested"
	HandlerIDSeedContactsCache       = "seed_contacts_cache"

	// Recovery-signal site IDs (PI-3 / PI-13).
	HandlerIDPublishMoveRebind = "publish_attestation_move_rebind"
	HandlerIDRevokeCapCleanup  = "revoke_attestation_cap_cleanup"
)

// emitControllerEvent binds a system/identity/event entity at the
// canonical PI-5 path. Used by phase-3 of :process_attestation on phase-2
// handler failure, and by PI-3 / PI-13 recovery sites when partial
// failure leaves orphaned/inconsistent state.
//
// subkind MUST be one of types.EventSubkindRecoverySignal (retention-
// pinned; controller intervention required) or
// types.EventSubkindFailureObservation (impl-defined retention; advisory).
//
// op is the TreeSet operation tag — keep distinct from
// process_attestation-* op names so the sync-hook re-entrance filter
// (isInternalProcessAttestationOp) doesn't suppress the event.
func emitControllerEvent(
	hctx *handler.HandlerContext,
	subkind, handlerID string,
	attHash hash.Hash,
	attKind, errCode, errDetail string,
) (hash.Hash, string, error) {
	ts := nowMillis()
	data := types.IdentityEventData{
		EventSubkind:    subkind,
		HandlerID:       handlerID,
		AttestationHash: attHash,
		AttestationKind: attKind,
		ErrorCode:       errCode,
		ErrorDetail:     errDetail,
		TimestampMs:     ts,
	}
	ent, err := data.ToEntity()
	if err != nil {
		return hash.Hash{}, "", err
	}
	if _, err := hctx.Store.Put(ent); err != nil {
		return hash.Hash{}, "", err
	}
	path := identityEventPath(ts, handlerID, attHash, ent.ContentHash)
	if _, err := hctx.TreeSet(path, ent.ContentHash, "controller-event-emit"); err != nil {
		return hash.Hash{}, "", fmt.Errorf("bind identity event %s: %w", path, err)
	}
	return ent.ContentHash, path, nil
}
