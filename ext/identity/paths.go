package identity

import (
	"encoding/hex"
	"fmt"

	"go.entitychurch.org/entity-core-go/core/hash"
	"go.entitychurch.org/entity-core-go/core/types"
)

// Tree path conventions for identity-extension entities per
// EXTENSION-IDENTITY v3.3 §5.1. All paths are peer-relative;
// NamespacedIndex canonicalizes to absolute /{local_peer_id}/... at
// storage time.
//
// Hash-typed segments use lowercase hex of the full system/hash byte
// sequence (algorithm byte + digest), per §5.3.
const (
	// Identity subtrees.
	identityRoot                = "system/identity"
	identityInternalCertPrefix  = "system/identity/internal/cert"
	identityPublicCertPrefix    = "system/identity/public/cert"
	identityRelationshipsPrefix = "system/identity/relationships"
	identityContactsPrefix      = "system/identity/contacts"
	identityPeerConfigPath      = "system/identity/peer-config"

	// Local cap storage for the local peer→controller cap. Per controller;
	// multi-controller deployments hold one cap per live controller cert.
	localPeerToControllerCapPrefix = "system/capability/grants/identity/peer-to-controller"

	// Controller-events stream root per PI-5 (Rev 3). Local-only (not
	// part of the cross-peer sync surface in §5.2). Path shape:
	//   system/identity/events/{ts_ms}/{handler_id}/{att_hash}/{event_hash}
	identityEventsPrefix = "system/identity/events"
)

// hexHash returns the lowercase hex form of a 33-byte content hash, used
// for path segments per §5.3.
func hexHash(h hash.Hash) string {
	return hex.EncodeToString(h.Bytes())
}

// internalCertPath returns the canonical storage path for an identity-cert
// (or lifecycle-event) attestation in the "internal" audience tier.
func internalCertPath(attHash hash.Hash) string {
	return identityInternalCertPrefix + "/" + hexHash(attHash)
}

// publicCertPath returns the canonical storage path for an identity-cert
// (or lifecycle-event) attestation in the "public" audience tier.
func publicCertPath(attHash hash.Hash) string {
	return identityPublicCertPrefix + "/" + hexHash(attHash)
}

// relationshipCertPath returns the canonical storage path for an
// identity-cert (or lifecycle-event) attestation in the "per-relationship"
// audience tier, namespaced by contact_id.
func relationshipCertPath(contactID, attHash hash.Hash) string {
	return identityRelationshipsPrefix + "/" + hexHash(contactID) + "/cert/" + hexHash(attHash)
}

// contactsQuorumPublishPath returns the path where a contact identity's
// most recent quorum-publish attestation is cached on the local peer per
// §5.1. Consulted by §9.4 fail-closed validation when processing
// identity-rotation-recovery attestations.
func contactsQuorumPublishPath(publishedHandle hash.Hash) string {
	return identityContactsPrefix + "/" + hexHash(publishedHandle) + "/quorum-publish"
}

// localPeerToControllerCapPath returns the path for the local peer→
// controller cap for a specific controller cert. Multi-controller
// deployments hold one cap per live top-level controller cert per §11.6.
func localPeerToControllerCapPath(controllerKey hash.Hash) string {
	return localPeerToControllerCapPrefix + "/" + hexHash(controllerKey)
}

// identityEventPath returns the canonical binding path for a controller-
// events entity per PI-5 (Rev 3):
//
//	system/identity/events/{ts_ms}/{handler_id}/{att_hash}/{event_hash}
//
// The trailing event-content-hash segment makes the path unique by
// definition; identical events at the same instant collapse to the same
// path (idempotent semantic).
func identityEventPath(timestampMs uint64, handlerID string, attHash, eventHash hash.Hash) string {
	return fmt.Sprintf("%s/%d/%s/%s/%s",
		identityEventsPrefix, timestampMs, handlerID, hexHash(attHash), hexHash(eventHash))
}

// canonicalCertPath returns the canonical storage path for an
// identity-cert attestation per §5.3 — purely a function of
// properties.mode (and properties.contact_id when mode="per-relationship").
// Returns empty string for mode="embedded" (no tree path; embedded in cap
// envelope).
//
// Per §4.2 the cert author sets mode explicitly at create-time; path
// resolution does NOT consult runtime shape state. This eliminates the
// in-flight-rotation race that a runtime shape lookup would create.
func canonicalCertPath(att types.AttestationData) (string, error) {
	if att.Kind() != types.KindIdentityCert {
		return "", fmt.Errorf("canonicalCertPath: expected identity-cert, got %q", att.Kind())
	}
	var props types.IdentityCertProperties
	if err := types.DecodeProperties(att.Properties, &props); err != nil {
		return "", fmt.Errorf("decode identity-cert properties: %w", err)
	}
	ent, err := att.ToEntity()
	if err != nil {
		return "", err
	}
	switch props.Mode {
	case types.ModeInternal:
		return internalCertPath(ent.ContentHash), nil
	case types.ModePublic:
		return publicCertPath(ent.ContentHash), nil
	case types.ModePerRelationship:
		if props.ContactID == nil || props.ContactID.IsZero() {
			return "", fmt.Errorf("identity-cert mode=per-relationship requires contact_id")
		}
		return relationshipCertPath(*props.ContactID, ent.ContentHash), nil
	case types.ModeEmbedded:
		return "", nil // no tree path
	default:
		return "", fmt.Errorf("invalid identity-cert mode: %q", props.Mode)
	}
}

// CanonicalCertPath is the exported form of canonicalCertPath, used by
// SDK consumers (ext/identity/sdk) to compute path-as-resource targets
// for create_attestation / supersede_attestation per V7 §3.2 / EXTENSION-
// IDENTITY §6.
func CanonicalCertPath(att types.AttestationData) (string, error) {
	return canonicalCertPath(att)
}

// InternalCertPath returns the canonical path for an internal-tier
// identity-cert. Exported for SDK use; mirrors internalCertPath.
func InternalCertPath(attHash hash.Hash) string {
	return internalCertPath(attHash)
}

// PublicCertPath returns the canonical path for a public-tier identity-
// cert. Exported for SDK use; mirrors publicCertPath.
func PublicCertPath(attHash hash.Hash) string {
	return publicCertPath(attHash)
}

// RelationshipCertPath returns the canonical path for a per-relationship
// identity-cert. Exported for SDK use; mirrors relationshipCertPath.
func RelationshipCertPath(contactID, attHash hash.Hash) string {
	return relationshipCertPath(contactID, attHash)
}

// PeerConfigPath is the canonical path of the identity peer-config entity.
// Exported for SDK use as the resource-target on :configure.
const PeerConfigPath = identityPeerConfigPath

// QuorumPathFor returns the canonical path for a system/quorum entity at
// `system/quorum/{q_hex}`. Exported for SDK use as the resource-target
// on :create_quorum.
func QuorumPathFor(quorumID hash.Hash) string {
	return "system/quorum/" + hexHash(quorumID)
}

// sameTierPath returns the path for a lifecycle-event attestation
// (identity-rotation-handoff, identity-rotation-recovery,
// identity-retirement, or revocation targeting an identity cert) operating
// on targetAtt, in the same audience tier as targetAtt per §5.3
// canonical_storage_path / same_tier_path.
//
// Lifecycle events inherit their target cert's mode for path resolution.
// The target cert's mode determines the tier; the lifecycle event's hash
// goes under that tier's cert subdirectory.
func sameTierPath(targetAtt types.AttestationData, attHash hash.Hash) (string, error) {
	if targetAtt.Kind() != types.KindIdentityCert {
		return "", fmt.Errorf("sameTierPath: target is not an identity-cert (kind=%q)", targetAtt.Kind())
	}
	var props types.IdentityCertProperties
	if err := types.DecodeProperties(targetAtt.Properties, &props); err != nil {
		return "", fmt.Errorf("decode target identity-cert properties: %w", err)
	}
	switch props.Mode {
	case types.ModeInternal:
		return internalCertPath(attHash), nil
	case types.ModePublic:
		return publicCertPath(attHash), nil
	case types.ModePerRelationship:
		if props.ContactID == nil || props.ContactID.IsZero() {
			return "", fmt.Errorf("target cert mode=per-relationship requires contact_id")
		}
		return relationshipCertPath(*props.ContactID, attHash), nil
	case types.ModeEmbedded:
		return "", fmt.Errorf("cannot derive lifecycle-event path for embedded target cert")
	default:
		return "", fmt.Errorf("invalid target cert mode: %q", props.Mode)
	}
}
