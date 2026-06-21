package validate

import (
	"context"

	"go.entitychurch.org/entity-core-go/core/entity"
	"go.entitychurch.org/entity-core-go/core/types"
)

// catIdentity is the validate-peer category for the EXTENSION-IDENTITY
// surface (v3.2). Verifies the handler manifest, operations, and entity
// types are present on a running peer. Deeper post-bootstrap checks
// (peer-config, attestation flows, kind-specific topology) require an in-
// process bootstrap and live in unit tests / cross-impl integration.
//
// In v3.2 the substrate split is a separate concern: attestation and
// quorum each have their own categories (see attestation.go and quorum.go);
// this category covers ONLY identity's convention layer (peer-config,
// identity-binding, identity-cert / lifecycle / retirement kinds).
const catIdentity = "identity"

func runIdentity(ctx context.Context, client *PeerClient) []CheckResult {
	r := NewCheckRunner(catIdentity)

	// --- Handler manifest + operations ---

	r.Declare("handler_manifest_present", "IDENTITY §6")
	r.Declare("handler_manifest_decode", "IDENTITY §6")
	for _, op := range identityOps {
		r.Declare("handler_op_"+op, "IDENTITY §6")
	}

	// --- Type registration ---

	for _, ty := range identityEntityTypes {
		r.Declare("type_"+ty.short, "IDENTITY §3")
	}
	for _, ty := range identityRequestTypes {
		r.Declare("type_"+ty.short, "IDENTITY §6")
	}

	// --- Step 1: Handler manifest ---

	r.Run("handler_manifest_present", func() CheckOutcome {
		return optionalManifestPresent(ctx, client, r, "system/handler/system/identity", "identity")
	})

	r.Run("handler_manifest_decode", func() CheckOutcome {
		if out, ok := r.Require("handler_manifest_present"); !ok {
			return out
		}
		ent := r.Load("manifest_entity").(entity.Entity)
		ifaceData, err := types.HandlerInterfaceDataFromEntity(ent)
		if err != nil {
			return FailCheck("could not decode identity handler manifest: " + err.Error())
		}
		r.Store("iface_data", ifaceData)
		return PassCheck("identity handler manifest decoded")
	})

	for _, op := range identityOps {
		op := op
		r.Run("handler_op_"+op, func() CheckOutcome {
			if out, ok := r.Require("handler_manifest_decode"); !ok {
				return out
			}
			iface := r.Load("iface_data").(types.HandlerInterfaceData)
			if _, exists := iface.Operations[op]; !exists {
				return FailCheck("identity handler missing operation: " + op)
			}
			return PassCheck("identity handler has operation: " + op)
		})
	}

	// --- Step 2: Type registration ---

	for _, ty := range identityEntityTypes {
		ty := ty
		r.Run("type_"+ty.short, func() CheckOutcome {
			if out, ok := r.Require("handler_manifest_present"); !ok {
				return out
			}
			if _, _, err := client.TreeGet(ctx, "system/type/"+ty.full); err != nil {
				return FailCheck("type not registered: " + ty.full + ": " + err.Error())
			}
			return PassCheck("type registered: " + ty.full)
		})
	}
	for _, ty := range identityRequestTypes {
		ty := ty
		r.Run("type_"+ty.short, func() CheckOutcome {
			if out, ok := r.Require("handler_manifest_present"); !ok {
				return out
			}
			if _, _, err := client.TreeGet(ctx, "system/type/"+ty.full); err != nil {
				return FailCheck("type not registered: " + ty.full + ": " + err.Error())
			}
			return PassCheck("type registered: " + ty.full)
		})
	}

	return r.Results()
}

// identityOps lists the §6 v3.2 operations. Seven operations preserved from
// v2.2 external surface; substrate primitive ops (system/attestation:create
// etc., system/quorum:create etc.) have their own validate categories.
var identityOps = []string{
	"configure",
	"create_quorum",
	"create_attestation",
	"supersede_attestation",
	"revoke_attestation",
	"publish_attestation",
	"process_attestation",
}

// identityEntityTypes lists the §3 v3.2 entity types: one primary
// (peer-config) plus one helper inner type (identity-binding). The v2.2
// types system/identity/quorum and system/identity/attestation are GONE —
// they live in EXTENSION-QUORUM and EXTENSION-ATTESTATION now.
var identityEntityTypes = []struct{ short, full string }{
	{"peer_config", types.TypeIdentityPeerConfig},
	{"identity_binding", types.TypeIdentityBinding},
}

// identityRequestTypes lists the §6 v3.2 handler request/result types.
var identityRequestTypes = []struct{ short, full string }{
	{"configure_request", types.TypeIdentityConfigureRequest},
	{"configure_result", types.TypeIdentityConfigureResult},
	{"create_quorum_request", types.TypeIdentityCreateQuorumRequest},
	{"create_quorum_result", types.TypeIdentityCreateQuorumResult},
	{"create_attestation_request", types.TypeIdentityCreateAttestationRequest},
	{"create_attestation_result", types.TypeIdentityCreateAttestationResult},
	{"supersede_attestation_request", types.TypeIdentitySupersedeAttestationRequest},
	{"supersede_attestation_result", types.TypeIdentitySupersedeAttestationResult},
	{"revoke_attestation_request", types.TypeIdentityRevokeAttestationRequest},
	{"revoke_attestation_result", types.TypeIdentityRevokeAttestationResult},
	{"publish_attestation_request", types.TypeIdentityPublishAttestationRequest},
	{"publish_attestation_result", types.TypeIdentityPublishAttestationResult},
}
