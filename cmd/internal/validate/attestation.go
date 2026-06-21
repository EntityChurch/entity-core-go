package validate

import (
	"context"

	"go.entitychurch.org/entity-core-go/core/entity"
	"go.entitychurch.org/entity-core-go/core/types"
)

// catAttestation is the validate-peer category for the EXTENSION-ATTESTATION
// surface (v1.0). Verifies the handler manifest, operations, and entity
// types are present on a running peer. The substrate primitive owns
// system/attestation (the edge type in the signed graph), one universal
// kind ("revocation"), six graph operations, and four handler operations.
//
// Index invariants I1-I5 (per §5.7) and the graph-walk test vectors
// TV-A1..A11 are exercised in the Go unit tests in ext/attestation/;
// cross-impl behavioral conformance vectors will land here as the cross-
// peer validate harness gains the support to drive create/supersede/revoke
// against arbitrary peer types via signed envelopes.
const catAttestation = "attestation"

func runAttestation(ctx context.Context, client *PeerClient) []CheckResult {
	r := NewCheckRunner(catAttestation)

	r.Declare("handler_manifest_present", "ATTESTATION §6")
	r.Declare("handler_manifest_decode", "ATTESTATION §6")
	for _, op := range attestationOps {
		r.Declare("handler_op_"+op, "ATTESTATION §6")
	}
	for _, ty := range attestationTypes {
		r.Declare("type_"+ty.short, "ATTESTATION §3 / §6")
	}

	// --- Manifest ---

	r.Run("handler_manifest_present", func() CheckOutcome {
		return optionalManifestPresent(ctx, client, r, "system/handler/system/attestation", "attestation")
	})

	r.Run("handler_manifest_decode", func() CheckOutcome {
		if out, ok := r.Require("handler_manifest_present"); !ok {
			return out
		}
		ent := r.Load("manifest_entity").(entity.Entity)
		iface, err := types.HandlerInterfaceDataFromEntity(ent)
		if err != nil {
			return FailCheck("could not decode attestation handler manifest: " + err.Error())
		}
		r.Store("iface_data", iface)
		return PassCheck("attestation handler manifest decoded")
	})

	for _, op := range attestationOps {
		op := op
		r.Run("handler_op_"+op, func() CheckOutcome {
			if out, ok := r.Require("handler_manifest_decode"); !ok {
				return out
			}
			iface := r.Load("iface_data").(types.HandlerInterfaceData)
			if _, exists := iface.Operations[op]; !exists {
				return FailCheck("attestation handler missing operation: " + op)
			}
			return PassCheck("attestation handler has operation: " + op)
		})
	}

	// --- Type registration ---

	for _, ty := range attestationTypes {
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

// attestationOps lists the §6 four handler operations defined by
// EXTENSION-ATTESTATION v1.0.
var attestationOps = []string{
	"create",
	"supersede",
	"revoke",
	"verify",
}

// attestationTypes lists the §3 entity type plus the eight handler
// request/result types defined by EXTENSION-ATTESTATION v1.0.
var attestationTypes = []struct{ short, full string }{
	{"attestation", types.TypeAttestation},
	{"create_request", types.TypeAttestationCreateRequest},
	{"create_result", types.TypeAttestationCreateResult},
	{"supersede_request", types.TypeAttestationSupersedeRequest},
	{"supersede_result", types.TypeAttestationSupersedeResult},
	{"revoke_request", types.TypeAttestationRevokeRequest},
	{"revoke_result", types.TypeAttestationRevokeResult},
	{"verify_request", types.TypeAttestationVerifyRequest},
	{"verify_result", types.TypeAttestationVerifyResult},
}
