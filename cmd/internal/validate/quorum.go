package validate

import (
	"context"

	"go.entitychurch.org/entity-core-go/core/entity"
	"go.entitychurch.org/entity-core-go/core/types"
)

// catQuorum is the validate-peer category for the EXTENSION-QUORUM surface
// (v1.0). Verifies the handler manifest, operations, and entity types are
// present on a running peer. The K-of-N node primitive owns system/quorum,
// two attestation kinds (quorum-update / quorum-publish — both
// system/attestation entities discriminated by properties.kind, NOT
// separate types), and four handler operations.
//
// Behavioral cross-impl vectors TV-Q1..Q9 (resolver fail-closed,
// is_quorum_id race semantics) and TV-QF12..QF15 (cache invalidation
// contract) are exercised in the Go unit tests in ext/quorum/.
const catQuorum = "quorum"

func runQuorum(ctx context.Context, client *PeerClient) []CheckResult {
	r := NewCheckRunner(catQuorum)

	r.Declare("handler_manifest_present", "QUORUM §6")
	r.Declare("handler_manifest_decode", "QUORUM §6")
	for _, op := range quorumOps {
		r.Declare("handler_op_"+op, "QUORUM §6")
	}
	for _, ty := range quorumTypes {
		r.Declare("type_"+ty.short, "QUORUM §3 / §6")
	}

	r.Run("handler_manifest_present", func() CheckOutcome {
		return optionalManifestPresent(ctx, client, r, "system/handler/system/quorum", "quorum")
	})

	r.Run("handler_manifest_decode", func() CheckOutcome {
		if out, ok := r.Require("handler_manifest_present"); !ok {
			return out
		}
		ent := r.Load("manifest_entity").(entity.Entity)
		iface, err := types.HandlerInterfaceDataFromEntity(ent)
		if err != nil {
			return FailCheck("could not decode quorum handler manifest: " + err.Error())
		}
		r.Store("iface_data", iface)
		return PassCheck("quorum handler manifest decoded")
	})

	for _, op := range quorumOps {
		op := op
		r.Run("handler_op_"+op, func() CheckOutcome {
			if out, ok := r.Require("handler_manifest_decode"); !ok {
				return out
			}
			iface := r.Load("iface_data").(types.HandlerInterfaceData)
			if _, exists := iface.Operations[op]; !exists {
				return FailCheck("quorum handler missing operation: " + op)
			}
			return PassCheck("quorum handler has operation: " + op)
		})
	}

	for _, ty := range quorumTypes {
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

var quorumOps = []string{
	"create",
	"update",
	"publish",
	"verify",
}

var quorumTypes = []struct{ short, full string }{
	{"quorum", types.TypeQuorum},
	{"create_request", types.TypeQuorumCreateRequest},
	{"create_result", types.TypeQuorumCreateResult},
	{"update_request", types.TypeQuorumUpdateRequest},
	{"update_result", types.TypeQuorumUpdateResult},
	{"publish_request", types.TypeQuorumPublishRequest},
	{"publish_result", types.TypeQuorumPublishResult},
	{"verify_request", types.TypeQuorumVerifyRequest},
	{"verify_result", types.TypeQuorumVerifyResult},
}
