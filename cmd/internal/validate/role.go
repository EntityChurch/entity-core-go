package validate

import (
	"context"

	"go.entitychurch.org/entity-core-go/core/entity"
	"go.entitychurch.org/entity-core-go/core/types"
)

// catRole is the validate-peer category for the EXTENSION-ROLE surface
// (v1.6 — landing per PROPOSAL-ROLE-V1.5-SPEC-FIXES). Verifies the
// handler manifest, operations, and entity types are present on a
// running peer. Behavioral conformance (assign + RL2 + derivation,
// exclusion sweep, re-derive cascade, IA8 reactive sweep) will land in
// the behavioral_v33 cross-impl harness as Python and Rust catch up.
//
// V0 scope: structural conformance only — manifest is fetchable, all
// seven ops are advertised, all 14 types are registered. Behavioral
// validation goes through ext/role/ in-process tests for now.
const catRole = "role"

func runRole(ctx context.Context, client *PeerClient) []CheckResult {
	r := NewCheckRunner(catRole)

	r.Declare("handler_manifest_present", "ROLE §4.1")
	r.Declare("handler_manifest_decode", "ROLE §4.1")
	for _, op := range roleOps {
		r.Declare("handler_op_"+op, "ROLE §4.1")
	}
	for _, ty := range roleTypes {
		r.Declare("type_"+ty.short, "ROLE §2 / §4.2")
	}

	// --- Manifest ---

	r.Run("handler_manifest_present", func() CheckOutcome {
		return optionalManifestPresent(ctx, client, r, "system/handler/system/role", "role")
	})

	r.Run("handler_manifest_decode", func() CheckOutcome {
		if out, ok := r.Require("handler_manifest_present"); !ok {
			return out
		}
		ent := r.Load("manifest_entity").(entity.Entity)
		iface, err := types.HandlerInterfaceDataFromEntity(ent)
		if err != nil {
			return FailCheck("could not decode role handler manifest: " + err.Error())
		}
		r.Store("iface_data", iface)
		return PassCheck("role handler manifest decoded")
	})

	for _, op := range roleOps {
		op := op
		r.Run("handler_op_"+op, func() CheckOutcome {
			if out, ok := r.Require("handler_manifest_decode"); !ok {
				return out
			}
			iface := r.Load("iface_data").(types.HandlerInterfaceData)
			if _, exists := iface.Operations[op]; !exists {
				return FailCheck("role handler missing operation: " + op)
			}
			return PassCheck("role handler has operation: " + op)
		})
	}

	// --- Type registration ---

	for _, ty := range roleTypes {
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

// roleOps lists the §4.1 seven handler operations defined by
// EXTENSION-ROLE v1.5.
var roleOps = []string{
	"define",
	"assign",
	"unassign",
	"exclude",
	"unexclude",
	"re-derive",
	"delegate",
}

// roleTypes lists the §2 four entity types plus the eleven handler
// request/result types defined by EXTENSION-ROLE v1.6 (added
// system/role/derived-token-link per SI-5).
var roleTypes = []struct{ short, full string }{
	{"role", types.TypeRole},
	{"role_assignment", types.TypeRoleAssignment},
	{"role_exclusion", types.TypeRoleExclusion},
	{"derived_token_link", types.TypeRoleDerivedTokenLink},
	{"initial_grant_policy", types.TypeRoleInitialGrantPolicy},
	{"define_request", types.TypeRoleDefineRequest},
	{"define_result", types.TypeRoleDefineResult},
	{"assign_request", types.TypeRoleAssignRequest},
	{"assign_result", types.TypeRoleAssignResult},
	{"unassign_result", types.TypeRoleUnassignResult},
	{"exclude_result", types.TypeRoleExcludeResult},
	{"unexclude_result", types.TypeRoleUnexcludeResult},
	{"re-derive_request", types.TypeRoleReDeriveRequest},
	{"re-derive_result", types.TypeRoleReDeriveResult},
	{"delegate_request", types.TypeRoleDelegateRequest},
	{"delegate_result", types.TypeRoleDelegateResult},
}
