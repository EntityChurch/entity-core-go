package role

import (
	"context"
	"strings"

	"github.com/fxamacker/cbor/v2"

	"go.entitychurch.org/entity-core-go/core/capability"
	"go.entitychurch.org/entity-core-go/core/crypto"
	"go.entitychurch.org/entity-core-go/core/entity"
	"go.entitychurch.org/entity-core-go/core/handler"
	"go.entitychurch.org/entity-core-go/core/hash"
	"go.entitychurch.org/entity-core-go/core/types"
)

// Phase plan: phases 3–7 + 9 landed in v1.5. v1.6 (this revision):
// updated wire encoding (peer-id-as-hex throughout), drop redundant
// fields per SI-3 + SI-21, add linkage entity per SI-5, add
// skipped_grantees per SI-15. Phase 8 (`delegate`) is the open spec
// gap — deferred pending end-to-end IA22 lifecycle review.

// handleDefine implements §4.2 / IA11 — write or mutate a role
// definition through the handler. RL2 at definition-write time: the
// caller's capability MUST cover the proposed grant set. On mutation
// of an existing definition, triggers a re-derive cascade per §5.5.
//
// Note (v1.6 SI-10): direct tree:put to role-managed paths is legal
// per the capability system (no kernel rejection mechanism exists);
// the spec recommends NOT granting raw tree:put on these paths to
// untrusted entities, but the handler is the canonical entry point
// because RL2 + cascade only fire here.
func (h *Handler) handleDefine(ctx context.Context, req *handler.Request) (*handler.Response, error) {
	hctx := req.Context
	if hctx == nil || hctx.Store == nil || hctx.LocationIndex == nil {
		return handler.NewErrorResponse(500, "internal_error",
			"missing store or location index")
	}
	kp, localIdentity, errResp := h.authority()
	if errResp != nil {
		return errResp, nil
	}

	path := resourcePath(req)
	if path == "" {
		return handler.NewErrorResponse(400, "missing_resource_path",
			"system/role:define requires a resource target path (the role definition)")
	}
	defInfo, ok := ParseRoleDefinitionPath(barePath(path))
	if !ok {
		return handler.NewErrorResponse(400, "malformed_resource",
			"expected system/role/{context}/{role_name}")
	}

	body, err := types.RoleDefineRequestDataFromEntity(req.Params)
	if err != nil {
		return handler.NewErrorResponse(400, "invalid_request",
			"decode RoleDefineRequest: "+err.Error())
	}
	if len(body.Grants) == 0 {
		return handler.NewErrorResponse(400, "invalid_define_request",
			"grants is required (a role with no grants is meaningless)")
	}

	// RL2 at definition-write time: caller's capability must cover the
	// proposed grants. Templates aren't resolved at this point (the
	// assignee is unknown until assign), so we check against the
	// templated form. For deployments where the caller's cap itself is
	// templated, this is a strict check; for typical admin caps with
	// concrete paths, it's a reasonable approximation.
	if hctx.CallerCapability.ContentHash.IsZero() {
		return handler.NewErrorResponse(403, "caller_capability_missing",
			"system/role:define requires a caller capability at runtime (RL2)")
	}
	callerCapData, err := types.CapabilityTokenDataFromEntity(hctx.CallerCapability)
	if err != nil {
		return handler.NewErrorResponse(400, "invalid_caller_capability",
			"decode caller capability: "+err.Error())
	}
	// Define-time RL2: hypothetical reflects what the role-derived caps
	// would inherit on issue. The future minting happens at assign-time
	// under a potentially different parent + role.ttl; at define-time
	// only the caller bound is known, so MIN_DEFINED collapses to the
	// caller's expiration. (§5.3 v2.0 MIN_DEFINED with parent/ttl=nil.)
	hypotheticalExp := effectiveExpiresAt(nil, nil, callerCapData.ExpiresAt)
	hypothetical := types.CapabilityTokenData{
		Grants:    body.Grants,
		ExpiresAt: hypotheticalExp,
	}
	if !capability.IsAttenuated(hypothetical, callerCapData, resolveGranterOrLocal(hctx, callerCapData), resolveGranterOrLocal(hctx, callerCapData)) {
		return handler.NewErrorResponse(403, "definer_authority_insufficient",
			"caller capability does not cover proposed grants for "+
				defInfo.RoleName+" (RL2 at definition-write time)")
	}

	def := types.RoleData{
		Name:     defInfo.RoleName,
		Grants:   body.Grants,
		Metadata: body.Metadata,
	}
	defEnt, err := def.ToEntity()
	if err != nil {
		return handler.NewErrorResponse(500, "encode_failed", err.Error())
	}
	if _, err := hctx.Store.Put(defEnt); err != nil {
		return handler.NewErrorResponse(500, "store_put_failed", err.Error())
	}
	if _, err := hctx.TreeSet(path, defEnt.ContentHash, "define"); err != nil {
		return handler.NewErrorResponse(500, "storage_error", "bind role definition: "+err.Error())
	}

	count, _, _, _ := h.runReDeriveCascade(
		hctx, kp, localIdentity, defInfo.Context, defInfo.RoleName, body.Grants, body.Metadata, callerCapData,
	)

	return handler.NewResponse(200, types.TypeRoleDefineResult,
		types.RoleDefineResultData{
			RolePath:       path,
			ReDerivedCount: count,
		})
}

// handleAssign implements §4.3 — bind a peer to a role within a context
// and issue a role-derived capability token.
//
// v1.6 changes (SI-1 / SI-8): the assignee's identity hash is read
// directly from the path's hex segment — no PeerID-to-hash conversion,
// no type-index walk. Path-segment encoding IS the cap grantee form.
//
// Steps (mirroring the spec's pseudocode):
//
//  1. Read assignment path from EXECUTE.resource.targets[0] per V7 §3.2.
//  2. Parse path → (context, peer-hash, role-name).
//  3. Reject reserved role names.
//  4. Validate params.role; require it to match the path's role segment
//     (consistency check per §4.2 SI-25).
//  5. Resolve the role definition at system/role/{context}/{role}; 404
//     if missing.
//  6. Layer-2 exclusion check (§4.3 step 4b, R7 layer 2).
//  7. Resolve template variables in grants → derived_grants (§5.2).
//  8. RL2: caller capability must cover derived_grants (§4.3 step 5,
//     IsAttenuated). Fail-closed per IA10.
//  9. Persist the assignment entity at the path.
//  10. Issue + persist the role-derived cap at the R4 storage path AND
//     the linkage entity at the sibling derived-tokens/ subtree.
//  11. Return assign-result with the derived token hash.
func (h *Handler) handleAssign(ctx context.Context, req *handler.Request) (*handler.Response, error) {
	hctx := req.Context
	if hctx == nil || hctx.Store == nil || hctx.LocationIndex == nil {
		return handler.NewErrorResponse(500, "internal_error",
			"missing store or location index")
	}
	kp, localIdentity, errResp := h.authority()
	if errResp != nil {
		return errResp, nil
	}

	path := resourcePath(req)
	if path == "" {
		return handler.NewErrorResponse(400, "missing_resource_path",
			"system/role:assign requires a resource target path")
	}
	info, ok := ParseAssignmentPath(barePath(path))
	if !ok {
		return handler.NewErrorResponse(400, "malformed_resource",
			"expected system/role/{context}/assignment/{peer_id_hex}/{role_name}")
	}
	if info.Role == "" {
		return handler.NewErrorResponse(400, "malformed_resource",
			"assign requires a role-name segment in the resource path")
	}
	if IsReservedRoleName(info.Role) {
		return handler.NewErrorResponse(400, "invalid_role_name",
			"role name is reserved (R10): "+info.Role)
	}
	// SEC-18 / V7 v7.39 PR-3: reject zero-hash assignee at the role
	// layer. Zero-hash never resolves to a system/peer entity, so the
	// minted cap would fail chain-walk anyway (PR-3 unresolvable_grantee
	// at use time). Failing fast here surfaces the error to the assigner
	// instead of leaving a dud cap bound (PLAN-LIFECYCLE-INTEGRATION-
	// VALIDATION docket §4.1 option (a)).
	if info.PeerHash.IsZero() {
		return handler.NewErrorResponse(400, "invalid_assign_request",
			"assignee peer_id_hex MUST NOT be a zero hash (SEC-18)")
	}

	body, err := types.RoleAssignRequestDataFromEntity(req.Params)
	if err != nil {
		return handler.NewErrorResponse(400, "invalid_request",
			"decode RoleAssignRequest: "+err.Error())
	}
	if body.Role == "" {
		return handler.NewErrorResponse(400, "invalid_assign_request",
			"role is required")
	}
	if body.Role != info.Role {
		return handler.NewErrorResponse(400, "invalid_request",
			"params.role must match the role-name segment of the assignment path (role_path_mismatch)")
	}

	roleDefPath := RoleDefinitionPath(info.Context, body.Role)
	roleDef, ok := loadRoleDefinition(hctx.Store, hctx.LocationIndex, roleDefPath)
	if !ok {
		return handler.NewErrorResponse(404, "role_not_found",
			"no role definition at "+roleDefPath)
	}

	if isExcluded(hctx.LocationIndex, info.Context, info.PeerHash) {
		return handler.NewErrorResponse(403, "assignee_excluded",
			"cannot assign role to a peer in the context's exclusion subtree")
	}

	derivedGrants := resolveGrants(roleDef.Grants, info.Context, info.PeerHash)

	if hctx.CallerCapability.ContentHash.IsZero() {
		return handler.NewErrorResponse(403, "caller_capability_missing",
			"system/role:assign requires a caller capability at runtime (RL2)")
	}
	callerCapData, err := types.CapabilityTokenDataFromEntity(hctx.CallerCapability)
	if err != nil {
		return handler.NewErrorResponse(400, "invalid_caller_capability",
			"decode caller capability: "+err.Error())
	}
	// Per §5.3 v2.0: issued cap's expiration is MIN_DEFINED over the
	// parent (handler grant), the role's TTL metadata, and the caller's
	// capability. RL2 hypothetical MUST match what would be minted, so
	// the attenuation check accounts for the same expiration (V7 §5.6
	// strict nil-vs-finite).
	issuedExp := effectiveExpiresAt(parentCapExpires(hctx), roleMetadataTTL(roleDef.Metadata), callerCapData.ExpiresAt)
	hypothetical := types.CapabilityTokenData{
		Grants:    derivedGrants,
		ExpiresAt: issuedExp,
	}
	if !capability.IsAttenuated(hypothetical, callerCapData, resolveGranterOrLocal(hctx, callerCapData), resolveGranterOrLocal(hctx, callerCapData)) {
		return handler.NewErrorResponse(403, "assigner_authority_insufficient",
			"caller capability does not cover role-derived grants for "+body.Role+
				" (RL2: derived grants are not an attenuation of the caller's authority)")
	}

	assignment := types.RoleAssignmentData{
		Role:       body.Role,
		AssignedBy: hctx.AuthorHash,
		AssignedAt: nowMillis(),
	}
	asnEnt, err := assignment.ToEntity()
	if err != nil {
		return handler.NewErrorResponse(500, "encode_failed", err.Error())
	}
	if _, err := hctx.Store.Put(asnEnt); err != nil {
		return handler.NewErrorResponse(500, "store_put_failed", err.Error())
	}
	if _, err := hctx.TreeSet(path, asnEnt.ContentHash, "assign"); err != nil {
		return handler.NewErrorResponse(500, "storage_error", "bind role assignment: "+err.Error())
	}

	// Role v2.0 PR-1: role-derived caps are ROOT CAPS (parent: nil). The
	// runtime authority check is RL2 above (caller cap covers derived
	// grants); the issued cap is a fresh root rooted at the local peer.
	// Symmetrical with startup-time L0 path per EXTENSION-ROLE §4.5.
	// Spec: PROPOSAL-ROLE-V2.0-PRODUCTION-READINESS PR-1; v2.0 §5.1.
	cap, err := issueRoleDerivedCap(
		hctx, kp, localIdentity,
		info.Context, info.PeerHash,
		derivedGrants, hash.Hash{}, issuedExp,
	)
	if err != nil {
		return handler.NewErrorResponse(500, "cap_issuance_failed", err.Error())
	}
	if err := writeRoleDerivedTokenLink(hctx, info.Context, info.PeerHash, body.Role, cap.CapHash, nowMillis()); err != nil {
		return handler.NewErrorResponse(500, "linkage_write_failed", err.Error())
	}

	// SEC-2 race mitigation: re-check exclusion AFTER cap issuance. If
	// an :exclude completed concurrently with this :assign — completing
	// its layer-1 sweep BEFORE this cap was bound — the sweep would
	// miss the cap, leaving an excluded peer with a valid token. Re-
	// checking here closes the check-then-act window: any exclusion
	// that landed at any point during this op rolls back the writes.
	// Per §6.1 layer 2 ("block new derivation"), this MUST be atomic
	// from the caller's perspective.
	if isExcluded(hctx.LocationIndex, info.Context, info.PeerHash) {
		hctx.TreeRemove(cap.CapPath, "assign-rollback-on-exclusion")
		hctx.TreeRemove(cap.SigInvariantPath, "assign-rollback-on-exclusion")
		hctx.TreeRemove(DerivedTokenLinkPath(info.Context, info.PeerHash, body.Role), "assign-rollback-on-exclusion")
		hctx.TreeRemove(path, "assign-rollback-on-exclusion")
		return handler.NewErrorResponse(403, "assignee_excluded",
			"exclusion landed during :assign — rolled back (SEC-2 race mitigation; §6.1 layer 2)")
	}

	return handler.NewResponse(200, types.TypeRoleAssignResult,
		types.RoleAssignResultData{
			AssignmentPath: path,
			DerivedTokens:  []hash.Hash{cap.CapHash},
		})
}

// handleUnassign implements §4.4 + §6.4.1 (IA12). v1.6 uses the linkage
// entity (per SI-5) to locate role-derived caps precisely — no broad
// peer-prefix sweep when removing a single role.
//
// Steps:
//  1. Remove the assignment entity at assignment/{peer_id_hex}/{role_name}.
//     If the trailing role segment is omitted, remove all assignments
//     for the peer in that context (and all linkage entities, and all
//     role-derived caps for the peer in the context).
//  2. For specific-role unassign: read the linkage entity to find T_old;
//     remove cap binding + signature + linkage entity.
//  3. Revoked tokens are reported in the result.
func (h *Handler) handleUnassign(ctx context.Context, req *handler.Request) (*handler.Response, error) {
	hctx := req.Context
	if hctx == nil || hctx.Store == nil || hctx.LocationIndex == nil {
		return handler.NewErrorResponse(500, "internal_error",
			"missing store or location index")
	}
	path := resourcePath(req)
	if path == "" {
		return handler.NewErrorResponse(400, "missing_resource_path",
			"system/role:unassign requires a resource target path")
	}
	info, ok := ParseAssignmentPath(barePath(path))
	if !ok {
		return handler.NewErrorResponse(400, "malformed_resource",
			"expected system/role/{context}/assignment/{peer_id_hex}[/{role_name}]")
	}

	var revoked []hash.Hash
	if info.Role != "" {
		// Specific role: precise sweep via linkage entity.
		hctx.TreeRemove(path, "unassign")
		revoked = sweepRoleDerivedTokensForRole(hctx, info.Context, info.PeerHash, info.Role)
	} else {
		// All roles for peer in context.
		prefix := roleRoot + "/" + info.Context + "/" + assignmentSeg + "/" + HashHex(info.PeerHash) + "/"
		for _, e := range hctx.LocationIndex.List(prefix) {
			hctx.TreeRemove(e.Path, "unassign")
		}
		revoked = sweepRoleDerivedTokens(hctx, info.Context, info.PeerHash)
	}

	return handler.NewResponse(200, types.TypeRoleUnassignResult,
		types.RoleUnassignResultData{
			AssignmentPath:     path,
			RevokedTokenHashes: revoked,
		})
}

// handleExclude implements §6 + §6.1 layer-1 sweep (v1.6 with SI-3
// dropping the body peer_id field). Steps:
//
//  1. Persist the exclusion entity at the resource path.
//  2. Layer-1 sweep: delete all role-derived tokens for the peer in
//     the context (broad sweep per SI-7).
func (h *Handler) handleExclude(ctx context.Context, req *handler.Request) (*handler.Response, error) {
	hctx := req.Context
	if hctx == nil || hctx.Store == nil || hctx.LocationIndex == nil {
		return handler.NewErrorResponse(500, "internal_error",
			"missing store or location index")
	}
	path := resourcePath(req)
	if path == "" {
		return handler.NewErrorResponse(400, "missing_resource_path",
			"system/role:exclude requires a resource target path")
	}
	info, ok := ParseExclusionPath(barePath(path))
	if !ok {
		return handler.NewErrorResponse(400, "malformed_resource",
			"expected system/role/{context}/excluded/{peer_id_hex}")
	}

	excl := types.RoleExclusionData{
		ExcludedBy: hctx.AuthorHash,
		ExcludedAt: nowMillis(),
	}
	exclEnt, err := excl.ToEntity()
	if err != nil {
		return handler.NewErrorResponse(500, "encode_failed", err.Error())
	}
	if _, err := hctx.Store.Put(exclEnt); err != nil {
		return handler.NewErrorResponse(500, "store_put_failed", err.Error())
	}
	if _, err := hctx.TreeSet(path, exclEnt.ContentHash, "exclude"); err != nil {
		return handler.NewErrorResponse(500, "storage_error", "bind role exclusion: "+err.Error())
	}

	revoked := sweepRoleDerivedTokens(hctx, info.Context, info.PeerHash)

	return handler.NewResponse(200, types.TypeRoleExcludeResult,
		types.RoleExcludeResultData{
			ExclusionPath:      path,
			RevokedTokenHashes: revoked,
		})
}

// handleUnexclude removes an exclusion entity at the resource path.
// Removing the exclusion does NOT auto-restore role-derived tokens —
// those were deleted by the layer-1 sweep at exclude time and cannot be
// resurrected. Re-assignment via system/role:assign is required (§6.4).
func (h *Handler) handleUnexclude(ctx context.Context, req *handler.Request) (*handler.Response, error) {
	hctx := req.Context
	if hctx == nil || hctx.Store == nil || hctx.LocationIndex == nil {
		return handler.NewErrorResponse(500, "internal_error",
			"missing store or location index")
	}
	path := resourcePath(req)
	if path == "" {
		return handler.NewErrorResponse(400, "missing_resource_path",
			"system/role:unexclude requires a resource target path")
	}
	if _, ok := ParseExclusionPath(barePath(path)); !ok {
		return handler.NewErrorResponse(400, "malformed_resource",
			"expected system/role/{context}/excluded/{peer_id_hex}")
	}
	hctx.TreeRemove(path, "unexclude")
	return handler.NewResponse(200, types.TypeRoleUnexcludeResult,
		types.RoleUnexcludeResultData{ExclusionPath: path})
}

// handleReDerive implements the re-derive cascade per §5.5 IA9 (v1.6).
// Walks every assignment of the named role in the named context, issues
// a fresh role-derived cap for each assignee (T_new) BEFORE revoking the
// existing cap (T_old) — issue-first ordering is load-bearing for safety.
//
// v1.6 SI-15: assignees that fail RL2 mid-cascade are reported in
// SkippedGrantees (the result schema's new field) rather than aborting.
// Skip-and-continue prevents earlier ordered-write pairs from being
// half-applied.
func (h *Handler) handleReDerive(ctx context.Context, req *handler.Request) (*handler.Response, error) {
	hctx := req.Context
	if hctx == nil || hctx.Store == nil || hctx.LocationIndex == nil {
		return handler.NewErrorResponse(500, "internal_error",
			"missing store or location index")
	}
	kp, localIdentity, errResp := h.authority()
	if errResp != nil {
		return errResp, nil
	}

	path := resourcePath(req)
	if path == "" {
		return handler.NewErrorResponse(400, "missing_resource_path",
			"system/role:re-derive requires a resource target path (the role definition)")
	}
	defInfo, ok := ParseRoleDefinitionPath(barePath(path))
	if !ok {
		return handler.NewErrorResponse(400, "malformed_resource",
			"expected system/role/{context}/{role_name}")
	}
	body, err := types.RoleReDeriveRequestDataFromEntity(req.Params)
	if err != nil {
		return handler.NewErrorResponse(400, "invalid_request",
			"decode RoleReDeriveRequest: "+err.Error())
	}
	if body.Role == "" {
		return handler.NewErrorResponse(400, "invalid_redrive_request",
			"role is required")
	}
	if body.Role != defInfo.RoleName {
		return handler.NewErrorResponse(400, "invalid_request",
			"params.role must match the role-name segment of the resource path (role_path_mismatch)")
	}

	roleDefPath := RoleDefinitionPath(defInfo.Context, body.Role)
	roleDef, ok := loadRoleDefinition(hctx.Store, hctx.LocationIndex, roleDefPath)
	if !ok {
		return handler.NewErrorResponse(404, "role_not_found",
			"no role definition at "+roleDefPath)
	}
	if hctx.CallerCapability.ContentHash.IsZero() {
		return handler.NewErrorResponse(403, "caller_capability_missing",
			"system/role:re-derive requires a caller capability at runtime (RL2)")
	}
	callerCapData, err := types.CapabilityTokenDataFromEntity(hctx.CallerCapability)
	if err != nil {
		return handler.NewErrorResponse(400, "invalid_caller_capability",
			"decode caller capability: "+err.Error())
	}

	count, newHashes, revokedHashes, skipped := h.runReDeriveCascade(
		hctx, kp, localIdentity, defInfo.Context, body.Role, roleDef.Grants, roleDef.Metadata, callerCapData,
	)

	return handler.NewResponse(200, types.TypeRoleReDeriveResult,
		types.RoleReDeriveResultData{
			ReDerivedCount:     count,
			RevokedTokenHashes: revokedHashes,
			NewTokenHashes:     newHashes,
			SkippedGrantees:    skipped,
		})
}

// runReDeriveCascade is the shared re-derive cascade walker called by
// both handleReDerive and handleDefine. Per §5.5 IA9: walks every
// assignment of (context, role), issues T_new BEFORE revoking T_old per
// assignee (issue-first), skips excluded peers, applies RL2 against the
// caller's capability per assignee.
//
// Returns the count of re-derived assignees, new cap hashes, revoked
// cap hashes, and the list of grantees skipped due to RL2 failure
// mid-cascade (per v1.6 SI-15 — they retain T_old).
func (h *Handler) runReDeriveCascade(
	hctx *handler.HandlerContext,
	kp crypto.Keypair,
	localIdentity entity.Entity,
	contextStr string,
	roleName string,
	grants []types.GrantEntry,
	metadata cbor.RawMessage,
	callerCapData types.CapabilityTokenData,
) (uint64, []hash.Hash, []hash.Hash, []hash.Hash) {
	asnPrefix := roleRoot + "/" + contextStr + "/" + assignmentSeg + "/"
	entries := hctx.LocationIndex.List(asnPrefix)
	// Role v2.0 PR-1: role-derived caps are ROOT CAPS (parent: nil).
	// parentExp from handler grant is still consulted for the §5.3
	// MIN_DEFINED expires_at bound (the handler's policy contributes
	// the lifetime ceiling), but the issued cap itself is rooted.
	parentExp := parentCapExpires(hctx)
	roleTTL := roleMetadataTTL(metadata)

	var newHashes []hash.Hash
	var revokedHashes []hash.Hash
	var skipped []hash.Hash
	var count uint64

	for _, e := range entries {
		bare := barePath(e.Path)
		info, ok := ParseAssignmentPath(bare)
		if !ok || info.Role != roleName {
			continue
		}
		if isExcluded(hctx.LocationIndex, info.Context, info.PeerHash) {
			continue
		}
		derived := resolveGrants(grants, info.Context, info.PeerHash)
		// Per §5.3 v2.0: MIN_DEFINED(parent, role.ttl, caller). RL2
		// hypothetical MUST match what would be minted (otherwise V7
		// §5.6 attenuation rejects the cap on chain validation later,
		// even though RL2 grant-coverage passes — "RL2 OK at issue,
		// chain-invalid at use" surface).
		issuedExp := effectiveExpiresAt(parentExp, roleTTL, callerCapData.ExpiresAt)
		hypothetical := types.CapabilityTokenData{
			Grants:    derived,
			ExpiresAt: issuedExp,
		}
		if !capability.IsAttenuated(hypothetical, callerCapData, resolveGranterOrLocal(hctx, callerCapData), resolveGranterOrLocal(hctx, callerCapData)) {
			// SI-15: skip-and-continue, report the grantee.
			skipped = append(skipped, info.PeerHash)
			continue
		}
		// Role v2.0 PR-1: root cap (parent: nil).
		newCap, err := issueRoleDerivedCap(
			hctx, kp, localIdentity,
			info.Context, info.PeerHash,
			derived, hash.Hash{}, issuedExp,
		)
		if err != nil {
			continue
		}
		if err := writeRoleDerivedTokenLink(hctx, info.Context, info.PeerHash, info.Role, newCap.CapHash, nowMillis()); err != nil {
			continue
		}
		// SEC-2 race mitigation (re-derive variant): if an :exclude
		// landed during this assignee's leg of the cascade, the late-
		// arriving exclusion's sweep would miss the freshly-issued
		// newCap. Re-check exclusion post-issue and roll back this
		// assignee's writes if so.
		if isExcluded(hctx.LocationIndex, info.Context, info.PeerHash) {
			hctx.TreeRemove(newCap.CapPath, "re-derive-rollback-on-exclusion")
			hctx.TreeRemove(newCap.SigInvariantPath, "re-derive-rollback-on-exclusion")
			hctx.TreeRemove(DerivedTokenLinkPath(info.Context, info.PeerHash, info.Role), "re-derive-rollback-on-exclusion")
			continue
		}
		newHashes = append(newHashes, newCap.CapHash)
		revoked := sweepRoleDerivedTokensExcluding(hctx, info.Context, info.PeerHash, newCap.CapHash)
		revokedHashes = append(revokedHashes, revoked...)
		count++
	}
	return count, newHashes, revokedHashes, skipped
}

// handleDelegate implements §5.6 IA22 — member-to-member delegation.
// Caller B delegates a role they hold (or a literal subset via `scope`)
// to peer C. The issued delegation cap is rooted at B's runtime peer
// and stored at the role-derived path so role's lifecycle machinery
// (exclusion sweep, chain validation) reaches it.
//
// Flow:
//  0. SI-19 locality: caller MUST equal local peer (400 delegator_must_be_local_peer).
//  1. Decode params; validate non-empty context/role/scope.
//  2. R10 reserved name check.
//  3. SI-20 literal scope check (no template variables → 400 scope_must_be_literal).
//  4. Selector-vs-path consistency: if a resource path is supplied,
//     it MUST be the delegator's assignment path with matching
//     context/role (else 400 invalid_request role_path_mismatch).
//  5. Verify delegator (author) holds the role (assignment entity bound).
//  6. Layer-2 exclusion of delegate target C.
//  7. Load role definition; resolve role grants for B → delegator authority.
//  8. RL2 attenuation: scope MUST be subset of delegator's authority.
//  9. SI-22 parent selection: B's linkage entity → parent cap hash.
//  10. Compute issued expiration: MIN_DEFINED(parent, role.ttl, params.expires_at).
//  11. Issue cap (granter=B's runtime peer = local; grantee=C; parent=
//     selected role-derived cap). NO linkage entity (delegation caps
//     don't participate in unassign-by-linkage).
func (h *Handler) handleDelegate(ctx context.Context, req *handler.Request) (*handler.Response, error) {
	hctx := req.Context
	if hctx == nil || hctx.Store == nil || hctx.LocationIndex == nil {
		return handler.NewErrorResponse(500, "internal_error",
			"missing store or location index")
	}
	kp, localIdentity, errResp := h.authority()
	if errResp != nil {
		return errResp, nil
	}

	// SI-19 locality invariant.
	if hctx.Author != hctx.LocalPeerID {
		return handler.NewErrorResponse(400, "delegator_must_be_local_peer",
			"system/role:delegate must run on the delegator's own runtime peer (SI-19)")
	}

	body, err := types.RoleDelegateRequestDataFromEntity(req.Params)
	if err != nil {
		return handler.NewErrorResponse(400, "invalid_request",
			"decode RoleDelegateRequest: "+err.Error())
	}
	if body.Context == "" {
		return handler.NewErrorResponse(400, "invalid_delegate_request",
			"context is required")
	}
	if body.Role == "" {
		return handler.NewErrorResponse(400, "invalid_delegate_request",
			"role is required")
	}
	if IsReservedRoleName(body.Role) {
		return handler.NewErrorResponse(400, "invalid_role_name",
			"role name is reserved (R10): "+body.Role)
	}
	if len(body.Scope) == 0 {
		return handler.NewErrorResponse(400, "invalid_delegate_request",
			"scope is required (a delegation with no grants is meaningless)")
	}
	if scopeContainsTemplates(body.Scope) {
		return handler.NewErrorResponse(400, "scope_must_be_literal",
			"system/role:delegate scope MUST NOT contain template variables (SI-20)")
	}

	// Selector-vs-path consistency. The resource path is OPTIONAL for
	// delegate; when present it MUST be the delegator's assignment path
	// with matching context/role/peer (per §4.2 alternative form).
	if path := resourcePath(req); path != "" {
		if info, ok := ParseAssignmentPath(barePath(path)); ok {
			if info.Context != body.Context || info.Role != body.Role {
				return handler.NewErrorResponse(400, "invalid_request",
					"params.context/role must match the resource path (role_path_mismatch)")
			}
			if info.PeerHash != hctx.AuthorHash {
				return handler.NewErrorResponse(400, "invalid_request",
					"resource path peer-id must match caller (delegator) hash")
			}
		}
		// If the path doesn't parse as an assignment path, accept it
		// silently — implementations MAY accept the role-derived target
		// path; we don't synthesize one but we also don't reject the
		// passthrough form.
	}

	// Delegator (B) must hold the role.
	delegatorAssignmentPath := AssignmentPath(body.Context, hctx.AuthorHash, body.Role)
	if !hctx.LocationIndex.Has(delegatorAssignmentPath) {
		return handler.NewErrorResponse(403, "delegator_role_not_held",
			"caller does not hold role "+body.Role+" in context "+body.Context)
	}

	// Layer-2 exclusion of the delegate target C.
	if isExcluded(hctx.LocationIndex, body.Context, body.Delegate) {
		return handler.NewErrorResponse(403, "delegate_excluded",
			"cannot delegate to a peer in the context's exclusion subtree")
	}

	// Load the role definition to bound delegator's authority.
	roleDefPath := RoleDefinitionPath(body.Context, body.Role)
	roleDef, ok := loadRoleDefinition(hctx.Store, hctx.LocationIndex, roleDefPath)
	if !ok {
		return handler.NewErrorResponse(404, "role_not_found",
			"no role definition at "+roleDefPath)
	}

	// RL2 (§5.6): scope MUST be an attenuation of role's grants as held
	// by B. Resolve role-def grants for B's identity (templates),
	// wrap as synthetic CapabilityTokenData, then IsAttenuated.
	delegatorGrants := resolveGrants(roleDef.Grants, body.Context, hctx.AuthorHash)
	delegatorAuth := types.CapabilityTokenData{Grants: delegatorGrants}
	scopeAsCap := types.CapabilityTokenData{Grants: body.Scope}
	if !capability.IsAttenuated(scopeAsCap, delegatorAuth, resolveGranterOrLocal(hctx, delegatorAuth), resolveGranterOrLocal(hctx, delegatorAuth)) {
		return handler.NewErrorResponse(403, "delegator_authority_insufficient",
			"scope is not an attenuation of the delegator's role grants (RL2)")
	}

	// SI-22 parent selection: B's linkage entity → parent cap hash.
	link, ok := loadDerivedTokenLink(hctx.Store, hctx.LocationIndex, body.Context, hctx.AuthorHash, body.Role)
	if !ok {
		return handler.NewErrorResponse(500, "internal_error",
			"delegator's role linkage entity missing — assignment exists but linkage is not bound (data integrity issue)")
	}
	parentHash := link.TokenHash

	// Read parent cap to extract its expires_at for the MIN_DEFINED bound.
	parentEnt, ok := hctx.Store.Get(parentHash)
	if !ok {
		return handler.NewErrorResponse(500, "internal_error",
			"delegator's parent cap entity not in store")
	}
	parentData, err := types.CapabilityTokenDataFromEntity(parentEnt)
	if err != nil {
		return handler.NewErrorResponse(500, "internal_error",
			"decode parent cap: "+err.Error())
	}

	// Issued expiration: MIN_DEFINED(parent.expires_at, role.ttl, request.expires_at).
	// The "caller" source in §5.3 v2.0 is the request's expires_at —
	// the delegator's request explicitly sets the bound; the role-
	// derived parent cap supplies the implicit upper bound.
	issuedExp := effectiveExpiresAt(parentData.ExpiresAt, roleMetadataTTL(roleDef.Metadata), body.ExpiresAt)

	// Issue the delegation cap. NO linkage entity write (delegation
	// caps don't participate in unassign-by-linkage; the (C, role)
	// linkage slot belongs to C's own assignment if any).
	cap, err := issueRoleDerivedCap(
		hctx, kp, localIdentity,
		body.Context, body.Delegate,
		body.Scope, parentHash, issuedExp,
	)
	if err != nil {
		return handler.NewErrorResponse(500, "cap_issuance_failed", err.Error())
	}

	// SEC-2 race mitigation (delegate variant): if an :exclude on the
	// delegate target C landed during this op — between the layer-2
	// pre-check and the cap TreeSet — the late exclusion's sweep
	// missed the freshly-issued cap. Re-check post-issue and roll
	// back if so. Per §6.1 layer 2, exclusion MUST block all new
	// derivation paths atomically.
	if isExcluded(hctx.LocationIndex, body.Context, body.Delegate) {
		hctx.TreeRemove(cap.CapPath, "delegate-rollback-on-exclusion")
		hctx.TreeRemove(cap.SigInvariantPath, "delegate-rollback-on-exclusion")
		return handler.NewErrorResponse(403, "delegate_excluded",
			"exclusion landed during :delegate — rolled back (SEC-2 race mitigation; §6.1 layer 2)")
	}

	return handler.NewResponse(200, types.TypeRoleDelegateResult,
		types.RoleDelegateResultData{
			DelegationTokenHash: cap.CapHash,
		})
}

// scopeContainsTemplates reports whether any grant entry in `scope`
// includes a template variable (per §5.6 / SI-20: scope MUST be literal).
// Used by handleDelegate when phase 8 lands.
func scopeContainsTemplates(scope []types.GrantEntry) bool {
	for _, g := range scope {
		for _, p := range g.Resources.Include {
			if strings.Contains(p, "{") {
				return true
			}
		}
		for _, p := range g.Resources.Exclude {
			if strings.Contains(p, "{") {
				return true
			}
		}
		for _, p := range g.Handlers.Include {
			if strings.Contains(p, "{") {
				return true
			}
		}
		for _, p := range g.Handlers.Exclude {
			if strings.Contains(p, "{") {
				return true
			}
		}
	}
	return false
}
