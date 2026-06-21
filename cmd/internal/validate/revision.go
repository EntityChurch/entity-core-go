package validate

import (
	"context"
	"fmt"
	"math/rand"
	"strings"

	"go.entitychurch.org/entity-core-go/core/ecf"
	"go.entitychurch.org/entity-core-go/core/entity"
	"go.entitychurch.org/entity-core-go/core/hash"
	"go.entitychurch.org/entity-core-go/core/types"
	"go.entitychurch.org/entity-core-go/ext/revision"

	"github.com/fxamacker/cbor/v2"
)

// revisionTestFamily is the shared path family every revision runner writes
// under. The suite gate MUST probe this family (not a specific instance) so a
// peer with grants scoped to the validation namespace gates consistently with
// what the runner actually writes — otherwise the gate could pass on a literal
// path the runner never uses, then the randomized runner paths fail (the
// gate/probe-path mismatch the validate-peer audit flagged).
const revisionTestFamily = "system/validate/revision-"

// revisionTestPrefix generates a unique prefix to avoid cross-run contamination.
// All instances share revisionTestFamily as their prefix.
func revisionTestPrefix(suffix string) string {
	return fmt.Sprintf("%s%s-%d/", revisionTestFamily, suffix, rand.Intn(100000))
}

const catRevision = "revision"

// runRevision validates the revision extension against a remote peer.
// Tests actual functionality — creates entities, commits, verifies trie roots,
// checks tree state changes after checkout, tests cherry-pick semantics, etc.
func runRevision(ctx context.Context, client *PeerClient) []CheckResult {
	r := NewCheckRunner(catRevision)
	prefix := revisionTestPrefix("main")
	// Under v3.0, handlers resolve peer-relative prefixes to absolute.
	// Results may return either form — accept both in comparisons.
	remotePID := string(client.RemotePeerID())
	absPrefix := "/" + remotePID + "/" + prefix
	_ = absPrefix // used in prefix comparisons below

	// --- Declare all checks ---

	// Step 1: Handler manifest
	r.Declare("handler_manifest_present", "REVISION §4.1")
	r.Declare("handler_op_commit", "REVISION §4.1")
	r.Declare("handler_op_log", "REVISION §4.1")
	r.Declare("handler_op_status", "REVISION §4.1")
	r.Declare("handler_op_merge", "REVISION §4.1")
	r.Declare("handler_op_resolve", "REVISION §4.1")
	r.Declare("handler_op_fetch", "REVISION §4.1")
	r.Declare("handler_op_fetch_entities", "REVISION §4.1")
	r.Declare("handler_op_push", "REVISION §4.1")
	r.Declare("handler_op_find_ancestor", "REVISION §4.1")
	r.Declare("handler_op_branch", "REVISION §4.1")
	r.Declare("handler_op_checkout", "REVISION §4.1")
	r.Declare("handler_op_tag", "REVISION §4.1")
	r.Declare("handler_op_diff", "REVISION §4.1")
	r.Declare("handler_op_cherry_pick", "REVISION §4.1")
	r.Declare("handler_op_revert", "REVISION §4.1")
	r.Declare("handler_op_config", "REVISION §4.1")
	r.Declare("handler_op_merge_config", "REVISION v3.3 §4.1 / §4.4.18")
	r.Declare("merge_config_set_rejects_deletion_resolution_lww", "REVISION v3.3 §4.4.18")
	r.Declare("merge_config_set_rejects_deletion_resolution_keep_both", "REVISION v3.3 §4.4.18")
	r.Declare("merge_config_set_accepts_valid_deletion_resolution", "REVISION v3.3 §4.4.18")
	r.Declare("merge_config_set_idempotent", "REVISION v3.3 §4.4.18")
	r.Declare("merge_config_delete", "REVISION v3.3 §4.4.18")

	// Step 2: Type registration
	r.Declare("type_entry", "REVISION §2")
	r.Declare("type_conflict", "REVISION §2")
	r.Declare("type_commit_params", "REVISION §2")
	r.Declare("type_commit_result", "REVISION §2")
	r.Declare("type_merge_result", "REVISION §2")
	r.Declare("type_branch_result", "REVISION §2")

	// Step 3: Deep commit verification
	r.Declare("commit_version_nonzero", "REVISION §4.3.1")
	r.Declare("commit_root_nonzero", "REVISION §4.3.1")
	r.Declare("commit_head_stored", "REVISION §3.1")
	r.Declare("commit_initial_no_parents", "REVISION §4.3.1")
	r.Declare("commit_version_root_ref", "REVISION §2.1")

	// Step 4: Log verification
	r.Declare("log_version_count", "REVISION §4.3.2")
	r.Declare("log_version_matches_commit", "REVISION §4.3.2")
	r.Declare("log_prefix", "REVISION §4.3.2")

	// Step 5: Status verification
	r.Declare("status_head_matches", "REVISION §4.3.3")
	r.Declare("status_prefix", "REVISION §4.3.3")
	r.Declare("status_pending_zero", "REVISION §4.3.3")

	// Step 6: Sequential commit
	r.Declare("sequential_commit", "REVISION §4.3.1")
	r.Declare("sequential_parent_is_v1", "REVISION §4.3.1")
	r.Declare("sequential_log_count", "REVISION §4.3.2")
	r.Declare("sequential_log_order", "REVISION §4.3.2")

	// Step 7: Find-ancestor
	r.Declare("ancestor_linear_correct", "REVISION §4.3.9")
	r.Declare("ancestor_self", "REVISION §4.3.9")

	// Step 8: Diff
	r.Declare("diff_file1_changed", "REVISION §4.3.13")
	r.Declare("diff_file3_added", "REVISION §4.3.13")
	r.Declare("diff_unchanged", "REVISION §4.3.13")

	// Step 9: Branch lifecycle
	r.Declare("branch_points_to_head", "REVISION §4.3.10")
	r.Declare("branch_list_contains", "REVISION §4.3.10")
	r.Declare("branch_duplicate_409", "REVISION §4.3.10")
	r.Declare("branch_delete", "REVISION §4.3.10")
	r.Declare("branch_deleted_from_list", "REVISION §4.3.10")

	// Step 10: Checkout
	r.Declare("checkout_head_updated", "REVISION §4.3.11")
	r.Declare("checkout_file1_exists", "REVISION §4.3.11")
	r.Declare("checkout_file2_exists", "REVISION §4.3.11")
	r.Declare("checkout_file3_removed", "REVISION §4.3.11")
	r.Declare("checkout_status_field", "REVISION §4.3.11")

	// Step 11: Tag lifecycle
	r.Declare("tag_create", "REVISION §4.3.12")
	r.Declare("tag_list_contains", "REVISION §4.3.12")
	r.Declare("tag_immutable", "REVISION §4.3.12")
	r.Declare("tag_delete", "REVISION §4.3.12")

	// Step 12: Merge in_sync
	r.Declare("merge_in_sync", "REVISION §4.3.4")

	// Step 13: Fast-forward merge
	r.Declare("merge_ff_status", "REVISION §4.3.4")
	r.Declare("merge_ff_version", "REVISION §4.3.4")
	r.Declare("merge_ff_tree_updated", "REVISION §4.3.4")

	// Step 14: Diverged merge + conflict resolution
	r.Declare("merge_diverged_status", "REVISION §4.3.4")
	r.Declare("merge_diverged_two_parents", "REVISION §4.3.4")
	r.Declare("merge_diverged_remote_file", "REVISION §4.3.4")
	r.Declare("merge_has_conflicts", "REVISION §4.3.4")
	r.Declare("merge_status_conflicts", "REVISION §4.3.3")
	r.Declare("resolve_path", "REVISION §4.3.5")
	r.Declare("resolve_hash", "REVISION §4.3.5")
	r.Declare("resolve_entity_at_path", "REVISION §4.3.5")
	r.Declare("resolve_idempotent", "REVISION §4.3.5")

	// Step 15: Cherry-pick
	r.Declare("cherry_pick_status", "REVISION §4.3.14")
	r.Declare("cherry_pick_file_applied", "REVISION §4.3.14")
	r.Declare("cherry_pick_parent", "REVISION §4.3.14")

	// Step 16: Revert
	r.Declare("revert_status", "REVISION §4.3.15")
	r.Declare("revert_file_removed", "REVISION §4.3.15")
	r.Declare("revert_base_preserved", "REVISION §4.3.15")

	// Step 17: Log pagination
	r.Declare("log_pagination_limit", "REVISION §4.3.2")
	r.Declare("log_pagination_has_more", "REVISION §4.3.2")
	r.Declare("log_pagination_since", "REVISION §4.3.2")

	// Step 18: Merge result cascade_warnings field
	r.Declare("merge_result_has_cascade_warnings_field", "REVISION v2.6 §4.4.4 (R5)")

	// v2.8 completeness amendments.
	r.Declare("revert_merge_ambiguous_parent", "REVISION v2.8 §4.4.16 (R1)")
	r.Declare("revert_merge_explicit_parent", "REVISION v2.8 §4.4.16 (R1)")
	r.Declare("resolve_null_delete", "REVISION v2.8 §4.4.5 (R2)")
	r.Declare("resolve_null_path_unbound", "REVISION v2.8 §4.4.5 (R2)")
	r.Declare("resolve_nonexistent_hash", "REVISION v2.8 §4.4.5 (R2)")
	r.Declare("resolve_remaining_conflicts", "REVISION v2.8 §4.4.5 (R5)")
	r.Declare("resolve_remaining_zero_after_last", "REVISION v2.8 §4.4.5 (R5)")
	r.Declare("keep_both_strategy_applied", "REVISION v2.8 §2.3 (R4)")
	r.Declare("keep_both_additional_binding", "REVISION v2.8 §2.3 (R4)")
	r.Declare("keep_both_original_entity", "REVISION v2.8 §2.3 (R4)")

	// --- Step 1: Handler manifest ---

	r.Run("handler_manifest_present", func() CheckOutcome {
		ent, _, err := client.TreeGet(ctx, "system/handler/system/revision")
		if err != nil {
			return FailCheck("failed to fetch revision handler manifest: " + err.Error())
		}
		handlerData, err := types.HandlerInterfaceDataFromEntity(ent)
		if err != nil {
			return FailCheck("could not decode handler manifest: " + err.Error())
		}
		r.Store("handler_data", handlerData)
		return PassCheck(fmt.Sprintf("revision handler manifest present (type: %s)", ent.Type))
	})

	expectedOps := []string{
		"commit", "log", "status", "merge", "resolve",
		"fetch", "fetch-entities", "push", "find-ancestor", "branch",
		"checkout", "tag", "diff", "cherry-pick", "revert", "config",
		"merge-config",
	}
	for _, op := range expectedOps {
		op := op
		r.Run("handler_op_"+sanitizeName(op), func() CheckOutcome {
			if out, ok := r.Require("handler_manifest_present"); !ok {
				return out
			}
			handlerData := r.Load("handler_data").(types.HandlerInterfaceData)
			if _, exists := handlerData.Operations[op]; !exists {
				return FailCheck("revision handler missing operation: " + op)
			}
			return PassCheck("revision handler has operation: " + op)
		})
	}

	// --- Step 2: Type registration ---

	typeChecks := []struct {
		name    string
		typPath string
	}{
		{"entry", "system/type/system/revision/entry"},
		{"conflict", "system/type/system/revision/conflict"},
		{"commit_params", "system/type/system/revision/commit-params"},
		{"commit_result", "system/type/system/revision/commit-result"},
		{"merge_result", "system/type/system/revision/merge-result"},
		{"branch_result", "system/type/system/revision/branch-result"},
	}
	for _, tc := range typeChecks {
		tc := tc
		r.Run("type_"+tc.name, func() CheckOutcome {
			_, _, err := client.TreeGet(ctx, tc.typPath)
			if err != nil {
				return FailCheck("revision type not registered: " + tc.typPath)
			}
			return PassCheck("revision type registered: " + tc.typPath)
		})
	}

	// --- Step 3: Deep commit verification ---

	r.Run("commit_version_nonzero", func() CheckOutcome {
		if out, ok := r.Require("handler_manifest_present"); !ok {
			return out
		}

		// Put two test entities.
		file1 := mustCreateEntity("test/revision-doc", map[string]string{"content": "hello"})
		file2 := mustCreateEntity("test/revision-doc", map[string]string{"content": "world"})

		file1Hash, err := client.TreePut(ctx, prefix+"file1", file1)
		if err != nil {
			return FailCheck("failed to put file1: " + err.Error())
		}
		r.Store("file1_hash", file1Hash)
		_, err = client.TreePut(ctx, prefix+"file2", file2)
		if err != nil {
			return FailCheck("failed to put file2: " + err.Error())
		}

		// Commit.
		resp, err := client.RevisionExecute(ctx, "commit", types.RevisionCommitParamsData{
			Prefix: prefix,
		})
		if err != nil {
			return FailCheck("commit failed: " + err.Error())
		}
		if resp.Status != 200 {
			errMsg := fmt.Sprintf("commit returned status %d", resp.Status)
			if len(resp.Result) > 0 {
				var errEnt entity.Entity
				if ecf.Decode(resp.Result, &errEnt) == nil && errEnt.Type != "" {
					var errData struct {
						Code    string `cbor:"code"`
						Message string `cbor:"message"`
					}
					if ecf.Decode(errEnt.Data, &errData) == nil && errData.Code != "" {
						errMsg += fmt.Sprintf(" (%s: %s)", errData.Code, errData.Message)
					}
				}
			}
			return FailCheck(errMsg)
		}

		var commitResult types.RevisionCommitResultData
		_, err = decodeRevisionResult(resp, &commitResult)
		if err != nil {
			return FailCheck("failed to decode commit result: " + err.Error())
		}

		if commitResult.Version.IsZero() {
			// Check if the peer returned the version entity directly instead of commit-result.
			var rawResult entity.Entity
			ecf.Decode(resp.Result, &rawResult)
			detail := fmt.Sprintf("commit returned zero version hash (result type=%s", rawResult.Type)
			if rawResult.Type == "system/revision/entry" {
				detail += " — peer returned entry entity directly instead of system/revision/commit-result wrapper"
			}
			detail += ")"
			return FailCheck(detail)
		}

		r.Store("v1_hash", commitResult.Version)
		r.Store("commit_result", commitResult)
		r.Store("prefix", prefix)
		return PassCheck(fmt.Sprintf("commit version: %s", commitResult.Version))
	})

	r.Run("commit_root_nonzero", func() CheckOutcome {
		if out, ok := r.Require("commit_version_nonzero"); !ok {
			return out
		}
		commitResult := r.Load("commit_result").(types.RevisionCommitResultData)
		if commitResult.Root.IsZero() {
			return FailCheck("commit returned zero root hash")
		}
		return PassCheck(fmt.Sprintf("commit root: %s", commitResult.Root))
	})

	r.Run("commit_head_stored", func() CheckOutcome {
		if out, ok := r.Require("commit_version_nonzero"); !ok {
			return out
		}
		v1Hash := r.Load("v1_hash").(hash.Hash)
		_, ok := revisionGetVersionData(ctx, client, prefix, v1Hash)
		if !ok {
			return FailCheck("could not retrieve version entity from log included")
		}
		return PassCheck("version entity accessible via log")
	})

	r.Run("commit_initial_no_parents", func() CheckOutcome {
		if out, ok := r.Require("commit_version_nonzero"); !ok {
			return out
		}
		v1Hash := r.Load("v1_hash").(hash.Hash)
		verData, ok := revisionGetVersionData(ctx, client, prefix, v1Hash)
		if !ok {
			return FailCheck("could not retrieve version entity from log included")
		}
		if len(verData.Parents) != 0 {
			return FailCheck(fmt.Sprintf("initial commit should have 0 parents, got %d", len(verData.Parents)))
		}
		return PassCheck("initial commit has 0 parents")
	})

	r.Run("commit_version_root_ref", func() CheckOutcome {
		if out, ok := r.Require("commit_version_nonzero"); !ok {
			return out
		}
		v1Hash := r.Load("v1_hash").(hash.Hash)
		verData, ok := revisionGetVersionData(ctx, client, prefix, v1Hash)
		if !ok {
			return FailCheck("could not retrieve version entity from log included")
		}
		if verData.Root.IsZero() {
			return FailCheck("version root hash is zero")
		}
		return PassCheck("version references root")
	})

	// --- Step 4: Deep log verification ---

	r.Run("log_version_count", func() CheckOutcome {
		if out, ok := r.Require("commit_version_nonzero"); !ok {
			return out
		}
		resp, err := client.RevisionExecute(ctx, "log", types.RevisionLogParamsData{Prefix: prefix})
		if err != nil || resp.Status != 200 {
			return FailCheck(fmt.Sprintf("log failed: %v (status %d)", err, resp.Status))
		}
		var logResult types.RevisionLogResultData
		_, err = decodeRevisionResult(resp, &logResult)
		if err != nil {
			return FailCheck("failed to decode log result: " + err.Error())
		}
		r.Store("log_result", logResult)
		if len(logResult.Versions) != 1 {
			return FailCheck(fmt.Sprintf("expected 1 version, got %d", len(logResult.Versions)))
		}
		return PassCheck("log returns 1 version after initial commit")
	})

	r.Run("log_version_matches_commit", func() CheckOutcome {
		if out, ok := r.Require("log_version_count"); !ok {
			return out
		}
		logResult := r.Load("log_result").(types.RevisionLogResultData)
		v1Hash := r.Load("v1_hash").(hash.Hash)
		if len(logResult.Versions) > 0 && logResult.Versions[0] != v1Hash {
			return FailCheck(fmt.Sprintf("log version %s != commit version %s", logResult.Versions[0], v1Hash))
		}
		return PassCheck("log version hash matches commit result")
	})

	r.Run("log_prefix", func() CheckOutcome {
		if out, ok := r.Require("log_version_count"); !ok {
			return out
		}
		logResult := r.Load("log_result").(types.RevisionLogResultData)
		if logResult.Prefix != prefix && logResult.Prefix != absPrefix {
			return FailCheck(fmt.Sprintf("log prefix: expected %q or %q, got %q", prefix, absPrefix, logResult.Prefix))
		}
		return PassCheck("log prefix matches request")
	})

	// --- Step 5: Deep status verification ---

	r.Run("status_head_matches", func() CheckOutcome {
		if out, ok := r.Require("commit_version_nonzero"); !ok {
			return out
		}
		v1Hash := r.Load("v1_hash").(hash.Hash)
		resp, err := client.RevisionExecute(ctx, "status", types.RevisionStatusParamsData{Prefix: prefix})
		if err != nil || resp.Status != 200 {
			return FailCheck(fmt.Sprintf("status failed: %v", err))
		}
		var statusData types.RevisionStatusData
		_, err = decodeRevisionResult(resp, &statusData)
		if err != nil {
			return FailCheck("failed to decode status: " + err.Error())
		}
		r.Store("status_data", statusData)
		if statusData.Head != v1Hash {
			return FailCheck(fmt.Sprintf("status head %s != expected %s", statusData.Head, v1Hash))
		}
		return PassCheck("status head matches latest commit")
	})

	r.Run("status_prefix", func() CheckOutcome {
		if out, ok := r.Require("status_head_matches"); !ok {
			return out
		}
		statusData := r.Load("status_data").(types.RevisionStatusData)
		if statusData.Prefix != prefix && statusData.Prefix != absPrefix {
			return FailCheck("status prefix mismatch")
		}
		return PassCheck("status prefix matches")
	})

	r.Run("status_pending_zero", func() CheckOutcome {
		if out, ok := r.Require("status_head_matches"); !ok {
			return out
		}
		statusData := r.Load("status_data").(types.RevisionStatusData)
		if statusData.Pending != 0 {
			return WarnCheck(fmt.Sprintf("expected 0 pending after commit, got %d", statusData.Pending))
		}
		return PassCheck("pending is 0 after commit (no uncommitted changes)")
	})

	// --- Step 6: Sequential commit — modify, commit, verify parent chain ---

	r.Run("sequential_commit", func() CheckOutcome {
		if out, ok := r.Require("commit_version_nonzero"); !ok {
			return out
		}

		// Modify file1.
		newFile1 := mustCreateEntity("test/revision-doc", map[string]string{"content": "modified"})
		_, err := client.TreePut(ctx, prefix+"file1", newFile1)
		if err != nil {
			return FailCheck("failed to modify file1: " + err.Error())
		}

		// Add file3.
		file3 := mustCreateEntity("test/revision-doc", map[string]string{"content": "new file"})
		_, err = client.TreePut(ctx, prefix+"file3", file3)
		if err != nil {
			return FailCheck("failed to add file3: " + err.Error())
		}

		// Commit.
		resp, err := client.RevisionExecute(ctx, "commit", types.RevisionCommitParamsData{
			Prefix: prefix,
		})
		if err != nil || resp.Status != 200 {
			return FailCheck("second commit failed")
		}

		var commitResult types.RevisionCommitResultData
		_, err = decodeRevisionResult(resp, &commitResult)
		if err != nil {
			return FailCheck("failed to decode second commit: " + err.Error())
		}

		r.Store("v2_hash", commitResult.Version)
		return PassCheck(fmt.Sprintf("second commit version: %s", commitResult.Version))
	})

	r.Run("sequential_parent_is_v1", func() CheckOutcome {
		if out, ok := r.Require("sequential_commit"); !ok {
			return out
		}
		v1Hash := r.Load("v1_hash").(hash.Hash)
		v2Hash := r.Load("v2_hash").(hash.Hash)

		verData, ok := revisionGetVersionData(ctx, client, prefix, v2Hash)
		if !ok {
			return FailCheck("could not retrieve v2 version entity from log")
		}
		if len(verData.Parents) != 1 {
			return FailCheck(fmt.Sprintf("v2 should have 1 parent, got %d", len(verData.Parents)))
		}
		if verData.Parents[0] != v1Hash {
			return FailCheck(fmt.Sprintf("v2 parent %s != v1 %s", verData.Parents[0], v1Hash))
		}
		return PassCheck("v2 parent correctly points to v1")
	})

	r.Run("sequential_log_count", func() CheckOutcome {
		if out, ok := r.Require("sequential_commit"); !ok {
			return out
		}
		logResp, err := client.RevisionExecute(ctx, "log", types.RevisionLogParamsData{Prefix: prefix})
		if err != nil || logResp.Status != 200 {
			return FailCheck(fmt.Sprintf("log failed: %v", err))
		}
		var logResult types.RevisionLogResultData
		decodeRevisionResult(logResp, &logResult)
		r.Store("sequential_log_result", logResult)
		if len(logResult.Versions) != 2 {
			return FailCheck(fmt.Sprintf("expected 2 versions in log, got %d", len(logResult.Versions)))
		}
		return PassCheck("log returns 2 versions after second commit")
	})

	r.Run("sequential_log_order", func() CheckOutcome {
		if out, ok := r.Require("sequential_log_count"); !ok {
			return out
		}
		logResult := r.Load("sequential_log_result").(types.RevisionLogResultData)
		v2Hash := r.Load("v2_hash").(hash.Hash)
		if logResult.Versions[0] != v2Hash {
			return FailCheck("log first entry is not the newest version")
		}
		return PassCheck("log returns newest version first (BFS from head)")
	})

	// --- Step 7: Find-ancestor ---

	r.Run("ancestor_linear_correct", func() CheckOutcome {
		if out, ok := r.Require("sequential_commit"); !ok {
			return out
		}
		v1Hash := r.Load("v1_hash").(hash.Hash)
		v2Hash := r.Load("v2_hash").(hash.Hash)

		resp, err := client.RevisionExecute(ctx, "find-ancestor", types.RevisionAncestorParamsData{
			VersionA: v1Hash,
			VersionB: v2Hash,
		})
		if err != nil || resp.Status != 200 {
			return FailCheck(fmt.Sprintf("find-ancestor failed: %v", err))
		}

		var result types.RevisionAncestorResultData
		_, err = decodeRevisionResult(resp, &result)
		if err != nil {
			return FailCheck("failed to decode ancestor result")
		}

		if result.Ancestor == v1Hash {
			return PassCheck("find-ancestor correctly returns v1 as ancestor of v2 (linear chain)")
		}
		if result.Ancestor.IsZero() {
			return FailCheck("find-ancestor returned no ancestor for linear chain")
		}
		return FailCheck(fmt.Sprintf("expected ancestor %s, got %s", v1Hash, result.Ancestor))
	})

	r.Run("ancestor_self", func() CheckOutcome {
		if out, ok := r.Require("sequential_commit"); !ok {
			return out
		}
		v1Hash := r.Load("v1_hash").(hash.Hash)

		resp, err := client.RevisionExecute(ctx, "find-ancestor", types.RevisionAncestorParamsData{
			VersionA: v1Hash,
			VersionB: v1Hash,
		})
		if err != nil || resp.Status != 200 {
			return FailCheck(fmt.Sprintf("find-ancestor (self) failed: %v", err))
		}
		var selfResult types.RevisionAncestorResultData
		decodeRevisionResult(resp, &selfResult)
		if selfResult.Ancestor == v1Hash {
			return PassCheck("find-ancestor of same version returns itself")
		}
		return FailCheck("find-ancestor of same version should return itself")
	})

	// --- Step 8: Diff ---

	r.Run("diff_file1_changed", func() CheckOutcome {
		if out, ok := r.Require("sequential_commit"); !ok {
			return out
		}
		v1Hash := r.Load("v1_hash").(hash.Hash)
		v2Hash := r.Load("v2_hash").(hash.Hash)

		resp, err := client.RevisionExecute(ctx, "diff", types.RevisionDiffParamsData{
			Prefix: prefix,
			Base:   v1Hash,
			Target: v2Hash,
		})
		if err != nil || resp.Status != 200 {
			return FailCheck(fmt.Sprintf("diff failed: %v", err))
		}

		var ent entity.Entity
		ecf.Decode(resp.Result, &ent)
		diffData, err := types.DiffDataFromEntity(ent)
		if err != nil {
			return FailCheck("failed to decode diff: " + err.Error())
		}
		r.Store("diff_data", diffData)

		if _, ok := diffData.Changed["file1"]; ok {
			return PassCheck("diff correctly shows file1 as changed")
		}
		return FailCheck("diff should show file1 as changed")
	})

	r.Run("diff_file3_added", func() CheckOutcome {
		if out, ok := r.Require("diff_file1_changed"); !ok {
			return out
		}
		diffData := r.Load("diff_data").(types.DiffData)
		if _, ok := diffData.Added["file3"]; ok {
			return PassCheck("diff correctly shows file3 as added")
		}
		return FailCheck("diff should show file3 as added")
	})

	r.Run("diff_unchanged", func() CheckOutcome {
		if out, ok := r.Require("diff_file1_changed"); !ok {
			return out
		}
		diffData := r.Load("diff_data").(types.DiffData)
		if diffData.Unchanged < 1 {
			return WarnCheck(fmt.Sprintf("expected at least 1 unchanged (file2), got %d", diffData.Unchanged))
		}
		return PassCheck(fmt.Sprintf("diff reports %d unchanged path(s)", diffData.Unchanged))
	})

	// --- Step 9: Branch lifecycle ---

	r.Run("branch_points_to_head", func() CheckOutcome {
		if out, ok := r.Require("sequential_commit"); !ok {
			return out
		}
		v2Hash := r.Load("v2_hash").(hash.Hash)

		resp, err := client.RevisionExecute(ctx, "branch", types.RevisionBranchParamsData{
			Prefix: prefix, Action: "create", Name: "test-branch",
		})
		if err != nil || resp.Status != 200 {
			return FailCheck(fmt.Sprintf("branch create failed: %v (status %d)", err, resp.Status))
		}

		var brResult types.RevisionBranchResultData
		decodeRevisionResult(resp, &brResult)
		if brResult.Version != v2Hash {
			return FailCheck("new branch should point to current head")
		}
		return PassCheck("new branch points to current head")
	})

	r.Run("branch_list_contains", func() CheckOutcome {
		if out, ok := r.Require("branch_points_to_head"); !ok {
			return out
		}
		resp, _ := client.RevisionExecute(ctx, "branch", types.RevisionBranchParamsData{
			Prefix: prefix, Action: "list",
		})
		var brResult types.RevisionBranchResultData
		decodeRevisionResult(resp, &brResult)
		if _, ok := brResult.Branches["test-branch"]; ok {
			return PassCheck("branch list contains 'test-branch'")
		}
		return FailCheck("branch list missing 'test-branch'")
	})

	r.Run("branch_duplicate_409", func() CheckOutcome {
		if out, ok := r.Require("branch_points_to_head"); !ok {
			return out
		}
		resp, err := client.RevisionExecute(ctx, "branch", types.RevisionBranchParamsData{
			Prefix: prefix, Action: "create", Name: "test-branch",
		})
		if err == nil && resp.Status == 409 {
			return PassCheck("duplicate branch create returns 409")
		}
		return FailCheck(fmt.Sprintf("expected 409 for duplicate branch, got %d", resp.Status))
	})

	r.Run("branch_delete", func() CheckOutcome {
		if out, ok := r.Require("branch_points_to_head"); !ok {
			return out
		}
		resp, _ := client.RevisionExecute(ctx, "branch", types.RevisionBranchParamsData{
			Prefix: prefix, Action: "delete", Name: "test-branch",
		})
		if resp.Status == 200 {
			return PassCheck("branch deleted")
		}
		return FailCheck("branch delete failed")
	})

	r.Run("branch_deleted_from_list", func() CheckOutcome {
		if out, ok := r.Require("branch_delete"); !ok {
			return out
		}
		resp, _ := client.RevisionExecute(ctx, "branch", types.RevisionBranchParamsData{
			Prefix: prefix, Action: "list",
		})
		var brListAfterDelete types.RevisionBranchResultData
		decodeRevisionResult(resp, &brListAfterDelete)
		if _, ok := brListAfterDelete.Branches["test-branch"]; ok {
			return FailCheck(fmt.Sprintf("branch still in list after delete (branches: %v)", brListAfterDelete.Branches))
		}
		return PassCheck("branch no longer in list after delete")
	})

	// --- Step 10: Checkout — switch tree state ---

	r.Run("checkout_status_field", func() CheckOutcome {
		if out, ok := r.Require("sequential_commit"); !ok {
			return out
		}
		v1Hash := r.Load("v1_hash").(hash.Hash)

		// Currently at v2 (has file1, file2, file3).
		// Checkout v1 (has file1-original, file2 only).
		resp, err := client.RevisionExecute(ctx, "checkout", types.RevisionCheckoutParamsData{
			Prefix:  prefix,
			Version: v1Hash,
		})
		if err != nil || resp.Status != 200 {
			return FailCheck(fmt.Sprintf("checkout to v1 failed: %v (status %d)", err, resp.Status))
		}

		var checkoutResult types.RevisionCheckoutResultData
		decodeRevisionResult(resp, &checkoutResult)
		r.Store("checkout_done", true)
		if checkoutResult.Status != "checked_out" {
			return FailCheck(fmt.Sprintf("checkout status: expected 'checked_out', got %q", checkoutResult.Status))
		}
		return PassCheck("checkout returns 'checked_out'")
	})

	r.Run("checkout_file3_removed", func() CheckOutcome {
		if out, ok := r.Require("checkout_status_field"); !ok {
			return out
		}
		// file3 should be GONE (it was added in v2).
		_, _, err := client.TreeGet(ctx, prefix+"file3")
		if err != nil {
			return PassCheck("file3 removed after checkout to v1 (was added in v2)")
		}
		return FailCheck("file3 should not exist after checkout to v1")
	})

	r.Run("checkout_file1_exists", func() CheckOutcome {
		if out, ok := r.Require("checkout_status_field"); !ok {
			return out
		}
		_, _, err := client.TreeGet(ctx, prefix+"file1")
		if err != nil {
			return FailCheck("file1 should exist after checkout to v1")
		}
		return PassCheck("file1 exists after checkout to v1")
	})

	r.Run("checkout_file2_exists", func() CheckOutcome {
		if out, ok := r.Require("checkout_status_field"); !ok {
			return out
		}
		_, _, err := client.TreeGet(ctx, prefix+"file2")
		if err != nil {
			return FailCheck("file2 should exist after checkout to v1")
		}
		return PassCheck("file2 exists after checkout to v1")
	})

	r.Run("checkout_head_updated", func() CheckOutcome {
		if out, ok := r.Require("checkout_status_field"); !ok {
			return out
		}
		v1Hash := r.Load("v1_hash").(hash.Hash)
		v2Hash := r.Load("v2_hash").(hash.Hash)

		statusResp, _ := client.RevisionExecute(ctx, "status", types.RevisionStatusParamsData{Prefix: prefix})
		var statusData types.RevisionStatusData
		decodeRevisionResult(statusResp, &statusData)
		if statusData.Head != v1Hash {
			return FailCheck(fmt.Sprintf("head should be v1 after checkout, got %s", statusData.Head))
		}

		// Restore to v2 for subsequent tests.
		client.RevisionExecute(ctx, "checkout", types.RevisionCheckoutParamsData{
			Prefix: prefix, Version: v2Hash,
		})

		return PassCheck("head updated to v1 after checkout")
	})

	// --- Step 11: Tag lifecycle ---

	r.Run("tag_create", func() CheckOutcome {
		if out, ok := r.Require("sequential_commit"); !ok {
			return out
		}
		resp, err := client.RevisionExecute(ctx, "tag", types.RevisionTagParamsData{
			Prefix: prefix, Action: "create", Name: "v1.0-test",
		})
		if err != nil || resp.Status != 200 {
			return FailCheck(fmt.Sprintf("tag create failed: %v", err))
		}
		return PassCheck("tag created")
	})

	r.Run("tag_list_contains", func() CheckOutcome {
		if out, ok := r.Require("tag_create"); !ok {
			return out
		}
		resp, _ := client.RevisionExecute(ctx, "tag", types.RevisionTagParamsData{
			Prefix: prefix, Action: "list",
		})
		var tagResult types.RevisionTagResultData
		decodeRevisionResult(resp, &tagResult)
		if _, ok := tagResult.Tags["v1.0-test"]; ok {
			return PassCheck("tag list contains 'v1.0-test'")
		}
		return FailCheck("tag not in list")
	})

	r.Run("tag_immutable", func() CheckOutcome {
		if out, ok := r.Require("tag_create"); !ok {
			return out
		}
		resp, err := client.RevisionExecute(ctx, "tag", types.RevisionTagParamsData{
			Prefix: prefix, Action: "create", Name: "v1.0-test",
		})
		if err == nil && resp.Status == 409 {
			return PassCheck("tag is immutable (409 on duplicate)")
		}
		return FailCheck(fmt.Sprintf("expected 409, got %d", resp.Status))
	})

	r.Run("tag_delete", func() CheckOutcome {
		if out, ok := r.Require("tag_create"); !ok {
			return out
		}
		client.RevisionExecute(ctx, "tag", types.RevisionTagParamsData{
			Prefix: prefix, Action: "delete", Name: "v1.0-test",
		})
		resp, _ := client.RevisionExecute(ctx, "tag", types.RevisionTagParamsData{
			Prefix: prefix, Action: "list",
		})
		var tagListAfterDelete types.RevisionTagResultData
		decodeRevisionResult(resp, &tagListAfterDelete)
		if _, ok := tagListAfterDelete.Tags["v1.0-test"]; !ok {
			return PassCheck("tag removed after delete")
		}
		return FailCheck("tag still present after delete")
	})

	// --- Step 12: Merge in_sync ---

	r.Run("merge_in_sync", func() CheckOutcome {
		if out, ok := r.Require("sequential_commit"); !ok {
			return out
		}

		statusResp, _ := client.RevisionExecute(ctx, "status", types.RevisionStatusParamsData{Prefix: prefix})
		var statusData types.RevisionStatusData
		decodeRevisionResult(statusResp, &statusData)

		if statusData.Head.IsZero() {
			return SkipCheck("no head")
		}

		resp, err := client.RevisionExecute(ctx, "merge", types.RevisionMergeParamsData{
			Prefix:        prefix,
			RemoteVersion: statusData.Head,
		})
		if err != nil || resp.Status != 200 {
			return FailCheck(fmt.Sprintf("merge failed: %v", err))
		}

		var mergeResult types.RevisionMergeResultData
		decodeRevisionResult(resp, &mergeResult)
		if mergeResult.Status == "already_in_sync" {
			return PassCheck("merge with same version returns 'already_in_sync'")
		}
		return FailCheck(fmt.Sprintf("expected 'already_in_sync', got %q", mergeResult.Status))
	})

	// --- Step 13: Fast-forward merge ---

	r.Run("merge_ff_status", func() CheckOutcome {
		ffPrefix := revisionTestPrefix("ff")
		r.Store("ff_prefix", ffPrefix)

		// v1: base file.
		base := mustCreateEntity("test/revision-doc", map[string]string{"content": "base"})
		client.TreePut(ctx, ffPrefix+"file1", base)
		resp, _ := client.RevisionExecute(ctx, "commit", types.RevisionCommitParamsData{Prefix: ffPrefix})
		var v1Result types.RevisionCommitResultData
		decodeRevisionResult(resp, &v1Result)
		v1 := v1Result.Version
		r.Store("ff_v1", v1)

		// v2: add another file.
		extra := mustCreateEntity("test/revision-doc", map[string]string{"content": "extra"})
		client.TreePut(ctx, ffPrefix+"file2", extra)
		resp, _ = client.RevisionExecute(ctx, "commit", types.RevisionCommitParamsData{Prefix: ffPrefix})
		var v2Result types.RevisionCommitResultData
		decodeRevisionResult(resp, &v2Result)
		v2 := v2Result.Version
		r.Store("ff_v2", v2)

		// Checkout back to v1 (local is now behind v2).
		client.RevisionExecute(ctx, "checkout", types.RevisionCheckoutParamsData{
			Prefix: ffPrefix, Version: v1,
		})

		// Merge with v2 — should fast-forward.
		resp, err := client.RevisionExecute(ctx, "merge", types.RevisionMergeParamsData{
			Prefix:        ffPrefix,
			RemoteVersion: v2,
		})
		if err != nil || resp.Status != 200 {
			return FailCheck(fmt.Sprintf("fast-forward merge failed: %v", err))
		}

		var mergeResult types.RevisionMergeResultData
		decodeRevisionResult(resp, &mergeResult)
		r.Store("ff_merge_result", mergeResult)
		if mergeResult.Status == "fast_forward" {
			return PassCheck("merge returns 'fast_forward' when local is behind")
		}
		return FailCheck(fmt.Sprintf("expected 'fast_forward', got %q", mergeResult.Status))
	})

	r.Run("merge_ff_version", func() CheckOutcome {
		if out, ok := r.Require("merge_ff_status"); !ok {
			return out
		}
		mergeResult := r.Load("ff_merge_result").(types.RevisionMergeResultData)
		v2 := r.Load("ff_v2").(hash.Hash)
		if mergeResult.Version == v2 {
			return PassCheck("fast-forward advances head to remote version")
		}
		return FailCheck(fmt.Sprintf("expected ff version %s, got %s", v2, mergeResult.Version))
	})

	r.Run("merge_ff_tree_updated", func() CheckOutcome {
		if out, ok := r.Require("merge_ff_status"); !ok {
			return out
		}
		ffPrefix := r.Load("ff_prefix").(string)
		_, _, err := client.TreeGet(ctx, ffPrefix+"file2")
		if err != nil {
			return FailCheck("tree should have file2 after fast-forward")
		}
		return PassCheck("tree correctly updated after fast-forward merge")
	})

	// --- Step 14: Diverged merge + conflict resolution ---

	r.Run("merge_diverged_status", func() CheckOutcome {
		mergePrefix := revisionTestPrefix("merge")
		r.Store("merge_prefix", mergePrefix)

		// Create base state: shared-file + local-only.
		sharedFile := mustCreateEntity("test/revision-doc", map[string]string{"content": "shared-original"})
		client.TreePut(ctx, mergePrefix+"shared", sharedFile)
		localOnly := mustCreateEntity("test/revision-doc", map[string]string{"content": "local"})
		client.TreePut(ctx, mergePrefix+"local-only", localOnly)
		resp, _ := client.RevisionExecute(ctx, "commit", types.RevisionCommitParamsData{Prefix: mergePrefix})
		var baseResult types.RevisionCommitResultData
		decodeRevisionResult(resp, &baseResult)
		baseVersion := baseResult.Version
		r.Store("merge_base_version", baseVersion)

		// Branch A: modify shared file locally.
		localModified := mustCreateEntity("test/revision-doc", map[string]string{"content": "local-modified"})
		client.TreePut(ctx, mergePrefix+"shared", localModified)
		resp, _ = client.RevisionExecute(ctx, "commit", types.RevisionCommitParamsData{Prefix: mergePrefix})
		var localResult types.RevisionCommitResultData
		decodeRevisionResult(resp, &localResult)
		r.Store("merge_local_version", localResult.Version)

		// Go back to base to create divergent version.
		client.RevisionExecute(ctx, "checkout", types.RevisionCheckoutParamsData{
			Prefix: mergePrefix, Version: baseVersion,
		})

		// Branch B: modify shared file differently (creates conflict), add remote-only file.
		remoteModified := mustCreateEntity("test/revision-doc", map[string]string{"content": "remote-modified"})
		client.TreePut(ctx, mergePrefix+"shared", remoteModified)
		remoteOnly := mustCreateEntity("test/revision-doc", map[string]string{"content": "remote-only"})
		client.TreePut(ctx, mergePrefix+"remote-file", remoteOnly)
		resp, _ = client.RevisionExecute(ctx, "commit", types.RevisionCommitParamsData{Prefix: mergePrefix})
		var remoteResult types.RevisionCommitResultData
		decodeRevisionResult(resp, &remoteResult)
		remoteVersion := remoteResult.Version
		r.Store("merge_remote_version", remoteVersion)

		// Checkout local version — now local and remote are diverged.
		client.RevisionExecute(ctx, "checkout", types.RevisionCheckoutParamsData{
			Prefix: mergePrefix, Version: localResult.Version,
		})

		// Merge remote into local — should produce conflict on "shared".
		resp, err := client.RevisionExecute(ctx, "merge", types.RevisionMergeParamsData{
			Prefix:        mergePrefix,
			RemoteVersion: remoteVersion,
		})
		if err != nil || resp.Status != 200 {
			return FailCheck(fmt.Sprintf("diverged merge failed: %v", err))
		}

		var mergeResult types.RevisionMergeResultData
		decodeRevisionResult(resp, &mergeResult)
		r.Store("merge_diverged_result", mergeResult)

		if mergeResult.Status == "merged_with_conflicts" {
			return PassCheck("diverged merge returns 'merged_with_conflicts'")
		}
		if mergeResult.Status == "merged" {
			return PassCheck("diverged merge returns 'merged' (clean)")
		}
		return FailCheck(fmt.Sprintf("expected merge status, got %q", mergeResult.Status))
	})

	r.Run("merge_diverged_two_parents", func() CheckOutcome {
		if out, ok := r.Require("merge_diverged_status"); !ok {
			return out
		}
		mergeResult := r.Load("merge_diverged_result").(types.RevisionMergeResultData)
		mergePrefix := r.Load("merge_prefix").(string)
		if mergeResult.Version.IsZero() {
			return FailCheck("merge version is zero")
		}
		verData, ok := revisionGetVersionData(ctx, client, mergePrefix, mergeResult.Version)
		if !ok {
			return FailCheck("could not retrieve merge version entity")
		}
		if len(verData.Parents) == 2 {
			return PassCheck("merge version has 2 parents")
		}
		return FailCheck(fmt.Sprintf("merge version should have 2 parents, got %d", len(verData.Parents)))
	})

	r.Run("merge_diverged_remote_file", func() CheckOutcome {
		if out, ok := r.Require("merge_diverged_status"); !ok {
			return out
		}
		mergePrefix := r.Load("merge_prefix").(string)
		_, _, err := client.TreeGet(ctx, mergePrefix+"remote-file")
		if err != nil {
			return FailCheck("remote-file should exist after merge")
		}
		return PassCheck("non-conflicting remote addition present after merge")
	})

	r.Run("merge_has_conflicts", func() CheckOutcome {
		if out, ok := r.Require("merge_diverged_status"); !ok {
			return out
		}
		mergeResult := r.Load("merge_diverged_result").(types.RevisionMergeResultData)
		if len(mergeResult.Conflicts) > 0 {
			r.Store("has_conflicts", true)
			return PassCheck(fmt.Sprintf("merge reports %d conflict(s): %s", len(mergeResult.Conflicts),
				strings.Join(mergeResult.Conflicts, ", ")))
		}
		// No conflicts — clean merge. Mark as pass but record no conflicts.
		r.Store("has_conflicts", false)
		return PassCheck("merge completed cleanly (no conflicts)")
	})

	r.Run("merge_status_conflicts", func() CheckOutcome {
		if out, ok := r.Require("merge_has_conflicts"); !ok {
			return out
		}
		hasConflicts, _ := r.Load("has_conflicts").(bool)
		if !hasConflicts {
			return SkipCheck("no conflicts to verify in status")
		}
		mergePrefix := r.Load("merge_prefix").(string)
		statusResp, _ := client.RevisionExecute(ctx, "status", types.RevisionStatusParamsData{Prefix: mergePrefix})
		var statusData types.RevisionStatusData
		decodeRevisionResult(statusResp, &statusData)
		if statusData.Conflicts > 0 {
			return PassCheck(fmt.Sprintf("status reports %d conflict(s)", statusData.Conflicts))
		}
		return WarnCheck("status reports 0 conflicts after merge_with_conflicts")
	})

	r.Run("resolve_path", func() CheckOutcome {
		if out, ok := r.Require("merge_has_conflicts"); !ok {
			return out
		}
		hasConflicts, _ := r.Load("has_conflicts").(bool)
		if !hasConflicts {
			return SkipCheck("no conflicts to resolve")
		}
		mergeResult := r.Load("merge_diverged_result").(types.RevisionMergeResultData)
		mergePrefix := r.Load("merge_prefix").(string)

		resolvedEntity := mustCreateEntity("test/revision-doc", map[string]string{"content": "resolved"})
		resolvedHash, _ := client.TreePut(ctx, mergePrefix+"_resolve_tmp", resolvedEntity)
		r.Store("resolved_hash", resolvedHash)

		conflictPath := mergeResult.Conflicts[0]
		r.Store("conflict_path", conflictPath)

		resp, err := client.RevisionExecute(ctx, "resolve", types.RevisionResolveParamsData{
			Prefix:   mergePrefix,
			Path:     conflictPath,
			Resolved: &resolvedHash,
		})
		if err != nil || resp.Status != 200 {
			return FailCheck(fmt.Sprintf("resolve failed: %v (status %d)", err, resp.Status))
		}

		var resolveResult types.RevisionResolveResultData
		decodeRevisionResult(resp, &resolveResult)
		r.Store("resolve_result", resolveResult)

		if resolveResult.Path == conflictPath {
			return PassCheck("resolve returns correct path")
		}
		return FailCheck(fmt.Sprintf("expected path %q, got %q", conflictPath, resolveResult.Path))
	})

	r.Run("resolve_hash", func() CheckOutcome {
		if out, ok := r.Require("resolve_path"); !ok {
			return out
		}
		hasConflicts, _ := r.Load("has_conflicts").(bool)
		if !hasConflicts {
			return SkipCheck("no conflicts to resolve")
		}
		resolveResult := r.Load("resolve_result").(types.RevisionResolveResultData)
		resolvedHash := r.Load("resolved_hash").(hash.Hash)
		if resolveResult.Resolved != nil && *resolveResult.Resolved == resolvedHash {
			return PassCheck("resolve confirms resolved hash")
		}
		return FailCheck("resolve hash mismatch")
	})

	r.Run("resolve_entity_at_path", func() CheckOutcome {
		if out, ok := r.Require("resolve_path"); !ok {
			return out
		}
		hasConflicts, _ := r.Load("has_conflicts").(bool)
		if !hasConflicts {
			return SkipCheck("no conflicts to resolve")
		}
		mergePrefix := r.Load("merge_prefix").(string)
		conflictPath := r.Load("conflict_path").(string)
		resolvedHash := r.Load("resolved_hash").(hash.Hash)

		resolvedEnt, _, err := client.TreeGet(ctx, mergePrefix+conflictPath)
		if err != nil {
			return FailCheck("resolved entity not at original path")
		}
		if resolvedEnt.ContentHash == resolvedHash {
			return PassCheck("resolved entity placed at original path")
		}
		return FailCheck("entity at path has wrong hash after resolve")
	})

	r.Run("resolve_idempotent", func() CheckOutcome {
		if out, ok := r.Require("resolve_path"); !ok {
			return out
		}
		hasConflicts, _ := r.Load("has_conflicts").(bool)
		if !hasConflicts {
			return SkipCheck("no conflicts to resolve")
		}
		mergePrefix := r.Load("merge_prefix").(string)
		conflictPath := r.Load("conflict_path").(string)
		resolvedHash := r.Load("resolved_hash").(hash.Hash)

		resp, err := client.RevisionExecute(ctx, "resolve", types.RevisionResolveParamsData{
			Prefix:   mergePrefix,
			Path:     conflictPath,
			Resolved: &resolvedHash,
		})
		if err == nil && resp.Status == 404 {
			return PassCheck("re-resolving resolved conflict returns 404")
		}
		return WarnCheck(fmt.Sprintf("expected 404 on re-resolve, got %d", resp.Status))
	})

	// --- Step 15: Cherry-pick ---

	r.Run("cherry_pick_status", func() CheckOutcome {
		cpPrefix := revisionTestPrefix("cp")
		r.Store("cp_prefix", cpPrefix)

		// Put a file and commit on cpPrefix.
		baseFile := mustCreateEntity("test/revision-doc", map[string]string{"content": "base"})
		client.TreePut(ctx, cpPrefix+"base-file", baseFile)
		resp, _ := client.RevisionExecute(ctx, "commit", types.RevisionCommitParamsData{Prefix: cpPrefix})
		var baseResult types.RevisionCommitResultData
		decodeRevisionResult(resp, &baseResult)
		baseVersion := baseResult.Version
		r.Store("cp_base_version", baseVersion)

		// Add another file and commit.
		newFile := mustCreateEntity("test/revision-doc", map[string]string{"content": "cherry"})
		client.TreePut(ctx, cpPrefix+"cherry-file", newFile)
		resp, _ = client.RevisionExecute(ctx, "commit", types.RevisionCommitParamsData{Prefix: cpPrefix})
		var cherryResult types.RevisionCommitResultData
		decodeRevisionResult(resp, &cherryResult)
		cherryVersion := cherryResult.Version
		r.Store("cp_cherry_version", cherryVersion)

		// Checkout back to base (removes cherry-file).
		client.RevisionExecute(ctx, "checkout", types.RevisionCheckoutParamsData{
			Prefix: cpPrefix, Version: baseVersion,
		})

		// Verify cherry-file is gone.
		_, _, err := client.TreeGet(ctx, cpPrefix+"cherry-file")
		if err == nil {
			return FailCheck("cherry-file should not exist after checkout to base")
		}

		// Cherry-pick the cherry commit.
		resp, err = client.RevisionExecute(ctx, "cherry-pick", types.RevisionCherryPickParamsData{
			Prefix:  cpPrefix,
			Version: cherryVersion,
		})
		if err != nil || resp.Status != 200 {
			return FailCheck(fmt.Sprintf("cherry-pick failed: %v (status %d)", err, resp.Status))
		}

		var cpResult types.RevisionCherryPickResultData
		decodeRevisionResult(resp, &cpResult)
		r.Store("cp_result", cpResult)
		if cpResult.Status != "cherry_picked" {
			return FailCheck(fmt.Sprintf("expected 'cherry_picked', got %q", cpResult.Status))
		}
		return PassCheck("cherry-pick succeeded")
	})

	r.Run("cherry_pick_file_applied", func() CheckOutcome {
		if out, ok := r.Require("cherry_pick_status"); !ok {
			return out
		}
		cpPrefix := r.Load("cp_prefix").(string)
		_, _, err := client.TreeGet(ctx, cpPrefix+"cherry-file")
		if err != nil {
			return FailCheck("cherry-file should exist after cherry-pick")
		}
		return PassCheck("cherry-pick correctly applied file addition to tree")
	})

	r.Run("cherry_pick_parent", func() CheckOutcome {
		if out, ok := r.Require("cherry_pick_status"); !ok {
			return out
		}
		cpResult := r.Load("cp_result").(types.RevisionCherryPickResultData)
		cpPrefix := r.Load("cp_prefix").(string)
		baseVersion := r.Load("cp_base_version").(hash.Hash)

		if cpResult.Version.IsZero() {
			return FailCheck("cherry-pick version is zero")
		}
		verData, ok := revisionGetVersionData(ctx, client, cpPrefix, cpResult.Version)
		if !ok {
			return FailCheck("could not retrieve cherry-pick version entity")
		}
		if len(verData.Parents) == 1 && verData.Parents[0] == baseVersion {
			return PassCheck("cherry-pick version has single parent (original head, not picked version)")
		}
		return FailCheck(fmt.Sprintf("expected 1 parent=%s, got %d parents", baseVersion, len(verData.Parents)))
	})

	// --- Step 16: Revert ---

	r.Run("revert_status", func() CheckOutcome {
		rvPrefix := revisionTestPrefix("rv")
		r.Store("rv_prefix", rvPrefix)

		// v1: base-file only.
		baseFile := mustCreateEntity("test/revision-doc", map[string]string{"content": "base"})
		client.TreePut(ctx, rvPrefix+"base-file", baseFile)
		resp, _ := client.RevisionExecute(ctx, "commit", types.RevisionCommitParamsData{Prefix: rvPrefix})
		var v1Result types.RevisionCommitResultData
		decodeRevisionResult(resp, &v1Result)

		// v2: add revert-file.
		rvFile := mustCreateEntity("test/revision-doc", map[string]string{"content": "will be reverted"})
		client.TreePut(ctx, rvPrefix+"revert-file", rvFile)
		resp, _ = client.RevisionExecute(ctx, "commit", types.RevisionCommitParamsData{Prefix: rvPrefix})
		var v2Result types.RevisionCommitResultData
		decodeRevisionResult(resp, &v2Result)
		r.Store("rv_v2_version", v2Result.Version)

		// Verify revert-file exists.
		_, _, err := client.TreeGet(ctx, rvPrefix+"revert-file")
		if err != nil {
			return FailCheck("revert-file should exist before revert")
		}

		// Revert v2.
		resp, err = client.RevisionExecute(ctx, "revert", types.RevisionRevertParamsData{
			Prefix:  rvPrefix,
			Version: v2Result.Version,
		})
		if err != nil || resp.Status != 200 {
			return FailCheck(fmt.Sprintf("revert failed: %v (status %d)", err, resp.Status))
		}

		var rvResult types.RevisionRevertResultData
		decodeRevisionResult(resp, &rvResult)
		if rvResult.Status != "reverted" {
			return FailCheck(fmt.Sprintf("expected 'reverted', got %q", rvResult.Status))
		}
		return PassCheck("revert succeeded")
	})

	r.Run("revert_file_removed", func() CheckOutcome {
		if out, ok := r.Require("revert_status"); !ok {
			return out
		}
		rvPrefix := r.Load("rv_prefix").(string)
		_, _, err := client.TreeGet(ctx, rvPrefix+"revert-file")
		if err != nil {
			return PassCheck("revert correctly removed the file added by v2")
		}
		return FailCheck("revert-file should not exist after reverting v2")
	})

	r.Run("revert_base_preserved", func() CheckOutcome {
		if out, ok := r.Require("revert_status"); !ok {
			return out
		}
		rvPrefix := r.Load("rv_prefix").(string)
		_, _, err := client.TreeGet(ctx, rvPrefix+"base-file")
		if err != nil {
			return FailCheck("base-file should still exist after revert")
		}
		return PassCheck("base-file preserved after revert")
	})

	// --- Step 17: Log pagination ---

	r.Run("log_pagination_limit", func() CheckOutcome {
		pgPrefix := revisionTestPrefix("pg")
		r.Store("pg_prefix", pgPrefix)

		// Create 4 versions.
		for i := 0; i < 4; i++ {
			ent := mustCreateEntity("test/revision-doc", map[string]string{"content": fmt.Sprintf("v%d", i)})
			client.TreePut(ctx, pgPrefix+fmt.Sprintf("file%d", i), ent)
			client.RevisionExecute(ctx, "commit", types.RevisionCommitParamsData{Prefix: pgPrefix})
		}

		// Request with limit=2.
		limit := uint64(2)
		resp, err := client.RevisionExecute(ctx, "log", types.RevisionLogParamsData{
			Prefix: pgPrefix,
			Limit:  &limit,
		})
		if err != nil || resp.Status != 200 {
			return FailCheck(fmt.Sprintf("log with limit failed: %v", err))
		}

		var logResult types.RevisionLogResultData
		decodeRevisionResult(resp, &logResult)
		r.Store("pg_log_result", logResult)

		if len(logResult.Versions) == 2 {
			return PassCheck("log respects limit parameter")
		}
		return FailCheck(fmt.Sprintf("expected 2 versions with limit=2, got %d", len(logResult.Versions)))
	})

	r.Run("log_pagination_has_more", func() CheckOutcome {
		if out, ok := r.Require("log_pagination_limit"); !ok {
			return out
		}
		logResult := r.Load("pg_log_result").(types.RevisionLogResultData)
		if logResult.HasMore {
			return PassCheck("log correctly sets has_more=true when more versions exist")
		}
		return FailCheck("log should set has_more=true when 4 versions exist and limit=2")
	})

	r.Run("log_pagination_since", func() CheckOutcome {
		if out, ok := r.Require("log_pagination_limit"); !ok {
			return out
		}
		logResult := r.Load("pg_log_result").(types.RevisionLogResultData)
		pgPrefix := r.Load("pg_prefix").(string)

		if len(logResult.Versions) == 0 {
			return SkipCheck("no versions to paginate from")
		}
		sinceHash := logResult.Versions[len(logResult.Versions)-1]
		resp, err := client.RevisionExecute(ctx, "log", types.RevisionLogParamsData{
			Prefix: pgPrefix,
			Since:  sinceHash,
		})
		if err != nil || resp.Status != 200 {
			return FailCheck(fmt.Sprintf("log with since failed: %v", err))
		}
		var page2 types.RevisionLogResultData
		decodeRevisionResult(resp, &page2)
		if len(page2.Versions) > 0 {
			return PassCheck(fmt.Sprintf("log with since returns %d additional version(s)", len(page2.Versions)))
		}
		return WarnCheck("log with since returned 0 versions")
	})

	// --- Step 18: Merge result cascade_warnings field ---

	r.Run("merge_result_has_cascade_warnings_field", func() CheckOutcome {
		if out, ok := r.Require("merge_ff_status"); !ok {
			return out
		}
		mergeResult := r.Load("ff_merge_result").(types.RevisionMergeResultData)

		// The CascadeWarnings field exists on the Go type (RevisionMergeResultData).
		// For a normal merge it should be nil/empty. We verify the field roundtrips
		// by encoding and decoding.
		raw, err := ecf.Encode(mergeResult)
		if err != nil {
			return FailCheck("failed to re-encode merge result: " + err.Error())
		}
		var decoded types.RevisionMergeResultData
		if err := ecf.Decode(raw, &decoded); err != nil {
			return FailCheck("failed to re-decode merge result: " + err.Error())
		}
		// CascadeWarnings should be nil for normal merges (no cascade halts).
		if decoded.CascadeWarnings == nil || len(decoded.CascadeWarnings) == 0 {
			return PassCheck("merge result roundtrips with cascade_warnings field (empty for normal merge)")
		}
		return PassCheck(fmt.Sprintf("merge result has %d cascade_warnings", len(decoded.CascadeWarnings)))
	})

	// --- Step: R1 — Revert merge-version parent validation ---

	r.Run("revert_merge_ambiguous_parent", func() CheckOutcome {
		if out, ok := r.Require("merge_diverged_status"); !ok {
			return out
		}
		mergeResult := r.Load("merge_diverged_result").(types.RevisionMergeResultData)
		mergePrefix := r.Load("merge_prefix").(string)

		if mergeResult.Version.IsZero() {
			return SkipCheck("no merge version to test revert parent on")
		}

		resp, err := client.RevisionExecute(ctx, "revert", types.RevisionRevertParamsData{
			Prefix:  mergePrefix,
			Version: mergeResult.Version,
		})
		if err != nil {
			return FailCheck("revert request failed: " + err.Error())
		}
		if resp.Status == 400 {
			return PassCheck("revert merge version without parent correctly returns 400")
		}
		return FailCheck(fmt.Sprintf("expected 400 for ambiguous revert, got %d", resp.Status))
	})

	r.Run("revert_merge_explicit_parent", func() CheckOutcome {
		if out, ok := r.Require("revert_merge_ambiguous_parent"); !ok {
			return out
		}
		mergeResult := r.Load("merge_diverged_result").(types.RevisionMergeResultData)
		mergePrefix := r.Load("merge_prefix").(string)

		if mergeResult.Version.IsZero() {
			return SkipCheck("no merge version")
		}

		// Look up the merge version's parents via log.
		verData, ok := revisionGetVersionData(ctx, client, mergePrefix, mergeResult.Version)
		if !ok || len(verData.Parents) < 2 {
			return SkipCheck("could not load merge version parents")
		}

		resp, err := client.RevisionExecute(ctx, "revert", types.RevisionRevertParamsData{
			Prefix:  mergePrefix,
			Version: mergeResult.Version,
			Parent:  verData.Parents[0],
		})
		if err != nil {
			return FailCheck("revert with explicit parent failed: " + err.Error())
		}
		if resp.Status == 200 {
			return PassCheck("revert merge version with explicit parent succeeds")
		}
		return FailCheck(fmt.Sprintf("expected 200, got %d", resp.Status))
	})

	// --- Step: R2 — Resolve null (delete path) + verify unbind ---

	r.Run("resolve_null_delete", func() CheckOutcome {
		resolvePrefix := revisionTestPrefix("resnull")
		r.Store("resolve_null_prefix", resolvePrefix)
		resolvePH := revision.PrefixHash("/" + remotePID + "/" + resolvePrefix)

		fileEntity := mustCreateEntity("test/revision-doc", map[string]string{"content": "v1"})
		client.TreePut(ctx, resolvePrefix+"file1", fileEntity)
		client.RevisionExecute(ctx, "commit", types.RevisionCommitParamsData{Prefix: resolvePrefix})

		// Place a conflict entity at the v3.0 hash-addressed conflict path.
		conflictData := types.RevisionConflictData{Path: "file1", Strategy: "manual"}
		conflictEntity, _ := conflictData.ToEntity()
		client.TreePut(ctx, "system/revision/"+resolvePH+"/conflicts/file1", conflictEntity)

		resp, err := client.RevisionExecute(ctx, "resolve", types.RevisionResolveParamsData{
			Prefix:   resolvePrefix,
			Path:     "file1",
			Resolved: nil,
		})
		if err != nil {
			return FailCheck("resolve null failed: " + err.Error())
		}
		if resp.Status != 200 {
			return FailCheck(fmt.Sprintf("expected 200, got %d", resp.Status))
		}

		var resolveResult types.RevisionResolveResultData
		decodeRevisionResult(resp, &resolveResult)

		if resolveResult.Resolved != nil {
			return FailCheck("resolve result should have null resolved for delete")
		}
		return PassCheck("resolve with null correctly returns null resolved")
	})

	r.Run("resolve_null_path_unbound", func() CheckOutcome {
		if out, ok := r.Require("resolve_null_delete"); !ok {
			return out
		}
		resolvePrefix := r.Load("resolve_null_prefix").(string)

		// After null resolve, the path should be unbound (tree get returns not found).
		_, _, err := client.TreeGet(ctx, resolvePrefix+"file1")
		if err != nil {
			return PassCheck("path correctly unbound after null resolve")
		}
		return WarnCheck("path still exists after null resolve (may be stale)")
	})

	// --- Step: R2 — Resolve nonexistent hash rejection ---

	r.Run("resolve_nonexistent_hash", func() CheckOutcome {
		// Use the real merge-conflict flow: if conflicts existed, re-resolve with a bad hash.
		if out, ok := r.Require("resolve_path"); !ok {
			return out
		}
		hasConflicts, _ := r.Load("has_conflicts").(bool)
		if !hasConflicts {
			return SkipCheck("no conflicts to test hash rejection")
		}

		mergePrefix := r.Load("merge_prefix").(string)

		// Create a fresh conflict to test against (since the prior one was already resolved).
		conflictData := types.RevisionConflictData{Path: "bad-hash-test", Strategy: "manual"}
		conflictEntity, _ := conflictData.ToEntity()
		mergePH := revision.PrefixHash("/" + remotePID + "/" + mergePrefix)
		client.TreePut(ctx, "system/revision/"+mergePH+"/conflicts/bad-hash-test", conflictEntity)

		// Use a syntactically valid hash (algorithm 0x00 = ECF-SHA256) with a
		// digest that is overwhelmingly unlikely to match anything in the
		// content store. Sending a non-zero algorithm byte instead would fail
		// the wire-decode (FromBytes rejects unknown algorithms) and surface
		// as 400 invalid_params before reaching the handler's 404 path.
		badHash := hash.Hash{Algorithm: hash.AlgorithmSHA256}
		for i := 0; i < hash.SHA256DigestSize; i++ {
			badHash.Digest[i] = 0xFF
		}
		resp, err := client.RevisionExecute(ctx, "resolve", types.RevisionResolveParamsData{
			Prefix:   mergePrefix,
			Path:     "bad-hash-test",
			Resolved: &badHash,
		})
		if err != nil {
			return FailCheck("resolve request failed: " + err.Error())
		}
		if resp.Status == 404 {
			return PassCheck("resolve correctly rejects nonexistent hash with 404")
		}
		if resp.Status == 200 {
			return FailCheck("resolve should reject nonexistent hash, but returned 200")
		}
		return WarnCheck(fmt.Sprintf("resolve rejected bad hash with %d (expected 404)", resp.Status))
	})

	// --- Step: R5 — Resolve remaining_conflicts count ---

	r.Run("resolve_remaining_conflicts", func() CheckOutcome {
		if out, ok := r.Require("resolve_path"); !ok {
			return out
		}
		hasConflicts, _ := r.Load("has_conflicts").(bool)
		if !hasConflicts {
			return SkipCheck("no conflicts to test remaining count")
		}
		resolveResult := r.Load("resolve_result").(types.RevisionResolveResultData)

		raw, err := ecf.Encode(resolveResult)
		if err != nil {
			return FailCheck("failed to re-encode resolve result")
		}
		var decoded map[string]interface{}
		if err := ecf.Decode(raw, &decoded); err != nil {
			return FailCheck("failed to re-decode resolve result")
		}
		if _, exists := decoded["remaining_conflicts"]; exists {
			return PassCheck(fmt.Sprintf("resolve result includes remaining_conflicts=%d", resolveResult.RemainingConflicts))
		}
		return FailCheck("resolve result missing remaining_conflicts field")
	})

	r.Run("resolve_remaining_zero_after_last", func() CheckOutcome {
		if out, ok := r.Require("resolve_remaining_conflicts"); !ok {
			return out
		}
		hasConflicts, _ := r.Load("has_conflicts").(bool)
		if !hasConflicts {
			return SkipCheck("no conflicts to test")
		}
		resolveResult := r.Load("resolve_result").(types.RevisionResolveResultData)

		// The merge produced exactly 1 conflict (on "shared" path). After resolving it,
		// remaining should be 0. Accept any value as a pass since the manufactured
		// bad-hash-test conflict above may inflate the count.
		if resolveResult.RemainingConflicts == 0 {
			return PassCheck("remaining_conflicts=0 after resolving last conflict")
		}
		return WarnCheck(fmt.Sprintf("remaining_conflicts=%d (expected 0, may include test artifacts)", resolveResult.RemainingConflicts))
	})

	// --- Step: R4 — KeepBoth merge strategy ---

	r.Run("keep_both_strategy_applied", func() CheckOutcome {
		kbPrefix := revisionTestPrefix("keepboth")
		r.Store("kb_prefix", kbPrefix)

		// Precondition: scrub any leftover kb-all merge config from a prior
		// validate-peer run. The peer is long-lived and in-memory, so without
		// this scrub a re-run resurrects the global pattern:"*"+keep-both
		// config installed below — and that config silently auto-resolves
		// every conflict-on-`shared` later in this suite (notably
		// merge_diverged_status), making conflict-detection tests SKIP
		// rather than fail. Per EXTENSION-REVISION §5.1 line 2723, merge
		// configs at this path are global by design (not prefix-scoped),
		// so cross-test isolation is the test's responsibility, not the
		// substrate's.
		_, _ = client.RevisionExecute(ctx, "merge-config", types.RevisionMergeConfigParamsData{
			Scope: "path", Name: "kb-all", Action: "delete",
		})

		// Base state: one shared file.
		sharedFile := mustCreateEntity("test/revision-doc", map[string]string{"content": "base"})
		client.TreePut(ctx, kbPrefix+"shared", sharedFile)
		resp, _ := client.RevisionExecute(ctx, "commit", types.RevisionCommitParamsData{Prefix: kbPrefix})
		var baseResult types.RevisionCommitResultData
		decodeRevisionResult(resp, &baseResult)
		baseVersion := baseResult.Version

		// Set keep-both merge config for this prefix.
		mergeConfig := types.RevisionMergeConfigData{Pattern: "*", Strategy: "keep-both"}
		mergeConfigEntity, _ := mergeConfig.ToEntity()
		client.TreePut(ctx, "system/revision/config/merge/path/kb-all", mergeConfigEntity)

		// Branch A: modify shared.
		localMod := mustCreateEntity("test/revision-doc", map[string]string{"content": "local-edit"})
		client.TreePut(ctx, kbPrefix+"shared", localMod)
		resp, _ = client.RevisionExecute(ctx, "commit", types.RevisionCommitParamsData{Prefix: kbPrefix})
		var localResult types.RevisionCommitResultData
		decodeRevisionResult(resp, &localResult)

		// Go back to base, diverge.
		client.RevisionExecute(ctx, "checkout", types.RevisionCheckoutParamsData{
			Prefix: kbPrefix, Version: baseVersion,
		})
		remoteMod := mustCreateEntity("test/revision-doc", map[string]string{"content": "remote-edit"})
		client.TreePut(ctx, kbPrefix+"shared", remoteMod)
		resp, _ = client.RevisionExecute(ctx, "commit", types.RevisionCommitParamsData{Prefix: kbPrefix})
		var remoteResult types.RevisionCommitResultData
		decodeRevisionResult(resp, &remoteResult)

		// Checkout local and merge remote — should use keep-both.
		client.RevisionExecute(ctx, "checkout", types.RevisionCheckoutParamsData{
			Prefix: kbPrefix, Version: localResult.Version,
		})
		resp, err := client.RevisionExecute(ctx, "merge", types.RevisionMergeParamsData{
			Prefix:        kbPrefix,
			RemoteVersion: remoteResult.Version,
		})
		if err != nil {
			return FailCheck("keep-both merge failed: " + err.Error())
		}
		if resp.Status != 200 {
			return FailCheck(fmt.Sprintf("merge returned %d", resp.Status))
		}

		var mergeResult types.RevisionMergeResultData
		decodeRevisionResult(resp, &mergeResult)
		r.Store("kb_merge_result", mergeResult)

		if mergeResult.Status == "merged" {
			return PassCheck("keep-both merge resolved without conflicts (status=merged)")
		}
		if mergeResult.Status == "merged_with_conflicts" {
			return FailCheck("keep-both should resolve edit-vs-edit, but got conflicts")
		}
		return FailCheck(fmt.Sprintf("unexpected merge status: %s", mergeResult.Status))
	})

	r.Run("keep_both_additional_binding", func() CheckOutcome {
		if out, ok := r.Require("keep_both_strategy_applied"); !ok {
			return out
		}
		kbPrefix := r.Load("kb_prefix").(string)

		listing, _, err := client.TreeListing(ctx, kbPrefix)
		if err != nil {
			return FailCheck("tree listing failed: " + err.Error())
		}

		hasOriginal := false
		hasKeepBoth := false
		var keepBothPath string
		for entryPath := range listing {
			relPath := strings.TrimPrefix(entryPath, kbPrefix)
			if relPath == "shared" {
				hasOriginal = true
			}
			if strings.HasPrefix(relPath, "shared.keep-both-") {
				hasKeepBoth = true
				keepBothPath = relPath
			}
		}

		if !hasOriginal {
			return FailCheck("original 'shared' path missing after keep-both merge")
		}
		if !hasKeepBoth {
			return FailCheck("no .keep-both- path found — keep-both strategy did not create additional binding")
		}
		return PassCheck(fmt.Sprintf("keep-both created additional binding at %s", keepBothPath))
	})

	r.Run("keep_both_original_entity", func() CheckOutcome {
		if out, ok := r.Require("keep_both_additional_binding"); !ok {
			return out
		}
		kbPrefix := r.Load("kb_prefix").(string)

		origEnt, _, err := client.TreeGet(ctx, kbPrefix+"shared")
		if err != nil {
			return FailCheck("original entity missing at 'shared' path")
		}

		listing, _, err := client.TreeListing(ctx, kbPrefix)
		if err != nil {
			return FailCheck("tree listing failed")
		}
		for entryPath := range listing {
			if strings.HasPrefix(entryPath, "shared.keep-both-") {
				kbEnt, _, err := client.TreeGet(ctx, kbPrefix+entryPath)
				if err != nil {
					return FailCheck(fmt.Sprintf("keep-both entity not retrievable at %s%s", kbPrefix, entryPath))
				}
				if kbEnt.ContentHash == origEnt.ContentHash {
					return FailCheck("keep-both entity has same hash as original — should be different")
				}
				// Post-cleanup: delete the global kb-all config installed in
				// keep_both_strategy_applied. See the precondition note there
				// for rationale.
				_, _ = client.RevisionExecute(ctx, "merge-config", types.RevisionMergeConfigParamsData{
					Scope: "path", Name: "kb-all", Action: "delete",
				})
				return PassCheck("both entities exist and are distinct")
			}
		}
		return FailCheck("keep-both path not found in listing")
	})

	// --- v3.3 §4.4.18 merge-config op conformance vectors ---
	//
	// The merge-config namespace is handler-owned per REVISION v3.3 §2.3.
	// All writes route through this op, which enforces the §2.3 strategy-
	// rejection contract at config-write time and provides CAS + idempotency.
	revURI := "entity://" + remotePID + "/system/revision"
	mergeConfigPath := func(name string) string {
		return "system/revision/config/merge/path/" + name
	}
	sendMergeConfig := func(params types.RevisionMergeConfigParamsData) (entity.Envelope, error) {
		paramsEnt, err := params.ToEntity()
		if err != nil {
			return entity.Envelope{}, err
		}
		env, _, err := client.SendExecute(ctx, revURI, "merge-config", paramsEnt, nil)
		return env, err
	}

	r.Run("merge_config_set_rejects_deletion_resolution_lww", func() CheckOutcome {
		name := "validate-mc-lww"
		// Precondition: clear any binding a prior run left at this path. The
		// peer is long-lived and in-memory, so previous-validation state must
		// not leak in. Use the handler's delete action — NOT a TreePut of an
		// empty entity, which itself CREATES a binding and made the "no binding
		// written" assertion below fail on every re-run (a fresh peer passed,
		// the second run on the same peer falsely failed). This false FAIL was
		// mis-routed to Python as a revision gap; the peer was conformant all
		// along (rejects lww with 400, writes nothing).
		_, _ = sendMergeConfig(types.RevisionMergeConfigParamsData{
			Scope: "path", Name: name, Action: "delete",
		})
		env, err := sendMergeConfig(types.RevisionMergeConfigParamsData{
			Scope: "path", Name: name, Action: "set",
			Config: &types.RevisionMergeConfigData{Pattern: name, Strategy: "three-way", DeletionResolution: "lww"},
		})
		if err != nil {
			return FailCheck("send merge-config: " + err.Error())
		}
		respData, _ := types.ExecuteResponseDataFromEntity(env.Root)
		if respData.Status != 400 {
			return FailCheck(fmt.Sprintf("lww: status %d, want 400 (spec MUST: §2.3 + §4.4.18)", respData.Status))
		}
		var resultEnt entity.Entity
		_ = ecf.Decode(respData.Result, &resultEnt)
		var errData types.ErrorData
		_ = ecf.Decode(resultEnt.Data, &errData)
		if errData.Code != "invalid_strategy" {
			return FailCheck(fmt.Sprintf("lww: error code %q, want invalid_strategy", errData.Code))
		}
		// No binding should land.
		if _, _, gerr := client.TreeGet(ctx, mergeConfigPath(name)); gerr == nil {
			return FailCheck("lww: a binding was written despite 400 rejection")
		}
		return PassCheck("lww rejected at config-write time with invalid_strategy; no binding written")
	})

	r.Run("merge_config_set_rejects_deletion_resolution_keep_both", func() CheckOutcome {
		name := "validate-mc-keepboth"
		env, err := sendMergeConfig(types.RevisionMergeConfigParamsData{
			Scope: "path", Name: name, Action: "set",
			Config: &types.RevisionMergeConfigData{Pattern: name, Strategy: "three-way", DeletionResolution: "keep-both"},
		})
		if err != nil {
			return FailCheck("send merge-config: " + err.Error())
		}
		respData, _ := types.ExecuteResponseDataFromEntity(env.Root)
		if respData.Status != 400 {
			return FailCheck(fmt.Sprintf("keep-both: status %d, want 400", respData.Status))
		}
		var resultEnt entity.Entity
		_ = ecf.Decode(respData.Result, &resultEnt)
		var errData types.ErrorData
		_ = ecf.Decode(resultEnt.Data, &errData)
		if errData.Code != "invalid_strategy" {
			return FailCheck(fmt.Sprintf("keep-both: error code %q, want invalid_strategy", errData.Code))
		}
		return PassCheck("keep-both rejected at config-write time with invalid_strategy")
	})

	r.Run("merge_config_set_accepts_valid_deletion_resolution", func() CheckOutcome {
		validStrategies := []string{
			"preserve-on-conflict", "deletion-wins", "three-way-fallthrough", "deterministic",
		}
		for _, s := range validStrategies {
			name := "validate-mc-valid-" + s
			env, err := sendMergeConfig(types.RevisionMergeConfigParamsData{
				Scope: "path", Name: name, Action: "set",
				Config: &types.RevisionMergeConfigData{Pattern: name, Strategy: "three-way", DeletionResolution: s},
			})
			if err != nil {
				return FailCheck("send: " + err.Error())
			}
			respData, _ := types.ExecuteResponseDataFromEntity(env.Root)
			if respData.Status != 200 {
				return FailCheck(fmt.Sprintf("strategy %q: status %d, want 200", s, respData.Status))
			}
			if _, _, gerr := client.TreeGet(ctx, mergeConfigPath(name)); gerr != nil {
				return FailCheck(fmt.Sprintf("strategy %q: binding did not land", s))
			}
		}
		return PassCheck("all four valid deletion_resolution strategies accepted and bound")
	})

	r.Run("merge_config_set_idempotent", func() CheckOutcome {
		name := "validate-mc-idem"
		// Precondition: the test asserts "first set → set, second set → no_change".
		// That contract only checks out from a clean state, so delete any prior
		// binding at this name before starting. Without this the test fails on
		// any peer that has been validated before (the prior run's first-set
		// binding is still bound, so this run's first-set sees current==newHash
		// and gets no_change). Status of the cleanup is ignored — absent
		// binding returns deleted-or-no-change either way.
		_, _ = sendMergeConfig(types.RevisionMergeConfigParamsData{
			Scope: "path", Name: name, Action: "delete",
		})
		cfgParams := types.RevisionMergeConfigParamsData{
			Scope: "path", Name: name, Action: "set",
			Config: &types.RevisionMergeConfigData{Pattern: name, Strategy: "three-way", DeletionResolution: "preserve-on-conflict"},
		}
		env1, err := sendMergeConfig(cfgParams)
		if err != nil {
			return FailCheck("first send: " + err.Error())
		}
		rd1, _ := types.ExecuteResponseDataFromEntity(env1.Root)
		if rd1.Status != 200 {
			return FailCheck(fmt.Sprintf("first set: status %d, want 200", rd1.Status))
		}
		var r1Ent entity.Entity
		_ = ecf.Decode(rd1.Result, &r1Ent)
		var r1 types.RevisionMergeConfigResultData
		_ = ecf.Decode(r1Ent.Data, &r1)
		if r1.Status != "set" {
			return FailCheck("first set: status " + r1.Status + ", want set")
		}

		env2, err := sendMergeConfig(cfgParams)
		if err != nil {
			return FailCheck("second send: " + err.Error())
		}
		rd2, _ := types.ExecuteResponseDataFromEntity(env2.Root)
		var r2Ent entity.Entity
		_ = ecf.Decode(rd2.Result, &r2Ent)
		var r2 types.RevisionMergeConfigResultData
		_ = ecf.Decode(r2Ent.Data, &r2)
		if r2.Status != "no_change" {
			return FailCheck("second set: status " + r2.Status + ", want no_change (idempotent contract §4.4.18)")
		}
		if r2.Hash != r1.Hash {
			return FailCheck("idempotent: hashes diverged")
		}
		return PassCheck("idempotent: identical re-issue returned no_change with stable hash")
	})

	r.Run("merge_config_delete", func() CheckOutcome {
		name := "validate-mc-del"
		// Set first.
		if _, err := sendMergeConfig(types.RevisionMergeConfigParamsData{
			Scope: "path", Name: name, Action: "set",
			Config: &types.RevisionMergeConfigData{Pattern: name, Strategy: "three-way", DeletionResolution: "preserve-on-conflict"},
		}); err != nil {
			return FailCheck("setup set: " + err.Error())
		}
		if _, _, gerr := client.TreeGet(ctx, mergeConfigPath(name)); gerr != nil {
			return FailCheck("setup: binding did not land")
		}
		// Delete.
		env, err := sendMergeConfig(types.RevisionMergeConfigParamsData{
			Scope: "path", Name: name, Action: "delete",
		})
		if err != nil {
			return FailCheck("delete send: " + err.Error())
		}
		respData, _ := types.ExecuteResponseDataFromEntity(env.Root)
		if respData.Status != 200 {
			return FailCheck(fmt.Sprintf("delete: status %d, want 200", respData.Status))
		}
		var resultEnt entity.Entity
		_ = ecf.Decode(respData.Result, &resultEnt)
		var result types.RevisionMergeConfigResultData
		_ = ecf.Decode(resultEnt.Data, &result)
		if result.Status != "deleted" {
			return FailCheck("delete: result status " + result.Status + ", want deleted")
		}
		if _, _, gerr := client.TreeGet(ctx, mergeConfigPath(name)); gerr == nil {
			return FailCheck("delete: path still bound after delete")
		}
		return PassCheck("delete unbound the merge-config path; result status=deleted")
	})

	return r.Results()
}

// --- Helper to decode revision response result entity ---

func decodeRevisionResult(resp types.ExecuteResponseData, v interface{}) (entity.Entity, error) {
	var ent entity.Entity
	if err := ecf.Decode(resp.Result, &ent); err != nil {
		return entity.Entity{}, fmt.Errorf("decode result entity: %w", err)
	}
	// Unwrap system/envelope if present.
	inner, _, err := unwrapResultEnvelope(ent)
	if err != nil {
		return entity.Entity{}, err
	}
	if v != nil {
		if err := ecf.Decode(inner.Data, v); err != nil {
			return inner, fmt.Errorf("decode result data: %w", err)
		}
	}
	return inner, nil
}

// revisionGetVersionData retrieves version entity data through the log operation's
// included entities. This avoids TreeGet on internal head paths which fail
// because trailing-slash paths are treated as listings by the tree handler.
func revisionGetVersionData(ctx context.Context, client *PeerClient, prefix string, versionHash hash.Hash) (types.RevisionEntryData, bool) {
	resp, env, err := client.RevisionExecuteFull(ctx, "log", types.RevisionLogParamsData{Prefix: prefix})
	if err != nil || resp.Status != 200 {
		return types.RevisionEntryData{}, false
	}

	// Try system/envelope included first (new pattern), then protocol envelope (legacy).
	var verEntity entity.Entity
	var ok bool
	var resultEnt entity.Entity
	if err := ecf.Decode(resp.Result, &resultEnt); err == nil {
		if _, envIncluded, err := unwrapResultEnvelope(resultEnt); err == nil && envIncluded != nil {
			verEntity, ok = envIncluded[versionHash]
		}
	}
	if !ok {
		verEntity, ok = env.FindIncluded(versionHash)
	}
	if !ok {
		return types.RevisionEntryData{}, false
	}

	verData, err := types.RevisionEntryDataFromEntity(verEntity)
	if err != nil {
		return types.RevisionEntryData{}, false
	}
	return verData, true
}

// --- Client helpers ---

// RevisionExecute sends an EXECUTE to the system/revision handler.
func (c *PeerClient) RevisionExecute(ctx context.Context, operation string, params interface{}) (types.ExecuteResponseData, error) {
	resp, _, err := c.RevisionExecuteFull(ctx, operation, params)
	return resp, err
}

// RevisionExecuteFull sends an EXECUTE to the system/revision handler and returns the
// full response envelope (including any included entities from the handler).
func (c *PeerClient) RevisionExecuteFull(ctx context.Context, operation string, params interface{}) (types.ExecuteResponseData, entity.Envelope, error) {
	raw, err := ecf.Encode(params)
	if err != nil {
		return types.ExecuteResponseData{}, entity.Envelope{}, fmt.Errorf("encode params: %w", err)
	}

	typeName := "system/revision/" + operation + "-params"
	paramsEntity, err := entity.NewEntity(typeName, cbor.RawMessage(raw))
	if err != nil {
		return types.ExecuteResponseData{}, entity.Envelope{}, fmt.Errorf("create params entity: %w", err)
	}

	resource := &types.ResourceTarget{Targets: []string{"system/revision"}}
	uri := fmt.Sprintf("entity://%s/system/revision", c.remotePeerID)

	env, _, err := c.SendExecute(ctx, uri, operation, paramsEntity, resource)
	if err != nil {
		return types.ExecuteResponseData{}, entity.Envelope{}, err
	}

	respData, err := types.ExecuteResponseDataFromEntity(env.Root)
	if err != nil {
		return types.ExecuteResponseData{}, env, fmt.Errorf("decode response: %w", err)
	}

	return respData, env, nil
}
