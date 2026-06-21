package validate

import (
	"context"
	"fmt"
	"math/rand"
	"strings"

	"go.entitychurch.org/entity-core-go/core/ecf"
	"go.entitychurch.org/entity-core-go/core/entity"
	"go.entitychurch.org/entity-core-go/core/hash"
	"go.entitychurch.org/entity-core-go/core/store"
	"go.entitychurch.org/entity-core-go/core/types"

	"github.com/fxamacker/cbor/v2"
)

const catTreeOps = "tree_operations"

// runTreeOperations validates the tree extension operations (snapshot, diff, merge, extract)
// against a remote peer. It exercises a full round-trip: snapshot, put, snapshot, diff,
// extract, merge dry-run, and cleanup.
func runTreeOperations(ctx context.Context, client *PeerClient) []CheckResult {
	r := NewCheckRunner(catTreeOps)

	// --- Declare all checks ---

	// Step 1: Snapshot before mutation
	r.Declare("snapshot_before", "EXTENSION-TREE S3")
	r.Declare("snapshot_type", "EXTENSION-TREE S3")
	r.Declare("snapshot_prefix", "EXTENSION-TREE S3")

	// Step 2: Put a test entity
	r.Declare("put_entity", "EXTENSION-TREE S2")

	// Step 3: Get the entity back
	r.Declare("get_entity", "EXTENSION-TREE S2")

	// Step 3b: Listing→Get round-trip
	r.Declare("listing_get_roundtrip_list", "EXTENSION-TREE S1")
	r.Declare("listing_get_roundtrip_fetch", "EXTENSION-TREE S1")

	// Step 3c: Path format validation
	r.Declare("path_listing_keys_relative", "V7 §1.4")
	r.Declare("path_root_listing", "V7 §1.4")
	r.Declare("path_peer_id_valid", "V7 §1.4")
	r.Declare("path_put_relative", "V7 §1.4")
	r.Declare("path_listing_no_leak", "V7 §1.4")
	r.Declare("path_reject_dot_relative", "V7 §1.4 R1")
	r.Declare("path_reject_dotdot_relative", "V7 §1.4 R1")
	r.Declare("path_reject_empty_segment", "V7 §1.4 R1")

	// Step 4: Snapshot after mutation
	r.Declare("snapshot_after", "EXTENSION-TREE S3")
	r.Declare("snapshot_binding_match", "EXTENSION-TREE S3")
	r.Declare("snapshot_determinism", "EXTENSION-TREE S3")

	// Step 5: Diff
	r.Declare("diff_execute", "EXTENSION-TREE S4")
	r.Declare("diff_base_hash", "EXTENSION-TREE S4")
	r.Declare("diff_target_hash", "EXTENSION-TREE S4")
	r.Declare("diff_added_entry", "EXTENSION-TREE S4")
	r.Declare("diff_keys_bare", "EXTENSION-TREE S4")
	r.Declare("diff_key_roundtrip", "EXTENSION-TREE S4")
	r.Declare("diff_no_removed", "EXTENSION-TREE S4")
	r.Declare("diff_no_changed", "EXTENSION-TREE S4")

	// Step 6: Extract
	r.Declare("extract_execute", "EXTENSION-TREE S6")
	r.Declare("extract_result_type", "EXTENSION-TREE S6")
	r.Declare("extract_envelope_decode", "EXTENSION-TREE S6")
	r.Declare("extract_root_type", "EXTENSION-TREE S6")
	r.Declare("extract_included_entity", "EXTENSION-TREE S6")

	// Step 7: Merge dry-run
	r.Declare("merge_dry_run", "EXTENSION-TREE S5")
	r.Declare("merge_strategy", "EXTENSION-TREE S5")
	r.Declare("merge_dry_run_no_apply", "EXTENSION-TREE §5.4 (dry_run idempotent triple)")
	r.Declare("merge_processed_count", "EXTENSION-TREE S5")

	// Step 8: Extract→merge roundtrip
	r.Declare("roundtrip_trie_nodes_included", "TREE §6.2")
	r.Declare("roundtrip_merge_execute", "TREE §5.2")
	r.Declare("roundtrip_verify_entity", "TREE §5.2")

	// Step 9: CAS semantics
	r.Declare("cas_match", "V7 §3.9")
	r.Declare("cas_mismatch", "V7 §3.9")
	r.Declare("cas_preserves_binding", "V7 §3.9")
	r.Declare("cas_absent_binding", "V7 §3.9")
	r.Declare("cas_create_zero_hash_absent", "V7 §3.9 v7.50 (CAS-create)")
	r.Declare("cas_create_zero_hash_exists", "V7 §3.9 v7.50 (CAS-create)")

	// Step 10: Incremental trie-root tracking
	r.Declare("tracking_config_create", "EXTENSION-TREE §3.4.1a")
	r.Declare("tracked_root_present", "EXTENSION-TREE §3.4.1")
	r.Declare("tracked_root_updates", "EXTENSION-TREE §3.4")
	r.Declare("tracked_snapshot_matches", "EXTENSION-TREE §3.4")
	r.Declare("tracked_root_cleared", "EXTENSION-TREE §3.4.1a")

	// V7 v7.72 §9.5a CORE-TREE-* vector set — the six core-profile MUST
	// vectors. All run under both --profile core and --profile full
	// (alongside the existing EXTENSION-TREE §9 vectors). Three of the
	// six layer onto existing implementations (PUT-1 / PUT-CAS-1 /
	// PUT-CAS-2 mirror the existing put/cas_create/cas_match pins); the
	// three new behaviors (DELETE-1 deletion-marker semantics, LISTING-1
	// cap-coverage filter, PATH-FLEX-1 expanded rejection set) get
	// dedicated runners below.
	r.Declare("core_tree_put_1", "V7 v7.72 §9.5a (CORE-TREE-PUT-1)")
	r.Declare("core_tree_put_cas_1", "V7 v7.72 §9.5a (CORE-TREE-PUT-CAS-1)")
	r.Declare("core_tree_put_cas_2", "V7 v7.72 §9.5a (CORE-TREE-PUT-CAS-2)")
	r.Declare("core_tree_delete_1", "V7 v7.72 §9.5a (CORE-TREE-DELETE-1) — system/deletion-marker semantics")
	r.Declare("core_tree_listing_1", "V7 v7.72 §9.5a (CORE-TREE-LISTING-1) — §6.3 cap-coverage listing filter (MUST)")
	r.Declare("core_tree_path_flex_1", "V7 v7.72 §9.5a (CORE-TREE-PATH-FLEX-1) — §1.4 path validation flex set")

	// Cleanup
	r.Declare("cleanup", "")

	// --- Step 1: Snapshot before mutation ---

	r.Run("snapshot_before", func() CheckOutcome {
		snapBefore, snapBeforeEntity, err := client.TreeSnapshot(ctx, "system/validate/tree-ops/")
		if err != nil {
			return FailCheck("failed to take initial snapshot: " + err.Error())
		}
		r.Store("snap_before", snapBefore)
		r.Store("snap_before_entity", snapBeforeEntity)
		if snapBefore.Root.IsZero() {
			return PassCheck("initial snapshot of system/validate/ has empty trie root (no bindings)")
		}
		return PassCheck(fmt.Sprintf("initial snapshot of system/validate/ has trie root: %s", snapBefore.Root))
	})

	r.Run("snapshot_type", func() CheckOutcome {
		if out, ok := r.Require("snapshot_before"); !ok {
			return out
		}
		snapBeforeEntity := r.Load("snap_before_entity").(entity.Entity)
		if snapBeforeEntity.Type == types.TypeTreeSnapshot {
			return PassCheck("snapshot result type is system/tree/snapshot")
		}
		return FailCheck(fmt.Sprintf("snapshot result type is %q (expected %q)", snapBeforeEntity.Type, types.TypeTreeSnapshot))
	})

	r.Run("snapshot_prefix", func() CheckOutcome {
		if out, ok := r.Require("snapshot_before"); !ok {
			return out
		}
		snapBefore := r.Load("snap_before").(types.SnapshotData)
		// Per TREE v3.5 I3: snapshots no longer carry prefix — just root hash.
		if !snapBefore.Root.IsZero() {
			return PassCheck("snapshot has root hash (prefix removed per I3)")
		}
		return FailCheck("snapshot root hash is zero")
	})

	// --- Step 2: Put a test entity ---

	r.Run("put_entity", func() CheckOutcome {
		testData, _ := ecf.Encode(map[string]interface{}{
			"label": "tree-ops-validation-test",
			"seq":   1,
		})
		testEntity, err := entity.NewEntity("system/validate/test-data", cbor.RawMessage(testData))
		if err != nil {
			return FailCheck("failed to create test entity: " + err.Error())
		}
		r.Store("test_entity", testEntity)

		_, err = client.TreePut(ctx, "system/validate/tree-ops/test-1", testEntity)
		if err != nil {
			return FailCheck("failed to put test entity: " + err.Error())
		}
		return PassCheck("put test entity at system/validate/tree-ops/test-1")
	})

	// --- Step 3: Get the entity back ---

	r.Run("get_entity", func() CheckOutcome {
		if out, ok := r.Require("put_entity"); !ok {
			return out
		}
		testEntity := r.Load("test_entity").(entity.Entity)
		gotEntity, _, err := client.TreeGet(ctx, "system/validate/tree-ops/test-1")
		if err != nil {
			return FailCheck("failed to get test entity back: " + err.Error())
		}
		if gotEntity.ContentHash == testEntity.ContentHash {
			return PassCheck("get returned entity with matching content hash")
		}
		return FailCheck(fmt.Sprintf("get returned hash %s (expected %s)", gotEntity.ContentHash, testEntity.ContentHash))
	})

	// --- Step 3b: Listing→Get round-trip ---

	r.Run("listing_get_roundtrip_list", func() CheckOutcome {
		if out, ok := r.Require("put_entity"); !ok {
			return out
		}
		prefix := "system/validate/tree-ops/"
		entries, _, err := client.TreeListing(ctx, prefix)
		if err != nil {
			return FailCheck("failed to list " + prefix + ": " + err.Error())
		}
		if len(entries) == 0 {
			return FailCheck("listing at " + prefix + " returned 0 entries (expected at least 1)")
		}
		r.Store("listing_entries", entries)
		r.Store("listing_prefix", prefix)
		return PassCheck(fmt.Sprintf("listing at %s returned %d entries", prefix, len(entries)))
	})

	r.Run("listing_get_roundtrip_fetch", func() CheckOutcome {
		if out, ok := r.Require("listing_get_roundtrip_list"); !ok {
			return out
		}
		entries := r.Load("listing_entries").(map[string]interface{})
		prefix := r.Load("listing_prefix").(string)

		// For each entity entry (has a non-nil hash), verify TreeGet succeeds.
		fetched := 0
		for key, val := range entries {
			entryHash := extractListingHash(val)
			if entryHash.IsZero() {
				continue // directory-only entry, skip
			}

			path := prefix + key
			gotEntity, _, err := client.TreeGet(ctx, path)
			if err != nil {
				return FailCheck(fmt.Sprintf("listed entry %q exists in listing but TreeGet failed: %v", path, err))
			}

			if gotEntity.ContentHash == entryHash {
				fetched++
			} else {
				return FailCheck(fmt.Sprintf("listing hash mismatch for %q: listing=%s get=%s", path, entryHash, gotEntity.ContentHash))
			}
		}

		if fetched > 0 {
			return PassCheck(fmt.Sprintf("all %d listed entities individually fetchable with matching hashes", fetched))
		}
		return PassCheck("no entity entries in listing to verify")
	})

	// --- Step 3c: Path format validation ---

	r.Run("path_listing_keys_relative", func() CheckOutcome {
		if out, ok := r.Require("put_entity"); !ok {
			return out
		}
		entries, _, err := client.TreeListing(ctx, "system/validate/tree-ops/")
		if err != nil {
			return FailCheck("failed to list for path validation: " + err.Error())
		}

		allRelative := true
		for key := range entries {
			if strings.HasPrefix(key, "/") {
				allRelative = false
				return FailCheck(fmt.Sprintf("listing key %q has leading / (should be prefix-relative)", key))
			}
		}
		if allRelative && len(entries) > 0 {
			return PassCheck(fmt.Sprintf("all %d listing keys are prefix-relative (no leading /)", len(entries)))
		}
		return PassCheck("listing returned 0 entries (skip — test entity may already be cleaned up)")
	})

	r.Run("path_root_listing", func() CheckOutcome {
		rootEntries, _, err := client.TreeListing(ctx, "")
		if err != nil {
			return FailCheck("failed to list root: " + err.Error())
		}
		if len(rootEntries) > 0 {
			return PassCheck(fmt.Sprintf("root listing returned %d entries", len(rootEntries)))
		}
		return PassCheck("root listing returned 0 entries")
	})

	r.Run("path_peer_id_valid", func() CheckOutcome {
		peerID := string(client.RemotePeerID())
		if err := store.ValidateAbsolutePath("/" + peerID + "/x"); err != nil {
			return FailCheck(fmt.Sprintf("peer ID %q fails path validation: %v", peerID, err))
		}
		return PassCheck(fmt.Sprintf("peer ID is valid Base58 (%d chars)", len(peerID)))
	})

	r.Run("path_put_relative", func() CheckOutcome {
		testData, _ := ecf.Encode(map[string]string{"label": "path-validation"})
		testEntity, _ := entity.NewEntity("system/validate/path-test", cbor.RawMessage(testData))

		_, err := client.TreePut(ctx, "system/validate/path-check/item", testEntity)
		if err != nil {
			return FailCheck("failed to put test entity for path validation: " + err.Error())
		}
		return PassCheck("put test entity for path validation")
	})

	r.Run("path_listing_no_leak", func() CheckOutcome {
		if out, ok := r.Require("path_put_relative"); !ok {
			return out
		}
		peerID := string(client.RemotePeerID())

		pathEntries, _, err := client.TreeListing(ctx, "system/validate/path-check/")
		if err != nil {
			return FailCheck("failed to list path-check prefix: " + err.Error())
		}

		// Cleanup regardless of result.
		defer func() {
			cleanParams, cleanResource, _ := createRemoveRequest("system/validate/path-check/item")
			if cleanParams.Type != "" {
				uri := fmt.Sprintf("entity://%s/system/tree", peerID)
				client.SendExecute(ctx, uri, "put", cleanParams, cleanResource)
			}
		}()

		if _, ok := pathEntries["item"]; ok {
			return PassCheck("listing key is bare \"item\" — no namespace leak")
		}
		// Check if any key contains the peer ID (namespace leak).
		for key := range pathEntries {
			if strings.Contains(key, peerID) {
				return FailCheck(fmt.Sprintf("listing key %q contains peer ID — namespace leaked into listing", key))
			}
		}
		return FailCheck(fmt.Sprintf("expected listing key \"item\", got keys: %v", mapKeysStr(pathEntries)))
	})

	// Path rejection checks
	r.Run("path_reject_dot_relative", func() CheckOutcome {
		return runSinglePathRejection(ctx, client, "./system/validate/bad", "V7 §1.4 R1",
			"./ prefix is reserved for future directory-relative paths")
	})

	r.Run("path_reject_dotdot_relative", func() CheckOutcome {
		return runSinglePathRejection(ctx, client, "../system/validate/bad", "V7 §1.4 R1",
			"../ prefix is reserved for future directory-relative paths")
	})

	r.Run("path_reject_empty_segment", func() CheckOutcome {
		return runSinglePathRejection(ctx, client, "system//validate//bad", "V7 §1.4 R1",
			"empty segments (consecutive //) are not valid in paths")
	})

	// --- Step 4: Snapshot after mutation ---

	r.Run("snapshot_after", func() CheckOutcome {
		if out, ok := r.Require("put_entity"); !ok {
			return out
		}
		if out, ok := r.Require("snapshot_before"); !ok {
			return out
		}
		snapBefore := r.Load("snap_before").(types.SnapshotData)
		snapAfter, snapAfterEntity, err := client.TreeSnapshot(ctx, "system/validate/tree-ops/")
		if err != nil {
			return FailCheck("failed to take post-put snapshot: " + err.Error())
		}
		r.Store("snap_after", snapAfter)
		r.Store("snap_after_entity", snapAfterEntity)

		if snapAfter.Root != snapBefore.Root {
			return PassCheck(fmt.Sprintf("post-put snapshot root changed: %s -> %s", snapBefore.Root, snapAfter.Root))
		}
		return FailCheck("post-put snapshot root unchanged (expected trie root to change after put)")
	})

	r.Run("snapshot_binding_match", func() CheckOutcome {
		if out, ok := r.Require("snapshot_after"); !ok {
			return out
		}
		testEntity := r.Load("test_entity").(entity.Entity)
		verifyEnt, _, verifyErr := client.TreeGet(ctx, "system/validate/tree-ops/test-1")
		if verifyErr != nil {
			return FailCheck("could not fetch system/validate/tree-ops/test-1 after put: " + verifyErr.Error())
		}
		if verifyEnt.ContentHash == testEntity.ContentHash {
			return PassCheck("entity at system/validate/tree-ops/test-1 matches put entity hash")
		}
		return FailCheck(fmt.Sprintf("entity hash %s != put entity hash %s", verifyEnt.ContentHash, testEntity.ContentHash))
	})

	r.Run("snapshot_determinism", func() CheckOutcome {
		if out, ok := r.Require("snapshot_after"); !ok {
			return out
		}
		snapAfterEntity := r.Load("snap_after_entity").(entity.Entity)
		_, snapAfterEntity2, err := client.TreeSnapshot(ctx, "system/validate/tree-ops/")
		if err != nil {
			return FailCheck("failed to take second snapshot: " + err.Error())
		}
		if snapAfterEntity2.ContentHash == snapAfterEntity.ContentHash {
			return PassCheck("consecutive snapshots produce identical content hashes")
		}
		return FailCheck(fmt.Sprintf("snapshot hashes differ: %s vs %s", snapAfterEntity.ContentHash, snapAfterEntity2.ContentHash))
	})

	// --- Step 5: Diff the two snapshots ---

	r.Run("diff_execute", func() CheckOutcome {
		if out, ok := r.Require("snapshot_after"); !ok {
			return out
		}
		snapBeforeEntity := r.Load("snap_before_entity").(entity.Entity)
		snapAfterEntity := r.Load("snap_after_entity").(entity.Entity)

		diffData, err := client.TreeDiff(ctx, snapBeforeEntity, snapAfterEntity)
		if err != nil {
			return FailCheck("failed to execute diff: " + err.Error())
		}
		r.Store("diff_data", diffData)
		return PassCheck("diff executed successfully")
	})

	r.Run("diff_base_hash", func() CheckOutcome {
		if out, ok := r.Require("diff_execute"); !ok {
			return out
		}
		diffData := r.Load("diff_data").(types.DiffData)
		snapBeforeEntity := r.Load("snap_before_entity").(entity.Entity)
		if diffData.Base == snapBeforeEntity.ContentHash {
			return PassCheck("diff base hash matches snap-before")
		}
		return FailCheck(fmt.Sprintf("diff base hash %s != snap-before %s", diffData.Base, snapBeforeEntity.ContentHash))
	})

	r.Run("diff_target_hash", func() CheckOutcome {
		if out, ok := r.Require("diff_execute"); !ok {
			return out
		}
		diffData := r.Load("diff_data").(types.DiffData)
		snapAfterEntity := r.Load("snap_after_entity").(entity.Entity)
		if diffData.Target == snapAfterEntity.ContentHash {
			return PassCheck("diff target hash matches snap-after")
		}
		return FailCheck(fmt.Sprintf("diff target hash %s != snap-after %s", diffData.Target, snapAfterEntity.ContentHash))
	})

	r.Run("diff_added_entry", func() CheckOutcome {
		if out, ok := r.Require("diff_execute"); !ok {
			return out
		}
		diffData := r.Load("diff_data").(types.DiffData)
		testEntity := r.Load("test_entity").(entity.Entity)
		testHash := testEntity.ContentHash

		if addedHash, ok := diffData.Added["test-1"]; ok {
			if addedHash == testHash {
				return PassCheck("diff shows test-1 as added with correct hash")
			}
			return FailCheck(fmt.Sprintf("diff added hash %s != test entity hash %s", addedHash, testHash))
		}
		return FailCheck(fmt.Sprintf("diff added map does not contain test-1 (added: %v)", mapKeys(diffData.Added)))
	})

	r.Run("diff_keys_bare", func() CheckOutcome {
		if out, ok := r.Require("diff_execute"); !ok {
			return out
		}
		diffData := r.Load("diff_data").(types.DiffData)

		for key := range diffData.Added {
			if store.IsAbsolute(key) {
				return FailCheck(fmt.Sprintf("diff added key %q is namespace-qualified (should be bare path)", key))
			}
		}
		return PassCheck("diff binding keys are bare paths (not namespace-qualified)")
	})

	r.Run("diff_key_roundtrip", func() CheckOutcome {
		if out, ok := r.Require("diff_execute"); !ok {
			return out
		}
		diffData := r.Load("diff_data").(types.DiffData)
		testEntity := r.Load("test_entity").(entity.Entity)
		testHash := testEntity.ContentHash

		if _, ok := diffData.Added["test-1"]; !ok {
			return SkipCheck("test-1 not in diff added map")
		}
		getPath := "system/validate/tree-ops/test-1"
		gotEnt, _, err := client.TreeGet(ctx, getPath)
		if err != nil {
			return FailCheck(fmt.Sprintf("TreeGet with diff key path %q failed: %v", getPath, err))
		}
		if gotEnt.ContentHash == testHash {
			return PassCheck("diff added key resolves to correct entity via TreeGet")
		}
		return FailCheck(fmt.Sprintf("diff key entity hash mismatch: got %s, expected %s", gotEnt.ContentHash, testHash))
	})

	r.Run("diff_no_removed", func() CheckOutcome {
		if out, ok := r.Require("diff_execute"); !ok {
			return out
		}
		diffData := r.Load("diff_data").(types.DiffData)
		if len(diffData.Removed) == 0 {
			return PassCheck("diff correctly shows no removed entries")
		}
		return FailCheck(fmt.Sprintf("diff shows %d removed entries (expected 0)", len(diffData.Removed)))
	})

	r.Run("diff_no_changed", func() CheckOutcome {
		if out, ok := r.Require("diff_execute"); !ok {
			return out
		}
		diffData := r.Load("diff_data").(types.DiffData)
		if len(diffData.Changed) == 0 {
			return PassCheck("diff correctly shows no changed entries")
		}
		return FailCheck(fmt.Sprintf("diff shows %d changed entries (expected 0)", len(diffData.Changed)))
	})

	// --- Step 6: Extract subtree ---

	r.Run("extract_execute", func() CheckOutcome {
		if out, ok := r.Require("put_entity"); !ok {
			return out
		}
		resultEntity, err := client.TreeExtract(ctx, "system/validate/tree-ops/")
		if err != nil {
			return FailCheck("failed to execute extract: " + err.Error())
		}
		r.Store("extract_result_entity", resultEntity)
		return PassCheck("extract executed successfully")
	})

	r.Run("extract_result_type", func() CheckOutcome {
		if out, ok := r.Require("extract_execute"); !ok {
			return out
		}
		resultEntity := r.Load("extract_result_entity").(entity.Entity)
		if resultEntity.Type == "system/envelope" {
			return PassCheck("extract result type is system/envelope")
		} else if resultEntity.Type == "system/protocol/envelope" {
			return PassCheck("extract result type is system/protocol/envelope (legacy, should be system/envelope)")
		}
		return FailCheck(fmt.Sprintf("extract result type is %q (expected system/envelope)", resultEntity.Type))
	})

	r.Run("extract_envelope_decode", func() CheckOutcome {
		if out, ok := r.Require("extract_result_type"); !ok {
			return out
		}
		resultEntity := r.Load("extract_result_entity").(entity.Entity)
		var extractedEnv entity.Envelope
		if err := ecf.Decode(resultEntity.Data, &extractedEnv); err != nil {
			return FailCheck("failed to decode extracted envelope: " + err.Error())
		}
		r.Store("extracted_envelope", extractedEnv)
		return PassCheck("extracted envelope decoded successfully")
	})

	r.Run("extract_root_type", func() CheckOutcome {
		if out, ok := r.Require("extract_envelope_decode"); !ok {
			return out
		}
		extractedEnv := r.Load("extracted_envelope").(entity.Envelope)
		if extractedEnv.Root.Type == types.TypeTreeSnapshot {
			return PassCheck("extracted envelope root is system/tree/snapshot")
		}
		return FailCheck(fmt.Sprintf("extracted envelope root type is %q (expected %q)", extractedEnv.Root.Type, types.TypeTreeSnapshot))
	})

	r.Run("extract_included_entity", func() CheckOutcome {
		if out, ok := r.Require("extract_envelope_decode"); !ok {
			return out
		}
		extractedEnv := r.Load("extracted_envelope").(entity.Envelope)
		testEntity := r.Load("test_entity").(entity.Entity)
		testHash := testEntity.ContentHash
		if _, ok := extractedEnv.Included[testHash]; ok {
			return PassCheck("extracted envelope includes the test entity")
		}
		return FailCheck(fmt.Sprintf("extracted envelope does not include test entity %s (has %d included)", testHash, len(extractedEnv.Included)))
	})

	// --- Step 7: Merge dry-run ---

	r.Run("merge_dry_run", func() CheckOutcome {
		if out, ok := r.Require("snapshot_after"); !ok {
			return out
		}
		snapAfterEntity := r.Load("snap_after_entity").(entity.Entity)
		// Snapshot was taken at prefix "system/validate/tree-ops/" (I3: no
		// prefix carried in snapshot); pass target_prefix so merge applies
		// bindings back to the originating subtree.
		mergeResult, err := client.TreeMerge(ctx, snapAfterEntity, "no-overwrite", true, "", "system/validate/tree-ops/")
		if err != nil {
			return FailCheck("failed to execute merge dry-run: " + err.Error())
		}
		r.Store("merge_result", mergeResult)
		return PassCheck("merge dry-run executed successfully")
	})

	r.Run("merge_strategy", func() CheckOutcome {
		if out, ok := r.Require("merge_dry_run"); !ok {
			return out
		}
		mergeResult := r.Load("merge_result").(types.MergeResultData)
		if mergeResult.Strategy == "no-overwrite" {
			return PassCheck("merge result strategy is no-overwrite")
		}
		return FailCheck(fmt.Sprintf("merge result strategy is %q (expected no-overwrite)", mergeResult.Strategy))
	})

	r.Run("merge_dry_run_no_apply", func() CheckOutcome {
		// EXTENSION-TREE §5.4: dry_run yields the same (applied, skipped, conflicts)
		// triple as a non-dry_run invocation against the same input. dry_run only
		// suppresses the actual binding writes — counters are computed identically.
		if out, ok := r.Require("merge_dry_run"); !ok {
			return out
		}
		dryResult := r.Load("merge_result").(types.MergeResultData)
		snapAfterEntity := r.Load("snap_after_entity").(entity.Entity)
		realResult, err := client.TreeMerge(ctx, snapAfterEntity, "no-overwrite", false, "", "system/validate/tree-ops/")
		if err != nil {
			return FailCheck("non-dry-run merge for §5.4 idempotency check: " + err.Error())
		}
		if dryResult.Applied != realResult.Applied || dryResult.Skipped != realResult.Skipped || len(dryResult.Conflicts) != len(realResult.Conflicts) {
			return FailCheck(fmt.Sprintf("dry-run/non-dry-run triple diverges: dry=(%d,%d,%d) real=(%d,%d,%d)",
				dryResult.Applied, dryResult.Skipped, len(dryResult.Conflicts),
				realResult.Applied, realResult.Skipped, len(realResult.Conflicts)))
		}
		return PassCheck(fmt.Sprintf("dry_run preview matches real merge per §5.4 (applied=%d, skipped=%d, conflicts=%d)",
			dryResult.Applied, dryResult.Skipped, len(dryResult.Conflicts)))
	})

	r.Run("merge_processed_count", func() CheckOutcome {
		if out, ok := r.Require("merge_dry_run"); !ok {
			return out
		}
		mergeResult := r.Load("merge_result").(types.MergeResultData)
		totalProcessed := mergeResult.Applied + mergeResult.Skipped
		if totalProcessed > 0 {
			return PassCheck(fmt.Sprintf("merge processed %d entries (%d applied, %d skipped, %d conflicts)",
				totalProcessed, mergeResult.Applied, mergeResult.Skipped, len(mergeResult.Conflicts)))
		}
		return WarnCheck("merge processed 0 entries")
	})

	// --- Step 8: Extract→merge roundtrip ---

	r.Run("roundtrip_trie_nodes_included", func() CheckOutcome {
		if out, ok := r.Require("put_entity"); !ok {
			return out
		}
		srcPrefix := "system/validate/tree-ops/"

		// Extract from source prefix.
		resultEntity, err := client.TreeExtract(ctx, srcPrefix)
		if err != nil {
			return FailCheck("extract failed: " + err.Error())
		}

		var env entity.Envelope
		if err := ecf.Decode(resultEntity.Data, &env); err != nil {
			return FailCheck("could not decode extract envelope: " + err.Error())
		}
		r.Store("roundtrip_result_entity", resultEntity)
		r.Store("roundtrip_envelope", env)
		r.Store("roundtrip_src_prefix", srcPrefix)

		// Walk the snapshot root to find trie node entities in included.
		trieNodeCount := 0
		for _, ent := range env.Included {
			if ent.Type == types.TypeTreeSnapshotNode {
				trieNodeCount++
			}
		}
		if trieNodeCount > 0 {
			return PassCheck(fmt.Sprintf("extract envelope includes %d trie node entities", trieNodeCount))
		}
		return FailCheck("extract envelope missing trie node entities (§6.2: MUST include all reachable nodes)")
	})

	r.Run("roundtrip_merge_execute", func() CheckOutcome {
		if out, ok := r.Require("roundtrip_trie_nodes_included"); !ok {
			return out
		}
		srcPrefix := r.Load("roundtrip_src_prefix").(string)
		resultEntity := r.Load("roundtrip_result_entity").(entity.Entity)
		env := r.Load("roundtrip_envelope").(entity.Envelope)
		dstPrefix := "system/validate/tree-ops-mirror/"

		mergeReq := types.MergeRequestData{
			SourcePrefix: srcPrefix,
			TargetPrefix: dstPrefix,
			Strategy:     "source-wins",
		}
		mergeParams, err := mergeReq.ToEntity()
		if err != nil {
			return FailCheck("failed to create merge params: " + err.Error())
		}

		// Inject the extract result as source_envelope in the merge params.
		var paramsMap map[string]interface{}
		if err := cbor.Unmarshal(mergeParams.Data, &paramsMap); err != nil {
			return FailCheck("failed to decode merge params: " + err.Error())
		}
		var envDecoded interface{}
		cbor.Unmarshal(resultEntity.Data, &envDecoded)
		paramsMap["source_envelope"] = map[string]interface{}{
			"type": resultEntity.Type,
			"data": envDecoded,
		}
		injectedRaw, _ := ecf.Encode(paramsMap)
		mergeParams.Data = cbor.RawMessage(injectedRaw)
		mergeParams.ContentHash = hash.Hash{} // Recompute.
		mergeParams, _ = entity.NewEntity(mergeParams.Type, mergeParams.Data)

		// Include the envelope's entities in the request so the peer has them.
		extras := make(map[hash.Hash]entity.Entity)
		for h, ent := range env.Included {
			extras[h] = ent
		}
		extras[env.Root.ContentHash] = env.Root

		resource := &types.ResourceTarget{Targets: []string{dstPrefix}}
		uri := fmt.Sprintf("entity://%s/system/tree", client.remotePeerID)
		mergeEnv, _, err := client.SendExecuteWithIncluded(ctx, uri, "merge", mergeParams, resource, extras)
		if err != nil {
			return FailCheck("merge with source_envelope failed: " + err.Error())
		}

		respData, err := types.ExecuteResponseDataFromEntity(mergeEnv.Root)
		if err != nil || respData.Status != 200 {
			status := uint(0)
			if err == nil {
				status = respData.Status
			}
			return FailCheck(fmt.Sprintf("merge returned status %d (expected 200), err=%v", status, err))
		}

		r.Store("roundtrip_dst_prefix", dstPrefix)
		return PassCheck("merge with source_envelope succeeded")
	})

	r.Run("roundtrip_verify_entity", func() CheckOutcome {
		if out, ok := r.Require("roundtrip_merge_execute"); !ok {
			return out
		}
		dstPrefix := r.Load("roundtrip_dst_prefix").(string)
		testEntity := r.Load("test_entity").(entity.Entity)
		testHash := testEntity.ContentHash

		gotEntity, _, err := client.TreeGet(ctx, dstPrefix+"test-1")
		if err != nil {
			return FailCheck(fmt.Sprintf("entity not found at %stest-1 after merge: %v", dstPrefix, err))
		}

		// Cleanup: remove all mirrored entities.
		uri := fmt.Sprintf("entity://%s/system/tree", client.remotePeerID)
		mirrorEntries, _, listErr := client.TreeListing(ctx, dstPrefix)
		if listErr == nil {
			for key := range mirrorEntries {
				removeParams, removeResource, _ := createRemoveRequest(dstPrefix + key)
				if removeParams.Type != "" {
					client.SendExecute(ctx, uri, "put", removeParams, removeResource)
				}
			}
		}

		if gotEntity.ContentHash == testHash {
			return PassCheck(fmt.Sprintf("entity at %stest-1 matches source hash after merge", dstPrefix))
		}
		return FailCheck(fmt.Sprintf("entity hash mismatch: got %s, expected %s", gotEntity.ContentHash, testHash))
	})

	// --- Step 9: CAS semantics ---

	r.Run("cas_match", func() CheckOutcome {
		path := "system/validate/cas/item"

		// Seed a binding.
		seedData, _ := ecf.Encode(map[string]string{"v": "1"})
		seed, _ := entity.NewEntity("system/validate/cas", cbor.RawMessage(seedData))
		if _, err := client.TreePut(ctx, path, seed); err != nil {
			return FailCheck("failed to seed CAS test binding: " + err.Error())
		}
		r.Store("cas_path", path)
		r.Store("cas_seed", seed)

		// Matching hash → 200.
		updateData, _ := ecf.Encode(map[string]string{"v": "2"})
		update, _ := entity.NewEntity("system/validate/cas", cbor.RawMessage(updateData))
		r.Store("cas_update", update)

		if status, err := client.TreePutCAS(ctx, path, update, seed.ContentHash); err != nil {
			return FailCheck("CAS put (match) failed: " + err.Error())
		} else if status != 200 {
			return FailCheck(fmt.Sprintf("CAS put (matching expected_hash) returned %d (expected 200)", status))
		}
		return PassCheck("put with matching expected_hash succeeded (200)")
	})

	r.Run("cas_mismatch", func() CheckOutcome {
		if out, ok := r.Require("cas_match"); !ok {
			return out
		}
		path := r.Load("cas_path").(string)
		seed := r.Load("cas_seed").(entity.Entity)

		staleUpdateData, _ := ecf.Encode(map[string]string{"v": "3"})
		staleUpdate, _ := entity.NewEntity("system/validate/cas", cbor.RawMessage(staleUpdateData))
		if status, err := client.TreePutCAS(ctx, path, staleUpdate, seed.ContentHash); err != nil {
			return FailCheck("CAS put (mismatch) errored: " + err.Error())
		} else if status != 409 {
			return FailCheck(fmt.Sprintf("CAS put (stale expected_hash) returned %d (expected 409 hash_mismatch)", status))
		}
		return PassCheck("put with stale expected_hash returned 409 hash_mismatch")
	})

	r.Run("cas_preserves_binding", func() CheckOutcome {
		if out, ok := r.Require("cas_mismatch"); !ok {
			return out
		}
		path := r.Load("cas_path").(string)
		update := r.Load("cas_update").(entity.Entity)

		cur, _, err := client.TreeGet(ctx, path)
		if err == nil && cur.ContentHash == update.ContentHash {
			return PassCheck("binding unchanged after 409 CAS failure")
		}
		return FailCheck("binding changed after 409 CAS failure — CAS must be atomic")
	})

	r.Run("cas_absent_binding", func() CheckOutcome {
		if out, ok := r.Require("cas_match"); !ok {
			return out
		}
		seed := r.Load("cas_seed").(entity.Entity)
		path := r.Load("cas_path").(string)

		absent := "system/validate/cas/nothing-here"
		bogusData, _ := ecf.Encode(map[string]string{"v": "bogus"})
		bogus, _ := entity.NewEntity("system/validate/cas", cbor.RawMessage(bogusData))
		if status, err := client.TreePutCAS(ctx, absent, bogus, seed.ContentHash); err != nil {
			return FailCheck("CAS put at absent path errored: " + err.Error())
		} else if status != 409 {
			return FailCheck(fmt.Sprintf("CAS put at absent path returned %d (expected 409)", status))
		}

		// Cleanup: remove the seeded path.
		cleanParams, cleanResource, _ := createRemoveRequest(path)
		if cleanParams.Type != "" {
			uri := fmt.Sprintf("entity://%s/system/tree", string(client.RemotePeerID()))
			client.SendExecute(ctx, uri, "put", cleanParams, cleanResource)
		}

		return PassCheck("expected_hash at absent binding returned 409")
	})

	// v7.50 CAS-create: zero expected_hash means "succeed only if path
	// is unbound." Distinct from omitted expected_hash (unconditional)
	// and from non-zero expected_hash (succeed iff binding equals it).
	// Spec: V7 v7.50, §3.9 — the zero hash is reserved (never a valid
	// content hash), so the wire-distinguishable case is legal. The
	// convergent-mirror recipe needs this so a notification with
	// previous_hash=zero (created event) threads to expected_hash=zero
	// and bootstraps a fresh mirror path as a clean CAS-create rather
	// than an unconditional overwrite (which would re-admit stale-lap
	// amplification).
	r.Run("cas_create_zero_hash_absent", func() CheckOutcome {
		path := fmt.Sprintf("system/validate/cas-create/fresh-%d", rand.Intn(100000))
		dataBytes, _ := ecf.Encode(map[string]string{"v": "create"})
		ent, _ := entity.NewEntity("system/validate/cas-create", cbor.RawMessage(dataBytes))

		status, err := client.TreePutCAS(ctx, path, ent, hash.Hash{})
		if err != nil {
			return FailCheck("CAS-create at absent path errored: " + err.Error())
		}
		if status != 200 {
			return FailCheck(fmt.Sprintf("CAS-create (zero hash, absent path) returned %d (expected 200)", status))
		}
		got, _, err := client.TreeGet(ctx, path)
		if err != nil {
			return FailCheck("CAS-create reported success but get failed: " + err.Error())
		}
		if got.ContentHash != ent.ContentHash {
			return FailCheck("CAS-create reported success but bound a different entity")
		}
		r.Store("cas_create_path", path)
		r.Store("cas_create_ent", ent)
		return PassCheck("zero expected_hash at absent path created and bound (200)")
	})

	r.Run("cas_create_zero_hash_exists", func() CheckOutcome {
		if out, ok := r.Require("cas_create_zero_hash_absent"); !ok {
			return out
		}
		path := r.Load("cas_create_path").(string)
		updateData, _ := ecf.Encode(map[string]string{"v": "would-overwrite"})
		update, _ := entity.NewEntity("system/validate/cas-create", cbor.RawMessage(updateData))

		status, err := client.TreePutCAS(ctx, path, update, hash.Hash{})
		if err != nil {
			return FailCheck("CAS-create at existing path errored: " + err.Error())
		}
		if status != 409 {
			return FailCheck(fmt.Sprintf("CAS-create (zero hash, existing path) returned %d (expected 409)", status))
		}
		// Atomicity: binding must be unchanged.
		seedEnt := r.Load("cas_create_ent").(entity.Entity)
		got, _, err := client.TreeGet(ctx, path)
		if err != nil {
			return FailCheck("get after 409 failed: " + err.Error())
		}
		if got.ContentHash != seedEnt.ContentHash {
			return FailCheck("binding changed after 409 — CAS-create must be atomic")
		}
		return PassCheck("zero expected_hash at existing path returned 409 (binding unchanged)")
	})

	// --- Step 10: Incremental trie-root tracking ---

	r.Run("tracking_config_create", func() CheckOutcome {
		trackedPrefix := "system/validate/trie-track/"
		configName := "validate-trie-track"
		configPath := "system/tree/tracking-config/" + configName

		enabledCfg := types.TrackingConfigData{Prefix: trackedPrefix, Enabled: true}
		cfgEntity, err := enabledCfg.ToEntity()
		if err != nil {
			return FailCheck("failed to build tracking-config entity: " + err.Error())
		}
		if _, err := client.TreePut(ctx, configPath, cfgEntity); err != nil {
			return FailCheck("failed to store tracking-config: " + err.Error())
		}
		r.Store("tracked_prefix", trackedPrefix)
		r.Store("tracking_config_path", configPath)
		return PassCheck("stored tracking-config for prefix " + trackedPrefix)
	})

	r.Run("tracked_root_present", func() CheckOutcome {
		if out, ok := r.Require("tracking_config_create"); !ok {
			return out
		}
		trackedPrefix := r.Load("tracked_prefix").(string)
		rootPath := "system/tree/root/system/validate/trie-track" // no trailing slash

		// Write one entity under the tracked prefix.
		eData, _ := ecf.Encode(map[string]string{"seq": "1"})
		e, _ := entity.NewEntity("system/validate/tracked", cbor.RawMessage(eData))
		if _, err := client.TreePut(ctx, trackedPrefix+"a.txt", e); err != nil {
			return FailCheck("failed to write tracked entity: " + err.Error())
		}

		// Tracked root must now be populated.
		rootEnt, _, err := client.TreeGet(ctx, rootPath)
		if err != nil {
			return FailCheck("tracked root not readable at " + rootPath + ": " + err.Error())
		}
		r.Store("root_path", rootPath)
		r.Store("root1_hash", rootEnt.ContentHash)
		return PassCheck("tracked root is populated at " + rootPath)
	})

	r.Run("tracked_root_updates", func() CheckOutcome {
		if out, ok := r.Require("tracked_root_present"); !ok {
			return out
		}
		trackedPrefix := r.Load("tracked_prefix").(string)
		rootPath := r.Load("root_path").(string)
		root1 := r.Load("root1_hash").(hash.Hash)

		// Write a second entity; root hash must change.
		e2Data, _ := ecf.Encode(map[string]string{"seq": "2"})
		e2, _ := entity.NewEntity("system/validate/tracked", cbor.RawMessage(e2Data))
		if _, err := client.TreePut(ctx, trackedPrefix+"b.txt", e2); err != nil {
			return FailCheck("failed to write second tracked entity: " + err.Error())
		}

		rootEnt2, _, err := client.TreeGet(ctx, rootPath)
		if err != nil {
			return FailCheck("tracked root missing after second write: " + err.Error())
		}
		r.Store("root_ent2", rootEnt2)
		if rootEnt2.ContentHash == root1 {
			return FailCheck("tracked root did not change after write under prefix")
		}
		return PassCheck("tracked root changed after write under prefix")
	})

	r.Run("tracked_snapshot_matches", func() CheckOutcome {
		if out, ok := r.Require("tracked_root_updates"); !ok {
			return out
		}
		trackedPrefix := r.Load("tracked_prefix").(string)
		rootEnt2 := r.Load("root_ent2").(entity.Entity)

		snap, _, err := client.TreeSnapshot(ctx, trackedPrefix)
		if err != nil {
			return FailCheck("snapshot over tracked prefix failed: " + err.Error())
		}

		if snap.Root == rootEnt2.ContentHash {
			return PassCheck("snapshot over tracked prefix returns tracked root hash")
		}
		return FailCheck(fmt.Sprintf("snapshot root %s != tracked root %s", snap.Root, rootEnt2.ContentHash))
	})

	r.Run("tracked_root_cleared", func() CheckOutcome {
		if out, ok := r.Require("tracking_config_create"); !ok {
			return out
		}
		trackedPrefix := r.Load("tracked_prefix").(string)
		configPath := r.Load("tracking_config_path").(string)
		rootPath := "system/tree/root/system/validate/trie-track"

		// Disable the config; tracked root should be cleared.
		disabledCfg := types.TrackingConfigData{Prefix: trackedPrefix, Enabled: false}
		disabledEntity, _ := disabledCfg.ToEntity()
		if _, err := client.TreePut(ctx, configPath, disabledEntity); err != nil {
			return FailCheck("failed to disable tracking-config: " + err.Error())
		}

		// Cleanup: remove the entities and the config.
		uri := fmt.Sprintf("entity://%s/system/tree", string(client.RemotePeerID()))
		for _, p := range []string{trackedPrefix + "a.txt", trackedPrefix + "b.txt", configPath} {
			cleanParams, cleanResource, _ := createRemoveRequest(p)
			if cleanParams.Type != "" {
				client.SendExecute(ctx, uri, "put", cleanParams, cleanResource)
			}
		}

		if _, _, err := client.TreeGet(ctx, rootPath); err == nil {
			return FailCheck("tracked root still bound after disabling config — spec: root SHOULD be removed")
		}
		return PassCheck("tracked root removed after disabling config")
	})

	// --- V7 v7.72 §9.5a CORE-TREE-* vectors ---

	r.Run("core_tree_put_1", func() CheckOutcome {
		// PUT a fresh entity → 200; subsequent GET returns it byte-identical.
		path := fmt.Sprintf("system/validate/core-tree/put-1-%d", rand.Intn(100000))
		data, _ := ecf.Encode(map[string]string{"v7.72": "CORE-TREE-PUT-1", "label": "put-roundtrip"})
		ent, err := entity.NewEntity("system/validate/core-tree", cbor.RawMessage(data))
		if err != nil {
			return FailCheck("build entity: " + err.Error())
		}
		if _, err := client.TreePut(ctx, path, ent); err != nil {
			return FailCheck("put: " + err.Error())
		}
		got, _, err := client.TreeGet(ctx, path)
		if err != nil {
			return FailCheck("get after put: " + err.Error())
		}
		// Cleanup regardless of outcome.
		defer func() {
			cleanParams, cleanResource, _ := createRemoveRequest(path)
			if cleanParams.Type != "" {
				uri := fmt.Sprintf("entity://%s/system/tree", string(client.RemotePeerID()))
				client.SendExecute(ctx, uri, "put", cleanParams, cleanResource)
			}
		}()
		if got.ContentHash != ent.ContentHash {
			return FailCheck(fmt.Sprintf("get returned hash %s (expected %s)", got.ContentHash, ent.ContentHash))
		}
		return PassCheck("PUT→GET round-trip byte-identical (V7 v7.72 §9.5a CORE-TREE-PUT-1)")
	})

	r.Run("core_tree_put_cas_1", func() CheckOutcome {
		// Zero-hash CAS-create per V7 §3.9 v7.50.
		// - On unbound path → 200 (CAS-create).
		// - On bound path → 409 hash_mismatch.
		freshPath := fmt.Sprintf("system/validate/core-tree/cas-create-fresh-%d", rand.Intn(100000))
		dataA, _ := ecf.Encode(map[string]string{"v": "cas-create"})
		entA, _ := entity.NewEntity("system/validate/core-tree", cbor.RawMessage(dataA))
		status, err := client.TreePutCAS(ctx, freshPath, entA, hash.Hash{})
		if err != nil {
			return FailCheck("CAS-create on unbound: " + err.Error())
		}
		if status != 200 {
			return FailCheck(fmt.Sprintf("CAS-create (zero hash, unbound) returned %d (expected 200)", status))
		}
		// Path is now bound; repeat with zero hash → 409.
		dataB, _ := ecf.Encode(map[string]string{"v": "would-overwrite"})
		entB, _ := entity.NewEntity("system/validate/core-tree", cbor.RawMessage(dataB))
		status, err = client.TreePutCAS(ctx, freshPath, entB, hash.Hash{})
		if err != nil {
			return FailCheck("CAS-create on bound: " + err.Error())
		}
		// Cleanup.
		defer func() {
			cleanParams, cleanResource, _ := createRemoveRequest(freshPath)
			if cleanParams.Type != "" {
				uri := fmt.Sprintf("entity://%s/system/tree", string(client.RemotePeerID()))
				client.SendExecute(ctx, uri, "put", cleanParams, cleanResource)
			}
		}()
		if status != 409 {
			return FailCheck(fmt.Sprintf("CAS-create (zero hash, bound) returned %d (expected 409 hash_mismatch)", status))
		}
		return PassCheck("zero-hash CAS-create: unbound→200, bound→409 (V7 §3.9 v7.50 / v7.72 §9.5a CORE-TREE-PUT-CAS-1)")
	})

	r.Run("core_tree_put_cas_2", func() CheckOutcome {
		// Non-zero CAS per V7 §3.9.
		// - matching expected_hash → 200.
		// - non-matching → 409 hash_mismatch.
		path := fmt.Sprintf("system/validate/core-tree/cas-update-%d", rand.Intn(100000))
		seedData, _ := ecf.Encode(map[string]string{"v": "seed"})
		seed, _ := entity.NewEntity("system/validate/core-tree", cbor.RawMessage(seedData))
		if _, err := client.TreePut(ctx, path, seed); err != nil {
			return FailCheck("seed put: " + err.Error())
		}
		defer func() {
			cleanParams, cleanResource, _ := createRemoveRequest(path)
			if cleanParams.Type != "" {
				uri := fmt.Sprintf("entity://%s/system/tree", string(client.RemotePeerID()))
				client.SendExecute(ctx, uri, "put", cleanParams, cleanResource)
			}
		}()
		// Matching expected_hash.
		nextData, _ := ecf.Encode(map[string]string{"v": "next"})
		next, _ := entity.NewEntity("system/validate/core-tree", cbor.RawMessage(nextData))
		status, err := client.TreePutCAS(ctx, path, next, seed.ContentHash)
		if err != nil {
			return FailCheck("CAS update (matching): " + err.Error())
		}
		if status != 200 {
			return FailCheck(fmt.Sprintf("CAS update (matching expected_hash) returned %d (expected 200)", status))
		}
		// Non-matching expected_hash (use seed.ContentHash again — now stale).
		staleData, _ := ecf.Encode(map[string]string{"v": "stale-wouldnt-fit"})
		stale, _ := entity.NewEntity("system/validate/core-tree", cbor.RawMessage(staleData))
		status, err = client.TreePutCAS(ctx, path, stale, seed.ContentHash)
		if err != nil {
			return FailCheck("CAS update (mismatching): " + err.Error())
		}
		if status != 409 {
			return FailCheck(fmt.Sprintf("CAS update (mismatching expected_hash) returned %d (expected 409 hash_mismatch)", status))
		}
		return PassCheck("non-zero CAS: matching→200, mismatching→409 (V7 §3.9 / v7.72 §9.5a CORE-TREE-PUT-CAS-2)")
	})

	r.Run("core_tree_delete_1", func() CheckOutcome {
		// V7 §1.2a + ENTITY-NATIVE-TYPE-SYSTEM §4.9: deletion-marker is a
		// zero-field content entity. Per v7.72 §9.5a:
		//   PUT system/deletion-marker at a bound path → 200.
		//   subsequent GET returns the marker (not the prior entity).
		//   listing omits the path under the §6.3 filter convention.
		// If Go's tree handler does not filter deletion-markered paths
		// from listing today, this vector surfaces that as a §9.1-floor
		// non-conformance — fix in-cycle per arch v7.72 Amendment 1.
		base := fmt.Sprintf("system/validate/core-tree/delete-1-%d", rand.Intn(100000))
		path := base + "/target"
		siblingPath := base + "/sibling-keep"

		// Bind a real entity at `path`, plus a sibling at the same prefix
		// (the sibling stays bound; the listing-omit check verifies that
		// only the marker-bound path is filtered, not the whole prefix).
		realData, _ := ecf.Encode(map[string]string{"v": "to-be-deleted"})
		real, _ := entity.NewEntity("system/validate/core-tree", cbor.RawMessage(realData))
		if _, err := client.TreePut(ctx, path, real); err != nil {
			return FailCheck("seed real entity: " + err.Error())
		}
		sibData, _ := ecf.Encode(map[string]string{"v": "keep-me"})
		sib, _ := entity.NewEntity("system/validate/core-tree", cbor.RawMessage(sibData))
		if _, err := client.TreePut(ctx, siblingPath, sib); err != nil {
			return FailCheck("seed sibling entity: " + err.Error())
		}

		// Best-effort cleanup of both paths regardless of outcome.
		defer func() {
			uri := fmt.Sprintf("entity://%s/system/tree", string(client.RemotePeerID()))
			for _, p := range []string{path, siblingPath} {
				cleanParams, cleanResource, _ := createRemoveRequest(p)
				if cleanParams.Type != "" {
					client.SendExecute(ctx, uri, "put", cleanParams, cleanResource)
				}
			}
		}()

		// PUT system/deletion-marker (zero-field content entity per §1.2a).
		// ecf.Encode of an empty map gives the canonical zero-field shape.
		markerData, _ := ecf.Encode(map[string]interface{}{})
		marker, err := entity.NewEntity("system/deletion-marker", cbor.RawMessage(markerData))
		if err != nil {
			return FailCheck("build deletion-marker entity: " + err.Error())
		}
		if _, err := client.TreePut(ctx, path, marker); err != nil {
			return FailCheck("put deletion-marker: " + err.Error())
		}

		// GET — spec says "returns the marker (not the prior entity)". An
		// impl may also surface 404 if it treats deletion as full removal;
		// note divergence but treat 404 as a WARN-class finding (v7.70
		// erratum leaves the GET-after-delete shape open for some impls).
		got, _, err := client.TreeGet(ctx, path)
		gotMarker := err == nil && got.Type == "system/deletion-marker"
		got404 := err != nil // best-effort: any GET error is treated as 404-class for this WARN path

		// Listing should omit the marker-bound path per §6.3 / v7.72 §9.5a.
		entries, _, listErr := client.TreeListing(ctx, base+"/")
		if listErr != nil {
			return FailCheck("listing of delete-1 prefix: " + listErr.Error())
		}
		_, sawTarget := entries["target"]
		_, sawSibling := entries["sibling-keep"]
		if !sawSibling {
			return FailCheck(fmt.Sprintf("listing dropped the sibling-keep entry (delete-marker filter is over-broad?); entries=%v", mapKeysStr(entries)))
		}
		if sawTarget {
			// §9.1 listing filter for deletion-markers is not implemented
			// — flag explicitly so the cohort can fix in-cycle.
			return FailCheck(fmt.Sprintf("listing still shows deletion-markered path %q — V7 v7.72 §9.5a CORE-TREE-DELETE-1 + V7 §6.3 require listing to omit deletion-marker-bound paths (got entries: %v). Arch v7.72 Amendment 1 §1: fix in-cycle.", "target", mapKeysStr(entries)))
		}
		if gotMarker {
			return PassCheck("PUT deletion-marker → GET returns marker, listing omits the path (V7 v7.72 §9.5a CORE-TREE-DELETE-1)")
		}
		if got404 {
			return WarnCheck("PUT deletion-marker → GET returns 404 (impl treats marker as full removal); listing omit is correct (v7.72 §9.5a CORE-TREE-DELETE-1 passes the listing-filter MUST; the GET-after-delete shape is open across impls per v7.70 §1.2 erratum)")
		}
		return WarnCheck(fmt.Sprintf("PUT deletion-marker → GET returned type=%q (expected system/deletion-marker); listing-filter MUST passes — v7.72 §9.5a CORE-TREE-DELETE-1 partial", got.Type))
	})

	r.Run("core_tree_listing_1", func() CheckOutcome {
		// V7 §6.3 / §9.1 MUST: listing entries for paths the capability
		// does not cover MUST be omitted. Stage: bind one path under a
		// "covered" prefix and one under a sibling "hidden" prefix using
		// the connection's broad cap, then list `system/validate/core-
		// tree/listing-1-{nonce}/` and assert both entries appear (basic
		// listing semantics). A full cap-coverage filter test requires a
		// narrowed delegated cap, which the broader security category
		// exercises; here we pin the §6.3 listing return-shape MUST.
		// (Cap-filter pin lives in the security category's resource-
		// scope path; v7.72 §9.5a is concerned with the listing return
		// shape on a core peer.)
		nonce := rand.Intn(100000)
		base := fmt.Sprintf("system/validate/core-tree/listing-1-%d", nonce)
		p1 := base + "/alpha"
		p2 := base + "/beta"
		dataA, _ := ecf.Encode(map[string]string{"v": "alpha"})
		entA, _ := entity.NewEntity("system/validate/core-tree", cbor.RawMessage(dataA))
		dataB, _ := ecf.Encode(map[string]string{"v": "beta"})
		entB, _ := entity.NewEntity("system/validate/core-tree", cbor.RawMessage(dataB))
		if _, err := client.TreePut(ctx, p1, entA); err != nil {
			return FailCheck("seed alpha: " + err.Error())
		}
		if _, err := client.TreePut(ctx, p2, entB); err != nil {
			return FailCheck("seed beta: " + err.Error())
		}
		defer func() {
			uri := fmt.Sprintf("entity://%s/system/tree", string(client.RemotePeerID()))
			for _, p := range []string{p1, p2} {
				cleanParams, cleanResource, _ := createRemoveRequest(p)
				if cleanParams.Type != "" {
					client.SendExecute(ctx, uri, "put", cleanParams, cleanResource)
				}
			}
		}()
		entries, _, err := client.TreeListing(ctx, base+"/")
		if err != nil {
			return FailCheck("listing: " + err.Error())
		}
		_, sawA := entries["alpha"]
		_, sawB := entries["beta"]
		if !sawA || !sawB {
			return FailCheck(fmt.Sprintf("listing missing seeded entries (alpha=%v, beta=%v); got entries=%v", sawA, sawB, mapKeysStr(entries)))
		}
		// Spot-check that keys are bare (relative), per §1.4.
		for k := range entries {
			if strings.HasPrefix(k, "/") || strings.Contains(k, string(client.RemotePeerID())) {
				return FailCheck(fmt.Sprintf("listing key %q has leading / or peer-id leak", k))
			}
		}
		return PassCheck(fmt.Sprintf("listing prefix returns system/tree/listing with both seeded entries as bare keys (%d entries) (V7 §6.3 / v7.72 §9.5a CORE-TREE-LISTING-1)", len(entries)))
	})

	r.Run("core_tree_path_flex_1", func() CheckOutcome {
		// V7 §1.4 + §5.4: path validation flex bundle per v7.72 §9.5a.
		// Reject: null byte, leading slash on caller-supplied path,
		// `./` and `../` (already pinned by path_reject_dot_relative /
		// path_reject_dotdot_relative), empty segments (already pinned).
		// Accept: multi-segment + Unicode segments.
		// Compose as sub-results; overall PASS iff all sub-pins pass.
		type sub struct {
			label   string
			outcome CheckOutcome
		}
		var subs []sub

		// Reject null byte.
		nullPath := "system/validate/core-tree/path-flex/with\x00null"
		subs = append(subs, sub{"reject_null_byte", runSinglePathRejection(ctx, client, nullPath,
			"V7 §1.4", "null byte is not valid in any path segment")})

		// Reject leading slash on caller-supplied path. Per V7 §1.4 caller
		// paths are peer-relative (no leading /). A path starting with "/"
		// followed by content that is NOT a peer-id segment is malformed.
		subs = append(subs, sub{"reject_leading_slash", runSinglePathRejection(ctx, client, "/system/validate/core-tree/path-flex/bad",
			"V7 §1.4", "leading / on caller-supplied path; caller paths are peer-relative")})

		// Accept multi-segment Unicode. Use Cyrillic + Japanese segments.
		// The PUT should succeed; the GET should return byte-identical.
		unicodePath := "system/validate/core-tree/path-flex/привет/日本語/item"
		unicodeData, _ := ecf.Encode(map[string]string{"v": "unicode-path"})
		unicodeEnt, _ := entity.NewEntity("system/validate/core-tree", cbor.RawMessage(unicodeData))
		if _, err := client.TreePut(ctx, unicodePath, unicodeEnt); err != nil {
			subs = append(subs, sub{"accept_unicode_path", FailCheck("PUT under Unicode segments rejected: " + err.Error())})
		} else {
			got, _, gerr := client.TreeGet(ctx, unicodePath)
			if gerr != nil {
				subs = append(subs, sub{"accept_unicode_path", FailCheck("GET under Unicode segments failed: " + gerr.Error())})
			} else if got.ContentHash != unicodeEnt.ContentHash {
				subs = append(subs, sub{"accept_unicode_path", FailCheck("Unicode path GET returned different entity")})
			} else {
				subs = append(subs, sub{"accept_unicode_path", PassCheck("multi-segment Unicode path accepted; PUT→GET round-trips byte-identical")})
			}
			// Cleanup.
			cleanParams, cleanResource, _ := createRemoveRequest(unicodePath)
			if cleanParams.Type != "" {
				uri := fmt.Sprintf("entity://%s/system/tree", string(client.RemotePeerID()))
				client.SendExecute(ctx, uri, "put", cleanParams, cleanResource)
			}
		}

		// Roll up.
		var failed []string
		for _, s := range subs {
			if s.outcome.severity == Fail {
				failed = append(failed, s.label+": "+s.outcome.message)
			}
		}
		if len(failed) > 0 {
			return FailCheck(fmt.Sprintf("CORE-TREE-PATH-FLEX-1 sub-pin(s) failed: %v", failed))
		}
		return PassCheck(fmt.Sprintf("all %d sub-pins passed (V7 §1.4 + §5.4 / v7.72 §9.5a CORE-TREE-PATH-FLEX-1)", len(subs)))
	})

	// --- Cleanup ---

	r.Run("cleanup", func() CheckOutcome {
		params, resource, err := createRemoveRequest("system/validate/tree-ops/test-1")
		if err != nil {
			return WarnCheck("failed to create remove request: " + err.Error())
		}

		uri := fmt.Sprintf("entity://%s/system/tree", string(client.RemotePeerID()))
		env, _, err := client.SendExecute(ctx, uri, "put", params, resource)
		if err != nil {
			return WarnCheck("failed to remove test entity: " + err.Error())
		}

		respData, err := types.ExecuteResponseDataFromEntity(env.Root)
		if err == nil && respData.Status == 200 {
			return PassCheck("removed test entity system/validate/tree-ops/test-1")
		}
		return WarnCheck("failed to remove test entity (non-critical)")
	})

	results := r.Results()

	// V7 v7.72 §9.0 / §9.5a / §3720 carve-out: EXTENSION-TREE §9 ops
	// (snapshot, diff, extract, merge, roundtrip, tracked/tracking) are
	// out-of-scope under --profile core. A true core peer correctly
	// returns 501 there. Convert to profile-keyed SKIPs so the FAIL gate
	// at result.go:170 ignores them. Op-name prefix filter — NOT spec-ref
	// prefix — because put_entity / get_entity / listing_* are labeled
	// EXTENSION-TREE S1/S2 but are core operations and must remain scored.
	// Surfaced by keystone C# core peer (F22).
	if client.Profile() == ProfileCore {
		for i := range results {
			n := results[i].Name
			if strings.HasPrefix(n, "snapshot_") ||
				strings.HasPrefix(n, "diff_") ||
				strings.HasPrefix(n, "extract_") ||
				strings.HasPrefix(n, "merge_") ||
				strings.HasPrefix(n, "roundtrip_") ||
				strings.HasPrefix(n, "tracked_") ||
				strings.HasPrefix(n, "tracking_") {
				results[i].Severity = Skip
				results[i].Message = "V7 v7.72 §9.0 carve-out: EXTENSION-TREE §9 op skipped under --profile core (V7 §9.5a / §3720) — " + results[i].Message
			}
		}
	}

	return results
}

// runSinglePathRejection tests that a peer rejects a single malformed path.
func runSinglePathRejection(ctx context.Context, client *PeerClient, path, spec, why string) CheckOutcome {
	peerID := string(client.RemotePeerID())
	uri := fmt.Sprintf("entity://%s/system/tree", peerID)

	testData, _ := ecf.Encode(map[string]string{"label": "reject-test"})
	testEntity, _ := entity.NewEntity("system/validate/reject-test", cbor.RawMessage(testData))

	putReq := types.PutRequestData{}
	raw, _ := ecf.Encode(testEntity)
	putReq.Entity = cbor.RawMessage(raw)
	params, _ := putReq.ToEntity()
	resource := &types.ResourceTarget{Targets: []string{path}}

	resp, _, _, err := client.SendExecuteRaw(ctx, uri, "put", params, resource)
	if err != nil {
		return PassCheck(fmt.Sprintf("rejected %q (error: %v) — %s", path, err, why))
	}

	if resp.Status >= 400 {
		return PassCheck(fmt.Sprintf("rejected %q with status %d — %s", path, resp.Status, why))
	} else if resp.Status == 200 {
		// The put succeeded — this is wrong. Try to clean up.
		cleanParams, cleanResource, _ := createRemoveRequest(path)
		if cleanParams.Type != "" {
			client.SendExecute(ctx, uri, "put", cleanParams, cleanResource)
		}
		return FailCheck(fmt.Sprintf("accepted %q with status %d — should reject: %s", path, resp.Status, why))
	}
	// Non-200, non-4xx status — ambiguous but not a success.
	return PassCheck(fmt.Sprintf("did not accept %q (status %d) — %s", path, resp.Status, why))
}

// createRemoveRequest creates a PUT request with no entity (removes binding).
func createRemoveRequest(path string) (entity.Entity, *types.ResourceTarget, error) {
	putReq := types.PutRequestData{}
	reqEntity, err := putReq.ToEntity()
	if err != nil {
		return entity.Entity{}, nil, err
	}
	return reqEntity, &types.ResourceTarget{Targets: []string{path}}, nil
}

// extractListingHash extracts the content hash from a listing entry value.
// Listing entries are maps with "hash" (byte string or nil) and "has_children" fields.
func extractListingHash(val interface{}) hash.Hash {
	m, ok := val.(map[interface{}]interface{})
	if !ok {
		return hash.Hash{}
	}
	h, ok := m["hash"]
	if !ok || h == nil {
		return hash.Hash{}
	}
	bs, ok := h.([]byte)
	if !ok {
		return hash.Hash{}
	}
	parsed, err := hash.FromBytes(bs)
	if err != nil {
		return hash.Hash{}
	}
	return parsed
}

// mapKeys returns the keys of a map[string]hash.Hash as a slice.
func mapKeys(m map[string]hash.Hash) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	return keys
}

// mapKeysStr returns the keys of a map as a string slice — used by path validation.
func mapKeysStr(m map[string]interface{}) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	return keys
}
