package validate

import (
	"context"
	"fmt"
	"math/rand"

	"go.entitychurch.org/entity-core-go/core/ecf"
	"go.entitychurch.org/entity-core-go/core/entity"
	"go.entitychurch.org/entity-core-go/core/hash"
	"go.entitychurch.org/entity-core-go/core/types"
)

const catAutoVersion = "auto_version"

// autoVersionTestFamily is the shared path family every auto_version runner
// writes under; the suite gate probes it (not a specific instance) so gating is
// consistent with the randomized runner paths. See revisionTestFamily.
const autoVersionTestFamily = "system/validate/auto-version-"

// autoVersionTestPrefix generates a unique prefix per run to avoid state leakage.
func autoVersionTestPrefix() string {
	return fmt.Sprintf("%s%d/", autoVersionTestFamily, rand.Intn(100000))
}

// runAutoVersion validates EXTENSION-REVISION §6.1 auto-version semantics
// against a peer. Covers: per-write version creation, tracking-config
// coordination, dedup, disable behavior, and commit-dedup under auto-version.
func runAutoVersion(ctx context.Context, client *PeerClient) []CheckResult {
	r := NewCheckRunner(catAutoVersion)
	prefix := autoVersionTestPrefix()

	// --- Declare all checks ---

	// Enable coordinates
	r.Declare("enable_config_put", "REVISION §6.1")
	r.Declare("tracking_config_coordinated", "REVISION §6.1")

	// Per-write entry
	r.Declare("per_write_put1", "REVISION §6.1")
	r.Declare("per_write_version_exists", "REVISION §6.1")
	r.Declare("per_write_put2", "REVISION §6.1")
	r.Declare("per_write_version_advanced", "REVISION §6.1")
	r.Declare("per_write_parent_chain", "REVISION §6.1")

	// Dedup
	r.Declare("dedup_setup", "REVISION §6.1")
	r.Declare("dedup_noop", "REVISION §6.1")

	// Commit dedup
	r.Declare("commit_dedup_setup", "REVISION §6.2")
	r.Declare("commit_dedup_returns_current_head", "REVISION §6.2")

	// Disable
	r.Declare("disable_config_put", "REVISION §6.1")
	r.Declare("disable_tracking_config", "REVISION §6.1")
	r.Declare("disable_no_new_versions", "REVISION §6.1")

	// --- Step 1: Enable coordinates ---

	r.Run("enable_config_put", func() CheckOutcome {
		if err := writeRevisionConfig(ctx, client, prefix, true, nil); err != nil {
			return FailCheck("failed to put revision config: " + err.Error())
		}
		return PassCheck("revision config with auto_version: true accepted")
	})

	r.Run("tracking_config_coordinated", func() CheckOutcome {
		if out, ok := r.Require("enable_config_put"); !ok {
			return out
		}
		trackingCfg, ok := findTrackingConfig(ctx, client, prefix)
		if !ok {
			return FailCheck("no tracking-config with matching prefix found after auto_version: true")
		}
		if !trackingCfg.Enabled {
			return FailCheck("coordinated tracking-config is not enabled")
		}
		return PassCheck("auto_version: true auto-created an enabled tracking-config for " + prefix)
	})

	// --- Step 2: Per-write entry ---

	r.Run("per_write_put1", func() CheckOutcome {
		if out, ok := r.Require("tracking_config_coordinated"); !ok {
			return out
		}
		ent1 := mustCreateEntity("test/auto-version-doc", map[string]string{"v": "1"})
		if _, err := client.TreePut(ctx, prefix+"file1", ent1); err != nil {
			return FailCheck("failed to put file1: " + err.Error())
		}
		return PassCheck("file1 written under tracked prefix")
	})

	r.Run("per_write_version_exists", func() CheckOutcome {
		if out, ok := r.Require("per_write_put1"); !ok {
			return out
		}
		resp, _, err := client.RevisionExecuteFull(ctx, "log", types.RevisionLogParamsData{Prefix: prefix})
		if err != nil || resp.Status != 200 {
			return FailCheck(fmt.Sprintf("log failed: %v status=%d", err, resp.Status))
		}
		var logResult types.RevisionLogResultData
		if _, err := decodeRevisionResult(resp, &logResult); err != nil {
			return FailCheck("decode log result: " + err.Error())
		}
		if len(logResult.Versions) < 1 {
			return FailCheck("no version entries created after first write")
		}
		r.Store("first_version_count", len(logResult.Versions))
		r.Store("first_head", logResult.Versions[0])
		return PassCheck(fmt.Sprintf("auto-version created %d entry/entries after first write", len(logResult.Versions)))
	})

	r.Run("per_write_put2", func() CheckOutcome {
		if out, ok := r.Require("per_write_version_exists"); !ok {
			return out
		}
		ent2 := mustCreateEntity("test/auto-version-doc", map[string]string{"v": "2"})
		if _, err := client.TreePut(ctx, prefix+"file2", ent2); err != nil {
			return FailCheck("failed to put file2: " + err.Error())
		}
		return PassCheck("file2 written under tracked prefix")
	})

	r.Run("per_write_version_advanced", func() CheckOutcome {
		if out, ok := r.Require("per_write_put2"); !ok {
			return out
		}
		firstVersionCount := r.Load("first_version_count").(int)
		resp, env, err := client.RevisionExecuteFull(ctx, "log", types.RevisionLogParamsData{Prefix: prefix})
		if err != nil || resp.Status != 200 {
			return FailCheck("log after second write failed")
		}
		var logResult types.RevisionLogResultData
		if _, err := decodeRevisionResult(resp, &logResult); err != nil {
			return FailCheck("decode log result: " + err.Error())
		}
		if len(logResult.Versions) <= firstVersionCount {
			return FailCheck(fmt.Sprintf("second write did not produce a new version (count: %d -> %d)",
				firstVersionCount, len(logResult.Versions)))
		}
		// Extract included entities from system/envelope result.
		var resultEnt entity.Entity
		if err := ecf.Decode(resp.Result, &resultEnt); err == nil {
			if _, envIncluded, err := unwrapResultEnvelope(resultEnt); err == nil && envIncluded != nil {
				r.Store("log_included", envIncluded)
			} else {
				r.Store("log_included", env.Included)
			}
		} else {
			r.Store("log_included", env.Included)
		}
		r.Store("newest_head", logResult.Versions[0])
		return PassCheck("second write produced a new version entry")
	})

	r.Run("per_write_parent_chain", func() CheckOutcome {
		if out, ok := r.Require("per_write_version_advanced"); !ok {
			return out
		}
		included := r.Load("log_included").(map[hash.Hash]entity.Entity)
		newestHead := r.Load("newest_head")
		firstHead := r.Load("first_head")
		verData, ok := revisionGetVersionDataFromIncluded(included, newestHead.(hash.Hash))
		if !ok {
			return WarnCheck("could not locate new version entity in log response")
		}
		firstHeadStr := firstHead.(interface{ String() string }).String()
		if len(verData.Parents) != 1 || verData.Parents[0].String() != firstHeadStr {
			return FailCheck(fmt.Sprintf("expected parent=%s, got parents=%v", firstHeadStr, verData.Parents))
		}
		return PassCheck("new version entry chains from previous head")
	})

	// --- Step 3: Dedup ---

	r.Run("dedup_setup", func() CheckOutcome {
		if out, ok := r.Require("tracking_config_coordinated"); !ok {
			return out
		}
		resp, _, err := client.RevisionExecuteFull(ctx, "log", types.RevisionLogParamsData{Prefix: prefix})
		if err != nil || resp.Status != 200 {
			return WarnCheck("could not snapshot log state")
		}
		var before types.RevisionLogResultData
		_, _ = decodeRevisionResult(resp, &before)
		r.Store("dedup_before_count", len(before.Versions))
		return PassCheck(fmt.Sprintf("captured log state: %d versions", len(before.Versions)))
	})

	r.Run("dedup_noop", func() CheckOutcome {
		if out, ok := r.Require("dedup_setup"); !ok {
			return out
		}
		beforeCount := r.Load("dedup_before_count").(int)

		ent := mustCreateEntity("test/auto-version-doc", map[string]string{"v": "dedup"})
		if _, err := client.TreePut(ctx, prefix+"dedup", ent); err != nil {
			return FailCheck("first dedup put: " + err.Error())
		}
		if _, err := client.TreePut(ctx, prefix+"dedup", ent); err != nil {
			return FailCheck("second dedup put: " + err.Error())
		}

		resp, _, err := client.RevisionExecuteFull(ctx, "log", types.RevisionLogParamsData{Prefix: prefix})
		if err != nil || resp.Status != 200 {
			return FailCheck("log after dedup failed")
		}
		var after types.RevisionLogResultData
		_, _ = decodeRevisionResult(resp, &after)

		expected := beforeCount + 1
		if len(after.Versions) != expected {
			return FailCheck(fmt.Sprintf("expected %d versions after dedup, got %d -- duplicate write created a version",
				expected, len(after.Versions)))
		}
		return PassCheck("duplicate write did not advance head (dedup)")
	})

	// --- Step 4: Commit dedup ---

	r.Run("commit_dedup_setup", func() CheckOutcome {
		if out, ok := r.Require("tracking_config_coordinated"); !ok {
			return out
		}
		resp, err := client.RevisionExecute(ctx, "status", types.RevisionStatusParamsData{Prefix: prefix})
		if err != nil || resp.Status != 200 {
			return WarnCheck("status failed")
		}
		var status types.RevisionStatusData
		if _, err := decodeRevisionResult(resp, &status); err != nil {
			return WarnCheck("decode status: " + err.Error())
		}
		r.Store("commit_dedup_head", status.Head)
		return PassCheck(fmt.Sprintf("captured current head: %s", status.Head.String()))
	})

	r.Run("commit_dedup_returns_current_head", func() CheckOutcome {
		if out, ok := r.Require("commit_dedup_setup"); !ok {
			return out
		}
		head := r.Load("commit_dedup_head")

		resp, err := client.RevisionExecute(ctx, "commit", types.RevisionCommitParamsData{Prefix: prefix})
		if err != nil || resp.Status != 200 {
			return FailCheck(fmt.Sprintf("commit failed: %v status=%d", err, resp.Status))
		}
		var cRes types.RevisionCommitResultData
		if _, err := decodeRevisionResult(resp, &cRes); err != nil {
			return FailCheck("decode commit result: " + err.Error())
		}
		headStr := head.(interface{ String() string }).String()
		if cRes.Version.String() != headStr {
			return FailCheck(fmt.Sprintf("no-op commit created new version %s (expected current head %s)",
				cRes.Version.String(), headStr))
		}
		return PassCheck("no-op commit under auto-version ON returned current head (dedup)")
	})

	// --- Step 5: Disable ---

	r.Run("disable_config_put", func() CheckOutcome {
		if out, ok := r.Require("tracking_config_coordinated"); !ok {
			return out
		}
		// Capture current log state before disabling.
		resp, _, err := client.RevisionExecuteFull(ctx, "log", types.RevisionLogParamsData{Prefix: prefix})
		if err != nil || resp.Status != 200 {
			return WarnCheck("log before disable failed")
		}
		var before types.RevisionLogResultData
		_, _ = decodeRevisionResult(resp, &before)
		r.Store("disable_before_count", len(before.Versions))

		if err := writeRevisionConfig(ctx, client, prefix, false, nil); err != nil {
			return FailCheck("failed to disable auto_version: " + err.Error())
		}
		return PassCheck("revision config with auto_version: false accepted")
	})

	r.Run("disable_tracking_config", func() CheckOutcome {
		if out, ok := r.Require("disable_config_put"); !ok {
			return out
		}
		if tc, ok := findTrackingConfig(ctx, client, prefix); !ok {
			return PassCheck("tracking-config removed on coordination (auto_version: false)")
		} else if tc.Enabled {
			return FailCheck("tracking-config still enabled after auto_version: false")
		} else {
			return PassCheck("tracking-config disabled on coordination")
		}
	})

	r.Run("disable_no_new_versions", func() CheckOutcome {
		if out, ok := r.Require("disable_config_put"); !ok {
			return out
		}
		beforeCount := r.Load("disable_before_count").(int)

		ent := mustCreateEntity("test/auto-version-doc", map[string]string{"v": "after-disable"})
		if _, err := client.TreePut(ctx, prefix+"post-disable", ent); err != nil {
			return FailCheck("post-disable put: " + err.Error())
		}

		resp, _, err := client.RevisionExecuteFull(ctx, "log", types.RevisionLogParamsData{Prefix: prefix})
		if err != nil || resp.Status != 200 {
			return FailCheck("log after disable failed")
		}
		var after types.RevisionLogResultData
		_, _ = decodeRevisionResult(resp, &after)

		if len(after.Versions) != beforeCount {
			return FailCheck(fmt.Sprintf("versions advanced after disable: %d -> %d",
				beforeCount, len(after.Versions)))
		}
		return PassCheck("no new versions created after auto_version: false")
	})

	return r.Results()
}

// writeRevisionConfig uses the revision/config operation (§4.4.17) to set a
// revision config. The handler manages the storage path internally.
func writeRevisionConfig(ctx context.Context, client *PeerClient, prefix string, autoVersion bool, exclude []string) error {
	cfgData := types.RevisionConfigData{
		Prefix:      prefix,
		AutoVersion: &autoVersion,
		Exclude:     exclude,
	}
	resp, err := client.RevisionExecute(ctx, "config", types.RevisionConfigParamsData{
		Name:   prefix,
		Action: "set",
		Config: &cfgData,
	})
	if err != nil {
		return fmt.Errorf("config operation: %w", err)
	}
	if resp.Status != 200 {
		return fmt.Errorf("config operation status %d", resp.Status)
	}
	// Typed-decode the result envelope. Status-only checks would let
	// cross-impl wire shape regressions through — e.g. an optional hash
	// field emitted as h'' instead of being omitted per `omitzero` would
	// pass a status check but fail any consumer that decodes the result.
	var result types.RevisionConfigResultData
	if _, err := decodeRevisionResult(resp, &result); err != nil {
		return fmt.Errorf("decode config result: %w", err)
	}
	if result.ConfigPath == "" {
		return fmt.Errorf("config result missing config_path")
	}
	if result.ConfigHash.IsZero() {
		return fmt.Errorf("config result has zero config_hash on action=set (must be the newly-emitted config entity hash)")
	}
	return nil
}

// findTrackingConfig searches for a tracking-config entity whose prefix
// field matches. Walks system/tree/tracking-config/ recursively because
// implementations vary in the binding-key convention: flat keys with
// slashes substituted (Go, Python) or nested paths preserving original
// prefix structure (Rust). The spec doesn't constrain the binding path.
func findTrackingConfig(ctx context.Context, client *PeerClient, prefix string) (types.TrackingConfigData, bool) {
	absPrefix := "/" + string(client.RemotePeerID()) + "/" + prefix
	return walkForTrackingConfig(ctx, client, "system/tree/tracking-config/", prefix, absPrefix, 0)
}

func walkForTrackingConfig(ctx context.Context, client *PeerClient, root, prefix, absPrefix string, depth int) (types.TrackingConfigData, bool) {
	if depth > 8 {
		return types.TrackingConfigData{}, false
	}
	entries, _, err := client.TreeListing(ctx, root)
	if err != nil {
		return types.TrackingConfigData{}, false
	}
	for name := range entries {
		fullPath := root + name
		if ent, _, err := client.TreeGet(ctx, fullPath); err == nil {
			var tc types.TrackingConfigData
			if err := ecf.Decode(ent.Data, &tc); err == nil && (tc.Prefix == prefix || tc.Prefix == absPrefix) {
				return tc, true
			}
		}
		if tc, ok := walkForTrackingConfig(ctx, client, fullPath+"/", prefix, absPrefix, depth+1); ok {
			return tc, true
		}
	}
	return types.TrackingConfigData{}, false
}

// revisionGetVersionDataFromIncluded looks up a version entity in an included map by hash.
func revisionGetVersionDataFromIncluded(included map[hash.Hash]entity.Entity, versionHash hash.Hash) (types.RevisionEntryData, bool) {
	inc, ok := included[versionHash]
	if !ok {
		return types.RevisionEntryData{}, false
	}
	data, err := types.RevisionEntryDataFromEntity(inc)
	if err != nil {
		return types.RevisionEntryData{}, false
	}
	return data, true
}
