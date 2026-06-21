package validate

import (
	"bytes"
	"context"
	"fmt"
	"time"

	"go.entitychurch.org/entity-core-go/core/entity"
	"go.entitychurch.org/entity-core-go/core/types"
)

// catUniversalAddressSpace pins V7 §1.4 — the universal tree root and the
// peer-id-keyed address space — empirically via wire round-trips. Distinct
// from `serving_mode` (which tests the HTTP read surface) and `tree_operations`
// (which tests handler semantics): this category proves the **addressing
// model** itself, end-to-end, against any peer.
//
// Spec receipts:
//
//   - §1.4 "Storage representation. All paths in the location index MUST be
//     stored as absolute paths — `/{peer_id}/{rest}`."
//   - §1.4 "Peer-relative paths. … Peer-relative always resolves to the local
//     peer's namespace: `system/tree` becomes `/{local_peer_id}/system/tree`."
//   - §1.4 (table) "Absolute path … Leading `/` denotes universal tree root."
//   - §1.4 "Synced remote peer data may include `system/handler` entities
//     (e.g., `/{remote_peer_id}/system/tree`) — these are cached data
//     describing the remote peer's handlers, not locally dispatchable
//     handlers."
//   - §1.4 (inbound dispatch) constrains the **handler URI** to local peer,
//     NOT the resource target — so `tree:put` with `Resource.Targets[0]`
//     = `/{other}/foo` to `entity://localPeer/system/tree` is conformant.
//
// What the category proves:
//
//  1. Peer-relative ≡ absolute-local: `tree:put` at `foo` and `tree:get` at
//     `/{localPeerID}/foo` (and the inverse) return the same entity.
//  2. Foreign-namespace publish: `tree:put` at `/{otherID}/foo` lands a
//     binding at that absolute path; `tree:get` at the same path retrieves it.
//  3. Namespace isolation: a foreign-namespace put is NOT visible under the
//     local peer's namespace.
//  4. Peer-relative input does NOT canonicalize to any foreign namespace.
//  5. Listings respect the foreign namespace — a `tree:get` listing under
//     `/{otherID}` surfaces children written there.
const catUniversalAddressSpace = "universal_address_space"

// uasFixturePeerID is a fixed base58 peer-id-shaped string used as the
// "foreign" peer in cross-namespace publish probes. Distinct from the
// `multi_peer_publish_via_tree_put` fixture in serving_mode.go so the two
// don't interfere when both categories run against the same peer process.
const uasFixturePeerID = "1HtVqLgPqkScVxjVN8VFGFiH7T2P3aSDwJxQ8DGEoooo2z"

func runUniversalAddressSpace(ctx context.Context, client *PeerClient) []CheckResult {
	r := NewCheckRunner(catUniversalAddressSpace)

	localPeerID := string(client.RemotePeerID())

	r.Declare("grants_sufficient",
		"validate-peer gate — connection grants MUST cover system/tree:put + system/tree:get on both the local and a synthetic foreign namespace; open-access satisfies this")
	r.Declare("local_peer_relative_equals_absolute",
		"V7 §1.4 — peer-relative `foo` ≡ absolute `/{localPeerID}/foo` (canonicalization is bidirectional round-trip)")
	r.Declare("local_absolute_equals_peer_relative",
		"V7 §1.4 — absolute `/{localPeerID}/foo` ≡ peer-relative `foo` (inverse round-trip)")
	r.Declare("foreign_namespace_publish_lands_at_absolute_path",
		"V7 §1.4 — `tree:put` with Resource.Targets[0]=`/{otherID}/foo` to `entity://localPeer/system/tree` lands a binding at that absolute path (universal address space slot is addressable)")
	r.Declare("foreign_namespace_invisible_under_local",
		"V7 §1.4 — a binding written at `/{otherID}/foo` MUST NOT appear under `/{localPeerID}/foo` (namespaces isolated)")
	r.Declare("peer_relative_never_resolves_to_foreign",
		"V7 §1.4 — peer-relative `foo` ALWAYS canonicalizes to local namespace; tree:get at `/{otherID}/foo` after `tree:put` at `foo` MUST 404 (peer-relative cannot leak to foreign)")
	r.Declare("foreign_namespace_listing_at_peer_root",
		"V7 §1.4 — `tree:get` listing at `/{otherID}/` lists children written under that peer-id (universal-tree-root walks foreign namespace)")
	r.Declare("foreign_namespace_listing_at_subpath",
		"V7 §1.4 — `tree:get` listing at `/{otherID}/system/validate/uas/` lists deeper children (listing traversal walks foreign namespace at arbitrary depth)")

	// ----- Gate: grants cover both local and synthetic foreign namespace.
	r.Run("grants_sufficient", func() CheckOutcome {
		if !client.GrantsAllow("/" + uasFixturePeerID + "/system/validate/uas/probe") {
			return SkipCheck("connection grants do not cover /<fixturePeer>/system/validate/uas/* — needs open-access or wildcard")
		}
		if !client.GrantsAllow("system/validate/uas/probe") {
			return SkipCheck("connection grants do not cover local system/validate/uas/* — needs open-access or wildcard")
		}
		return PassCheck("grants cover both local and foreign-namespace system/validate/uas/* (put + get)")
	})

	// Build a payload entity unique per run so we can verify byte identity.
	mkPayload := func(tag string) entity.Entity {
		payload := []byte(fmt.Sprintf("uas-probe %s ts=%d", tag, time.Now().UnixNano()))
		ent, _ := types.ContentChunkData{Payload: payload}.ToEntity()
		return ent
	}

	// ----- Check 1: peer-relative `foo` round-trips as absolute `/{local}/foo`.
	r.Run("local_peer_relative_equals_absolute", func() CheckOutcome {
		if out, ok := r.Require("grants_sufficient"); !ok {
			return out
		}
		ent := mkPayload("local-relative-1")
		relPath := "system/validate/uas/local-relative-1"
		absPath := "/" + localPeerID + "/" + relPath
		if _, err := client.TreePut(ctx, relPath, ent); err != nil {
			return FailCheck(fmt.Sprintf("tree:put at peer-relative %q failed: %v", relPath, err))
		}
		got, _, err := client.TreeGet(ctx, absPath)
		if err != nil {
			return FailCheck(fmt.Sprintf("tree:get at absolute %q failed (peer-relative should canonicalize to this): %v", absPath, err))
		}
		if got.ContentHash != ent.ContentHash {
			return FailCheck(fmt.Sprintf("entity at %q has hash %s, expected %s (canonicalization not equivalent)",
				absPath, got.ContentHash, ent.ContentHash))
		}
		return PassCheck(fmt.Sprintf("peer-relative %q ≡ absolute %q (same entity, hash=%s)", relPath, absPath, ent.ContentHash))
	})

	// ----- Check 2: absolute `/{local}/foo` round-trips as peer-relative `foo`.
	r.Run("local_absolute_equals_peer_relative", func() CheckOutcome {
		if out, ok := r.Require("grants_sufficient"); !ok {
			return out
		}
		ent := mkPayload("local-absolute-1")
		relPath := "system/validate/uas/local-absolute-1"
		absPath := "/" + localPeerID + "/" + relPath
		if _, err := client.TreePut(ctx, absPath, ent); err != nil {
			return FailCheck(fmt.Sprintf("tree:put at absolute %q failed: %v", absPath, err))
		}
		got, _, err := client.TreeGet(ctx, relPath)
		if err != nil {
			return FailCheck(fmt.Sprintf("tree:get at peer-relative %q failed (absolute should canonicalize to this): %v", relPath, err))
		}
		if got.ContentHash != ent.ContentHash {
			return FailCheck(fmt.Sprintf("entity at %q has hash %s, expected %s (inverse canonicalization not equivalent)",
				relPath, got.ContentHash, ent.ContentHash))
		}
		return PassCheck(fmt.Sprintf("absolute %q ≡ peer-relative %q (same entity, hash=%s)", absPath, relPath, ent.ContentHash))
	})

	// ----- Check 3: foreign-namespace publish lands at the absolute foreign path.
	r.Run("foreign_namespace_publish_lands_at_absolute_path", func() CheckOutcome {
		if out, ok := r.Require("grants_sufficient"); !ok {
			return out
		}
		if uasFixturePeerID == localPeerID {
			return SkipCheck("fixture peer-id collides with target's peer-id")
		}
		ent := mkPayload("foreign-publish-1")
		foreignPath := "/" + uasFixturePeerID + "/system/validate/uas/probe-1"
		if _, err := client.TreePut(ctx, foreignPath, ent); err != nil {
			return FailCheck(fmt.Sprintf("tree:put at foreign %q failed: %v — universal address space not addressable", foreignPath, err))
		}
		got, _, err := client.TreeGet(ctx, foreignPath)
		if err != nil {
			return FailCheck(fmt.Sprintf("tree:get at foreign %q failed: %v — binding written but not retrievable, address space inconsistent", foreignPath, err))
		}
		if got.ContentHash != ent.ContentHash {
			return FailCheck(fmt.Sprintf("entity at foreign %q has hash %s, expected %s", foreignPath, got.ContentHash, ent.ContentHash))
		}
		// Also verify byte-identical CBOR data round-trip (not just hash).
		if !bytes.Equal(got.Data, ent.Data) {
			return FailCheck(fmt.Sprintf("entity data bytes differ at foreign %q (got len=%d, want len=%d)", foreignPath, len(got.Data), len(ent.Data)))
		}
		return PassCheck(fmt.Sprintf("foreign %q binding round-trips (hash=%s, %d bytes)", foreignPath, ent.ContentHash, len(ent.Data)))
	})

	// ----- Check 4: foreign-namespace binding NOT visible under local namespace.
	r.Run("foreign_namespace_invisible_under_local", func() CheckOutcome {
		if out, ok := r.Require("foreign_namespace_publish_lands_at_absolute_path"); !ok {
			return out
		}
		localShadowPath := "/" + localPeerID + "/system/validate/uas/probe-1"
		_, _, err := client.TreeGet(ctx, localShadowPath)
		if err == nil {
			return FailCheck(fmt.Sprintf("tree:get at %q succeeded — foreign binding leaked into local namespace, namespaces NOT isolated", localShadowPath))
		}
		return PassCheck(fmt.Sprintf("local %q correctly not bound (foreign /{other}/... isolated from /{local}/...)", localShadowPath))
	})

	// ----- Check 5: peer-relative input never resolves to foreign.
	r.Run("peer_relative_never_resolves_to_foreign", func() CheckOutcome {
		if out, ok := r.Require("grants_sufficient"); !ok {
			return out
		}
		if uasFixturePeerID == localPeerID {
			return SkipCheck("fixture peer-id collides with target's peer-id")
		}
		ent := mkPayload("peer-relative-isolation")
		relPath := "system/validate/uas/peer-relative-isolation"
		if _, err := client.TreePut(ctx, relPath, ent); err != nil {
			return FailCheck(fmt.Sprintf("tree:put at peer-relative %q failed: %v", relPath, err))
		}
		got, _, err := client.TreeGet(ctx, "/"+localPeerID+"/"+relPath)
		if err != nil || got.ContentHash != ent.ContentHash {
			return FailCheck(fmt.Sprintf("setup failure: peer-relative put did not appear under local namespace (err=%v)", err))
		}
		foreignShadow := "/" + uasFixturePeerID + "/" + relPath
		_, _, err = client.TreeGet(ctx, foreignShadow)
		if err == nil {
			return FailCheck(fmt.Sprintf("tree:get at %q succeeded — peer-relative put leaked to foreign namespace, canonicalization broken", foreignShadow))
		}
		return PassCheck(fmt.Sprintf("peer-relative %q canonicalized to local-only (not visible at %q)", relPath, foreignShadow))
	})

	// ----- Check 6: listing at /{otherID}/ surfaces children under foreign namespace.
	r.Run("foreign_namespace_listing_at_peer_root", func() CheckOutcome {
		if out, ok := r.Require("foreign_namespace_publish_lands_at_absolute_path"); !ok {
			return out
		}
		foreignRoot := "/" + uasFixturePeerID + "/"
		entries, _, err := client.TreeListing(ctx, foreignRoot)
		if err != nil {
			return FailCheck(fmt.Sprintf("tree:get listing at %q failed: %v", foreignRoot, err))
		}
		if _, ok := entries["system"]; !ok {
			names := make([]string, 0, len(entries))
			for k := range entries {
				names = append(names, k)
			}
			return FailCheck(fmt.Sprintf("listing at %q missing `system` child after publishing at %q. entries=%v",
				foreignRoot, "/"+uasFixturePeerID+"/system/validate/uas/probe-1", names))
		}
		return PassCheck(fmt.Sprintf("listing at %q surfaces foreign-namespace children (system/ present)", foreignRoot))
	})

	// ----- Check 7: listing at deeper subpath under foreign namespace walks tree.
	r.Run("foreign_namespace_listing_at_subpath", func() CheckOutcome {
		if out, ok := r.Require("foreign_namespace_publish_lands_at_absolute_path"); !ok {
			return out
		}
		subpath := "/" + uasFixturePeerID + "/system/validate/uas/"
		entries, _, err := client.TreeListing(ctx, subpath)
		if err != nil {
			return FailCheck(fmt.Sprintf("tree:get listing at %q failed: %v", subpath, err))
		}
		if _, ok := entries["probe-1"]; !ok {
			names := make([]string, 0, len(entries))
			for k := range entries {
				names = append(names, k)
			}
			return FailCheck(fmt.Sprintf("listing at %q missing `probe-1` child after publishing at %q. entries=%v",
				subpath, subpath+"probe-1", names))
		}
		return PassCheck(fmt.Sprintf("listing at %q surfaces deep foreign-namespace child (probe-1 present)", subpath))
	})

	return r.Results()
}
