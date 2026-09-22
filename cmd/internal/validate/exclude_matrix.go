package validate

import (
	"context"
	"fmt"

	"github.com/fxamacker/cbor/v2"

	"go.entitychurch.org/entity-core-go/core/ecf"
	"go.entitychurch.org/entity-core-go/core/entity"
	"go.entitychurch.org/entity-core-go/core/hash"
	"go.entitychurch.org/entity-core-go/core/types"
)

const catExcludeMatrix = "exclude_matrix"

// runExcludeMatrix drives the §5.2/§5.4/§6.3 capability-EXCLUDE read/enumeration
// matrix on the wire, under a NARROW cap carrying an exclude — the arm every
// existing category is structurally blind to because they drive the broad
// connection cap, the one shape where the correct and buggy authorization
// answers agree (the CORE-TREE-LISTING-1-cannot-fail gap).
//
// The class was found only by a sibling reading a tree or by driving an
// excluding cap; an implementation never authors the excluded shape against its
// own peer, so go-on-go / rust-on-rust / py-on-py stays green across every hole.
// These arms are the wire mirrors of the in-process teeth in
// core/capability/h1_scope_test.go and core/tree/listing_extract_filter_test.go.
//
// Every arm carries a WELL-FORMED-exclude control, so a "deny everything" or
// "allow everything" mutation cannot pass it vacuously — that discrimination is
// the entire point, since the leak is exactly a filter that silently does
// nothing.
//
//	1  unmatchable grant-exclude fail-closed (§5.4 NEVER_MATCH; CORE-EXCLUDE-UNMATCHABLE-1)
//	3  listing per-entry filter + filtered count (§6.3 / EXTENSION-TREE §8.2)
//	4  extract per-entry filter (full-prefix AND explicit paths[])
//	5  snapshot commits only to visible bindings; diff-against-empty must not leak
//
// Vectors 2 (params-path-total) live in tree_operations.go, 6 (subscription
// include_payload overlapping exclude) in subscriptions.go, and 7 (query bulk
// read) in query.go — each where its op's machinery already is.
func runExcludeMatrix(ctx context.Context, client *PeerClient) []CheckResult {
	r := NewCheckRunner(catExcludeMatrix)

	r.Declare("unmatchable_exclude_deny_all",
		"V7 §5.4 (CORE-EXCLUDE-UNMATCHABLE-1): a grant exclude `*/secret` canonicalizes to NEVER_MATCH; in an EXCLUDE position that is fail-OPEN unless honored — an unmatchable exclude MUST exclude EVERYTHING (deny), so even the in-include path is denied. A peer that runs the unmatchable pattern through the matcher (→false→not-excluded) silently WIDENS the grant.")
	r.Declare("unmatchable_exclude_wellformed_control",
		"V7 §5.4/§6.3 (CORE-EXCLUDE-UNMATCHABLE-1 control): the SAME cap with a WELL-FORMED exclude must still ALLOW a non-excluded path (200) AND DENY the excluded path (403). Without this arm, arm 1's deny-all is unattributable — a peer that denies everything would pass it for the wrong reason.")
	r.Declare("listing_cap_filter",
		"V7 §6.3 / EXTENSION-TREE §8.2: a listing under a cap covering the prefix but EXCLUDING one child MUST omit the child, and `count` MUST reflect the filtered visible set. Driven with limit:1 too, since py measured the excluded child returned FIRST under limit 1 (the leak was order-adverse, not a no-op). Control: a broad cap shows both children and count 2.")
	r.Declare("extract_cap_filter",
		"V7 §6.3 / EXTENSION-TREE §8.2: an extract under the excluding cap MUST NOT carry the excluded binding's entity in the envelope — for a full-prefix extract AND for an explicit paths:[excluded] request (a caller naming the excluded path is still denied it). Control: a broad cap carries both entities.")
	r.Declare("snapshot_diff_no_leak",
		"V7 §6.3 / EXTENSION-TREE §11: a snapshot under the excluding cap MUST commit only to visible bindings. §11 exempts diff from path checks, sound ONLY if snapshot filters — else snapshot+diff-against-empty returns the excluded key and its content hash through the exempt op. Control: a broad-cap snapshot leaks the secret key into diff.added, proving the diff surface really sees it.")

	remote := string(client.RemotePeerID())
	treeURI := fmt.Sprintf("entity://%s/system/tree", remote)

	base := "system/validate/exclude-matrix"
	dataPrefix := base + "/data/"
	publicPath := base + "/data/public"
	secretPath := base + "/data/secret"
	voidPrefix := base + "/void/" // guaranteed-empty, for the diff baseline

	const publicType = "system/validate/xm-public-marker"
	const secretType = "system/validate/xm-secret-marker"

	// Remote-qualified patterns: a bare pattern in a child cap canonicalizes
	// against the child's granter (us), not the target peer (§5.5 / PR-8).
	gAll := "/" + remote + "/" + base + "/data/*"
	gSecret := "/" + remote + "/" + base + "/data/secret"

	// Well-formed excluding cap: covers data/* except data/secret. Ops include
	// snapshot/extract so the DISPATCH-level op check passes; §6.3 maps
	// snapshot/extract/listing to the `get` base permission for the per-entry
	// resource filter.
	scopedGrant := types.GrantEntry{
		Handlers:   types.CapabilityScope{Include: []string{"system/tree"}},
		Resources:  types.CapabilityScope{Include: []string{gAll}, Exclude: []string{gSecret}},
		Operations: types.CapabilityScope{Include: []string{"get", "snapshot", "extract"}},
	}
	// Unmatchable exclude: `*/secret` → NEVER_MATCH. Only `get` needed.
	unmatchableGrant := types.GrantEntry{
		Handlers:   types.CapabilityScope{Include: []string{"system/tree"}},
		Resources:  types.CapabilityScope{Include: []string{gAll}, Exclude: []string{"*/secret"}},
		Operations: types.CapabilityScope{Include: []string{"get"}},
	}
	// Broad control: covers data/* with NO exclude.
	broadGrant := types.GrantEntry{
		Handlers:   types.CapabilityScope{Include: []string{"system/tree"}},
		Resources:  types.CapabilityScope{Include: []string{gAll}},
		Operations: types.CapabilityScope{Include: []string{"get", "snapshot", "extract"}},
	}

	// --- setup: bind two distinct-type markers via our full connection cap,
	// then mint the three child caps. Recorded once; each arm gates on it. ---
	setupErr := ""
	mkMarker := func(typ, tag string) (entity.Entity, error) {
		raw, err := ecf.Encode(map[string]string{"marker": tag})
		if err != nil {
			return entity.Entity{}, err
		}
		return entity.NewEntity(typ, cbor.RawMessage(raw))
	}
	publicMarker, err := mkMarker(publicType, "public")
	if err != nil {
		setupErr = "build public marker: " + err.Error()
	}
	secretMarker, err := mkMarker(secretType, "secret")
	if err != nil && setupErr == "" {
		setupErr = "build secret marker: " + err.Error()
	}
	if setupErr == "" {
		if _, err := client.TreePut(ctx, publicPath, publicMarker); err != nil {
			setupErr = "bind public marker: " + err.Error()
		}
	}
	if setupErr == "" {
		if _, err := client.TreePut(ctx, secretPath, secretMarker); err != nil {
			setupErr = "bind secret marker: " + err.Error()
		}
	}
	defer func() {
		client.TreeRemove(ctx, publicPath)
		client.TreeRemove(ctx, secretPath)
	}()

	var scopedCap, scopedSig, unmatchCap, unmatchSig, broadCap, broadSig entity.Entity
	mint := func(g types.GrantEntry, label string) (entity.Entity, entity.Entity) {
		if setupErr != "" {
			return entity.Entity{}, entity.Entity{}
		}
		c, s, e := buildAttenuatedChildCap(client, g)
		if e != nil {
			setupErr = "mint " + label + " child cap: " + e.Error()
		}
		return c, s
	}
	scopedCap, scopedSig = mint(scopedGrant, "scoped")
	unmatchCap, unmatchSig = mint(unmatchableGrant, "unmatchable")
	broadCap, broadSig = mint(broadGrant, "broad")

	// drive sends an EXECUTE presenting the given child cap.
	drive := func(cap, sig entity.Entity, uri, op string, params entity.Entity, res *types.ResourceTarget) (uint, string, types.ExecuteResponseData, error) {
		env, err := buildDelegatedExecute(client, cap, sig, uri, op, params, res)
		if err != nil {
			return 0, "", types.ExecuteResponseData{}, err
		}
		respEnv, _, err := client.SendRawEnvelope(env)
		if err != nil {
			return 0, "", types.ExecuteResponseData{}, err
		}
		return extractStatusAndCode(respEnv)
	}

	gate := func() (CheckOutcome, bool) {
		if setupErr != "" {
			return FailCheck("setup: " + setupErr), false
		}
		return CheckOutcome{}, true
	}

	getParams := func() entity.Entity {
		p, _ := types.GetRequestData{}.ToEntity()
		return p
	}

	// --- (1) unmatchable grant exclude → fail closed ---

	r.Run("unmatchable_exclude_deny_all", func() CheckOutcome {
		if out, ok := gate(); !ok {
			return out
		}
		// get the IN-INCLUDE public path under the unmatchable-exclude cap: an
		// honored unmatchable exclude denies EVERYTHING, so this is 403.
		res := &types.ResourceTarget{Targets: []string{publicPath}}
		status, code, _, err := drive(unmatchCap, unmatchSig, treeURI, "get", getParams(), res)
		if err != nil {
			return FailCheck("drive: " + err.Error())
		}
		if status == 200 {
			return FailCheck("UNMATCHABLE FAIL: get on an in-include path under exclude `*/secret` (NEVER_MATCH) answered 200 — the peer ran the unmatchable pattern through the matcher and treated it as excluding nothing, silently widening the grant (fail-open exclude)")
		}
		if status == 403 {
			return PassCheck(fmt.Sprintf("unmatchable exclude `*/secret` excludes EVERYTHING → in-include path denied (status=%d code=%q); fail closed", status, code))
		}
		return FailCheck(fmt.Sprintf("UNMATCHABLE FAIL: got status=%d code=%q; want 403 (denied)", status, code))
	})

	r.Run("unmatchable_exclude_wellformed_control", func() CheckOutcome {
		if out, ok := gate(); !ok {
			return out
		}
		// Well-formed exclude: public allowed, secret denied — proving the peer
		// CAN allow and DOES honor a well-formed exclude, so arm 1's deny-all is
		// attributable to the unmatchable semantics, not a deny-everything peer.
		resPub := &types.ResourceTarget{Targets: []string{publicPath}}
		sp, _, _, err := drive(scopedCap, scopedSig, treeURI, "get", getParams(), resPub)
		if err != nil {
			return FailCheck("drive public: " + err.Error())
		}
		if sp != 200 {
			return FailCheck(fmt.Sprintf("CONTROL FAIL: well-formed-exclude cap denied the NON-excluded public path (status=%d) — a deny-all peer; arm unmatchable_exclude_deny_all is unattributable", sp))
		}
		resSec := &types.ResourceTarget{Targets: []string{secretPath}}
		ss, sc, _, err := drive(scopedCap, scopedSig, treeURI, "get", getParams(), resSec)
		if err != nil {
			return FailCheck("drive secret: " + err.Error())
		}
		if ss == 200 {
			return FailCheck("CONTROL FAIL: well-formed exclude `.../data/secret` did NOT deny the excluded path (200) — the exclude is ignored")
		}
		if ss == 403 {
			return PassCheck(fmt.Sprintf("control: well-formed exclude ALLOWS public (200) and DENIES secret (status=%d code=%q) — discriminating", ss, sc))
		}
		return FailCheck(fmt.Sprintf("CONTROL FAIL: excluded secret got status=%d code=%q; want 403", ss, sc))
	})

	// --- (3) listing per-entry filter + count ---

	r.Run("listing_cap_filter", func() CheckOutcome {
		if out, ok := gate(); !ok {
			return out
		}
		listUnder := func(cap, sig entity.Entity, limit *uint64) (types.ListingData, uint, error) {
			req := types.GetRequestData{Limit: limit}
			params, perr := req.ToEntity()
			if perr != nil {
				return types.ListingData{}, 0, perr
			}
			res := &types.ResourceTarget{Targets: []string{dataPrefix}}
			status, _, respData, derr := drive(cap, sig, treeURI, "get", params, res)
			if derr != nil {
				return types.ListingData{}, status, derr
			}
			if status != 200 {
				return types.ListingData{}, status, fmt.Errorf("listing status %d", status)
			}
			var re entity.Entity
			if e := ecf.Decode(respData.Result, &re); e != nil {
				return types.ListingData{}, status, e
			}
			ld, e := types.ListingDataFromEntity(re)
			return ld, status, e
		}

		// Scoped (excludes secret) — no limit: secret omitted, public present, count 1.
		ld, _, err := listUnder(scopedCap, scopedSig, nil)
		if err != nil {
			return FailCheck("scoped listing: " + err.Error())
		}
		if _, ok := ld.Entries["secret"]; ok {
			return FailCheck(fmt.Sprintf("LISTING FILTER FAIL: excluded child `secret` present in the listing under an excluding cap (entries=%v) — §6.3 per-entry filter not applied", xmListingKeys(ld.Entries)))
		}
		if _, ok := ld.Entries["public"]; !ok {
			return FailCheck(fmt.Sprintf("LISTING FILTER FAIL: in-scope child `public` missing (entries=%v) — over-aggressive filter", xmListingKeys(ld.Entries)))
		}
		if ld.Count != 1 {
			return FailCheck(fmt.Sprintf("LISTING FILTER FAIL: count=%d, want 1 (must reflect the filtered visible set, not the raw child count)", ld.Count))
		}

		// Scoped with limit:1 — the excluded child must not be surfaced FIRST
		// (py's order-adverse leak).
		one := uint64(1)
		ld1, _, err := listUnder(scopedCap, scopedSig, &one)
		if err != nil {
			return FailCheck("scoped listing limit:1: " + err.Error())
		}
		if _, ok := ld1.Entries["secret"]; ok {
			return FailCheck("LISTING FILTER FAIL: excluded child `secret` returned under limit:1 — the leak is order-adverse (excluded entry surfaced before the visible one)")
		}

		// Control: broad cap shows BOTH and count 2 — proving the filter, not a
		// blanket drop, removed `secret`.
		bd, _, err := listUnder(broadCap, broadSig, nil)
		if err != nil {
			return FailCheck("broad listing (control): " + err.Error())
		}
		if _, ok := bd.Entries["secret"]; !ok {
			return FailCheck(fmt.Sprintf("CONTROL FAIL: broad cap did NOT show `secret` (entries=%v) — the scoped omission is not attributable to the exclude", xmListingKeys(bd.Entries)))
		}
		if bd.Count != 2 {
			return FailCheck(fmt.Sprintf("CONTROL FAIL: broad cap count=%d, want 2", bd.Count))
		}
		return PassCheck("listing under an excluding cap omits `secret`, count=1, holds under limit:1; broad-cap control shows both (count=2) — filter is per-entry and attributable")
	})

	// --- (4) extract per-entry filter (§9 op) ---

	r.Run("extract_cap_filter", func() CheckOutcome {
		if out, ok := gate(); !ok {
			return out
		}
		if client.Profile() == ProfileCore {
			return SkipCheck("V7 v7.72 §9.0 carve-out: EXTENSION-TREE §9 op (extract) skipped under --profile core")
		}
		extractInc := func(cap, sig entity.Entity, params entity.Entity, res *types.ResourceTarget) (entity.Envelope, uint, error) {
			status, _, respData, derr := drive(cap, sig, treeURI, "extract", params, res)
			if derr != nil {
				return entity.Envelope{}, status, derr
			}
			if status != 200 {
				return entity.Envelope{}, status, nil
			}
			var re entity.Entity
			if e := ecf.Decode(respData.Result, &re); e != nil {
				return entity.Envelope{}, status, e
			}
			var env entity.Envelope
			if e := ecf.Decode(re.Data, &env); e != nil {
				return entity.Envelope{}, status, e
			}
			return env, status, nil
		}

		// Full-prefix extract under the excluding cap.
		fullParams, _ := types.ExtractRequestData{Prefix: dataPrefix}.ToEntity()
		env, status, err := extractInc(scopedCap, scopedSig, fullParams, &types.ResourceTarget{Targets: []string{dataPrefix}})
		if err != nil {
			return FailCheck("scoped extract: " + err.Error())
		}
		if status != 200 {
			return FailCheck(fmt.Sprintf("EXTRACT FILTER FAIL: full-prefix extract under the excluding cap got status=%d, want 200 (with filtered envelope)", status))
		}
		if _, ok := env.Included[secretMarker.ContentHash]; ok {
			return FailCheck("EXTRACT FILTER FAIL: excluded binding's entity rode in the extract envelope — §6.3 per-entry filter not applied before BuildTrie (the envelope disclosed a forbidden entity)")
		}
		if _, ok := env.Included[publicMarker.ContentHash]; !ok {
			return FailCheck("EXTRACT FILTER FAIL: in-scope public entity missing from the extract envelope — over-aggressive filter")
		}

		// Explicit paths:[secret] — a caller naming the excluded path is still
		// denied it (either refused, or an envelope without the secret entity).
		explParams, _ := types.ExtractRequestData{Paths: []string{secretPath}}.ToEntity()
		env2, st2, err := extractInc(scopedCap, scopedSig, explParams, &types.ResourceTarget{Targets: []string{secretPath}})
		if err != nil {
			return FailCheck("scoped explicit-path extract: " + err.Error())
		}
		if st2 == 200 {
			if _, ok := env2.Included[secretMarker.ContentHash]; ok {
				return FailCheck("EXTRACT FILTER FAIL: explicit paths:[secret] returned the excluded entity — naming an excluded path explicitly bypasses the filter")
			}
		}

		// Control: broad cap carries BOTH.
		bParams, _ := types.ExtractRequestData{Prefix: dataPrefix}.ToEntity()
		benv, _, err := extractInc(broadCap, broadSig, bParams, &types.ResourceTarget{Targets: []string{dataPrefix}})
		if err != nil {
			return FailCheck("broad extract (control): " + err.Error())
		}
		if _, ok := benv.Included[secretMarker.ContentHash]; !ok {
			return FailCheck("CONTROL FAIL: broad cap extract did NOT carry the secret entity — the scoped omission is not attributable to the exclude")
		}
		if _, ok := benv.Included[publicMarker.ContentHash]; !ok {
			return FailCheck("CONTROL FAIL: broad cap extract did NOT carry the public entity")
		}
		return PassCheck("extract under an excluding cap omits the excluded entity (full-prefix AND explicit paths[]); broad-cap control carries both — filter is per-entry and attributable")
	})

	// --- (5) snapshot commits only to visible bindings; diff must not leak ---

	r.Run("snapshot_diff_no_leak", func() CheckOutcome {
		if out, ok := gate(); !ok {
			return out
		}
		if client.Profile() == ProfileCore {
			return SkipCheck("V7 v7.72 §9.0 carve-out: EXTENSION-TREE §9 op (snapshot) skipped under --profile core")
		}
		snapUnder := func(cap, sig entity.Entity) (entity.Entity, uint, error) {
			params, _ := types.SnapshotRequestData{Prefix: dataPrefix}.ToEntity()
			status, _, respData, derr := drive(cap, sig, treeURI, "snapshot", params, &types.ResourceTarget{Targets: []string{dataPrefix}})
			if derr != nil {
				return entity.Entity{}, status, derr
			}
			if status != 200 {
				return entity.Entity{}, status, nil
			}
			var re entity.Entity
			if e := ecf.Decode(respData.Result, &re); e != nil {
				return entity.Entity{}, status, e
			}
			return re, status, nil
		}

		// Empty baseline snapshot (connection cap; a guaranteed-empty prefix).
		_, emptySnapEntity, err := client.TreeSnapshot(ctx, voidPrefix)
		if err != nil {
			return FailCheck("empty baseline snapshot: " + err.Error())
		}

		// Scoped snapshot (excludes secret).
		scopedSnap, st, err := snapUnder(scopedCap, scopedSig)
		if err != nil {
			return FailCheck("scoped snapshot: " + err.Error())
		}
		if st != 200 {
			return FailCheck(fmt.Sprintf("SNAPSHOT FILTER FAIL: scoped snapshot got status=%d, want 200", st))
		}
		// diff is path-exempt (§11) → drive under the connection cap.
		diff, err := client.TreeDiff(ctx, emptySnapEntity, scopedSnap)
		if err != nil {
			return FailCheck("diff empty→scoped: " + err.Error())
		}
		if _, ok := diff.Added["secret"]; ok {
			return FailCheck("SNAPSHOT FILTER FAIL: the excluded key `secret` appears in diff(empty, scoped).added — the scoped snapshot committed to a binding the caller may not see; snapshot+diff-against-empty leaks the key and its content hash through the diff exemption")
		}
		for _, h := range diff.Added {
			if h == secretMarker.ContentHash {
				return FailCheck("SNAPSHOT FILTER FAIL: the excluded content hash appears in diff(empty, scoped).added under a different key — the excluded entity leaked")
			}
		}
		if _, ok := diff.Added["public"]; !ok {
			return FailCheck(fmt.Sprintf("SNAPSHOT FILTER FAIL: the in-scope key `public` is missing from diff.added (added=%v) — over-aggressive filter or empty snapshot", diffKeys(diff.Added)))
		}

		// Control: broad-cap snapshot leaks `secret` into diff.added — proving
		// the diff surface really exposes it, so the scoped omission is real.
		broadSnap, bst, err := snapUnder(broadCap, broadSig)
		if err != nil {
			return FailCheck("broad snapshot (control): " + err.Error())
		}
		if bst != 200 {
			return FailCheck(fmt.Sprintf("CONTROL FAIL: broad snapshot got status=%d, want 200", bst))
		}
		bdiff, err := client.TreeDiff(ctx, emptySnapEntity, broadSnap)
		if err != nil {
			return FailCheck("diff empty→broad (control): " + err.Error())
		}
		if _, ok := bdiff.Added["secret"]; !ok {
			return FailCheck(fmt.Sprintf("CONTROL FAIL: broad-cap diff.added does NOT contain `secret` (added=%v) — the diff surface cannot see it, so the scoped omission is not attributable to the exclude", diffKeys(bdiff.Added)))
		}
		return PassCheck("snapshot under an excluding cap commits only to the visible binding — `secret` absent from diff-against-empty (key and hash); broad-cap control leaks it, proving the diff surface exposes it")
	})

	return r.Results()
}

// listingKeys returns the keys of a listing Entries map for diagnostics.
func xmListingKeys(m map[string]interface{}) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	return keys
}

// diffKeys returns the keys of a diff Added map for diagnostics.
func diffKeys(m map[string]hash.Hash) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	return keys
}
