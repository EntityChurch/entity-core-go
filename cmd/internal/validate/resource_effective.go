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

const catResourceEffective = "resource_effective"

// runResourceEffective drives CORE-RESOURCE-EFFECTIVE-1 (§3.3, §5.2, §6.3 —
// 0.8.2.20): the subject a handler acts on is drawn from effective_targets
// (targets minus the CALLER's own excludes), never resource.targets[0]. Five
// arms plus the G6/R11 fail-closed row, positive and negative.
//
// F68 is a two-layer drift: check_resource_scope skips caller-excluded targets
// while a handler that indexes targets[0] acts on one the authorizer never
// checked. The bypass needs a grant that does NOT cover the target the caller
// excludes, so the scoped child cap below covers only .../allowed/*; the
// forbidden target .../secret is out of grant. A degenerate open grant would
// have nothing to bypass (the measurement invariant arch names), so this check
// presents a NARROW cap, not the connection cap.
//
// The mixed case (arm b / §2.4c) cannot be scored on a status: targets:[P,Q]
// exclude:[P] answers 200 whichever target was read. It is scored on a WITNESS —
// the type of the returned entity, which can only have come from one path.
func runResourceEffective(ctx context.Context, client *PeerClient) []CheckResult {
	r := NewCheckRunner(catResourceEffective)

	r.Declare("resource_effective_self_excluded_path_required",
		"V7 §3.3/§5.2 (CORE-RESOURCE-EFFECTIVE-1 a): a resource-requiring op with targets:[P] exclude:[P] has an EMPTY effective set — the absent case — and MUST answer 400 path_required, NOT act on P. Security vector: three artifacts answered 200 with an unauthorized entity (F68).")
	r.Declare("resource_effective_antecedent_denied",
		"V7 §5.2 (CORE-RESOURCE-EFFECTIVE-1 c): the antecedent control — the same forbidden target P with NO exclude MUST be denied 403 capability_denied. Without this arm a self-excluded pass cannot be told from a peer that denies everything.")
	r.Declare("resource_effective_two_targets_ambiguous",
		"V7 §3.3 (CORE-RESOURCE-EFFECTIVE-1 d): two in-grant effective targets on a resource-requiring op MUST answer 400 ambiguous_resource. Unreachable by accident, which is why three impls shipped the absent arm alone against correct text.")
	r.Declare("resource_effective_pattern_malformed",
		"V7 §3.3 (CORE-RESOURCE-EFFECTIVE-1 e): a single pattern target on a resource-requiring op (which takes a concrete path) MUST answer 400 malformed_resource.")
	r.Declare("resource_effective_case_d_witness",
		"V7 §5.2 (CORE-RESOURCE-EFFECTIVE-1 b): targets:[P,Q] exclude:[P] with Q in-grant and P not MUST proceed on Q — decided by a WITNESS FIELD (the returned entity type), never a status, since both selections answer 200. The witness rule is GUIDE-CONFORMANCE §2.4c. A peer that counts the effective list and then indexes targets[0] reads P; the witness is what catches it.")
	r.Declare("resource_effective_no_disclosure",
		"V7 §6.3/§5.2 (CORE-RESOURCE-EFFECTIVE-1 a, disclosure form): tree:get with targets:[P] exclude:[P], P out of grant with a distinct entity bound at P, MUST NOT return P's entity (the F68 disclosure). A conformant peer refuses or lists; it never discloses the excluded, unauthorized path.")
	r.Declare("resource_effective_tree_get_n6_two_empties",
		"ENTITY-CORE-PROTOCOL §3.3 (N6, 0.8.2.24; EXTENSION-TREE get row): the two empties differ. A genuinely ABSENT resource → 200 root listing (the positive control, established by the same drive); a resource PRESENT with a non-empty target set whose EFFECTIVE set is empty (in-grant P, exclude:[P]) → 400 path_required. Serving the second case a listing answers a request for one excluded path with a listing of the tree — the defect N6 closes. The excluded target is IN-GRANT so the 400 is attributable to N6, not to a capability denial. WIRE vector: an in-tree test cannot see a dispatch that pre-narrows targets to effective (rust's N6 was dead code at the wire for exactly this reason); this arm drives the real dispatch path.")
	r.Declare("resource_effective_tree_snapshot_n6_two_empties",
		"ENTITY-CORE-PROTOCOL 0.8.2.24 N6, snapshot form (py's cross-impl finding 2026-09-12): tree:snapshot binds N6 too, and is its widest form — §8.4 exempts the snapshot→diff path from a path check, so a self-excluded target served the whole-tree snapshot leaks the excluded key + its content hash out of a diff-against-empty. ABSENT resource → 200 snapshot (positive control); PRESENT with empty effective set → 400 path_required.")
	r.Declare("resource_effective_tree_extract_n6_two_empties",
		"ENTITY-CORE-PROTOCOL 0.8.2.25 N6, extract form (EXTENSION-TREE §2.2a; arch ROUTING-2026-09-14-e §4): tree:extract is the THIRD BROAD-RESULT site and the WIDEST — get leaks a listing of paths, snapshot a root hash, extract returns the bound entities themselves. Until 0.8.2.25 go's handleExtract had no N6 guard (self-excluded target fell back to the params prefix, default \"\", validatePrefix(\"\") true → whole-tree extract at 200). ABSENT resource → 200 extract of the tree (positive control, established by the same drive so the 400 is attributable to N6, not a capability denial); PRESENT with empty effective set (targets:[P] exclude:[P]) → 400 path_required. WIRE vector: an in-tree test cannot see the dispatch pre-narrowing (rust's N6 was dead code at the wire for exactly this).")

	remote := string(client.RemotePeerID())
	treeURI := fmt.Sprintf("entity://%s/system/tree", remote)
	contentURI := fmt.Sprintf("entity://%s/system/content", remote)

	base := "system/validate/f68"
	secretPath := base + "/secret"     // forbidden: out of the scoped grant
	allowedPath := base + "/allowed/y" // permitted: under .../allowed/*
	allowedA := base + "/allowed/a"
	allowedB := base + "/allowed/b"
	allowedPattern := base + "/allowed/*"

	const secretType = "system/validate/f68-secret-marker"
	const allowedType = "system/validate/f68-allowed-marker"

	// Scoped child cap: covers ONLY .../allowed and .../allowed/*, on the REMOTE
	// peer's namespace. Absolute remote-qualified patterns are required — a bare
	// pattern in the child cap canonicalizes against the child's granter (us),
	// not the target peer (§5.5 / PR-8).
	grantAllowed := "/" + remote + "/" + base + "/allowed"
	grantAllowedSub := "/" + remote + "/" + base + "/allowed/*"
	scopedGrant := types.GrantEntry{
		Handlers:   types.CapabilityScope{Include: []string{"system/tree", "system/content"}},
		Resources:  types.CapabilityScope{Include: []string{grantAllowed, grantAllowedSub}},
		Operations: types.CapabilityScope{Include: []string{"get"}},
	}

	// --- setup: bind the two distinct-type markers via our own (full) cap, and
	// mint the scoped child cap. Recorded once; each arm gates on it. ---
	setupErr := ""
	mkMarker := func(typ, tag string) (entity.Entity, error) {
		raw, err := ecf.Encode(map[string]string{"marker": tag})
		if err != nil {
			return entity.Entity{}, err
		}
		return entity.NewEntity(typ, cbor.RawMessage(raw))
	}
	secretMarker, err := mkMarker(secretType, "secret")
	if err != nil {
		setupErr = "build secret marker: " + err.Error()
	}
	allowedMarker, err := mkMarker(allowedType, "allowed")
	if err != nil && setupErr == "" {
		setupErr = "build allowed marker: " + err.Error()
	}
	if setupErr == "" {
		if _, err := client.TreePut(ctx, secretPath, secretMarker); err != nil {
			setupErr = "bind secret marker: " + err.Error()
		}
	}
	if setupErr == "" {
		if _, err := client.TreePut(ctx, allowedPath, allowedMarker); err != nil {
			setupErr = "bind allowed marker: " + err.Error()
		}
	}
	defer func() {
		client.TreeRemove(ctx, secretPath)
		client.TreeRemove(ctx, allowedPath)
	}()

	var childCap, childSig entity.Entity
	if setupErr == "" {
		childCap, childSig, err = buildAttenuatedChildCap(client, scopedGrant)
		if err != nil {
			setupErr = "mint scoped child cap: " + err.Error()
		}
	}

	// drive sends an EXECUTE presenting the scoped child cap.
	drive := func(uri, op string, params entity.Entity, res *types.ResourceTarget) (uint, string, types.ExecuteResponseData, error) {
		env, err := buildDelegatedExecute(client, childCap, childSig, uri, op, params, res)
		if err != nil {
			return 0, "", types.ExecuteResponseData{}, err
		}
		respEnv, _, err := client.SendRawEnvelope(env)
		if err != nil {
			return 0, "", types.ExecuteResponseData{}, err
		}
		return extractStatusAndCode(respEnv)
	}

	// content:get params — a resource-requiring op whose §3.3 cardinality fires
	// in requireResource BEFORE the hashes are read, so a dummy hash suffices.
	var dummy hash.Hash
	dummy.Algorithm = hash.AlgorithmSHA256
	dummy.Digest[0] = 0x01
	contentGetParams, cgErr := types.ContentGetRequestData{Hashes: []hash.Hash{dummy}}.ToEntity()
	if cgErr != nil && setupErr == "" {
		setupErr = "build content get params: " + cgErr.Error()
	}

	gate := func() (CheckOutcome, bool) {
		if setupErr != "" {
			return FailCheck("setup: " + setupErr), false
		}
		return CheckOutcome{}, true
	}

	// (a) self-excluded → path_required (content:get, resource-requiring).
	r.Run("resource_effective_self_excluded_path_required", func() CheckOutcome {
		if out, ok := gate(); !ok {
			return out
		}
		res := &types.ResourceTarget{Targets: []string{secretPath}, Exclude: []string{secretPath}}
		status, code, _, err := drive(contentURI, "get", contentGetParams, res)
		if err != nil {
			return FailCheck("drive: " + err.Error())
		}
		if status == 400 && code == "path_required" {
			return PassCheck("targets:[P] exclude:[P] → empty effective → 400 path_required (F68 closed; the excluded, out-of-grant P is never acted on)")
		}
		if status == 200 {
			return FailCheck(fmt.Sprintf("RESOURCE-EFFECTIVE a FAIL: targets:[P] exclude:[P] answered 200 — the peer acted on a caller-excluded target (F68 bypass)"))
		}
		return FailCheck(fmt.Sprintf("RESOURCE-EFFECTIVE a FAIL: got status=%d code=%q; want 400 path_required", status, code))
	})

	// (c) antecedent control: same P, no exclude → 403 capability_denied.
	r.Run("resource_effective_antecedent_denied", func() CheckOutcome {
		if out, ok := gate(); !ok {
			return out
		}
		res := &types.ResourceTarget{Targets: []string{secretPath}}
		status, code, _, err := drive(contentURI, "get", contentGetParams, res)
		if err != nil {
			return FailCheck("drive: " + err.Error())
		}
		if status == 403 && code == "capability_denied" {
			return PassCheck("antecedent control: forbidden P with no exclude → 403 capability_denied (proves the scoped cap really excludes P, so arm (a)'s path_required is attributable to the exclusion, not to a deny-all peer)")
		}
		return FailCheck(fmt.Sprintf("RESOURCE-EFFECTIVE c FAIL: forbidden P with no exclude got status=%d code=%q; want 403 capability_denied — if this is not a denial the whole family is unattributable", status, code))
	})

	// (d) two in-grant targets → ambiguous_resource.
	r.Run("resource_effective_two_targets_ambiguous", func() CheckOutcome {
		if out, ok := gate(); !ok {
			return out
		}
		res := &types.ResourceTarget{Targets: []string{allowedA, allowedB}}
		status, code, _, err := drive(contentURI, "get", contentGetParams, res)
		if err != nil {
			return FailCheck("drive: " + err.Error())
		}
		if status == 400 && code == "ambiguous_resource" {
			return PassCheck("two in-grant effective targets → 400 ambiguous_resource (§3.3)")
		}
		return FailCheck(fmt.Sprintf("RESOURCE-EFFECTIVE d FAIL: two targets got status=%d code=%q; want 400 ambiguous_resource", status, code))
	})

	// (e) single pattern target → malformed_resource.
	r.Run("resource_effective_pattern_malformed", func() CheckOutcome {
		if out, ok := gate(); !ok {
			return out
		}
		res := &types.ResourceTarget{Targets: []string{allowedPattern}}
		status, code, _, err := drive(contentURI, "get", contentGetParams, res)
		if err != nil {
			return FailCheck("drive: " + err.Error())
		}
		if status == 400 && code == "malformed_resource" {
			return PassCheck("single pattern target on a resource-requiring op → 400 malformed_resource (§3.3)")
		}
		return FailCheck(fmt.Sprintf("RESOURCE-EFFECTIVE e FAIL: pattern target got status=%d code=%q; want 400 malformed_resource", status, code))
	})

	// (b) case D: mixed target, one excluded, witness on the returned type.
	r.Run("resource_effective_case_d_witness", func() CheckOutcome {
		if out, ok := gate(); !ok {
			return out
		}
		// targets:[secret, allowed] exclude:[secret] → effective [allowed].
		res := &types.ResourceTarget{Targets: []string{secretPath, allowedPath}, Exclude: []string{secretPath}}
		status, code, respData, err := drive(treeURI, "get", mustSimpleTreeGetParams(), res)
		if err != nil {
			return FailCheck("drive: " + err.Error())
		}
		if status != 200 {
			return FailCheck(fmt.Sprintf("RESOURCE-EFFECTIVE b FAIL: expected 200 on effective [Q], got status=%d code=%q", status, code))
		}
		var result entity.Entity
		if derr := ecf.Decode(respData.Result, &result); derr != nil {
			return FailCheck("decode result entity for witness: " + derr.Error())
		}
		switch result.Type {
		case allowedType:
			return PassCheck("case D: targets:[P,Q] exclude:[P] read Q — witness type is the allowed marker, never P's (the subject is effective[0], not targets[0])")
		case secretType:
			return FailCheck("RESOURCE-EFFECTIVE b FAIL: witness type is the SECRET marker — the peer read targets[0]=P, a caller-excluded, unauthorized path (F68 confused selection)")
		default:
			return WarnCheck(fmt.Sprintf("RESOURCE-EFFECTIVE b INCONCLUSIVE: witness type %q is neither marker; setup or listing shape differs — investigate before trusting", result.Type))
		}
	})

	// (a, disclosure form) tree:get self-excluded forbidden P → never discloses P.
	r.Run("resource_effective_no_disclosure", func() CheckOutcome {
		if out, ok := gate(); !ok {
			return out
		}
		res := &types.ResourceTarget{Targets: []string{secretPath}, Exclude: []string{secretPath}}
		status, code, respData, err := drive(treeURI, "get", mustSimpleTreeGetParams(), res)
		if err != nil {
			return FailCheck("drive: " + err.Error())
		}
		if status == 200 {
			var result entity.Entity
			if derr := ecf.Decode(respData.Result, &result); derr == nil && result.Type == secretType {
				return FailCheck("RESOURCE-EFFECTIVE a-disclosure FAIL: tree:get on targets:[P] exclude:[P] returned P's entity — the F68 disclosure")
			}
			// 200 without P's entity (e.g. an empty/other listing) is not a disclosure.
			return PassCheck("tree:get on the self-excluded forbidden P did not disclose P's entity (200 without the secret marker)")
		}
		// A refusal (403 path-denied / 400 path_required) is the cleaner non-disclosure.
		return PassCheck(fmt.Sprintf("tree:get on the self-excluded forbidden P refused (status=%d code=%q) — P's entity is not disclosed", status, code))
	})

	// N6 (0.8.2.24) — tree:get two-empties on the WIRE. These arms drive with the
	// client's OWN connection cap (full authority), NOT the scoped child cap: the
	// discriminator's positive control is that the ABSENT case is SERVED (200), so
	// the cap must cover the root listing. Under a scoped cap an absent tree:get is
	// 403 (root out of grant) and the 400 becomes unattributable — a lesson the
	// wire run taught after the in-tree test could not (the in-tree Resource never
	// traverses dispatch; the wire does). N6 fires in the handler BEFORE the path
	// check, so the excluded target need not be specially placed.
	n6ProbePath := "system/validate/n6/x"
	r.Run("resource_effective_tree_get_n6_two_empties", func() CheckOutcome {
		// Positive control: a genuinely absent resource is served (200 listing).
		aEnv, _, aErr := client.SendExecute(ctx, treeURI, "get", mustSimpleTreeGetParams(), nil)
		if aErr != nil {
			return FailCheck("send absent: " + aErr.Error())
		}
		aStatus, aCode, _, _ := extractStatusAndCode(aEnv)
		if aStatus != 200 {
			return FailCheck(fmt.Sprintf("N6 get UNATTRIBUTABLE: absent resource did not serve a listing (status=%d code=%q); the 400 below cannot be attributed to presence-with-exclusion", aStatus, aCode))
		}
		// Discriminator: present with a target the caller excludes → empty
		// effective set → 400 path_required, NOT a listing.
		res := &types.ResourceTarget{Targets: []string{n6ProbePath}, Exclude: []string{n6ProbePath}}
		env, _, err := client.SendExecute(ctx, treeURI, "get", mustSimpleTreeGetParams(), res)
		if err != nil {
			return FailCheck("send self-excluded: " + err.Error())
		}
		status, code, _, _ := extractStatusAndCode(env)
		if status == 400 && code == "path_required" {
			return PassCheck("N6: absent → 200 listing, present-but-effectively-empty (targets:[P] exclude:[P]) → 400 path_required. The two empties are distinguished on the WIRE; go's dispatch carries Exclude to the handler and does not pre-narrow targets to effective, so the handler's N6 guard is live (not dead code at the wire).")
		}
		if status == 200 {
			return FailCheck("N6 get FAIL: targets:[P] exclude:[P] answered 200 — the peer served a listing for a request that names one excluded path (the two empties collapsed; if the dispatch pre-narrows targets to effective, the handler's N6 guard is dead code at the wire)")
		}
		return FailCheck(fmt.Sprintf("N6 get FAIL: got status=%d code=%q; want 400 path_required", status, code))
	})

	// N6 (0.8.2.24) — tree:snapshot two-empties on the WIRE (py's finding).
	r.Run("resource_effective_tree_snapshot_n6_two_empties", func() CheckOutcome {
		snapParams, sErr := types.SnapshotRequestData{}.ToEntity()
		if sErr != nil {
			return FailCheck("build snapshot params: " + sErr.Error())
		}
		// Positive control: absent resource → whole-tree snapshot served (200).
		aEnv, _, aErr := client.SendExecute(ctx, treeURI, "snapshot", snapParams, nil)
		if aErr != nil {
			return FailCheck("send absent snapshot: " + aErr.Error())
		}
		aStatus, aCode, _, _ := extractStatusAndCode(aEnv)
		if aStatus != 200 {
			return FailCheck(fmt.Sprintf("N6 snapshot UNATTRIBUTABLE: absent resource did not serve a snapshot (status=%d code=%q)", aStatus, aCode))
		}
		// Discriminator: present, sole target excluded → 400 path_required.
		n6Prefix := "system/validate/n6/"
		res := &types.ResourceTarget{Targets: []string{n6Prefix}, Exclude: []string{n6Prefix}}
		env, _, err := client.SendExecute(ctx, treeURI, "snapshot", snapParams, res)
		if err != nil {
			return FailCheck("send self-excluded snapshot: " + err.Error())
		}
		status, code, _, _ := extractStatusAndCode(env)
		if status == 400 && code == "path_required" {
			return PassCheck("N6 snapshot: absent → 200 snapshot, present-but-effectively-empty → 400 path_required. The §8.4 diff exemption cannot leak an excluded key via a whole-tree snapshot.")
		}
		if status == 200 {
			return FailCheck("N6 snapshot FAIL: targets:[P] exclude:[P] answered 200 — a self-excluded target was served the whole-tree snapshot (the §8.4 leak py drove)")
		}
		return FailCheck(fmt.Sprintf("N6 snapshot FAIL: got status=%d code=%q; want 400 path_required", status, code))
	})

	// N6 (0.8.2.25) — tree:extract two-empties on the WIRE (arch §4, the widest
	// BROAD-RESULT site). Same shape as snapshot; extract returns the ENTITIES, so
	// the positive control is scoped to the already-seeded `base/` prefix (the two
	// f68 markers) rather than the whole tree — a whole-tree extract after the full
	// suite has run returns every bound entity and times out. arch requirement 2:
	// assert the absent extract CONTAINS a seeded binding, so a peer that never
	// reached the branch (empty count) does not pass the positive control.
	r.Run("resource_effective_tree_extract_n6_two_empties", func() CheckOutcome {
		if setupErr != "" {
			return FailCheck("setup: " + setupErr)
		}
		basePrefix := base + "/"
		extractParams, eErr := types.ExtractRequestData{Prefix: basePrefix}.ToEntity()
		if eErr != nil {
			return FailCheck("build extract params: " + eErr.Error())
		}
		// Positive control: absent resource → extract of the seeded prefix (200),
		// and it MUST contain the seeded bindings.
		aEnv, _, aErr := client.SendExecute(ctx, treeURI, "extract", extractParams, nil)
		if aErr != nil {
			return FailCheck("send absent extract: " + aErr.Error())
		}
		aStatus, aCode, _, _ := extractStatusAndCode(aEnv)
		if aStatus != 200 {
			return FailCheck(fmt.Sprintf("N6 extract UNATTRIBUTABLE: absent resource did not serve an extract of the seeded prefix (status=%d code=%q); the 400 below cannot be attributed to presence-with-exclusion", aStatus, aCode))
		}
		if n := extractedBindingCount(aEnv); n == 0 {
			return FailCheck("N6 extract UNATTRIBUTABLE: absent extract of the seeded prefix returned no bindings — cannot distinguish a served extract from a peer that never reached the branch (arch requirement 2)")
		}
		// Discriminator: present, sole target excluded → empty effective → 400
		// path_required (the N6 guard fires before the prefix/path check, so the
		// target path need not be specially placed; the 400 is path_required, not
		// a capability denial).
		selfExcl := base + "/allowed/y"
		res := &types.ResourceTarget{Targets: []string{selfExcl}, Exclude: []string{selfExcl}}
		env, _, err := client.SendExecute(ctx, treeURI, "extract", extractParams, res)
		if err != nil {
			return FailCheck("send self-excluded extract: " + err.Error())
		}
		status, code, _, _ := extractStatusAndCode(env)
		if status == 400 && code == "path_required" {
			return PassCheck("N6 extract: absent → 200 extract with the seeded bindings, present-but-effectively-empty (targets:[P] exclude:[P]) → 400 path_required. The widest BROAD-RESULT site does not return the bound entities for a request that names one excluded path.")
		}
		if status == 200 {
			return FailCheck("N6 extract FAIL: targets:[P] exclude:[P] answered 200 — a self-excluded target was served the extract (bound entities), the widest N6 leak")
		}
		return FailCheck(fmt.Sprintf("N6 extract FAIL: got status=%d code=%q; want 400 path_required", status, code))
	})

	return r.Results()
}

// extractedBindingCount returns the number of bindings in a tree:extract
// response. handleExtract bundles the result as an envelope encoded into the
// result entity's Data, so we decode two layers: the EXECUTE_RESPONSE result
// entity, then the extract envelope it carries. Returns 0 on any decode miss —
// the caller treats 0 as "no bindings", which fails the positive control.
func extractedBindingCount(respEnv entity.Envelope) int {
	respData, err := types.ExecuteResponseDataFromEntity(respEnv.Root)
	if err != nil {
		return 0
	}
	var resultEnt entity.Entity
	if err := ecf.Decode(respData.Result, &resultEnt); err != nil {
		return 0
	}
	var extractEnv entity.Envelope
	if err := ecf.Decode(resultEnt.Data, &extractEnv); err != nil {
		return 0
	}
	return len(extractEnv.Included)
}

// mustSimpleTreeGetParams builds a minimal system/tree/get-request params entity.
func mustSimpleTreeGetParams() entity.Entity {
	params, _, err := buildSimpleGetParams()
	if err != nil {
		// buildSimpleGetParams only fails on an ECF encode bug; a zero entity
		// makes the drive fail loudly rather than silently pass.
		return entity.Entity{}
	}
	return params
}
