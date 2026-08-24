package validate

import (
	"context"
	"fmt"
	"reflect"
	"sort"
	"strings"

	"go.entitychurch.org/entity-core-go/core/ecf"
	"go.entitychurch.org/entity-core-go/core/entity"
	"go.entitychurch.org/entity-core-go/core/hash"
	"go.entitychurch.org/entity-core-go/core/types"
)

const catTypeSystem = "type_system"

// runTypeSystem compares the remote peer's type definitions against
// the local registry and the spec.
func runTypeSystem(ctx context.Context, client *PeerClient) []CheckResult {
	r := NewCheckRunner(catTypeSystem)
	coreOnly := client.Profile() == ProfileCore

	// Build local registry with all types.
	localReg := types.NewTypeRegistry()
	types.RegisterCoreTypes(localReg)

	// Also register handler-specific types the same way handlers do.
	// Connect types.
	localReg.ReflectType(types.TypeHello, reflect.TypeOf(types.HelloData{}))
	localReg.ReflectType(types.TypeAuthenticate, reflect.TypeOf(types.AuthenticateData{}))
	localReg.OverrideField(types.TypeHello, "peer_id", types.FieldSpec{TypeRef: "system/peer-id"})
	localReg.OverrideField(types.TypeAuthenticate, "peer_id", types.FieldSpec{TypeRef: "system/peer-id"})
	// Tree types.
	localReg.ReflectType(types.TypeTreeGetRequest, reflect.TypeOf(types.GetRequestData{}))
	localReg.ReflectType(types.TypeTreePutRequest, reflect.TypeOf(types.PutRequestData{}))
	localReg.OverrideField(types.TypeTreePutRequest, "entity",
		types.FieldSpec{TypeRef: types.TypeCoreEntity, Optional: true})
	localReg.ReflectType(types.TypeTreeListing, reflect.TypeOf(types.ListingData{}))
	localReg.OverrideField(types.TypeTreeListing, "entries",
		types.FieldSpec{MapOf: &types.FieldSpec{TypeRef: "system/tree/listing-entry"}})
	localReg.OverrideField(types.TypeTreeListing, "path",
		types.FieldSpec{TypeRef: "system/tree/path"})

	allLocalTypes := localReg.All()

	// --- Declare all checks ---

	r.Declare("types_listing_available", "Types §11.4")

	// Declare per-type fetch and match checks.
	for _, localDef := range allLocalTypes {
		prefix := "type_" + sanitizeName(localDef.Name)
		r.Declare(prefix+"_fetch", "Types §11.2")
		r.Declare(prefix+"_match", "Types §12.3")
	}

	r.Declare("types_all_present", "Types §11.2")

	// --- Run checks ---

	r.Run("types_listing_available", func() CheckOutcome {
		entries, _, err := client.TreeListing(ctx, "system/type/")
		if err != nil {
			return FailCheck("failed to fetch system/type/ listing: " + err.Error())
		}
		return PassCheck(fmt.Sprintf("system/type/ listing returned %d entries", len(entries)))
	})

	// Track which types are present remotely. Provisional (proposal-stage)
	// types are tracked separately — their absence/divergence must NOT count
	// toward the ratified-core conformance floor (R1 / GUIDE-CONFORMANCE §7).
	presentCount := 0
	missingNames := []string{}
	provisionalMissing := []string{}

	for _, localDef := range allLocalTypes {
		localDef := localDef
		prefix := "type_" + sanitizeName(localDef.Name)
		// V7 v7.72 §9.5: under --profile core, types outside the 53-type
		// core floor are treated as provisional (matched-if-present,
		// not-a-FAIL-if-absent). Same precedent shape as the
		// system/substitute/* family — see isProvisionalType.
		// §6.7 is OPTIONAL as a whole (§12.3) and, per the 2026-08-07 ruling
		// (arch `c78b3dc`, MUST), a peer that declines it does not owe its
		// types. Same carve-out shape, different reason: these are ratified,
		// not proposal-stage.
		optionalSection := section67TypesOnly([]string{localDef.Name})
		provisional := isProvisionalType(localDef.Name) || optionalSection ||
			(coreOnly && !inCoreTypeFloor(localDef.Name))

		r.Run(prefix+"_fetch", func() CheckOutcome {
			path := localDef.TreePath()
			remoteEnt, _, err := client.TreeGet(ctx, path)
			if err != nil {
				// Provisional family: absence is conformant (the surface is
				// proposal-stage, scoped to an unratified extension — like
				// durability). Under --profile core (v7.72 §9.5) the 97
				// extension types are likewise matched-if-present, not-a-
				// FAIL-if-absent. Surface as WARN, keep out of the floor.
				if provisional {
					provisionalMissing = append(provisionalMissing, localDef.Name)
					reason := "provisional (proposal-stage) type — conformant; not part of ratified-core floor (R1)"
					if optionalSection {
						// NOTE the limit of this check: it cannot see whether the
						// peer actually OFFERS §6.7. A peer that ships the
						// operations but omits their types is under-reported here.
						// The operations themselves are scored by the
						// `reachability` category, which is where offering-without-
						// vocabulary would surface.
						reason = "EXTENSION-NETWORK §6.7 (reachability facts) is OPTIONAL as a whole (§12.3), and a peer that declines the section does not owe its types — ruled 2026-08-07 (arch c78b3dc, MUST): a type is owed by the surface that uses it. Absence here is conformant, not a gap"
					}
					if coreOnly && !inCoreTypeFloor(localDef.Name) {
						reason = "outside V7 v7.72 §9.5 Core Type Floor — matched-if-present under --profile core, not-a-FAIL-if-absent"
					}
					return WarnCheck(fmt.Sprintf("%s absent — %s", localDef.Name, reason))
				}
				missingNames = append(missingNames, localDef.Name)
				return FailCheck(fmt.Sprintf("failed to fetch %s: %v", path, err))
			}
			presentCount++

			// Decode remote type definition.
			var remoteDef types.TypeDefinition
			if err := ecf.Decode(remoteEnt.Data, &remoteDef); err != nil {
				r.Store(prefix+"_decode_err", err.Error())
				return PassCheck(fmt.Sprintf("fetched %s (decode checked separately)", path))
			}
			r.Store(prefix+"_remote_def", remoteDef)
			return PassCheck(fmt.Sprintf("fetched %s", path))
		})

		r.Run(prefix+"_match", func() CheckOutcome {
			if out, ok := r.Require(prefix + "_fetch"); !ok {
				return out
			}
			if r.Load(prefix+"_decode_err") != nil {
				return FailCheck("failed to decode type definition: " + r.Load(prefix+"_decode_err").(string))
			}
			remoteDef := r.Load(prefix + "_remote_def")
			if remoteDef == nil {
				// Mirror the _fetch carve-out: if the type is provisional
				// (R1 substitute/durability family) or non-§9.5-floor under
				// --profile core, _fetch surfaced absence as WARN. _match
				// must follow — Require() passes through on Warn deps, so
				// without this branch we'd FAIL what _fetch already excused.
				// Surfaced by keystone C# core peer (F21).
				if provisional {
					reason := "provisional (proposal-stage, not ratified-core floor per R1)"
					if coreOnly && !inCoreTypeFloor(localDef.Name) {
						reason = "outside V7 v7.72 §9.5 Core Type Floor (--profile core matches if present; absence is not a core FAIL)"
					}
					return WarnCheck("remote type definition not available — " + reason)
				}
				return FailCheck("remote type definition not available")
			}
			outcome := compareTypeDefsOutcome(localDef, remoteDef.(types.TypeDefinition))
			// Provisional family (R1 or v7.72 §9.5 non-floor): retain cross-
			// impl-agreement coverage but downgrade FAIL→WARN so the
			// proposal-stage / extension-type shape isn't presented as core
			// conformance.
			if provisional && outcome.severity == Fail {
				reason := "provisional (proposal-stage, not ratified-core floor per R1)"
				if coreOnly && !inCoreTypeFloor(localDef.Name) {
					reason = "outside V7 v7.72 §9.5 Core Type Floor (--profile core matches if present; divergence is not a core FAIL)"
				}
				return WarnCheck(reason + ": " + outcome.message)
			}
			return outcome
		})
	}

	r.Run("types_all_present", func() CheckOutcome {
		note := ""
		if len(provisionalMissing) > 0 {
			tag := "provisional/proposal-stage"
			if coreOnly {
				tag = "provisional + non-§9.5-floor (matched-if-present)"
			}
			note = fmt.Sprintf(" (+%d %s types absent, not counted: %v)", len(provisionalMissing), tag, provisionalMissing)
		}
		floorTag := "ratified-core"
		if coreOnly {
			floorTag = "V7 §9.5 core-floor"
		}
		if len(missingNames) == 0 {
			return PassCheck(fmt.Sprintf("all %d %s types fetchable from remote%s", presentCount, floorTag, note))
		}
		// RULED 2026-08-07 (arch `c78b3dc`, NETWORK §12.3, MUST): **a type is owed
		// by the surface that uses it.** A peer that declines an OPTIONAL section
		// installs none of its operations and therefore does NOT owe that
		// section's types — declining §6.7 declines `system/network/candidate`,
		// `check-reachability-result` and `observe-address-result` with it. This
		// follows core §9.5 ("absence of extension handlers means absence of their
		// types") one level down, at the section.
		//
		// This was a FAIL while the question was open — deliberately, since
		// over-reporting is the safe direction pending a ruling. It is now settled
		// the other way, so it PASSes: charging a conformance penalty for
		// exercising an option §12.3 explicitly grants would make "offering
		// neither is fully conformant" false. This withdrew 7 failures against
		// entity-core-py with no code change on their side.
		//
		// Consumer half of the same ruling, enforced elsewhere: support is
		// discovered from the OPERATION'S RESPONSE (403-or-unimplemented → try
		// another reflector), never from the presence or absence of these types.
		if declined := section67TypesOnly(missingNames); declined {
			return PassCheck(fmt.Sprintf("all %d %s types fetchable from remote%s — the %d absent type(s) %v are EXTENSION-NETWORK §6.7's, and this peer declines §6.7, which per the 2026-08-07 §12.3 ruling declines its types with it (not owed, not a gap)", presentCount, floorTag, note, len(missingNames), missingNames))
		}
		return FailCheck(fmt.Sprintf("%d %s types missing from remote: %v%s", len(missingNames), floorTag, missingNames, note))
	})

	return r.Results()
}

// isProvisionalType reports whether a type name belongs to a surface that
// is NOT part of the ratified-core conformance floor (R1,
// RULING-CYCLE-CLOSEOUT-0.3 / GUIDE-CONFORMANCE §7).
//
// system/substitute/* graduated to landed spec EXTENSION-SUBSTITUTE v1.0
// (arch ARCH-RESPONSE-COHORT-RELEASE-GREEN-AMBIGUITIES Q2/Q3
// + consolidation of the prior PROPOSAL-EXTENSION-STORAGE-SUBSTITUTE-
// {SOURCES,HTTP} pair). The shapes are now contract: source.endpoint =
// opaque primitive/any? (Q3); endpoint.content_url_prefix = REQUIRED (Q2).
// Stays in the provisional WARN bucket for this commit so Python (where
// the Q2/Q3 shapes are still tightening per the cohort dispatch) is not
// FAILed before its align lands. Drop this entry once Python ships the
// Q1/Q2/Q3 corrections and Rust's SUBSTITUTE leg holds — then divergences
// promote to ratified-core FAIL behavior.
func isProvisionalType(name string) bool {
	return strings.HasPrefix(name, "system/substitute/")
}

// compareTypeDefsOutcome compares a local and remote TypeDefinition.
// Returns a single CheckOutcome.
//
// Severity policy:
//   - Identical content_hash → PASS.
//   - Required-field mismatch / type-ref mismatch → FAIL (interop-breaking).
//   - Optional-field membership differences or spec-mismatch on optionals →
//     WARN with the FULL diff enumerated (not "no structural differences
//     found"). Hash divergence with no structural diff at all (encoding
//     edge) also WARN, but explicitly says so.
func compareTypeDefsOutcome(local, remote types.TypeDefinition) CheckOutcome {
	// Hash comparison — compute from type definition entity.
	localEnt, localErr := local.ToEntity()
	remoteEnt, remoteErr := remote.ToEntity()
	if localErr != nil || remoteErr != nil {
		return WarnCheck("could not compute entity hashes for comparison")
	}
	if localEnt.ContentHash == remoteEnt.ContentHash {
		return PassCheck("content hash match")
	}

	// Structural comparison when hashes differ. Collect required-vs-required
	// failures separately from optional-membership warnings so callers can
	// tell apart "interop-breaking" from "tolerable per open-type semantics
	// but worth flagging upstream."
	var failIssues []string
	var warnIssues []string

	if local.Extends != remote.Extends {
		failIssues = append(failIssues, fmt.Sprintf("extends: local=%q remote=%q", local.Extends, remote.Extends))
	}

	f, w := compareFieldDiffs(local.Fields, remote.Fields)
	failIssues = append(failIssues, f...)
	warnIssues = append(warnIssues, w...)

	// §3.3 field constraints are part of the descriptor and therefore part of
	// its content hash, but they are NOT part of the shape comparison above —
	// fieldSpecsEqual deliberately compares only the shape (type_ref, optional,
	// array/map/union, byte_size). Without this pass a descriptor that differs
	// ONLY in its constraints hashes differently and reports zero structural
	// differences, which this function then attributed to "likely a CBOR
	// encoding edge" — sending every reader of the report hunting an encoder
	// determinism bug that does not exist. That misdiagnosis was live against
	// both siblings on exactly the five built-ins where Go publishes the spec's
	// constraints (arch Q4 / v7.78: spec-defined built-ins SHOULD reflect with
	// their spec constraints), so the false signal was reproducible and
	// cohort-wide.
	//
	// Severity stays WARN regardless of the field's optionality: reflecting
	// spec constraints on built-ins is a SHOULD, and user-defined types are
	// divergence-tolerant per §1.5 Invariant 5. This pass changes what the
	// report SAYS, never how hard it bites.
	warnIssues = append(warnIssues, compareFieldConstraints(local.Fields, remote.Fields)...)

	if len(failIssues) > 0 {
		return FailCheck(fmt.Sprintf("%d interop-breaking issue(s): %v (warn-level diffs also: %v)",
			len(failIssues), failIssues, warnIssues))
	}
	if len(warnIssues) > 0 {
		return WarnCheck(fmt.Sprintf("hash mismatch with %d structural difference(s) (open-type-tolerable): %v (local: %s, remote: %s)",
			len(warnIssues), warnIssues, localEnt.ContentHash, remoteEnt.ContentHash))
	}
	return WarnCheck(fmt.Sprintf("content hash mismatch with no structural differences detected — likely a CBOR encoding edge (local: %s, remote: %s)",
		localEnt.ContentHash, remoteEnt.ContentHash))
}

// compareFieldConstraints reports per-field EXTENSION-TYPE §3.3 constraint
// divergence. Constraints are compared as a multiset of constraint entities
// keyed by content hash — order is not significant — and reported by their type
// URI, because "the one_of is missing" is the actionable sentence and a bare
// hash is not.
func compareFieldConstraints(local, remote map[string]types.FieldSpec) []string {
	names := make([]string, 0, len(local))
	for name := range local {
		names = append(names, name)
	}
	for name := range remote {
		if _, both := local[name]; !both {
			names = append(names, name)
		}
	}
	sort.Strings(names)

	var issues []string
	for _, name := range names {
		missing, extra := constraintSetDiff(local[name].Constraints, remote[name].Constraints)
		switch {
		case len(missing) > 0 && len(extra) > 0:
			issues = append(issues, fmt.Sprintf("field %q: constraints differ — local-only %v, remote-only %v", name, missing, extra))
		case len(missing) > 0:
			issues = append(issues, fmt.Sprintf("field %q: constraint(s) %v present locally, absent remotely", name, missing))
		case len(extra) > 0:
			issues = append(issues, fmt.Sprintf("field %q: constraint(s) %v present remotely, absent locally", name, extra))
		}
	}
	return issues
}

// constraintSetDiff returns the constraint types present only in a and only in
// b, matching on content hash so a semantically identical constraint declared in
// a different position is not reported as a difference.
func constraintSetDiff(a, b []entity.Entity) (onlyA, onlyB []string) {
	index := func(set []entity.Entity) map[hash.Hash]string {
		m := make(map[hash.Hash]string, len(set))
		for _, c := range set {
			m[c.ContentHash] = c.Type
		}
		return m
	}
	ai, bi := index(a), index(b)
	for h, typ := range ai {
		if _, ok := bi[h]; !ok {
			onlyA = append(onlyA, typ)
		}
	}
	for h, typ := range bi {
		if _, ok := ai[h]; !ok {
			onlyB = append(onlyB, typ)
		}
	}
	sort.Strings(onlyA)
	sort.Strings(onlyB)
	return onlyA, onlyB
}

// compareFieldDiffs compares field maps and partitions the differences:
// failIssues are interop-breaking (required-field divergence); warnIssues
// are tolerable under open-type semantics (optional-field membership,
// optional-field spec mismatch, extra remote fields).
func compareFieldDiffs(local, remote map[string]types.FieldSpec) (failIssues, warnIssues []string) {
	allNames := make(map[string]bool)
	for k := range local {
		allNames[k] = true
	}
	for k := range remote {
		allNames[k] = true
	}

	sorted := make([]string, 0, len(allNames))
	for k := range allNames {
		sorted = append(sorted, k)
	}
	sort.Strings(sorted)

	for _, fieldName := range sorted {
		localField, inLocal := local[fieldName]
		remoteField, inRemote := remote[fieldName]

		if inLocal && !inRemote {
			if !localField.Optional {
				failIssues = append(failIssues, fmt.Sprintf("field %q: REQUIRED locally but MISSING remotely (spec: %s)",
					fieldName, formatFieldSpec(localField)))
			} else {
				warnIssues = append(warnIssues, fmt.Sprintf("field %q: optional locally, missing remotely (spec: %s)",
					fieldName, formatFieldSpec(localField)))
			}
			continue
		}
		if !inLocal && inRemote {
			warnIssues = append(warnIssues, fmt.Sprintf("field %q: extra on remote (spec: %s)",
				fieldName, formatFieldSpec(remoteField)))
			continue
		}
		if !fieldSpecsEqual(localField, remoteField) {
			// A required-vs-required spec mismatch is interop-breaking;
			// optional-vs-optional spec mismatch is tolerable per open-type.
			msg := fmt.Sprintf("field %q: spec mismatch (local: %s, remote: %s)",
				fieldName, formatFieldSpec(localField), formatFieldSpec(remoteField))
			if !localField.Optional && !remoteField.Optional {
				failIssues = append(failIssues, msg)
			} else {
				warnIssues = append(warnIssues, msg)
			}
		}
	}
	return failIssues, warnIssues
}

// fieldSpecsEqual compares two FieldSpecs.
func fieldSpecsEqual(a, b types.FieldSpec) bool {
	if a.TypeRef != b.TypeRef {
		return false
	}
	if a.Optional != b.Optional {
		return false
	}
	if a.KeyType != b.KeyType {
		return false
	}
	if (a.ArrayOf == nil) != (b.ArrayOf == nil) {
		return false
	}
	if a.ArrayOf != nil && !fieldSpecsEqual(*a.ArrayOf, *b.ArrayOf) {
		return false
	}
	if (a.MapOf == nil) != (b.MapOf == nil) {
		return false
	}
	if a.MapOf != nil && !fieldSpecsEqual(*a.MapOf, *b.MapOf) {
		return false
	}
	if (a.ByteSize == nil) != (b.ByteSize == nil) {
		return false
	}
	if a.ByteSize != nil && *a.ByteSize != *b.ByteSize {
		return false
	}
	if len(a.UnionOf) != len(b.UnionOf) {
		return false
	}
	for i := range a.UnionOf {
		if !fieldSpecsEqual(a.UnionOf[i], b.UnionOf[i]) {
			return false
		}
	}
	return true
}

// formatFieldSpec returns a brief human-readable description of a FieldSpec.
func formatFieldSpec(fs types.FieldSpec) string {
	s := ""
	if fs.TypeRef != "" {
		s = fs.TypeRef
	} else if fs.ArrayOf != nil {
		s = "array_of(" + formatFieldSpec(*fs.ArrayOf) + ")"
	} else if fs.MapOf != nil {
		s = "map_of(" + formatFieldSpec(*fs.MapOf) + ")"
		if fs.KeyType != "" {
			s += "[key=" + fs.KeyType + "]"
		}
	} else if len(fs.UnionOf) > 0 {
		parts := make([]string, len(fs.UnionOf))
		for i, u := range fs.UnionOf {
			parts[i] = formatFieldSpec(u)
		}
		s = "union_of(" + strings.Join(parts, "|") + ")"
	} else {
		s = "<empty>"
	}
	if fs.Optional {
		s += "?"
	}
	if fs.ByteSize != nil {
		s += fmt.Sprintf("[byte_size=%d]", *fs.ByteSize)
	}
	return s
}

// sanitizeName converts a type name like "system/peer" to "system_identity"
// for use in check names.
func sanitizeName(name string) string {
	result := make([]byte, len(name))
	for i := range name {
		if name[i] == '/' || name[i] == '-' {
			result[i] = '_'
		} else {
			result[i] = name[i]
		}
	}
	return string(result)
}

// section67TypesOnly reports whether every missing type belongs to
// EXTENSION-NETWORK §6.7 — the optional reachability-facts section.
//
// Since the 2026-08-07 §12.3 ruling (arch `c78b3dc`) this SUPPRESSES the
// failure rather than merely annotating it: an OPTIONAL section's types are
// owed only if the section is offered.
func section67TypesOnly(missing []string) bool {
	if len(missing) == 0 {
		return false
	}
	section67 := map[string]bool{
		"system/network/candidate":                 true,
		"system/network/check-reachability-result": true,
		"system/network/observe-address-result":    true,
	}
	for _, name := range missing {
		if !section67[name] {
			return false
		}
	}
	return true
}
