package validate

// Conformance profile (V7 v7.72 §9.0).
//
// `core` runs the 14-category core-profile category set; extension-only
// categories skip with diagnostic. The two profiles are publication
// contracts: `core` scores against the 53-type floor (§9.5), the
// CORE-TREE-* vector set (§9.5a), and the core handler set; `full`
// keeps the historical behavior (every category, every type, every op).
//
// See PROPOSAL-V7-V7.72-CORE-CONFORMANCE-PROFILE-AND-TYPE-FLOOR.md +
// Amendment 1 for the spec contract; see the IMPL-TEAM-ALIGNMENT-V7.72-CORE-
// PROFILE cohort handoff.

const (
	ProfileCore = "core"
	ProfileFull = "full"
)

// coreProfileCategories is the set of categories the oracle runs under
// `--profile core`, per V7 v7.72 §9.0. Other categories are extension-
// only and skip with a profile-keyed diagnostic. Universal address space
// added per arch's "the keystone missed this one" note (§4.1 of v7.72).
//
// Source of truth is V7 §9.0 (prose enumeration after "Oracle-side
// contract."). The drift gate at profile_v9_drift_test.go re-parses the
// spec and fails if this map and §9.0 disagree — per §10.3 of
// PROPOSAL-V7-V7.74-CORE-EXTENSIBILITY-BOUNDARY. Update both in lockstep
// when the spec adds or removes a core-profile category.
var coreProfileCategories = map[string]bool{
	catConnectivity:          true,
	catEncoding:              true,
	catUniversalAddressSpace: true,
	catPeerCanonicalization:  true,
	catFormatAgility:         true,
	catCryptoAgility:         true,
	catNegotiation:           true,
	catMultiSig:              true,
	catTypeSystem:            true,
	catHandlers:              true,
	catTreeOps:               true,
	catCapability:            true,
	catAuthz:                 true,
	catSecurity:              true,
	catConcurrency:           true, // v7.75 §9.0 fold (was a §10.2-style carve-out under v7.72)
	catResourceBounds:        true, // v7.75 §9.0 fold (gate-landed 3-way GREEN, §4.10(a)+(b) now §9.1 floor MUSTs)
}

// inCoreProfile reports whether a category runs under --profile core.
func inCoreProfile(cat string) bool {
	return coreProfileCategories[cat]
}

// coreTypeFloor is the 53-type Core Type Floor Manifest per V7 v7.72
// §9.5 — names verbatim from the spec table. A peer claiming
// `--profile core` MUST publish these and SHOULD NOT publish others.
// Types outside this floor are treated as matched-if-present, not-a-
// FAIL-if-absent (same precedent shape as system/substitute/* via
// isProvisionalType).
//
// Source: V7 v7.72 §9.5 (53 entries; cross-verified against
// core/types/core.go::RegisterCoreTypes — zero re-classifications).
var coreTypeFloor = map[string]bool{
	// Primitives (8) — V7 §2.4
	"primitive/any":    true,
	"primitive/bool":   true,
	"primitive/bytes":  true,
	"primitive/float":  true,
	"primitive/int":    true,
	"primitive/null":   true,
	"primitive/string": true,
	"primitive/uint":   true,

	// Structural roots / envelopes (5) — V7 §1.1, §3.1
	"entity":                   true,
	"core/entity":              true,
	"core/envelope":            true,
	"system/envelope":          true,
	"system/protocol/envelope": true,

	// Identity / hash / signature (4) — V7 §1.2, §1.5, §3.5
	"system/hash":      true,
	"system/peer":      true,
	"system/peer-id":   true,
	"system/signature": true,

	// Protocol surface (6) — V7 §3.1, §3.2, §3.3, §3.8
	"system/protocol/connect/authenticate": true,
	"system/protocol/connect/hello":        true,
	"system/protocol/error":                true,
	"system/protocol/execute":              true,
	"system/protocol/execute/response":     true,
	"system/protocol/resource-target":      true,

	// Capability (12) — V7 §3.6, §6.2
	"system/capability/grant":               true,
	"system/capability/grant-entry":         true,
	"system/capability/id-scope":            true,
	"system/capability/path-scope":          true,
	"system/capability/request":             true,
	"system/capability/revocation":          true,
	"system/capability/revoke-request":      true,
	"system/capability/delegate-request":    true,
	"system/capability/delegation-caveats":  true,
	"system/capability/policy-entry":        true,
	"system/capability/token":               true,
	"system/capability/multi-granter":       true,

	// Handler machinery (6) — V7 §3.7, §3.12, §6.1
	"system/handler":                   true,
	"system/handler/interface":         true,
	"system/handler/manifest":          true,
	"system/handler/operation-spec":    true,
	"system/handler/register-request":  true,
	"system/handler/register-result":   true,

	// Tree (5) — V7 §3.9, §6.3
	"system/tree/get-request":   true,
	"system/tree/put-request":   true,
	"system/tree/listing":       true,
	"system/tree/listing-entry": true,
	"system/tree/path":          true,

	// Type-system bootstrap (3) — V7 §2.1, §2.2, §2.7
	"system/type":            true,
	"system/type/field-spec": true,
	"system/type/name":       true,

	// Operational (4) — V7 §1.2a, §3.11, §3.13
	"system/bounds":           true,
	"system/resource-limits":  true,
	"system/delivery-spec":    true,
	"system/deletion-marker":  true,
}

// inCoreTypeFloor reports whether a type name is part of the V7 §9.5
// Core Type Floor Manifest (the 53 normative core types).
func inCoreTypeFloor(name string) bool {
	return coreTypeFloor[name]
}
