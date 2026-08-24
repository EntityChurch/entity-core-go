package revision

import (
	"context"
	"encoding/hex"
	"fmt"
	"strings"

	"go.entitychurch.org/entity-core-go/core/ecf"
	"go.entitychurch.org/entity-core-go/core/entity"
	"go.entitychurch.org/entity-core-go/core/handler"
	"go.entitychurch.org/entity-core-go/core/hash"
	"go.entitychurch.org/entity-core-go/core/store"
	"go.entitychurch.org/entity-core-go/core/types"

	"github.com/fxamacker/cbor/v2"
)

// mergeStrategy identifies a merge strategy.
type mergeStrategy string

const (
	strategyThreeWay   mergeStrategy = "three-way"
	strategySourceWins mergeStrategy = "source-wins"
	strategyTargetWins mergeStrategy = "target-wins"
	strategyKeepBoth   mergeStrategy = "keep-both"
	strategyManual     mergeStrategy = "manual"
	strategyLWW        mergeStrategy = "lww"
	// strategyHandler is the custom-dispatch SENTINEL (v3.9). The handler
	// path travels in the config's companion `handler` field, never as the
	// strategy value — the open-value reading was retracted because a value
	// set admitting any path string cannot support §2.3's pinned
	// `400 invalid_strategy` at config-write time.
	strategyHandler mergeStrategy = "handler"
)

// strategyChoice is what the §5.1 cascade selects: a strategy, plus the
// companion handler path that travels with the `handler` SENTINEL. The two are
// separate fields because v3.9 retracted the encoding in which the strategy
// value *was* the path — §2.3's `400 invalid_strategy` at config-write time
// cannot exist over a value set that admits any path string, and §5.1's
// apply_strategy(strategy, …, handler_path) takes them as separate arguments.
// handlerPath is empty for every built-in strategy.
type strategyChoice struct {
	strategy    mergeStrategy
	handlerPath string
}

// additionalBinding is a path→hash pair produced by strategies like keep-both.
type additionalBinding struct {
	Path string
	Hash hash.Hash
}

// mergeStrategyResult is the outcome of applying a merge strategy to a conflict.
type mergeStrategyResult struct {
	resolved           bool
	hash               hash.Hash
	additionalBindings []additionalBinding
}

// findMergeStrategy determines the merge strategy for a given path.
//
// Cascade per §5.1: override → per-type config (step 1) → per-path config
// (step 2) → default three-way (step 3).
//
// STEP 1 WAS NOT IMPLEMENTED UNTIL 2026-08-14, and this comment claimed it
// was. The `merge-config` op accepted `scope: "type"`, wrote
// `system/revision/config/merge/type/{type_name}` and answered 200 "set"
// (mergeConfigTypeScope, merge_config.go) while NOTHING IN THIS REPO READ
// THAT NAMESPACE — an operator configured a per-type strategy, received a
// success receipt, and the config was never consulted. A producer with no
// consumer, and it passed every test its author wrote because the tests
// asserted the write. Built out below (G-21).
//
// The absence was PROVEN, not grepped for a literal: a prefix grep alone
// would miss a reader that scans the parent namespace, and one exists —
// AutoVersioner.reloadConfigs lists `system/revision/` wholesale. It cannot
// reach these configs (isRevisionConfigPath requires `system/revision/
// {hex}/config`, and the entity-type filter demands TypeRevisionConfig while
// merge configs carry TypeRevisionMergeConfig — two independent gates).
//
// And NO VECTOR COULD HAVE CAUGHT IT: the suite drove per-PATH config only.
// Both this gap and the `handler` gap were invisible to a 1574-check 0-FAIL
// gate, which is why a read found them and the oracle did not. Vectors landed
// with the build, not after it.
//
// THE GAP WAS OURS, NOT THE COHORT'S — and the first draft of this comment said
// otherwise. "Nothing in the cohort has built it" was inherited framing plus a
// grep of our own tree, generalized to two repos nobody had measured. The
// vector measured them: `entity-core-py` 808d9e6 PASSES
// merge_config_type_scope_is_consulted AND its control, so python implements
// step 1 and has for longer than we have. `entity-core-rust` cc6cb56 is
// UNMEASURED, not failing — its control row fails (an all-paths-conflict
// divergence answers `oscillation_detected`), so every cascade row against it
// is blocked rather than judged. Measured 2026-08-14; re-measure before citing.
func findMergeStrategy(hctx *handler.HandlerContext, prefix, relPath string, override string, local, remote hash.Hash) strategyChoice {
	if override != "" {
		return strategyChoice{strategy: mergeStrategy(override)}
	}

	// Step 1 (§5.1): Per-type merge config, keyed by ENTITY TYPE.
	//
	// "Check local type first (existing entity), then remote type (incoming).
	// When types differ, both configs get a chance — either side's handler may
	// understand cross-type merge. When types are the same, only one lookup
	// occurs." Ordering is normative: local wins a tie, so two peers merging
	// the same pair reach the same config.
	for _, typeName := range mergeConfigTypesToCheck(hctx.Store, local, remote) {
		ent, ok := lookupEntity(hctx, mergeConfigTypeScope(typeName))
		if !ok {
			continue
		}
		cfg, err := types.RevisionMergeConfigDataFromEntity(ent)
		if err != nil {
			continue
		}
		// A config that fails write-time validation can only have arrived by a
		// raw tree:put bypassing the handler op (§2.3 v3.3 D1 calls that a
		// deployment misconfiguration). Skip it rather than let it silently
		// outrank a valid per-path config below.
		if ValidateMergeStrategy(cfg.Strategy, cfg.Handler) != nil {
			continue
		}
		return strategyChoice{strategy: mergeStrategy(cfg.Strategy), handlerPath: cfg.Handler}
	}

	// Step 2 (§5.1): Per-path merge config.
	// Configs stored at system/revision/config/merge/path/{name} (global, not prefix-scoped).
	// Pattern matched against trie-relative path within the merge prefix.
	configEntries := hctx.LocationIndex.List("system/revision/config/merge/path/")
	var bestMatch strategyChoice
	var bestKey mergeConfigKey
	haveBest := false
	for _, entry := range configEntries {
		ent, ok := hctx.Store.Get(entry.Hash)
		if !ok {
			continue
		}
		cfg, err := types.RevisionMergeConfigDataFromEntity(ent)
		if err != nil {
			continue
		}
		if !mergePatternMatch(cfg.Pattern, relPath) {
			continue
		}
		// v3.12 total order — select the winning config deterministically, never
		// by store-enumeration order (ties are impossible; see mergeConfigKey).
		key := mergeConfigKeyOf(cfg.Pattern, mergeConfigName(entry.Path))
		if !haveBest || key.moreSpecific(bestKey) {
			bestMatch = strategyChoice{strategy: mergeStrategy(cfg.Strategy), handlerPath: cfg.Handler}
			bestKey = key
			haveBest = true
		}
	}
	if haveBest {
		return bestMatch
	}

	// Step 3 (§5.1): default three-way.
	return strategyChoice{strategy: strategyThreeWay}
}

// mergeConfigTypesToCheck returns the entity type names to consult for a
// per-type merge config, in §5.1's normative order: local type first, then
// remote's only when it differs. A side whose hash is zero (deleted) or whose
// entity is not in the store contributes no type.
func mergeConfigTypesToCheck(cs store.ContentStore, local, remote hash.Hash) []string {
	var out []string
	if !local.IsZero() {
		if ent, ok := cs.Get(local); ok {
			out = append(out, ent.Type)
		}
	}
	if !remote.IsZero() {
		if ent, ok := cs.Get(remote); ok {
			if len(out) == 0 || ent.Type != out[0] {
				out = append(out, ent.Type)
			}
		}
	}
	return out
}

// lookupEntity resolves a tree path to its entity, qualifying the path against
// the local peer so per-type configs are found under the same namespace the
// merge-config write path binds them at.
func lookupEntity(hctx *handler.HandlerContext, path string) (entity.Entity, bool) {
	if hctx.LocationIndex == nil || hctx.Store == nil {
		return entity.Entity{}, false
	}
	h, ok := hctx.LocationIndex.Get(path)
	if !ok {
		if qualified := store.QualifyPath(string(hctx.LocalPeerID), path); qualified != path {
			h, ok = hctx.LocationIndex.Get(qualified)
		}
	}
	if !ok {
		return entity.Entity{}, false
	}
	return hctx.Store.Get(h)
}

// mergePatternMatch matches a merge-config `pattern` against a trie-relative
// path per §5.1's "Path argument scope." It is the SAME grammar as snapshot
// excludes: ENTITY-CORE-PROTOCOL §5.4's four closed forms (globMatch) — a bare
// "*" matches every path, "<lit>/*" is a subtree prefix that crosses "/",
// "*<lit>" a trailing-literal suffix, "<lit>" exact. §5.1 names bare "*" the
// peer-WIDE config in as many words ("matches all paths within any merge,
// regardless of prefix"), which is exactly globMatch's form 1.
//
// This wrapper predates the 2026-08-18 four-forms fold, when `globMatch` was
// Go's segment-scoped path.Match and a bare "*" silently narrowed a peer-wide
// operator config to top-level keys (G-22, 2026-08-14). The fold replaced
// globMatch with the four-form matcher whose form 1 already matches all, so the
// special case that used to live here is now globMatch's own; this stays a thin
// named alias only so the merge-config call site reads for what it is.
//
// core-py SA-PY-12 flags that §2.3 invokes glob_match on merge patterns while
// §2.4 scopes glob_match to exclude/exclude_types. Go applies the one §5.4
// grammar at both sites, which is conformant under either reading of that
// scoping — the ambiguity is routed to arch, not resolved by diverging here.
func mergePatternMatch(pattern, relPath string) bool {
	return globMatch(pattern, relPath)
}

// mergeConfigKey is §5.1's `pattern_specificity`, pinned as a TOTAL ORDER
// (EXTENSION-REVISION v3.12; arch ROUTING-2026-08-18-m §3 R15). The corpus called
// pattern_specificity and defined it nowhere, and all three impls invented a
// different one — go/py scored literal characters, rust used pattern.len()
// (counting the `*`) — so `"*"` vs `"a"` on path `a` resolved differently across
// peers, silently, on a merge whose result is byte-identical to a clean one.
//
// Ranks, most specific first: exact (3) → subtree prefix `<lit>/*` (2) → trailing
// literal `*<lit>` (1) → match-all `*` (0). `literal` is the pattern with its
// single `*` removed; within a rank the LONGER literal wins. Rank 2 above rank 1
// is arch's one recorded choice (anchored beats floating). The residual tie —
// two configs may legitimately carry the same `pattern` under different `{name}`s
// — breaks on lexicographic `pattern` then `{name}`, both peer-independent, so
// TIES ARE IMPOSSIBLE and no conflict is resolved by unspecified store-enumeration
// order (the old `specificity > best` kept whatever list() yielded first).
type mergeConfigKey struct {
	rank, litLen  int
	pattern, name string
}

func mergeConfigKeyOf(pattern, name string) mergeConfigKey {
	rank := 3 // exact
	switch {
	case pattern == "*":
		rank = 0
	case strings.HasSuffix(pattern, "/*"):
		rank = 2
	case strings.HasPrefix(pattern, "*"):
		rank = 1
	}
	return mergeConfigKey{
		rank:    rank,
		litLen:  len(strings.Replace(pattern, "*", "", 1)),
		pattern: pattern,
		name:    name,
	}
}

// moreSpecific reports whether a outranks b under the v3.12 total order.
func (a mergeConfigKey) moreSpecific(b mergeConfigKey) bool {
	switch {
	case a.rank != b.rank:
		return a.rank > b.rank
	case a.litLen != b.litLen:
		return a.litLen > b.litLen
	case a.pattern != b.pattern:
		return a.pattern < b.pattern
	default:
		return a.name < b.name
	}
}

// mergeConfigName is the config's `{name}` — the last segment of its storage path
// system/revision/config/merge/path/{name} — the final tiebreak in the order.
func mergeConfigName(storagePath string) string {
	if i := strings.LastIndex(storagePath, "/"); i >= 0 {
		return storagePath[i+1:]
	}
	return storagePath
}

// applyMergeStrategy applies the given strategy to resolve a conflict.
// path is the trie-relative path being merged (needed by keep-both for additional binding paths).
//
// ctx and hctx are used only by the `handler` sentinel, which dispatches out to
// an application handler. Both may be nil for the built-in strategies — the
// dispatch arm degrades to a conflict entity rather than panicking, which keeps
// the many direct unit-test call sites working unchanged.
func applyMergeStrategy(ctx context.Context, hctx *handler.HandlerContext, cs store.ContentStore, choice strategyChoice, path string, base, local, remote hash.Hash) mergeStrategyResult {
	switch choice.strategy {
	case strategySourceWins:
		return mergeStrategyResult{resolved: true, hash: remote}

	case strategyTargetWins:
		return mergeStrategyResult{resolved: true, hash: local}

	case strategyKeepBoth:
		if local.IsZero() || remote.IsZero() {
			return mergeStrategyResult{resolved: false}
		}
		hashPrefix := hex.EncodeToString(remote.Digest[:4])
		return mergeStrategyResult{
			resolved: true,
			hash:     local,
			additionalBindings: []additionalBinding{
				{Path: path + ".keep-both-" + hashPrefix, Hash: remote},
			},
		}

	case strategyManual:
		return mergeStrategyResult{resolved: false}

	case strategyThreeWay:
		return applyThreeWayMerge(cs, base, local, remote)

	case strategyLWW:
		// NORMATIVE as of v3.10 [RULED 2026-08-14]: `lww` stays in the
		// vocabulary, is accepted at config-write time (so the pinned
		// `400 invalid_strategy` contract does not churn), and **MUST NOT
		// resolve** — it degrades to a conflict entity.
		//
		// We routed this arm as unpinned; arch found it worse than reported.
		// §5.1's `apply_strategy` arm read `lww_resolve(local_hash,
		// remote_hash)` — a helper defined NOWHERE in the corpus — over a
		// comparison basis §2.3 itself
		// says is unavailable ("real LWW requires commit-metadata not
		// currently spec'd"). Three seats implementing that arm would have
		// produced three comparison bases and a convergence bug. The ruling
		// deliberately does NOT invent a basis; it waits on one, and
		// application-layer LWW is available today via `handler`.
		return mergeStrategyResult{resolved: false}

	case strategyHandler:
		// The sentinel means DELEGATE: not an algorithm this switch runs, but
		// "dispatch to the handler named in the config's companion `handler`
		// field." It reads like a category error — `handler` is this
		// protocol's word for every request-serving component — and it is
		// merely a merge driver, the `merge=<driver>` of gitattributes.
		//
		// v3.10 ruled this an IMPLEMENTATION GAP, not a spec gap: §5.3 fully
		// specifies the delegation and §5.1's `apply_strategy` has always
		// carried a working dispatch arm (`dispatch_merge_handler`). Nothing
		// in the cohort had built it — go, rust and py all degraded to a
		// conflict entity, which is safe but NOT conformant. Built 2026-08-14
		// (G-18); rust and py still owe it.
		//
		// CITE §5.1, NOT §5.2. v3.10's §2.3 disposition table says "§5.2's
		// arm" for both this row and `lww`, and §5.2 is `three_way_merge` and
		// nothing else — it contains no dispatch. Routed to arch as a pointer
		// defect; corrected here so the next reader lands in the right
		// section.
		//
		// SHAPE: three sites disagree and the divergence is cross-impl
		// observable (a type-validating merge handler rejects whichever seat
		// guessed differently) — §5.3's EXECUTE example passes
		// {path, base, local, remote}; the normative merge-request type block
		// declares {base, local, remote} with NO `path`; §5.1's dispatch
		// passes {base, local, remote}. We build the type block: normative
		// site, and §5.1 independently agrees. Routed to arch as A-6 E1. If
		// arch rules for `path`, the struct and the vector move together.
		return dispatchMergeHandler(ctx, hctx, choice.handlerPath, base, local, remote)

	default:
		// Unreachable from the handler write path — ValidateMergeStrategy
		// rejects unknown values at config-write time with
		// `400 invalid_strategy` (§2.3). Reachable only for a config written
		// by a raw `tree:put` that bypassed the handler op, which §2.3
		// (v3.3, D1) calls a deployment misconfiguration. Conflict entity:
		// collapse to the safe outcome rather than guess an intent.
		return mergeStrategyResult{resolved: false}
	}
}

// dispatchMergeHandler delegates a leaf conflict to a custom merge handler per
// §5.3: EXECUTE <handler_path> operation "merge" with a
// system/revision/merge-request, read back a system/revision/merge-response.
//
// THREE DISPOSITIONS §5.3 DOES NOT SPECIFY, decided here because Go leads and
// implementation-defined means we define it. Published in A-6 E4 so rust and py
// can match or object rather than each invent one:
//
//  1. AUTHORITY — the dispatch runs under the merge caller's context via
//     hctx.Execute, which is the cap-checked path. A merge that the caller may
//     perform does not thereby grant that caller's authority anywhere new: the
//     handler is invoked with the same context the revision handler itself was
//     invoked under. The alternative (dispatch under the revision handler's own
//     broader grant) would let any caller who can merge reach any handler the
//     revision extension can reach — a privilege escalation, so it is not that.
//  2. MISSING / NON-MERGE HANDLER — conflict entity, never an error. A handler
//     path that does not resolve, or resolves to something with no "merge"
//     operation, is a misconfiguration whose blast radius should be one path's
//     divergence recorded for an operator, not a failed merge of the whole
//     prefix. Same disposition every other unresolvable arm takes.
//  3. MALFORMED RESPONSE — conflict entity. `resolved: true` with no entity, an
//     entity naming a hash the store does not have, or a response of the wrong
//     type are all treated as "did not resolve." A handler that claims a merge
//     it cannot produce must not be able to bind an unresolvable hash into the
//     merged tree, which is the one outcome here that would corrupt state
//     rather than merely record a conflict.
//
// A nil ctx/hctx (direct unit-test call sites for built-in strategies) yields a
// conflict entity rather than a panic.
func dispatchMergeHandler(ctx context.Context, hctx *handler.HandlerContext, handlerPath string, base, local, remote hash.Hash) mergeStrategyResult {
	// ValidateMergeStrategy pins the sentinel's companion field at
	// config-write time, so an empty path here means the config bypassed the
	// handler op (§2.3 v3.3 D1 deployment misconfiguration).
	if handlerPath == "" || hctx == nil || hctx.Execute == nil {
		return mergeStrategyResult{resolved: false}
	}
	if ctx == nil {
		ctx = context.Background()
	}

	reqEntity, err := types.RevisionMergeRequestData{Base: base, Local: local, Remote: remote}.ToEntity()
	if err != nil {
		return mergeStrategyResult{resolved: false}
	}

	resp, err := hctx.Execute(ctx, handlerPath, "merge", reqEntity)
	if err != nil || resp == nil || resp.Status != 200 {
		return mergeStrategyResult{resolved: false}
	}
	if resp.Result.Type != types.TypeRevisionMergeResponse {
		return mergeStrategyResult{resolved: false}
	}

	out, err := types.RevisionMergeResponseDataFromEntity(resp.Result)
	if err != nil || !out.Resolved || out.Entity.IsZero() {
		return mergeStrategyResult{resolved: false}
	}
	// Disposition 3: a hash we cannot resolve must not reach the merged tree.
	if hctx.Store == nil {
		return mergeStrategyResult{resolved: false}
	}
	if _, ok := hctx.Store.Get(out.Entity); !ok {
		return mergeStrategyResult{resolved: false}
	}
	return mergeStrategyResult{resolved: true, hash: out.Entity}
}

// applyThreeWayMerge implements field-by-field three-way merge for structured entities.
func applyThreeWayMerge(cs store.ContentStore, base, local, remote hash.Hash) mergeStrategyResult {
	if base.IsZero() || local.IsZero() || remote.IsZero() {
		return mergeStrategyResult{resolved: false}
	}

	baseEnt, ok := cs.Get(base)
	if !ok {
		return mergeStrategyResult{resolved: false}
	}
	localEnt, ok := cs.Get(local)
	if !ok {
		return mergeStrategyResult{resolved: false}
	}
	remoteEnt, ok := cs.Get(remote)
	if !ok {
		return mergeStrategyResult{resolved: false}
	}

	if baseEnt.Type != localEnt.Type || baseEnt.Type != remoteEnt.Type {
		return mergeStrategyResult{resolved: false}
	}

	var baseMap, localMap, remoteMap map[string]interface{}
	if err := ecf.Decode(baseEnt.Data, &baseMap); err != nil {
		return mergeStrategyResult{resolved: false}
	}
	if err := ecf.Decode(localEnt.Data, &localMap); err != nil {
		return mergeStrategyResult{resolved: false}
	}
	if err := ecf.Decode(remoteEnt.Data, &remoteMap); err != nil {
		return mergeStrategyResult{resolved: false}
	}

	allKeys := make(map[string]bool)
	for k := range baseMap {
		allKeys[k] = true
	}
	for k := range localMap {
		allKeys[k] = true
	}
	for k := range remoteMap {
		allKeys[k] = true
	}

	merged := make(map[string]interface{})
	for key := range allKeys {
		baseVal := baseMap[key]
		localVal := localMap[key]
		remoteVal := remoteMap[key]

		baseBytes, _ := ecf.Encode(baseVal)
		localBytes, _ := ecf.Encode(localVal)
		remoteBytes, _ := ecf.Encode(remoteVal)

		localChanged := string(localBytes) != string(baseBytes)
		remoteChanged := string(remoteBytes) != string(baseBytes)

		switch {
		case !localChanged && !remoteChanged:
			merged[key] = baseVal
		case localChanged && !remoteChanged:
			merged[key] = localVal
		case !localChanged && remoteChanged:
			merged[key] = remoteVal
		case string(localBytes) == string(remoteBytes):
			merged[key] = localVal
		default:
			return mergeStrategyResult{resolved: false}
		}
	}

	mergedRaw, err := ecf.Encode(merged)
	if err != nil {
		return mergeStrategyResult{resolved: false}
	}
	mergedEnt, err := entity.NewEntity(baseEnt.Type, cbor.RawMessage(mergedRaw))
	if err != nil {
		return mergeStrategyResult{resolved: false}
	}
	mergedHash, err := cs.Put(mergedEnt)
	if err != nil {
		return mergeStrategyResult{resolved: false}
	}

	return mergeStrategyResult{resolved: true, hash: mergedHash}
}

// mergeSnapshots performs path-by-path merge of three binding maps.
func mergeSnapshots(
	ctx context.Context,
	hctx *handler.HandlerContext,
	prefix, strategyOverride string,
	ancestor, local, remote map[string]hash.Hash,
	localVersion, remoteVersion hash.Hash,
) (merged map[string]hash.Hash, deletions []string, conflicts []types.RevisionConflictData) {
	merged = make(map[string]hash.Hash)

	allPaths := make(map[string]bool)
	for p := range ancestor {
		allPaths[p] = true
	}
	for p := range local {
		allPaths[p] = true
	}
	for p := range remote {
		allPaths[p] = true
	}

	for relPath := range allPaths {
		baseHash := ancestor[relPath]
		localHash := local[relPath]
		remoteHash := remote[relPath]

		inLocal := !localHash.IsZero()
		inRemote := !remoteHash.IsZero()

		localChanged := localHash != baseHash
		remoteChanged := remoteHash != baseHash

		switch {
		case !localChanged && !remoteChanged:
			if !baseHash.IsZero() {
				merged[relPath] = baseHash
			}

		case !localChanged && remoteChanged:
			if inRemote {
				// Remote modified or set a marker — take remote's value.
				// (Marker hashes go through this branch like any other entity
				// hash; the apply phase will translate them to TreeRemove.)
				merged[relPath] = remoteHash
			} else {
				// Remote's trie lacks this path that ancestor (and unchanged
				// local) has. Under PROPOSAL-DELETION-MARKERS.md A.8, absence
				// is preserved — deletion requires an explicit marker binding.
				// Mirrors mergeBindingAtNode's preserve-on-absence (the
				// recursive path; this is the flat-merge analogue). Aligning
				// the two paths closes TestTrieMerge_MatchesFlatMerge.
				merged[relPath] = baseHash
			}

		case localChanged && !remoteChanged:
			if inLocal {
				merged[relPath] = localHash
			} else {
				// Local removed it but ancestor has it. Same as above,
				// mirrored: preserve base. Without an explicit marker we
				// can't distinguish "local hasn't seen yet" from "local
				// intentionally deleted." Conservative: preserve.
				merged[relPath] = baseHash
			}

		default:
			if localHash == remoteHash {
				merged[relPath] = localHash
				continue
			}

			// One side absent (zero hash), other side has a non-zero hash
			// (entity or marker). Under PROPOSAL-DELETION-MARKERS A.8
			// absence-is-preserve semantics, the absent side has no opinion
			// — the non-absent side's value wins. Mirrors the equivalent
			// path-level handling in trieMergeBindings::mergeDeleteVsModify.
			// Without this, both-changed+one-absent falls through to the
			// entity-vs-entity strategy and surfaces a phantom conflict.
			if localHash.IsZero() {
				merged[relPath] = remoteHash
				continue
			}
			if remoteHash.IsZero() {
				merged[relPath] = localHash
				continue
			}

			// Deletion-vs-entity conflict per Amendment 4. Mirrors the
			// equivalent branch in trieMergeBindings::mergeBindingAtNode.
			if result := resolveDeletionVsEntity(
				hctx.Store,
				resolveDeletionStrategy(hctx, prefix, relPath),
				relPath, localHash, remoteHash, localVersion, remoteVersion,
			); result.HasConflict {
				merged[relPath] = result.ResolvedHash
				for _, sb := range result.SidecarBindings {
					merged[sb.Path] = sb.Hash
				}
				continue
			}

			choice := findMergeStrategy(hctx, prefix, relPath, strategyOverride, localHash, remoteHash)
			result := applyMergeStrategy(ctx, hctx, hctx.Store, choice, relPath, baseHash, localHash, remoteHash)

			if result.resolved {
				merged[relPath] = result.hash
				for _, ab := range result.additionalBindings {
					merged[ab.Path] = ab.Hash
				}
			} else {
				conflict := types.RevisionConflictData{
					Path:          relPath,
					Strategy:      string(choice.strategy),
					VersionLocal:  localVersion,
					VersionRemote: remoteVersion,
				}
				if !baseHash.IsZero() {
					conflict.Base = baseHash
				}
				if inLocal {
					conflict.Local = localHash
				}
				if inRemote {
					conflict.Remote = remoteHash
				}
				conflicts = append(conflicts, conflict)

				if inLocal {
					merged[relPath] = localHash
				}
			}
		}
	}

	return merged, deletions, conflicts
}

// --- §2.3 write-time strategy rejection ------------------------------------

// The merge-strategy vocabulary, read from EXTENSION-REVISION §2.3's built-in
// table — the authority, per v3.9. `handler` is the custom-dispatch SENTINEL
// (companion `handler` field carries the path), not a strategy name in the
// table.
//
// v3.9 exists because this corpus declared the vocabulary three incompatible
// ways and the disagreement was cross-impl-observable: `400 invalid_strategy`
// is pinned at config-write time, so *which values a peer rejects* depended on
// which of the three lists its implementer read. Go read the table, so our
// dispatch was on the right leg — but we never validated `strategy` at write
// time at all, so the pinned contract could not fire for a bad strategy. That
// is this block.
var validMergeStrategies = map[mergeStrategy]bool{
	strategyThreeWay:   true,
	strategySourceWins: true,
	strategyTargetWins: true,
	strategyLWW:        true,
	strategyKeepBoth:   true,
	strategyManual:     true,
	strategyHandler:    true, // sentinel
}

// ValidateMergeStrategy enforces §2.3's write-time strategy-rejection contract
// for the `strategy` field. Returns an error whose Error() carries the
// `invalid_strategy` prefix, matching ValidateDeletionResolution's shape so
// merge-config maps both to `400 invalid_strategy`.
//
// Empty → the spec's documented default (`three-way`); valid.
func ValidateMergeStrategy(strategy, handlerPath string) error {
	if strategy == "" {
		return nil
	}
	s := mergeStrategy(strategy)
	if !validMergeStrategies[s] {
		return fmt.Errorf("invalid_strategy: %q is not a merge strategy (§2.3 built-in table: three-way, source-wins, target-wins, lww, keep-both, manual; or the custom-dispatch sentinel \"handler\" with the path in the companion `handler` field)", strategy)
	}
	// The sentinel is only meaningful with its companion path. Accepting
	// `strategy: "handler"` with no handler stores a config whose dispatch has
	// nothing to dispatch to — an invalid persisted value that read-time
	// validation could only collapse silently, which is exactly what §2.3
	// pinned write-time rejection to prevent.
	if s == strategyHandler && handlerPath == "" {
		return fmt.Errorf("invalid_strategy: strategy %q is the custom-dispatch sentinel and requires the companion `handler` field naming the handler path (§2.3 Custom strategies, corrected v3.9)", strategy)
	}
	// A handler path on a built-in strategy is a config that reads as custom
	// dispatch and is not — the open-value encoding v3.9 retracted.
	if s != strategyHandler && handlerPath != "" {
		return fmt.Errorf("invalid_strategy: `handler` is set but strategy is %q, not the \"handler\" sentinel — v3.9 retracted the reading where any path string is a strategy value; custom dispatch is the sentinel plus the companion field", strategy)
	}
	return nil
}
