package revision

import (
	"context"
	"encoding/hex"
	"reflect"
	"strings"
	"sync"

	"go.entitychurch.org/entity-core-go/core/crypto"
	"go.entitychurch.org/entity-core-go/core/ecf"
	"go.entitychurch.org/entity-core-go/core/entity"
	"go.entitychurch.org/entity-core-go/core/handler"
	"go.entitychurch.org/entity-core-go/core/hash"
	"go.entitychurch.org/entity-core-go/core/store"
	"go.entitychurch.org/entity-core-go/core/types"

	"github.com/fxamacker/cbor/v2"
)

const handlerPattern = "system/revision"

// Handler implements the system/revision handler per EXTENSION-REVISION.md v2.1.
type Handler struct {
	mu sync.Mutex // serialize commits per prefix

	// av is an optional reference to the peer's AutoVersioner. When set,
	// version-transcription operations (merge, fast-forward, checkout,
	// cherry-pick, revert) acquire the AV's per-prefix mutex during their
	// binding-apply phase. This prevents the phantom-deletion-marker race:
	// without coordination, a concurrent Put during a mid-apply merge fires
	// AV.fire(), which reads partial-merge live-tree state and emits
	// phantom markers for paths the merge is about to apply.
	// See the workbench's deletion-markers phase-2 validation.
	// Nil-safe — when unset, the binding-apply runs without AV coordination
	// (acceptable for handler-only test fixtures that don't wire AV).
	av *AutoVersioner
}

// NewHandler creates a new revision handler.
func NewHandler() *Handler {
	return &Handler{}
}

// SetAutoVersioner attaches the peer's AutoVersioner so version-transcription
// operations can serialize their binding-apply phases with AV's emit phase
// on the same prefix. Call once during peer setup, after both Handler and
// AutoVersioner are constructed.
func (h *Handler) SetAutoVersioner(av *AutoVersioner) {
	h.av = av
}

// lockPrefixForApply returns a no-op unlock if AV isn't wired, else acquires
// AV's per-prefix mutex and returns its unlock. Used by every
// version-transcription operation's binding-apply phase.
func (h *Handler) lockPrefixForApply(prefix string) func() {
	if h.av == nil {
		return func() {}
	}
	return h.av.LockPrefix(prefix)
}

func (h *Handler) Name() string { return "revision" }

// Manifest returns the handler's self-description with all 18 operations.
//
// InternalScope is declared (not defaulted) because `pull` is the one kernel
// operation whose entire purpose is to reach a FOREIGN peer: it dispatches
// `system/revision:fetch` / `:fetch-entities` at `entity://{remote}/…` to pull
// a diff and merge it locally (pull.go). Under 0.8.2.19 E1 the executing
// handler's grant gates all four dimensions of an outbound sub-dispatch,
// including Dimension 4 (peers) — and the DEFAULT self-grant
// (defaultHandlerSelfGrant, core/peer/peer.go) leaves the peers dimension
// absent, so it defaults to {include:[local]} and a default-scope handler is
// cross-peer-INERT. A handler that legitimately reaches a foreign peer must say
// so in its own manifest; the default is deliberately not widened (that would
// hand cross-peer authority to every handler). So we spell two entries:
//
//   - Entry 1 reproduces the default self-grant verbatim (all handlers/ops,
//     resources /*/*, peers absent → local). This preserves every LOCAL
//     sub-dispatch revision makes (the strategy.go merge delegation, etc.)
//     identically to what the default gave.
//   - Entry 2 is the cross-peer reach for pull's outbound fetch: narrow in the
//     three dimensions the handler CAN name at manifest time — handler
//     `system/revision`, operations `fetch`/`fetch-entities` — and wildcard
//     ONLY in the dimension it cannot: which peer an operator will pull from.
//     This is the minimal-escalation shape (workbench-go's `blob-resolve`
//     `system/content:get` Peers:["*"] is the same pattern for the same reason).
//
// Note (E1 delivery-vs-backfill, cohort-wide): a pull triggered by a
// SUBSCRIPTION DELIVERY runs under the subscription's dispatch_capability, not
// this handler grant — so an embedder wiring follow→pull must give that
// dispatch_capability the same peers reach. That is the installer's grant, not
// this manifest.
func (h *Handler) Manifest() types.HandlerManifestData {
	return types.HandlerManifestData{
		Pattern: handlerPattern,
		Name:    "revision",
		Operations: map[string]types.HandlerOperationSpec{
			"commit":         {InputType: types.TypeRevisionCommitParams},
			"log":            {InputType: types.TypeRevisionLogParams},
			"status":         {InputType: types.TypeRevisionStatusParams},
			"merge":          {InputType: types.TypeRevisionMergeParams},
			"resolve":        {InputType: types.TypeRevisionResolveParams},
			"fetch":          {InputType: types.TypeRevisionFetchParams},
			"fetch-entities": {InputType: types.TypeRevisionFetchEntitiesParams},
			"fetch-diff":     {InputType: types.TypeRevisionFetchDiffParams},
			"pull":           {InputType: types.TypeRevisionFetchParams},
			"push":           {InputType: types.TypeRevisionPushParams},
			"find-ancestor":  {InputType: types.TypeRevisionAncestorParams},
			"branch":         {InputType: types.TypeRevisionBranchParams},
			"checkout":       {InputType: types.TypeRevisionCheckoutParams},
			"tag":            {InputType: types.TypeRevisionTagParams},
			"diff":           {InputType: types.TypeRevisionDiffParams},
			"cherry-pick":    {InputType: types.TypeRevisionCherryPickParams},
			"revert":         {InputType: types.TypeRevisionRevertParams},
			"config":         {InputType: types.TypeRevisionConfigParams},
			"merge-config":   {InputType: types.TypeRevisionMergeConfigParams},
		},
		InternalScope: []types.GrantEntry{
			// Entry 1: the default self-grant, verbatim — all LOCAL authority
			// (peers absent → local peer only), unchanged from the default.
			{
				Handlers:   types.CapabilityScope{Include: []string{"*"}},
				Operations: types.CapabilityScope{Include: []string{"*"}},
				Resources:  types.CapabilityScope{Include: []string{"/*/*"}},
			},
			// Entry 2: cross-peer reach for pull's outbound fetch. Narrow in
			// handlers/operations/resources; peers wildcard is the one
			// dimension unknowable at manifest time.
			{
				Handlers:   types.CapabilityScope{Include: []string{"system/revision"}},
				Operations: types.CapabilityScope{Include: []string{"fetch", "fetch-entities"}},
				Resources:  types.CapabilityScope{Include: []string{"/*/*"}},
				Peers:      &types.CapabilityScope{Include: []string{"*"}},
			},
		},
	}
}

// RegisterTypes registers revision-specific types.
func (h *Handler) RegisterTypes(r *types.TypeRegistry) {
	r.ReflectType(types.TypeRevisionEntry, reflect.TypeOf(types.RevisionEntryData{}))
	r.ReflectType(types.TypeRevisionFetchDiffParams, reflect.TypeOf(types.RevisionFetchDiffParamsData{}))
	r.ReflectType(types.TypeRevisionConflict, reflect.TypeOf(types.RevisionConflictData{}))
	r.ReflectType(types.TypeRevisionCommitParams, reflect.TypeOf(types.RevisionCommitParamsData{}))
	r.ReflectType(types.TypeRevisionCommitResult, reflect.TypeOf(types.RevisionCommitResultData{}))
	r.ReflectType(types.TypeRevisionCascadeWarning, reflect.TypeOf(types.RevisionCascadeWarningData{}))
	r.ReflectType(types.TypeRevisionMergeResult, reflect.TypeOf(types.RevisionMergeResultData{}))
	r.ReflectType(types.TypeRevisionBranchResult, reflect.TypeOf(types.RevisionBranchResultData{}))
	r.ReflectType(types.TypeRevisionConfigParams, reflect.TypeOf(types.RevisionConfigParamsData{}))
	r.ReflectType(types.TypeRevisionConfigResult, reflect.TypeOf(types.RevisionConfigResultData{}))
	r.ReflectType(types.TypeRevisionMergeConfigParams, reflect.TypeOf(types.RevisionMergeConfigParamsData{}))
	r.ReflectType(types.TypeRevisionMergeConfigResult, reflect.TypeOf(types.RevisionMergeConfigResultData{}))
}

// Handle dispatches to the appropriate operation.
func (h *Handler) Handle(ctx context.Context, req *handler.Request) (*handler.Response, error) {
	switch req.Operation {
	case "commit":
		return h.handleCommit(ctx, req)
	case "log":
		return h.handleLog(ctx, req)
	case "status":
		return h.handleStatus(ctx, req)
	case "find-ancestor":
		return h.handleFindAncestor(ctx, req)
	case "merge":
		return h.handleMerge(ctx, req)
	case "resolve":
		return h.handleResolve(ctx, req)
	case "branch":
		return h.handleBranch(ctx, req)
	case "checkout":
		return h.handleCheckout(ctx, req)
	case "tag":
		return h.handleTag(ctx, req)
	case "diff":
		return h.handleDiff(ctx, req)
	case "cherry-pick":
		return h.handleCherryPick(ctx, req)
	case "revert":
		return h.handleRevert(ctx, req)
	case "fetch":
		return h.handleFetch(ctx, req)
	case "fetch-entities":
		return h.handleFetchEntities(ctx, req)
	case "fetch-diff":
		return h.handleFetchDiff(ctx, req)
	case "pull":
		return h.handlePull(ctx, req)
	case "push":
		return h.handlePush(ctx, req)
	case "config":
		return h.handleConfig(ctx, req)
	case "merge-config":
		return h.handleMergeConfig(ctx, req)
	default:
		resp, _ := handler.NewErrorResponse(501, "unsupported_operation",
			"revision handler does not support operation: "+req.Operation)
		return resp, nil
	}
}

// --- Shared helpers ---

// checkContext validates that the handler context has required stores.
func checkContext(hctx *handler.HandlerContext) *handler.Response {
	if hctx == nil || hctx.Store == nil || hctx.LocationIndex == nil {
		resp, _ := handler.NewErrorResponse(500, "internal_error", "missing store or location index")
		return resp
	}
	return nil
}

// PrefixHash computes the 66-char hex-encoded ECF content hash of an absolute
// prefix path, per REVISION v3.0 §3.1. The prefix MUST be absolute (start with /).
func PrefixHash(prefix string) string {
	data, _ := ecf.Encode(prefix)
	h, _ := hash.Compute("system/tree/path", cbor.RawMessage(data))
	return hex.EncodeToString(h.Bytes())
}

// resolvePrefix resolves a prefix to absolute form per V7 §5.4.
func resolvePrefix(prefix, localPeerID string) string {
	if strings.HasPrefix(prefix, "/") {
		return prefix
	}
	return "/" + localPeerID + "/" + prefix
}

// peerRelativePrefix strips the leading /{peerID}/ from an absolute prefix,
// returning the peer-relative form. Used for subsystems (RootTracker) that
// operate in peer-relative space.
func peerRelativePrefix(absPrefix, localPeerID string) string {
	pfx := "/" + localPeerID + "/"
	if strings.HasPrefix(absPrefix, pfx) {
		return absPrefix[len(pfx):]
	}
	return absPrefix
}

// headPath returns the location index path for a prefix's head pointer.
func headPath(ph string) string {
	return "system/revision/" + ph + "/head"
}

// activeBranchPath returns the location index path for the active branch.
func activeBranchPath(ph string) string {
	return "system/revision/" + ph + "/active-branch"
}

// branchPath returns the location index path for a named branch.
func branchPath(ph, name string) string {
	return "system/revision/" + ph + "/branches/" + name
}

// branchListPrefix returns the location index prefix for listing branches.
func branchListPrefix(ph string) string {
	return "system/revision/" + ph + "/branches/"
}

// tagPath returns the location index path for a named tag.
func tagPath(ph, name string) string {
	return "system/revision/" + ph + "/tags/" + name
}

// tagListPrefix returns the location index prefix for listing tags.
func tagListPrefix(ph string) string {
	return "system/revision/" + ph + "/tags/"
}

// conflictPath returns the location index path for a conflict entry.
func conflictPath(ph, path string) string {
	return "system/revision/" + ph + "/conflicts/" + path
}

// conflictListPrefix returns the location index prefix for listing conflicts.
func conflictListPrefix(ph string) string {
	return "system/revision/" + ph + "/conflicts/"
}

// configPath returns the location index path for a revision config.
// Per REVISION v3.0 §3.1.1: stored at system/revision/{prefix_hash}/config.
func configPath(ph string) string {
	return "system/revision/" + ph + "/config"
}

// remotePath returns the location index path for a remote head.
func remotePath(ph, remoteName string) string {
	return "system/revision/" + ph + "/remotes/" + remoteName
}

// isRevisionConfigPath checks whether a bare path matches the
// system/revision/{H}/config pattern for hot-reload detection, where {H} is a
// prefix_hash — the lowercase hex of a full content_hash wire form.
//
// The width of {H} is the one its own format byte implies and is never a
// constant: REVISION §3.1 spells this out ("66 chars under ECFv1-SHA-256 `00`,
// 98 under ECFv1-SHA-384 `01`; never assumed"), under the corpus-wide rule
// SPECIFICATION-FORMAT §8.4.5. This tested `len(mid) == 66`.
//
// Nothing failed today, because PrefixHash pins SHA-256 and 66 is its value —
// the two SHA-256 assumptions agreed. That agreement is the hazard: the moment
// prefix_hash follows the peer's home format (which is the reading §3.1's
// own wording invites, and is unruled — see
// docs/validation/spec-issues/2026-08-10-b-*), a SHA-384 peer's config path is
// 98 hex and this returns false. Hot reload would then stop firing SILENTLY —
// no error, no log, just a config that never reloads. Deriving the answer from
// the format byte removes the coupling instead of documenting it.
func isRevisionConfigPath(path string) bool {
	const prefix = "system/revision/"
	const suffix = "/config"
	if !strings.HasPrefix(path, prefix) || !strings.HasSuffix(path, suffix) {
		return false
	}
	mid := path[len(prefix) : len(path)-len(suffix)]
	if !isHex(mid) {
		return false
	}
	// ParseHex accepts only a hex string whose length matches the width its
	// leading format byte implies, so this is a width check that stays correct
	// under every allocated content_hash_format.
	_, err := hash.ParseHex(mid)
	return err == nil
}

func isHex(s string) bool {
	for _, c := range s {
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')) {
			return false
		}
	}
	return true
}

// storeStringEntity stores a primitive/string entity and returns its hash.
func storeStringEntity(hctx *handler.HandlerContext, value string) (hash.Hash, error) {
	raw, err := ecf.Encode(value)
	if err != nil {
		return hash.Hash{}, err
	}
	ent, err := entity.NewEntity("primitive/string", cbor.RawMessage(raw))
	if err != nil {
		return hash.Hash{}, err
	}
	return hctx.Store.Put(ent)
}

// readStringEntity reads a primitive/string entity at a binding path.
func readStringEntity(hctx *handler.HandlerContext, path string) (string, bool) {
	h, ok := hctx.LocationIndex.Get(path)
	if !ok {
		return "", false
	}
	ent, ok := hctx.Store.Get(h)
	if !ok {
		return "", false
	}
	var s string
	if err := ecf.Decode(ent.Data, &s); err != nil {
		return "", false
	}
	return s, true
}

// loadConfig loads the revision config for a prefix hash, if one exists.
func loadConfig(hctx *handler.HandlerContext, ph string) (types.RevisionConfigData, bool) {
	h, ok := hctx.LocationIndex.Get(configPath(ph))
	if !ok {
		return types.RevisionConfigData{}, false
	}
	ent, ok := hctx.Store.Get(h)
	if !ok {
		return types.RevisionConfigData{}, false
	}
	cfg, err := types.RevisionConfigDataFromEntity(ent)
	if err != nil {
		return types.RevisionConfigData{}, false
	}
	return cfg, true
}

// loadVersion loads a version entry entity from the content store.
func loadVersion(hctx *handler.HandlerContext, h hash.Hash) (types.RevisionEntryData, bool) {
	ent, ok := hctx.Store.Get(h)
	if !ok {
		return types.RevisionEntryData{}, false
	}
	v, err := types.RevisionEntryDataFromEntity(ent)
	if err != nil {
		return types.RevisionEntryData{}, false
	}
	return v, true
}

// loadVersionFromStore is the same as loadVersion but takes a ContentStore
// directly. Used by AutoVersioner.fire, which doesn't have a HandlerContext.
func loadVersionFromStore(cs store.ContentStore, h hash.Hash) (types.RevisionEntryData, bool) {
	if h.IsZero() {
		return types.RevisionEntryData{}, false
	}
	ent, ok := cs.Get(h)
	if !ok {
		return types.RevisionEntryData{}, false
	}
	v, err := types.RevisionEntryDataFromEntity(ent)
	if err != nil {
		return types.RevisionEntryData{}, false
	}
	return v, true
}

// trimPrefix removes the qualified prefix from a full path, returning the relative path.
// peerID identifies which peer's namespace the entries belong to. If prefix is
// already absolute (starts with "/"), it is used directly; otherwise it is
// qualified with the peer ID.
func trimPrefix(path, prefix string, peerID crypto.PeerID) string {
	var qualifiedPrefix string
	if strings.HasPrefix(prefix, "/") {
		qualifiedPrefix = prefix
	} else {
		qualifiedPrefix = store.QualifyPath(string(peerID), prefix)
	}
	return strings.TrimPrefix(path, qualifiedPrefix)
}
