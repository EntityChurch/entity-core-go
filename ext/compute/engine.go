package compute

import (
	"context"
	"crypto/sha256"
	"encoding/base32"
	"errors"
	"fmt"
	"log"
	"strings"
	"sync"
	"time"

	"go.entitychurch.org/entity-core-go/core/capability"
	"go.entitychurch.org/entity-core-go/core/crypto"
	"go.entitychurch.org/entity-core-go/core/ecf"
	"go.entitychurch.org/entity-core-go/core/entity"
	ecerrors "go.entitychurch.org/entity-core-go/core/errors"
	"go.entitychurch.org/entity-core-go/core/handler"
	"go.entitychurch.org/entity-core-go/core/hash"
	"go.entitychurch.org/entity-core-go/core/store"
	"go.entitychurch.org/entity-core-go/core/types"
)

const subgraphPrefix = "system/compute/processes/"

type dependencyEntry struct {
	ExpressionURI string
	SubgraphPath  string
}

// Engine manages reactive compute subgraphs and handles install/uninstall operations.
type Engine struct {
	mu              sync.RWMutex
	store           store.ContentStore
	locationIndex   store.LocationIndex
	localPeerID     string
	dependencyIndex map[string][]dependencyEntry
	debugLog        *log.Logger
}

// NewEngine creates a compute engine.
func NewEngine(cs store.ContentStore, li store.LocationIndex, debugLog *log.Logger) *Engine {
	return &Engine{
		store:           cs,
		locationIndex:   li,
		dependencyIndex: make(map[string][]dependencyEntry),
		debugLog:        debugLog,
	}
}

// SetLocalPeerID sets the peer identity after construction.
func (e *Engine) SetLocalPeerID(peerID string) {
	e.localPeerID = peerID
}

// SetLocationIndex replaces the engine's location index. Called after peer
// construction to inject the NotifyingLocationIndex so that result writes
// trigger the sync hook cascade (enabling multi-stage reactive chains).
func (e *Engine) SetLocationIndex(li store.LocationIndex) {
	e.locationIndex = li
}

func (e *Engine) debugf(format string, args ...interface{}) {
	if e.debugLog != nil {
		e.debugLog.Printf("[compute] "+format, args...)
	}
}

// --- Install / Uninstall ---

func (e *Engine) HandleInstall(ctx context.Context, req *handler.Request) (*handler.Response, error) {
	hctx := req.Context

	// V7 §3.2 path-as-resource: root expression path comes from
	// EXECUTE.resource.targets[0]. Single-target, URI-only.
	if hctx.Resource == nil || len(hctx.Resource.Targets) != 1 {
		return handler.NewErrorResponse(400, "ambiguous_resource",
			"install requires exactly one resource target (the root expression path)")
	}
	rootPath := hctx.Resource.Targets[0]

	var params types.ComputeInstallRequestData
	if err := ecf.Decode(req.Params.Data, &params); err != nil {
		return handler.NewErrorResponse(400, ErrInvalidExpression, "Invalid install request: "+err.Error())
	}

	exprHash, ok := hctx.LocationIndex.Get(rootPath)
	if !ok {
		return handler.NewErrorResponse(404, ErrNotFound, "No expression at path: "+rootPath)
	}
	expression, ok := hctx.Store.Get(exprHash)
	if !ok {
		return handler.NewErrorResponse(404, ErrNotFound, "No expression at path: "+rootPath)
	}
	if !IsComputeExpression(expression) {
		return handler.NewErrorResponse(400, ErrInvalidExpression,
			"Entity at path is not a compute expression: "+expression.Type)
	}

	// Phase 1: Audit subgraph for impure operations.
	resolver := func(h hash.Hash) (entity.Entity, bool) {
		if ent, ok := hctx.Included[h]; ok {
			return ent, true
		}
		return hctx.Store.Get(h)
	}
	audit := auditSubgraph(expression, hctx.Store, rootPath, e.localPeerID, auditConfig{
		Installer: hctx.AuthorHash,
		Resolve:   resolver,
		FindSig:   capability.IncludedSignatureResolver(hctx.Included),
	})

	// Structural rejection: F5 (PROPOSAL-COMPUTE-APPLY-RESOURCE-CEILING),
	// CP1 (PROPOSAL-COHERENT-CAPABILITY-AUTHORITY), or other static-shape
	// errors the walker raises. Status carries 400/403/404 per the rule
	// that fired.
	if audit.Err != nil {
		status := audit.Err.Status
		if status == 0 {
			status = 400
		}
		return handler.NewErrorResponse(status, audit.Err.Code, audit.Err.Message)
	}

	// Phase 2: Verify caller's capability covers all impure operations.
	callerCap := hctx.CallerCapability
	if !callerCap.ContentHash.IsZero() {
		capData, err := types.CapabilityTokenDataFromEntity(callerCap)
		if err == nil {
			granterPeerID, gerr := capability.ResolveGranterPeerID(capData.Granter, hctx.Store, hctx.LocalPeerID)
			if gerr != nil {
				return handler.NewErrorResponse(403, ErrPermissionDenied,
					"granter unresolvable: "+gerr.Error())
			}
			for _, path := range audit.ReadPaths {
				if !capability.CheckPathPermission("get", path, capData, hctx.HandlerPattern, hctx.LocalPeerID, granterPeerID) {
					return handler.NewErrorResponse(403, ErrPermissionDenied,
						"Caller capability does not cover read: "+path)
				}
			}
			for _, target := range audit.HandlerTargets {
				// PROPOSAL-COMPUTE-APPLY-RESOURCE-CEILING F3: check the actual
				// static resource against the caller cap. Dynamic resources
				// (target.Resource == nil) defer to runtime — the resource
				// dimension is unchecked here, matching V7 §5.2.
				exec := types.ExecuteData{
					Operation: target.Operation,
					Resource:  target.Resource,
				}
				if !capability.CheckPermission(exec, capData, target.Path, hctx.LocalPeerID, granterPeerID) {
					return handler.NewErrorResponse(403, ErrPermissionDenied,
						"Caller capability does not cover handler: "+target.Path+"."+target.Operation)
				}
			}
		}
	}

	resultPath := params.ResultPath
	if resultPath == "" {
		resultPath = rootPath + "/result"
	}

	if !callerCap.ContentHash.IsZero() {
		capData, err := types.CapabilityTokenDataFromEntity(callerCap)
		if err == nil {
			granterPeerID, gerr := capability.ResolveGranterPeerID(capData.Granter, hctx.Store, hctx.LocalPeerID)
			if gerr != nil {
				return handler.NewErrorResponse(403, ErrPermissionDenied,
					"granter unresolvable: "+gerr.Error())
			}
			if !capability.CheckPathPermission("put", resultPath, capData, hctx.HandlerPattern, hctx.LocalPeerID, granterPeerID) {
				return handler.NewErrorResponse(403, ErrPermissionDenied,
					"Caller capability does not cover result write: "+resultPath)
			}
			for _, path := range audit.WritePaths {
				if !capability.CheckPathPermission("put", path, capData, hctx.HandlerPattern, hctx.LocalPeerID, granterPeerID) {
					return handler.NewErrorResponse(403, ErrPermissionDenied,
						"Caller capability does not cover write: "+path)
				}
			}
		}
	}

	// Persist the installation grant so the reactive engine can retrieve it later.
	if !callerCap.ContentHash.IsZero() {
		hctx.Store.Put(callerCap)
	}

	// Persist any embedded compute/apply.capability cap entities and their
	// authority chains so reactive re-evaluation can resolve them later
	// (chain-entity persistence). Chains were collected end-to-end at audit
	// time via CheckCreatorAuthority, so persistence is a flat write loop.
	if err := persistEmbeddedCaps(hctx.Store, audit.EmbeddedCaps); err != nil {
		return handler.NewErrorResponse(500, "internal_error", err.Error())
	}

	// Phase 2b: Validate compute/lookup/hash data references (D5/D6).
	var authorizedDataHashes []hash.Hash
	for _, entry := range audit.DataHashes {
		if entry.Path != "" {
			treeHash, pathOk := hctx.LocationIndex.Get(entry.Path)
			if !pathOk {
				return handler.NewErrorResponse(404, ErrNotFound,
					"No entity at hint path: "+entry.Path)
			}
			if treeHash != entry.Hash {
				return handler.NewErrorResponse(400, "hash_mismatch",
					"Entity at "+entry.Path+" has different hash than expression references")
			}
			if !callerCap.ContentHash.IsZero() {
				capData, err := types.CapabilityTokenDataFromEntity(callerCap)
				if err == nil {
					granterPeerID, gerr := capability.ResolveGranterPeerID(capData.Granter, hctx.Store, hctx.LocalPeerID)
					if gerr != nil {
						return handler.NewErrorResponse(403, ErrPermissionDenied,
							"granter unresolvable: "+gerr.Error())
					}
					if !capability.CheckPathPermission("get", entry.Path, capData, "system/tree", hctx.LocalPeerID, granterPeerID) {
						return handler.NewErrorResponse(403, ErrPermissionDenied,
							"Caller grant does not cover tree GET at: "+entry.Path)
					}
				}
			}
			authorizedDataHashes = append(authorizedDataHashes, entry.Hash)
		} else {
			return handler.NewErrorResponse(400, "no_authorization_path",
				"compute/lookup/hash without path hint requires content_store_access")
		}
	}

	// Phase 3: Create subgraph metadata.
	subgraphID := deterministicID(rootPath)
	subgraphPath := subgraphPrefix + subgraphID

	subgraphData := types.ComputeSubgraphData{
		RootExpressionPath:   rootPath,
		RootExpression:       expression.ContentHash,
		InstallationGrant:    callerCap.ContentHash,
		InstalledBy:          hctx.AuthorHash,
		ResultPath:           resultPath,
		Status:               "active",
		AuthorizedDataHashes: authorizedDataHashes,
	}
	subgraphEnt, err := subgraphData.ToEntity()
	if err != nil {
		return handler.NewErrorResponse(500, "internal", "Failed to create subgraph entity")
	}
	subgraphHash, err := hctx.Store.Put(subgraphEnt)
	if err != nil {
		return handler.NewErrorResponse(500, "internal", "Failed to store subgraph entity")
	}
	if _, err := hctx.TreeSet(store.QualifyPath(e.localPeerID, subgraphPath), subgraphHash, "install"); err != nil {
		return handler.NewErrorResponse(500, "storage_error", "bind subgraph: "+err.Error())
	}

	// Phase 4: Register dependencies.
	e.registerSubgraphDependencies(subgraphPath, rootPath, expression)

	e.debugf("installed subgraph %s for expression at %s → result at %s", subgraphPath, rootPath, resultPath)

	resultData := types.ComputeInstallResultData{
		SubgraphPath: subgraphPath,
		ImpureOperations: map[string]interface{}{
			"read_paths":      audit.ReadPaths,
			"handler_targets": audit.HandlerTargets,
			"write_paths":     audit.WritePaths,
		},
		ResultPath: resultPath,
	}
	resultEnt, err := resultData.ToEntity()
	if err != nil {
		return handler.NewErrorResponse(500, "internal", "Failed to create install result")
	}
	return &handler.Response{Status: 200, Result: resultEnt}, nil
}

func (e *Engine) HandleUninstall(ctx context.Context, req *handler.Request) (*handler.Response, error) {
	hctx := req.Context

	// V7 §3.2 path-as-resource: subgraph path comes from
	// EXECUTE.resource.targets[0]. Single-target, URI-only. Uninstall takes
	// no params (empty primitive/any per the empty-params wire shape).
	if hctx.Resource == nil || len(hctx.Resource.Targets) != 1 {
		return handler.NewErrorResponse(400, "ambiguous_resource",
			"uninstall requires exactly one resource target (the subgraph path)")
	}
	subgraphPath := hctx.Resource.Targets[0]

	qualifiedPath := store.QualifyPath(e.localPeerID, subgraphPath)
	sgHash, ok := hctx.LocationIndex.Get(qualifiedPath)
	if !ok {
		return handler.NewErrorResponse(404, ErrNotFound, "No installed subgraph at path: "+subgraphPath)
	}
	sgEnt, ok := hctx.Store.Get(sgHash)
	if !ok || sgEnt.Type != types.TypeComputeSubgraph {
		return handler.NewErrorResponse(404, ErrNotFound, "No installed subgraph at path: "+subgraphPath)
	}

	e.removeSubgraph(subgraphPath)
	hctx.TreeRemove(qualifiedPath, "uninstall")

	e.debugf("uninstalled subgraph %s", subgraphPath)
	return &handler.Response{Status: 200}, nil
}

// --- Reactive Mode ---

// OnTreeChange is the sync hook for reactive re-evaluation.
func (e *Engine) OnTreeChange(evt store.TreeChangeEvent) *store.ConsumerResult {
	e.mu.RLock()
	entries := e.dependencyIndex[evt.Path]
	e.mu.RUnlock()

	if len(entries) == 0 {
		return nil
	}

	for _, entry := range entries {
		e.reEvaluate(entry.ExpressionURI, entry.SubgraphPath, evt)
	}
	return nil
}

func (e *Engine) reEvaluate(expressionURI, subgraphPath string, evt store.TreeChangeEvent) {
	qualifiedSGPath := store.QualifyPath(e.localPeerID, subgraphPath)
	sgHash, ok := e.locationIndex.Get(qualifiedSGPath)
	if !ok {
		e.removeSubgraph(subgraphPath)
		return
	}
	sgEnt, ok := e.store.Get(sgHash)
	if !ok || sgEnt.Type != types.TypeComputeSubgraph {
		e.removeSubgraph(subgraphPath)
		return
	}
	var sgData types.ComputeSubgraphData
	if err := ecf.Decode(sgEnt.Data, &sgData); err != nil {
		return
	}
	if sgData.Status == "frozen" {
		return
	}

	// Check cascade depth.
	var cascadeDepth uint64
	if evt.Context != nil && evt.Context.CascadeDepth != nil {
		cascadeDepth = *evt.Context.CascadeDepth
	}
	if cascadeDepth >= DefaultMaxCascadeDepth {
		e.freezeSubgraph(qualifiedSGPath, sgData, "cascade_limit",
			"Cascade depth exceeded during reactive re-evaluation", expressionURI, evt)
		return
	}

	// Verify installation grant validity.
	grantEnt, grantOk := e.store.Get(sgData.InstallationGrant)
	if !grantOk {
		e.freezeSubgraph(qualifiedSGPath, sgData, ErrInstallationGrantInvalid,
			"Installation grant missing", expressionURI, evt)
		return
	}
	capData, err := types.CapabilityTokenDataFromEntity(grantEnt)
	if err != nil {
		e.freezeSubgraph(qualifiedSGPath, sgData, ErrInstallationGrantInvalid,
			"Installation grant invalid", expressionURI, evt)
		return
	}
	if capData.ExpiresAt != nil && *capData.ExpiresAt < uint64(time.Now().UnixMilli()) {
		e.freezeSubgraph(qualifiedSGPath, sgData, ErrInstallationGrantInvalid,
			"Installation grant expired", expressionURI, evt)
		return
	}

	// Resolve and evaluate expression.
	exprPath := sgData.RootExpressionPath
	exprHash, ok := e.locationIndex.Get(exprPath)
	if !ok {
		e.removeSubgraph(subgraphPath)
		return
	}
	expression, ok := e.store.Get(exprHash)
	if !ok || !IsComputeExpression(expression) {
		e.removeSubgraph(subgraphPath)
		return
	}

	// Build sealed set from subgraph metadata (D5).
	var authorizedSet map[hash.Hash]bool
	if len(sgData.AuthorizedDataHashes) > 0 {
		authorizedSet = make(map[hash.Hash]bool, len(sgData.AuthorizedDataHashes))
		for _, h := range sgData.AuthorizedDataHashes {
			authorizedSet[h] = true
		}
	}

	// Reactive path: autonomous re-eval (PROPOSAL-ENTITY-NATIVE-HANDLER-DISPATCH §6.4).
	// ctx.Capability = installation grant; CallerCapability absent; Author = local peer.
	evalCtx := &EvalContext{
		ContentStore:         e.store,
		LocationIndex:        e.locationIndex,
		LocalPeerID:          e.localPeerID,
		Capability:           grantEnt,
		Author:               crypto.PeerID(e.localPeerID),
		Included:             make(map[hash.Hash]entity.Entity),
		AuthorizedDataHashes: authorizedSet,
		SubgraphRoot:         sgData.RootExpressionPath,
	}

	budget := reactiveBudget(grantEnt, e.store)
	scope := NewScope()

	result, evalErr := Evaluate(expression, scope, budget, evalCtx)

	resultPath := sgData.ResultPath
	if evalErr != nil {
		if ce, ok := evalErr.(*ComputeError); ok {
			errEnt, entErr := ce.ToEntity()
			if entErr == nil {
				errHash, _ := e.store.Put(errEnt)
				e.writeResult(resultPath, errHash, evt)
			}
		}
		return
	}

	resultEnt, err := wrapResult(result, expression.ContentHash)
	if err != nil {
		return
	}

	newHash, err := e.store.Put(resultEnt)
	if err != nil {
		return
	}

	// Convergence check: skip write if result unchanged.
	oldHash, ok := e.locationIndex.Get(resultPath)
	if ok && oldHash == newHash {
		return
	}

	e.writeResult(resultPath, newHash, evt)
	e.debugf("reactive re-eval: %s → %s (result written to %s)", subgraphPath, expression.ContentHash, resultPath)
}

func (e *Engine) writeResult(path string, h hash.Hash, evt store.TreeChangeEvent) {
	var setErr error
	if cw, ok := e.locationIndex.(store.ContextualWriter); ok {
		var cascadeDepth uint64
		if evt.Context != nil && evt.Context.CascadeDepth != nil {
			cascadeDepth = *evt.Context.CascadeDepth + 1
		}
		mutCtx := &store.MutationContext{
			HandlerPattern: "system/compute",
			Operation:      "reactive-eval",
			CascadeDepth:   &cascadeDepth,
		}
		if evt.Context != nil {
			mutCtx.ChainID = evt.Context.ChainID
		}
		_, setErr = cw.SetWithContext(path, h, mutCtx)
	} else {
		setErr = e.locationIndex.Set(path, h)
	}
	if setErr != nil {
		// Reactive engine runs in a background goroutine; no caller to
		// propagate to. Log so operator sees stale compute results.
		e.debugf("reactive re-eval: write %s failed: %v", path, setErr)
	}
}

func (e *Engine) freezeSubgraph(qualifiedPath string, sgData types.ComputeSubgraphData, code, message, at string, evt store.TreeChangeEvent) {
	errData := types.ComputeErrorData{
		Code:    code,
		Message: message,
		At:      at,
	}
	errEnt, err := errData.ToEntity()
	if err != nil {
		return
	}
	errHash, err := e.store.Put(errEnt)
	if err != nil {
		return
	}
	e.writeResult(sgData.ResultPath, errHash, evt)

	sgData.Status = "frozen"
	frozenEnt, err := sgData.ToEntity()
	if err != nil {
		return
	}
	frozenHash, err := e.store.Put(frozenEnt)
	if err != nil {
		return
	}
	e.locationIndex.Set(qualifiedPath, frozenHash)

	e.debugf("frozen subgraph at %s: %s", qualifiedPath, code)
}

// --- Dependency Index ---

func (e *Engine) registerSubgraphDependencies(subgraphPath, rootPath string, expression entity.Entity) {
	deps := walkTreeLookups(expression, e.store, rootPath, e.localPeerID)
	e.mu.Lock()
	defer e.mu.Unlock()
	for _, dep := range deps {
		e.dependencyIndex[dep] = append(e.dependencyIndex[dep], dependencyEntry{
			ExpressionURI: rootPath,
			SubgraphPath:  subgraphPath,
		})
	}
}

func (e *Engine) removeSubgraph(subgraphPath string) {
	e.mu.Lock()
	defer e.mu.Unlock()
	for path, entries := range e.dependencyIndex {
		filtered := entries[:0]
		for _, entry := range entries {
			if entry.SubgraphPath != subgraphPath {
				filtered = append(filtered, entry)
			}
		}
		if len(filtered) == 0 {
			delete(e.dependencyIndex, path)
		} else {
			e.dependencyIndex[path] = filtered
		}
	}
}

// RebuildDependencyIndex scans system/compute/processes/* and re-registers
// dependencies for all active subgraphs. Called on peer startup.
func (e *Engine) RebuildDependencyIndex() {
	prefix := store.QualifyPath(e.localPeerID, subgraphPrefix)
	entries := e.locationIndex.List(prefix)
	rebuilt := 0
	for _, entry := range entries {
		sgEnt, ok := e.store.Get(entry.Hash)
		if !ok || sgEnt.Type != types.TypeComputeSubgraph {
			continue
		}
		var sgData types.ComputeSubgraphData
		if err := ecf.Decode(sgEnt.Data, &sgData); err != nil {
			continue
		}
		if sgData.Status != "active" {
			continue
		}
		exprHash, ok := e.locationIndex.Get(sgData.RootExpressionPath)
		if !ok {
			continue
		}
		expression, ok := e.store.Get(exprHash)
		if !ok || !IsComputeExpression(expression) {
			continue
		}
		barePath := strings.TrimPrefix(entry.Path, prefix)
		e.registerSubgraphDependencies(subgraphPrefix+barePath, sgData.RootExpressionPath, expression)
		rebuilt++
	}
	if rebuilt > 0 {
		e.debugf("rebuilt dependency index: %d subgraphs", rebuilt)
	}
}

// --- Audit Walker ---

type dataHashEntry struct {
	Hash hash.Hash
	Path string
}

type auditResult struct {
	ReadPaths      []string
	HandlerTargets []handlerTarget
	WritePaths     []string
	DataHashes     []dataHashEntry
	// EmbeddedCaps is the list of capability-token entities that compute/apply
	// nodes statically embed via the `capability` field. Populated by the
	// CP1 chain-root check; persisted by the install handler so reactive
	// re-evaluation can resolve them later (proposal §2 chain persistence).
	EmbeddedCaps []entity.Entity
	// Err is set when the walker rejects the subgraph as structurally invalid
	// (F5 of PROPOSAL-COMPUTE-APPLY-RESOURCE-CEILING; CP1 of
	// PROPOSAL-COHERENT-CAPABILITY-AUTHORITY). The install loop short-circuits.
	Err *auditError
}

type auditError struct {
	Status  uint
	Code    string
	Message string
}

type handlerTarget struct {
	Path      string                `cbor:"path"`
	Operation string                `cbor:"operation"`
	Resource  *types.ResourceTarget `cbor:"resource,omitempty"`
}

// auditConfig threads R1 inputs into the audit walker. When Installer is
// non-zero, the walker runs the CP1 chain-root check against any static
// literal `compute/apply.capability` it encounters. When Installer is zero,
// the CP1 check is skipped (used by tests that don't need the check).
type auditConfig struct {
	Installer hash.Hash
	Resolve   capability.EntityResolver
	FindSig   capability.SignatureResolver
}

func auditSubgraph(expression entity.Entity, cs store.ContentStore, rootPath, localPeerID string, cfg auditConfig) auditResult {
	result := auditResult{}
	visited := make(map[hash.Hash]bool)
	auditWalk(expression, &result, visited, cs, rootPath, localPeerID, cfg)
	return result
}

func auditWalk(ent entity.Entity, result *auditResult, visited map[hash.Hash]bool, cs store.ContentStore, rootPath, localPeerID string, cfg auditConfig) {
	if visited[ent.ContentHash] {
		return
	}
	visited[ent.ContentHash] = true

	if ent.Type == types.TypeComputeLookupTree {
		var d types.ComputeLookupTreeData
		if err := ecf.Decode(ent.Data, &d); err == nil {
			path := d.Path
			if d.Relative && rootPath != "" {
				path = store.CleanPath(rootPath + "/" + path)
			} else if !strings.HasPrefix(path, "/") && localPeerID != "" {
				// EXTENSION-COMPUTE v3.20 / V7 §5.4 — canonicalize bare path.
				path = store.QualifyPath(localPeerID, path)
			}
			result.ReadPaths = append(result.ReadPaths, path)
		}
		return
	}

	if ent.Type == types.TypeComputeLookupHash {
		var d types.ComputeLookupHashData
		if err := ecf.Decode(ent.Data, &d); err == nil {
			path := d.Path
			if d.Relative && rootPath != "" {
				path = store.CleanPath(rootPath + "/" + path)
			}
			result.DataHashes = append(result.DataHashes, dataHashEntry{Hash: d.Hash, Path: path})
		}
		return
	}

	if ent.Type == types.TypeComputeApply {
		var d types.ComputeApplyData
		if err := ecf.Decode(ent.Data, &d); err == nil && d.Path != "" {
			// F5 install-time enforcement: capability override without resource
			// is a static structural error, regardless of whether the resource
			// would be statically resolvable.
			if !d.Capability.IsZero() && d.Resource.IsZero() {
				if result.Err == nil {
					result.Err = &auditError{
						Status:  400,
						Code:    ErrInvalidExpression,
						Message: "compute/apply with capability field MUST also have resource field",
					}
				}
				return
			}
			// CP1 chain-root check on static-literal capability override
			// (PROPOSAL-COHERENT-CAPABILITY-AUTHORITY §6.1). Runs BEFORE
			// resource-coverage check per §8.2 ordering: chain-root is
			// cheaper and more fundamental. Dynamic capability values
			// (non-literal compute expressions) defer to runtime per the
			// in-flight resource-ceiling proposal's dual-check.
			if !d.Capability.IsZero() && !cfg.Installer.IsZero() && cfg.Resolve != nil {
				if cpErr := checkApplyCapability(d.Capability, cs, cfg, result); cpErr != nil {
					return
				}
			}
			// Resolve a static literal resource if present. Dynamic resources
			// (computed at runtime) are deferred to the runtime dual-check.
			var staticResource *types.ResourceTarget
			if !d.Resource.IsZero() {
				if resEnt, ok := cs.Get(d.Resource); ok && resEnt.Type == types.TypeComputeLiteral {
					var litData types.ComputeLiteralData
					if err := ecf.Decode(resEnt.Data, &litData); err == nil {
						staticResource = staticResourceTarget(litData.Value)
					}
				}
			}
			// SA-11 (v3.16 §3.3): pure collection builtins (map/filter/fold) are
			// exempt from install-time handler-target authorization — they perform
			// no tree or capability access. Only `store` is gated (via its
			// write_path collection below).
			if !isPureCollectionBuiltin(d.Path) {
				result.HandlerTargets = append(result.HandlerTargets, handlerTarget{
					Path: d.Path, Operation: d.Operation, Resource: staticResource,
				})
			}
			// Check for store builtin with literal path.
			if d.Path == "system/compute/builtins/store" {
				if pathHash, ok := d.Args["path"]; ok {
					if pathEnt, ok := cs.Get(pathHash); ok && pathEnt.Type == types.TypeComputeLiteral {
						var litData types.ComputeLiteralData
						if err := ecf.Decode(pathEnt.Data, &litData); err == nil {
							if pathStr, ok := litData.Value.(string); ok {
								result.WritePaths = append(result.WritePaths, pathStr)
							}
						}
					}
				}
			}
		}
	}

	// Walk hash references in entity data.
	walkHashRefs(ent, visited, result, cs, rootPath, localPeerID, cfg)
}

func walkHashRefs(ent entity.Entity, visited map[hash.Hash]bool, result *auditResult, cs store.ContentStore, rootPath, localPeerID string, cfg auditConfig) {
	var dataMap map[string]interface{}
	if err := ecf.Decode(ent.Data, &dataMap); err != nil {
		return
	}
	for _, v := range dataMap {
		walkValue(v, visited, result, cs, rootPath, localPeerID, cfg)
	}
}

func walkValue(v interface{}, visited map[hash.Hash]bool, result *auditResult, cs store.ContentStore, rootPath, localPeerID string, cfg auditConfig) {
	switch val := v.(type) {
	case []byte:
		h, err := hash.FromBytes(val)
		if err != nil {
			return
		}
		if ref, ok := cs.Get(h); ok {
			auditWalk(ref, result, visited, cs, rootPath, localPeerID, cfg)
		}
	case []interface{}:
		for _, item := range val {
			walkValue(item, visited, result, cs, rootPath, localPeerID, cfg)
		}
	case map[interface{}]interface{}:
		for _, item := range val {
			walkValue(item, visited, result, cs, rootPath, localPeerID, cfg)
		}
	case map[string]interface{}:
		for _, item := range val {
			walkValue(item, visited, result, cs, rootPath, localPeerID, cfg)
		}
	}
}

// checkApplyCapability resolves a compute/apply.capability hash. If it
// resolves to a compute/literal whose value is a cap-entity hash, this runs
// the R1 chain-root check against the installer's identity via the unified
// chain walker (PROPOSAL-UNIFIED-CHAIN-WALK-PRIMITIVE §3.2). On success,
// appends the full collected chain to result.EmbeddedCaps for later
// persistence by the install handler. Returns nil for the dynamic case
// (capability isn't a static literal — runtime dual-check covers).
func checkApplyCapability(capRefHash hash.Hash, cs store.ContentStore, cfg auditConfig, result *auditResult) error {
	capRefEnt, ok := cs.Get(capRefHash)
	if !ok {
		// Capability expression not in store — treat as dynamic; runtime path covers.
		return nil
	}
	if capRefEnt.Type != types.TypeComputeLiteral {
		// Dynamic value (e.g., compute/lookup/scope("caller_capability")) —
		// runtime dual-check applies, no install-time chain check.
		return nil
	}
	var litData types.ComputeLiteralData
	if err := ecf.Decode(capRefEnt.Data, &litData); err != nil {
		return nil
	}
	// Literal value should be a cap entity hash, encoded as a 33-byte string.
	capBytes, ok := litData.Value.([]byte)
	if !ok {
		return nil
	}
	capEntityHash, err := hash.FromBytes(capBytes)
	if err != nil {
		return nil
	}
	capEntity, ok := cfg.Resolve(capEntityHash)
	if !ok {
		if result.Err == nil {
			result.Err = &auditError{
				Status:  404,
				Code:    "chain_unreachable",
				Message: "compute/apply.capability literal references a cap entity not in envelope or store",
			}
		}
		return errCapAuditRejected
	}
	found, chain, walkErr := capability.CheckCreatorAuthority(capEntity, cfg.Installer, cfg.Resolve, cfg.FindSig)
	if walkErr != nil {
		if errors.Is(walkErr, ecerrors.ErrChainUnreachable) {
			if result.Err == nil {
				result.Err = &auditError{
					Status:  404,
					Code:    "chain_unreachable",
					Message: "compute/apply.capability authority chain not fully resolvable",
				}
			}
			return errCapAuditRejected
		}
		if errors.Is(walkErr, ecerrors.ErrChainTooDeep) {
			if result.Err == nil {
				result.Err = &auditError{
					Status:  400,
					Code:    "chain_too_deep",
					Message: "compute/apply.capability authority chain exceeds maximum depth",
				}
			}
			return errCapAuditRejected
		}
		if result.Err == nil {
			result.Err = &auditError{Status: 500, Code: "internal_error", Message: walkErr.Error()}
		}
		return errCapAuditRejected
	}
	if !found {
		// Per proposal §3.2: do NOT persist the chain on rejection.
		if result.Err == nil {
			result.Err = &auditError{
				Status:  403,
				Code:    "embedded_cap_unauthorized",
				Message: "installer identity not in compute/apply.capability authority chain",
			}
		}
		return errCapAuditRejected
	}
	// Authorized — flatten the collected chain into EmbeddedCaps. The install
	// handler persists by looping over this slice. Store.Put is idempotent
	// so repeated entries from overlapping chains are safe.
	result.EmbeddedCaps = append(result.EmbeddedCaps, chain...)
	return nil
}

// errCapAuditRejected is a sentinel returned by checkApplyCapability when
// the cap audit fails. The caller short-circuits on it; result.Err already
// carries the user-facing details.
var errCapAuditRejected = errors.New("cap audit rejected")

// persistEmbeddedCaps writes each cap-chain entity in the audit's EmbeddedCaps
// list to the local content store. Store.Put is idempotent so duplicates from
// overlapping chains are safe. Replaces the prior persistCapChain helper —
// the chains are now collected end-to-end at audit time, no re-walk needed.
func persistEmbeddedCaps(cs store.ContentStore, caps []entity.Entity) error {
	for _, ent := range caps {
		if _, err := cs.Put(ent); err != nil {
			return fmt.Errorf("persist embedded cap %s: %w", ent.ContentHash, err)
		}
	}
	return nil
}

// isPureCollectionBuiltin matches the three pure collection builtins
// (map/filter/fold) per §3.5. These perform no tree or capability access, so
// per SA-11 (v3.16) they're exempt from install-time handler-target auth.
// store stays gated (via its write_path collection).
func isPureCollectionBuiltin(path string) bool {
	switch path {
	case "system/compute/builtins/map",
		"system/compute/builtins/filter",
		"system/compute/builtins/fold":
		return true
	}
	return false
}

// staticResourceTarget converts a compute/literal value into a *ResourceTarget
// at install audit time. Per PROPOSAL-COMPUTE-APPLY-RESOURCE-CEILING §3.3, the
// literal carries a system/protocol/resource-target struct ({targets, exclude}),
// not a path string. Returns nil if the value isn't a recognizable target shape.
func staticResourceTarget(v interface{}) *types.ResourceTarget {
	raw, err := ecf.Encode(v)
	if err != nil {
		return nil
	}
	var rt types.ResourceTarget
	if err := ecf.Decode(raw, &rt); err != nil {
		return nil
	}
	if len(rt.Targets) == 0 {
		return nil
	}
	return &rt
}

// walkTreeLookups collects all tree-read dependency paths from an expression graph.
func walkTreeLookups(expression entity.Entity, cs store.ContentStore, rootPath, localPeerID string) []string {
	var deps []string
	visited := make(map[hash.Hash]bool)
	walkDeps(expression, &deps, visited, cs, rootPath, localPeerID)
	return deps
}

func walkDeps(ent entity.Entity, deps *[]string, visited map[hash.Hash]bool, cs store.ContentStore, rootPath, localPeerID string) {
	if visited[ent.ContentHash] {
		return
	}
	visited[ent.ContentHash] = true

	if ent.Type == types.TypeComputeLookupTree {
		var d types.ComputeLookupTreeData
		if err := ecf.Decode(ent.Data, &d); err == nil {
			path := d.Path
			if d.Relative && rootPath != "" {
				path = store.CleanPath(rootPath + "/" + path)
			} else if !strings.HasPrefix(path, "/") && localPeerID != "" {
				// EXTENSION-COMPUTE v3.20 / V7 §5.4 — canonicalize bare path so
				// dep-index keys match tree-write notification paths.
				path = store.QualifyPath(localPeerID, path)
			}
			*deps = append(*deps, path)
		}
		return
	}

	var dataMap map[string]interface{}
	if err := ecf.Decode(ent.Data, &dataMap); err != nil {
		return
	}
	for _, v := range dataMap {
		walkDepValue(v, deps, visited, cs, rootPath, localPeerID)
	}
}

func walkDepValue(v interface{}, deps *[]string, visited map[hash.Hash]bool, cs store.ContentStore, rootPath, localPeerID string) {
	switch val := v.(type) {
	case []byte:
		h, err := hash.FromBytes(val)
		if err != nil {
			return
		}
		if ref, ok := cs.Get(h); ok {
			walkDeps(ref, deps, visited, cs, rootPath, localPeerID)
		}
	case []interface{}:
		for _, item := range val {
			walkDepValue(item, deps, visited, cs, rootPath, localPeerID)
		}
	case map[interface{}]interface{}:
		for _, item := range val {
			walkDepValue(item, deps, visited, cs, rootPath, localPeerID)
		}
	case map[string]interface{}:
		for _, item := range val {
			walkDepValue(item, deps, visited, cs, rootPath, localPeerID)
		}
	}
}

// --- Helpers ---

// deterministicID produces a stable subgraph ID from a root path per §3.3.
func deterministicID(rootPath string) string {
	digest := sha256.Sum256([]byte(rootPath))
	return strings.ToLower(base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(digest[:]))
}

// reactiveBudget creates a budget for reactive re-evaluation per §7.4.
func reactiveBudget(installationGrant entity.Entity, cs store.ContentStore) *Budget {
	ops := DefaultMaxOps
	depth := DefaultMaxDepth
	capOps, capDepth := extractComputeConstraints(installationGrant, cs)
	if capOps > 0 && capOps < ops {
		ops = capOps
	}
	if capDepth > 0 && capDepth < depth {
		depth = capDepth
	}
	return NewBudget(ops, depth)
}

// qualifySubgraphPath ensures the subgraph path is fully qualified.
func (e *Engine) qualifySubgraphPath(path string) string {
	if strings.HasPrefix(path, "/") {
		return path
	}
	return store.QualifyPath(e.localPeerID, path)
}
