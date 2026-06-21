package localfiles

import (
	"context"
	"fmt"
	"log"
	"path/filepath"
	"reflect"
	"strings"
	"sync"

	"go.entitychurch.org/entity-core-go/core/handler"
	"go.entitychurch.org/entity-core-go/core/hash"
	"go.entitychurch.org/entity-core-go/core/store"
	"go.entitychurch.org/entity-core-go/core/types"
)

// configPathPrefix is the tree prefix under which root configs are persisted.
// AddRoot writes each root config at configPathPrefix + name.
const configPathPrefix = "system/config/local/files/"

const handlerPattern = "local/files"

// Handler implements the local/files domain handler per DOMAIN-LOCAL-FILES.md.
type Handler struct {
	mu             sync.Mutex
	roots          map[string]*RootMapping
	watchers       map[string]*watcher
	reverseTracker *reverseTracker
	localNS        string // local peer ID for namespace stripping in reverse write
	logger         *log.Logger
	statCache      *statCache // L7 stat-cache per §10.2 SHOULD (Git racy-clean shape)
}

// NewHandler creates a new local files handler.
func NewHandler(logger *log.Logger) *Handler {
	return &Handler{
		roots:     make(map[string]*RootMapping),
		watchers:  make(map[string]*watcher),
		logger:    logger,
		statCache: newStatCache(),
	}
}

func (h *Handler) Name() string { return "local-files" }

// Close stops all active watchers and releases their inotify instances.
// Safe to call multiple times — second and subsequent calls find an empty
// watchers map and are no-ops. Returns nil; individual watcher Stop()
// errors are swallowed (best-effort teardown).
//
// Surfaced by workbench-go Stage 4 multi-peer suite — multi-peer-per-process
// tests accumulate inotify instances until Linux's per-user
// fs.inotify.max_user_instances cap (default 128) is hit. See the
// workbench watcher-close feedback. Production peers
// (one peer per process, long-lived) don't bite the cap; the close path
// is for test harnesses + embedded-mode consumers that spin up many
// peers in one process.
//
// Wire via peer.WithCloseFunc(func() { _ = filesH.Close() }) so the
// peer's Close() drives watcher teardown automatically.
func (h *Handler) Close() error {
	h.mu.Lock()
	defer h.mu.Unlock()
	for _, w := range h.watchers {
		w.Stop()
	}
	h.watchers = map[string]*watcher{}
	return nil
}

// StartWatching starts the fsnotify watcher for a named root. Call after AddRoot.
// The peerIdentityHash is the content hash of the local peer's identity entity,
// used to build execution context for watcher-triggered tree writes.
func (h *Handler) StartWatching(ctx context.Context, rootName string, cs store.ContentStore, li store.LocationIndex, peerIdentityHash hash.Hash) error {
	h.mu.Lock()
	root, exists := h.roots[rootName]
	if !exists {
		h.mu.Unlock()
		return fmt.Errorf("root %q not found", rootName)
	}
	h.mu.Unlock()

	// Look up the handler grant for background context.
	var capHash hash.Hash
	if gh, ok := li.Get("system/capability/grants/" + handlerPattern); ok {
		capHash = gh
	}

	w, err := newWatcher(root, 2000, cs, li, h.logger, h.statCache)
	if err != nil {
		return fmt.Errorf("create watcher: %w", err)
	}
	w.bgCtx = &store.MutationContext{
		AuthorHash:     peerIdentityHash,
		CapabilityHash: capHash,
		HandlerPattern: handlerPattern,
		Operation:      "watch",
	}

	h.mu.Lock()
	if old, ok := h.watchers[rootName]; ok {
		old.Stop()
	}
	h.watchers[rootName] = w
	h.mu.Unlock()

	w.Start(ctx)
	return nil
}

// Manifest returns the handler's self-description (v1.2 §5.5).
//
// The system/content grant (ingest, get) is load-bearing: read/write
// chunk through ext/content's CONTENT v3.6 substrate and persist blob +
// chunk entities by hash. The system/content/descriptor/* tree:put
// grant declares potential authority for descriptor publication; the
// actual write is gated per-root by RootConfig.PublishDescriptors at
// the read call site.
func (h *Handler) Manifest() types.HandlerManifestData {
	return types.HandlerManifestData{
		Pattern: handlerPattern,
		Name:    "local-files",
		Operations: map[string]types.HandlerOperationSpec{
			"read":   {OutputType: TypeFile},
			"write":  {InputType: TypeWriteRequest, OutputType: TypeFile},
			"list":   {OutputType: TypeDirectory},
			"delete": {OutputType: TypeDeleted},
			"watch":  {InputType: TypeWatchRequest, OutputType: TypeWatcherConfig},
		},
		InternalScope: []types.GrantEntry{
			{
				Handlers:   types.CapabilityScope{Include: []string{"system/tree"}},
				Resources:  types.CapabilityScope{Include: []string{"local/files/*"}},
				Operations: types.CapabilityScope{Include: []string{"get", "put"}},
			},
			{
				Handlers:   types.CapabilityScope{Include: []string{"system/subscription"}},
				Resources:  types.CapabilityScope{Include: []string{"local/files/*"}},
				Operations: types.CapabilityScope{Include: []string{"subscribe", "unsubscribe"}},
			},
			{
				Handlers:   types.CapabilityScope{Include: []string{"system/content"}},
				Resources:  types.CapabilityScope{Include: []string{"system/content"}},
				Operations: types.CapabilityScope{Include: []string{"ingest", "get"}},
			},
			{
				Handlers:   types.CapabilityScope{Include: []string{"system/tree"}},
				Resources:  types.CapabilityScope{Include: []string{"system/content/descriptor/*"}},
				Operations: types.CapabilityScope{Include: []string{"put"}},
			},
		},
	}
}

// RegisterTypes registers domain types into the type registry.
func (h *Handler) RegisterTypes(r *types.TypeRegistry) {
	// Register DirectoryEntryData first (referenced by DirectoryData).
	r.ReflectType(TypeDirectoryEntry, reflect.TypeOf(DirectoryEntryData{}))

	r.ReflectType(TypeFile, reflect.TypeOf(FileData{}))
	r.ReflectType(TypeDirectory, reflect.TypeOf(DirectoryData{}))
	r.ReflectType(TypeDeleted, reflect.TypeOf(DeletedData{}))
	r.ReflectType(TypeRootConfig, reflect.TypeOf(RootConfigData{}))
	r.ReflectType(TypeWatcherConfig, reflect.TypeOf(WatcherConfigData{}))
	r.ReflectType(TypeWriteRequest, reflect.TypeOf(WriteRequestData{}))
	r.ReflectType(TypeWatchRequest, reflect.TypeOf(WatchRequestData{}))
}

// Handle dispatches to the appropriate operation.
func (h *Handler) Handle(ctx context.Context, req *handler.Request) (*handler.Response, error) {
	switch req.Operation {
	case "read":
		return h.handleRead(ctx, req)
	case "write":
		return h.handleWrite(ctx, req)
	case "list":
		return h.handleList(ctx, req)
	case "delete":
		return h.handleDelete(ctx, req)
	case "watch":
		return h.handleWatch(ctx, req)
	default:
		resp, _ := handler.NewErrorResponse(400, "unknown_operation",
			"local/files handler does not support operation: "+req.Operation)
		return resp, nil
	}
}

func (h *Handler) logf(format string, args ...any) {
	if h.logger != nil {
		h.logger.Printf(format, args...)
	}
}

// Load rehydrates root mappings from configs persisted in the tree under
// system/config/local/files/* and restarts the fsnotify watchers for each
// loaded root. Call once during peer startup after the content store and
// location index are wired (the same point at which subscription.Engine.Load
// runs) so a restart with an existing identity-aware peer + SQLite store
// resumes filesystem watching automatically.
//
// Mirrors GUIDE-RESTART-AND-PERSISTENCE §3 RE-1: the canonical
// in-memory-from-tree rebuild pattern. Idempotent — re-running with the same
// tree content rewrites the in-memory map without side effects.
//
// Watcher-config entities at system/config/local/files/watch/* are not roots;
// they're created by the watch operation and replay through a different path.
// Load filters by entity type so only TypeRootConfig entries are processed.
func (h *Handler) Load(ctx context.Context, cs store.ContentStore, li store.LocationIndex, peerIdentityHash hash.Hash) error {
	if li == nil || cs == nil {
		return nil
	}
	loaded := 0
	for _, entry := range li.List(configPathPrefix) {
		// Skip the watch/ sub-namespace (watcher configs, not root configs).
		rel := strings.TrimPrefix(entry.Path, configPathPrefix)
		if rel == "" || strings.Contains(rel, "/") {
			continue
		}
		ent, ok := cs.Get(entry.Hash)
		if !ok || ent.Type != TypeRootConfig {
			continue
		}
		cfg, err := RootConfigDataFromEntity(ent)
		if err != nil {
			h.logf("local-files: skip malformed root config at %s: %v", entry.Path, err)
			continue
		}
		name := rel
		if err := h.addRootInMemory(name, cfg); err != nil {
			h.logf("local-files: skip root %q: %v", name, err)
			continue
		}
		if err := h.StartWatching(ctx, name, cs, li, peerIdentityHash); err != nil {
			h.logf("local-files: start watcher for %q failed: %v", name, err)
			continue
		}
		loaded++
	}
	if loaded > 0 {
		h.logf("local-files: rehydrated %d root(s) from tree", loaded)
	}
	return nil
}

// addRootInMemory rebuilds the in-memory RootMapping without re-persisting
// the config entity. Used by Load to restore state from configs already in
// the tree — AddRoot is the create path (persists + maps); this is the
// rehydrate path.
func (h *Handler) addRootInMemory(name string, cfg RootConfigData) error {
	absRoot, err := filepath.Abs(cfg.FilesystemRoot)
	if err != nil {
		return fmt.Errorf("resolve filesystem root: %w", err)
	}
	prefix := cfg.Prefix
	if prefix != "" && !strings.HasSuffix(prefix, "/") {
		prefix += "/"
	}

	h.mu.Lock()
	defer h.mu.Unlock()

	// Idempotent: overwrite an existing same-named root rather than failing
	// the overlap check against itself.
	if _, exists := h.roots[name]; !exists {
		for _, existing := range h.roots {
			if strings.HasPrefix(prefix, existing.Prefix) || strings.HasPrefix(existing.Prefix, prefix) {
				return fmt.Errorf("prefix %q overlaps with existing root %q (prefix %q)", prefix, existing.Name, existing.Prefix)
			}
		}
	}

	h.roots[name] = &RootMapping{
		Name:               name,
		Prefix:             prefix,
		FSRoot:             absRoot,
		ReadOnly:           cfg.ReadOnly,
		Exclude:            cfg.Exclude,
		Include:            cfg.Include,
		PublishDescriptors: cfg.PublishDescriptors,
	}
	return nil
}
