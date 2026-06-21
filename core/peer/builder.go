package peer

import (
	"encoding/json"
	"fmt"
	"log"
	"os"

	"go.entitychurch.org/entity-core-go/core/crypto"
	"go.entitychurch.org/entity-core-go/core/ecf"
	"go.entitychurch.org/entity-core-go/core/handler"
	"go.entitychurch.org/entity-core-go/core/hash"
	"go.entitychurch.org/entity-core-go/core/protocol"
	"go.entitychurch.org/entity-core-go/core/store"
	"go.entitychurch.org/entity-core-go/core/tree"
	"go.entitychurch.org/entity-core-go/core/types"

	"github.com/fxamacker/cbor/v2"
)

// remoteEntry holds a remote peer registration for builder configuration.
type remoteEntry struct {
	peerID crypto.PeerID
	addr   string
}

// config holds peer construction parameters.
type config struct {
	keypair                *crypto.Keypair
	store                  store.ContentStore
	locationIndex          store.LocationIndex
	listenAddr             string
	handlers               []handlerEntry
	protocols              []string
	treeEventBuffer        int
	debugLog               *log.Logger
	connectionGrants       []types.GrantEntry
	grantResolver          protocol.GrantResolver
	treeEventSinks         []chan<- store.TreeChangeEvent
	namedSyncHooks         []store.NamedSyncHook
	namedContentHooks      []store.NamedContentHook
	dispatchHooks          []handler.NamedDispatchHook
	wireHooks              []NamedWireHook
	closeFuncs             []func()
	remotes                []remoteEntry
	rootTracker            *tree.RootTracker
	contextFields          []store.ContextFieldRegistration
	identityBindingChecker protocol.IdentityBindingChecker
	maxCascadeDepth        *uint64
	ownerIdentityHash      *hash.Hash
	seedPolicy             []SeedPolicyEntry
}

// handlerEntry preserves WithHandler insertion order so type registration
// runs deterministically. ext/identity's RegisterTypes references Go
// structs from ext/attestation and ext/quorum; if their RegisterTypes
// hasn't run yet, the cross-package struct fields reflect as
// "unregistered struct type" and ReflectType silently fails (the error
// is discarded). Iteration order matters — a map produced intermittent
// failures (different types missing each peer restart).
type handlerEntry struct {
	pattern string
	h       handler.Handler
}

// Option configures a Peer during construction.
type Option func(*config)

// WithIdentity sets the peer's keypair.
func WithIdentity(kp crypto.Keypair) Option {
	return func(c *config) {
		c.keypair = &kp
	}
}

// WithStore sets the peer's content store.
func WithStore(s store.ContentStore) Option {
	return func(c *config) {
		c.store = s
	}
}

// WithLocationIndex sets the peer's location index.
func WithLocationIndex(li store.LocationIndex) Option {
	return func(c *config) {
		c.locationIndex = li
	}
}

// WithListenAddr sets the TCP listen address.
func WithListenAddr(addr string) Option {
	return func(c *config) {
		c.listenAddr = addr
	}
}

// WithHandler registers a custom handler at the given pattern. Multiple
// WithHandler calls preserve order; type registration runs in insertion
// order so cross-extension struct field references resolve correctly.
func WithHandler(pattern string, h handler.Handler) Option {
	return func(c *config) {
		c.handlers = append(c.handlers, handlerEntry{pattern: pattern, h: h})
	}
}

// WithProtocols sets the supported protocol versions.
func WithProtocols(protocols []string) Option {
	return func(c *config) {
		c.protocols = protocols
	}
}

// WithTreeEventBuffer sets the buffer size for the tree events channel.
// Default is 256.
func WithTreeEventBuffer(size int) Option {
	return func(c *config) {
		c.treeEventBuffer = size
	}
}

// WithDebugLog enables debug protocol logging with the given logger.
// When nil (default), no debug output is produced.
func WithDebugLog(l *log.Logger) Option {
	return func(c *config) {
		c.debugLog = l
	}
}

// WithConnectionGrants overrides the default connection grants given to connecting peers.
// Use OpenAccessGrants() for full read/write access during testing.
func WithConnectionGrants(grants []types.GrantEntry) Option {
	return func(c *config) {
		c.connectionGrants = grants
	}
}

// WithGrantResolver sets a dynamic grant resolver that determines connection
// grants based on the remote peer's identity. If the resolver returns nil for
// a peer, the handler falls through to static connectionGrants or defaults.
func WithGrantResolver(r protocol.GrantResolver) Option {
	return func(c *config) {
		c.grantResolver = r
	}
}

// WithOwnerIdentity sets the principal-level owner-cap grantee per V7
// v7.74 Phase 2 §6.9a. The default (when this option is not supplied)
// is the peer's own identity hash — the key-holder is owner by
// construction. Override to a separate identity for multi-key /
// operator-administration models (--operator <id> equivalent).
func WithOwnerIdentity(identityHash hash.Hash) Option {
	return func(c *config) {
		h := identityHash
		c.ownerIdentityHash = &h
	}
}

// WithSeedPolicy declares additional startup-time capability policy
// entries per V7 v7.74 Phase 2 §6.9a. Entries materialize at L0
// alongside the self-owner seed entry at
// system/capability/policy/{Pattern} per v7.64 dual-form discipline.
//
// The self-owner entry is always materialized (see WithOwnerIdentity);
// this option adds operator / admin / reader / default entries on top.
// Existing entries at the bound path (e.g., from a persisted store)
// are NOT clobbered.
func WithSeedPolicy(entries []SeedPolicyEntry) Option {
	return func(c *config) {
		c.seedPolicy = append(c.seedPolicy, entries...)
	}
}

// WithSeedPolicyFromFile reads a JSON seed-policy file and appends its
// entries via WithSeedPolicy. CLI / config sugar that desugars to the
// builder per SDK-OPERATIONS §3.5.
//
// JSON shape (one object per entry):
//
//	[
//	  {
//	    "pattern": "abc123...",              // hex form, Base58 form, or "default"
//	    "grants": [ { ...GrantEntry... } ],
//	    "ttl_ms": 3600000,                    // optional
//	    "notes": "operator admin entry"       // optional
//	  }
//	]
//
// Keystone's protocol-generator/shared/seed-policy/ is the canonical
// cross-impl file-format authority once authored; this is a minimal
// shape pinned by Go's CapabilityPolicyEntryData CBOR field names.
func WithSeedPolicyFromFile(path string) Option {
	return func(c *config) {
		raw, err := os.ReadFile(path)
		if err != nil {
			panic(fmt.Errorf("WithSeedPolicyFromFile: read %s: %w", path, err))
		}
		var rawEntries []struct {
			Pattern string             `json:"pattern"`
			Grants  []types.GrantEntry `json:"grants"`
			TTLMs   *uint64            `json:"ttl_ms,omitempty"`
			Notes   string             `json:"notes,omitempty"`
		}
		if err := json.Unmarshal(raw, &rawEntries); err != nil {
			panic(fmt.Errorf("WithSeedPolicyFromFile: parse %s: %w", path, err))
		}
		for _, e := range rawEntries {
			c.seedPolicy = append(c.seedPolicy, SeedPolicyEntry{
				Pattern: e.Pattern,
				Grants:  e.Grants,
				TTLMs:   e.TTLMs,
				Notes:   e.Notes,
			})
		}
	}
}

// WithIdentityBindingChecker installs the EXTENSION-IDENTITY §12.3 / IA23
// cross-cut. Once wired, dispatch verifies (after V7 §5.5 chain validation)
// that incoming caps' grantee peers are bound to recognized identities via
// runtime-peer-attestations cached locally or embedded in the envelope. Nil
// (the default) preserves V7-only behavior.
func WithIdentityBindingChecker(checker protocol.IdentityBindingChecker) Option {
	return func(c *config) {
		c.identityBindingChecker = checker
	}
}

// WithNamedSyncHook registers a named synchronous hook on the
// NotifyingLocationIndex. Hooks run inline during writes, before the async
// channel emit. A non-200 return halts the cascade — remaining hooks are
// skipped. Consumer names appear in 207 partial-result responses.
func WithNamedSyncHook(name string, fn func(store.TreeChangeEvent) *store.ConsumerResult) Option {
	return func(c *config) {
		c.namedSyncHooks = append(c.namedSyncHooks, store.NamedSyncHook{Name: name, Fn: fn})
	}
}

// WithNamedSyncHookPattern is the pattern-filtered variant of WithNamedSyncHook.
// The hook only fires for events whose Path matches pattern (grammar: `*` for
// all, `prefix/*` for prefix match, or exact path — mirrors Python's
// `_pattern_matches`). Non-matching events skip the hook silently; it does
// not participate in the CascadeResult for that event.
//
// Use this when a consumer's responsibility is scoped to a known path family
// (e.g., a query-index that only cares about its own indexed prefix). Moves
// the prefix check from the consumer's fn body into the engine, so the
// registration site declares intent and the engine can skip the call entirely.
func WithNamedSyncHookPattern(name, pattern string, fn func(store.TreeChangeEvent) *store.ConsumerResult) Option {
	return func(c *config) {
		c.namedSyncHooks = append(c.namedSyncHooks, store.NamedSyncHook{Name: name, Pattern: pattern, Fn: fn})
	}
}

// WithNamedContentHook registers a named synchronous hook on the
// NotifyingContentStore. Hooks run inline during Put when a new entity hash
// enters the store. A non-200 return halts the cascade — remaining hooks are
// skipped. Consumer ordering per SYSTEM-COMPOSITION v1.2 section 2.2:
// persistence at position 0, query content indexes at position 1.
func WithNamedContentHook(name string, fn func(store.ContentStoreEvent) *store.ContentConsumerResult) Option {
	return func(c *config) {
		c.namedContentHooks = append(c.namedContentHooks, store.NamedContentHook{Name: name, Fn: fn})
	}
}

// WithBindingHook registers a parallel observation hook for binding events
// (location-index mutations) per GUIDE-INSPECTABILITY v1.1 §2.1 #2. This is
// an observe-only alias for WithNamedSyncHook: the signature drops the
// *ConsumerResult return so the hook cannot accidentally halt the cascade —
// which is the right shape for inspect consumers that just want to observe.
//
// Use WithNamedSyncHook directly if your hook participates in the cascade
// pipeline (query index, history recorder, root tracker, etc.) and may
// legitimately halt with a non-200 result. Use this alias for pure
// observation (BindingStream / inspect tooling) where halting is a bug.
//
// Same fire site, same TreeChangeEvent fact-tuple: (Path, PeerID, Hash,
// PreviousHash, ChangeType ∈ {Created, Modified, Deleted}, Context.CascadeDepth).
// Maps to v1.1 §2.1 #2's (path, kind, hash, prior_hash, timestamp, cascade_depth?).
// Timestamp is observer-stamped on receipt (same as ContentStream).
func WithBindingHook(name string, fn func(store.TreeChangeEvent)) Option {
	return WithNamedSyncHook(name, func(evt store.TreeChangeEvent) *store.ConsumerResult {
		fn(evt)
		return nil
	})
}

// WithBindingHookPattern is the pattern-filtered variant of WithBindingHook.
// Same grammar as WithNamedSyncHookPattern; same observe-only semantics as
// WithBindingHook (hook cannot halt the cascade).
func WithBindingHookPattern(name, pattern string, fn func(store.TreeChangeEvent)) Option {
	return WithNamedSyncHookPattern(name, pattern, func(evt store.TreeChangeEvent) *store.ConsumerResult {
		fn(evt)
		return nil
	})
}

// WithWireHook registers a parallel observation hook at the wire I/O
// boundary per GUIDE-INSPECTABILITY v1.1 §2.1 #7. Fires once per envelope
// crossing the network boundary — post-decode for inbound (so the hook
// sees both the raw frame bytes and the decoded root type / request_id),
// post-write for outbound (after the frame is committed to the socket).
//
// Security note: the FrameBytes field carries the full CBOR envelope as
// it traveled on the wire, including capability tokens, signatures, and
// payload entities. A wire recorder hooked here observes raw authority
// material; operator policy on recording-sink access is load-bearing per
// the security addendum to the v1.1 review.
//
// Hook fires on the wire hot path. Snapshot the fields you need (copying
// FrameBytes if you need to retain it) and return. Sync; runs inside the
// connection's read goroutine for inbound or under writeMu for outbound.
func WithWireHook(name string, fn WireEventFn) Option {
	return func(c *config) {
		c.wireHooks = append(c.wireHooks, NamedWireHook{Name: name, Fn: fn})
	}
}

// WithDispatchHook registers a parallel observation hook at the
// dispatcher↔handler boundary per GUIDE-INSPECTABILITY v1.1 §2.1 #3. The
// hook fires twice per dispatch: once at entry (before the handler body
// runs) and once at exit (after it returns, before the response envelope is
// built). Fires for both wire-entry dispatches and handler-from-handler
// local dispatches.
//
// Observation-only: the hook fn receives the event by value and cannot
// influence the dispatch flow. Do NOT spawn entity writes from inside the
// hook — that would recurse through content/binding hooks and risk cascade
// blowup. Out-of-band sinks (ring buffer, channel, log) are the right
// pattern per v1.1 §4.1.
//
// Hooks fire on the dispatch hot path. Snapshot the fields you need and
// return; do NOT retain references to the event or its hash-typed fields'
// underlying entities. To inspect the response body, read it from the
// content store via the ResponseHash.
//
// Handshake-path dispatches (the AUTHENTICATE / CONNECT flow before the
// connection state is established) do NOT fire this hook — those aren't
// handler-body invocations in the cross-impl-comparable sense (synthesis
// §3.4 / Python P4 baseline). The wire hook surface (when added) covers
// handshake observation.
func WithDispatchHook(name string, fn handler.DispatchEventFn) Option {
	return func(c *config) {
		c.dispatchHooks = append(c.dispatchHooks, handler.NamedDispatchHook{Name: name, Fn: fn})
	}
}

// WithTreeEventSink registers an additional consumer of tree change events.
// Events are copied to all registered sinks via fan-out. Use for extensions
// that consume the emit pathway (subscription, history, compute, etc.).
//
// **Contract**: the caller MUST drain `sink` (or close the peer to release
// the fan-out goroutine). The fan-out sends are blocking — a full sink
// applies backpressure to every writer that calls Set. This is intentional:
// tree change events are correctness-critical (see V7 §2870 on post-commit
// observability) and the previous drop-on-full behavior caused silent data
// loss under bursty writes (see the workbench SQLite busy bulk-ingest
// review and follow-up emit/fanOut drop analysis).
//
// Size the sink for expected burst depth — peer.TreeEvents() uses
// `treeEventBuffer` (256 default) and is fine for most cases; extensions
// that ingest from cold-start mounts (1000+ files) should size accordingly.
func WithTreeEventSink(sink chan<- store.TreeChangeEvent) Option {
	return func(c *config) {
		c.treeEventSinks = append(c.treeEventSinks, sink)
	}
}

// WithMaxCascadeDepth overrides the system cascade-depth refusal threshold
// (store.DefaultMaxCascadeDepth, 32). A write whose effective cascade depth
// reaches this value is refused — the binding does not commit. This is the
// bound that terminates a cross-peer subscription cycle (writes propagating
// A→B→C→D→A) before it runs unbounded. Mainly useful for tests that want a
// tight, deterministic loop guard and for operators tuning a topology with
// known sync-chain depth.
func WithMaxCascadeDepth(depth uint64) Option {
	return func(c *config) {
		c.maxCascadeDepth = &depth
	}
}

// WithRootTracker attaches an incremental trie-root tracker to the tree
// handler so snapshot operations over tracked prefixes return the maintained
// root without rebuilding (EXTENSION-TREE v3.8 §3.4). The tracker must also
// be registered as a sync hook via WithNamedSyncHook and wired with the
// peer's location index after construction.
func WithRootTracker(t *tree.RootTracker) Option {
	return func(c *config) {
		c.rootTracker = t
	}
}

// WithContextField registers an extension-contributed context field
// (SYSTEM-COMPOSITION section 1.5). Fields are validated during peer
// construction — core field name conflicts and duplicates are rejected.
func WithContextField(reg store.ContextFieldRegistration) Option {
	return func(c *config) {
		c.contextFields = append(c.contextFields, reg)
	}
}

// WithCloseFunc registers a function called during Peer.Close().
// Used by extensions to clean up resources (cancel engine contexts, etc.).
func WithCloseFunc(fn func()) Option {
	return func(c *config) {
		c.closeFuncs = append(c.closeFuncs, fn)
	}
}

// WithRemotePeer registers a remote peer's transport address at construction
// time. The address is stored in the tree at system/peer/transport/{peer_id}
// per EXTENSION-NETWORK §10. Connections are established lazily on first use.
func WithRemotePeer(peerID crypto.PeerID, addr string) Option {
	return func(c *config) {
		c.remotes = append(c.remotes, remoteEntry{peerID: peerID, addr: addr})
	}
}

// OpenAccessGrants returns grants that give full access to all handlers,
// resources, and operations. Use for development/testing only.
//
// Includes a separate query grant entry with explicit constraints and
// allowances per PROPOSAL-CAPABILITY-GRANT-ALLOWANCES (v7.14) so both
// the constraint and allowance pathways are exercised in open-access mode.
// Constraints: wildcard type_scope (required for content_store scope).
// Allowances: content_store scope (full access to all entities).
func OpenAccessGrants() []types.GrantEntry {
	// General wildcard grant — covers all handlers/ops/resources.
	// Resources include both "*" (canonicalizes to /{local}/* — local
	// namespace) and "/*/*" (cross-peer wildcard — any peer's subtree). The
	// cross-peer pattern is required for test scenarios that pre-bind
	// signatures into auxiliary signers' namespaces (per EXTENSION-IDENTITY
	// §8 V7 invariant pointer pattern: /{signer_peer_id}/system/signature/...).
	general := types.GrantEntry{
		Handlers:   types.CapabilityScope{Include: []string{"*"}},
		Resources:  types.CapabilityScope{Include: []string{"*", "/*/*"}},
		Operations: types.CapabilityScope{Include: []string{"*"}},
	}

	// Query-specific grant — exercises both constraint and allowance pathways.
	queryConstraintData := types.QueryConstraintsData{
		TypeScope: &types.CapabilityScope{Include: []string{"*"}},
	}
	constraintRaw, err := ecf.Encode(queryConstraintData)
	if err != nil {
		return []types.GrantEntry{general}
	}

	queryAllowanceData := types.QueryAllowancesData{
		Scope: "content_store",
	}
	allowanceRaw, err := ecf.Encode(queryAllowanceData)
	if err != nil {
		return []types.GrantEntry{general}
	}

	queryGrant := types.GrantEntry{
		Handlers:    types.CapabilityScope{Include: []string{"system/query"}},
		Resources:   types.CapabilityScope{Include: []string{"*"}},
		Operations:  types.CapabilityScope{Include: []string{"find", "count"}},
		Constraints: cbor.RawMessage(constraintRaw),
		Allowances:  cbor.RawMessage(allowanceRaw),
	}

	// Query grant first — more specific, will match query requests before
	// the general wildcard. CheckPermission returns first matching entry.
	return []types.GrantEntry{queryGrant, general}
}
