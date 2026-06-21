package protocol

import (
	"context"
	"encoding/hex"
	"fmt"
	"log"
	"strings"
	"sync"
	"time"

	"go.entitychurch.org/entity-core-go/core/capability"
	"go.entitychurch.org/entity-core-go/core/crypto"
	"go.entitychurch.org/entity-core-go/core/entity"
	"go.entitychurch.org/entity-core-go/core/handler"
	"go.entitychurch.org/entity-core-go/core/hash"
	"go.entitychurch.org/entity-core-go/core/store"
	"go.entitychurch.org/entity-core-go/core/types"
)

// dedupKey formats the (author, request_id) idempotency key used by the
// durability contract (EXTENSION-DURABILITY §5 / §6 / §8). Author hash hex
// + ":" + request_id is the canonical receiver-side uniqueness key.
func dedupKey(authorHash hash.Hash, requestID string) string {
	return authorHash.String() + ":" + requestID
}

const connectPath = "system/protocol/connect"

// Dispatcher decodes envelopes, verifies auth, and routes to handlers.
type Dispatcher struct {
	Registry          *handler.Registry
	Store             store.ContentStore
	LocationIndex     store.LocationIndex
	// CapabilityIndex is the observational hash→path index for cap bindings
	// (V7 v7.62 §5.1 capability_path_for). Threaded through HandlerContext;
	// nil means use a no-op index (binding-check defense-in-depth disabled,
	// is_revoked still works via the marker check).
	CapabilityIndex   capability.CapabilityIndex
	LocalKeypair      crypto.Keypair
	LocalPeerID       crypto.PeerID
	LocalIdentityHash hash.Hash
	Logger            *log.Logger

	// RemoteExecute handles Execute calls to remote peers. Set by Peer after
	// construction. Nil means remote execution is not available.
	RemoteExecute func(ctx context.Context, uri, operation string, params entity.Entity, resource *types.ResourceTarget, async ...*AsyncDelivery) (*handler.Response, error)

	// EvaluateExpression handles compute-backed handler dispatch (V7 §3.7, §6.6).
	// When a tree-walked handler has expression_path, dispatch calls this with
	// the same Request that a compiled handler would receive. The compute
	// evaluator extracts what it needs from the HandlerContext.
	// Set by the compute extension after peer construction.
	EvaluateExpression func(ctx context.Context, expressionPath string, req *handler.Request) (*handler.Response, error)

	// IdentityBindingChecker is the EXTENSION-IDENTITY §12.3 / IA23 cross-cut.
	// When non-nil, dispatch verifies the cap's grantee is bound to a
	// recognized identity (via the local tree's RPAs or the envelope's
	// included entities) AFTER VerifyChain succeeds. Nil means V7-only
	// behavior (no binding check).
	IdentityBindingChecker IdentityBindingChecker

	// asyncPool bounds fire-and-forget async dispatch (continuation advance
	// + deliver_to delivery). See asyncpool.go. Lazily started; stopped via
	// StopAsyncPool() (wired into Peer.Close()).
	asyncPool *asyncPool

	// DurabilityPolicy is the receiver's own configured durability policy
	// (EXTENSION-DURABILITY §4 — exploratory extension). Zero value = no
	// durable store (never overclaims). NewDispatcher sets the default
	// ("stored" self-determinable).
	DurabilityPolicy DurabilityPolicy

	// preservedRequests is the idempotency index for durably-preserved
	// requests (EXTENSION-DURABILITY §5 / §6 / §8). Key:
	// "{authorHashHex}:{requestID}". Value: the handle (absolute path) of
	// the preserved entry. A second durable request with the same
	// (author, request_id) returns 409 duplicate_request_id with the cached
	// handle. In-memory by design — idempotency caching is
	// implementation-defined per the extension.
	preservedRequests sync.Map

	// dispatchHooks fire at request-entry + request-exit around every
	// handler-body invocation (`invoke` in handleExecute and makeLocalExecute).
	// Per GUIDE-INSPECTABILITY v1.1 §2.1 #3. Registered at peer construction
	// via peer.WithDispatchHook; immutable after Build returns so reads are
	// lock-free on the dispatch hot path. Out-of-band convention: hook fns
	// observe + return; they MUST NOT spawn entity writes from inside the
	// hook (recursion + cascade risk per review §6.2).
	dispatchHooks []handler.NamedDispatchHook
}

// SetDispatchHooks installs the dispatch hook list. Called once by peer
// builder before the dispatcher is exposed to any traffic. Replacing after
// the peer is live is unsafe (reads are lock-free on the hot path).
func (d *Dispatcher) SetDispatchHooks(hooks []handler.NamedDispatchHook) {
	d.dispatchHooks = hooks
}

// fireDispatchHooks invokes every registered dispatch hook with the event.
// Inline on the dispatch hot path — hooks MUST be fast. The order matches
// registration order (peer-builder insertion order).
func (d *Dispatcher) fireDispatchHooks(evt handler.DispatchEvent) {
	for _, h := range d.dispatchHooks {
		h.Fn(evt)
	}
}

// NewDispatcher creates a protocol dispatcher.
func NewDispatcher(reg *handler.Registry, cs store.ContentStore, li store.LocationIndex, kp crypto.Keypair, logger *log.Logger) *Dispatcher {
	return &Dispatcher{
		Registry:         reg,
		Store:            cs,
		LocationIndex:    li,
		LocalKeypair:     kp,
		LocalPeerID:      kp.PeerID(),
		Logger:           logger,
		asyncPool:        newAsyncPool(defaultAsyncWorkers, defaultAsyncQueueSize),
		DurabilityPolicy: DefaultDurabilityPolicy(),
	}
}

// submitAsync enqueues fn on the bounded async-dispatch pool. It returns
// false (non-blocking) when the pool is saturated or stopped — the caller
// must surface backpressure (429 / durable mailbox) rather than spawn an
// unbounded goroutine. Exposed to handlers via HandlerContext.GoAsync.
func (d *Dispatcher) submitAsync(fn func()) bool {
	if d.asyncPool == nil {
		// Defensive: a Dispatcher built without NewDispatcher. Preserve the
		// pre-pool fire-and-forget behavior rather than drop the work.
		go fn()
		return true
	}
	return d.asyncPool.Submit(fn)
}

// AsyncDispatchRefused reports how many async dispatch jobs were rejected
// because the bounded pool was saturated or stopped. Surfaced via
// Peer.Stats().AsyncDispatchRefused — a non-zero, growing value means the
// peer is shedding async delivery / continuation-advance load.
func (d *Dispatcher) AsyncDispatchRefused() uint64 {
	if d.asyncPool == nil {
		return 0
	}
	return d.asyncPool.Refused()
}

// StopAsyncPool stops the bounded async-dispatch pool and waits for
// in-flight jobs. Idempotent; wired into Peer.Close().
func (d *Dispatcher) StopAsyncPool() {
	if d.asyncPool != nil {
		d.asyncPool.Stop()
	}
}

func (d *Dispatcher) debugf(format string, args ...any) {
	if d.Logger != nil {
		d.Logger.Printf(format, args...)
	}
}

func (d *Dispatcher) diagnoseEnvelope(label string, env entity.Envelope) {
	if d.Logger == nil {
		return
	}
	d.Logger.Printf("hash mismatch in %s envelope — dumping all entities:", label)
	d.Logger.Printf("root:\n%s", env.Root.DiagnoseHash())
	for h, ent := range env.Included {
		d.Logger.Printf("included[%s]:\n%s", h, ent.DiagnoseHash())
	}
}

func (d *Dispatcher) makeResponse(requestID string, resp *handler.Response) (entity.Envelope, error) {
	resultRaw, err := encodeToRaw(resp.Result)
	if err != nil {
		return entity.Envelope{}, err
	}

	respData := types.ExecuteResponseData{
		RequestID: requestID,
		Status:    resp.Status,
		Result:    resultRaw,
	}
	respEntity, err := respData.ToEntity()
	if err != nil {
		return entity.Envelope{}, err
	}

	return entity.NewEnvelope(respEntity, resp.Included), nil
}

func (d *Dispatcher) makeErrorResponse(requestID string, status uint, code, message string) (entity.Envelope, error) {
	return d.makeErrorResponseWithRejectedMarker(requestID, status, code, message, hash.Hash{})
}

// makeErrorResponseWithRejectedMarker builds an error response carrying
// an optional ErrorData.RejectedMarker mirror-pointer per EXTENSION-
// CONTINUATION v1.20 §3.10.4. When rejectedMarker is the zero hash, the
// field is omitted (omitzero).
func (d *Dispatcher) makeErrorResponseWithRejectedMarker(requestID string, status uint, code, message string, rejectedMarker hash.Hash) (entity.Envelope, error) {
	d.debugf("execute: -> error status=%d code=%s", status, code)
	errData := types.ErrorData{Code: code, Message: message, RejectedMarker: rejectedMarker}
	errEntity, err := errData.ToEntity()
	if err != nil {
		return entity.Envelope{}, err
	}

	resultRaw, err := encodeToRaw(errEntity)
	if err != nil {
		return entity.Envelope{}, err
	}

	respData := types.ExecuteResponseData{
		RequestID: requestID,
		Status:    status,
		Result:    resultRaw,
	}
	respEntity, err := respData.ToEntity()
	if err != nil {
		return entity.Envelope{}, err
	}

	return entity.NewEnvelope(respEntity, nil), nil
}

// requestingPeerIDFromExec returns the originating peer's ID string from
// the EXECUTE's author field. Used by the rejected-marker body for
// in-body inspection of who attempted the rejected request. Returns ""
// when the author entity can't be located (best-effort diagnostic field).
func requestingPeerIDFromExec(execData types.ExecuteData, env entity.Envelope) string {
	if execData.Author.IsZero() {
		return ""
	}
	authorEntity, ok := env.FindIncluded(execData.Author)
	if !ok {
		return ""
	}
	var idData types.PeerData
	if err := decodeEntity(authorEntity.Data, &idData); err != nil {
		return ""
	}
	// v7.65 §1.5: derive peer_id from (public_key, key_type) — canonical
	// form per crypto.CanonicalHashType.
	ktByte, ktOK := idData.KeyTypeByte()
	if !ktOK {
		return ""
	}
	pid, err := crypto.PeerIDFromPublicKey(idData.PublicKey, ktByte)
	if err != nil {
		return ""
	}
	return string(pid)
}

// bindRejectedChainErrorMarker binds a receiver-side `rejected` chain-
// error marker per EXTENSION-CONTINUATION v1.20 §3.10.3 when an inbound
// EXECUTE carrying Bounds.ChainID is refused on cap-check. Returns the
// marker's content_hash for inclusion in the outgoing ErrorData.
// RejectedMarker mirror-pointer per §3.10.4.
//
// Scope: chain-dispatches only — when execData.Bounds.ChainID is empty,
// returns the zero hash and binds nothing (ordinary cap-rejection is
// already observable via the synchronous 403 response per §3.10.3
// Scope). Best-effort: bind failures are logged + swallowed; the 403
// response is returned regardless.
//
// The dispatcher binds under component-owned authority (core protocol's
// "core/chain-errors" internal_scope per §3.10.7 binding-components
// rule); mechanism is impl-private — Go uses the unwrapped LocationIndex
// directly which routes through the namespaced + notifying wrappers
// without requiring a HandlerContext-level capability check.
//
// Path: system/runtime/chain-errors/rejected/{chain_id}/{step_index}/
//
//	{reason}/{marker_hash}
//
// where {marker_hash} is the V7 §3.5 invariant-pointer hex form
// (lowercase, format-code-included, 66 chars).
func (d *Dispatcher) bindRejectedChainErrorMarker(execData types.ExecuteData, code, attemptedURI string, requestingPeerID string) hash.Hash {
	if execData.Bounds == nil || execData.Bounds.ChainID == "" {
		// §3.10.3 scope: rejected variant fires only for chain dispatches.
		return hash.Hash{}
	}
	if d.Store == nil || d.LocationIndex == nil {
		return hash.Hash{}
	}
	chainID := execData.Bounds.ChainID
	stepKey := execData.RequestID
	if stepKey == "" {
		stepKey = "0"
	}
	// §3.10.6 timestamp-capture: origination is the moment cap-check
	// fails (i.e., right now in the dispatcher's call stack).
	originTS := uint64(time.Now().UnixMilli())

	marker, err := types.ChainErrorLostData{
		Reason:           code,
		Timestamp:        originTS,
		ChainID:          chainID,
		StepIndex:        stepKey,
		RequestingPeerID: requestingPeerID,
		AttemptedURI:     attemptedURI,
	}.ToEntity()
	if err != nil {
		return hash.Hash{}
	}
	markerHash, err := d.Store.Put(marker)
	if err != nil {
		return hash.Hash{}
	}
	// v1.20 path: terminal {marker_hash} segment using V7 §3.5
	// invariant-pointer hex form.
	markerPath := "system/runtime/chain-errors/rejected/" + chainID + "/" + stepKey + "/" + code + "/" + hex.EncodeToString(markerHash.Bytes())
	if err := d.LocationIndex.Set(markerPath, markerHash); err != nil {
		// Per §3.10.8 bind-failure visibility (F11 generalization):
		// surface the failure rather than silently claim success.
		d.debugf("rejected chain-error marker bind FAILED at %s: %v (code=%q attempted_uri=%q requesting_peer=%q) — operator visibility gap",
			markerPath, err, code, attemptedURI, requestingPeerID)
		return hash.Hash{}
	}
	d.debugf("bound rejected chain-error marker at %s (code=%q attempted_uri=%q requesting_peer=%q)",
		markerPath, code, attemptedURI, requestingPeerID)
	return markerHash
}

func decrementBounds(b *types.BoundsData) (*types.BoundsData, error) {
	if b == nil {
		return nil, nil
	}
	child := *b
	if child.TTL != nil {
		if *child.TTL == 0 {
			return nil, fmt.Errorf("TTL exhausted")
		}
		newTTL := *child.TTL - 1
		child.TTL = &newTTL
	}
	return &child, nil
}

// processAsyncDelivery handles an EXECUTE with a deliver_to field asynchronously.
// It runs the handler invocation (compiled handler or entity-native expression
// — the caller chooses by passing the appropriate closure), then delivers the
// result to the inbox. The dispatcher does not branch deliver_to on handler
// shape: V7 §6.6 says the tree binds dispatch targets; this layer honors
// deliver_to uniformly across handler types.

func qualifyIfRelative(localPeerID, path string) string {
	if strings.HasPrefix(path, "/") {
		return path
	}
	return store.QualifyPath(localPeerID, path)
}

// isRemoteURI returns true if the URI targets a different peer.
func isRemoteURI(uri string, localPeerID crypto.PeerID) bool {
	parsed, err := entity.ParseURI(uri)
	if err != nil {
		return false
	}
	return parsed.PeerID != "" && parsed.PeerID != string(localPeerID)
}

// normalizeResourceTargets resolves entity URIs in resource targets to local paths.
// If a target is entity://local_peer/path, it becomes just path.
// If a target is entity://other_peer/path, it stays as-is (cross-peer resource reference).
// If a target is already a bare path, it stays as-is.
func normalizeResourceTargets(resource *types.ResourceTarget, localPeerID crypto.PeerID) *types.ResourceTarget {
	if resource == nil || len(resource.Targets) == 0 {
		return resource
	}
	normalized := &types.ResourceTarget{Targets: make([]string, len(resource.Targets))}
	for i, target := range resource.Targets {
		parsed, err := entity.ParseURI(target)
		if err == nil && parsed.PeerID == string(localPeerID) && parsed.Path != "" {
			// Local peer URI — extract bare path.
			normalized.Targets[i] = parsed.Path
		} else {
			normalized.Targets[i] = target
		}
	}
	return normalized
}
