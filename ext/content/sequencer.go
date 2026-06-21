// Package content — SDK closure-completion surface per
// SDK-EXTENSION-OPERATIONS v0.8 §11 + PROPOSAL-CONTENT-MATERIALIZATION-
// FIRST-CLASS Amendment A (v2 closure-think reframe).
//
// EnsureClosure is the load-bearing primitive: a cap-checked sequencer
// over system/content:get that drains until the requested blob's full
// closure (blob entity + every chunk it references) is locally present.
// It does NOT return bytes. Byte extraction is Reassemble (see
// builder.go) — a pure local helper over a complete closure.
//
// AtPeer is the peer-aimed Dispatcher for handler-cross-peer dispatch
// per workbench Option B: when a handler running on peer B needs to
// drive closure-completion against peer A's namespace (subscription-
// driven cross-peer materialization, etc.).
package content

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"go.entitychurch.org/entity-core-go/core/crypto"
	"go.entitychurch.org/entity-core-go/core/ecf"
	"go.entitychurch.org/entity-core-go/core/entity"
	"go.entitychurch.org/entity-core-go/core/handler"
	"go.entitychurch.org/entity-core-go/core/hash"
	"go.entitychurch.org/entity-core-go/core/store"
	"go.entitychurch.org/entity-core-go/core/types"
)

// GetBatchSize is the §7.1 SHOULD sender-side batching window — initial
// value 16 chunks per system/content:get request per CONTENT v3.6 §7.4
// transport-aware batching responsibility split. Tunable per deployment.
const GetBatchSize = 16

// MaxPendingSyncRetries bounds how many times EnsureClosure retries a
// system/content:get sub-dispatch that returned 503 blob_pending_sync
// before giving up. Per CONTENT v3.6 §3.4: 503 is "retry on next sync
// event"; this counter prevents infinite loops when a peer keeps
// reporting pending on a hash that won't actually arrive. Matched
// against Rust's MAX_PENDING_SYNC_RETRIES for cross-impl symmetry.
const MaxPendingSyncRetries = 3

// EnsureClosure drives system/content:get dispatches against the given
// dispatcher until the blob at `blobHash` and every chunk it references
// are locally present in the dispatcher's content store. Returns nil on
// closure-complete; returns an error matching the partial-sync taxonomy
// (403 forbidden / 404 not_found / 503 blob_pending_sync) on failure.
//
// Per CONTENT v3.6 §7.4 receiver-side frame-budget MUST: responses may
// arrive with non-empty `missing` even when the requested hashes exist
// at the responder (the response was frame-budget-capped). EnsureClosure
// honors this by re-batching `missing` until either every hash arrives
// or a hash genuinely cannot be served (404 sync-state-visibility miss).
//
// The dispatcher is the cap surface: each system/content:get sub-call
// is independently cap-checked by the dispatcher per V7 §6.8 v7.49
// propagated-cap-not-a-gate.
func EnsureClosure(
	ctx context.Context,
	dispatcher handler.Dispatcher,
	blobHash hash.Hash,
	namespace string,
) error {
	if dispatcher == nil {
		return errors.New("EnsureClosure: nil dispatcher")
	}
	if blobHash.IsZero() {
		return errors.New("EnsureClosure: zero blob hash")
	}
	if namespace == "" {
		return errors.New("EnsureClosure: empty namespace (cap-scope target required)")
	}

	cs, err := dispatcherStore(dispatcher)
	if err != nil {
		return err
	}

	if _, ok := cs.Get(blobHash); !ok {
		if err := fetchWithPendingRetry(ctx, dispatcher, namespace, []hash.Hash{blobHash}); err != nil {
			return fmt.Errorf("EnsureClosure: fetch blob: %w", err)
		}
		if _, ok := cs.Get(blobHash); !ok {
			return statusError(404, "not_found", "blob "+blobHash.String()+" not delivered")
		}
	}

	blobEnt, _ := cs.Get(blobHash)
	if blobEnt.Type != types.TypeContentBlob {
		return fmt.Errorf("EnsureClosure: hash %s is not a blob (type %q)", blobHash, blobEnt.Type)
	}
	chunkHashes, err := blobChunkHashes(blobEnt)
	if err != nil {
		return fmt.Errorf("EnsureClosure: %w", err)
	}

	needed := missingFromStore(cs, chunkHashes)
	for len(needed) > 0 {
		if err := ctx.Err(); err != nil {
			return err
		}
		batch := needed
		if len(batch) > GetBatchSize {
			batch = batch[:GetBatchSize]
		}
		if err := fetchWithPendingRetry(ctx, dispatcher, namespace, batch); err != nil {
			return fmt.Errorf("EnsureClosure: fetch chunks: %w", err)
		}
		stillMissing := missingFromStore(cs, batch)
		if len(stillMissing) == len(batch) {
			return statusError(404, "not_found", fmt.Sprintf("chunk %s not delivered", batch[0]))
		}
		needed = missingFromStore(cs, needed)
	}
	return nil
}

// fetchWithPendingRetry wraps fetchOnce with 503 blob_pending_sync
// retry semantics. Per CONTENT v3.6 §3.4: 503 means "retry on next sync
// event"; bounded by MaxPendingSyncRetries to prevent unbounded loops
// when sync state never advances. 403 / 404 / other errors propagate
// immediately. Symmetric across blob fetch + chunk fetch paths so a
// 503 on the blob doesn't fall through as 404 (the bug Rust caught
// during their pickup).
func fetchWithPendingRetry(ctx context.Context, dispatcher handler.Dispatcher, namespace string, hashes []hash.Hash) error {
	var lastErr error
	for attempt := 0; attempt <= MaxPendingSyncRetries; attempt++ {
		if err := ctx.Err(); err != nil {
			return err
		}
		err := fetchOnce(ctx, dispatcher, namespace, hashes)
		if err == nil {
			return nil
		}
		var se *StatusError
		if errors.As(err, &se) && se.Status == 503 {
			lastErr = err
			continue
		}
		return err
	}
	return lastErr
}

// AtPeer returns a Dispatcher that aims at the given source peer. The
// returned Dispatcher rewrites any URI that omits an authority into
// entity://{sourcePeer}/{rest}, while leaving already-authority-qualified
// URIs untouched (per V7 §1.4 absolute path discipline).
//
// Use AtPeer when a handler running on peer B drives EnsureClosure
// against peer A's namespace — e.g., subscription-driven cross-peer
// materialization per workbench Stage 3 case 1.5. The namespace arg
// to EnsureClosure stays purely a cap-scope concept; peer authority
// is this Dispatcher's concern.
func AtPeer(hctx *handler.HandlerContext, sourcePeer crypto.PeerID) handler.Dispatcher {
	return atPeerDispatcher{
		inner:      handler.HandlerContextDispatcher(hctx),
		sourcePeer: sourcePeer,
	}
}

type atPeerDispatcher struct {
	inner      handler.Dispatcher
	sourcePeer crypto.PeerID
}

func (d atPeerDispatcher) Execute(ctx context.Context, req handler.ExecuteRequest) (handler.ExecuteResponse, error) {
	req.URI = qualifyURIWithPeer(req.URI, d.sourcePeer)
	return d.inner.Execute(ctx, req)
}

// Store delegates to the inner dispatcher so EnsureClosure can inspect
// the local content store when AtPeer wraps a HandlerContext-backed
// dispatcher. The store is always the local handler's store — AtPeer
// only changes where dispatch is aimed, not where fetched entities
// land.
func (d atPeerDispatcher) Store() store.ContentStore {
	if sc, ok := d.inner.(storeCarrier); ok {
		return sc.Store()
	}
	return nil
}

func qualifyURIWithPeer(uri string, peer crypto.PeerID) string {
	if strings.HasPrefix(uri, "entity://") {
		rest := strings.TrimPrefix(uri, "entity://")
		if slash := strings.IndexByte(rest, '/'); slash > 0 {
			// Already has an authority segment — pass through unchanged.
			return uri
		}
		return "entity://" + string(peer) + "/" + rest
	}
	return "entity://" + string(peer) + "/" + strings.TrimPrefix(uri, "/")
}

// dispatcherStore extracts the local content store from the dispatcher
// for read-side closure checks. EnsureClosure needs to inspect what's
// already local to decide what to fetch; this is a pre-dispatch decision
// that doesn't pass through the cap check.
//
// Both adapter types (HandlerContext + Connection) expose Store() via
// structural interface match. The dispatcher's identity is enough to
// know which content store backs it; AtPeer's wrapper delegates the
// Store() to its inner dispatcher.
func dispatcherStore(d handler.Dispatcher) (store.ContentStore, error) {
	if sc, ok := d.(storeCarrier); ok {
		return sc.Store(), nil
	}
	return nil, errors.New("EnsureClosure: dispatcher does not expose a content store; wrap with handler.HandlerContextDispatcher or peer.ConnectionDispatcher")
}

// storeCarrier is structurally matched against the adapter types. Both
// handlerCtxDispatcher and connectionDispatcher expose Store() that
// returns the local content store. AtPeer wraps either and re-exposes
// Store() through inner.
type storeCarrier interface {
	Store() store.ContentStore
}

func fetchOnce(ctx context.Context, dispatcher handler.Dispatcher, namespace string, hashes []hash.Hash) error {
	params, err := types.ContentGetRequestData{Hashes: hashes}.ToEntity()
	if err != nil {
		return fmt.Errorf("encode get request: %w", err)
	}
	resp, err := dispatcher.Execute(ctx, handler.ExecuteRequest{
		URI:       "system/content",
		Operation: "get",
		Resource:  &types.ResourceTarget{Targets: []string{namespace}},
		Params:    params,
	})
	if err != nil {
		return err
	}
	if resp.Status != 200 {
		return statusError(resp.Status, errorCodeFromResult(resp.Result), errorMessageFromResult(resp.Result))
	}
	cs, err := dispatcherStore(dispatcher)
	if err != nil {
		return err
	}
	for _, ent := range resp.Included {
		if _, perr := cs.Put(ent); perr != nil {
			return fmt.Errorf("stash included entity: %w", perr)
		}
	}
	return nil
}

func missingFromStore(cs store.ContentStore, hashes []hash.Hash) []hash.Hash {
	out := make([]hash.Hash, 0)
	for _, h := range hashes {
		if _, ok := cs.Get(h); !ok {
			out = append(out, h)
		}
	}
	return out
}

func blobChunkHashes(blobEnt entity.Entity) ([]hash.Hash, error) {
	var blob types.ContentBlobData
	if err := ecf.Decode(blobEnt.Data, &blob); err != nil {
		return nil, fmt.Errorf("decode blob: %w", err)
	}
	return blob.Chunks, nil
}

// StatusError is the error shape EnsureClosure returns on op-level
// failures so callers can branch on status without re-parsing the
// message body. Exported so cross-package callers (workbench-go,
// validate-peer) can type-assert.
type StatusError struct {
	Status  uint
	Code    string
	Message string
}

func (e *StatusError) Error() string {
	return fmt.Sprintf("status %d %s: %s", e.Status, e.Code, e.Message)
}

func statusError(status uint, code, message string) error {
	return &StatusError{Status: status, Code: code, Message: message}
}

func errorCodeFromResult(result entity.Entity) string {
	if result.Type != types.TypeError {
		return ""
	}
	errData, err := types.ErrorDataFromEntity(result)
	if err != nil {
		return ""
	}
	return errData.Code
}

func errorMessageFromResult(result entity.Entity) string {
	if result.Type != types.TypeError {
		return ""
	}
	errData, err := types.ErrorDataFromEntity(result)
	if err != nil {
		return ""
	}
	return errData.Message
}
