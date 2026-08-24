// Package node implements the SERVER half of EXTENSION-SIGNALING — the
// `system/signaling` rendezvous node (§4 operations, §5 bucket semantics): an
// opaque per-key blob store with offer / collect / advertise.
//
// ext/signaling builds the CLIENT and deliberately left the node to Rust; this
// is the Go node, so Go self-hosts the rendezvous for the cross-impl punch gate
// rather than depending on the Rust `entity-signaling-node`. A second server is
// exactly the value the spec calls for — §5's "single-implementation server
// means underspecification stays invisible; one implementation cannot disagree
// with itself." Two servers hit by three clients is a real convergence signal.
//
// The node is opaque (§6.2 carrier opacity): it "sees only the 33-byte key and
// an opaque blob; it never decodes any coordination message." So this stores raw
// message bytes keyed by the rendezvous key, deduplicates by the hash of those
// bytes (§5 pin 2), and never inspects them. Signature / peer-id / nonce checks
// are the CLIENTS' job on read (§6.3/§6.4), never the node's.
//
// This is the WRAPPED surface (§8.1): an ordinary capability-gated EXECUTE to
// `system/signaling`, so authority is enforced by the transport before Handle is
// reached and this code holds no cap logic. The §9 unwrapped raw-CBOR listener
// and the §9.3 STUN reflector are separate surfaces, not built here.
package node

import (
	"context"
	"crypto/sha256"
	"fmt"
	"sync"
	"time"

	"go.entitychurch.org/entity-core-go/core/handler"
	"go.entitychurch.org/entity-core-go/core/types"
	"go.entitychurch.org/entity-core-go/ext/signaling"
)

// §5 pin 5 / pin 6 defaults — the committed §4.5 limits. Field units are the
// wire contract: bytes, blob count, and SECONDS (not ms).
const (
	DefaultMaxBlobBytes   uint64 = 8192
	DefaultMaxBucketBlobs uint64 = 32
	DefaultTTLSeconds     uint64 = 60

	// keyLen is the fixed rendezvous-key length (§8: "exactly 33 bytes, opaque,
	// compared byte-wise. Any other length is bad_request").
	keyLen = 33
)

// entry is one deposited blob with its dedup digest and reap deadline.
type entry struct {
	blob   []byte
	digest [32]byte
	expiry time.Time
}

// Handler is the in-memory `system/signaling` node. Buckets are keyed by the raw
// 33-byte rendezvous key; entries within a bucket stay in arrival order so
// collect returns oldest-first (§5 pin 4). TTL is binding on the service (§5 pin
// 3 / pin 6): expired entries are reaped lazily on every touch of their bucket.
type Handler struct {
	mu      sync.Mutex
	buckets map[string][]entry
	now     func() time.Time // injectable for tests

	endpoint       string
	maxBlobBytes   uint64
	maxBucketBlobs uint64
	ttl            time.Duration
	lobbyConstant  []byte
	reflectionURIs []string
}

// Option configures a node Handler. Every field is a §4.5 deployment limit or
// the advertised endpoint — none touch the interoperable key/blob semantics.
type Option func(*Handler)

// WithEndpoint sets the endpoint string advertised by `advertise` (§4.5) — the
// node's own reachable address, which entity-peer supplies from its listen addr.
func WithEndpoint(endpoint string) Option { return func(h *Handler) { h.endpoint = endpoint } }

// WithLimits overrides the §4.5 bucket limits. A zero argument keeps the default
// for that field, so a caller can set one limit without restating the others.
func WithLimits(maxBlobBytes, maxBucketBlobs, ttlSeconds uint64) Option {
	return func(h *Handler) {
		if maxBlobBytes > 0 {
			h.maxBlobBytes = maxBlobBytes
		}
		if maxBucketBlobs > 0 {
			h.maxBucketBlobs = maxBucketBlobs
		}
		if ttlSeconds > 0 {
			h.ttl = time.Duration(ttlSeconds) * time.Second
		}
	}
}

// WithLobbyConstant sets the optional §4.5 `lobby` override advertised inside
// limits. Absent (the default) means the node uses signaling.LobbyDefault and
// advertises no override.
func WithLobbyConstant(b []byte) Option { return func(h *Handler) { h.lobbyConstant = b } }

// WithReflectionEndpoints sets the node's OWN §9.3 STUN listener(s), published
// in `advertise`'s top-level `reflection_endpoints` (§4.5.1, added v1.1). Supply
// these ONLY if this deployment actually serves §9.3 reflection — advertising a
// reflector it does not run is non-conformant, and the reference deployment
// co-locates the reflector on the signaling VM (§4.5.1). Each entry MUST be an
// RFC 7064 `stun:`/`stuns:` URI in the pinned non-hierarchical form; callers
// should validate with signaling.ValidateReflectionEndpoint before passing them
// (the node emits verbatim — the wire form is the operator's contract, §4.5.1).
// Absent (the default) advertises no reflection, the already-legal state a
// pre-v1.1 node was in. Never another node's endpoints.
func WithReflectionEndpoints(uris ...string) Option {
	return func(h *Handler) {
		if len(uris) == 0 {
			h.reflectionURIs = nil
			return
		}
		h.reflectionURIs = append([]string(nil), uris...)
	}
}

// WithClock injects the time source (tests drive TTL without sleeping).
func WithClock(fn func() time.Time) Option { return func(h *Handler) { h.now = fn } }

// New builds a node Handler with the §4.5 defaults, overridden by opts.
func New(opts ...Option) *Handler {
	h := &Handler{
		buckets:        make(map[string][]entry),
		now:            time.Now,
		maxBlobBytes:   DefaultMaxBlobBytes,
		maxBucketBlobs: DefaultMaxBucketBlobs,
		ttl:            time.Duration(DefaultTTLSeconds) * time.Second,
	}
	for _, o := range opts {
		o(h)
	}
	return h
}

// Name identifies the handler in debug surfaces.
func (h *Handler) Name() string { return "signaling-node" }

// Handle dispatches the three §5.1 operations. An unknown op is bad_request, per
// the closed error enum (§8).
func (h *Handler) Handle(_ context.Context, req *handler.Request) (*handler.Response, error) {
	switch req.Operation {
	case signaling.OpOffer:
		return h.offer(req)
	case signaling.OpCollect:
		return h.collect(req)
	case signaling.OpAdvertise:
		return h.advertise()
	default:
		return badRequest("unknown op: " + req.Operation)
	}
}

// offer appends a blob at a key (§4.1, §5 pin 2). Idempotent by content hash — a
// re-offer of the same bytes is a no-op success, so a client's retry after a
// timeout never accumulates (§5 pin 1). Refuses (never truncates/evicts) on the
// §4.5 limits.
func (h *Handler) offer(req *handler.Request) (*handler.Response, error) {
	d, err := types.OfferRequestDataFromEntity(req.Params)
	if err != nil {
		return badRequest("malformed offer-request: " + err.Error())
	}
	if len(d.RendezvousKey) != keyLen {
		return badRequest(fmt.Sprintf("rendezvous_key is %d bytes, want %d", len(d.RendezvousKey), keyLen))
	}
	if uint64(len(d.Message)) > h.maxBlobBytes {
		// §8 message_too_large — refused, never truncated.
		return errResponse(413, "message_too_large",
			fmt.Sprintf("blob is %d bytes, node max_blob_bytes is %d", len(d.Message), h.maxBlobBytes))
	}

	h.mu.Lock()
	defer h.mu.Unlock()
	key := string(d.RendezvousKey)
	bucket := h.liveBucketLocked(key)
	digest := sha256.Sum256(d.Message)
	for i := range bucket {
		if bucket[i].digest == digest {
			// Duplicate: idempotent success, bucket unchanged (§5 pin 1).
			h.buckets[key] = bucket
			return offerOK()
		}
	}
	if uint64(len(bucket)) >= h.maxBucketBlobs {
		// §8 bucket_full — refused, never evicted. Restore the reaped view first.
		h.buckets[key] = bucket
		return errResponse(429, "bucket_full",
			fmt.Sprintf("bucket at max_bucket_blobs (%d)", h.maxBucketBlobs))
	}
	bucket = append(bucket, entry{
		blob:   append([]byte(nil), d.Message...),
		digest: digest,
		expiry: h.now().Add(h.ttl),
	})
	h.buckets[key] = bucket
	return offerOK()
}

// collect returns a key's live blobs, oldest-first (§4.1, §5 pin 4). An unknown
// or empty key is an empty list and success, never a 404 (§4.4, §5 pin 1).
func (h *Handler) collect(req *handler.Request) (*handler.Response, error) {
	d, err := types.CollectRequestDataFromEntity(req.Params)
	if err != nil {
		return badRequest("malformed collect-request: " + err.Error())
	}
	if len(d.RendezvousKey) != keyLen {
		return badRequest(fmt.Sprintf("rendezvous_key is %d bytes, want %d", len(d.RendezvousKey), keyLen))
	}

	h.mu.Lock()
	bucket := h.liveBucketLocked(string(d.RendezvousKey))
	h.buckets[string(d.RendezvousKey)] = bucket
	messages := make([][]byte, len(bucket))
	for i := range bucket {
		messages[i] = bucket[i].blob
	}
	h.mu.Unlock()

	return handler.NewResponse(200, types.TypeSignalingCollectResult,
		types.CollectResultData{Messages: messages})
}

// advertise returns the node's endpoint and §4.5 limits so clients read limits
// rather than assuming them (§4.5, §5 pin 5/6).
func (h *Handler) advertise() (*handler.Response, error) {
	h.mu.Lock()
	limits := types.SignalingLimitsData{
		MaxBlobBytes:   h.maxBlobBytes,
		MaxBucketBlobs: h.maxBucketBlobs,
		TTLSeconds:     uint64(h.ttl / time.Second),
		LobbyConstant:  h.lobbyConstant,
	}
	endpoint := h.endpoint
	// §4.5.1: emit the node's own reflection listeners as a top-level field.
	// nil stays nil so omitempty omits it — absent ⇒ no reflection, the pre-v1.1
	// state. Copy so a caller mutating the returned slice cannot reach into the
	// handler's config under the lock's protection.
	var reflection []string
	if len(h.reflectionURIs) > 0 {
		reflection = append([]string(nil), h.reflectionURIs...)
	}
	h.mu.Unlock()

	return handler.NewResponse(200, types.TypeSignalingAdvertiseResult,
		types.AdvertiseResultData{
			Endpoint:            endpoint,
			Limits:              limits,
			ReflectionEndpoints: reflection,
		})
}

// liveBucketLocked returns key's bucket with expired entries dropped (TTL binding
// on the service, §5 pin 3). Caller holds h.mu and is responsible for storing the
// returned slice back (so the reap persists). Returns a slice that may alias the
// stored backing array up to the surviving length.
func (h *Handler) liveBucketLocked(key string) []entry {
	bucket := h.buckets[key]
	if len(bucket) == 0 {
		return bucket
	}
	now := h.now()
	live := bucket[:0]
	for _, e := range bucket {
		if e.expiry.After(now) {
			live = append(live, e)
		}
	}
	return live
}

func offerOK() (*handler.Response, error) {
	return handler.NewResponse(200, types.TypeSignalingOfferResult, types.OfferResultData{Ok: true})
}

// badRequest renders the §8 `bad_request` code on the wrapped surface. Status 400
// so the client's status check surfaces it (the wrapped surface conveys the
// closed-enum error as an ErrorData entity; the raw §9 listener uses {ok:false}).
func badRequest(msg string) (*handler.Response, error) {
	return errResponse(400, "bad_request", msg)
}

func errResponse(status uint, code, msg string) (*handler.Response, error) {
	return handler.NewErrorResponse(status, code, msg)
}
