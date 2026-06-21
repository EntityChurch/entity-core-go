// Package storagesubstitutehttp implements the system/substitute/http
// convention handler per EXTENSION-SUBSTITUTE v1.0 §7 (the HTTP convention,
// consolidated into the landed spec; was the standalone
// PROPOSAL-EXTENSION-STORAGE-SUBSTITUTE-HTTP before promotion). It
// registers at handler pattern `system/substitute/http` with op `try`.
// On invocation:
//
//  1. Decode the system/substitute/try-request entity (entry, hash).
//  2. Read the source entity's endpoint block (a TransportEndpoint).
//  3. Build the content URL via types.BuildContentURL.
//  4. Reject http:// by default (HTTPS-scheme defense-in-depth; matches
//     core-rust and core-py).
//  5. Perform an inline HTTP GET, bound by a timeout + max-size limit.
//  6. Decode the body as entity.Entity, recompute hash(Type, Data), and
//     verify it matches the requested hash (the load-bearing Mechanism A
//     trust check — §1).
//  7. Return the raw entity directly (Ruling 3 — no wrapper).
//
// Manifest processing (§3-RES.1/.4) is OUT OF SCOPE for v1.0 per Ruling 5
// — every impl ships bare-hash only; manifests land in lock-step v1.1.
//
// NOT BRIDGE-HTTP. This is Mechanism A — bytes-on-wire ARE entity-encoded
// bytes; the content hash is the trust anchor. See
// `GUIDE-EXTENSION-DEVELOPMENT.md §3.7`.
package storagesubstitutehttp

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"reflect"
	"strings"
	"sync"
	"time"

	"go.entitychurch.org/entity-core-go/core/ecf"
	"go.entitychurch.org/entity-core-go/core/entity"
	"go.entitychurch.org/entity-core-go/core/handler"
	"go.entitychurch.org/entity-core-go/core/hash"
	"go.entitychurch.org/entity-core-go/core/types"

	"github.com/fxamacker/cbor/v2"
)

// HandlerPattern is the registration pattern.
const HandlerPattern = "system/substitute/http"

// Default knobs. Operators MAY override via NewHandler options.
const (
	DefaultFetchTimeout = 30 * time.Second
	// DefaultMaxResponseBytes caps the response body size to bound memory
	// the handler is willing to spend on an unverified fetch. The content
	// is then hash-verified anyway, but limiting before the hash compute
	// prevents an attacker from DoS'ing the consumer with a huge body.
	// 64 MiB is comfortably above CONTENT v3.6 §3.5's 8 MiB MaxChunkSize.
	DefaultMaxResponseBytes int64 = 64 * 1024 * 1024
)

// Option is a functional-options knob for NewHandler.
type Option func(*Handler)

// WithHTTPClient overrides the http.Client used for outbound fetches.
// Useful for tests (httptest.NewServer + httptest.NewServer.Client()) and
// for deployments wanting custom transport / proxy / TLS config.
func WithHTTPClient(c *http.Client) Option {
	return func(h *Handler) { h.client = c }
}

// WithAllowHTTP disables the HTTPS-only default. Off by default — only
// flip on for local-loopback testing (httptest spawns an http:// server)
// or trusted-network deployments. Matches core-rust + core-py defaults.
func WithAllowHTTP(allow bool) Option {
	return func(h *Handler) { h.allowHTTP = allow }
}

// WithFetchTimeout overrides DefaultFetchTimeout.
func WithFetchTimeout(d time.Duration) Option {
	return func(h *Handler) { h.fetchTimeout = d }
}

// WithMaxResponseBytes overrides DefaultMaxResponseBytes.
func WithMaxResponseBytes(n int64) Option {
	return func(h *Handler) { h.maxResponseBytes = n }
}

// Handler implements the system/substitute/http:try convention handler.
type Handler struct {
	mu               sync.Mutex
	client           *http.Client
	allowHTTP        bool
	fetchTimeout     time.Duration
	maxResponseBytes int64
}

// NewHandler constructs a configured handler. Defaults: stdlib
// http.DefaultClient, HTTPS-only, 30s fetch timeout, 64 MiB cap.
func NewHandler(opts ...Option) *Handler {
	h := &Handler{
		client:           http.DefaultClient,
		allowHTTP:        false,
		fetchTimeout:     DefaultFetchTimeout,
		maxResponseBytes: DefaultMaxResponseBytes,
	}
	for _, opt := range opts {
		opt(h)
	}
	return h
}

// Name implements handler.Handler.
func (h *Handler) Name() string { return "storage-substitute-http" }

// Manifest declares the handler's published surface.
//
// InternalScope.Operations name the outbound HTTP fetch cap so the
// dispatcher's authority-check passes when the handler invokes its own
// fetch path. We name a Mechanism-A-specific cap (storage-substitute-
// http-fetch) — the two-mechanism disambiguation in EXTENSION-SUBSTITUTE
// v1.0's preamble + §7 plus GUIDE-EXTENSION-DEVELOPMENT §3.7 keeps the
// BRIDGE-HTTP namespace cleanly separate (BRIDGE-HTTP is Mechanism B —
// foreign content wrapped as `system/bridge/http/fetched`).
func (h *Handler) Manifest() types.HandlerManifestData {
	return types.HandlerManifestData{
		Pattern: HandlerPattern,
		Name:    "storage-substitute-http",
		Operations: map[string]types.HandlerOperationSpec{
			types.OpSubstituteTry: {
				InputType: types.TypeSubstituteTryRequest,
				// Raw entity return per Ruling 3 — no result-wrapper type;
				// output type is empty (the response carries whatever
				// entity-type the publisher served).
				OutputType: "",
			},
		},
		InternalScope: []types.GrantEntry{
			{
				Handlers:   types.CapabilityScope{Include: []string{HandlerPattern}},
				Resources:  types.CapabilityScope{Include: []string{HandlerPattern + "/*"}},
				Operations: types.CapabilityScope{Include: []string{types.OpSubstituteTry}},
			},
		},
	}
}

// RegisterTypes is a no-op — the substitute substrate types are
// registered centrally in core/types.RegisterCoreTypes (they're shared
// with ext/storagesubstitutesources and core-rust + core-py read the
// same wire shapes).
func (h *Handler) RegisterTypes(r *types.TypeRegistry) {
	// No-op: types live in core/types/substitute.go + content.go +
	// transport_url.go and register in RegisterCoreTypes.
	_ = reflect.TypeOf // keep the import shape if added later
}

// Handle dispatches the supported operations.
func (h *Handler) Handle(ctx context.Context, req *handler.Request) (*handler.Response, error) {
	switch req.Operation {
	case types.OpSubstituteTry:
		return h.handleTry(ctx, req)
	default:
		return handler.NewErrorResponse(400, "unknown_operation",
			HandlerPattern+" handler does not support operation: "+req.Operation)
	}
}

// handleTry implements the convention handler op per Ruling 2 + Ruling 3.
func (h *Handler) handleTry(ctx context.Context, req *handler.Request) (*handler.Response, error) {
	// 1. Decode the try-request entity.
	var trReq types.SubstituteTryRequestData
	if err := ecf.Decode(req.Params.Data, &trReq); err != nil {
		return handler.NewErrorResponse(400, "invalid_request",
			"could not decode system/substitute/try-request: "+err.Error())
	}

	// 2. Validate entry type + decode as substitute source.
	if trReq.Entry.Type != types.TypeSubstituteSource {
		return handler.NewErrorResponse(400, "invalid_entry",
			"try-request.entry must be "+types.TypeSubstituteSource+
				", got "+trReq.Entry.Type)
	}
	src, err := types.SubstituteSourceDataFromEntity(trReq.Entry)
	if err != nil {
		return handler.NewErrorResponse(400, "invalid_entry",
			"could not decode source entity: "+err.Error())
	}

	// 3. Confirm substitute_type matches this handler's convention.
	if src.SubstituteType != types.SubstituteTypeHTTP {
		return handler.NewErrorResponse(400, "wrong_substitute_type",
			"this handler serves substitute_type=\""+types.SubstituteTypeHTTP+
				"\"; got \""+src.SubstituteType+"\"")
	}

	// 4. Extract endpoint.
	ep, ok, err := src.HTTPEndpoint()
	if err != nil {
		return handler.NewErrorResponse(400, "invalid_endpoint",
			"could not decode endpoint: "+err.Error())
	}
	if !ok {
		// Legacy fetch_template entries are out of scope for v1; the spec
		// pins the structured endpoint as the primary path.
		return handler.NewErrorResponse(400, "no_endpoint",
			"substitute entry has no endpoint block (legacy fetch_template "+
				"not supported in v1.0)")
	}

	// 5. Build URL. Honor the §6.4 default-resolution rule (D-14):
	// when content_url_prefix is absent, derive {tree_url_prefix}/content.
	contentPrefix := types.EffectiveContentURLPrefix(ep)
	if contentPrefix == "" {
		return handler.NewErrorResponse(400, "no_content_prefix",
			"endpoint has neither content_url_prefix nor tree_url_prefix")
	}
	url, err := types.BuildContentURL(contentPrefix, ep.ContentLayout, trReq.Hash)
	if err != nil {
		return handler.NewErrorResponse(400, "url_build_failed", err.Error())
	}

	// 6. HTTPS-only default (matches core-rust + core-py).
	if !strings.HasPrefix(url, "https://") && !h.allowHTTP {
		return handler.NewErrorResponse(403, "https_required",
			"http:// URLs require explicit WithAllowHTTP(true); only "+
				"https:// is accepted by default")
	}

	// 7. Outbound fetch.
	body, err := h.fetch(ctx, url)
	if err != nil {
		if errors.Is(err, errNotFound) {
			return handler.NewErrorResponse(404, "not_found",
				"upstream returned 404 for "+url)
		}
		return handler.NewErrorResponse(502, "bad_gateway", err.Error())
	}

	// 8. Decode wire bytes as entity + recompute hash + verify.
	ent, err := decodeAndVerify(body, trReq.Hash)
	if err != nil {
		return handler.NewErrorResponse(502, "hash_mismatch", err.Error())
	}

	// 9. Return the raw entity (Ruling 3 — no try-result wrapper). The
	// chain orchestrator already holds the hash and re-verifies post-call.
	return &handler.Response{Status: 200, Result: ent}, nil
}

// errNotFound is the sentinel for upstream 404s; the handler maps it to
// the storage-substitute layer's `not_found` so the chain orchestrator
// advances to the next entry rather than treating it as a hard error.
var errNotFound = errors.New("upstream_not_found")

// fetch performs the inline HTTP GET bounded by the configured timeout
// and max-size cap. Returns errNotFound for 404; wraps everything else.
func (h *Handler) fetch(ctx context.Context, url string) ([]byte, error) {
	fetchCtx, cancel := context.WithTimeout(ctx, h.fetchTimeout)
	defer cancel()

	httpReq, err := http.NewRequestWithContext(fetchCtx, http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("build request: %w", err)
	}

	resp, err := h.client.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("http get: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		return nil, errNotFound
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected status: %d", resp.StatusCode)
	}

	limited := io.LimitReader(resp.Body, h.maxResponseBytes+1)
	body, err := io.ReadAll(limited)
	if err != nil {
		return nil, fmt.Errorf("read body: %w", err)
	}
	if int64(len(body)) > h.maxResponseBytes {
		return nil, fmt.Errorf("response exceeds max %d bytes", h.maxResponseBytes)
	}
	return body, nil
}

// decodeAndVerify decodes the wire bytes as an entity.Entity and verifies
// its computed content hash matches the requested target hash. This is
// the load-bearing Mechanism A trust check: hash-match means the bytes
// are trustworthy regardless of where they came from.
func decodeAndVerify(body []byte, target hash.Hash) (entity.Entity, error) {
	var ent entity.Entity
	if err := cbor.Unmarshal(body, &ent); err != nil {
		return entity.Entity{}, fmt.Errorf("decode entity wire: %w", err)
	}
	if ent.Type == "" {
		return entity.Entity{}, fmt.Errorf("entity has empty type")
	}
	if len(ent.Data) == 0 {
		return entity.Entity{}, fmt.Errorf("entity has empty data")
	}

	// Recompute under the target's Algorithm — the requested format is
	// intrinsic to the target hash (v7.67 §2.3 format-code interpretation).
	computed, err := hash.ComputeFormat(target.Algorithm, ent.Type, ent.Data)
	if err != nil {
		return entity.Entity{}, fmt.Errorf("compute hash: %w", err)
	}
	if computed != target {
		return entity.Entity{}, fmt.Errorf(
			"wire content does not hash to requested target: computed=%s target=%s",
			computed, target)
	}
	// Also self-consistency: the wire-declared content_hash, when present,
	// should agree with the recomputed value. This catches malformed
	// publishers that wrote a different value than what their bytes hash
	// to.
	if !ent.ContentHash.IsZero() && ent.ContentHash != computed {
		return entity.Entity{}, fmt.Errorf(
			"wire content_hash field disagrees with computed: wire=%s computed=%s",
			ent.ContentHash, computed)
	}
	return ent, nil
}
