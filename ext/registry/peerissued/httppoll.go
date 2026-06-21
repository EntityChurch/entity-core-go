// HTTPPollReader wraps ext/httplive.Outbound so the peer-issued backend
// can read against a registry served as a static coral-reef over HTTP
// (the demo's Mode-S transport — SUBSTITUTE §7 / NETWORK §6.5.3).
//
// The backend code never sees Outbound; this file is the v1 wire-up.
// A future live-socket Reader (RemoteExecute against the registry peer)
// would be a sibling implementation; the Backend swap is one line.

package peerissued

import (
	"context"
	"errors"

	"go.entitychurch.org/entity-core-go/core/entity"
	"go.entitychurch.org/entity-core-go/core/hash"
	"go.entitychurch.org/entity-core-go/ext/httplive"
)

// HTTPPollReader adapts an httplive.Outbound to the Reader interface. The
// Outbound carries the dial profile (URLs, suffixes, content-layout) +
// any operator-provided knobs (TLS client, HTTPS-only override, timeouts).
type HTTPPollReader struct {
	outbound       *httplive.Outbound
	registryPeerID string // base58 — the {peer_id} URL segment per Amendment 5
}

// NewHTTPPollReader builds a Reader that fetches against an http-poll
// registry. `registryPeerID` is the registry's base58 peer-id (the
// segment Amendment 5 §6.5.6 demands as the first path component on
// tree URLs).
func NewHTTPPollReader(out *httplive.Outbound, registryPeerID string) *HTTPPollReader {
	return &HTTPPollReader{outbound: out, registryPeerID: registryPeerID}
}

// TreeGet fetches the system/hash bound at `path` in the registry peer's
// tree, translating httplive.ErrOutboundNotFound into Reader's ErrNotFound.
func (r *HTTPPollReader) TreeGet(ctx context.Context, path string) (hash.Hash, error) {
	h, err := r.outbound.FetchTreeLeafPointer(ctx, r.registryPeerID, path)
	if err != nil {
		if errors.Is(err, httplive.ErrOutboundNotFound) {
			return hash.Hash{}, ErrNotFound
		}
		return hash.Hash{}, err
	}
	return h, nil
}

// ContentGet fetches the entity addressed by `h`, hash-verified per
// Mechanism A.
func (r *HTTPPollReader) ContentGet(ctx context.Context, h hash.Hash) (entity.Entity, error) {
	ent, err := r.outbound.FetchContent(ctx, h)
	if err != nil {
		if errors.Is(err, httplive.ErrOutboundNotFound) {
			return entity.Entity{}, ErrNotFound
		}
		return entity.Entity{}, err
	}
	return ent, nil
}
