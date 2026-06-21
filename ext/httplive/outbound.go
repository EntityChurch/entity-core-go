// Outbound is the http-poll dialer half — the consumer counterpart to
// PollHandler. Given an http-poll TransportEndpoint (advertised on a
// system/peer/transport/http-poll profile), it lets a caller fetch the
// publisher's signed system/peer/published-root, verify it against the
// publisher's identity, then hash-verify any content fetched by hash.
//
// Trust model (per PROPOSAL-PEER-MANIFEST-STATIC-HANDSHAKE §1 + §4):
//   - The manifest URL is operated by a host the consumer does NOT trust
//     for content integrity (CDN, mirror, attacker on path).
//   - HOST BYTES are trusted only after a hash check. The published-root
//     signature is verified against the publisher's identity key; every
//     content fetch is hash-verified against the requested target.
//   - Path bindings retrieved via tree-leaf URLs (the pointer surface) are
//     HOST-CLAIMED — they MAY be fabricated; verified-tree-walk has to
//     hash-chain from the signed root. This package returns the host's
//     pointer answer but does NOT promote it to trusted state on its own.
//
// Mechanism A (entity-encoded bytes on wire) per
// GUIDE-EXTENSION-DEVELOPMENT §3.7. NOT BRIDGE-HTTP.

package httplive

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"

	"go.entitychurch.org/entity-core-go/core/crypto"
	"go.entitychurch.org/entity-core-go/core/entity"
	"go.entitychurch.org/entity-core-go/core/hash"
	"go.entitychurch.org/entity-core-go/core/types"

	"github.com/fxamacker/cbor/v2"
)

// OutboundOption tunes the connector.
type OutboundOption func(*Outbound)

// WithOutboundHTTPClient overrides the http.Client used for fetches.
// Useful for tests (httptest.NewServer.Client()) and operator-supplied
// transports with bespoke TLS / proxy / timeout configuration.
func WithOutboundHTTPClient(c *http.Client) OutboundOption {
	return func(o *Outbound) { o.client = c }
}

// WithOutboundAllowHTTP disables the HTTPS-only default. Off by default
// (mirrors storagesubstitutehttp). Flip on for localhost / httptest.
func WithOutboundAllowHTTP(allow bool) OutboundOption {
	return func(o *Outbound) { o.allowHTTP = allow }
}

// WithOutboundFetchTimeout caps wall-clock per-request fetch time.
// Defaults to DefaultOutboundFetchTimeout.
func WithOutboundFetchTimeout(d time.Duration) OutboundOption {
	return func(o *Outbound) { o.fetchTimeout = d }
}

// WithOutboundMaxResponseBytes caps the body size of any fetch. Defaults
// to DefaultOutboundMaxResponseBytes; the cap is enforced BEFORE hash
// computation to bound memory the consumer spends on unverified bytes.
func WithOutboundMaxResponseBytes(n int64) OutboundOption {
	return func(o *Outbound) { o.maxResponseBytes = n }
}

// WithPinnedIdentity binds the connector to a specific publisher identity
// (the content_hash of the publisher's system/peer entity, per V7 §1.5).
// Manifest signatures MUST verify under this identity's public key.
//
// `peerEntity` is the bytes-form system/peer entity — needed to recover
// the public key (the published-root signature is verified directly with
// the publisher's pubkey, since pubkey IS identity).
//
// Without a pin, FetchPublishedRoot returns the entity but does NOT
// signature-verify; the caller is responsible for trust establishment
// (e.g., a §7.4 ESR-style binding with a pinned identity). This is the
// out-of-band trust anchor the §1.2 / §2 trust model assumes.
func WithPinnedIdentity(peerEntity entity.Entity) OutboundOption {
	return func(o *Outbound) {
		o.pinnedIdentity = &peerEntity
	}
}

// Default knobs.
const (
	DefaultOutboundFetchTimeout         = 30 * time.Second
	DefaultOutboundMaxResponseBytes int64 = 64 * 1024 * 1024 // 64 MiB
)

// Outbound is a configured http-poll consumer for one publisher profile.
type Outbound struct {
	profile  types.HTTPPollProfileData
	endpoint types.TransportEndpoint

	mu             sync.Mutex
	client         *http.Client
	allowHTTP      bool
	fetchTimeout   time.Duration
	maxResponseBytes int64
	pinnedIdentity *entity.Entity

	// lastSeq tracks the highest published-root.seq seen for this profile.
	// The connector rejects any later FetchPublishedRoot whose seq is less
	// than this — per snapshot-manifest §3-RES.4 rollback discipline.
	lastSeq uint64
}

// NewOutbound builds a connector for the given http-poll profile. The
// profile's Endpoint block carries the URLs the consumer dials.
func NewOutbound(profile types.HTTPPollProfileData, opts ...OutboundOption) *Outbound {
	o := &Outbound{
		profile:          profile,
		endpoint:         profile.Endpoint,
		client:           &http.Client{Timeout: DefaultOutboundFetchTimeout},
		allowHTTP:        false,
		fetchTimeout:     DefaultOutboundFetchTimeout,
		maxResponseBytes: DefaultOutboundMaxResponseBytes,
	}
	for _, opt := range opts {
		opt(o)
	}
	return o
}

// PublishedRoot is a verification-bound view of a fetched published-root.
// Entity is the raw wire entity; Data is the decoded payload; Verified is
// true iff the connector had a pinned identity AND the signature checked
// out against it (otherwise the caller has only host-claimed bytes).
type PublishedRoot struct {
	Entity   entity.Entity
	Data     types.PublishedRootData
	Verified bool
}

// FetchPublishedRoot performs MANIFEST_GET, decodes the body as a
// system/peer/published-root entity, enforces seq monotonicity against
// prior fetches under this connector, and (when pinned) verifies the
// signature against the publisher's identity.
//
// The signature path is the V7 §5.2 / §975 invariant pointer
// `{tree_url_prefix}/{signer_peer_id_hex}/system/signature/{published_root_hash_hex}.bin`
// fetched as a tree-leaf pointer, then content-fetched.
func (o *Outbound) FetchPublishedRoot(ctx context.Context) (PublishedRoot, error) {
	manifestURL, err := o.manifestURL()
	if err != nil {
		return PublishedRoot{}, err
	}

	body, err := o.fetch(ctx, manifestURL)
	if err != nil {
		return PublishedRoot{}, fmt.Errorf("manifest fetch %s: %w", manifestURL, err)
	}

	var ent entity.Entity
	if err := cbor.Unmarshal(body, &ent); err != nil {
		return PublishedRoot{}, fmt.Errorf("decode manifest entity: %w", err)
	}
	if ent.Type != types.TypePeerPublishedRoot {
		return PublishedRoot{}, fmt.Errorf(
			"manifest entity type %q is not %s", ent.Type, types.TypePeerPublishedRoot)
	}
	// Recompute the content hash to catch publisher / transit corruption
	// (mirrors storagesubstitutehttp.decodeAndVerify discipline). We use
	// the entity's claimed Algorithm — published-roots are authored under
	// the publisher's process-global content_hash_format (v7.67 §2.3).
	alg := ent.ContentHash.Algorithm
	if ent.ContentHash.IsZero() {
		alg = hash.AlgorithmSHA256
	}
	computed, err := hash.ComputeFormat(alg, ent.Type, ent.Data)
	if err != nil {
		return PublishedRoot{}, fmt.Errorf("recompute manifest hash: %w", err)
	}
	if !ent.ContentHash.IsZero() && ent.ContentHash != computed {
		return PublishedRoot{}, fmt.Errorf(
			"manifest content_hash disagrees with wire bytes: wire=%s computed=%s",
			ent.ContentHash, computed)
	}
	ent.ContentHash = computed

	data, err := types.PublishedRootDataFromEntity(ent)
	if err != nil {
		return PublishedRoot{}, fmt.Errorf("decode published-root: %w", err)
	}

	// Seq monotonicity gate per §4 + snapshot-manifest §3-RES.4.
	o.mu.Lock()
	if data.Seq < o.lastSeq {
		prev := o.lastSeq
		o.mu.Unlock()
		return PublishedRoot{}, fmt.Errorf(
			"manifest seq %d < cached %d (rollback rejected per §3-RES.4)",
			data.Seq, prev)
	}
	o.lastSeq = data.Seq
	pinned := o.pinnedIdentity
	o.mu.Unlock()

	pr := PublishedRoot{Entity: ent, Data: data, Verified: false}

	if pinned != nil {
		// Ruling-1 (cross-impl-run absorption): published-root.peer_id
		// is the Base58 peer-id per V7 §1.5. Derive the pinned identity's
		// Base58 from its public_key and compare strings.
		pinnedData, err := types.PeerDataFromEntity(*pinned)
		if err != nil {
			return pr, fmt.Errorf("decode pinned identity: %w", err)
		}
		pinnedKeyType, ok := crypto.KeyTypeByte(pinnedData.KeyType)
		if !ok {
			return pr, fmt.Errorf("pinned identity unsupported key_type %q", pinnedData.KeyType)
		}
		pinnedPeerID, err := crypto.PeerIDFromPublicKey(pinnedData.PublicKey, pinnedKeyType)
		if err != nil {
			return pr, fmt.Errorf("derive pinned peer-id: %w", err)
		}
		if string(pinnedPeerID) != data.PeerID {
			return pr, fmt.Errorf(
				"published-root.peer_id %s does not match pinned peer-id %s",
				data.PeerID, pinnedPeerID)
		}
		if err := o.verifySignature(ctx, ent, *pinned); err != nil {
			return pr, fmt.Errorf("verify manifest signature: %w", err)
		}
		pr.Verified = true
	}
	return pr, nil
}

// FetchContent GETs the content bytes for hash h and verifies the response
// hashes to h under h's Algorithm. The trust check is identical to
// storagesubstitutehttp.decodeAndVerify (Mechanism A).
func (o *Outbound) FetchContent(ctx context.Context, h hash.Hash) (entity.Entity, error) {
	url, err := o.contentURL(h)
	if err != nil {
		return entity.Entity{}, err
	}
	body, err := o.fetch(ctx, url)
	if err != nil {
		return entity.Entity{}, fmt.Errorf("content fetch %s: %w", url, err)
	}
	return decodeAndVerifyContent(body, h)
}

// FetchTreeLeafPointer GETs a tree-leaf URL and returns the hash the host
// claims is bound at treePath under signerPeerIDHex (the {peer_id} URL
// segment). The response shape is a 2-key bare pointer
// `ECF({type: "system/hash", data: <33-byte-hash>})` per Amendment 6 §8.
//
// **The returned hash is HOST-CLAIMED, not yet trusted.** A consumer that
// requires the binding to be authentic for this publisher MUST hash-chain
// the path from the signed published-root before treating the pointer as
// authoritative. This method intentionally separates "what the host said"
// from "what the publisher signed."
func (o *Outbound) FetchTreeLeafPointer(ctx context.Context, signerPeerIDHex, treePath string) (hash.Hash, error) {
	url := o.treeLeafURL(signerPeerIDHex, treePath)
	body, err := o.fetch(ctx, url)
	if err != nil {
		return hash.Hash{}, fmt.Errorf("tree leaf fetch %s: %w", url, err)
	}
	return decodeTreeLeafPointer(body)
}

// verifySignature resolves the signature for `signed` via the V7 §5.2
// invariant-pointer path and verifies it against `signer`'s public key.
//
// The tree-leaf URL is keyed by the signer's BASE58 peer-id (the form
// PollHandler accepts on the first URL segment; the form the publisher's
// NamespacedIndex used to prepend `LocalSignaturePath` writes). The
// profile.PeerID field carries this string per EXTENSION-NETWORK §6.5
// errata F1.
func (o *Outbound) verifySignature(ctx context.Context, signed entity.Entity, signer entity.Entity) error {
	signerData, err := types.PeerDataFromEntity(signer)
	if err != nil {
		return fmt.Errorf("decode pinned identity: %w", err)
	}
	keyType, ok := crypto.KeyTypeByte(signerData.KeyType)
	if !ok {
		return fmt.Errorf("unsupported signer key_type %q", signerData.KeyType)
	}
	signerPeerID, err := crypto.PeerIDFromPublicKey(signerData.PublicKey, keyType)
	if err != nil {
		return fmt.Errorf("derive signer peer-id: %w", err)
	}
	sigPath := "system/signature/" + hex.EncodeToString(signed.ContentHash.Bytes())

	sigPointer, err := o.FetchTreeLeafPointer(ctx, string(signerPeerID), sigPath)
	if err != nil {
		return fmt.Errorf("fetch signature pointer at %s: %w", sigPath, err)
	}
	sigEnt, err := o.FetchContent(ctx, sigPointer)
	if err != nil {
		return fmt.Errorf("fetch signature entity: %w", err)
	}
	if sigEnt.Type != types.TypeSignature {
		return fmt.Errorf("signature entity has wrong type %q", sigEnt.Type)
	}
	sd, err := types.SignatureDataFromEntity(sigEnt)
	if err != nil {
		return fmt.Errorf("decode signature: %w", err)
	}
	if sd.Target != signed.ContentHash {
		return fmt.Errorf("signature target %s ≠ signed entity hash %s", sd.Target, signed.ContentHash)
	}
	if sd.Signer != signer.ContentHash {
		return fmt.Errorf("signature signer %s ≠ pinned identity hash %s", sd.Signer, signer.ContentHash)
	}
	if !crypto.Verify(keyType, signerData.PublicKey, signed.ContentHash.Bytes(), sd.Signature) {
		return fmt.Errorf("signature does not verify under pinned identity's public key")
	}
	return nil
}

// manifestURL resolves the URL the connector dials for MANIFEST_GET.
// Preference: profile.Endpoint.ManifestURLPrefix when set; otherwise
// `{TreeURLPrefix}/manifest` (the same path PollHandler serves under).
func (o *Outbound) manifestURL() (string, error) {
	if o.endpoint.ManifestURLPrefix != "" {
		return o.endpoint.ManifestURLPrefix, nil
	}
	if o.endpoint.TreeURLPrefix == "" {
		return "", fmt.Errorf("manifest URL: profile has neither manifest_url_prefix nor tree_url_prefix")
	}
	return strings.TrimRight(o.endpoint.TreeURLPrefix, "/") + "/manifest", nil
}

func (o *Outbound) contentURL(h hash.Hash) (string, error) {
	prefix := types.EffectiveContentURLPrefix(o.endpoint)
	if prefix == "" {
		return "", fmt.Errorf("content URL: profile has no content_url_prefix or tree_url_prefix")
	}
	// Go's serveContent (poll.go) gates by hex(H.Bytes()) — 66 chars including
	// the 1-byte algorithm prefix. types.BuildContentURL renders the 32-byte
	// digest only (per the spec's §10.1 examples convention). To dial Go's
	// own poll surface, we use the 33-byte form here; the cohort-wide content
	// URL shape is being reconciled separately (snapshot-manifest §3-RES.2
	// vs Amendment 5's hash-shape pin). Once that lands, this can collapse
	// back into types.BuildContentURL.
	prefix = strings.TrimRight(prefix, "/")
	hexHash := hex.EncodeToString(h.Bytes())
	switch o.endpoint.ContentLayout {
	case "", types.ContentLayoutFlat:
		return prefix + "/" + hexHash, nil
	case types.ContentLayoutSharded2Flat:
		return prefix + "/" + hexHash[0:2] + "/" + hexHash, nil
	case types.ContentLayoutSharded24, types.ContentLayoutSharded22:
		return prefix + "/" + hexHash[0:2] + "/" + hexHash[2:4] + "/" + hexHash, nil
	default:
		return "", fmt.Errorf("unknown content_layout %q", o.endpoint.ContentLayout)
	}
}

func (o *Outbound) treeLeafURL(signerPeerIDHex, treePath string) string {
	prefix := strings.TrimRight(o.endpoint.TreeURLPrefix, "/")
	// `{tree_url_prefix}/{peer_id}/{path}{leaf_suffix}` per
	// EXTENSION-NETWORK §6.5.3.1 Amendment 5. PollHandler reads peer_id as
	// the base58 form, but invariant-pointer signatures live under the
	// signer's identity-hash hex (V7 §5.2). The published-root publisher
	// (ext/publishedroot) binds them as such; consumer mirrors.
	suffix := o.endpoint.EffectiveTreeLeafSuffix()
	return prefix + "/" + signerPeerIDHex + "/" + strings.TrimLeft(treePath, "/") + suffix
}

// fetch performs the inline HTTP GET bounded by timeout + max-size. Mirrors
// storagesubstitutehttp.fetch so the trust + DoS posture is identical.
func (o *Outbound) fetch(ctx context.Context, url string) ([]byte, error) {
	if !strings.HasPrefix(url, "https://") && !o.allowHTTP {
		return nil, fmt.Errorf("http:// URL requires WithOutboundAllowHTTP(true): %s", url)
	}
	fetchCtx, cancel := context.WithTimeout(ctx, o.fetchTimeout)
	defer cancel()

	req, err := http.NewRequestWithContext(fetchCtx, http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("build request: %w", err)
	}
	resp, err := o.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("http get: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		return nil, ErrOutboundNotFound
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected status %d", resp.StatusCode)
	}

	limited := io.LimitReader(resp.Body, o.maxResponseBytes+1)
	body, err := io.ReadAll(limited)
	if err != nil {
		return nil, fmt.Errorf("read body: %w", err)
	}
	if int64(len(body)) > o.maxResponseBytes {
		return nil, fmt.Errorf("response exceeds max %d bytes", o.maxResponseBytes)
	}
	return body, nil
}

// ErrOutboundNotFound is the sentinel for upstream 404s. Callers may want
// to treat this differently from a true error (e.g., "tree binding does
// not exist" vs "the network broke").
var ErrOutboundNotFound = errors.New("outbound: upstream returned 404")

// decodeAndVerifyContent decodes wire bytes as entity.Entity and verifies
// the content hash matches `target`. Same posture as
// storagesubstitutehttp.decodeAndVerify (the load-bearing Mechanism A
// trust check — §1).
func decodeAndVerifyContent(body []byte, target hash.Hash) (entity.Entity, error) {
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
	computed, err := hash.ComputeFormat(target.Algorithm, ent.Type, ent.Data)
	if err != nil {
		return entity.Entity{}, fmt.Errorf("compute hash: %w", err)
	}
	if computed != target {
		return entity.Entity{}, fmt.Errorf(
			"wire content does not hash to requested target: computed=%s target=%s",
			computed, target)
	}
	if !ent.ContentHash.IsZero() && ent.ContentHash != computed {
		return entity.Entity{}, fmt.Errorf(
			"wire content_hash disagrees with computed: wire=%s computed=%s",
			ent.ContentHash, computed)
	}
	ent.ContentHash = computed
	return ent, nil
}

// decodeTreeLeafPointer decodes a tree-leaf pointer body — a 2-key bare
// `ECF({type:"system/hash", data:<33-byte-hash>})` per Amendment 6 §8.
//
// The pointer is not signed; the caller is responsible for trust gating
// (hash-chain from a signed root, see FetchTreeLeafPointer doc).
func decodeTreeLeafPointer(body []byte) (hash.Hash, error) {
	// The body is the hashable form: cbor map {type, data}. Decode loosely.
	var raw struct {
		Type string          `cbor:"type"`
		Data cbor.RawMessage `cbor:"data"`
	}
	if err := cbor.Unmarshal(body, &raw); err != nil {
		return hash.Hash{}, fmt.Errorf("decode pointer wire: %w", err)
	}
	if raw.Type != "system/hash" {
		return hash.Hash{}, fmt.Errorf("pointer type %q is not system/hash", raw.Type)
	}
	var hashBytes []byte
	if err := cbor.Unmarshal(raw.Data, &hashBytes); err != nil {
		return hash.Hash{}, fmt.Errorf("decode pointer data: %w", err)
	}
	h, err := hash.FromBytes(hashBytes)
	if err != nil {
		return hash.Hash{}, fmt.Errorf("decode pointer hash bytes: %w", err)
	}
	return h, nil
}

