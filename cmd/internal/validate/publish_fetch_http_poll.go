// Category: publish_fetch_http_poll. The Tier-1 (publish→fetch) v1 gate
// per `docs/RELEASE-READINESS.md` Thread B + arch's three-tier reframe.
//
// Substrate is GREEN cohort-wide (Phase P published-root + httplive
// PollHandler + Outbound dialer). What this category proves is the
// *end-to-end* flow: a publisher mints a signed root over a small tree
// of authored entities, exposes its tree directory as a static HTTP
// origin (PollHandler mounted on httptest.Server — wire-equivalent to
// nginx / R2 / S3 serving the same routes), and a consumer drives the
// full read flow:
//
//	resolve → MANIFEST_GET → signature verify → TREE_GET (system/hash
//	pointer per Amendment 6) → CONTENT_GET /content/{hex33(H)} → re-hash
//	→ ingest → byte-equality assertion against publisher originals.
//
// This is **Mechanism A** (NETWORK §6.5.3.1 — HTTP-as-storage-transport),
// NOT BRIDGE-HTTP. The disambiguation matters: we are exercising the
// existing http-poll read surface end-to-end, not standing up the
// alternate handler-over-HTTP bridge.
//
// The category is fully self-contained — runs in-process, needs no live
// peer, no -poll-url, no -reference-peer. The publisher and consumer
// are wired against the same httptest.Server; the publisher writes via
// the namespaced index, the consumer reads via the public HTTP face.
// Same trust gates fire as against a real CDN deployment (host-bytes-
// distrust per §1.1; pinned-identity signature verify per §4).
//
// Vectors:
//
//	v1 publish_manifest_served       — Publisher mints, PollHandler
//	                                   serves a system/peer/published-
//	                                   root via MANIFEST_GET.
//	v2 manifest_signature_verified   — Outbound with pinned identity
//	                                   verifies the signature carriage
//	                                   (V7 §5.2 invariant pointer).
//	v3 tree_leaf_pointer_resolves    — For each authored blog path,
//	                                   FetchTreeLeafPointer returns the
//	                                   bound hash (Amendment 6 pointer).
//	v4 content_fetch_hash_verified   — CONTENT_GET on each pointer
//	                                   returns byte-equal entity that
//	                                   re-hashes to the requested H.
//	v5 ingest_byte_equality          — Decoded entities' .data fields
//	                                   match publisher originals byte-
//	                                   for-byte (ECF stability).
//	v6 host_bytes_distrust           — Swap-bytes origin is rejected by
//	                                   the connector's hash check (§1.1
//	                                   threat-model gate, applied to the
//	                                   blog-entity shape).

package validate

import (
	"bytes"
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"

	"go.entitychurch.org/entity-core-go/core/crypto"
	"go.entitychurch.org/entity-core-go/core/entity"
	"go.entitychurch.org/entity-core-go/core/hash"
	"go.entitychurch.org/entity-core-go/core/store"
	"go.entitychurch.org/entity-core-go/core/tree"
	"go.entitychurch.org/entity-core-go/core/types"
	"go.entitychurch.org/entity-core-go/ext/httplive"
	"go.entitychurch.org/entity-core-go/ext/publishedroot"

	"github.com/fxamacker/cbor/v2"
)

const catPublishFetchHTTPPoll = "publish_fetch_http_poll"

// publishFetchEntry is one entity authored by the publisher into the
// static origin tree. peerRelativePath is what the consumer dials
// (FetchTreeLeafPointer strips/adds the /{peer_id}/ shell). data is
// the raw CBOR payload — the consumer asserts byte-equality on it.
type publishFetchEntry struct {
	peerRelativePath string
	entityType       string
	data             []byte
}

func runPublishFetchHTTPPoll(ctx context.Context) []CheckResult {
	r := NewCheckRunner(catPublishFetchHTTPPoll)

	r.Declare("v1_publish_manifest_served", "PROPOSAL-PEER-MANIFEST-STATIC-HANDSHAKE §4 + NETWORK §6.5.3.1 — publisher mints a system/peer/published-root and PollHandler MANIFEST_GET serves it (Tier-1 end-to-end first step)")
	r.Declare("v2_manifest_signature_verified", "V7 §5.2 / PEER-MANIFEST §4 — Outbound with pinned identity walks the invariant-pointer signature carriage and reaches Verified=true")
	r.Declare("v3_tree_leaf_pointer_resolves", "NETWORK §6.5.3.1 Amendment 6 — TREE_GET for each authored peer-relative path returns the bound system/hash pointer at that leaf")
	r.Declare("v4_content_fetch_hash_verified", "NETWORK §6.5.3.1 — CONTENT_GET /content/{hex33(H)} returns byte-equal entity that re-hashes to the requested hash (Mechanism A trust gate fires positively)")
	r.Declare("v5_ingest_byte_equality", "End-to-end gate: every consumer-ingested entity's .data is byte-equal to the publisher's original (ECF byte-stability across the wire round-trip)")
	r.Declare("v6_host_bytes_distrust", "NETWORK §1.1 threat-model gate — a swap-bytes static origin is rejected by the connector's CONTENT_GET hash check, applied to the blog-entity shape (proves the gate is shape-agnostic)")

	// One harness backs v1..v5. v6 is independent (its own malicious server).
	h, err := setupPublishFetchHarness()
	if err != nil {
		fail := FailCheck("setup harness: " + err.Error())
		r.Run("v1_publish_manifest_served", func() CheckOutcome { return fail })
		r.Run("v2_manifest_signature_verified", func() CheckOutcome { return fail })
		r.Run("v3_tree_leaf_pointer_resolves", func() CheckOutcome { return fail })
		r.Run("v4_content_fetch_hash_verified", func() CheckOutcome { return fail })
		r.Run("v5_ingest_byte_equality", func() CheckOutcome { return fail })
		r.Run("v6_host_bytes_distrust", func() CheckOutcome { return runPublishFetchHostBytesDistrust(ctx) })
		return r.Results()
	}
	defer h.srv.Close()

	r.Run("v1_publish_manifest_served", func() CheckOutcome { return runPublishFetchManifestServed(ctx, h) })
	r.Run("v2_manifest_signature_verified", func() CheckOutcome { return runPublishFetchManifestVerified(ctx, h) })
	r.Run("v3_tree_leaf_pointer_resolves", func() CheckOutcome { return runPublishFetchTreeLeafPointers(ctx, h) })
	r.Run("v4_content_fetch_hash_verified", func() CheckOutcome { return runPublishFetchContentHashVerified(ctx, h) })
	r.Run("v5_ingest_byte_equality", func() CheckOutcome { return runPublishFetchIngestByteEquality(ctx, h) })
	r.Run("v6_host_bytes_distrust", func() CheckOutcome { return runPublishFetchHostBytesDistrust(ctx) })

	return r.Results()
}

// publishFetchHarness is the in-process publisher + static origin used
// by v1..v5. The PollHandler IS the static origin: the routes it serves
// (MANIFEST_GET / TREE_GET / CONTENT_GET) are byte-for-byte what a real
// nginx-fronted R2 bucket would serve for the same tree layout.
type publishFetchHarness struct {
	srv      *httptest.Server
	cs       store.ContentStore
	li       store.LocationIndex
	pub      *publishedroot.Publisher
	kp       crypto.Keypair
	identity entity.Entity
	entries  []publishFetchEntryAuthored
}

type publishFetchEntryAuthored struct {
	publishFetchEntry
	ent entity.Entity
}

func setupPublishFetchHarness() (*publishFetchHarness, error) {
	cs := store.NewMemoryContentStore()
	li := store.NewMemoryLocationIndex()
	kp, err := crypto.Generate()
	if err != nil {
		return nil, fmt.Errorf("generate kp: %w", err)
	}
	identityEnt, err := kp.IdentityEntity()
	if err != nil {
		return nil, fmt.Errorf("identity entity: %w", err)
	}
	if _, err := cs.Put(identityEnt); err != nil {
		return nil, fmt.Errorf("put identity: %w", err)
	}
	nli := store.NewNamespacedIndex(li, string(kp.PeerID()))

	tracker := tree.NewRootTracker(cs, string(kp.PeerID()), nil)
	pub := publishedroot.NewPublisher(cs, tracker, publishedroot.PrefixForLocalPeer, nil)
	if err := pub.SetupAuthority(nli, kp, identityEnt, false); err != nil {
		return nil, fmt.Errorf("setup authority: %w", err)
	}

	// Author a small blog tree. Three entries at peer-relative paths
	// (the publisher's NamespacedIndex prepends /{peer_id}/ on Set —
	// matches what the PollHandler resolves on TREE_GET). The .data
	// is hand-rolled CBOR so byte-equality assertions don't depend on
	// any Go-only serializer behavior; cohort impls mirror the bytes.
	entries := []publishFetchEntry{
		{peerRelativePath: "system/blog/post/entry-1", entityType: "test/blog/post/v1", data: mustCBORMap(map[string]any{"title": "first", "body": "hello"})},
		{peerRelativePath: "system/blog/post/entry-2", entityType: "test/blog/post/v1", data: mustCBORMap(map[string]any{"title": "second", "body": "world"})},
		{peerRelativePath: "system/blog/post/entry-3", entityType: "test/blog/post/v1", data: mustCBORMap(map[string]any{"title": "third", "body": "fin"})},
	}
	authored := make([]publishFetchEntryAuthored, 0, len(entries))
	for _, e := range entries {
		ent, err := entity.NewEntity(e.entityType, e.data)
		if err != nil {
			return nil, fmt.Errorf("author %s: %w", e.peerRelativePath, err)
		}
		if _, err := cs.Put(ent); err != nil {
			return nil, fmt.Errorf("cs.Put %s: %w", e.peerRelativePath, err)
		}
		if err := nli.Set(e.peerRelativePath, ent.ContentHash); err != nil {
			return nil, fmt.Errorf("nli.Set %s: %w", e.peerRelativePath, err)
		}
		authored = append(authored, publishFetchEntryAuthored{publishFetchEntry: e, ent: ent})
	}

	// Mint the published-root over a deterministic root hash. The Tier-1
	// gate does not assert the trie-walk closure from root_hash → leaves
	// (that's a separate v7 trie-closure check in published_root); here
	// we exercise the wire flow + per-leaf hash verification, which is
	// the slice arch named as the v1 gate (handoff §3.1).
	if _, err := pub.Publish(publishFetchRootHash(0xC0)); err != nil {
		return nil, fmt.Errorf("publish initial root: %w", err)
	}

	pollH := httplive.NewPollHandler("", cs, li, httplive.WholeStoreScope{}, kp.PeerID())
	pollH.ManifestProvider = func() *entity.Entity {
		e, ok := pub.Current()
		if !ok {
			return nil
		}
		return e
	}
	srv := httptest.NewServer(pollH)

	return &publishFetchHarness{
		srv:      srv,
		cs:       cs,
		li:       li,
		pub:      pub,
		kp:       kp,
		identity: identityEnt,
		entries:  authored,
	}, nil
}

func (h *publishFetchHarness) profile() types.HTTPPollProfileData {
	return types.HTTPPollProfileData{
		PeerID:        string(h.kp.PeerID()),
		TransportType: "http-poll",
		Endpoint: types.TransportEndpoint{
			TreeURLPrefix:    h.srv.URL,
			ContentURLPrefix: h.srv.URL + "/content",
			ContentLayout:    types.ContentLayoutFlat,
		},
		SupportedOps:  []string{types.OpTreeGet, types.OpContentGet, types.OpManifestGet},
		NonceRequired: false,
	}
}

// v1 — publisher mints, PollHandler serves a published-root via the
// raw MANIFEST_GET route. We assert the wire shape (entity type +
// non-zero root_hash). Unpinned fetch is fine for this vector — the
// signature verify cycle is v2's gate.
func runPublishFetchManifestServed(ctx context.Context, h *publishFetchHarness) CheckOutcome {
	out := httplive.NewOutbound(h.profile(), httplive.WithOutboundAllowHTTP(true))
	pr, err := out.FetchPublishedRoot(ctx)
	if err != nil {
		return FailCheck("MANIFEST_GET: " + err.Error())
	}
	if pr.Entity.Type != types.TypePeerPublishedRoot {
		return FailCheck(fmt.Sprintf("manifest entity type %q is not %s", pr.Entity.Type, types.TypePeerPublishedRoot))
	}
	if pr.Data.RootHash.IsZero() {
		return FailCheck("published-root.root_hash is zero — publisher misconfigured")
	}
	if pr.Data.PeerID != string(h.kp.PeerID()) {
		return FailCheck(fmt.Sprintf("manifest PeerID %q ≠ publisher PeerID %q", pr.Data.PeerID, h.kp.PeerID()))
	}
	return PassCheck(fmt.Sprintf("manifest served — seq=%d root=%s", pr.Data.Seq, pr.Data.RootHash))
}

// v2 — Outbound with pinned identity walks the invariant-pointer
// signature carriage and reaches Verified=true. This is the §4 contract:
// MANIFEST_GET body + system/signature/{hex(root_hash)} tree-leaf
// pointer + CONTENT_GET of the signature entity → verify against
// pinned pubkey.
func runPublishFetchManifestVerified(ctx context.Context, h *publishFetchHarness) CheckOutcome {
	out := httplive.NewOutbound(h.profile(),
		httplive.WithOutboundAllowHTTP(true),
		httplive.WithPinnedIdentity(h.identity),
	)
	pr, err := out.FetchPublishedRoot(ctx)
	if err != nil {
		return FailCheck("pinned fetch: " + err.Error())
	}
	if !pr.Verified {
		return FailCheck("Verified=false after pinned fetch — signature carriage / verify cycle is broken")
	}
	return PassCheck(fmt.Sprintf("verified manifest — seq=%d root=%s", pr.Data.Seq, pr.Data.RootHash))
}

// v3 — for each authored peer-relative path, the consumer dials
// TREE_GET and recovers the bound hash (Amendment 6 system/hash
// pointer). The pointer MUST equal the publisher's authored
// ContentHash exactly.
func runPublishFetchTreeLeafPointers(ctx context.Context, h *publishFetchHarness) CheckOutcome {
	out := httplive.NewOutbound(h.profile(),
		httplive.WithOutboundAllowHTTP(true),
		httplive.WithPinnedIdentity(h.identity),
	)
	signerHex := string(h.kp.PeerID())
	for _, a := range h.entries {
		ptr, err := out.FetchTreeLeafPointer(ctx, signerHex, a.peerRelativePath)
		if err != nil {
			return FailCheck("FetchTreeLeafPointer " + a.peerRelativePath + ": " + err.Error())
		}
		if ptr != a.ent.ContentHash {
			return FailCheck(fmt.Sprintf("pointer drift at %s: got %s want %s", a.peerRelativePath, ptr, a.ent.ContentHash))
		}
	}
	return PassCheck(fmt.Sprintf("resolved %d tree-leaf pointers (Amendment 6 system/hash)", len(h.entries)))
}

// v4 — CONTENT_GET on each leaf pointer returns an entity that
// re-hashes to the requested H. The connector enforces this on every
// fetch; PASS proves the positive path of the §1.1 trust gate fires
// (v6 covers the negative path with a swap-bytes origin).
func runPublishFetchContentHashVerified(ctx context.Context, h *publishFetchHarness) CheckOutcome {
	out := httplive.NewOutbound(h.profile(),
		httplive.WithOutboundAllowHTTP(true),
		httplive.WithPinnedIdentity(h.identity),
	)
	for _, a := range h.entries {
		got, err := out.FetchContent(ctx, a.ent.ContentHash)
		if err != nil {
			return FailCheck("FetchContent " + a.peerRelativePath + ": " + err.Error())
		}
		if got.ContentHash != a.ent.ContentHash {
			return FailCheck(fmt.Sprintf("content hash drift at %s after fetch", a.peerRelativePath))
		}
		if got.Type != a.entityType {
			return FailCheck(fmt.Sprintf("type drift at %s: got %q want %q", a.peerRelativePath, got.Type, a.entityType))
		}
	}
	return PassCheck(fmt.Sprintf("fetched + hash-verified %d entities (Mechanism A trust gate fires positively)", len(h.entries)))
}

// v5 — the *end-to-end ingest* assertion that Tier-1 names as the v1
// gate: after the full publish→fetch flow, every consumer-side entity's
// .data field is byte-equal to the publisher's original. ECF
// determinism across the wire round-trip — the cohort agreement signal.
func runPublishFetchIngestByteEquality(ctx context.Context, h *publishFetchHarness) CheckOutcome {
	out := httplive.NewOutbound(h.profile(),
		httplive.WithOutboundAllowHTTP(true),
		httplive.WithPinnedIdentity(h.identity),
	)
	signerHex := string(h.kp.PeerID())
	for _, a := range h.entries {
		ptr, err := out.FetchTreeLeafPointer(ctx, signerHex, a.peerRelativePath)
		if err != nil {
			return FailCheck("ingest walk (tree) " + a.peerRelativePath + ": " + err.Error())
		}
		got, err := out.FetchContent(ctx, ptr)
		if err != nil {
			return FailCheck("ingest walk (content) " + a.peerRelativePath + ": " + err.Error())
		}
		if !bytes.Equal([]byte(got.Data), a.data) {
			return FailCheck(fmt.Sprintf("ingest data drift at %s — wire round-trip changed bytes (ECF determinism broken)", a.peerRelativePath))
		}
	}
	return PassCheck(fmt.Sprintf("end-to-end ingest: %d entities byte-equal to publisher originals", len(h.entries)))
}

// v6 — §1.1 threat-model gate specialized to the blog-entity shape.
// A malicious or corrupted static origin serves bytes whose hash does
// NOT match the requested hash; the connector MUST reject. Mirrors the
// existing relay_static_cdn_test.go specialization for relay shapes —
// proves the gate is shape-agnostic.
func runPublishFetchHostBytesDistrust(_ context.Context) CheckOutcome {
	realData := mustCBORMap(map[string]any{"title": "real", "body": "post"})
	realEnt, _ := entity.NewEntity("test/blog/post/v1", realData)

	imposterData := mustCBORMap(map[string]any{"title": "imposter", "body": "bytes"})
	imposterEnt, _ := entity.NewEntity("test/blog/post/v1", imposterData)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasPrefix(r.URL.Path, "/content/") {
			http.NotFound(w, r)
			return
		}
		// Host serves imposter bytes regardless of the requested hash.
		body, _ := cbor.Marshal(imposterEnt)
		w.Header().Set("Content-Type", "application/cbor")
		w.WriteHeader(http.StatusOK)
		w.Write(body)
	}))
	defer srv.Close()

	kp, _ := crypto.Generate()
	out := httplive.NewOutbound(types.HTTPPollProfileData{
		PeerID:        string(kp.PeerID()),
		TransportType: "http-poll",
		Endpoint: types.TransportEndpoint{
			TreeURLPrefix:    srv.URL,
			ContentURLPrefix: srv.URL + "/content",
			ContentLayout:    types.ContentLayoutFlat,
		},
	}, httplive.WithOutboundAllowHTTP(true))

	_, err := out.FetchContent(context.Background(), realEnt.ContentHash)
	if err == nil {
		return FailCheck("FetchContent silently accepted wrong-bytes response — §1.1 gate broken for blog-entity shape")
	}
	if !strings.Contains(err.Error(), "hash") {
		return FailCheck("rejection happened but error did not cite hash mismatch: " + err.Error())
	}
	return PassCheck("connector rejected mismatched bytes on blog-entity shape (§1.1 gate shape-agnostic)")
}

// Helpers --------------------------------------------------------------

// publishFetchRootHash returns a deterministic SHA-256 hash. Same shape
// the published_root + relay_static_cdn tests use — the published-root
// signs over this hash; the trie-walk closure is not in scope for this
// category.
func publishFetchRootHash(b byte) hash.Hash {
	var h hash.Hash
	h.Algorithm = hash.AlgorithmSHA256
	h.Digest[0] = b
	return h
}

// mustCBORMap encodes a Go map as deterministic CBOR using the same
// CoreDetEncOptions the rest of the codebase uses. Panics on encode
// error — fixture data is hand-rolled and trivially valid.
func mustCBORMap(m map[string]any) []byte {
	em, err := cbor.CoreDetEncOptions().EncMode()
	if err != nil {
		panic("cbor enc mode: " + err.Error())
	}
	b, err := em.Marshal(m)
	if err != nil {
		panic("cbor marshal: " + err.Error())
	}
	return b
}
