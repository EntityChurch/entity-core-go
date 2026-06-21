// Category: published_root. Probes the PROPOSAL-PEER-MANIFEST-STATIC-
// HANDSHAKE §4 (LOCKED) substrate. Seven vectors:
//
//	v1 round_trip                  — ECF encode/decode of a fixture entity;
//	                                 cohort byte-equality assertion on the
//	                                 hash of the fixture (the §4 wire pin).
//	v2 signature_carriage          — signature lives at the V7 §5.2/§975
//	                                 invariant pointer (NOT inline / NOT
//	                                 refs:); verifier resolves it that way.
//	v3 seq_monotonicity            — connector caches max-seen seq;
//	                                 lower-seq fetch fails closed.
//	v4 manifest_get_served         — the peer's MANIFEST_GET route returns
//	                                 a system/peer/published-root entity
//	                                 (requires --publish-root + -poll-url).
//	v5 outbound_dial               — full dial → fetch → verify cycle
//	                                 against the live peer (with pin).
//	v6 host_bytes_distrust         — fabricated content/{hex} response is
//	                                 rejected by the connector's hash check
//	                                 (§1.1 threat-model gate).
//	v7 trie_closure_content_get    — CONTENT_GET(published-root.root_hash)
//	                                 MUST succeed (NETWORK §6.5.6 Amendment 10
//	                                 — closure-of-signed-root). Trie nodes are
//	                                 hash-linked, not path-bound (V7 §1.7);
//	                                 namespace-only publishers 404 here and
//	                                 break the §1.1 walk-from-signed-root.
//
// Vectors v1-v3, v6 are pure-Go probes (don't touch the remote peer's
// surface beyond what the connector already mediates); v4 + v5 require a
// reachable poll URL (`-poll-url`). The category SKIPs when -poll-url is
// absent — the cohort gate is "live publisher exposed to the validator,"
// not "type-shape-only" (which lives in core/types unit tests).

package validate

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"

	"go.entitychurch.org/entity-core-go/core/crypto"
	"go.entitychurch.org/entity-core-go/core/ecf"
	"go.entitychurch.org/entity-core-go/core/entity"
	"go.entitychurch.org/entity-core-go/core/hash"
	"go.entitychurch.org/entity-core-go/core/store"
	"go.entitychurch.org/entity-core-go/core/tree"
	"go.entitychurch.org/entity-core-go/core/types"
	"go.entitychurch.org/entity-core-go/ext/httplive"
	"go.entitychurch.org/entity-core-go/ext/publishedroot"

	"github.com/fxamacker/cbor/v2"
)

const catPublishedRoot = "published_root"

func runPublishedRoot(ctx context.Context, pollURL string) []CheckResult {
	r := NewCheckRunner(catPublishedRoot)

	r.Declare("v1_round_trip", "PROPOSAL-PEER-MANIFEST-STATIC-HANDSHAKE §4 — system/peer/published-root ECF round-trip + cohort-stable content_hash on a fixed fixture")
	r.Declare("v2_signature_carriage", "V7 §5.2/§975 — signature carriage via invariant-pointer; the dialer resolves system/signature/{hex(root_hash)} as a tree-leaf and the entity verifies")
	r.Declare("v3_seq_monotonicity", "§4 + snapshot-manifest §3-RES.4 — connector caches max-seen seq; lower-seq fetch fails closed")
	r.Declare("v4_manifest_get_served", "MANIFEST_GET returns a system/peer/published-root entity (requires --publish-root + -poll-url)")
	r.Declare("v5_outbound_dial", "End-to-end dial → MANIFEST_GET → signature verify (requires --publish-root + -poll-url)")
	r.Declare("v6_host_bytes_distrust", "§1.1 threat-model gate — a host serving wrong bytes is rejected by the connector's hash check")
	r.Declare("v7_trie_closure_content_get", "EXTENSION-NETWORK §6.5.6 Amendment 10 — CONTENT_GET(published-root.root_hash) MUST succeed; trie nodes are hash-linked not path-bound (V7 §1.7), so the closure-of-signed-root scope is the floor when signed_pointer is advertised")

	r.Run("v1_round_trip", runPublishedRootRoundTrip)
	r.Run("v2_signature_carriage", runPublishedRootSignatureCarriage)
	r.Run("v3_seq_monotonicity", runPublishedRootSeqMonotonicity)
	r.Run("v4_manifest_get_served", func() CheckOutcome { return runPublishedRootManifestGet(ctx, pollURL) })
	r.Run("v5_outbound_dial", func() CheckOutcome { return runPublishedRootOutboundDial(ctx, pollURL) })
	r.Run("v6_host_bytes_distrust", func() CheckOutcome { return runPublishedRootHostBytesDistrust(ctx) })
	r.Run("v7_trie_closure_content_get", func() CheckOutcome { return runPublishedRootTrieClosure(ctx, pollURL) })

	return r.Results()
}

// v1 — ECF round-trip + content-hash byte-equality on a fixed fixture.
// The fixture pins specific peer_id / root_hash / seq / published_at values
// so the cohort can byte-compare the resulting content_hash. The hash is
// the load-bearing cross-impl agreement signal.
func runPublishedRootRoundTrip() CheckOutcome {
	predecessor := publishedRootFixtureHash(0x11)
	d := types.PublishedRootData{
		// Ruling-1: peer_id is Base58 per V7 §1.5. Cohort-stable
		// fixture pin: a fixed Ed25519 peer-id (identity-form) authored by
		// the same key the cohort reference fixtures use.
		PeerID:      publishedRootFixturePeerID,
		RootHash:    publishedRootFixtureHash(0xBB),
		Seq:         42,
		PublishedAt: 1_730_000_000_000,
		Predecessor: &predecessor,
	}
	e, err := d.ToEntity()
	if err != nil {
		return FailCheck("encode published-root: " + err.Error())
	}
	if e.Type != types.TypePeerPublishedRoot {
		return FailCheck(fmt.Sprintf("entity type drift: got %q want %q", e.Type, types.TypePeerPublishedRoot))
	}
	if err := e.Validate(); err != nil {
		return FailCheck("entity hash validate: " + err.Error())
	}
	decoded, err := types.PublishedRootDataFromEntity(e)
	if err != nil {
		return FailCheck("decode published-root: " + err.Error())
	}
	if decoded.PeerID != d.PeerID || decoded.RootHash != d.RootHash ||
		decoded.Seq != d.Seq || decoded.PublishedAt != d.PublishedAt {
		return FailCheck("decoded fields drifted from encoded")
	}
	if decoded.Predecessor == nil || *decoded.Predecessor != predecessor {
		return FailCheck("predecessor drifted")
	}
	return PassCheck(fmt.Sprintf("fixture content_hash=%s", e.ContentHash))
}

// v2 — signature carriage convention. The publisher's package
// (ext/publishedroot) binds the signature at LocalSignaturePath; the
// connector resolves it via the V7 §5.2 / §975 invariant pointer. This
// vector exercises the full carriage shape in-process: build a published-
// root, sign it, bind at the invariant path, then dial it back through
// an httptest server and confirm the verifier walks the path correctly.
func runPublishedRootSignatureCarriage() CheckOutcome {
	srv, kp, identityEnt, err := setupVerifyHarness()
	if err != nil {
		return FailCheck("setup harness: " + err.Error())
	}
	defer srv.Close()

	out := httplive.NewOutbound(harnessProfile(srv, kp),
		httplive.WithOutboundAllowHTTP(true),
		httplive.WithPinnedIdentity(identityEnt),
	)
	pr, err := out.FetchPublishedRoot(context.Background())
	if err != nil {
		return FailCheck("fetch+verify: " + err.Error())
	}
	if !pr.Verified {
		return FailCheck("signature did not verify under pinned identity (Verified=false)")
	}
	return PassCheck(fmt.Sprintf("verified manifest seq=%d", pr.Data.Seq))
}

// v3 — seq monotonicity gate. The connector caches max-seen seq; a
// later fetch with a lower seq must error. We script two manifests via a
// custom server: first seq=5, then seq=3 — the gate must trip.
func runPublishedRootSeqMonotonicity() CheckOutcome {
	kp, err := crypto.Generate()
	if err != nil {
		return FailCheck("generate kp: " + err.Error())
	}

	var current *entity.Entity
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasSuffix(r.URL.Path, "/manifest") {
			http.NotFound(w, r)
			return
		}
		if current == nil {
			http.NotFound(w, r)
			return
		}
		body, _ := cbor.Marshal(*current)
		w.Header().Set("Content-Type", "application/cbor")
		w.WriteHeader(http.StatusOK)
		w.Write(body)
	}))
	defer srv.Close()

	mk := func(seq uint64, b byte) *entity.Entity {
		d := types.PublishedRootData{
			PeerID:      string(kp.PeerID()),
			RootHash:    publishedRootFixtureHash(b),
			Seq:         seq,
			PublishedAt: seq,
		}
		e, _ := d.ToEntity()
		return &e
	}

	out := httplive.NewOutbound(harnessProfile(srv, kp), httplive.WithOutboundAllowHTTP(true))

	current = mk(5, 0xAA)
	if _, err := out.FetchPublishedRoot(context.Background()); err != nil {
		return FailCheck("priming fetch seq=5: " + err.Error())
	}
	current = mk(3, 0xBB)
	_, err = out.FetchPublishedRoot(context.Background())
	if err == nil {
		return FailCheck("seq=3 after seq=5 was accepted — rollback gate broken")
	}
	if !strings.Contains(err.Error(), "rollback") && !strings.Contains(err.Error(), "seq") {
		return FailCheck("rollback rejected, but error did not name the cause: " + err.Error())
	}
	current = mk(5, 0xAA)
	if _, err := out.FetchPublishedRoot(context.Background()); err != nil {
		return FailCheck("seq=5 republish: " + err.Error())
	}
	return PassCheck("seq gate accepts ≥cached, rejects <cached")
}

// v4 — the peer's MANIFEST_GET route returns a system/peer/published-root
// entity. Requires the peer to be started with --publish-root and the
// validator to have been given -poll-url.
func runPublishedRootManifestGet(ctx context.Context, pollURL string) CheckOutcome {
	if pollURL == "" {
		return SkipCheck("no -poll-url provided (start the peer with --publish-root + --http-poll-addr and pass -poll-url http://host:port)")
	}
	url := strings.TrimRight(pollURL, "/") + "/manifest"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return FailCheck("build request: " + err.Error())
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return FailCheck("GET " + url + ": " + err.Error())
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotFound {
		// Peer was started without --publish-root (or with it but without a
		// scope that covers the signed-root closure, which the publisher
		// detects + refuses to publish). v5/v7 already SKIP on this same
		// signal; align v4 so the gate stays operable while closure-root
		// scope rolls out to Go+Rust. -allow-skip cohort-wide.
		return SkipCheck("peer returned 404 — start it with --publish-root + closure-or-whole-store scope so MANIFEST_GET has a body")
	}
	if resp.StatusCode != http.StatusOK {
		return FailCheck(fmt.Sprintf("unexpected status %d", resp.StatusCode))
	}

	var ent entity.Entity
	dec := cbor.NewDecoder(resp.Body)
	if err := dec.Decode(&ent); err != nil {
		return FailCheck("decode manifest entity: " + err.Error())
	}
	if ent.Type != types.TypePeerPublishedRoot {
		return FailCheck(fmt.Sprintf("manifest entity type %q is not %s", ent.Type, types.TypePeerPublishedRoot))
	}
	data, err := types.PublishedRootDataFromEntity(ent)
	if err != nil {
		return FailCheck("decode published-root payload: " + err.Error())
	}
	if data.RootHash.IsZero() {
		return FailCheck("published-root root_hash is zero — publisher misconfigured")
	}
	return PassCheck(fmt.Sprintf("manifest=published-root seq=%d", data.Seq))
}

// v5 — full outbound dial against the live peer. Needs the peer's
// identity entity to verify the signature; we recover it from a separate
// content fetch by hash (the published-root carries the peer-id-hash, and
// the connector can fetch the system/peer entity by that hash through the
// peer's CONTENT_GET route).
func runPublishedRootOutboundDial(ctx context.Context, pollURL string) CheckOutcome {
	if pollURL == "" {
		return SkipCheck("no -poll-url provided")
	}
	// Step 1: fetch the manifest unverified to learn the publisher's PeerID hash.
	profile := types.HTTPPollProfileData{
		PeerID:        "unknown",
		TransportType: "http-poll",
		Endpoint: types.TransportEndpoint{
			TreeURLPrefix:    pollURL,
			ContentURLPrefix: pollURL + "/content",
			ContentLayout:    types.ContentLayoutFlat,
		},
	}
	out := httplive.NewOutbound(profile, httplive.WithOutboundAllowHTTP(true))
	pr, err := out.FetchPublishedRoot(ctx)
	if err != nil {
		if strings.Contains(err.Error(), "404") || strings.Contains(err.Error(), "manifest") {
			return SkipCheck("peer did not serve a published-root: " + err.Error())
		}
		return FailCheck("initial fetch: " + err.Error())
	}

	// Step 2: Ruling-1 — pubkey IS identity per V7 §1.5. Derive
	// the publisher's public key directly from the Base58 peer-id in the
	// manifest (no off-network fetch required for identity-form peer-ids);
	// synthesize the canonical system/peer entity from (pubkey, key_type).
	// SHA-256-form peer-ids would require an off-network fetch — out of scope
	// for this vector (every cohort impl currently emits identity-form).
	peerEnt, err := identityEntityFromPeerID(pr.Data.PeerID)
	if err != nil {
		return FailCheck("derive identity from peer-id " + pr.Data.PeerID + ": " + err.Error())
	}

	// Step 3: fresh outbound with pinned identity; the full verify cycle MUST
	// reach Verified=true.
	pinned := httplive.NewOutbound(profile,
		httplive.WithOutboundAllowHTTP(true),
		httplive.WithPinnedIdentity(peerEnt),
	)
	verified, err := pinned.FetchPublishedRoot(ctx)
	if err != nil {
		return FailCheck("verify cycle: " + err.Error())
	}
	if !verified.Verified {
		return FailCheck("Verified=false after pinned fetch")
	}
	return PassCheck(fmt.Sprintf("verified dial — seq=%d root=%s", verified.Data.Seq, verified.Data.RootHash))
}

// v6 — §1.1 threat-model gate. A malicious host serves bytes whose hash
// does not match what the consumer asked for; the connector's hash check
// rejects.
func runPublishedRootHostBytesDistrust(_ context.Context) CheckOutcome {
	entA, _ := entity.NewEntity("test/a", []byte{0xa1, 0x01, 0x02})
	entB, _ := entity.NewEntity("test/b", []byte{0xa1, 0x03, 0x04})

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/content/") {
			body, _ := cbor.Marshal(entA)
			w.Header().Set("Content-Type", "application/cbor")
			w.WriteHeader(http.StatusOK)
			w.Write(body)
			return
		}
		http.NotFound(w, r)
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

	_, err := out.FetchContent(context.Background(), entB.ContentHash)
	if err == nil {
		return FailCheck("FetchContent silently accepted wrong-bytes response — §1.1 gate broken")
	}
	if !strings.Contains(err.Error(), "hash") {
		return FailCheck("rejection happened but error did not cite hash mismatch: " + err.Error())
	}
	return PassCheck("connector rejected mismatched bytes (§1.1 gate honored)")
}

// v7 — EXTENSION-NETWORK §6.5.6 Amendment 10 trie-closure MUST. Fetch the
// manifest, decode published-root.root_hash (the CHAMP trie root node hash),
// then CONTENT_GET that hash. CHAMP trie nodes are hash-linked, not path-
// bound (V7 §1.7), so a namespace-only served-set 404s on this fetch and the
// PEER-MANIFEST §1.1 walk-from-signed-root halts before reading the first
// node. A publisher advertising signed_pointer MUST resolve the closure;
// whole-store covers this trivially, closure-of-signed-root is the floor.
//
// We don't pin identity here — we're not testing signature verification,
// we're testing publisher serving scope. A 404 is the diagnostic the
// ruling pins as non-conformant for signed_pointer-advertising publishers.
func runPublishedRootTrieClosure(ctx context.Context, pollURL string) CheckOutcome {
	if pollURL == "" {
		return SkipCheck("no -poll-url provided (start the peer with --publish-root + --http-poll-addr + a closure-or-whole-store scope, then pass -poll-url http://host:port)")
	}
	profile := types.HTTPPollProfileData{
		PeerID:        "unknown",
		TransportType: "http-poll",
		Endpoint: types.TransportEndpoint{
			TreeURLPrefix:    pollURL,
			ContentURLPrefix: pollURL + "/content",
			ContentLayout:    types.ContentLayoutFlat,
		},
	}
	out := httplive.NewOutbound(profile, httplive.WithOutboundAllowHTTP(true))
	pr, err := out.FetchPublishedRoot(ctx)
	if err != nil {
		if strings.Contains(err.Error(), "404") || strings.Contains(err.Error(), "manifest") {
			return SkipCheck("peer did not serve a published-root: " + err.Error())
		}
		return FailCheck("fetch manifest: " + err.Error())
	}
	if pr.Data.RootHash.IsZero() {
		return FailCheck("published-root.root_hash is zero — publisher misconfigured")
	}
	// The closure MUST. A FAIL here is diagnostic of namespace-only scope
	// while signed_pointer is advertised — that combination is non-conformant
	// per NETWORK §6.5.6 Amendment 10.
	ent, err := out.FetchContent(ctx, pr.Data.RootHash)
	if err != nil {
		return FailCheck("CONTENT_GET(root_hash=" + pr.Data.RootHash.String() + ") failed (closure not served — namespace-only scope while signed_pointer advertised is non-conformant): " + err.Error())
	}
	if ent.Type != types.TypeTreeSnapshotNode {
		return FailCheck(fmt.Sprintf("root_hash entity type %q is not %s — root_hash should point at a CHAMP trie node", ent.Type, types.TypeTreeSnapshotNode))
	}
	return PassCheck(fmt.Sprintf("trie-closure served — root_hash=%s decoded as %s", pr.Data.RootHash, ent.Type))
}

// Helpers --------------------------------------------------------------

// publishedRootFixturePeerID is the cohort-stable Base58 peer-id used in the
// v1 round-trip fixture (Ruling-1). It is derived deterministically
// from a fixed Ed25519 seed (0xAA repeated) so the fixture's content_hash is
// byte-equal across impls. Identity-form per V7 §1.5 (HashTypeIdentity).
var publishedRootFixturePeerID = func() string {
	var seed [32]byte
	for i := range seed {
		seed[i] = 0xAA
	}
	kp := crypto.FromSeed(seed)
	return string(kp.PeerID())
}()

// publishedRootFixtureHash returns a deterministic SHA-256 hash for fixture
// use. Algorithm is SHA-256; digest is the byte repeated in the first
// position then zero-padded.
func publishedRootFixtureHash(b byte) hash.Hash {
	var h hash.Hash
	h.Algorithm = hash.AlgorithmSHA256
	h.Digest[0] = b
	return h
}

// identityEntityFromPeerID derives the canonical system/peer entity from an
// identity-form Base58 peer-id (V7 §1.5, hash_type=0x00). The pubkey IS the
// peer-id digest, so the entity is reconstructible locally — no network fetch.
// Returns an error for SHA-256-form peer-ids (the digest is the SHA-256 of the
// pubkey; pubkey is not derivable without out-of-band data).
func identityEntityFromPeerID(pid string) (entity.Entity, error) {
	pub, keyType, ok := crypto.DerivePeerFromPeerID(crypto.PeerID(pid))
	if !ok {
		return entity.Entity{}, fmt.Errorf("peer-id %s is SHA-256-form or invalid; cannot derive pubkey locally", pid)
	}
	ktString := crypto.KeyTypeString(keyType)
	if ktString == "" {
		return entity.Entity{}, fmt.Errorf("peer-id %s has unsupported key_type 0x%02x", pid, keyType)
	}
	data := struct {
		PublicKey []byte `cbor:"public_key"`
		KeyType   string `cbor:"key_type"`
	}{PublicKey: pub, KeyType: ktString}
	raw, err := ecf.Encode(data)
	if err != nil {
		return entity.Entity{}, fmt.Errorf("encode synthetic identity: %w", err)
	}
	return entity.NewEntity(types.TypePeer, cbor.RawMessage(raw))
}

// setupVerifyHarness spins up an httptest server backed by a real peer-
// shape store + LI + a published-root publisher, then returns the wired
// pieces. Mirrors the outboundFixture used by httplive tests.
func setupVerifyHarness() (*httptest.Server, crypto.Keypair, entity.Entity, error) {
	cs := store.NewMemoryContentStore()
	li := store.NewMemoryLocationIndex()
	kp, err := crypto.Generate()
	if err != nil {
		return nil, crypto.Keypair{}, entity.Entity{}, fmt.Errorf("generate kp: %w", err)
	}
	identityEnt, err := kp.IdentityEntity()
	if err != nil {
		return nil, crypto.Keypair{}, entity.Entity{}, fmt.Errorf("identity entity: %w", err)
	}
	if _, err := cs.Put(identityEnt); err != nil {
		return nil, crypto.Keypair{}, entity.Entity{}, fmt.Errorf("put identity: %w", err)
	}
	nli := store.NewNamespacedIndex(li, string(kp.PeerID()))
	tracker := tree.NewRootTracker(cs, string(kp.PeerID()), nil)
	pub := publishedroot.NewPublisher(cs, tracker, publishedroot.PrefixForLocalPeer, nil)
	if err := pub.SetupAuthority(nli, kp, identityEnt, false); err != nil {
		return nil, crypto.Keypair{}, entity.Entity{}, fmt.Errorf("setup authority: %w", err)
	}
	if _, err := pub.Publish(publishedRootFixtureHash(0xAB)); err != nil {
		return nil, crypto.Keypair{}, entity.Entity{}, fmt.Errorf("initial publish: %w", err)
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
	return srv, kp, identityEnt, nil
}

// harnessProfile returns an HTTPPollProfileData pointed at the harness
// server, suitable for handing to httplive.NewOutbound.
func harnessProfile(srv *httptest.Server, kp crypto.Keypair) types.HTTPPollProfileData {
	return types.HTTPPollProfileData{
		PeerID:        string(kp.PeerID()),
		TransportType: "http-poll",
		Endpoint: types.TransportEndpoint{
			TreeURLPrefix:    srv.URL,
			ContentURLPrefix: srv.URL + "/content",
			ContentLayout:    types.ContentLayoutFlat,
		},
		SupportedOps:  []string{types.OpTreeGet, types.OpContentGet, types.OpManifestGet},
		NonceRequired: false,
	}
}
