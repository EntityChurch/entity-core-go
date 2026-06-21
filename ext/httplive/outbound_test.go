package httplive_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

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

// outboundFixture wires a publisher onto a PollHandler served via httptest
// and returns the pieces a test needs to dial it back.
type outboundFixture struct {
	ts        *httptest.Server
	cs        store.ContentStore
	li        store.LocationIndex
	publisher *publishedroot.Publisher
	kp        crypto.Keypair
	identity  entity.Entity
}

func newOutboundFixture(t *testing.T) *outboundFixture {
	t.Helper()
	cs := store.NewMemoryContentStore()
	li := store.NewMemoryLocationIndex()
	kp, err := crypto.Generate()
	if err != nil {
		t.Fatalf("generate kp: %v", err)
	}
	identityEnt, err := kp.IdentityEntity()
	if err != nil {
		t.Fatalf("identity entity: %v", err)
	}
	if _, err := cs.Put(identityEnt); err != nil {
		t.Fatalf("put identity: %v", err)
	}
	// NamespacedIndex prepends "/{base58PeerID}/" to every Set/Get —
	// matches what peer.New wires so the publisher's LocalSignaturePath
	// writes land at the same fully-qualified path PollHandler resolves
	// against.
	nli := store.NewNamespacedIndex(li, string(kp.PeerID()))

	tracker := tree.NewRootTracker(cs, string(kp.PeerID()), nil)
	publisher := publishedroot.NewPublisher(cs, tracker, publishedroot.PrefixForLocalPeer, nil)
	if err := publisher.SetupAuthority(nli, kp, identityEnt, false); err != nil {
		t.Fatalf("setup authority: %v", err)
	}

	pollH := httplive.NewPollHandler("", cs, li, httplive.WholeStoreScope{}, kp.PeerID())
	pollH.ManifestProvider = func() *entity.Entity {
		e, ok := publisher.Current()
		if !ok {
			return nil
		}
		return e
	}
	ts := httptest.NewServer(pollH)
	t.Cleanup(ts.Close)

	return &outboundFixture{
		ts:        ts,
		cs:        cs,
		li:        li,
		publisher: publisher,
		kp:        kp,
		identity:  identityEnt,
	}
}

func (f *outboundFixture) profile() types.HTTPPollProfileData {
	return types.HTTPPollProfileData{
		PeerID:        string(f.kp.PeerID()),
		TransportType: "http-poll",
		Endpoint: types.TransportEndpoint{
			TreeURLPrefix:    f.ts.URL,
			ContentURLPrefix: f.ts.URL + "/content",
			ContentLayout:    types.ContentLayoutFlat,
		},
		SupportedOps:  []string{types.OpTreeGet, types.OpContentGet, types.OpManifestGet},
		NonceRequired: false,
	}
}

func TestOutboundFetchPublishedRoot_VerifiesPinnedSignature(t *testing.T) {
	f := newOutboundFixture(t)
	if _, err := f.publisher.Publish(fakeRoot(0xAB)); err != nil {
		t.Fatalf("publish initial root: %v", err)
	}

	out := httplive.NewOutbound(f.profile(),
		httplive.WithOutboundAllowHTTP(true),
		httplive.WithPinnedIdentity(f.identity),
	)
	pr, err := out.FetchPublishedRoot(context.Background())
	if err != nil {
		t.Fatalf("FetchPublishedRoot: %v", err)
	}
	if !pr.Verified {
		t.Fatal("pinned identity provided; Verified must be true")
	}
	if pr.Data.PeerID != string(f.kp.PeerID()) {
		t.Fatalf("PeerID drift: %s vs %s", pr.Data.PeerID, f.kp.PeerID())
	}
}

func TestOutboundFetchPublishedRoot_NoPin_DoesNotVerify(t *testing.T) {
	f := newOutboundFixture(t)
	if _, err := f.publisher.Publish(fakeRoot(0xCD)); err != nil {
		t.Fatalf("publish: %v", err)
	}
	out := httplive.NewOutbound(f.profile(), httplive.WithOutboundAllowHTTP(true))
	pr, err := out.FetchPublishedRoot(context.Background())
	if err != nil {
		t.Fatalf("FetchPublishedRoot: %v", err)
	}
	if pr.Verified {
		t.Fatal("no pin → Verified MUST stay false")
	}
}

func TestOutboundFetchPublishedRoot_SeqMonotonicity(t *testing.T) {
	// Same fixture, two scripted manifests: first served at seq=5 to set the
	// floor; second served at seq=3 (rollback). The connector must reject.
	cs := store.NewMemoryContentStore()
	li := store.NewMemoryLocationIndex()
	kp, _ := crypto.Generate()
	idEnt, _ := kp.IdentityEntity()
	cs.Put(idEnt)

	pollH := httplive.NewPollHandler("", cs, li, httplive.WholeStoreScope{}, kp.PeerID())
	var currentManifest *entity.Entity
	pollH.ManifestProvider = func() *entity.Entity { return currentManifest }
	ts := httptest.NewServer(pollH)
	t.Cleanup(ts.Close)

	mk := func(seq uint64, rootByte byte) *entity.Entity {
		d := types.PublishedRootData{
			PeerID:      string(kp.PeerID()),
			RootHash:    fakeRoot(rootByte),
			Seq:         seq,
			PublishedAt: seq,
		}
		e, _ := d.ToEntity()
		return &e
	}
	_ = idEnt

	out := httplive.NewOutbound(types.HTTPPollProfileData{
		PeerID:        string(kp.PeerID()),
		TransportType: "http-poll",
		Endpoint: types.TransportEndpoint{
			TreeURLPrefix:    ts.URL,
			ContentURLPrefix: ts.URL + "/content",
			ContentLayout:    types.ContentLayoutFlat,
		},
	}, httplive.WithOutboundAllowHTTP(true))

	currentManifest = mk(5, 0xAA)
	if _, err := out.FetchPublishedRoot(context.Background()); err != nil {
		t.Fatalf("seq=5 fetch: %v", err)
	}
	// Roll back to seq=3 — must reject.
	currentManifest = mk(3, 0xBB)
	_, err := out.FetchPublishedRoot(context.Background())
	if err == nil {
		t.Fatal("seq=3 after seq=5 must reject per §3-RES.4 rollback discipline")
	}
	if !strings.Contains(err.Error(), "rollback") &&
		!strings.Contains(err.Error(), "seq") {
		t.Fatalf("error %q does not name the rollback / seq gate", err)
	}
	// Equal seq is allowed (republish on timer).
	currentManifest = mk(5, 0xAA)
	if _, err := out.FetchPublishedRoot(context.Background()); err != nil {
		t.Fatalf("seq=5 republish: %v", err)
	}
}

func TestOutboundFetchContent_HashVerified(t *testing.T) {
	f := newOutboundFixture(t)
	if _, err := f.publisher.Publish(fakeRoot(0x01)); err != nil {
		t.Fatalf("publish: %v", err)
	}

	out := httplive.NewOutbound(f.profile(),
		httplive.WithOutboundAllowHTTP(true),
		httplive.WithPinnedIdentity(f.identity),
	)
	pr, err := out.FetchPublishedRoot(context.Background())
	if err != nil {
		t.Fatalf("FetchPublishedRoot: %v", err)
	}

	got, err := out.FetchContent(context.Background(), pr.Entity.ContentHash)
	if err != nil {
		t.Fatalf("FetchContent: %v", err)
	}
	if got.Type != types.TypePeerPublishedRoot {
		t.Fatalf("got type %s", got.Type)
	}
	if got.ContentHash != pr.Entity.ContentHash {
		t.Fatal("content hash drift")
	}
}

func TestOutboundFetchContent_RejectsHostBytesDistrust(t *testing.T) {
	// §1.1 threat-model gate: a malicious host serves bytes whose hash does
	// NOT match the requested hash. FetchContent MUST reject.
	entA, _ := entity.NewEntity("test/a", []byte{0xa1, 0x01, 0x02})
	entB, _ := entity.NewEntity("test/b", []byte{0xa1, 0x03, 0x04})

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Always serve entA's bytes regardless of what the consumer asked for.
		if strings.HasPrefix(r.URL.Path, "/content/") {
			body, _ := cbor.Marshal(entA)
			w.Header().Set("Content-Type", "application/cbor")
			w.WriteHeader(http.StatusOK)
			w.Write(body)
			return
		}
		http.NotFound(w, r)
	}))
	defer ts.Close()

	kp, _ := crypto.Generate()
	out := httplive.NewOutbound(types.HTTPPollProfileData{
		PeerID:        string(kp.PeerID()),
		TransportType: "http-poll",
		Endpoint: types.TransportEndpoint{
			TreeURLPrefix:    ts.URL,
			ContentURLPrefix: ts.URL + "/content",
			ContentLayout:    types.ContentLayoutFlat,
		},
	}, httplive.WithOutboundAllowHTTP(true))

	// Ask for entB by hash — host serves entA's bytes. Must reject.
	_, err := out.FetchContent(context.Background(), entB.ContentHash)
	if err == nil {
		t.Fatal("FetchContent should have rejected wrong-bytes response")
	}
	if !strings.Contains(err.Error(), "hash") {
		t.Fatalf("expected hash mismatch error, got: %v", err)
	}
}

func TestOutboundFetchPublishedRoot_PinnedMismatchRejects(t *testing.T) {
	// A consumer pinning identity X must reject a manifest signed by Y.
	f := newOutboundFixture(t)
	if _, err := f.publisher.Publish(fakeRoot(0x44)); err != nil {
		t.Fatalf("publish: %v", err)
	}
	otherKP, _ := crypto.Generate()
	otherID, _ := otherKP.IdentityEntity()

	out := httplive.NewOutbound(f.profile(),
		httplive.WithOutboundAllowHTTP(true),
		httplive.WithPinnedIdentity(otherID),
	)
	_, err := out.FetchPublishedRoot(context.Background())
	if err == nil {
		t.Fatal("identity mismatch must surface as error")
	}
	if !strings.Contains(err.Error(), "pinned identity") &&
		!strings.Contains(err.Error(), "peer_id") {
		t.Fatalf("error %q does not name the mismatched pin", err)
	}
}

// fakeRoot returns a deterministic SHA-256 hash for fixture use.
func fakeRoot(b byte) hash.Hash {
	var h hash.Hash
	h.Algorithm = hash.AlgorithmSHA256
	h.Digest[0] = b
	return h
}
