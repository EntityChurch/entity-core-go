// Tests for the Amendment 5 poll surface. Covers the named-object
// addressing (`.bin`/`.list` suffixes), the literal-or-peer-id-parse
// demux, the universal-tree-root listing (`peers.list`), and the
// status-code discipline (no 501, no 3xx, %2F → 400).

package httplive_test

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"go.entitychurch.org/entity-core-go/core/crypto"
	"go.entitychurch.org/entity-core-go/core/ecf"
	"go.entitychurch.org/entity-core-go/core/entity"
	"go.entitychurch.org/entity-core-go/core/hash"
	"go.entitychurch.org/entity-core-go/core/store"
	"go.entitychurch.org/entity-core-go/core/types"
	"go.entitychurch.org/entity-core-go/ext/httplive"
)

// testPeerID is a base58-shaped string of length ≥46 — passes
// looksLikePeerIDSegment without needing a real keypair. Real peers use
// crypto.Generate(), but unit tests want a deterministic value.
const testPeerID = "2KZwKoRbLJrTs1T8bYbivCnHuW2fXsChasyXM8wB1SzH1b"

// pollFixture wires a content-store + location-index + scope into a
// PollHandler mounted on an httptest server. Returns the URL the handler
// is reachable at.
type pollFixture struct {
	store  store.ContentStore
	index  store.LocationIndex
	server *httptest.Server
	url    string
}

func newPollFixture(t *testing.T, prefix string, scopeFn func(idx store.LocationIndex) httplive.ScopePredicate) *pollFixture {
	t.Helper()
	cs := store.NewMemoryContentStore()
	li := store.NewMemoryLocationIndex()
	scope := scopeFn(li)
	h := httplive.NewPollHandler(prefix, cs, li, scope, crypto.PeerID(testPeerID))
	ts := httptest.NewServer(h)
	t.Cleanup(ts.Close)
	return &pollFixture{
		store:  cs,
		index:  li,
		server: ts,
		url:    ts.URL,
	}
}

// putChunk creates a content/chunk entity, stores it, and returns its hash.
func putChunk(t *testing.T, cs store.ContentStore, payload []byte) hash.Hash {
	t.Helper()
	ent, err := types.ContentChunkData{Payload: payload}.ToEntity()
	if err != nil {
		t.Fatalf("ContentChunkData.ToEntity: %v", err)
	}
	h, err := cs.Put(ent)
	if err != nil {
		t.Fatalf("store.Put: %v", err)
	}
	return h
}

// bindNamespace records H at "{namespace}/{hex(H)}" in the index — the
// CONTENT §6.4.2 Hash Tree Presence shape NamespaceScope looks for.
func bindNamespace(t *testing.T, idx store.LocationIndex, namespace string, h hash.Hash) {
	t.Helper()
	path := strings.TrimRight(namespace, "/") + "/" + hex.EncodeToString(h.Bytes())
	if err := idx.Set(path, h); err != nil {
		t.Fatalf("index.Set: %v", err)
	}
}

// --- CONTENT_GET — unchanged by Amendment 5 ---

func TestPoll_ContentGet_NamespaceScope_HitReturnsHashableBytes(t *testing.T) {
	const ns = "system/content/public"
	fx := newPollFixture(t, "", func(idx store.LocationIndex) httplive.ScopePredicate {
		return httplive.NamespaceScope{Index: idx, Namespace: ns}
	})

	payload := []byte("hello, public world")
	h := putChunk(t, fx.store, payload)
	bindNamespace(t, fx.index, ns, h)

	url := fx.url + "/content/" + hex.EncodeToString(h.Bytes())
	resp, err := http.Get(url)
	if err != nil {
		t.Fatalf("GET %s: %v", url, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status: got %d want 200", resp.StatusCode)
	}
	if ct := resp.Header.Get("Content-Type"); ct != "application/cbor" {
		t.Errorf("Content-Type: got %q want application/cbor", ct)
	}
	if cc := resp.Header.Get("Cache-Control"); !strings.Contains(cc, "immutable") {
		t.Errorf("Cache-Control: got %q want substring 'immutable'", cc)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	if sum := sha256.Sum256(body); !bytes.Equal(sum[:], h.EffectiveDigest()) {
		t.Errorf("SHA-256(body) != H.digest — pure-body-rehash invariant broken")
	}

	var got entity.Entity
	if err := ecf.Decode(body, &got); err != nil {
		t.Fatalf("decode hashable: %v", err)
	}
	if got.Type != types.TypeContentChunk {
		t.Errorf("type: got %q want %q", got.Type, types.TypeContentChunk)
	}
	if !got.ContentHash.IsZero() {
		t.Errorf("body carries content_hash — bare hashable form MUST NOT include it")
	}
}

func TestPoll_ContentGet_OutOfScope_404(t *testing.T) {
	const ns = "system/content/public"
	fx := newPollFixture(t, "", func(idx store.LocationIndex) httplive.ScopePredicate {
		return httplive.NamespaceScope{Index: idx, Namespace: ns}
	})
	private := putChunk(t, fx.store, []byte("secret"))
	resp, err := http.Get(fx.url + "/content/" + hex.EncodeToString(private.Bytes()))
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("status: got %d want 404", resp.StatusCode)
	}
}

func TestPoll_ContentGet_MalformedHashReturns400(t *testing.T) {
	fx := newPollFixture(t, "", func(idx store.LocationIndex) httplive.ScopePredicate {
		return httplive.WholeStoreScope{}
	})
	cases := []struct {
		name, hex string
	}{
		{"too short", "deadbeef"},
		{"digest-only 64", strings.Repeat("aa", hash.DigestSize)},
		{"too long", strings.Repeat("aa", hash.HashSize+1)},
		{"not hex", strings.Repeat("zz", hash.HashSize)},
		{"unknown algorithm byte", "ff" + strings.Repeat("aa", hash.DigestSize)},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			resp, err := http.Get(fx.url + "/content/" + c.hex)
			if err != nil {
				t.Fatalf("GET: %v", err)
			}
			resp.Body.Close()
			if resp.StatusCode != http.StatusBadRequest {
				t.Errorf("status: got %d want 400", resp.StatusCode)
			}
		})
	}
}

func TestPoll_ContentGet_PostReturns405WithAllowGET(t *testing.T) {
	fx := newPollFixture(t, "", func(idx store.LocationIndex) httplive.ScopePredicate {
		return httplive.WholeStoreScope{}
	})
	h := putChunk(t, fx.store, []byte("x"))
	resp, err := http.Post(fx.url+"/content/"+hex.EncodeToString(h.Bytes()), "application/octet-stream", strings.NewReader("x"))
	if err != nil {
		t.Fatalf("POST: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusMethodNotAllowed {
		t.Errorf("status: got %d want 405", resp.StatusCode)
	}
	if allow := resp.Header.Get("Allow"); allow != "GET" {
		t.Errorf("Allow: got %q want GET", allow)
	}
}

// --- TREE_GET — Amendment 5 named-object addressing ---

func TestPoll_TreeEntity_LeafSuffix_200(t *testing.T) {
	const ns = "system/content/public"
	fx := newPollFixture(t, "", func(idx store.LocationIndex) httplive.ScopePredicate {
		return httplive.NamespaceScope{Index: idx, Namespace: ns}
	})
	payload := []byte("welcome entity")
	h := putChunk(t, fx.store, payload)
	bindNamespace(t, fx.index, ns, h)
	if err := fx.index.Set("/"+testPeerID+"/system/content/public/welcome", h); err != nil {
		t.Fatalf("index.Set: %v", err)
	}

	// Amendment 5: GET /{peer_id}/{path}.bin → entity at {path}.
	url := fx.url + "/" + testPeerID + "/system/content/public/welcome.bin"
	resp, err := http.Get(url)
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status: got %d want 200 (url=%s)", resp.StatusCode, url)
	}
	if ct := resp.Header.Get("Content-Type"); ct != "application/cbor" {
		t.Errorf("Content-Type: got %q want application/cbor", ct)
	}
	if cc := resp.Header.Get("Cache-Control"); cc != "" {
		t.Errorf("Cache-Control on tree entity: got %q want empty (mutable bindings)", cc)
	}
	wantETag := `"` + hex.EncodeToString(h.Bytes()) + `"`
	if et := resp.Header.Get("ETag"); et != wantETag {
		t.Errorf("ETag: got %q want %q", et, wantETag)
	}
}

func TestPoll_TreeEntity_NoSuffix_404(t *testing.T) {
	const ns = "system/content/public"
	fx := newPollFixture(t, "", func(idx store.LocationIndex) httplive.ScopePredicate {
		return httplive.NamespaceScope{Index: idx, Namespace: ns}
	})
	h := putChunk(t, fx.store, []byte("x"))
	bindNamespace(t, fx.index, ns, h)
	if err := fx.index.Set("/"+testPeerID+"/system/content/public/welcome", h); err != nil {
		t.Fatalf("index.Set: %v", err)
	}

	// Bare no-suffix path → 404 (Amendment 5: leaf MUST carry its suffix).
	url := fx.url + "/" + testPeerID + "/system/content/public/welcome"
	resp, err := http.Get(url)
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("status: got %d want 404", resp.StatusCode)
	}
}

func TestPoll_TreeListing_ListSuffix_200(t *testing.T) {
	const ns = "system/content/public"
	fx := newPollFixture(t, "", func(idx store.LocationIndex) httplive.ScopePredicate {
		return httplive.NamespaceScope{Index: idx, Namespace: ns}
	})
	// Seed two in-scope children + one out-of-scope sibling.
	hA := putChunk(t, fx.store, []byte("a"))
	hB := putChunk(t, fx.store, []byte("b"))
	hPriv := putChunk(t, fx.store, []byte("private"))
	bindNamespace(t, fx.index, ns, hA)
	bindNamespace(t, fx.index, ns, hB)
	// fx.index.Set without bindNamespace → not in scope:
	if err := fx.index.Set("/"+testPeerID+"/system/content/public/alpha", hA); err != nil {
		t.Fatal(err)
	}
	if err := fx.index.Set("/"+testPeerID+"/system/content/public/beta", hB); err != nil {
		t.Fatal(err)
	}
	if err := fx.index.Set("/"+testPeerID+"/system/content/public/secret", hPriv); err != nil {
		t.Fatal(err)
	}

	// Amendment 5: GET /{peer_id}/system/content/public.list → listing of
	// direct children. Scope-gated: secret (out-of-scope hash) is filtered.
	url := fx.url + "/" + testPeerID + "/system/content/public.list"
	resp, err := http.Get(url)
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status: got %d want 200", resp.StatusCode)
	}
	if ct := resp.Header.Get("Content-Type"); ct != "application/cbor" {
		t.Errorf("Content-Type: got %q want application/cbor", ct)
	}
	if cc := resp.Header.Get("Cache-Control"); cc != "" {
		t.Errorf("Cache-Control on listing: got %q want empty (mutable)", cc)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	var ent entity.Entity
	if err := ecf.Decode(body, &ent); err != nil {
		t.Fatalf("decode listing entity: %v", err)
	}
	if ent.Type != types.TypeTreeListing {
		t.Errorf("entity type: got %q want %q", ent.Type, types.TypeTreeListing)
	}
	ld, err := types.ListingDataFromEntity(ent)
	if err != nil {
		t.Fatalf("decode ListingData: %v", err)
	}
	// alpha and beta are in scope; the §6.4.2 leaf-bindings themselves are
	// also in-scope siblings; secret is filtered.
	if _, ok := ld.Entries["alpha"]; !ok {
		t.Errorf("entries missing alpha")
	}
	if _, ok := ld.Entries["beta"]; !ok {
		t.Errorf("entries missing beta")
	}
	if _, ok := ld.Entries["secret"]; ok {
		t.Errorf("entries should NOT include out-of-scope secret (TREE §1176 filtered)")
	}
	if ld.Count != uint64(len(ld.Entries)) {
		t.Errorf("Count %d != len(Entries) %d — filtered count must match", ld.Count, len(ld.Entries))
	}
}

func TestPoll_TreeListing_EmptyInScope_200(t *testing.T) {
	// Amendment 5 Q2: in-scope prefix with no children → 200 + entries={} + count=0.
	// We achieve "in-scope but no children" by binding a parent entity at the
	// prefix itself with no children underneath.
	const ns = "system/content/public"
	fx := newPollFixture(t, "", func(idx store.LocationIndex) httplive.ScopePredicate {
		return httplive.WholeStoreScope{}
	})
	h := putChunk(t, fx.store, []byte("self"))
	if err := fx.index.Set("/"+testPeerID+"/system/content/public", h); err != nil {
		t.Fatal(err)
	}
	_ = ns

	url := fx.url + "/" + testPeerID + "/system/content/public.list"
	resp, err := http.Get(url)
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status: got %d want 200", resp.StatusCode)
	}
	body, _ := io.ReadAll(resp.Body)
	var ent entity.Entity
	if err := ecf.Decode(body, &ent); err != nil {
		t.Fatal(err)
	}
	ld, err := types.ListingDataFromEntity(ent)
	if err != nil {
		t.Fatal(err)
	}
	if ld.Count != 0 {
		t.Errorf("Count: got %d want 0", ld.Count)
	}
	if len(ld.Entries) != 0 {
		t.Errorf("Entries: got %d want 0", len(ld.Entries))
	}
}

func TestPoll_TreeListing_NonexistentPrefix_404(t *testing.T) {
	fx := newPollFixture(t, "", func(idx store.LocationIndex) httplive.ScopePredicate {
		return httplive.WholeStoreScope{}
	})
	// No bindings under /{peer_id}/does/not/exist → 404 (T4: indistinguishable
	// from out-of-scope).
	url := fx.url + "/" + testPeerID + "/does/not/exist.list"
	resp, err := http.Get(url)
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("status: got %d want 404", resp.StatusCode)
	}
}

func TestPoll_TreeRootListing_PeerIDDotList_200(t *testing.T) {
	// `{peer_id}.list` (no further path) — listing of the peer's tree root.
	fx := newPollFixture(t, "", func(idx store.LocationIndex) httplive.ScopePredicate {
		return httplive.WholeStoreScope{}
	})
	h := putChunk(t, fx.store, []byte("under-system"))
	if err := fx.index.Set("/"+testPeerID+"/system/handler/x", h); err != nil {
		t.Fatal(err)
	}

	url := fx.url + "/" + testPeerID + ".list"
	resp, err := http.Get(url)
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status: got %d want 200", resp.StatusCode)
	}
	body, _ := io.ReadAll(resp.Body)
	var ent entity.Entity
	if err := ecf.Decode(body, &ent); err != nil {
		t.Fatal(err)
	}
	ld, err := types.ListingDataFromEntity(ent)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := ld.Entries["system"]; !ok {
		t.Errorf("peer-root listing missing 'system' direct child; got entries=%v", ld.Entries)
	}
}

// --- universal-tree-root listing (peers.list) ---

// TestPoll_PeersList_MultiPeer is the test that pins Amendment 5's
// universal-tree-root listing semantic: when a peer holds bindings for
// multiple peer-ids (the normal case — sync, mirroring, etc.), peers.list
// surfaces every one of them. If this fails because of the NamespacedIndex
// canonicalization seam, you cannot publish the tree.
func TestPoll_PeersList_MultiPeer(t *testing.T) {
	const other1 = "2KbU1SwsiFbqrSU3CuXLuhYQKh1tdjW116vPtqYk6xvgsS"
	const other2 = "2KXjSkTvqZU8yp6HpaTmSzXhSxaqi5X7BAymXUugT1dtoj"
	fx := newPollFixture(t, "", func(idx store.LocationIndex) httplive.ScopePredicate {
		return httplive.WholeStoreScope{}
	})
	h := putChunk(t, fx.store, []byte("x"))
	if err := fx.index.Set("/"+testPeerID+"/system/handler/a", h); err != nil {
		t.Fatal(err)
	}
	if err := fx.index.Set("/"+other1+"/local/files/b", h); err != nil {
		t.Fatal(err)
	}
	if err := fx.index.Set("/"+other2+"/system/content/public/c", h); err != nil {
		t.Fatal(err)
	}

	resp, err := http.Get(fx.url + "/peers.list")
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status: got %d want 200", resp.StatusCode)
	}
	body, _ := io.ReadAll(resp.Body)
	var ent entity.Entity
	if err := ecf.Decode(body, &ent); err != nil {
		t.Fatal(err)
	}
	ld, err := types.ListingDataFromEntity(ent)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{testPeerID, other1, other2} {
		if _, ok := ld.Entries[want]; !ok {
			t.Errorf("peers.list missing peer-id %s; got entries=%v", want, ld.Entries)
		}
	}
	if ld.Count != uint64(len(ld.Entries)) {
		t.Errorf("Count %d != len(Entries) %d", ld.Count, len(ld.Entries))
	}
}

func TestPoll_PeersBareNoSuffix_404(t *testing.T) {
	// Amendment 5: bare `peers` (no suffix) is NOT a valid address.
	fx := newPollFixture(t, "", func(idx store.LocationIndex) httplive.ScopePredicate {
		return httplive.WholeStoreScope{}
	})
	resp, err := http.Get(fx.url + "/peers")
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("status: got %d want 404", resp.StatusCode)
	}
}

// --- manifest ---

func TestPoll_Manifest_None_404(t *testing.T) {
	// Amendment 5 status table: NO 501 in shipped peer. No manifest published
	// → 404.
	fx := newPollFixture(t, "", func(idx store.LocationIndex) httplive.ScopePredicate {
		return httplive.WholeStoreScope{}
	})
	resp, err := http.Get(fx.url + "/manifest")
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("status: got %d want 404 (no manifest published, never 501)", resp.StatusCode)
	}
}

func TestPoll_ManifestTrailingSlash_404(t *testing.T) {
	// Amendment 5: /manifest is terminal; /manifest/ → 404.
	fx := newPollFixture(t, "", func(idx store.LocationIndex) httplive.ScopePredicate {
		return httplive.WholeStoreScope{}
	})
	resp, err := http.Get(fx.url + "/manifest/")
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("status: got %d want 404", resp.StatusCode)
	}
}

// --- status-table edges ---

func TestPoll_PercentEncodedSlash_400(t *testing.T) {
	// Amendment 5 status table: %2F in a path segment is malformed.
	fx := newPollFixture(t, "", func(idx store.LocationIndex) httplive.ScopePredicate {
		return httplive.WholeStoreScope{}
	})
	req, _ := http.NewRequest("GET", fx.url+"/"+testPeerID+"/foo%2Fbar.bin", nil)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("status: got %d want 400 (%%2F in path)", resp.StatusCode)
	}
}

func TestPoll_UnknownFirstSegment_404(t *testing.T) {
	fx := newPollFixture(t, "", func(idx store.LocationIndex) httplive.ScopePredicate {
		return httplive.WholeStoreScope{}
	})
	resp, err := http.Get(fx.url + "/nope")
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("status: got %d want 404", resp.StatusCode)
	}
}

func TestPoll_PrefixMount_RoutesUnderPrefix(t *testing.T) {
	// Posture 2 — mount under "/poll" prefix.
	const ns = "system/content/public"
	fx := newPollFixture(t, "/poll", func(idx store.LocationIndex) httplive.ScopePredicate {
		return httplive.NamespaceScope{Index: idx, Namespace: ns}
	})
	h := putChunk(t, fx.store, []byte("prefix-mount"))
	bindNamespace(t, fx.index, ns, h)
	hx := hex.EncodeToString(h.Bytes())

	resp, err := http.Get(fx.url + "/poll/content/" + hx)
	if err != nil {
		t.Fatalf("GET prefixed: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("status: got %d want 200 (prefixed)", resp.StatusCode)
	}

	resp2, err := http.Get(fx.url + "/content/" + hx)
	if err != nil {
		t.Fatalf("GET bare: %v", err)
	}
	resp2.Body.Close()
	if resp2.StatusCode != http.StatusNotFound {
		t.Errorf("bare status: got %d want 404", resp2.StatusCode)
	}
}
