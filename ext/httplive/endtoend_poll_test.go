// Go-only end-to-end for the Chunk E content GET — verifies the
// same pin-matrix rows the cross-impl harness checks, but in-process
// (no env setup, no other impls). Acts as the convergence baseline:
// when the cross-impl test runs against Go's listener, this is the
// behavior it asserts equality against.

package httplive_test

import (
	"encoding/hex"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"go.entitychurch.org/entity-core-go/core/ecf"
	"go.entitychurch.org/entity-core-go/core/entity"
	"go.entitychurch.org/entity-core-go/core/hash"
	"go.entitychurch.org/entity-core-go/core/store"
	"go.entitychurch.org/entity-core-go/core/types"
	"go.entitychurch.org/entity-core-go/core/crypto"
	"go.entitychurch.org/entity-core-go/ext/httplive"
)

func TestPoll_EndToEnd_Go(t *testing.T) {
	cs := store.NewMemoryContentStore()
	li := store.NewMemoryLocationIndex()
	const ns = "system/content/public"

	// Seed a chunk + bind it in the namespace — the operator-side
	// publish ceremony in microcosm. The Hash Tree Presence binding
	// at NS/{hex(H)} is what NamespaceScope checks.
	payload := []byte("Chunk E end-to-end payload — published in the public namespace.")
	ent, err := types.ContentChunkData{Payload: payload}.ToEntity()
	if err != nil {
		t.Fatalf("ContentChunkData.ToEntity: %v", err)
	}
	H, err := cs.Put(ent)
	if err != nil {
		t.Fatalf("cs.Put: %v", err)
	}
	bindingPath := ns + "/" + hex.EncodeToString(H.Bytes())
	if err := li.Set(bindingPath, H); err != nil {
		t.Fatalf("li.Set: %v", err)
	}

	// Mount the poll handler under an httptest server. Posture 1 —
	// empty prefix; routes top-level.
	// testPeerID lives in poll_test.go; Amendment 5 requires a peer-id on
	// the handler since tree URLs are peer-id-keyed.
	pollH := httplive.NewPollHandler("", cs, li, httplive.NamespaceScope{
		Index:     li,
		Namespace: ns,
	}, crypto.PeerID(testPeerID))
	ts := httptest.NewServer(pollH)
	defer ts.Close()

	hexH := hex.EncodeToString(H.Bytes())

	// Pin 1 — 200 + body re-hashes to URL hash.
	resp, err := http.Get(ts.URL + "/content/" + hexH)
	if err != nil {
		t.Fatalf("GET hit: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("hit status: got %d want 200", resp.StatusCode)
	}

	// Pin 4 — Content-Type.
	if ct := resp.Header.Get("Content-Type"); ct != "application/cbor" {
		t.Errorf("Content-Type: got %q want application/cbor", ct)
	}

	// Pin 5 — Cache-Control immutable + ETag.
	if cc := resp.Header.Get("Cache-Control"); !strings.Contains(cc, "immutable") {
		t.Errorf("Cache-Control: got %q want substring 'immutable'", cc)
	}
	wantETag := `"` + hexH + `"`
	if et := resp.Header.Get("ETag"); et != wantETag {
		t.Errorf("ETag: got %q want %q", et, wantETag)
	}

	// Body re-hash invariant.
	var got entity.Entity
	if err := ecf.Decode(body, &got); err != nil {
		t.Fatalf("decode entity: %v", err)
	}
	if err := hash.Validate(got.Type, got.Data, H); err != nil {
		t.Errorf("body hash invariant failed: %v", err)
	}

	// Pin 2/3 — out-of-scope (stored but not bound) → identical 404.
	// Stash a second chunk; do NOT bind it.
	otherPayload := []byte("not published — should 404")
	otherEnt, _ := types.ContentChunkData{Payload: otherPayload}.ToEntity()
	otherH, _ := cs.Put(otherEnt)
	otherHex := hex.EncodeToString(otherH.Bytes())
	respMiss, err := http.Get(ts.URL + "/content/" + otherHex)
	if err != nil {
		t.Fatalf("GET miss: %v", err)
	}
	respMiss.Body.Close()
	if respMiss.StatusCode != http.StatusNotFound {
		t.Errorf("out-of-scope status: got %d want 404", respMiss.StatusCode)
	}

	// Pin 6 — malformed.
	respBad, _ := http.Get(ts.URL + "/content/not-real-hex-deadbeef")
	respBad.Body.Close()
	if respBad.StatusCode != http.StatusBadRequest {
		t.Errorf("malformed status: got %d want 400", respBad.StatusCode)
	}

	// Pin 8 — POST on content route → 405 Allow:GET.
	respPost, _ := http.Post(ts.URL+"/content/"+hexH, "application/octet-stream", strings.NewReader(""))
	respPost.Body.Close()
	if respPost.StatusCode != http.StatusMethodNotAllowed {
		t.Errorf("POST status: got %d want 405", respPost.StatusCode)
	}
	if a := respPost.Header.Get("Allow"); a != "GET" {
		t.Errorf("Allow: got %q want GET", a)
	}

	// Recover original payload from served entity — the v1 wire
	// contract: chunk payload is one CBOR field decode away.
	var roundTrip types.ContentChunkData
	if err := ecf.Decode(got.Data, &roundTrip); err != nil {
		t.Fatalf("decode chunk payload: %v", err)
	}
	if string(roundTrip.Payload) != string(payload) {
		t.Errorf("payload round-trip: got %q want %q", roundTrip.Payload, payload)
	}
}
