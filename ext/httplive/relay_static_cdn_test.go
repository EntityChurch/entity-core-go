// Test #1b — truly-static CDN read-flow for the RELAY namespace.
//
// Closes the pre-release item (Item 3) per arch's batched-handoff ruling:
//
//   - The static-CDN Mode-S surface is **Mechanism A** (NETWORK §6.5
//     http-poll), NOT BRIDGE-HTTP. The prior "blocked on BRIDGE-HTTP"
//     framing was the two-HTTP-mechanisms conflation firing a third
//     time.
//   - The read flow already exists in ext/httplive (TREE_GET /
//     CONTENT_GET, §6.5.3.1). A truly-static CDN is read-only over the
//     protocol: the publisher writes to the static origin out-of-band
//     (S3 push / static deploy); the receiver polls + fetches.
//
// What this test exercises (and what it does not):
//
//   - Positive read flow: an out-of-band publisher binds a relay
//     store-entry + its inner envelope at the canonical §3.2 paths
//     (RelayStorePath / RelayInnerPath) and publishes a signed
//     published-root. A consumer Outbound, pinned to the publisher's
//     identity, fetches the manifest (sig-verified), reads the
//     tree-leaf pointer at each relay path, fetches the entity bytes
//     by hash, and hash-verifies each fetch.
//
//   - Mechanism A host-bytes-distrust: an alternate run swaps the
//     served bytes for unrelated content; FetchContent rejects on
//     hash mismatch (the trust gate that makes a truly-static origin
//     safe to read from).
//
// What this does NOT exercise: verified-tree-walk (hash-chain from
// signed root → leaf pointer). That trust escalation is a consumer-
// side concern documented in Outbound's package doc; this test
// confirms the wire flow + hash-verification gate, which is the slice
// arch named as exercisable today.

package httplive_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"go.entitychurch.org/entity-core-go/core/entity"
	"go.entitychurch.org/entity-core-go/core/store"
	"go.entitychurch.org/entity-core-go/core/types"
	"go.entitychurch.org/entity-core-go/ext/httplive"

	"github.com/fxamacker/cbor/v2"
)

func TestOutbound_RelayNamespace_StaticCDN_ReadFlow(t *testing.T) {
	f := newOutboundFixture(t)
	if _, err := f.publisher.Publish(fakeRoot(0x71)); err != nil {
		t.Fatalf("publish initial root: %v", err)
	}

	// Out-of-band publication of a relay store-entry + inner envelope at
	// the canonical §3.2 tree paths. A truly-static CDN deployment would
	// run this step as an S3 upload / static-deploy; in-process we drive
	// the publisher's content store + namespaced index directly.
	const namespace = "test-relay-ns-static-cdn"

	innerBytes, _ := cbor.Marshal(map[string]string{
		"opaque-inner-envelope": "this would be a real EXECUTE; the relay never decodes",
	})
	innerEnt, err := entity.NewEntity(types.TypeEnvelope, innerBytes)
	if err != nil {
		t.Fatalf("inner envelope NewEntity: %v", err)
	}

	entryData := types.StoreEntryData{
		Namespace:     namespace,
		PutBy:         string(f.kp.PeerID()),
		EnvelopeInner: innerEnt.ContentHash,
	}
	entryEnt, err := entryData.ToEntity()
	if err != nil {
		t.Fatalf("store-entry ToEntity: %v", err)
	}

	if _, err := f.cs.Put(innerEnt); err != nil {
		t.Fatalf("cs.Put inner: %v", err)
	}
	if _, err := f.cs.Put(entryEnt); err != nil {
		t.Fatalf("cs.Put store-entry: %v", err)
	}

	nli := store.NewNamespacedIndex(f.li, string(f.kp.PeerID()))
	entryPath := types.RelayStorePath(namespace, entryEnt.ContentHash)
	innerPath := types.RelayInnerPath(namespace, innerEnt.ContentHash)
	if err := nli.Set(entryPath, entryEnt.ContentHash); err != nil {
		t.Fatalf("nli.Set entry: %v", err)
	}
	if err := nli.Set(innerPath, innerEnt.ContentHash); err != nil {
		t.Fatalf("nli.Set inner: %v", err)
	}

	// Consumer: pinned-identity Outbound dialing the static origin.
	out := httplive.NewOutbound(f.profile(),
		httplive.WithOutboundAllowHTTP(true),
		httplive.WithPinnedIdentity(f.identity),
	)

	pr, err := out.FetchPublishedRoot(context.Background())
	if err != nil {
		t.Fatalf("FetchPublishedRoot: %v", err)
	}
	if !pr.Verified {
		t.Fatal("pinned identity provided; manifest signature MUST verify")
	}

	signerHex := string(f.kp.PeerID())

	entryPointer, err := out.FetchTreeLeafPointer(context.Background(), signerHex, entryPath)
	if err != nil {
		t.Fatalf("FetchTreeLeafPointer(entry): %v", err)
	}
	if entryPointer != entryEnt.ContentHash {
		t.Fatalf("entry pointer drift: got %s want %s", entryPointer, entryEnt.ContentHash)
	}

	gotEntry, err := out.FetchContent(context.Background(), entryPointer)
	if err != nil {
		t.Fatalf("FetchContent(entry): %v", err)
	}
	if gotEntry.Type != types.TypeRelayStoreEntry {
		t.Fatalf("entry type drift: got %q want %q", gotEntry.Type, types.TypeRelayStoreEntry)
	}
	if gotEntry.ContentHash != entryEnt.ContentHash {
		t.Fatalf("entry hash drift after fetch")
	}

	innerPointer, err := out.FetchTreeLeafPointer(context.Background(), signerHex, innerPath)
	if err != nil {
		t.Fatalf("FetchTreeLeafPointer(inner): %v", err)
	}
	if innerPointer != innerEnt.ContentHash {
		t.Fatalf("inner pointer drift: got %s want %s", innerPointer, innerEnt.ContentHash)
	}

	gotInner, err := out.FetchContent(context.Background(), innerPointer)
	if err != nil {
		t.Fatalf("FetchContent(inner): %v", err)
	}
	if gotInner.Type != types.TypeEnvelope {
		t.Fatalf("inner type drift: got %q want %q", gotInner.Type, types.TypeEnvelope)
	}
	if gotInner.ContentHash != innerEnt.ContentHash {
		t.Fatal("inner hash drift after fetch")
	}

	// Round-trip the decoded store-entry — proves the consumer can act on
	// the fetched bytes (resolve EnvelopeInner → the inner-envelope hash
	// it just fetched).
	decodedEntry, err := types.StoreEntryDataFromEntity(gotEntry)
	if err != nil {
		t.Fatalf("StoreEntryDataFromEntity: %v", err)
	}
	if decodedEntry.Namespace != namespace {
		t.Fatalf("namespace drift: got %q want %q", decodedEntry.Namespace, namespace)
	}
	if decodedEntry.EnvelopeInner != innerEnt.ContentHash {
		t.Fatalf("envelope_inner drift: got %s want %s", decodedEntry.EnvelopeInner, innerEnt.ContentHash)
	}
}

func TestOutbound_RelayNamespace_StaticCDN_HostBytesDistrust(t *testing.T) {
	// Mechanism A trust gate for relay-shaped content: a malicious or
	// corrupt static origin serves bytes whose hash does NOT match the
	// requested hash. FetchContent MUST reject.
	//
	// Specialization of TestOutboundFetchContent_RejectsHostBytesDistrust
	// to the relay store-entry shape — proves the gate fires regardless
	// of entity type and that no relay-specific path-shape leakage
	// undermines it.

	realInnerBytes, _ := cbor.Marshal(map[string]string{"real": "inner"})
	realInner, _ := entity.NewEntity(types.TypeEnvelope, realInnerBytes)
	realEntry, _ := types.StoreEntryData{
		Namespace:     "ns",
		PutBy:         "Qm-real-putter",
		EnvelopeInner: realInner.ContentHash,
	}.ToEntity()

	imposterBytes, _ := cbor.Marshal(map[string]string{"imposter": "bytes"})
	imposter, _ := entity.NewEntity(types.TypeEnvelope, imposterBytes)

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasPrefix(r.URL.Path, "/content/") {
			http.NotFound(w, r)
			return
		}
		// Host serves imposter bytes regardless of the requested hash.
		body, _ := cbor.Marshal(imposter)
		w.Header().Set("Content-Type", "application/cbor")
		w.WriteHeader(http.StatusOK)
		w.Write(body)
	}))
	defer ts.Close()

	out := httplive.NewOutbound(types.HTTPPollProfileData{
		PeerID:        "Qm-static-cdn-fake",
		TransportType: "http-poll",
		Endpoint: types.TransportEndpoint{
			TreeURLPrefix:    ts.URL,
			ContentURLPrefix: ts.URL + "/content",
			ContentLayout:    types.ContentLayoutFlat,
		},
	}, httplive.WithOutboundAllowHTTP(true))

	// Ask for the real entry by hash — host serves imposter bytes.
	_, err := out.FetchContent(context.Background(), realEntry.ContentHash)
	if err == nil {
		t.Fatal("FetchContent should have rejected wrong-bytes response for relay store-entry")
	}
	if !strings.Contains(err.Error(), "hash") {
		t.Fatalf("expected hash mismatch error, got: %v", err)
	}

	// Same gate fires for the inner envelope shape.
	_, err = out.FetchContent(context.Background(), realInner.ContentHash)
	if err == nil {
		t.Fatal("FetchContent should have rejected wrong-bytes response for inner envelope")
	}
	if !strings.Contains(err.Error(), "hash") {
		t.Fatalf("expected hash mismatch error, got: %v", err)
	}
}
