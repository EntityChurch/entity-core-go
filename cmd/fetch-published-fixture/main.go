// fetch-published-fixture — cross-impl interop harness consumer (Go-side).
//
// Drives the Tier-1 published-root read flow against an external HTTP-poll
// origin URL — MANIFEST_GET → signature verify → TREE_GET (Amendment 6
// system/hash pointers) → CONTENT_GET → byte-equality. Asserts the
// contract written to stdout by cmd/publish-fixture/.
//
// This is the Go-side proof that the publisher contract holds end-to-end
// over real HTTP wire (not in-process). Rust and Python siblings own
// equivalent consumer drivers against the same publisher; cohort
// convergence = all three exit 0 against the same URL + pinned hashes.
//
// Usage:
//
//	fetch-published-fixture -url http://127.0.0.1:9301 \
//	  -peer-id 2KHcFAKPfQLw2ug7exu2mYTYAzPSKrWX2CsYY1cBVbBYJt
//
// Exit 0 on full PASS; 1 on first FAIL with a diagnostic to stderr.

package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/fxamacker/cbor/v2"

	"go.entitychurch.org/entity-core-go/core/crypto"
	"go.entitychurch.org/entity-core-go/core/entity"
	"go.entitychurch.org/entity-core-go/core/hash"
	"go.entitychurch.org/entity-core-go/core/types"
	"go.entitychurch.org/entity-core-go/ext/httplive"
)

// expected — the fixture entries the publisher writes. Kept in lockstep
// with cmd/publish-fixture/fixtureEntries.
var expected = []struct {
	path string
	typ  string
}{
	{"system/blog/post/entry-1", "test/blog/post/v1"},
	{"system/blog/post/entry-2", "test/blog/post/v1"},
	{"system/blog/post/entry-3", "test/blog/post/v1"},
}

// publisherSeed mirrors cmd/publish-fixture/. Used to derive the pinned
// identity locally when -peer-id is not supplied — saves a flag for the
// common case of running the Go-self leg.
var publisherSeed = [32]byte{
	'e', 'n', 't', 'i', 't', 'y', '-', 'c', 'o', 'r', 'e',
	'-', 'p', 'u', 'b', 'l', 'i', 's', 'h', '-', 'f', 'i',
	'x', 't', 'u', 'r', 'e', '-', 'v', '1', 0, 0,
}

func main() {
	url := flag.String("url", "", "publisher http-poll URL (e.g. http://127.0.0.1:9301)")
	peerIDFlag := flag.String("peer-id", "", "publisher peer-id (Base58); when empty, derive from the fixture seed")
	flag.Parse()

	if *url == "" {
		fail("url flag is required")
	}

	// Pin identity. For Go-self the fixture seed gives us the publisher
	// keypair directly; for cross-impl we'd accept -peer-id and load the
	// pubkey from a flag/file — but the cohort handoff doc pins the
	// publisher peer-id as a constant, so all consumers know it
	// out-of-band.
	kp := crypto.FromSeed(publisherSeed)
	identity, err := kp.IdentityEntity()
	if err != nil {
		fail("derive identity entity: " + err.Error())
	}
	if *peerIDFlag != "" && *peerIDFlag != string(kp.PeerID()) {
		fail(fmt.Sprintf("-peer-id %q ≠ fixture-seed-derived peer-id %q", *peerIDFlag, kp.PeerID()))
	}

	profile := types.HTTPPollProfileData{
		PeerID:        string(kp.PeerID()),
		TransportType: "http-poll",
		Endpoint: types.TransportEndpoint{
			TreeURLPrefix:    *url,
			ContentURLPrefix: *url + "/content",
			ContentLayout:    types.ContentLayoutFlat,
		},
		SupportedOps:  []string{types.OpTreeGet, types.OpContentGet, types.OpManifestGet},
		NonceRequired: false,
	}

	out := httplive.NewOutbound(profile,
		httplive.WithOutboundAllowHTTP(true),
		httplive.WithPinnedIdentity(identity),
		httplive.WithOutboundFetchTimeout(5*time.Second),
	)

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	// v1 + v2 — fetch manifest, signature must verify against pinned id.
	pr, err := out.FetchPublishedRoot(ctx)
	if err != nil {
		fail("FetchPublishedRoot: " + err.Error())
	}
	if pr.Entity.Type != types.TypePeerPublishedRoot {
		fail(fmt.Sprintf("manifest entity type %q != %s", pr.Entity.Type, types.TypePeerPublishedRoot))
	}
	if !pr.Verified {
		fail("Verified=false after pinned fetch — signature carriage / verify cycle broken")
	}
	if pr.Data.PeerID != string(kp.PeerID()) {
		fail(fmt.Sprintf("manifest PeerID %q != publisher %q", pr.Data.PeerID, kp.PeerID()))
	}
	pass(fmt.Sprintf("v1+v2: manifest served + signature verified (seq=%d root=%s)", pr.Data.Seq, pr.Data.RootHash))

	// v3 + v4 — for each path, fetch tree-leaf pointer + content + verify.
	leafHashes := make([]hash.Hash, len(expected))
	for i, e := range expected {
		ptr, err := out.FetchTreeLeafPointer(ctx, string(kp.PeerID()), e.path)
		if err != nil {
			fail(fmt.Sprintf("v3 FetchTreeLeafPointer %s: %v", e.path, err))
		}
		got, err := out.FetchContent(ctx, ptr)
		if err != nil {
			fail(fmt.Sprintf("v4 FetchContent %s (ptr=%s): %v", e.path, ptr, err))
		}
		if got.ContentHash != ptr {
			fail(fmt.Sprintf("v4 hash drift %s after re-hash: got %s want %s", e.path, got.ContentHash, ptr))
		}
		if got.Type != e.typ {
			fail(fmt.Sprintf("v4 type drift %s: got %q want %q", e.path, got.Type, e.typ))
		}
		leafHashes[i] = ptr
	}
	pass(fmt.Sprintf("v3+v4: resolved %d tree-leaf pointers + fetched + hash-verified", len(expected)))

	// v5 — byte-equality: the fetched .data is byte-identical to what an
	// independent caller authoring the same shape would produce. We
	// approximate by re-fetching once and asserting hash stability across
	// a second round (the publisher is deterministic).
	for i, e := range expected {
		got, err := out.FetchContent(ctx, leafHashes[i])
		if err != nil {
			fail(fmt.Sprintf("v5 re-fetch %s: %v", e.path, err))
		}
		if !bytesEqualEntity(got, expectedEntityAt(i)) {
			fail(fmt.Sprintf("v5 byte-equality drift at %s", e.path))
		}
	}
	pass(fmt.Sprintf("v5: byte-equality holds across %d entities", len(expected)))

	fmt.Println("ALL PASS")
}

// expectedEntityAt — author the fixture entry locally and compare against
// what the consumer received. Same code path as the publisher.
func expectedEntityAt(i int) entity.Entity {
	kvs := []struct{ k, v string }{}
	switch i {
	case 0:
		kvs = []struct{ k, v string }{{"body", "hello"}, {"title", "first"}}
	case 1:
		kvs = []struct{ k, v string }{{"body", "world"}, {"title", "second"}}
	case 2:
		kvs = []struct{ k, v string }{{"body", "fin"}, {"title", "third"}}
	}
	m := make(map[string]string, len(kvs))
	for _, kv := range kvs {
		m[kv.k] = kv.v
	}
	opts, _ := cbor.CoreDetEncOptions().EncMode()
	raw, _ := opts.Marshal(m)
	ent, _ := entity.NewEntity(expected[i].typ, raw)
	return ent
}

func bytesEqualEntity(a, b entity.Entity) bool {
	if a.Type != b.Type {
		return false
	}
	if len(a.Data) != len(b.Data) {
		return false
	}
	for i := range a.Data {
		if a.Data[i] != b.Data[i] {
			return false
		}
	}
	return a.ContentHash == b.ContentHash
}

func pass(msg string) {
	fmt.Fprintf(os.Stderr, "PASS  %s\n", msg)
}

func fail(msg string) {
	fmt.Fprintf(os.Stderr, "FAIL  %s\n", msg)
	os.Exit(1)
}
