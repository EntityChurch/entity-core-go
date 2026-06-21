// publish-fixture — cross-impl interop harness publisher.
//
// Spins up an HTTP-poll publisher (Tier-1 NETWORK §6.5.3.1) with a fixed
// deterministic identity and a fixed deterministic blog tree, and exposes
// it on a real net.Listener (NOT httptest). The contract is reproducible
// across runs/hosts: every time this binary starts on the same flags, it
// publishes the same peer-id, identity-pubkey, root-hash, leaf hashes, and
// content bytes.
//
// Used as the publisher side of cross-impl publish→fetch wire drives:
// each cohort impl runs its own consumer against this URL and asserts
// byte-equality against the contract written to stdout at startup. The
// matching consumer is cmd/fetch-published-fixture/ for Go-self.
//
// Stays running until SIGINT/SIGTERM.

package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"

	"go.entitychurch.org/entity-core-go/core/crypto"
	"go.entitychurch.org/entity-core-go/core/entity"
	"go.entitychurch.org/entity-core-go/core/hash"
	"go.entitychurch.org/entity-core-go/core/store"
	"go.entitychurch.org/entity-core-go/core/tree"
	"go.entitychurch.org/entity-core-go/ext/httplive"
	"go.entitychurch.org/entity-core-go/ext/publishedroot"

	"github.com/fxamacker/cbor/v2"
)

// fixtureEntry — one authored entry in the deterministic blog tree.
// peerRelativePath is the path under /{peer_id}/ on the wire. data is
// hand-rolled CBOR so byte-equality assertions don't depend on Go-only
// serializer behavior — cohort impls mirror the literal bytes.
type fixtureEntry struct {
	peerRelativePath string
	entityType       string
	dataKV           []kv // deterministic order
}

type kv struct {
	k string
	v string
}

// Fixed deterministic seed for the publisher keypair. Same seed → same
// peer-id, same identity pubkey, same signature over the root → cohort
// consumers pin against the values in the cohort handoff doc.
var publisherSeed = [32]byte{
	'e', 'n', 't', 'i', 't', 'y', '-', 'c', 'o', 'r', 'e',
	'-', 'p', 'u', 'b', 'l', 'i', 's', 'h', '-', 'f', 'i',
	'x', 't', 'u', 'r', 'e', '-', 'v', '1', 0, 0,
}

// Fixed deterministic root hash. The trie-walk closure root_hash → leaves
// is NOT asserted by this fixture (that's a separate v7 trie-closure check);
// what we exercise is the wire flow + per-leaf hash verification — the
// slice arch named as the v1 gate.
var publishedRootHash = func() hash.Hash {
	var digest [hash.SHA256DigestSize]byte
	for i := range digest {
		digest[i] = byte(0xC0 + i)
	}
	return hash.NewSHA256(digest)
}()

// Authored fixture entries — same data every run.
var fixtureEntries = []fixtureEntry{
	{
		peerRelativePath: "system/blog/post/entry-1",
		entityType:       "test/blog/post/v1",
		dataKV:           []kv{{"body", "hello"}, {"title", "first"}},
	},
	{
		peerRelativePath: "system/blog/post/entry-2",
		entityType:       "test/blog/post/v1",
		dataKV:           []kv{{"body", "world"}, {"title", "second"}},
	},
	{
		peerRelativePath: "system/blog/post/entry-3",
		entityType:       "test/blog/post/v1",
		dataKV:           []kv{{"body", "fin"}, {"title", "third"}},
	},
}

func main() {
	addr := flag.String("addr", "127.0.0.1:9301", "HTTP listen address for the http-poll origin")
	flag.Parse()

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	pollH, kp, identity, leafHashes, err := buildPublisher()
	if err != nil {
		log.Fatalf("build publisher: %v", err)
	}

	listener, err := net.Listen("tcp", *addr)
	if err != nil {
		log.Fatalf("listen %s: %v", *addr, err)
	}
	defer listener.Close()
	bound := listener.Addr().String()
	url := "http://" + bound

	printContract(url, kp, identity, leafHashes)

	srv := &http.Server{Handler: pollH}
	go func() {
		<-ctx.Done()
		_ = srv.Close()
	}()
	if err := srv.Serve(listener); err != nil && err != http.ErrServerClosed {
		log.Fatalf("serve: %v", err)
	}
	log.Printf("shut down")
}

func buildPublisher() (*httplive.PollHandler, crypto.Keypair, entity.Entity, []hash.Hash, error) {
	cs := store.NewMemoryContentStore()
	li := store.NewMemoryLocationIndex()

	kp := crypto.FromSeed(publisherSeed)
	identity, err := kp.IdentityEntity()
	if err != nil {
		return nil, crypto.Keypair{}, entity.Entity{}, nil, fmt.Errorf("identity entity: %w", err)
	}
	if _, err := cs.Put(identity); err != nil {
		return nil, crypto.Keypair{}, entity.Entity{}, nil, fmt.Errorf("put identity: %w", err)
	}
	nli := store.NewNamespacedIndex(li, string(kp.PeerID()))

	tracker := tree.NewRootTracker(cs, string(kp.PeerID()), nil)
	pub := publishedroot.NewPublisher(cs, tracker, publishedroot.PrefixForLocalPeer, nil)
	if err := pub.SetupAuthority(nli, kp, identity, false); err != nil {
		return nil, crypto.Keypair{}, entity.Entity{}, nil, fmt.Errorf("setup authority: %w", err)
	}

	leafHashes := make([]hash.Hash, 0, len(fixtureEntries))
	for _, e := range fixtureEntries {
		raw, err := encodeFixtureData(e.dataKV)
		if err != nil {
			return nil, crypto.Keypair{}, entity.Entity{}, nil, fmt.Errorf("encode %s: %w", e.peerRelativePath, err)
		}
		ent, err := entity.NewEntity(e.entityType, raw)
		if err != nil {
			return nil, crypto.Keypair{}, entity.Entity{}, nil, fmt.Errorf("author %s: %w", e.peerRelativePath, err)
		}
		if _, err := cs.Put(ent); err != nil {
			return nil, crypto.Keypair{}, entity.Entity{}, nil, fmt.Errorf("cs.Put %s: %w", e.peerRelativePath, err)
		}
		if err := nli.Set(e.peerRelativePath, ent.ContentHash); err != nil {
			return nil, crypto.Keypair{}, entity.Entity{}, nil, fmt.Errorf("nli.Set %s: %w", e.peerRelativePath, err)
		}
		leafHashes = append(leafHashes, ent.ContentHash)
	}

	if _, err := pub.Publish(publishedRootHash); err != nil {
		return nil, crypto.Keypair{}, entity.Entity{}, nil, fmt.Errorf("publish root: %w", err)
	}

	pollH := httplive.NewPollHandler("", cs, li, httplive.WholeStoreScope{}, kp.PeerID())
	pollH.ManifestProvider = func() *entity.Entity {
		e, ok := pub.Current()
		if !ok {
			return nil
		}
		return e
	}
	return pollH, kp, identity, leafHashes, nil
}

// encodeFixtureData is deterministic CBOR encoding of a fixed-order map.
// Hand-rolled so byte-equality assertions across impls don't depend on a
// Go-only serializer.
func encodeFixtureData(items []kv) ([]byte, error) {
	m := make(map[string]string, len(items))
	for _, kv := range items {
		m[kv.k] = kv.v
	}
	opts, err := cbor.CoreDetEncOptions().EncMode()
	if err != nil {
		return nil, err
	}
	return opts.Marshal(m)
}

func printContract(url string, kp crypto.Keypair, identity entity.Entity, leafHashes []hash.Hash) {
	fmt.Printf("# publish-fixture contract (deterministic across runs)\n")
	fmt.Printf("url=%s\n", url)
	fmt.Printf("peer_id=%s\n", string(kp.PeerID()))
	fmt.Printf("key_type=%s\n", keyTypeName(kp.KeyType))
	fmt.Printf("identity_content_hash=%s\n", identity.ContentHash)
	fmt.Printf("published_root_hash=%s\n", publishedRootHash)
	for i, e := range fixtureEntries {
		fmt.Printf("entry[%d].path=%s\n", i, e.peerRelativePath)
		fmt.Printf("entry[%d].type=%s\n", i, e.entityType)
		fmt.Printf("entry[%d].content_hash=%s\n", i, leafHashes[i])
	}
	fmt.Printf("# ready — serving until SIGINT\n")
}

func keyTypeName(k byte) string {
	switch k {
	case crypto.KeyTypeEd25519:
		return "ed25519"
	case crypto.KeyTypeEd448:
		return "ed448"
	default:
		return fmt.Sprintf("0x%02x", k)
	}
}
