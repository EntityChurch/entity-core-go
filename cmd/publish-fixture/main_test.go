package main

import (
	"strings"
	"testing"

	"go.entitychurch.org/entity-core-go/core/hash"
	"go.entitychurch.org/entity-core-go/core/tree"
)

// TestPublishedRootResolvesEveryKey is the teeth for B4 half-2: the published
// root must resolve every served key when walked BY ITS HASH — the consumer's
// terminal operation, not the last hop of a producer-convenient probe.
//
// The go-self consumer (cmd/fetch-published-fixture) resolves leaves through
// FetchTreeLeafPointer, a PATH-index lookup served straight from `li` — so it
// never walks the signed root trie and could not see an empty one. browser-rust
// walks the root by hash and resolved zero keys: the publisher built the trie
// through the raw `li` while the entries were written through `nli`, so the two
// disagreed about key space and BuildTrieForPrefix silently produced the
// canonical EMPTY root. This test walks the actual published root closure out
// of the same content store the poll handler serves, exactly as a by-hash
// consumer does, and asserts each key resolves to its authored leaf.
//
// RED with the pre-fix `li` (0 bindings under the empty root); GREEN with `nli`.
func TestPublishedRootResolvesEveryKey(t *testing.T) {
	_, cs, kp, _, root, leafHashes, err := buildPublisher()
	if err != nil {
		t.Fatalf("buildPublisher: %v", err)
	}

	// The consumer's terminal operation: resolve keys by walking the SIGNED
	// root trie from the content store, keyed by hash — no path index.
	bindings := tree.CollectAllBindings(cs, root, "")
	if len(bindings) != len(fixtureEntries) {
		t.Fatalf("published root resolves %d keys, want %d — an empty/short root walked to Absent (bindings=%v)",
			len(bindings), len(fixtureEntries), bindings)
	}

	// Each authored entry, stripped of the PrefixForLocalPeer the trie is
	// rooted at, must resolve to its authored leaf hash.
	for i, e := range fixtureEntries {
		relKey := strings.TrimPrefix(e.peerRelativePath, "system/")
		got, ok := bindings[relKey]
		if !ok {
			t.Fatalf("key %q not resolved from published root %s (peer=%s)", relKey, root, kp.PeerID())
		}
		if got != leafHashes[i] {
			t.Fatalf("key %q resolves to %s, want authored leaf %s", relKey, got, leafHashes[i])
		}
	}
}

// TestPublishedRootWalkDiscriminates is the negative control: the walk above is
// only evidence if it can also come up empty. A root hash the store does not
// carry (and the canonical empty root) must resolve zero keys — proving a
// full-count PASS above is the trie's content, not the walker always finding
// something. (browser-rust's B4 ratchet: a proof needs a negative control that
// shows it discriminates.)
func TestPublishedRootWalkDiscriminates(t *testing.T) {
	_, cs, _, _, root, _, err := buildPublisher()
	if err != nil {
		t.Fatalf("buildPublisher: %v", err)
	}

	// A hash that is not a stored node → LoadTrieNode misses → 0 bindings.
	var bogus hash.Hash
	bogus = root
	bogus.Digest[0] ^= 0xFF // flip a bit: no such node in cs
	if n := len(tree.CollectAllBindings(cs, bogus, "")); n != 0 {
		t.Fatalf("walk of a non-existent root resolved %d keys, want 0 — the walk does not discriminate", n)
	}

	// The canonical empty root (what the bug produced) must also resolve 0.
	empty, err := tree.BuildTrie(cs, nil)
	if err != nil {
		t.Fatalf("BuildTrie(nil): %v", err)
	}
	if n := len(tree.CollectAllBindings(cs, empty, "")); n != 0 {
		t.Fatalf("canonical empty root resolved %d keys, want 0", n)
	}
}
