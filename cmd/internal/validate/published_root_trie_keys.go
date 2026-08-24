// v8 — the trie-key convention vector. Closes the oracle hole rust reported
// on 2026-08-08.
//
// # Why this exists
//
// The 2026-07-31 closure on the trie key convention read `published_root`
// 7·0·0·0 as evidence that the cohort's trie keys byte-match. They do not
// establish that. Auditing our own category confirms rust's reading:
//
//   - v2 / v5 verify a SIGNATURE over the root hash.
//   - v7 CONTENT_GETs `root_hash` and asserts the entity TYPE is a snapshot
//     node.
//
// Neither resolves a key, and no other vector in any Go category walks a path
// from a published root. A green published_root category was therefore
// consistent with two impls whose trie keys disagree completely — which is
// exactly the state the cohort turned out to be in (Go tracks `system/`, rust
// tracks the universal `/`). The oracle encoded Go's reading and could not
// falsify it, because Go's writer and reader share the assumption.
//
// # What this vector actually proves
//
// It mirrors the served trie over the wire, collects every (relative_key →
// value_hash) pair, and REBUILDS the trie locally from those pairs. The
// rebuilt root hash MUST equal the served `root_hash`.
//
// That single equality is a complete structural check of EXTENSION-TREE §3.3
// and §3.1, and every clause it covers is a MUST:
//
//   - routing is SHA-256(canonical-normalize(relative_key)) — an impl that
//     hashed the ABSOLUTE path (the §3.3 named ambiguity, and the literal
//     purpose of conformance fixture #2) routes to different positions and
//     the rebuild diverges;
//   - bitWidth = 5, bucketSize = 3 — pinned, MUST NOT be per-tree config;
//   - the canonical-form invariant and the bucket-sort invariant, which are
//     what make the same binding set produce the same root under arbitrary
//     insert/delete history.
//
// # What it deliberately does NOT prove — read this before trusting a PASS
//
// The rebuild takes its keys FROM THE TRIE, so it is self-consistent by
// construction with respect to the key form. An impl that keys the trie by
// the ABSOLUTE path rather than the relative_key rebuilds to its own root
// perfectly and PASSES — the one thing §3.3 names as the ambiguity to catch
// is the one thing this equality cannot see.
//
// That is why the observed key convention is classified and printed on every
// run, PASS included, with literal sample keys. The classification is the
// part that surfaces a wrong key form; the equality is the part that proves
// the routing algorithm. Neither substitutes for the other, and a reader who
// takes the PASS without reading the convention line has learned less than
// they think.
//
// Measured 2026-08-08 — three impls, three conventions, all three PASSing the
// equality:
//
//	Go      `system/`-relative   keys `attestation`, `peer/published-root/…`
//	rust    peer-relative        keys `system/attestation`, `local/files`
//	python  absolute             keys `/{peer_id}/system/signature/…`
//
// Go and rust differ by exactly the `system/` segment; python trims nothing.
// Routed to arch — see docs/validation/spec-issues/.
//
// # The prefix is not on the wire — see docs/validation/spec-issues/
//
// §3.3: `relative_key = trim_prefix(path, "/" + peer_id + "/" +
// operation_prefix)`, and "The prefix is an operational parameter ... not
// stored in the snapshot entity. Full paths are reconstructed by the
// consumer: `prefix + relative_key`."
//
// `system/peer/published-root` carries `root_hash` and no prefix. So a
// consumer holding a manifest has the keys but not the operand it needs to
// reconstruct a single path — and §3.4.1a makes both `"system/"` and the
// universal `"/"` valid choices. That is the root cause of the cohort
// divergence, and it is a spec gap rather than anyone's bug.

package validate

import (
	"context"
	"fmt"
	"sort"
	"strings"

	"go.entitychurch.org/entity-core-go/core/hash"
	"go.entitychurch.org/entity-core-go/core/store"
	"go.entitychurch.org/entity-core-go/core/tree"
	"go.entitychurch.org/entity-core-go/core/types"
	"go.entitychurch.org/entity-core-go/ext/httplive"
)

// mirrorTrieOverWire fetches the trie rooted at `root` through the peer's
// http-poll CONTENT_GET route into a local content store, following every
// link entry. Returns the mirror plus the number of nodes fetched.
//
// A missing node is a hard error, not a partial mirror: NETWORK §6.5.6
// Amendment 10 makes the transitive closure the served floor when a signed
// pointer is advertised, so a 404 mid-walk is itself the finding.
func mirrorTrieOverWire(ctx context.Context, out *httplive.Outbound, root hash.Hash) (store.ContentStore, int, error) {
	cs := store.NewMemoryContentStore()
	seen := map[hash.Hash]bool{}

	var walk func(h hash.Hash) error
	walk = func(h hash.Hash) error {
		if seen[h] {
			return nil
		}
		seen[h] = true

		ent, err := out.FetchContent(ctx, h)
		if err != nil {
			return fmt.Errorf("CONTENT_GET(%s): %w", h.String(), err)
		}
		if ent.Type != types.TypeTreeSnapshotNode {
			return fmt.Errorf("node %s has type %q, want %s", h.String(), ent.Type, types.TypeTreeSnapshotNode)
		}
		if _, err := cs.Put(ent); err != nil {
			return fmt.Errorf("mirror put %s: %w", h.String(), err)
		}
		node, ok := tree.LoadTrieNode(cs, h)
		if !ok {
			return fmt.Errorf("node %s did not decode as a snapshot node", h.String())
		}
		for _, e := range node.Data {
			if e.IsLink() {
				if err := walk(*e.Link); err != nil {
					return err
				}
			}
		}
		return nil
	}

	if err := walk(root); err != nil {
		return nil, 0, err
	}
	return cs, len(seen), nil
}

// classifyKeyConvention reports which prefix the observed keys appear to be
// relative to. Informational — §3.4.1a permits both — but it is what makes
// the cohort divergence visible in the run output instead of only in source.
func classifyKeyConvention(keys []string, peerID string) string {
	// Three shapes are observable, distinguished by what the key retains:
	//
	//	fully-qualified  `{peer_id}/system/...`  — nothing trimmed but the
	//	                                           leading slash
	//	peer-relative    `system/...`, `local/…` — `/{peer_id}/` trimmed; this
	//	                                           is the universal `/` prefix
	//	                                           (§3.4.1a: "all paths in the
	//	                                           peer's tree")
	//	system-relative  `attestation`, `peer/…` — `/{peer_id}/system/` trimmed
	//
	// The last two differ by exactly one path segment, which is why the
	// divergence survived a green category for as long as it did.
	universal, peerRel, systemRel := 0, 0, 0
	for _, k := range keys {
		switch {
		// Absolute form: the key still carries the leading `/` and a peer-id
		// segment, i.e. nothing was trimmed. §3.3 names exactly this as the
		// ambiguity conformance fixture #2 exists to catch ("relative-key vs
		// absolute-path"), so count it with the fully-qualified shape.
		case strings.HasPrefix(k, "/"):
			universal++
		case peerID != "" && strings.HasPrefix(k, peerID+"/"):
			universal++
		case strings.HasPrefix(k, "system/") || strings.HasPrefix(k, "local/"):
			peerRel++
		case strings.HasPrefix(k, "peer/") || strings.HasPrefix(k, "tree/") ||
			strings.HasPrefix(k, "content/") || strings.HasPrefix(k, "signature/") ||
			strings.HasPrefix(k, "attestation") || strings.HasPrefix(k, "capability"):
			systemRel++
		}
	}
	// Always carry a literal sample. A classifier that reports only its own
	// verdict is unfalsifiable by the reader — and the first cross-impl run
	// of this check returned "indeterminate" against rust, which told nobody
	// anything. The keys themselves are the evidence.
	sample := keys
	if len(sample) > 3 {
		sample = sample[:3]
	}
	verdict := "indeterminate"
	distinct := 0
	for _, n := range []int{universal, peerRel, systemRel} {
		if n > 0 {
			distinct++
		}
	}
	switch {
	case distinct > 1:
		verdict = fmt.Sprintf("MIXED — %d fully-qualified, %d peer-relative, %d system-relative keys in one trie",
			universal, peerRel, systemRel)
	case universal > 0:
		verdict = fmt.Sprintf("ABSOLUTE / fully-qualified `[/]{peer_id}/…` — nothing trimmed; §3.3 requires the SHA-256 input be the relative_key, NOT the absolute path (%d matched)", universal)
	case peerRel > 0:
		verdict = fmt.Sprintf("peer-relative — the universal `/` prefix, covering the whole peer tree incl. non-system subtrees (%d matched)", peerRel)
	case systemRel > 0:
		verdict = fmt.Sprintf("`system/`-relative — the `system/` prefix, which EXCLUDES non-system subtrees such as local/files (%d matched)", systemRel)
	}
	return fmt.Sprintf("%s; first keys %v", verdict, sample)
}

func runPublishedRootTrieKeys(ctx context.Context, pollURL string) CheckOutcome {
	if pollURL == "" {
		return SkipCheck("no -poll-url provided (start the peer with --publish-root + --http-poll-addr + --serve-closure-root, then pass -poll-url http://host:port)")
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
		return SkipCheck("peer served no published-root, so there is no trie to walk: " + err.Error())
	}
	if pr.Data.RootHash.IsZero() {
		return FailCheck("published-root.root_hash is zero — publisher misconfigured")
	}

	// Mirror the trie, tolerating a root advance underneath us.
	//
	// A peer that republishes on every tree-root change (which is the
	// contract) can retire the closure we are halfway through walking: the
	// manifest we read names root R, the peer advances to R', its closure
	// scope re-derives from R', and a node reachable only from R now 404s.
	// That is CORRECT behaviour, and reporting it as a §6.5.6 serving gap
	// would be a MUST-failure manufactured by our own timing.
	//
	// So on a mirror failure, re-read the manifest. If the root moved, the
	// walk raced and we retry against the new head. Only a 404 under a root
	// that did NOT move is a real closure gap.
	var mirror store.ContentStore
	var nodeCount int
	const mirrorAttempts = 3
	for attempt := 1; ; attempt++ {
		var err error
		mirror, nodeCount, err = mirrorTrieOverWire(ctx, out, pr.Data.RootHash)
		if err == nil {
			break
		}
		if attempt >= mirrorAttempts {
			return FailCheck(fmt.Sprintf(
				"could not mirror the trie from root_hash=%s after %d attempts, with the root stable across "+
					"retries: %v. NETWORK §6.5.6 Amendment 10 makes the transitive trie-node closure the served "+
					"floor once a signed pointer is advertised, so a node that will not fetch under a stable root "+
					"is a serving gap, not a harness race",
				pr.Data.RootHash.String(), attempt, err))
		}
		next, ferr := out.FetchPublishedRoot(ctx)
		if ferr != nil {
			return FailCheck(fmt.Sprintf(
				"mirror failed (%v) and the manifest could not be re-read to tell a root advance from a serving "+
					"gap: %v", err, ferr))
		}
		if next.Data.RootHash == pr.Data.RootHash {
			return FailCheck(fmt.Sprintf(
				"could not mirror the trie from root_hash=%s: %v. The root did NOT advance between the walk and "+
					"the re-read (seq %d both times), so this is not a race: a node inside the CURRENT signed "+
					"root's closure is not served. NETWORK §6.5.6 Amendment 10 makes that closure the served floor "+
					"once a signed pointer is advertised, and a consumer's §1.1 hash-chain walk halts here",
				pr.Data.RootHash.String(), err, pr.Data.Seq))
		}
		// Root advanced — retry against the new head.
		pr = next
	}

	bindings := tree.CollectAllBindings(mirror, pr.Data.RootHash, "")
	if len(bindings) == 0 {
		// An empty tree is conformant (the canonical empty-root node exists),
		// but it proves nothing about key routing — say so rather than
		// claiming a pass.
		return SkipCheck(fmt.Sprintf(
			"the served trie is empty (%d node(s) from root_hash=%s) — the key-routing MUST has nothing to "+
				"exercise. Seed a binding under the peer's tracked prefix and republish before scoring this",
			nodeCount, pr.Data.RootHash.String()))
	}

	// The MUST. Rebuild from the collected (relative_key → value_hash) pairs
	// with our own routing + canonical-form implementation. Equality proves
	// the peer routes by SHA-256(relative_key) under the pinned parameters
	// and maintains both canonical invariants.
	rebuilt := make([]tree.Binding, 0, len(bindings))
	keys := make([]string, 0, len(bindings))
	for k, v := range bindings {
		rebuilt = append(rebuilt, tree.Binding{Path: k, Hash: v})
		keys = append(keys, k)
	}
	sort.Strings(keys)

	rebuiltRoot, err := tree.BuildTrie(store.NewMemoryContentStore(), rebuilt)
	if err != nil {
		return FailCheck("rebuild trie from collected bindings: " + err.Error())
	}

	convention := classifyKeyConvention(keys, pr.Data.PeerID)

	if rebuiltRoot != pr.Data.RootHash {
		sample := keys
		if len(sample) > 5 {
			sample = sample[:5]
		}
		return FailCheck(fmt.Sprintf(
			"trie rebuilt from the served bindings hashes to %s, but the peer published root_hash=%s. "+
				"Same %d binding(s), same keys, different root — so the divergence is in HOW the trie is built, "+
				"not in what it contains. EXTENSION-TREE §3.3 pins every input: routing MUST be "+
				"SHA-256(canonical-normalize(relative_key)) — NOT the absolute path, the named ambiguity that "+
				"conformance fixture #2 exists to catch — with bitWidth=5 and bucketSize=3 fixed, plus the §3.1 "+
				"canonical-form and bucket-sort invariants. Observed key convention: %s. First keys: %v",
			rebuiltRoot.String(), pr.Data.RootHash.String(), len(bindings), convention, sample))
	}

	return PassCheck(fmt.Sprintf(
		"walked %d trie node(s) from the published root and rebuilt %d binding(s) to the identical root hash %s "+
			"— routing by SHA-256(relative_key), the pinned bitWidth/bucketSize, and both canonical invariants all "+
			"agree with this implementation. Observed key convention: %s (informational — §3.4.1a permits both "+
			"`system/` and the universal `/`, and published-root carries no prefix field, so a consumer cannot "+
			"reconstruct full paths from the manifest alone; see docs/validation/spec-issues/)",
		nodeCount, len(bindings), pr.Data.RootHash.String(), convention))
}
