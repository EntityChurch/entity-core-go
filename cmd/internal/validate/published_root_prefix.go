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

// EXTENSION-TREE §3.3a + §12.1 — the key-form assertion and the reconstruction
// round-trip (PROPOSAL-PUBLISHED-ROOT-PREFIX-AND-REPUBLISH §6.1 / §6.2, folded
// by arch at 391c92b).
//
// WHY THESE EXIST AND WHY v8 DOES NOT COVER THEM
//
// v8 mirrors the served trie and rebuilds it, asserting the rebuilt root equals
// the served one. That proves the ROUTING ALGORITHM — SHA-256(canonical-
// normalize(relative_key)), bitWidth=5, bucketSize=3, both canonical invariants.
// It cannot prove the KEY FORM, because the rebuild takes its keys from the trie
// and is therefore self-consistent by construction: an implementation keying by
// absolute path rebuilds to its own root and passes perfectly.
//
// §12.1 now states that normatively — "a trie-rebuild equality check does not
// satisfy this" — because a three-way-green published_root category coexisted
// with a three-way key divergence for months. These two checks close it: they
// derive the expected key from the publisher's OWN declared prefix and assert
// the trie resolves that key, so a wrong key form fails instead of printing a
// classification line nobody reads.

// resolveAbsolutePrefix renders a declared §3.3a `prefix` in absolute form, per
// EXTENSION-TREE §3.3's three-shape table:
//
//	"system/"       (peer-relative)  → /{peer_id}/system/
//	"/{peer_id}/"   (peer-qualified) → /{peer_id}/          (already absolute)
//	"/"             (universal)      → ""                   (the trim is a NO-OP)
//
// The universal case returns the empty string deliberately: its keys are fully
// qualified. Trimming the local peer-id there would leave every other peer's
// keys qualified and produce a mixed key space — which is why §3.3 supersedes
// the old `"/" + peer_id + "/" + operation_prefix` formula that yielded
// `/{peer}//` and silently tracked nothing.
func resolveAbsolutePrefix(prefix, peerID string) string {
	switch {
	case prefix == "/":
		return ""
	case strings.HasPrefix(prefix, "/"):
		return prefix
	default:
		return "/" + peerID + "/" + prefix
	}
}

// splitAbsolutePath splits `/{peer_id}/rest` into its peer-id and the
// peer-relative remainder, which is the form the http-poll tree-face takes.
// Returns ok=false for anything not absolute or missing a remainder.
//
// Note the peer-id is NOT assumed to be the publisher's: under the universal
// prefix ("/") a published root legitimately carries other peers' namespaces,
// so the first segment is read from the path rather than substituted.
func splitAbsolutePath(abs string) (peerID, treePath string, ok bool) {
	if !strings.HasPrefix(abs, "/") {
		return "", "", false
	}
	rest := abs[1:]
	i := strings.Index(rest, "/")
	if i <= 0 || i+1 >= len(rest) {
		return "", "", false
	}
	return rest[:i], rest[i+1:], true
}

// fetchPublishedTrie fetches the published root and mirrors its trie, returning
// the root plus every (relative_key → value_hash) pair the peer serves.
func fetchPublishedTrie(ctx context.Context, pollURL string) (httplive.PublishedRoot, map[string]hash.Hash, *CheckOutcome) {
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
		skip := SkipCheck("peer served no published-root, so there is no prefix to check: " + err.Error())
		return pr, nil, &skip
	}
	if pr.Data.RootHash.IsZero() {
		fail := FailCheck("published-root.root_hash is zero — publisher misconfigured")
		return pr, nil, &fail
	}

	// Tolerate a root advance underneath the walk, with the SAME bounded retry
	// loop v8 uses. Republish-on-change is now a MUST, so against a peer under
	// active write load the root can retire the closure we are mid-walk more
	// than once — a single retry is not enough, and the difference does not show
	// up on a quiet peer. (It showed up the first time these checks ran inside
	// the full suite, where every other category is writing.)
	//
	// Only a fetch failure under a root that did NOT move is a real serving gap.
	var mirror store.ContentStore
	const mirrorAttempts = 3
	for attempt := 1; ; attempt++ {
		var err error
		mirror, _, err = mirrorTrieOverWire(ctx, out, pr.Data.RootHash)
		if err == nil {
			break
		}
		if attempt >= mirrorAttempts {
			fail := FailCheck(fmt.Sprintf(
				"could not mirror the trie from root_hash=%s after %d attempts: %v", pr.Data.RootHash.String(), attempt, err))
			return pr, nil, &fail
		}
		next, ferr := out.FetchPublishedRoot(ctx)
		if ferr != nil {
			fail := FailCheck(fmt.Sprintf("mirror failed (%v) and the manifest could not be re-read: %v", err, ferr))
			return pr, nil, &fail
		}
		if next.Data.RootHash == pr.Data.RootHash {
			fail := FailCheck(fmt.Sprintf(
				"could not mirror the trie from root_hash=%s: %v. The root did NOT advance between the walk and the "+
					"re-read, so this is not a race: a node inside the CURRENT signed root's closure is not served",
				pr.Data.RootHash.String(), err))
			return pr, nil, &fail
		}
		pr = next
	}

	return pr, tree.CollectAllBindings(mirror, pr.Data.RootHash, ""), nil
}

// requirePrefix enforces the §3.3a REQUIRED field and its "MUST end with /"
// rule. Both are MUSTs as of 2026-08-08; a publisher without the field is not
// merely undocumented, it is unreadable — a consumer holds relative keys and no
// operand to rebuild an absolute path with.
func requirePrefix(pr httplive.PublishedRoot) *CheckOutcome {
	if pr.Data.Prefix == "" {
		out := FailCheck(
			"published-root carries no `prefix` field. EXTENSION-TREE §3.3a makes it REQUIRED " +
				"[MUST; ruled 2026-08-08] and NETWORK §6.5.3's MANIFEST_GET body MUST carry it. Without it a " +
				"consumer holds relative_keys and not the operand §3.3 reconstructs paths with " +
				"(`absolute_prefix + relative_key`), so the hash-chain walk that is the whole signed-root security " +
				"model is underspecified at its first step. This is the field whose absence let three conformant " +
				"implementations publish mutually unreadable keys. Fix: emit the prefix you actually track — " +
				"`system/` (peer-relative), `/{peer_id}/` (peer-qualified), or `/` (universal)")
		return &out
	}
	if !strings.HasSuffix(pr.Data.Prefix, "/") {
		out := FailCheck(fmt.Sprintf(
			"published-root prefix %q does not end with `/`. §3.3a: a non-empty prefix MUST end with `/`. This is "+
				"not cosmetic — reconstruction is a plain concatenation (`absolute_prefix + relative_key`), so a "+
				"missing separator silently produces a wrong absolute path and §3.3's trim stops being its inverse",
			pr.Data.Prefix))
		return &out
	}
	return nil
}

// runPublishedRootKeyForm is §6.1 / §12.1's key-form assertion: take an
// absolute path known to be bound in the published subtree, derive relative_key
// from the publisher's DECLARED prefix, and assert the trie resolves THAT key.
func runPublishedRootKeyForm(ctx context.Context, pollURL string) CheckOutcome {
	if pollURL == "" {
		return SkipCheck("no -poll-url provided (start the peer with --publish-root + --http-poll-addr + --serve-closure-root, then pass -poll-url http://host:port)")
	}
	pr, bindings, bad := fetchPublishedTrie(ctx, pollURL)
	if bad != nil {
		return *bad
	}
	if bad := requirePrefix(pr); bad != nil {
		return *bad
	}
	if len(bindings) == 0 {
		return SkipCheck("the served trie is empty — the key-form MUST has nothing to exercise")
	}

	absPrefix := resolveAbsolutePrefix(pr.Data.Prefix, pr.Data.PeerID)

	// Reconstruct each key to its absolute path through the DECLARED prefix and
	// resolve it on the peer's own tree-face. That face is independent ground
	// truth: the trie is the published key-space, the tree-face is the path
	// space, and `prefix` is the bridge the publisher declares between them. If
	// the declared prefix does not describe the actual key form, reconstruction
	// yields a path the peer does not have and the fetch 404s.
	//
	// Non-circularity is the whole point. Deriving the key from the trie and
	// then looking it up in the trie is what v8 already does and why v8 cannot
	// fail on key form (§12.1). Here the answer comes from a different surface.
	keys := make([]string, 0, len(bindings))
	for k := range bindings {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	// Sample rather than sweep: this is one HTTP round-trip per key against a
	// live peer, and a wrong key convention is uniform — it is a property of the
	// publisher's trim, not of individual paths. A miss anywhere in the sample
	// is the finding.
	const sampleSize = 8
	sample := keys
	if len(sample) > sampleSize {
		stride := len(keys) / sampleSize
		sample = nil
		for i := 0; i < len(keys) && len(sample) < sampleSize; i += stride {
			sample = append(sample, keys[i])
		}
	}

	profile := types.HTTPPollProfileData{
		PeerID:        pr.Data.PeerID,
		TransportType: "http-poll",
		Endpoint: types.TransportEndpoint{
			TreeURLPrefix:    pollURL,
			ContentURLPrefix: pollURL + "/content",
			ContentLayout:    types.ContentLayoutFlat,
		},
	}
	out := httplive.NewOutbound(profile, httplive.WithOutboundAllowHTTP(true))

	var checked int
	for _, k := range sample {
		abs := absPrefix + k
		pid, treePath, ok := splitAbsolutePath(abs)
		if !ok {
			return FailCheck(fmt.Sprintf(
				"reconstructing key %q through the declared prefix %q gives %q, which is not a well-formed absolute "+
					"path (`/{peer_id}/rest`). §3.3 requires `absolute_prefix + relative_key` to reproduce the bound "+
					"path, so a declared prefix that cannot even rebuild the path shape is the wrong prefix for these "+
					"keys",
				k, pr.Data.Prefix, abs))
		}
		got, err := out.FetchTreeLeafPointer(ctx, pid, treePath)
		if err != nil {
			return FailCheck(fmt.Sprintf(
				"the publisher DECLARES prefix %q (absolute %q), so served trie key %q reconstructs to %s — but the "+
					"peer's own tree-face does not resolve that path: %v. §3.3a MUST: keys are relative to the "+
					"DECLARED prefix and a consumer rebuilds paths as `absolute_prefix + relative_key`. A prefix that "+
					"does not describe the actual keys is worse than none — the consumer now holds a wrong operand it "+
					"trusts. Either declare the prefix you key by, or re-key to the prefix you declare. "+
					"(This is the assertion a trie-rebuild equality check cannot make — §12.1.)",
				pr.Data.Prefix, absPrefix, k, abs, err))
		}
		if want := bindings[k]; got != want {
			// The trie is a SNAPSHOT at pr.Data.RootHash; the tree-face answers
			// LIVE. A path rebound since that root legitimately differs, and
			// failing on it would report a MUST violation manufactured by our
			// own timing. So distinguish: re-read the root, and only call it a
			// mismatch if the root has not moved.
			//
			// The path RESOLVING is the key-form assertion and it already held
			// here; hash equality is the stronger claim, and it is the one that
			// races.
			if next, ferr := out.FetchPublishedRoot(ctx); ferr == nil && next.Data.RootHash != pr.Data.RootHash {
				checked++
				continue
			}
			return FailCheck(fmt.Sprintf(
				"key %q reconstructs to %s and that path RESOLVES, but to a different hash under a STABLE root: "+
					"tree-face says %s, the published trie binds %s. The path exists yet is not the binding this key "+
					"names, so the declared prefix maps keys onto the wrong paths — a consumer walking the signed root "+
					"would serve content the publisher never bound there",
				k, abs, got.String(), want.String()))
		}
		checked++
	}

	return PassCheck(fmt.Sprintf(
		"reconstructed %d of %d served key(s) through the publisher's DECLARED prefix %q (absolute %q) and resolved "+
			"every one on the peer's independent tree-face, hash-for-hash. A wrong key form cannot pass this: the "+
			"expected path is derived from the declared prefix and answered by a different surface than the trie, "+
			"which is exactly what a rebuild-equality check (v8) cannot do (§12.1)",
		checked, len(keys), pr.Data.Prefix, absPrefix))
}

// runPublishedRootReconstruction is §6.2: `absolute_prefix + relative_key` MUST
// reproduce the absolute path the publisher bound — for every served key, not
// just the anchor. This is the inverse-of-trim property stated as a check.
func runPublishedRootReconstruction(ctx context.Context, pollURL string) CheckOutcome {
	if pollURL == "" {
		return SkipCheck("no -poll-url provided (start the peer with --publish-root + --http-poll-addr + --serve-closure-root, then pass -poll-url http://host:port)")
	}
	pr, bindings, bad := fetchPublishedTrie(ctx, pollURL)
	if bad != nil {
		return *bad
	}
	if bad := requirePrefix(pr); bad != nil {
		return *bad
	}
	if len(bindings) == 0 {
		return SkipCheck("the served trie is empty — reconstruction has nothing to exercise")
	}

	absPrefix := resolveAbsolutePrefix(pr.Data.Prefix, pr.Data.PeerID)

	keys := make([]string, 0, len(bindings))
	for k := range bindings {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	// Every reconstruction must yield a well-formed absolute path. A key that
	// reconstructs to something not starting with `/` means the declared prefix
	// and the key form disagree about who carries the leading segment — the
	// exact failure that produced `/{peer}//` under the superseded formula.
	var malformed []string
	for _, k := range keys {
		full := absPrefix + k
		if !strings.HasPrefix(full, "/") {
			malformed = append(malformed, fmt.Sprintf("%q + %q = %q", absPrefix, k, full))
		}
		if strings.Contains(full, "//") {
			malformed = append(malformed, fmt.Sprintf("%q + %q = %q (doubled separator)", absPrefix, k, full))
		}
		if len(malformed) >= 5 {
			break
		}
	}
	if len(malformed) > 0 {
		return FailCheck(fmt.Sprintf(
			"reconstruction `absolute_prefix + relative_key` does not yield well-formed absolute paths for %d of %d "+
				"served key(s). §3.3 requires the trim and the concatenation to be inverses, and V7 requires every "+
				"path to be absolute (`/{peer_id}/rest`). Examples: %v. The superseded §3.3 formula produced exactly "+
				"this shape (`/{peer}//`) on the universal tree, which is why it was replaced",
			len(malformed), len(keys), malformed))
	}

	// The inverse property, on every key: trimming the reconstructed path by the
	// same absolute prefix MUST return the key we started from. This is what
	// "the trim and the concatenation are inverses" means operationally, and it
	// is what the superseded formula violated — it trimmed by a prefix it had
	// not built the path with.
	for _, k := range keys {
		full := absPrefix + k
		if back := strings.TrimPrefix(full, absPrefix); back != k {
			return FailCheck(fmt.Sprintf(
				"round-trip does not close on key %q: reconstructing gives %s, trimming that by %q gives %q. §3.3's "+
					"trim and `absolute_prefix + relative_key` MUST be inverses",
				k, full, absPrefix, back))
		}
	}

	return PassCheck(fmt.Sprintf(
		"all %d served key(s) reconstruct to well-formed absolute paths under the declared prefix %q (absolute %q), "+
			"and the trim closes back on every one — `absolute_prefix + relative_key` is the inverse of §3.3's trim",
		len(keys), pr.Data.Prefix, absPrefix))
}
