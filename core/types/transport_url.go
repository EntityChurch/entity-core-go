package types

import (
	"encoding/hex"
	"fmt"
	"strings"

	"go.entitychurch.org/entity-core-go/core/hash"
)

// TypeSubstituteEndpoint names the shared URL-construction block reused by
// the http-poll profile (NETWORK §6.5.3) and the storage-substitute
// snapshot manifest (STORAGE-SUBSTITUTE-HTTP §3-RES.2). Pinned per the
// storage-substitute cross-impl rulings, Ruling 1
// — Python's call, kept under system/substitute/* cohesion. Reflection-
// registered separately so outer structs that embed it can resolve.
const TypeSubstituteEndpoint = "system/substitute/endpoint"

// Content-layout enum values per STORAGE-SUBSTITUTE-HTTP §3-RES.2 and
// EXTENSION-NETWORK §6.5.3. These describe how content-hash URLs are
// constructed under content_url_prefix. The publisher commits to a layout
// in the http-poll transport profile (and the snapshot manifest's
// endpoint block when one is published); consumers MUST honor it literally.
const (
	ContentLayoutFlat         = "flat"           // {prefix}/{hash}
	ContentLayoutSharded2Flat = "sharded-2-flat" // {prefix}/{hash[0:2]}/{hash}
	ContentLayoutSharded24    = "sharded-2-4"    // {prefix}/{hash[0:2]}/{hash[2:4]}/{hash}
	ContentLayoutSharded22    = "sharded-2-2"    // alias for sharded-2-4 (kept for naming clarity)
)

// DefaultTreeLeafSuffix is the publisher's default suffix appended to
// tree-leaf URLs to resolve the leaf-AND-subtree-at-same-name ambiguity
// imposed by filesystem / HTTP shape. Operators MAY override per
// STORAGE-SUBSTITUTE-HTTP §3-RES.2.
const DefaultTreeLeafSuffix = ".bin"

// DefaultTreeListingSuffix is the publisher's default suffix appended to
// tree-listing URLs per EXTENSION-NETWORK §6.5.3 / §6.5.3.1 Amendment 5.
// Listings are named objects (no trailing slash; doesn't survive static
// CDNs); the listing suffix MUST be distinct from tree_leaf_suffix so
// `{path}.bin` and `{path}.list` resolve to leaf vs listing unambiguously.
const DefaultTreeListingSuffix = ".list"

// TransportEndpoint is the URL-construction block shared between the
// http-poll transport profile (NETWORK §6.5.3) and the storage-substitute
// snapshot manifest (STORAGE-SUBSTITUTE-HTTP §3-RES.2). Both surfaces
// declare the same fields so a consumer presented with either can build
// URLs identically. (The Go type name retains "Transport" for stability;
// the wire string is system/substitute/endpoint per Ruling 1.)
//
//   - TreeURLPrefix is consulted for tree-path-keyed URLs:
//     {tree_url_prefix}/{peer_id}/{path}{tree_leaf_suffix}     ⇒ leaf hash-pointer
//     {tree_url_prefix}/{peer_id}/{path}{tree_listing_suffix}  ⇒ listing
//     {tree_url_prefix}/{peer_id}{tree_listing_suffix}         ⇒ peer-root listing
//     {tree_url_prefix}/peers{tree_listing_suffix}             ⇒ all-peers listing
//   - ContentURLPrefix is consulted for content-hash-keyed URLs:
//     {content_url_prefix}/{layout-path}/{hex33(H)}.
//   - ManifestURLPrefix is the singular signed manifest URL:
//     {manifest_url_prefix} (terminal; no suffix, no trailing slash).
//   - ContentLayout selects the layout-path shape per the constants above.
//   - TreeLeafSuffix / TreeListingSuffix are the disambiguator suffixes
//     consumers MUST append to tree-leaf / tree-listing URLs. Empty string
//     defaults to DefaultTreeLeafSuffix / DefaultTreeListingSuffix at the
//     URL-construction call site. They MUST be distinct (§6.5.3 / §6.5.3.1
//     Amendment 5: REQUIRED distinct); Validate enforces this.
//
// ManifestURLPrefix and TreeListingSuffix are tagged `omitempty` so a
// pre-Amendment-5 publisher emitting the older four-field shape still
// decodes (empty fields then default to Amendment 5 defaults at the
// URL-construction call site, with manifest_url_prefix treated as absent
// — derivation from origin is operator-side, not type-side).
type TransportEndpoint struct {
	TreeURLPrefix     string `cbor:"tree_url_prefix"`
	ContentURLPrefix  string `cbor:"content_url_prefix"`
	ManifestURLPrefix string `cbor:"manifest_url_prefix,omitempty"`
	ContentLayout     string `cbor:"content_layout"`
	TreeLeafSuffix    string `cbor:"tree_leaf_suffix,omitempty"`
	TreeListingSuffix string `cbor:"tree_listing_suffix,omitempty"`
}

// EffectiveTreeLeafSuffix returns the suffix a URL-construction call site
// SHOULD use: the explicit value if set, otherwise DefaultTreeLeafSuffix.
func (ep TransportEndpoint) EffectiveTreeLeafSuffix() string {
	if ep.TreeLeafSuffix != "" {
		return ep.TreeLeafSuffix
	}
	return DefaultTreeLeafSuffix
}

// EffectiveTreeListingSuffix returns the suffix a URL-construction call
// site SHOULD use: the explicit value if set, otherwise
// DefaultTreeListingSuffix.
func (ep TransportEndpoint) EffectiveTreeListingSuffix() string {
	if ep.TreeListingSuffix != "" {
		return ep.TreeListingSuffix
	}
	return DefaultTreeListingSuffix
}

// Validate enforces the EXTENSION-NETWORK §6.5.3 / §6.5.3.1 Amendment 5
// invariant: the effective leaf and listing suffixes MUST be distinct. The
// check resolves defaults first so an endpoint that overrides only one of
// the two is still validated against the other's default.
//
// Validate is intended for constructor / config-loader use, not per
// URL-build call sites. ContentLayout is NOT validated here — BuildContentURL
// rejects unknown layouts at the call site, and an empty layout is
// meaningful (consumer falls through to the default-resolution rule at the
// publisher's discretion).
func (ep TransportEndpoint) Validate() error {
	if ep.EffectiveTreeLeafSuffix() == ep.EffectiveTreeListingSuffix() {
		return fmt.Errorf(
			"transport_endpoint: tree_leaf_suffix (%q) must differ from tree_listing_suffix (%q) per EXTENSION-NETWORK §6.5.3 Amendment 5",
			ep.EffectiveTreeLeafSuffix(), ep.EffectiveTreeListingSuffix(),
		)
	}
	return nil
}

// EffectiveContentURLPrefix returns the content-URL prefix a consumer
// SHOULD use given a TransportEndpoint, applying the EXTENSION-NETWORK
// §6.4 default-resolution rule (D-14): when content_url_prefix is absent,
// derive it as `{tree_url_prefix}/content` (single-peer single-host
// default). Split/dedup hosts (audit S4/S5) MUST emit content_url_prefix
// explicitly; this default applies only to the absent case.
//
// Returns the empty string if both prefixes are absent — callers should
// treat that as a malformed endpoint.
func EffectiveContentURLPrefix(ep TransportEndpoint) string {
	if ep.ContentURLPrefix != "" {
		return ep.ContentURLPrefix
	}
	if ep.TreeURLPrefix == "" {
		return ""
	}
	return strings.TrimRight(ep.TreeURLPrefix, "/") + "/content"
}

// BuildContentURL constructs the full URL a consumer GETs to fetch the
// bytes of content-hash h from a publisher whose http-poll profile (or
// snapshot manifest endpoint block) advertises the given prefix + layout.
//
// The hash is rendered as the hex of its 32-byte digest — the algorithm
// byte is implicit at the URL layer (currently only ecf-sha256). This
// matches the conventional content-addressed URL shape used in
// STORAGE-SUBSTITUTE-HTTP §3-RES.2 and the §10.1 examples.
//
// Returns an error on an unknown layout value — the spec's enum is
// closed, and a publisher advertising a layout outside it is publishing
// something the consumer cannot interpret.
//
// Callers with a TransportEndpoint in hand SHOULD pass
// EffectiveContentURLPrefix(ep) for contentURLPrefix so the §6.4 default-
// resolution rule applies automatically.
func BuildContentURL(contentURLPrefix, layout string, h hash.Hash) (string, error) {
	prefix := strings.TrimRight(contentURLPrefix, "/")
	hexHash := hex.EncodeToString(h.EffectiveDigest())

	switch layout {
	case ContentLayoutFlat:
		return prefix + "/" + hexHash, nil
	case ContentLayoutSharded2Flat:
		return prefix + "/" + hexHash[0:2] + "/" + hexHash, nil
	case ContentLayoutSharded24, ContentLayoutSharded22:
		return prefix + "/" + hexHash[0:2] + "/" + hexHash[2:4] + "/" + hexHash, nil
	default:
		return "", fmt.Errorf("unknown content_layout %q", layout)
	}
}

// BuildTreeLeafURL constructs the URL a consumer GETs to fetch the entity
// bound at treePath under the publisher's tree-URL prefix. The leaf
// suffix is appended literally — per STORAGE-SUBSTITUTE-HTTP §3-RES.2,
// URL rewriting at consume time is not normative; the consumer uses the
// publisher's committed suffix as-is.
//
// An empty suffix argument defaults to DefaultTreeLeafSuffix (".bin"). The
// treePath argument is the tree-relative path (e.g., "docs/readme") —
// leading slashes are trimmed before joining to the prefix.
func BuildTreeLeafURL(treeURLPrefix, treePath, suffix string) string {
	return buildTreeSuffixURL(treeURLPrefix, treePath, suffix, DefaultTreeLeafSuffix)
}

// BuildTreeListingURL constructs the URL a consumer GETs to fetch the
// listing at treePath per EXTENSION-NETWORK §6.5.3.1 Amendment 5. The
// listing suffix is appended literally; an empty suffix defaults to
// DefaultTreeListingSuffix (".list").
//
// Listings are named objects — there is no trailing-slash form (it does
// not survive static CDNs). The peer-root listing is constructed by
// passing the peer_id as treePath with the empty-path semantics handled
// at the caller (the suffix lands directly on the peer_id segment).
func BuildTreeListingURL(treeURLPrefix, treePath, suffix string) string {
	return buildTreeSuffixURL(treeURLPrefix, treePath, suffix, DefaultTreeListingSuffix)
}

func buildTreeSuffixURL(treeURLPrefix, treePath, suffix, defaultSuffix string) string {
	prefix := strings.TrimRight(treeURLPrefix, "/")
	path := strings.TrimLeft(treePath, "/")
	if suffix == "" {
		suffix = defaultSuffix
	}
	if path == "" {
		return prefix + suffix
	}
	return prefix + "/" + path + suffix
}
