// EXTENSION-NETWORK Amendment 5 §6.5.6 / §5A — `serve_scope` as a
// capability token.
//
// CapTokenScope is the RECOMMENDED ScopePredicate for the Amendment 5 read
// surface. The publisher generates a literal `system/capability` token that
// brackets exactly the served set; the serving impl evaluates it against the
// SAME cap evaluator the live-EXECUTE surface uses
// (`capability.CheckPathPermission`).
//
// The spec wires the unauthenticated request to the published cap explicitly
// (§6.5.6 ¶974): "Impls MUST pass the published cap as the effective cap
// (MUST NOT reach into capability internals or synthesize a connection
// context). Where the live surface asks 'does the connection's cap-set
// permit get(path)?', the serving surface asks 'does serve_scope.cap permit
// get(path)?' — one ACL machinery, no drift."
//
// This file is that wire. CapTokenScope.InScopePath calls
// capability.CheckPathPermission with the published cap; CapTokenScope.InScope
// derives the §6.4.2 binding path from the content hash and reuses the same
// path-permission check. The cap is the entire authorization context — no
// connection state, no synthetic context.

package httplive

import (
	"context"
	"encoding/hex"
	"fmt"
	"strings"

	"go.entitychurch.org/entity-core-go/core/capability"
	"go.entitychurch.org/entity-core-go/core/crypto"
	"go.entitychurch.org/entity-core-go/core/hash"
	"go.entitychurch.org/entity-core-go/core/store"
	"go.entitychurch.org/entity-core-go/core/types"
)

// CapTokenScope is the Amendment 5 §5A normative scope predicate. The
// publisher's `serve_scope` cap brackets exactly what the routes answer for;
// the same cap evaluator the live-EXECUTE surface uses gates every read.
//
// Fields:
//
//   - Cap: the published `serve_scope` capability token data. MUST be the
//     full unwrapped cap-token data (extract from the cap entity once at
//     handler construction; don't re-parse per request).
//   - HandlerPattern: the handler scope this cap is filtered by — typically
//     a wildcard-matching pattern covering both `system/tree` and
//     `system/content` if the cap spans both faces. Defaults to "*".
//   - LocalPeerID: the peer serving the request. Used by Canonicalize for
//     request-side path normalization (V7 §5.4).
//   - GranterPeerID: the peer that signed the cap. Used by Canonicalize for
//     resource-side pattern normalization (V7 §5.5 / PR-8). Resolve via
//     `capability.ResolveGranterPeerID` once at handler construction.
//   - ContentNamespace: the §6.4.2 Hash Tree Presence namespace. Used by
//     InScope (the content route's hash-keyed face) to derive the binding
//     path from the hash, so the cap check happens against a real path even
//     though the URL itself carried only the hash. Default
//     "system/content/public".
//   - Index: the local LocationIndex. Used by InScope to confirm the
//     substrate binding exists before checking the cap (§6.4.2 Hash Tree
//     Presence is a substrate condition, not part of the cap check).
type CapTokenScope struct {
	Cap              types.CapabilityTokenData
	HandlerPattern   string
	LocalPeerID      crypto.PeerID
	GranterPeerID    crypto.PeerID
	ContentNamespace string
	Index            store.LocationIndex
}

// DefaultContentNamespace is the §6.4.2 Hash Tree Presence namespace used by
// CapTokenScope when ContentNamespace is left empty.
const DefaultContentNamespace = "system/content/public"

// handlerPattern returns the configured pattern or "*" as the fallback.
func (s CapTokenScope) handlerPattern() string {
	if s.HandlerPattern == "" {
		return "*"
	}
	return s.HandlerPattern
}

// contentNamespace returns the configured §6.4.2 namespace or the default.
func (s CapTokenScope) contentNamespace() string {
	if s.ContentNamespace == "" {
		return DefaultContentNamespace
	}
	return s.ContentNamespace
}

// InScope evaluates the content-route hash-keyed face. The URL on
// /content/{hex33(H)} carries only the hash; the cap operates on paths. So
// we derive the §6.4.2 binding path `{namespace}/{hex33(H)}` from H, confirm
// the substrate binding exists in the index (Hash Tree Presence — the
// publisher has actually published this hash), then ask the same evaluator
// whether the cap permits get on that path.
//
// Both conditions matter:
//   - Substrate-only without cap check would re-introduce a second ACL
//     machinery (the NamespaceScope flavor the spec is moving off).
//   - Cap-only without substrate check would let the route answer for hashes
//     the publisher's tree doesn't actually expose — the spec uses the
//     §6.4.2 binding as the publication record.
//
// (Spec §6.5.6 ¶975: "An out-of-scope or non-existent prefix returns 404 —
// identical to not-held — T4". Both legs of this AND collapse to 404 on the
// wire, identical to a not-held content hash.)
func (s CapTokenScope) InScope(_ context.Context, h hash.Hash) (bool, error) {
	if h.IsZero() {
		return false, nil
	}
	if s.Index == nil {
		return false, fmt.Errorf("cap-token scope: Index required for InScope (substrate check)")
	}
	bindingPath := strings.TrimRight(s.contentNamespace(), "/") + "/" + hex.EncodeToString(h.Bytes())
	if !s.Index.Has(bindingPath) {
		return false, nil
	}
	return capability.CheckPathPermission(
		"get",
		bindingPath,
		s.Cap,
		s.handlerPattern(),
		s.LocalPeerID,
		s.GranterPeerID,
	), nil
}

// InScopePath evaluates the tree-route path-keyed face. The URL on
// /{peer_id}/{path}.{bin|list} naturally carries the tree path; we ask the
// cap evaluator directly.
//
// No substrate check here — for the tree face the binding lookup happens in
// the handler (Index.Get for the entity form; Index.List for the listing
// form), and a missing binding produces 404 there. The scope check is purely
// "does the cap permit get on this path?"
func (s CapTokenScope) InScopePath(_ context.Context, path string) (bool, error) {
	return capability.CheckPathPermission(
		"get",
		path,
		s.Cap,
		s.handlerPattern(),
		s.LocalPeerID,
		s.GranterPeerID,
	), nil
}
