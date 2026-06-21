package validate

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"go.entitychurch.org/entity-core-go/core/ecf"
	"go.entitychurch.org/entity-core-go/core/entity"
	"go.entitychurch.org/entity-core-go/core/hash"
	"go.entitychurch.org/entity-core-go/core/types"

	"github.com/fxamacker/cbor/v2"
)

const catServingMode = "serving_mode"

// Amendment 5 §6.5.3 endpoint defaults.
const (
	servingModeNamespace     = "system/content/public"
	servingModeLeafSuffix    = ".bin"
	servingModeListingSuffix = ".list"
)

// runServingMode validates the EXTENSION-NETWORK Amendment 5 HTTP read
// surface against a remote peer exposed at pollURL. Activated by validate-peer
// `-poll-url http://host:port`; SKIPs cleanly when absent.
//
// Amendment 5 URL shapes:
//
//	GET {pollURL}/content/{hex33(H)}                  CONTENT_GET
//	GET {pollURL}/manifest                            MANIFEST_GET (terminal)
//	GET {pollURL}/peers.list                          universal-tree-root listing
//	GET {pollURL}/{peer_id}.list                      peer-root listing
//	GET {pollURL}/{peer_id}/{path}.bin                tree entity
//	GET {pollURL}/{peer_id}/{path}.list               tree listing
//
// No trailing-slash listings (don't survive static CDNs). No 501. No 3xx.
// Reserved literals {content, manifest, peers.list}. Peer-id first segment
// is the tree signal; tree has no reserved word (§6.5.6 demux Option B).
//
// Seed: `system/tree:put` a chunk entity at
// `/{peer_id}/system/content/public/{hex33(H)}` — the §6.4.2 Hash Tree
// Presence binding NamespaceScope checks AND the path Amendment 5's
// CapTokenScope check resolves against. A second chunk at a different
// non-namespace path is the out-of-scope probe.
func runServingMode(ctx context.Context, client *PeerClient, pollURL string) []CheckResult {
	r := NewCheckRunner(catServingMode)
	peerID := string(client.RemotePeerID())

	// Helpers to build Amendment 5 URLs from the structural parts.
	urlContent := func(hex string) string { return pollURL + "/content/" + hex }
	urlManifest := func() string { return pollURL + "/manifest" }
	urlPeersList := func() string { return pollURL + "/peers" + servingModeListingSuffix }
	urlPeerRoot := func(pid string) string { return pollURL + "/" + pid + servingModeListingSuffix }
	urlTreeEntity := func(pid, path string) string {
		return pollURL + "/" + pid + "/" + path + servingModeLeafSuffix
	}
	urlTreeListing := func(pid, path string) string {
		return pollURL + "/" + pid + "/" + path + servingModeListingSuffix
	}

	// Declare every check up-front so anything we don't reach surfaces as
	// FAIL rather than silently disappearing.

	// seed
	r.Declare("seed_in_scope", "Amendment 5 §6.4.2 — seed: in-scope binding via tree:put")
	r.Declare("seed_out_of_scope", "Amendment 5 — seed: out-of-scope binding (not under served namespace)")

	// CONTENT_GET — unchanged in Amendment 5
	r.Declare("content_get_in_scope_status", "Amendment 4 §6.5.3.1 / §5 A")
	r.Declare("content_get_in_scope_content_type", "Amendment 4 §6.5.3.1")
	r.Declare("content_get_in_scope_etag", "Amendment 4 §6.5.3.1 — ETag = 66-hex content hash")
	r.Declare("content_get_in_scope_cache_control_immutable", "Amendment 4 §6.5.3.1 — immutable on hash-keyed route")
	r.Declare("content_get_in_scope_cache_control_max_age", "Amendment 4 §6.5.3.1 — Cache-Control mandates max-age + immutable")
	r.Declare("content_get_in_scope_body_rehash", "Amendment 4 §5 — pure-body-rehash invariant")
	r.Declare("content_get_in_scope_body_shape_two_key", "Amendment 4 §5 A — ECF({type,data}) bare hashable body")

	r.Declare("content_get_out_of_scope_404", "Amendment 5 §6.5.6 T4")
	r.Declare("content_get_not_held_404", "Amendment 5 §6.5.3.1 — unknown hash")
	r.Declare("content_get_t4_oracle_identity", "Amendment 5 §6.5.6 T4 — identical 404 byte-for-byte")

	r.Declare("content_get_strict66_rejects_64char", "Amendment 4 §7 / V7 §3.5 — strict-66")
	r.Declare("content_get_strict66_rejects_unknown_algo", "Amendment 4 §7 — unknown algorithm byte → 400")
	r.Declare("content_get_strict66_rejects_sha384_fwd", "Amendment 4 §7 — reserved algo byte → 400")
	r.Declare("content_get_strict66_rejects_non_hex", "Amendment 4 §6.5.3.1 — invalid hex → 400")

	r.Declare("content_get_method_post_405", "Amendment 5 status table — GET only")
	r.Declare("content_get_method_allow_header", "Amendment 5 status table — Allow: GET")
	r.Declare("content_get_method_PUT_405", "Amendment 5 status table — PUT → 405")
	r.Declare("content_get_method_DELETE_405", "Amendment 5 status table — DELETE → 405")

	// TREE_GET leaf (Amendment 5 demux + Amendment 6 body: /{peer_id}/{path}.bin
	// returns the BOUND HASH as a system/hash 2-key pointer, NOT the dereferenced
	// entity. Consumer second-hops via /content/{hex33(H)} for the bytes.
	// Per V7 §1.7 dedup invariant: tree holds path→hash; content store holds
	// hash→bytes once; one-hop materializes N copies on a static CDN.)
	r.Declare("tree_entity_status", "Amendment 5 §6.5.3.1 — .bin → 200")
	r.Declare("tree_entity_content_type", "Amendment 5 §6.5.3.1")
	r.Declare("tree_entity_body_is_hash_pointer", "Amendment 6 §6.5.3.1 — body is `system/hash` 2-key pointer ECF({type, data}); NOT the dereferenced wire entity (V7 §1.7 dedup invariant)")
	r.Declare("tree_entity_pointer_data_matches_bound_hash", "Amendment 6 — pointer's `data` MUST equal the bound hash H (the path's resolution)")
	r.Declare("tree_entity_second_hop_dereferences", "Amendment 6 — CONTENT_GET /content/{hex33(H)} for H from the pointer MUST round-trip the entity bytes")
	r.Declare("tree_entity_etag", "Amendment 5 §6.5.3.1 + Amendment 6 polish — ETag = 66-hex BOUND hash (not pointer self-hash; changes on rebind = correct mutable cache key)")
	r.Declare("tree_entity_no_immutable", "Amendment 4 §6.5.3.1 — bindings mutable; MUST NOT mark immutable")
	r.Declare("tree_entity_out_of_scope_404", "Amendment 5 §6.5.6 T4")
	r.Declare("tree_entity_unbound_404", "Amendment 5 §6.5.6 T4")
	r.Declare("tree_entity_t4_oracle_identity", "Amendment 5 §6.5.6 — out-of-scope ≡ unbound byte-for-byte")
	r.Declare("tree_entity_no_suffix_404", "Amendment 5 §6.5.3.1 — bare no-suffix path → 404 (leaf MUST carry .bin)")
	r.Declare("tree_entity_method_POST_405", "Amendment 5 status table — GET only")
	r.Declare("tree_entity_method_allow_header", "Amendment 5 status table — Allow: GET")

	// TREE_GET listing (Amendment 5: /{peer_id}/{path}.list)
	r.Declare("tree_listing_status", "Amendment 5 §6.5.3.1 — .list → system/tree/listing entity")
	r.Declare("tree_listing_content_type", "Amendment 5 §6.5.3.1")
	r.Declare("tree_listing_no_immutable", "Amendment 5 §6.5.3.1 — listings mutable; MUST NOT mark immutable")
	r.Declare("tree_listing_body_is_listing_type", "Amendment 5 §6.5.3.1 — body decodes to system/tree/listing")
	r.Declare("tree_listing_count_matches_entries", "TREE §1176 — count = in-scope filtered total = len(entries)")
	r.Declare("tree_listing_nonexistent_404", "Amendment 5 §6.5.6 T4 — non-existent prefix → 404")
	r.Declare("tree_listing_empty_in_scope_200", "Amendment 5 Q2 — empty in-scope prefix → 200 + entries={} + count=0")

	// Root + peers listings
	r.Declare("peer_root_listing_status", "Amendment 5 §6.5.3.1 — {peer_id}.list → root listing")
	r.Declare("peer_root_listing_is_listing_type", "Amendment 5 §6.5.3.1")
	r.Declare("peers_list_status", "Amendment 5 §6.5.6 — peers.list → universal-tree-root listing")
	r.Declare("peers_list_is_listing_type", "Amendment 5 §6.5.6")
	r.Declare("peers_list_contains_peer", "Amendment 5 §6.5.6 — peers.list lists peer-ids with bindings")
	r.Declare("bare_peers_no_suffix_404", "Amendment 5 §6.5.6 — bare `peers` no suffix → 404")
	r.Declare("multi_peer_publish_via_tree_put", "Amendment 5 §6.5.6 — peer can publish another peer's namespace (the universal-tree semantic): tree:put at /<other_peer>/... lands a binding the store actually holds")
	r.Declare("peers_list_surfaces_other_peer", "Amendment 5 §6.5.6 — peers.list MUST include every top-level peer-id with bindings, not just the local one")

	// MANIFEST_GET (Amendment 5: NO 501)
	r.Declare("manifest_no_501", "Amendment 5 §6.5.3.1 — manifest route MUST NOT 501 in shipped peer")
	r.Declare("manifest_trailing_slash_404", "Amendment 5 §6.5.3.1 — /manifest/ → 404 (terminal)")

	// Status-table edges
	r.Declare("percent_encoded_slash_400", "Amendment 5 status table — %2F → 400")
	r.Declare("unknown_first_segment_404", "Amendment 5 §6.5.6 — unknown literal → 404")

	// Cross-route consistency
	r.Declare("cross_route_consistency", "Amendment 5 — entity content_hash round-trips through /content")

	// --- seed phase ---

	r.Run("seed_in_scope", func() CheckOutcome {
		payload := []byte(fmt.Sprintf("amendment-5 serving-mode validate %d", time.Now().UnixNano()))
		chunkEnt, err := types.ContentChunkData{Payload: payload}.ToEntity()
		if err != nil {
			return FailCheck("encode chunk: " + err.Error())
		}
		hexH := hex.EncodeToString(chunkEnt.ContentHash.Bytes())
		// §6.4.2 binding under the served namespace — this is the path
		// both NamespaceScope (substrate) and CapTokenScope (cap-evaluator
		// on the §6.4.2 namespace) accept.
		bindingPath := servingModeNamespace + "/" + hexH
		storedHash, err := client.TreePut(ctx, bindingPath, chunkEnt)
		if err != nil {
			return FailCheck(fmt.Sprintf("tree:put at %s: %v", bindingPath, err))
		}
		if storedHash != chunkEnt.ContentHash {
			return FailCheck(fmt.Sprintf("stored hash %s != local %s — ECF drift",
				storedHash.String(), chunkEnt.ContentHash.String()))
		}
		r.Store("in_scope_entity", chunkEnt)
		r.Store("in_scope_hash_hex", hexH)
		r.Store("in_scope_binding_path", bindingPath)
		return PassCheck(fmt.Sprintf("seeded in-scope at %s", bindingPath))
	})

	r.Run("seed_out_of_scope", func() CheckOutcome {
		payload := []byte(fmt.Sprintf("amendment-5 out-of-scope %d", time.Now().UnixNano()))
		chunkEnt, err := types.ContentChunkData{Payload: payload}.ToEntity()
		if err != nil {
			return FailCheck("encode chunk: " + err.Error())
		}
		oosPath := fmt.Sprintf("system/validate/serving-mode/oos-%s",
			hex.EncodeToString(chunkEnt.ContentHash.Bytes())[:16])
		if _, err := client.TreePut(ctx, oosPath, chunkEnt); err != nil {
			return FailCheck(fmt.Sprintf("tree:put at %s: %v", oosPath, err))
		}
		r.Store("oos_entity", chunkEnt)
		r.Store("oos_hash_hex", hex.EncodeToString(chunkEnt.ContentHash.Bytes()))
		r.Store("oos_path", oosPath)
		return PassCheck(fmt.Sprintf("seeded out-of-scope at %s", oosPath))
	})

	// --- CONTENT_GET in-scope ---

	r.Run("content_get_in_scope_status", func() CheckOutcome {
		if out, ok := r.Require("seed_in_scope"); !ok {
			return out
		}
		hx := r.Load("in_scope_hash_hex").(string)
		resp, _, err := httpGet(ctx, urlContent(hx))
		if err != nil {
			return FailCheck("GET /content/{hex}: " + err.Error())
		}
		if resp.StatusCode != http.StatusOK {
			return FailCheck(fmt.Sprintf("status %d, want 200", resp.StatusCode))
		}
		r.Store("content_in_scope_response", resp)
		return PassCheck("GET /content/{hex33(H)} → 200")
	})

	r.Run("content_get_in_scope_content_type", func() CheckOutcome {
		if out, ok := r.Require("content_get_in_scope_status"); !ok {
			return out
		}
		resp := r.Load("content_in_scope_response").(*storedResponse)
		ct := resp.Header.Get("Content-Type")
		if ct != "application/cbor" {
			return FailCheck(fmt.Sprintf("Content-Type %q, want application/cbor", ct))
		}
		return PassCheck("Content-Type: application/cbor")
	})

	r.Run("content_get_in_scope_etag", func() CheckOutcome {
		if out, ok := r.Require("content_get_in_scope_status"); !ok {
			return out
		}
		resp := r.Load("content_in_scope_response").(*storedResponse)
		wantHex := r.Load("in_scope_hash_hex").(string)
		want := `"` + wantHex + `"`
		got := resp.Header.Get("ETag")
		if got != want {
			return FailCheck(fmt.Sprintf("ETag %q, want %q", got, want))
		}
		return PassCheck("ETag = quoted 66-hex content hash")
	})

	r.Run("content_get_in_scope_cache_control_immutable", func() CheckOutcome {
		if out, ok := r.Require("content_get_in_scope_status"); !ok {
			return out
		}
		resp := r.Load("content_in_scope_response").(*storedResponse)
		cc := resp.Header.Get("Cache-Control")
		if !strings.Contains(cc, "immutable") {
			return FailCheck(fmt.Sprintf("Cache-Control %q missing immutable", cc))
		}
		return PassCheck(fmt.Sprintf("Cache-Control contains immutable: %q", cc))
	})

	r.Run("content_get_in_scope_cache_control_max_age", func() CheckOutcome {
		if out, ok := r.Require("content_get_in_scope_status"); !ok {
			return out
		}
		resp := r.Load("content_in_scope_response").(*storedResponse)
		cc := resp.Header.Get("Cache-Control")
		if !strings.Contains(cc, "max-age=") {
			return FailCheck(fmt.Sprintf("Cache-Control %q missing max-age", cc))
		}
		return PassCheck("Cache-Control contains max-age")
	})

	r.Run("content_get_in_scope_body_rehash", func() CheckOutcome {
		if out, ok := r.Require("content_get_in_scope_status"); !ok {
			return out
		}
		resp := r.Load("content_in_scope_response").(*storedResponse)
		ent := r.Load("in_scope_entity").(entity.Entity)
		got := sha256.Sum256(resp.Body)
		if !bytes.Equal(got[:], ent.ContentHash.EffectiveDigest()) {
			return FailCheck(fmt.Sprintf(
				"SHA-256(body) = %x, want %x — pure-body-rehash broken", got, ent.ContentHash.EffectiveDigest()))
		}
		return PassCheck("SHA-256(body) == URL.hash.digest")
	})

	r.Run("content_get_in_scope_body_shape_two_key", func() CheckOutcome {
		if out, ok := r.Require("content_get_in_scope_status"); !ok {
			return out
		}
		resp := r.Load("content_in_scope_response").(*storedResponse)
		ent := r.Load("in_scope_entity").(entity.Entity)
		want, err := ecf.EncodeHashable(ent.Type, ent.Data)
		if err != nil {
			return FailCheck("recompute ECF({type,data}): " + err.Error())
		}
		if !bytes.Equal(resp.Body, want) {
			return FailCheck(fmt.Sprintf(
				"body (%d B) != ECF({type,data}) (%d B)", len(resp.Body), len(want)))
		}
		return PassCheck("body == ECF({type,data})")
	})

	// --- CONTENT_GET T4 ---

	r.Run("content_get_out_of_scope_404", func() CheckOutcome {
		if out, ok := r.Require("seed_out_of_scope"); !ok {
			return out
		}
		oosHex := r.Load("oos_hash_hex").(string)
		resp, _, err := httpGet(ctx, urlContent(oosHex))
		if err != nil {
			return FailCheck("GET out-of-scope: " + err.Error())
		}
		if resp.StatusCode != http.StatusNotFound {
			return FailCheck(fmt.Sprintf("out-of-scope returned %d, want 404", resp.StatusCode))
		}
		r.Store("oos_response", resp)
		return PassCheck("out-of-scope hash → 404")
	})

	r.Run("content_get_not_held_404", func() CheckOutcome {
		notHeld := hash.Hash{Algorithm: hash.AlgorithmSHA256}
		copy(notHeld.Digest[:hash.SHA256DigestSize], "validate-not-held-content-hash--32")
		nhHex := hex.EncodeToString(notHeld.Bytes())
		resp, _, err := httpGet(ctx, urlContent(nhHex))
		if err != nil {
			return FailCheck("GET not-held: " + err.Error())
		}
		if resp.StatusCode != http.StatusNotFound {
			return FailCheck(fmt.Sprintf("not-held returned %d, want 404", resp.StatusCode))
		}
		r.Store("nh_response", resp)
		return PassCheck("not-held hash → 404")
	})

	r.Run("content_get_t4_oracle_identity", func() CheckOutcome {
		if out, ok := r.Require("content_get_out_of_scope_404", "content_get_not_held_404"); !ok {
			return out
		}
		oos := r.Load("oos_response").(*storedResponse)
		nh := r.Load("nh_response").(*storedResponse)
		if oos.StatusCode != nh.StatusCode {
			return FailCheck(fmt.Sprintf("status mismatch: oos=%d nh=%d", oos.StatusCode, nh.StatusCode))
		}
		if !bytes.Equal(oos.Body, nh.Body) {
			return FailCheck(fmt.Sprintf(
				"body mismatch — oos=%d B (%q...) nh=%d B (%q...) — presence oracle leak",
				len(oos.Body), preview(oos.Body), len(nh.Body), preview(nh.Body)))
		}
		return PassCheck("out-of-scope ≡ not-held byte-for-byte")
	})

	// --- CONTENT_GET strict-66 ---

	r.Run("content_get_strict66_rejects_64char", func() CheckOutcome {
		bad := strings.Repeat("ab", 32)
		resp, _, err := httpGet(ctx, urlContent(bad))
		if err != nil {
			return FailCheck("GET 64-char: " + err.Error())
		}
		if resp.StatusCode != http.StatusBadRequest {
			return FailCheck(fmt.Sprintf("returned %d, want 400", resp.StatusCode))
		}
		return PassCheck("64-char → 400")
	})

	r.Run("content_get_strict66_rejects_unknown_algo", func() CheckOutcome {
		bad := "ff" + strings.Repeat("ab", 32)
		resp, _, err := httpGet(ctx, urlContent(bad))
		if err != nil {
			return FailCheck("GET ff...: " + err.Error())
		}
		if resp.StatusCode != http.StatusBadRequest {
			return FailCheck(fmt.Sprintf("returned %d, want 400", resp.StatusCode))
		}
		return PassCheck("unknown algo (0xff) → 400")
	})

	r.Run("content_get_strict66_rejects_sha384_fwd", func() CheckOutcome {
		bad := "01" + strings.Repeat("ab", 32)
		resp, _, err := httpGet(ctx, urlContent(bad))
		if err != nil {
			return FailCheck("GET 01...: " + err.Error())
		}
		if resp.StatusCode != http.StatusBadRequest {
			return FailCheck(fmt.Sprintf("returned %d, want 400", resp.StatusCode))
		}
		return PassCheck("reserved algo (0x01) → 400")
	})

	r.Run("content_get_strict66_rejects_non_hex", func() CheckOutcome {
		bad := strings.Repeat("zz", 33)
		resp, _, err := httpGet(ctx, urlContent(bad))
		if err != nil {
			return FailCheck("GET non-hex: " + err.Error())
		}
		if resp.StatusCode != http.StatusBadRequest {
			return FailCheck(fmt.Sprintf("returned %d, want 400", resp.StatusCode))
		}
		return PassCheck("non-hex → 400")
	})

	// --- CONTENT_GET method discipline ---

	r.Run("content_get_method_post_405", func() CheckOutcome {
		if out, ok := r.Require("seed_in_scope"); !ok {
			return out
		}
		hx := r.Load("in_scope_hash_hex").(string)
		resp, _, err := httpDo(ctx, "POST", urlContent(hx), []byte("x"))
		if err != nil {
			return FailCheck("POST: " + err.Error())
		}
		if resp.StatusCode != http.StatusMethodNotAllowed {
			return FailCheck(fmt.Sprintf("returned %d, want 405", resp.StatusCode))
		}
		r.Store("post_content_response", resp)
		return PassCheck("POST → 405")
	})

	r.Run("content_get_method_allow_header", func() CheckOutcome {
		if out, ok := r.Require("content_get_method_post_405"); !ok {
			return out
		}
		resp := r.Load("post_content_response").(*storedResponse)
		allow := resp.Header.Get("Allow")
		if !strings.Contains(allow, "GET") {
			return FailCheck(fmt.Sprintf("Allow %q missing GET", allow))
		}
		return PassCheck("Allow: GET")
	})

	r.Run("content_get_method_PUT_405", func() CheckOutcome {
		if out, ok := r.Require("seed_in_scope"); !ok {
			return out
		}
		hx := r.Load("in_scope_hash_hex").(string)
		resp, _, err := httpDo(ctx, "PUT", urlContent(hx), []byte("x"))
		if err != nil {
			return FailCheck("PUT: " + err.Error())
		}
		if resp.StatusCode != http.StatusMethodNotAllowed {
			return FailCheck(fmt.Sprintf("returned %d, want 405", resp.StatusCode))
		}
		return PassCheck("PUT → 405")
	})

	r.Run("content_get_method_DELETE_405", func() CheckOutcome {
		if out, ok := r.Require("seed_in_scope"); !ok {
			return out
		}
		hx := r.Load("in_scope_hash_hex").(string)
		resp, _, err := httpDo(ctx, "DELETE", urlContent(hx), nil)
		if err != nil {
			return FailCheck("DELETE: " + err.Error())
		}
		if resp.StatusCode != http.StatusMethodNotAllowed {
			return FailCheck(fmt.Sprintf("returned %d, want 405", resp.StatusCode))
		}
		return PassCheck("DELETE → 405")
	})

	// --- TREE_GET entity (.bin) ---

	r.Run("tree_entity_status", func() CheckOutcome {
		if out, ok := r.Require("seed_in_scope"); !ok {
			return out
		}
		bindingPath := r.Load("in_scope_binding_path").(string)
		resp, _, err := httpGet(ctx, urlTreeEntity(peerID, bindingPath))
		if err != nil {
			return FailCheck("GET tree entity: " + err.Error())
		}
		if resp.StatusCode != http.StatusOK {
			return FailCheck(fmt.Sprintf("status %d, want 200 (url=%s)", resp.StatusCode, urlTreeEntity(peerID, bindingPath)))
		}
		r.Store("tree_entity_response", resp)
		return PassCheck("GET /{peer_id}/{path}.bin → 200")
	})

	r.Run("tree_entity_content_type", func() CheckOutcome {
		if out, ok := r.Require("tree_entity_status"); !ok {
			return out
		}
		resp := r.Load("tree_entity_response").(*storedResponse)
		ct := resp.Header.Get("Content-Type")
		if ct != "application/cbor" {
			return FailCheck(fmt.Sprintf("Content-Type %q, want application/cbor", ct))
		}
		return PassCheck("Content-Type: application/cbor")
	})

	// Amendment 6: the leaf body MUST be a system/hash 2-key pointer
	// `ECF({type:"system/hash", data: <33-byte H>})`, NOT the dereferenced
	// entity. Decode + assert the shape; store H for the second-hop check.
	r.Run("tree_entity_body_is_hash_pointer", func() CheckOutcome {
		if out, ok := r.Require("tree_entity_status"); !ok {
			return out
		}
		resp := r.Load("tree_entity_response").(*storedResponse)
		var decoded map[string]cbor.RawMessage
		if err := ecf.Decode(resp.Body, &decoded); err != nil {
			return FailCheck("decode body as CBOR map: " + err.Error())
		}
		if len(decoded) != 2 {
			keys := make([]string, 0, len(decoded))
			for k := range decoded {
				keys = append(keys, k)
			}
			return FailCheck(fmt.Sprintf("body has %d keys %v; Amendment 6 requires 2-key bare form {type, data} — a 3-key wire entity here means peer is returning the dereferenced entity, NOT the system/hash pointer (V7 §1.7 dedup invariant)", len(decoded), keys))
		}
		var typeStr string
		if err := ecf.Decode(decoded["type"], &typeStr); err != nil {
			return FailCheck("decode type field: " + err.Error())
		}
		if typeStr != "system/hash" {
			return FailCheck(fmt.Sprintf("body type %q, want \"system/hash\" — Amendment 6 leaf is a hash pointer, not a dereferenced entity", typeStr))
		}
		var pointerData []byte
		if err := ecf.Decode(decoded["data"], &pointerData); err != nil {
			return FailCheck("decode data field as bytes: " + err.Error())
		}
		if len(pointerData) != 33 {
			return FailCheck(fmt.Sprintf("pointer data is %d bytes, want 33 (V7 §3.5 hex33: 1 algorithm byte + 32 digest)", len(pointerData)))
		}
		r.Store("tree_entity_pointer_data", pointerData)
		return PassCheck(fmt.Sprintf("body is system/hash 2-key pointer (33-byte hash, hex33=%s)", hex.EncodeToString(pointerData)))
	})

	r.Run("tree_entity_pointer_data_matches_bound_hash", func() CheckOutcome {
		if out, ok := r.Require("tree_entity_body_is_hash_pointer"); !ok {
			return out
		}
		pointerData := r.Load("tree_entity_pointer_data").([]byte)
		wantHex := r.Load("in_scope_hash_hex").(string)
		gotHex := hex.EncodeToString(pointerData)
		if gotHex != wantHex {
			return FailCheck(fmt.Sprintf("pointer data %s ≠ bound hash %s — the leaf MUST return the hash that the path resolves to (path→hash; second hop fetches hash→bytes)", gotHex, wantHex))
		}
		return PassCheck("pointer data = bound hash (path→hash resolution correct)")
	})

	// Amendment 6: the second hop. Take H from the pointer, do
	// CONTENT_GET /content/{hex33(H)}, assert the dereferenced body round-trips
	// the entity bytes. This is the *consumer flow* — the path→hash→bytes
	// pipeline §6.5.3 step 5 describes.
	r.Run("tree_entity_second_hop_dereferences", func() CheckOutcome {
		if out, ok := r.Require("tree_entity_pointer_data_matches_bound_hash"); !ok {
			return out
		}
		pointerData := r.Load("tree_entity_pointer_data").([]byte)
		contentURL := urlContent(hex.EncodeToString(pointerData))
		resp, _, err := httpGet(ctx, contentURL)
		if err != nil {
			return FailCheck("second-hop CONTENT_GET: " + err.Error())
		}
		if resp.StatusCode != http.StatusOK {
			return FailCheck(fmt.Sprintf("CONTENT_GET %s → %d, want 200 (universal-tree dereference path broken)", contentURL, resp.StatusCode))
		}
		// Body must pure-body-rehash to H per §6.5.3.1 CONTENT_GET rule.
		computed := sha256.Sum256(resp.Body)
		var expected [33]byte
		copy(expected[1:], computed[:])
		// expected[0] = 0x00 (ECFv1-SHA-256 algorithm byte)
		if !bytes.Equal(pointerData, expected[:]) {
			return FailCheck(fmt.Sprintf("CONTENT_GET body rehashes to %s, expected pointer hash %s (Mechanism A pure-body-rehash failed — peer's content store ≠ tree binding)", hex.EncodeToString(expected[:]), hex.EncodeToString(pointerData)))
		}
		return PassCheck(fmt.Sprintf("path→hash→bytes round-trip OK (%d bytes content)", len(resp.Body)))
	})

	r.Run("tree_entity_etag", func() CheckOutcome {
		if out, ok := r.Require("tree_entity_status"); !ok {
			return out
		}
		resp := r.Load("tree_entity_response").(*storedResponse)
		wantHex := r.Load("in_scope_hash_hex").(string)
		want := `"` + wantHex + `"`
		got := resp.Header.Get("ETag")
		if got != want {
			return FailCheck(fmt.Sprintf("ETag %q, want %q", got, want))
		}
		return PassCheck("ETag = resolved hash hex")
	})

	r.Run("tree_entity_no_immutable", func() CheckOutcome {
		if out, ok := r.Require("tree_entity_status"); !ok {
			return out
		}
		resp := r.Load("tree_entity_response").(*storedResponse)
		cc := resp.Header.Get("Cache-Control")
		if strings.Contains(cc, "immutable") {
			return FailCheck(fmt.Sprintf("Cache-Control %q contains immutable — bindings mutable", cc))
		}
		return PassCheck("Cache-Control has no immutable on tree entity")
	})

	r.Run("tree_entity_out_of_scope_404", func() CheckOutcome {
		if out, ok := r.Require("seed_out_of_scope"); !ok {
			return out
		}
		oosPath := r.Load("oos_path").(string)
		resp, _, err := httpGet(ctx, urlTreeEntity(peerID, oosPath))
		if err != nil {
			return FailCheck("GET oos tree entity: " + err.Error())
		}
		if resp.StatusCode != http.StatusNotFound {
			return FailCheck(fmt.Sprintf("returned %d, want 404", resp.StatusCode))
		}
		r.Store("tree_entity_oos_response", resp)
		return PassCheck("out-of-scope tree entity → 404")
	})

	r.Run("tree_entity_unbound_404", func() CheckOutcome {
		resp, _, err := httpGet(ctx, urlTreeEntity(peerID, "system/validate/serving-mode/never-bound"))
		if err != nil {
			return FailCheck("GET unbound: " + err.Error())
		}
		if resp.StatusCode != http.StatusNotFound {
			return FailCheck(fmt.Sprintf("returned %d, want 404", resp.StatusCode))
		}
		r.Store("tree_entity_unbound_response", resp)
		return PassCheck("unbound tree entity → 404")
	})

	r.Run("tree_entity_t4_oracle_identity", func() CheckOutcome {
		if out, ok := r.Require("tree_entity_out_of_scope_404", "tree_entity_unbound_404"); !ok {
			return out
		}
		oos := r.Load("tree_entity_oos_response").(*storedResponse)
		nb := r.Load("tree_entity_unbound_response").(*storedResponse)
		if oos.StatusCode != nb.StatusCode {
			return FailCheck(fmt.Sprintf("status mismatch: oos=%d unbound=%d", oos.StatusCode, nb.StatusCode))
		}
		if !bytes.Equal(oos.Body, nb.Body) {
			return FailCheck("body mismatch — out-of-scope leaks distinguishably from unbound")
		}
		return PassCheck("out-of-scope ≡ unbound byte-for-byte")
	})

	r.Run("tree_entity_no_suffix_404", func() CheckOutcome {
		if out, ok := r.Require("seed_in_scope"); !ok {
			return out
		}
		// Same path as the in-scope entity but WITHOUT the .bin suffix.
		bindingPath := r.Load("in_scope_binding_path").(string)
		resp, _, err := httpGet(ctx, pollURL+"/"+peerID+"/"+bindingPath)
		if err != nil {
			return FailCheck("GET no-suffix: " + err.Error())
		}
		if resp.StatusCode != http.StatusNotFound {
			return FailCheck(fmt.Sprintf("returned %d, want 404 (bare no-suffix MUST 404)", resp.StatusCode))
		}
		return PassCheck("bare no-suffix tree path → 404")
	})

	r.Run("tree_entity_method_POST_405", func() CheckOutcome {
		if out, ok := r.Require("seed_in_scope"); !ok {
			return out
		}
		bindingPath := r.Load("in_scope_binding_path").(string)
		resp, _, err := httpDo(ctx, "POST", urlTreeEntity(peerID, bindingPath), []byte("x"))
		if err != nil {
			return FailCheck("POST: " + err.Error())
		}
		if resp.StatusCode != http.StatusMethodNotAllowed {
			return FailCheck(fmt.Sprintf("returned %d, want 405", resp.StatusCode))
		}
		r.Store("tree_entity_post_response", resp)
		return PassCheck("POST tree entity → 405")
	})

	r.Run("tree_entity_method_allow_header", func() CheckOutcome {
		if out, ok := r.Require("tree_entity_method_POST_405"); !ok {
			return out
		}
		resp := r.Load("tree_entity_post_response").(*storedResponse)
		allow := resp.Header.Get("Allow")
		if !strings.Contains(allow, "GET") {
			return FailCheck(fmt.Sprintf("Allow %q missing GET", allow))
		}
		return PassCheck("Allow: GET")
	})

	// --- TREE_GET listing (.list) ---

	r.Run("tree_listing_status", func() CheckOutcome {
		if out, ok := r.Require("seed_in_scope"); !ok {
			return out
		}
		// List the served namespace itself — the §6.4.2 namespace where
		// the in-scope seed lives. This is guaranteed to have at least
		// one in-scope entry (the seed).
		resp, _, err := httpGet(ctx, urlTreeListing(peerID, servingModeNamespace))
		if err != nil {
			return FailCheck("GET listing: " + err.Error())
		}
		if resp.StatusCode != http.StatusOK {
			return FailCheck(fmt.Sprintf("status %d, want 200 (url=%s)", resp.StatusCode, urlTreeListing(peerID, servingModeNamespace)))
		}
		r.Store("tree_listing_response", resp)
		return PassCheck("GET /{peer_id}/{path}.list → 200")
	})

	r.Run("tree_listing_content_type", func() CheckOutcome {
		if out, ok := r.Require("tree_listing_status"); !ok {
			return out
		}
		resp := r.Load("tree_listing_response").(*storedResponse)
		ct := resp.Header.Get("Content-Type")
		if ct != "application/cbor" {
			return FailCheck(fmt.Sprintf("Content-Type %q, want application/cbor", ct))
		}
		return PassCheck("Content-Type: application/cbor")
	})

	r.Run("tree_listing_no_immutable", func() CheckOutcome {
		if out, ok := r.Require("tree_listing_status"); !ok {
			return out
		}
		resp := r.Load("tree_listing_response").(*storedResponse)
		cc := resp.Header.Get("Cache-Control")
		if strings.Contains(cc, "immutable") {
			return FailCheck(fmt.Sprintf("Cache-Control %q contains immutable — listings mutable", cc))
		}
		return PassCheck("Cache-Control has no immutable on tree listing")
	})

	r.Run("tree_listing_body_is_listing_type", func() CheckOutcome {
		if out, ok := r.Require("tree_listing_status"); !ok {
			return out
		}
		resp := r.Load("tree_listing_response").(*storedResponse)
		var ent entity.Entity
		if err := ecf.Decode(resp.Body, &ent); err != nil {
			return FailCheck("decode listing entity: " + err.Error())
		}
		if ent.Type != types.TypeTreeListing {
			return FailCheck(fmt.Sprintf("type %q, want %q", ent.Type, types.TypeTreeListing))
		}
		ld, err := types.ListingDataFromEntity(ent)
		if err != nil {
			return FailCheck("decode ListingData: " + err.Error())
		}
		r.Store("tree_listing_decoded", ld)
		return PassCheck(fmt.Sprintf("body is system/tree/listing (entries=%d count=%d)", len(ld.Entries), ld.Count))
	})

	r.Run("tree_listing_count_matches_entries", func() CheckOutcome {
		if out, ok := r.Require("tree_listing_body_is_listing_type"); !ok {
			return out
		}
		ld := r.Load("tree_listing_decoded").(types.ListingData)
		if ld.Count != uint64(len(ld.Entries)) {
			return FailCheck(fmt.Sprintf(
				"Count %d != len(Entries) %d — TREE §1176 mandates filtered count",
				ld.Count, len(ld.Entries)))
		}
		return PassCheck(fmt.Sprintf("Count %d == len(Entries) %d", ld.Count, len(ld.Entries)))
	})

	r.Run("tree_listing_nonexistent_404", func() CheckOutcome {
		resp, _, err := httpGet(ctx, urlTreeListing(peerID, "system/validate/serving-mode/nonexistent-prefix"))
		if err != nil {
			return FailCheck("GET nonexistent: " + err.Error())
		}
		if resp.StatusCode != http.StatusNotFound {
			return FailCheck(fmt.Sprintf("returned %d, want 404", resp.StatusCode))
		}
		return PassCheck("nonexistent listing prefix → 404")
	})

	r.Run("tree_listing_empty_in_scope_200", func() CheckOutcome {
		if out, ok := r.Require("seed_in_scope"); !ok {
			return out
		}
		// Listing of the §6.4.2 leaf path itself — has no children (it IS
		// a leaf binding). For impls that treat "binding-at-prefix" as
		// "exists" but with no children, this should be 200 + entries={}
		// + count=0. For impls that demand sub-children to exist, this
		// may 404 (still defensible per the spec's T4 wording). Accept
		// either as long as the response is conformant.
		bindingPath := r.Load("in_scope_binding_path").(string)
		resp, _, err := httpGet(ctx, urlTreeListing(peerID, bindingPath))
		if err != nil {
			return FailCheck("GET leaf-as-listing: " + err.Error())
		}
		switch resp.StatusCode {
		case http.StatusOK:
			var ent entity.Entity
			if err := ecf.Decode(resp.Body, &ent); err != nil {
				return FailCheck("decode listing: " + err.Error())
			}
			ld, err := types.ListingDataFromEntity(ent)
			if err != nil {
				return FailCheck("decode ListingData: " + err.Error())
			}
			if ld.Count != 0 || len(ld.Entries) != 0 {
				return FailCheck(fmt.Sprintf("empty in-scope listing has count=%d entries=%d, want both 0", ld.Count, len(ld.Entries)))
			}
			return PassCheck("empty in-scope leaf listing → 200 + entries={} + count=0")
		case http.StatusNotFound:
			return PassCheck("empty leaf listing → 404 (defensible — no children)")
		default:
			return FailCheck(fmt.Sprintf("returned %d, want 200 or 404", resp.StatusCode))
		}
	})

	// --- root + peers listings ---

	r.Run("peer_root_listing_status", func() CheckOutcome {
		if out, ok := r.Require("seed_in_scope"); !ok {
			return out
		}
		resp, _, err := httpGet(ctx, urlPeerRoot(peerID))
		if err != nil {
			return FailCheck("GET peer-root: " + err.Error())
		}
		if resp.StatusCode != http.StatusOK {
			return FailCheck(fmt.Sprintf("status %d, want 200 (url=%s)", resp.StatusCode, urlPeerRoot(peerID)))
		}
		r.Store("peer_root_response", resp)
		return PassCheck("GET /{peer_id}.list → 200")
	})

	r.Run("peer_root_listing_is_listing_type", func() CheckOutcome {
		if out, ok := r.Require("peer_root_listing_status"); !ok {
			return out
		}
		resp := r.Load("peer_root_response").(*storedResponse)
		var ent entity.Entity
		if err := ecf.Decode(resp.Body, &ent); err != nil {
			return FailCheck("decode: " + err.Error())
		}
		if ent.Type != types.TypeTreeListing {
			return FailCheck(fmt.Sprintf("type %q, want %q", ent.Type, types.TypeTreeListing))
		}
		return PassCheck("peer-root listing body is system/tree/listing")
	})

	r.Run("peers_list_status", func() CheckOutcome {
		resp, _, err := httpGet(ctx, urlPeersList())
		if err != nil {
			return FailCheck("GET peers.list: " + err.Error())
		}
		if resp.StatusCode != http.StatusOK {
			return FailCheck(fmt.Sprintf("status %d, want 200", resp.StatusCode))
		}
		r.Store("peers_list_response", resp)
		return PassCheck("GET /peers.list → 200")
	})

	r.Run("peers_list_is_listing_type", func() CheckOutcome {
		if out, ok := r.Require("peers_list_status"); !ok {
			return out
		}
		resp := r.Load("peers_list_response").(*storedResponse)
		var ent entity.Entity
		if err := ecf.Decode(resp.Body, &ent); err != nil {
			return FailCheck("decode: " + err.Error())
		}
		if ent.Type != types.TypeTreeListing {
			return FailCheck(fmt.Sprintf("type %q, want %q", ent.Type, types.TypeTreeListing))
		}
		ld, err := types.ListingDataFromEntity(ent)
		if err != nil {
			return FailCheck("decode ListingData: " + err.Error())
		}
		r.Store("peers_list_decoded", ld)
		return PassCheck(fmt.Sprintf("peers.list body is system/tree/listing (entries=%d)", len(ld.Entries)))
	})

	r.Run("peers_list_contains_peer", func() CheckOutcome {
		if out, ok := r.Require("seed_in_scope", "peers_list_is_listing_type"); !ok {
			return out
		}
		ld := r.Load("peers_list_decoded").(types.ListingData)
		if _, ok := ld.Entries[peerID]; !ok {
			return FailCheck(fmt.Sprintf("peers.list missing peer-id %s (entries=%v)", peerID, ld.Entries))
		}
		return PassCheck("peers.list contains the local peer-id")
	})

	r.Run("bare_peers_no_suffix_404", func() CheckOutcome {
		resp, _, err := httpGet(ctx, pollURL+"/peers")
		if err != nil {
			return FailCheck("GET /peers: " + err.Error())
		}
		if resp.StatusCode != http.StatusNotFound {
			return FailCheck(fmt.Sprintf("returned %d, want 404 (bare peers MUST 404)", resp.StatusCode))
		}
		return PassCheck("bare /peers → 404")
	})

	// --- Multi-peer publish: a real peer must be able to publish another
	// peer's namespace (the universal-tree semantic). Without this, peers.list
	// is just "did you boot a peer," not "can you publish the tree."
	//
	// We use a fixed base58 peer-id-shaped string that is unambiguously NOT
	// the target peer (its length passes looksLikePeerIDSegment; it differs
	// from the target's local peer-id). tree:put with an absolute path
	// under that peer-id MUST land a real binding the index then holds; the
	// universal-tree-root listing MUST then include that peer-id.

	r.Run("multi_peer_publish_via_tree_put", func() CheckOutcome {
		otherPeer := "1HtVqLgPqkScVxjVN8VFGFiH7T2P3aSDwJxQ8DGEoooo1z"
		if otherPeer == peerID {
			return SkipCheck("test fixture peer-id collides with target; pick another")
		}
		payload := []byte(fmt.Sprintf("amendment-5 cross-peer publish %d", time.Now().UnixNano()))
		ent, err := types.ContentChunkData{Payload: payload}.ToEntity()
		if err != nil {
			return FailCheck("encode chunk: " + err.Error())
		}
		absPath := "/" + otherPeer + "/system/validate/cross-peer/probe"
		if _, err := client.TreePut(ctx, absPath, ent); err != nil {
			return FailCheck(fmt.Sprintf("tree:put at %s failed: %v — peer cannot publish other peers' namespaces; universal-tree semantic broken", absPath, err))
		}
		r.Store("other_peer_id", otherPeer)
		return PassCheck(fmt.Sprintf("tree:put at /<other_peer>/... accepted (other=%s)", otherPeer))
	})

	r.Run("peers_list_surfaces_other_peer", func() CheckOutcome {
		if out, ok := r.Require("multi_peer_publish_via_tree_put"); !ok {
			return out
		}
		other := r.Load("other_peer_id").(string)
		// Fresh fetch — the listing must include the just-seeded peer-id.
		resp, _, err := httpGet(ctx, pollURL+"/peers"+servingModeListingSuffix)
		if err != nil {
			return FailCheck("GET peers.list: " + err.Error())
		}
		if resp.StatusCode != http.StatusOK {
			return FailCheck(fmt.Sprintf("peers.list returned %d, want 200", resp.StatusCode))
		}
		var ent entity.Entity
		if err := ecf.Decode(resp.Body, &ent); err != nil {
			return FailCheck("decode listing entity: " + err.Error())
		}
		ld, err := types.ListingDataFromEntity(ent)
		if err != nil {
			return FailCheck("decode ListingData: " + err.Error())
		}
		if _, ok := ld.Entries[other]; !ok {
			names := make([]string, 0, len(ld.Entries))
			for k := range ld.Entries {
				names = append(names, k)
			}
			return FailCheck(fmt.Sprintf("peers.list missing %s after cross-peer publish — peer cannot serve other peers' namespaces. entries=%v", other, names))
		}
		return PassCheck(fmt.Sprintf("peers.list includes %s after cross-peer tree:put — multi-peer publish works", other))
	})

	// --- MANIFEST_GET (no 501) ---

	r.Run("manifest_no_501", func() CheckOutcome {
		resp, _, err := httpGet(ctx, urlManifest())
		if err != nil {
			return FailCheck("GET /manifest: " + err.Error())
		}
		if resp.StatusCode == http.StatusNotImplemented {
			return FailCheck("/manifest → 501 — Amendment 5: NO 501 steady-state in shipped peer")
		}
		// 200 (manifest published) or 404 (none published) both conformant.
		if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusNotFound {
			return FailCheck(fmt.Sprintf("/manifest → %d, want 200 or 404", resp.StatusCode))
		}
		return PassCheck(fmt.Sprintf("/manifest → %d (Amendment 5 conformant)", resp.StatusCode))
	})

	r.Run("manifest_trailing_slash_404", func() CheckOutcome {
		resp, _, err := httpGet(ctx, urlManifest()+"/")
		if err != nil {
			return FailCheck("GET /manifest/: " + err.Error())
		}
		if resp.StatusCode != http.StatusNotFound {
			return FailCheck(fmt.Sprintf("/manifest/ → %d, want 404 (terminal)", resp.StatusCode))
		}
		return PassCheck("/manifest/ → 404 (terminal, no slash)")
	})

	// --- status-table edges ---

	r.Run("percent_encoded_slash_400", func() CheckOutcome {
		// %2F in any path segment must be rejected (smuggled slash bypassing
		// URI delimiters). Use a peer-id segment + %2F in the tail.
		url := pollURL + "/" + peerID + "/foo%2Fbar.bin"
		resp, _, err := httpGet(ctx, url)
		if err != nil {
			return FailCheck("GET %2F: " + err.Error())
		}
		if resp.StatusCode != http.StatusBadRequest {
			return FailCheck(fmt.Sprintf("returned %d, want 400 (Amendment 5 status table)", resp.StatusCode))
		}
		return PassCheck("%2F in path → 400")
	})

	r.Run("unknown_first_segment_404", func() CheckOutcome {
		// Unknown short literal — not a peer-id-shaped string, not a
		// reserved word.
		resp, _, err := httpGet(ctx, pollURL+"/notathing")
		if err != nil {
			return FailCheck("GET /notathing: " + err.Error())
		}
		if resp.StatusCode != http.StatusNotFound {
			return FailCheck(fmt.Sprintf("returned %d, want 404", resp.StatusCode))
		}
		return PassCheck("unknown first segment → 404")
	})

	// --- cross-route consistency ---

	r.Run("cross_route_consistency", func() CheckOutcome {
		if out, ok := r.Require("tree_entity_etag", "content_get_in_scope_body_rehash"); !ok {
			return out
		}
		treeResp := r.Load("tree_entity_response").(*storedResponse)
		etag := strings.Trim(treeResp.Header.Get("ETag"), `"`)
		resp, _, err := httpGet(ctx, urlContent(etag))
		if err != nil {
			return FailCheck("re-fetch /content/{etag}: " + err.Error())
		}
		if resp.StatusCode != http.StatusOK {
			return FailCheck(fmt.Sprintf("re-fetch status %d, want 200", resp.StatusCode))
		}
		raw, err := hex.DecodeString(etag)
		if err != nil {
			return FailCheck("decode ETag hex: " + err.Error())
		}
		H, err := hash.FromBytes(raw)
		if err != nil {
			return FailCheck("Hash from ETag: " + err.Error())
		}
		got := sha256.Sum256(resp.Body)
		if !bytes.Equal(got[:], H.EffectiveDigest()) {
			return FailCheck("re-fetched body doesn't rehash to tree ETag")
		}
		return PassCheck("tree ETag round-trips through /content")
	})

	return r.Results()
}

// storedResponse + httpGet + httpDo + preview reused from earlier impl.

type storedResponse struct {
	StatusCode int
	Header     http.Header
	Body       []byte
}

func httpGet(ctx context.Context, url string) (*storedResponse, *http.Response, error) {
	return httpDo(ctx, "GET", url, nil)
}

func httpDo(ctx context.Context, method, url string, body []byte) (*storedResponse, *http.Response, error) {
	var rdr io.Reader
	if body != nil {
		rdr = bytes.NewReader(body)
	}
	req, err := http.NewRequestWithContext(ctx, method, url, rdr)
	if err != nil {
		return nil, nil, err
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, nil, err
	}
	defer resp.Body.Close()
	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, nil, err
	}
	stored := &storedResponse{
		StatusCode: resp.StatusCode,
		Header:     resp.Header.Clone(),
		Body:       respBody,
	}
	return stored, resp, nil
}

func preview(b []byte) string {
	const max = 32
	if len(b) <= max {
		return string(b)
	}
	return string(b[:max]) + "…"
}
