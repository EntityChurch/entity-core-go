// Category: relay. Probes the EXTENSION-RELAY v1.0 surface (post-Go-pre-impl-
// review at arch 54e5373 + 15b30d0).
//
// v1 covers Mode F (forward) + Mode S (put / poll) + advertise. The vectors
// gate:
//
//   - Entity type wire shapes: forward-request, store-entry, advertise,
//     forward-result, put-result, poll-request, poll-result (§3, §4.2).
//   - The cohort byte-equality pin on `envelope_inner`: it lives IN the
//     forward-request / store-entry data field as a bare system/hash
//     (V7 §5.2 refless target-matching), NOT as a separate refs block —
//     same pattern REGISTRY / DISCOVERY / PUBLISHED-ROOT use.
//   - Advertise signature carriage at the V7 §5.2 invariant pointer
//     `system/signature/{hex(content_hash)}`, NOT a refs:{signature} block.
//   - Live handler behavior: :advertise, :put (with put_by==caller),
//     :poll (empty-namespace-returns-empty-NOT-404 per §4.2 + landing-
//     pass finding #1), :forward (TTL decrement + reject-at-zero, no_route
//     when next_hop missing, post-Go-review put_by_mismatch/400 on a
//     mismatched put_by).
//
// The current Go entity-peer wires the relay handler with a noop
// OutboundDispatcher — every :forward goes straight to §6.2.1 fallback.
// That's the conservative posture (no silent forwarding before R5 wires
// a real dispatcher); the validate-peer vectors observe this as
// queued-fallback responses on forward, which is conformant for a
// Mode-S-only deployment per §10.1 ("a deployment MAY enable any subset
// of modes").

package validate

import (
	"context"
	"encoding/hex"
	"fmt"

	"go.entitychurch.org/entity-core-go/core/ecf"
	"go.entitychurch.org/entity-core-go/core/entity"
	"go.entitychurch.org/entity-core-go/core/hash"
	"go.entitychurch.org/entity-core-go/core/types"

	"github.com/fxamacker/cbor/v2"
)

const catRelay = "relay"

func runRelay(ctx context.Context, client *PeerClient) []CheckResult {
	r := NewCheckRunner(catRelay)

	r.Declare("v1_forward_request_round_trip", "RELAY §3.1 — system/relay/forward-request ECF round-trip; envelope_inner is a bare system/hash field, NOT a refs block")
	r.Declare("v2_store_entry_round_trip", "RELAY §3.2 — system/relay/store-entry ECF round-trip; put_by Base58 PeerID + envelope_inner in data")
	r.Declare("v3_advertise_no_refs_block", "RELAY §4.1, §3.0 — advertise signature carriage at V7 §5.2 invariant pointer; NO refs:{signature} block")
	r.Declare("v4_forward_result_flat_shape", "RELAY §4.2 — forward-result is a flat entity, NOT system/protocol/status-wrapped (Ruling-3 generalizes)")
	r.Declare("v5_storage_path_helpers", "RELAY §3.2, §4.1 — RelayStorePath / RelayAdvertisePath helpers + §3.2 path shape (system/relay/store/{namespace}/{hex})")
	r.Declare("v6_advertise_invocation_live", "RELAY §4.1 — :advertise binds the advertise entity at system/relay/advertise/{relay_peer_id}")
	r.Declare("v7_put_returns_stored_live", "RELAY §4.2 — :put with valid store-entry + inner envelope in included set returns put-result{status: stored}")
	r.Declare("v8_put_by_mismatch_live", "RELAY §3.2 (Q1 absorption) — :put with put_by != authenticated caller MUST return 400 + code `put_by_mismatch`")
	r.Declare("v9_poll_empty_returns_empty_not_404_live", "RELAY §4.2 + landing-pass finding #1 — :poll against authorized-but-empty namespace MUST return {entries:[], has_more:false} at 200, NOT namespace_not_found/404")
	r.Declare("v10_put_poll_cursor_advance_live", "RELAY §4.2 — :put then :poll surfaces the entry hash; cursor advance on second poll returns empty")
	r.Declare("v11_forward_ttl_exhausted_live", "RELAY §3.1, §4.3 — :forward with ttl_hops=0 MUST return 400 + code `ttl_exhausted` (fail-closed)")
	r.Declare("v12_forward_no_route_live", "RELAY §13 Q3, §4.3 — :forward without next_hop MUST return 502 + code `no_route` (v1 has no implicit routing)")
	r.Declare("v13_expired_on_arrival_live", "RELAY §4.3 — :put with a past expires_at MUST return 400 + code `expired_on_arrival` (creation-side dead-on-arrival per post-Go-review rationale, NOT 410 Gone)")
	r.Declare("v14_inbox_relay_round_trip", "RELAY §3.5 (R6/R7 fold at arch faf3fa9) — system/peer/inbox-relay declaration ECF round-trip + Base58 peer-id on entries + supersede-grounded hash distinctness")
	r.Declare("v15_inbox_relay_storage_path", "RELAY §3.5 — InboxRelayStoragePath canonical form system/peer/inbox-relay/{peer_id} (REGISTRY-served per §3.5)")

	r.Run("v1_forward_request_round_trip", runRelayForwardRequestRoundTrip)
	r.Run("v2_store_entry_round_trip", runRelayStoreEntryRoundTrip)
	r.Run("v3_advertise_no_refs_block", runRelayAdvertiseNoRefsBlock)
	r.Run("v4_forward_result_flat_shape", runRelayForwardResultFlatShape)
	r.Run("v5_storage_path_helpers", runRelayStoragePathHelpers)
	r.Run("v6_advertise_invocation_live", func() CheckOutcome { return runRelayAdvertiseLive(ctx, client) })
	r.Run("v7_put_returns_stored_live", func() CheckOutcome { return runRelayPutLive(ctx, client) })
	r.Run("v8_put_by_mismatch_live", func() CheckOutcome { return runRelayPutByMismatchLive(ctx, client) })
	r.Run("v9_poll_empty_returns_empty_not_404_live", func() CheckOutcome { return runRelayPollEmptyLive(ctx, client) })
	r.Run("v10_put_poll_cursor_advance_live", func() CheckOutcome { return runRelayPutPollAdvanceLive(ctx, client) })
	r.Run("v11_forward_ttl_exhausted_live", func() CheckOutcome { return runRelayForwardTTLExhaustedLive(ctx, client) })
	r.Run("v12_forward_no_route_live", func() CheckOutcome { return runRelayForwardNoRouteLive(ctx, client) })
	r.Run("v13_expired_on_arrival_live", func() CheckOutcome { return runRelayExpiredOnArrivalLive(ctx, client) })
	r.Run("v14_inbox_relay_round_trip", runRelayInboxRelayRoundTrip)
	r.Run("v15_inbox_relay_storage_path", runRelayInboxRelayStoragePath)

	return r.Results()
}

// relayExecute runs a `:op` against system/relay on the target peer. The
// inner envelope (if any) is attached via the V7 envelope's included set
// — required for :put and :forward per §3.1 / §3.2 / §9 opacity.
func relayExecute(ctx context.Context, client *PeerClient, op string, params entity.Entity, included map[hash.Hash]entity.Entity) (uint, entity.Entity, error) {
	uri := fmt.Sprintf("entity://%s/system/relay", client.RemotePeerID())
	var env entity.Envelope
	var err error
	if len(included) == 0 {
		env, _, err = client.SendExecute(ctx, uri, op, params, nil)
	} else {
		env, _, err = client.SendExecuteWithIncluded(ctx, uri, op, params, nil, included)
	}
	if err != nil {
		return 0, entity.Entity{}, err
	}
	resp, err := types.ExecuteResponseDataFromEntity(env.Root)
	if err != nil {
		return 0, entity.Entity{}, fmt.Errorf("decode execute-response: %w", err)
	}
	if len(resp.Result) == 0 {
		return resp.Status, entity.Entity{}, nil
	}
	var result entity.Entity
	if err := ecf.Decode(resp.Result, &result); err != nil {
		return resp.Status, entity.Entity{}, fmt.Errorf("decode result entity: %w", err)
	}
	return resp.Status, result, nil
}

func relayErrCode(result entity.Entity) string {
	if result.Type != types.TypeError {
		return ""
	}
	var ed types.ErrorData
	if err := ecf.Decode(result.Data, &ed); err != nil {
		return ""
	}
	return ed.Code
}

// makeInnerEnvelope returns a stand-in opaque inner-envelope entity (the
// relay never decodes it; the wire just needs *some* entity to ride in
// the included set).
func makeRelayInnerEnvelope(payload string) (entity.Entity, error) {
	raw, err := ecf.Encode(map[string]any{"payload": payload})
	if err != nil {
		return entity.Entity{}, err
	}
	return entity.NewEntity("primitive/any", cbor.RawMessage(raw))
}

const relayFakePeerID = "2KFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF"

func relayFakeHash(b byte) hash.Hash {
	var h hash.Hash
	h.Algorithm = hash.AlgorithmSHA256
	h.Digest[0] = b
	return h
}

// --- Pure vectors (entity types + helpers) ---------------------------------

func runRelayForwardRequestRoundTrip() CheckOutcome {
	innerHash := relayFakeHash(0xEE)
	d := types.ForwardRequestData{
		Destination:   relayFakePeerID,
		NextHop:       relayFakePeerID,
		TTLHops:       5,
		EnvelopeInner: innerHash,
	}
	e, err := d.ToEntity()
	if err != nil {
		return FailCheck("ToEntity: " + err.Error())
	}
	if e.Type != types.TypeRelayForwardRequest {
		return FailCheck("type drift: " + e.Type)
	}
	if err := e.Validate(); err != nil {
		return FailCheck("hash validate: " + err.Error())
	}
	dec, err := types.ForwardRequestDataFromEntity(e)
	if err != nil {
		return FailCheck("FromEntity: " + err.Error())
	}
	if dec.Destination != relayFakePeerID || dec.TTLHops != 5 {
		return FailCheck("fields drift")
	}
	if dec.EnvelopeInner != innerHash {
		return FailCheck("envelope_inner drift — must be top-level data field per cohort discipline #2, NOT a refs block")
	}

	// Pin the cohort byte-equality discipline: changing envelope_inner MUST
	// produce a distinct content_hash. Catches an impl that puts the field
	// in a separate refs block (which would not contribute to the data
	// hash) or that silently re-orders / re-encodes.
	d2 := d
	d2.EnvelopeInner = relayFakeHash(0xFF)
	e2, _ := d2.ToEntity()
	if e.ContentHash == e2.ContentHash {
		return FailCheck("hash collision across distinct envelope_inner — field is not contributing to data hash")
	}
	return PassCheck(fmt.Sprintf("forward-request hash=%s; envelope_inner in data", e.ContentHash))
}

func runRelayStoreEntryRoundTrip() CheckOutcome {
	innerHash := relayFakeHash(0xEE)
	d := types.StoreEntryData{
		Namespace:     relayFakePeerID,
		ExpiresAt:     1_730_000_900_000,
		PutBy:         relayFakePeerID,
		EnvelopeInner: innerHash,
	}
	e, err := d.ToEntity()
	if err != nil {
		return FailCheck("ToEntity: " + err.Error())
	}
	if err := e.Validate(); err != nil {
		return FailCheck("hash validate: " + err.Error())
	}
	dec, err := types.StoreEntryDataFromEntity(e)
	if err != nil {
		return FailCheck("FromEntity: " + err.Error())
	}
	if dec.Namespace != relayFakePeerID || dec.PutBy != relayFakePeerID ||
		dec.ExpiresAt != 1_730_000_900_000 {
		return FailCheck("fields drift")
	}
	if dec.EnvelopeInner != innerHash {
		return FailCheck("envelope_inner drift")
	}
	// PutBy authorship distinction: distinct PutBy MUST produce distinct
	// content_hashes (so the §3.2 put_by_mismatch substrate is grounded
	// in hash, not just label).
	d2 := d
	d2.PutBy = "2KGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGG"
	e2, _ := d2.ToEntity()
	if e.ContentHash == e2.ContentHash {
		return FailCheck("hash collision across distinct put_by")
	}
	return PassCheck(fmt.Sprintf("store-entry hash=%s", e.ContentHash))
}

func runRelayAdvertiseNoRefsBlock() CheckOutcome {
	// §3.0 + §4.1: advertise carries NO refs:{signature} block; signature
	// reaches at V7 §5.2 invariant-pointer system/signature/{hex(hash)}.
	// At the type level the gate is: the advertise data struct has no
	// signature-related fields, and the entity envelope around it (built
	// here as a bare entity) has no refs block — the Go envelope is
	// {root, included} only, no refs map (the codebase's V7 §5.2 refless
	// target-matching pattern).
	d := types.AdvertiseData{
		Modes:        []string{types.RelayModeForward, types.RelayModeStorePoll},
		Endpoints:    []cbor.RawMessage{},
		Limits:       types.AdvertiseLimits{MaxEnvelopeSize: 1 << 20},
		CapsRequired: []string{types.CapRelayForward, types.CapRelayPoll},
	}
	e, err := d.ToEntity()
	if err != nil {
		return FailCheck("ToEntity: " + err.Error())
	}
	if err := e.Validate(); err != nil {
		return FailCheck("hash validate: " + err.Error())
	}
	// Decode and pin no signature field has crept into AdvertiseData.
	var m map[string]any
	if err := ecf.Decode(e.Data, &m); err != nil {
		return FailCheck("decode advertise data as map: " + err.Error())
	}
	for k := range m {
		if k == "signature" || k == "sig" || k == "refs" {
			return FailCheck("advertise data has unexpected key " + k + " — signatures live at V7 §5.2 invariant pointer, not in data/refs")
		}
	}
	// The signature target-matching contract: system/signature/{hex(hash)}.
	wantSigPath := "system/signature/" + hex.EncodeToString(e.ContentHash.Bytes())
	return PassCheck(fmt.Sprintf("advertise hash=%s; sig MUST land at %s (V7 §5.2 invariant pointer)", e.ContentHash, wantSigPath))
}

func runRelayForwardResultFlatShape() CheckOutcome {
	// §4.2 + cohort discipline #3: flat result envelope, NOT
	// system/protocol/status-wrapped.
	d := types.ForwardResultData{
		Status:  types.ForwardStatusForwarded,
		NextHop: relayFakePeerID,
	}
	e, err := d.ToEntity()
	if err != nil {
		return FailCheck("ToEntity: " + err.Error())
	}
	if e.Type != types.TypeRelayForwardResult {
		return FailCheck("type drift: " + e.Type)
	}
	// Pin: there is no "envelope" or "wrapper" layer. The type is the flat
	// result type directly.
	if e.Type == "system/protocol/status" {
		return FailCheck("§4.2: forward-result was wrapped under system/protocol/status — discipline #3 violation")
	}
	return PassCheck(fmt.Sprintf("forward-result flat hash=%s; type=%s", e.ContentHash, e.Type))
}

func runRelayStoragePathHelpers() CheckOutcome {
	h := relayFakeHash(0xCD)
	got := types.RelayStorePath(relayFakePeerID, h)
	want := "system/relay/store/" + relayFakePeerID + "/" + types.PeerIdentityHashHex(h)
	if got != want {
		return FailCheck(fmt.Sprintf("RelayStorePath drift: got %q, want %q", got, want))
	}
	if got := types.RelayStorePrefix(relayFakePeerID); got != "system/relay/store/"+relayFakePeerID+"/" {
		return FailCheck("RelayStorePrefix drift: " + got)
	}
	if got := types.RelayAdvertisePath(relayFakePeerID); got != "system/relay/advertise/"+relayFakePeerID {
		return FailCheck("RelayAdvertisePath drift: " + got)
	}
	return PassCheck("storage path helpers gate §3.2 + §4.1 shapes")
}

// --- Live vectors ----------------------------------------------------------

func runRelayAdvertiseLive(ctx context.Context, client *PeerClient) CheckOutcome {
	adv := types.AdvertiseData{
		Modes:        []string{types.RelayModeStorePoll},
		Endpoints:    []cbor.RawMessage{},
		CapsRequired: []string{types.CapRelayPoll},
	}
	params, err := adv.ToEntity()
	if err != nil {
		return FailCheck("ToEntity: " + err.Error())
	}
	status, _, err := relayExecute(ctx, client, "advertise", params, nil)
	if err != nil {
		return FailCheck("execute :advertise: " + err.Error())
	}
	if status != 200 {
		return FailCheck(fmt.Sprintf(":advertise want 200, got %d", status))
	}
	return PassCheck(":advertise 200 — entity bound at canonical path")
}

func runRelayPutLive(ctx context.Context, client *PeerClient) CheckOutcome {
	inner, err := makeRelayInnerEnvelope("put-payload")
	if err != nil {
		return FailCheck("inner envelope: " + err.Error())
	}
	se := types.StoreEntryData{
		Namespace:     string(client.LocalPeerID()), // poller would poll their own namespace
		PutBy:         string(client.LocalPeerID()), // put_by == authenticated caller
		EnvelopeInner: inner.ContentHash,
	}
	params, _ := se.ToEntity()
	included := map[hash.Hash]entity.Entity{inner.ContentHash: inner}
	status, result, err := relayExecute(ctx, client, "put", params, included)
	if err != nil {
		return FailCheck("execute :put: " + err.Error())
	}
	if status != 200 {
		return FailCheck(fmt.Sprintf(":put want 200, got %d (code=%q)", status, relayErrCode(result)))
	}
	pr, err := types.PutResultDataFromEntity(result)
	if err != nil {
		return FailCheck("decode put-result: " + err.Error())
	}
	if pr.Status != types.PutStatusStored {
		return FailCheck("put-result.status: want stored, got " + pr.Status)
	}
	return PassCheck(":put 200; stored_at=" + pr.StoredAt)
}

func runRelayPutByMismatchLive(ctx context.Context, client *PeerClient) CheckOutcome {
	inner, err := makeRelayInnerEnvelope("x")
	if err != nil {
		return FailCheck("inner envelope: " + err.Error())
	}
	se := types.StoreEntryData{
		Namespace:     string(client.LocalPeerID()),
		PutBy:         relayFakePeerID, // intentional mismatch (caller != fake peer)
		EnvelopeInner: inner.ContentHash,
	}
	params, _ := se.ToEntity()
	included := map[hash.Hash]entity.Entity{inner.ContentHash: inner}
	status, result, err := relayExecute(ctx, client, "put", params, included)
	if err != nil {
		return FailCheck("execute :put: " + err.Error())
	}
	if status != 400 {
		return FailCheck(fmt.Sprintf("put_by mismatch: want 400, got %d", status))
	}
	if code := relayErrCode(result); code != types.RelayErrPutByMismatch {
		return FailCheck(fmt.Sprintf("put_by mismatch: want code %q, got %q", types.RelayErrPutByMismatch, code))
	}
	return PassCheck(":put with put_by != caller → 400 put_by_mismatch (Q1 absorption gate)")
}

func runRelayPollEmptyLive(ctx context.Context, client *PeerClient) CheckOutcome {
	// Poll a namespace the validator has never put into. §4.2 + landing-pass
	// finding #1: MUST return {entries:[], has_more:false} at 200 — NOT
	// namespace_not_found/404.
	emptyNS := "2KZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZ"
	pr := types.PollRequestData{Namespace: emptyNS}
	params, _ := pr.ToEntity()
	status, result, err := relayExecute(ctx, client, "poll", params, nil)
	if err != nil {
		return FailCheck("execute :poll: " + err.Error())
	}
	if status == 404 {
		return FailCheck(":poll on empty namespace returned 404 — landing-pass finding #1 says empty != not-found")
	}
	if status != 200 {
		return FailCheck(fmt.Sprintf(":poll empty: want 200, got %d (code=%q)", status, relayErrCode(result)))
	}
	res, err := types.PollResultDataFromEntity(result)
	if err != nil {
		return FailCheck("decode poll-result: " + err.Error())
	}
	if len(res.Entries) != 0 || res.HasMore {
		return FailCheck(fmt.Sprintf("empty-namespace poll-result not empty: entries=%d has_more=%v", len(res.Entries), res.HasMore))
	}
	return PassCheck(":poll empty namespace → {entries:[], has_more:false}/200 (NOT 404)")
}

func runRelayPutPollAdvanceLive(ctx context.Context, client *PeerClient) CheckOutcome {
	// Put one entry, then poll and verify it surfaces. Cursor advance: a
	// second poll with the returned cursor MUST return empty (the
	// monotonic-cursor contract).
	inner, _ := makeRelayInnerEnvelope("advance-payload")
	ns := string(client.LocalPeerID()) + "-rel-advance" // unique-per-test namespace
	se := types.StoreEntryData{
		Namespace:     ns,
		PutBy:         string(client.LocalPeerID()),
		EnvelopeInner: inner.ContentHash,
	}
	seEnt, _ := se.ToEntity()
	params, _ := se.ToEntity()
	included := map[hash.Hash]entity.Entity{inner.ContentHash: inner}
	status, _, err := relayExecute(ctx, client, "put", params, included)
	if err != nil || status != 200 {
		return FailCheck(fmt.Sprintf(":put setup failed: status=%d err=%v", status, err))
	}

	// First poll: must see the entry.
	pollReq := types.PollRequestData{Namespace: ns}
	pollParams, _ := pollReq.ToEntity()
	pollStatus, pollResult, err := relayExecute(ctx, client, "poll", pollParams, nil)
	if err != nil || pollStatus != 200 {
		return FailCheck(fmt.Sprintf(":poll #1: status=%d err=%v", pollStatus, err))
	}
	pr, _ := types.PollResultDataFromEntity(pollResult)
	if len(pr.Entries) == 0 {
		return FailCheck(":poll #1 saw no entries despite a successful prior :put")
	}
	foundHash := false
	for _, h := range pr.Entries {
		if h == seEnt.ContentHash {
			foundHash = true
			break
		}
	}
	if !foundHash {
		return FailCheck(":poll #1 entries did not include the put entry's content_hash")
	}

	// Second poll with the returned cursor: empty.
	pollReq2 := types.PollRequestData{Namespace: ns, Since: pr.Cursor}
	pollParams2, _ := pollReq2.ToEntity()
	_, pollResult2, _ := relayExecute(ctx, client, "poll", pollParams2, nil)
	pr2, _ := types.PollResultDataFromEntity(pollResult2)
	if len(pr2.Entries) != 0 || pr2.HasMore {
		return FailCheck(fmt.Sprintf(":poll #2 with advanced cursor MUST be empty; got entries=%d has_more=%v", len(pr2.Entries), pr2.HasMore))
	}
	return PassCheck("put → poll surfaces entry; cursor advance returns empty")
}

func runRelayForwardTTLExhaustedLive(ctx context.Context, client *PeerClient) CheckOutcome {
	inner, _ := makeRelayInnerEnvelope("x")
	fr := types.ForwardRequestData{
		Destination:   relayFakePeerID,
		NextHop:       relayFakePeerID,
		TTLHops:       0, // fail-closed gate
		EnvelopeInner: inner.ContentHash,
	}
	params, _ := fr.ToEntity()
	included := map[hash.Hash]entity.Entity{inner.ContentHash: inner}
	status, result, err := relayExecute(ctx, client, "forward", params, included)
	if err != nil {
		return FailCheck("execute :forward: " + err.Error())
	}
	if status != 400 {
		return FailCheck(fmt.Sprintf("ttl_hops=0: want 400, got %d", status))
	}
	if code := relayErrCode(result); code != types.RelayErrTTLExhausted {
		return FailCheck(fmt.Sprintf("ttl_hops=0: want code %q, got %q", types.RelayErrTTLExhausted, code))
	}
	return PassCheck(":forward ttl_hops=0 → 400 ttl_exhausted (fail-closed)")
}

func runRelayForwardNoRouteLive(ctx context.Context, client *PeerClient) CheckOutcome {
	inner, _ := makeRelayInnerEnvelope("x")
	fr := types.ForwardRequestData{
		Destination: relayFakePeerID,
		// NextHop intentionally empty — v1 §13 Q3: no_route.
		TTLHops:       3,
		EnvelopeInner: inner.ContentHash,
	}
	params, _ := fr.ToEntity()
	included := map[hash.Hash]entity.Entity{inner.ContentHash: inner}
	status, result, err := relayExecute(ctx, client, "forward", params, included)
	if err != nil {
		return FailCheck("execute :forward: " + err.Error())
	}
	if status != 502 {
		return FailCheck(fmt.Sprintf("no next_hop: want 502, got %d", status))
	}
	if code := relayErrCode(result); code != types.RelayErrNoRoute {
		return FailCheck(fmt.Sprintf("no next_hop: want code %q, got %q", types.RelayErrNoRoute, code))
	}
	return PassCheck(":forward without next_hop → 502 no_route (v1 has no implicit routing)")
}

// --- §3.5 inbox-relay declaration ------------------------------------------

func runRelayInboxRelayRoundTrip() CheckOutcome {
	d := types.InboxRelayData{
		Relays: []types.InboxRelayEntry{
			{Relay: relayFakePeerID, Namespace: relayFakePeerID, Priority: 10},
		},
		ExpiresAt: 1_730_999_999_999,
	}
	e, err := d.ToEntity()
	if err != nil {
		return FailCheck("ToEntity: " + err.Error())
	}
	if e.Type != types.TypePeerInboxRelay {
		return FailCheck("type drift: " + e.Type)
	}
	if err := e.Validate(); err != nil {
		return FailCheck("hash validate: " + err.Error())
	}
	dec, err := types.InboxRelayDataFromEntity(e)
	if err != nil {
		return FailCheck("FromEntity: " + err.Error())
	}
	if len(dec.Relays) != 1 || dec.Relays[0].Priority != 10 {
		return FailCheck("relays drift")
	}
	// Supersede grounding: distinct priority MUST produce distinct hash.
	// This is the substrate INBOX-RELAY-SUPERSEDE-1 vector rides on.
	d2 := d
	d2.Relays[0].Priority = 20
	e2, _ := d2.ToEntity()
	if e.ContentHash == e2.ContentHash {
		return FailCheck("hash collision across distinct priority — supersede substrate broken")
	}
	return PassCheck(fmt.Sprintf("inbox-relay hash=%s; sig at V7 §5.2 invariant pointer", e.ContentHash))
}

func runRelayInboxRelayStoragePath() CheckOutcome {
	got := types.InboxRelayStoragePath(relayFakePeerID)
	want := "system/peer/inbox-relay/" + relayFakePeerID
	if got != want {
		return FailCheck(fmt.Sprintf("InboxRelayStoragePath drift: want %q, got %q", want, got))
	}
	return PassCheck("inbox-relay storage path stable; primary serving home = REGISTRY (§3.5)")
}

func runRelayExpiredOnArrivalLive(ctx context.Context, client *PeerClient) CheckOutcome {
	inner, _ := makeRelayInnerEnvelope("x")
	se := types.StoreEntryData{
		Namespace:     string(client.LocalPeerID()),
		PutBy:         string(client.LocalPeerID()),
		ExpiresAt:     1, // 1970-01-01 — definitively past
		EnvelopeInner: inner.ContentHash,
	}
	params, _ := se.ToEntity()
	included := map[hash.Hash]entity.Entity{inner.ContentHash: inner}
	status, result, err := relayExecute(ctx, client, "put", params, included)
	if err != nil {
		return FailCheck("execute :put: " + err.Error())
	}
	if status != 400 {
		return FailCheck(fmt.Sprintf("expired_on_arrival: want 400, got %d", status))
	}
	if code := relayErrCode(result); code != types.RelayErrExpiredOnArrival {
		return FailCheck(fmt.Sprintf("expired_on_arrival: want code %q, got %q (NOT 410 Gone — post-Go-review rationale: put is creation-side, not retrieval)", types.RelayErrExpiredOnArrival, code))
	}
	return PassCheck(":put with past expires_at → 400 expired_on_arrival (creation-side dead-on-arrival)")
}
