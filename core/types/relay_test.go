package types

import (
	"bytes"
	"testing"

	"go.entitychurch.org/entity-core-go/core/ecf"
	"go.entitychurch.org/entity-core-go/core/hash"

	"github.com/fxamacker/cbor/v2"
)

func relayFakeHash(b byte) hash.Hash {
	var h hash.Hash
	h.Algorithm = hash.AlgorithmSHA256
	h.Digest[0] = b
	return h
}

// relayFakePeerID — deterministic Base58-shaped string for fixture use. Same
// convention as discovery_test.go + published_root_test.go (no cryptographic
// derivation here — the cross-impl cohort byte-equal fixture lives in
// cmd/internal/validate at R4/R5).
const (
	relayFakePeerIDSender = "2KSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSS"
	relayFakePeerIDRelay  = "2KRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRR"
	relayFakePeerIDDest   = "2KDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDD"
)

// -----------------------------------------------------------------------
// system/relay/forward-request (§3.1)
// -----------------------------------------------------------------------

func TestForwardRequestRoundtripExplicitHop(t *testing.T) {
	innerHash := relayFakeHash(0xEE)
	d := ForwardRequestData{
		Destination:   relayFakePeerIDDest,
		NextHop:       relayFakePeerIDRelay,
		TTLHops:       8,
		EnvelopeInner: innerHash,
	}
	e, err := d.ToEntity()
	if err != nil {
		t.Fatalf("ToEntity: %v", err)
	}
	if e.Type != TypeRelayForwardRequest {
		t.Fatalf("type drift: %q", e.Type)
	}
	if err := e.Validate(); err != nil {
		t.Fatalf("validate hash: %v", err)
	}
	dec, err := ForwardRequestDataFromEntity(e)
	if err != nil {
		t.Fatalf("FromEntity: %v", err)
	}
	if dec.Destination != relayFakePeerIDDest {
		t.Fatalf("Destination drift: %q", dec.Destination)
	}
	if dec.NextHop != relayFakePeerIDRelay {
		t.Fatalf("NextHop drift: %q", dec.NextHop)
	}
	if dec.TTLHops != 8 {
		t.Fatalf("TTLHops drift: %d", dec.TTLHops)
	}
	if !bytes.Equal(dec.EnvelopeInner.Bytes(), innerHash.Bytes()) {
		t.Fatalf("EnvelopeInner drift")
	}
}

func TestForwardRequestNextHopOmitempty(t *testing.T) {
	// §3.1: NextHop is optional. Empty string MUST drop from the wire (a
	// next_hop-absent envelope is distinct from one carrying next_hop: "" on
	// ECF — primitive/string.0 vs absent — and the absent form is canonical
	// for "no explicit routing hint." Routing without NextHop is per §6.2.1
	// fallback / no_route per §4.3.
	d := ForwardRequestData{
		Destination:   relayFakePeerIDDest,
		TTLHops:       4,
		EnvelopeInner: relayFakeHash(0xEE),
	}
	e, _ := d.ToEntity()
	dec, err := ForwardRequestDataFromEntity(e)
	if err != nil {
		t.Fatalf("FromEntity: %v", err)
	}
	if dec.NextHop != "" {
		t.Fatalf("NextHop should be empty (omitempty) on absence, got %q", dec.NextHop)
	}
}

func TestForwardRequestHashStability(t *testing.T) {
	mk := func() ForwardRequestData {
		return ForwardRequestData{
			Destination:   relayFakePeerIDDest,
			NextHop:       relayFakePeerIDRelay,
			TTLHops:       5,
			EnvelopeInner: relayFakeHash(0xEE),
		}
	}
	e1, _ := mk().ToEntity()
	e2, _ := mk().ToEntity()
	if e1.ContentHash != e2.ContentHash {
		t.Fatalf("hash drift across equal inputs: %x vs %x",
			e1.ContentHash.Bytes(), e2.ContentHash.Bytes())
	}
	// TTLHops change → distinct hash (no integer collapse).
	d3 := mk()
	d3.TTLHops = 6
	e3, _ := d3.ToEntity()
	if e1.ContentHash == e3.ContentHash {
		t.Fatal("hash collision across distinct TTLHops")
	}
	// Destination change → distinct hash.
	d4 := mk()
	d4.Destination = relayFakePeerIDSender
	e4, _ := d4.ToEntity()
	if e1.ContentHash == e4.ContentHash {
		t.Fatal("hash collision across distinct Destination")
	}
}

// TestForwardRequestRouteFieldRoundtrip exercises the source-routed multi-hop
// addition (PROPOSAL-RELAY-SOURCE-ROUTED-MULTIHOP §2.1). A non-empty Route
// round-trips byte-for-byte through ECF.
func TestForwardRequestRouteFieldRoundtrip(t *testing.T) {
	d := ForwardRequestData{
		Destination:   relayFakePeerIDDest,
		Route:         []string{relayFakePeerIDRelay, relayFakePeerIDDest},
		NextHop:       relayFakePeerIDRelay, // proposal §2.1: when both set, MUST equal Route[0]
		TTLHops:       8,
		EnvelopeInner: relayFakeHash(0xEE),
	}
	e, err := d.ToEntity()
	if err != nil {
		t.Fatalf("ToEntity: %v", err)
	}
	dec, err := ForwardRequestDataFromEntity(e)
	if err != nil {
		t.Fatalf("FromEntity: %v", err)
	}
	if len(dec.Route) != 2 ||
		dec.Route[0] != relayFakePeerIDRelay ||
		dec.Route[1] != relayFakePeerIDDest {
		t.Fatalf("Route drift: %v", dec.Route)
	}
}

// TestForwardRequestRouteOmitemptyMatchesLegacyShape pins the ECF byte-equal
// guarantee: a v1.0 single-hop forward-request (Route absent) encodes
// identically to itself with the new struct shape — adding the Route field
// is a non-breaking wire addition.
func TestForwardRequestRouteOmitemptyMatchesLegacyShape(t *testing.T) {
	withoutRoute := ForwardRequestData{
		Destination:   relayFakePeerIDDest,
		NextHop:       relayFakePeerIDDest,
		TTLHops:       4,
		EnvelopeInner: relayFakeHash(0xEE),
	}
	withNilRoute := ForwardRequestData{
		Destination:   relayFakePeerIDDest,
		Route:         nil, // explicit nil — omitempty MUST drop it
		NextHop:       relayFakePeerIDDest,
		TTLHops:       4,
		EnvelopeInner: relayFakeHash(0xEE),
	}
	e1, _ := withoutRoute.ToEntity()
	e2, _ := withNilRoute.ToEntity()
	if !bytes.Equal(e1.Data, e2.Data) {
		t.Fatalf("ECF byte drift between zero-value Route and explicit nil Route:\n  %x\n  %x", e1.Data, e2.Data)
	}
	if e1.ContentHash != e2.ContentHash {
		t.Fatal("content_hash drift across Route nil vs absent")
	}
}

// TestForwardRequestRouteDistinguishesHash — distinct routes hash distinct.
func TestForwardRequestRouteDistinguishesHash(t *testing.T) {
	mk := func(route []string) ForwardRequestData {
		return ForwardRequestData{
			Destination:   relayFakePeerIDDest,
			Route:         route,
			NextHop:       relayFakePeerIDRelay,
			TTLHops:       5,
			EnvelopeInner: relayFakeHash(0xEE),
		}
	}
	e1, _ := mk([]string{relayFakePeerIDRelay, relayFakePeerIDDest}).ToEntity()
	e2, _ := mk([]string{relayFakePeerIDRelay, relayFakePeerIDSender, relayFakePeerIDDest}).ToEntity()
	if e1.ContentHash == e2.ContentHash {
		t.Fatal("hash collision across distinct Route lengths")
	}
	// Reordering the path → distinct hash (path is ordered).
	e3, _ := mk([]string{relayFakePeerIDDest, relayFakePeerIDRelay}).ToEntity()
	if e1.ContentHash == e3.ContentHash {
		t.Fatal("hash collision across reordered Route")
	}
}

// -----------------------------------------------------------------------
// system/relay/store-entry (§3.2)
// -----------------------------------------------------------------------

func TestStoreEntryRoundtripFullFields(t *testing.T) {
	innerHash := relayFakeHash(0xEE)
	d := StoreEntryData{
		Namespace:     relayFakePeerIDDest, // §6.2.1 fallback convention: namespace = destination peer_id
		ExpiresAt:     1_730_000_900_000,
		PutBy:         relayFakePeerIDRelay, // §6.2.1: PutBy is the forwarding relay, NOT the origin (authorship comes from the inner envelope signature)
		EnvelopeInner: innerHash,
	}
	e, err := d.ToEntity()
	if err != nil {
		t.Fatalf("ToEntity: %v", err)
	}
	if e.Type != TypeRelayStoreEntry {
		t.Fatalf("type drift: %q", e.Type)
	}
	if err := e.Validate(); err != nil {
		t.Fatalf("validate hash: %v", err)
	}
	dec, err := StoreEntryDataFromEntity(e)
	if err != nil {
		t.Fatalf("FromEntity: %v", err)
	}
	if dec.Namespace != relayFakePeerIDDest {
		t.Fatalf("Namespace drift: %q", dec.Namespace)
	}
	if dec.ExpiresAt != 1_730_000_900_000 {
		t.Fatalf("ExpiresAt drift: %d", dec.ExpiresAt)
	}
	if dec.PutBy != relayFakePeerIDRelay {
		t.Fatalf("PutBy drift: %q", dec.PutBy)
	}
	if !bytes.Equal(dec.EnvelopeInner.Bytes(), innerHash.Bytes()) {
		t.Fatalf("EnvelopeInner drift")
	}
}

func TestStoreEntryExpiresAtNullable(t *testing.T) {
	// §3.2: ExpiresAt nullable (0 == null). Omitempty MUST drop the field on
	// the wire so a no-expiry entry doesn't collide-hash with an explicit
	// expiresAt: 0 entry (which would be `expired_on_arrival`/400 at :put
	// time anyway per §4.3).
	d := StoreEntryData{
		Namespace:     relayFakePeerIDDest,
		PutBy:         relayFakePeerIDRelay,
		EnvelopeInner: relayFakeHash(0xEE),
	}
	e, _ := d.ToEntity()
	dec, err := StoreEntryDataFromEntity(e)
	if err != nil {
		t.Fatalf("FromEntity: %v", err)
	}
	if dec.ExpiresAt != 0 {
		t.Fatalf("ExpiresAt should be 0 on null, got %d", dec.ExpiresAt)
	}
}

func TestStoreEntryPutByAuthorshipDistinction(t *testing.T) {
	// §3.2 post-Go-review: PutBy is placement-identity, NOT authorship. The
	// §6.2.1 fallback path is the proof — there PutBy == forwarding relay
	// while authorship is the origin's inner-envelope signature. Type-level
	// invariant we can pin: two store-entries with identical Namespace +
	// ExpiresAt but distinct PutBy MUST produce distinct content_hashes (so
	// the relay's put_by_mismatch check is hash-grounded, not just
	// label-grounded).
	innerHash := relayFakeHash(0xEE)
	a, _ := StoreEntryData{
		Namespace:     relayFakePeerIDDest,
		ExpiresAt:     1_730_000_900_000,
		PutBy:         relayFakePeerIDRelay,
		EnvelopeInner: innerHash,
	}.ToEntity()
	b, _ := StoreEntryData{
		Namespace:     relayFakePeerIDDest,
		ExpiresAt:     1_730_000_900_000,
		PutBy:         relayFakePeerIDSender, // different placer
		EnvelopeInner: innerHash,
	}.ToEntity()
	if a.ContentHash == b.ContentHash {
		t.Fatal("hash collision across distinct PutBy — put_by_mismatch substrate would not work")
	}
}

// -----------------------------------------------------------------------
// system/relay/advertise (§4.1)
// -----------------------------------------------------------------------

func TestAdvertiseRoundtripBothModes(t *testing.T) {
	endpoint1, _ := ecf.Encode(map[string]any{
		"transport": "tcp",
		"addr":      "192.0.2.7",
		"port":      uint64(9002),
	})
	endpoint2, _ := ecf.Encode(map[string]any{
		"transport": "http-poll",
		"url":       "https://example.invalid/relay",
	})
	d := AdvertiseData{
		Modes: []string{RelayModeForward, RelayModeStorePoll},
		Endpoints: []cbor.RawMessage{
			cbor.RawMessage(endpoint1),
			cbor.RawMessage(endpoint2),
		},
		Limits: AdvertiseLimits{
			MaxEnvelopeSize:  1 << 20, // 1 MiB
			MaxStorageBytes:  1 << 30, // 1 GiB
			ForwardRateLimit: 100,
		},
		CapsRequired: []string{CapRelayForward, CapRelayPut, CapRelayPoll},
		ExpiresAt:    1_730_999_999_999,
	}
	e, err := d.ToEntity()
	if err != nil {
		t.Fatalf("ToEntity: %v", err)
	}
	if e.Type != TypeRelayAdvertise {
		t.Fatalf("type drift: %q", e.Type)
	}
	if err := e.Validate(); err != nil {
		t.Fatalf("validate hash: %v", err)
	}
	dec, err := AdvertiseDataFromEntity(e)
	if err != nil {
		t.Fatalf("FromEntity: %v", err)
	}
	if len(dec.Modes) != 2 || dec.Modes[0] != RelayModeForward || dec.Modes[1] != RelayModeStorePoll {
		t.Fatalf("Modes drift: %+v", dec.Modes)
	}
	if len(dec.Endpoints) != 2 {
		t.Fatalf("Endpoints count drift: %d", len(dec.Endpoints))
	}
	if !bytes.Equal(dec.Endpoints[0], cbor.RawMessage(endpoint1)) ||
		!bytes.Equal(dec.Endpoints[1], cbor.RawMessage(endpoint2)) {
		t.Fatal("Endpoints byte drift (substitute-substrate invariant)")
	}
	if dec.Limits.MaxEnvelopeSize != 1<<20 || dec.Limits.MaxStorageBytes != 1<<30 ||
		dec.Limits.ForwardRateLimit != 100 {
		t.Fatalf("Limits drift: %+v", dec.Limits)
	}
	if len(dec.CapsRequired) != 3 {
		t.Fatalf("CapsRequired drift: %+v", dec.CapsRequired)
	}
	if dec.ExpiresAt != 1_730_999_999_999 {
		t.Fatalf("ExpiresAt drift: %d", dec.ExpiresAt)
	}
}

func TestAdvertiseRoundtripStoreOnly(t *testing.T) {
	// Static-CDN-style: Mode S only, no limits, no expiry. Verifies the
	// optional-field omission path doesn't break round-trip + that an empty
	// Limits sub-struct encodes as {} (not dropped).
	d := AdvertiseData{
		Modes:        []string{RelayModeStorePoll},
		Endpoints:    []cbor.RawMessage{},
		CapsRequired: []string{CapRelayPoll}, // open-read CDN
	}
	e, _ := d.ToEntity()
	dec, err := AdvertiseDataFromEntity(e)
	if err != nil {
		t.Fatalf("FromEntity: %v", err)
	}
	if len(dec.Modes) != 1 || dec.Modes[0] != RelayModeStorePoll {
		t.Fatalf("Modes drift: %+v", dec.Modes)
	}
	if dec.Limits.MaxEnvelopeSize != 0 || dec.Limits.MaxStorageBytes != 0 ||
		dec.Limits.ForwardRateLimit != 0 {
		t.Fatalf("Limits drift on empty round-trip: %+v", dec.Limits)
	}
	if dec.ExpiresAt != 0 {
		t.Fatalf("ExpiresAt should be 0 (null) on omission, got %d", dec.ExpiresAt)
	}
}

// -----------------------------------------------------------------------
// system/relay/forward-result (§4.2)
// -----------------------------------------------------------------------

func TestForwardResultForwarded(t *testing.T) {
	d := ForwardResultData{
		Status:  ForwardStatusForwarded,
		NextHop: relayFakePeerIDRelay,
	}
	e, _ := d.ToEntity()
	if e.Type != TypeRelayForwardResult {
		t.Fatalf("type drift: %q", e.Type)
	}
	dec, err := ForwardResultDataFromEntity(e)
	if err != nil {
		t.Fatalf("FromEntity: %v", err)
	}
	if dec.Status != ForwardStatusForwarded {
		t.Fatalf("Status drift: %q", dec.Status)
	}
	if dec.NextHop != relayFakePeerIDRelay {
		t.Fatalf("NextHop drift: %q", dec.NextHop)
	}
	if dec.StoredAt != "" {
		t.Fatalf("StoredAt should be empty on forwarded, got %q", dec.StoredAt)
	}
}

func TestForwardResultQueuedFallback(t *testing.T) {
	// §4.2 + §6.2.1 (Rust R6 catch): forward-result.stored_at is the BARE
	// NAMESPACE (= destination peer_id), NOT the full store path. Spec
	// comment: "namespace, if queued-fallback". This is what the destination
	// passes to :poll. Distinct from put-result.stored_at which IS the full
	// `system/relay/store/{namespace}/{hash}` path (its spec comment pins
	// the path-with-hash shape).
	storedAt := relayFakePeerIDDest
	d := ForwardResultData{
		Status:   ForwardStatusQueuedFallback,
		StoredAt: storedAt,
	}
	e, _ := d.ToEntity()
	dec, err := ForwardResultDataFromEntity(e)
	if err != nil {
		t.Fatalf("FromEntity: %v", err)
	}
	if dec.Status != ForwardStatusQueuedFallback {
		t.Fatalf("Status drift: %q", dec.Status)
	}
	if dec.StoredAt != storedAt {
		t.Fatalf("StoredAt drift: %q", dec.StoredAt)
	}
	if dec.NextHop != "" {
		t.Fatalf("NextHop should be empty on queued-fallback, got %q", dec.NextHop)
	}
}

// -----------------------------------------------------------------------
// system/relay/put-result (§4.2)
// -----------------------------------------------------------------------

func TestPutResultRoundtrip(t *testing.T) {
	entryHash := relayFakeHash(0xCC)
	storedAt := RelayStorePath(relayFakePeerIDDest, entryHash)
	d := PutResultData{
		Status:    PutStatusStored,
		StoredAt:  storedAt,
		EntryHash: entryHash,
		ExpiresAt: 1_730_000_900_000,
	}
	e, _ := d.ToEntity()
	if e.Type != TypeRelayPutResult {
		t.Fatalf("type drift: %q", e.Type)
	}
	dec, err := PutResultDataFromEntity(e)
	if err != nil {
		t.Fatalf("FromEntity: %v", err)
	}
	if dec.Status != PutStatusStored {
		t.Fatalf("Status drift: %q", dec.Status)
	}
	if dec.StoredAt != storedAt {
		t.Fatalf("StoredAt drift: %q", dec.StoredAt)
	}
	if !bytes.Equal(dec.EntryHash.Bytes(), entryHash.Bytes()) {
		t.Fatalf("EntryHash drift")
	}
	if dec.ExpiresAt != 1_730_000_900_000 {
		t.Fatalf("ExpiresAt drift: %d", dec.ExpiresAt)
	}
}

// -----------------------------------------------------------------------
// system/relay/poll-request + poll-result (§4.2)
// -----------------------------------------------------------------------

func TestPollRequestFreshStart(t *testing.T) {
	// First poll: Since absent (omitempty drops on nil), Limit absent.
	d := PollRequestData{
		Namespace: relayFakePeerIDDest,
	}
	e, _ := d.ToEntity()
	dec, err := PollRequestDataFromEntity(e)
	if err != nil {
		t.Fatalf("FromEntity: %v", err)
	}
	if dec.Namespace != relayFakePeerIDDest {
		t.Fatalf("Namespace drift: %q", dec.Namespace)
	}
	if len(dec.Since) != 0 {
		t.Fatalf("Since should be empty on fresh poll, got %x", dec.Since)
	}
	if dec.Limit != 0 {
		t.Fatalf("Limit should be 0 on absence, got %d", dec.Limit)
	}
}

func TestPollRequestContinue(t *testing.T) {
	d := PollRequestData{
		Namespace: relayFakePeerIDDest,
		Since:     cbor.RawMessage{0x44, 0xDE, 0xAD, 0xBE, 0xEF}, // CBOR bstr(4)
		Limit:     50,
	}
	e, _ := d.ToEntity()
	dec, err := PollRequestDataFromEntity(e)
	if err != nil {
		t.Fatalf("FromEntity: %v", err)
	}
	if !bytes.Equal(dec.Since, cbor.RawMessage{0x44, 0xDE, 0xAD, 0xBE, 0xEF}) {
		t.Fatalf("Since drift: %x", dec.Since)
	}
	if dec.Limit != 50 {
		t.Fatalf("Limit drift: %d", dec.Limit)
	}
}

func TestPollResultEmpty(t *testing.T) {
	// §4.2 + landing-pass finding #1: empty namespace returns
	// {entries: [], has_more: false} at 200, NOT namespace_not_found/404.
	// Pin the type-level round-trip; the handler enforces the status code at
	// R2.
	// Cursor as a CBOR-encoded byte string (Go's chosen format). Per cohort
	// R6/R7 the wire shape is impl choice — Python emits text strings; here
	// we use Go's bstr form. cbor.RawMessage holds the pre-encoded CBOR.
	d := PollResultData{
		Entries: []hash.Hash{},
		Cursor:  cbor.RawMessage{0x40}, // CBOR bstr(0) — empty byte string, "fresh state"
		HasMore: false,
	}
	e, _ := d.ToEntity()
	if e.Type != TypeRelayPollResult {
		t.Fatalf("type drift: %q", e.Type)
	}
	dec, err := PollResultDataFromEntity(e)
	if err != nil {
		t.Fatalf("FromEntity: %v", err)
	}
	if len(dec.Entries) != 0 {
		t.Fatalf("Entries should be empty, got %d", len(dec.Entries))
	}
	if dec.HasMore {
		t.Fatal("HasMore should be false on empty result")
	}
}

func TestPollResultWithEntries(t *testing.T) {
	entries := []hash.Hash{relayFakeHash(0x01), relayFakeHash(0x02), relayFakeHash(0x03)}
	// Cursor: CBOR bstr(3) = 0x43 + 3 raw bytes.
	cursorCBOR := cbor.RawMessage{0x43, 0x01, 0x02, 0x03}
	d := PollResultData{
		Entries: entries,
		Cursor:  cursorCBOR,
		HasMore: true,
	}
	e, _ := d.ToEntity()
	dec, err := PollResultDataFromEntity(e)
	if err != nil {
		t.Fatalf("FromEntity: %v", err)
	}
	if len(dec.Entries) != 3 {
		t.Fatalf("Entries count drift: %d", len(dec.Entries))
	}
	for i, want := range entries {
		if !bytes.Equal(dec.Entries[i].Bytes(), want.Bytes()) {
			t.Fatalf("Entries[%d] drift", i)
		}
	}
	if !bytes.Equal(dec.Cursor, cursorCBOR) {
		t.Fatalf("Cursor drift: %x", dec.Cursor)
	}
	if !dec.HasMore {
		t.Fatal("HasMore should be true")
	}
}

// -----------------------------------------------------------------------
// Storage path helpers (§3.2, §4.1).
// -----------------------------------------------------------------------

func TestRelayPathHelpers(t *testing.T) {
	h := relayFakeHash(0xAB)
	got := RelayStorePath(relayFakePeerIDDest, h)
	want := "system/relay/store/" + relayFakePeerIDDest + "/" + PeerIdentityHashHex(h)
	if got != want {
		t.Fatalf("RelayStorePath: want %q got %q", want, got)
	}
	if got := RelayStorePrefix(relayFakePeerIDDest); got != "system/relay/store/"+relayFakePeerIDDest+"/" {
		t.Fatalf("RelayStorePrefix drift: %q", got)
	}
	if got := RelayAdvertisePath(relayFakePeerIDRelay); got != "system/relay/advertise/"+relayFakePeerIDRelay {
		t.Fatalf("RelayAdvertisePath drift: %q", got)
	}
	// RULING-RELAY-RECEIVE-SIDE-FETCH-SURFACE: inner under same
	// namespace subtree as the store-entry.
	innerH := relayFakeHash(0xCD)
	if got := RelayInnerPath(relayFakePeerIDDest, innerH); got != "system/relay/store/"+relayFakePeerIDDest+"/inner/"+PeerIdentityHashHex(innerH) {
		t.Fatalf("RelayInnerPath drift: %q", got)
	}
	if got := RelayInnerPrefix(relayFakePeerIDDest); got != "system/relay/store/"+relayFakePeerIDDest+"/inner/" {
		t.Fatalf("RelayInnerPrefix drift: %q", got)
	}
}

// -----------------------------------------------------------------------
// Registry wiring (mirror of TestDiscoveryTypesRegistered).
// -----------------------------------------------------------------------

// -----------------------------------------------------------------------
// §3.5 system/peer/inbox-relay (MX-equivalent declaration)
// -----------------------------------------------------------------------

func TestInboxRelayRoundtripTwoRelays(t *testing.T) {
	d := InboxRelayData{
		Relays: []InboxRelayEntry{
			{Relay: relayFakePeerIDRelay, Namespace: relayFakePeerIDDest, Priority: 10},
			{Relay: relayFakePeerIDSender, Namespace: relayFakePeerIDDest, Priority: 50}, // backup
		},
		ExpiresAt: 1_730_999_999_999,
	}
	e, err := d.ToEntity()
	if err != nil {
		t.Fatalf("ToEntity: %v", err)
	}
	if e.Type != TypePeerInboxRelay {
		t.Fatalf("type drift: %q", e.Type)
	}
	if err := e.Validate(); err != nil {
		t.Fatalf("validate: %v", err)
	}
	dec, err := InboxRelayDataFromEntity(e)
	if err != nil {
		t.Fatalf("FromEntity: %v", err)
	}
	if len(dec.Relays) != 2 {
		t.Fatalf("relays count drift: %d", len(dec.Relays))
	}
	if dec.Relays[0].Relay != relayFakePeerIDRelay || dec.Relays[0].Priority != 10 {
		t.Fatalf("primary relay drift: %+v", dec.Relays[0])
	}
	if dec.Relays[1].Priority != 50 {
		t.Fatalf("backup priority drift: %d", dec.Relays[1].Priority)
	}
	if dec.ExpiresAt != 1_730_999_999_999 {
		t.Fatalf("ExpiresAt drift: %d", dec.ExpiresAt)
	}
}

func TestInboxRelayRoundtripNoExpiry(t *testing.T) {
	// §3.5: expires_at: null means "until superseded". Omitempty drops it.
	d := InboxRelayData{
		Relays: []InboxRelayEntry{
			{Relay: relayFakePeerIDRelay, Namespace: relayFakePeerIDDest, Priority: 10},
		},
	}
	e, _ := d.ToEntity()
	dec, _ := InboxRelayDataFromEntity(e)
	if dec.ExpiresAt != 0 {
		t.Fatalf("ExpiresAt should be 0 (null) on absence: %d", dec.ExpiresAt)
	}
}

func TestInboxRelayHashStability(t *testing.T) {
	mk := func() InboxRelayData {
		return InboxRelayData{
			Relays: []InboxRelayEntry{
				{Relay: relayFakePeerIDRelay, Namespace: relayFakePeerIDDest, Priority: 10},
			},
		}
	}
	e1, _ := mk().ToEntity()
	e2, _ := mk().ToEntity()
	if e1.ContentHash != e2.ContentHash {
		t.Fatalf("hash drift across equal inputs: %x vs %x", e1.ContentHash.Bytes(), e2.ContentHash.Bytes())
	}
	// Changing priority MUST produce a distinct hash (so SUPERSEDE semantics
	// have a hash-grounded delta — INBOX-RELAY-SUPERSEDE-1 test vector
	// depends on this).
	d3 := mk()
	d3.Relays[0].Priority = 20
	e3, _ := d3.ToEntity()
	if e1.ContentHash == e3.ContentHash {
		t.Fatal("hash collision across distinct priority")
	}
}

func TestInboxRelayStoragePath(t *testing.T) {
	got := InboxRelayStoragePath(relayFakePeerIDDest)
	want := "system/peer/inbox-relay/" + relayFakePeerIDDest
	if got != want {
		t.Fatalf("InboxRelayStoragePath drift: want %q, got %q", want, got)
	}
}

func TestRelayTypesRegistered(t *testing.T) {
	r := NewTypeRegistry()
	RegisterCoreTypes(r)
	for _, name := range []string{
		TypeRelayForwardRequest,
		TypeRelayStoreEntry,
		TypeRelayAdvertise,
		TypeRelayForwardResult,
		TypeRelayPutResult,
		TypeRelayPollRequest,
		TypeRelayPollResult,
	} {
		if _, ok := r.Get(name); !ok {
			t.Errorf("type %q not registered", name)
		}
	}

	// forward-request.destination is mandatory Base58 (system/peer-id).
	def, _ := r.Get(TypeRelayForwardRequest)
	if fs, ok := def.Fields["destination"]; !ok || fs.TypeRef != "system/peer-id" || fs.Optional {
		t.Errorf("forward-request.destination override missing/wrong: %+v", fs)
	}
	// forward-request.next_hop is optional Base58.
	if fs, ok := def.Fields["next_hop"]; !ok || fs.TypeRef != "system/peer-id" || !fs.Optional {
		t.Errorf("forward-request.next_hop override missing/wrong: %+v", fs)
	}
	// store-entry.put_by is mandatory Base58 (§3.2 verification gate).
	def, _ = r.Get(TypeRelayStoreEntry)
	if fs, ok := def.Fields["put_by"]; !ok || fs.TypeRef != "system/peer-id" || fs.Optional {
		t.Errorf("store-entry.put_by override missing/wrong: %+v", fs)
	}
	// forward-result.next_hop is optional Base58.
	def, _ = r.Get(TypeRelayForwardResult)
	if fs, ok := def.Fields["next_hop"]; !ok || fs.TypeRef != "system/peer-id" || !fs.Optional {
		t.Errorf("forward-result.next_hop override missing/wrong: %+v", fs)
	}
}
