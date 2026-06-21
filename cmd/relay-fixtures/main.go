// Package main emits the EXTENSION-RELAY v1.0 byte-equal fixtures for the
// R5 cohort handoff. Reproducible derivation — no live wire — so Rust + Py
// re-deriving with the same inputs MUST produce byte-equal CBOR + the same
// content_hash, byte-for-byte.
//
// Seeds chosen to keep the fixtures small and human-decodable in `od -An
// -tx1 | head -2`; cross-impl agreement is what matters, not the input
// values themselves.
//
// Reproduce: `go run ./cmd/relay-fixtures/`.
package main

import (
	"encoding/hex"
	"fmt"

	"go.entitychurch.org/entity-core-go/core/entity"
	"go.entitychurch.org/entity-core-go/core/hash"
	"go.entitychurch.org/entity-core-go/core/types"

	"github.com/fxamacker/cbor/v2"
)

const (
	fixSender = "2KAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
	fixRelay  = "2KBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB"
	fixDest   = "2KCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC"
)

func fixHash(b byte) hash.Hash {
	var h hash.Hash
	h.Algorithm = hash.AlgorithmSHA256
	for i := 0; i < 32; i++ {
		h.Digest[i] = b
	}
	return h
}

func must(b []byte, err error) cbor.RawMessage {
	if err != nil {
		panic(err)
	}
	return cbor.RawMessage(b)
}

func mustEnt(e entity.Entity, err error) entity.Entity {
	if err != nil {
		panic(err)
	}
	return e
}

func emit(label string, e entity.Entity) {
	fmt.Printf("## %s\n", label)
	fmt.Printf("type:         %s\n", e.Type)
	fmt.Printf("data (hex):   %s\n", hex.EncodeToString(e.Data))
	fmt.Printf("content_hash: %s\n", e.ContentHash.String())
	fmt.Println()
}

func main() {
	fmt.Println("# RELAY v1.0 byte-equal fixtures — Go reference (R5 cohort handoff)")
	fmt.Println("#")
	fmt.Println("# Each fixture lists: input → ECF-encoded data bytes (hex) → wrapped entity content_hash.")
	fmt.Println("# Cross-impl convergence gate: same inputs MUST produce the SAME data bytes AND the SAME content_hash.")
	fmt.Println()

	emit("F1 forward-request (full fields)", mustEnt(types.ForwardRequestData{
		Destination:   fixDest,
		NextHop:       fixRelay,
		TTLHops:       5,
		EnvelopeInner: fixHash(0xEE),
	}.ToEntity()))

	emit("F2 forward-request (no next_hop — omitempty drops it)", mustEnt(types.ForwardRequestData{
		Destination:   fixDest,
		TTLHops:       3,
		EnvelopeInner: fixHash(0xEE),
	}.ToEntity()))

	emit("S1 store-entry (full fields)", mustEnt(types.StoreEntryData{
		Namespace:     fixDest,
		ExpiresAt:     1_730_000_900_000,
		PutBy:         fixSender,
		EnvelopeInner: fixHash(0xEE),
	}.ToEntity()))

	emit("S2 store-entry (no expires_at — omitempty drops it)", mustEnt(types.StoreEntryData{
		Namespace:     fixDest,
		PutBy:         fixSender,
		EnvelopeInner: fixHash(0xEE),
	}.ToEntity()))

	emit("A1 advertise (Mode F + Mode S, with limits + caps)", mustEnt(types.AdvertiseData{
		Modes: []string{types.RelayModeForward, types.RelayModeStorePoll},
		Endpoints: []cbor.RawMessage{
			must(cbor.Marshal(map[string]any{"transport": "tcp", "port": uint64(9002)})),
		},
		Limits: types.AdvertiseLimits{
			MaxEnvelopeSize:  1 << 20,
			MaxStorageBytes:  1 << 30,
			ForwardRateLimit: 100,
		},
		CapsRequired: []string{types.CapRelayForward, types.CapRelayPoll},
		ExpiresAt:    1_730_999_999_999,
	}.ToEntity()))

	emit("A2 advertise (Mode S only, no limits, no expiry)", mustEnt(types.AdvertiseData{
		Modes:        []string{types.RelayModeStorePoll},
		Endpoints:    []cbor.RawMessage{},
		CapsRequired: []string{types.CapRelayPoll},
	}.ToEntity()))

	emit("R1 forward-result (forwarded)", mustEnt(types.ForwardResultData{
		Status:  types.ForwardStatusForwarded,
		NextHop: fixRelay,
	}.ToEntity()))

	emit("R2 forward-result (queued-fallback at §6.2.1 rendezvous — stored_at is bare namespace per §4.2 spec comment)", mustEnt(types.ForwardResultData{
		Status:   types.ForwardStatusQueuedFallback,
		StoredAt: fixDest, // bare namespace, NOT full path (Rust R6 catch)
	}.ToEntity()))

	emit("R3 put-result", mustEnt(types.PutResultData{
		Status:    types.PutStatusStored,
		StoredAt:  types.RelayStorePath(fixDest, fixHash(0xAB)),
		EntryHash: fixHash(0xAB),
		ExpiresAt: 1_730_000_900_000,
	}.ToEntity()))

	emit("R4 poll-request (fresh — no cursor, no limit)", mustEnt(types.PollRequestData{
		Namespace: fixDest,
	}.ToEntity()))

	// Cursor is CBOR-encoded opaque; Go uses bstr(8) = 0x48 + 8 BE bytes.
	// Other impls (Python uses text strings) emit a different shape;
	// PollResultData.Cursor is cbor.RawMessage to preserve any wire form.
	emit("R5 poll-request (with cursor + limit)", mustEnt(types.PollRequestData{
		Namespace: fixDest,
		Since:     cbor.RawMessage{0x48, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x05}, // bstr(8) seq=5
		Limit:     20,
	}.ToEntity()))

	emit("R6 poll-result (empty namespace per §4.2)", mustEnt(types.PollResultData{
		Entries: []hash.Hash{},
		Cursor:  cbor.RawMessage{0x48, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}, // bstr(8) seq=0
		HasMore: false,
	}.ToEntity()))

	emit("R7 poll-result (with entries + cursor)", mustEnt(types.PollResultData{
		Entries: []hash.Hash{fixHash(0xA1), fixHash(0xA2), fixHash(0xA3)},
		Cursor:  cbor.RawMessage{0x48, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03}, // bstr(8) seq=3
		HasMore: true,
	}.ToEntity()))

	// §3.5 inbox-relay declaration (R6/R7 fold at arch faf3fa9).
	emit("I1 inbox-relay (single relay, with expiry)", mustEnt(types.InboxRelayData{
		Relays: []types.InboxRelayEntry{
			{Relay: fixRelay, Namespace: fixDest, Priority: 10},
		},
		ExpiresAt: 1_730_999_999_999,
	}.ToEntity()))

	emit("I2 inbox-relay (primary + backup, no expiry)", mustEnt(types.InboxRelayData{
		Relays: []types.InboxRelayEntry{
			{Relay: fixRelay, Namespace: fixDest, Priority: 10},
			{Relay: fixSender, Namespace: fixDest, Priority: 50}, // backup
		},
	}.ToEntity()))
}
