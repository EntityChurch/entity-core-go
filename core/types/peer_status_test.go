package types

import (
	"encoding/hex"
	"reflect"
	"testing"

	"go.entitychurch.org/entity-core-go/core/hash"
)

// TestPeerStatusRoundTrip covers the §3.13 status entity encode/decode and the
// Amendment 12 §A2 additive-optional discipline: reason/last_error omitempty so
// a peer that never sets them emits the bare {peer_id, status} shape.
func TestPeerStatusRoundTrip(t *testing.T) {
	cases := []struct {
		name string
		in   PeerStatusData
	}{
		{
			name: "bare connected (pre-A2 shape)",
			in:   PeerStatusData{PeerID: "2KabcPeerBase58", Status: PeerStatusConnected},
		},
		{
			name: "suspect with transport-error reason (A1)",
			in: PeerStatusData{
				PeerID:    "2KabcPeerBase58",
				Status:    PeerStatusSuspect,
				Reason:    PeerStatusReasonTransportError,
				LastError: "write: connection reset by peer",
			},
		},
		{
			name: "disconnected via keepalive-miss",
			in:   PeerStatusData{PeerID: "2KabcPeerBase58", Status: PeerStatusDisconnected, Reason: PeerStatusReasonKeepaliveMiss},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ent, err := tc.in.ToEntity()
			if err != nil {
				t.Fatalf("ToEntity: %v", err)
			}
			if ent.Type != TypePeerStatus {
				t.Fatalf("entity type = %q, want %q", ent.Type, TypePeerStatus)
			}
			got, err := PeerStatusDataFromEntity(ent)
			if err != nil {
				t.Fatalf("FromEntity: %v", err)
			}
			if !reflect.DeepEqual(got, tc.in) {
				t.Fatalf("round-trip mismatch:\n got  %+v\n want %+v", got, tc.in)
			}
		})
	}
}

// TestPeerStatusOmitemptyByteIdentity pins the additive-forward-compat claim:
// the bare shape and a shape whose optional fields are empty strings encode to
// identical bytes (empty ⇒ absent under omitempty), so a pre-A2 peer and an
// A2-aware peer that hasn't set reason agree on the wire.
func TestPeerStatusOmitemptyByteIdentity(t *testing.T) {
	bare, err := PeerStatusData{PeerID: "p", Status: PeerStatusConnected}.ToEntity()
	if err != nil {
		t.Fatalf("bare ToEntity: %v", err)
	}
	emptyOpt, err := PeerStatusData{PeerID: "p", Status: PeerStatusConnected, Reason: "", LastError: ""}.ToEntity()
	if err != nil {
		t.Fatalf("emptyOpt ToEntity: %v", err)
	}
	if bare.ContentHash != emptyOpt.ContentHash {
		t.Fatalf("empty optional fields changed the hash: bare=%s emptyOpt=%s", bare.ContentHash, emptyOpt.ContentHash)
	}
}

// TestPeerStatusRegistered confirms RegisterCoreTypes wires the type in so
// cross-impl type reflection (compare-types) sees it.
func TestPeerStatusRegistered(t *testing.T) {
	r := NewTypeRegistry()
	RegisterCoreTypes(r)
	if _, ok := r.Get(TypePeerStatus); !ok {
		t.Fatalf("%s not registered by RegisterCoreTypes", TypePeerStatus)
	}
}

// TestPeerStatusPath pins the path convention: /{local}/system/peer/status/{hex}
// where hex is the 33-byte (algorithm||digest) form via h.Bytes().
func TestPeerStatusPath(t *testing.T) {
	var h hash.Hash
	h.Algorithm = hash.AlgorithmSHA256
	for i := 0; i < 32; i++ {
		h.Digest[i] = byte(i)
	}
	got := PeerStatusPath("2KlocalBase58", h)
	want := "/2KlocalBase58/system/peer/status/" + hex.EncodeToString(h.Bytes())
	if got != want {
		t.Fatalf("PeerStatusPath = %q, want %q", got, want)
	}
}
