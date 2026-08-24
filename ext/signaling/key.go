package signaling

import (
	"go.entitychurch.org/entity-core-go/core/ecf"
	"go.entitychurch.org/entity-core-go/core/hash"

	cbor "github.com/fxamacker/cbor/v2"
)

// The rendezvous key — peer-side derivation (§2.2).
//
//	payload        = "entity:rdv:v1" ‖ SEP ‖ mode ‖ SEP ‖ canonical(mode_input)
//	rendezvous_key = varint(0x00) ‖ SHA-256( ecf_for_hash("system/signaling/rendezvous-key",
//	                                                      cbor_bstr(payload)) )
//
// This binds peers only; the node is mode-blind and derives nothing. Both peers
// MUST produce byte-identical hash input AND byte-identical key bytes, or they
// derive different keys and SILENTLY never meet — invisible to any same-impl
// test. §2.2.1 supplies differential properties (key_test.go) instead of
// authored vectors.
//
// The load-bearing pin is the format code: a rendezvous key is a lookup token
// two independent parties must reproduce, so it is pinned to the SHA-256 floor
// (0x00) REGARDLESS of the deriving peer's home hash format. This is why
// Derive calls hash.Compute (unconditionally SHA-256) and explicitly NOT
// entity.NewEntity, which hashes under the process-global default
// (entity.DefaultHashAlgorithm). key_test.go's home-format-independence test
// flips that global and proves the derivation ignores it.

// RendezvousPayload builds the pre-hash payload. Exported because §2.2.1's stage
// bisect names it as the first place two disagreeing impls compare bytes: if the
// payloads match and the keys don't, the fault is the CBOR framing or the
// digest, not the concatenation.
func RendezvousPayload(mode string, canonicalInput []byte) []byte {
	payload := make([]byte, 0, len(domain)+len(mode)+len(canonicalInput)+2)
	payload = append(payload, domain...)
	payload = append(payload, sep)
	payload = append(payload, mode...)
	payload = append(payload, sep)
	payload = append(payload, canonicalInput...)
	return payload
}

// Derive derives a 33-byte key (algorithm‖digest at the SHA-256 floor) from a
// mode tag and an already-canonicalized input.
//
// Prefer the four named constructors below — they own the canonicalization,
// which is where pair's sort-and-separate rule lives. This is the escape hatch
// for a mode added upstream before this package knows about it.
func Derive(mode string, canonicalInput []byte) ([]byte, error) {
	payload := RendezvousPayload(mode, canonicalInput)
	// data = payload wrapped as a single CBOR bstr with a minimal-length head
	// (§2.2). ecf.Encode of a []byte yields exactly that bstr; hash.Compute's
	// ecf.EncodeHashable then embeds it verbatim under the "data" key — the
	// same double-encoding every entity has.
	data, err := ecf.Encode(payload)
	if err != nil {
		return nil, err
	}
	// hash.Compute is unconditionally SHA-256 → format 0x00, 33 bytes on the
	// wire. NOT entity.NewEntity, which follows the process home format.
	h, err := hash.Compute(rendezvousKeyType, cbor.RawMessage(data))
	if err != nil {
		return nil, err
	}
	return h.Bytes(), nil
}

// PairKey — exactly those two peers meet. Identity is the key; peer-ids are
// public, so no secret is needed. Canonicalization: the two peer-ids byte-wise
// sorted ascending, joined lo ‖ SEP ‖ hi. Both halves are load-bearing — the
// sort makes pair(A,B) == pair(B,A); the separator disambiguates, since bare
// concatenation makes sorted("ab","c") and sorted("a","bc") both "abc", so two
// different pairs would share one bucket.
func PairKey(peerA, peerB string) ([]byte, error) {
	// peerIDLess, not an inline compare: §6.5's offerer rule assigns negotiation
	// roles from THIS ordering, and the spec pins it as the same sort rather than
	// a second convention. Two copies that agreed today could drift apart later
	// and desynchronize the key and the role at once.
	lo, hi := peerA, peerB
	if !peerIDLess(peerA, peerB) {
		lo, hi = peerB, peerA
	}
	input := make([]byte, 0, len(lo)+len(hi)+1)
	input = append(input, lo...)
	input = append(input, sep)
	input = append(input, hi...)
	return Derive(modePair, input)
}

// TagKey — anyone who knows the label meets. A public discovery convenience,
// explicitly NOT access control: the label is guessable by design. The label is
// byte-exact UTF-8 — no case-folding, no Unicode normalization.
func TagKey(label string) ([]byte, error) {
	return Derive(modeTag, []byte(label))
}

// SecretKey — anyone who knows the string meets, so knowing it is a lightweight
// admission gate, only as strong as its entropy (§2.2). Even a high-entropy
// secret only INTRODUCES; the coordination entities are still verified and the
// connection still runs the ordinary handshake and capability flow. Byte-exact
// UTF-8, like TagKey.
func SecretKey(secret string) ([]byte, error) {
	return Derive(modeSecret, []byte(secret))
}

// LobbyKey — "connect me to anyone here, right now." Pass the pool's constant:
// LobbyDefault unless the node's advertise published an override, in which case
// pass that (§2.2 Finding B).
func LobbyKey(lobbyConstant string) ([]byte, error) {
	return Derive(modeLobby, []byte(lobbyConstant))
}
