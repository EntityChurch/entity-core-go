package encryption

import (
	"errors"
	"testing"

	"go.entitychurch.org/entity-core-go/core/hash"
	"go.entitychurch.org/entity-core-go/core/types"
)

func makeHash(b byte) hash.Hash {
	var h hash.Hash
	h.Algorithm = hash.AlgorithmSHA256
	for i := 0; i < 32; i++ {
		h.Digest[i] = b
	}
	return h
}

func TestIsPubkeyRevoked(t *testing.T) {
	pkA, pkB := makeHash(0x11), makeHash(0x22)
	revs := []types.EncryptionRevocationData{{Revokes: pkA, Reason: "rotated"}}
	if !IsPubkeyRevoked(pkA, revs) {
		t.Fatalf("pkA MUST be reported as revoked")
	}
	if IsPubkeyRevoked(pkB, revs) {
		t.Fatalf("pkB MUST NOT be reported as revoked")
	}
}

func TestNextInHandoffChain(t *testing.T) {
	pkA, pkB := makeHash(0x11), makeHash(0x22)
	chains := []types.EncryptionHandoffData{{PreviousPubkey: pkA, NextPubkey: pkB}}
	next, ok := NextInHandoffChain(pkA, chains)
	if !ok || next != pkB {
		t.Fatalf("expected pkA→pkB, got (%s, %v)", next, ok)
	}
	if _, ok := NextInHandoffChain(pkB, chains); ok {
		t.Fatalf("pkB MUST have no successor")
	}
}

func TestResolveCurrentRecipient_HandoffChainWalks(t *testing.T) {
	pkA, pkB, pkC := makeHash(0x11), makeHash(0x22), makeHash(0x33)
	handoffs := []types.EncryptionHandoffData{
		{PreviousPubkey: pkA, NextPubkey: pkB},
		{PreviousPubkey: pkB, NextPubkey: pkC},
	}
	got, err := ResolveCurrentRecipient(pkA, nil, handoffs)
	if err != nil {
		t.Fatalf("resolve from pkA: %v", err)
	}
	if got != pkC {
		t.Fatalf("resolve from pkA: got %s, want pkC %s", got, pkC)
	}
}

func TestResolveCurrentRecipient_RevokedInitialRejected(t *testing.T) {
	pkA := makeHash(0x11)
	revs := []types.EncryptionRevocationData{{Revokes: pkA}}
	if _, err := ResolveCurrentRecipient(pkA, revs, nil); err == nil {
		t.Fatalf("expected encryption_key_revoked, got nil")
	} else if !errors.Is(err, ErrEncryptionKeyRevoked) {
		t.Fatalf("expected ErrEncryptionKeyRevoked, got %v", err)
	}
}

func TestResolveCurrentRecipient_RevokedHandoffTargetRejected(t *testing.T) {
	pkA, pkB := makeHash(0x11), makeHash(0x22)
	handoffs := []types.EncryptionHandoffData{{PreviousPubkey: pkA, NextPubkey: pkB}}
	revs := []types.EncryptionRevocationData{{Revokes: pkB}}
	if _, err := ResolveCurrentRecipient(pkA, revs, handoffs); err == nil {
		t.Fatalf("expected encryption_key_revoked for revoked successor, got nil")
	} else if !errors.Is(err, ErrEncryptionKeyRevoked) {
		t.Fatalf("expected ErrEncryptionKeyRevoked, got %v", err)
	}
}

func TestResolveCurrentRecipient_CycleBounded(t *testing.T) {
	pkA, pkB := makeHash(0x11), makeHash(0x22)
	// Malformed: A → B → A → ... an impl MUST NOT loop indefinitely.
	handoffs := []types.EncryptionHandoffData{
		{PreviousPubkey: pkA, NextPubkey: pkB},
		{PreviousPubkey: pkB, NextPubkey: pkA},
	}
	if _, err := ResolveCurrentRecipient(pkA, nil, handoffs); err == nil {
		t.Fatalf("expected cycle-bound error, got nil")
	}
}
