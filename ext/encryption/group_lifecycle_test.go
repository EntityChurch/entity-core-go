package encryption

import (
	"bytes"
	"crypto/ecdh"
	"crypto/rand"
	"testing"

	"go.entitychurch.org/entity-core-go/core/types"
)

// TestGroupAddMember — §8.5 add: a fresh wrap is appended for the new
// member; existing members continue to decrypt the SAME outer
// ciphertext under the SAME group_aead_key; the new member decrypts
// to the same plaintext.
func TestGroupAddMember(t *testing.T) {
	privA, mA := makeMember(t)
	privB, mB := makeMember(t)
	plaintext, err := EncKATInnerPlaintext()
	if err != nil {
		t.Fatalf("plaintext: %v", err)
	}

	groupKey := bytes.Repeat([]byte{0x80}, AEADKeySize)
	outerNonce := bytes.Repeat([]byte{0x81}, AEADNonceSize)
	mA.EphemeralPrivateSeed = bytes.Repeat([]byte{0x82}, 32)
	mA.WrapNonce = bytes.Repeat([]byte{0x83}, AEADNonceSize)
	mB.EphemeralPrivateSeed = bytes.Repeat([]byte{0x84}, 32)
	mB.WrapNonce = bytes.Repeat([]byte{0x85}, AEADNonceSize)

	initial, err := GroupEncrypt(GroupEncryptInput{
		Members:      []GroupMember{mA, mB},
		Plaintext:    plaintext,
		OuterNonce:   outerNonce,
		GroupAEADKey: groupKey,
	})
	if err != nil {
		t.Fatalf("GroupEncrypt initial: %v", err)
	}
	if len(initial.WrappedKeys) != 2 {
		t.Fatalf("initial wrap count = %d, want 2", len(initial.WrappedKeys))
	}

	// Add C — same key, fresh wrap.
	privC, mC := makeMember(t)
	mC.EphemeralPrivateSeed = bytes.Repeat([]byte{0x86}, 32)
	mC.WrapNonce = bytes.Repeat([]byte{0x87}, AEADNonceSize)
	extended, err := GroupAddMember(initial, groupKey, mC)
	if err != nil {
		t.Fatalf("GroupAddMember: %v", err)
	}
	if len(extended.WrappedKeys) != 3 {
		t.Fatalf("extended wrap count = %d, want 3", len(extended.WrappedKeys))
	}
	if !bytes.Equal(extended.Ciphertext, initial.Ciphertext) {
		t.Fatalf("§8.5 add: outer ciphertext changed (group_aead_key MUST NOT change)")
	}
	if !bytes.Equal(extended.Nonce, initial.Nonce) {
		t.Fatalf("§8.5 add: outer nonce changed unexpectedly")
	}
	for i := 0; i < 2; i++ {
		if extended.WrappedKeys[i].RecipientKey != initial.WrappedKeys[i].RecipientKey {
			t.Fatalf("§8.5 add: existing wrap[%d] mutated", i)
		}
	}

	// All three members decrypt to the same plaintext.
	cases := []struct {
		name string
		priv *ecdh.PrivateKey
		hash GroupMember
	}{{"A", privA, mA}, {"B", privB, mB}, {"C", privC, mC}}
	for _, tc := range cases {
		got, err := GroupDecrypt(GroupDecryptInput{
			Wrapper:      extended,
			MyPubkeyHash: tc.hash.PubkeyHash,
			MyPriv:       tc.priv.Bytes(),
		})
		if err != nil {
			t.Fatalf("member %s decrypt extended: %v", tc.name, err)
		}
		if !bytes.Equal(got, plaintext) {
			t.Fatalf("member %s plaintext divergence", tc.name)
		}
	}
}

// TestGroupRekey — §8.5 remove: fresh group_aead_key + full re-encrypt
// MUST exclude the removed member and protect FUTURE plaintexts. The
// removed member can still decrypt the OLD entity (no PFS) but the new
// one MUST refuse them at the wrap-lookup level.
func TestGroupRekey(t *testing.T) {
	privA, mA := makeMember(t)
	privB, mB := makeMember(t)
	privC, mC := makeMember(t)

	oldPlain := []byte("the truth before rekey")
	oldGroupKey := bytes.Repeat([]byte{0x90}, AEADKeySize)
	oldNonce := bytes.Repeat([]byte{0x91}, AEADNonceSize)

	oldEnt, err := GroupEncrypt(GroupEncryptInput{
		Members:      []GroupMember{mA, mB, mC},
		Plaintext:    oldPlain,
		OuterNonce:   oldNonce,
		GroupAEADKey: oldGroupKey,
	})
	if err != nil {
		t.Fatalf("initial GroupEncrypt: %v", err)
	}

	// Remove B. Fresh key, re-wrap for {A, C}.
	newPlain := []byte("the truth after rekey")
	newGroupKey, _ := makeFreshAEADKey(t)
	newNonce, _ := makeFreshAEADNonce(t)
	rekeyed, err := GroupRekey(
		newPlain,
		[]GroupMember{mA, mC},
		newGroupKey,
		newNonce,
	)
	if err != nil {
		t.Fatalf("GroupRekey: %v", err)
	}
	if len(rekeyed.WrappedKeys) != 2 {
		t.Fatalf("rekeyed wrap count = %d, want 2", len(rekeyed.WrappedKeys))
	}
	if bytes.Equal(rekeyed.Ciphertext, oldEnt.Ciphertext) {
		t.Fatalf("§8.5 remove: outer ciphertext identical to pre-rekey — re-encrypt missed")
	}
	if bytes.Equal(rekeyed.Nonce, oldEnt.Nonce) {
		t.Fatalf("§8.5 remove: outer nonce identical to pre-rekey — fresh nonce expected")
	}

	// A and C decrypt the new entity to the new plaintext.
	for _, tc := range []struct {
		name string
		priv *ecdh.PrivateKey
		m    GroupMember
	}{{"A", privA, mA}, {"C", privC, mC}} {
		got, err := GroupDecrypt(GroupDecryptInput{
			Wrapper:      rekeyed,
			MyPubkeyHash: tc.m.PubkeyHash,
			MyPriv:       tc.priv.Bytes(),
		})
		if err != nil {
			t.Fatalf("member %s decrypt rekeyed: %v", tc.name, err)
		}
		if !bytes.Equal(got, newPlain) {
			t.Fatalf("member %s plaintext drift on rekeyed", tc.name)
		}
	}

	// B (removed) MUST fail wrap lookup on the rekeyed entity.
	if _, err := GroupDecrypt(GroupDecryptInput{
		Wrapper:      rekeyed,
		MyPubkeyHash: mB.PubkeyHash,
		MyPriv:       privB.Bytes(),
	}); err == nil {
		t.Fatalf("removed member B decrypted rekeyed entity — §8.5 remove broken")
	}

	// B can still decrypt the OLD entity — honest framing, no PFS at the
	// message level (§8.5).
	if _, err := GroupDecrypt(GroupDecryptInput{
		Wrapper:      oldEnt,
		MyPubkeyHash: mB.PubkeyHash,
		MyPriv:       privB.Bytes(),
	}); err != nil {
		t.Fatalf("B can no longer decrypt OLD entity (§8.5 should NOT enforce backward-secrecy): %v", err)
	}

	// F2-1 commitment property survives the re-key: the rekeyed outer is
	// only openable under newGroupKey, NOT under oldGroupKey. Constructing
	// a wrap that delivers oldGroupKey to a member would fail outer AEAD
	// because the rekeyed outer AAD commits to SHA-256(newGroupKey).
	// Tampering the rekeyed wrapper to point at the old key's commitment
	// would change outer AAD and break AEAD.Open. We exercise this by
	// trying to open the rekeyed outer with the old key directly.
	if _, err := XChaChaDecrypt(oldGroupKey, rekeyed.Nonce,
		mustOuterAAD(t, rekeyed, oldGroupKey),
		rekeyed.Ciphertext,
	); err == nil {
		t.Fatalf("rekeyed outer opened under oldGroupKey — F2-1 commitment property lost across re-key")
	}
}

func makeFreshAEADKey(t *testing.T) ([]byte, error) {
	t.Helper()
	k := make([]byte, AEADKeySize)
	if _, err := rand.Read(k); err != nil {
		t.Fatalf("rand: %v", err)
	}
	return k, nil
}

func makeFreshAEADNonce(t *testing.T) ([]byte, error) {
	t.Helper()
	n := make([]byte, AEADNonceSize)
	if _, err := rand.Read(n); err != nil {
		t.Fatalf("rand: %v", err)
	}
	return n, nil
}

func mustOuterAAD(t *testing.T, w types.EncryptedData, key []byte) []byte {
	t.Helper()
	aad, err := GroupOuterAAD(byte(w.AEADID), byte(w.KDFID), w.Nonce, key)
	if err != nil {
		t.Fatalf("GroupOuterAAD: %v", err)
	}
	return aad
}
