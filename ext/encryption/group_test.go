package encryption

import (
	"bytes"
	"crypto/ecdh"
	"crypto/rand"
	"encoding/hex"
	"testing"

	"go.entitychurch.org/entity-core-go/core/types"
)

// makeMember returns (priv, member-input, pubkeyHash) for a fresh X25519
// keypair authored as a Tier-A pubkey entity. Fresh randomness inside.
func makeMember(t *testing.T) (priv *ecdh.PrivateKey, m GroupMember) {
	t.Helper()
	p, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("gen member key: %v", err)
	}
	pub := p.PublicKey().Bytes()
	pubHash, err := ComputePubkeyHash(types.EncryptionPubkeyData{
		EncKeyType:       uint(types.EncKeyTypeX25519),
		PublicKey:        pub,
		SupportedAEADIDs: []uint{uint(types.AEADIDXChaCha20Poly1305)},
		SupportedKDFIDs:  []uint{uint(types.KDFIDHKDFSHA256)},
	})
	if err != nil {
		t.Fatalf("pubkey hash: %v", err)
	}
	return p, GroupMember{Pubkey: pub, PubkeyHash: pubHash}
}

// TestGroupRoundtrip — three members, each decrypts the same plaintext.
func TestGroupRoundtrip(t *testing.T) {
	privA, mA := makeMember(t)
	privB, mB := makeMember(t)
	privC, mC := makeMember(t)

	plaintext := []byte("hello group, all three of you")
	ed, err := GroupEncrypt(GroupEncryptInput{
		Members:   []GroupMember{mA, mB, mC},
		Plaintext: plaintext,
	})
	if err != nil {
		t.Fatalf("GroupEncrypt: %v", err)
	}
	if ed.Mode != types.EncryptionModeGroup {
		t.Fatalf("Mode = %q, want %q", ed.Mode, types.EncryptionModeGroup)
	}
	if len(ed.WrappedKeys) != 3 {
		t.Fatalf("wrapped_keys len = %d, want 3", len(ed.WrappedKeys))
	}

	for i, tc := range []struct {
		name string
		priv *ecdh.PrivateKey
		m    GroupMember
	}{{"A", privA, mA}, {"B", privB, mB}, {"C", privC, mC}} {
		got, err := GroupDecrypt(GroupDecryptInput{
			Wrapper:      ed,
			MyPubkeyHash: tc.m.PubkeyHash,
			MyPriv:       tc.priv.Bytes(),
		})
		if err != nil {
			t.Fatalf("member %s decrypt[%d]: %v", tc.name, i, err)
		}
		if !bytes.Equal(got, plaintext) {
			t.Fatalf("member %s mismatch", tc.name)
		}
	}
}

// TestGroupNonMemberCannotDecrypt — a peer whose pubkey is not in
// wrapped_keys gets encryption_recipient_unknown.
func TestGroupNonMemberCannotDecrypt(t *testing.T) {
	_, mA := makeMember(t)
	_, mB := makeMember(t)
	outsider, mOut := makeMember(t)

	ed, _ := GroupEncrypt(GroupEncryptInput{
		Members:   []GroupMember{mA, mB},
		Plaintext: []byte("members only"),
	})
	if _, err := GroupDecrypt(GroupDecryptInput{
		Wrapper:      ed,
		MyPubkeyHash: mOut.PubkeyHash,
		MyPriv:       outsider.Bytes(),
	}); err == nil {
		t.Fatalf("outsider decrypted group entity — want error")
	}
}

// TestGroupKAT1 — §16.4 with v2.4 commitment-bound outer AAD and the
// v2.5 R3 ENC-KAT-INNER plaintext (system/note real-entity ECF).
// 3 members + pinned seeds + pinned outer/per-wrap nonces + pinned
// group_aead_key. Per-wrap ephemeral seeds = 0x70+i per R1 (locked).
// Emits all expected_* hex for byte-pin lock (§16.5).
func TestGroupKAT1(t *testing.T) {
	memberSeeds := [][]byte{
		bytes.Repeat([]byte{0x50}, 32),
		bytes.Repeat([]byte{0x51}, 32),
		bytes.Repeat([]byte{0x52}, 32),
	}
	outerNonce := bytes.Repeat([]byte{0x53}, 24)
	groupKey := bytes.Repeat([]byte{0x54}, 32)
	perWrapNonces := [][]byte{
		bytes.Repeat([]byte{0x60}, 24),
		bytes.Repeat([]byte{0x61}, 24),
		bytes.Repeat([]byte{0x62}, 24),
	}
	// Per-wrap ephemeral seeds = 0x70+i per arch R1 — Go+Rust
	// independent 2-of-3 convergence pinned this shape.
	perWrapEphSeeds := [][]byte{
		bytes.Repeat([]byte{0x70}, 32),
		bytes.Repeat([]byte{0x71}, 32),
		bytes.Repeat([]byte{0x72}, 32),
	}
	plaintext, err := EncKATInnerPlaintext()
	if err != nil {
		t.Fatalf("EncKATInnerPlaintext: %v", err)
	}
	t.Logf("ENC-KAT-INNER plaintext (%d bytes): %s", len(plaintext), hex.EncodeToString(plaintext))

	members := make([]GroupMember, 3)
	privs := make([]*ecdh.PrivateKey, 3)
	for i, seed := range memberSeeds {
		priv, err := ecdh.X25519().NewPrivateKey(seed)
		if err != nil {
			t.Fatalf("member[%d] priv: %v", i, err)
		}
		privs[i] = priv
		pub := priv.PublicKey().Bytes()
		pubHash, err := ComputePubkeyHash(types.EncryptionPubkeyData{
			EncKeyType:       uint(types.EncKeyTypeX25519),
			PublicKey:        pub,
			SupportedAEADIDs: []uint{uint(types.AEADIDXChaCha20Poly1305)},
			SupportedKDFIDs:  []uint{uint(types.KDFIDHKDFSHA256)},
		})
		if err != nil {
			t.Fatalf("member[%d] pubkey hash: %v", i, err)
		}
		t.Logf("member[%d] pubkey: %s", i, hex.EncodeToString(pub))
		t.Logf("member[%d] pubkey_hash (33B wire): %s", i, hex.EncodeToString(pubHash.Bytes()))
		members[i] = GroupMember{
			Pubkey:               pub,
			PubkeyHash:           pubHash,
			EphemeralPrivateSeed: perWrapEphSeeds[i],
			WrapNonce:            perWrapNonces[i],
		}
	}

	// Outer AAD (with F2-1 commitment).
	outerAAD, err := GroupOuterAAD(
		types.AEADIDXChaCha20Poly1305, types.KDFIDHKDFSHA256,
		outerNonce, groupKey,
	)
	if err != nil {
		t.Fatalf("GroupOuterAAD: %v", err)
	}
	commitment := Commitment(groupKey)
	t.Logf("group_aead_key (32B): %s", hex.EncodeToString(groupKey))
	t.Logf("commitment = SHA-256(group_aead_key): %s", hex.EncodeToString(commitment))
	t.Logf("ENC-GROUP-KAT-1 outer AAD (%d bytes): %s", len(outerAAD), hex.EncodeToString(outerAAD))

	ed, err := GroupEncrypt(GroupEncryptInput{
		Members:      members,
		Plaintext:    plaintext,
		OuterNonce:   outerNonce,
		GroupAEADKey: groupKey,
	})
	if err != nil {
		t.Fatalf("GroupEncrypt: %v", err)
	}
	t.Logf("ENC-GROUP-KAT-1 outer ciphertext (%d bytes): %s", len(ed.Ciphertext), hex.EncodeToString(ed.Ciphertext))
	for i, w := range ed.WrappedKeys {
		t.Logf("wrap[%d].ephemeral_key:   %s", i, hex.EncodeToString(w.EphemeralKey))
		t.Logf("wrap[%d].wrapped_aead_key: %s", i, hex.EncodeToString(w.WrappedAEADKey))
	}

	// Round-trip sanity for all three members.
	for i := range members {
		got, err := GroupDecrypt(GroupDecryptInput{
			Wrapper:      ed,
			MyPubkeyHash: members[i].PubkeyHash,
			MyPriv:       memberSeeds[i],
		})
		if err != nil {
			t.Fatalf("member[%d] decrypt: %v", i, err)
		}
		if !bytes.Equal(got, plaintext) {
			t.Fatalf("member[%d] mismatch", i)
		}
	}
}

// TestGroupCommitmentRejectsEquivocation — §16 ENC-GROUP-COMMIT-1.
// A malicious author constructs ONE outer (ciphertext, nonce, AAD) and
// wraps TWO DIFFERENT group_aead_key values to two members. The outer
// AAD's commitment binds the single key the outer ciphertext was
// actually sealed under, so the second member's reconstructed AAD
// diverges and AEAD.Open MUST fail with encryption_aead_failed. The
// invisible-salamanders class is structurally rejected.
func TestGroupCommitmentRejectsEquivocation(t *testing.T) {
	// Two members.
	privA, mA := makeMember(t)
	privB, mB := makeMember(t)
	_ = privA
	_ = privB

	// Two distinct group_aead_keys.
	keyHonest := bytes.Repeat([]byte{0x01}, AEADKeySize)
	keyDecoy := bytes.Repeat([]byte{0x02}, AEADKeySize)

	// Outer ciphertext sealed under keyHonest (committed via AAD).
	plaintext := []byte("the truth")
	outerNonce := bytes.Repeat([]byte{0xAA}, AEADNonceSize)
	outerAAD, _ := GroupOuterAAD(types.AEADIDXChaCha20Poly1305, types.KDFIDHKDFSHA256, outerNonce, keyHonest)
	outerCT, err := XChaChaEncrypt(keyHonest, outerNonce, outerAAD, plaintext)
	if err != nil {
		t.Fatalf("seal outer: %v", err)
	}

	// Member A's wrap delivers the HONEST key (matches what's committed).
	wA, err := wrapForMember(GroupMember{
		Pubkey:               mA.Pubkey,
		PubkeyHash:           mA.PubkeyHash,
		EphemeralPrivateSeed: bytes.Repeat([]byte{0x33}, 32),
		WrapNonce:            bytes.Repeat([]byte{0x44}, AEADNonceSize),
	}, keyHonest, types.AEADIDXChaCha20Poly1305, types.KDFIDHKDFSHA256)
	if err != nil {
		t.Fatalf("wrap honest: %v", err)
	}
	// Member B's wrap delivers a DECOY key (equivocation attempt).
	wB, err := wrapForMember(GroupMember{
		Pubkey:               mB.Pubkey,
		PubkeyHash:           mB.PubkeyHash,
		EphemeralPrivateSeed: bytes.Repeat([]byte{0x55}, 32),
		WrapNonce:            bytes.Repeat([]byte{0x66}, AEADNonceSize),
	}, keyDecoy, types.AEADIDXChaCha20Poly1305, types.KDFIDHKDFSHA256)
	if err != nil {
		t.Fatalf("wrap decoy: %v", err)
	}

	equivocated := types.EncryptedData{
		Mode:        types.EncryptionModeGroup,
		AEADID:      uint(types.AEADIDXChaCha20Poly1305),
		KDFID:       uint(types.KDFIDHKDFSHA256),
		Nonce:       outerNonce,
		Ciphertext:  outerCT,
		WrappedKeys: []types.WrappedKey{wA, wB},
	}

	// Member A reconstructs AAD with SHA-256(keyHonest) → matches what was
	// sealed → opens cleanly.
	got, err := GroupDecrypt(GroupDecryptInput{
		Wrapper:      equivocated,
		MyPubkeyHash: mA.PubkeyHash,
		MyPriv:       privA.Bytes(),
	})
	if err != nil {
		t.Fatalf("member A (honest) decrypt: %v", err)
	}
	if !bytes.Equal(got, plaintext) {
		t.Fatalf("member A plaintext mismatch")
	}

	// Member B reconstructs AAD with SHA-256(keyDecoy) → diverges from
	// what was sealed → AEAD.Open MUST fail. F2-1 commitment closes the
	// equivocation; without it, B would happily decrypt to a different
	// plaintext (or garbled-but-accepted bytes).
	_, err = GroupDecrypt(GroupDecryptInput{
		Wrapper:      equivocated,
		MyPubkeyHash: mB.PubkeyHash,
		MyPriv:       privB.Bytes(),
	})
	if err == nil {
		t.Fatalf("ENC-GROUP-COMMIT-1: equivocated outer opened under decoy key — F2-1 commitment ABSENT or broken")
	}
	t.Logf("equivocation correctly rejected: %v", err)
}
