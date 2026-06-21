package validate

import (
	"bytes"
	"crypto/ecdh"

	"go.entitychurch.org/entity-core-go/core/types"
	"go.entitychurch.org/entity-core-go/ext/encryption"
)

// runEncGroupAddRekey — EXTENSION-ENCRYPTION §8.5 group lifecycle
// (BLOCK-1 scenario B1-3). Exercises:
//
//   add member  — fresh wrap appended; existing outer ciphertext +
//                 group_aead_key unchanged; new member decrypts.
//   re-key      — fresh group_aead_key + full re-encrypt; removed
//                 member rejected at wrap lookup on the new entity but
//                 can still open the OLD entity (no PFS at the message
//                 level, honest framing); F2-1 commitment property
//                 holds across the re-key (rekeyed outer cannot be
//                 opened under the old key).
func runEncGroupAddRekey() CheckOutcome {
	type member struct {
		priv *ecdh.PrivateKey
		gm   encryption.GroupMember
	}
	makeMember := func() (*member, error) {
		priv, err := ecdh.X25519().GenerateKey(secureRand{})
		if err != nil {
			return nil, err
		}
		pub := priv.PublicKey().Bytes()
		h, err := encryption.ComputePubkeyHash(types.EncryptionPubkeyData{
			EncKeyType: uint(types.EncKeyTypeX25519), PublicKey: pub,
			SupportedAEADIDs: []uint{uint(types.AEADIDXChaCha20Poly1305)},
			SupportedKDFIDs:  []uint{uint(types.KDFIDHKDFSHA256)},
		})
		if err != nil {
			return nil, err
		}
		return &member{priv: priv, gm: encryption.GroupMember{Pubkey: pub, PubkeyHash: h}}, nil
	}

	mA, err := makeMember()
	if err != nil {
		return FailCheck("makeMember A: " + err.Error())
	}
	mB, err := makeMember()
	if err != nil {
		return FailCheck("makeMember B: " + err.Error())
	}
	mC, err := makeMember()
	if err != nil {
		return FailCheck("makeMember C: " + err.Error())
	}

	plaintext, err := encryption.EncKATInnerPlaintext()
	if err != nil {
		return FailCheck("EncKATInnerPlaintext: " + err.Error())
	}
	groupKey := bytes.Repeat([]byte{0x88}, encryption.AEADKeySize)

	// Initial encryption to {A, B}.
	initial, err := encryption.GroupEncrypt(encryption.GroupEncryptInput{
		Members:      []encryption.GroupMember{mA.gm, mB.gm},
		Plaintext:    plaintext,
		GroupAEADKey: groupKey,
	})
	if err != nil {
		return FailCheck("initial GroupEncrypt: " + err.Error())
	}

	// === add member C ===
	extended, err := encryption.GroupAddMember(initial, groupKey, mC.gm)
	if err != nil {
		return FailCheck("GroupAddMember: " + err.Error())
	}
	if len(extended.WrappedKeys) != 3 {
		return FailCheck("add: wrap count != 3")
	}
	if !bytes.Equal(extended.Ciphertext, initial.Ciphertext) || !bytes.Equal(extended.Nonce, initial.Nonce) {
		return FailCheck("add: outer ciphertext/nonce changed — §8.5 says group_aead_key unchanged")
	}
	for _, m := range []*member{mA, mB, mC} {
		got, err := encryption.GroupDecrypt(encryption.GroupDecryptInput{
			Wrapper: extended, MyPubkeyHash: m.gm.PubkeyHash, MyPriv: m.priv.Bytes(),
		})
		if err != nil {
			return FailCheck("add: member decrypt: " + err.Error())
		}
		if !bytes.Equal(got, plaintext) {
			return FailCheck("add: member plaintext divergence")
		}
	}

	// === remove member B (re-key) ===
	newPlain := []byte("post-rekey plaintext canary")
	newGroupKey := bytes.Repeat([]byte{0x99}, encryption.AEADKeySize)
	rekeyed, err := encryption.GroupRekey(newPlain, []encryption.GroupMember{mA.gm, mC.gm}, newGroupKey, nil)
	if err != nil {
		return FailCheck("GroupRekey: " + err.Error())
	}
	if len(rekeyed.WrappedKeys) != 2 {
		return FailCheck("rekey: wrap count != 2")
	}
	// A and C decrypt rekeyed to newPlain.
	for _, m := range []*member{mA, mC} {
		got, err := encryption.GroupDecrypt(encryption.GroupDecryptInput{
			Wrapper: rekeyed, MyPubkeyHash: m.gm.PubkeyHash, MyPriv: m.priv.Bytes(),
		})
		if err != nil {
			return FailCheck("rekey: retained member decrypt: " + err.Error())
		}
		if !bytes.Equal(got, newPlain) {
			return FailCheck("rekey: retained member plaintext drift")
		}
	}
	// B rejected on rekeyed.
	if _, err := encryption.GroupDecrypt(encryption.GroupDecryptInput{
		Wrapper: rekeyed, MyPubkeyHash: mB.gm.PubkeyHash, MyPriv: mB.priv.Bytes(),
	}); err == nil {
		return FailCheck("rekey: removed member B decrypted rekeyed — §8.5 broken")
	}
	// B still decrypts the OLD entity (no PFS at message level).
	if _, err := encryption.GroupDecrypt(encryption.GroupDecryptInput{
		Wrapper: extended, MyPubkeyHash: mB.gm.PubkeyHash, MyPriv: mB.priv.Bytes(),
	}); err != nil {
		return FailCheck("rekey: B should still decrypt OLD entity (§8.5 honest framing): " + err.Error())
	}
	// F2-1 commitment property: rekeyed outer cannot be opened with the
	// old group_aead_key — the outer AAD commits to SHA-256(newGroupKey).
	outerAAD, err := encryption.GroupOuterAAD(
		byte(rekeyed.AEADID), byte(rekeyed.KDFID), rekeyed.Nonce, groupKey,
	)
	if err != nil {
		return FailCheck("rebuild outer AAD: " + err.Error())
	}
	if _, err := encryption.XChaChaDecrypt(groupKey, rekeyed.Nonce, outerAAD, rekeyed.Ciphertext); err == nil {
		return FailCheck("rekey: rekeyed outer opened under OLD key — F2-1 commitment broken across re-key")
	}

	return PassCheck("§8.5 add (same key, wrap appended) + re-key (fresh key, B rejected on new, B decrypts old, F2-1 holds)")
}
