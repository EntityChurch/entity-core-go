package validate

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"encoding/hex"
	"fmt"

	"go.entitychurch.org/entity-core-go/core/crypto"
	"go.entitychurch.org/entity-core-go/core/ecf"
	"go.entitychurch.org/entity-core-go/core/types"
	"go.entitychurch.org/entity-core-go/ext/encryption"
)

// runEncSenderAuthPeer — ENCRYPTION §7.4 / §7.5 recipient-side sender
// authentication (B1-7). For a peer-mode encrypted entity, the sender
// publishes a `system/signature` at the V7 invariant pointer
// `system/signature/{hex(content_hash(encrypted_entity))}` (F-GO-3 / §5.2
// post-v7.74). The recipient computes the hash of the received entity,
// resolves the invariant pointer, verifies the signature with the
// signer's identity-cert pubkey, and asserts signer matches the
// expected sender identity.
//
// Vector layout:
//
//	(positive) Encrypt → publish sig at invariant pointer → recipient
//	  computes hash → resolves sig → verifies Ed25519 → signer matches
//	  client identity hash → PASS.
//
//	(tamper inner / ciphertext) Flip a ciphertext byte → PeerDecrypt MUST
//	  fail with encryption_aead_failed (§7.5 step 6 / ENC-AAD-1).
//
//	(tamper outer / invariant-pointer binding) Tamper the EncryptedData
//	  wrapper bytes (e.g. flip the nonce). The tampered entity hashes to
//	  h' != h, so resolving system/signature/{hex(h')} MUST yield 404 →
//	  encryption_unsigned_sender (§7.5 step 1). The original signature
//	  cannot be lifted onto a tampered entity because the invariant
//	  pointer is keyed by the entity's own hash.
func runEncSenderAuthPeer(ctx context.Context, client *PeerClient) CheckOutcome {
	if client.Keypair().IsZero() {
		return SkipCheck("client has no signing keypair — start validate-peer with -identity to exercise sender-auth")
	}

	// Recipient encryption keypair (independent of the validator's signing
	// identity per R6).
	recipientPriv, err := ecdh.X25519().GenerateKey(secureRand{})
	if err != nil {
		return FailCheck("X25519 keygen: " + err.Error())
	}
	recipientPub := recipientPriv.PublicKey().Bytes()
	pkData := types.EncryptionPubkeyData{
		EncKeyType:       uint(types.EncKeyTypeX25519),
		PublicKey:        recipientPub,
		SupportedAEADIDs: []uint{uint(types.AEADIDXChaCha20Poly1305)},
		SupportedKDFIDs:  []uint{uint(types.KDFIDHKDFSHA256)},
		Created:          0,
	}
	pkHash, err := encryption.ComputePubkeyHash(pkData)
	if err != nil {
		return FailCheck("ComputePubkeyHash: " + err.Error())
	}

	plaintext, err := encryption.EncKATInnerPlaintext()
	if err != nil {
		return FailCheck("EncKATInnerPlaintext: " + err.Error())
	}

	// Peer-mode encrypt.
	wrapper, err := encryption.PeerEncrypt(encryption.PeerEncryptInput{
		RecipientPubkey:     recipientPub,
		RecipientPubkeyHash: pkHash,
		Plaintext:           plaintext,
	})
	if err != nil {
		return FailCheck("PeerEncrypt: " + err.Error())
	}

	// Wrap the §5.1 data into the outer system/encrypted entity (the
	// object whose content_hash is the invariant-pointer target).
	encEnt, err := encEntityFromData(types.TypeEncrypted, wrapper)
	if err != nil {
		return FailCheck("build encrypted entity: " + err.Error())
	}

	// §7.4: publish sender signature at the invariant pointer over the
	// encrypted entity's content_hash. publishInvariantSig signs with the
	// client's identity keypair and writes to system/signature/{hex}.
	if err := publishInvariantSig(ctx, client, encEnt.ContentHash); err != nil {
		return FailCheck("publish sender signature: " + err.Error())
	}

	// === Positive recipient flow per §7.5 step 1 + §7.4 step 1–3 ===
	sigPath := "system/signature/" + hex.EncodeToString(encEnt.ContentHash.Bytes())
	sigEnt, _, err := client.TreeGet(ctx, sigPath)
	if err != nil {
		return FailCheck("(positive) resolve sender signature at invariant pointer: " + err.Error())
	}
	var sigData types.SignatureData
	if err := ecf.Decode(sigEnt.Data, &sigData); err != nil {
		return FailCheck("(positive) decode sender signature: " + err.Error())
	}
	if sigData.Target != encEnt.ContentHash {
		return FailCheck(fmt.Sprintf(
			"(positive) signature target mismatch: got %s, want %s", sigData.Target, encEnt.ContentHash))
	}
	clientIdentity := client.IdentityEntity()
	if sigData.Signer != clientIdentity.ContentHash {
		return FailCheck(fmt.Sprintf(
			"(positive) signer != client identity: got %s, want %s", sigData.Signer, clientIdentity.ContentHash))
	}
	// V7 §5.2 / §7.4 step 2 — verify the Ed25519 signature with the signer's
	// pubkey bytes (which we know to be the client's own here).
	if !crypto.Verify(crypto.KeyTypeEd25519,
		client.Keypair().PublicKeyBytes(),
		encEnt.ContentHash.Bytes(),
		sigData.Signature,
	) {
		return FailCheck("(positive) Ed25519 signature verification FAILED")
	}

	// === Tamper inner / ciphertext (ENC-AAD-1 corner per §7.5 step 6) ===
	innerTampered := wrapper
	innerTampered.Ciphertext = bytes.Clone(wrapper.Ciphertext)
	innerTampered.Ciphertext[0] ^= 0xFF
	if _, err := encryption.PeerDecrypt(encryption.PeerDecryptInput{
		Wrapper:       innerTampered,
		RecipientPriv: recipientPriv.Bytes(),
	}); err == nil {
		return FailCheck("(tamper-inner) PeerDecrypt accepted a flipped-ciphertext byte — AEAD binding broken")
	}

	// === Tamper outer / invariant-pointer binding (§7.5 step 1) ===
	outerTampered := wrapper
	outerTampered.Nonce = bytes.Clone(wrapper.Nonce)
	outerTampered.Nonce[0] ^= 0xFF
	tamperedEnt, err := encEntityFromData(types.TypeEncrypted, outerTampered)
	if err != nil {
		return FailCheck("(tamper-outer) build tampered entity: " + err.Error())
	}
	if tamperedEnt.ContentHash == encEnt.ContentHash {
		return FailCheck("(tamper-outer) tampered entity hash unchanged — test setup broken")
	}
	tamperedSigPath := "system/signature/" + hex.EncodeToString(tamperedEnt.ContentHash.Bytes())
	if _, _, err := client.TreeGet(ctx, tamperedSigPath); err == nil {
		return FailCheck(fmt.Sprintf(
			"(tamper-outer) sender signature resolved at h' invariant pointer %s — invariant-pointer binding broken",
			tamperedSigPath))
	}

	return PassCheck(
		"§7.4/§7.5 sender-auth: invariant-pointer resolve + Ed25519 verify + signer match; " +
			"ciphertext-tamper → AEAD fail; outer-tamper → invariant pointer 404")
}
