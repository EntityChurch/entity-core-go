// Category: encryption. Probes the EXTENSION-ENCRYPTION v1.0 surface — three
// modes (self/peer/group) plus the §4.2.a Tier-A publish/sign/handoff/revoke
// lifecycle. Per §1, encryption is a CLIENT-SIDE primitive (no over-the-wire
// handler ops) — most checks run against the local ext/encryption package;
// only cert_lifecycle_tier_a + the type-registration probes hit the remote
// peer.
//
// Vectors (§16):
//
//   type_*                            — encryption entity types registered on remote
//   self_kat_roundtrip                — §6 + ENC-SELF-KAT-1 (offline, cheap-Argon2id)
//   peer_kat_roundtrip                — §7 + ENC-PEER-KAT-1 (offline)
//   group_kat_roundtrip               — §8 + ENC-GROUP-KAT-1 (offline, 3 members)
//   group_commit_rejects_equivocation — §16 ENC-GROUP-COMMIT-1 (F2-1 structural)
//   aad_tamper_self                   — §16 ENC-AAD-1 for self mode
//   aad_tamper_peer                   — §16 ENC-AAD-1 for peer mode
//   resource_bounds_group             — §16 ENC-RESOURCE-BOUNDS-1 (>256 wraps → reject)
//   cert_lifecycle_tier_a             — §16 ENC-CERT-LIFECYCLE-1 at Tier A (over wire)
//
// Cohort byte-pin KATs (§16.5 lock) run as ext/encryption package tests at v1
// baseline Argon2id (64 MiB / t=3); they emit the reference hex the cohort
// uses to byte-equal Go ↔ Rust ↔ Python. Including them here would balloon
// validate-peer wall-clock without adding signal beyond "the package works".

package validate

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"

	"github.com/fxamacker/cbor/v2"

	"go.entitychurch.org/entity-core-go/core/ecf"
	"go.entitychurch.org/entity-core-go/core/entity"
	"go.entitychurch.org/entity-core-go/core/hash"
	"go.entitychurch.org/entity-core-go/core/types"
	"go.entitychurch.org/entity-core-go/ext/encryption"
)

const catEncryption = "encryption"

var encryptionTypes = []struct{ short, full string }{
	{"pubkey", types.TypeEncryptionPubkey},
	{"encrypted", types.TypeEncrypted},
	{"handoff", types.TypeEncryptionHandoff},
	{"revocation", types.TypeEncryptionRevocation},
	{"key_backup", types.TypeEncryptionKeyBackup},
}

// cheapKDF is a fast Argon2id profile for fast-running validate-peer checks.
// The v1 baseline (m=65536, t=3) is used by the cohort byte-pin KATs in the
// ext/encryption package tests; running it here would add seconds-per-check
// without surfacing different conformance signal.
var cheapKDF = types.KDFParams{
	Argon2Version: types.Argon2idVersion,
	MemoryCost:    8,
	TimeCost:      1,
	Parallelism:   1,
	OutputLen:     32,
}

func runEncryption(ctx context.Context, client *PeerClient) []CheckResult {
	r := NewCheckRunner(catEncryption)

	for _, ty := range encryptionTypes {
		r.Declare("type_"+ty.short, "ENCRYPTION §4 / §5 / §10 / §11 — entity type registered")
	}
	r.Declare("self_kat_roundtrip", "ENCRYPTION §6 — self-mode encrypt/decrypt round-trip")
	r.Declare("peer_kat_roundtrip", "ENCRYPTION §7 — peer-mode encrypt/decrypt round-trip")
	r.Declare("group_kat_roundtrip", "ENCRYPTION §8 — group-mode 3-member encrypt/decrypt round-trip")
	r.Declare("group_commit_rejects_equivocation", "ENCRYPTION §16 ENC-GROUP-COMMIT-1 — F2-1 key-commitment rejects equivocation")
	r.Declare("aad_tamper_self", "ENCRYPTION §16 ENC-AAD-1 — tampering self-mode AAD-bound field MUST fail")
	r.Declare("aad_tamper_peer", "ENCRYPTION §16 ENC-AAD-1 — tampering peer-mode AAD-bound field MUST fail")
	r.Declare("resource_bounds_group", "ENCRYPTION §16 ENC-RESOURCE-BOUNDS-1 — >256 wrapped_keys → encryption_wrapped_keys_too_many")
	r.Declare("cert_lifecycle_tier_a", "ENCRYPTION §16 ENC-CERT-LIFECYCLE-1 — Tier-A publish/rotate/revoke over the wire")
	r.Declare("key_separation", "ENCRYPTION §16 ENC-KEY-SEPARATION-1 — encryption pubkey MUST be independent of identity key (R6)")
	r.Declare("sender_auth_peer", "ENCRYPTION §7.4 / §7.5 — recipient-side sender-auth via invariant-pointer signature (B1-7)")
	r.Declare("group_add_rekey", "ENCRYPTION §8.5 — group lifecycle: add (same key) + re-key (fresh key, B1-3)")

	for _, ty := range encryptionTypes {
		ty := ty
		r.Run("type_"+ty.short, func() CheckOutcome {
			if _, _, err := client.TreeGet(ctx, "system/type/"+ty.full); err != nil {
				return FailCheck("type not registered on remote: " + ty.full + ": " + err.Error())
			}
			return PassCheck("type registered: " + ty.full)
		})
	}

	r.Run("self_kat_roundtrip", runEncSelfRoundtrip)
	r.Run("peer_kat_roundtrip", runEncPeerRoundtrip)
	r.Run("group_kat_roundtrip", runEncGroupRoundtrip)
	r.Run("group_commit_rejects_equivocation", runEncGroupCommit)
	r.Run("aad_tamper_self", runEncAADTamperSelf)
	r.Run("aad_tamper_peer", runEncAADTamperPeer)
	r.Run("resource_bounds_group", runEncResourceBoundsGroup)
	r.Run("cert_lifecycle_tier_a", func() CheckOutcome {
		return runEncCertLifecycleTierA(ctx, client)
	})
	r.Run("key_separation", func() CheckOutcome {
		return runEncKeySeparation(ctx, client)
	})
	r.Run("sender_auth_peer", func() CheckOutcome {
		return runEncSenderAuthPeer(ctx, client)
	})
	r.Run("group_add_rekey", runEncGroupAddRekey)

	return r.Results()
}

func runEncSelfRoundtrip() CheckOutcome {
	pt := []byte("self-roundtrip plaintext")
	pass := []byte("self-roundtrip-passphrase-xx")
	ed, err := encryption.SelfEncrypt(pass, "test-key", pt, encryption.SelfEncryptParams{Params: cheapKDF})
	if err != nil {
		return FailCheck("SelfEncrypt: " + err.Error())
	}
	got, err := encryption.SelfDecrypt(pass, ed)
	if err != nil {
		return FailCheck("SelfDecrypt: " + err.Error())
	}
	if !bytes.Equal(got, pt) {
		return FailCheck("self round-trip plaintext mismatch")
	}
	return PassCheck(fmt.Sprintf("self-mode round-trip OK (ciphertext %d bytes)", len(ed.Ciphertext)))
}

func runEncPeerRoundtrip() CheckOutcome {
	priv, _ := ecdh.X25519().GenerateKey(secureRand{})
	pub := priv.PublicKey().Bytes()
	pkHash, err := encryption.ComputePubkeyHash(types.EncryptionPubkeyData{
		EncKeyType: uint(types.EncKeyTypeX25519), PublicKey: pub,
		SupportedAEADIDs: []uint{uint(types.AEADIDXChaCha20Poly1305)},
		SupportedKDFIDs:  []uint{uint(types.KDFIDHKDFSHA256)},
	})
	if err != nil {
		return FailCheck("ComputePubkeyHash: " + err.Error())
	}
	pt := []byte("peer-roundtrip plaintext")
	ed, err := encryption.PeerEncrypt(encryption.PeerEncryptInput{
		RecipientPubkey: pub, RecipientPubkeyHash: pkHash, Plaintext: pt,
	})
	if err != nil {
		return FailCheck("PeerEncrypt: " + err.Error())
	}
	got, err := encryption.PeerDecrypt(encryption.PeerDecryptInput{Wrapper: ed, RecipientPriv: priv.Bytes()})
	if err != nil {
		return FailCheck("PeerDecrypt: " + err.Error())
	}
	if !bytes.Equal(got, pt) {
		return FailCheck("peer round-trip plaintext mismatch")
	}
	return PassCheck(fmt.Sprintf("peer-mode round-trip OK (ciphertext %d bytes)", len(ed.Ciphertext)))
}

func runEncGroupRoundtrip() CheckOutcome {
	type m struct {
		priv *ecdh.PrivateKey
		gm   encryption.GroupMember
	}
	var ms []m
	for i := 0; i < 3; i++ {
		p, _ := ecdh.X25519().GenerateKey(secureRand{})
		pub := p.PublicKey().Bytes()
		h, err := encryption.ComputePubkeyHash(types.EncryptionPubkeyData{
			EncKeyType: uint(types.EncKeyTypeX25519), PublicKey: pub,
			SupportedAEADIDs: []uint{uint(types.AEADIDXChaCha20Poly1305)},
			SupportedKDFIDs:  []uint{uint(types.KDFIDHKDFSHA256)},
		})
		if err != nil {
			return FailCheck(fmt.Sprintf("member[%d] pubkey hash: %v", i, err))
		}
		ms = append(ms, m{priv: p, gm: encryption.GroupMember{Pubkey: pub, PubkeyHash: h}})
	}
	members := make([]encryption.GroupMember, len(ms))
	for i, x := range ms {
		members[i] = x.gm
	}
	pt := []byte("group-roundtrip plaintext")
	ed, err := encryption.GroupEncrypt(encryption.GroupEncryptInput{Members: members, Plaintext: pt})
	if err != nil {
		return FailCheck("GroupEncrypt: " + err.Error())
	}
	for i, x := range ms {
		got, err := encryption.GroupDecrypt(encryption.GroupDecryptInput{
			Wrapper: ed, MyPubkeyHash: x.gm.PubkeyHash, MyPriv: x.priv.Bytes(),
		})
		if err != nil {
			return FailCheck(fmt.Sprintf("member[%d] decrypt: %v", i, err))
		}
		if !bytes.Equal(got, pt) {
			return FailCheck(fmt.Sprintf("member[%d] plaintext mismatch", i))
		}
	}
	return PassCheck(fmt.Sprintf("group-mode 3-member round-trip OK (outer ciphertext %d bytes, 3 wraps)", len(ed.Ciphertext)))
}

func runEncGroupCommit() CheckOutcome {
	// Two members. Two distinct group_aead_keys. Outer ciphertext sealed
	// under keyHonest, wrap-to-A delivers keyHonest, wrap-to-B delivers
	// keyDecoy. F2-1: B's reconstructed AAD diverges → AEAD.Open MUST
	// fail. Without commitment, B would happily decrypt to garbled bytes
	// (or worse, attacker-chosen plaintext).
	privA, gmA, err := genGroupMember()
	if err != nil {
		return FailCheck("gen member A: " + err.Error())
	}
	privB, gmB, err := genGroupMember()
	if err != nil {
		return FailCheck("gen member B: " + err.Error())
	}
	keyHonest := bytes.Repeat([]byte{0x01}, encryption.AEADKeySize)
	keyDecoy := bytes.Repeat([]byte{0x02}, encryption.AEADKeySize)
	outerNonce := bytes.Repeat([]byte{0xAA}, encryption.AEADNonceSize)
	outerAAD, err := encryption.GroupOuterAAD(types.AEADIDXChaCha20Poly1305, types.KDFIDHKDFSHA256, outerNonce, keyHonest)
	if err != nil {
		return FailCheck("GroupOuterAAD: " + err.Error())
	}
	outerCT, err := encryption.XChaChaEncrypt(keyHonest, outerNonce, outerAAD, []byte("the truth"))
	if err != nil {
		return FailCheck("seal outer: " + err.Error())
	}

	// Manually craft the equivocation; honest GroupEncrypt would never
	// produce divergent per-member keys.
	wA, err := wrapMemberForCommitTest(gmA, keyHonest)
	if err != nil {
		return FailCheck("wrap honest: " + err.Error())
	}
	wB, err := wrapMemberForCommitTest(gmB, keyDecoy)
	if err != nil {
		return FailCheck("wrap decoy: " + err.Error())
	}
	equivocated := types.EncryptedData{
		Mode: types.EncryptionModeGroup, AEADID: uint(types.AEADIDXChaCha20Poly1305),
		KDFID: uint(types.KDFIDHKDFSHA256), Nonce: outerNonce, Ciphertext: outerCT,
		WrappedKeys: []types.WrappedKey{wA, wB},
	}

	// Honest member opens.
	if _, err := encryption.GroupDecrypt(encryption.GroupDecryptInput{
		Wrapper: equivocated, MyPubkeyHash: gmA.PubkeyHash, MyPriv: privA.Bytes(),
	}); err != nil {
		return FailCheck("honest member failed to decrypt: " + err.Error())
	}
	// Decoy member MUST fail — F2-1 commitment rejection.
	if _, err := encryption.GroupDecrypt(encryption.GroupDecryptInput{
		Wrapper: equivocated, MyPubkeyHash: gmB.PubkeyHash, MyPriv: privB.Bytes(),
	}); err == nil {
		return FailCheck("ENC-GROUP-COMMIT-1: equivocated outer opened under decoy key — F2-1 commitment ABSENT or broken")
	}
	return PassCheck("F2-1 key-commitment rejects equivocation (invisible-salamanders class closed)")
}

func runEncAADTamperSelf() CheckOutcome {
	pt := []byte("tamper canary self")
	pass := []byte("tamper-passphrase")
	ed, err := encryption.SelfEncrypt(pass, "k", pt, encryption.SelfEncryptParams{Params: cheapKDF})
	if err != nil {
		return FailCheck("SelfEncrypt: " + err.Error())
	}
	cases := []struct {
		name   string
		mutate func(*types.EncryptedData)
	}{
		{"nonce", func(e *types.EncryptedData) { e.Nonce = bytes.Clone(e.Nonce); e.Nonce[0] ^= 0xFF }},
		{"kdf_salt", func(e *types.EncryptedData) { e.KDFSalt = bytes.Clone(e.KDFSalt); e.KDFSalt[0] ^= 0xFF }},
		{"kdf_params", func(e *types.EncryptedData) { p := *e.KDFParams; p.TimeCost++; e.KDFParams = &p }},
		{"key_id", func(e *types.EncryptedData) { e.KeyID = "different-key" }},
		{"ciphertext", func(e *types.EncryptedData) { e.Ciphertext = bytes.Clone(e.Ciphertext); e.Ciphertext[0] ^= 0xFF }},
	}
	for _, c := range cases {
		bad := ed
		c.mutate(&bad)
		if _, err := encryption.SelfDecrypt(pass, bad); err == nil {
			return FailCheck("self-mode tamper(" + c.name + ") did NOT fail — AAD binding broken")
		}
	}
	return PassCheck("self-mode AAD tamper detection covers 5 fields")
}

func runEncAADTamperPeer() CheckOutcome {
	priv, _ := ecdh.X25519().GenerateKey(secureRand{})
	pub := priv.PublicKey().Bytes()
	pkHash, _ := encryption.ComputePubkeyHash(types.EncryptionPubkeyData{
		EncKeyType: uint(types.EncKeyTypeX25519), PublicKey: pub,
		SupportedAEADIDs: []uint{uint(types.AEADIDXChaCha20Poly1305)},
		SupportedKDFIDs:  []uint{uint(types.KDFIDHKDFSHA256)},
	})
	ed, err := encryption.PeerEncrypt(encryption.PeerEncryptInput{
		RecipientPubkey: pub, RecipientPubkeyHash: pkHash, Plaintext: []byte("tamper canary peer"),
	})
	if err != nil {
		return FailCheck("PeerEncrypt: " + err.Error())
	}
	cases := []struct {
		name   string
		mutate func(*types.EncryptedData)
	}{
		{"nonce", func(e *types.EncryptedData) { e.Nonce = bytes.Clone(e.Nonce); e.Nonce[0] ^= 0xFF }},
		{"ephemeral_key", func(e *types.EncryptedData) { e.EphemeralKey = bytes.Clone(e.EphemeralKey); e.EphemeralKey[0] ^= 0xFF }},
		{"ciphertext", func(e *types.EncryptedData) { e.Ciphertext = bytes.Clone(e.Ciphertext); e.Ciphertext[0] ^= 0xFF }},
	}
	for _, c := range cases {
		bad := ed
		c.mutate(&bad)
		if _, err := encryption.PeerDecrypt(encryption.PeerDecryptInput{Wrapper: bad, RecipientPriv: priv.Bytes()}); err == nil {
			return FailCheck("peer-mode tamper(" + c.name + ") did NOT fail — AAD binding broken")
		}
	}
	return PassCheck("peer-mode AAD tamper detection covers 3 fields")
}

func runEncResourceBoundsGroup() CheckOutcome {
	// Build GroupMaxMembers+1 dummy members.
	members := make([]encryption.GroupMember, encryption.GroupMaxMembers+1)
	for i := range members {
		priv, _ := ecdh.X25519().GenerateKey(secureRand{})
		pub := priv.PublicKey().Bytes()
		h, err := encryption.ComputePubkeyHash(types.EncryptionPubkeyData{
			EncKeyType: uint(types.EncKeyTypeX25519), PublicKey: pub,
			SupportedAEADIDs: []uint{uint(types.AEADIDXChaCha20Poly1305)},
			SupportedKDFIDs:  []uint{uint(types.KDFIDHKDFSHA256)},
		})
		if err != nil {
			return FailCheck("ComputePubkeyHash: " + err.Error())
		}
		members[i] = encryption.GroupMember{Pubkey: pub, PubkeyHash: h}
	}
	_, err := encryption.GroupEncrypt(encryption.GroupEncryptInput{Members: members, Plaintext: []byte("too many")})
	if err == nil {
		return FailCheck("GroupEncrypt accepted >256 members — §8.6 ceiling NOT enforced")
	}
	return PassCheck(fmt.Sprintf("group >%d members rejected (§16 ENC-RESOURCE-BOUNDS-1): %v",
		encryption.GroupMaxMembers, err))
}

func runEncCertLifecycleTierA(ctx context.Context, client *PeerClient) CheckOutcome {
	// Mint a fresh X25519 keypair for an encryption-pubkey at Tier A. The
	// pubkey + its V7-signed system/signature ride into the client's
	// namespace on the remote peer. Then publish a handoff, then a
	// revocation. Verify each entity round-trips via TreeGet.
	if client.Keypair().IsZero() {
		return SkipCheck("client has no signing keypair — start validate-peer with -identity to exercise lifecycle")
	}

	x25519Priv, err := ecdh.X25519().GenerateKey(secureRand{})
	if err != nil {
		return FailCheck("gen X25519: " + err.Error())
	}
	pubData := types.EncryptionPubkeyData{
		EncKeyType:       uint(types.EncKeyTypeX25519),
		PublicKey:        x25519Priv.PublicKey().Bytes(),
		SupportedAEADIDs: []uint{uint(types.AEADIDXChaCha20Poly1305)},
		SupportedKDFIDs:  []uint{uint(types.KDFIDHKDFSHA256)},
		Created:          0,
	}
	pkEnt, err := encEntityFromData(types.TypeEncryptionPubkey, pubData)
	if err != nil {
		return FailCheck("build pubkey entity: " + err.Error())
	}
	pkHash := pkEnt.ContentHash
	pkPath := "system/encryption/pubkey/" + hex.EncodeToString(pkHash.Bytes())
	if _, err := client.TreePut(ctx, pkPath, pkEnt); err != nil {
		return FailCheck("publish pubkey at " + pkPath + ": " + err.Error())
	}
	if err := publishInvariantSig(ctx, client, pkHash); err != nil {
		return FailCheck("publish pubkey signature: " + err.Error())
	}

	// Verify the pubkey round-trips at the discoverable path.
	gotEnt, _, err := client.TreeGet(ctx, pkPath)
	if err != nil {
		return FailCheck("resolve pubkey: " + err.Error())
	}
	if gotEnt.ContentHash != pkHash {
		return FailCheck(fmt.Sprintf("pubkey resolve hash mismatch: got %s, want %s", gotEnt.ContentHash, pkHash))
	}

	// Rotate: new pubkey + handoff entity. The handoff is signed by the OLD
	// holder via the client keypair (which authored the old pubkey too;
	// this single-peer-controls-both-keys shape is the Tier A "self-rooted"
	// case). The cross-signer "OLD keypair signs new pubkey ownership"
	// shape needs a second X25519 keypair the validator doesn't have; we
	// cover the single-keypair path here and leave cross-impl dual-sig to
	// the §10.1 cohort discussion.
	newX25519, _ := ecdh.X25519().GenerateKey(secureRand{})
	newPubData := pubData
	newPubData.PublicKey = newX25519.PublicKey().Bytes()
	newPubData.Created = 1
	newPubEnt, err := encEntityFromData(types.TypeEncryptionPubkey, newPubData)
	if err != nil {
		return FailCheck("build new pubkey: " + err.Error())
	}
	newPath := "system/encryption/pubkey/" + hex.EncodeToString(newPubEnt.ContentHash.Bytes())
	if _, err := client.TreePut(ctx, newPath, newPubEnt); err != nil {
		return FailCheck("publish new pubkey: " + err.Error())
	}
	if err := publishInvariantSig(ctx, client, newPubEnt.ContentHash); err != nil {
		return FailCheck("publish new pubkey signature: " + err.Error())
	}
	handoffEnt, err := encEntityFromData(types.TypeEncryptionHandoff, types.EncryptionHandoffData{
		PreviousPubkey: pkHash, NextPubkey: newPubEnt.ContentHash, Created: 1,
	})
	if err != nil {
		return FailCheck("build handoff: " + err.Error())
	}
	hoPath := "system/encryption/handoff/" + hex.EncodeToString(handoffEnt.ContentHash.Bytes())
	if _, err := client.TreePut(ctx, hoPath, handoffEnt); err != nil {
		return FailCheck("publish handoff: " + err.Error())
	}
	if err := publishInvariantSig(ctx, client, handoffEnt.ContentHash); err != nil {
		return FailCheck("publish handoff signature: " + err.Error())
	}

	// Revoke the original pubkey.
	revEnt, err := encEntityFromData(types.TypeEncryptionRevocation, types.EncryptionRevocationData{
		Revokes: pkHash, Reason: "rotated", Created: 2,
	})
	if err != nil {
		return FailCheck("build revocation: " + err.Error())
	}
	revPath := "system/encryption/revocation/" + hex.EncodeToString(revEnt.ContentHash.Bytes())
	if _, err := client.TreePut(ctx, revPath, revEnt); err != nil {
		return FailCheck("publish revocation: " + err.Error())
	}
	if err := publishInvariantSig(ctx, client, revEnt.ContentHash); err != nil {
		return FailCheck("publish revocation signature: " + err.Error())
	}

	// Re-read all three to confirm acceptance + persistence.
	for _, p := range []string{pkPath, newPath, hoPath, revPath} {
		if _, _, err := client.TreeGet(ctx, p); err != nil {
			return FailCheck("post-write resolve " + p + ": " + err.Error())
		}
	}

	// B1-4 behavioral refusal — exercise §10 handoff walk + §11 revocation
	// against the just-published lifecycle. The validate-peer client holds
	// the authored handoff + revocation entities in-process, so it can
	// reconstruct the resolver inputs without re-listing the remote tree
	// (the listing surface is best-effort across cohort impls; the
	// behavioral discipline is what we're gating).
	handoffs := []types.EncryptionHandoffData{{
		PreviousPubkey: pkHash, NextPubkey: newPubEnt.ContentHash, Created: 1,
	}}
	revocationsPreRevoke := []types.EncryptionRevocationData{}
	revocationsPostRevoke := []types.EncryptionRevocationData{{
		Revokes: pkHash, Reason: "rotated", Created: 2,
	}}
	// §10 handoff resolves old→new when nothing is revoked yet.
	resolved, err := encryption.ResolveCurrentRecipient(pkHash, revocationsPreRevoke, handoffs)
	if err != nil {
		return FailCheck("pre-revoke handoff walk: " + err.Error())
	}
	if resolved != newPubEnt.ContentHash {
		return FailCheck(fmt.Sprintf("pre-revoke handoff walk: resolved %s, want new pubkey %s",
			resolved, newPubEnt.ContentHash))
	}
	// §11 revocation supersedes — sender requesting OLD pubkey gets refused.
	if _, err := encryption.ResolveCurrentRecipient(pkHash, revocationsPostRevoke, handoffs); err == nil {
		return FailCheck("post-revoke ResolveCurrentRecipient(old) MUST fail with encryption_key_revoked, got nil")
	} else if !errors.Is(err, encryption.ErrEncryptionKeyRevoked) {
		return FailCheck("post-revoke ResolveCurrentRecipient(old) wrong error: " + err.Error())
	}
	// Successor is still live — sender requesting the NEW pubkey succeeds.
	if got, err := encryption.ResolveCurrentRecipient(
		newPubEnt.ContentHash, revocationsPostRevoke, handoffs,
	); err != nil {
		return FailCheck("post-revoke ResolveCurrentRecipient(new): " + err.Error())
	} else if got != newPubEnt.ContentHash {
		return FailCheck(fmt.Sprintf("post-revoke resolve(new) drifted: got %s, want %s", got, newPubEnt.ContentHash))
	}
	return PassCheck("Tier-A pubkey + handoff + revocation published and round-tripped; §10 chain walks; §11 encryption_key_revoked refuses revoked key")
}

// --- helpers ---

// secureRand is a tiny crypto/rand-backed io.Reader, used wherever ecdh
// needs an entropy source.
type secureRand struct{}

func (secureRand) Read(p []byte) (int, error) {
	return rand.Read(p)
}

func cryptoRandRead(p []byte) (int, error) {
	return rand.Read(p)
}

func encEntityFromData(typeName string, data interface{}) (entity.Entity, error) {
	raw, err := ecf.Encode(data)
	if err != nil {
		return entity.Entity{}, err
	}
	return entity.NewEntity(typeName, cbor.RawMessage(raw))
}

func publishInvariantSig(ctx context.Context, client *PeerClient, target hash.Hash) error {
	kp := client.Keypair()
	if kp.IsZero() {
		return fmt.Errorf("client keypair missing")
	}
	identity := client.IdentityEntity()
	sig := kp.Sign(target.Bytes())
	sigEnt, err := types.SignatureData{
		Target:    target,
		Signer:    identity.ContentHash,
		Algorithm: "ed25519",
		Signature: sig,
	}.ToEntity()
	if err != nil {
		return fmt.Errorf("build signature: %w", err)
	}
	if _, err := client.TreePut(ctx, "system/signature/"+hex.EncodeToString(target.Bytes()), sigEnt); err != nil {
		return fmt.Errorf("tree:put signature: %w", err)
	}
	return nil
}

func genGroupMember() (*ecdh.PrivateKey, encryption.GroupMember, error) {
	priv, err := ecdh.X25519().GenerateKey(secureRand{})
	if err != nil {
		return nil, encryption.GroupMember{}, err
	}
	pub := priv.PublicKey().Bytes()
	h, err := encryption.ComputePubkeyHash(types.EncryptionPubkeyData{
		EncKeyType: uint(types.EncKeyTypeX25519), PublicKey: pub,
		SupportedAEADIDs: []uint{uint(types.AEADIDXChaCha20Poly1305)},
		SupportedKDFIDs:  []uint{uint(types.KDFIDHKDFSHA256)},
	})
	if err != nil {
		return nil, encryption.GroupMember{}, err
	}
	return priv, encryption.GroupMember{Pubkey: pub, PubkeyHash: h}, nil
}

// wrapMemberForCommitTest builds a single per-member wrap delivering the
// given groupKey. It crafts ephemeral material directly via the
// ext/encryption primitives so the equivocation test can use distinct
// groupKeys per member (which the honest GroupEncrypt path forbids).
func wrapMemberForCommitTest(m encryption.GroupMember, groupKey []byte) (types.WrappedKey, error) {
	ephSeed := make([]byte, encryption.X25519PrivateSize)
	if _, err := cryptoRandRead(ephSeed); err != nil {
		return types.WrappedKey{}, err
	}
	wrapNonce, err := encryption.RandomNonce()
	if err != nil {
		return types.WrappedKey{}, err
	}
	ephPriv, err := ecdh.X25519().NewPrivateKey(ephSeed)
	if err != nil {
		return types.WrappedKey{}, err
	}
	memberPub, err := ecdh.X25519().NewPublicKey(m.Pubkey)
	if err != nil {
		return types.WrappedKey{}, err
	}
	shared, err := ephPriv.ECDH(memberPub)
	if err != nil {
		return types.WrappedKey{}, err
	}
	info := append([]byte("entity-core/peer/"), m.PubkeyHash.Bytes()...)
	wrapKey, err := encryption.HKDFSHA256(shared, wrapNonce, info, encryption.AEADKeySize)
	if err != nil {
		return types.WrappedKey{}, err
	}
	aad, err := encryption.GroupWrapAAD(types.EncKeyTypeX25519, types.AEADIDXChaCha20Poly1305,
		types.KDFIDHKDFSHA256, wrapNonce, m.PubkeyHash, ephPriv.PublicKey().Bytes())
	if err != nil {
		return types.WrappedKey{}, err
	}
	wrapped, err := encryption.XChaChaEncrypt(wrapKey, wrapNonce, aad, groupKey)
	if err != nil {
		return types.WrappedKey{}, err
	}
	return types.WrappedKey{
		RecipientKey:   m.PubkeyHash,
		EncKeyType:     uint(types.EncKeyTypeX25519),
		EphemeralKey:   ephPriv.PublicKey().Bytes(),
		WrappedAEADKey: wrapped,
		WrapNonce:      wrapNonce,
	}, nil
}
