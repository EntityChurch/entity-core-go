// ENC-ROUNDTRIP-FORMAT-1 (§16) — the content_hash_format seam under
// encryption.
//
// §16 words this vector "floor when SHA-384 active," which reads like a
// distant conditional and is not one: `entity-peer --hash-type sha384`
// ships in all three implementations today, and until this check existed
// nothing in the suite had ever turned it on. An entire crypto-agility
// surface sat unexercised beneath encryption — and the first thing writing
// this found was a real defect in our own library (ComputePubkeyHash
// hashed unconditionally under SHA-256 while documenting itself as
// following the peer's home format), invisible for exactly that reason.
//
// WHAT THE VECTOR ASSERTS. §7.4's note, per V7 §1.8 + v7.69 §4.5a:
// `recipient_key` is the recipient's **authored** content_hash under the
// **recipient's** home format. A sender MUST NOT re-derive it under its
// own. Two things follow, and the check asserts both:
//
//  1. A peer must carry a reference in a format other than its home
//     without touching it. That is Part A, and it is peer-attributable:
//     the peer under test has a SHA-256 home in a normal run, and it must
//     still store and serve a SHA-384-authored entity at the SHA-384
//     address, returning a content_hash that still validates.
//  2. The binding path must use the recipient's bytes verbatim. That is
//     Part B, against our own library.
//
// WHY PART B DOES NOT MUTATE THE PROCESS HOME FORMAT. The natural way to
// write "a SHA-256 sender and a SHA-384 recipient" is to flip
// entity.SetDefaultHashAlgorithm mid-check. Checks do run sequentially,
// so it would mostly work — but earlier checks leave background servers
// and goroutines alive (peer_issued_fixture's HTTP server, among others),
// and any entity one of them authored inside the window would silently
// land in the wrong address space. A conformance check that can corrupt
// an unrelated check by timing is not worth the fidelity. Both homes are
// therefore named explicitly via ComputePubkeyHashFormat. That the
// process-global path follows suit is pinned separately, in
// ext/encryption's TestComputePubkeyHashFollowsHomeFormat, where the
// package's own sequencing makes the flip safe — and end-to-end by
// running the whole suite against a peer started --hash-type sha384.
//
// SCOPE, STATED RATHER THAN ASSUMED. §16's phrasing — "encrypt on SHA-256
// peer, decrypt on SHA-384 peer" — describes two peers with *different*
// home formats, which V7 §1.2a calls the experimental two-address-space
// mode and puts out of v1 scope. The v1-floor reading is the other one: a
// network on a SHA-384 home format, where everything must work, plus the
// §1.8 reference discipline that applies to any peer holding a reference
// it did not author. This check gates the v1-floor reading. The
// divergence is filed as a spec issue rather than resolved here.

package validate

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"encoding/hex"
	"fmt"

	"github.com/fxamacker/cbor/v2"

	"go.entitychurch.org/entity-core-go/core/ecf"
	"go.entitychurch.org/entity-core-go/core/entity"
	"go.entitychurch.org/entity-core-go/core/hash"
	"go.entitychurch.org/entity-core-go/core/types"
	"go.entitychurch.org/entity-core-go/ext/encryption"
)

// mintEncPubkeyFormat authors one inner system/encryption-pubkey entity
// under a NAMED content_hash_format rather than the process home format,
// and returns it with its X25519 private key.
//
// The entity and the hash come from one call, not two: mintEncPubkey pairs
// entity.NewEntity with encryption.ComputePubkeyHash, and the whole class
// of bug this vector exists to catch is those two disagreeing about the
// format. Deriving the hash from the authored entity makes the two
// unable to disagree here.
func mintEncPubkeyFormat(alg byte, created uint64) (*ecdh.PrivateKey, entity.Entity, error) {
	priv, err := ecdh.X25519().GenerateKey(secureRand{})
	if err != nil {
		return nil, entity.Entity{}, fmt.Errorf("gen X25519: %w", err)
	}
	raw, err := ecf.Encode(types.EncryptionPubkeyData{
		EncKeyType:       uint(types.EncKeyTypeX25519),
		PublicKey:        priv.PublicKey().Bytes(),
		SupportedAEADIDs: []uint{uint(types.AEADIDXChaCha20Poly1305)},
		SupportedKDFIDs:  []uint{uint(types.KDFIDHKDFSHA256)},
		Created:          created,
	})
	if err != nil {
		return nil, entity.Entity{}, fmt.Errorf("encode pubkey data: %w", err)
	}
	ent, err := entity.NewEntityFormat(alg, types.TypeEncryptionPubkey, cbor.RawMessage(raw))
	if err != nil {
		return nil, entity.Entity{}, fmt.Errorf("build pubkey entity under 0x%02x: %w", alg, err)
	}
	return priv, ent, nil
}

func runEncRoundtripFormat(ctx context.Context, client *PeerClient) CheckOutcome {
	if client.Keypair().IsZero() {
		return SkipCheck("client has no signing keypair — start validate-peer with -identity to exercise the §4.2.a publication path")
	}

	// --- Part A: the peer carries a foreign-format reference untouched ---

	foreignPriv, foreignEnt, err := mintEncPubkeyFormat(hash.AlgorithmSHA384, 1000)
	if err != nil {
		return FailCheck(err.Error())
	}
	if foreignEnt.ContentHash.Algorithm != hash.AlgorithmSHA384 {
		return FailCheck(fmt.Sprintf("authored under 0x01 but entity carries 0x%02x — "+
			"entity.NewEntityFormat ignored its format argument",
			foreignEnt.ContentHash.Algorithm))
	}
	if n := len(foreignEnt.ContentHash.Bytes()); n != 49 {
		return FailCheck(fmt.Sprintf("SHA-384 content_hash wire form is %d bytes, want 49 "+
			"(1 format byte + 48 digest)", n))
	}

	// The §4.2.a path is derived from Bytes(), so a SHA-384 publication
	// lands at a 98-hex-char path. That it generalizes without a special
	// case is itself part of what "floor when SHA-384 active" means.
	path := encPubkeyPath(foreignEnt.ContentHash)
	if err := publishSigned(ctx, client, path, foreignEnt); err != nil {
		return FailCheck("publish SHA-384-authored pubkey: " + err.Error())
	}

	gotEnt, _, err := client.TreeGet(ctx, path)
	if err != nil {
		return FailCheck(fmt.Sprintf("read back SHA-384-authored pubkey at %s: %v", path, err))
	}
	if !bytes.Equal(gotEnt.ContentHash.Bytes(), foreignEnt.ContentHash.Bytes()) {
		return FailCheck(fmt.Sprintf("peer returned content_hash %x for an entity authored as %x — "+
			"a stored reference was re-derived under the peer's home format (V7 §1.8 / v7.69 §4.5a forbid this)",
			gotEnt.ContentHash.Bytes(), foreignEnt.ContentHash.Bytes()))
	}
	if err := gotEnt.Validate(); err != nil {
		return FailCheck("peer-returned SHA-384 entity fails its own content_hash: " + err.Error())
	}

	// --- Part B: the binding uses the recipient's authored bytes ---

	// Forward — SHA-256-home sender, SHA-384-home recipient.
	fwdMsg := []byte("cross-format peer-mode message")
	fwd, err := encryption.PeerEncrypt(encryption.PeerEncryptInput{
		RecipientPubkey:     foreignPriv.PublicKey().Bytes(),
		RecipientPubkeyHash: foreignEnt.ContentHash,
		Plaintext:           fwdMsg,
	})
	if err != nil {
		return FailCheck("PeerEncrypt to a SHA-384 recipient: " + err.Error())
	}
	if !bytes.Equal(fwd.RecipientKey.Bytes(), foreignEnt.ContentHash.Bytes()) {
		return FailCheck(fmt.Sprintf("bound recipient_key %x != the recipient's authored hash %x",
			fwd.RecipientKey.Bytes(), foreignEnt.ContentHash.Bytes()))
	}
	back, err := encryption.PeerDecrypt(encryption.PeerDecryptInput{
		Wrapper: fwd, RecipientPriv: foreignPriv.Bytes(),
	})
	if err != nil {
		return FailCheck("PeerDecrypt across formats: " + err.Error())
	}
	if !bytes.Equal(back, fwdMsg) {
		return FailCheck("cross-format round-trip plaintext mismatch")
	}

	// Reverse — the recipient is the one on SHA-256. Run both directions
	// because "handles the other format" and "handles the format it is not
	// currently on" are different claims, and a sender that hardcoded 49
	// bytes would pass the forward direction alone.
	homePriv, homeEnt, err := mintEncPubkeyFormat(hash.AlgorithmSHA256, 1000)
	if err != nil {
		return FailCheck(err.Error())
	}
	revMsg := []byte("reverse-direction message")
	rev, err := encryption.PeerEncrypt(encryption.PeerEncryptInput{
		RecipientPubkey:     homePriv.PublicKey().Bytes(),
		RecipientPubkeyHash: homeEnt.ContentHash,
		Plaintext:           revMsg,
	})
	if err != nil {
		return FailCheck("PeerEncrypt to a SHA-256 recipient: " + err.Error())
	}
	if !bytes.Equal(rev.RecipientKey.Bytes(), homeEnt.ContentHash.Bytes()) {
		return FailCheck(fmt.Sprintf("reverse: bound recipient_key %x != authored %x",
			rev.RecipientKey.Bytes(), homeEnt.ContentHash.Bytes()))
	}
	if back, err := encryption.PeerDecrypt(encryption.PeerDecryptInput{
		Wrapper: rev, RecipientPriv: homePriv.Bytes(),
	}); err != nil || !bytes.Equal(back, revMsg) {
		return FailCheck(fmt.Sprintf("reverse-direction round-trip failed: %v", err))
	}

	// --- The forbidden move, and where it is actually caught ---

	// A sender that re-derived the recipient's key under its own home
	// format. The algorithm byte is bound into both the HKDF info and the
	// AAD, so the wrapper differs — but the re-deriving sender is
	// self-consistent and PeerDecrypt rebuilds both from the wrapper's own
	// recipient_key, so it still opens. The AEAD does NOT catch this. What
	// catches it is the recipient's key lookup: the re-derived hash names
	// an entity the recipient never authored. Asserting the enforcement
	// point explicitly is what stops this from being "simplified" later
	// into a decrypt-must-fail that would not fail.
	reDerived, err := encryption.ComputePubkeyHashFormat(hash.AlgorithmSHA256, types.EncryptionPubkeyData{
		EncKeyType:       uint(types.EncKeyTypeX25519),
		PublicKey:        foreignPriv.PublicKey().Bytes(),
		SupportedAEADIDs: []uint{uint(types.AEADIDXChaCha20Poly1305)},
		SupportedKDFIDs:  []uint{uint(types.KDFIDHKDFSHA256)},
		Created:          1000,
	})
	if err != nil {
		return FailCheck("re-derive under sender home format: " + err.Error())
	}
	if bytes.Equal(reDerived.Bytes(), foreignEnt.ContentHash.Bytes()) {
		return FailCheck("re-derivation under the sender's format produced the recipient's " +
			"authored hash — the negative control has no teeth")
	}
	wrong, err := encryption.PeerEncrypt(encryption.PeerEncryptInput{
		RecipientPubkey:     foreignPriv.PublicKey().Bytes(),
		RecipientPubkeyHash: reDerived,
		Plaintext:           fwdMsg,
	})
	if err != nil {
		return FailCheck("PeerEncrypt (re-derived): " + err.Error())
	}
	if bytes.Equal(wrong.Ciphertext, fwd.Ciphertext) {
		return FailCheck("re-derived recipient_key produced identical ciphertext — the " +
			"content_hash_format byte is not reaching the §7.3 step-4 HKDF info")
	}
	// The recipient published exactly one key, at its authored address.
	published := map[hash.Hash]bool{foreignEnt.ContentHash: true}
	if published[wrong.RecipientKey] {
		return FailCheck("a re-derived recipient_key resolved against the recipient's published set")
	}
	if !published[fwd.RecipientKey] {
		return FailCheck("the correctly-bound recipient_key did not resolve against the published set")
	}
	// And the same fact over the wire: the re-derived address is not where
	// the recipient published, so a sender that re-derived would 404 before
	// it ever encrypted.
	if _, _, err := client.TreeGet(ctx, encPubkeyPath(reDerived)); err == nil {
		return FailCheck(fmt.Sprintf("the re-derived address %s resolved on the peer — "+
			"the two formats are not distinct address spaces (V7 §1.2a)",
			encPubkeyPath(reDerived)))
	}

	return PassCheck(fmt.Sprintf(
		"ENC-ROUNDTRIP-FORMAT-1: peer stored + served a SHA-384-authored pubkey at its 49-byte "+
			"address (%s…) with content_hash intact; peer-mode binds the recipient's authored "+
			"hash in both directions (0x01→49 B, 0x00→33 B); re-derivation under the sender's "+
			"home format yields a distinct key that fails recipient lookup and 404s on the wire",
		hex.EncodeToString(foreignEnt.ContentHash.Bytes())[:16]))
}
