package validate

import (
	"context"
	"crypto/ecdh"
	"crypto/ed25519"
	"errors"
	"fmt"

	"go.entitychurch.org/entity-core-go/core/crypto"
	"go.entitychurch.org/entity-core-go/core/ecf"
	"go.entitychurch.org/entity-core-go/core/types"
	"go.entitychurch.org/entity-core-go/ext/encryption"
)

// runEncKeySeparation — ENC-KEY-SEPARATION-1 (§16, BLOCK-1, R6).
//
// Asserts the EXTENSION-ENCRYPTION §2 / §9.4 normative MUST: the X25519
// encryption keypair MUST be independent of the Ed25519 identity keypair.
// Forbidden derivations:
//
//   (a) encryption_pk == identity_pk (raw-bytes reuse).
//
//   (b) encryption_pk == birational(identity_pk) — the libsodium
//       crypto_sign_ed25519_pk_to_curve25519 / age transform
//       u = (1+y)/(1-y) mod 2^255-19.
//
// Property check (always runs): a synthetic Ed25519 keypair is generated
// inside this check; (i) an independent X25519 keypair MUST pass
// ValidateKeySeparation, (ii) the identity bytes used as a fake X25519
// pubkey MUST be rejected, and (iii) the birational image of the
// identity MUST be rejected. Failure here is a Go-side R6 helper bug.
//
// Published-pubkey check (best-effort): list
// system/encryption/pubkey/{hex} on the remote peer. For each pubkey
// entity found, decode the X25519 public_key field and ValidateKeySeparation
// against the remote peer's identity public key (from the connect-time
// granter identity). Pubkeys without a recoverable remote-peer pubkey
// are skipped with a note (separation cannot be checked without the
// identity to separate from). If no encryption-pubkey is published yet,
// the check still passes — the property check above proves the helper
// is correct; the BLOCK-1 gate is enforced wherever the peer authors an
// encryption keypair.
func runEncKeySeparation(ctx context.Context, client *PeerClient) CheckOutcome {
	// Step 1 — synthetic property check.
	synthSeed := make([]byte, ed25519.SeedSize)
	for i := range synthSeed {
		synthSeed[i] = 0xC3 // distinct from any KAT seed
	}
	synthPriv := ed25519.NewKeyFromSeed(synthSeed)
	var synthIdentity [32]byte
	copy(synthIdentity[:], synthPriv.Public().(ed25519.PublicKey))

	independentX, err := ecdh.X25519().GenerateKey(secureRand{})
	if err != nil {
		return FailCheck("ecdh.X25519 keygen: " + err.Error())
	}
	var independentXPK [32]byte
	copy(independentXPK[:], independentX.PublicKey().Bytes())

	// (i) Independent keypair — accept.
	if err := encryption.ValidateKeySeparation(synthIdentity, independentXPK); err != nil {
		return FailCheck("ENC-KEY-SEPARATION-1 (i) independent X25519 keypair rejected: " + err.Error())
	}
	// (ii) Identity bytes as encryption-pk — reject.
	if err := encryption.ValidateKeySeparation(synthIdentity, synthIdentity); err == nil {
		return FailCheck("ENC-KEY-SEPARATION-1 (ii) identity-as-encryption-pk MUST fail (R6)")
	} else if !errors.Is(err, encryption.ErrEncryptionKeyDerivedFromIdentity) {
		return FailCheck("ENC-KEY-SEPARATION-1 (ii) wrong error: " + err.Error())
	}
	// (iii) Birational(identity) — reject.
	birat, err := encryption.BirationalEdToX25519(synthIdentity)
	if err != nil {
		return FailCheck("ENC-KEY-SEPARATION-1 (iii) BirationalEdToX25519: " + err.Error())
	}
	if err := encryption.ValidateKeySeparation(synthIdentity, birat); err == nil {
		return FailCheck("ENC-KEY-SEPARATION-1 (iii) birational(identity) MUST fail (R6 libsodium-pattern forbidden)")
	} else if !errors.Is(err, encryption.ErrEncryptionKeyDerivedFromIdentity) {
		return FailCheck("ENC-KEY-SEPARATION-1 (iii) wrong error: " + err.Error())
	}

	// Step 2 — probe the remote peer for published encryption-pubkeys.
	// List system/encryption/pubkey/ ; per-entry decode and (where the
	// remote identity is recoverable) validate separation.
	entries, _, err := client.TreeListing(ctx, "system/encryption/pubkey")
	if err != nil {
		// Listing failure is fine (path may not exist on a fresh peer);
		// the property check above is the gating signal.
		return PassCheck("R6 helper property check OK; no published encryption-pubkey to validate (listing: " + err.Error() + ")")
	}
	if len(entries) == 0 {
		return PassCheck("R6 helper property check OK; no encryption-pubkey published on remote")
	}

	// Recover the remote peer's identity public key from connect-time
	// granter identity. If unavailable, the published-pubkey check
	// degrades to a presence count (separation cannot be asserted
	// without the identity to separate from).
	remoteIdentity, identityKnown := remoteIdentityEd25519(client)
	if !identityKnown {
		return PassCheck(fmt.Sprintf(
			"R6 helper property check OK; %d encryption-pubkey(s) published but remote identity Ed25519 pubkey not recoverable",
			len(entries)))
	}

	validated := 0
	for path := range entries {
		ent, _, err := client.TreeGet(ctx, path)
		if err != nil {
			continue
		}
		if ent.Type != types.TypeEncryptionPubkey {
			continue
		}
		var pkData types.EncryptionPubkeyData
		if err := ecf.Decode(ent.Data, &pkData); err != nil {
			continue
		}
		if pkData.EncKeyType != uint(types.EncKeyTypeX25519) || len(pkData.PublicKey) != 32 {
			continue // skip non-X25519 (separation rule is X25519-specific)
		}
		var encPK [32]byte
		copy(encPK[:], pkData.PublicKey)
		if err := encryption.ValidateKeySeparation(remoteIdentity, encPK); err != nil {
			return FailCheck(fmt.Sprintf("ENC-KEY-SEPARATION-1 published-pubkey %s violates R6: %v", path, err))
		}
		validated++
	}
	return PassCheck(fmt.Sprintf("R6 helper property check OK; %d published X25519 encryption-pubkey(s) independent of remote identity", validated))
}

// remoteIdentityEd25519 extracts the remote peer's Ed25519 public key
// bytes from the connect-time granter identity entity (already validated
// during PerformHandshake). Returns (pk, true) when the granter identity
// is an Ed25519 key. Other key types (Ed448) are out of scope for R6 —
// the birational map is Ed25519↔X25519-specific.
func remoteIdentityEd25519(client *PeerClient) ([32]byte, bool) {
	var zero [32]byte
	granterHash := client.RemotePeerIdentityHash()
	if granterHash.Algorithm == 0 && len(granterHash.Digest) == 0 {
		return zero, false
	}
	env := client.AuthenticateResponseEnv
	granter, ok := env.FindIncluded(granterHash)
	if !ok {
		return zero, false
	}
	var pd types.PeerData
	if err := ecf.Decode(granter.Data, &pd); err != nil {
		return zero, false
	}
	if pd.KeyType != crypto.KeyTypeStringEd25519 || len(pd.PublicKey) != 32 {
		return zero, false
	}
	var pk [32]byte
	copy(pk[:], pd.PublicKey)
	return pk, true
}
