package persistence

import (
	"bytes"
	"path/filepath"
	"testing"

	"go.entitychurch.org/entity-core-go/core/crypto"
	"go.entitychurch.org/entity-core-go/core/ecf"
	"go.entitychurch.org/entity-core-go/core/entity"
	"go.entitychurch.org/entity-core-go/core/types"

	"go.entitychurch.org/entity-core-go/ext/encryption"

	"github.com/fxamacker/cbor/v2"
)

// TestSqliteSelfModeStorageRoundTrip — EXTENSION-ENCRYPTION §6 / §6.5 +
// BLOCK-1 scenario B1-1 (storage round-trip): an entity encrypted in
// self-mode and persisted on the sqlite-backed peer MUST decrypt
// byte-identically after a cold restart against the same disk dir.
// Also asserts wrong-passphrase + wrong-kdf_params fail with AEAD
// errors (DoS-of-own-data, not silent corruption).
func TestSqliteSelfModeStorageRoundTrip(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "peer.db")

	kp, err := crypto.Generate()
	if err != nil {
		t.Fatal(err)
	}

	plaintext, err := encryption.EncKATInnerPlaintext()
	if err != nil {
		t.Fatalf("EncKATInnerPlaintext: %v", err)
	}
	passphrase := []byte("entity-core/test/sqlite-storage-roundtrip")
	const keyID = "storage-roundtrip-key"
	// Use the cheap KDF profile so the test runs in milliseconds; the v1
	// baseline costs ~250ms per encrypt+decrypt and adds no signal here
	// (the round-trip property is independent of the Argon2id profile).
	cheapKDF := types.KDFParams{
		Argon2Version: types.Argon2idVersion,
		MemoryCost:    8,
		TimeCost:      1,
		Parallelism:   1,
		OutputLen:     32,
	}

	encWrapper, err := encryption.SelfEncrypt(
		passphrase, keyID, plaintext,
		encryption.SelfEncryptParams{Params: cheapKDF},
	)
	if err != nil {
		t.Fatalf("SelfEncrypt: %v", err)
	}

	// Build the outer system/encrypted entity and persist it via the
	// sqlite-backed store. Path is content-addressed under the encryption
	// subtree per §6.5; the exact path doesn't matter for B1-1 (we re-read
	// by path).
	encEnt, err := buildEncryptedEntity(encWrapper)
	if err != nil {
		t.Fatalf("buildEncryptedEntity: %v", err)
	}
	const storagePath = "system/encrypted/storage-roundtrip-test"

	{
		ep := openExtensionPeer(t, dbPath, kp)
		if _, err := ep.p.Store().Put(encEnt); err != nil {
			ep.closeFn()
			t.Fatalf("session 1 store put: %v", err)
		}
		ep.p.LocationIndex().Set(storagePath, encEnt.ContentHash)
		ep.closeFn()
	}

	// Cold restart against the same on-disk db.
	{
		ep := openExtensionPeer(t, dbPath, kp)
		defer ep.closeFn()

		h, ok := ep.p.LocationIndex().Get(storagePath)
		if !ok {
			t.Fatalf("session 2: location index missing %s after restart", storagePath)
		}
		if h != encEnt.ContentHash {
			t.Fatalf("session 2: hash %s != pre-restart %s", h, encEnt.ContentHash)
		}
		got, ok2 := ep.p.Store().Get(h)
		if !ok2 {
			t.Fatalf("session 2 store get: missing entity %s", h)
		}
		if got.Type != types.TypeEncrypted {
			t.Fatalf("session 2: type %q != %q", got.Type, types.TypeEncrypted)
		}

		// Decode + decrypt — MUST recover byte-identical plaintext.
		var decoded types.EncryptedData
		if err := ecf.Decode(got.Data, &decoded); err != nil {
			t.Fatalf("session 2 decode wrapper: %v", err)
		}
		recovered, err := encryption.SelfDecrypt(passphrase, decoded)
		if err != nil {
			t.Fatalf("session 2 SelfDecrypt: %v", err)
		}
		if !bytes.Equal(recovered, plaintext) {
			t.Fatalf("session 2 plaintext bytes diverge:\n  got %x\n  want %x", recovered, plaintext)
		}

		// Wrong passphrase MUST fail (encryption_aead_failed, not silent).
		if _, err := encryption.SelfDecrypt([]byte("wrong-passphrase-1234567890"), decoded); err == nil {
			t.Fatalf("session 2 SelfDecrypt with wrong passphrase: want error, got nil")
		}

		// Wrong kdf_params — F2-4 binds params into the AAD, so any change
		// MUST fail before HKDF derivation paths even matter.
		bad := decoded
		badParams := *decoded.KDFParams
		badParams.TimeCost = decoded.KDFParams.TimeCost + 1
		bad.KDFParams = &badParams
		if _, err := encryption.SelfDecrypt(passphrase, bad); err == nil {
			t.Fatalf("session 2 SelfDecrypt with tampered kdf_params: want error, got nil")
		}
	}
}

// buildEncryptedEntity wraps a §5.1 EncryptedData into the outer
// system/encrypted entity (the one tree:put accepts).
func buildEncryptedEntity(data types.EncryptedData) (entity.Entity, error) {
	raw, err := ecf.Encode(data)
	if err != nil {
		return entity.Entity{}, err
	}
	return entity.NewEntity(types.TypeEncrypted, cbor.RawMessage(raw))
}
