package encryption

import (
	"fmt"

	"go.entitychurch.org/entity-core-go/core/ecf"
	"go.entitychurch.org/entity-core-go/core/entity"
	"go.entitychurch.org/entity-core-go/core/types"
)

// ENC-KAT-INNER per R3 (arch ruling). The canonical fixed
// inner entity used as the plaintext for ENC-SELF-KAT-1 / ENC-PEER-KAT-1 /
// ENC-GROUP-KAT-1. Pinned shape:
//
//	system/note {
//	  body:    "entity-core encryption KAT inner entity"
//	  created: 0
//	}
//
// Plaintext = ECF({data, type}) — the hashable 2-key form per
// ENTITY-CBOR-ENCODING §4.2, identical to what content_hash is computed
// over. This matches the spec's "ECF(ENC-KAT-INNER)" reference and gives
// decrypt-and-reinject (§13.3) a real typed entity to re-author.

const (
	// EncKATInnerType is the entity type name for ENC-KAT-INNER.
	EncKATInnerType = "system/note"

	// EncKATInnerBody is the pinned body field of ENC-KAT-INNER.
	EncKATInnerBody = "entity-core encryption KAT inner entity"

	// EncKATInnerCreated is the pinned created field of ENC-KAT-INNER.
	EncKATInnerCreated uint64 = 0
)

// encKATInnerData mirrors the {body, created} field set with cbor tags
// so ecf.Encode produces deterministic length-first key order
// ("body" len 4 < "created" len 7).
type encKATInnerData struct {
	Body    string `cbor:"body"`
	Created uint64 `cbor:"created"`
}

// EncKATInnerEntity returns the canonical ENC-KAT-INNER as a fully-formed
// entity (type, data, content_hash). The data field is the ECF encoding
// of the {body, created} fields per ENTITY-CBOR-ENCODING.
func EncKATInnerEntity() (entity.Entity, error) {
	data, err := ecf.Encode(encKATInnerData{Body: EncKATInnerBody, Created: EncKATInnerCreated})
	if err != nil {
		return entity.Entity{}, fmt.Errorf("%s: encode ENC-KAT-INNER data: %w",
			types.EncryptionErrInvalidWrapper, err)
	}
	return entity.NewEntity(EncKATInnerType, data)
}

// EncKATInnerPlaintext returns the §16 KAT plaintext: the ECF bytes of
// ENC-KAT-INNER in the hashable {data, type} 2-key form. This is what
// gets fed into SelfEncrypt / PeerEncrypt / GroupEncrypt for the byte-pin
// vectors.
func EncKATInnerPlaintext() ([]byte, error) {
	ent, err := EncKATInnerEntity()
	if err != nil {
		return nil, err
	}
	pt, err := ecf.EncodeHashable(ent.Type, ent.Data)
	if err != nil {
		return nil, fmt.Errorf("%s: encode ENC-KAT-INNER plaintext: %w",
			types.EncryptionErrInvalidWrapper, err)
	}
	return pt, nil
}
