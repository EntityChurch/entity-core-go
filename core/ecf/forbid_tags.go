package ecf

import (
	"encoding/binary"
	"fmt"

	ecerrors "go.entitychurch.org/entity-core-go/core/errors"
)

// ForbidTags walks a CBOR-encoded value and returns ErrNonCanonicalECF if a
// CBOR tag (major type 6) appears at ANY depth (ENTITY-CBOR-ENCODING §6.3 —
// tags are non-canonical in ECF and MUST NOT be accepted, forwarded, or
// silently stripped). It is the receive-boundary counterpart to hash
// validation: hash validation proves the bytes are the sender's; this proves
// they are canonical.
//
// Why this is needed even though ecf.Decode succeeds on a tagged frame: the
// package decoder runs default DecOptions (tags allowed), and an entity's data
// field is held as cbor.RawMessage to preserve byte fidelity for hashing — so a
// tag inside a data field is captured whole and never parsed by the entity
// decode. A tagged entity self-verifies (the sender computed content_hash over
// the same tagged bytes), so hash validation cannot see it. Only an explicit
// walk does. Because an entity's data may itself embed nested entity data
// (an EXECUTE root's data carries the params entity), one recursive walk over a
// data field reaches every nested data field it contains — total at no extra
// decode.
//
// The walk is definite-length only: indefinite-length items are themselves
// non-canonical (ECF forbids them) and are reported as such. The input is
// assumed already accepted by ecf.Decode as well-formed CBOR; ForbidTags does
// not re-validate structure beyond what it must traverse to find a tag.
func ForbidTags(data []byte) error {
	off, err := forbidTagsScan(data, 0, 0)
	if err != nil {
		return err
	}
	if off != len(data) {
		return fmt.Errorf("%w: %d trailing bytes after top-level CBOR item",
			ecerrors.ErrNonCanonicalECF, len(data)-off)
	}
	return nil
}

// forbidTagsScan scans one CBOR data item starting at off and returns the
// offset just past it, erroring on the first tag (major 6) at any depth.
func forbidTagsScan(data []byte, off, depth int) (int, error) {
	if off >= len(data) {
		return 0, fmt.Errorf("%w: unexpected end of CBOR at offset %d",
			ecerrors.ErrNonCanonicalECF, off)
	}
	ib := data[off]
	major := ib >> 5
	ai := ib & 0x1f
	off++

	var arg uint64
	switch {
	case ai < 24:
		arg = uint64(ai)
	case ai == 24:
		if off+1 > len(data) {
			return 0, fmt.Errorf("%w: truncated 1-byte arg at %d", ecerrors.ErrNonCanonicalECF, off)
		}
		arg = uint64(data[off])
		off++
	case ai == 25:
		if off+2 > len(data) {
			return 0, fmt.Errorf("%w: truncated 2-byte arg at %d", ecerrors.ErrNonCanonicalECF, off)
		}
		arg = uint64(binary.BigEndian.Uint16(data[off:]))
		off += 2
	case ai == 26:
		if off+4 > len(data) {
			return 0, fmt.Errorf("%w: truncated 4-byte arg at %d", ecerrors.ErrNonCanonicalECF, off)
		}
		arg = uint64(binary.BigEndian.Uint32(data[off:]))
		off += 4
	case ai == 27:
		if off+8 > len(data) {
			return 0, fmt.Errorf("%w: truncated 8-byte arg at %d", ecerrors.ErrNonCanonicalECF, off)
		}
		arg = binary.BigEndian.Uint64(data[off:])
		off += 8
	case ai == 31:
		return 0, fmt.Errorf("%w: indefinite-length item (major %d) is non-canonical",
			ecerrors.ErrNonCanonicalECF, major)
	default:
		return 0, fmt.Errorf("%w: reserved additional info %d (major %d)",
			ecerrors.ErrNonCanonicalECF, ai, major)
	}

	switch major {
	case 0, 1: // unsigned / negative int — no payload beyond arg
		return off, nil
	case 2, 3: // byte / text string — arg bytes of payload
		end := off + int(arg)
		if end > len(data) || end < off {
			return 0, fmt.Errorf("%w: truncated string payload at %d (need %d bytes)",
				ecerrors.ErrNonCanonicalECF, off, arg)
		}
		return end, nil
	case 4: // array — arg items
		for i := uint64(0); i < arg; i++ {
			var err error
			if off, err = forbidTagsScan(data, off, depth+1); err != nil {
				return 0, err
			}
		}
		return off, nil
	case 5: // map — arg key/value pairs
		for i := uint64(0); i < arg; i++ {
			var err error
			if off, err = forbidTagsScan(data, off, depth+1); err != nil { // key
				return 0, err
			}
			if off, err = forbidTagsScan(data, off, depth+1); err != nil { // value
				return 0, err
			}
		}
		return off, nil
	case 6: // TAG — forbidden by §6.3 at any depth. This is the check.
		return 0, fmt.Errorf("%w: CBOR tag %d (major type 6) at depth %d — tags are forbidden in ECF (ENTITY-CBOR-ENCODING §6.3)",
			ecerrors.ErrNonCanonicalECF, arg, depth)
	case 7: // simple value / float — no nested item
		return off, nil
	default:
		return 0, fmt.Errorf("%w: unknown CBOR major type %d", ecerrors.ErrNonCanonicalECF, major)
	}
}
