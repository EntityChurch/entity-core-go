package validate

import (
	"bytes"
	"encoding/binary"
	"fmt"
)

// verifyCanonicalKeyOrder walks a CBOR-encoded frame and verifies that
// every map's keys are in canonical ECF order: ascending bytewise
// lexicographic order of each key's full encoded byte span (RFC 8949
// §4.2.1 core deterministic; ECF §4.2). It also rejects indefinite-length
// items and duplicate keys, which ECF forbids.
//
// Why not decode + re-encode through Go's ecf.Encode and byte-compare:
// that conflates the key-ordering rule with value canonicalization (float
// minimization, integer sizing) AND treats Go's encoder as the reference
// — the privileged-encoder anti-pattern GUIDE-CONFORMANCE §3.4 retracts.
// The authority for cross-impl byte agreement is the offline `conformance`
// corpus diff. This live check validates ONLY the spec's key-ordering rule,
// directly, so it neither blesses Go's encoder nor false-fails a peer whose
// value canonicalization is correct but differs from Go's at some corner.
func verifyCanonicalKeyOrder(data []byte) error {
	off, err := scanCBORItem(data, 0)
	if err != nil {
		return err
	}
	if off != len(data) {
		return fmt.Errorf("%d trailing bytes after top-level item", len(data)-off)
	}
	return nil
}

// scanCBORItem scans one CBOR data item starting at off, recursively
// verifying map key ordering, and returns the offset just past it.
func scanCBORItem(data []byte, off int) (int, error) {
	if off >= len(data) {
		return 0, fmt.Errorf("unexpected end of CBOR at offset %d", off)
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
			return 0, fmt.Errorf("truncated 1-byte arg at %d", off)
		}
		arg = uint64(data[off])
		off++
	case ai == 25:
		if off+2 > len(data) {
			return 0, fmt.Errorf("truncated 2-byte arg at %d", off)
		}
		arg = uint64(binary.BigEndian.Uint16(data[off:]))
		off += 2
	case ai == 26:
		if off+4 > len(data) {
			return 0, fmt.Errorf("truncated 4-byte arg at %d", off)
		}
		arg = uint64(binary.BigEndian.Uint32(data[off:]))
		off += 4
	case ai == 27:
		if off+8 > len(data) {
			return 0, fmt.Errorf("truncated 8-byte arg at %d", off)
		}
		arg = binary.BigEndian.Uint64(data[off:])
		off += 8
	case ai == 31:
		return 0, fmt.Errorf("indefinite-length item (major %d) is non-canonical — ECF forbids", major)
	default:
		return 0, fmt.Errorf("reserved additional info %d (major %d)", ai, major)
	}

	switch major {
	case 0, 1: // unsigned int, negative int — no payload beyond arg
		return off, nil
	case 2, 3: // byte string, text string — arg bytes of payload
		end := off + int(arg)
		if end > len(data) || end < off {
			return 0, fmt.Errorf("truncated string payload at %d (need %d bytes)", off, arg)
		}
		return end, nil
	case 4: // array — arg items
		for i := uint64(0); i < arg; i++ {
			var err error
			off, err = scanCBORItem(data, off)
			if err != nil {
				return 0, err
			}
		}
		return off, nil
	case 5: // map — arg pairs; verify key ordering
		var prevKey []byte
		for i := uint64(0); i < arg; i++ {
			keyStart := off
			var err error
			off, err = scanCBORItem(data, off) // key
			if err != nil {
				return 0, err
			}
			key := data[keyStart:off]
			if prevKey != nil {
				switch bytes.Compare(prevKey, key) {
				case 1:
					return 0, fmt.Errorf("map keys out of canonical order: %x precedes %x (must be ascending bytewise)", prevKey, key)
				case 0:
					return 0, fmt.Errorf("duplicate map key %x (non-canonical)", key)
				}
			}
			prevKey = key
			off, err = scanCBORItem(data, off) // value
			if err != nil {
				return 0, err
			}
		}
		return off, nil
	case 6: // tag — arg is the tag number; one content item follows
		return scanCBORItem(data, off)
	case 7: // simple value / float — payload (if any) already consumed by arg
		return off, nil
	}
	return 0, fmt.Errorf("unhandled major type %d", major)
}
