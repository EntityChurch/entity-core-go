package main

// Canonical ECF encoding for the diag value tree.
//
// fxamacker/cbor's CoreDetEncOptions handles primitives (int / float / text /
// bool / null) correctly per RFC 8949 §4.2: shortest int argument-length,
// Rule 4 float minimization (f64 → f32 → f16), canonical NaN payload. We
// delegate primitives there. Composites (arrays and maps) are emitted by
// hand so we control:
//
//   1. Map key sort by encoded-key bytes, byte-wise lexicographic (the ECF
//      §4.2.1 rule). This is the same as CoreDet's map sort, but our key
//      space includes byteKey (CBOR byte-string keys) which are not
//      ergonomic to express through fxamacker's tagging surface.
//
//   2. Mixed text-string + byte-string keys in one map (map_keys.5).
//
//   3. Top-level arrays of arbitrarily-typed vector entries — the corpus
//      shape.
//
// Result: encodeCanonical(parsedDiag) produces the canonical ECF bytes of
// the corpus, byte-identical to what every conformant impl should produce
// on the same value tree.

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"sort"

	"go.entitychurch.org/entity-core-go/core/ecf"
)

// encodeCanonical encodes a diag-parsed value tree to canonical ECF bytes.
func encodeCanonical(v interface{}) ([]byte, error) {
	switch t := v.(type) {
	case nil:
		return ecf.Encode(nil)
	case bool:
		return ecf.Encode(t)
	case int64:
		return ecf.Encode(t)
	case float64:
		return ecf.Encode(t)
	case string:
		return ecf.Encode(t)
	case []byte:
		return ecf.Encode(t)
	case byteKey:
		// Encountered as a value (rare). Encode as CBOR byte string.
		return ecf.Encode([]byte(t))
	case []interface{}:
		return encodeArrayCanonical(t)
	case map[interface{}]interface{}:
		return encodeMapCanonical(t)
	}
	return nil, fmt.Errorf("encodeCanonical: unsupported type %T", v)
}

func encodeArrayCanonical(arr []interface{}) ([]byte, error) {
	body := bytes.NewBuffer(encodeHeader(4, uint64(len(arr))))
	for i, item := range arr {
		b, err := encodeCanonical(item)
		if err != nil {
			return nil, fmt.Errorf("array[%d]: %w", i, err)
		}
		body.Write(b)
	}
	return body.Bytes(), nil
}

func encodeMapCanonical(m map[interface{}]interface{}) ([]byte, error) {
	type pair struct {
		k, v []byte
	}
	pairs := make([]pair, 0, len(m))
	for k, v := range m {
		kb, err := encodeKey(k)
		if err != nil {
			return nil, fmt.Errorf("map key %#v: %w", k, err)
		}
		vb, err := encodeCanonical(v)
		if err != nil {
			return nil, fmt.Errorf("map value for key %#v: %w", k, err)
		}
		pairs = append(pairs, pair{kb, vb})
	}
	// Canonical sort: byte-wise lexicographic on encoded key bytes.
	sort.Slice(pairs, func(i, j int) bool {
		return bytes.Compare(pairs[i].k, pairs[j].k) < 0
	})
	out := bytes.NewBuffer(encodeHeader(5, uint64(len(pairs))))
	for _, p := range pairs {
		out.Write(p.k)
		out.Write(p.v)
	}
	return out.Bytes(), nil
}

func encodeKey(k interface{}) ([]byte, error) {
	switch t := k.(type) {
	case string:
		return ecf.Encode(t)
	case byteKey:
		return ecf.Encode([]byte(t))
	case int64:
		return ecf.Encode(t)
	case bool:
		return ecf.Encode(t)
	}
	return nil, fmt.Errorf("unsupported map key type %T", k)
}

// encodeHeader emits a CBOR initial-byte + argument bytes for the given
// major type and argument value, picking the shortest argument length
// (RFC 8949 §4.2.1 Rule 1).
func encodeHeader(majorType byte, arg uint64) []byte {
	head := majorType << 5
	switch {
	case arg < 24:
		return []byte{head | byte(arg)}
	case arg < 1<<8:
		return []byte{head | 24, byte(arg)}
	case arg < 1<<16:
		b := []byte{head | 25, 0, 0}
		binary.BigEndian.PutUint16(b[1:], uint16(arg))
		return b
	case arg < 1<<32:
		b := []byte{head | 26, 0, 0, 0, 0}
		binary.BigEndian.PutUint32(b[1:], uint32(arg))
		return b
	default:
		b := []byte{head | 27, 0, 0, 0, 0, 0, 0, 0, 0}
		binary.BigEndian.PutUint64(b[1:], arg)
		return b
	}
}
