package entity

import (
	"encoding/hex"
	"fmt"
	"strings"

	"go.entitychurch.org/entity-core-go/core/ecf"
	ecerrors "go.entitychurch.org/entity-core-go/core/errors"
	"go.entitychurch.org/entity-core-go/core/hash"

	"github.com/fxamacker/cbor/v2"
)

// Entity is a typed data unit with a content hash.
// The Data field is cbor.RawMessage to preserve byte fidelity for hash verification.
type Entity struct {
	Type        string          `cbor:"type"`
	Data        cbor.RawMessage `cbor:"data"`
	ContentHash hash.Hash       `cbor:"content_hash"`
}

// defaultHashAlgorithm is the content_hash_format code used by NewEntity
// when no per-call algorithm is given. Process-global because every peer
// runs as one process with one configured authoring format; the receive
// path always dispatches per-hash via the claimed Algorithm byte and is
// not affected by this setting.
//
// V7.67 §4 supported formats: 0x00 ECFv1-SHA-256, 0x01 ECFv1-SHA-384.
// The default tracks v7.66 behavior (SHA-256) until SetDefaultHashAlgorithm
// is called — typically from an entity-peer CLI flag (--hash-type).
var defaultHashAlgorithm = hash.AlgorithmSHA256

// SetDefaultHashAlgorithm shifts the authoring algorithm read by NewEntity.
// Intended to be called once during process startup (e.g., from a peer's
// CLI flag parsing). Concurrent callers reading via NewEntity see a
// consistent byte; no lock is necessary because the value is set before
// any peer goroutines start authoring.
func SetDefaultHashAlgorithm(alg byte) {
	defaultHashAlgorithm = alg
}

// DefaultHashAlgorithm returns the current authoring algorithm.
func DefaultHashAlgorithm() byte {
	return defaultHashAlgorithm
}

// NewEntity creates an entity with the given type and data, computing its
// content hash under the configured default format (process-global,
// settable via SetDefaultHashAlgorithm; SHA-256 if unset).
func NewEntity(entityType string, data cbor.RawMessage) (Entity, error) {
	return NewEntityFormat(defaultHashAlgorithm, entityType, data)
}

// NewEntityFormat creates an entity with the given type and data, computing
// its content hash under the requested content_hash_format code (v7.67 §4).
// Supported formats: 0x00 ECFv1-SHA-256, 0x01 ECFv1-SHA-384.
func NewEntityFormat(alg byte, entityType string, data cbor.RawMessage) (Entity, error) {
	if entityType == "" {
		return Entity{}, fmt.Errorf("%w: type is empty", ecerrors.ErrInvalidEntity)
	}
	if len(data) == 0 {
		return Entity{}, fmt.Errorf("%w: data is empty", ecerrors.ErrInvalidEntity)
	}

	h, err := hash.ComputeFormat(alg, entityType, data)
	if err != nil {
		return Entity{}, err
	}

	return Entity{
		Type:        entityType,
		Data:        data,
		ContentHash: h,
	}, nil
}

// Validate recomputes the content hash and checks it against ContentHash.
func (e Entity) Validate() error {
	if e.Type == "" {
		return fmt.Errorf("%w: type is empty", ecerrors.ErrInvalidEntity)
	}
	if len(e.Data) == 0 {
		return fmt.Errorf("%w: data is empty", ecerrors.ErrInvalidEntity)
	}
	if err := hash.Validate(e.Type, e.Data, e.ContentHash); err != nil {
		return fmt.Errorf("entity %q (hash %s): %w", e.Type, e.ContentHash, err)
	}
	return nil
}

// ValidateHash is an alias for Validate.
func (e Entity) ValidateHash() error {
	return e.Validate()
}

// DiagnoseHash returns a multi-line diagnostic string showing the entity's
// type, decoded data fields, claimed hash, recomputed hash, and ECF hash input.
// Useful for debugging cross-implementation hash mismatches.
func (e Entity) DiagnoseHash() string {
	var b strings.Builder
	fmt.Fprintf(&b, "  type:         %q\n", e.Type)
	fmt.Fprintf(&b, "  claimed_hash: %s\n", e.ContentHash)

	// Decode and print data fields.
	fmt.Fprintf(&b, "  data (%d bytes):\n", len(e.Data))
	var dataMap interface{}
	if err := ecf.Decode(e.Data, &dataMap); err != nil {
		fmt.Fprintf(&b, "    (decode error: %v)\n", err)
		fmt.Fprintf(&b, "    raw: %s\n", hex.EncodeToString(e.Data))
	} else {
		FormatCBORValue(&b, "    ", dataMap)
	}

	computed, err := hash.ComputeFormat(e.ContentHash.Algorithm, e.Type, e.Data)
	if err != nil {
		fmt.Fprintf(&b, "  recompute:    ERROR: %v\n", err)
		return b.String()
	}
	fmt.Fprintf(&b, "  recomputed:   %s\n", computed)

	if computed == e.ContentHash {
		fmt.Fprintf(&b, "  result:       OK\n")
	} else {
		fmt.Fprintf(&b, "  result:       MISMATCH\n")
		fmt.Fprintf(&b, "  data_hex:     %s\n", hex.EncodeToString(e.Data))
		hashInput, err := ecf.EncodeHashable(e.Type, e.Data)
		if err != nil {
			fmt.Fprintf(&b, "  hash_input:   ERROR: %v\n", err)
		} else {
			fmt.Fprintf(&b, "  hash_input (%d bytes):\n    %s\n", len(hashInput), hex.EncodeToString(hashInput))
		}
	}
	return b.String()
}

// FormatCBORValue writes a human-readable representation of a decoded CBOR value
// with the given indent prefix. Handles maps, arrays, byte strings, hashes, etc.
func FormatCBORValue(b *strings.Builder, indent string, v interface{}) {
	switch val := v.(type) {
	case map[interface{}]interface{}:
		fmt.Fprintf(b, "%s{\n", indent)
		for k, v := range val {
			fmt.Fprintf(b, "%s  %v: ", indent, k)
			FormatInlineValue(b, v)
			fmt.Fprintf(b, "\n")
		}
		fmt.Fprintf(b, "%s}\n", indent)
	default:
		fmt.Fprintf(b, "%s%v\n", indent, FormatSingleValue(v))
	}
}

// FormatInlineValue writes a CBOR value inline (no leading indent, no trailing newline).
func FormatInlineValue(b *strings.Builder, v interface{}) {
	switch val := v.(type) {
	case nil:
		fmt.Fprint(b, "null")
	case []byte:
		if len(val) == 33 && val[0] == 0x00 {
			fmt.Fprintf(b, "hash(ecf-sha256:%s)", hex.EncodeToString(val[1:]))
		} else {
			fmt.Fprintf(b, "bytes(%d):%s", len(val), hex.EncodeToString(val))
		}
	case map[interface{}]interface{}:
		fmt.Fprint(b, "{")
		first := true
		for k, v := range val {
			if !first {
				fmt.Fprint(b, ", ")
			}
			fmt.Fprintf(b, "%v: ", k)
			FormatInlineValue(b, v)
			first = false
		}
		fmt.Fprint(b, "}")
	case []interface{}:
		fmt.Fprint(b, "[")
		for i, item := range val {
			if i > 0 {
				fmt.Fprint(b, ", ")
			}
			FormatInlineValue(b, item)
		}
		fmt.Fprint(b, "]")
	default:
		fmt.Fprint(b, FormatSingleValue(v))
	}
}

// FormatSingleValue returns a string representation of a single CBOR value.
func FormatSingleValue(v interface{}) string {
	switch val := v.(type) {
	case nil:
		return "null"
	case []byte:
		if len(val) == 33 && val[0] == 0x00 {
			return fmt.Sprintf("hash(ecf-sha256:%s)", hex.EncodeToString(val[1:]))
		}
		return fmt.Sprintf("bytes(%d):%s", len(val), hex.EncodeToString(val))
	case string:
		return fmt.Sprintf("%q", val)
	default:
		return fmt.Sprintf("%v", val)
	}
}
