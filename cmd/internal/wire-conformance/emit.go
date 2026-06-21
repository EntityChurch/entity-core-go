package main

// emit-canonical: produce the per-impl emission file per
// GUIDE-CONFORMANCE §3.1.
//
//   emission = {
//     "impl":           tstr,
//     "impl_version":   tstr,
//     "corpus_version": tstr,
//     "spec_version":   tstr,
//     "encode_results": { tstr → bstr }
//     "decode_results": { tstr → bool }
//     "errors":         { tstr → tstr }
//   }
//
// Vector dispatch by id prefix:
//
//   Class A (re-encode through canonical encoder):
//     float.* int.* map_keys.* length.* primitive.* nested.*
//
//   Class B (protocol-surface construction):
//     content_hash.*  varint(format_code) || SHA256(ECF({type,data}))
//     peer_id.*       ECF(text-string(Base58(varint(kt) || varint(ht) || digest)))
//     signature.*     RFC 8032 Ed25519 sign over canonical-ECF entity bytes
//     envelope.*      re-encode the envelope shape
//
//   decode_reject vectors: feed canonical bytes to a strict ECF decoder
//   (tags forbidden, indefinite-length forbidden). True iff the decoder
//   rejected.

import (
	"crypto/ed25519"
	"crypto/sha256"
	"fmt"
	"os"
	"sort"
	"strings"

	"go.entitychurch.org/entity-core-go/core/ecf"

	"github.com/fxamacker/cbor/v2"
	"github.com/mr-tron/base58"
)

const (
	corpusVersion = "v1"
	specVersion   = "1.5"
	implName      = "core-go"
)

type emission struct {
	Impl           string                 `cbor:"impl"`
	ImplVersion    string                 `cbor:"impl_version"`
	CorpusVersion  string                 `cbor:"corpus_version"`
	SpecVersion    string                 `cbor:"spec_version"`
	EncodeResults  map[string][]byte      `cbor:"encode_results"`
	DecodeResults  map[string]bool        `cbor:"decode_results"`
	DecodeCodes    map[string]string      `cbor:"decode_codes"`
	Errors         map[string]string      `cbor:"errors"`
}

func runEmitCanonical(args []string) error {
	var inPath, outPath, implVersion string
	implVersion = "unspecified"
	if err := parseFlags("emit-canonical", args, map[string]*string{
		"input":        &inPath,
		"out":          &outPath,
		"impl-version": &implVersion,
	}); err != nil {
		return err
	}
	if inPath == "" || outPath == "" {
		return fmt.Errorf("emit-canonical: --input and --out are required")
	}

	corpusBytes, err := os.ReadFile(inPath)
	if err != nil {
		return fmt.Errorf("read corpus: %w", err)
	}

	vectors, err := loadCorpus(corpusBytes)
	if err != nil {
		return fmt.Errorf("load corpus: %w", err)
	}

	em := emission{
		Impl:          implName,
		ImplVersion:   implVersion,
		CorpusVersion: corpusVersion,
		SpecVersion:   specVersion,
		EncodeResults: map[string][]byte{},
		DecodeResults: map[string]bool{},
		DecodeCodes:   map[string]string{},
		Errors:        map[string]string{},
	}

	for _, v := range vectors {
		switch v.Kind {
		case "encode_equal":
			b, err := encodeVector(v)
			if err != nil {
				em.Errors[v.ID] = err.Error()
				continue
			}
			em.EncodeResults[v.ID] = b
		case "decode_reject":
			rejected, code, errMsg := decodeReject(v.Canonical)
			em.DecodeResults[v.ID] = rejected
			if rejected {
				em.DecodeCodes[v.ID] = code
			}
			if errMsg != "" && !rejected {
				em.Errors[v.ID] = errMsg
			}
		default:
			em.Errors[v.ID] = fmt.Sprintf("unknown kind: %q", v.Kind)
		}
	}

	out, err := ecf.Encode(em)
	if err != nil {
		return fmt.Errorf("encode emission: %w", err)
	}
	if err := os.WriteFile(outPath, out, 0644); err != nil {
		return fmt.Errorf("write emission: %w", err)
	}

	encodeIDs := sortedKeys(em.EncodeResults)
	decodeIDs := sortedKeys(em.DecodeResults)
	errorIDs := sortedKeys(em.Errors)
	fmt.Printf("emit-canonical: wrote %s (%d bytes)\n", outPath, len(out))
	fmt.Printf("  encode_results: %d vectors\n", len(encodeIDs))
	fmt.Printf("  decode_results: %d vectors\n", len(decodeIDs))
	fmt.Printf("  decode_codes:   %d vectors\n", len(em.DecodeCodes))
	fmt.Printf("  errors:         %d vectors\n", len(errorIDs))
	if len(errorIDs) > 0 {
		fmt.Printf("  errored ids: %s\n", strings.Join(errorIDs, ", "))
	}
	return nil
}

// rawVector is a vector as loaded from the corpus, with Input preserved as
// its raw CBOR bytes so we can re-decode into our value tree.
type rawVector struct {
	ID          string          `cbor:"id"`
	Description string          `cbor:"description"`
	Kind        string          `cbor:"kind"`
	Input       cbor.RawMessage `cbor:"input"`
	Canonical   []byte          `cbor:"canonical"`
}

func loadCorpus(data []byte) ([]rawVector, error) {
	dec, err := cbor.DecOptions{
		// Allow byte-string keys to come through as cbor.ByteString (the lib
		// default) so we can dispatch on key type in normalizeDecoded.
	}.DecMode()
	if err != nil {
		return nil, err
	}
	var arr []rawVector
	if err := dec.Unmarshal(data, &arr); err != nil {
		return nil, err
	}
	return arr, nil
}

func encodeVector(v rawVector) ([]byte, error) {
	id := v.ID
	switch {
	case strings.HasPrefix(id, "content_hash."):
		return emitContentHash(v)
	case strings.HasPrefix(id, "peer_id."):
		return emitPeerID(v)
	case strings.HasPrefix(id, "signature."):
		return emitSignature(v)
	case strings.HasPrefix(id, "envelope."):
		return emitEnvelope(v)
	default:
		return emitClassA(v)
	}
}

func emitClassA(v rawVector) ([]byte, error) {
	val, err := decodeInputToValueTree(v.Input)
	if err != nil {
		return nil, fmt.Errorf("decode input: %w", err)
	}
	return encodeCanonical(val)
}

func emitContentHash(v rawVector) ([]byte, error) {
	val, err := decodeInputToValueTree(v.Input)
	if err != nil {
		return nil, fmt.Errorf("decode input: %w", err)
	}
	m, ok := val.(map[interface{}]interface{})
	if !ok {
		return nil, fmt.Errorf("content_hash input must be a map, got %T", val)
	}
	typ, ok := m["type"].(string)
	if !ok {
		return nil, fmt.Errorf("content_hash input missing 'type'")
	}
	data, ok := m["data"]
	if !ok {
		return nil, fmt.Errorf("content_hash input missing 'data'")
	}
	formatCode := int64(0)
	if fc, ok := m["format_code"]; ok {
		fcInt, ok := fc.(int64)
		if !ok {
			return nil, fmt.Errorf("content_hash format_code must be int, got %T", fc)
		}
		formatCode = fcInt
	}
	if formatCode < 0 {
		return nil, fmt.Errorf("content_hash format_code must be >= 0")
	}
	// ECF({type, data}) — keys sort to {data, type}.
	hashInput := map[interface{}]interface{}{
		"type": typ,
		"data": data,
	}
	encoded, err := encodeCanonical(hashInput)
	if err != nil {
		return nil, fmt.Errorf("encode hash input: %w", err)
	}
	digest := sha256.Sum256(encoded)
	out := append(varintLEB128(uint64(formatCode)), digest[:]...)
	return out, nil
}

func emitPeerID(v rawVector) ([]byte, error) {
	val, err := decodeInputToValueTree(v.Input)
	if err != nil {
		return nil, fmt.Errorf("decode input: %w", err)
	}
	m, ok := val.(map[interface{}]interface{})
	if !ok {
		return nil, fmt.Errorf("peer_id input must be a map, got %T", val)
	}
	kt, err := mapInt(m, "key_type")
	if err != nil {
		return nil, err
	}
	ht, err := mapInt(m, "hash_type")
	if err != nil {
		return nil, err
	}
	digest, err := mapBytes(m, "digest")
	if err != nil {
		return nil, err
	}
	if kt < 0 || ht < 0 {
		return nil, fmt.Errorf("peer_id codes must be >= 0")
	}
	prefix := append(varintLEB128(uint64(kt)), varintLEB128(uint64(ht))...)
	raw := append(prefix, digest...)
	enc := base58.Encode(raw)
	// Canonical = ECF text-string encoding of the base58 string.
	return encodeCanonical(enc)
}

func emitSignature(v rawVector) ([]byte, error) {
	val, err := decodeInputToValueTree(v.Input)
	if err != nil {
		return nil, fmt.Errorf("decode input: %w", err)
	}
	m, ok := val.(map[interface{}]interface{})
	if !ok {
		return nil, fmt.Errorf("signature input must be a map, got %T", val)
	}
	seed, err := mapBytes(m, "seed")
	if err != nil {
		return nil, err
	}
	if len(seed) != ed25519.SeedSize {
		return nil, fmt.Errorf("signature seed must be %d bytes, got %d", ed25519.SeedSize, len(seed))
	}
	entityVal, ok := m["entity"]
	if !ok {
		return nil, fmt.Errorf("signature input missing 'entity'")
	}
	entityBytes, err := encodeCanonical(entityVal)
	if err != nil {
		return nil, fmt.Errorf("encode entity: %w", err)
	}
	priv := ed25519.NewKeyFromSeed(seed)
	sig := ed25519.Sign(priv, entityBytes)
	return sig, nil
}

func emitEnvelope(v rawVector) ([]byte, error) {
	val, err := decodeInputToValueTree(v.Input)
	if err != nil {
		return nil, fmt.Errorf("decode input: %w", err)
	}
	return encodeCanonical(val)
}

// decodeInputToValueTree round-trips a corpus input field (raw CBOR bytes
// produced by build-fixture) into the same value-tree shape encodeCanonical
// expects (string / int64 / float64 / []byte / bool / nil; map keys as
// string for tstr or byteKey for bstr).
func decodeInputToValueTree(raw cbor.RawMessage) (interface{}, error) {
	if len(raw) == 0 {
		return nil, fmt.Errorf("empty input")
	}
	dec, err := cbor.DecOptions{}.DecMode()
	if err != nil {
		return nil, err
	}
	var v interface{}
	if err := dec.Unmarshal(raw, &v); err != nil {
		return nil, err
	}
	return normalizeDecoded(v), nil
}

func normalizeDecoded(v interface{}) interface{} {
	switch t := v.(type) {
	case nil:
		return nil
	case bool:
		return t
	case uint64:
		// All v1 corpus uints fit in int64 (max int.10 = MaxInt64).
		return int64(t)
	case int64:
		return t
	case float64:
		return t
	case string:
		return t
	case []byte:
		return t
	case cbor.ByteString:
		// Byte-string in value position (not common; mainly map keys come back
		// here). Coerce to []byte so encodeCanonical emits bstr.
		return []byte(t)
	case []interface{}:
		out := make([]interface{}, len(t))
		for i, e := range t {
			out[i] = normalizeDecoded(e)
		}
		return out
	case map[interface{}]interface{}:
		out := make(map[interface{}]interface{}, len(t))
		for k, val := range t {
			var nk interface{}
			switch tk := k.(type) {
			case cbor.ByteString:
				nk = byteKey(string(tk))
			case string:
				nk = tk
			case uint64:
				nk = int64(tk)
			case int64:
				nk = tk
			case bool:
				nk = tk
			default:
				nk = tk
			}
			out[nk] = normalizeDecoded(val)
		}
		return out
	}
	return v
}

// varintLEB128 encodes a value as a multicodec-style LEB128 varint
// (V7 §7.3): codes 0–127 are a single byte with the high bit clear;
// codes ≥128 emit continuation bytes (high bit set on every byte except
// the last).
func varintLEB128(v uint64) []byte {
	if v < 0x80 {
		return []byte{byte(v)}
	}
	var out []byte
	for v >= 0x80 {
		out = append(out, byte(v&0x7f)|0x80)
		v >>= 7
	}
	out = append(out, byte(v))
	return out
}

func mapInt(m map[interface{}]interface{}, key string) (int64, error) {
	v, ok := m[key]
	if !ok {
		return 0, fmt.Errorf("missing %q", key)
	}
	switch t := v.(type) {
	case int64:
		return t, nil
	case uint64:
		if t > 1<<63-1 {
			return 0, fmt.Errorf("%q overflows int64", key)
		}
		return int64(t), nil
	}
	return 0, fmt.Errorf("%q must be integer, got %T", key, v)
}

func mapBytes(m map[interface{}]interface{}, key string) ([]byte, error) {
	v, ok := m[key]
	if !ok {
		return nil, fmt.Errorf("missing %q", key)
	}
	switch t := v.(type) {
	case []byte:
		return t, nil
	case cbor.ByteString:
		return []byte(t), nil
	}
	return nil, fmt.Errorf("%q must be byte string, got %T", key, v)
}

func sortedKeys[V any](m map[string]V) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
