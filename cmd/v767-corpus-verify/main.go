// Command v767-corpus-verify decodes the v7.67 agility conformance corpus
// (`conformance-vectors-v1.cbor`) end-to-end and asserts:
//
//   1. File sha256 matches the F16 re-stamp 8e7c5232…f31f982e (or the value
//      supplied via -expected-sha).
//   2. F16 structural invariants on the file's input-side fields:
//        A) every Ed448 secret_seed / pubkey-from-seed input is 57 B (RFC 8032)
//        B) every `experimental-test` public_key is 64 B
//        C) every matrix.*.expected_* field is CBOR bytes, not the literal
//           text "TBD-COHORT-ROUND-TRIP"
//   3. Phase-1 and Phase-2 cryptographic outputs re-derive from the inputs
//      embedded in the corpus and match the corresponding `expected_*` /
//      `canonical*` pins.
//
// This closes the F16 cohort action surfaced by Keystone — "decode the
// artifact, not its sha256" — on the Go side. No impl code change is required;
// the verifier is a pure consumer of the corpus.
//
// Reproduce: `go run ./cmd/v767-corpus-verify`. Add `-path <file>` to point at
// a different corpus copy. Add `-verbose` for a per-vector line.
package main

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"flag"
	"fmt"
	"os"
	"reflect"
	"sort"

	"github.com/cloudflare/circl/sign/ed448"
	"github.com/fxamacker/cbor/v2"

	"go.entitychurch.org/entity-core-go/core/crypto"
	"go.entitychurch.org/entity-core-go/core/ecf"
	"go.entitychurch.org/entity-core-go/core/entity"
	"go.entitychurch.org/entity-core-go/core/hash"
	"go.entitychurch.org/entity-core-go/core/types"
)

const (
	defaultPath = "../entity-core-architecture/docs/architecture/v7.0-core-revision/core-protocol-domain/specs/test-vectors/v767/conformance-vectors-v1.cbor"
	expectedSHA = "8e7c5232f64bee83d628679f930c771e4e49f2f1e37d19e41e0d7838e31f982e"
)

var (
	flagPath        = flag.String("path", defaultPath, "path to conformance-vectors-v1.cbor")
	flagExpectedSHA = flag.String("expected-sha", expectedSHA, "expected file sha256 (hex)")
	flagVerbose     = flag.Bool("verbose", false, "print a line per vector")
)

type checks struct {
	pass, fail int
	verbose    bool
}

func (c *checks) record(id, gate string, ok bool, detail string) {
	if ok {
		c.pass++
		if c.verbose {
			fmt.Printf("  PASS %-50s %s\n", id+"/"+gate, detail)
		}
		return
	}
	c.fail++
	fmt.Printf("  FAIL %-50s %s\n", id+"/"+gate, detail)
}

func main() {
	flag.Parse()

	data, err := os.ReadFile(*flagPath)
	if err != nil {
		die("read corpus: %v", err)
	}
	got := sha256.Sum256(data)
	gotHex := hex.EncodeToString(got[:])
	fmt.Printf("corpus: %s\n", *flagPath)
	fmt.Printf("size:   %d B\n", len(data))
	fmt.Printf("sha256: %s\n", gotHex)
	if gotHex != *flagExpectedSHA {
		die("sha256 mismatch: got %s, want %s", gotHex, *flagExpectedSHA)
	}
	fmt.Printf("        ✓ matches F16 re-stamp\n\n")

	// Decode the corpus as []map[string]any with all nested maps coerced to
	// the same Go type so navigation is m["key"] across the tree.
	dm, err := cbor.DecOptions{
		DefaultMapType: reflect.TypeOf(map[string]any{}),
	}.DecMode()
	if err != nil {
		die("DecMode: %v", err)
	}
	var corpus []map[string]any
	if err := dm.Unmarshal(data, &corpus); err != nil {
		die("decode corpus: %v", err)
	}
	fmt.Printf("decoded %d vectors\n\n", len(corpus))

	c := &checks{verbose: *flagVerbose}

	// Pass 1 — F16 structural invariants on every vector. Walk by id.
	fmt.Println("§1 F16 structural invariants (decode the artifact, not its sha)")
	for _, v := range corpus {
		id := mustStr(v, "id")
		switch id {
		case "key-type-ed448.1.pubkey":
			seed := mustBytes(v, "input")
			c.record(id, "ed448-seed-57B", len(seed) == 57,
				fmt.Sprintf("len=%d", len(seed)))
		case "key-type-ed448.4.signature":
			seed := mustBytes(mustMap(v, "input"), "secret_seed")
			c.record(id, "ed448-seed-57B", len(seed) == 57,
				fmt.Sprintf("len=%d", len(seed)))
		case "hash-format-sha-384.1.inherited_sha256_pin",
			"hash-format-sha-384.2.rehash":
			pub := mustBytes(mustMap(mustMap(v, "input"), "data"), "public_key")
			c.record(id, "exp-test-pubkey-64B", len(pub) == 64,
				fmt.Sprintf("len=%d", len(pub)))
		case "matrix.M2", "matrix.M6":
			seed := mustBytes(mustMap(v, "input_peer_a"), "secret_seed")
			c.record(id, "ed448-seed-57B", len(seed) == 57,
				fmt.Sprintf("len=%d (peer_a)", len(seed)))
			fallthrough
		case "matrix.M3":
			// every matrix.* must have bytes-typed expected_* fields,
			// not the F16 placeholder tstr "TBD-COHORT-ROUND-TRIP".
			for _, k := range sortedKeys(v) {
				if len(k) < 9 || k[:9] != "expected_" {
					continue
				}
				if isMatrixByteField(k) {
					raw, ok := v[k].([]byte)
					detail := fmt.Sprintf("type=%T", v[k])
					if ok {
						detail = fmt.Sprintf("len=%d bytes", len(raw))
					}
					c.record(id, k+"=bytes", ok, detail)
				}
			}
		}
	}
	fmt.Println()

	// Pass 2 — re-derive Phase-1 and Phase-2 crypto outputs from the corpus
	// inputs and compare against the in-file expected pins.
	fmt.Println("§2 Crypto re-derivation (Phase-1 + Phase-2)")
	for _, v := range corpus {
		id := mustStr(v, "id")
		switch id {
		case "key-type-ed448.1.pubkey":
			verifyEd448SeedToPubkey(c, id, v)
		case "key-type-ed448.2.peer_id":
			verifyPeerIDConstruct(c, id, v)
		case "key-type-ed448.3.system_peer_entity":
			verifyEd448PeerEntity(c, id, v)
		case "key-type-ed448.4.signature":
			verifyEd448Signature(c, id, v)
		case "hash-format-sha-384.1.inherited_sha256_pin":
			verifyPeerEntityUnderFormat(c, id, v, 0x00, "canonical_content_hash")
		case "hash-format-sha-384.2.rehash":
			verifyPeerEntityUnderFormat(c, id, v, 0x01, "canonical_content_hash")
		case "matrix.M2":
			verifyMatrix(c, id, v, false /*sha384gate*/)
		case "matrix.M3", "matrix.M6":
			verifyMatrix(c, id, v, true)
		}
	}
	fmt.Println()

	fmt.Printf("=== %d PASS, %d FAIL ===\n", c.pass, c.fail)
	if c.fail > 0 {
		os.Exit(1)
	}
}

// --- structural helpers ---

func isMatrixByteField(k string) bool {
	// Every matrix.* expected_* field that is a byte string in the .diag.
	// Suffix _base58 is the only tstr-typed expected_ field; everything else
	// is bytes.
	if len(k) < 9 || k[:9] != "expected_" {
		return false
	}
	// kludge: matches names ending with one of these tokens.
	tails := []string{"_pubkey", "_content_hash", "_content_hash_sha256",
		"_content_hash_sha384", "_signature"}
	for _, t := range tails {
		if len(k) >= len(t) && k[len(k)-len(t):] == t {
			return true
		}
	}
	return false
}

// --- crypto verifiers ---

func verifyEd448SeedToPubkey(c *checks, id string, v map[string]any) {
	seed := mustBytes(v, "input")
	want := mustBytes(v, "canonical")
	if len(seed) != ed448.SeedSize {
		c.record(id, "pubkey-derive", false, fmt.Sprintf("seed len %d ≠ %d", len(seed), ed448.SeedSize))
		return
	}
	var s [ed448.SeedSize]byte
	copy(s[:], seed)
	kp := crypto.Ed448FromSeed(s)
	got := kp.PublicKeyBytes()
	c.record(id, "pubkey-derive", bytesEq(got, want),
		fmt.Sprintf("derived %s", hex.EncodeToString(got)[:20]+"…"))
}

func verifyPeerIDConstruct(c *checks, id string, v map[string]any) {
	in := mustMap(v, "input")
	pub := mustBytes(in, "public_key")
	kt := mustStr(in, "key_type")
	wantB58 := mustStr(v, "canonical_base58")
	ktByte, ok := crypto.KeyTypeByte(kt)
	if !ok {
		c.record(id, "peer_id", false, fmt.Sprintf("unknown key_type %q", kt))
		return
	}
	pid, err := crypto.PeerIDFromPublicKey(pub, ktByte)
	if err != nil {
		c.record(id, "peer_id", false, fmt.Sprintf("PeerIDFromPublicKey: %v", err))
		return
	}
	c.record(id, "peer_id", string(pid) == wantB58,
		fmt.Sprintf("derived %s", string(pid)))
}

func verifyEd448PeerEntity(c *checks, id string, v map[string]any) {
	in := mustMap(v, "input")
	dataIn := mustMap(in, "data")
	pub := mustBytes(dataIn, "public_key")
	wantCBOR := mustBytes(v, "canonical_data_cbor")
	wantHash := mustBytes(v, "canonical_content_hash")
	var seed [ed448.SeedSize]byte
	copy(seed[:], make([]byte, ed448.SeedSize))
	for i := range seed {
		seed[i] = 0x42
	}
	kp := crypto.Ed448FromSeed(seed)
	if !bytesEq(kp.PublicKeyBytes(), pub) {
		c.record(id, "entity-cbor", false, "derived pubkey ≠ input.data.public_key")
		return
	}
	ent, err := kp.IdentityEntityFormat(0x00)
	if err != nil {
		c.record(id, "entity-cbor", false, fmt.Sprintf("IdentityEntityFormat: %v", err))
		return
	}
	c.record(id, "entity-cbor", bytesEq(ent.Data, wantCBOR),
		fmt.Sprintf("len=%d", len(ent.Data)))
	c.record(id, "entity-content-hash", bytesEq(ent.ContentHash.Bytes(), wantHash),
		fmt.Sprintf("%s", hex.EncodeToString(ent.ContentHash.Bytes())[:20]+"…"))
}

func verifyEd448Signature(c *checks, id string, v map[string]any) {
	in := mustMap(v, "input")
	seed := mustBytes(in, "secret_seed")
	msg := mustBytes(in, "message")
	want := mustBytes(v, "canonical")
	var s [ed448.SeedSize]byte
	copy(s[:], seed)
	kp := crypto.Ed448FromSeed(s)
	sig := kp.Sign(msg)
	c.record(id, "ed448-sign", bytesEq(sig, want),
		fmt.Sprintf("siglen=%d", len(sig)))
}

func verifyPeerEntityUnderFormat(c *checks, id string, v map[string]any, alg byte, wantKey string) {
	in := mustMap(v, "input")
	dataIn := mustMap(in, "data")
	pub := mustBytes(dataIn, "public_key")
	kt := mustStr(dataIn, "key_type")
	want := mustBytes(v, wantKey)

	// Author the system/peer entity directly under the requested format using
	// the same ECF encoding path the protocol uses on the wire.
	peerData := types.PeerData{
		KeyType:   kt,
		PublicKey: pub,
	}
	dataCBOR, err := ecf.Encode(peerData)
	if err != nil {
		c.record(id, "content_hash", false, fmt.Sprintf("ecf.Encode: %v", err))
		return
	}
	ent, err := entity.NewEntityFormat(alg, types.TypePeer, dataCBOR)
	if err != nil {
		c.record(id, "content_hash", false, fmt.Sprintf("NewEntityFormat: %v", err))
		return
	}
	c.record(id, fmt.Sprintf("content_hash(alg=0x%02x)", alg),
		bytesEq(ent.ContentHash.Bytes(), want),
		fmt.Sprintf("%s", hex.EncodeToString(ent.ContentHash.Bytes())[:20]+"…"))
}

func verifyMatrix(c *checks, id string, v map[string]any, sha384gate bool) {
	a := mustMap(v, "input_peer_a")
	b := mustMap(v, "input_peer_b")
	keyA := keyFromInput(a)
	keyB := keyFromInput(b)
	homeA := byte(mustU64(a, "home_content_hash_format"))
	homeB := byte(mustU64(b, "home_content_hash_format"))
	active := byte(mustU64(v, "negotiated_active_format"))

	// Peer A side
	if want, ok := v["expected_peer_a_pubkey"].([]byte); ok {
		c.record(id, "peer_a.pubkey", bytesEq(keyA.PublicKeyBytes(), want),
			fmt.Sprintf("len=%d", len(keyA.PublicKeyBytes())))
	}
	pidA, err := crypto.PeerIDFromPublicKey(keyA.PublicKeyBytes(), keyA.KeyType)
	if err != nil {
		c.record(id, "peer_a.peer_id", false, err.Error())
	} else if want := mustStr(v, "expected_peer_a_peer_id_base58"); true {
		c.record(id, "peer_a.peer_id", string(pidA) == want,
			fmt.Sprintf("derived %s", string(pidA)))
	}
	entA, err := keyA.IdentityEntityFormat(homeA)
	if err != nil {
		c.record(id, "peer_a.content_hash", false, err.Error())
	} else {
		key := "expected_peer_a_content_hash"
		if sha384gate {
			key = "expected_peer_a_content_hash_sha384"
		}
		if want, ok := v[key].([]byte); ok {
			c.record(id, "peer_a.content_hash["+key+"]",
				bytesEq(entA.ContentHash.Bytes(), want),
				fmt.Sprintf("len=%d", len(entA.ContentHash.Bytes())))
		}
	}

	// Peer B side
	if want, ok := v["expected_peer_b_pubkey"].([]byte); ok {
		c.record(id, "peer_b.pubkey", bytesEq(keyB.PublicKeyBytes(), want),
			fmt.Sprintf("len=%d", len(keyB.PublicKeyBytes())))
	}
	pidB, err := crypto.PeerIDFromPublicKey(keyB.PublicKeyBytes(), keyB.KeyType)
	if err != nil {
		c.record(id, "peer_b.peer_id", false, err.Error())
	} else if want := mustStr(v, "expected_peer_b_peer_id_base58"); true {
		c.record(id, "peer_b.peer_id", string(pidB) == want,
			fmt.Sprintf("derived %s", string(pidB)))
	}
	entB, err := keyB.IdentityEntityFormat(homeB)
	if err != nil {
		c.record(id, "peer_b.content_hash", false, err.Error())
		return
	}
	keyBHash := "expected_peer_b_content_hash"
	if sha384gate {
		keyBHash = "expected_peer_b_content_hash_sha256" // M3/M6: B home = SHA-256
	}
	if want, ok := v[keyBHash].([]byte); ok {
		c.record(id, "peer_b.content_hash["+keyBHash+"]",
			bytesEq(entB.ContentHash.Bytes(), want),
			fmt.Sprintf("len=%d", len(entB.ContentHash.Bytes())))
	}

	// Cap-token under ACTIVE format
	zero := uint64(0)
	tokenData := types.CapabilityTokenData{
		Grants: []types.GrantEntry{
			{
				Resources: types.CapabilityScope{
					Include: []string{"system/validate/matrix/*"},
				},
			},
		},
		Granter:   types.SingleSigGranter(mustHash(entA.ContentHash.Bytes())),
		Grantee:   mustHash(entB.ContentHash.Bytes()),
		Parent:    nil,
		CreatedAt: 0,
		ExpiresAt: &zero,
	}
	dataCBOR, err := ecf.Encode(tokenData)
	if err != nil {
		c.record(id, "cap.cbor", false, err.Error())
		return
	}
	capEnt, err := entity.NewEntityFormat(active, types.TypeCapToken, dataCBOR)
	if err != nil {
		c.record(id, "cap.entity", false, err.Error())
		return
	}
	if want, ok := v["expected_root_cap_content_hash"].([]byte); ok {
		c.record(id, "root_cap.content_hash",
			bytesEq(capEnt.ContentHash.Bytes(), want),
			fmt.Sprintf("%s", hex.EncodeToString(capEnt.ContentHash.Bytes())[:20]+"…"))
	}
	sig := keyA.Sign(capEnt.ContentHash.Bytes())
	if want, ok := v["expected_root_cap_signature"].([]byte); ok {
		c.record(id, "root_cap.signature", bytesEq(sig, want),
			fmt.Sprintf("len=%d", len(sig)))
	}
}

func keyFromInput(m map[string]any) crypto.Keypair {
	kt := mustStr(m, "key_type")
	seed := mustBytes(m, "secret_seed")
	switch kt {
	case "ed25519":
		if len(seed) != ed25519.SeedSize {
			die("ed25519 seed wrong len %d", len(seed))
		}
		var s [ed25519.SeedSize]byte
		copy(s[:], seed)
		return crypto.FromSeed(s)
	case "ed448":
		if len(seed) != ed448.SeedSize {
			die("ed448 seed wrong len %d", len(seed))
		}
		var s [ed448.SeedSize]byte
		copy(s[:], seed)
		return crypto.Ed448FromSeed(s)
	default:
		die("unsupported key_type %q", kt)
	}
	return crypto.Keypair{}
}

// --- nav helpers ---

func mustMap(m map[string]any, k string) map[string]any {
	v, ok := m[k]
	if !ok {
		die("missing field %q", k)
	}
	mm, ok := v.(map[string]any)
	if !ok {
		die("field %q: want map, got %T", k, v)
	}
	return mm
}

func mustBytes(m map[string]any, k string) []byte {
	v, ok := m[k]
	if !ok {
		die("missing field %q", k)
	}
	b, ok := v.([]byte)
	if !ok {
		die("field %q: want bytes, got %T (value %v)", k, v, v)
	}
	return b
}

func mustStr(m map[string]any, k string) string {
	v, ok := m[k]
	if !ok {
		die("missing field %q", k)
	}
	s, ok := v.(string)
	if !ok {
		die("field %q: want string, got %T", k, v)
	}
	return s
}

func mustU64(m map[string]any, k string) uint64 {
	v, ok := m[k]
	if !ok {
		die("missing field %q", k)
	}
	switch x := v.(type) {
	case uint64:
		return x
	case int64:
		return uint64(x)
	case uint:
		return uint64(x)
	default:
		die("field %q: want uint, got %T", k, v)
		return 0
	}
}

func sortedKeys(m map[string]any) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func bytesEq(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func mustHash(raw []byte) hash.Hash {
	h, err := hash.FromBytes(raw)
	if err != nil {
		die("hash.FromBytes: %v", err)
	}
	return h
}

func die(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "v767-corpus-verify: "+format+"\n", args...)
	os.Exit(1)
}
