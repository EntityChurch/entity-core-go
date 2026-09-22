// Command agility-corpus-verify decodes the v7.67 agility conformance corpus
// (`conformance-vectors-v1.cbor`) end-to-end and asserts:
//
//  1. File sha256 matches the F16 re-stamp 8e7c5232…f31f982e (or the value
//     supplied via -expected-sha).
//  2. F16 structural invariants on the file's input-side fields:
//     A) every Ed448 secret_seed / pubkey-from-seed input is 57 B (RFC 8032)
//     B) every `experimental-test` public_key is 64 B
//     C) every matrix.*.expected_* field is CBOR bytes, not the literal
//     text "TBD-COHORT-ROUND-TRIP"
//  3. Phase-1 and Phase-2 cryptographic outputs re-derive from the inputs
//     embedded in the corpus and match the corresponding `expected_*` /
//     `canonical*` pins.
//
// This closes the F16 cohort action surfaced by Keystone — "decode the
// artifact, not its sha256" — on the Go side. No impl code change is required;
// the verifier is a pure consumer of the corpus.
//
// Reproduce: `go run ./cmd/agility-corpus-verify`. Add `-path <file>` to point at
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

	"go.entitychurch.org/entity-core-go/cmd/internal/corpus"
	"go.entitychurch.org/entity-core-go/core/crypto"
	"go.entitychurch.org/entity-core-go/core/ecf"
	"go.entitychurch.org/entity-core-go/core/entity"
	"go.entitychurch.org/entity-core-go/core/hash"
	"go.entitychurch.org/entity-core-go/core/types"
)

const (
	// LANDED 2026-08-11. The v767 corpus missed the V8 split and sat in the
	// pre-V8 architecture repo, which is archived and not part of the
	// active working set; it now lives beside its
	// two siblings (`ecf-conformance`, `crypto-agility`) in
	// entity-core-protocol/specs/test-vectors/ — core-protocol `56d4de4`,
	// copied verbatim, legacy tree untouched.
	//
	// THE PIN IS UNCHANGED AND THAT IS THE POINT: the bytes are identical, so
	// expectedSHA still verifies at the new location. Re-computed here, not
	// taken on report — `sha256sum` at the landed path returns
	// 8e7c5232…e31f982e. Path changed; pin did not.
	//
	// RE-STAMP STATUS [2026-08-12, read live in every tree named]. The round
	// trip is at SEEDS.md §5 step 4, and step 4 is architecture's.
	//
	//   step 2 (Go)          DONE — six derived expectations, one root cause,
	//                        routed to arch 2026-08-11 as the v767 M3/M6
	//                        re-stamp proposal
	//   step 3 (rust + py)   DONE, 3-of-3 byte-equal — py re-derived all six
	//                        independently at entity-core-py da5e820 (`test(v767):
	//                        re-derive M3/M6 under §4.5a item 1a — byte-equal to
	//                        go's re-stamp`); rust matched at entity-core-rust
	//                        21eb223.
	//   step 4 (arch)        OWED. entity-core-protocol HEAD is 3042bd8 and its
	//                        two commits today (213a2ac, 3042bd8) touched
	//                        SEEDS.md prose ONLY — `git show --stat` on both,
	//                        one file each. conformance-vectors-v1.cbor is
	//                        unchanged: same 9236 B, same sha256 as the pin
	//                        below, mtime 08-11. So the six M3/M6 assertions
	//                        are still red HERE, and this tool is still NOT
	//                        wireable into validate-complete.sh (never
	//                        hand-edit a red run green). That is A-3's real
	//                        blocker; "unblocked" described step 3, not this.
	//
	// The re-stamp WILL change expectedSHA, and it MUST land in both copies
	// together — `crypto-agility/agility-vectors-v1.cbor` is byte-identical
	// today (arch ruled 3042bd8: identical .cbor is the standing invariant, and
	// re-stamping one copy is what would CREATE the divergence).
	//
	// OUR HALF OF THE OTHER RULING IS DONE. Arch also ruled
	// `hash-format-sha-384.2.rehash` INVERTED rather than retargeted — it
	// asserts a system/peer under content_hash_format = 0x01 that §4.5a item 1a
	// forbids, and stayed green only because this verifier built the entity by
	// hand and bypassed the pinned constructor. The verifier now asserts the
	// refusal instead (verifyIdentityUnderNonFloorRefused), goes through the
	// pinned constructor for the floor vector, and the bypass is closed at the
	// constructor itself so it cannot recur (core/entity.NewEntityFormat).
	// That assertion needs no field the re-stamp has yet to land, so it is
	// green today; the vector's residual 0x01 pin is reported as a NOTE.
	defaultPath = "../entity-core-protocol/specs/test-vectors/crypto-agility/agility-vectors.cbor"

	// MOVED 2026-08-12 — A-3 closed. Both blockers landed at core-protocol
	// `8d38e62` (the F16 sweep-back into both sources, and the M3/M6
	// description reconciliation), so `agility-corpus-build -both` ran for the
	// first time and produced this digest from BOTH sources, byte-identical.
	//
	// 8e7c5232…e31f982e was the June artifact, and it is not gone: it remains
	// the encoder's pinned self-check. `agility-corpus-build -verify-legacy`
	// re-encodes the `.diag` frozen at core-protocol `56d4de4` (with the six
	// F16 input-width corrections applied) and asserts it reproduces
	// 8e7c5232… exactly. That pair is FROZEN on purpose: it is the only
	// evidence that this encoder reproduces bytes it did not itself author,
	// and it must not be re-pinned to a moving source. Re-verified green in
	// the same run that produced the digest below.
	// THE VALUE ITSELF LIVES IN `cmd/internal/corpus`, not here. It used to be
	// a literal in this file, which made it a second home for a fact the corpus
	// registry also had to know — and a pin that exists in two places is a pin
	// that will eventually exist at two values. `expectedSHA()` reads the
	// registry; re-pinning happens there, once, for every tool.
)

// expectedSHA is the pinned artifact digest for the crypto-agility corpus,
// read from the single registry rather than restated here.
func expectedSHA() string {
	c, ok := corpus.ByName("crypto-agility")
	if !ok {
		// Unreachable unless the registry entry is renamed out from under this
		// tool — in which case failing loudly beats verifying against "".
		panic("corpus registry has no crypto-agility entry: this verifier cannot pin an artifact it cannot name")
	}
	return c.ExpectedSHA
}

var (
	flagPath        = flag.String("path", defaultPath, "path to the crypto-agility agility-vectors.cbor")
	flagExpectedSHA = flag.String("expected-sha", expectedSHA(), "expected file sha256 (hex)")
	flagVerbose     = flag.Bool("verbose", false, "print a line per vector")
	flagFullHashes  = flag.Bool("full-hashes", false, "print derived hashes in full rather than truncated — required when producing a re-stamp proposal, since a truncated value cannot be ratified")
)

// hx renders a derived value for reporting. Truncated by default to keep
// the summary readable; full under -full-hashes, which is the mode a
// re-stamp proposal has to be written from (arch ratifies literal bytes,
// and "009b78514a0c74a757e6…" is not a value anyone can ratify).
func hx(b []byte) string {
	h := hex.EncodeToString(b)
	if *flagFullHashes || len(h) <= 20 {
		return h
	}
	return h[:20] + "…"
}

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

	for _, v := range corpus {
		byID[mustStr(v, "id")] = v
	}

	c := &checks{verbose: *flagVerbose}

	// Pass 0 — every vector this tool dispatches on by `id` must still make the
	// assertion the dispatch assumes.
	//
	// WHY THIS EXISTS. `hash-format-sha-384.2.rehash` had its `kind` flipped
	// from `content_hash_under_format` to `construct_reject` (arch 4cf0990) —
	// the vector now asserts the OPPOSITE of what it used to. This tool
	// switches on `id` alone, so nothing in it would have noticed: a vector
	// whose meaning inverted underneath a verifier that still recognised its
	// name would have been checked under the old assumption and reported PASS.
	//
	// That is the same defect one level up. The vector certified a forbidden
	// construction because the verifier routed around the constructor; the
	// verifier would keep certifying a retired assertion because it routes
	// around the `kind`. Binding the two means the corpus cannot change what a
	// vector claims without this tool going red and being made to agree.
	fmt.Println("§0 Vector kinds match what this verifier asserts")
	for _, id := range sortedIDs(corpus) {
		want, known := expectedKinds[id]
		if !known {
			continue
		}
		got, _ := byID[id]["kind"].(string)
		c.record(id, "kind="+want, got == want, fmt.Sprintf("kind=%q", got))
	}
	fmt.Println()

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
			verifyIdentityAtFloor(c, id, v, "canonical_content_hash")
		case "hash-format-sha-384.2.rehash":
			verifyIdentityUnderNonFloorRefused(c, id, v)
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
		fmt.Sprintf("derived %s", hx(got)))
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
	ent, err := kp.IdentityEntity()
	if err != nil {
		c.record(id, "entity-cbor", false, fmt.Sprintf("IdentityEntityFormat: %v", err))
		return
	}
	c.record(id, "entity-cbor", bytesEq(ent.Data, wantCBOR),
		fmt.Sprintf("len=%d", len(ent.Data)))
	c.record(id, "entity-content-hash", bytesEq(ent.ContentHash.Bytes(), wantHash),
		hx(ent.ContentHash.Bytes()))
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

// peerDataFromVector reads the {public_key, key_type} pair a
// hash-format-sha-384.* vector carries at input.data.
func peerDataFromVector(v map[string]any) types.PeerData {
	dataIn := mustMap(mustMap(v, "input"), "data")
	return types.PeerData{
		PublicKey: mustBytes(dataIn, "public_key"),
		KeyType:   mustStr(dataIn, "key_type"),
	}
}

// verifyIdentityAtFloor checks the vector's pinned identity hash THROUGH THE
// PINNED CONSTRUCTOR (types.PeerData.ToEntity), not by hand-encoding and
// choosing a format.
//
// The distinction is the whole point and it is not stylistic. This function
// used to be `verifyPeerEntityUnderFormat(alg, …)`, taking the format as a
// parameter and calling entity.NewEntityFormat — which is how it could ALSO
// serve the 0x01 vector below, and therefore how the corpus could assert a
// construction ENTITY-CORE-PROTOCOL §4.5a item 1a forbids and still report
// PASS. A verifier that reaches around the constructor whose rule it is
// testing has no way to observe the rule. Going through the constructor means
// this check now fails if the floor pin is ever loosened, which is the
// behavior a conformance tool is for.
func verifyIdentityAtFloor(c *checks, id string, v map[string]any, wantKey string) {
	want := mustBytes(v, wantKey)
	ent, err := peerDataFromVector(v).ToEntity()
	if err != nil {
		c.record(id, "content_hash(floor)", false, fmt.Sprintf("PeerData.ToEntity: %v", err))
		return
	}
	if ent.ContentHash.Algorithm != hash.AlgorithmSHA256 {
		c.record(id, "content_hash(floor)", false,
			fmt.Sprintf("pinned constructor authored under 0x%02x, want the 0x00 floor", ent.ContentHash.Algorithm))
		return
	}
	c.record(id, "content_hash(floor=0x00)",
		bytesEq(ent.ContentHash.Bytes(), want),
		hx(ent.ContentHash.Bytes()))
}

// verifyIdentityUnderNonFloorRefused is the INVERTED form of
// hash-format-sha-384.2.rehash, per architecture's 2026-08-12 ruling
// (entity-core-protocol 213a2ac, SEEDS.md §5).
//
// The vector as authored asserts a `system/peer` content_hash under
// content_hash_format = 0x01. §4.5a item 1a (v7.77) pins that entity to the
// ECFv1-SHA-256 floor unconditionally, so the vector describes a construction
// the spec forbids — and it stayed green only because this verifier built the
// entity by hand and routed around the constructor that forbids it. Arch ruled
// it INVERTED rather than retargeted: the vector becomes the guard for the rule
// that retired it.
//
// So the assertion is a refusal, and it is checkable against the corpus as it
// stands today — it needs no field the re-stamp has yet to land. The stale
// `canonical_content_hash` the vector still carries is reported as a NOTE
// rather than silently ignored, because a pin that no longer means anything and
// is not mentioned is indistinguishable from one that was checked.
func verifyIdentityUnderNonFloorRefused(c *checks, id string, v map[string]any) {
	pd := peerDataFromVector(v)
	dataCBOR, err := ecf.Encode(pd)
	if err != nil {
		c.record(id, "non-floor-refused", false, fmt.Sprintf("ecf.Encode: %v", err))
		return
	}

	// Route 1 — the EXPLICIT format request. A caller naming 0x01 outright.
	_, err = entity.NewEntityFormat(hash.AlgorithmSHA384, types.TypePeer, dataCBOR)
	c.record(id, "non-floor-refused(0x01)", err != nil, refusalDetail(err))

	// Routes 2 and 3 — the HOME FORMAT, which is the half the vector's
	// `verifier_requirement` is really about and the half this check was
	// missing until 2026-08-13.
	//
	// §4.5a item 1a pins system/peer to the floor *"whatever the peer's home
	// format"*. Everything above runs under the ambient process default, which
	// in this tool is the 0x00 floor — so "the floor still authors" was true
	// for the trivial reason that nothing had asked for anything else. It
	// asserted the home-format clause without ever setting a home format.
	//
	// So set one. Under a 0x01 home format a real peer authoring its own
	// identity takes one of exactly two paths, and 1a has to hold on both:
	// the implicit constructor (NewEntity, which reads the default) must
	// REFUSE, and the pinned peer-entity constructor (PeerData.ToEntity, the
	// one the vector names) must still land on the floor rather than follow
	// the home format it is sitting in.
	prev := entity.DefaultHashAlgorithm()
	entity.SetDefaultHashAlgorithm(hash.AlgorithmSHA384)
	defer entity.SetDefaultHashAlgorithm(prev)

	_, err = entity.NewEntity(types.TypePeer, dataCBOR)
	c.record(id, "non-floor-refused(home=0x01)", err != nil, refusalDetail(err))

	ent, err := pd.ToEntity()
	if err != nil {
		c.record(id, "floor-holds-under-home=0x01", false, fmt.Sprintf("PeerData.ToEntity: %v", err))
		return
	}
	c.record(id, "floor-holds-under-home=0x01",
		ent.ContentHash.Algorithm == hash.AlgorithmSHA256,
		fmt.Sprintf("authored 0x%02x %s", ent.ContentHash.Algorithm, hx(ent.ContentHash.Bytes())))

	// The vector names the floor form it DOES have; check we reproduce it, so
	// the refusal above cannot be satisfied by a constructor that refuses
	// everything. `floor_form` is prose pointing at .1, so the value is read
	// from .1 rather than parsed out of the sentence.
	if want := floorFormFromSibling(id); want != nil {
		c.record(id, "floor-form-matches-.1", bytesEq(ent.ContentHash.Bytes(), want), hx(ent.ContentHash.Bytes()))
	}
}

// expectedKinds pins the assertion each dispatched vector makes. Every id this
// tool switches on in §1/§2 appears here; a vector whose `kind` moves out from
// under its verifier goes red rather than being checked under a retired
// assumption. Vectors the tool does not dispatch on (the `decode_reject`
// family, checked elsewhere) are deliberately absent — this asserts what THIS
// tool relies on, not the corpus's whole shape.
var expectedKinds = map[string]string{
	"key-type-ed448.1.pubkey":                    "ed448_seed_to_pubkey",
	"key-type-ed448.2.peer_id":                   "peer_id_construct",
	"key-type-ed448.3.system_peer_entity":        "peer_entity_construct",
	"key-type-ed448.4.signature":                 "ed448_sign",
	"hash-format-sha-384.1.inherited_sha256_pin": "inherited_corpus_pin",

	// Flipped from `content_hash_under_format` by arch 4cf0990. The old value
	// asserted that a system/peer CAN be authored under 0x01 — the
	// construction §4.5a item 1a forbids.
	"hash-format-sha-384.2.rehash": "construct_reject",

	"matrix.M2": "matrix_flow",
	"matrix.M3": "matrix_flow",
	"matrix.M6": "matrix_flow",
}

// sortedIDs gives the kind pass a stable order independent of corpus order.
func sortedIDs(corpus []map[string]any) []string {
	out := make([]string, 0, len(corpus))
	for _, v := range corpus {
		out = append(out, mustStr(v, "id"))
	}
	sort.Strings(out)
	return out
}

// byID indexes the decoded corpus so one vector's check can read a value another
// vector pins, rather than restating it here. A verifier that carries its own
// copy of a corpus value is a second home for the pin — the exact shape
// `expectedSHA()` was moved into the registry to avoid.
var byID = map[string]map[string]any{}

// floorFormFromSibling returns the floor-form content_hash that
// `hash-format-sha-384.2.rehash` points at via its `floor_form` field: *"see
// hash-format-sha-384.1.inherited_sha256_pin — 003d0c34b5… is the only
// content_hash this fixture has."* Both vectors carry the same fixture entity,
// so .1's pin is .2's floor form.
//
// Read from the sibling vector rather than hardcoded, and nil when the sibling
// is absent — a missing sibling makes this check unavailable, not failed.
func floorFormFromSibling(id string) []byte {
	if id != "hash-format-sha-384.2.rehash" {
		return nil
	}
	sib, ok := byID["hash-format-sha-384.1.inherited_sha256_pin"]
	if !ok {
		return nil
	}
	b, _ := sib["canonical_content_hash"].([]byte)
	return b
}

// refusalDetail renders a refusal for the report: the error when the guard
// fired, and an explicit statement of what was accepted when it did not.
func refusalDetail(err error) string {
	if err != nil {
		return fmt.Sprintf("refused: %v", err)
	}
	return "ACCEPTED — §4.5a item 1a requires the constructor to refuse system/peer under 0x01"
}

func verifyMatrix(c *checks, id string, v map[string]any, sha384gate bool) {
	a := mustMap(v, "input_peer_a")
	b := mustMap(v, "input_peer_b")
	keyA := keyFromInput(a)
	keyB := keyFromInput(b)
	// home_content_hash_format is still read so a malformed vector still
	// fails loudly here, but it no longer selects the identity hash: §4.5a
	// item 1a floor-pins system/peer whatever a peer's home format is.
	_ = byte(mustU64(a, "home_content_hash_format"))
	_ = byte(mustU64(b, "home_content_hash_format"))
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
	// §4.5a item 1a (v7.77): system/peer is floor-authored whatever the home
	// format, so homeA no longer selects the identity hash. The corresponding
	// expected_peer_a_content_hash_sha384 vector below describes behavior the
	// ruling RETIRED — see the header note.
	entA, err := keyA.IdentityEntity()
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
				fmt.Sprintf("len=%d derived=%s want=%s",
					len(entA.ContentHash.Bytes()), hx(entA.ContentHash.Bytes()), hx(want)))
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
	entB, err := keyB.IdentityEntity() // floor-pinned per §4.5a item 1a
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
			hx(capEnt.ContentHash.Bytes()))
	}
	sig := keyA.Sign(capEnt.ContentHash.Bytes())
	if want, ok := v["expected_root_cap_signature"].([]byte); ok {
		c.record(id, "root_cap.signature", bytesEq(sig, want),
			fmt.Sprintf("len=%d derived=%s want=%s", len(sig), hx(sig), hx(want)))
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
	fmt.Fprintf(os.Stderr, "agility-corpus-verify: "+format+"\n", args...)
	os.Exit(1)
}
