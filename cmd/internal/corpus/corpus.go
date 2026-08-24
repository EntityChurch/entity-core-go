// Package corpus is the one contract every conformance corpus is held to.
//
// # Why this package exists
//
// There were two corpora and two unrelated processes. `crypto-agility` had both
// gates — a pinned sha (artifact-is-expected) and a re-encode (source-produces-
// artifact) — wired into the conformance gate. `ecf-conformance`, the larger and
// more widely vendored of the two, had NEITHER: its builder wrote the artifact on
// demand, its only test read the `.cbor` and never the `.diag`, and no sha was
// pinned for it anywhere. The defect that cost two months on the first corpus was
// structurally undetectable on the second.
//
// That is not two tools disagreeing; it is one contract that was only ever written
// down as code, in one of the two places that needed it. This package is the
// contract, and the registry below is the list of corpora it applies to. Adding a
// corpus means adding a registry entry — not writing a third process.
//
// # The contract
//
// A conformance corpus is a `.diag` source and one or more committed `.cbor`
// artifacts. Three assertions, and the second is the one whose absence hurts:
//
//	VERIFY  the committed artifact is the one we expect       (pinned sha256)
//	CHECK   the committed source still produces that artifact (re-encode, compare)
//	AGREE   where a corpus has several copies, they are byte-identical
//
// VERIFY alone is what the crypto-agility corpus had for two months while its
// `.diag` and `.cbor` disagreed: both files stayed internally plausible, the
// verifier scored 52/0 against the artifact, and nothing asked whether the source
// still produced it.
//
// # What this package deliberately does not do
//
// It writes nothing. Building an artifact is a separate, deliberate act with an
// owner (SEEDS.md §4: arch sets fields, the encoder settles bytes, arch commits);
// a gate that could rewrite the thing it is checking would launder a drift into a
// pass. It also carries no corpus-specific depth — the crypto re-derivation of the
// agility vectors lives in `v767-corpus-verify`, layered on top of this floor.
package corpus

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"go.entitychurch.org/entity-core-go/cmd/internal/diagcodec"
)

// Root is the spec repo the corpora live in. They are arch's artifacts; this
// repo builds and checks them but never commits them.
const Root = "../entity-core-protocol/specs/test-vectors"

// Copy is one committed location of a corpus.
type Copy struct {
	Label string
	Diag  string
	Cbor  string
}

// Corpus is a set of conformance vectors under the contract above.
type Corpus struct {
	// Name is the selector (`-corpus <name>`) and the identity a conformance
	// citation carries per the de-version proposal's
	// (spec-version, corpus-name, artifact sha256) form.
	Name string

	// Subject is what the corpus tests, in one line.
	Subject string

	// ExpectedSHA is the sha256 of the committed artifact. THE SINGLE HOME for
	// this fact — `v767-corpus-verify` reads it from here rather than carrying
	// its own copy, because a pin that exists twice is a pin that will
	// eventually exist at two values.
	ExpectedSHA string

	// Copies is every committed location. More than one means the byte-identity
	// invariant applies (arch 3042bd8). When arch's de-version proposal collapses
	// the crypto-agility pair, that entry loses a copy and the invariant
	// disappears with it — which is the point: the invariant exists because the
	// second copy does.
	Copies []Copy
}

// All is the registry. Adding a corpus is an entry here; there is no second
// process to write.
func All() []Corpus {
	return []Corpus{
		{
			Name:    "crypto-agility",
			Subject: "format/key-type agility — content_hash_format and key_type seed matrices (V7 §1.2, §1.5)",
			// Re-pinned 2026-08-13 for the rehash inversion. Arch landed
			// SEEDS.md §4.4 step 1 at entity-core-protocol 4cf0990 —
			// `hash-format-sha-384.2.rehash` flipped from
			// `content_hash_under_format` to `construct_reject`, its three
			// SHA-384 pins removed, `expected_behavior` /
			// `verifier_requirement` / `floor_form` added. Those are encoded
			// fields, so the artifact legitimately moves: 9742 B
			// `6d0f4a94…` -> 10874 B `b5484e84…`.
			//
			// Step 2 (ours) ran the encoder self-check FIRST, against the
			// frozen legacy pair now in `cmd/v767-corpus-build/testdata/` —
			// it still reproduces the June artifact `8e7c5232…` at 9236 B.
			// Re-pinning on the output of an unproven encoder is how a build
			// tool mints its own oracle.
			ExpectedSHA: "b5484e84dd2cddfa7d3cc8a041deba92cb29615aedb2180e31d8b6910ac5b648",
			Copies: []Copy{
				{"v767 (versioned)", Root + "/v767/conformance-vectors-v1.diag", Root + "/v767/conformance-vectors-v1.cbor"},
				{"crypto-agility (public release form)", Root + "/crypto-agility/agility-vectors-v1.diag", Root + "/crypto-agility/agility-vectors-v1.cbor"},
			},
		},
		{
			Name:    "ecf-conformance",
			Subject: "Entity Canonical Form encoding — the ECF vector set (ENTITY-CBOR-ENCODING Appendix E)",
			// Pinned 2026-08-13 at entity-core-protocol da6baa8, the first time
			// this corpus was pinned at all. Verified reproducible from source
			// before pinning: re-encoding the committed .diag yields exactly
			// these bytes, so the gate goes in green rather than red.
			ExpectedSHA: "9695b1f1d939cfdfdd4297f8ad32122d424b1ec180cfae74c92d509d88f7c6dc",
			Copies: []Copy{
				{"ecf-conformance", Root + "/ecf-conformance/conformance-vectors-v1.diag", Root + "/ecf-conformance/conformance-vectors-v1.cbor"},
			},
		},
	}
}

// ErrAbsent means the spec repo is not checked out. Reported as a loud skip by
// callers rather than swallowed: an absent input is not a passing check, and it
// is also not a corpus defect.
var ErrAbsent = errors.New("spec repo not present")

// Result is one corpus's outcome under the contract.
type Result struct {
	Corpus   Corpus
	Encoded  map[string]string // copy label -> sha256 the .diag encodes to
	OnDisk   map[string]string // copy label -> sha256 of the committed .cbor
	Sizes    map[string]int
	Vectors  int
	Failures []string
}

func (r Result) OK() bool { return len(r.Failures) == 0 }

// Check runs the whole contract. It reads; it never writes.
func (c Corpus) Check() (Result, error) {
	res := Result{
		Corpus:  c,
		Encoded: map[string]string{},
		OnDisk:  map[string]string{},
		Sizes:   map[string]int{},
	}
	for _, cp := range c.Copies {
		if _, err := os.Stat(cp.Diag); err != nil {
			return res, fmt.Errorf("%w: %s", ErrAbsent, filepath.Dir(cp.Diag))
		}
	}

	var first string
	for _, cp := range c.Copies {
		encoded, n, err := encode(cp.Diag)
		if err != nil {
			return res, err
		}
		res.Vectors = n
		res.Encoded[cp.Label] = shaHex(encoded)

		onDisk, err := os.ReadFile(cp.Cbor)
		if err != nil {
			return res, fmt.Errorf("read %s: %w", cp.Cbor, err)
		}
		res.OnDisk[cp.Label] = shaHex(onDisk)
		res.Sizes[cp.Label] = len(onDisk)

		// AGREE — every copy's SOURCE must encode to the same bytes. Checked on
		// the encoded form, not the committed form, because that is where a
		// de-versioning edit to an *encoded* field (id, description) shows up.
		if first == "" {
			first = res.Encoded[cp.Label]
		} else if res.Encoded[cp.Label] != first {
			res.Failures = append(res.Failures, fmt.Sprintf(
				"copies encode to different bytes (%s vs %s) — the .diag files have diverged in ENCODED content (id/description are encoded; comments are not). arch 3042bd8 makes byte-identity the standing invariant",
				first, res.Encoded[cp.Label]))
		}

		// CHECK — source produces artifact.
		if res.OnDisk[cp.Label] != res.Encoded[cp.Label] {
			res.Failures = append(res.Failures, fmt.Sprintf(
				"%s: DRIFT — committed .cbor is %s (%d B) but %s encodes to %s",
				cp.Label, res.OnDisk[cp.Label], len(onDisk), cp.Diag, res.Encoded[cp.Label]))
		}

		// VERIFY — artifact is the one we expect.
		if c.ExpectedSHA != "" && res.OnDisk[cp.Label] != c.ExpectedSHA {
			res.Failures = append(res.Failures, fmt.Sprintf(
				"%s: committed .cbor sha %s does not match the pinned %s",
				cp.Label, res.OnDisk[cp.Label], c.ExpectedSHA))
		}
	}
	return res, nil
}

// DriftAdvice is printed whenever CHECK fails. It deliberately does NOT tell the
// reader to rebuild: on this corpus the `.cbor` was the correct side and the
// `.diag` the stale one, so a blind rebuild would have destroyed the good copy.
// Deciding which side is right is the step the June regen skipped, and it is the
// whole reason this check exists.
const DriftAdvice = `The committed artifact is NOT what the committed source produces.

Do not "fix" this by rebuilding until you know WHICH SIDE IS RIGHT — that is the
decision the June regeneration skipped. On the crypto-agility corpus the .cbor was
correct and the .diag stale (the F16 seed widths), so rebuilding blindly would have
destroyed the good copy and made the drift permanent and invisible.

Diff the two, decide which is authoritative, then rebuild deliberately.`

func encode(diagPath string) ([]byte, int, error) {
	src, err := os.ReadFile(diagPath)
	if err != nil {
		return nil, 0, fmt.Errorf("read %s: %w", diagPath, err)
	}
	val, err := diagcodec.ParseDiag(string(src))
	if err != nil {
		return nil, 0, fmt.Errorf("parse %s: %w", diagPath, err)
	}
	arr, ok := val.([]interface{})
	if !ok {
		return nil, 0, fmt.Errorf("%s: expected a top-level array, got %T", diagPath, val)
	}
	b, err := diagcodec.EncodeCanonical(arr)
	if err != nil {
		return nil, 0, fmt.Errorf("encode %s: %w", diagPath, err)
	}
	return b, len(arr), nil
}

func shaHex(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

// ByName returns one registered corpus.
func ByName(name string) (Corpus, bool) {
	for _, c := range All() {
		if c.Name == name {
			return c, true
		}
	}
	return Corpus{}, false
}
