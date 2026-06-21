package validate

// EXTENSION-CBOR-ENCODING Appendix E conformance category.
//
// Unlike the other validate-peer categories, conformance is OFFLINE: it
// does not connect to any live peer. Instead it diffs the per-impl
// `emit-canonical` artifacts that each impl's wire-conformance harness
// produces against the shared corpus. See GUIDE-CONFORMANCE.md §3.3.
//
// Invocation:
//
//   validate-peer -category conformance \
//                 -corpus  conformance-vectors-v1.cbor \
//                 -peers   go:emit-go.cbor,rust:emit-rust.cbor,py:emit-py.cbor \
//                 -json-out reports/conformance-v1.json
//
// The -peers flag carries `<label>:<path>` pairs (paths to emission
// files), NOT `<label>:<addr>`. The validate-peer entry point routes
// the conformance category here without attempting peer connections.

import (
	"bytes"
	"context"
	"encoding/hex"
	"fmt"
	"os"
	"sort"
	"strings"

	"github.com/fxamacker/cbor/v2"
)

const catConformance = "conformance"

// ConformancePeerEmission carries a single impl's emission file location.
type ConformancePeerEmission struct {
	Label string
	Path  string
}

// ConformanceEmission is the GUIDE-CONFORMANCE §3.1 emission shape as
// loaded from disk.
type ConformanceEmission struct {
	Impl          string            `cbor:"impl"`
	ImplVersion   string            `cbor:"impl_version"`
	CorpusVersion string            `cbor:"corpus_version"`
	SpecVersion   string            `cbor:"spec_version"`
	EncodeResults map[string][]byte `cbor:"encode_results"`
	DecodeResults map[string]bool   `cbor:"decode_results"`
	DecodeCodes   map[string]string `cbor:"decode_codes"`
	Errors        map[string]string `cbor:"errors"`
}

// ConformanceVector is the corpus's vector shape (only id + kind needed
// to drive the diff loop).
type ConformanceVector struct {
	ID   string `cbor:"id"`
	Kind string `cbor:"kind"`
}

// RunConformance is the offline conformance category entry point.
func RunConformance(ctx context.Context, corpusPath string, peers []ConformancePeerEmission) (*Report, error) {
	if corpusPath == "" {
		return nil, fmt.Errorf("conformance: -corpus is required")
	}
	if len(peers) < 1 {
		return nil, fmt.Errorf("conformance: at least one -peers <label>:<path> entry required")
	}

	report := NewReport("conformance")
	for _, p := range peers {
		report.Peers = append(report.Peers, PeerInfo{Label: p.Label, Addr: p.Path})
	}

	corpus, err := loadConformanceCorpus(corpusPath)
	if err != nil {
		return nil, fmt.Errorf("load corpus %s: %w", corpusPath, err)
	}

	emissions := make(map[string]*ConformanceEmission, len(peers))
	for _, p := range peers {
		em, err := loadConformanceEmission(p.Path)
		if err != nil {
			return nil, fmt.Errorf("load emission %s (%s): %w", p.Label, p.Path, err)
		}
		emissions[p.Label] = em
	}

	r := NewCheckRunner(catConformance)

	// Metadata agreement (corpus_version, spec_version).
	r.Declare("corpus_version_agreement", "GUIDE-CONFORMANCE §5.1")
	r.Declare("spec_version_agreement", "GUIDE-CONFORMANCE §5.1")

	r.Run("corpus_version_agreement", func() CheckOutcome {
		return agreementCheck(peers, emissions, "corpus_version", func(em *ConformanceEmission) string { return em.CorpusVersion })
	})
	r.Run("spec_version_agreement", func() CheckOutcome {
		return agreementCheck(peers, emissions, "spec_version", func(em *ConformanceEmission) string { return em.SpecVersion })
	})

	// Per-vector cross-impl diff. Each vector becomes one check.
	for _, v := range corpus {
		switch v.Kind {
		case "encode_equal":
			r.Declare("encode_"+v.ID, "EXTENSION-CBOR-ENCODING §E.3")
		case "decode_reject":
			r.Declare("decode_"+v.ID, "EXTENSION-CBOR-ENCODING §6.3")
		default:
			r.Declare("vector_"+v.ID, "EXTENSION-CBOR-ENCODING §E.2")
		}
	}
	for _, v := range corpus {
		v := v
		switch v.Kind {
		case "encode_equal":
			r.Run("encode_"+v.ID, func() CheckOutcome {
				return diffEncodeEqual(v.ID, peers, emissions)
			})
		case "decode_reject":
			r.Run("decode_"+v.ID, func() CheckOutcome {
				return diffDecodeReject(v.ID, peers, emissions)
			})
		default:
			r.Run("vector_"+v.ID, func() CheckOutcome {
				return FailCheck(fmt.Sprintf("unknown vector kind: %q", v.Kind))
			})
		}
	}

	report.AddAll(r.Results())
	return report, nil
}

func loadConformanceCorpus(path string) ([]ConformanceVector, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	dec, err := cbor.DecOptions{}.DecMode()
	if err != nil {
		return nil, err
	}
	var arr []ConformanceVector
	if err := dec.Unmarshal(data, &arr); err != nil {
		return nil, err
	}
	return arr, nil
}

func loadConformanceEmission(path string) (*ConformanceEmission, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	dec, err := cbor.DecOptions{}.DecMode()
	if err != nil {
		return nil, err
	}
	var em ConformanceEmission
	if err := dec.Unmarshal(data, &em); err != nil {
		return nil, err
	}
	return &em, nil
}

func agreementCheck(peers []ConformancePeerEmission, emissions map[string]*ConformanceEmission, fieldName string, get func(*ConformanceEmission) string) CheckOutcome {
	var seen string
	for _, p := range peers {
		v := get(emissions[p.Label])
		if seen == "" {
			seen = v
			continue
		}
		if v != seen {
			return FailCheck(fmt.Sprintf("%s disagrees: %s reports %q, others %q", fieldName, p.Label, v, seen))
		}
	}
	return PassCheck(fmt.Sprintf("all impls report %s=%s", fieldName, seen))
}

type implResult struct {
	label string
	bytes []byte
	err   string
}

func diffEncodeEqual(id string, peers []ConformancePeerEmission, emissions map[string]*ConformanceEmission) CheckOutcome {
	var results []implResult
	for _, p := range peers {
		em := emissions[p.Label]
		if errMsg, ok := em.Errors[id]; ok {
			results = append(results, implResult{p.Label, nil, errMsg})
			continue
		}
		b, ok := em.EncodeResults[id]
		if !ok {
			return FailCheck(fmt.Sprintf("%s: vector missing from encode_results and errors", p.Label))
		}
		results = append(results, implResult{p.Label, b, ""})
	}

	// All-errored case: pass-by-consensus IF every impl errored. The
	// content_hash.4 / peer_id.3 vectors test forward-compat varints
	// every impl may legitimately not yet support; conformance is
	// about agreement, not feature presence. See CROSS-TEAM-
	// ASSIGNMENT-ECF-CONFORMANCE-V1 §6.
	allErrored := true
	anyErrored := false
	for _, r := range results {
		if r.err != "" {
			anyErrored = true
		} else {
			allErrored = false
		}
	}
	if allErrored && len(results) > 1 {
		return PassCheck(fmt.Sprintf("all %d impls errored consistently: %s", len(results), summarizeErrors(results)))
	}
	if anyErrored {
		return FailCheck(fmt.Sprintf("split errored/encoded outcomes: %s", summarizeMixed(results)))
	}

	first := results[0].bytes
	for _, r := range results[1:] {
		if !bytes.Equal(r.bytes, first) {
			return FailCheck(fmt.Sprintf("byte divergence: %s", summarizeDiverged(results)))
		}
	}
	if len(results) == 1 {
		return WarnCheck(fmt.Sprintf("single-impl run (%s): %d bytes; cross-impl gate requires 2+", results[0].label, len(first)))
	}
	return PassCheck(fmt.Sprintf("byte-identical across %d impls: %s (%d B)", len(results), hex.EncodeToString(first), len(first)))
}

func diffDecodeReject(id string, peers []ConformancePeerEmission, emissions map[string]*ConformanceEmission) CheckOutcome {
	type implReject struct {
		label    string
		rejected bool
		code     string // "" if the impl's emission predates decode_codes
		hasCode  bool
	}
	var results []implReject
	for _, p := range peers {
		em := emissions[p.Label]
		v, ok := em.DecodeResults[id]
		if !ok {
			return FailCheck(fmt.Sprintf("%s: vector missing from decode_results", p.Label))
		}
		code, hasCode := em.DecodeCodes[id]
		results = append(results, implReject{p.Label, v, code, hasCode})
	}

	// Rejection gate first (the load-bearing MUST).
	allRejected := true
	for _, r := range results {
		if !r.rejected {
			allRejected = false
		}
	}
	if !allRejected {
		var b strings.Builder
		for i, r := range results {
			if i > 0 {
				b.WriteString(", ")
			}
			fmt.Fprintf(&b, "%s=%v", r.label, r.rejected)
		}
		return FailCheck(fmt.Sprintf("split rejection: %s", b.String()))
	}

	// Error-code gate (§6.3 / Appendix E §1328). The expected code is per
	// category; the v1 corpus's decode_reject vectors are all tag_reject →
	// `non_canonical_ecf`. Other categories without a documented code skip
	// the code assertion (rejection alone is the gate).
	want := expectedRejectCode(id)
	if want != "" {
		var mismatched, missing []string
		for _, r := range results {
			if !r.hasCode {
				// Emission predates decode_codes — can't assert the code for
				// this impl yet. Don't fail it; flag for the team to update
				// its emit harness (GUIDE-CONFORMANCE §3.1).
				missing = append(missing, r.label)
				continue
			}
			if r.code != want {
				mismatched = append(mismatched, fmt.Sprintf("%s=%q", r.label, r.code))
			}
		}
		if len(mismatched) > 0 {
			return FailCheck(fmt.Sprintf("rejected by all, but error code ≠ %q: %s (§6.3)", want, strings.Join(mismatched, ", ")))
		}
		if len(missing) > 0 {
			return WarnCheck(fmt.Sprintf("rejected by all %d impls; code %q confirmed for %d, but %s emission(s) carry no decode_codes — update their emit harness to assert the §6.3 code",
				len(results), want, len(results)-len(missing), strings.Join(missing, ", ")))
		}
		if len(results) == 1 {
			return WarnCheck(fmt.Sprintf("single-impl run (%s): rejected with code %q; cross-impl gate requires 2+", results[0].label, want))
		}
		return PassCheck(fmt.Sprintf("rejected by all %d impls with code %q", len(results), want))
	}

	if len(results) == 1 {
		return WarnCheck(fmt.Sprintf("single-impl run (%s): rejected; cross-impl gate requires 2+", results[0].label))
	}
	return PassCheck(fmt.Sprintf("rejected by all %d impls", len(results)))
}

// expectedRejectCode returns the spec error code a decode_reject vector's
// category must produce, or "" if the category has no documented code (in
// which case rejection alone is the gate). Per Appendix E §1328, tag_reject
// vectors reject with `400 non_canonical_ecf` (ENTITY-CBOR-ENCODING §6.3).
func expectedRejectCode(vectorID string) string {
	category := vectorID
	if dot := strings.IndexByte(vectorID, '.'); dot >= 0 {
		category = vectorID[:dot]
	}
	switch category {
	case "tag_reject":
		return "non_canonical_ecf"
	default:
		return ""
	}
}

func summarizeErrors(rs []implResult) string {
	sort.Slice(rs, func(i, j int) bool { return rs[i].label < rs[j].label })
	var b strings.Builder
	for i, r := range rs {
		if i > 0 {
			b.WriteString("; ")
		}
		fmt.Fprintf(&b, "%s=%q", r.label, r.err)
	}
	return b.String()
}

func summarizeMixed(rs []implResult) string {
	sort.Slice(rs, func(i, j int) bool { return rs[i].label < rs[j].label })
	var b strings.Builder
	for i, r := range rs {
		if i > 0 {
			b.WriteString("; ")
		}
		if r.err != "" {
			fmt.Fprintf(&b, "%s=err(%s)", r.label, r.err)
		} else {
			fmt.Fprintf(&b, "%s=%dB", r.label, len(r.bytes))
		}
	}
	return b.String()
}

func summarizeDiverged(rs []implResult) string {
	sort.Slice(rs, func(i, j int) bool { return rs[i].label < rs[j].label })
	var b strings.Builder
	for i, r := range rs {
		if i > 0 {
			b.WriteString("; ")
		}
		fmt.Fprintf(&b, "%s=%s", r.label, hex.EncodeToString(r.bytes))
	}
	return b.String()
}
