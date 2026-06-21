package validate

// EXTENSION-CBOR-ENCODING Appendix E — pass-through (double-check)
// conformance via validate-peer's existing TREE PUT / GET surface.
//
// Complementary to the offline `conformance` category (which diffs
// emit-canonical files cross-impl). This category drives the corpus
// into a single live peer and asserts content-hash agreement: if the
// peer computes a different content_hash from the wrapper {type, data}
// shape than we did locally, the peer rejects the PUT — that surfaces
// the encoder divergence as one named failure per vector.
//
// What this catches:
//   - Wrapper encoder bugs (outer {type, data} ECF encoding).
//   - Storage byte-fidelity bugs (the W2 pattern: receive-side
//     decode→re-encode of the data field, which breaks PUT-then-GET
//     byte equality).
//   - Acceptance of non-canonical wire bytes in entities (when the
//     peer accepts tag-bearing data instead of rejecting).
//
// What this does NOT catch (use the offline `conformance` category for
// these, driven by per-impl emit-canonical):
//   - Fresh-encoder bugs (Rule 4 float minimization in particular).
//     The wrapper test passes the inner value's pre-encoded bytes
//     verbatim; the peer doesn't re-encode the float, only wraps it.
//   - peer_id / signature / envelope construction — no standard
//     wire surface exposes those for arbitrary inputs.
//
// Invocation:
//
//   validate-peer -addr <peer:port> \
//                 -category conformance_passthrough \
//                 -corpus  conformance-vectors-v1.cbor

import (
	"bytes"
	"context"
	"fmt"
	"math/rand"
	"os"
	"strings"

	"go.entitychurch.org/entity-core-go/core/ecf"
	"go.entitychurch.org/entity-core-go/core/entity"

	"github.com/fxamacker/cbor/v2"
)

const catConformancePassthrough = "conformance_passthrough"

// RunConformancePassthrough drives the corpus into a single live peer.
func RunConformancePassthrough(ctx context.Context, client *PeerClient, corpusPath string) (*Report, error) {
	if corpusPath == "" {
		return nil, fmt.Errorf("conformance_passthrough: -corpus is required")
	}
	if client == nil {
		return nil, fmt.Errorf("conformance_passthrough: live peer client required")
	}

	corpus, err := loadConformancePassthroughCorpus(corpusPath)
	if err != nil {
		return nil, fmt.Errorf("load corpus %s: %w", corpusPath, err)
	}

	report := NewReport(client.Addr())
	report.PeerID = string(client.RemotePeerID())

	r := NewCheckRunner(catConformancePassthrough)

	// Per-run prefix to avoid collision with prior runs.
	suffix := fmt.Sprintf("%d", rand.Intn(1<<24))
	basePrefix := "system/validate/conformance-passthrough-" + suffix

	// Single informational check summarizing what categories are out of
	// scope for pass-through (peer_id, signature, envelope — covered by
	// the offline `conformance` category instead). Reported as WARN so it
	// surfaces in summaries without failing the run.
	r.Declare("out_of_scope_summary", "EXTENSION-CBOR-ENCODING §E.1")
	r.Run("out_of_scope_summary", func() CheckOutcome {
		var skipped []string
		for _, v := range corpus {
			if skipPassthroughVector(v) {
				skipped = append(skipped, v.ID)
			}
		}
		if len(skipped) == 0 {
			return PassCheck("all corpus vectors covered by pass-through")
		}
		return WarnCheck(fmt.Sprintf("%d vectors covered by offline `conformance` category only (no PUT/GET wire surface): %s",
			len(skipped), strings.Join(skipped, ", ")))
	})

	// Declare in-scope per-vector checks up front.
	for _, v := range corpus {
		if skipPassthroughVector(v) {
			continue
		}
		switch v.Kind {
		case "encode_equal":
			r.Declare("put_"+v.ID, "EXTENSION-CBOR-ENCODING §E.3 (content_hash agreement)")
			r.Declare("get_"+v.ID, "ENTITY-CORE-MACHINE-SPEC §1.8 (byte-fidelity on read)")
		case "decode_reject":
			r.Declare("reject_"+v.ID, "EXTENSION-CBOR-ENCODING §6.3")
		}
	}

	for _, v := range corpus {
		v := v
		if skipPassthroughVector(v) {
			continue
		}
		switch v.Kind {
		case "encode_equal":
			path := basePrefix + "/" + sanitizeID(v.ID)
			r.Run("put_"+v.ID, func() CheckOutcome {
				return passthroughPutCheck(ctx, client, path, v)
			})
			r.Run("get_"+v.ID, func() CheckOutcome {
				if out, ok := r.Require("put_" + v.ID); !ok {
					return out
				}
				return passthroughGetCheck(ctx, client, path, v)
			})
		case "decode_reject":
			path := basePrefix + "/reject/" + sanitizeID(v.ID)
			r.Run("reject_"+v.ID, func() CheckOutcome {
				return passthroughRejectCheck(ctx, client, path, v)
			})
		}
	}

	report.AddAll(r.Results())
	return report, nil
}

// passthroughVector is the corpus vector with input + canonical fields
// preserved as raw CBOR for re-emit.
type passthroughVector struct {
	ID        string          `cbor:"id"`
	Kind      string          `cbor:"kind"`
	Input     cbor.RawMessage `cbor:"input"`
	Canonical []byte          `cbor:"canonical"`
}

func loadConformancePassthroughCorpus(path string) ([]passthroughVector, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	dec, err := cbor.DecOptions{}.DecMode()
	if err != nil {
		return nil, err
	}
	var arr []passthroughVector
	if err := dec.Unmarshal(data, &arr); err != nil {
		return nil, err
	}
	return arr, nil
}

// skipPassthroughVector returns true for vectors whose semantics cannot
// be tested through the existing PUT/GET surface. Those need the
// emit-canonical / offline conformance route instead.
func skipPassthroughVector(v passthroughVector) bool {
	if strings.HasPrefix(v.ID, "peer_id.") ||
		strings.HasPrefix(v.ID, "signature.") ||
		strings.HasPrefix(v.ID, "envelope.") {
		return true
	}
	return false
}

func passthroughSkipReason(v passthroughVector) string {
	switch {
	case strings.HasPrefix(v.ID, "peer_id."):
		return "peer_id construction: no PUT/GET surface (peer's own peer_id is observable but cannot test synthetic key_type/digest); use offline `conformance` category"
	case strings.HasPrefix(v.ID, "signature."):
		return "signature: no 'sign arbitrary bytes with peer key' wire surface; use offline `conformance` category"
	case strings.HasPrefix(v.ID, "envelope."):
		return "envelope: no standalone construction surface; use offline `conformance` category"
	}
	return "category not pass-through testable"
}

// passthroughPutCheck wraps the vector's input as an entity and PUTs it
// to the peer. Acceptance == content_hash agreement (the peer re-derives
// the same hash from {type, data} that we did locally).
func passthroughPutCheck(ctx context.Context, client *PeerClient, path string, v passthroughVector) CheckOutcome {
	ent, err := buildPassthroughEntity(v)
	if err != nil {
		return FailCheck(fmt.Sprintf("build entity: %v", err))
	}
	if _, err := client.TreePut(ctx, path, ent); err != nil {
		return FailCheck(fmt.Sprintf("PUT rejected (likely content_hash divergence): %v", err))
	}
	return PassCheck(fmt.Sprintf("PUT accepted; peer-side content_hash agrees (%s)", ent.ContentHash))
}

// passthroughGetCheck reads back the entity and compares raw data bytes.
// W2-style receive-side re-encode bugs surface as a byte-divergence here.
func passthroughGetCheck(ctx context.Context, client *PeerClient, path string, v passthroughVector) CheckOutcome {
	expected, err := buildPassthroughEntity(v)
	if err != nil {
		return FailCheck(fmt.Sprintf("build entity: %v", err))
	}
	got, _, err := client.TreeGet(ctx, path)
	if err != nil {
		return FailCheck(fmt.Sprintf("GET failed: %v", err))
	}
	if got.Type != expected.Type {
		return FailCheck(fmt.Sprintf("type changed: got %q expected %q", got.Type, expected.Type))
	}
	if !bytes.Equal([]byte(got.Data), []byte(expected.Data)) {
		return FailCheck(fmt.Sprintf("data byte divergence (W2-pattern receive-side re-encode?): sent %d B got %d B",
			len(expected.Data), len(got.Data)))
	}
	if got.ContentHash != expected.ContentHash {
		return FailCheck(fmt.Sprintf("content_hash diverged on read-back: sent %s got %s",
			expected.ContentHash, got.ContentHash))
	}
	return PassCheck(fmt.Sprintf("read-back byte-identical (%d B, hash %s)", len(got.Data), got.ContentHash))
}

// passthroughRejectCheck attempts to put an entity whose `data` field
// carries non-canonical bytes (tag-bearing). The peer should reject —
// either at content_hash verification time (the wrapper still
// computes deterministically, but a strict ECF decoder would reject
// the inner data) OR at storage time if it strict-decodes data.
//
// Limitation: if the impl treats data as opaque RawMessage without
// strict-mode validation, this check will report a soft WARN rather
// than FAIL — the offline `conformance` category remains authoritative
// for decode_reject. We surface that nuance in the message.
func passthroughRejectCheck(ctx context.Context, client *PeerClient, path string, v passthroughVector) CheckOutcome {
	// Wrap the tag-bearing canonical bytes as an entity. The bytes
	// themselves are an ECF map encoding (a2 ...) so we can use them
	// directly as the data field.
	ent, err := entity.NewEntity("system/validate/conformance-tag/"+sanitizeID(v.ID), cbor.RawMessage(v.Canonical))
	if err != nil {
		// Construction itself failed — that's a rejection at the Go
		// client side, fine.
		return PassCheck(fmt.Sprintf("entity construction rejected non-canonical data: %v", err))
	}
	_, err = client.TreePut(ctx, path, ent)
	if err != nil {
		return PassCheck(fmt.Sprintf("PUT rejected (good): %v", err))
	}
	return WarnCheck("PUT accepted — peer does not strict-validate the data field for ECF non-canonicity. Use offline `conformance` category for the authoritative decode_reject gate.")
}

// buildPassthroughEntity constructs the validate-peer test entity for a
// vector. The data field is `{"value": <vector.input>}` — Class A and
// content_hash inputs (already entity-shaped) take slightly different
// paths.
func buildPassthroughEntity(v passthroughVector) (entity.Entity, error) {
	typ := "system/validate/conformance/" + sanitizeID(v.ID)
	if strings.HasPrefix(v.ID, "content_hash.") {
		// The vector's input is already an entity {type, data}; use it
		// directly as the test entity so the peer's content_hash matches
		// what the corpus expects. Path uniqueness handles collision —
		// no need to mangle the type.
		var raw struct {
			Type string          `cbor:"type"`
			Data cbor.RawMessage `cbor:"data"`
		}
		if err := cbor.Unmarshal(v.Input, &raw); err != nil {
			return entity.Entity{}, fmt.Errorf("decode content_hash input: %w", err)
		}
		return entity.NewEntity(raw.Type, raw.Data)
	}
	// Wrap the input value in a single-key data map.
	wrapper := map[string]cbor.RawMessage{"value": cbor.RawMessage(v.Input)}
	data, err := ecf.Encode(wrapper)
	if err != nil {
		return entity.Entity{}, fmt.Errorf("encode wrapper: %w", err)
	}
	return entity.NewEntity(typ, cbor.RawMessage(data))
}

// sanitizeID swaps the dot separator for a hyphen so the vector id is
// safe to use as a path segment (paths use slash separators and
// reserved-character handling).
func sanitizeID(id string) string {
	return strings.ReplaceAll(id, ".", "-")
}

