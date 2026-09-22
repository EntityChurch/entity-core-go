package validate

import (
	"context"
	"fmt"

	"go.entitychurch.org/entity-core-go/core/ecf"
	"go.entitychurch.org/entity-core-go/core/entity"
	"go.entitychurch.org/entity-core-go/core/tree"
	"go.entitychurch.org/entity-core-go/core/types"

	"github.com/fxamacker/cbor/v2"
)

// catTreePutErr cites the EXTENSION-TREE Appendix A (v4.4) `put`/`set` error
// rows this probe gates. `put`/`get` are the two CORE tree operations
// (ENTITY-CORE-PROTOCOL §6.3); §3.3 (line 851) routes their error codes to
// EXTENSION-TREE Appendix A, and v4.4 finally gives them rows.
const catTreePutErr = "V7 §3.3 / EXTENSION-TREE Appendix A (v4.4)"

// runTreePutErrorCodes gates the three `put` error rows EXTENSION-TREE v4.4 added
// — the rows core-rust flagged as untested (tree_operations was green about a
// surface it did not exercise). The discriminator is settled (v4.4) and agreed
// three ways (go landed, py conformant, rust landed), so this is a true
// cross-impl signal, not a reading-under-test (the deferred-gate rule is
// cleared). It reads the `code` field, never the status alone — the existing
// cas_mismatch check asserts only the 409 status, which cannot tell
// `hash_mismatch` from any other 409.
//
// Rows (EXTENSION-TREE Appendix A, v4.4):
//   - undecodable entity        → 400 invalid_request  (row 1; §3.3's 400 default)
//   - content-hash mismatch     → 400 hash_mismatch    (row 2; = EXTENSION-CONTENT §923's code)
//   - CAS expected_hash race    → 409 hash_mismatch    (row 3; V7 §3.6 behaviour)
//
// Carry-the-teeth: a valid put MUST land 200 first (the positive control),
// proving the probe reaches the handler — so a 400/409 on the hostile inputs is
// attributable to the input, not to an unreachable handler or a denied cap. If
// the control does not land 200, every row SKIPs (unattributable), never PASSes.
func runTreePutErrorCodes(ctx context.Context, client *PeerClient) []CheckResult {
	r := NewCheckRunner(catTreeOps)
	r.Declare("put_error_control_valid_200", catTreePutErr)
	r.Declare("put_undecodable_400_invalid_request", catTreePutErr)
	r.Declare("put_absent_content_hash_400_invalid_request", catTreePutErr)
	r.Declare("put_unsupported_content_hash_format_400", catTreePutErr)
	r.Declare("put_hash_mismatch_400_hash_mismatch", catTreePutErr)
	r.Declare("put_cas_race_409_hash_mismatch", catTreePutErr)

	if !client.Connected() {
		skip := func() CheckOutcome { return SkipCheck("client not connected/handshaked") }
		r.Run("put_error_control_valid_200", skip)
		r.Run("put_undecodable_400_invalid_request", skip)
		r.Run("put_absent_content_hash_400_invalid_request", skip)
		r.Run("put_unsupported_content_hash_format_400", skip)
		r.Run("put_hash_mismatch_400_hash_mismatch", skip)
		r.Run("put_cas_race_409_hash_mismatch", skip)
		return r.Results()
	}

	uri := fmt.Sprintf("entity://%s/system/tree", client.remotePeerID)
	const base = "system/validate/tree-put-errcodes"

	// sendPut executes a put of pre-built params and returns (status, code).
	sendPut := func(params entity.Entity, resource *types.ResourceTarget) (uint, string, error) {
		env, _, err := client.SendExecute(ctx, uri, "put", params, resource)
		if err != nil {
			return 0, "", err
		}
		status, code, _, derr := extractStatusAndCode(env)
		return status, code, derr
	}

	// Positive control: a well-formed put lands 200. Gates the rest.
	r.Run("put_error_control_valid_200", func() CheckOutcome {
		data, _ := ecf.Encode(map[string]string{"v": "control"})
		ent, err := entity.NewEntity("system/validate/tree-put-err", cbor.RawMessage(data))
		if err != nil {
			return FailCheck("build control entity: " + err.Error())
		}
		params, resource, err := tree.CreatePutRequest(base+"/control", &ent)
		if err != nil {
			return FailCheck("build control put: " + err.Error())
		}
		status, code, err := sendPut(params, resource)
		if err != nil {
			return FailCheck("control put send/recv: " + err.Error())
		}
		if status != 200 {
			return FailCheck(fmt.Sprintf("control put answered %d/%q, want 200 — cannot attribute the error probes", status, code))
		}
		return PassCheck("valid put → 200 (control: the error probes below are attributable to their inputs)")
	})
	r.Gate("put_error_control_valid_200")

	// Row 1: a non-decoding entity (valid CBOR, wrong shape — a bare integer)
	// is the generic structurally-invalid case → 400 invalid_request.
	r.Run("put_undecodable_400_invalid_request", func() CheckOutcome {
		bad, _ := ecf.Encode(42)
		putReq := types.PutRequestData{Entity: cbor.RawMessage(bad)}
		params, err := putReq.ToEntity()
		if err != nil {
			return FailCheck("build undecodable put: " + err.Error())
		}
		status, code, err := sendPut(params, &types.ResourceTarget{Targets: []string{base + "/undecodable"}})
		if err != nil {
			return FailCheck("undecodable put send/recv: " + err.Error())
		}
		if status != 400 || code != "invalid_request" {
			return FailCheck(fmt.Sprintf("non-decoding entity answered %d/%q, want 400/invalid_request (EXTENSION-TREE Appendix A put row 1; §3.3 400 default)", status, code))
		}
		return PassCheck("non-decoding entity → 400/invalid_request")
	})

	// Row 1 (v4.5), the cross-seat arm: a two-key {type, data} entity with
	// content_hash ABSENT — the exact shape rust/py SDKs send. content_hash is
	// a required field of core/entity (ENTITY-NATIVE-TYPE-SYSTEM §8.1), so its
	// absence is a STRUCTURAL defect (step 1 of §6.3) → 400 invalid_request,
	// NOT hash_mismatch (a peer that authors the hash on absence answers 200 —
	// non-conformant SDK-vs-peer split, arch 0.8.2.11). This is the row that is
	// only observable across a seat boundary (a lenient peer + a stripping SDK
	// in one tree round-trips cleanly).
	r.Run("put_absent_content_hash_400_invalid_request", func() CheckOutcome {
		d, _ := ecf.Encode(map[string]string{"v": "noHash"})
		twoKey, err := ecf.Encode(map[string]interface{}{
			"type": "system/validate/tree-put-err",
			"data": cbor.RawMessage(d),
		})
		if err != nil {
			return FailCheck("build absent-hash entity: " + err.Error())
		}
		putReq := types.PutRequestData{Entity: cbor.RawMessage(twoKey)}
		params, err := putReq.ToEntity()
		if err != nil {
			return FailCheck("build absent-hash put: " + err.Error())
		}
		status, code, err := sendPut(params, &types.ResourceTarget{Targets: []string{base + "/absenthash"}})
		if err != nil {
			return FailCheck("absent-hash put send/recv: " + err.Error())
		}
		if status == 200 {
			return FailCheck("absent content_hash was ACCEPTED (200) — the peer authored a hash the submitter did not provide; put is a receipt path, not an authoring one (ENTITY-NATIVE-TYPE-SYSTEM §8.1, EXTENSION-TREE v4.5 row 1)")
		}
		if status != 400 || code != "invalid_request" {
			return FailCheck(fmt.Sprintf("absent content_hash answered %d/%q, want 400/invalid_request (a required field's absence is structural, not a hash mismatch)", status, code))
		}
		return PassCheck("absent content_hash → 400/invalid_request (structural, step 1)")
	})

	// Row 4 (v4.5): a well-formed content_hash byte string whose leading format
	// code the peer does not support → 400 unsupported_content_hash_format (the
	// §1.2 ingest-dispatch case, ENTITY-CORE-PROTOCOL §4.7 row 5). NOT
	// invalid_request — the value is a valid hash, the peer just cannot verify
	// the format. rust + py both drove go into invalid_request here; the arm
	// binds every seat that ingests a put.
	r.Run("put_unsupported_content_hash_format_400", func() CheckOutcome {
		d, _ := ecf.Encode(map[string]string{"v": "badfmt"})
		badHash := make([]byte, 1+64) // format 0x02 (unallocated) + 64-byte digest
		badHash[0] = 0x02
		twoPlus, err := ecf.Encode(map[string]interface{}{
			"type":         "system/validate/tree-put-err",
			"data":         cbor.RawMessage(d),
			"content_hash": badHash,
		})
		if err != nil {
			return FailCheck("build bad-format entity: " + err.Error())
		}
		putReq := types.PutRequestData{Entity: cbor.RawMessage(twoPlus)}
		params, err := putReq.ToEntity()
		if err != nil {
			return FailCheck("build bad-format put: " + err.Error())
		}
		status, code, err := sendPut(params, &types.ResourceTarget{Targets: []string{base + "/badformat"}})
		if err != nil {
			return FailCheck("bad-format put send/recv: " + err.Error())
		}
		if status != 400 || code != "unsupported_content_hash_format" {
			return FailCheck(fmt.Sprintf("unsupported content_hash format answered %d/%q, want 400/unsupported_content_hash_format (EXTENSION-TREE Appendix A put row 4, v4.5; ENTITY-CORE-PROTOCOL §4.7 row 5)", status, code))
		}
		return PassCheck("unsupported content_hash format → 400/unsupported_content_hash_format")
	})

	// Row 2: a decoded entity whose content_hash does not match {type,data}
	// → 400 hash_mismatch (distinct from the 409 CAS race).
	r.Run("put_hash_mismatch_400_hash_mismatch", func() CheckOutcome {
		d1, _ := ecf.Encode(map[string]string{"v": "1"})
		e1, err := entity.NewEntity("system/validate/tree-put-err", cbor.RawMessage(d1))
		if err != nil {
			return FailCheck("build entity: " + err.Error())
		}
		d2, _ := ecf.Encode(map[string]string{"v": "2"})
		e2, _ := entity.NewEntity("system/validate/tree-put-err", cbor.RawMessage(d2))
		e1.ContentHash = e2.ContentHash // now claims a hash that does not match its own {type,data}
		params, resource, err := tree.CreatePutRequest(base+"/hashmismatch", &e1)
		if err != nil {
			return FailCheck("build tampered put: " + err.Error())
		}
		status, code, err := sendPut(params, resource)
		if err != nil {
			return FailCheck("tampered-hash put send/recv: " + err.Error())
		}
		if status != 400 || code != "hash_mismatch" {
			return FailCheck(fmt.Sprintf("content-hash mismatch answered %d/%q, want 400/hash_mismatch (EXTENSION-TREE Appendix A put row 2; = EXTENSION-CONTENT §923)", status, code))
		}
		return PassCheck("content-hash mismatch → 400/hash_mismatch")
	})

	// Row 3: a CAS expected_hash that loses the race → 409 hash_mismatch. The
	// existing cas_mismatch check asserts only the 409 STATUS; this asserts the
	// CODE, which is the row's actual content.
	r.Run("put_cas_race_409_hash_mismatch", func() CheckOutcome {
		// Seed a real binding so a stale expected_hash can lose to it.
		seedData, _ := ecf.Encode(map[string]string{"v": "seed"})
		seed, err := entity.NewEntity("system/validate/tree-put-err", cbor.RawMessage(seedData))
		if err != nil {
			return FailCheck("build seed entity: " + err.Error())
		}
		casPath := base + "/casrace"
		if _, err := client.TreePut(ctx, casPath, seed); err != nil {
			return FailCheck("seed put for CAS race: " + err.Error())
		}
		// A different (stale) expected_hash: the seed's own data hashed under a
		// different value — reuse a second entity's hash as the wrong expectation.
		staleData, _ := ecf.Encode(map[string]string{"v": "stale"})
		stale, _ := entity.NewEntity("system/validate/tree-put-err", cbor.RawMessage(staleData))
		updateData, _ := ecf.Encode(map[string]string{"v": "update"})
		update, _ := entity.NewEntity("system/validate/tree-put-err", cbor.RawMessage(updateData))
		params, resource, err := tree.CreatePutRequestCAS(casPath, &update, &stale.ContentHash)
		if err != nil {
			return FailCheck("build CAS put: " + err.Error())
		}
		status, code, err := sendPut(params, resource)
		if err != nil {
			return FailCheck("CAS-race put send/recv: " + err.Error())
		}
		if status != 409 || code != "hash_mismatch" {
			return FailCheck(fmt.Sprintf("stale expected_hash answered %d/%q, want 409/hash_mismatch (EXTENSION-TREE Appendix A put row 3; V7 §3.6)", status, code))
		}
		return PassCheck("stale expected_hash → 409/hash_mismatch")
	})

	return r.Results()
}
