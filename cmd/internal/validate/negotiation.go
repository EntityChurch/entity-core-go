package validate

import (
	"context"
	"fmt"

	"go.entitychurch.org/entity-core-go/core/crypto"
	"go.entitychurch.org/entity-core-go/core/ecf"
	"go.entitychurch.org/entity-core-go/core/entity"
	"go.entitychurch.org/entity-core-go/core/hash"
	"go.entitychurch.org/entity-core-go/core/types"

	"github.com/fxamacker/cbor/v2"
)

// catNegotiation is the V7 v7.69 §4.5/§4.5a hello-negotiation conformance
// category. Two vectors:
//
//   - NEGOTIATE-FORMAT-1: hash_formats is a single-active-value field. A
//     conformant peer advertises non-empty hash_formats including
//     "ecfv1-sha256" (the §4.5 default floor); a disjoint client
//     advertisement MUST be rejected at hello with 400
//     incompatible_hash_format.
//
//   - NEGOTIATE-KEYTYPE-1: key_types is an accept-set (identity-bound).
//     A conformant peer advertises non-empty key_types including
//     "ed25519" (the §4.5 default floor); a client whose own key_type
//     is absent from the responder's set, OR whose advertised set
//     excludes the responder's own key_type, MUST be rejected with
//     400 unsupported_key_type.
const catNegotiation = "negotiation"

func runNegotiation(ctx context.Context, client *PeerClient) []CheckResult {
	r := NewCheckRunner(catNegotiation)

	r.Declare("format_advertised",
		"V7 v7.69 §4.5 (NEGOTIATE-FORMAT-1 a: responder's hello carries a non-empty hash_formats list including ecfv1-sha256)")
	r.Declare("format_disjoint_reject",
		"V7 v7.69 §4.5 (NEGOTIATE-FORMAT-1 b: a hello advertising hash_formats with no overlap MUST be rejected with 400 incompatible_hash_format)")
	r.Declare("keytype_advertised",
		"V7 v7.69 §4.5 (NEGOTIATE-KEYTYPE-1 a: responder's hello carries a non-empty key_types accept-set including ed25519)")
	r.Declare("keytype_disjoint_reject",
		"V7 v7.69 §4.5 (NEGOTIATE-KEYTYPE-1 b: a hello whose key_types accept-set excludes the responder's own key_type MUST be rejected with 400 unsupported_key_type)")

	// --- Sub-check: format_advertised + keytype_advertised ---
	//
	// Decode the hello-response captured during the suite's standard
	// PerformHandshake — that envelope is preserved on the client. The
	// responder's hello carries its advertised hash_formats and key_types
	// sets (per §4.5 the two negotiated fields a v7.69 peer SHALL
	// populate).
	r.Run("format_advertised", func() CheckOutcome {
		var helloEnt entity.Entity
		respData, err := types.ExecuteResponseDataFromEntity(client.HelloResponseEnvelope.Root)
		if err != nil {
			return FailCheck(fmt.Sprintf("decode hello response: %v", err))
		}
		if err := ecf.Decode(respData.Result, &helloEnt); err != nil {
			return FailCheck(fmt.Sprintf("decode hello result entity: %v", err))
		}
		helloData, err := types.HelloDataFromEntity(helloEnt)
		if err != nil {
			return FailCheck(fmt.Sprintf("decode hello data: %v", err))
		}
		if len(helloData.HashFormats) == 0 {
			return FailCheck("NEGOTIATE-FORMAT-1 a FAIL: responder advertised no hash_formats (empty list)")
		}
		floorSeen := false
		for _, s := range helloData.HashFormats {
			if s == "ecfv1-sha256" {
				floorSeen = true
				break
			}
		}
		if !floorSeen {
			return FailCheck(fmt.Sprintf("NEGOTIATE-FORMAT-1 a FAIL: responder hash_formats %v does not include the §4.5 default floor \"ecfv1-sha256\"",
				helloData.HashFormats))
		}
		return PassCheck(fmt.Sprintf("NEGOTIATE-FORMAT-1 a: responder advertised hash_formats %v (includes \"ecfv1-sha256\" floor)",
			helloData.HashFormats))
	})

	r.Run("keytype_advertised", func() CheckOutcome {
		var helloEnt entity.Entity
		respData, err := types.ExecuteResponseDataFromEntity(client.HelloResponseEnvelope.Root)
		if err != nil {
			return FailCheck(fmt.Sprintf("decode hello response: %v", err))
		}
		if err := ecf.Decode(respData.Result, &helloEnt); err != nil {
			return FailCheck(fmt.Sprintf("decode hello result entity: %v", err))
		}
		helloData, err := types.HelloDataFromEntity(helloEnt)
		if err != nil {
			return FailCheck(fmt.Sprintf("decode hello data: %v", err))
		}
		if len(helloData.KeyTypes) == 0 {
			return FailCheck("NEGOTIATE-KEYTYPE-1 a FAIL: responder advertised no key_types accept-set (empty list)")
		}
		floorSeen := false
		for _, s := range helloData.KeyTypes {
			if s == "ed25519" {
				floorSeen = true
				break
			}
		}
		if !floorSeen {
			return FailCheck(fmt.Sprintf("NEGOTIATE-KEYTYPE-1 a FAIL: responder key_types %v does not include the §4.5 default floor \"ed25519\"",
				helloData.KeyTypes))
		}
		return PassCheck(fmt.Sprintf("NEGOTIATE-KEYTYPE-1 a: responder advertised key_types %v (includes \"ed25519\" floor)",
			helloData.KeyTypes))
	})

	// --- Sub-check: format_disjoint_reject ---
	//
	// Open a fresh transport connection to the target and send a custom
	// hello whose hash_formats list contains only a fabricated value the
	// peer cannot possibly support. Expect 400 incompatible_hash_format.
	r.Run("format_disjoint_reject", func() CheckOutcome {
		status, code, err := attemptHelloWithAdvertisedSets(
			ctx, client.Addr(),
			[]string{"ecfv1-fake-disjoint-format"}, // disjoint hash_formats
			nil,                                    // default key_types
		)
		if err != nil {
			return FailCheck(fmt.Sprintf("NEGOTIATE-FORMAT-1 b FAIL: hello round-trip errored: %v", err))
		}
		if status != 400 || code != "incompatible_hash_format" {
			return FailCheck(fmt.Sprintf("NEGOTIATE-FORMAT-1 b FAIL: disjoint hash_formats hello returned status=%d code=%q; want 400 incompatible_hash_format (V7 v7.69 §4.5)",
				status, code))
		}
		return PassCheck("NEGOTIATE-FORMAT-1 b: disjoint hash_formats hello rejected with 400 incompatible_hash_format")
	})

	// --- Sub-check: keytype_disjoint_reject ---
	r.Run("keytype_disjoint_reject", func() CheckOutcome {
		status, code, err := attemptHelloWithAdvertisedSets(
			ctx, client.Addr(),
			nil,                                  // default hash_formats
			[]string{"fake-disjoint-key-type"},   // disjoint key_types — excludes responder's own
		)
		if err != nil {
			return FailCheck(fmt.Sprintf("NEGOTIATE-KEYTYPE-1 b FAIL: hello round-trip errored: %v", err))
		}
		if status != 400 || code != "unsupported_key_type" {
			return FailCheck(fmt.Sprintf("NEGOTIATE-KEYTYPE-1 b FAIL: disjoint key_types hello returned status=%d code=%q; want 400 unsupported_key_type (V7 v7.69 §4.5)",
				status, code))
		}
		return PassCheck("NEGOTIATE-KEYTYPE-1 b: disjoint key_types hello rejected with 400 unsupported_key_type")
	})

	return r.Results()
}

// attemptHelloWithAdvertisedSets opens a fresh transport connection to
// addr, constructs a single-shot hello whose hash_formats / key_types
// fields are the given overrides, sends it, decodes the response, and
// returns (status, code). nil values pass through the §4.5 default for
// that field on the v7.69 implementation. Used by NEGOTIATE-FORMAT-1 b
// and NEGOTIATE-KEYTYPE-1 b — the disjoint-set rejection cases.
func attemptHelloWithAdvertisedSets(ctx context.Context, addr string, hashFormats, keyTypes []string) (uint, string, error) {
	kp, err := crypto.Generate()
	if err != nil {
		return 0, "", fmt.Errorf("generate keypair: %w", err)
	}
	c, err := NewPeerClientWithKeypair(addr, kp)
	if err != nil {
		return 0, "", fmt.Errorf("new client: %w", err)
	}
	defer c.Close()
	if err := c.Connect(ctx); err != nil {
		return 0, "", fmt.Errorf("connect: %w", err)
	}

	helloData := types.HelloData{
		PeerID:      string(kp.PeerID()),
		Nonce:       make([]byte, 32),
		Protocols:   []string{"entity-core/1.0"},
		Timestamp:   0,
		HashFormats: hashFormats,
		KeyTypes:    keyTypes,
	}
	helloEnt, err := helloData.ToEntity()
	if err != nil {
		return 0, "", fmt.Errorf("hello ToEntity: %w", err)
	}
	helloParamsRaw, err := ecf.Encode(helloEnt)
	if err != nil {
		return 0, "", fmt.Errorf("encode hello params: %w", err)
	}
	helloExecData := types.ExecuteData{
		RequestID: "negotiate-disjoint-hello",
		URI:       "system/protocol/connect",
		Operation: "hello",
		Params:    cbor.RawMessage(helloParamsRaw),
	}
	helloExecEnt, err := helloExecData.ToEntity()
	if err != nil {
		return 0, "", fmt.Errorf("hello ExecuteData.ToEntity: %w", err)
	}
	helloEnv := entity.NewEnvelope(helloExecEnt, map[hash.Hash]entity.Entity{
		helloEnt.ContentHash: helloEnt,
	})
	if err := c.writeEnvelope(ctx, helloEnv); err != nil {
		return 0, "", fmt.Errorf("send hello: %w", err)
	}
	respBytes, err := c.readFrame(ctx)
	if err != nil {
		return 0, "", fmt.Errorf("read hello response: %w", err)
	}
	var respEnv entity.Envelope
	if err := ecf.Decode(respBytes, &respEnv); err != nil {
		return 0, "", fmt.Errorf("decode hello response: %w", err)
	}
	status, code, _, err := extractStatusAndCode(respEnv)
	if err != nil {
		return 0, "", err
	}
	return status, code, nil
}
