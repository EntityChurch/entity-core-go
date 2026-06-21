package types

import (
	"testing"

	"go.entitychurch.org/entity-core-go/core/hash"

	"github.com/fxamacker/cbor/v2"
)

func TestContinuationRoundtrip(t *testing.T) {
	remaining := uint64(1)
	d := ContinuationData{
		Target:    "system/tree",
		Operation: "put",
		Resource:  &ResourceTarget{Targets: []string{"local/data/output"}},
		Params:    cbor.RawMessage([]byte{0xA0}), // empty map
		ResultTransform: &ContinuationTransformData{
			Extract: "data.metrics.score",
		},
		ResultField:         "score",
		OnError:             &DeliverySpec{URI: "system/inbox/error-handler", Operation: "receive"},
		RemainingExecutions: &remaining,
	}
	e, err := d.ToEntity()
	if err != nil {
		t.Fatal(err)
	}
	if e.Type != TypeContinuation {
		t.Fatalf("expected type %s, got %s", TypeContinuation, e.Type)
	}

	decoded, err := ContinuationDataFromEntity(e)
	if err != nil {
		t.Fatal(err)
	}
	if decoded.Target != "system/tree" {
		t.Fatalf("Target: expected system/tree, got %s", decoded.Target)
	}
	if decoded.Operation != "put" {
		t.Fatalf("Operation: expected put, got %s", decoded.Operation)
	}
	if decoded.ResultField != "score" {
		t.Fatalf("ResultField: expected score, got %s", decoded.ResultField)
	}
	if decoded.RemainingExecutions == nil || *decoded.RemainingExecutions != 1 {
		t.Fatalf("RemainingExecutions: expected 1, got %v", decoded.RemainingExecutions)
	}
	if decoded.ResultTransform == nil {
		t.Fatal("ResultTransform: expected non-nil")
	}
	if decoded.ResultTransform.Extract != "data.metrics.score" {
		t.Fatalf("ResultTransform.Extract: expected data.metrics.score, got %s", decoded.ResultTransform.Extract)
	}
	if decoded.OnError == nil {
		t.Fatal("OnError: expected non-nil")
	}
	if decoded.OnError.URI != "system/inbox/error-handler" {
		t.Fatalf("OnError.URI: expected system/inbox/error-handler, got %s", decoded.OnError.URI)
	}
}

func TestContinuationTransformRoundtrip(t *testing.T) {
	d := ContinuationTransformData{
		Extract: "result.data",
		Select:  map[string]string{"name": "user.name", "score": "metrics.total"},
	}
	e, err := d.ToEntity()
	if err != nil {
		t.Fatal(err)
	}
	if e.Type != TypeContinuationTransform {
		t.Fatalf("expected type %s, got %s", TypeContinuationTransform, e.Type)
	}

	decoded, err := ContinuationTransformDataFromEntity(e)
	if err != nil {
		t.Fatal(err)
	}
	if decoded.Extract != "result.data" {
		t.Fatalf("Extract: expected result.data, got %s", decoded.Extract)
	}
	if len(decoded.Select) != 2 {
		t.Fatalf("Select: expected 2 entries, got %d", len(decoded.Select))
	}
	if decoded.Select["name"] != "user.name" {
		t.Fatalf("Select[name]: expected user.name, got %s", decoded.Select["name"])
	}
}

func TestContinuationJoinRoundtrip(t *testing.T) {
	d := ContinuationJoinData{
		Expected:  []string{"left", "right"},
		Target:    "system/tree",
		Operation: "put",
		// nil RemainingExecutions = standing (unlimited)
	}
	e, err := d.ToEntity()
	if err != nil {
		t.Fatal(err)
	}
	if e.Type != TypeContinuationJoin {
		t.Fatalf("expected type %s, got %s", TypeContinuationJoin, e.Type)
	}

	decoded, err := ContinuationJoinDataFromEntity(e)
	if err != nil {
		t.Fatal(err)
	}
	if len(decoded.Expected) != 2 {
		t.Fatalf("Expected: expected 2 slots, got %d", len(decoded.Expected))
	}
	if decoded.Expected[0] != "left" || decoded.Expected[1] != "right" {
		t.Fatalf("Expected: got %v", decoded.Expected)
	}
	if decoded.RemainingExecutions != nil {
		t.Fatalf("RemainingExecutions: expected nil, got %v", decoded.RemainingExecutions)
	}
}

func TestContinuationJoinWithReceivedRoundtrip(t *testing.T) {
	remaining := uint64(1)
	d := ContinuationJoinData{
		Expected: []string{"a", "b"},
		Received: map[string]cbor.RawMessage{
			"a": cbor.RawMessage([]byte{0x63, 0x66, 0x6f, 0x6f}), // "foo"
		},
		Target:              "system/tree",
		Operation:           "put",
		RemainingExecutions: &remaining,
	}
	e, err := d.ToEntity()
	if err != nil {
		t.Fatal(err)
	}

	decoded, err := ContinuationJoinDataFromEntity(e)
	if err != nil {
		t.Fatal(err)
	}
	if len(decoded.Received) != 1 {
		t.Fatalf("Received: expected 1 entry, got %d", len(decoded.Received))
	}
	if _, ok := decoded.Received["a"]; !ok {
		t.Fatal("Received: missing key 'a'")
	}
}

func TestContinuationSuspendedRoundtrip(t *testing.T) {
	d := ContinuationSuspendedData{
		Target:         "system/tree",
		Operation:      "put",
		Reason:         "ttl_exhausted",
		ChainID:        "chain-abc",
		OriginalAuthor: hash.Hash{Algorithm: hash.AlgorithmSHA256},
		SuspendedAt:    1709500000000,
	}
	e, err := d.ToEntity()
	if err != nil {
		t.Fatal(err)
	}
	if e.Type != TypeContinuationSuspended {
		t.Fatalf("expected type %s, got %s", TypeContinuationSuspended, e.Type)
	}

	decoded, err := ContinuationSuspendedDataFromEntity(e)
	if err != nil {
		t.Fatal(err)
	}
	if decoded.Reason != "ttl_exhausted" {
		t.Fatalf("Reason: expected ttl_exhausted, got %s", decoded.Reason)
	}
	if decoded.ChainID != "chain-abc" {
		t.Fatalf("ChainID: expected chain-abc, got %s", decoded.ChainID)
	}
	if decoded.SuspendedAt != 1709500000000 {
		t.Fatalf("SuspendedAt: expected 1709500000000, got %d", decoded.SuspendedAt)
	}
}

func TestContinuationResumeRequestRoundtrip(t *testing.T) {
	ttl := uint64(10)
	d := ContinuationResumeRequestData{
		Bounds:     &BoundsData{TTL: &ttl},
		Resolution: cbor.RawMessage([]byte{0xA1, 0x64, 0x6D, 0x6F, 0x64, 0x65, 0x64, 0x66, 0x61, 0x73, 0x74}), // {"mode":"fast"}
	}
	e, err := d.ToEntity()
	if err != nil {
		t.Fatal(err)
	}
	if e.Type != TypeContinuationResumeRequest {
		t.Fatalf("expected type %s, got %s", TypeContinuationResumeRequest, e.Type)
	}

	decoded, err := ContinuationResumeRequestDataFromEntity(e)
	if err != nil {
		t.Fatal(err)
	}
	if decoded.Bounds == nil || decoded.Bounds.TTL == nil || *decoded.Bounds.TTL != 10 {
		t.Fatalf("Bounds.TTL: expected 10, got %v", decoded.Bounds)
	}
}

func TestContinuationAbandonRequestRoundtrip(t *testing.T) {
	d := ContinuationAbandonRequestData{}
	e, err := d.ToEntity()
	if err != nil {
		t.Fatal(err)
	}
	if e.Type != TypeContinuationAbandonRequest {
		t.Fatalf("expected type %s, got %s", TypeContinuationAbandonRequest, e.Type)
	}

	_, err = ContinuationAbandonRequestDataFromEntity(e)
	if err != nil {
		t.Fatal(err)
	}
}

func TestContinuationAdvanceRequestRoundtrip(t *testing.T) {
	status := uint(200)
	d := ContinuationAdvanceRequestData{
		Result: cbor.RawMessage([]byte{0xA0}), // empty map
		Status: &status,
	}
	e, err := d.ToEntity()
	if err != nil {
		t.Fatal(err)
	}
	if e.Type != TypeContinuationAdvanceRequest {
		t.Fatalf("expected type %s, got %s", TypeContinuationAdvanceRequest, e.Type)
	}

	decoded, err := ContinuationAdvanceRequestDataFromEntity(e)
	if err != nil {
		t.Fatal(err)
	}
	if decoded.Status == nil || *decoded.Status != 200 {
		t.Fatalf("Status: expected 200, got %v", decoded.Status)
	}
}
