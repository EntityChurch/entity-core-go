package continuation

import (
	"context"
	"path"
	"strings"
	"testing"

	"go.entitychurch.org/entity-core-go/core/entity"
	"go.entitychurch.org/entity-core-go/core/handler"
	"go.entitychurch.org/entity-core-go/core/types"
)

// The §3.10 marker path interpolates three values that a REMOTE chooses:
//
//	system/runtime/chain-errors/lost/{chain_id}/{step_index}/{reason}/{marker_hash}
//
// {chain_id} is bounds.chain_id off the inbound EXECUTE, {step_index} is its
// request_id, and {reason} is the target handler's error code. Each MUST be
// exactly one segment.
//
// The escape is not the leading-"../" form CleanPath rejects: interpolated
// values land in the MIDDLE of the path, and path.Clean RESOLVES an interior
// "..", walking the marker back out of the chain-errors subtree. A request_id
// of "../../../../authority/keys" put the marker at system/authority/keys/…
// once cleaned; via bounds.chain_id it left system/ entirely. Values are
// stored literally today, so nothing normalizes them at bind time — this test
// pins the containment at the source rather than relying on that.
//
// Asserted on the CLEANED path: the literal form is only safe for as long as
// nothing cleans it, and "system/…/lost/{X}/.." is inside the sink by string
// prefix while naming somewhere else entirely.
func TestLostMarkerContainsHostileWireSuppliedSegments(t *testing.T) {
	const escape = "../../../../authority/keys"
	const sink = "system/runtime/chain-errors/lost/"

	cases := []struct {
		name      string
		requestID string
		chainID   string
		code      string
	}{
		{"step_index carries request_id", escape, "", "handler_said_no"},
		{"reason carries the handler's code", "req-1", "", escape},
		{"chain_id carries bounds.chain_id", "req-1", escape, "handler_said_no"},
		{"segment is a bare dot-dot", "..", "", "handler_said_no"},
		{"segment merely forks the tree", "a/b/c", "", "handler_said_no"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h := NewHandler()
			hctx := newTestContext()
			hctx.RequestID = tc.requestID
			if tc.chainID != "" {
				hctx.Bounds = &types.BoundsData{ChainID: tc.chainID}
			}
			code := tc.code
			hctx.Execute = func(ctx context.Context, uri, op string, params entity.Entity, opts ...handler.ExecuteOption) (*handler.Response, error) {
				ed, _ := types.ErrorData{Code: code}.ToEntity()
				return &handler.Response{Status: 500, Result: ed}, nil
			}

			remaining := uint64(1)
			capHash := testCapHash(t, hctx.Store)
			storeContinuation(t, hctx, "system/inbox/fwd", types.ContinuationData{
				Target:              "system/tree",
				Operation:           "put",
				RemainingExecutions: &remaining,
				DispatchCapability:  capHash,
			})

			if _, err := h.Handle(context.Background(),
				makeAdvanceRequest(t, hctx, "system/inbox/fwd", 200, "payload")); err != nil {
				t.Fatalf("advance returned an error: %v", err)
			}

			bound := 0
			for _, e := range hctx.LocationIndex.List("system/") {
				p := strings.TrimPrefix(e.Path, "/")
				if !strings.Contains(p, "chain-errors") {
					continue
				}
				bound++
				if cleaned := path.Clean(p); !strings.HasPrefix(cleaned, sink) {
					t.Errorf("marker escaped the chain-errors sink\n  bound at: %s\n  resolves: %s\n  want under: %s",
						p, cleaned, sink)
				}
				// Containment is necessary but not sufficient: the coordinate
				// must still be the ruled 4-level shape, or a hostile value
				// forks the marker tree without leaving the sink.
				rest := strings.TrimPrefix(path.Clean(p), sink)
				if got := len(strings.Split(rest, "/")); got != 4 {
					t.Errorf("marker coordinate is %d segments below the sink, want 4 ({chain_id}/{step_index}/{reason}/{marker_hash}): %s",
						got, p)
				}
			}
			if bound != 1 {
				t.Fatalf("expected exactly 1 chain-error marker, got %d", bound)
			}
		})
	}
}
