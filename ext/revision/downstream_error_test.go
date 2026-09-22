package revision

import (
	"strings"
	"testing"

	"go.entitychurch.org/entity-core-go/core/handler"
	"go.entitychurch.org/entity-core-go/core/types"
)

// TestDownstreamErrorCarriesCode is the teeth for workbench-go tracker row 21:
// the revision:pull 502 wrapper used to render a failed remote response as
// `status=%d`, discarding the downstream `code`. A downstream
// `403 capability_denied` collapsed to the bare number `403`, and since the
// `lost` marker records THIS op's code (`remote_fetch_failed`), the true cause
// (an E1 denial) survived nowhere greppable — actively supporting the wrong
// conclusion. downstreamError carries the code (and message) verbatim.
//
// Mutation witness: revert downstreamError to `fmt.Sprintf("status=%d", ...)`
// and the "must contain the downstream code" assertion reds.
func TestDownstreamErrorCarriesCode(t *testing.T) {
	errEnt, err := types.ErrorData{Code: "capability_denied", Message: "no peers scope covering the target"}.ToEntity()
	if err != nil {
		t.Fatalf("build error entity: %v", err)
	}
	resp := &handler.Response{Status: 403, Result: errEnt}

	got := downstreamError(resp)
	if !strings.Contains(got, "capability_denied") {
		t.Fatalf("downstream 502 wrapper must carry the downstream CODE; got %q", got)
	}
	if !strings.Contains(got, "no peers scope covering the target") {
		t.Fatalf("downstream 502 wrapper should carry the downstream message; got %q", got)
	}
	if !strings.Contains(got, "403") {
		t.Fatalf("downstream wrapper should still carry the status; got %q", got)
	}

	// Control: a nil response is rendered, not panicked.
	if s := downstreamError(nil); s == "" {
		t.Fatal("nil response must render a non-empty string")
	}

	// Control: a non-error result (no system/protocol/error) falls back to status.
	plain := &handler.Response{Status: 502}
	if s := downstreamError(plain); !strings.Contains(s, "502") {
		t.Fatalf("non-error result should fall back to status; got %q", s)
	}
}
