package revision

import (
	"context"
	"strings"
	"testing"

	"go.entitychurch.org/entity-core-go/core/ecf"
	"go.entitychurch.org/entity-core-go/core/entity"
	"go.entitychurch.org/entity-core-go/core/handler"
	"go.entitychurch.org/entity-core-go/core/hash"
	"go.entitychurch.org/entity-core-go/core/types"

	"github.com/fxamacker/cbor/v2"
)

// makeMergeConfigRequest builds a request for the merge-config op. Distinct
// from makeRequest because the params entity type is
// system/revision/merge-config-params (not the suffix-derived form
// makeRequest uses).
func makeMergeConfigRequest(t *testing.T, hctx *handler.HandlerContext, params types.RevisionMergeConfigParamsData) *handler.Request {
	t.Helper()
	raw, err := ecf.Encode(params)
	if err != nil {
		t.Fatal(err)
	}
	paramsEntity, err := entity.NewEntity(types.TypeRevisionMergeConfigParams, cbor.RawMessage(raw))
	if err != nil {
		t.Fatal(err)
	}
	return &handler.Request{
		Operation: "merge-config",
		Params:    paramsEntity,
		Context:   hctx,
	}
}

func decodeMergeConfigResult(t *testing.T, resp *handler.Response) types.RevisionMergeConfigResultData {
	t.Helper()
	var result types.RevisionMergeConfigResultData
	if err := ecf.Decode(resp.Result.Data, &result); err != nil {
		t.Fatalf("decode merge-config result: %v", err)
	}
	return result
}

// EXTENSION-REVISION v3.3 §4.4.18 conformance vector
// `merge_config_set_rejects_deletion_resolution_lww`: action=set,
// config.deletion_resolution="lww" → 400 invalid_strategy; no binding lands.
func TestMergeConfig_RejectsDeletionResolutionLww(t *testing.T) {
	h := NewHandler()
	hctx := newTestContext()

	req := makeMergeConfigRequest(t, hctx, types.RevisionMergeConfigParamsData{
		Scope:  "path",
		Name:   "docs/*",
		Action: "set",
		Config: &types.RevisionMergeConfigData{
			Pattern:            "docs/*",
			Strategy:           "three-way",
			DeletionResolution: "lww",
		},
	})
	resp, err := h.Handle(context.Background(), req)
	if err != nil {
		t.Fatal(err)
	}
	if resp.Status != 400 {
		t.Fatalf("status: got %d, want 400", resp.Status)
	}
	var errData types.ErrorData
	if err := ecf.Decode(resp.Result.Data, &errData); err != nil {
		t.Fatalf("decode error: %v", err)
	}
	if errData.Code != "invalid_strategy" {
		t.Fatalf("error code: got %q, want invalid_strategy", errData.Code)
	}
	if _, ok := hctx.LocationIndex.Get("system/revision/config/merge/path/docs/*"); ok {
		t.Fatal("rejected merge-config must NOT bind a path")
	}
}

// `merge_config_set_rejects_deletion_resolution_keep_both`.
func TestMergeConfig_RejectsDeletionResolutionKeepBoth(t *testing.T) {
	h := NewHandler()
	hctx := newTestContext()

	req := makeMergeConfigRequest(t, hctx, types.RevisionMergeConfigParamsData{
		Scope:  "path",
		Name:   "docs/*",
		Action: "set",
		Config: &types.RevisionMergeConfigData{
			Pattern:            "docs/*",
			Strategy:           "three-way",
			DeletionResolution: "keep-both",
		},
	})
	resp, err := h.Handle(context.Background(), req)
	if err != nil {
		t.Fatal(err)
	}
	if resp.Status != 400 {
		t.Fatalf("status: got %d, want 400", resp.Status)
	}
	var errData types.ErrorData
	_ = ecf.Decode(resp.Result.Data, &errData)
	if errData.Code != "invalid_strategy" {
		t.Fatalf("error code: got %q, want invalid_strategy", errData.Code)
	}
}

// `merge_config_set_accepts_valid_deletion_resolution`: all four valid
// strategies bind successfully.
func TestMergeConfig_AcceptsValidDeletionResolution(t *testing.T) {
	h := NewHandler()
	for _, strategy := range []string{
		"preserve-on-conflict",
		"deletion-wins",
		"three-way-fallthrough",
		"deterministic",
	} {
		t.Run(strategy, func(t *testing.T) {
			hctx := newTestContext()
			req := makeMergeConfigRequest(t, hctx, types.RevisionMergeConfigParamsData{
				Scope:  "path",
				Name:   "docs/*",
				Action: "set",
				Config: &types.RevisionMergeConfigData{
					Pattern:            "docs/*",
					Strategy:           "three-way",
					DeletionResolution: strategy,
				},
			})
			resp, err := h.Handle(context.Background(), req)
			if err != nil {
				t.Fatal(err)
			}
			if resp.Status != 200 {
				t.Fatalf("strategy %q: status %d, want 200", strategy, resp.Status)
			}
			result := decodeMergeConfigResult(t, resp)
			if result.Status != "set" {
				t.Fatalf("strategy %q: result status %q, want set", strategy, result.Status)
			}
			if _, ok := hctx.LocationIndex.Get("system/revision/config/merge/path/docs/*"); !ok {
				t.Fatalf("strategy %q: binding did not land", strategy)
			}
		})
	}
}

// `merge_config_set_idempotent`: re-issuing identical config returns no_change.
func TestMergeConfig_Idempotent(t *testing.T) {
	h := NewHandler()
	hctx := newTestContext()
	mkReq := func() *handler.Request {
		return makeMergeConfigRequest(t, hctx, types.RevisionMergeConfigParamsData{
			Scope:  "path",
			Name:   "docs/*",
			Action: "set",
			Config: &types.RevisionMergeConfigData{
				Pattern:            "docs/*",
				Strategy:           "three-way",
				DeletionResolution: "preserve-on-conflict",
			},
		})
	}

	resp1, err := h.Handle(context.Background(), mkReq())
	if err != nil || resp1.Status != 200 {
		t.Fatalf("first call: status=%d err=%v", resp1.Status, err)
	}
	r1 := decodeMergeConfigResult(t, resp1)
	if r1.Status != "set" {
		t.Fatalf("first call status %q, want set", r1.Status)
	}

	resp2, err := h.Handle(context.Background(), mkReq())
	if err != nil || resp2.Status != 200 {
		t.Fatalf("second call: status=%d err=%v", resp2.Status, err)
	}
	r2 := decodeMergeConfigResult(t, resp2)
	if r2.Status != "no_change" {
		t.Fatalf("second call status %q, want no_change", r2.Status)
	}
	if r2.Hash != r1.Hash {
		t.Fatalf("idempotent hashes diverged: %s vs %s", r1.Hash, r2.Hash)
	}
}

// `merge_config_cas_guard`: stale expected_hash → 409 stale_expected_hash;
// no binding written.
func TestMergeConfig_CASGuard(t *testing.T) {
	h := NewHandler()
	hctx := newTestContext()

	// Initial write.
	resp1, _ := h.Handle(context.Background(), makeMergeConfigRequest(t, hctx, types.RevisionMergeConfigParamsData{
		Scope:  "path", Name: "docs/*", Action: "set",
		Config: &types.RevisionMergeConfigData{Pattern: "docs/*", Strategy: "three-way", DeletionResolution: "preserve-on-conflict"},
	}))
	r1 := decodeMergeConfigResult(t, resp1)

	// Write again with stale expected_hash (zero hash, current is r1.Hash).
	stale := hash.Hash{}
	resp2, _ := h.Handle(context.Background(), makeMergeConfigRequest(t, hctx, types.RevisionMergeConfigParamsData{
		Scope: "path", Name: "docs/*", Action: "set",
		Config:       &types.RevisionMergeConfigData{Pattern: "docs/*", Strategy: "three-way", DeletionResolution: "deletion-wins"},
		ExpectedHash: &stale,
	}))
	if resp2.Status != 409 {
		t.Fatalf("stale CAS: status %d, want 409", resp2.Status)
	}
	var errData types.ErrorData
	_ = ecf.Decode(resp2.Result.Data, &errData)
	if errData.Code != "stale_expected_hash" {
		t.Fatalf("error code %q, want stale_expected_hash", errData.Code)
	}
	// Binding unchanged.
	current, _ := hctx.LocationIndex.Get("system/revision/config/merge/path/docs/*")
	if current != r1.Hash {
		t.Fatal("stale CAS must not modify binding")
	}
}

// `merge_config_delete`: action=delete unbinds the path; returns status=deleted.
func TestMergeConfig_Delete(t *testing.T) {
	h := NewHandler()
	hctx := newTestContext()

	// Set first.
	h.Handle(context.Background(), makeMergeConfigRequest(t, hctx, types.RevisionMergeConfigParamsData{
		Scope: "path", Name: "docs/*", Action: "set",
		Config: &types.RevisionMergeConfigData{Pattern: "docs/*", Strategy: "three-way", DeletionResolution: "preserve-on-conflict"},
	}))
	if _, ok := hctx.LocationIndex.Get("system/revision/config/merge/path/docs/*"); !ok {
		t.Fatal("setup: binding did not land")
	}

	// Delete.
	resp, err := h.Handle(context.Background(), makeMergeConfigRequest(t, hctx, types.RevisionMergeConfigParamsData{
		Scope: "path", Name: "docs/*", Action: "delete",
	}))
	if err != nil || resp.Status != 200 {
		t.Fatalf("delete: status=%d err=%v", resp.Status, err)
	}
	result := decodeMergeConfigResult(t, resp)
	if result.Status != "deleted" {
		t.Fatalf("delete status %q, want deleted", result.Status)
	}
	if _, ok := hctx.LocationIndex.Get("system/revision/config/merge/path/docs/*"); ok {
		t.Fatal("delete must unbind the path")
	}
}

// Verify type-scope path uses /type/ namespace.
func TestMergeConfig_TypeScope(t *testing.T) {
	h := NewHandler()
	hctx := newTestContext()

	resp, err := h.Handle(context.Background(), makeMergeConfigRequest(t, hctx, types.RevisionMergeConfigParamsData{
		Scope:  "type",
		Name:   "test/document",
		Action: "set",
		Config: &types.RevisionMergeConfigData{Pattern: "*", Strategy: "three-way", DeletionResolution: "deletion-wins"},
	}))
	if err != nil || resp.Status != 200 {
		t.Fatalf("type-scope set: status=%d err=%v", resp.Status, err)
	}
	result := decodeMergeConfigResult(t, resp)
	if !strings.Contains(result.Path, "/config/merge/type/test/document") {
		t.Fatalf("type-scope write_path %q does not contain expected segment", result.Path)
	}
}

// Invalid scope → 400.
func TestMergeConfig_InvalidScope(t *testing.T) {
	h := NewHandler()
	hctx := newTestContext()
	resp, _ := h.Handle(context.Background(), makeMergeConfigRequest(t, hctx, types.RevisionMergeConfigParamsData{
		Scope: "neither", Name: "x", Action: "set",
		Config: &types.RevisionMergeConfigData{Pattern: "*"},
	}))
	if resp.Status != 400 {
		t.Fatalf("invalid scope: status %d, want 400", resp.Status)
	}
}
