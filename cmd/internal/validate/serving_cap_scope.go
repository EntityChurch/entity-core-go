package validate

import (
	"context"
	"fmt"
	"net/http"

	"github.com/fxamacker/cbor/v2"

	"go.entitychurch.org/entity-core-go/core/ecf"
	"go.entitychurch.org/entity-core-go/core/entity"
)

const catServingCapScope = "serving_cap_scope"

// runServingCapScope drives EXTENSION-NETWORK Amendment 5 §5A CapTokenScope on
// the HTTP serving face — the narrow-cap arm of the exclude matrix, one surface
// over from the live-EXECUTE checks in exclude_matrix.go. The served set is
// bracketed by a serve_scope CAPABILITY evaluated by the SAME
// capability.CheckPathPermission the live surface uses, so a cap EXCLUDE must
// filter the unauthenticated read face identically.
//
// This requires the peer started with
//
//	--serve-cap-scope "system/validate/served/*:system/validate/served/secret"
//
// i.e. the served tree subtree `served/*` MINUS `served/secret`. The category
// is therefore NOT in the default all-categories run (it needs a posture no
// other serving pass arms — see notInAnyRun); it runs in its own gate pass.
//
// The discriminating shape: an in-scope path served (200) PROVES the scope is
// not deny-all, so the excluded path's 404 is attributable to the cap EXCLUDE
// rather than to a peer that 404s everything. A peer in any OTHER serving
// posture (whole-store, a namespace covering both) answers 200/200 and FAILs
// `cap_scope_excluded_404` — which is correct, because this pass guarantees the
// cap-scope posture.
func runServingCapScope(ctx context.Context, client *PeerClient, pollURL string) []CheckResult {
	r := NewCheckRunner(catServingCapScope)

	r.Declare("seed", "EXTENSION-NETWORK §6.5.6 (Amendment 5 serve_scope-as-cap) — bind an in-scope and an excluded tree path via live tree:put")
	r.Declare("cap_scope_in_scope_served", "EXTENSION-NETWORK §6.5.6 (Amendment 5 serve_scope-as-cap) — an in-scope tree path under the serve_scope cap → 200 (scope is not deny-all)")
	r.Declare("cap_scope_excluded_404", "EXTENSION-NETWORK §6.5.6 T4 (Amendment 5 serve_scope-as-cap) — a path EXCLUDED by the serve_scope cap → 404 (the cap evaluator's exclude filters the read face, identical to not-held)")
	r.Declare("cap_scope_not_held_404", "EXTENSION-NETWORK Amendment 5 §6.5.3.1 — an in-scope but UNBOUND path → 404 (not-held; the substrate leg, distinct from the exclude leg)")

	peerID := string(client.RemotePeerID())
	urlTreeEntity := func(path string) string { return pollURL + "/" + peerID + "/" + path + servingModeLeafSuffix }

	servedBase := "system/validate/served"
	publicPath := servedBase + "/public"
	secretPath := servedBase + "/secret"
	ghostPath := servedBase + "/ghost" // in-scope but never bound

	mk := func(tag string) (entity.Entity, error) {
		raw, err := ecf.Encode(map[string]string{"served": tag})
		if err != nil {
			return entity.Entity{}, err
		}
		return entity.NewEntity("system/validate/served-marker", cbor.RawMessage(raw))
	}

	r.Run("seed", func() CheckOutcome {
		pub, err := mk("public")
		if err != nil {
			return FailCheck("build public marker: " + err.Error())
		}
		sec, err := mk("secret")
		if err != nil {
			return FailCheck("build secret marker: " + err.Error())
		}
		if _, err := client.TreePut(ctx, publicPath, pub); err != nil {
			return FailCheck("bind public: " + err.Error())
		}
		if _, err := client.TreePut(ctx, secretPath, sec); err != nil {
			return FailCheck("bind secret: " + err.Error())
		}
		return PassCheck(fmt.Sprintf("bound %s (in-scope) and %s (excluded)", publicPath, secretPath))
	})

	r.Run("cap_scope_in_scope_served", func() CheckOutcome {
		if out, ok := r.Require("seed"); !ok {
			return out
		}
		resp, _, err := httpGet(ctx, urlTreeEntity(publicPath))
		if err != nil {
			return FailCheck("GET in-scope tree path: " + err.Error())
		}
		if resp.StatusCode == http.StatusOK {
			return PassCheck("in-scope tree path under the serve_scope cap → 200 (scope is not deny-all)")
		}
		return FailCheck(fmt.Sprintf("in-scope tree path got %d, want 200 — the serve_scope cap does not cover its own include (url=%s); arm cap_scope_excluded_404 would be unattributable", resp.StatusCode, urlTreeEntity(publicPath)))
	})

	r.Run("cap_scope_excluded_404", func() CheckOutcome {
		if out, ok := r.Require("seed", "cap_scope_in_scope_served"); !ok {
			return out
		}
		resp, _, err := httpGet(ctx, urlTreeEntity(secretPath))
		if err != nil {
			return FailCheck("GET excluded tree path: " + err.Error())
		}
		if resp.StatusCode == http.StatusOK {
			return FailCheck("CAP-SCOPE FILTER FAIL: a tree path EXCLUDED by the serve_scope cap was served 200 — the serving face did not run the cap EXCLUDE (the in-scope path served 200, so this is not a deny-all; the exclude is simply not honored on the read face)")
		}
		if resp.StatusCode == http.StatusNotFound {
			return PassCheck("excluded tree path → 404 — the serve_scope cap's exclude filters the read face (identical to not-held, §6.5.6 T4), while the in-scope path serves 200")
		}
		return FailCheck(fmt.Sprintf("excluded tree path got %d, want 404 (not 200, so no disclosure, but not the mandated T4 status)", resp.StatusCode))
	})

	r.Run("cap_scope_not_held_404", func() CheckOutcome {
		if out, ok := r.Require("seed"); !ok {
			return out
		}
		resp, _, err := httpGet(ctx, urlTreeEntity(ghostPath))
		if err != nil {
			return FailCheck("GET unbound in-scope tree path: " + err.Error())
		}
		if resp.StatusCode == http.StatusNotFound {
			return PassCheck("in-scope but unbound tree path → 404 (not-held; the substrate leg)")
		}
		return FailCheck(fmt.Sprintf("unbound in-scope tree path got %d, want 404", resp.StatusCode))
	})

	return r.Results()
}
