package handler

import (
	"testing"

	"go.entitychurch.org/entity-core-go/core/crypto"
	"go.entitychurch.org/entity-core-go/core/types"
)

const rsTestPeer = crypto.PeerID("2KZFtestpeerAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")

func rsCtx(res *types.ResourceTarget) *HandlerContext {
	return &HandlerContext{LocalPeerID: rsTestPeer, Resource: res}
}

// TestResourceSubjectCardinality pins §3.3's cardinality on the EFFECTIVE set
// (§5.2, 0.8.2.20) as resolved by the shared handler helper: empty →
// path_required, more than one → ambiguous_resource, a single pattern →
// malformed_resource, exactly one concrete → that path.
func TestResourceSubjectCardinality(t *testing.T) {
	p := "/" + string(rsTestPeer) + "/x"
	q := "/" + string(rsTestPeer) + "/y"
	pat := "/" + string(rsTestPeer) + "/sub/*"

	cases := []struct {
		name     string
		res      *types.ResourceTarget
		wantPath string
		wantCode string // "" means success
	}{
		{"nil", nil, "", "path_required"},
		{"empty", &types.ResourceTarget{}, "", "path_required"},
		{"self-excluded", &types.ResourceTarget{Targets: []string{p}, Exclude: []string{p}}, "", "path_required"},
		{"two", &types.ResourceTarget{Targets: []string{p, q}}, "", "ambiguous_resource"},
		{"pattern", &types.ResourceTarget{Targets: []string{pat}}, "", "malformed_resource"},
		{"one-concrete", &types.ResourceTarget{Targets: []string{p}}, p, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			path, resp := rsCtx(tc.res).ResourceSubject("op")
			if tc.wantCode == "" {
				if resp != nil {
					t.Fatalf("expected success, got response status %d", resp.Status)
				}
				if path != tc.wantPath {
					t.Fatalf("path = %q, want %q", path, tc.wantPath)
				}
				return
			}
			if resp == nil {
				t.Fatalf("expected %q error, got success path %q", tc.wantCode, path)
			}
			if resp.Status != 400 {
				t.Fatalf("expected 400, got %d", resp.Status)
			}
			ed, err := types.ErrorDataFromEntity(resp.Result)
			if err != nil {
				t.Fatalf("decode error entity: %v", err)
			}
			if ed.Code != tc.wantCode {
				t.Fatalf("code = %q, want %q", ed.Code, tc.wantCode)
			}
		})
	}
}

// TestResourceSubjectSelectsEffectiveNotTargetsZero is the F68 confused-selection
// teeth (case D): targets:[P,Q] exclude:[P] with Q the survivor MUST select Q,
// never P (Targets[0]). The cardinality passes either way (effective size 1), so
// this is the arm that catches a handler that counts the effective list and then
// indexes Targets[0]. Mutation: make ResourceSubject return Targets[0] and this
// reddens while the cardinality tests stay green.
func TestResourceSubjectSelectsEffectiveNotTargetsZero(t *testing.T) {
	p := "/" + string(rsTestPeer) + "/forbidden"
	q := "/" + string(rsTestPeer) + "/allowed"
	res := &types.ResourceTarget{Targets: []string{p, q}, Exclude: []string{p}}

	path, resp := rsCtx(res).ResourceSubject("op")
	if resp != nil {
		t.Fatalf("expected success (effective [Q] is size one), got status %d", resp.Status)
	}
	if path != q {
		t.Fatalf("subject = %q, want the survivor %q (never Targets[0] = %q)", path, q, p)
	}
}
