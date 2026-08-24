package main

import (
	"reflect"
	"testing"
)

// TestPartitionByOwner pins the rule that came out of the 2026-08-12 incident:
// one host, one state file, three sessions driving it — so `stop --all` must
// never reach a peer this session did not start. A core-rust session's
// `stop --all` took out core-py's `pyf1` mid-run; the peers are cheap, but a
// validation run that loses its counterpart halfway reports a conformance
// failure rather than an error, which is the expensive part.
func TestPartitionByOwner(t *testing.T) {
	state := &State{Peers: map[string]*PeerEntry{
		"gof1": {Name: "gof1", Owner: "go"},
		"rsf1": {Name: "rsf1", Owner: "rust"},
		"pyf1": {Name: "pyf1", Owner: "py"},
		"v3py": {Name: "v3py", Owner: ""}, // started before Owner existed
	}}

	tests := []struct {
		name       string
		me         string
		anyOwner   bool
		wantMine   []string
		wantTheirs []string
	}{
		{
			name:       "a session claims only its own",
			me:         "rust",
			wantMine:   []string{"rsf1"},
			wantTheirs: []string{"gof1", "pyf1", "v3py"},
		},
		{
			// The incident, as a test: without an owner set, a session claims
			// NOTHING rather than everything. The old code's behaviour here was
			// to stop all four.
			name:       "an unattributed session claims nothing",
			me:         "",
			wantMine:   nil,
			wantTheirs: []string{"gof1", "pyf1", "rsf1", "v3py"},
		},
		{
			// Unattributed PEERS are never swept up by a matching owner either
			// — "no owner" is not "everyone's".
			name:       "an unattributed peer belongs to no session",
			me:         "go",
			wantMine:   []string{"gof1"},
			wantTheirs: []string{"pyf1", "rsf1", "v3py"},
		},
		{
			name:       "--any-owner is the explicit host-wide teardown",
			me:         "go",
			anyOwner:   true,
			wantMine:   []string{"gof1", "pyf1", "rsf1", "v3py"},
			wantTheirs: nil,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			mine, theirs := partitionByOwner(state, tc.me, tc.anyOwner)
			if !reflect.DeepEqual(mine, tc.wantMine) {
				t.Errorf("mine = %v, want %v", mine, tc.wantMine)
			}
			if !reflect.DeepEqual(theirs, tc.wantTheirs) {
				t.Errorf("theirs = %v, want %v", theirs, tc.wantTheirs)
			}
		})
	}
}
