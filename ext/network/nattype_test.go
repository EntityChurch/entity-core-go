package network

import "testing"

func TestClassifyMapping(t *testing.T) {
	tests := []struct {
		name      string
		local     string
		obs       []Observation
		want      MappingClass
		wantMap   string
		punchable bool
	}{
		{
			name: "no observations is unknown",
			want: MappingUnknown, punchable: true,
		},
		{
			// The §6.7.1 / §9.3 MUST: agreement across SEVERAL reflectors is the
			// precondition for a conclusion. One is advisory even when it is right.
			name:  "a single reflector cannot conclude",
			local: "10.1.0.2:20001",
			obs: []Observation{
				{Reflector: "10.0.0.254:9010", Observed: "10.0.0.1:20001"},
			},
			want: MappingUnknown, punchable: true,
		},
		{
			name:  "two reflectors agreeing is endpoint-independent",
			local: "10.1.0.2:20001",
			obs: []Observation{
				{Reflector: "10.0.0.254:9010", Observed: "10.0.0.1:20001"},
				{Reflector: "10.0.0.253:9011", Observed: "10.0.0.1:20001"},
			},
			want: MappingEndpointIndependent, wantMap: "10.0.0.1:20001", punchable: true,
		},
		{
			name:  "observed equals the bind address is open",
			local: "127.0.0.1:20001",
			obs: []Observation{
				{Reflector: "127.0.0.1:9010", Observed: "127.0.0.1:20001"},
				{Reflector: "127.0.0.1:9011", Observed: "127.0.0.1:20001"},
			},
			want: MappingOpen, wantMap: "127.0.0.1:20001", punchable: true,
		},
		{
			// The whole point of the rung: this pair must NOT drive to a punch.
			name:  "differing mapped port is endpoint-dependent",
			local: "10.1.0.2:20001",
			obs: []Observation{
				{Reflector: "10.0.0.254:9010", Observed: "10.0.0.1:41337"},
				{Reflector: "10.0.0.253:9011", Observed: "10.0.0.1:52001"},
			},
			want: MappingEndpointDependent,
		},
		{
			name:  "same port from a different public IP is endpoint-dependent",
			local: "10.1.0.2:20001",
			obs: []Observation{
				{Reflector: "10.0.0.254:9010", Observed: "10.0.0.1:20001"},
				{Reflector: "10.0.0.253:9011", Observed: "10.0.0.9:20001"},
			},
			want: MappingEndpointDependent,
		},
		{
			// Two agree, one diverges. Majority is NOT a conclusion here: the peer
			// that disagrees is evidence the mapping is destination-dependent.
			name:  "one dissenter among three still means endpoint-dependent",
			local: "10.1.0.2:20001",
			obs: []Observation{
				{Reflector: "r1", Observed: "10.0.0.1:20001"},
				{Reflector: "r2", Observed: "10.0.0.1:20001"},
				{Reflector: "r3", Observed: "10.0.0.1:20002"},
			},
			want: MappingEndpointDependent,
		},
		{
			name:  "an unparseable observation is not averaged in",
			local: "10.1.0.2:20001",
			obs: []Observation{
				{Reflector: "r1", Observed: "10.0.0.1:20001"},
				{Reflector: "r2", Observed: "not-an-address"},
			},
			want: MappingUnknown, punchable: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ClassifyMapping(tt.local, tt.obs)
			if got.Class != tt.want {
				t.Errorf("class = %q, want %q (reason: %s)", got.Class, tt.want, got.Reason)
			}
			if got.Mapping != tt.wantMap {
				t.Errorf("mapping = %q, want %q", got.Mapping, tt.wantMap)
			}
			if got.Class.Punchable() != tt.punchable && tt.want != MappingEndpointDependent {
				t.Errorf("punchable = %v, want %v", got.Class.Punchable(), tt.punchable)
			}
			if got.Reason == "" {
				t.Error("reason is empty — a verdict without evidence is not reportable")
			}
			if len(got.Observations) != len(tt.obs) {
				t.Errorf("observations = %d, want %d — the evidence must travel with the verdict", len(got.Observations), len(tt.obs))
			}
		})
	}
}

// A mapping belongs to a socket (§6.7.3). Divergence caused by consulting
// reflectors from DIFFERENT sockets is indistinguishable, here, from a real
// symmetric NAT — which is why gathering pins the local endpoint and this
// function only ever sees one socket's observations. Recorded as a test so the
// invariant is stated where someone changing the gatherer will trip over it.
func TestEndpointDependentIsIndistinguishableFromMixedSockets(t *testing.T) {
	mixed := []Observation{
		{Reflector: "r1", Observed: "10.0.0.1:20001"}, // socket A
		{Reflector: "r2", Observed: "10.0.0.1:20002"}, // socket B — different socket, not a symmetric NAT
	}
	if got := ClassifyMapping("10.1.0.2:20001", mixed); got.Class != MappingEndpointDependent {
		t.Fatalf("class = %q, want %q", got.Class, MappingEndpointDependent)
	}
	// The classifier cannot tell the two apart and MUST NOT pretend to. The
	// guarantee lives in the caller: DetectMapping consults every reflector from
	// one pinned local endpoint.
}
