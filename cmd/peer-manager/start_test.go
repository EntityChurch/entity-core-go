package main

import (
	"slices"
	"testing"
)

func TestParseKeepalive(t *testing.T) {
	tests := []struct {
		name    string
		spec    string
		want    keepaliveSpec
		wantErr bool
	}{
		{name: "empty", spec: "", want: keepaliveSpec{}},
		{name: "full triple", spec: "1500,800,2", want: keepaliveSpec{intervalMS: "1500", timeoutMS: "800", maxMissed: "2"}},
		{name: "spaces trimmed", spec: " 1500 , 800 , 2 ", want: keepaliveSpec{intervalMS: "1500", timeoutMS: "800", maxMissed: "2"}},
		// A field may be empty to keep its §2.3 spec default; all three impls
		// apply only the explicitly-set fields.
		{name: "partial: interval only", spec: "1500,,", want: keepaliveSpec{intervalMS: "1500"}},
		{name: "partial: max_missed only", spec: ",,2", want: keepaliveSpec{maxMissed: "2"}},
		{name: "zero is a value, not absence", spec: "0,0,0", want: keepaliveSpec{intervalMS: "0", timeoutMS: "0", maxMissed: "0"}},
		{name: "too few fields", spec: "1500,800", wantErr: true},
		{name: "too many fields", spec: "1500,800,2,9", wantErr: true},
		{name: "non-numeric", spec: "1500,abc,2", wantErr: true},
		{name: "negative", spec: "1500,-800,2", wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := parseKeepalive(tt.spec)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("parseKeepalive(%q) = %+v, want error", tt.spec, got)
				}
				return
			}
			if err != nil {
				t.Fatalf("parseKeepalive(%q): unexpected error: %v", tt.spec, err)
			}
			if got != tt.want {
				t.Errorf("parseKeepalive(%q) = %+v, want %+v", tt.spec, got, tt.want)
			}
		})
	}
}

func TestKeepaliveSpecEmpty(t *testing.T) {
	if !(keepaliveSpec{}).empty() {
		t.Error("zero keepaliveSpec should be empty")
	}
	if (keepaliveSpec{maxMissed: "2"}).empty() {
		t.Error("spec with any field set should not be empty")
	}
}

// The flag names are identical across impls; only the dash count differs.
// Go's stdlib flag takes -keepalive-interval-ms, Python's argparse takes
// --keepalive-interval-ms (Python 0a0eb48). Rust has no CLI surface, so it is
// dropped before reaching a renderer.
func TestKeepaliveSpecArgs(t *testing.T) {
	tests := []struct {
		name string
		ka   keepaliveSpec
		dash string
		want []string
	}{
		{
			name: "go dialect, full triple",
			ka:   keepaliveSpec{intervalMS: "1500", timeoutMS: "800", maxMissed: "2"},
			dash: "-",
			want: []string{"-keepalive-interval-ms", "1500", "-keepalive-timeout-ms", "800", "-keepalive-max-missed", "2"},
		},
		{
			name: "python dialect, full triple",
			ka:   keepaliveSpec{intervalMS: "1500", timeoutMS: "800", maxMissed: "2"},
			dash: "--",
			want: []string{"--keepalive-interval-ms", "1500", "--keepalive-timeout-ms", "800", "--keepalive-max-missed", "2"},
		},
		{
			name: "python dialect, partial omits unset fields",
			ka:   keepaliveSpec{intervalMS: "1500"},
			dash: "--",
			want: []string{"--keepalive-interval-ms", "1500"},
		},
		{
			name: "empty spec renders no args",
			ka:   keepaliveSpec{},
			dash: "--",
			want: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.ka.args(tt.dash)
			if !slices.Equal(got, tt.want) {
				t.Errorf("args(%q) = %v, want %v", tt.dash, got, tt.want)
			}
		})
	}
}
