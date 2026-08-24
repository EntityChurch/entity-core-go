package signaling

import "testing"

// TestValidateReflectionEndpoint pins the RFC 7064 form EXTENSION-SIGNALING
// §4.5.1 requires (identical to EXTENSION-REGISTRY §3b.0): scheme stun:/stuns:,
// non-hierarchical (no //), host required, optional 1..65535 port.
func TestValidateReflectionEndpoint(t *testing.T) {
	valid := []string{
		"stun:stun.example.org",
		"stun:stun.example.org:3478",
		"stuns:stun.example.org:5349",
		"stun:1.2.3.4:3478",
		"stun:[2001:db8::1]",
		"stuns:[2001:db8::1]:5349",
	}
	for _, s := range valid {
		if err := ValidateReflectionEndpoint(s); err != nil {
			t.Errorf("ValidateReflectionEndpoint(%q) = %v, want nil", s, err)
		}
	}

	invalid := []string{
		"",                          // empty
		"stun.example.org:3478",     // bare host, no scheme
		"stun://stun.example.org",   // hierarchical — the // is forbidden
		"stuns://stun.example.org",  // hierarchical, tls scheme
		"http:stun.example.org",     // wrong scheme
		"turn:relay.example.org",    // turn is not served here (§3.3)
		"stun:",                     // scheme only, no host
		"stun::3478",                // port with no host
		"stun:stun.example.org:0",   // port out of range
		"stun:stun.example.org:70000",
		"stun:stun.example.org:abc", // non-numeric port
		"stun:[2001:db8::1",         // unterminated IPv6 literal
		"stun:[]:3478",              // empty IPv6 literal
		"stun:2001:db8::1",          // unbracketed IPv6 literal — must be [..] (rust correction, 2026-08-15-c)
		"stun:stun:relay.example:3478", // doubled scheme — §4.5.1's named failure mode (rust correction)
	}
	for _, s := range invalid {
		if err := ValidateReflectionEndpoint(s); err == nil {
			t.Errorf("ValidateReflectionEndpoint(%q) = nil, want error", s)
		}
	}
}
