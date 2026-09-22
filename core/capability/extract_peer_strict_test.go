package capability

import (
	"testing"

	"go.entitychurch.org/entity-core-go/core/crypto"
)

// TestExtractPeerStrict pins that the strict extractor returns a peer ONLY when
// the locator carries one, and never substitutes the local peer (unlike
// ExtractPeer). It is what lets a chain-error `lost` marker record the target
// peer for an entity:// URI and leave it absent for a bare handler path (row 17).
func TestExtractPeerStrict(t *testing.T) {
	kp, err := crypto.Generate()
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	peer := string(kp.PeerID())

	cases := []struct {
		locator  string
		wantPeer string
		wantOK   bool
	}{
		{"entity://" + peer + "/system/revision", peer, true},
		{"/" + peer + "/system/tree/x", peer, true},
		{"system/network", "", false},          // bare handler path — no peer
		{"", "", false},                        // empty
		{"system/tree/root/prefix", "", false}, // path segments, none a peer id
	}
	for _, c := range cases {
		gotPeer, gotOK := ExtractPeerStrict(c.locator)
		if gotOK != c.wantOK || string(gotPeer) != c.wantPeer {
			t.Errorf("ExtractPeerStrict(%q) = (%q, %v), want (%q, %v)",
				c.locator, gotPeer, gotOK, c.wantPeer, c.wantOK)
		}
	}
}
