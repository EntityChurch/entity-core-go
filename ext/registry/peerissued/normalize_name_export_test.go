package peerissued

import "testing"

// TestNormalizeNameExported pins the exported cross-impl name-normalization
// contract (workbench-go tracker row 6): NFC + §6.3 name-path safety, dots
// allowed, no case-fold. It exists so the contract is enforced through the
// exported surface a consumer actually calls.
func TestNormalizeNameExported(t *testing.T) {
	if got, err := NormalizeName("billslab.com"); err != nil || got != "billslab.com" {
		t.Fatalf("NormalizeName(\"billslab.com\") = (%q, %v), want (\"billslab.com\", nil)", got, err)
	}
	if _, err := NormalizeName("has/slash"); err == nil {
		t.Fatal("NormalizeName must reject a name containing '/' (§6.3 name-path safety)")
	}
	if _, err := NormalizeName(""); err == nil {
		t.Fatal("NormalizeName must reject an empty name")
	}
	// No case-fold: mixed case is preserved.
	if got, _ := NormalizeName("MixedCase"); got != "MixedCase" {
		t.Fatalf("NormalizeName must not case-fold; got %q", got)
	}
}
