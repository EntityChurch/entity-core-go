package capability

import (
	"testing"

	"go.entitychurch.org/entity-core-go/core/crypto"
	"go.entitychurch.org/entity-core-go/core/entity"
	"go.entitychurch.org/entity-core-go/core/hash"
	"go.entitychurch.org/entity-core-go/core/types"
)

// TestMintReattenuatedShape verifies the C-3 mint helper produces the
// EXTENSION-CONTINUATION §4.2 case-3 shape: a chain ROOTED AT B's conferred
// authority with the installer in-chain as the re-attenuation leaf granter.
// This is exactly what makes both gates pass — B's advance-time VerifyChain
// (B-rooted) and the install-time in-chain check (§3.1a, installer in-chain)
// — and is NOT a chain rooted at the installer (the cross-peer-breaking
// shape the spec warns about).
func TestMintReattenuatedShape(t *testing.T) {
	bKP, _ := crypto.Generate()    // target peer B
	instKP, _ := crypto.Generate() // installer (caller/admin)
	hostKP, _ := crypto.Generate() // dispatching host peer A (EXECUTE author)
	bID, _ := bKP.IdentityEntity()
	instID, _ := instKP.IdentityEntity()
	hostID, _ := hostKP.IdentityEntity()

	included := map[hash.Hash]entity.Entity{
		bID.ContentHash:    bID,
		instID.ContentHash: instID,
		hostID.ContentHash: hostID,
	}

	// B confers authority on the installer (the connection grant): granter=B,
	// grantee=installer, no parent → B-rooted root.
	connCap := buildCap(t, bID.ContentHash, instID.ContentHash, nil, included)

	attenuated := []types.GrantEntry{{
		Handlers:   types.CapabilityScope{Include: []string{"system/tree"}},
		Resources:  types.CapabilityScope{Include: []string{"peer_b/data/shared/*"}},
		Operations: types.CapabilityScope{Include: []string{"put"}},
	}}
	// v1.11 §4.2 case 3 (iii): grantee = the dispatching host peer, NOT the
	// installer (self-wielding is the closed gap).
	capEnt, sigEnt, err := MintReattenuated(instKP, instID, hostID.ContentHash, connCap, attenuated, 2000, nil)
	if err != nil {
		t.Fatalf("MintReattenuated: %v", err)
	}

	// (iii): the minted cap's grantee MUST be the host peer (EXECUTE
	// author), and MUST NOT be self-wielded to the installer.
	leafData, _ := types.CapabilityTokenDataFromEntity(capEnt)
	if leafData.Grantee != hostID.ContentHash {
		t.Fatal("grantee MUST be the dispatching host peer (§4.2 case 3 (iii))")
	}
	if leafData.Grantee == instID.ContentHash {
		t.Fatal("grantee MUST NOT be the installer (the v1.9 self-wielded gap → `grantee != author` at B)")
	}
	included[capEnt.ContentHash] = capEnt
	included[sigEnt.ContentHash] = sigEnt

	// Chain: leaf (minted) -> connCap (B-rooted root).
	chain, err := CollectAuthorityChain(capEnt, IncludedResolver(included))
	if err != nil {
		t.Fatalf("CollectAuthorityChain: %v", err)
	}
	if len(chain) != 2 {
		t.Fatalf("expected chain length 2 (leaf -> B root), got %d", len(chain))
	}
	if chain[0].ContentHash != capEnt.ContentHash {
		t.Fatal("chain[0] must be the minted leaf cap")
	}
	if chain[len(chain)-1].ContentHash != connCap.ContentHash {
		t.Fatal("chain root must be the B-conferred connection cap")
	}

	rootData, _ := types.CapabilityTokenDataFromEntity(chain[len(chain)-1])
	rootGranter, _ := rootData.Granter.SingleHash()
	if rootGranter != bID.ContentHash {
		t.Fatal("chain MUST be rooted at B's conferred authority (root granter != B)")
	}
	if rootGranter == instID.ContentHash {
		t.Fatal("chain MUST NOT be rooted at the installer (the cross-peer-breaking shape)")
	}

	// Installer is in-chain as the leaf granter → the §3.1a install-time
	// in-chain check passes (writer/installer appears as a granter).
	resolver := IncludedResolver(included)
	found, _, err := CheckCreatorAuthority(capEnt, instID.ContentHash, resolver,
		IncludedSignatureResolver(included))
	if err != nil {
		t.Fatalf("CheckCreatorAuthority(installer): %v", err)
	}
	if !found {
		t.Fatal("installer MUST be in-chain (leaf granter) so the §3.1a install check passes")
	}

	// And B (root granter) is also in-chain — sanity on the B-rooted end.
	foundB, _, err := CheckCreatorAuthority(capEnt, bID.ContentHash, resolver,
		IncludedSignatureResolver(included))
	if err != nil {
		t.Fatalf("CheckCreatorAuthority(B): %v", err)
	}
	if !foundB {
		t.Fatal("B (root granter) must be in-chain")
	}
}

func TestMintReattenuatedRejectsBadInput(t *testing.T) {
	instKP, _ := crypto.Generate()
	instID, _ := instKP.IdentityEntity()
	hostKP, _ := crypto.Generate()
	hostID, _ := hostKP.IdentityEntity()
	g := []types.GrantEntry{{Operations: types.CapabilityScope{Include: []string{"put"}}}}

	if _, _, err := MintReattenuated(instKP, instID, hostID.ContentHash, entity.Entity{}, g, 1, nil); err == nil {
		t.Fatal("expected error when parent cap is zero (no B-recognized anchor)")
	}
	parent, _ := types.CapabilityTokenData{
		Granter: types.SingleSigGranter(instID.ContentHash), Grantee: instID.ContentHash, CreatedAt: 1,
	}.ToEntity()
	if _, _, err := MintReattenuated(instKP, instID, hostID.ContentHash, parent, nil, 1, nil); err == nil {
		t.Fatal("expected error when grants is empty")
	}
	if _, _, err := MintReattenuated(instKP, instID, hash.Hash{}, parent, g, 1, nil); err == nil {
		t.Fatal("expected error when grantee is zero (§4.2 case 3 (iii) requires the dispatching host peer)")
	}
}
