package capability

import (
	"fmt"

	"go.entitychurch.org/entity-core-go/core/crypto"
	"go.entitychurch.org/entity-core-go/core/entity"
	"go.entitychurch.org/entity-core-go/core/hash"
	"go.entitychurch.org/entity-core-go/core/types"
)

// MintReattenuated mints a re-attenuated capability for cross-peer
// continuation dispatch (EXTENSION-CONTINUATION §4.2 case 3 / §8.2 C-3 —
// the SDK "re-attenuation mint helper").
//
// The minted cap's parent is `parent` — a capability the target peer B
// already recognizes, typically the connection grant B conferred on the
// installer at connect. `signer` (the installer) is the re-attenuation
// LEAF granter. `grantee` is the identity that will WIELD the cap — the
// continuation's dispatching host peer, which authors the dispatched
// EXECUTE (§4.2 case 3 (iii), v1.11). The resulting authority chain is:
//
//	leaf (granter=signer, grantee=grantee, parent=parent) → parent → … → root B recognizes
//
// i.e. rooted at B's conferred authority ((i)), installer in-chain as the
// re-attenuation leaf granter ((ii)), granted to the dispatching host peer
// ((iii)). That shape satisfies ALL THREE gates: B's advance-time
// VerifyChain incl. `grantee == EXECUTE author` (V7 §5.2 — chain B-rooted
// AND grantee is the host peer that signs the dispatch) and the
// install-time in-chain check (§3.1a — installer is a granter in the
// chain). `grantee` MUST be the dispatching host peer, NOT self-wielded to
// the installer: the installer is the caller/admin that set the
// continuation up, but the dispatcher is structurally the host peer (the
// only key the continuation handler holds). Self-wielding to the installer
// is the v1.9 gap Amendment 2 closes — B rejects `grantee != author`.
// Rooting the chain at the installer instead is the local sufficient
// condition only and is wrong cross-peer (B can't verify it).
//
// `grants` MUST be an attenuation of the parent's grants (the caller is
// responsible for narrowing scope; this helper does not re-validate
// attenuation — VerifyChain does that at B). `expiresAt` SHOULD inherit /
// not exceed the parent's expiry per V7 §5.6.
//
// Returns the cap entity and its detached signature. The caller stores both
// and bundles the full chain — use CollectAuthorityChain on the returned
// cap — into the dispatched envelope's `included` per §4.3 chain transport.
func MintReattenuated(
	signer crypto.Keypair,
	signerIdentity entity.Entity,
	grantee hash.Hash,
	parent entity.Entity,
	grants []types.GrantEntry,
	createdAt uint64,
	expiresAt *uint64,
) (capEnt entity.Entity, sigEnt entity.Entity, err error) {
	if parent.ContentHash.IsZero() {
		return entity.Entity{}, entity.Entity{}, fmt.Errorf("MintReattenuated: parent capability is required (the B-recognized root anchor)")
	}
	if grantee.IsZero() {
		return entity.Entity{}, entity.Entity{}, fmt.Errorf("MintReattenuated: grantee is required (the dispatching host peer / EXECUTE author — §4.2 case 3 (iii))")
	}
	if len(grants) == 0 {
		return entity.Entity{}, entity.Entity{}, fmt.Errorf("MintReattenuated: at least one grant entry is required")
	}

	parentHash := parent.ContentHash
	tokenData := types.CapabilityTokenData{
		Grants:  grants,
		Granter: types.SingleSigGranter(signerIdentity.ContentHash),
		// §4.2 case 3 (iii): the WIELDER is the dispatching host peer (the
		// EXECUTE author), NOT the installer. Self-wielding here is the
		// v1.9 gap that B rejects `grantee != author`.
		Grantee:   grantee,
		Parent:    &parentHash,
		CreatedAt: createdAt,
		ExpiresAt: expiresAt,
	}
	capEnt, err = tokenData.ToEntity()
	if err != nil {
		return entity.Entity{}, entity.Entity{}, fmt.Errorf("MintReattenuated: build cap entity: %w", err)
	}

	sig := signer.Sign(capEnt.ContentHash.Bytes())
	sigEnt, err = types.SignatureData{
		Target:    capEnt.ContentHash,
		Signer:    signerIdentity.ContentHash,
		Algorithm: crypto.KeyTypeString(signer.KeyType),
		Signature: sig,
	}.ToEntity()
	if err != nil {
		return entity.Entity{}, entity.Entity{}, fmt.Errorf("MintReattenuated: build signature entity: %w", err)
	}
	return capEnt, sigEnt, nil
}
