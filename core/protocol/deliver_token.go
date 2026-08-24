package protocol

import (
	"fmt"
	"time"

	"go.entitychurch.org/entity-core-go/core/crypto"
	"go.entitychurch.org/entity-core-go/core/entity"
	"go.entitychurch.org/entity-core-go/core/hash"
	"go.entitychurch.org/entity-core-go/core/types"
)

// The internal deliver_token — EXTENSION-CONTINUATION §4.2 Step 4, the second
// line:
//
//	execute.deliver_to    = continuation.data.deliver_to
//	execute.deliver_token = generate_internal_deliver_token(continuation.data.deliver_to)
//
// Go implemented the first line and not the second, for as long as cross-peer
// continuations have existed. The gap is invisible same-impl and fatal
// cross-impl, and the reason is worth keeping next to the fix.
//
// When a dispatched EXECUTE carries `deliver_to`, the peer that SERVICES it
// (B) authors the result delivery back to the requester (A). The far side runs
// V7 §5.2's `grantee == author` check on whatever capability that delivery
// presents, so B needs a cap naming B as grantee. Nothing in the request
// carried one: the remote branch passed `callerCtx.HandlerGrant`, which is the
// grant the CALLER holds — its grantee is the caller, never B.
//
// With no usable token, B has to improvise the delivery's authority, and the
// three implementations improvise differently:
//
//   - go's B sees a token that does not name it (`tokenGranteeIs` fails) and
//     falls back to the connection's session capability. On a dialed
//     connection that cap happens to be the one the far side granted us, so it
//     verifies — which is why go→go passed. async.go's own comment already
//     called this "works by accident."
//   - rust's B presents the inbound dispatch capability, whose grantee is A,
//     and authors as itself — so A refuses `403 capability_denied,
//     grantee != author`, and the result never lands.
//
// Neither peer is wrong. The dispatch was malformed at the source: it named a
// delivery it did not authorize. This mint is that missing authorization.
//
// Shape, per §4.2's authority table (the "result deliver_token" row): rooted
// at the installer (self-rooted here — we are the peer whose inbox receives
// the delivery, so we are the root), granted to the result-delivering peer
// (B's engine), scoped to exactly the one delivery — one handler, one
// resource path, one operation.
//
// mintDeliverToken returns the cap entity, its detached signature, and the
// local identity entity. All three MUST travel in the dispatched envelope's
// `included`: the far side walks cap → signature → granter identity, and a
// root cap with no signature is rejected `missing_signature` at the §5.5 chain
// walk.
//
// It refuses to mint — and the caller keeps the pre-existing behaviour — when
// the delivery target is not us. A peer cannot root authority over a third
// peer's inbox, and the §4.2 table does not ask it to: the token's root and
// the delivery's destination are the same seat by construction.
func (d *Dispatcher) mintDeliverToken(targetPeerID crypto.PeerID, deliverTo *types.DeliverySpec) (capEnt, sigEnt, identEnt entity.Entity, err error) {
	if deliverTo == nil || deliverTo.URI == "" {
		return entity.Entity{}, entity.Entity{}, entity.Entity{}, fmt.Errorf("deliver_token: no delivery spec")
	}
	if deliverTo.Operation == "" {
		return entity.Entity{}, entity.Entity{}, entity.Entity{}, fmt.Errorf("deliver_token: delivery spec names no operation")
	}

	// The grantee is the SERVICING peer's identity-entity content hash —
	// what verify resolves and compares to the author — never the peer_id
	// string. Conflating the two mints a cap that fails `grantee_mismatch`
	// one field over (the same hazard BuildReentryGrantEnvelope documents).
	granteeHash, err := ResolveRemoteIdentityHash(targetPeerID, nil)
	if err != nil {
		return entity.Entity{}, entity.Entity{}, entity.Entity{}, fmt.Errorf("deliver_token: grantee hash underivable: %w", err)
	}

	parsed, err := entity.ParseURI(deliverTo.URI)
	if err != nil {
		return entity.Entity{}, entity.Entity{}, entity.Entity{}, fmt.Errorf("deliver_token: parse delivery URI: %w", err)
	}
	if parsed.PeerID != string(d.LocalPeerID) {
		return entity.Entity{}, entity.Entity{}, entity.Entity{}, fmt.Errorf(
			"deliver_token: delivery target %s is not this peer — we cannot root authority over another peer's inbox", parsed.PeerID)
	}
	if parsed.Path == "" {
		return entity.Entity{}, entity.Entity{}, entity.Entity{}, fmt.Errorf("deliver_token: delivery URI names no path")
	}

	// The handler dimension is checked against the RESOLVED handler pattern
	// at the receiving side, not against the request path. We are that
	// receiving side, so resolve it exactly rather than guessing a prefix —
	// a grant naming `system/inbox/rexec-result-x` where the check compares
	// `system/inbox` is a cap that verifies nothing.
	if d.Registry == nil {
		return entity.Entity{}, entity.Entity{}, entity.Entity{}, fmt.Errorf("deliver_token: no handler registry to resolve the delivery pattern")
	}
	_, handlerPattern, ok := d.Registry.Resolve(parsed.Path)
	if !ok {
		return entity.Entity{}, entity.Entity{}, entity.Entity{}, fmt.Errorf("deliver_token: no handler serves %s", parsed.Path)
	}

	// Resources in ABSOLUTE `/{peer_id}/rest` form. Cap resource patterns
	// canonicalize against the GRANTER's namespace (V7 §5.5 / PR-8) and we
	// are the granter, so the peer-relative form would resolve to the same
	// place here — but the absolute form says so explicitly and survives the
	// token being re-verified anywhere else in the chain.
	deliverPath := entity.NormalizePath(deliverTo.URI)

	localIdentity, err := d.LocalKeypair.IdentityEntity()
	if err != nil {
		return entity.Entity{}, entity.Entity{}, entity.Entity{}, fmt.Errorf("deliver_token: local identity: %w", err)
	}

	capEnt, err = types.CapabilityTokenData{
		Grants: []types.GrantEntry{{
			Handlers:   types.CapabilityScope{Include: []string{handlerPattern}},
			Resources:  types.CapabilityScope{Include: []string{deliverPath}},
			Operations: types.CapabilityScope{Include: []string{deliverTo.Operation}},
		}},
		Granter:   types.SingleSigGranter(localIdentity.ContentHash),
		Grantee:   granteeHash,
		CreatedAt: uint64(time.Now().UnixMilli()),
	}.ToEntity()
	if err != nil {
		return entity.Entity{}, entity.Entity{}, entity.Entity{}, fmt.Errorf("deliver_token: build cap entity: %w", err)
	}

	sigEnt, err = types.SignatureData{
		Target:    capEnt.ContentHash,
		Signer:    localIdentity.ContentHash,
		Algorithm: crypto.KeyTypeString(d.LocalKeypair.KeyType),
		Signature: d.LocalKeypair.Sign(capEnt.ContentHash.Bytes()),
	}.ToEntity()
	if err != nil {
		return entity.Entity{}, entity.Entity{}, entity.Entity{}, fmt.Errorf("deliver_token: build cap signature entity: %w", err)
	}

	return capEnt, sigEnt, localIdentity, nil
}

// deliverTokenExtras folds a minted token's three entities into an
// AsyncDelivery's Extras map, allocating it if needed. Over-inclusion is free
// (content-addressed dedup at the receiver); omission is a chain the far side
// cannot walk.
func deliverTokenExtras(ad *AsyncDelivery, ents ...entity.Entity) {
	if ad.Extras == nil {
		ad.Extras = make(map[hash.Hash]entity.Entity, len(ents))
	}
	for _, e := range ents {
		ad.Extras[e.ContentHash] = e
	}
}
