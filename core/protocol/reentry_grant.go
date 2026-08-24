package protocol

import (
	"fmt"
	"time"

	"github.com/fxamacker/cbor/v2"
	"go.entitychurch.org/entity-core-go/core/crypto"
	"go.entitychurch.org/entity-core-go/core/ecf"
	"go.entitychurch.org/entity-core-go/core/entity"
	"go.entitychurch.org/entity-core-go/core/hash"
	"go.entitychurch.org/entity-core-go/core/types"
)

// The reciprocal reentry grant — EXTENSION-SIGNALING §6.5 (b) "Symmetric
// origination authority", folded 2026-08-05 (arch c8c7bc8).
//
// On a §6.5 (b) symmetric establishment — one reached by meeting at a §3
// rendezvous key — the DIALER mints a capability for the ACCEPTOR and sends it
// over the just-opened connection. The §6.6 handshake already gives the dialer
// authority to originate to the acceptor; this is the one missing mirror, and
// together they make the pair symmetric. Without it the acceptor fails closed
// on any spontaneous origination (the observed `no originating authority` on
// the two-browser rung-1 run that started this arc).
//
// Wire shape, matched to `entity-core-rust` (`build_reentry_grant_envelope`,
// `accept_reentry_grant`, commits 0eccb3f / 9e77417 / 5596370) — see
// docs/validation/spec-issues/ for why this is the shipped shape and not the
// §7a.2a in-band-params carriage the folded text names:
//
//	EXECUTE  uri=system/protocol/connect  operation=reentry-grant
//	         request_id=connect-reentry-grant  params=<the cap entity>
//	included { cap, cap signature (signer = granter), granter identity }
//
// The frame carries NO author / capability / signature of its own. It is a
// connect-phase frame that self-verifies through the enclosed granter
// signature, which is what lets it arrive before any authority relationship
// exists that could authorize it. It is fire-and-forget: the acceptor sends no
// EXECUTE_RESPONSE, and the dialer awaits none.
const (
	// ReentryGrantOperation is the connect-handler operation that carries a
	// reciprocal grant.
	ReentryGrantOperation = "reentry-grant"

	// ReentryGrantRequestID is the fixed request_id on the grant frame. Fixed
	// rather than sequenced because the frame is fire-and-forget — nothing
	// correlates a response to it.
	ReentryGrantRequestID = "connect-reentry-grant"
)

// BuildReentryGrantEnvelope mints and signs the reciprocal capability the
// dialer grants the acceptor, and wraps it in the connect-phase frame that
// carries it.
//
// granteeHash MUST be the acceptor's identity-entity CONTENT HASH — what the
// core verify contract resolves and compares to the author — and never the
// §3.2 rendezvous `system/peer-id`. Conflating the two mints a cap that fails
// `grantee_mismatch` at the far side (the #67 id-encoding hazard, one field
// over).
//
// grants is the ASSEMBLED inbound-dialer grant for this counterpart — build it
// with ConnectHandler.AssembleInboundGrants, never with DefaultConnectionGrants
// directly (§6.5 (b) Contents, arch f8f736a Q2). Passing the flat floor here is
// the exact defect the ruling names: the reciprocal direction 403s on anything
// out-of-floor while the inbound direction grants the assembled set.
//
// activeFormat is the connection's negotiated `content_hash_format`: every
// entity that goes on a connection is authored under it (V7 v7.69 §4.5a), and
// a cap chain that crosses a format boundary cannot be walked.
func BuildReentryGrantEnvelope(kp crypto.Keypair, granteeHash hash.Hash, grants []types.GrantEntry, activeFormat byte) (entity.Envelope, error) {
	if granteeHash.IsZero() {
		return entity.Envelope{}, fmt.Errorf("reentry grant: zero grantee (unresolvable_grantee by construction)")
	}
	// An empty assembly is a real outcome, not a nil-guard to paper over:
	// advertisement filtering can drop every entry on a peer that registers
	// none of what it resolves. Minting an all-denying cap would advertise
	// authority that dispatches to nothing, so decline to mint — the
	// counterpart stays in the pre-adoption state, which fails closed.
	if len(grants) == 0 {
		return entity.Envelope{}, fmt.Errorf("reentry grant: assembled grant set is empty (nothing to authorize)")
	}
	// §4.5a item 1a: the identity entity is floor-authored, not
	// active-format-authored. The cap token and its signature below still
	// follow activeFormat.
	localIdentity, err := kp.IdentityEntity()
	if err != nil {
		return entity.Envelope{}, fmt.Errorf("reentry grant: local identity: %w", err)
	}

	// Contents: the grant an inbound dialer would actually receive from us —
	// floor ∪ policy, advertisement-filtered (§6.5 (b) "Contents"). Assembled
	// by the caller so this stays one mint over whatever the caller's §6.6
	// assembly produced, rather than a second, drifting copy of it.
	capToken := types.CapabilityTokenData{
		Grants:    grants,
		Granter:   types.SingleSigGranter(localIdentity.ContentHash),
		Grantee:   granteeHash,
		CreatedAt: uint64(time.Now().UnixMilli()),
	}
	capRaw, err := ecf.Encode(capToken)
	if err != nil {
		return entity.Envelope{}, fmt.Errorf("reentry grant: encode cap: %w", err)
	}
	capEntity, err := entity.NewEntityFormat(activeFormat, types.TypeCapToken, cbor.RawMessage(capRaw))
	if err != nil {
		return entity.Envelope{}, fmt.Errorf("reentry grant: build cap entity: %w", err)
	}

	// A single-sig root cap is rejected `missing_signature` at the §5.5 chain
	// walk unless a signature entity targeting its content hash, signed by the
	// granter, travels with it. Signed exactly as the acceptor signs the
	// connection cap it mints in handleAuthenticate.
	sigData := types.SignatureData{
		Target:    capEntity.ContentHash,
		Signer:    localIdentity.ContentHash,
		Algorithm: crypto.KeyTypeString(kp.KeyType),
		Signature: kp.Sign(capEntity.ContentHash.Bytes()),
	}
	sigRaw, err := ecf.Encode(sigData)
	if err != nil {
		return entity.Envelope{}, fmt.Errorf("reentry grant: encode cap signature: %w", err)
	}
	sigEntity, err := entity.NewEntityFormat(activeFormat, types.TypeSignature, cbor.RawMessage(sigRaw))
	if err != nil {
		return entity.Envelope{}, fmt.Errorf("reentry grant: build cap signature entity: %w", err)
	}

	paramsRaw, err := ecf.Encode(capEntity)
	if err != nil {
		return entity.Envelope{}, fmt.Errorf("reentry grant: encode params: %w", err)
	}
	execEntity, err := types.ExecuteData{
		RequestID: ReentryGrantRequestID,
		URI:       connectPath,
		Operation: ReentryGrantOperation,
		Params:    cbor.RawMessage(paramsRaw),
	}.ToEntity()
	if err != nil {
		return entity.Envelope{}, fmt.Errorf("reentry grant: build execute: %w", err)
	}

	// The acceptor's own handshake auth_included cannot contain these — we
	// authored them — so they travel here, and the acceptor re-injects them
	// when it later originates under this cap.
	return entity.NewEnvelope(execEntity, map[hash.Hash]entity.Entity{
		capEntity.ContentHash:     capEntity,
		sigEntity.ContentHash:     sigEntity,
		localIdentity.ContentHash: localIdentity,
	}), nil
}

// IsReentryGrant reports whether env is a reciprocal-grant frame. Cheap enough
// to run on every post-handshake EXECUTE: it decodes the root only when the
// type already matches.
func IsReentryGrant(env entity.Envelope) bool {
	if env.Root.Type != types.TypeExecute {
		return false
	}
	execData, err := types.ExecuteDataFromEntity(env.Root)
	if err != nil {
		return false
	}
	return execData.Operation == ReentryGrantOperation
}

// AcceptReentryGrant validates an inbound reciprocal grant and returns the
// capability plus the supporting entities that must ride whenever we originate
// under it.
//
// remoteIdentityHash is the identity hash of the peer we AUTHENTICATED on this
// connection — not one read out of the frame. The grant's granter must be that
// peer; a grant claiming any other granter is both useless (the far side roots
// the chain at its own identity) and dishonest to store.
//
// The checks are exactly the legs the frame carries, and no more
// (EXTENSION-SIGNALING §6.5 (b) "The mint"; proposal §8.3):
//
//   - the cap's claimed content hash recomputes (a substituted entity would
//     otherwise index under the wrong hash);
//   - granter == the authenticated peer;
//   - a signature entity targets the cap, its signer IS the granter, and it
//     verifies under the granter's key.
//
// It deliberately does NOT run the full chain walk. That walk also resolves the
// GRANTEE — us — whose identity entity is absent from a grant the dialer
// authored, and in Go it rejects even earlier, on `capability.VerifyChain`'s
// rule that a root cap's granter must be the local peer. Either way the full
// walk rejects every valid grant.
//
// A rejected grant is not a connection error: we simply keep no originating
// authority, which is the pre-adoption state and fails closed.
func AcceptReentryGrant(env entity.Envelope, remoteIdentityHash hash.Hash) (entity.Entity, map[hash.Hash]entity.Entity, error) {
	var capEntity entity.Entity
	var found bool
	for _, ent := range env.Included {
		if ent.Type == types.TypeCapToken {
			if found {
				return entity.Entity{}, nil, fmt.Errorf("reentry grant: more than one capability token in included")
			}
			capEntity, found = ent, true
		}
	}
	if !found {
		return entity.Entity{}, nil, fmt.Errorf("reentry grant: no capability token in included")
	}

	// Structural integrity: recompute the hash the entity claims.
	rebuilt, err := entity.NewEntityFormat(capEntity.ContentHash.Algorithm, capEntity.Type, capEntity.Data)
	if err != nil {
		return entity.Entity{}, nil, fmt.Errorf("reentry grant: rebuild cap: %w", err)
	}
	if rebuilt.ContentHash != capEntity.ContentHash {
		return entity.Entity{}, nil, fmt.Errorf("reentry grant: cap failed hash validation")
	}

	capData, err := types.CapabilityTokenDataFromEntity(capEntity)
	if err != nil {
		return entity.Entity{}, nil, fmt.Errorf("reentry grant: decode cap: %w", err)
	}
	granterHash, single := capData.Granter.SingleHash()
	if !single || granterHash != remoteIdentityHash {
		return entity.Entity{}, nil, fmt.Errorf("reentry grant: granter is not the peer authenticated on this connection")
	}

	if err := verifyGrantSignature(env, capEntity, remoteIdentityHash); err != nil {
		return entity.Entity{}, nil, err
	}

	supporting := make(map[hash.Hash]entity.Entity, len(env.Included))
	for h, ent := range env.Included {
		if h == capEntity.ContentHash {
			continue
		}
		supporting[h] = ent
	}
	return capEntity, supporting, nil
}

// verifyGrantSignature runs the single-sig signature leg of the §5.5 chain walk
// against the grant frame: find a signature targeting the cap whose signer is
// the granter, resolve the granter identity out of the same frame, and verify.
//
// Fail-fast here rather than letting the far side's chain walk be the only
// thing that ever checks it: an unverifiable grant can authorize nothing, so
// installing it only trades this named local drop for a `403 missing_signature`
// one dispatch later, at the cross-peer seam, where it is hardest to attribute.
func verifyGrantSignature(env entity.Envelope, capEntity entity.Entity, granterHash hash.Hash) error {
	granterEntity, ok := env.Included[granterHash]
	if !ok {
		return fmt.Errorf("reentry grant: granter identity entity not in included")
	}
	granterData, err := types.PeerDataFromEntity(granterEntity)
	if err != nil {
		return fmt.Errorf("reentry grant: decode granter identity: %w", err)
	}
	ktByte, ktOK := granterData.KeyTypeByte()
	if !ktOK {
		return fmt.Errorf("reentry grant: granter key_type %q not supported", granterData.KeyType)
	}

	for _, ent := range env.Included {
		if ent.Type != types.TypeSignature {
			continue
		}
		sigData, sigErr := types.SignatureDataFromEntity(ent)
		if sigErr != nil {
			continue
		}
		if sigData.Target != capEntity.ContentHash || sigData.Signer != granterHash {
			continue
		}
		if !crypto.Verify(ktByte, granterData.PublicKey, capEntity.ContentHash.Bytes(), sigData.Signature) {
			return fmt.Errorf("reentry grant: granter signature did not verify")
		}
		return nil
	}
	return fmt.Errorf("reentry grant: no granter signature targeting the cap")
}
