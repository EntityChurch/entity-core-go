package validate

import (
	"context"
	"fmt"

	"go.entitychurch.org/entity-core-go/core/entity"
	"go.entitychurch.org/entity-core-go/core/types"

	"github.com/fxamacker/cbor/v2"
)

// catSession is the EXTENSION-NETWORK §6.6 conformance category (landed
// Amendment 8) — the per-peer session entity at
// /{target}/system/peer/session/{validator}.
//
// What it tests (§6.6 principle: the session entity is the durable per-
// peer AUTH record):
//
//   - the entity exists at the canonical path after a fresh handshake
//   - schema matches §6.6 (no last_active, no status; carries the auth
//     relationship via held_capability and/or minted_capability)
//   - the cap chain is leaf→root ordered, length ≥ 1
//
// Role-awareness (§6.6 REQUIRED/OPTIONAL is per-role, not global):
//
//   - held_capability  — the cap the *remote* granted *this peer*; REQUIRED
//     for the DIALER role (dispatch reads it to skip re-handshake).
//   - minted_capability — the cap *this peer* issued *to the remote*;
//     OPTIONAL granter-side bookkeeping (R3a idempotency / revocation).
//
// In validate-peer's flow the validator DIALS the target, so the target is
// the ACCEPTOR/GRANTER: its session record about the validator carries
// minted_capability; held_capability is absent unless the target has also
// dialed back (uncommon in single-peer flow). The oracle therefore:
//
//   - requires the entity to carry the auth relationship (≥1 cap field),
//   - validates whichever cap field(s) are present,
//   - SKIPs the minted-specific R3a checks when minted_capability is
//     absent (it is OPTIONAL — absence is conformant, not a failure).
const catSession = "session"

func runSession(ctx context.Context, client *PeerClient) []CheckResult {
	r := NewCheckRunner(catSession)

	r.Declare("session_entity_landed", "EXTENSION-NETWORK §6.6 (R6)")
	r.Declare("session_schema_v9", "EXTENSION-NETWORK §6.6 (held/minted, granted_at)")
	r.Declare("session_no_dropped_fields", "EXTENSION-NETWORK §6.6 (no status / last_active)")
	r.Declare("session_held_capability_when_present", "EXTENSION-NETWORK §6.6 (held_capability REQUIRED for dialer role)")
	r.Declare("session_chain_leaf_to_root", "EXTENSION-NETWORK §6.6 (chain leaf→root, length ≥ 1)")
	r.Declare("session_no_self_session", "EXTENSION-NETWORK §6.6 (no self-session)")
	r.Declare("session_minted_matches_handshake", "EXTENSION-NETWORK §6.6 (minted_capability = handshake cap)")
	r.Declare("session_persists_across_redial", "EXTENSION-NETWORK §6.6 (R3a idempotency across reconnect)")

	allChecks := []string{
		"session_entity_landed",
		"session_schema_v9",
		"session_no_dropped_fields",
		"session_held_capability_when_present",
		"session_chain_leaf_to_root",
		"session_no_self_session",
		"session_minted_matches_handshake",
		"session_persists_across_redial",
	}

	if !client.GrantsAllow("system/peer/session/*") {
		skip := SkipCheck("validator's connection grants do not cover system/peer/session/* — run with -identity framework-admin")
		for _, name := range allChecks {
			r.Run(name, func() CheckOutcome { return skip })
		}
		return r.Results()
	}

	targetPeerID := string(client.RemotePeerID())
	validatorPeerID := string(client.keypair.PeerID())
	// V7.64 path-encoding alignment: the {remote_peer_id_hex} segment is hex
	// of the validator's canonical identity hash (system/peer content_hash),
	// not Base58 PeerID.
	validatorIdentityHash, hashErr := types.ComputePeerIdentityHashFromPeerID(client.keypair.PeerID())
	if hashErr != nil {
		skip := SkipCheck("validator identity hash undericable (non-identity-form keypair) — v7.64 path requires public_key for SHA-256-form: " + hashErr.Error())
		for _, name := range allChecks {
			r.Run(name, func() CheckOutcome { return skip })
		}
		return r.Results()
	}
	sessionPath := "system/peer/session/" + types.PeerIdentityHashHex(validatorIdentityHash)

	var (
		sessionEntityFound bool
		sessionEntity      types.SessionData
		sessionRawData     cbor.RawMessage
		mintedPresent      bool
	)

	r.Run("session_entity_landed", func() CheckOutcome {
		ent, _, err := client.TreeGet(ctx, sessionPath)
		if err != nil {
			return FailCheck(fmt.Sprintf(
				"no R6 session entity at /%s/%s on target — granter still keeps the handshake cap in connection memory: %v",
				targetPeerID, sessionPath, err,
			))
		}
		if ent.Type != types.TypePeerSession {
			return FailCheck(fmt.Sprintf("entity at %s has type %q, expected %q", sessionPath, ent.Type, types.TypePeerSession))
		}
		data, decErr := types.SessionDataFromEntity(ent)
		if decErr != nil {
			return FailCheck("session entity failed to decode: " + decErr.Error())
		}
		sessionEntity = data
		sessionRawData = ent.Data
		sessionEntityFound = true
		return PassCheck("session entity present at " + sessionPath)
	})

	if !sessionEntityFound {
		skip := SkipCheck("no session entity to inspect")
		for _, name := range allChecks[1:] {
			r.Run(name, func() CheckOutcome { return skip })
		}
		return r.Results()
	}

	r.Run("session_schema_v9", func() CheckOutcome {
		if sessionEntity.RemotePeerID != validatorPeerID {
			return FailCheck(fmt.Sprintf("remote_peer_id field is %q, expected validator id %q", sessionEntity.RemotePeerID, validatorPeerID))
		}
		if sessionEntity.GrantedAt == 0 {
			return FailCheck("granted_at is zero — must be set to handshake wall-clock")
		}
		// §6.6 per-role: held REQUIRED for the dialer, minted OPTIONAL for
		// the granter. The entity MUST carry the auth relationship — at least
		// one cap field, well-formed. Absence of minted is NOT a failure (it
		// is OPTIONAL); the minted-specific checks below skip in that case.
		held := sessionEntity.HeldCapability
		minted := sessionEntity.MintedCapability
		if held == nil && minted == nil {
			return FailCheck("session entity carries neither held_capability nor minted_capability — no auth relationship recorded (§6.6)")
		}
		if held != nil {
			if msg := validateSessionCap("held_capability", *held); msg != "" {
				return FailCheck(msg)
			}
		}
		if minted != nil {
			if msg := validateSessionCap("minted_capability", *minted); msg != "" {
				return FailCheck(msg)
			}
			mintedPresent = true
		}
		if !mintedPresent {
			return PassCheck("schema matches §6.6 (held_capability present + granted_at set; minted_capability absent — OPTIONAL granter bookkeeping)")
		}
		return PassCheck("schema matches §6.6 (minted_capability + granted_at populated; no status / last_active fields)")
	})

	r.Run("session_no_dropped_fields", func() CheckOutcome {
		// §6.6: status and last_active are not part of the schema. A peer
		// that ships them is on a stale shape — typed-decode silently ignores
		// unknown keys, so we walk the raw CBOR map keys directly.
		var keyed map[string]cbor.RawMessage
		if err := cbor.Unmarshal(sessionRawData, &keyed); err != nil {
			return FailCheck("session data is not a CBOR map: " + err.Error())
		}
		dropped := []string{}
		if _, has := keyed["status"]; has {
			dropped = append(dropped, "status")
		}
		if _, has := keyed["last_active"]; has {
			dropped = append(dropped, "last_active")
		}
		if len(dropped) > 0 {
			return FailCheck(fmt.Sprintf(
				"session entity carries fields not in the §6.6 schema: %v — peer is on a pre-Amendment-8 shape",
				dropped,
			))
		}
		return PassCheck("status and last_active absent (schema is §6.6)")
	})

	r.Run("session_held_capability_when_present", func() CheckOutcome {
		// §6.6 makes held_capability REQUIRED for the DIALER role. In
		// validate-peer's flow the target is the acceptor, so held is
		// typically absent — that is conformant. When present (bidirectional
		// pair: target also dialed the validator), validate its shape.
		held := sessionEntity.HeldCapability
		if held == nil {
			// Conformant, not unverifiable: held_capability is REQUIRED only
			// for the dialer role. The target is acceptor-only for this
			// validator (it did not dial back), so absence is correct — PASS
			// (a SKIP would count as a failure per the summary's skip policy).
			return PassCheck("held_capability absent — conformant: target is acceptor-only for this validator (REQUIRED only for the dialer role)")
		}
		if msg := validateSessionCap("held_capability", *held); msg != "" {
			return FailCheck(msg)
		}
		return PassCheck(fmt.Sprintf("held_capability well-formed (hash %s, chain length %d, leaf-first)", held.Hash, len(held.Chain)))
	})

	r.Run("session_chain_leaf_to_root", func() CheckOutcome {
		if out, ok := r.Require("session_schema_v9"); !ok {
			return out
		}
		if !mintedPresent {
			return SkipCheck("minted_capability absent (OPTIONAL §6.6) — leaf→root correlation with the handshake cap requires the granter-side record")
		}
		chain := sessionEntity.MintedCapability.Chain
		// §6.6: chain is hash pointers ordered leaf→root, length ≥ 1.
		// Load-bearing invariants verifiable wire-observably:
		//   (a) length ≥ 1 (covered by validateSessionCap)
		//   (b) chain[0] equals minted_capability.hash (leaf-first ordering)
		//   (c) chain[0]'s Parent equals chain[1] (Parent-link sanity for the
		//       first hop; surfaces ordering reversal immediately).
		// The handshake cap the validator received (client.capEntity) IS the
		// cap the target minted — so it correlates with minted_capability.
		if chain[0] != sessionEntity.MintedCapability.Hash {
			return FailCheck(fmt.Sprintf(
				"chain[0]=%s ≠ minted_capability.hash=%s — chain is not leaf-first ordered (root-first would be the reversal regression)",
				chain[0], sessionEntity.MintedCapability.Hash,
			))
		}
		if len(chain) == 1 {
			// Self-rooted cap: leaf == root. Pin that the leaf cap we got
			// from AUTHENTICATE actually IS self-rooted (no Parent).
			leafTok, err := types.CapabilityTokenDataFromEntity(client.capEntity)
			if err != nil {
				return FailCheck("decode leaf cap: " + err.Error())
			}
			if leafTok.Parent != nil {
				return FailCheck("chain length 1 but leaf cap has a Parent — chain truncated below the real root")
			}
			return PassCheck("chain leaf-only (length 1) and leaf cap is self-rooted")
		}
		// Multi-hop: chain[0].Parent must equal chain[1].
		leafTok, err := types.CapabilityTokenDataFromEntity(client.capEntity)
		if err != nil {
			return FailCheck("decode leaf cap: " + err.Error())
		}
		if leafTok.Parent == nil {
			return FailCheck("chain length > 1 but leaf cap has no Parent — chain claims depth the cap doesn't have")
		}
		if *leafTok.Parent != chain[1] {
			return FailCheck(fmt.Sprintf(
				"chain[1]=%s ≠ leaf.Parent=%s — chain ordering reversed or stale",
				chain[1], *leafTok.Parent,
			))
		}
		return PassCheck(fmt.Sprintf("chain leaf→root verified (length %d, leaf=%s, first parent link matches)", len(chain), chain[0]))
	})

	r.Run("session_no_self_session", func() CheckOutcome {
		// §6.6: the target MUST NOT write a session entity at
		// /{target}/system/peer/session/{target_hex}. Local dispatch
		// short-circuits in memory; persisting a self-session leaks
		// internal degenerate state onto the inspectable tree.
		// V7.64: path segment is hex of the target's identity hash.
		targetIdentityHash, hashErr := types.ComputePeerIdentityHashFromPeerID(client.RemotePeerID())
		if hashErr != nil {
			return SkipCheck("target identity hash undericable for self-session check (SHA-256-form): " + hashErr.Error())
		}
		selfPath := "system/peer/session/" + types.PeerIdentityHashHex(targetIdentityHash)
		_, _, err := client.TreeGet(ctx, selfPath)
		if err == nil {
			return FailCheck(fmt.Sprintf(
				"target wrote a self-session entity at /%s/%s — §6.6 violation",
				targetPeerID, selfPath,
			))
		}
		return PassCheck("no self-session entity at /" + targetPeerID + "/" + selfPath)
	})

	r.Run("session_minted_matches_handshake", func() CheckOutcome {
		if out, ok := r.Require("session_schema_v9"); !ok {
			return out
		}
		if !mintedPresent {
			return SkipCheck("minted_capability absent (OPTIONAL §6.6) — granter-side R3a anchor not recorded; nothing to match against the handshake cap")
		}
		ourCapHash := client.capEntity.ContentHash
		if sessionEntity.MintedCapability.Hash == ourCapHash {
			return PassCheck("minted_capability.hash equals the cap hash from AUTHENTICATE_RESPONSE")
		}
		return FailCheck(fmt.Sprintf(
			"minted_capability.hash=%s does not match handshake cap hash=%s — the granter's tree state and the cap it returned have diverged",
			sessionEntity.MintedCapability.Hash, ourCapHash,
		))
	})

	r.Run("session_persists_across_redial", func() CheckOutcome {
		if out, ok := r.Require("session_schema_v9"); !ok {
			return out
		}
		if !mintedPresent {
			return SkipCheck("minted_capability absent (OPTIONAL §6.6) — R3a idempotency anchor not recorded; nothing to verify across redial")
		}
		originalHash := sessionEntity.MintedCapability.Hash
		// Redial with a fresh client (new TCP connection, same identity).
		// Same grants ⇒ §6.6 R3a mint-fresh-overwrite leaves the cap hash
		// stable. A regression would surface here as a fresh hash
		// (CreatedAt-bearing token re-minted) or a missing entity.
		fresh, err := NewPeerClientWithKeypair(client.Addr(), client.keypair)
		if err != nil {
			return FailCheck("create redial client: " + err.Error())
		}
		defer fresh.Close()
		if err := fresh.Connect(ctx); err != nil {
			return FailCheck("redial connect: " + err.Error())
		}
		checks := fresh.PerformHandshake(ctx)
		for _, ch := range checks {
			if ch.Severity == Fail {
				return FailCheck("redial handshake failed: " + ch.Message)
			}
		}
		ent, _, err := fresh.TreeGet(ctx, sessionPath)
		if err != nil {
			return FailCheck("redial session read: " + err.Error())
		}
		var second entity.Entity = ent
		data, decErr := types.SessionDataFromEntity(second)
		if decErr != nil {
			return FailCheck("redial session decode: " + decErr.Error())
		}
		if data.MintedCapability == nil {
			return FailCheck("minted_capability absent after redial — session entity was cleared")
		}
		if data.MintedCapability.Hash != originalHash {
			return FailCheck(fmt.Sprintf(
				"minted_capability.hash changed across redial: was %s, now %s — R3a idempotency broken (CreatedAt churn?)",
				originalHash, data.MintedCapability.Hash,
			))
		}
		return PassCheck("minted_capability.hash stable across redial (R3a idempotency holds end-to-end)")
	})

	return r.Results()
}

// validateSessionCap checks the wire-observable shape invariants of a
// session capability reference (§6.6): non-zero hash, non-empty chain,
// and leaf-first ordering (chain[0] == hash). Returns "" on success or a
// failure message naming the field.
func validateSessionCap(field string, ref types.SessionCapability) string {
	if ref.Hash.IsZero() {
		return field + ".hash is zero"
	}
	if len(ref.Chain) == 0 {
		return field + ".chain is empty — leaf→root chain pointers not recorded (§6.6, length ≥ 1)"
	}
	if ref.Chain[0] != ref.Hash {
		return fmt.Sprintf("%s.chain[0]=%s ≠ %s.hash=%s — chain is not leaf-first ordered", field, ref.Chain[0], field, ref.Hash)
	}
	return ""
}
