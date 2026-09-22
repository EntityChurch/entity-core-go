// Category: relay_store_bounds. The EXTENSION-RELAY v1.3 §8.1 retention-ceiling
// wire checks (arch ROUTING-2026-08-31-a §6, RL-4 rows 1-2).
//
// POSTURE-GATED, like registry_issuer / serving_mode. §8.1 is default-off: a
// relay with no configured ceiling enforces none, so these checks would SKIP
// against a bare peer. They are excluded from PASS 1 and scored in their own
// validate-complete.sh pass against a peer started with
// --relay-store-retention-ms. A run that cannot reach an armed ceiling reports
// could-not-look (SKIP) and never a PASS — the harness requirement is part of
// the check, not an assumption about the deployment.
//
// The construction is a behavioural cross-check that needs no cap-negotiated
// read of the advertise: the put-result echoes the STORED expires_at (the clamp
// is applied before storage, §8.1), so a null put and a far-future put both
// clamp to the SAME now+ceiling — comparing the two proves the clamp without
// the client knowing the ceiling's exact value. (The §4.1 self-advertise that
// carries the ceiling for a client to DISCOVER is verified separately, unit-
// level, in ext/relay/peerwiring TestPublishSelfAdvertise_*.)
//
// Row 3 (forward-request.expires_at on the §6.2.1 fallback, clamped/no-extend)
// needs the multi-peer offline-fallback harness with the relay armed; it is
// unit-gated in ext/relay TestForward_Fallback_* and is a relay_multipeer
// follow-up. Row 4 (storage-full/507) is deferred until spec-issue 2026-09-01-a
// rules the max_storage_bytes byte metric — a wire check on go's metric would
// test go's reading, not the spec.

package validate

import (
	"context"
	"fmt"
	"time"

	"go.entitychurch.org/entity-core-go/core/entity"
	"go.entitychurch.org/entity-core-go/core/hash"
	"go.entitychurch.org/entity-core-go/core/types"
)

const catRelayStoreBounds = "relay_store_bounds"

// clampCrossCheckSlackMs bounds how far the null-clamp and far-clamp results may
// differ. They are two sequential puts, so the gap is the inter-put wall time
// (round-trips + handler work) — well under a second in practice; 60s is
// generous and still discriminates against the ~decades-away unclamped value.
const clampCrossCheckSlackMs = 60_000

// farExpiryMs returns an expires_at guaranteed to exceed any real retention
// ceiling — ~100 years out — so a clamped result lands far below it.
func farExpiryMs() uint64 {
	return uint64(time.Now().UnixMilli()) + 100*365*24*3600*1000
}

// retentionClamp puts one store-entry with a null expires_at and one with a
// far-future expires_at, and returns the STORED (put-result) expires_at of each
// plus the far value used. relayExecute drives the client's default connection
// grant for system/relay, so no cap is minted here (as runRelayPutLive does).
func retentionClamp(ctx context.Context, client *PeerClient) (eNull, eFar, far uint64, out CheckOutcome, ok bool) {
	far = farExpiryMs()
	put := func(payload string, expiresAt uint64) (uint64, CheckOutcome, bool) {
		inner, err := makeRelayInnerEnvelope(payload)
		if err != nil {
			return 0, FailCheck("inner envelope: " + err.Error()), false
		}
		se := types.StoreEntryData{
			Namespace:     string(client.LocalPeerID()),
			PutBy:         string(client.LocalPeerID()),
			EnvelopeInner: inner.ContentHash,
			ExpiresAt:     expiresAt,
		}
		params, _ := se.ToEntity()
		included := map[hash.Hash]entity.Entity{inner.ContentHash: inner}
		status, result, err := relayExecute(ctx, client, "put", params, included)
		if err != nil {
			return 0, FailCheck("execute :put: " + err.Error()), false
		}
		if status != 200 {
			return 0, FailCheck(fmt.Sprintf(":put want 200, got %d (code=%q)", status, relayErrCode(result))), false
		}
		pr, err := types.PutResultDataFromEntity(result)
		if err != nil {
			return 0, FailCheck("decode put-result: " + err.Error()), false
		}
		return pr.ExpiresAt, CheckOutcome{}, true
	}
	if eNull, out, ok = put("retention-clamp-null", 0); !ok {
		return
	}
	if eFar, out, ok = put("retention-clamp-far", far); !ok {
		return
	}
	return eNull, eFar, far, CheckOutcome{}, true
}

// armed reports whether the peer enforces a retention ceiling (it clamped
// something): null took a positive ceiling, OR the far value was pulled below
// its input. Neither → the peer enforces no §8.1 ceiling.
func retentionArmed(eNull, eFar, far uint64) bool {
	return eNull > 0 || eFar < far
}

func runRelayStoreBounds(ctx context.Context, client *PeerClient) []CheckResult {
	r := NewCheckRunner(catRelayStoreBounds)

	r.Declare("v1_retention_clamp_beyond_ceiling_live",
		"RELAY §8.1 (v1.3) — a store-entry expires_at BEYOND the retention ceiling is stored CLAMPED to now+ceiling, never refused (RL-4 row 1)")
	r.Declare("v2_retention_clamp_null_takes_ceiling_live",
		"RELAY §8.1 (v1.3) — a store-entry with NULL expires_at takes the ceiling (RL-4 row 2)")

	r.Run("v1_retention_clamp_beyond_ceiling_live", func() CheckOutcome {
		eNull, eFar, far, out, ok := retentionClamp(ctx, client)
		if !ok {
			return out
		}
		if !retentionArmed(eNull, eFar, far) {
			return SkipCheck("peer enforces no §8.1 retention ceiling (far expires_at survived verbatim) — start it with --relay-store-retention-ms to reach this row; could-not-look, not a pass")
		}
		if eFar >= far {
			return FailCheck(fmt.Sprintf("far expires_at NOT clamped: put %d, stored %d (§8.1 requires clamp to now+ceiling)", far, eFar))
		}
		// eNull is the ceiling reference (now+ceiling). A conformant far clamp
		// lands at the same ceiling, within the inter-put window.
		if eNull == 0 {
			return FailCheck(fmt.Sprintf("far expires_at clamped to %d but the null-put reference is absent (null not clamped) — cannot confirm clamp is to the ceiling; see row 2", eFar))
		}
		diff := int64(eFar) - int64(eNull)
		if diff < 0 {
			diff = -diff
		}
		if diff > clampCrossCheckSlackMs {
			return FailCheck(fmt.Sprintf("far clamp %d and null clamp %d differ by %dms (> %dms slack) — not clamped to the same ceiling", eFar, eNull, diff, clampCrossCheckSlackMs))
		}
		return PassCheck(fmt.Sprintf("far expires_at %d clamped to ceiling %d (null-clamp reference %d, Δ%dms)", far, eFar, eNull, diff))
	})

	r.Run("v2_retention_clamp_null_takes_ceiling_live", func() CheckOutcome {
		eNull, eFar, far, out, ok := retentionClamp(ctx, client)
		if !ok {
			return out
		}
		if !retentionArmed(eNull, eFar, far) {
			return SkipCheck("peer enforces no §8.1 retention ceiling (null expires_at stayed null) — start it with --relay-store-retention-ms to reach this row; could-not-look, not a pass")
		}
		if eNull == 0 {
			return FailCheck("null expires_at NOT clamped: stored 0 while the peer clamps a far value — §8.1's null arm (min(x,ceiling) has no arm for null, so it is stated) was not applied")
		}
		if eNull >= far {
			return FailCheck(fmt.Sprintf("null clamp %d is not below the far probe %d — the ceiling is not a real bound", eNull, far))
		}
		nowMs := uint64(time.Now().UnixMilli())
		if eNull <= nowMs {
			return FailCheck(fmt.Sprintf("null clamp %d is not in the future (now≈%d) — an expired-on-arrival entry, not a ceiling", eNull, nowMs))
		}
		return PassCheck(fmt.Sprintf("null expires_at took the ceiling %d (below the far probe %d)", eNull, far))
	})

	return r.Results()
}
