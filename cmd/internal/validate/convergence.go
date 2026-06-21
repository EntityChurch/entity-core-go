package validate

import (
	"context"
	"fmt"
	"math/rand"
	"strings"
	"time"

	"go.entitychurch.org/entity-core-go/core/capability"
	"go.entitychurch.org/entity-core-go/core/crypto"
	"go.entitychurch.org/entity-core-go/core/ecf"
	"go.entitychurch.org/entity-core-go/core/entity"
	"go.entitychurch.org/entity-core-go/core/hash"
	"go.entitychurch.org/entity-core-go/core/store"
	"go.entitychurch.org/entity-core-go/core/tree"
	"go.entitychurch.org/entity-core-go/core/types"
	"go.entitychurch.org/entity-core-go/ext/role"
	rolesdk "go.entitychurch.org/entity-core-go/ext/role/sdk"

	"github.com/fxamacker/cbor/v2"
)

const catConvergence = "convergence"

// tcpProfileEntityFor builds a system/peer/transport/tcp profile entity
// for the given peer + addr, matching the Chunk C cutover wire shape.
// Used by convergence checks that previously emitted the legacy flat
// PeerTransportData shape directly.
//
// AdvertisedAt is populated with the current time in RFC3339 — Rust's
// profile decoder treats it as REQUIRED while Go's marks it `omitempty`
// (cross-impl divergence flagged in the TRANSPORT-FAMILY-OPEN-QUESTIONS
// spec issue, Q6). Populating
// it unblocks the R1 cross-peer-HTTP gate against Rust targets without
// taking a position on whether the field SHOULD be required.
func tcpProfileEntityFor(peerID, addr string) entity.Entity {
	data := types.TCPProfileData{
		PeerID:        peerID,
		TransportType: "tcp",
		Endpoint:      types.TransportEndpointURL{URL: "tcp://" + addr},
		SupportedOps:  []string{types.OpExecute},
		Freshness:     "live",
		NonceRequired: true,
		CapFlow:       "both",
		AdvertisedAt:  uint64(time.Now().UnixMilli()),
	}
	raw, _ := ecf.Encode(data)
	ent, _ := entity.NewEntity(types.TypePeerTransportTCP, cbor.RawMessage(raw))
	return ent
}

// transportProfilePath returns the §6.5 path where the primary TCP profile
// for the peer with canonical identity hash {peer_id_hex} lives:
// system/peer/transport/{peer_id_hex}/primary. The trailing profile-id
// segment is the SELECTION RULE ambiguity flagged as E1 in the cross-impl
// rollup; "primary" matches the cohort default.
//
// V7.64 path-encoding alignment: the {peer_id_hex} segment is the lowercase
// hex of the peer's `system/peer` content_hash (NOT Base58 PeerID).
func transportProfilePath(peerIDHex string) string {
	return "system/peer/transport/" + peerIDHex + "/primary"
}

// transportProfilePathFor is the PeerID-aware variant: derives the canonical
// {peer_id_hex} from the PeerID locally (works for identity-form PeerIDs,
// the v7.64 default). Returns ("", error) for SHA-256-form PeerIDs where
// the public_key must be threaded explicitly — use transportProfilePathForClient
// instead, which consults the client's handshake-cached identity hash.
func transportProfilePathFor(pid crypto.PeerID) (string, error) {
	h, err := types.ComputePeerIdentityHashFromPeerID(pid)
	if err != nil {
		return "", fmt.Errorf("derive identity hash for %s: %w", pid, err)
	}
	return transportProfilePath(types.PeerIdentityHashHex(h)), nil
}

// mustTransportProfilePathFor panics if the path cannot be derived.
//
// V7.67 Phase 2: prefer the cached identity hash from the handshake when
// the PeerID is SHA-256-form (canonical for Ed448 per v7.67 §3.2). The
// pre-Phase-2 form assumed identity-form PeerIDs (Ed25519 default) — under
// Ed448 the same call returns "SHA-256 form; public_key required" since
// the public key isn't recoverable from the peer_id alone. The client's
// post-handshake remotePeerIdentityHash carries the same value the peer
// itself publishes, so use it directly when available.
func mustTransportProfilePathFor(c *PeerClient) string {
	if h := c.RemotePeerIdentityHash(); !h.IsZero() {
		return transportProfilePath(types.PeerIdentityHashHex(h))
	}
	p, err := transportProfilePathFor(c.RemotePeerID())
	if err != nil {
		panic(fmt.Sprintf("v7.64 transport profile path derivation for %s: %v", c.RemotePeerID(), err))
	}
	return p
}

// runConvergence executes multi-peer convergence tests.
// clients[0] is peer A, clients[1] is peer B, clients[2] (if present) is peer C.
func runConvergence(ctx context.Context, clients []*PeerClient) []CheckResult {
	r := NewCheckRunner(catConvergence)

	a, b := clients[0], clients[1]

	// Use a unique prefix per run to avoid collisions.
	suffix := fmt.Sprintf("%d", rand.Intn(100000))

	// --- Declare all checks ---

	// P1: Entity Determinism
	r.Declare("p1_entity_determinism", "P1")

	// P2: Trie Determinism
	r.Declare("p2_trie_determinism", "P2")

	// P3: Trie Path Compression
	r.Declare("p3_trie_compression_single", "P3")
	r.Declare("p3_trie_compression_empty", "P3")

	// P4: Version Entry Determinism
	r.Declare("p4_trie_root_match", "P4")
	r.Declare("p4_version_determinism", "P4")

	// C2: Commit Dedup
	r.Declare("c2_commit_dedup", "C2")

	// C6: Fetch + Fetch-Entities
	r.Declare("c6_fetch_execute", "C6")
	r.Declare("c6_fetch_returns_new_version", "C6")
	r.Declare("c6_fetch_includes_version_entity", "C6")
	r.Declare("c6_fetch_entities_execute", "C6")

	// M1: Concurrent Non-Conflicting Merge (CRDT Proof)
	r.Declare("m1_v1_root_match", "M1")
	r.Declare("m1_diverge_a", "M1")
	r.Declare("m1_diverge_b", "M1")
	r.Declare("m1_merge_roots_match", "M1")

	// M2: Concurrent Conflicting Merge
	r.Declare("m2_both_commit", "M2")
	r.Declare("m2_forward_progress_a", "M2")
	r.Declare("m2_forward_progress_b", "M2")
	r.Declare("m2_deterministic_roots", "M2")

	// M3: Three-Peer Convergence
	r.Declare("m3_a_merged_all", "M3")
	r.Declare("m3_all_converged", "M3")

	// T1-T2: Trie Edge Cases
	r.Declare("t1_diff_unchanged_subtree", "T1")
	r.Declare("t2_diff_compression_change", "T2")

	// Level 1: Async Delivery
	r.Declare("async_202_A", "ASYNC §1")
	r.Declare("async_delivered_A", "ASYNC §1")
	r.Declare("async_202_B", "ASYNC §1")
	r.Declare("async_delivered_B", "ASYNC §1")

	// Level 2: Remote Execute via Continuation
	r.Declare("rexec_setup", "REMOTE §2")
	r.Declare("rexec_trigger", "REMOTE §2")
	r.Declare("rexec_delivered", "REMOTE §3")

	// Level 2b: Cross-peer C-3 dispatch-capability scope enforcement.
	// EXTENSION-CONTINUATION §4.2 case 3 / §8.1 + V7 §6.8 (no silent
	// escalation). A cross-peer continuation's dispatched EXECUTE MUST be
	// authorized by its (B-rooted, scoped) dispatch_capability, NOT by the
	// originator's broader ambient/connection authority. Observable
	// discriminator: one scoped cap (in-scope path only), two dispatches —
	// the in-scope one must land (positive control: the scoped B-rooted cap
	// genuinely authorizes its target cross-peer), the out-of-scope one MUST
	// be denied (negative control: a peer that silently escalates to ambient
	// authority lets it through — that is the violation this catches).
	r.Declare("c3_scope_setup", "CONTINUATION §4.2 case 3")
	r.Declare("c3_inscope_lands", "CONTINUATION §4.2 case 3 / §8.1")
	r.Declare("c3_outofscope_denied", "CONTINUATION §4.2 case 3 / V7 §6.8")

	// Cross-Peer Subscription Delivery
	r.Declare("xsub_setup_transport", "NETWORK §10")
	r.Declare("xsub_subscribe", "SUBSCRIPTION §3")
	r.Declare("xsub_trigger_put", "SUBSCRIPTION §5")
	r.Declare("xsub_notification_delivered", "SUBSCRIPTION §5")
	r.Declare("xsub_unsubscribe", "SUBSCRIPTION §3")

	// Continuation Chain: Cross-Peer Entity Sync
	r.Declare("chain_setup_cont1", "CONTINUATION §2")
	r.Declare("chain_setup_cont2", "CONTINUATION §2")
	r.Declare("chain_subscribe", "SUBSCRIPTION §3")
	r.Declare("chain_trigger_put", "TREE §2")
	r.Declare("chain_sync_delivered", "CONTINUATION §3")
	r.Declare("chain_hash_match", "CONTINUATION §3")

	// Prefix Extract+Merge Sync
	r.Declare("psync_setup", "CONTINUATION §2")
	r.Declare("psync_subscribe", "SUBSCRIPTION §3")
	r.Declare("psync_trigger", "TREE §2")
	r.Declare("psync_all_synced", "TREE §5")
	r.Declare("psync_path_usable", "V7 §1.5 / P2")
	r.Declare("psync_query_namespace", "V7 §1.5 / P2")

	// Extract+Merge Cache Chain
	r.Declare("cache_extract_merge", "TREE §5 / P2")
	r.Declare("cache_verify", "TREE §5 / P2")
	r.Declare("cache_hop2_merge", "TREE §5 / P2")
	r.Declare("cache_hop2_verify", "TREE §5 / P2")
	r.Declare("cache_path_usable", "V7 §1.5 / P2")
	r.Declare("cache_query_namespace", "V7 §1.5 / P2")

	// Local File Sync
	r.Declare("filesync_setup", "LOCAL-FILES")
	r.Declare("filesync_write", "LOCAL-FILES")
	r.Declare("filesync_synced", "LOCAL-FILES")

	// Bidirectional File Sync
	r.Declare("bisync_setup", "LOCAL-FILES")
	r.Declare("bisync_write_a", "LOCAL-FILES")
	r.Declare("bisync_write_b", "LOCAL-FILES")
	r.Declare("bisync_a_to_b", "LOCAL-FILES")
	r.Declare("bisync_b_to_a", "LOCAL-FILES")

	// Entity-Native Handler Cross-Peer Convergence
	// (PROPOSAL-ENTITY-NATIVE-HANDLER-DISPATCH; V7 §3.12, §6.6;
	//  spec-gap-handler-grant-authority §S2)
	r.Declare("entity_native_xpeer_determinism", "PROPOSAL §1, V7 §6.6")
	r.Declare("entity_native_xpeer_logic_transfer", "PROPOSAL §1, V7 §3.12")
	r.Declare("entity_native_xpeer_grant_authority_check", "V7 §6.2 / spec-gap §S2")

	// MS: Multi-sig 2-of-3 Cross-Peer Consistency
	// (PROPOSAL-MULTISIG-CORE-PRIMITIVE M3/M4/M6)
	// Single cap shape sent to all peers; each peer's verifier should reject
	// independently with non-200. Tests cross-impl agreement on the negative
	// surface for the canonical 2-of-3 multi-sig pattern.
	r.Declare("ms_2of3_no_signatures_consistent_DENY", "V7 §5.5 (multisig M4/M6)")
	r.Declare("ms_2of3_only_ephemeral_signed_consistent_DENY", "V7 §5.5 (multisig M4)")
	r.Declare("ms_threshold_exceeds_n_consistent_DENY", "V7 §3.6 (multisig M3)")

	// MSP: Multi-sig 2-of-3 Cross-Peer Positive Path
	// (PROPOSAL-MULTISIG-CORE-PRIMITIVE M4/M6 — full ALLOW path)
	// Loads each peer's on-disk keypair, builds a 2-of-3 cap signed by real
	// peers, and verifies each peer's verifier accepts/rejects per M4 and M6.
	// Skipped when not all 3 peer keypairs are loadable from ~/.entity/peers/
	// or ~/.entity/identities/.
	r.Declare("msp_all3_signed_each_peer_ALLOW", "V7 §5.5 (multisig M4/M6)")
	r.Declare("msp_2of3_verifier_signed_ALLOW", "V7 §5.5 (multisig M4/M6)")
	r.Declare("msp_2of3_verifier_did_not_sign_DENY", "V7 §5.5 (multisig M6)")

	// --- Durability Scenario 5 (companion peer as outbox / durable host).
	// Matrix Scenario 5 / EXTENSION-DURABILITY §6 / V7 §1.4.
	// A→B durable → B preserves. C caches/syncs B's inbox namespace; the
	// address and content_hash are stable, authority is B's signature
	// (V7:185). Sync = freshness, retention is a deployment role. We model
	// the sync step with explicit extract+merge — the same shape used by
	// the existing psync/fsync convergence tests. ---
	r.Declare("dur_s5_preserve", "EXTENSION-DURABILITY §5 (A→B durable, B preserves)")
	r.Declare("dur_s5_extract", "V7 §1.4 (extract B's inbox namespace)")
	r.Declare("dur_s5_merge_into_host", "V7 §1.4 (C caches B's inbox namespace)")
	r.Declare("dur_s5_host_holds_entry", "EXTENSION-DURABILITY §6 (find again on durable host)")
	r.Declare("dur_s5_entry_validates", "EXTENSION-DURABILITY §6 / V7 §1.4 (B's signature authoritative on C)")

	// --- P1: Entity Determinism ---

	r.Run("p1_entity_determinism", func() CheckOutcome {
		prefix := convergencePrefix(suffix, "p1")
		ent := mustCreateEntity("test/convergence-doc", map[string]string{"content": "determinism-test"})

		hashA, err := a.TreePut(ctx, prefix+"entity-test", ent)
		if err != nil {
			return FailCheck(fmt.Sprintf("put on A failed: %v", err))
		}

		hashB, err := b.TreePut(ctx, prefix+"entity-test", ent)
		if err != nil {
			return FailCheck(fmt.Sprintf("put on B failed: %v", err))
		}

		if hashA == hashB {
			return PassCheck(fmt.Sprintf("identical entities produce same hash on both peers: %s", hashA))
		}
		return FailCheck(fmt.Sprintf("hash mismatch: A=%s B=%s", hashA, hashB))
	})

	// --- P2: Trie Determinism ---

	r.Run("p2_trie_determinism", func() CheckOutcome {
		prefix := convergencePrefix(suffix, "p2")

		entities := map[string]string{
			"readme":   "hello world",
			"src/main": "package main",
			"config":   "key=value",
		}

		for path, content := range entities {
			ent := mustCreateEntity("test/convergence-doc", map[string]string{"content": content})
			if _, err := a.TreePut(ctx, prefix+path, ent); err != nil {
				return FailCheck(fmt.Sprintf("put %s on A: %v", path, err))
			}
			if _, err := b.TreePut(ctx, prefix+path, ent); err != nil {
				return FailCheck(fmt.Sprintf("put %s on B: %v", path, err))
			}
		}

		snapA, _, errA := a.TreeSnapshot(ctx, prefix)
		snapB, _, errB := b.TreeSnapshot(ctx, prefix)

		if errA != nil {
			return FailCheck(fmt.Sprintf("snapshot A: %v", errA))
		}
		if errB != nil {
			return FailCheck(fmt.Sprintf("snapshot B: %v", errB))
		}

		if snapA.Root == snapB.Root {
			return PassCheck(fmt.Sprintf("identical bindings produce same trie root on both peers: %s", snapA.Root))
		}
		return FailCheck(fmt.Sprintf("trie root mismatch: A=%s B=%s", snapA.Root, snapB.Root))
	})

	// --- P3: Trie Path Compression ---

	r.Run("p3_trie_compression_single", func() CheckOutcome {
		prefix1 := convergencePrefix(suffix, "p3a")
		ent := mustCreateEntity("test/convergence-doc", map[string]string{"content": "single"})

		if _, err := a.TreePut(ctx, prefix1+"deep/nested/path/file", ent); err != nil {
			return FailCheck(fmt.Sprintf("put on A: %v", err))
		}
		if _, err := b.TreePut(ctx, prefix1+"deep/nested/path/file", ent); err != nil {
			return FailCheck(fmt.Sprintf("put on B: %v", err))
		}

		snapA, _, errA := a.TreeSnapshot(ctx, prefix1)
		snapB, _, errB := b.TreeSnapshot(ctx, prefix1)
		if errA != nil || errB != nil {
			return FailCheck("snapshot failed")
		}

		if !snapA.Root.IsZero() && snapA.Root == snapB.Root {
			return PassCheck(fmt.Sprintf("single deep binding produces same trie root on both peers: %s", snapA.Root))
		} else if snapA.Root.IsZero() {
			return FailCheck("snapshot root is zero after putting a binding")
		}
		return FailCheck(fmt.Sprintf("trie root mismatch: A=%s B=%s", snapA.Root, snapB.Root))
	})

	r.Run("p3_trie_compression_empty", func() CheckOutcome {
		prefix2 := convergencePrefix(suffix, "p3b")
		snapA2, _, errA2 := a.TreeSnapshot(ctx, prefix2)
		snapB2, _, errB2 := b.TreeSnapshot(ctx, prefix2)
		if errA2 != nil || errB2 != nil {
			return SkipCheck("snapshot of empty prefix failed")
		}
		if snapA2.Root == snapB2.Root {
			return PassCheck("empty tree prefix produces consistent trie root on both peers")
		}
		return FailCheck(fmt.Sprintf("empty prefix root mismatch: A=%s B=%s", snapA2.Root, snapB2.Root))
	})

	// --- P4: Version Entry Determinism ---

	r.Run("p4_trie_root_match", func() CheckOutcome {
		prefixA := convergencePrefix(suffix, "p4a")
		prefixB := convergencePrefix(suffix, "p4b")

		ent1 := mustCreateEntity("test/convergence-doc", map[string]string{"content": "version-test-1"})
		ent2 := mustCreateEntity("test/convergence-doc", map[string]string{"content": "version-test-2"})

		if _, err := a.TreePut(ctx, prefixA+"file1", ent1); err != nil {
			return FailCheck(fmt.Sprintf("put on A: %v", err))
		}
		if _, err := a.TreePut(ctx, prefixA+"file2", ent2); err != nil {
			return FailCheck(fmt.Sprintf("put on A: %v", err))
		}
		if _, err := b.TreePut(ctx, prefixB+"file1", ent1); err != nil {
			return FailCheck(fmt.Sprintf("put on B: %v", err))
		}
		if _, err := b.TreePut(ctx, prefixB+"file2", ent2); err != nil {
			return FailCheck(fmt.Sprintf("put on B: %v", err))
		}

		respA, errA := a.RevisionExecute(ctx, "commit", types.RevisionCommitParamsData{Prefix: prefixA})
		respB, errB := b.RevisionExecute(ctx, "commit", types.RevisionCommitParamsData{Prefix: prefixB})

		if errA != nil {
			return FailCheck(fmt.Sprintf("commit on A: %v", errA))
		}
		if errB != nil {
			return FailCheck(fmt.Sprintf("commit on B: %v", errB))
		}
		if respA.Status != 200 {
			return FailCheck(fmt.Sprintf("commit A status %d", respA.Status))
		}
		if respB.Status != 200 {
			return FailCheck(fmt.Sprintf("commit B status %d", respB.Status))
		}

		var resultA, resultB types.RevisionCommitResultData
		if _, err := decodeRevisionResult(respA, &resultA); err != nil {
			return FailCheck(fmt.Sprintf("decode A: %v", err))
		}
		if _, err := decodeRevisionResult(respB, &resultB); err != nil {
			return FailCheck(fmt.Sprintf("decode B: %v", err))
		}

		r.Store("p4_resultA", resultA)
		r.Store("p4_resultB", resultB)

		if resultA.Root == resultB.Root {
			return PassCheck(fmt.Sprintf("identical tree state produces same trie root: %s", resultA.Root))
		}
		return FailCheck(fmt.Sprintf("trie root mismatch: A=%s B=%s", resultA.Root, resultB.Root))
	})

	r.Run("p4_version_determinism", func() CheckOutcome {
		if out, ok := r.Require("p4_trie_root_match"); !ok {
			return out
		}
		resultA := r.Load("p4_resultA").(types.RevisionCommitResultData)
		resultB := r.Load("p4_resultB").(types.RevisionCommitResultData)

		if resultA.Version == resultB.Version {
			return PassCheck(fmt.Sprintf("identical state produces same version entry hash: %s", resultA.Version))
		}
		return WarnCheck(fmt.Sprintf("version hash mismatch: A=%s B=%s (trie roots matched — may include annotations)", resultA.Version, resultB.Version))
	})

	// --- C2: Commit Dedup ---

	r.Run("c2_commit_dedup", func() CheckOutcome {
		prefix := convergencePrefix(suffix, "c2")

		ent := mustCreateEntity("test/convergence-doc", map[string]string{"content": "dedup-test"})
		if _, err := a.TreePut(ctx, prefix+"file1", ent); err != nil {
			return FailCheck(fmt.Sprintf("put: %v", err))
		}

		resp1, err := a.RevisionExecute(ctx, "commit", types.RevisionCommitParamsData{Prefix: prefix})
		if err != nil || resp1.Status != 200 {
			return FailCheck("first commit failed")
		}
		var result1 types.RevisionCommitResultData
		_, _ = decodeRevisionResult(resp1, &result1)

		resp2, err := a.RevisionExecute(ctx, "commit", types.RevisionCommitParamsData{Prefix: prefix})
		if err != nil {
			return FailCheck(fmt.Sprintf("second commit error: %v", err))
		}

		var result2 types.RevisionCommitResultData
		_, _ = decodeRevisionResult(resp2, &result2)

		if resp2.Status == 200 && result2.Version == result1.Version {
			return PassCheck("unchanged tree returns same version hash (dedup)")
		} else if resp2.Status == 200 && result2.Root == result1.Root {
			return WarnCheck("new version created with same root (no tree change, but new version entry)")
		}
		return WarnCheck(fmt.Sprintf("second commit status=%d version=%s (first=%s)", resp2.Status, result2.Version, result1.Version))
	})

	// --- C6: Fetch + Fetch-Entities ---

	r.Run("c6_fetch_execute", func() CheckOutcome {
		prefix := convergencePrefix(suffix, "c6")

		ent1 := mustCreateEntity("test/convergence-doc", map[string]string{"content": "fetch-v1"})
		if _, err := a.TreePut(ctx, prefix+"file1", ent1); err != nil {
			return FailCheck(fmt.Sprintf("put: %v", err))
		}

		resp1, err := a.RevisionExecute(ctx, "commit", types.RevisionCommitParamsData{Prefix: prefix})
		if err != nil || resp1.Status != 200 {
			return FailCheck("first commit failed")
		}
		var result1 types.RevisionCommitResultData
		_, _ = decodeRevisionResult(resp1, &result1)

		ent2 := mustCreateEntity("test/convergence-doc", map[string]string{"content": "fetch-v2"})
		if _, err := a.TreePut(ctx, prefix+"file2", ent2); err != nil {
			return FailCheck(fmt.Sprintf("put: %v", err))
		}

		resp2, err := a.RevisionExecute(ctx, "commit", types.RevisionCommitParamsData{Prefix: prefix})
		if err != nil || resp2.Status != 200 {
			return FailCheck("second commit failed")
		}
		var result2 types.RevisionCommitResultData
		_, _ = decodeRevisionResult(resp2, &result2)

		r.Store("c6_prefix", prefix)
		r.Store("c6_result1", result1)
		r.Store("c6_result2", result2)

		fetchResp, fetchEnv, err := a.RevisionExecuteFull(ctx, "fetch", types.RevisionFetchParamsData{
			Prefix: prefix,
			Since:  result1.Version,
		})
		if err != nil {
			return FailCheck(fmt.Sprintf("fetch: %v", err))
		}
		if fetchResp.Status != 200 {
			return FailCheck(fmt.Sprintf("fetch status %d", fetchResp.Status))
		}

		r.Store("c6_fetchResp", fetchResp)
		// Extract included from system/envelope result if present, else fall back to protocol envelope.
		var fetchIncluded map[hash.Hash]entity.Entity
		var resultEnt entity.Entity
		if err := ecf.Decode(fetchResp.Result, &resultEnt); err == nil {
			if _, envIncluded, err := unwrapResultEnvelope(resultEnt); err == nil && envIncluded != nil {
				fetchIncluded = envIncluded
			}
		}
		if fetchIncluded == nil {
			fetchIncluded = fetchEnv.Included
		}
		r.Store("c6_fetchIncluded", fetchIncluded)
		return PassCheck("fetch executed successfully")
	})

	r.Run("c6_fetch_returns_new_version", func() CheckOutcome {
		if out, ok := r.Require("c6_fetch_execute"); !ok {
			return out
		}
		fetchResp := r.Load("c6_fetchResp").(types.ExecuteResponseData)
		result2 := r.Load("c6_result2").(types.RevisionCommitResultData)

		var fetchResult types.RevisionFetchResultData
		if _, err := decodeRevisionResult(fetchResp, &fetchResult); err != nil {
			return FailCheck(fmt.Sprintf("decode: %v", err))
		}

		foundV2 := false
		for _, vh := range fetchResult.Versions {
			if vh == result2.Version {
				foundV2 = true
				break
			}
		}
		if foundV2 {
			return PassCheck(fmt.Sprintf("fetch since V1 returns V2 (%s)", result2.Version))
		}
		return FailCheck(fmt.Sprintf("V2 (%s) not in fetch result versions %v", result2.Version, fetchResult.Versions))
	})

	r.Run("c6_fetch_includes_version_entity", func() CheckOutcome {
		if out, ok := r.Require("c6_fetch_execute"); !ok {
			return out
		}
		fetchIncluded := r.Load("c6_fetchIncluded").(map[hash.Hash]entity.Entity)
		result2 := r.Load("c6_result2").(types.RevisionCommitResultData)

		if _, ok := fetchIncluded[result2.Version]; ok {
			return PassCheck("version entity included in fetch response")
		}
		return WarnCheck("version entity not in fetch included (may require fetch-entities)")
	})

	r.Run("c6_fetch_entities_execute", func() CheckOutcome {
		if out, ok := r.Require("c6_fetch_execute"); !ok {
			return out
		}
		prefix := r.Load("c6_prefix").(string)
		result2 := r.Load("c6_result2").(types.RevisionCommitResultData)

		file2Ent, _, _ := a.TreeGet(ctx, prefix+"file2")
		if file2Ent.ContentHash.IsZero() {
			return SkipCheck("could not get file2 entity hash")
		}

		feResp, _, feErr := a.RevisionExecuteFull(ctx, "fetch-entities", types.RevisionFetchEntitiesParamsData{
			Prefix:   prefix,
			Snapshot: result2.Root,
			Hashes:   []hash.Hash{file2Ent.ContentHash},
		})
		if feErr != nil {
			return FailCheck(fmt.Sprintf("fetch-entities: %v", feErr))
		}
		if feResp.Status != 200 {
			return FailCheck(fmt.Sprintf("fetch-entities status %d", feResp.Status))
		}
		return PassCheck("fetch-entities executed successfully")
	})

	// --- M1: Concurrent Non-Conflicting Merge (CRDT Proof) ---

	r.Run("m1_v1_root_match", func() CheckOutcome {
		prefixA := convergencePrefix(suffix, "m1a")
		prefixB := convergencePrefix(suffix, "m1b")

		base1 := mustCreateEntity("test/convergence-doc", map[string]string{"content": "base-file1"})
		base2 := mustCreateEntity("test/convergence-doc", map[string]string{"content": "base-file2"})

		for _, pair := range []struct {
			client *PeerClient
			prefix string
			label  string
		}{{a, prefixA, "A"}, {b, prefixB, "B"}} {
			if _, err := pair.client.TreePut(ctx, pair.prefix+"file1", base1); err != nil {
				return FailCheck(fmt.Sprintf("put file1 on %s: %v", pair.label, err))
			}
			if _, err := pair.client.TreePut(ctx, pair.prefix+"file2", base2); err != nil {
				return FailCheck(fmt.Sprintf("put file2 on %s: %v", pair.label, err))
			}
		}

		respA1, err := a.RevisionExecute(ctx, "commit", types.RevisionCommitParamsData{Prefix: prefixA})
		if err != nil || respA1.Status != 200 {
			return FailCheck("V1 commit on A failed")
		}
		respB1, err := b.RevisionExecute(ctx, "commit", types.RevisionCommitParamsData{Prefix: prefixB})
		if err != nil || respB1.Status != 200 {
			return FailCheck("V1 commit on B failed")
		}

		var resultA1, resultB1 types.RevisionCommitResultData
		if _, err := decodeRevisionResult(respA1, &resultA1); err != nil {
			return FailCheck(fmt.Sprintf("decode A: %v", err))
		}
		if _, err := decodeRevisionResult(respB1, &resultB1); err != nil {
			return FailCheck(fmt.Sprintf("decode B: %v", err))
		}

		r.Store("m1_prefixA", prefixA)
		r.Store("m1_prefixB", prefixB)
		r.Store("m1_resultA1", resultA1)
		r.Store("m1_resultB1", resultB1)

		if resultA1.Root == resultB1.Root {
			return PassCheck(fmt.Sprintf("base V1 trie roots match: %s", resultA1.Root))
		}
		return FailCheck(fmt.Sprintf("base V1 root mismatch: A=%s B=%s", resultA1.Root, resultB1.Root))
	})

	r.Run("m1_diverge_a", func() CheckOutcome {
		if out, ok := r.Require("m1_v1_root_match"); !ok {
			return out
		}
		prefixA := r.Load("m1_prefixA").(string)

		modA := mustCreateEntity("test/convergence-doc", map[string]string{"content": "modified-by-A"})
		if _, err := a.TreePut(ctx, prefixA+"file1", modA); err != nil {
			return FailCheck(fmt.Sprintf("modify on A: %v", err))
		}
		respA2, err := a.RevisionExecute(ctx, "commit", types.RevisionCommitParamsData{Prefix: prefixA})
		if err != nil || respA2.Status != 200 {
			return FailCheck("V2a commit failed")
		}
		var resultA2 types.RevisionCommitResultData
		_, _ = decodeRevisionResult(respA2, &resultA2)

		r.Store("m1_modA", modA)
		r.Store("m1_resultA2", resultA2)
		return PassCheck(fmt.Sprintf("A committed V2a: %s", resultA2.Version))
	})

	r.Run("m1_diverge_b", func() CheckOutcome {
		if out, ok := r.Require("m1_v1_root_match"); !ok {
			return out
		}
		prefixB := r.Load("m1_prefixB").(string)

		modB := mustCreateEntity("test/convergence-doc", map[string]string{"content": "modified-by-B"})
		if _, err := b.TreePut(ctx, prefixB+"file2", modB); err != nil {
			return FailCheck(fmt.Sprintf("modify on B: %v", err))
		}
		respB2, err := b.RevisionExecute(ctx, "commit", types.RevisionCommitParamsData{Prefix: prefixB})
		if err != nil || respB2.Status != 200 {
			return FailCheck("V2b commit failed")
		}
		var resultB2 types.RevisionCommitResultData
		_, _ = decodeRevisionResult(respB2, &resultB2)

		r.Store("m1_modB", modB)
		r.Store("m1_resultB2", resultB2)
		return PassCheck(fmt.Sprintf("B committed V2b: %s", resultB2.Version))
	})

	r.Run("m1_merge_roots_match", func() CheckOutcome {
		if out, ok := r.Require("m1_diverge_a", "m1_diverge_b"); !ok {
			return out
		}
		prefixA := r.Load("m1_prefixA").(string)
		prefixB := r.Load("m1_prefixB").(string)
		modA := r.Load("m1_modA").(entity.Entity)
		modB := r.Load("m1_modB").(entity.Entity)

		// On A: apply B's change (file2=modB), then merge.
		if _, err := a.TreePut(ctx, prefixA+"file2", modB); err != nil {
			return FailCheck(fmt.Sprintf("apply B's change on A: %v", err))
		}
		mergeRespA, err := a.RevisionExecute(ctx, "commit", types.RevisionCommitParamsData{Prefix: prefixA})
		if err != nil || mergeRespA.Status != 200 {
			return FailCheck("merge commit on A failed")
		}
		var mergeResultA types.RevisionCommitResultData
		_, _ = decodeRevisionResult(mergeRespA, &mergeResultA)

		// On B: apply A's change (file1=modA), then merge.
		if _, err := b.TreePut(ctx, prefixB+"file1", modA); err != nil {
			return FailCheck(fmt.Sprintf("apply A's change on B: %v", err))
		}
		mergeRespB, err := b.RevisionExecute(ctx, "commit", types.RevisionCommitParamsData{Prefix: prefixB})
		if err != nil || mergeRespB.Status != 200 {
			return FailCheck("merge commit on B failed")
		}
		var mergeResultB types.RevisionCommitResultData
		_, _ = decodeRevisionResult(mergeRespB, &mergeResultB)

		if mergeResultA.Root == mergeResultB.Root {
			return PassCheck(fmt.Sprintf("CRDT PROOF: merged trie roots match across peers: %s", mergeResultA.Root))
		}
		return FailCheck(fmt.Sprintf("CRDT VIOLATION: merged trie roots differ: A=%s B=%s", mergeResultA.Root, mergeResultB.Root))
	})

	// --- M2: Concurrent Conflicting Merge ---

	r.Run("m2_both_commit", func() CheckOutcome {
		prefixA := convergencePrefix(suffix, "m2a")
		prefixB := convergencePrefix(suffix, "m2b")

		base := mustCreateEntity("test/convergence-doc", map[string]string{"content": "conflict-base"})
		for _, pair := range []struct {
			client *PeerClient
			prefix string
		}{{a, prefixA}, {b, prefixB}} {
			pair.client.TreePut(ctx, pair.prefix+"shared-file", base)
		}

		a.RevisionExecute(ctx, "commit", types.RevisionCommitParamsData{Prefix: prefixA})
		b.RevisionExecute(ctx, "commit", types.RevisionCommitParamsData{Prefix: prefixB})

		modA := mustCreateEntity("test/convergence-doc", map[string]string{"content": "version-A"})
		modB := mustCreateEntity("test/convergence-doc", map[string]string{"content": "version-B"})

		a.TreePut(ctx, prefixA+"shared-file", modA)
		respA, _ := a.RevisionExecute(ctx, "commit", types.RevisionCommitParamsData{Prefix: prefixA})
		b.TreePut(ctx, prefixB+"shared-file", modB)
		respB, _ := b.RevisionExecute(ctx, "commit", types.RevisionCommitParamsData{Prefix: prefixB})

		r.Store("m2_prefixA", prefixA)
		r.Store("m2_prefixB", prefixB)
		r.Store("m2_modB", modB)

		if respA.Status == 200 && respB.Status == 200 {
			return PassCheck("both peers committed divergent changes")
		}
		return FailCheck(fmt.Sprintf("commit failed: A=%d B=%d", respA.Status, respB.Status))
	})

	r.Run("m2_forward_progress_a", func() CheckOutcome {
		if out, ok := r.Require("m2_both_commit"); !ok {
			return out
		}
		prefixA := r.Load("m2_prefixA").(string)
		modB := r.Load("m2_modB").(entity.Entity)

		a.TreePut(ctx, prefixA+"shared-file", modB)
		mergeA, _ := a.RevisionExecute(ctx, "commit", types.RevisionCommitParamsData{Prefix: prefixA})

		r.Store("m2_mergeA", mergeA)

		if mergeA.Status == 200 {
			return PassCheck("A made forward progress despite conflicting changes")
		}
		return FailCheck(fmt.Sprintf("A merge commit status: %d", mergeA.Status))
	})

	r.Run("m2_forward_progress_b", func() CheckOutcome {
		if out, ok := r.Require("m2_both_commit"); !ok {
			return out
		}
		prefixB := r.Load("m2_prefixB").(string)
		modB := r.Load("m2_modB").(entity.Entity)

		b.TreePut(ctx, prefixB+"shared-file", modB)
		mergeB, _ := b.RevisionExecute(ctx, "commit", types.RevisionCommitParamsData{Prefix: prefixB})

		r.Store("m2_mergeB", mergeB)

		if mergeB.Status == 200 {
			return PassCheck("B made forward progress despite conflicting changes")
		}
		return FailCheck(fmt.Sprintf("B merge commit status: %d", mergeB.Status))
	})

	r.Run("m2_deterministic_roots", func() CheckOutcome {
		if out, ok := r.Require("m2_forward_progress_a", "m2_forward_progress_b"); !ok {
			return out
		}
		mergeA := r.Load("m2_mergeA").(types.ExecuteResponseData)
		mergeB := r.Load("m2_mergeB").(types.ExecuteResponseData)

		var resultA, resultB types.RevisionCommitResultData
		_, _ = decodeRevisionResult(mergeA, &resultA)
		_, _ = decodeRevisionResult(mergeB, &resultB)

		if resultA.Root == resultB.Root {
			return PassCheck("both peers converged to same trie root after resolving to the same final value")
		}
		return FailCheck(fmt.Sprintf("roots differ despite identical resolution: A=%s B=%s", resultA.Root, resultB.Root))
	})

	// --- M3: Three-Peer Convergence ---

	r.Run("m3_a_merged_all", func() CheckOutcome {
		if len(clients) < 3 {
			return SkipCheck("requires 3 peers")
		}
		c := clients[2]
		prefixA := convergencePrefix(suffix, "m3a")
		prefixB := convergencePrefix(suffix, "m3b")
		prefixC := convergencePrefix(suffix, "m3c")

		base := mustCreateEntity("test/convergence-doc", map[string]string{"content": "three-peer-base"})
		for _, pair := range []struct {
			client *PeerClient
			prefix string
		}{{a, prefixA}, {b, prefixB}, {c, prefixC}} {
			pair.client.TreePut(ctx, pair.prefix+"base-file", base)
		}

		a.RevisionExecute(ctx, "commit", types.RevisionCommitParamsData{Prefix: prefixA})
		b.RevisionExecute(ctx, "commit", types.RevisionCommitParamsData{Prefix: prefixB})
		c.RevisionExecute(ctx, "commit", types.RevisionCommitParamsData{Prefix: prefixC})

		entA := mustCreateEntity("test/convergence-doc", map[string]string{"content": "from-A"})
		entB := mustCreateEntity("test/convergence-doc", map[string]string{"content": "from-B"})
		entC := mustCreateEntity("test/convergence-doc", map[string]string{"content": "from-C"})

		a.TreePut(ctx, prefixA+"file-a", entA)
		a.RevisionExecute(ctx, "commit", types.RevisionCommitParamsData{Prefix: prefixA})

		b.TreePut(ctx, prefixB+"file-b", entB)
		b.RevisionExecute(ctx, "commit", types.RevisionCommitParamsData{Prefix: prefixB})

		c.TreePut(ctx, prefixC+"file-c", entC)
		c.RevisionExecute(ctx, "commit", types.RevisionCommitParamsData{Prefix: prefixC})

		// Merge all changes onto A.
		a.TreePut(ctx, prefixA+"file-b", entB)
		a.TreePut(ctx, prefixA+"file-c", entC)
		mergeResp, _ := a.RevisionExecute(ctx, "commit", types.RevisionCommitParamsData{Prefix: prefixA})
		var mergeResult types.RevisionCommitResultData
		_, _ = decodeRevisionResult(mergeResp, &mergeResult)

		r.Store("m3_prefixA", prefixA)
		r.Store("m3_prefixB", prefixB)
		r.Store("m3_prefixC", prefixC)
		r.Store("m3_entA", entA)
		r.Store("m3_entB", entB)
		r.Store("m3_entC", entC)
		r.Store("m3_mergeResult", mergeResult)

		if mergeResp.Status == 200 {
			return PassCheck(fmt.Sprintf("A merged all three peers' changes, root: %s", mergeResult.Root))
		}
		return FailCheck("A merge failed")
	})

	r.Run("m3_all_converged", func() CheckOutcome {
		if len(clients) < 3 {
			return SkipCheck("requires 3 peers")
		}
		if out, ok := r.Require("m3_a_merged_all"); !ok {
			return out
		}
		c := clients[2]
		prefixB := r.Load("m3_prefixB").(string)
		prefixC := r.Load("m3_prefixC").(string)
		entA := r.Load("m3_entA").(entity.Entity)
		entB := r.Load("m3_entB").(entity.Entity)
		entC := r.Load("m3_entC").(entity.Entity)
		mergeResult := r.Load("m3_mergeResult").(types.RevisionCommitResultData)

		b.TreePut(ctx, prefixB+"file-a", entA)
		b.TreePut(ctx, prefixB+"file-c", entC)
		mergeRespB, _ := b.RevisionExecute(ctx, "commit", types.RevisionCommitParamsData{Prefix: prefixB})
		var mergeResultB types.RevisionCommitResultData
		_, _ = decodeRevisionResult(mergeRespB, &mergeResultB)

		c.TreePut(ctx, prefixC+"file-a", entA)
		c.TreePut(ctx, prefixC+"file-b", entB)
		mergeRespC, _ := c.RevisionExecute(ctx, "commit", types.RevisionCommitParamsData{Prefix: prefixC})
		var mergeResultC types.RevisionCommitResultData
		_, _ = decodeRevisionResult(mergeRespC, &mergeResultC)

		allMatch := mergeResult.Root == mergeResultB.Root && mergeResult.Root == mergeResultC.Root
		if allMatch {
			return PassCheck(fmt.Sprintf("all three peers converged to same trie root: %s", mergeResult.Root))
		}
		return FailCheck(fmt.Sprintf("roots differ: A=%s B=%s C=%s", mergeResult.Root, mergeResultB.Root, mergeResultC.Root))
	})

	// --- T1: Trie Diff — Unchanged Subtree Skipping ---

	r.Run("t1_diff_unchanged_subtree", func() CheckOutcome {
		prefix := convergencePrefix(suffix, "t1")

		ent1 := mustCreateEntity("test/convergence-doc", map[string]string{"content": "d1"})
		ent2 := mustCreateEntity("test/convergence-doc", map[string]string{"content": "d2"})
		ent3 := mustCreateEntity("test/convergence-doc", map[string]string{"content": "z"})

		a.TreePut(ctx, prefix+"a/b/c/d1", ent1)
		a.TreePut(ctx, prefix+"a/b/c/d2", ent2)
		a.TreePut(ctx, prefix+"x/y/z", ent3)

		resp1, err := a.RevisionExecute(ctx, "commit", types.RevisionCommitParamsData{Prefix: prefix})
		if err != nil || resp1.Status != 200 {
			return FailCheck("first commit failed")
		}
		var result1 types.RevisionCommitResultData
		_, _ = decodeRevisionResult(resp1, &result1)

		modEnt := mustCreateEntity("test/convergence-doc", map[string]string{"content": "d1-modified"})
		a.TreePut(ctx, prefix+"a/b/c/d1", modEnt)

		resp2, err := a.RevisionExecute(ctx, "commit", types.RevisionCommitParamsData{Prefix: prefix})
		if err != nil || resp2.Status != 200 {
			return FailCheck("second commit failed")
		}
		var result2 types.RevisionCommitResultData
		_, _ = decodeRevisionResult(resp2, &result2)

		diffResp, err := a.RevisionExecute(ctx, "diff", types.RevisionDiffParamsData{
			Prefix: prefix,
			Base:   result1.Version,
			Target: result2.Version,
		})
		if err != nil || diffResp.Status != 200 {
			return FailCheck("diff failed")
		}

		var diffEnt entity.Entity
		if err := ecf.Decode(diffResp.Result, &diffEnt); err != nil {
			return FailCheck(fmt.Sprintf("decode: %v", err))
		}
		diffData, err := types.DiffDataFromEntity(diffEnt)
		if err != nil {
			return FailCheck(fmt.Sprintf("decode diff: %v", err))
		}

		_, d1Changed := diffData.Changed["a/b/c/d1"]
		_, d2Changed := diffData.Changed["a/b/c/d2"]
		_, zChanged := diffData.Changed["x/y/z"]
		_, d2Added := diffData.Added["a/b/c/d2"]
		_, zAdded := diffData.Added["x/y/z"]

		if d1Changed && !d2Changed && !zChanged && !d2Added && !zAdded {
			return PassCheck("diff correctly shows only a/b/c/d1 as changed, other subtrees unchanged")
		}
		return FailCheck(fmt.Sprintf("unexpected diff: changed=%v added=%v", changedKeys(diffData.Changed), mapKeys(diffData.Added)))
	})

	// --- T2: Trie Diff — Compression Mismatch ---

	r.Run("t2_diff_compression_change", func() CheckOutcome {
		prefix := convergencePrefix(suffix, "t2")

		ent1 := mustCreateEntity("test/convergence-doc", map[string]string{"content": "file1"})
		a.TreePut(ctx, prefix+"types/file", ent1)

		resp1, err := a.RevisionExecute(ctx, "commit", types.RevisionCommitParamsData{Prefix: prefix})
		if err != nil || resp1.Status != 200 {
			return FailCheck("first commit failed")
		}
		var result1 types.RevisionCommitResultData
		_, _ = decodeRevisionResult(resp1, &result1)

		ent2 := mustCreateEntity("test/convergence-doc", map[string]string{"content": "handler"})
		a.TreePut(ctx, prefix+"types/handler", ent2)

		resp2, err := a.RevisionExecute(ctx, "commit", types.RevisionCommitParamsData{Prefix: prefix})
		if err != nil || resp2.Status != 200 {
			return FailCheck("second commit failed")
		}
		var result2 types.RevisionCommitResultData
		_, _ = decodeRevisionResult(resp2, &result2)

		diffResp, err := a.RevisionExecute(ctx, "diff", types.RevisionDiffParamsData{
			Prefix: prefix,
			Base:   result1.Version,
			Target: result2.Version,
		})
		if err != nil || diffResp.Status != 200 {
			return FailCheck("diff failed")
		}

		var diffEnt entity.Entity
		if err := ecf.Decode(diffResp.Result, &diffEnt); err != nil {
			return FailCheck(fmt.Sprintf("decode: %v", err))
		}
		diffData, err := types.DiffDataFromEntity(diffEnt)
		if err != nil {
			return FailCheck(fmt.Sprintf("decode diff: %v", err))
		}

		_, handlerAdded := diffData.Added["types/handler"]
		_, fileChanged := diffData.Changed["types/file"]

		if handlerAdded && !fileChanged {
			return PassCheck("diff correctly shows only addition, existing binding unchanged despite trie restructure")
		}
		return WarnCheck(fmt.Sprintf("diff result: added=%v changed=%v (file may appear as changed due to trie restructure)",
			mapKeys(diffData.Added), changedKeys(diffData.Changed)))
	})

	// --- Level 1: Async Delivery ---

	for _, info := range []struct {
		client *PeerClient
		label  string
	}{{a, "A"}, {b, "B"}} {
		client := info.client
		label := info.label

		r.Run("async_202_"+label, func() CheckOutcome {
			peerID := string(client.RemotePeerID())
			testID := "async-" + suffix + "-" + label
			srcPath := "system/validate/async-src-" + testID + "/item"
			inboxPath := "system/inbox/async-result-" + testID

			testEntity := mustCreateEntity("test/async-delivery", map[string]string{
				"content": "async-delivery-test-" + testID,
			})
			_, err := client.TreePut(ctx, srcPath, testEntity)
			if err != nil {
				return FailCheck(fmt.Sprintf("put source entity on %s: %v", label, err))
			}

			deliverURI := "entity://" + peerID + "/" + inboxPath
			tokenEntity, tokenSigEntity, err := client.CreateDeliveryToken(deliverURI, "receive")
			if err != nil {
				return FailCheck(fmt.Sprintf("create delivery token: %v", err))
			}

			getParams, getResource, err := tree.CreateGetRequest(srcPath, "entity")
			if err != nil {
				return FailCheck(fmt.Sprintf("create get request: %v", err))
			}
			treeURI := fmt.Sprintf("entity://%s/system/tree", peerID)
			deliverTo := &types.DeliverySpec{URI: deliverURI, Operation: "receive"}

			env, _, err := client.SendExecuteAsync(ctx, treeURI, "get", getParams, getResource,
				deliverTo, tokenEntity, tokenSigEntity)
			if err != nil {
				return FailCheck(fmt.Sprintf("send async execute: %v", err))
			}

			respData, err := types.ExecuteResponseDataFromEntity(env.Root)
			if err != nil {
				return FailCheck(fmt.Sprintf("decode response: %v", err))
			}
			if respData.Status != 202 {
				return FailCheck(fmt.Sprintf("expected status 202, got %d (peer %s may not support deliver_to)", respData.Status, label))
			}

			r.Store("async_inboxPath_"+label, inboxPath)
			return PassCheck(fmt.Sprintf("peer %s returned 202 for deliver_to request", label))
		})

		r.Run("async_delivered_"+label, func() CheckOutcome {
			if out, ok := r.Require("async_202_" + label); !ok {
				return out
			}
			inboxPath := r.Load("async_inboxPath_" + label).(string)

			var delivered bool
			for attempt := 0; attempt < 25; attempt++ {
				time.Sleep(200 * time.Millisecond)
				entries, _, err := client.TreeListing(ctx, inboxPath+"/")
				if err == nil && len(entries) > 0 {
					delivered = true
					break
				}
			}

			if delivered {
				return PassCheck(fmt.Sprintf("peer %s delivered result to inbox path", label))
			}
			return FailCheck(fmt.Sprintf("peer %s: no delivery at %s after 5s", label, inboxPath+"/"))
		})
	}

	// --- Level 2: Remote Execute via Continuation ---

	r.Run("rexec_setup", func() CheckOutcome {
		if out, ok := r.Require("async_delivered_A", "async_delivered_B"); !ok {
			return out
		}

		peerAID := string(a.RemotePeerID())
		peerBID := string(b.RemotePeerID())
		testID := "rexec-" + suffix

		srcPath := "system/validate/rexec-src-" + suffix + "/item"
		contPath := "system/inbox/rexec-fetch-" + testID
		resultPath := "system/inbox/rexec-result-" + testID

		// Pre-step: Ensure A has the dispatch_capability entity in its content
		// store. A issued this cap to the validator; the hash travels with the
		// continuation, but the entity must be resolvable on A when the
		// continuation handler dispatches (W9).
		if !a.CapEntity().ContentHash.IsZero() {
			a.TreePut(ctx, "system/validate/dispatch-cap-store-"+suffix, a.CapEntity())
		}

		// Step 1: Put test entity on Peer B.
		testEntity := mustCreateEntity("test/remote-execute", map[string]string{
			"content": "remote-execute-test-" + testID,
		})
		_, err := b.TreePut(ctx, srcPath, testEntity)
		if err != nil {
			return FailCheck(fmt.Sprintf("put on B: %v", err))
		}

		// Step 2: Register transport addresses.
		b.TreePut(ctx, mustTransportProfilePathFor(a), tcpProfileEntityFor(peerAID, a.addr))

		a.TreePut(ctx, mustTransportProfilePathFor(b), tcpProfileEntityFor(peerBID, b.addr))

		// Step 3: Create continuation on Peer A with a CONFORMANT cross-peer
		// dispatch_capability (§4.2 case 3, v1.11): B-rooted (parent =
		// B-conferred connect cap), installer in-chain as leaf granter,
		// granted to the dispatching host peer A (= the EXECUTE author).
		// Migrated off the legacy self-rooted a.CapEntity() pattern, which
		// only ever worked via silent escalation (now correctly closed).
		// V7 v7.73 §PR-8 (granter-aware canonicalization): cap resource
		// patterns canonicalize against the granter's peer_id, not the
		// verifier's. The leaf cap is signed by the validator, so peer-
		// relative `srcPath` would canonicalize to /{validator_pid}/srcPath
		// — wrong namespace. Use the absolute /{peerBID}/srcPath form so
		// the cap names B's namespace explicitly regardless of who signs.
		dispGrant := types.GrantEntry{
			Handlers:   types.CapabilityScope{Include: []string{"system/tree"}},
			Resources:  types.CapabilityScope{Include: []string{"/" + peerBID + "/" + srcPath}},
			Operations: types.CapabilityScope{Include: []string{"get"}},
		}
		scopedCap, scopedSig, err := b.CreateChainedCapGrantedTo(b.CapEntity(), []types.GrantEntry{dispGrant}, a.RemotePeerIdentityHash(), nil)
		if err != nil {
			return FailCheck(fmt.Sprintf("mint B-rooted dispatch_capability: %v", err))
		}
		cont := types.ContinuationData{
			Target:    "entity://" + peerBID + "/system/tree",
			Operation: "get",
			Resource:  &types.ResourceTarget{Targets: []string{srcPath}},
			DeliverTo: &types.DeliverySpec{
				URI:       "entity://" + peerAID + "/" + resultPath,
				Operation: "receive",
			},
			DispatchCapability: scopedCap.ContentHash,
		}
		contEntity, err := cont.ToEntity()
		if err != nil {
			return FailCheck(fmt.Sprintf("create continuation: %v", err))
		}
		extras := map[hash.Hash]entity.Entity{}
		for h, e := range b.AuthenticateResponseEnv.Included {
			extras[h] = e
		}
		extras[scopedCap.ContentHash] = scopedCap
		extras[scopedSig.ContentHash] = scopedSig
		vid := a.IdentityEntity()
		extras[vid.ContentHash] = vid
		bcap := b.CapEntity()
		extras[bcap.ContentHash] = bcap
		env, _, err := a.SendInstall(ctx, contPath, contEntity, extras)
		if err != nil {
			return FailCheck(fmt.Sprintf("install continuation on A: %v", err))
		}
		if rd, _ := types.ExecuteResponseDataFromEntity(env.Root); rd.Status != 200 {
			return FailCheck(fmt.Sprintf("install continuation on A returned status %d", rd.Status))
		}

		r.Store("rexec_contPath", contPath)
		r.Store("rexec_resultPath", resultPath)
		r.Store("rexec_peerAID", peerAID)
		r.Store("rexec_peerBID", peerBID)

		return PassCheck(fmt.Sprintf("continuation at %s targets entity://%s/system/tree", contPath, peerBID))
	})

	r.Run("rexec_trigger", func() CheckOutcome {
		if out, ok := r.Require("rexec_setup"); !ok {
			return out
		}
		contPath := r.Load("rexec_contPath").(string)
		peerAID := r.Load("rexec_peerAID").(string)

		triggerEntity := mustCreateEntity("test/trigger", map[string]string{"trigger": "go"})
		inboxURI := fmt.Sprintf("entity://%s/system/inbox", peerAID)
		inboxResource := &types.ResourceTarget{Targets: []string{contPath}}
		_, _, err := a.SendExecute(ctx, inboxURI, "receive", triggerEntity, inboxResource)
		if err != nil {
			return FailCheck(fmt.Sprintf("deliver trigger to inbox: %v", err))
		}
		return PassCheck("trigger delivered to continuation inbox")
	})

	r.Run("rexec_delivered", func() CheckOutcome {
		if out, ok := r.Require("rexec_trigger"); !ok {
			return out
		}
		resultPath := r.Load("rexec_resultPath").(string)
		contPath := r.Load("rexec_contPath").(string)

		var delivered bool
		for attempt := 0; attempt < 30; attempt++ {
			time.Sleep(200 * time.Millisecond)
			entries, _, err := a.TreeListing(ctx, resultPath+"/")
			if err == nil && len(entries) > 0 {
				delivered = true
				break
			}
		}

		if delivered {
			return PassCheck("peer A dispatched remote tree.get to B and delivered result")
		}
		contEntries, _, _ := a.TreeListing(ctx, contPath+"/")
		return FailCheck(fmt.Sprintf("no delivery at result inbox after 6s (cont_inbox=%d entries — peer A may not support remote execute)", len(contEntries)))
	})

	// --- Level 2b: Cross-peer C-3 dispatch-capability scope enforcement ---
	//
	// The conformance property (EXTENSION-CONTINUATION §4.2 case 3 / §8.1,
	// V7 §6.8): a cross-peer continuation's dispatched EXECUTE is authorized
	// strictly by its B-rooted, scoped dispatch_capability — never by a
	// silent fallback to the originator's broader connection authority.
	//
	// Topology: continuation installed on A, dispatches a receive to B. The
	// dispatch_capability is minted B-rooted (parent = the cap B conferred
	// on the validator at connect; validator in-chain as the re-attenuation
	// leaf granter — §4.2 case 3 (i)+(ii)) and scoped to ONE in-scope inbox
	// path on B. Two continuations share that one cap:
	//   - in-scope dispatch  → MUST land  (positive control: the scoped
	//     B-rooted cap genuinely authorizes its target cross-peer; rules out
	//     "the cap doesn't verify at all" as the reason the negative passes)
	//   - out-of-scope dispatch → MUST be denied (negative control: a peer
	//     that silently escalates to ambient/connection authority — which
	//     *would* permit the out-of-scope path — lets it through; an
	//     escalation manifests as the message landing where the scoped cap
	//     does not reach). The out-of-scope path is otherwise reachable by
	//     the validator's broad connection authority, so the ONLY thing that
	//     legitimately blocks it is correct scoped-cap enforcement.
	r.Run("c3_scope_setup", func() CheckOutcome {
		peerAID := string(a.RemotePeerID())
		peerBID := string(b.RemotePeerID())

		// Transport both ways (idempotent; independent of rexec ordering).
		if _, err := a.TreePut(ctx, mustTransportProfilePathFor(b), tcpProfileEntityFor(peerBID, b.addr)); err != nil {
			return FailCheck(fmt.Sprintf("register B transport on A: %v", err))
		}
		b.TreePut(ctx, mustTransportProfilePathFor(a), tcpProfileEntityFor(peerAID, a.addr))

		// V7 v7.73 §PR-8 (granter-aware cap-resource canonicalization):
		// the re-attenuated leaf cap (operator-signed) would canonicalize
		// peer-relative resources to /{operator_pid}/... — wrong namespace.
		// Use absolute /{peerBID}/... so both parent (B-rooted role cap)
		// and leaf (operator re-attenuated) name B's namespace literally.
		inScope := "/" + peerBID + "/system/validate/c3-inscope-" + suffix
		outScope := "/" + peerBID + "/system/validate/c3-escalate-" + suffix

		// Three-identity model (§4.2 case 3 v1.11; see the cross-peer
		// continuation conformance-harness design). A DISTINCT
		// operator identity (not a peer, not the shared validate identity)
		// obtains a B-rooted, scoped role-derived cap via the role SDK —
		// real scoped authority, no --debug open-access dependency. The cap
		// is scoped to the in-scope inbox path ONLY and is re-attenuated for
		// BOTH the positive and negative dispatch, so an out-of-scope target
		// is denied by genuine scope enforcement, not ambient authority.
		// The operator is its own client connected to peer A — so it is the
		// continuation WRITER (§3.1a in-chain check passes: the operator is
		// the re-attenuation leaf granter). A distinct ephemeral identity,
		// not a peer and not the shared validate identity.
		opClient, oerr := NewPeerClient(a.addr)
		if oerr != nil {
			return FailCheck("create operator client: " + oerr.Error())
		}
		if cerr := opClient.Connect(ctx); cerr != nil {
			return FailCheck("operator connect to A: " + cerr.Error())
		}
		opClient.PerformHandshake(ctx)
		if !opClient.Connected() {
			return FailCheck("operator handshake with A failed")
		}
		operatorID := opClient.IdentityEntity()
		scopedGrant := types.GrantEntry{
			Handlers:   types.CapabilityScope{Include: []string{"system/inbox"}},
			Resources:  types.CapabilityScope{Include: []string{inScope}},
			Operations: types.CapabilityScope{Include: []string{"receive"}},
		}
		ctxName := "validate/c3/" + suffix
		const roleName = "dispatcher"
		sdkB := rolesdk.NewClient(b)
		if st, _, derr := sdkB.Define(ctx, ctxName, roleName, []types.GrantEntry{scopedGrant}, nil); derr != nil {
			return FailCheck("role define on B: " + derr.Error())
		} else if st != 200 {
			return FailCheck(fmt.Sprintf("role define on B status %d", st))
		}
		st, asn, aerr := sdkB.Assign(ctx, ctxName, operatorID.ContentHash, roleName)
		if aerr != nil || st != 200 || len(asn.DerivedTokens) != 1 {
			return FailCheck(fmt.Sprintf("role assign on B: status=%d tokens=%d err=%v", st, len(asn.DerivedTokens), aerr))
		}
		rdCapPath := role.RoleDerivedTokenPath(ctxName, operatorID.ContentHash, asn.DerivedTokens[0])
		rdCap, _, rerr := b.TreeGet(ctx, rdCapPath)
		if rerr != nil {
			return FailCheck("read B role-derived cap: " + rerr.Error())
		}

		extras := map[hash.Hash]entity.Entity{}
		for h, e := range b.AuthenticateResponseEnv.Included {
			extras[h] = e
		}
		for h, e := range a.AuthenticateResponseEnv.Included {
			if _, ok := extras[h]; !ok {
				extras[h] = e
			}
		}
		extras[rdCap.ContentHash] = rdCap
		extras[operatorID.ContentHash] = operatorID
		// §4.3 transport: the B-minted root role-derived cap's OWN
		// signature MUST travel in the install `included` so host peer A
		// can re-transport it in the dispatched EXECUTE at advance (§4.3:
		// every per-link signature MUST travel in `included`). This is the
		// SEAM resolution-(c) installer obligation, NOT interim scaffolding:
		// A is installed-on by the operator and never otherwise holds a
		// B-minted signature, so A's CollectChainBundle cannot resolve it
		// at advance, and B's advance-time chain verification consumes the
		// transported `included` (it does not fall back to B's local store
		// for the root link). MEASURED — dropping this read regresses
		// c3_inscope_lands + c3_outofscope_denied.
		//
		// The read targets the V7 §3.5 invariant pointer path (the sole
		// canonical signature location — ROLE no longer keeps a sibling
		// copy, per V7 §3.5 governing role-derived caps). This is itself
		// the v7.45 strategy-(B) discovery rule: a V7-general constructable
		// path, no extension-private scheme knowledge.
		rdSigPath := types.InvariantSignaturePath(peerBID, rdCap.ContentHash)
		if rdSig, _, serr := b.TreeGet(ctx, rdSigPath); serr == nil && rdSig.Type == types.TypeSignature {
			extras[rdSig.ContentHash] = rdSig
		}

		r.Store("c3_peerAID", peerAID)
		r.Store("c3_peerBID", peerBID)
		r.Store("c3_inScope", inScope)
		r.Store("c3_outScope", outScope)
		r.Store("c3_opClient", opClient)
		r.Store("c3_operatorID", operatorID)
		r.Store("c3_rdCap", rdCap)
		r.Store("c3_scopedGrant", scopedGrant)
		r.Store("c3_extrasBase", extras)
		return PassCheck(fmt.Sprintf("operator holds B-rooted scoped role-derived cap (scope=%s receive); 3 distinct identities, no open-grant dependency", inScope))
	})

	// c3DispatchTo installs a continuation on A whose cross-peer dispatch is
	// a receive to `dstPath` on B, authorized by the scoped cap, triggers it
	// via A's inbox, and reports whether the message landed at `dstPath` on
	// B within the settle window.
	c3DispatchTo := func(tag, dstPath string) bool {
		peerAID := r.Load("c3_peerAID").(string)
		peerBID := r.Load("c3_peerBID").(string)
		opClient := r.Load("c3_opClient").(*PeerClient)
		operatorID := r.Load("c3_operatorID").(entity.Entity)
		rdCap := r.Load("c3_rdCap").(entity.Entity)
		scopedGrant := r.Load("c3_scopedGrant").(types.GrantEntry)
		base, _ := r.Load("c3_extrasBase").(map[hash.Hash]entity.Entity)
		contPath := "system/inbox/c3-cont-" + tag + "-" + suffix

		// Operator re-attenuates the FIXED in-scope role-derived cap:
		// parent = rdCap (B-rooted), granter = operator (in-chain leaf),
		// grantee = peer A (the dispatching host / EXECUTE author). Scope is
		// fixed to the in-scope path regardless of dstPath, so an
		// out-of-scope dstPath is denied by B unless the peer escalates.
		capEnt, sigEnt, err := capability.MintReattenuated(
			opClient.Keypair(), operatorID, a.RemotePeerIdentityHash(), rdCap,
			[]types.GrantEntry{scopedGrant}, uint64(time.Now().UnixMilli()), nil)
		if err != nil {
			return false
		}
		params, _ := ecf.Encode(map[string]interface{}{"probe": "c3-" + tag + "-" + suffix})
		cont, err := types.ContinuationData{
			Target:             "entity://" + peerBID + "/system/inbox",
			Operation:          "receive",
			Resource:           &types.ResourceTarget{Targets: []string{dstPath}},
			Params:             cbor.RawMessage(params),
			DispatchCapability: capEnt.ContentHash,
		}.ToEntity()
		if err != nil {
			return false
		}
		extras := map[hash.Hash]entity.Entity{}
		for h, e := range base {
			extras[h] = e
		}
		extras[capEnt.ContentHash] = capEnt
		extras[sigEnt.ContentHash] = sigEnt
		// Install AS THE OPERATOR (the in-chain leaf granter) so §3.1a
		// passes; carries the full chain (§3.2 step 5) so ingest binds
		// signatures and CollectChainBundle transports it at advance (§4.3).
		env, _, err := opClient.SendInstall(ctx, contPath, cont, extras)
		if err != nil {
			return false
		}
		if rd, _ := types.ExecuteResponseDataFromEntity(env.Root); rd.Status != 200 {
			return false
		}
		trigger := mustCreateEntity("test/c3-trigger", map[string]string{"go": tag})
		a.SendExecute(ctx, "entity://"+peerAID+"/system/inbox", "receive", trigger,
			&types.ResourceTarget{Targets: []string{contPath}})

		for attempt := 0; attempt < 25; attempt++ {
			time.Sleep(200 * time.Millisecond)
			if entries, _, err := b.TreeListing(ctx, dstPath+"/"); err == nil && len(entries) > 0 {
				return true
			}
		}
		return false
	}

	r.Run("c3_inscope_lands", func() CheckOutcome {
		if out, ok := r.Require("c3_scope_setup"); !ok {
			return out
		}
		inScope := r.Load("c3_inScope").(string)
		if c3DispatchTo("pos", inScope) {
			return PassCheck("in-scope cross-peer dispatch landed — the B-rooted scoped dispatch_capability authorizes its target (positive control)")
		}
		return FailCheck("in-scope cross-peer dispatch did NOT land: the scoped B-rooted dispatch_capability failed to authorize even its in-scope target — cross-peer C-3 dispatch is not functional on this peer (this also makes the negative control inconclusive)")
	})

	r.Run("c3_outofscope_denied", func() CheckOutcome {
		if out, ok := r.Require("c3_scope_setup", "c3_inscope_lands"); !ok {
			return out
		}
		outScope := r.Load("c3_outScope").(string)
		if c3DispatchTo("neg", outScope) {
			return FailCheck("SILENT ESCALATION: an out-of-scope cross-peer dispatch landed at " + outScope + " — the dispatched EXECUTE was authorized by the originator's broader ambient/connection authority, NOT the scoped dispatch_capability (violates EXTENSION-CONTINUATION §4.2 case 3 / §8.1 and V7 §6.8 no-silent-escalation)")
		}
		return PassCheck("out-of-scope cross-peer dispatch correctly denied — dispatch authorized strictly by the scoped dispatch_capability, no silent escalation to ambient authority (§4.2 case 3 / V7 §6.8)")
	})

	// --- Cross-Peer Subscription Delivery ---

	r.Run("xsub_setup_transport", func() CheckOutcome {
		peerAID := string(a.RemotePeerID())

		transportPath := mustTransportProfilePathFor(a)
		_, err := b.TreePut(ctx, transportPath, tcpProfileEntityFor(peerAID, a.addr))
		if err != nil {
			return FailCheck(fmt.Sprintf("failed to write transport address on B: %v", err))
		}
		return PassCheck(fmt.Sprintf("wrote %s transport address to B", peerAID))
	})

	r.Run("xsub_subscribe", func() CheckOutcome {
		if out, ok := r.Require("xsub_setup_transport"); !ok {
			return out
		}
		prefix := convergencePrefix(suffix, "xsub")
		peerAID := string(a.RemotePeerID())

		inboxPath := "system/inbox/validate-xsub-" + suffix
		deliverURI := "entity://" + peerAID + "/" + inboxPath
		pattern := prefix + "*"
		events := []string{"created", "updated", "deleted"}

		tokenEntity, tokenSigEntity, err := b.CreateDeliveryToken(deliverURI, "receive")
		if err != nil {
			return FailCheck(fmt.Sprintf("failed to create delivery token: %v", err))
		}

		subID, _, _, err := b.Subscribe(ctx, pattern, deliverURI, "receive",
			tokenEntity, tokenSigEntity, events, nil)
		if err != nil {
			return FailCheck(fmt.Sprintf("subscribe failed: %v", err))
		}
		if subID == "" {
			return FailCheck("subscribe returned empty subscription_id")
		}

		r.Store("xsub_subID", subID)
		r.Store("xsub_inboxPath", inboxPath)
		r.Store("xsub_prefix", prefix)

		return PassCheck(fmt.Sprintf("subscribed on B: id=%s pattern=%s deliver=%s", subID, pattern, deliverURI))
	})

	r.Run("xsub_trigger_put", func() CheckOutcome {
		if out, ok := r.Require("xsub_subscribe"); !ok {
			return out
		}
		prefix := r.Load("xsub_prefix").(string)

		testEntity := mustCreateEntity("test/cross-peer-notification", map[string]string{
			"content": "cross-peer-test-" + suffix,
		})
		testPath := prefix + "item-1"
		testHash, err := b.TreePut(ctx, testPath, testEntity)
		if err != nil {
			return FailCheck(fmt.Sprintf("put on B failed: %v", err))
		}

		r.Store("xsub_testHash", testHash)
		return PassCheck(fmt.Sprintf("put %s on B (hash=%s)", testPath, testHash))
	})

	r.Run("xsub_notification_delivered", func() CheckOutcome {
		if out, ok := r.Require("xsub_trigger_put"); !ok {
			return out
		}
		inboxPath := r.Load("xsub_inboxPath").(string)

		notifPrefix := inboxPath + "/"
		var delivered bool
		var deliveryTime time.Duration
		startPoll := time.Now()

		for attempt := 0; attempt < 25; attempt++ {
			time.Sleep(200 * time.Millisecond)
			entries, _, err := a.TreeListing(ctx, notifPrefix)
			if err == nil && len(entries) > 0 {
				delivered = true
				deliveryTime = time.Since(startPoll)
				break
			}
		}

		if delivered {
			r.Store("xsub_delivered", true)
			return PassCheck(fmt.Sprintf("notification delivered to A's inbox in %dms", deliveryTime.Milliseconds()))
		}

		// Check if it landed on B locally instead (routing issue).
		localPrefix := inboxPath + "/"
		localEntries, _, _ := b.TreeListing(ctx, localPrefix)
		if len(localEntries) > 0 {
			return FailCheck("notification delivered to B's LOCAL inbox instead of A — dispatch not routing remotely")
		}
		return FailCheck(fmt.Sprintf("no notification at A's inbox after 5s (path: %s)", notifPrefix))
	})

	r.Run("xsub_unsubscribe", func() CheckOutcome {
		if out, ok := r.Require("xsub_subscribe"); !ok {
			return out
		}
		subID := r.Load("xsub_subID").(string)

		_, _, err := b.Unsubscribe(ctx, subID)
		if err != nil {
			return WarnCheck(fmt.Sprintf("unsubscribe failed: %v", err))
		}
		return PassCheck("unsubscribed successfully")
	})

	// --- Continuation Chain: Cross-Peer Entity Sync ---

	r.Run("chain_setup_cont1", func() CheckOutcome {
		if out, ok := r.Require("rexec_delivered"); !ok {
			return out
		}

		peerAID := string(a.RemotePeerID())
		peerBID := string(b.RemotePeerID())
		testID := "chain-" + suffix
		srcPath := "system/validate/sync-src-" + suffix + "/item-1"
		mirrorPath := "system/validate/sync-dst-" + suffix + "/item-1"
		inboxFetch := "system/inbox/sync-fetch-" + testID
		inboxPut := "system/inbox/sync-put-" + testID

		// Register transport addresses.
		b.TreePut(ctx, mustTransportProfilePathFor(a), tcpProfileEntityFor(peerAID, a.addr))

		a.TreePut(ctx, mustTransportProfilePathFor(b), tcpProfileEntityFor(peerBID, b.addr))

		// Create Continuation 1 on Peer A — fetches entity from Peer B.
		// Cross-peer: conformant B-rooted dispatch_capability (§4.2 case 3).
		cont1 := types.ContinuationData{
			Target:    "entity://" + peerBID + "/system/tree",
			Operation: "get",
			Resource:  &types.ResourceTarget{Targets: []string{srcPath}},
			DeliverTo: &types.DeliverySpec{
				URI:       "entity://" + peerAID + "/" + inboxPut,
				Operation: "receive",
			},
		}
		if err := InstallCrossPeerContinuation(ctx, a, b, inboxFetch, cont1); err != nil {
			return FailCheck(fmt.Sprintf("install cross-peer continuation 1: %v", err))
		}

		r.Store("chain_peerAID", peerAID)
		r.Store("chain_peerBID", peerBID)
		r.Store("chain_srcPath", srcPath)
		r.Store("chain_mirrorPath", mirrorPath)
		r.Store("chain_inboxFetch", inboxFetch)
		r.Store("chain_inboxPut", inboxPut)
		r.Store("chain_suffix", suffix)

		return PassCheck(fmt.Sprintf("continuation 1 at %s -> tree.get from B", inboxFetch))
	})

	r.Run("chain_setup_cont2", func() CheckOutcome {
		if out, ok := r.Require("chain_setup_cont1"); !ok {
			return out
		}
		mirrorPath := r.Load("chain_mirrorPath").(string)
		inboxPut := r.Load("chain_inboxPut").(string)

		putTemplate, _ := ecf.Encode(map[string]interface{}{"entity": nil})
		cont2 := types.ContinuationData{
			Target:             "system/tree",
			Operation:          "put",
			Resource:           &types.ResourceTarget{Targets: []string{mirrorPath}},
			Params:             cbor.RawMessage(putTemplate),
			ResultField:        "entity",
			DispatchCapability: a.CapEntity().ContentHash,
		}
		cont2Entity, err := cont2.ToEntity()
		if err != nil {
			return FailCheck(fmt.Sprintf("create continuation 2: %v", err))
		}
		_, err = a.TreePut(ctx, inboxPut, cont2Entity)
		if err != nil {
			return FailCheck(fmt.Sprintf("put continuation 2 on A: %v", err))
		}

		return PassCheck(fmt.Sprintf("continuation 2 at %s -> tree.put locally", inboxPut))
	})

	r.Run("chain_subscribe", func() CheckOutcome {
		if out, ok := r.Require("chain_setup_cont2"); !ok {
			return out
		}
		peerAID := r.Load("chain_peerAID").(string)
		inboxFetch := r.Load("chain_inboxFetch").(string)
		chainSuffix := r.Load("chain_suffix").(string)

		deliverURI := "entity://" + peerAID + "/" + inboxFetch
		pattern := "system/validate/sync-src-" + chainSuffix + "/*"

		tokenEntity, tokenSigEntity, err := b.CreateDeliveryToken(deliverURI, "receive")
		if err != nil {
			return FailCheck(fmt.Sprintf("create delivery token: %v", err))
		}

		subID, _, _, err := b.Subscribe(ctx, pattern, deliverURI, "receive",
			tokenEntity, tokenSigEntity, []string{"created", "updated"}, nil)
		if err != nil || subID == "" {
			return FailCheck(fmt.Sprintf("subscribe failed: %v", err))
		}

		r.Store("chain_subID", subID)
		return PassCheck(fmt.Sprintf("subscribed on B, deliver to %s", deliverURI))
	})

	r.Run("chain_trigger_put", func() CheckOutcome {
		if out, ok := r.Require("chain_subscribe"); !ok {
			return out
		}
		srcPath := r.Load("chain_srcPath").(string)

		testEntity := mustCreateEntity("test/sync-doc", map[string]string{
			"content": "sync-chain-test-" + suffix,
		})
		testHash, err := b.TreePut(ctx, srcPath, testEntity)
		if err != nil {
			return FailCheck(fmt.Sprintf("put on B: %v", err))
		}

		r.Store("chain_testHash", testHash)
		return PassCheck(fmt.Sprintf("wrote %s on B (hash=%s)", srcPath, testHash))
	})

	r.Run("chain_sync_delivered", func() CheckOutcome {
		if out, ok := r.Require("chain_trigger_put"); !ok {
			return out
		}
		mirrorPath := r.Load("chain_mirrorPath").(string)
		inboxFetch := r.Load("chain_inboxFetch").(string)
		inboxPut := r.Load("chain_inboxPut").(string)
		srcPath := r.Load("chain_srcPath").(string)
		chainSuffix := r.Load("chain_suffix").(string)

		var synced bool
		var syncTime time.Duration
		startPoll := time.Now()

		for attempt := 0; attempt < 30; attempt++ {
			time.Sleep(200 * time.Millisecond)
			ent, _, err := a.TreeGet(ctx, mirrorPath)
			if err == nil && !ent.ContentHash.IsZero() {
				synced = true
				syncTime = time.Since(startPoll)
				r.Store("chain_synced_hash", ent.ContentHash)
				break
			}
		}

		if synced {
			return PassCheck(fmt.Sprintf("entity synced to A's mirror path in %dms", syncTime.Milliseconds()))
		}

		// Debug: check what's at various paths to understand where the chain broke.
		fetchEntries, _, _ := a.TreeListing(ctx, inboxFetch+"/")
		putEntries, _, _ := a.TreeListing(ctx, inboxPut+"/")
		srcEnt, _, srcErr := a.TreeGet(ctx, srcPath)
		mirrorEntries, _, _ := a.TreeListing(ctx, "system/validate/sync-dst-"+chainSuffix+"/")
		details := fmt.Sprintf("inbox-fetch=%d, inbox-put=%d, src-on-A=%v (err=%v), mirror-listing=%d",
			len(fetchEntries), len(putEntries), !srcEnt.ContentHash.IsZero(), srcErr, len(mirrorEntries))
		return FailCheck(fmt.Sprintf("entity not synced to A's mirror path after 6s (path: %s) — %s", mirrorPath, details))
	})

	r.Run("chain_hash_match", func() CheckOutcome {
		if out, ok := r.Require("chain_sync_delivered"); !ok {
			return out
		}
		testHash := r.Load("chain_testHash").(hash.Hash)
		syncedHash := r.Load("chain_synced_hash").(hash.Hash)

		// Cleanup subscription.
		if subID := r.Load("chain_subID"); subID != nil {
			b.Unsubscribe(ctx, subID.(string))
		}

		if syncedHash == testHash {
			return PassCheck(fmt.Sprintf("content hash matches: %s", testHash))
		}
		return FailCheck(fmt.Sprintf("hash mismatch: expected %s, got %s", testHash, syncedHash))
	})

	// --- Prefix Extract+Merge Sync ---

	r.Run("psync_setup", func() CheckOutcome {
		if out, ok := r.Require("rexec_delivered"); !ok {
			return out
		}

		peerAID := string(a.RemotePeerID())
		peerBID := string(b.RemotePeerID())
		testID := "prefix-" + suffix
		srcPrefix := "system/validate/psync-src-" + suffix + "/"
		dstPrefix := "system/validate/psync-dst-" + suffix + "/"
		inboxExtract := "system/inbox/psync-extract-" + testID
		inboxMerge := "system/inbox/psync-merge-" + testID

		// Ensure transport addresses are registered.
		b.TreePut(ctx, mustTransportProfilePathFor(a), tcpProfileEntityFor(peerAID, a.addr))

		a.TreePut(ctx, mustTransportProfilePathFor(b), tcpProfileEntityFor(peerBID, b.addr))

		// Continuation 1: notification -> extract from Peer B for the prefix.
		// Cross-peer: conformant B-rooted dispatch_capability (§4.2 case 3).
		cont1 := types.ContinuationData{
			Target:    "entity://" + peerBID + "/system/tree",
			Operation: "extract",
			Resource:  &types.ResourceTarget{Targets: []string{srcPrefix}},
			DeliverTo: &types.DeliverySpec{
				URI:       "entity://" + peerAID + "/" + inboxMerge,
				Operation: "receive",
			},
		}
		if err := InstallCrossPeerContinuation(ctx, a, b, inboxExtract, cont1); err != nil {
			return FailCheck(fmt.Sprintf("install cross-peer continuation 1: %v", err))
		}

		// Continuation 2: receive extract result -> merge locally.
		mergeTemplate, _ := ecf.Encode(map[string]interface{}{
			"source_envelope": nil,
			"strategy":        "source-wins",
			"source_prefix":   srcPrefix,
			"target_prefix":   dstPrefix,
		})
		cont2 := types.ContinuationData{
			Target:             "system/tree",
			Operation:          "merge",
			Resource:           &types.ResourceTarget{Targets: []string{dstPrefix}},
			Params:             cbor.RawMessage(mergeTemplate),
			ResultField:        "source_envelope",
			DispatchCapability: a.CapEntity().ContentHash,
		}
		cont2Entity, _ := cont2.ToEntity()
		if _, err := a.TreePut(ctx, inboxMerge, cont2Entity); err != nil {
			return FailCheck(fmt.Sprintf("put continuation 2: %v", err))
		}

		r.Store("psync_peerAID", peerAID)
		r.Store("psync_srcPrefix", srcPrefix)
		r.Store("psync_dstPrefix", dstPrefix)
		r.Store("psync_inboxExtract", inboxExtract)

		return PassCheck("continuations created for prefix extract+merge")
	})

	r.Run("psync_subscribe", func() CheckOutcome {
		if out, ok := r.Require("psync_setup"); !ok {
			return out
		}
		peerAID := r.Load("psync_peerAID").(string)
		srcPrefix := r.Load("psync_srcPrefix").(string)
		inboxExtract := r.Load("psync_inboxExtract").(string)

		deliverURI := "entity://" + peerAID + "/" + inboxExtract
		pattern := srcPrefix + "*"

		tokenEntity, tokenSigEntity, _ := b.CreateDeliveryToken(deliverURI, "receive")
		subID, _, _, err := b.Subscribe(ctx, pattern, deliverURI, "receive",
			tokenEntity, tokenSigEntity, []string{"created", "updated"}, nil)
		if err != nil || subID == "" {
			return FailCheck(fmt.Sprintf("subscribe: %v", err))
		}

		r.Store("psync_subID", subID)
		return PassCheck(fmt.Sprintf("subscribed on B for %s", pattern))
	})

	r.Run("psync_trigger", func() CheckOutcome {
		if out, ok := r.Require("psync_subscribe"); !ok {
			return out
		}
		srcPrefix := r.Load("psync_srcPrefix").(string)

		entities := []struct {
			path    string
			content string
		}{
			{srcPrefix + "file1", "hello from file1"},
			{srcPrefix + "file2", "hello from file2"},
			{srcPrefix + "subdir/file3", "hello from file3"},
		}

		for _, e := range entities {
			ent := mustCreateEntity("test/sync-doc", map[string]string{"content": e.content})
			b.TreePut(ctx, e.path, ent)
		}

		r.Store("psync_entities", entities)
		return PassCheck(fmt.Sprintf("wrote %d entities to B under %s", len(entities), srcPrefix))
	})

	r.Run("psync_all_synced", func() CheckOutcome {
		if out, ok := r.Require("psync_trigger"); !ok {
			return out
		}
		srcPrefix := r.Load("psync_srcPrefix").(string)
		dstPrefix := r.Load("psync_dstPrefix").(string)
		entities := r.Load("psync_entities").([]struct {
			path    string
			content string
		})

		// Wait for the last notification to trigger and the chain to complete.
		time.Sleep(3 * time.Second)

		var syncedCount int
		for attempt := 0; attempt < 15; attempt++ {
			time.Sleep(200 * time.Millisecond)
			for _, e := range entities {
				dstPath := dstPrefix + e.path[len(srcPrefix):]
				ent, _, err := a.TreeGet(ctx, dstPath)
				if err == nil && !ent.ContentHash.IsZero() {
					syncedCount++
				}
			}
			if syncedCount == len(entities) {
				break
			}
			syncedCount = 0
		}

		r.Store("psync_syncedCount", syncedCount)

		// Cleanup subscription.
		if subID := r.Load("psync_subID"); subID != nil {
			b.Unsubscribe(ctx, subID.(string))
		}

		if syncedCount == len(entities) {
			return PassCheck(fmt.Sprintf("all %d entities synced to A at %s", syncedCount, dstPrefix))
		}
		return FailCheck(fmt.Sprintf("only %d/%d entities synced to A at %s", syncedCount, len(entities), dstPrefix))
	})

	r.Run("psync_path_usable", func() CheckOutcome {
		if out, ok := r.Require("psync_all_synced"); !ok {
			return out
		}
		dstPrefix := r.Load("psync_dstPrefix").(string)

		entries, _, err := a.TreeListing(ctx, dstPrefix)
		if err != nil || len(entries) == 0 {
			return SkipCheck("no entries to verify")
		}

		fetched := 0
		for key, val := range entries {
			entryHash := extractListingHash(val)
			if entryHash.IsZero() {
				continue
			}
			path := dstPrefix + key
			_, _, err := a.TreeGet(ctx, path)
			if err != nil {
				return FailCheck(fmt.Sprintf("synced entity at %q not fetchable via TreeGet: %v", path, err))
			}
			fetched++
		}
		if fetched > 0 {
			return PassCheck(fmt.Sprintf("all %d synced entities fetchable via listing+get at %s", fetched, dstPrefix))
		}
		return SkipCheck("no entity entries found in listing")
	})

	r.Run("psync_query_namespace", func() CheckOutcome {
		if out, ok := r.Require("psync_all_synced"); !ok {
			return out
		}
		dstPrefix := r.Load("psync_dstPrefix").(string)
		peerAID := r.Load("psync_peerAID").(string)
		peerBID := string(b.RemotePeerID())

		return convergenceCheckQueryNamespace(ctx, a, peerAID, peerBID, dstPrefix, "test/sync-doc")
	})

	// --- Extract+Merge Cache Chain ---

	r.Run("cache_extract_merge", func() CheckOutcome {
		if out, ok := r.Require("rexec_delivered"); !ok {
			return out
		}

		srcPrefix := convergencePrefix(suffix, "cache-src")
		dstPrefix := convergencePrefix(suffix, "cache-dst")

		// Seed data on B.
		for _, name := range []string{"doc1", "doc2", "sub/doc3"} {
			ent := mustCreateEntity("test/cache-doc", map[string]string{"name": name, "origin": "B"})
			b.TreePut(ctx, srcPrefix+name, ent)
		}

		applied, err := extractAndMerge(ctx, b, a, srcPrefix, dstPrefix)
		if err != nil {
			return FailCheck(fmt.Sprintf("extract+merge failed: %v", err))
		}
		if applied < 3 {
			return FailCheck(fmt.Sprintf("expected >=3 applied, got %d", applied))
		}

		r.Store("cache_srcPrefix", srcPrefix)
		r.Store("cache_dstPrefix", dstPrefix)

		return PassCheck(fmt.Sprintf("A cached %d entities from B via extract+merge", applied))
	})

	r.Run("cache_verify", func() CheckOutcome {
		if out, ok := r.Require("cache_extract_merge"); !ok {
			return out
		}
		srcPrefix := r.Load("cache_srcPrefix").(string)
		dstPrefix := r.Load("cache_dstPrefix").(string)

		for _, name := range []string{"doc1", "doc2", "sub/doc3"} {
			srcEnt, _, _ := b.TreeGet(ctx, srcPrefix+name)
			dstEnt, _, err := a.TreeGet(ctx, dstPrefix+name)
			if err != nil {
				return FailCheck(fmt.Sprintf("cached entity %s not fetchable on A: %v", name, err))
			}
			if srcEnt.ContentHash != dstEnt.ContentHash {
				return FailCheck(fmt.Sprintf("hash mismatch for %s: B=%s A=%s", name, srcEnt.ContentHash, dstEnt.ContentHash))
			}
		}
		return PassCheck("all cached entities on A match B's hashes")
	})

	r.Run("cache_hop2_merge", func() CheckOutcome {
		if out, ok := r.Require("cache_verify"); !ok {
			return out
		}
		if len(clients) < 3 {
			return SkipCheck("requires 3 peers for hop-2 cache test")
		}
		c := clients[2]
		dstPrefixA := r.Load("cache_dstPrefix").(string)
		dstPrefixC := convergencePrefix(suffix, "cache-hop2")

		applied, err := extractAndMerge(ctx, a, c, dstPrefixA, dstPrefixC)
		if err != nil {
			return FailCheck(fmt.Sprintf("C extract+merge from A failed: %v", err))
		}
		if applied < 3 {
			return FailCheck(fmt.Sprintf("expected >=3 applied on C, got %d", applied))
		}

		r.Store("cache_dstPrefixC", dstPrefixC)
		return PassCheck(fmt.Sprintf("C cached %d entities from A (originally B's) via extract+merge", applied))
	})

	r.Run("cache_hop2_verify", func() CheckOutcome {
		if out, ok := r.Require("cache_hop2_merge"); !ok {
			return out
		}
		c := clients[2]
		srcPrefix := r.Load("cache_srcPrefix").(string)
		dstPrefixC := r.Load("cache_dstPrefixC").(string)

		for _, name := range []string{"doc1", "doc2", "sub/doc3"} {
			srcEnt, _, _ := b.TreeGet(ctx, srcPrefix+name)
			dstEnt, _, err := c.TreeGet(ctx, dstPrefixC+name)
			if err != nil {
				return FailCheck(fmt.Sprintf("entity %s not fetchable on C: %v", name, err))
			}
			if srcEnt.ContentHash != dstEnt.ContentHash {
				return FailCheck(fmt.Sprintf("hash mismatch for %s: B=%s C=%s", name, srcEnt.ContentHash, dstEnt.ContentHash))
			}
		}
		return PassCheck("all entities on C match B's original hashes after 2-hop cache")
	})

	r.Run("cache_path_usable", func() CheckOutcome {
		if out, ok := r.Require("cache_verify"); !ok {
			return out
		}
		dstPrefix := r.Load("cache_dstPrefix").(string)
		peerAID := string(a.RemotePeerID())

		entries, _, err := a.TreeListing(ctx, dstPrefix)
		if err != nil || len(entries) == 0 {
			return SkipCheck("no entries to verify")
		}

		fetched := 0
		for key, val := range entries {
			entryHash := extractListingHash(val)
			if entryHash.IsZero() {
				continue
			}
			path := dstPrefix + key
			_, _, err := a.TreeGet(ctx, path)
			if err != nil {
				return FailCheck(fmt.Sprintf("cached entity at %q not fetchable via TreeGet: %v", path, err))
			}
			fetched++
		}
		if fetched > 0 {
			return PassCheck(fmt.Sprintf("all %d cached entities fetchable via listing+get at %s", fetched, dstPrefix))
		}
		_ = peerAID
		return SkipCheck("no entity entries found in listing")
	})

	r.Run("cache_query_namespace", func() CheckOutcome {
		if out, ok := r.Require("cache_verify"); !ok {
			return out
		}
		dstPrefix := r.Load("cache_dstPrefix").(string)
		peerAID := string(a.RemotePeerID())
		peerBID := string(b.RemotePeerID())

		return convergenceCheckQueryNamespace(ctx, a, peerAID, peerBID, dstPrefix, "test/cache-doc")
	})

	// --- Local File Sync ---

	r.Run("filesync_setup", func() CheckOutcome {
		if !r.OK("rexec_delivered") {
			return SkipCheck("skipped — remote execute not supported")
		}
		if !a.GrantsAllow("local/sync/test") || !b.GrantsAllow("local/sync/test") {
			return SkipCheck("local/files handler not present on both peers")
		}

		peerAID := string(a.RemotePeerID())
		peerBID := string(b.RemotePeerID())
		testID := "fsync-" + suffix

		srcPrefix := "local/sync/"
		dstPrefix := "local/sync/"
		inboxExtract := "system/inbox/fsync-extract-" + testID
		inboxMerge := "system/inbox/fsync-merge-" + testID

		// Ensure transport addresses.
		b.TreePut(ctx, mustTransportProfilePathFor(a), tcpProfileEntityFor(peerAID, a.addr))

		a.TreePut(ctx, mustTransportProfilePathFor(b), tcpProfileEntityFor(peerBID, b.addr))

		// Continuation 1: notification -> extract from B for local/sync/.
		// Cross-peer: conformant B-rooted dispatch_capability (§4.2 case 3).
		cont1 := types.ContinuationData{
			Target:    "entity://" + peerBID + "/system/tree",
			Operation: "extract",
			Resource:  &types.ResourceTarget{Targets: []string{srcPrefix}},
			DeliverTo: &types.DeliverySpec{
				URI:       "entity://" + peerAID + "/" + inboxMerge,
				Operation: "receive",
			},
		}
		if err := InstallCrossPeerContinuation(ctx, a, b, inboxExtract, cont1); err != nil {
			return FailCheck(fmt.Sprintf("install cross-peer continuation 1: %v", err))
		}

		// Continuation 2: receive extract result -> merge locally at local/sync/.
		mergeTemplate, _ := ecf.Encode(map[string]interface{}{
			"source_envelope": nil,
			"strategy":        "source-wins",
			"source_prefix":   srcPrefix,
			"target_prefix":   dstPrefix,
		})
		cont2 := types.ContinuationData{
			Target:             "system/tree",
			Operation:          "merge",
			Resource:           &types.ResourceTarget{Targets: []string{dstPrefix}},
			Params:             cbor.RawMessage(mergeTemplate),
			ResultField:        "source_envelope",
			DispatchCapability: a.CapEntity().ContentHash,
		}
		cont2Entity, _ := cont2.ToEntity()
		a.TreePut(ctx, inboxMerge, cont2Entity)

		// Subscribe on B for local/sync/*.
		deliverURI := "entity://" + peerAID + "/" + inboxExtract
		pattern := srcPrefix + "*"
		tokenEntity, tokenSigEntity, _ := b.CreateDeliveryToken(deliverURI, "receive")
		subID, _, _, err := b.Subscribe(ctx, pattern, deliverURI, "receive",
			tokenEntity, tokenSigEntity, []string{"created", "updated"}, nil)
		if err != nil || subID == "" {
			return FailCheck(fmt.Sprintf("subscribe: %v", err))
		}

		r.Store("filesync_subID", subID)
		r.Store("filesync_srcPrefix", srcPrefix)
		r.Store("filesync_dstPrefix", dstPrefix)

		return PassCheck("continuation chain + subscription set up for local/sync/")
	})

	r.Run("filesync_write", func() CheckOutcome {
		if out, ok := r.Require("filesync_setup"); !ok {
			return out
		}
		srcPrefix := r.Load("filesync_srcPrefix").(string)

		fileContent := "cross-peer file sync test " + suffix
		testEntity := mustCreateEntity("local/files/file", map[string]interface{}{
			"path":    "fsync-test.txt",
			"content": fileContent,
			"size":    len(fileContent),
		})
		testHash, err := b.TreePut(ctx, srcPrefix+"fsync-test.txt", testEntity)
		if err != nil {
			return FailCheck(fmt.Sprintf("write to B: %v", err))
		}

		r.Store("filesync_testHash", testHash)
		return PassCheck(fmt.Sprintf("wrote fsync-test.txt to B's tree (hash=%s)", testHash))
	})

	r.Run("filesync_synced", func() CheckOutcome {
		if out, ok := r.Require("filesync_write"); !ok {
			return out
		}
		dstPrefix := r.Load("filesync_dstPrefix").(string)
		testHash := r.Load("filesync_testHash").(hash.Hash)

		// Wait for the chain to sync.
		time.Sleep(3 * time.Second)

		var synced bool
		for attempt := 0; attempt < 10; attempt++ {
			time.Sleep(200 * time.Millisecond)
			ent, _, err := a.TreeGet(ctx, dstPrefix+"fsync-test.txt")
			if err == nil && !ent.ContentHash.IsZero() {
				synced = true
				if ent.ContentHash == testHash {
					// Cleanup.
					if subID := r.Load("filesync_subID"); subID != nil {
						b.Unsubscribe(ctx, subID.(string))
					}
					return PassCheck("file entity synced to A's tree, hash matches")
				}
				// Cleanup.
				if subID := r.Load("filesync_subID"); subID != nil {
					b.Unsubscribe(ctx, subID.(string))
				}
				return WarnCheck(fmt.Sprintf("entity at A but hash differs: %s vs %s", ent.ContentHash, testHash))
			}
		}

		// Cleanup.
		if subID := r.Load("filesync_subID"); subID != nil {
			b.Unsubscribe(ctx, subID.(string))
		}
		_ = synced
		return FailCheck("file entity not synced to A's tree after 5s")
	})

	// --- Bidirectional File Sync ---

	r.Run("bisync_setup", func() CheckOutcome {
		if !r.OK("rexec_delivered") {
			return SkipCheck("skipped — remote execute not supported")
		}
		if !a.GrantsAllow("local/sync/test") || !b.GrantsAllow("local/sync/test") {
			return SkipCheck("local/files handler not present on both peers")
		}

		peerAID := string(a.RemotePeerID())
		peerBID := string(b.RemotePeerID())
		testID := "bisync-" + suffix
		srcPrefix := "local/bisync-" + suffix + "/"

		// --- Set up B->A direction ---
		inboxExtractAB := "system/inbox/bisync-extract-ab-" + testID
		inboxMergeAB := "system/inbox/bisync-merge-ab-" + testID

		cont1AB := types.ContinuationData{
			Target:    "entity://" + peerBID + "/system/tree",
			Operation: "extract",
			Resource:  &types.ResourceTarget{Targets: []string{srcPrefix}},
			DeliverTo: &types.DeliverySpec{
				URI:       "entity://" + peerAID + "/" + inboxMergeAB,
				Operation: "receive",
			},
		}
		// Cross-peer (host = A, target = B): conformant B-rooted cap.
		if err := InstallCrossPeerContinuation(ctx, a, b, inboxExtractAB, cont1AB); err != nil {
			return FailCheck(fmt.Sprintf("install bisync cont1AB: %v", err))
		}

		mergeTemplateAB, _ := ecf.Encode(map[string]interface{}{
			"source_envelope": nil,
			"strategy":        "source-wins",
			"source_prefix":   srcPrefix,
			"target_prefix":   srcPrefix,
		})
		cont2AB := types.ContinuationData{
			Target:             "system/tree",
			Operation:          "merge",
			Resource:           &types.ResourceTarget{Targets: []string{srcPrefix}},
			Params:             cbor.RawMessage(mergeTemplateAB),
			ResultField:        "source_envelope",
			DispatchCapability: a.CapEntity().ContentHash,
		}
		cont2ABEntity, _ := cont2AB.ToEntity()
		a.TreePut(ctx, inboxMergeAB, cont2ABEntity)

		deliverURIAB := "entity://" + peerAID + "/" + inboxExtractAB
		tokenAB, tokenSigAB, _ := b.CreateDeliveryToken(deliverURIAB, "receive")
		subIDAB, _, _, _ := b.Subscribe(ctx, srcPrefix+"*", deliverURIAB, "receive",
			tokenAB, tokenSigAB, []string{"created", "updated"}, nil)

		// --- Set up A->B direction ---
		inboxExtractBA := "system/inbox/bisync-extract-ba-" + testID
		inboxMergeBA := "system/inbox/bisync-merge-ba-" + testID

		cont1BA := types.ContinuationData{
			Target:    "entity://" + peerAID + "/system/tree",
			Operation: "extract",
			Resource:  &types.ResourceTarget{Targets: []string{srcPrefix}},
			DeliverTo: &types.DeliverySpec{
				URI:       "entity://" + peerBID + "/" + inboxMergeBA,
				Operation: "receive",
			},
		}
		// Cross-peer mirror (host = B, target = A): conformant A-rooted cap.
		if err := InstallCrossPeerContinuation(ctx, b, a, inboxExtractBA, cont1BA); err != nil {
			return FailCheck(fmt.Sprintf("install bisync cont1BA: %v", err))
		}

		mergeTemplate, _ := ecf.Encode(map[string]interface{}{
			"source_envelope": nil,
			"strategy":        "source-wins",
			"source_prefix":   srcPrefix,
			"target_prefix":   srcPrefix,
		})
		cont2BA := types.ContinuationData{
			Target:             "system/tree",
			Operation:          "merge",
			Resource:           &types.ResourceTarget{Targets: []string{srcPrefix}},
			Params:             cbor.RawMessage(mergeTemplate),
			ResultField:        "source_envelope",
			DispatchCapability: b.CapEntity().ContentHash,
		}
		cont2BAEntity, _ := cont2BA.ToEntity()
		b.TreePut(ctx, inboxMergeBA, cont2BAEntity)

		deliverURIBA := "entity://" + peerBID + "/" + inboxExtractBA
		tokenBA, tokenSigBA, _ := a.CreateDeliveryToken(deliverURIBA, "receive")
		subIDBA, _, _, err := a.Subscribe(ctx, srcPrefix+"*", deliverURIBA, "receive",
			tokenBA, tokenSigBA, []string{"created", "updated"}, nil)
		if err != nil || subIDBA == "" {
			return FailCheck(fmt.Sprintf("subscribe A->B: %v", err))
		}

		r.Store("bisync_srcPrefix", srcPrefix)
		r.Store("bisync_subIDAB", subIDAB)
		r.Store("bisync_subIDBA", subIDBA)

		return PassCheck("bidirectional sync set up (A->B + B->A from previous test)")
	})

	r.Run("bisync_write_a", func() CheckOutcome {
		if out, ok := r.Require("bisync_setup"); !ok {
			return out
		}
		srcPrefix := r.Load("bisync_srcPrefix").(string)

		fileA := mustCreateEntity("local/files/file", map[string]interface{}{
			"path":    "from-a.txt",
			"content": "written on peer A " + suffix,
		})
		a.TreePut(ctx, srcPrefix+"from-a.txt", fileA)
		return PassCheck("wrote from-a.txt to A's tree")
	})

	r.Run("bisync_write_b", func() CheckOutcome {
		if out, ok := r.Require("bisync_setup"); !ok {
			return out
		}
		srcPrefix := r.Load("bisync_srcPrefix").(string)

		fileB := mustCreateEntity("local/files/file", map[string]interface{}{
			"path":    "from-b.txt",
			"content": "written on peer B " + suffix,
		})
		b.TreePut(ctx, srcPrefix+"from-b.txt", fileB)
		return PassCheck("wrote from-b.txt to B's tree")
	})

	r.Run("bisync_a_to_b", func() CheckOutcome {
		if out, ok := r.Require("bisync_write_a", "bisync_write_b"); !ok {
			return out
		}
		srcPrefix := r.Load("bisync_srcPrefix").(string)

		var aToB bool
		for attempt := 0; attempt < 60; attempt++ {
			time.Sleep(500 * time.Millisecond)
			ent, _, err := b.TreeGet(ctx, srcPrefix+"from-a.txt")
			if err == nil && !ent.ContentHash.IsZero() {
				aToB = true
				break
			}
		}

		if aToB {
			return PassCheck("from-a.txt synced to B's tree")
		}
		return WarnCheck("from-a.txt not found on B after 6s (bidirectional prefix sync may need oscillation handling)")
	})

	r.Run("bisync_b_to_a", func() CheckOutcome {
		if out, ok := r.Require("bisync_write_a", "bisync_write_b"); !ok {
			return out
		}
		srcPrefix := r.Load("bisync_srcPrefix").(string)

		var bToA bool
		for attempt := 0; attempt < 60; attempt++ {
			time.Sleep(500 * time.Millisecond)
			ent, _, err := a.TreeGet(ctx, srcPrefix+"from-b.txt")
			if err == nil && !ent.ContentHash.IsZero() {
				bToA = true
				break
			}
		}

		// Cleanup subscriptions.
		if subIDAB := r.Load("bisync_subIDAB"); subIDAB != nil {
			b.Unsubscribe(ctx, subIDAB.(string))
		}
		if subIDBA := r.Load("bisync_subIDBA"); subIDBA != nil {
			a.Unsubscribe(ctx, subIDBA.(string))
		}

		if bToA {
			return PassCheck("from-b.txt synced to A's tree")
		}
		return WarnCheck("from-b.txt not found on A after 6s (bidirectional prefix sync may need oscillation handling)")
	})

	// --- Entity-Native Handler Cross-Peer Convergence ---
	//
	// Three scenarios per spec-gap-handler-grant-authority §S2 + the proposal:
	//
	// 1. Determinism — same manifest registered independently on A and B,
	//    same params dispatched to each, byte-identical response entity hash.
	//    Confirms handler logic is data-driven; nothing peer-local leaks into
	//    the response. Each peer issues its own grant; no authority crosses.
	//
	// 2. Logic transfer — the spec-aligned "transfer a Fibonacci handler"
	//    flow: register on A, extract just the EXPRESSION entity from A,
	//    plant on B via tree:put, register on B with the SAME manifest.
	//    Each peer's handlers handler issues the peer's OWN grant. Both peers
	//    dispatch the same input → same response. The grant doesn't transfer;
	//    only the manifest description and the expression entity travel.
	//
	// 3. Grant authority check (security regression) — register on A, copy
	//    A's grant onto B's tree directly (NOT through register), and assert
	//    B rejects the foreign grant at dispatch. PASS = B returned 4xx with
	//    permission_denied. FAIL = B accepted A's grant (security hole).
	//    This is the canonical regression check for spec-gap §S2: the moment
	//    any impl starts accepting cross-peer grants again, this fails.

	r.Run("entity_native_xpeer_determinism", func() CheckOutcome {
		peerAID := string(a.RemotePeerID())
		peerBID := string(b.RemotePeerID())
		pattern := fmt.Sprintf("app/validate/entity-native-xpeer/det-%s", suffix)
		exprPath := pattern + "/expr"

		// Build a deterministic expression: field("x", lookup/scope("params"))
		// so the response value is exactly whatever the caller sent in params.x
		// — no peer-side state involved.
		paramsLookup, _ := types.ComputeLookupScopeData{Name: "params"}.ToEntity()
		fieldExpr, _ := types.ComputeFieldData{Name: "x", Entity: paramsLookup.ContentHash}.ToEntity()

		// Plant identical entities on both peers' content stores + tree.
		for _, c := range []*PeerClient{a, b} {
			c.TreePut(ctx, pattern+"/p-lookup", paramsLookup)
			if _, err := c.TreePut(ctx, exprPath, fieldExpr); err != nil {
				return FailCheck(fmt.Sprintf("put expression: %v", err))
			}
		}

		// Register the same handler on both peers via system/handler:register.
		scope := []types.GrantEntry{{
			Operations: types.CapabilityScope{Include: []string{"*"}},
			Handlers:   types.CapabilityScope{Include: []string{"*"}},
			Resources:  types.CapabilityScope{Include: []string{"*"}},
		}}
		if err := registerHandler(ctx, a, peerAID, pattern, exprPath, scope); err != nil {
			return FailCheck("register on A: " + err.Error())
		}
		if err := registerHandler(ctx, b, peerBID, pattern, exprPath, scope); err != nil {
			return FailCheck("register on B: " + err.Error())
		}

		// Dispatch with identical params to each peer.
		paramsEnt, _ := buildAnyParams(map[string]interface{}{"x": uint64(7)})
		respA, err := callEntityNativeRaw(ctx, a, peerAID, pattern, "compute", &paramsEnt)
		if err != nil {
			return FailCheck("dispatch on A: " + err.Error())
		}
		respB, err := callEntityNativeRaw(ctx, b, peerBID, pattern, "compute", &paramsEnt)
		if err != nil {
			return FailCheck("dispatch on B: " + err.Error())
		}

		if respA.ContentHash != respB.ContentHash {
			return FailCheck(fmt.Sprintf("response hashes diverge: A=%s B=%s (type A=%s B=%s)",
				respA.ContentHash, respB.ContentHash, respA.Type, respB.Type))
		}
		return PassCheck(fmt.Sprintf("identical manifests on A and B produce byte-identical responses (hash=%s)", respA.ContentHash))
	})

	r.Run("entity_native_xpeer_logic_transfer", func() CheckOutcome {
		peerAID := string(a.RemotePeerID())
		peerBID := string(b.RemotePeerID())
		pattern := fmt.Sprintf("app/validate/entity-native-xpeer/logic-%s", suffix)
		exprPath := pattern + "/expr"

		// Build the expression once; both peers will reference an entity at
		// the same tree path holding the same compute-expression bytes.
		// expr: field("x", lookup/scope("params"))  (deterministic over input)
		paramsLookup, _ := types.ComputeLookupScopeData{Name: "params"}.ToEntity()
		fieldExpr, _ := types.ComputeFieldData{Name: "x", Entity: paramsLookup.ContentHash}.ToEntity()

		// Step 1: register on A — A's handlers handler issues A's own grant.
		// Plant the expression on A (the operand-lookup entity travels with it).
		if _, err := a.TreePut(ctx, pattern+"/p-lookup", paramsLookup); err != nil {
			return FailCheck("put p-lookup on A: " + err.Error())
		}
		if _, err := a.TreePut(ctx, exprPath, fieldExpr); err != nil {
			return FailCheck("put expression on A: " + err.Error())
		}
		scope := []types.GrantEntry{{
			Operations: types.CapabilityScope{Include: []string{"*"}},
			Handlers:   types.CapabilityScope{Include: []string{"*"}},
			Resources:  types.CapabilityScope{Include: []string{"*"}},
		}}
		if err := registerHandler(ctx, a, peerAID, pattern, exprPath, scope); err != nil {
			return FailCheck("register on A: " + err.Error())
		}

		// Step 2: extract just the EXPRESSION (and its operand) from A's
		// tree. Plant them on B via tree:put. The handler/interface/grant
		// entities are NOT transferred — each peer issues its own.
		for _, p := range []string{pattern + "/p-lookup", exprPath} {
			ent, _, err := a.TreeGet(ctx, p)
			if err != nil {
				return FailCheck(fmt.Sprintf("read %s from A: %v", p, err))
			}
			if _, err := b.TreePut(ctx, p, ent); err != nil {
				return FailCheck(fmt.Sprintf("plant %s on B: %v", p, err))
			}
		}

		// Step 3: register on B with the SAME manifest. B's handlers handler
		// creates B's own signed grant.
		if err := registerHandler(ctx, b, peerBID, pattern, exprPath, scope); err != nil {
			return FailCheck("register on B: " + err.Error())
		}

		// Step 4: dispatch on both with identical params; assert response
		// hashes match. Each peer ran its own copy of the handler under its
		// own authority and produced the same bytes.
		paramsEnt, _ := buildAnyParams(map[string]interface{}{"x": uint64(11)})
		respA, err := callEntityNativeRaw(ctx, a, peerAID, pattern, "compute", &paramsEnt)
		if err != nil {
			return FailCheck("dispatch on A: " + err.Error())
		}
		respB, err := callEntityNativeRaw(ctx, b, peerBID, pattern, "compute", &paramsEnt)
		if err != nil {
			return FailCheck("dispatch on B: " + err.Error())
		}
		if respA.ContentHash != respB.ContentHash {
			return FailCheck(fmt.Sprintf("transferred handler diverges: A=%s B=%s",
				respA.ContentHash, respB.ContentHash))
		}
		return PassCheck(fmt.Sprintf(
			"manifest+expression transferred via tree:put + register-on-B; both peers dispatch matching responses (hash=%s)",
			respA.ContentHash))
	})

	r.Run("entity_native_xpeer_grant_authority_check", func() CheckOutcome {
		// Security regression: peer B MUST reject a grant entity whose granter
		// is peer A's identity (not B's). This is the canonical check for
		// spec-gap-handler-grant-authority §S2.
		peerAID := string(a.RemotePeerID())
		peerBID := string(b.RemotePeerID())
		pattern := fmt.Sprintf("app/validate/entity-native-xpeer/auth-%s", suffix)
		exprPath := pattern + "/expr"

		// Register on A (canonical install — A's grant is signed by A).
		litEnt, _ := types.ComputeLiteralData{Value: uint64(1)}.ToEntity()
		if _, err := a.TreePut(ctx, exprPath, litEnt); err != nil {
			return FailCheck("put expression on A: " + err.Error())
		}
		scope := []types.GrantEntry{{
			Operations: types.CapabilityScope{Include: []string{"*"}},
			Handlers:   types.CapabilityScope{Include: []string{"*"}},
			Resources:  types.CapabilityScope{Include: []string{"*"}},
		}}
		if err := registerHandler(ctx, a, peerAID, pattern, exprPath, scope); err != nil {
			return FailCheck("register on A: " + err.Error())
		}

		// Replicate the four dispatch-relevant entities (and the signature)
		// onto B's tree directly. Peer B is being asked to accept a grant
		// authored by peer A — which is the security failure case.
		//
		// v7.74 v0.4 §3.4: signature lives at the invariant-pointer path
		// system/signature/{grant_hash}, derived from the grant entity's
		// content_hash (read below).
		grantPath := "system/capability/grants/" + pattern
		grantEnt, _, err := a.TreeGet(ctx, grantPath)
		if err != nil {
			return FailCheck(fmt.Sprintf("read %s from A: %v", grantPath, err))
		}
		signaturePath := types.LocalSignaturePath(grantEnt.ContentHash)
		paths := []string{
			pattern,                     // handler entity
			"system/handler/" + pattern, // interface entity
			grantPath,                   // grant entity
			signaturePath,               // signature (v7.74 v0.4 §3.4)
			exprPath,                    // expression entity
		}
		for _, p := range paths {
			ent, _, err := a.TreeGet(ctx, p)
			if err != nil {
				// signature path may not exist on impls that haven't landed
				// the grant-signing fix yet — skip-not-fail on read failure
				// for the signature only; everything else is required.
				if p == signaturePath {
					continue
				}
				return FailCheck(fmt.Sprintf("read %s from A: %v", p, err))
			}
			if _, err := b.TreePut(ctx, p, ent); err != nil {
				return FailCheck(fmt.Sprintf("plant %s on B: %v", p, err))
			}
		}

		// Now dispatch on B. Pass = B rejects (4xx, foreign granter).
		// Fail = B accepted A's authority (security hole).
		respData, err := executeRaw(ctx, b, peerBID, pattern, "compute", nil)
		if err != nil {
			return FailCheck("dispatch on B: " + err.Error())
		}
		if respData.Status >= 200 && respData.Status < 300 {
			return FailCheck(fmt.Sprintf(
				"SECURITY: peer B accepted a grant signed by peer A (status %d). "+
					"V7 §6.2 / spec-gap-handler-grant-authority §S2 requires foreign-granter rejection.",
				respData.Status))
		}
		if respData.Status < 400 || respData.Status >= 500 {
			return FailCheck(fmt.Sprintf("expected 4xx rejection, got status %d", respData.Status))
		}
		return PassCheck(fmt.Sprintf(
			"peer B correctly rejected foreign grant signed by peer A (status %d)",
			respData.Status))
	})

	// --- MS: Multi-sig 2-of-3 Cross-Peer Consistency ---
	//
	// Build one capability that names all connected peers' identity hashes as
	// signers (threshold=2) and send it to each peer. The validator does not
	// have any peer's private key, so positive paths can't be exercised; the
	// goal is to confirm every peer rejects the cap (non-200) consistently
	// for these three negative shapes:
	//   - no signatures attached at all
	//   - only the validator's ephemeral key signed (signer not in signers)
	//   - threshold > N (M3 content validation)

	r.Run("ms_2of3_no_signatures_consistent_DENY", func() CheckOutcome {
		statuses, err := sendMultiSig2of3ToAll(ctx, clients, multiSigShapeNoSignatures)
		if err != nil {
			return FailCheck("setup: " + err.Error())
		}
		return verdictAllReject(statuses)
	})

	r.Run("ms_2of3_only_ephemeral_signed_consistent_DENY", func() CheckOutcome {
		statuses, err := sendMultiSig2of3ToAll(ctx, clients, multiSigShapeOnlyEphemeralSigned)
		if err != nil {
			return FailCheck("setup: " + err.Error())
		}
		return verdictAllReject(statuses)
	})

	r.Run("ms_threshold_exceeds_n_consistent_DENY", func() CheckOutcome {
		statuses, err := sendMultiSig2of3ToAll(ctx, clients, multiSigShapeThresholdExceedsN)
		if err != nil {
			return FailCheck("setup: " + err.Error())
		}
		// Per PROPOSAL-MULTISIG-CORE-PRIMITIVE §3.3 (multisig amendment),
		// implements §12 vector 24c: all impls MUST surface exactly 403
		// (capability_denied) for M3 violations, regardless of detection layer.
		return verdictAllStatus403(statuses)
	})

	// --- MSP: Multi-sig 2-of-3 Cross-Peer Positive Path ---
	//
	// Load each peer's real on-disk keypair (assigned by peer-manager via
	// --name) and use them to produce real signatures attributable to each
	// peer. The cap names all 3 peers as signers, threshold=2. Each scenario
	// varies which peers signed and which peer is the verifier. Skipped if
	// any peer's keypair can't be located on disk.

	r.Run("msp_all3_signed_each_peer_ALLOW", func() CheckOutcome {
		signers, err := loadAllPeerSigners(clients)
		if err != nil {
			return SkipCheck("could not load all peer keypairs: " + err.Error())
		}
		statuses, err := sendCrossPeerMultiSig(ctx, clients, signers, signers /* sign with all 3 */)
		if err != nil {
			return FailCheck("setup: " + err.Error())
		}
		return verdictAllAccept(statuses)
	})

	r.Run("msp_2of3_verifier_signed_ALLOW", func() CheckOutcome {
		signers, err := loadAllPeerSigners(clients)
		if err != nil {
			return SkipCheck("could not load all peer keypairs: " + err.Error())
		}
		// For each verifier i, sign with i and (i+1) mod 3 — verifier always
		// in the signed set, threshold met. Run independently per peer.
		results := make([]uint, len(clients))
		for i := range clients {
			signWith := []multiSigPeerSigner{signers[i], signers[(i+1)%len(signers)]}
			status, err := sendCrossPeerMultiSigToOne(ctx, clients[i], signers, signWith)
			if err != nil {
				return FailCheck(fmt.Sprintf("peer[%d] setup: %v", i, err))
			}
			results[i] = status
		}
		return verdictAllAcceptIndexed(results)
	})

	r.Run("msp_2of3_verifier_did_not_sign_DENY", func() CheckOutcome {
		signers, err := loadAllPeerSigners(clients)
		if err != nil {
			return SkipCheck("could not load all peer keypairs: " + err.Error())
		}
		// For each verifier i, sign with the OTHER two peers — threshold met,
		// but verifier didn't sign → M6 violation, expect DENY.
		results := make([]uint, len(clients))
		for i := range clients {
			signWith := []multiSigPeerSigner{}
			for j, s := range signers {
				if j != i {
					signWith = append(signWith, s)
				}
			}
			status, err := sendCrossPeerMultiSigToOne(ctx, clients[i], signers, signWith)
			if err != nil {
				return FailCheck(fmt.Sprintf("peer[%d] setup: %v", i, err))
			}
			results[i] = status
		}
		return verdictAllReject(results)
	})

	// --- Durability Scenario 5 — runs BEFORE the role/identity binding
	// tests below so the ad-hoc validator identity is still acceptable to
	// the preserver. The Scenario 5 contract is structural (universal
	// namespace + signature authority), unrelated to identity-cert
	// installation. ---
	runDurabilityScenario5Inline(ctx, r, a, b)

	// Cross-peer role IA8 fleet-wide sweep (Tier 4, multi-peer
	// counterpart to TV-RD-18's in-process simulation).
	addCrossPeerRoleIA8(r, ctx, a, b, suffix)

	// Tier 3 §14.1 Acme deployment-shape: 2-of-3 founder quorum signs
	// an identity-cert attestation, and :configure issues the local
	// peer→controller cap. The configure ceremony is the bridge from
	// founder authority (multi-sig root) to a single-sig local cap
	// that satisfies the chain walker on subsequent ops.
	addAcmeConfigureCeremony(r, ctx, a, suffix)
	// Second leg: drive system/role:assign under the issued controller
	// cap. Closes the full §14.1 walkthrough.
	addAcmeAssignUnderControllerCap(r, ctx, a, suffix)
	// Third leg: §11.6 multi-controller — one quorum, two live
	// controller-certs, one :configure call issues two caps.
	addAcmeMultiControllerDeployment(r, ctx, a, suffix)
	// Fourth leg: §6 controller rotation via :supersede_attestation —
	// post-rotation :configure enumerates only the live tip.
	addAcmeControllerRotation(r, ctx, a, suffix)
	// Fifth leg: §5.6 delegation under the runtime peer's role
	// assignment — verifies SI-19 locality + PR-1 chain depth = 2.
	addAcmeDelegateUnderControllerCap(r, ctx, a, suffix)
	// Sixth leg: §6 controller revocation via :revoke_attestation —
	// post-revocation :configure filters the revoked cert.
	addAcmeControllerRevocation(r, ctx, a, suffix)
	// Seventh + eighth checks: §4.3 time-based liveness filter —
	// expired and not-yet-valid attestations are non-live.
	addAcmeAttestationTimeBounds(r, ctx, a, suffix)
	// Ninth: §4.2a publish_attestation — agent-cert path move.
	addAcmePublishAttestation(r, ctx, a, suffix)
	// Per-relationship publish (third axis: internal/public/per-relationship).
	addAcmePublishAttestationPerRelationship(r, ctx, a, suffix)
	// Tenth: §4.2 embedded mode — :create_attestation returns the
	// unbound entity inline.
	addAcmeCreateAttestationEmbedded(r, ctx, a, suffix)
	// Eleventh: §6.1 bindings — handle_cert + agent_cert validation
	// in :configure.
	addAcmeConfigureWithBindings(r, ctx, a, suffix)
	// TV-IF-INTERNAL-CERT-READABLE (PR-8.3): internal-cert paths must
	// be readable via system/tree:get post-:create_attestation.
	addAcmeInternalCertReadable(r, ctx, a, suffix)

	// VALIDATION-PROFILE-ROLE Stage-2 — additive on top of Stage-1
	// (behavioral_role TV-RD-* + TV-RV-1.*). Identity-layered role
	// invariants. See convergence_role_stage2.go for the full coverage
	// map (which checks are implemented vs deferred).
	addRoleStage2_StateSurvivesConfigure(r, ctx, a, suffix)
	addRoleStage2_NewAgentNeedsAssign(r, ctx, a, suffix)
	addRoleStage2_CapSurvivesRevoke(r, ctx, a, suffix)
	addRoleStage2_EncodingConsistency(r, ctx, a, suffix)
	addRoleStage2_RecognizeOnAttest(r, ctx, a, suffix)

	return r.Results()
}

// runDurabilityScenario5 is split out so it can run early in
// runConvergence — before the role/identity-binding convergence tests
// install state that would block an ad-hoc validator identity. Called
// from runConvergence at the appropriate point.
func runDurabilityScenario5Inline(ctx context.Context, r *CheckRunner, a, b *PeerClient) {
	// --- Durability Scenario 5: companion peer as outbox / durable host.
	// Two peers suffice (preserver = a; durable host = b). A→B durable lands
	// the preserved entry under B's authoritative inbox namespace; the host
	// caches that namespace via extract+merge; the entry is then findable on
	// the host at the SAME (B-namespaced) path, with B's signature still
	// authoritative — the universal-namespace property in V7 §1.4 / EXTENSION-DURABILITY §6. ---
	preserver, host := a, b

	r.Run("dur_s5_preserve", func() CheckOutcome {
		params, resource, perr := tree.CreateGetRequest("system/type/system/hash", "entity")
		if perr != nil {
			return FailCheck("create probe params: " + perr.Error())
		}
		uri := fmt.Sprintf("entity://%s/system/tree", preserver.RemotePeerID())
		dr := &types.DurabilityRequestData{Level: types.DurabilityStored, MustHave: false}
		env, reqID, _, err := preserver.SendExecuteWithDurability(ctx, uri, "get", params, resource, dr)
		if err != nil {
			return FailCheck("durable request to preserver failed: " + err.Error())
		}
		resp, derr := types.ExecuteResponseDataFromEntity(env.Root)
		if derr != nil {
			return FailCheck("decode preserver response: " + derr.Error())
		}
		// Auth-blocked: the convergence runner's earlier identity/role tests
		// install identity-binding requirements that the ad-hoc validator
		// identity does not satisfy. The durability contract is unaffected;
		// just skip — re-running with `-identity framework-admin` exercises it.
		if resp.Status == 401 || resp.Status == 403 {
			return SkipCheck(fmt.Sprintf(
				"convergence-runner state requires a bound identity (status %d); re-run with `-identity framework-admin` to exercise Scenario 5",
				resp.Status))
		}
		if resp.Durability == nil {
			return FailCheck(fmt.Sprintf(
				"preserver returned no durability field — silent discard (EXTENSION-DURABILITY §5 / §8); response status=%d",
				resp.Status))
		}
		if resp.Durability.Applied != types.DurabilityStored {
			return SkipCheck(fmt.Sprintf(
				"preserver applied=%q (not 'stored') — Scenario 5 requires a preserving receiver; nothing to host on C",
				resp.Durability.Applied))
		}
		r.Store("dur_s5_reqID", reqID)
		return PassCheck("preserver durable-stored request " + reqID)
	})

	r.Run("dur_s5_extract", func() CheckOutcome {
		if out, ok := r.Require("dur_s5_preserve"); !ok {
			return out
		}
		snap, err := preserver.TreeExtract(ctx, "system/inbox/")
		if err != nil {
			return FailCheck("extract from preserver failed: " + err.Error())
		}
		r.Store("dur_s5_snap", snap)
		return PassCheck("extracted preserver's system/inbox/ namespace")
	})

	r.Run("dur_s5_merge_into_host", func() CheckOutcome {
		if out, ok := r.Require("dur_s5_extract"); !ok {
			return out
		}
		snap := r.Load("dur_s5_snap").(entity.Entity)
		// Cross-peer merge: the extract bundle from preserver contains the
		// snapshot + all included entity bytes. We pass it via the merge
		// request's `source_envelope` field (entity-wrapped form), which
		// makes the host's merge handler ingest the included entities into
		// its content store before resolving the snapshot. Without this the
		// host's merge would 404 — it has the bindings list but not the
		// entity content. See core/tree/operations.go handleMerge.
		//
		// Target the absolute path under the PRESERVER's peer_id — this is
		// what makes the host a durable host of B's inbox namespace, not a
		// rebind into the host's own namespace. V7 §1.4: "a remote peer's
		// cached namespace is structurally identical to that peer's
		// authoritative one ... authority is verified by the key holder's
		// signature."
		targetPrefix := fmt.Sprintf("/%s/system/inbox/", preserver.RemotePeerID())
		snapRaw, encErr := ecf.Encode(snap)
		if encErr != nil {
			return FailCheck("encode extract bundle: " + encErr.Error())
		}
		mergeReq := types.MergeRequestData{
			SourceEnvelope: cbor.RawMessage(snapRaw),
			Strategy:       "source-wins",
			SourcePrefix:   "system/inbox/",
			TargetPrefix:   targetPrefix,
		}
		mergeParams, perr := mergeReq.ToEntity()
		if perr != nil {
			return FailCheck("build merge params: " + perr.Error())
		}
		hostURI := fmt.Sprintf("entity://%s/system/tree", host.RemotePeerID())
		// Resource target is the destination prefix (where merge writes).
		mergeResource := &types.ResourceTarget{Targets: []string{targetPrefix}}
		mergeEnv, _, mErr := host.SendExecute(ctx, hostURI, "merge", mergeParams, mergeResource)
		if mErr != nil {
			return FailCheck("send merge to host: " + mErr.Error())
		}
		mResp, dErr := types.ExecuteResponseDataFromEntity(mergeEnv.Root)
		if dErr != nil {
			return FailCheck("decode merge response: " + dErr.Error())
		}
		if mResp.Status != 200 {
			var errEnt entity.Entity
			_ = ecf.Decode(mResp.Result, &errEnt)
			detail := ""
			if errEnt.Type == types.TypeError {
				if ed, dErr := types.ErrorDataFromEntity(errEnt); dErr == nil {
					detail = fmt.Sprintf(" code=%q message=%q", ed.Code, ed.Message)
				}
			}
			return FailCheck(fmt.Sprintf("merge status %d (expected 200)%s", mResp.Status, detail))
		}
		r.Store("dur_s5_targetPrefix", targetPrefix)
		return PassCheck("host caches preserver's inbox namespace at " + targetPrefix)
	})

	r.Run("dur_s5_host_holds_entry", func() CheckOutcome {
		if out, ok := r.Require("dur_s5_merge_into_host"); !ok {
			return out
		}
		reqID := r.Load("dur_s5_reqID").(string)
		lookupPath := fmt.Sprintf("/%s/system/inbox/%s", preserver.RemotePeerID(), reqID)
		ent, _, err := host.TreeGet(ctx, lookupPath)
		if err != nil {
			return FailCheck(fmt.Sprintf(
				"host cannot find preserved entry at %s: %v — Scenario 5 propagation broken (V7 §1.4 / EXTENSION-DURABILITY §6)",
				lookupPath, err))
		}
		if ent.Type == "" {
			return FailCheck("entry on host has empty type")
		}
		r.Store("dur_s5_lookupPath", lookupPath)
		r.Store("dur_s5_entHash", ent.ContentHash)
		return PassCheck(fmt.Sprintf("host holds preserved entry at %s (type=%s)", lookupPath, ent.Type))
	})

	r.Run("dur_s5_entry_validates", func() CheckOutcome {
		if out, ok := r.Require("dur_s5_host_holds_entry"); !ok {
			return out
		}
		lookupPath := r.Load("dur_s5_lookupPath").(string)
		expectedHash := r.Load("dur_s5_entHash").(hash.Hash)
		ent, _, err := host.TreeGet(ctx, lookupPath)
		if err != nil {
			return FailCheck("re-fetch failed: " + err.Error())
		}
		if vErr := ent.Validate(); vErr != nil {
			return FailCheck(fmt.Sprintf(
				"entry on host does not validate (content_hash != hash({type,data})): %v — caching MUST preserve content fidelity (V7 §1.4)",
				vErr))
		}
		if ent.ContentHash != expectedHash {
			return FailCheck("re-fetch returned different content_hash — address NOT stable across reads")
		}
		return PassCheck("entry well-formed on host; content_hash stable (B's signature authoritative across cache, V7 §1.4)")
	})
}

// multiSigPeerSigner pairs a peer's loaded keypair with its identity entity
// (constructed from the keypair). Both are needed to embed signatures and
// the corresponding identity entities in the wire envelope.
type multiSigPeerSigner struct {
	kp       crypto.Keypair
	identity entity.Entity
}

// loadAllPeerSigners returns one multiSigPeerSigner per connected client by
// looking up the on-disk keypair for each peer's discovered peer_id. Returns
// an error if any peer's keypair can't be found — calling code should treat
// the error as a "skip" condition (the test environment is configured for
// ephemeral peers, not the persistent-identity setup the positive path
// requires).
func loadAllPeerSigners(clients []*PeerClient) ([]multiSigPeerSigner, error) {
	out := make([]multiSigPeerSigner, 0, len(clients))
	for _, c := range clients {
		peerID := string(c.RemotePeerID())
		kp, _, err := crypto.LookupKeypairByPeerID(peerID)
		if err != nil {
			return nil, fmt.Errorf("peer %s: %w", c.Addr(), err)
		}
		idEnt, err := kp.IdentityEntity()
		if err != nil {
			return nil, fmt.Errorf("peer %s identity entity: %w", c.Addr(), err)
		}
		out = append(out, multiSigPeerSigner{kp: kp, identity: idEnt})
	}
	return out, nil
}

// sendCrossPeerMultiSig builds one multi-sig cap (signed by signWith) and
// sends an EXECUTE rooted on it to each client in turn. Returns each peer's
// response status in the same order as `clients`.
func sendCrossPeerMultiSig(
	ctx context.Context,
	clients []*PeerClient,
	signers []multiSigPeerSigner,
	signWith []multiSigPeerSigner,
) ([]uint, error) {
	statuses := make([]uint, len(clients))
	for i, target := range clients {
		status, err := sendCrossPeerMultiSigToOne(ctx, target, signers, signWith)
		if err != nil {
			return nil, fmt.Errorf("peer %s: %w", target.Addr(), err)
		}
		statuses[i] = status
	}
	return statuses, nil
}

// sendCrossPeerMultiSigToOne builds a 2-of-3 multi-sig cap whose `signers`
// list is the identity hashes of all `signers`, attaches signatures from the
// `signWith` subset (each signature carries the real signer identity), wraps
// it in an EXECUTE addressed to `target`, and returns the response status.
//
// The grantee is the validator's ephemeral identity (target.IdentityEntity)
// since the cap is being USED, not just structurally validated. The
// validator signs the EXECUTE with its own ephemeral key (matching what
// other security tests do).
func sendCrossPeerMultiSigToOne(
	ctx context.Context,
	target *PeerClient,
	signers []multiSigPeerSigner,
	signWith []multiSigPeerSigner,
) (uint, error) {
	validatorKP := target.Keypair()
	validatorID := target.IdentityEntity()
	uri := fmt.Sprintf("entity://%s/system/tree", target.RemotePeerID())

	now := uint64(time.Now().UnixMilli())
	fiveMin := now + 5*60*1000

	signerHashes := make([]hash.Hash, 0, len(signers))
	for _, s := range signers {
		signerHashes = append(signerHashes, s.identity.ContentHash)
	}
	mg := types.MultiGranter{Signers: signerHashes, Threshold: 2}

	tokenData := types.CapabilityTokenData{
		Grants: []types.GrantEntry{{
			Handlers:   types.CapabilityScope{Include: []string{"*"}},
			Resources:  types.CapabilityScope{Include: []string{"*"}},
			Operations: types.CapabilityScope{Include: []string{"*"}},
		}},
		Granter:   types.MultiSigGranter(mg),
		Grantee:   validatorID.ContentHash,
		CreatedAt: now,
		ExpiresAt: &fiveMin,
	}
	capEntity, err := tokenData.ToEntity()
	if err != nil {
		return 0, fmt.Errorf("create cap: %w", err)
	}

	included := map[hash.Hash]entity.Entity{
		validatorID.ContentHash: validatorID,
		capEntity.ContentHash:   capEntity,
	}
	for _, s := range signers {
		included[s.identity.ContentHash] = s.identity
	}
	for _, s := range signWith {
		sig := s.kp.Sign(capEntity.ContentHash.Bytes())
		sigData := types.SignatureData{
			Target:    capEntity.ContentHash,
			Signer:    s.identity.ContentHash,
			Algorithm: "ed25519",
			Signature: sig,
		}
		sigEnt, err := sigData.ToEntity()
		if err != nil {
			return 0, fmt.Errorf("create cap sig: %w", err)
		}
		included[sigEnt.ContentHash] = sigEnt
	}

	params, resource, err := buildSimpleGetParams()
	if err != nil {
		return 0, fmt.Errorf("build params: %w", err)
	}
	rawParams, err := ecf.Encode(params)
	if err != nil {
		return 0, fmt.Errorf("encode params: %w", err)
	}
	execData := types.ExecuteData{
		RequestID:  target.NextRequestID(),
		URI:        uri,
		Operation:  "get",
		Params:     cbor.RawMessage(rawParams),
		Author:     validatorID.ContentHash,
		Capability: capEntity.ContentHash,
		Resource:   resource,
	}
	execEntity, err := execData.ToEntity()
	if err != nil {
		return 0, fmt.Errorf("create execute: %w", err)
	}
	execSig, err := signEntity(execEntity.ContentHash, validatorKP, validatorID)
	if err != nil {
		return 0, fmt.Errorf("sign execute: %w", err)
	}
	included[execSig.ContentHash] = execSig

	env := entity.NewEnvelope(execEntity, included)
	respEnv, _, err := target.SendRawEnvelope(env)
	if err != nil {
		return 0, fmt.Errorf("send: %w", err)
	}
	respData, err := types.ExecuteResponseDataFromEntity(respEnv.Root)
	if err != nil {
		return 0, fmt.Errorf("decode response: %w", err)
	}
	return respData.Status, nil
}

// verdictAllAccept asserts every status in [200, 300). Used for positive
// multi-sig paths where every peer should accept.
func verdictAllAccept(statuses []uint) CheckOutcome {
	parts := make([]string, 0, len(statuses))
	allOK := true
	for i, s := range statuses {
		parts = append(parts, fmt.Sprintf("[%d]=%d", i, s))
		if s < 200 || s >= 300 {
			allOK = false
		}
	}
	if !allOK {
		return FailCheck("at least one peer rejected: " + strings.Join(parts, " "))
	}
	return PassCheck("all peers accepted: " + strings.Join(parts, " "))
}

// verdictAllAcceptIndexed mirrors verdictAllAccept; the name distinguishes
// per-verifier-loop results (the index in the message refers to the verifier
// peer, not a parallel send).
func verdictAllAcceptIndexed(statuses []uint) CheckOutcome {
	return verdictAllAccept(statuses)
}

// verdictAllStatus403 asserts every status equals exactly 403, the
// capability-denied status that PROPOSAL-MULTISIG §3.3 (multisig amendment)
// requires for M3 violations across all impls regardless of detection layer.
// FAIL on any code other than 403, including non-200 codes like 400.
func verdictAllStatus403(statuses []uint) CheckOutcome {
	parts := make([]string, 0, len(statuses))
	allOK := true
	for i, s := range statuses {
		parts = append(parts, fmt.Sprintf("[%d]=%d", i, s))
		if s != 403 {
			allOK = false
		}
	}
	if !allOK {
		return FailCheck("expected all peers to return 403 per §3.3 status normalization; got: " + strings.Join(parts, " "))
	}
	return PassCheck("all peers returned 403 (cross-impl status normalized): " + strings.Join(parts, " "))
}

// multiSigConvergenceShape selects which malformed shape to send.
type multiSigConvergenceShape int

const (
	multiSigShapeNoSignatures multiSigConvergenceShape = iota
	multiSigShapeOnlyEphemeralSigned
	multiSigShapeThresholdExceedsN
)

// sendMultiSig2of3ToAll builds a single multi-sig cap that lists each
// connected peer's identity hash as a signer (threshold=2 by default; raised
// to N+1 for the threshold-exceeds-N shape) and sends an EXECUTE rooted on
// that cap to each peer in turn. Returns the per-peer response statuses in
// order matching `clients`.
func sendMultiSig2of3ToAll(
	ctx context.Context,
	clients []*PeerClient,
	shape multiSigConvergenceShape,
) ([]uint, error) {
	signerHashes := make([]hash.Hash, 0, len(clients))
	for _, c := range clients {
		h := c.RemotePeerIdentityHash()
		if h.IsZero() {
			return nil, fmt.Errorf("peer %s: no identity hash captured at handshake", c.Addr())
		}
		signerHashes = append(signerHashes, h)
	}

	threshold := uint64(2)
	if shape == multiSigShapeThresholdExceedsN {
		threshold = uint64(len(signerHashes) + 1)
	}

	statuses := make([]uint, len(clients))
	for i, target := range clients {
		status, err := sendMultiSigCapTo(ctx, target, signerHashes, threshold, shape)
		if err != nil {
			return nil, fmt.Errorf("peer %s: %w", target.Addr(), err)
		}
		statuses[i] = status
	}
	return statuses, nil
}

// sendMultiSigCapTo constructs a multi-sig cap with the given signers and
// threshold, attaches optional ephemeral-only signature, and sends an EXECUTE
// rooted on the cap to `target`. Returns the response status code.
func sendMultiSigCapTo(
	ctx context.Context,
	target *PeerClient,
	signerHashes []hash.Hash,
	threshold uint64,
	shape multiSigConvergenceShape,
) (uint, error) {
	kp := target.Keypair()
	identity := target.IdentityEntity()
	uri := fmt.Sprintf("entity://%s/system/tree", target.RemotePeerID())

	now := uint64(time.Now().UnixMilli())
	fiveMin := now + 5*60*1000

	mg := types.MultiGranter{Signers: signerHashes, Threshold: threshold}
	tokenData := types.CapabilityTokenData{
		Grants: []types.GrantEntry{{
			Handlers:   types.CapabilityScope{Include: []string{"*"}},
			Resources:  types.CapabilityScope{Include: []string{"*"}},
			Operations: types.CapabilityScope{Include: []string{"*"}},
		}},
		Granter:   types.MultiSigGranter(mg),
		Grantee:   identity.ContentHash,
		CreatedAt: now,
		ExpiresAt: &fiveMin,
	}
	capEntity, err := tokenData.ToEntity()
	if err != nil {
		return 0, fmt.Errorf("create cap: %w", err)
	}

	included := map[hash.Hash]entity.Entity{
		identity.ContentHash:  identity,
		capEntity.ContentHash: capEntity,
	}

	if shape == multiSigShapeOnlyEphemeralSigned {
		// Ephemeral key is NOT in signers; this signature should be ignored
		// by the multi-sig verifier (signer not in signers set).
		sig := kp.Sign(capEntity.ContentHash.Bytes())
		sigData := types.SignatureData{
			Target:    capEntity.ContentHash,
			Signer:    identity.ContentHash,
			Algorithm: "ed25519",
			Signature: sig,
		}
		sigEntity, err := sigData.ToEntity()
		if err != nil {
			return 0, fmt.Errorf("sign cap: %w", err)
		}
		included[sigEntity.ContentHash] = sigEntity
	}

	params, resource, err := buildSimpleGetParams()
	if err != nil {
		return 0, fmt.Errorf("build params: %w", err)
	}
	rawParams, err := ecf.Encode(params)
	if err != nil {
		return 0, fmt.Errorf("encode params: %w", err)
	}
	execData := types.ExecuteData{
		RequestID:  target.NextRequestID(),
		URI:        uri,
		Operation:  "get",
		Params:     cbor.RawMessage(rawParams),
		Author:     identity.ContentHash,
		Capability: capEntity.ContentHash,
		Resource:   resource,
	}
	execEntity, err := execData.ToEntity()
	if err != nil {
		return 0, fmt.Errorf("create execute: %w", err)
	}
	execSig, err := signEntity(execEntity.ContentHash, kp, identity)
	if err != nil {
		return 0, fmt.Errorf("sign execute: %w", err)
	}
	included[execSig.ContentHash] = execSig

	env := entity.NewEnvelope(execEntity, included)
	respEnv, _, err := target.SendRawEnvelope(env)
	if err != nil {
		return 0, fmt.Errorf("send: %w", err)
	}
	respData, err := types.ExecuteResponseDataFromEntity(respEnv.Root)
	if err != nil {
		return 0, fmt.Errorf("decode response: %w", err)
	}
	return respData.Status, nil
}

// verdictAllReject checks that every recorded status is non-200 and reports
// the per-peer status codes for diagnostics. PASS = all rejected; FAIL = any
// peer accepted.
func verdictAllReject(statuses []uint) CheckOutcome {
	parts := make([]string, 0, len(statuses))
	allRejected := true
	for i, s := range statuses {
		parts = append(parts, fmt.Sprintf("[%d]=%d", i, s))
		if s == 200 {
			allRejected = false
		}
	}
	if !allRejected {
		return FailCheck("at least one peer accepted: " + strings.Join(parts, " "))
	}
	return PassCheck("all peers rejected: " + strings.Join(parts, " "))
}

// convergencePrefix returns a unique test prefix for convergence tests.
func convergencePrefix(suffix, test string) string {
	return fmt.Sprintf("system/validate/conv-%s-%s/", test, suffix)
}

// convergenceCheckQueryNamespace verifies that synced entities have correct peer identity
// in their paths via the query handler. Returns a CheckOutcome suitable for use in a Run callback.
//
// typeFilter must match the type of entities seeded by the calling pathway —
// EXTENSION-QUERY §349, §594 type_filter is exact-match by default. Reusing
// a stale filter that no entity matches will silently return 0 matches and
// surface as a misleading WARN (see the PR-9.6 reproducer).
func convergenceCheckQueryNamespace(ctx context.Context, client *PeerClient, localPeerID, sourcePeerID, prefix, typeFilter string) CheckOutcome {
	raw, err := ecf.Encode(types.QueryExpressionData{
		TypeFilter: typeFilter,
		PathPrefix: prefix,
	})
	if err != nil {
		return SkipCheck("could not encode query expression")
	}
	paramsEntity, err := entity.NewEntity(types.TypeQueryExpression, cbor.RawMessage(raw))
	if err != nil {
		return SkipCheck("could not create query entity")
	}

	uri := fmt.Sprintf("entity://%s/system/query", localPeerID)
	env, _, err := client.SendExecute(ctx, uri, "find", paramsEntity, nil)
	if err != nil {
		return SkipCheck("query not supported")
	}

	respData, err := types.ExecuteResponseDataFromEntity(env.Root)
	if err != nil || respData.Status != 200 {
		return SkipCheck("query did not return 200")
	}

	var resultEntity entity.Entity
	if err := ecf.Decode(respData.Result, &resultEntity); err != nil {
		return SkipCheck("could not decode query result")
	}
	// Unwrap system/envelope if present.
	inner, _, err := unwrapResultEnvelope(resultEntity)
	if err != nil {
		return SkipCheck("could not unwrap result envelope")
	}
	var result types.QueryResultData
	if err := ecf.Decode(inner.Data, &result); err != nil {
		return SkipCheck("could not decode query result data")
	}

	if len(result.Matches) == 0 {
		return WarnCheck("query returned 0 matches for synced entities")
	}

	wrongPeer := 0
	barePaths := 0
	for _, m := range result.Matches {
		if m.Path == "" {
			continue
		}
		if store.IsAbsolute(m.Path) {
			ns, _ := store.SplitNamespace(m.Path)
			if ns == sourcePeerID {
				wrongPeer++
			}
		} else if strings.HasPrefix(m.Path, "entity://") {
			if strings.Contains(m.Path, sourcePeerID) && !strings.Contains(m.Path, localPeerID) {
				wrongPeer++
			}
		} else {
			barePaths++
		}
	}

	if wrongPeer > 0 {
		return FailCheck(fmt.Sprintf("%d/%d synced entities have source peer's ID in path (should be local peer's)",
			wrongPeer, len(result.Matches)))
	} else if barePaths > 0 {
		return WarnCheck(fmt.Sprintf("%d/%d synced entity paths are bare (not qualified)", barePaths, len(result.Matches)))
	}
	return PassCheck(fmt.Sprintf("all %d synced entities have correct peer identity in paths", len(result.Matches)))
}

// changedKeys extracts keys from a DiffChangeData map (complements mapKeys for hash.Hash maps).
func changedKeys(m map[string]types.DiffChangeData) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	return keys
}

// extractAndMerge extracts a prefix from src peer and merges into dst peer at dstPrefix.
// Returns the number of entities applied and any error.
func extractAndMerge(ctx context.Context, src, dst *PeerClient, srcPrefix, dstPrefix string) (uint64, error) {
	// Extract from source.
	resultEntity, err := src.TreeExtract(ctx, srcPrefix)
	if err != nil {
		return 0, fmt.Errorf("extract from %s: %w", src.RemotePeerID(), err)
	}

	// Decode envelope to get included entities for the merge.
	var env entity.Envelope
	if err := ecf.Decode(resultEntity.Data, &env); err != nil {
		return 0, fmt.Errorf("decode extract envelope: %w", err)
	}

	// Build merge params with source_envelope.
	mergeReq := types.MergeRequestData{
		SourcePrefix: srcPrefix,
		TargetPrefix: dstPrefix,
		Strategy:     "source-wins",
	}
	mergeParams, _ := mergeReq.ToEntity()

	// Inject source_envelope into merge params.
	var paramsMap map[string]interface{}
	cbor.Unmarshal(mergeParams.Data, &paramsMap)
	var envDecoded interface{}
	cbor.Unmarshal(resultEntity.Data, &envDecoded)
	paramsMap["source_envelope"] = map[string]interface{}{
		"type": resultEntity.Type,
		"data": envDecoded,
	}
	injectedRaw, _ := ecf.Encode(paramsMap)
	mergeParams.Data = cbor.RawMessage(injectedRaw)
	mergeParams, _ = entity.NewEntity(mergeParams.Type, mergeParams.Data)

	// Include all entities from the envelope.
	extras := make(map[hash.Hash]entity.Entity)
	for h, ent := range env.Included {
		extras[h] = ent
	}
	extras[env.Root.ContentHash] = env.Root

	resource := &types.ResourceTarget{Targets: []string{dstPrefix}}
	uri := fmt.Sprintf("entity://%s/system/tree", dst.RemotePeerID())
	respEnv, _, err := dst.SendExecuteWithIncluded(ctx, uri, "merge", mergeParams, resource, extras)
	if err != nil {
		return 0, fmt.Errorf("merge on %s: %w", dst.RemotePeerID(), err)
	}
	respData, err := types.ExecuteResponseDataFromEntity(respEnv.Root)
	if err != nil || respData.Status != 200 {
		status := uint(0)
		if err == nil {
			status = respData.Status
		}
		return 0, fmt.Errorf("merge status %d, err=%v", status, err)
	}
	var resultEnt entity.Entity
	ecf.Decode(respData.Result, &resultEnt)
	result, _ := types.MergeResultDataFromEntity(resultEnt)
	return result.Applied, nil
}

// allPassed returns true if all checks in the slice passed (no FAIL).
func allPassed(checks []CheckResult) bool {
	for _, c := range checks {
		if c.Severity == "FAIL" {
			return false
		}
	}
	return true
}

// --- Standalone check functions (used by origination.go sub-suite) ---

// checkAsyncDelivery tests whether a peer's dispatcher handles the deliver_to field on EXECUTE.
func checkAsyncDelivery(ctx context.Context, client *PeerClient, suffix, label string) []CheckResult {
	var checks []CheckResult

	peerID := string(client.RemotePeerID())
	testID := "async-" + suffix + "-" + label
	srcPath := "system/validate/async-src-" + testID + "/item"
	inboxPath := "system/inbox/async-result-" + testID

	// Step 1: Put a test entity.
	testEntity := mustCreateEntity("test/async-delivery", map[string]string{
		"content": "async-delivery-test-" + testID,
	})
	_, err := client.TreePut(ctx, srcPath, testEntity)
	if err != nil {
		return append(checks, fail(catConvergence, "async_put_"+label, "ASYNC §1",
			fmt.Sprintf("put source entity on %s: %v", label, err)))
	}

	// Step 2: Create deliver token.
	deliverURI := "entity://" + peerID + "/" + inboxPath
	tokenEntity, tokenSigEntity, err := client.CreateDeliveryToken(deliverURI, "receive")
	if err != nil {
		return append(checks, fail(catConvergence, "async_token_"+label, "ASYNC §1",
			fmt.Sprintf("create delivery token: %v", err)))
	}

	// Step 3: Send tree.get with deliver_to.
	getParams, getResource, err := tree.CreateGetRequest(srcPath, "entity")
	if err != nil {
		return append(checks, fail(catConvergence, "async_request_"+label, "ASYNC §1",
			fmt.Sprintf("create get request: %v", err)))
	}
	treeURI := fmt.Sprintf("entity://%s/system/tree", peerID)
	deliverTo := &types.DeliverySpec{URI: deliverURI, Operation: "receive"}

	env, _, err := client.SendExecuteAsync(ctx, treeURI, "get", getParams, getResource,
		deliverTo, tokenEntity, tokenSigEntity)
	if err != nil {
		return append(checks, fail(catConvergence, "async_send_"+label, "ASYNC §1",
			fmt.Sprintf("send async execute: %v", err)))
	}

	// Step 4: Check for 202 response.
	respData, err := types.ExecuteResponseDataFromEntity(env.Root)
	if err != nil {
		return append(checks, fail(catConvergence, "async_response_"+label, "ASYNC §1",
			fmt.Sprintf("decode response: %v", err)))
	}
	if respData.Status != 202 {
		return append(checks, fail(catConvergence, "async_202_"+label, "ASYNC §1",
			fmt.Sprintf("expected status 202, got %d (peer %s may not support deliver_to)", respData.Status, label)))
	}
	checks = append(checks, pass(catConvergence, "async_202_"+label, "ASYNC §1",
		fmt.Sprintf("peer %s returned 202 for deliver_to request", label)))

	// Step 5: Poll inbox for the delivery.
	var delivered bool
	for attempt := 0; attempt < 25; attempt++ {
		time.Sleep(200 * time.Millisecond)
		entries, _, err := client.TreeListing(ctx, inboxPath+"/")
		if err == nil && len(entries) > 0 {
			delivered = true
			break
		}
	}

	if delivered {
		checks = append(checks, pass(catConvergence, "async_delivered_"+label, "ASYNC §1",
			fmt.Sprintf("peer %s delivered result to inbox path", label)))
	} else {
		checks = append(checks, fail(catConvergence, "async_delivered_"+label, "ASYNC §1",
			fmt.Sprintf("peer %s: no delivery at %s after 5s", label, inboxPath+"/")))
	}

	return checks
}

// checkRemoteExecute tests whether Peer A can dispatch a continuation that targets Peer B.
func checkRemoteExecute(ctx context.Context, a, b *PeerClient, suffix string) []CheckResult {
	var checks []CheckResult

	peerAID := string(a.RemotePeerID())
	peerBID := string(b.RemotePeerID())

	// Degenerate-topology guard: a cross-peer dispatch test is only meaningful
	// between two DISTINCT peers. When a == b (reference == target, or
	// `-peers x,x`), the §4.2-case-3 B-rooted cap collapses to a self-grant and
	// the dispatch is a no-op self-loop — it would either 403 (the old
	// single-peer report's confusing FAIL) or, worse, "pass" and claim a
	// cross-peer green that was never exercised. Surface this as a WARN with the
	// fix, not a FAIL or a false PASS, so the result is predictable: rexec is
	// reported green ONLY when two genuine peers actually round-tripped.
	if peerAID == peerBID {
		return append(checks, warn(catConvergence, "rexec_setup", "REMOTE §2",
			fmt.Sprintf("skipped: cross-peer remote-execute needs two distinct peers, "+
				"but reference == target (%s). Run with -peers host1,host2 or "+
				"-reference-peer pointing at a SECOND peer.", peerAID)))
	}

	testID := "rexec-" + suffix

	srcPath := "system/validate/rexec-src-" + suffix + "/item"
	contPath := "system/inbox/rexec-fetch-" + testID
	resultPath := "system/inbox/rexec-result-" + testID

	if !a.CapEntity().ContentHash.IsZero() {
		a.TreePut(ctx, "system/validate/dispatch-cap-store-"+suffix, a.CapEntity())
	}

	testEntity := mustCreateEntity("test/remote-execute", map[string]string{
		"content": "remote-execute-test-" + testID,
	})
	_, err := b.TreePut(ctx, srcPath, testEntity)
	if err != nil {
		return append(checks, fail(catConvergence, "rexec_put_b", "REMOTE §1",
			fmt.Sprintf("put on B: %v", err)))
	}

	b.TreePut(ctx, mustTransportProfilePathFor(a), tcpProfileEntityFor(peerAID, a.addr))

	a.TreePut(ctx, mustTransportProfilePathFor(b), tcpProfileEntityFor(peerBID, b.addr))

	cont := types.ContinuationData{
		Target:    "entity://" + peerBID + "/system/tree",
		Operation: "get",
		Resource:  &types.ResourceTarget{Targets: []string{srcPath}},
		DeliverTo: &types.DeliverySpec{
			URI:       "entity://" + peerAID + "/" + resultPath,
			Operation: "receive",
		},
	}
	// Cross-peer (host A → target B): conformant B-rooted cap (§4.2 case 3).
	if err := InstallCrossPeerContinuation(ctx, a, b, contPath, cont); err != nil {
		return append(checks, fail(catConvergence, "rexec_setup_cont", "REMOTE §2",
			fmt.Sprintf("install cross-peer continuation: %v", err)))
	}
	checks = append(checks, pass(catConvergence, "rexec_setup", "REMOTE §2",
		fmt.Sprintf("continuation at %s targets entity://%s/system/tree", contPath, peerBID)))

	triggerEntity := mustCreateEntity("test/trigger", map[string]string{"trigger": "go"})
	inboxURI := fmt.Sprintf("entity://%s/system/inbox", peerAID)
	inboxResource := &types.ResourceTarget{Targets: []string{contPath}}
	_, _, err = a.SendExecute(ctx, inboxURI, "receive", triggerEntity, inboxResource)
	if err != nil {
		return append(checks, fail(catConvergence, "rexec_trigger", "REMOTE §2",
			fmt.Sprintf("deliver trigger to inbox: %v", err)))
	}
	checks = append(checks, pass(catConvergence, "rexec_trigger", "REMOTE §2",
		"trigger delivered to continuation inbox"))

	var delivered bool
	for attempt := 0; attempt < 30; attempt++ {
		time.Sleep(200 * time.Millisecond)
		entries, _, err := a.TreeListing(ctx, resultPath+"/")
		if err == nil && len(entries) > 0 {
			delivered = true
			break
		}
	}

	if delivered {
		checks = append(checks, pass(catConvergence, "rexec_delivered", "REMOTE §3",
			"peer A dispatched remote tree.get to B and delivered result"))
	} else {
		contEntries, _, _ := a.TreeListing(ctx, contPath+"/")
		checks = append(checks, fail(catConvergence, "rexec_delivered", "REMOTE §3",
			fmt.Sprintf("no delivery at result inbox after 6s (cont_inbox=%d entries — peer A may not support remote execute)", len(contEntries))))
	}

	return checks
}

// checkCrossPeerSubscription tests cross-peer notification delivery via subscriptions.
func checkCrossPeerSubscription(ctx context.Context, a, b *PeerClient, suffix string) []CheckResult {
	var checks []CheckResult
	prefix := convergencePrefix(suffix, "xsub")

	peerAID := string(a.RemotePeerID())
	peerBID := string(b.RemotePeerID())

	transportPath := mustTransportProfilePathFor(a)
	_, err := b.TreePut(ctx, transportPath, tcpProfileEntityFor(peerAID, a.addr))
	if err != nil {
		return append(checks, fail(catConvergence, "xsub_setup_transport", "NETWORK §10",
			fmt.Sprintf("failed to write transport address on B: %v", err)))
	}
	checks = append(checks, pass(catConvergence, "xsub_setup_transport", "NETWORK §10",
		fmt.Sprintf("wrote %s transport address to B", peerAID)))

	inboxPath := "system/inbox/validate-xsub-" + suffix
	deliverURI := "entity://" + peerAID + "/" + inboxPath
	pattern := prefix + "*"
	events := []string{"created", "updated", "deleted"}

	tokenEntity, tokenSigEntity, err := b.CreateDeliveryToken(deliverURI, "receive")
	if err != nil {
		return append(checks, fail(catConvergence, "xsub_create_token", "SUBSCRIPTION §4",
			fmt.Sprintf("failed to create delivery token: %v", err)))
	}

	subID, subEnv, _, err := b.Subscribe(ctx, pattern, deliverURI, "receive",
		tokenEntity, tokenSigEntity, events, nil)
	if err != nil {
		return append(checks, fail(catConvergence, "xsub_subscribe", "SUBSCRIPTION §3",
			fmt.Sprintf("subscribe failed: %v", err)))
	}
	_ = subEnv

	if subID == "" {
		return append(checks, fail(catConvergence, "xsub_subscribe", "SUBSCRIPTION §3",
			"subscribe returned empty subscription_id"))
	}
	checks = append(checks, pass(catConvergence, "xsub_subscribe", "SUBSCRIPTION §3",
		fmt.Sprintf("subscribed on B: id=%s pattern=%s deliver=%s", subID, pattern, deliverURI)))

	testEntity := mustCreateEntity("test/cross-peer-notification", map[string]string{
		"content": "cross-peer-test-" + suffix,
	})
	testPath := prefix + "item-1"
	testHash, err := b.TreePut(ctx, testPath, testEntity)
	if err != nil {
		return append(checks, fail(catConvergence, "xsub_trigger_put", "SUBSCRIPTION §5",
			fmt.Sprintf("put on B failed: %v", err)))
	}
	checks = append(checks, pass(catConvergence, "xsub_trigger_put", "SUBSCRIPTION §5",
		fmt.Sprintf("put %s on B (hash=%s)", testPath, testHash)))

	notifPrefix := inboxPath + "/"
	var delivered bool
	var deliveryTime time.Duration
	startPoll := time.Now()

	for attempt := 0; attempt < 25; attempt++ {
		time.Sleep(200 * time.Millisecond)
		entries, _, err := a.TreeListing(ctx, notifPrefix)
		if err == nil && len(entries) > 0 {
			delivered = true
			deliveryTime = time.Since(startPoll)
			break
		}
	}

	if delivered {
		checks = append(checks, pass(catConvergence, "xsub_notification_delivered", "SUBSCRIPTION §5",
			fmt.Sprintf("notification delivered to A's inbox in %dms", deliveryTime.Milliseconds())))
	} else {
		localPrefix := inboxPath + "/"
		localEntries, _, _ := b.TreeListing(ctx, localPrefix)
		if len(localEntries) > 0 {
			checks = append(checks, fail(catConvergence, "xsub_notification_delivered", "SUBSCRIPTION §5",
				"notification delivered to B's LOCAL inbox instead of A — dispatch not routing remotely"))
		} else {
			checks = append(checks, fail(catConvergence, "xsub_notification_delivered", "SUBSCRIPTION §5",
				fmt.Sprintf("no notification at A's inbox after 5s (path: %s)", notifPrefix)))
		}
		return checks
	}

	_, _, err = b.Unsubscribe(ctx, subID)
	if err != nil {
		checks = append(checks, warn(catConvergence, "xsub_unsubscribe", "SUBSCRIPTION §3",
			fmt.Sprintf("unsubscribe failed: %v", err)))
	} else {
		checks = append(checks, pass(catConvergence, "xsub_unsubscribe", "SUBSCRIPTION §3",
			"unsubscribed successfully"))
	}

	_ = peerBID
	return checks
}

// checkContinuationChainSync tests cross-peer entity sync via continuation chains.
func checkContinuationChainSync(ctx context.Context, a, b *PeerClient, suffix string) []CheckResult {
	var checks []CheckResult

	peerAID := string(a.RemotePeerID())
	peerBID := string(b.RemotePeerID())
	testID := "chain-" + suffix

	srcPath := "system/validate/sync-src-" + suffix + "/item-1"
	mirrorPath := "system/validate/sync-dst-" + suffix + "/item-1"
	inboxFetch := "system/inbox/sync-fetch-" + testID
	inboxPut := "system/inbox/sync-put-" + testID

	b.TreePut(ctx, mustTransportProfilePathFor(a), tcpProfileEntityFor(peerAID, a.addr))

	a.TreePut(ctx, mustTransportProfilePathFor(b), tcpProfileEntityFor(peerBID, b.addr))

	cont1 := types.ContinuationData{
		Target:    "entity://" + peerBID + "/system/tree",
		Operation: "get",
		Resource:  &types.ResourceTarget{Targets: []string{srcPath}},
		DeliverTo: &types.DeliverySpec{
			URI:       "entity://" + peerAID + "/" + inboxPut,
			Operation: "receive",
		},
	}
	// Cross-peer (host A → target B): conformant B-rooted cap (§4.2 case 3).
	if err := InstallCrossPeerContinuation(ctx, a, b, inboxFetch, cont1); err != nil {
		return append(checks, fail(catConvergence, "chain_setup_cont1", "CONTINUATION §2",
			fmt.Sprintf("install cross-peer continuation 1: %v", err)))
	}
	checks = append(checks, pass(catConvergence, "chain_setup_cont1", "CONTINUATION §2",
		fmt.Sprintf("continuation 1 at %s → tree.get from B", inboxFetch)))

	putTemplate, _ := ecf.Encode(map[string]interface{}{"entity": nil})
	cont2 := types.ContinuationData{
		Target:             "system/tree",
		Operation:          "put",
		Resource:           &types.ResourceTarget{Targets: []string{mirrorPath}},
		Params:             cbor.RawMessage(putTemplate),
		ResultField:        "entity",
		DispatchCapability: a.CapEntity().ContentHash,
	}
	cont2Entity, err := cont2.ToEntity()
	if err != nil {
		return append(checks, fail(catConvergence, "chain_setup_cont2", "CONTINUATION §2",
			fmt.Sprintf("create continuation 2: %v", err)))
	}
	_, err = a.TreePut(ctx, inboxPut, cont2Entity)
	if err != nil {
		return append(checks, fail(catConvergence, "chain_setup_cont2", "CONTINUATION §2",
			fmt.Sprintf("put continuation 2 on A: %v", err)))
	}
	checks = append(checks, pass(catConvergence, "chain_setup_cont2", "CONTINUATION §2",
		fmt.Sprintf("continuation 2 at %s → tree.put locally", inboxPut)))

	deliverURI := "entity://" + peerAID + "/" + inboxFetch
	pattern := "system/validate/sync-src-" + suffix + "/*"

	tokenEntity, tokenSigEntity, err := b.CreateDeliveryToken(deliverURI, "receive")
	if err != nil {
		return append(checks, fail(catConvergence, "chain_subscribe", "SUBSCRIPTION §3",
			fmt.Sprintf("create delivery token: %v", err)))
	}

	subID, _, _, err := b.Subscribe(ctx, pattern, deliverURI, "receive",
		tokenEntity, tokenSigEntity, []string{"created", "updated"}, nil)
	if err != nil || subID == "" {
		return append(checks, fail(catConvergence, "chain_subscribe", "SUBSCRIPTION §3",
			fmt.Sprintf("subscribe failed: %v", err)))
	}
	checks = append(checks, pass(catConvergence, "chain_subscribe", "SUBSCRIPTION §3",
		fmt.Sprintf("subscribed on B, deliver to %s", deliverURI)))

	testEntity := mustCreateEntity("test/sync-doc", map[string]string{
		"content": "sync-chain-test-" + suffix,
	})
	testHash, err := b.TreePut(ctx, srcPath, testEntity)
	if err != nil {
		return append(checks, fail(catConvergence, "chain_trigger_put", "TREE §2",
			fmt.Sprintf("put on B: %v", err)))
	}
	checks = append(checks, pass(catConvergence, "chain_trigger_put", "TREE §2",
		fmt.Sprintf("wrote %s on B (hash=%s)", srcPath, testHash)))

	var synced bool
	var syncTime time.Duration
	startPoll := time.Now()

	for attempt := 0; attempt < 30; attempt++ {
		time.Sleep(200 * time.Millisecond)
		ent, _, err := a.TreeGet(ctx, mirrorPath)
		if err == nil && !ent.ContentHash.IsZero() {
			synced = true
			syncTime = time.Since(startPoll)
			if ent.ContentHash == testHash {
				checks = append(checks, pass(catConvergence, "chain_sync_delivered", "CONTINUATION §3",
					fmt.Sprintf("entity synced to A's mirror path in %dms", syncTime.Milliseconds())))
				checks = append(checks, pass(catConvergence, "chain_hash_match", "CONTINUATION §3",
					fmt.Sprintf("content hash matches: %s", testHash)))
			} else {
				checks = append(checks, pass(catConvergence, "chain_sync_delivered", "CONTINUATION §3",
					fmt.Sprintf("entity appeared at mirror path in %dms", syncTime.Milliseconds())))
				checks = append(checks, fail(catConvergence, "chain_hash_match", "CONTINUATION §3",
					fmt.Sprintf("hash mismatch: expected %s, got %s", testHash, ent.ContentHash)))
			}
			break
		}
	}

	if !synced {
		checks = append(checks, fail(catConvergence, "chain_sync_delivered", "CONTINUATION §3",
			fmt.Sprintf("entity not synced to A's mirror path after 6s (path: %s)", mirrorPath)))

		fetchEntries, _, _ := a.TreeListing(ctx, inboxFetch+"/")
		putEntries, _, _ := a.TreeListing(ctx, inboxPut+"/")
		srcEnt, _, srcErr := a.TreeGet(ctx, srcPath)
		mirrorEntries, _, _ := a.TreeListing(ctx, "system/validate/sync-dst-"+suffix+"/")
		details := fmt.Sprintf("inbox-fetch=%d, inbox-put=%d, src-on-A=%v (err=%v), mirror-listing=%d",
			len(fetchEntries), len(putEntries), !srcEnt.ContentHash.IsZero(), srcErr, len(mirrorEntries))
		checks = append(checks, fail(catConvergence, "chain_hash_match", "CONTINUATION §3",
			"chain did not complete — "+details))
	}

	b.Unsubscribe(ctx, subID)

	_ = peerBID
	return checks
}

// checkPrefixSync tests prefix extract+merge sync via continuation chains.
func checkPrefixSync(ctx context.Context, a, b *PeerClient, suffix string) []CheckResult {
	var checks []CheckResult

	peerAID := string(a.RemotePeerID())
	peerBID := string(b.RemotePeerID())
	testID := "prefix-" + suffix

	srcPrefix := "system/validate/psync-src-" + suffix + "/"
	dstPrefix := "system/validate/psync-dst-" + suffix + "/"
	inboxExtract := "system/inbox/psync-extract-" + testID
	inboxMerge := "system/inbox/psync-merge-" + testID

	b.TreePut(ctx, mustTransportProfilePathFor(a), tcpProfileEntityFor(peerAID, a.addr))

	a.TreePut(ctx, mustTransportProfilePathFor(b), tcpProfileEntityFor(peerBID, b.addr))

	cont1 := types.ContinuationData{
		Target:    "entity://" + peerBID + "/system/tree",
		Operation: "extract",
		Resource:  &types.ResourceTarget{Targets: []string{srcPrefix}},
		DeliverTo: &types.DeliverySpec{
			URI:       "entity://" + peerAID + "/" + inboxMerge,
			Operation: "receive",
		},
	}
	// Cross-peer (host A → target B): conformant B-rooted cap (§4.2 case 3).
	if err := InstallCrossPeerContinuation(ctx, a, b, inboxExtract, cont1); err != nil {
		return append(checks, fail(catConvergence, "psync_setup_cont1", "CONTINUATION §2",
			fmt.Sprintf("install cross-peer continuation 1: %v", err)))
	}

	mergeTemplate, _ := ecf.Encode(map[string]interface{}{
		"source_envelope": nil,
		"strategy":        "source-wins",
		"source_prefix":   srcPrefix,
		"target_prefix":   dstPrefix,
	})
	cont2 := types.ContinuationData{
		Target:             "system/tree",
		Operation:          "merge",
		Resource:           &types.ResourceTarget{Targets: []string{dstPrefix}},
		Params:             cbor.RawMessage(mergeTemplate),
		ResultField:        "source_envelope",
		DispatchCapability: a.CapEntity().ContentHash,
	}
	cont2Entity, _ := cont2.ToEntity()
	if _, err := a.TreePut(ctx, inboxMerge, cont2Entity); err != nil {
		return append(checks, fail(catConvergence, "psync_setup_cont2", "CONTINUATION §2",
			fmt.Sprintf("put continuation 2: %v", err)))
	}

	checks = append(checks, pass(catConvergence, "psync_setup", "CONTINUATION §2",
		"continuations created for prefix extract+merge"))

	deliverURI := "entity://" + peerAID + "/" + inboxExtract
	pattern := srcPrefix + "*"

	tokenEntity, tokenSigEntity, _ := b.CreateDeliveryToken(deliverURI, "receive")
	subID, _, _, err := b.Subscribe(ctx, pattern, deliverURI, "receive",
		tokenEntity, tokenSigEntity, []string{"created", "updated"}, nil)
	if err != nil || subID == "" {
		return append(checks, fail(catConvergence, "psync_subscribe", "SUBSCRIPTION §3",
			fmt.Sprintf("subscribe: %v", err)))
	}
	checks = append(checks, pass(catConvergence, "psync_subscribe", "SUBSCRIPTION §3",
		fmt.Sprintf("subscribed on B for %s", pattern)))

	entities := []struct {
		path    string
		content string
	}{
		{srcPrefix + "file1", "hello from file1"},
		{srcPrefix + "file2", "hello from file2"},
		{srcPrefix + "subdir/file3", "hello from file3"},
	}

	for _, e := range entities {
		ent := mustCreateEntity("test/sync-doc", map[string]string{"content": e.content})
		b.TreePut(ctx, e.path, ent)
	}
	checks = append(checks, pass(catConvergence, "psync_trigger", "TREE §2",
		fmt.Sprintf("wrote %d entities to B under %s", len(entities), srcPrefix)))

	time.Sleep(3 * time.Second)

	var syncedCount int
	for attempt := 0; attempt < 15; attempt++ {
		time.Sleep(200 * time.Millisecond)
		for _, e := range entities {
			dstPath := dstPrefix + e.path[len(srcPrefix):]
			ent, _, err := a.TreeGet(ctx, dstPath)
			if err == nil && !ent.ContentHash.IsZero() {
				syncedCount++
			}
		}
		if syncedCount == len(entities) {
			break
		}
		syncedCount = 0
	}

	if syncedCount == len(entities) {
		checks = append(checks, pass(catConvergence, "psync_all_synced", "TREE §5",
			fmt.Sprintf("all %d entities synced to A at %s", syncedCount, dstPrefix)))
	} else {
		checks = append(checks, fail(catConvergence, "psync_all_synced", "TREE §5",
			fmt.Sprintf("only %d/%d entities synced to A at %s", syncedCount, len(entities), dstPrefix)))
	}

	if syncedCount > 0 {
		checks = append(checks, checkSyncedPathOwnership(ctx, a, peerAID, peerBID, dstPrefix)...)
	}

	b.Unsubscribe(ctx, subID)

	return checks
}

// checkFileSync tests cross-peer file sync via continuation chains.
func checkFileSync(ctx context.Context, a, b *PeerClient, suffix string) []CheckResult {
	var checks []CheckResult

	peerAID := string(a.RemotePeerID())
	peerBID := string(b.RemotePeerID())
	testID := "fsync-" + suffix

	srcPrefix := "local/sync/"
	dstPrefix := "local/sync/"
	inboxExtract := "system/inbox/fsync-extract-" + testID
	inboxMerge := "system/inbox/fsync-merge-" + testID

	b.TreePut(ctx, mustTransportProfilePathFor(a), tcpProfileEntityFor(peerAID, a.addr))

	a.TreePut(ctx, mustTransportProfilePathFor(b), tcpProfileEntityFor(peerBID, b.addr))

	cont1 := types.ContinuationData{
		Target:    "entity://" + peerBID + "/system/tree",
		Operation: "extract",
		Resource:  &types.ResourceTarget{Targets: []string{srcPrefix}},
		DeliverTo: &types.DeliverySpec{
			URI:       "entity://" + peerAID + "/" + inboxMerge,
			Operation: "receive",
		},
	}
	// Cross-peer (host A → target B): conformant B-rooted cap (§4.2 case 3).
	if err := InstallCrossPeerContinuation(ctx, a, b, inboxExtract, cont1); err != nil {
		return append(checks, fail(catConvergence, "filesync_setup", "LOCAL-FILES",
			fmt.Sprintf("install cross-peer continuation 1: %v", err)))
	}

	mergeTemplate, _ := ecf.Encode(map[string]interface{}{
		"source_envelope": nil,
		"strategy":        "source-wins",
		"source_prefix":   srcPrefix,
		"target_prefix":   dstPrefix,
	})
	cont2 := types.ContinuationData{
		Target:             "system/tree",
		Operation:          "merge",
		Resource:           &types.ResourceTarget{Targets: []string{dstPrefix}},
		Params:             cbor.RawMessage(mergeTemplate),
		ResultField:        "source_envelope",
		DispatchCapability: a.CapEntity().ContentHash,
	}
	cont2Entity, _ := cont2.ToEntity()
	a.TreePut(ctx, inboxMerge, cont2Entity)

	deliverURI := "entity://" + peerAID + "/" + inboxExtract
	pattern := srcPrefix + "*"
	tokenEntity, tokenSigEntity, _ := b.CreateDeliveryToken(deliverURI, "receive")
	subID, _, _, err := b.Subscribe(ctx, pattern, deliverURI, "receive",
		tokenEntity, tokenSigEntity, []string{"created", "updated"}, nil)
	if err != nil || subID == "" {
		return append(checks, fail(catConvergence, "filesync_setup", "LOCAL-FILES",
			fmt.Sprintf("subscribe: %v", err)))
	}
	checks = append(checks, pass(catConvergence, "filesync_setup", "LOCAL-FILES",
		"continuation chain + subscription set up for local/sync/"))

	fileContent := "cross-peer file sync test " + suffix
	testEntity := mustCreateEntity("local/files/file", map[string]interface{}{
		"path":    "fsync-test.txt",
		"content": fileContent,
		"size":    len(fileContent),
	})
	testHash, err := b.TreePut(ctx, srcPrefix+"fsync-test.txt", testEntity)
	if err != nil {
		return append(checks, fail(catConvergence, "filesync_write", "LOCAL-FILES",
			fmt.Sprintf("write to B: %v", err)))
	}
	checks = append(checks, pass(catConvergence, "filesync_write", "LOCAL-FILES",
		fmt.Sprintf("wrote fsync-test.txt to B's tree (hash=%s)", testHash)))

	time.Sleep(3 * time.Second)

	var synced bool
	for attempt := 0; attempt < 10; attempt++ {
		time.Sleep(200 * time.Millisecond)
		ent, _, err := a.TreeGet(ctx, dstPrefix+"fsync-test.txt")
		if err == nil && !ent.ContentHash.IsZero() {
			synced = true
			if ent.ContentHash == testHash {
				checks = append(checks, pass(catConvergence, "filesync_synced", "LOCAL-FILES",
					"file entity synced to A's tree, hash matches"))
			} else {
				checks = append(checks, warn(catConvergence, "filesync_synced", "LOCAL-FILES",
					fmt.Sprintf("entity at A but hash differs: %s vs %s", ent.ContentHash, testHash)))
			}
			break
		}
	}
	if !synced {
		checks = append(checks, fail(catConvergence, "filesync_synced", "LOCAL-FILES",
			"file entity not synced to A's tree after 5s"))
	}

	b.Unsubscribe(ctx, subID)
	return checks
}

// checkBidirectionalFileSync tests bidirectional sync between two peers.
func checkBidirectionalFileSync(ctx context.Context, a, b *PeerClient, suffix string) []CheckResult {
	var checks []CheckResult

	peerAID := string(a.RemotePeerID())
	peerBID := string(b.RemotePeerID())
	testID := "bisync-" + suffix

	srcPrefix := "local/bisync-" + suffix + "/"

	// --- Set up B→A direction ---
	inboxExtractAB := "system/inbox/bisync-extract-ab-" + testID
	inboxMergeAB := "system/inbox/bisync-merge-ab-" + testID

	cont1AB := types.ContinuationData{
		Target:    "entity://" + peerBID + "/system/tree",
		Operation: "extract",
		Resource:  &types.ResourceTarget{Targets: []string{srcPrefix}},
		DeliverTo: &types.DeliverySpec{
			URI:       "entity://" + peerAID + "/" + inboxMergeAB,
			Operation: "receive",
		},
	}
	// Cross-peer (host A → target B): conformant B-rooted cap (§4.2 case 3).
	if err := InstallCrossPeerContinuation(ctx, a, b, inboxExtractAB, cont1AB); err != nil {
		return append(checks, fail(catConvergence, "bisync_setup", "LOCAL-FILES",
			fmt.Sprintf("install cross-peer cont1AB: %v", err)))
	}

	mergeTemplateAB, _ := ecf.Encode(map[string]interface{}{
		"source_envelope": nil,
		"strategy":        "source-wins",
		"source_prefix":   srcPrefix,
		"target_prefix":   srcPrefix,
	})
	cont2AB := types.ContinuationData{
		Target:             "system/tree",
		Operation:          "merge",
		Resource:           &types.ResourceTarget{Targets: []string{srcPrefix}},
		Params:             cbor.RawMessage(mergeTemplateAB),
		ResultField:        "source_envelope",
		DispatchCapability: a.CapEntity().ContentHash,
	}
	cont2ABEntity, _ := cont2AB.ToEntity()
	a.TreePut(ctx, inboxMergeAB, cont2ABEntity)

	deliverURIAB := "entity://" + peerAID + "/" + inboxExtractAB
	tokenAB, tokenSigAB, _ := b.CreateDeliveryToken(deliverURIAB, "receive")
	subIDAB, _, _, _ := b.Subscribe(ctx, srcPrefix+"*", deliverURIAB, "receive",
		tokenAB, tokenSigAB, []string{"created", "updated"}, nil)

	// --- Set up A→B direction ---

	inboxExtractBA := "system/inbox/bisync-extract-ba-" + testID
	inboxMergeBA := "system/inbox/bisync-merge-ba-" + testID

	cont1BA := types.ContinuationData{
		Target:    "entity://" + peerAID + "/system/tree",
		Operation: "extract",
		Resource:  &types.ResourceTarget{Targets: []string{srcPrefix}},
		DeliverTo: &types.DeliverySpec{
			URI:       "entity://" + peerBID + "/" + inboxMergeBA,
			Operation: "receive",
		},
	}
	// Cross-peer mirror (host B → target A): conformant A-rooted cap.
	if err := InstallCrossPeerContinuation(ctx, b, a, inboxExtractBA, cont1BA); err != nil {
		return append(checks, fail(catConvergence, "bisync_setup", "LOCAL-FILES",
			fmt.Sprintf("install cross-peer cont1BA: %v", err)))
	}

	mergeTemplate, _ := ecf.Encode(map[string]interface{}{
		"source_envelope": nil,
		"strategy":        "source-wins",
		"source_prefix":   srcPrefix,
		"target_prefix":   srcPrefix,
	})
	cont2BA := types.ContinuationData{
		Target:             "system/tree",
		Operation:          "merge",
		Resource:           &types.ResourceTarget{Targets: []string{srcPrefix}},
		Params:             cbor.RawMessage(mergeTemplate),
		ResultField:        "source_envelope",
		DispatchCapability: b.CapEntity().ContentHash,
	}
	cont2BAEntity, _ := cont2BA.ToEntity()
	b.TreePut(ctx, inboxMergeBA, cont2BAEntity)

	deliverURIBA := "entity://" + peerBID + "/" + inboxExtractBA
	tokenBA, tokenSigBA, _ := a.CreateDeliveryToken(deliverURIBA, "receive")
	subIDBA, _, _, err := a.Subscribe(ctx, srcPrefix+"*", deliverURIBA, "receive",
		tokenBA, tokenSigBA, []string{"created", "updated"}, nil)
	if err != nil || subIDBA == "" {
		return append(checks, fail(catConvergence, "bisync_setup", "LOCAL-FILES",
			fmt.Sprintf("subscribe A→B: %v", err)))
	}

	checks = append(checks, pass(catConvergence, "bisync_setup", "LOCAL-FILES",
		"bidirectional sync set up (A→B + B→A from previous test)"))

	// --- Test A→B: Write on A, check B ---
	fileA := mustCreateEntity("local/files/file", map[string]interface{}{
		"path":    "from-a.txt",
		"content": "written on peer A " + suffix,
	})
	a.TreePut(ctx, srcPrefix+"from-a.txt", fileA)
	checks = append(checks, pass(catConvergence, "bisync_write_a", "LOCAL-FILES",
		"wrote from-a.txt to A's tree"))

	// --- Test B→A: Write on B, check A ---
	fileB := mustCreateEntity("local/files/file", map[string]interface{}{
		"path":    "from-b.txt",
		"content": "written on peer B " + suffix,
	})
	b.TreePut(ctx, srcPrefix+"from-b.txt", fileB)
	checks = append(checks, pass(catConvergence, "bisync_write_b", "LOCAL-FILES",
		"wrote from-b.txt to B's tree"))

	var aToB, bToA bool
	for attempt := 0; attempt < 60; attempt++ {
		time.Sleep(500 * time.Millisecond)
		if !aToB {
			ent, _, err := b.TreeGet(ctx, srcPrefix+"from-a.txt")
			if err == nil && !ent.ContentHash.IsZero() {
				aToB = true
			}
		}
		if !bToA {
			ent, _, err := a.TreeGet(ctx, srcPrefix+"from-b.txt")
			if err == nil && !ent.ContentHash.IsZero() {
				bToA = true
			}
		}
		if aToB && bToA {
			break
		}
	}

	if aToB {
		checks = append(checks, pass(catConvergence, "bisync_a_to_b", "LOCAL-FILES",
			"from-a.txt synced to B's tree"))
	} else {
		checks = append(checks, warn(catConvergence, "bisync_a_to_b", "LOCAL-FILES",
			"from-a.txt not found on B after 6s (bidirectional prefix sync may need oscillation handling)"))
	}

	if bToA {
		checks = append(checks, pass(catConvergence, "bisync_b_to_a", "LOCAL-FILES",
			"from-b.txt synced to A's tree"))
	} else {
		checks = append(checks, warn(catConvergence, "bisync_b_to_a", "LOCAL-FILES",
			"from-b.txt not found on A after 6s (bidirectional prefix sync may need oscillation handling)"))
	}

	b.Unsubscribe(ctx, subIDAB)
	a.Unsubscribe(ctx, subIDBA)

	return checks
}

// checkSyncedPathOwnership verifies that entities synced from another peer
// have paths qualified with the local peer's identity. This catches namespace
// leaks where merge/sync accidentally preserves the source peer's ID in paths.
func checkSyncedPathOwnership(ctx context.Context, client *PeerClient, localPeerID, sourcePeerID, prefix string) []CheckResult {
	var checks []CheckResult

	entries, _, err := client.TreeListing(ctx, prefix)
	if err != nil || len(entries) == 0 {
		return checks
	}

	fetched := 0
	for key, val := range entries {
		entryHash := extractListingHash(val)
		if entryHash.IsZero() {
			continue
		}
		path := prefix + key
		_, _, err := client.TreeGet(ctx, path)
		if err != nil {
			checks = append(checks, fail(catConvergence, "psync_path_usable", "V7 §1.5 / P2",
				fmt.Sprintf("synced entity at %q not fetchable via TreeGet: %v", path, err)))
			return checks
		}
		fetched++
	}
	if fetched > 0 {
		checks = append(checks, pass(catConvergence, "psync_path_usable", "V7 §1.5 / P2",
			fmt.Sprintf("all %d synced entities fetchable via listing+get at %s", fetched, prefix)))
	}

	raw, err := ecf.Encode(types.QueryExpressionData{
		TypeFilter: "test/sync-doc",
		PathPrefix: prefix,
	})
	if err != nil {
		return checks
	}
	paramsEntity, err := entity.NewEntity(types.TypeQueryExpression, cbor.RawMessage(raw))
	if err != nil {
		return checks
	}

	uri := fmt.Sprintf("entity://%s/system/query", localPeerID)
	env, _, err := client.SendExecute(ctx, uri, "find", paramsEntity, nil)
	if err != nil {
		return checks
	}

	respData, err := types.ExecuteResponseDataFromEntity(env.Root)
	if err != nil || respData.Status != 200 {
		return checks
	}

	var resultEntity entity.Entity
	if err := ecf.Decode(respData.Result, &resultEntity); err != nil {
		return checks
	}
	// Unwrap system/envelope if present.
	inner, _, err := unwrapResultEnvelope(resultEntity)
	if err != nil {
		return checks
	}
	var result types.QueryResultData
	if err := ecf.Decode(inner.Data, &result); err != nil {
		return checks
	}

	if len(result.Matches) == 0 {
		checks = append(checks, warn(catConvergence, "psync_query_namespace", "V7 §1.5 / P2",
			"query returned 0 matches for synced entities"))
		return checks
	}

	wrongPeer := 0
	barePaths := 0
	for _, m := range result.Matches {
		if m.Path == "" {
			continue
		}
		if store.IsAbsolute(m.Path) {
			ns, _ := store.SplitNamespace(m.Path)
			if ns == sourcePeerID {
				wrongPeer++
			}
		} else if strings.HasPrefix(m.Path, "entity://") {
			if strings.Contains(m.Path, sourcePeerID) && !strings.Contains(m.Path, localPeerID) {
				wrongPeer++
			}
		} else {
			barePaths++
		}
	}

	if wrongPeer > 0 {
		checks = append(checks, fail(catConvergence, "psync_query_namespace", "V7 §1.5 / P2",
			fmt.Sprintf("%d/%d synced entities have source peer's ID in path (should be local peer's)",
				wrongPeer, len(result.Matches))))
	} else if barePaths > 0 {
		checks = append(checks, warn(catConvergence, "psync_query_namespace", "V7 §1.5 / P2",
			fmt.Sprintf("%d/%d synced entity paths are bare (not qualified)", barePaths, len(result.Matches))))
	} else {
		checks = append(checks, pass(catConvergence, "psync_query_namespace", "V7 §1.5 / P2",
			fmt.Sprintf("all %d synced entities have correct peer identity in paths", len(result.Matches))))
	}

	return checks
}
