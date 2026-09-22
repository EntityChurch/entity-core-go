package validate

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"time"

	"go.entitychurch.org/entity-core-go/core/crypto"
	"go.entitychurch.org/entity-core-go/core/types"
)

// addBurstConvergenceCheck drives a CONCURRENT write burst at a single peer and
// asserts auto-version captured every write — the wire-level detector for the
// symmetric last-burst-write loss (workbench-go CORE-GO-LAST-BURST-WRITE-LOSS,
// 2026-08-20; entity-core-go fixed 2026-08-30).
//
// Why this exists: the loss is SILENT and INVISIBLE to the rest of the suite.
// Every other auto_version / convergence check writes sequentially, so the
// serving peer never processes two writes to the same tracked prefix at once —
// exactly the contention the bug needs. A peer can be fully conformant on every
// existing vector and still drop the last write of a burst with no error on
// either side. This check makes it visible: it opens N connections and bursts
// them so the SERVER handles concurrent writes, then reads `status` (REVISION
// §6.1). Convergence is TWO conditions, not one: pending==0 AND a non-zero
// head. pending is the count of live-tree paths not captured by the head
// version — a non-zero pending after settle is the partial loss (a head exists,
// a write missed it). But pending is computed only WHEN a head exists, so on a
// total loss — no head ever minted for this prefix — it reads 0 and is blind;
// head presence is the second condition that catches that. See the round loop.
//
// The oracle is impl-agnostic (REVISION §6.1 `status`), so this runs against
// go, rust and python identically. Go's bug was a stale tracked-root READ in
// fire(), fixed 2026-08-30 (go PASSes). Measured 2026-08-30: rust FAILed this
// (status.pending stayed non-zero) — contradicting the earlier code-read that
// rust was "structurally exempt", the reason to measure rather than read; rust
// then classified it as a real capture loss and fixed it (their 7776675).
// Python PASSed but its peer proved the pending-only form BLIND to a total loss
// (a capture-disabled py peer still passed 16/16), routed here as py SA-PY-28
// and closed by the head-presence arm added 2026-08-31 — WITHOUT changing
// status.pending's no-head semantics, which stay unruled.
func addBurstConvergenceCheck(ctx context.Context, client *PeerClient, r *CheckRunner) {
	r.Declare("burst_convergence_no_capture_loss", "REVISION §6.1 — auto-version MUST capture every write of a CONCURRENT burst; head must not lag the live tree (the symmetric last-burst-write loss). Converged iff status.pending==0 AND a head exists — pending alone is blind to a total capture loss (no head ever minted).")

	r.Run("burst_convergence_no_capture_loss", func() CheckOutcome {
		const (
			writers = 8
			rounds  = 6
			// A correct peer captures a burst in milliseconds (go: ~24ms across
			// all rounds); a terminal loss never converges (rust: still pending
			// at 20s). 8s is far past any real settle time yet short enough that
			// a genuine loss is reported promptly — the PASS path short-circuits
			// the moment pending hits 0, so this only bounds FAIL latency.
			settleWindow = 8 * time.Second
		)
		prefix := autoVersionTestPrefix()

		// Arm auto-version (no excludes: the version root then equals the live
		// tracked root, so status.pending is a clean capture oracle).
		if err := writeRevisionConfig(ctx, client, prefix, true, nil); err != nil {
			return FailCheck("arm auto-version on burst prefix: " + err.Error())
		}
		if _, ok := findTrackingConfig(ctx, client, prefix); !ok {
			return FailCheck("tracking-config not coordinated for burst prefix " + prefix)
		}

		// Open N writable connections, each a DISTINCT identity. Writes to a
		// peer-relative path (system/validate/...) qualify to the SERVING peer's
		// namespace regardless of the writer's identity, so all N still target
		// the same tracked prefix and the serving peer processes them
		// concurrently (one connection per server goroutine) — the contention
		// the bug needs. Distinct identities avoid perturbing the peer's
		// per-identity connection state (which many-same-identity connections
		// do, destabilising unrelated concurrency checks in the same pass). A
		// single connection serializes on writeMu and would never contend.
		burst := make([]*PeerClient, 0, writers)
		for i := 0; i < writers; i++ {
			kp, kerr := crypto.Generate()
			if kerr != nil {
				return WarnCheck(fmt.Sprintf("could not generate burst keypair %d: %v", i, kerr))
			}
			pc, err := NewPeerClientWithKeypair(client.Addr(), kp)
			if err != nil {
				return WarnCheck(fmt.Sprintf("could not create burst client %d: %v", i, err))
			}
			defer pc.Close()
			if err := pc.Connect(ctx); err != nil {
				return WarnCheck(fmt.Sprintf("burst client %d connect failed: %v", i, err))
			}
			for _, ch := range pc.PerformHandshake(ctx) {
				if ch.Severity == Fail && !strings.HasPrefix(ch.Name, "connection_grants_") {
					return WarnCheck(fmt.Sprintf("burst client %d handshake failed: %s", i, ch.Message))
				}
			}
			if !pc.Connected() {
				return WarnCheck(fmt.Sprintf("burst client %d handshake bound no capability", i))
			}
			burst = append(burst, pc)
		}

		for round := 0; round < rounds; round++ {
			// Release all writers at once for maximum server-side contention.
			var wg sync.WaitGroup
			start := make(chan struct{})
			errs := make([]error, writers)
			for i := 0; i < writers; i++ {
				wg.Add(1)
				go func(i int) {
					defer wg.Done()
					ent := mustCreateEntity("test/burst-doc", map[string]string{
						"round": fmt.Sprint(round), "writer": fmt.Sprint(i),
					})
					path := fmt.Sprintf("%sr%d-w%d.md", prefix, round, i)
					<-start
					_, errs[i] = burst[i].TreePut(ctx, path, ent)
				}(i)
			}
			close(start)
			wg.Wait()
			for i, e := range errs {
				if e != nil {
					return FailCheck(fmt.Sprintf("round %d writer %d: burst write failed: %v", round, i, e))
				}
			}

			// Poll status until the head catches up to the live tree, or the
			// settle window elapses. A transient pending>0 is normal mid-burst;
			// a pending that never reaches 0 is the terminal loss.
			//
			// Convergence requires BOTH pending==0 AND a non-zero head — not
			// pending==0 alone. `status.pending` is computed only when a head
			// exists (ext/revision/status.go, `if !headVal.IsZero()`; the same
			// guard rides every impl), so on a peer that captured NOTHING for
			// this prefix — no head ever minted — pending reads 0 and conflates
			// "fully captured" with "captured nothing". This check bursts at a
			// fresh prefix, so total capture failure is exactly the blind path:
			// pending==0 with an absent head. entity-core-py measured that blind
			// spot on a py peer (a peer with capture disabled by mutation still
			// passed 16/16) and routed it here 2026-08-30. Arming on head
			// presence closes it WITHOUT touching status.pending's no-head arm,
			// which is unruled (py SA-PY-28) — so this stays impl-agnostic and
			// does not converge go onto py's reading of the absent case.
			st, perr := waitStatusConverged(ctx, client, prefix, settleWindow)
			if perr != nil {
				return FailCheck(fmt.Sprintf("round %d: status probe failed: %v", round, perr))
			}
			if st.Pending != 0 {
				return FailCheck(fmt.Sprintf(
					"round %d: %d write(s) of a %d-writer concurrent burst were NEVER captured — auto-version's head lags the live tree after settle (status.pending=%d). This is the symmetric last-burst-write loss: the write is in the live tree but in no version, so a follower can never receive it.",
					round, st.Pending, writers, st.Pending))
			}
			if st.Head.IsZero() {
				return FailCheck(fmt.Sprintf(
					"round %d: %d writes reached the live tree but auto-version minted NO head for the prefix after settle — total capture loss. status.pending reads 0 here only because it is not computed without a head (the no-head arm), so pending alone is blind to this case; head presence is what catches it.",
					round, writers))
			}
		}
		return PassCheck(fmt.Sprintf("%d concurrent writers x %d rounds: every write captured (each round converged — status.pending==0 with a head minted)", writers, rounds))
	})
}

// waitStatusConverged polls the revision `status` op until the burst has
// converged — pending==0 AND a non-zero head — or the deadline elapses,
// returning the last observed status. Head presence is part of convergence on
// purpose: pending==0 with an absent head is not "captured", it is the no-head
// blind arm (see the caller), and returning early on pending==0 alone would let
// a total capture loss read as converged before any head is ever minted. A
// correct peer mints a head in milliseconds, so requiring it costs no real
// latency; only a genuine total loss ever rides the window out with head zero.
func waitStatusConverged(ctx context.Context, client *PeerClient, prefix string, within time.Duration) (types.RevisionStatusData, error) {
	deadline := time.Now().Add(within)
	var last types.RevisionStatusData
	for {
		resp, err := client.RevisionExecute(ctx, "status", types.RevisionStatusParamsData{Prefix: prefix})
		if err != nil {
			return types.RevisionStatusData{}, err
		}
		if resp.Status != 200 {
			return types.RevisionStatusData{}, fmt.Errorf("status returned %d", resp.Status)
		}
		if _, err := decodeRevisionResult(resp, &last); err != nil {
			return types.RevisionStatusData{}, fmt.Errorf("decode status: %w", err)
		}
		converged := last.Pending == 0 && !last.Head.IsZero()
		if converged || time.Now().After(deadline) {
			return last, nil
		}
		time.Sleep(50 * time.Millisecond)
	}
}
