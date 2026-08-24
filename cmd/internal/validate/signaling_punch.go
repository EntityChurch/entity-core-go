package validate

import (
	"context"
	"errors"
	"fmt"
	"net"
	"sync/atomic"
	"time"

	"go.entitychurch.org/entity-core-go/core/crypto"
	"go.entitychurch.org/entity-core-go/core/peer"
	"go.entitychurch.org/entity-core-go/core/store"
	"go.entitychurch.org/entity-core-go/core/types"
	"go.entitychurch.org/entity-core-go/ext/signaling"
)

// runSignalingPunch adds the §7 PUNCH half of the signaling gate to the runner
// the meet checks already populated. Where signalingMeet proves the coordination
// messages cross the node (offer→collect→answer), this proves the whole punch on
// top of that carrier: two in-process peers derive a pair key, exchange
// candidates + punch-sync through the LIVE node, complete a §7.1 simultaneous
// open over loopback, run PerformConnect + the §7.4.1 identity check, and carry a
// ping/pong over the punched transport — then a second op after an idle proves
// the transport pooled and survives (§10.3 obligation 1). It also asserts the
// §7.1-step-4 both-fire MUST by tapping each side's dial seam.
//
// The node is the carrier under test (sigA/sigB ride the harness's connections to
// it); the two punch peers are fresh in-process identities so pair-mode has two
// real ids and §7.4.1 binds a specific expected peer. Loopback has no NAT, so this
// is the coordination + socket-choreography half of §11.5 — not traversal.
func runSignalingPunch(ctx context.Context, r *CheckRunner, sigA, sigB *signaling.Client) {
	r.Declare("signaling_punch",
		"EXTENSION-SIGNALING brief §7.1/§7.4.1/§10.3 — two peers punch through the live node carrier: candidate+sync exchange, both-fire simultaneous open, identity-checked handshake, a verified op over the direct path, and pooled-transport reuse after an idle")

	r.Run("signaling_punch", func() CheckOutcome {
		if out, ok := r.Require("signaling_authority"); !ok {
			return out
		}

		peerA, err := buildInProcPunchPeer()
		if err != nil {
			return FailCheck("build punch peer A: " + err.Error())
		}
		defer peerA.Close()
		peerB, err := buildInProcPunchPeer()
		if err != nil {
			return FailCheck("build punch peer B: " + err.Error())
		}
		defer peerB.Close()
		idA := peerA.PeerID().String()
		idB := peerB.PeerID().String()

		localA, err := reserveLoopbackPort()
		if err != nil {
			return FailCheck("reserve loopback port A: " + err.Error())
		}
		localB, err := reserveLoopbackPort()
		if err != nil {
			return FailCheck("reserve loopback port B: " + err.Error())
		}

		// Both parties key on the SAME pair bucket. Carriers are the live node.
		key, err := signaling.PairKey(idA, idB)
		if err != nil {
			return FailCheck("derive pair key: " + err.Error())
		}
		var dialedA, dialedB atomic.Bool
		// §11.5 deposit-bound teeth: count what reaches the node, per side, so a
		// brute-force establishment cannot pass this gate on volume.
		carrierA := &countingCarrier{Carrier: sigA}
		carrierB := &countingCarrier{Carrier: sigB}
		partyA := punchParty(carrierA, key, peerA.Keypair(), localA, &dialedA)
		partyB := punchParty(carrierB, key, peerB.Keypair(), localB, &dialedB)

		// Bound the punch so a stall never hangs the whole validator.
		pctx, cancel := context.WithTimeout(ctx, 30*time.Second)
		defer cancel()

		// Responder concurrently: punch back, serve the crossed conn as a server so
		// A's PerformConnect completes.
		type respResult struct {
			initiator string
			err       error
		}
		bCh := make(chan respResult, 1)
		go func() {
			raw, initiator, err := partyB.Respond(pctx)
			if err != nil {
				bCh <- respResult{err: err}
				return
			}
			// §4.4 (rev 3): responder camped on the §3 key — symmetric.
			peerB.ServeConn(raw).MarkEstablishedViaRendezvousKey()
			bCh <- respResult{initiator: initiator}
		}()

		// Initiator: punch, wrap, handshake, §7.4.1 identity check.
		raw, err := partyA.Initiate(pctx, idB)
		if err != nil {
			return FailCheck("initiator punch through live node: " + err.Error())
		}
		conn := peerA.ConnectVia(raw)
		// §6.5 (b) §4.4: initiator drove the crossing off the §3 key —
		// symmetric. Set before the handshake; the mint fires at its tail.
		conn.MarkEstablishedViaRendezvousKey()
		if err := conn.PerformConnect(pctx); err != nil {
			conn.Close()
			return FailCheck("handshake over punched path: " + err.Error())
		}
		authID := conn.Session().RemotePeerID
		if authID.String() != idB {
			conn.Close()
			return FailCheck(fmt.Sprintf("punched path authenticated as %s, want expected %s (§7.4.1 identity binding)", authID, idB))
		}
		if _, err := peerA.AddRemoteConnection(authID, conn); err != nil {
			conn.Close()
			return FailCheck("pool punched conn: " + err.Error())
		}

		// First op over the direct path (§3.2 proof-of-punch).
		if err := pingPong(pctx, peerA, idB); err != nil {
			return FailCheck("ping over punched path: " + err.Error())
		}

		// Responder side completed and saw us as the initiator.
		br := <-bCh
		if br.err != nil {
			return FailCheck("responder punch: " + br.err.Error())
		}
		if br.initiator != idA {
			return FailCheck(fmt.Sprintf("responder saw initiator %q, want %q", br.initiator, idA))
		}

		// §7.1 step-4 both-fire MUST — the check loopback can otherwise not see.
		if !dialedA.Load() || !dialedB.Load() {
			return FailCheck(fmt.Sprintf("both-fire violated: initiator dialed=%v responder dialed=%v — a listen-only side never opens its NAT hole (§7.1 step 4)", dialedA.Load(), dialedB.Load()))
		}

		// §10.3 obligation 1: the punched transport pooled and survives an idle —
		// a second dispatch reuses it rather than re-establishing.
		select {
		case <-pctx.Done():
			return FailCheck("context ended before idle-reuse probe: " + pctx.Err().Error())
		case <-time.After(1 * time.Second):
		}
		if !peerA.IsConnected(peerB.PeerID()) {
			return FailCheck("punched transport did not survive a 1s idle (not pooled)")
		}
		if err := pingPong(pctx, peerA, idB); err != nil {
			return FailCheck("second op after idle (pooled-transport reuse): " + err.Error())
		}

		// §11.5 (arch-pinned @ 78fdd13) — the channel MUST open within a BOUNDED
		// number of coordination deposits: O(1), never scaling with poll or
		// dispatch count. A gate that only asks "did a channel open?" is passed
		// green by brute force — N independent negotiations deposited until two
		// happen to overlap — which is exactly what NETWORK §10.3 obligation 5
		// forbids and what hammers the shared carrier. Counting semantics are the
		// pinned ones: OFFER deposits, node vantage, PER SIDE, per establishment.
		//
		// The bound is a fixed constant, and the property that fails brute force
		// is that it is fixed — not its exact value (§11.5 is explicit on this).
		//
		// The ceiling is SUBSTRATE-SCOPED as of arch c78b3dc (2026-08-07): WebRTC
		// has glare-rollback and ICE-restart re-offers, native TCP
		// simultaneous-open has neither, so 16-on-WebRTC and 3-on-native are both
		// conformant readings and neither transfers. This gate drives the native
		// punch, so it scores against 3 — Go measures 1–2/side, still an order of
		// magnitude below the ~470 brute force produced. The previous 8 came from
		// browser-rust's WebRTC harness figure and was the wrong scope here.
		if depA, depB := carrierA.offers(), carrierB.offers(); depA > sigDepositBound || depB > sigDepositBound {
			return FailCheck(fmt.Sprintf("§11.5 deposit bound exceeded though the channel opened: initiator deposited %d offers, responder %d, bound %d/side on '"+sigDepositSubstrate+"' — a bounded-O(1) establishment is the requirement, not merely a successful one (NETWORK §10.3 obligation 5)", depA, depB, sigDepositBound))
		}

		return PassCheck(fmt.Sprintf("punched %s↔%s through the live node: candidate+sync exchange, both-fire simultaneous open, §7.4.1 identity, ping/pong over the direct path, reuse after a 1s idle, and %d/%d offer deposits per side within the §11.5 bound of %d", idA[:8], idB[:8], carrierA.offers(), carrierB.offers(), sigDepositBound))
	})
}

// sigDepositBound is the §11.5 ceiling on coordination deposits per side per
// establishment. It is a fixed O(1) constant: §11.5 is explicit that the
// property which fails brute force is the ceiling being FIXED (never scaling
// with poll / dispatch / tick count), not its value.
//
// SUBSTRATE-SCOPED, and a claim MUST name its substrate's value
// `[MUST; arch c78b3dc, 2026-08-07]`. The ceiling covers the re-offer paths a
// substrate can actually produce: WebRTC has glare-rollback and ICE-restart
// re-offers, native TCP simultaneous-open has neither. **3 on native** and
// **16 on WebRTC** are both conformant readings of the same rule and neither
// transfers to the other substrate — comparing a figure across substrates is
// meaningless.
//
// This validator drives the NATIVE punch, so the bound is 3. It was 8 — a
// number carried over before the ceiling was substrate-scoped, and too loose
// for native: it would have passed a peer depositing 5, which the ruling makes
// non-conformant here. Go measures 2/1 per side, inside 3 either way.
const sigDepositBound = 3

// sigDepositSubstrate names the substrate the bound above belongs to, so a
// published figure carries its scope rather than inviting a cross-substrate
// comparison the ruling calls meaningless.
const sigDepositSubstrate = "native TCP simultaneous-open"

// countingCarrier tallies what a punch party deposits at the node so the gate
// can assert §11.5's bound. It counts OFFER only — the pinned semantics count
// deposits, and `collect` is a non-destructive poll of a bucket that persists
// 60 s (§5 pins 1/6), i.e. the "deposit-once-and-poll-to-completion" shape
// obligation 5 asks for rather than the load it bounds.
type countingCarrier struct {
	signaling.Carrier
	offerCount atomic.Int64
}

func (c *countingCarrier) Offer(ctx context.Context, key, message []byte) (uint, error) {
	c.offerCount.Add(1)
	return c.Carrier.Offer(ctx, key, message)
}

func (c *countingCarrier) offers() int64 { return c.offerCount.Load() }

// buildInProcPunchPeer builds a minimal in-process peer for a punch: no listener
// is started (the punch dials peer-to-peer over the crossed socket; the serve
// context is live from peer.New), memory stores, open grants.
func buildInProcPunchPeer() (*peer.Peer, error) {
	kp, err := crypto.Generate()
	if err != nil {
		return nil, err
	}
	return peer.New(
		peer.WithIdentity(kp),
		peer.WithListenAddr("127.0.0.1:0"),
		peer.WithStore(store.NewMemoryContentStore()),
		peer.WithLocationIndex(store.NewMemoryLocationIndex()),
		peer.WithConnectionGrants(peer.OpenAccessGrants()),
	)
}

// reserveLoopbackPort returns a free loopback TCP address with nothing listening
// on it — the port a punch party binds and advertises as srflx (loopback models
// the §7.3 shared socket where, with no NAT, srflx == the local bind).
func reserveLoopbackPort() (*net.TCPAddr, error) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, err
	}
	addr := l.Addr().(*net.TCPAddr)
	l.Close()
	return &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: addr.Port}, nil
}

// punchParty assembles a PunchParty on the given carrier with a recording dial
// (so both-fire is observable) and the same tight loopback tunables the punch
// tests use.
func punchParty(carrier signaling.Carrier, key []byte, identity crypto.Keypair, local *net.TCPAddr, dialed *atomic.Bool) *signaling.PunchParty {
	return &signaling.PunchParty{
		Carrier: carrier,
		Key:     key,
		// The party derives its own id from this keypair and seals every §6.1
		// deposit with it (§6.3). Tolerant on the read side for the duration of
		// the flag day — this check has to keep meeting a counterpart that has
		// not flipped.
		Identity: identity,
		Trust:    signaling.VerifyTolerant,
		LocalCands: []types.NetworkCandidateData{
			{Type: types.CandidateTypeSrflx, Substrate: types.CandidateSubstrateTCP, Address: local.String()},
		},
		LocalAddr:       local,
		Dial:            recordingPunchDial(dialed),
		Poll:            20 * time.Millisecond,
		CrossingRetries: 40,
		DialTimeout:     300 * time.Millisecond,
		ExchangeTimeout: 15 * time.Second,
	}
}

// recordingPunchDial taps whether this side issued a genuine outbound connect on
// the shared endpoint (the both-fire signal), delegating to the real dialer. It
// records only a real bind+connect: a reuseport-unsupported failure never leaves
// the endpoint (and PunchParty maps it to the relay fallback), so it does not
// count. dialLoop guarantees this is never called on an already-cancelled ctx.
func recordingPunchDial(dialed *atomic.Bool) signaling.DialFunc {
	return func(ctx context.Context, local *net.TCPAddr, remote string) (net.Conn, error) {
		conn, err := signaling.DialReusePort(ctx, local, remote)
		if !errors.Is(err, signaling.ErrReusePortUnsupported) {
			dialed.Store(true)
		}
		return conn, err
	}
}

// pingPong dispatches one ping to target over whatever pooled transport peer p
// holds and checks the pong comes back.
func pingPong(ctx context.Context, p *peer.Peer, targetID string) error {
	ping, err := types.PingData{Timestamp: 1709740800000, Sequence: 7}.ToEntity()
	if err != nil {
		return fmt.Errorf("build ping: %w", err)
	}
	resp, err := p.RemoteExecute(ctx, fmt.Sprintf("entity://%s/system/protocol/connect", targetID), "ping", ping, nil)
	if err != nil {
		return err
	}
	if resp.Status != 200 || resp.Result.Type != types.TypeNetworkPong {
		return fmt.Errorf("ping response status=%d type=%q, want 200/%s", resp.Status, resp.Result.Type, types.TypeNetworkPong)
	}
	return nil
}
