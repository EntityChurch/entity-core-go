package validate

import (
	"testing"

	"go.entitychurch.org/entity-core-go/core/entity"
	"go.entitychurch.org/entity-core-go/core/types"
)

// respEnvelope builds an EXECUTE_RESPONSE envelope echoing requestID, as a
// conformant peer does per V7 §6.11(b).
func respEnvelope(t *testing.T, requestID string) entity.Envelope {
	t.Helper()
	ent, err := types.ExecuteResponseData{RequestID: requestID, Status: 200}.ToEntity()
	if err != nil {
		t.Fatalf("build response entity: %v", err)
	}
	return entity.Envelope{Root: ent}
}

// TestRouteBGResponse_DropsLateOrphan is the S2 desync regression. It models
// the post-timeout state on the shared connection: request N timed out (its
// waiter was already cleaned up), request N+1 is now the sole outstanding
// waiter, and N's response only now drains off the socket. The late orphan must
// NOT be handed to N+1's waiter — doing so put the connection one response out
// of phase and cascaded mismatched assertions through the rest of the run.
func TestRouteBGResponse_DropsLateOrphan(t *testing.T) {
	c := &PeerClient{}

	// N+1 ("validate-2") is waiting; N ("validate-1") already timed out.
	waiter := make(chan bgFrame, 1)
	c.bgPending.Store("validate-2", waiter)
	c.bgWaiters.Add(1)

	// N's late response drains in first. It carries its own request_id.
	c.routeBGResponse([]byte("orphan-N"), respEnvelope(t, "validate-1"))

	select {
	case f := <-waiter:
		t.Fatalf("N+1's waiter received stale orphan frame %q — connection desynced", f.raw)
	default:
		// Correct: orphan dropped, waiter still pending.
	}
	if got := c.bgWaiters.Load(); got != 1 {
		t.Fatalf("bgWaiters after orphan drop = %d, want 1 (N+1 still outstanding)", got)
	}

	// N+1's real response arrives next and must be delivered to it.
	c.routeBGResponse([]byte("real-N+1"), respEnvelope(t, "validate-2"))

	select {
	case f := <-waiter:
		if string(f.raw) != "real-N+1" {
			t.Fatalf("N+1 got %q, want its own response real-N+1", f.raw)
		}
	default:
		t.Fatalf("N+1's waiter never received its response after orphan drop")
	}
	if got := c.bgWaiters.Load(); got != 0 {
		t.Fatalf("bgWaiters after delivery = %d, want 0", got)
	}
}

// TestRouteBGResponse_MatchesByRequestID confirms the primary demux path: a
// response is delivered to the waiter whose request_id it echoes, even when
// other waiters are tracked (defense against any future concurrent use).
func TestRouteBGResponse_MatchesByRequestID(t *testing.T) {
	c := &PeerClient{}
	w1 := make(chan bgFrame, 1)
	c.bgPending.Store("validate-1", w1)
	c.bgWaiters.Add(1)

	c.routeBGResponse([]byte("r1"), respEnvelope(t, "validate-1"))

	select {
	case f := <-w1:
		if string(f.raw) != "r1" {
			t.Fatalf("got %q, want r1", f.raw)
		}
	default:
		t.Fatalf("waiter did not receive its matched response")
	}
}

// TestRouteBGResponse_IDLessFallback confirms a frame carrying no request_id
// still reaches the single outstanding waiter — the legitimate positional path
// that the orphan-drop must not regress.
func TestRouteBGResponse_IDLessFallback(t *testing.T) {
	c := &PeerClient{}
	w := make(chan bgFrame, 1)
	c.bgPending.Store("validate-1", w)
	c.bgWaiters.Add(1)

	// Envelope with no decodable response shape ⇒ responseRequestIDOf == "".
	c.routeBGResponse([]byte("idless"), entity.Envelope{Root: entity.Entity{Type: "system/something/else"}})

	select {
	case f := <-w:
		if string(f.raw) != "idless" {
			t.Fatalf("got %q, want idless", f.raw)
		}
	default:
		t.Fatalf("id-less frame not delivered to the lone waiter")
	}
}
