package protocol

import (
	"context"
	"errors"
	"testing"

	"go.entitychurch.org/entity-core-go/core/crypto"
	ecerrors "go.entitychurch.org/entity-core-go/core/errors"
	"go.entitychurch.org/entity-core-go/core/handler"
	"go.entitychurch.org/entity-core-go/core/types"
)

// TestValidateConnectionSequencePing pins the §5.1 gating: ping is the one
// connect-handler op that REQUIRES an established connection — the inverse
// of hello/authenticate, which are rejected once established.
func TestValidateConnectionSequencePing(t *testing.T) {
	fresh := NewConnectionState()
	if err := ValidateConnectionSequence(fresh, "ping"); !errors.Is(err, ecerrors.ErrConnectionRequired) {
		t.Fatalf("pre-handshake ping: err = %v, want ErrConnectionRequired", err)
	}

	established := NewConnectionState()
	established.Completed = true
	established.Phase = "completed"
	if err := ValidateConnectionSequence(established, "ping"); err != nil {
		t.Fatalf("established ping: unexpected err %v", err)
	}
	// The handshake ops stay rejected post-establishment (unchanged).
	if err := ValidateConnectionSequence(established, "hello"); !errors.Is(err, ecerrors.ErrConnectionEstablished) {
		t.Fatalf("established hello: err = %v, want ErrConnectionEstablished", err)
	}
}

// TestConnectHandlerPing pins the §5.2/§5.3 responder shape: pong echoes
// timestamp + sequence and stamps server_time; a params entity that is not
// system/network/ping is a 400.
func TestConnectHandlerPing(t *testing.T) {
	kp, err := crypto.Generate()
	if err != nil {
		t.Fatalf("generate keypair: %v", err)
	}
	h, err := NewConnectHandler(kp, []string{"7.0"})
	if err != nil {
		t.Fatalf("NewConnectHandler: %v", err)
	}

	ping, err := types.PingData{Timestamp: 99, Sequence: 3}.ToEntity()
	if err != nil {
		t.Fatalf("ping ToEntity: %v", err)
	}
	resp, err := h.Handle(context.Background(), &handler.Request{
		Path:      "system/protocol/connect",
		Operation: "ping",
		Params:    ping,
	})
	if err != nil {
		t.Fatalf("ping handle: %v", err)
	}
	if resp.Status != 200 {
		t.Fatalf("ping status = %d, want 200", resp.Status)
	}
	pong, err := types.PongDataFromEntity(resp.Result)
	if err != nil {
		t.Fatalf("decode pong: %v", err)
	}
	if pong.Timestamp != 99 || pong.Sequence != 3 || pong.ServerTime == 0 {
		t.Fatalf("bad pong echo: %+v", pong)
	}

	// Wrong params type → 400 invalid_params.
	notPing, err := types.PongData{Timestamp: 1, Sequence: 1, ServerTime: 1}.ToEntity()
	if err != nil {
		t.Fatalf("notPing ToEntity: %v", err)
	}
	resp, err = h.Handle(context.Background(), &handler.Request{
		Path:      "system/protocol/connect",
		Operation: "ping",
		Params:    notPing,
	})
	if err != nil {
		t.Fatalf("bad-params handle: %v", err)
	}
	if resp.Status != 400 {
		t.Fatalf("bad-params status = %d, want 400", resp.Status)
	}
}
