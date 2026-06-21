// WebSocket transport adapter — wraps a *coderws.Conn as a net.Conn so
// the existing core/peer Connection + wire codec machinery (designed
// around io.Reader/io.Writer over net.Conn) drives WebSocket peers
// unchanged.
//
// V7 §6.5.2c L864 mandates "one V7 §1.6 length-prefixed ECF envelope
// per binary WS message" — opposite of http-live, which forbids the
// prefix because HTTP frames the body natively. This adapter relies
// on core/wire.WriteFrame writing one Write call per frame (length +
// payload concatenated) so each frame maps 1:1 to a binary WS message.
// On the read side, each Read drains from the current buffered message
// until exhausted, then pulls the next message — io.ReadFull naturally
// reads (4-byte length) then (N-byte payload) within the same message
// without any framing-aware glue here.

package peer

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"time"

	coderws "github.com/coder/websocket"
)

// wsConn wraps a *coderws.Conn as a net.Conn. Read/Write are NOT safe
// for concurrent use within the same direction (matches net.Conn
// semantics — wire codec serializes via writeMu / read loop).
type wsConn struct {
	conn   *coderws.Conn
	ctx    context.Context
	cancel context.CancelFunc

	// readBuf is the unread tail of the most recent binary message.
	// Subsequent Read calls drain it before pulling the next message.
	readBuf []byte

	// localAddr / remoteAddr expose endpoint addressing via net.Addr.
	// Best-effort — coder/websocket abstracts the underlying TCP conn,
	// so we synthesize string-form addrs from the dial URL or http.Request.
	localAddr  net.Addr
	remoteAddr net.Addr

	closeOnce sync.Once
	closeErr  error
}

// wsAddr is a minimal net.Addr for WS endpoints. Used so peer logs
// and Conn.RemoteAddr() callers see a sensible "ws://host/path" string.
type wsAddr struct{ url string }

func (a wsAddr) Network() string { return "websocket" }
func (a wsAddr) String() string  { return a.url }

// newWSConn wraps a coder/websocket Conn (returned by Accept or Dial)
// as a net.Conn. The parent ctx scopes Read/Write deadlines; cancelling
// it closes the underlying WS connection.
func newWSConn(parent context.Context, c *coderws.Conn, local, remote net.Addr) *wsConn {
	ctx, cancel := context.WithCancel(parent)
	return &wsConn{
		conn:       c,
		ctx:        ctx,
		cancel:     cancel,
		localAddr:  local,
		remoteAddr: remote,
	}
}

// Read drains bytes from the current binary message buffer, fetching
// the next message when the buffer is empty. Returns io.EOF on normal
// peer close; any other failure surfaces as an error.
func (w *wsConn) Read(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	if len(w.readBuf) == 0 {
		typ, data, err := w.conn.Read(w.ctx)
		if err != nil {
			// Normalize close to io.EOF so connection.serve's read loop
			// treats it the same as a TCP-side close.
			var ce coderws.CloseError
			if errors.As(err, &ce) {
				return 0, io.EOF
			}
			if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
				return 0, io.EOF
			}
			return 0, err
		}
		if typ != coderws.MessageBinary {
			return 0, fmt.Errorf("ws: unexpected non-binary message type %v (V7 §6.5.2c — binary only)", typ)
		}
		w.readBuf = data
	}
	n := copy(p, w.readBuf)
	w.readBuf = w.readBuf[n:]
	return n, nil
}

// Write sends p as a single binary WS message. The wire codec invariant
// (one length-prefixed envelope per WriteFrame call) lines up with one
// Write call per binary message — see file-level doc.
func (w *wsConn) Write(p []byte) (int, error) {
	if err := w.conn.Write(w.ctx, coderws.MessageBinary, p); err != nil {
		return 0, err
	}
	return len(p), nil
}

func (w *wsConn) Close() error {
	w.closeOnce.Do(func() {
		w.closeErr = w.conn.Close(coderws.StatusNormalClosure, "")
		w.cancel()
	})
	return w.closeErr
}

func (w *wsConn) LocalAddr() net.Addr  { return w.localAddr }
func (w *wsConn) RemoteAddr() net.Addr { return w.remoteAddr }

// Deadline methods are net.Conn surface; coder/websocket uses context
// for cancellation rather than deadlines, so these are no-ops. The
// per-Connection serve loop already handles cancellation via its own
// context plumbing — no deadline handshake needed in practice.
func (w *wsConn) SetDeadline(time.Time) error      { return nil }
func (w *wsConn) SetReadDeadline(time.Time) error  { return nil }
func (w *wsConn) SetWriteDeadline(time.Time) error { return nil }
