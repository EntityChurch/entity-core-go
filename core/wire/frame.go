package wire

import (
	"encoding/binary"
	"fmt"
	"io"

	ecerrors "go.entitychurch.org/entity-core-go/core/errors"
)

const (
	// MaxFrameSize is the default maximum frame size (16 MiB).
	MaxFrameSize = 16 * 1024 * 1024

	// frameLenSize is the size of the length prefix in bytes.
	frameLenSize = 4
)

// WriteFrame writes a length-prefixed frame to the writer in a single
// Write call. The length prefix and payload are concatenated into one
// buffer before the underlying Write so that adapters with message
// semantics (WebSocket, where each Write becomes one binary message
// per V7 §6.5.2c L864) emit exactly one length-prefixed ECF envelope
// per WS message. On byte-stream substrates (TCP, HTTP body) the
// outcome is byte-identical to two sequential writes — one syscall
// instead of two.
func WriteFrame(w io.Writer, data []byte) error {
	if len(data) > MaxFrameSize {
		return fmt.Errorf("%w: frame too large: %d bytes (max %d)", ecerrors.ErrFrameTooLarge, len(data), MaxFrameSize)
	}

	buf := make([]byte, frameLenSize+len(data))
	binary.BigEndian.PutUint32(buf[:frameLenSize], uint32(len(data)))
	copy(buf[frameLenSize:], data)

	if _, err := w.Write(buf); err != nil {
		return fmt.Errorf("write frame: %w", err)
	}
	return nil
}

// ReadFrame reads a length-prefixed frame from the reader.
func ReadFrame(r io.Reader) ([]byte, error) {
	var lenBuf [frameLenSize]byte
	if _, err := io.ReadFull(r, lenBuf[:]); err != nil {
		return nil, fmt.Errorf("read frame length: %w", err)
	}

	length := binary.BigEndian.Uint32(lenBuf[:])
	if int(length) > MaxFrameSize {
		return nil, fmt.Errorf("%w: frame too large: %d bytes (max %d)", ecerrors.ErrFrameTooLarge, length, MaxFrameSize)
	}

	data := make([]byte, length)
	if _, err := io.ReadFull(r, data); err != nil {
		return nil, fmt.Errorf("read frame payload: %w", err)
	}
	return data, nil
}
