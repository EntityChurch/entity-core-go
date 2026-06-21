package wire

import (
	"bytes"
	"encoding/binary"
	"testing"

	"go.entitychurch.org/entity-core-go/core/ecf"
	"go.entitychurch.org/entity-core-go/core/entity"
	"go.entitychurch.org/entity-core-go/core/hash"

	"github.com/fxamacker/cbor/v2"
)

func makeEntity(t *testing.T, typ string, data interface{}) entity.Entity {
	t.Helper()
	raw, err := ecf.Encode(data)
	if err != nil {
		t.Fatal(err)
	}
	e, err := entity.NewEntity(typ, cbor.RawMessage(raw))
	if err != nil {
		t.Fatal(err)
	}
	return e
}

func TestWriteReadFrame(t *testing.T) {
	payload := []byte("hello frame world")
	var buf bytes.Buffer

	if err := WriteFrame(&buf, payload); err != nil {
		t.Fatal(err)
	}

	// Verify length prefix.
	if buf.Len() != frameLenSize+len(payload) {
		t.Fatalf("expected %d bytes, got %d", frameLenSize+len(payload), buf.Len())
	}

	// Read back.
	data, err := ReadFrame(&buf)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(data, payload) {
		t.Fatalf("payload mismatch: %q != %q", data, payload)
	}
}

func TestFrameLengthPrefix(t *testing.T) {
	payload := []byte{0x01, 0x02, 0x03}
	var buf bytes.Buffer

	WriteFrame(&buf, payload)

	// First 4 bytes should be big-endian length = 3.
	var lenBuf [4]byte
	copy(lenBuf[:], buf.Bytes()[:4])
	length := binary.BigEndian.Uint32(lenBuf[:])
	if length != 3 {
		t.Fatalf("expected length 3, got %d", length)
	}
}

func TestFrameMaxSizeReject(t *testing.T) {
	// Writing a frame larger than MaxFrameSize should fail.
	huge := make([]byte, MaxFrameSize+1)
	var buf bytes.Buffer
	if err := WriteFrame(&buf, huge); err == nil {
		t.Fatal("expected error for oversized frame")
	}
}

func TestReadFrameMaxSizeReject(t *testing.T) {
	// Manually write a length prefix that exceeds max.
	var buf bytes.Buffer
	var lenBuf [4]byte
	binary.BigEndian.PutUint32(lenBuf[:], uint32(MaxFrameSize+1))
	buf.Write(lenBuf[:])
	buf.Write(make([]byte, 10)) // partial payload

	_, err := ReadFrame(&buf)
	if err == nil {
		t.Fatal("expected error for oversized frame length")
	}
}

func TestWriteReadEnvelope(t *testing.T) {
	root := makeEntity(t, "test/root", map[string]string{"key": "value"})
	inc := makeEntity(t, "test/included", "data")

	env := entity.NewEnvelope(root, map[hash.Hash]entity.Entity{
		inc.ContentHash: inc,
	})

	var buf bytes.Buffer
	if err := WriteEnvelope(&buf, env); err != nil {
		t.Fatal(err)
	}

	decoded, err := ReadEnvelope(&buf)
	if err != nil {
		t.Fatal(err)
	}

	if decoded.Root.Type != "test/root" {
		t.Fatalf("root type: expected test/root, got %s", decoded.Root.Type)
	}
	if decoded.Root.ContentHash != root.ContentHash {
		t.Fatal("root hash mismatch")
	}

	found, ok := decoded.FindIncluded(inc.ContentHash)
	if !ok {
		t.Fatal("included entity not found")
	}
	if found.Type != "test/included" {
		t.Fatalf("included type: expected test/included, got %s", found.Type)
	}
}

func TestMultipleFrames(t *testing.T) {
	var buf bytes.Buffer

	// Write multiple frames.
	for i := 0; i < 5; i++ {
		e := makeEntity(t, "test", i)
		env := entity.NewEnvelope(e, nil)
		if err := WriteEnvelope(&buf, env); err != nil {
			t.Fatal(err)
		}
	}

	// Read them back.
	for i := 0; i < 5; i++ {
		env, err := ReadEnvelope(&buf)
		if err != nil {
			t.Fatalf("frame %d: %v", i, err)
		}
		if env.Root.Type != "test" {
			t.Fatalf("frame %d: expected type test, got %s", i, env.Root.Type)
		}
	}
}

func TestEmptyPayload(t *testing.T) {
	var buf bytes.Buffer
	if err := WriteFrame(&buf, []byte{}); err != nil {
		t.Fatal(err)
	}
	data, err := ReadFrame(&buf)
	if err != nil {
		t.Fatal(err)
	}
	if len(data) != 0 {
		t.Fatalf("expected empty payload, got %d bytes", len(data))
	}
}
