package wire

import (
	"fmt"
	"io"

	"go.entitychurch.org/entity-core-go/core/ecf"
	"go.entitychurch.org/entity-core-go/core/entity"
)

// WriteEnvelope ECF-encodes an envelope and writes it as a length-prefixed frame.
func WriteEnvelope(w io.Writer, env entity.Envelope) error {
	data, err := ecf.Encode(env)
	if err != nil {
		return fmt.Errorf("encode envelope: %w", err)
	}
	return WriteFrame(w, data)
}

// ReadEnvelope reads a frame, decodes the envelope, and validates all hashes.
func ReadEnvelope(r io.Reader) (entity.Envelope, error) {
	env, err := ReadEnvelopeNoValidate(r)
	if err != nil {
		return entity.Envelope{}, err
	}

	if err := env.ValidateAll(); err != nil {
		return entity.Envelope{}, fmt.Errorf("validate envelope: %w", err)
	}

	return env, nil
}

// ReadEnvelopeNoValidate reads a frame and decodes the envelope without
// validating entity hashes. Use this when the caller needs to inspect the
// envelope contents even if hashes don't match (e.g. for diagnostics).
func ReadEnvelopeNoValidate(r io.Reader) (entity.Envelope, error) {
	data, err := ReadFrame(r)
	if err != nil {
		return entity.Envelope{}, err
	}

	var env entity.Envelope
	if err := ecf.Decode(data, &env); err != nil {
		return entity.Envelope{}, fmt.Errorf("decode envelope: %w", err)
	}

	return env, nil
}
