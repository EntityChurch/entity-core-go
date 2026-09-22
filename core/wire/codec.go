package wire

import (
	"fmt"
	"io"

	"go.entitychurch.org/entity-core-go/core/ecf"
	"go.entitychurch.org/entity-core-go/core/entity"
	ecerrors "go.entitychurch.org/entity-core-go/core/errors"
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
		// §4.11 (0.8.2.25): a whole frame that will not decode is the
		// "never becomes an Envelope" population — tag it so the serve loop
		// answers 400 invalid_request rather than bare-closing, and so it can
		// keep the (synchronized) connection alive for admitted in-flight work.
		return entity.Envelope{}, fmt.Errorf("decode envelope: %w: %w", ecerrors.ErrEnvelopeDecode, err)
	}

	return env, nil
}
