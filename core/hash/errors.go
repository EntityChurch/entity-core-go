package hash

import (
	ecerrors "go.entitychurch.org/entity-core-go/core/errors"
)

// Re-export errors used in this package for convenience.
var (
	ErrHashMismatch                 = ecerrors.ErrHashMismatch
	ErrInvalidHash                  = ecerrors.ErrInvalidHash
	ErrUnknownAlgorithm             = ecerrors.ErrUnknownAlgorithm
	ErrUnsupportedContentHashFormat = ecerrors.ErrUnsupportedContentHashFormat
)
