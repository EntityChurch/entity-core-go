package entity

import (
	"go.entitychurch.org/entity-core-go/core/ecf"
)

// cborDecode is a package-internal helper wrapping ecf.Decode.
func cborDecode(data []byte, v interface{}) error {
	return ecf.Decode(data, v)
}
