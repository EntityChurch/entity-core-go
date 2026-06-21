package handler

import (
	"go.entitychurch.org/entity-core-go/core/ecf"
)

func ecfEncode(v interface{}) ([]byte, error) {
	return ecf.Encode(v)
}
