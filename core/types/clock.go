package types

import (
	"go.entitychurch.org/entity-core-go/core/ecf"
	"go.entitychurch.org/entity-core-go/core/entity"
	"go.entitychurch.org/entity-core-go/core/hash"

	"github.com/fxamacker/cbor/v2"
)

// Clock type constants — 9 types per EXTENSION-CLOCK.md §9.5.
const (
	TypeClockTimestamp     = "system/clock/timestamp"
	TypeClockLogical       = "system/clock/logical"
	TypeClockVector        = "system/clock/vector"
	TypeClockHLC           = "system/clock/hlc"
	TypeClockConfig        = "system/clock/config"
	TypeClockState         = "system/clock/state"
	TypeClockCompareParams = "system/clock/compare-params"
	TypeClockCompareResult = "system/clock/compare-result"
	TypeClockTick          = "system/clock/tick"
)

// Clock constants per EXTENSION-CLOCK.md §8.
const (
	DefaultTickIntervalMs = 1000
	MaxVectorEntries      = 1024
	MaxHLCDriftMs         = 60000
	DefaultClockMode      = "wall"
)

// ClockTimestampData is the data payload for system/clock/timestamp (§2.1).
type ClockTimestampData struct {
	Ms uint64 `cbor:"ms"`
}

func (d ClockTimestampData) ToEntity() (entity.Entity, error) {
	raw, err := ecf.Encode(d)
	if err != nil {
		return entity.Entity{}, err
	}
	return entity.NewEntity(TypeClockTimestamp, cbor.RawMessage(raw))
}

func ClockTimestampDataFromEntity(e entity.Entity) (ClockTimestampData, error) {
	var d ClockTimestampData
	if err := ecf.Decode(e.Data, &d); err != nil {
		return ClockTimestampData{}, err
	}
	return d, nil
}

// ClockLogicalData is the data payload for system/clock/logical (§2.2).
type ClockLogicalData struct {
	Counter uint64 `cbor:"counter"`
}

func (d ClockLogicalData) ToEntity() (entity.Entity, error) {
	raw, err := ecf.Encode(d)
	if err != nil {
		return entity.Entity{}, err
	}
	return entity.NewEntity(TypeClockLogical, cbor.RawMessage(raw))
}

func ClockLogicalDataFromEntity(e entity.Entity) (ClockLogicalData, error) {
	var d ClockLogicalData
	if err := ecf.Decode(e.Data, &d); err != nil {
		return ClockLogicalData{}, err
	}
	return d, nil
}

// ClockVectorData is the data payload for system/clock/vector (§2.3).
type ClockVectorData struct {
	Entries map[string]uint64 `cbor:"entries"`
}

func (d ClockVectorData) ToEntity() (entity.Entity, error) {
	raw, err := ecf.Encode(d)
	if err != nil {
		return entity.Entity{}, err
	}
	return entity.NewEntity(TypeClockVector, cbor.RawMessage(raw))
}

func ClockVectorDataFromEntity(e entity.Entity) (ClockVectorData, error) {
	var d ClockVectorData
	if err := ecf.Decode(e.Data, &d); err != nil {
		return ClockVectorData{}, err
	}
	return d, nil
}

// ClockHLCData is the data payload for system/clock/hlc (§2.4).
type ClockHLCData struct {
	Physical uint64    `cbor:"physical"`
	Logical  uint64    `cbor:"logical"`
	Peer     hash.Hash `cbor:"peer"`
}

func (d ClockHLCData) ToEntity() (entity.Entity, error) {
	raw, err := ecf.Encode(d)
	if err != nil {
		return entity.Entity{}, err
	}
	return entity.NewEntity(TypeClockHLC, cbor.RawMessage(raw))
}

func ClockHLCDataFromEntity(e entity.Entity) (ClockHLCData, error) {
	var d ClockHLCData
	if err := ecf.Decode(e.Data, &d); err != nil {
		return ClockHLCData{}, err
	}
	return d, nil
}

// ClockConfigData is the data payload for system/clock/config (§2.5).
type ClockConfigData struct {
	Mode         string  `cbor:"mode"`
	WallClock    *bool   `cbor:"wall_clock,omitempty"`
	TickInterval *uint64 `cbor:"tick_interval,omitempty"`
}

func (d ClockConfigData) ToEntity() (entity.Entity, error) {
	raw, err := ecf.Encode(d)
	if err != nil {
		return entity.Entity{}, err
	}
	return entity.NewEntity(TypeClockConfig, cbor.RawMessage(raw))
}

func ClockConfigDataFromEntity(e entity.Entity) (ClockConfigData, error) {
	var d ClockConfigData
	if err := ecf.Decode(e.Data, &d); err != nil {
		return ClockConfigData{}, err
	}
	return d, nil
}

// ClockStateData is the data payload for system/clock/state (§2.6).
type ClockStateData struct {
	Mode      string              `cbor:"mode"`
	Timestamp *ClockTimestampData `cbor:"timestamp,omitempty"`
	Logical   *ClockLogicalData   `cbor:"logical,omitempty"`
	Vector    *ClockVectorData    `cbor:"vector,omitempty"`
	HLC       *ClockHLCData       `cbor:"hlc,omitempty"`
}

func (d ClockStateData) ToEntity() (entity.Entity, error) {
	raw, err := ecf.Encode(d)
	if err != nil {
		return entity.Entity{}, err
	}
	return entity.NewEntity(TypeClockState, cbor.RawMessage(raw))
}

func ClockStateDataFromEntity(e entity.Entity) (ClockStateData, error) {
	var d ClockStateData
	if err := ecf.Decode(e.Data, &d); err != nil {
		return ClockStateData{}, err
	}
	return d, nil
}

// ClockCompareParamsData is the data payload for system/clock/compare-params (§2.7).
// A and B are raw CBOR since they can be any clock type.
type ClockCompareParamsData struct {
	A cbor.RawMessage `cbor:"a"`
	B cbor.RawMessage `cbor:"b"`
}

func ClockCompareParamsDataFromEntity(e entity.Entity) (ClockCompareParamsData, error) {
	var d ClockCompareParamsData
	if err := ecf.Decode(e.Data, &d); err != nil {
		return ClockCompareParamsData{}, err
	}
	return d, nil
}

// ClockCompareResultData is the data payload for system/clock/compare-result (§2.7).
type ClockCompareResultData struct {
	Order string `cbor:"order"`
}

func (d ClockCompareResultData) ToEntity() (entity.Entity, error) {
	raw, err := ecf.Encode(d)
	if err != nil {
		return entity.Entity{}, err
	}
	return entity.NewEntity(TypeClockCompareResult, cbor.RawMessage(raw))
}

// ClockTickData is the data payload for system/clock/tick (§2.8).
type ClockTickData struct {
	Sequence uint64         `cbor:"sequence"`
	State    ClockStateData `cbor:"state"`
}

func (d ClockTickData) ToEntity() (entity.Entity, error) {
	raw, err := ecf.Encode(d)
	if err != nil {
		return entity.Entity{}, err
	}
	return entity.NewEntity(TypeClockTick, cbor.RawMessage(raw))
}
