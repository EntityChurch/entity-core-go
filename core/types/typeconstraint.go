package types

import (
	"go.entitychurch.org/entity-core-go/core/ecf"
	"go.entitychurch.org/entity-core-go/core/entity"

	"github.com/fxamacker/cbor/v2"
)

// Standard constraint type paths per EXTENSION-TYPE v1.1 §4 / §11.1.
// Each constraint is an entity bound at system/type/constraint/{kind}; the
// path is also the dispatch target for the standard constraint handler at
// pattern system/type/constraint/*.
const (
	TypeConstraintMin         = "system/type/constraint/min"
	TypeConstraintMax         = "system/type/constraint/max"
	TypeConstraintMinLength   = "system/type/constraint/min-length"
	TypeConstraintMaxLength   = "system/type/constraint/max-length"
	TypeConstraintMinCount    = "system/type/constraint/min-count"
	TypeConstraintMaxCount    = "system/type/constraint/max-count"
	TypeConstraintPattern     = "system/type/constraint/pattern"
	TypeConstraintOneOf       = "system/type/constraint/one-of"
	TypeConstraintNotOneOf    = "system/type/constraint/not-one-of"
	TypeConstraintFormat      = "system/type/constraint/format"
	TypeConstraintTypePattern = "system/type/constraint/type-pattern"

	// Standard constraint handler request/result envelope.
	TypeConstraintValidateReq    = "system/type/constraint/validate-request"
	TypeConstraintValidateResult = "system/type/constraint/validate-result"

	// Type handler analysis-op types per §8.
	TypeTypeViolation             = "system/type/violation"
	TypeTypeFieldComparison       = "system/type/field-comparison"
	TypeTypeFieldIncompatibility  = "system/type/field-incompatibility"
	TypeTypeCompareRequest        = "system/type/compare-request"
	TypeTypeCompareResult         = "system/type/compare-result"
	TypeTypeCompatibleRequest     = "system/type/compatible-request"
	TypeTypeCompatibilityReport   = "system/type/compatibility-report"
	TypeTypeConvergeRequest       = "system/type/converge-request"
	TypeTypeAdoptRequest          = "system/type/adopt-request"
	TypeTypeReconcileRequest      = "system/type/reconcile-request"
	TypeTypeReconcileResult       = "system/type/reconcile-result"
)

// Well-known violation kinds per EXTENSION-TYPE v1.1 §8.5 / §1.2.
const (
	ViolationKindStructural        = "structural"
	ViolationKindConstraint        = "constraint"
	ViolationKindUnknownConstraint = "unknown_constraint"
)

// Well-known format names the standard constraint handler MUST recognize
// per EXTENSION-TYPE v1.1 §4.5. Implementations MAY recognize additional
// names; unknown names fail closed.
const (
	FormatURI      = "uri"
	FormatDateTime = "date-time"
	FormatDate     = "date"
	FormatUUID     = "uuid"
	FormatBase58   = "base58"
	FormatRE2      = "re2"
)

// ConstraintMinData is the data payload for system/type/constraint/min.
type ConstraintMinData struct {
	Min float64 `cbor:"min"`
}

func (d ConstraintMinData) ToEntity() (entity.Entity, error) {
	raw, err := ecf.Encode(d)
	if err != nil {
		return entity.Entity{}, err
	}
	return entity.NewEntity(TypeConstraintMin, cbor.RawMessage(raw))
}

// ConstraintMaxData is the data payload for system/type/constraint/max.
type ConstraintMaxData struct {
	Max float64 `cbor:"max"`
}

func (d ConstraintMaxData) ToEntity() (entity.Entity, error) {
	raw, err := ecf.Encode(d)
	if err != nil {
		return entity.Entity{}, err
	}
	return entity.NewEntity(TypeConstraintMax, cbor.RawMessage(raw))
}

// ConstraintMinLengthData is the data payload for system/type/constraint/min-length.
type ConstraintMinLengthData struct {
	MinLength uint64 `cbor:"min_length"`
}

func (d ConstraintMinLengthData) ToEntity() (entity.Entity, error) {
	raw, err := ecf.Encode(d)
	if err != nil {
		return entity.Entity{}, err
	}
	return entity.NewEntity(TypeConstraintMinLength, cbor.RawMessage(raw))
}

// ConstraintMaxLengthData is the data payload for system/type/constraint/max-length.
type ConstraintMaxLengthData struct {
	MaxLength uint64 `cbor:"max_length"`
}

func (d ConstraintMaxLengthData) ToEntity() (entity.Entity, error) {
	raw, err := ecf.Encode(d)
	if err != nil {
		return entity.Entity{}, err
	}
	return entity.NewEntity(TypeConstraintMaxLength, cbor.RawMessage(raw))
}

// ConstraintMinCountData is the data payload for system/type/constraint/min-count.
type ConstraintMinCountData struct {
	MinCount uint64 `cbor:"min_count"`
}

func (d ConstraintMinCountData) ToEntity() (entity.Entity, error) {
	raw, err := ecf.Encode(d)
	if err != nil {
		return entity.Entity{}, err
	}
	return entity.NewEntity(TypeConstraintMinCount, cbor.RawMessage(raw))
}

// ConstraintMaxCountData is the data payload for system/type/constraint/max-count.
type ConstraintMaxCountData struct {
	MaxCount uint64 `cbor:"max_count"`
}

func (d ConstraintMaxCountData) ToEntity() (entity.Entity, error) {
	raw, err := ecf.Encode(d)
	if err != nil {
		return entity.Entity{}, err
	}
	return entity.NewEntity(TypeConstraintMaxCount, cbor.RawMessage(raw))
}

// ConstraintPatternData is the data payload for system/type/constraint/pattern.
// Pattern is an RE2 expression evaluated full-match per §4.3.
type ConstraintPatternData struct {
	Pattern string `cbor:"pattern"`
}

func (d ConstraintPatternData) ToEntity() (entity.Entity, error) {
	raw, err := ecf.Encode(d)
	if err != nil {
		return entity.Entity{}, err
	}
	return entity.NewEntity(TypeConstraintPattern, cbor.RawMessage(raw))
}

// ConstraintOneOfData is the data payload for system/type/constraint/one-of.
// Comparison MUST use ECF byte equality (§4.4, §5.5 normative).
type ConstraintOneOfData struct {
	Values []cbor.RawMessage `cbor:"values"`
}

func (d ConstraintOneOfData) ToEntity() (entity.Entity, error) {
	raw, err := ecf.Encode(d)
	if err != nil {
		return entity.Entity{}, err
	}
	return entity.NewEntity(TypeConstraintOneOf, cbor.RawMessage(raw))
}

// ConstraintNotOneOfData is the data payload for system/type/constraint/not-one-of.
type ConstraintNotOneOfData struct {
	Values []cbor.RawMessage `cbor:"values"`
}

func (d ConstraintNotOneOfData) ToEntity() (entity.Entity, error) {
	raw, err := ecf.Encode(d)
	if err != nil {
		return entity.Entity{}, err
	}
	return entity.NewEntity(TypeConstraintNotOneOf, cbor.RawMessage(raw))
}

// ConstraintFormatData is the data payload for system/type/constraint/format.
type ConstraintFormatData struct {
	Format string `cbor:"format"`
}

func (d ConstraintFormatData) ToEntity() (entity.Entity, error) {
	raw, err := ecf.Encode(d)
	if err != nil {
		return entity.Entity{}, err
	}
	return entity.NewEntity(TypeConstraintFormat, cbor.RawMessage(raw))
}

// ConstraintTypePatternData is the data payload for
// system/type/constraint/type-pattern. Pattern is a glob over type names;
// `*` matches one segment, `**` zero or more (§4.6).
type ConstraintTypePatternData struct {
	Pattern string `cbor:"pattern"`
}

func (d ConstraintTypePatternData) ToEntity() (entity.Entity, error) {
	raw, err := ecf.Encode(d)
	if err != nil {
		return entity.Entity{}, err
	}
	return entity.NewEntity(TypeConstraintTypePattern, cbor.RawMessage(raw))
}

// ConstraintValidateRequestData is the dispatch envelope for the standard
// constraint handler per §5.2.
type ConstraintValidateRequestData struct {
	Value          cbor.RawMessage `cbor:"value"`
	ConstraintType string          `cbor:"constraint_type"`
	ConstraintData cbor.RawMessage `cbor:"constraint_data"`
}

func (d ConstraintValidateRequestData) ToEntity() (entity.Entity, error) {
	raw, err := ecf.Encode(d)
	if err != nil {
		return entity.Entity{}, err
	}
	return entity.NewEntity(TypeConstraintValidateReq, cbor.RawMessage(raw))
}

// ConstraintValidateResultData is the dispatch result for the standard
// constraint handler per §5.3. Reason is absent when Valid is true.
type ConstraintValidateResultData struct {
	Valid  bool   `cbor:"valid"`
	Reason string `cbor:"reason,omitempty"`
}

func (d ConstraintValidateResultData) ToEntity() (entity.Entity, error) {
	raw, err := ecf.Encode(d)
	if err != nil {
		return entity.Entity{}, err
	}
	return entity.NewEntity(TypeConstraintValidateResult, cbor.RawMessage(raw))
}

// Violation reports a single failed check from system/type:validate per §8.5.
type Violation struct {
	Field      string `cbor:"field"`
	Kind       string `cbor:"kind"`
	Constraint string `cbor:"constraint,omitempty"`
	Reason     string `cbor:"reason"`
}

// FieldComparisonData is the per-field result of system/type:compare per §8.1.
type FieldComparisonData struct {
	TypeMatch       bool   `cbor:"type_match"`
	ConstraintMatch bool   `cbor:"constraint_match"`
	AOptional       bool   `cbor:"a_optional"`
	BOptional       bool   `cbor:"b_optional"`
	Detail          string `cbor:"detail,omitempty"`
}

// FieldIncompatibilityData reports a field that could not be reconciled
// across two type definitions per §8.2.
type FieldIncompatibilityData struct {
	FieldName string `cbor:"field_name"`
	AType     string `cbor:"a_type"`
	BType     string `cbor:"b_type"`
	Reason    string `cbor:"reason"`
}

// CompareRequestData is the input for system/type:compare per §7.2.
type CompareRequestData struct {
	TypeA string `cbor:"type_a"`
	TypeB string `cbor:"type_b"`
}

// ToEntity creates a system/type/compare-request entity.
func (d CompareRequestData) ToEntity() (entity.Entity, error) {
	raw, err := ecf.Encode(d)
	if err != nil {
		return entity.Entity{}, err
	}
	return entity.NewEntity(TypeTypeCompareRequest, cbor.RawMessage(raw))
}

// CompareResultData is the output of system/type:compare per §7.2.
type CompareResultData struct {
	TypeAPath    string                         `cbor:"type_a_path"`
	TypeBPath    string                         `cbor:"type_b_path"`
	Shared       map[string]FieldComparisonData `cbor:"shared"`
	OnlyA        []string                       `cbor:"only_a"`
	OnlyB        []string                       `cbor:"only_b"`
	Incompatible []FieldIncompatibilityData     `cbor:"incompatible,omitempty"`
}

// CompatibleRequestData is the input for system/type:compatible per §7.3.
type CompatibleRequestData struct {
	TypeA     string `cbor:"type_a"`
	TypeB     string `cbor:"type_b"`
	Direction string `cbor:"direction"`
}

// ToEntity creates a system/type/compatible-request entity.
func (d CompatibleRequestData) ToEntity() (entity.Entity, error) {
	raw, err := ecf.Encode(d)
	if err != nil {
		return entity.Entity{}, err
	}
	return entity.NewEntity(TypeTypeCompatibleRequest, cbor.RawMessage(raw))
}

// CompatibilityReportData is the output of system/type:compatible per §7.3.
type CompatibilityReportData struct {
	TypeAPath          string                     `cbor:"type_a_path"`
	TypeBPath          string                     `cbor:"type_b_path"`
	Direction          string                     `cbor:"direction"`
	Level              string                     `cbor:"level"`
	SharedFields       []string                   `cbor:"shared_fields"`
	IncompatibleFields []FieldIncompatibilityData `cbor:"incompatible_fields,omitempty"`
	MissingRequiredA   []string                   `cbor:"missing_required_a,omitempty"`
	MissingRequiredB   []string                   `cbor:"missing_required_b,omitempty"`
}

// Well-known compatibility levels per §7.3.
const (
	CompatibilityFullyCompatible     = "fully_compatible"
	CompatibilityForwardOnly         = "forward_only"
	CompatibilityBackwardOnly        = "backward_only"
	CompatibilityPartiallyCompatible = "partially_compatible"
	CompatibilityIncompatible        = "incompatible"
)

// Well-known compatibility directions per §7.3.
const (
	DirectionForward       = "forward"
	DirectionBackward      = "backward"
	DirectionBidirectional = "bidirectional"
)

// ConvergeRequestData is the input for system/type:converge per §7.4.
type ConvergeRequestData struct {
	TypePaths []string `cbor:"type_paths"`
}

// ToEntity creates a system/type/converge-request entity.
func (d ConvergeRequestData) ToEntity() (entity.Entity, error) {
	raw, err := ecf.Encode(d)
	if err != nil {
		return entity.Entity{}, err
	}
	return entity.NewEntity(TypeTypeConvergeRequest, cbor.RawMessage(raw))
}

// AdoptRequestData is the input for system/type:adopt per §7.5.
type AdoptRequestData struct {
	SourcePath string `cbor:"source_path"`
	LocalName  string `cbor:"local_name,omitempty"`
}

// ToEntity creates a system/type/adopt-request entity.
func (d AdoptRequestData) ToEntity() (entity.Entity, error) {
	raw, err := ecf.Encode(d)
	if err != nil {
		return entity.Entity{}, err
	}
	return entity.NewEntity(TypeTypeAdoptRequest, cbor.RawMessage(raw))
}

// ReconcileRequestData is the input for system/type:reconcile per §7.6.
type ReconcileRequestData struct {
	TypePaths []string `cbor:"type_paths"`
	Strategy  string   `cbor:"strategy"`
}

// ToEntity creates a system/type/reconcile-request entity.
func (d ReconcileRequestData) ToEntity() (entity.Entity, error) {
	raw, err := ecf.Encode(d)
	if err != nil {
		return entity.Entity{}, err
	}
	return entity.NewEntity(TypeTypeReconcileRequest, cbor.RawMessage(raw))
}

// Well-known reconcile strategies per §7.6.
const (
	ReconcileIntersect = "intersect"
	ReconcileUnion     = "union"
	ReconcilePrefer    = "prefer"
)

// ReconcileResultData is the output of system/type:reconcile per §7.6.
type ReconcileResultData struct {
	ReconciledType     cbor.RawMessage            `cbor:"reconciled_type"`
	StrategyUsed       string                     `cbor:"strategy_used"`
	Sources            []string                   `cbor:"sources"`
	FieldsDropped      []string                   `cbor:"fields_dropped,omitempty"`
	FieldsMadeOptional []string                   `cbor:"fields_made_optional,omitempty"`
	Incompatibilities  []FieldIncompatibilityData `cbor:"incompatibilities,omitempty"`
}

// ToEntity creates a system/type/reconcile-result entity.
func (d ReconcileResultData) ToEntity() (entity.Entity, error) {
	raw, err := ecf.Encode(d)
	if err != nil {
		return entity.Entity{}, err
	}
	return entity.NewEntity(TypeTypeReconcileResult, cbor.RawMessage(raw))
}

// mustMinCountConstraint builds an inline min-count constraint entity for
// embedding in a FieldSpec.Constraints slot. Panics on encode failure (these
// are compile-time literals registered at init).
func mustMinCountConstraint(n uint64) entity.Entity {
	e, err := ConstraintMinCountData{MinCount: n}.ToEntity()
	if err != nil {
		panic(err)
	}
	return e
}

// mustOneOfStringsConstraint builds an inline one-of constraint entity whose
// values are ECF-encoded strings. Each member's wire form is the canonical
// ECF encoding of the string per ENTITY-CBOR-ENCODING.md §4.2 — required
// because §5.5 mandates ECF byte equality on one-of membership tests.
func mustOneOfStringsConstraint(values ...string) entity.Entity {
	raws := make([]cbor.RawMessage, 0, len(values))
	for _, v := range values {
		raw, err := ecf.Encode(v)
		if err != nil {
			panic(err)
		}
		raws = append(raws, cbor.RawMessage(raw))
	}
	e, err := ConstraintOneOfData{Values: raws}.ToEntity()
	if err != nil {
		panic(err)
	}
	return e
}
