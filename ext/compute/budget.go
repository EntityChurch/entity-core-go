package compute

// Recommended limits per EXTENSION-COMPUTE §9.3.
const (
	DefaultMaxOps          = 100000
	DefaultMaxDepth        = 1024
	DefaultMaxCascadeDepth = 16
)

// Budget tracks remaining evaluation resources.
type Budget struct {
	Operations int
	Depth      int
}

// NewBudget creates a budget with the given limits.
func NewBudget(ops, depth int) *Budget {
	return &Budget{Operations: ops, Depth: depth}
}

// DefaultBudget creates a budget with recommended defaults.
func DefaultBudget() *Budget {
	return &Budget{Operations: DefaultMaxOps, Depth: DefaultMaxDepth}
}
