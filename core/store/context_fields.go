package store

import "fmt"

// ContextFieldRegistration describes an extension-contributed field on the
// execution context. Extensions register their fields at peer init time;
// the registry is read-only during operation. See SYSTEM-COMPOSITION section 1.5.
type ContextFieldRegistration struct {
	Name     string // Field name (e.g., "clock")
	TypeName string // Entity type name for the field value (e.g., "system/clock/state")
	Owner    string // Handler pattern or consumer name that owns this field
}

// ContextFieldRegistry tracks extension-contributed context fields.
// Fields are registered at peer init time; the registry is read-only during
// operation. Core field names are reserved and cannot be registered (section 1.5.4).
type ContextFieldRegistry struct {
	fields map[string]ContextFieldRegistration
}

// NewContextFieldRegistry creates an empty context field registry.
func NewContextFieldRegistry() *ContextFieldRegistry {
	return &ContextFieldRegistry{fields: make(map[string]ContextFieldRegistration)}
}

// coreFields are reserved field names that belong to the protocol core and
// cannot be claimed by extensions (SYSTEM-COMPOSITION section 1.5.4).
var coreFields = map[string]bool{
	"chain_id":          true,
	"parent_chain_id":   true,
	"author":            true,
	"caller_capability": true,
	"request_id":        true,
	"bounds":            true,
	"cascade_depth":     true,
	"capability":        true,
	"handler_grant":     true,
	"handler_pattern":   true,
	"operation":         true,
}

// Register adds a context field. Returns error if the name conflicts with a
// core field or an already-registered extension field (section 1.5.1, section 1.5.4).
func (r *ContextFieldRegistry) Register(reg ContextFieldRegistration) error {
	if coreFields[reg.Name] {
		return fmt.Errorf("context field %q conflicts with core field name", reg.Name)
	}
	if existing, exists := r.fields[reg.Name]; exists {
		return fmt.Errorf("context field %q already registered by %s", reg.Name, existing.Owner)
	}
	r.fields[reg.Name] = reg
	return nil
}

// Get returns the registration for a field name, or false if not registered.
func (r *ContextFieldRegistry) Get(name string) (ContextFieldRegistration, bool) {
	reg, ok := r.fields[name]
	return reg, ok
}

// All returns all registered fields.
func (r *ContextFieldRegistry) All() []ContextFieldRegistration {
	result := make([]ContextFieldRegistration, 0, len(r.fields))
	for _, reg := range r.fields {
		result = append(result, reg)
	}
	return result
}
