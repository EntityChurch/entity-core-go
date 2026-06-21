package types

import (
	"fmt"
	"reflect"
	"sort"
	"sync"
)

// TypeRegistry holds type definitions indexed by spec name,
// with bidirectional Go type ↔ spec name mapping for reflection.
type TypeRegistry struct {
	mu           sync.RWMutex
	definitions  map[string]TypeDefinition
	goTypeToName map[reflect.Type]string
}

// NewTypeRegistry creates an empty type registry.
func NewTypeRegistry() *TypeRegistry {
	return &TypeRegistry{
		definitions:  make(map[string]TypeDefinition),
		goTypeToName: make(map[reflect.Type]string),
	}
}

// RegisterPrimitive registers a name-only type (no fields, no extends).
func (r *TypeRegistry) RegisterPrimitive(name string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.definitions[name] = TypeDefinition{Name: name}
}

// RegisterManual registers a fully specified type definition.
func (r *TypeRegistry) RegisterManual(def TypeDefinition) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.definitions[def.Name] = def
}

// RegisterGoType maps a Go type to a spec name without generating a definition.
// Used for sentinel types like hash.Hash that need to be recognized during
// reflection of other structs.
func (r *TypeRegistry) RegisterGoType(goType reflect.Type, specName string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.goTypeToName[goType] = specName
}

// ReflectType reflects a Go struct to produce a TypeDefinition and registers it.
// The Go type mapping is registered first so self-referential types resolve.
func (r *TypeRegistry) ReflectType(specName string, goType reflect.Type) (TypeDefinition, error) {
	r.mu.Lock()
	defer r.mu.Unlock()

	// Pre-register Go type mapping for self-referential resolution.
	r.goTypeToName[goType] = specName

	// Snapshot known types for the reflection pass.
	known := make(map[reflect.Type]string, len(r.goTypeToName))
	for k, v := range r.goTypeToName {
		known[k] = v
	}

	// Dereference pointer for struct reflection.
	st := goType
	if st.Kind() == reflect.Ptr {
		st = st.Elem()
	}
	if st.Kind() != reflect.Struct {
		return TypeDefinition{}, fmt.Errorf("ReflectType %s: expected struct, got %s", specName, st.Kind())
	}

	fields := make(map[string]FieldSpec)
	for i := 0; i < st.NumField(); i++ {
		sf := st.Field(i)
		if !sf.IsExported() {
			continue
		}

		cborName, omitempty, skip := parseCBORTag(sf)
		if skip {
			continue
		}

		optional := omitempty || sf.Type.Kind() == reflect.Ptr
		ft := sf.Type
		if ft.Kind() == reflect.Ptr {
			ft = ft.Elem()
		}

		fs, err := resolveFieldSpec(ft, optional, known)
		if err != nil {
			return TypeDefinition{}, fmt.Errorf("ReflectType %s, field %q (Go: %s): %w",
				specName, cborName, sf.Name, err)
		}
		fields[cborName] = fs
	}

	def := TypeDefinition{
		Name:   specName,
		Fields: fields,
	}
	r.definitions[specName] = def
	return def, nil
}

// SetExtends sets the extends field on an already-registered type.
func (r *TypeRegistry) SetExtends(specName, extendsName string) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	def, ok := r.definitions[specName]
	if !ok {
		return fmt.Errorf("SetExtends: type %q not registered", specName)
	}
	def.Extends = extendsName
	r.definitions[specName] = def
	return nil
}

// OverrideField replaces a field spec in an already-registered type.
func (r *TypeRegistry) OverrideField(specName, fieldName string, spec FieldSpec) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	def, ok := r.definitions[specName]
	if !ok {
		return fmt.Errorf("OverrideField: type %q not registered", specName)
	}
	if def.Fields == nil {
		def.Fields = make(map[string]FieldSpec)
	}
	def.Fields[fieldName] = spec
	r.definitions[specName] = def
	return nil
}

// AddField adds a new field to an already-registered type.
func (r *TypeRegistry) AddField(specName, fieldName string, spec FieldSpec) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	def, ok := r.definitions[specName]
	if !ok {
		return fmt.Errorf("AddField: type %q not registered", specName)
	}
	if def.Fields == nil {
		def.Fields = make(map[string]FieldSpec)
	}
	if _, exists := def.Fields[fieldName]; exists {
		return fmt.Errorf("AddField: field %q already exists in type %q", fieldName, specName)
	}
	def.Fields[fieldName] = spec
	r.definitions[specName] = def
	return nil
}

// Get retrieves a type definition by spec name.
func (r *TypeRegistry) Get(name string) (TypeDefinition, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	d, ok := r.definitions[name]
	return d, ok
}

// All returns all registered type definitions sorted by name.
func (r *TypeRegistry) All() []TypeDefinition {
	r.mu.RLock()
	defer r.mu.RUnlock()

	defs := make([]TypeDefinition, 0, len(r.definitions))
	for _, d := range r.definitions {
		defs = append(defs, d)
	}
	sort.Slice(defs, func(i, j int) bool {
		return defs[i].Name < defs[j].Name
	})
	return defs
}
