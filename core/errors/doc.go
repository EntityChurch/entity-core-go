// Package errors defines sentinel errors and error types for entity-core-go.
//
// This is a leaf package with no internal dependencies. All other packages
// import from here to use shared error values with errors.Is and errors.As.
//
// Sentinel errors follow the pattern:
//
//	var ErrNotFound = errors.New("entity not found")
//
// Checked with:
//
//	if errors.Is(err, errors.ErrNotFound) { ... }
package errors
