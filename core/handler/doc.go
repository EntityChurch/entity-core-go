// Package handler defines the Handler interface, handler registry, request
// context, and dispatch logic.
//
// Handlers are registered at path patterns and process EXECUTE requests.
// The registry matches incoming request paths to registered handlers.
// HandlerContext provides the execution environment (storage access,
// capability checking, entity emission).
//
// Dependencies: entity, hash, capability, store
package handler
