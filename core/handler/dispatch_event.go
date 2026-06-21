package handler

import (
	"time"

	"go.entitychurch.org/entity-core-go/core/hash"
)

// DispatchPhase distinguishes the two firings per dispatch.
type DispatchPhase int

const (
	// DispatchEntry fires before the handler body is invoked. ResponseStatus
	// and ResponseHash are zero at entry.
	DispatchEntry DispatchPhase = iota
	// DispatchExit fires after the handler body returns, before the response
	// envelope is built. ResponseStatus and ResponseHash carry the outcome.
	DispatchExit
)

// DispatchEvent describes one dispatch boundary crossing — entry into a
// handler body, or exit from it. Fires at the dispatcher↔handler boundary
// per GUIDE-INSPECTABILITY v1.1 §2.1 #3.
//
// The hook fn receives this by value; it MUST NOT retain pointers to mutable
// handler-owned objects past return (see review §6.4). To inspect the
// response body, use ResponseHash and read via the content store.
type DispatchEvent struct {
	Phase      DispatchPhase
	TargetURI  string    // qualified handler URI (entity://{peer}/{handler-path})
	Operation  string    // op name from the EXECUTE request
	ParamsHash hash.Hash // content hash of the params entity
	RequestID  string
	Timestamp  time.Time

	// Exit-phase only. Zero at entry.
	ResponseStatus uint      // 2xx/4xx/5xx from the handler response
	ResponseHash   hash.Hash // content hash of the response entity (per review §7.1 — load-bearing)
}

// DispatchEventFn observes a dispatch event. Receives the event by value;
// MUST NOT block the calling goroutine for any meaningful duration (fires on
// the dispatch hot path) and MUST NOT retain references to mutable handler
// state past return.
type DispatchEventFn func(DispatchEvent)

// NamedDispatchHook pairs a hook fn with a stable identifier used in
// debug surfaces and (future) telemetry attribution.
type NamedDispatchHook struct {
	Name string
	Fn   DispatchEventFn
}
