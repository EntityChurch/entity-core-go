package subscription

import (
	"time"

	"go.entitychurch.org/entity-core-go/core/hash"
)

// EmitEvent fires when the subscription engine matches a state change and
// constructs a notification entity. Distinct from delivery: emit means
// "matcher decided to notify"; delivery means "wire attempt completed."
// Per GUIDE-INSPECTABILITY v1.1 §2.1 #6.
//
// Splitting emit from deliver matters: same conflation in v1.0 hid F-CIMP-2
// (Cohort B) because Python's logs showed "emitted 20, accepted at status
// 200" while actual delivery failures lived a layer up. Two events ⇒
// failure-mode distinguishable in one histogram row.
type EmitEvent struct {
	SubscriptionID   string
	SourceChangeURI  string    // the URI whose change matched the subscription
	NotificationHash hash.Hash // content hash of the constructed notification entity
	Timestamp        time.Time
}

// DeliverEvent fires when the engine attempts to dispatch a notification
// over the wire (or in-process for local delivery). Status carries the
// delivery outcome; ErrorCode is populated on failure. Per
// GUIDE-INSPECTABILITY v1.1 §2.1 #7.
type DeliverEvent struct {
	SubscriptionID   string
	NotificationHash hash.Hash
	DeliverURI       string
	Status           uint   // 2xx success, 4xx/5xx failure; 0 if Deliver returned a transport error
	ErrorCode        string // populated when Deliver returned an error or non-2xx status
	Timestamp        time.Time
}

// EmitHookFn observes emit events. Receives the event by value; MUST be
// fast and MUST NOT retain references that escape the hook's lifetime.
// Out-of-band convention per GUIDE-INSPECTABILITY §4.1: no entity writes
// from inside the hook.
type EmitHookFn func(EmitEvent)

// DeliverHookFn observes deliver events. Same constraints as EmitHookFn.
type DeliverHookFn func(DeliverEvent)

// AddEmitHook registers a named emit-event hook. Fires inline at the
// notification-construction site for every subscription matched by a tree
// change. Hooks fire in registration order; the order is stable across
// engine lifetime. Should be called before the peer starts accepting
// traffic — registration races with active OnTreeChange goroutines are
// not synchronized.
//
// API shape: lives on Engine, not on the peer builder, because the
// subscription engine is in ext/ and the peer builder is in core/. The
// core/ext dependency DAG forbids core importing ext (per
// entity-core-go/CLAUDE.md). Inspect consumers thread the engine via the
// same wiring code that hands the engine to subscription.Register.
func (e *Engine) AddEmitHook(name string, fn EmitHookFn) {
	e.emitHooks = append(e.emitHooks, namedEmitHook{Name: name, Fn: fn})
}

// AddDeliverHook registers a named deliver-event hook. Fires inline at
// the deliveryLoop's e.Deliver call boundary — distinct site from emit
// per v1.1 §2.1 split. Same registration constraints as AddEmitHook.
func (e *Engine) AddDeliverHook(name string, fn DeliverHookFn) {
	e.deliverHooks = append(e.deliverHooks, namedDeliverHook{Name: name, Fn: fn})
}

type namedEmitHook struct {
	Name string
	Fn   EmitHookFn
}

type namedDeliverHook struct {
	Name string
	Fn   DeliverHookFn
}

func (e *Engine) fireEmit(evt EmitEvent) {
	for _, h := range e.emitHooks {
		h.Fn(evt)
	}
}

func (e *Engine) fireDeliver(evt DeliverEvent) {
	for _, h := range e.deliverHooks {
		h.Fn(evt)
	}
}
