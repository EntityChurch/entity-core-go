package types

import (
	"go.entitychurch.org/entity-core-go/core/ecf"
	"go.entitychurch.org/entity-core-go/core/entity"
	"go.entitychurch.org/entity-core-go/core/hash"

	"github.com/fxamacker/cbor/v2"
)

// Delivery, inbox, and subscription type constants.
const (
	TypeDeliverySpec         = "system/delivery-spec"
	TypeInboxDelivery        = "system/protocol/inbox/delivery"
	TypeInboxNotification    = "system/protocol/inbox/notification"
	TypeSubscription         = "system/subscription"
	TypeSubscriptionRequest  = "system/subscription/request"
	TypeSubscriptionLimits   = "system/subscription/limits"
	TypeSubscriptionCancel   = "system/subscription/cancel"
	TypeSubscriptionRedirect = "system/subscription/redirect"
)

// DeliverySpec is the data for system/delivery-spec.
type DeliverySpec struct {
	URI       string `cbor:"uri"`
	Operation string `cbor:"operation"`
}

// InboxDeliveryData is the data payload for system/protocol/inbox/delivery.
type InboxDeliveryData struct {
	OriginalRequestID string          `cbor:"original_request_id"`
	Status            uint            `cbor:"status"`
	Result            cbor.RawMessage `cbor:"result"`
}

// ToEntity creates a system/protocol/inbox/delivery entity.
func (d InboxDeliveryData) ToEntity() (entity.Entity, error) {
	raw, err := ecf.Encode(d)
	if err != nil {
		return entity.Entity{}, err
	}
	return entity.NewEntity(TypeInboxDelivery, cbor.RawMessage(raw))
}

// InboxDeliveryDataFromEntity decodes an inbox delivery entity's data.
func InboxDeliveryDataFromEntity(e entity.Entity) (InboxDeliveryData, error) {
	var d InboxDeliveryData
	if err := ecf.Decode(e.Data, &d); err != nil {
		return InboxDeliveryData{}, err
	}
	return d, nil
}

// InboxNotificationData is the data payload for system/protocol/inbox/notification.
type InboxNotificationData struct {
	SubscriptionID string    `cbor:"subscription_id"`
	Event          string    `cbor:"event"`
	URI            string    `cbor:"uri"`
	Hash           hash.Hash `cbor:"hash,omitzero"`
	PreviousHash   hash.Hash `cbor:"previous_hash,omitzero"`
}

// ToEntity creates a system/protocol/inbox/notification entity.
func (d InboxNotificationData) ToEntity() (entity.Entity, error) {
	raw, err := ecf.Encode(d)
	if err != nil {
		return entity.Entity{}, err
	}
	return entity.NewEntity(TypeInboxNotification, cbor.RawMessage(raw))
}

// InboxNotificationDataFromEntity decodes an inbox notification entity's data.
func InboxNotificationDataFromEntity(e entity.Entity) (InboxNotificationData, error) {
	var d InboxNotificationData
	if err := ecf.Decode(e.Data, &d); err != nil {
		return InboxNotificationData{}, err
	}
	return d, nil
}

// SubscriptionData is the data payload for system/subscription.
type SubscriptionData struct {
	SubscriptionID     string                  `cbor:"subscription_id"`
	Pattern            string                  `cbor:"pattern"` // qualified path pattern, e.g. "{peerID}/data/*"
	Events             []string                `cbor:"events"`
	DeliverURI         string                  `cbor:"deliver_uri"`
	DeliverOperation   string                  `cbor:"deliver_operation"`
	SubscriberIdentity hash.Hash               `cbor:"subscriber_identity"`
	DeliverToken       hash.Hash               `cbor:"deliver_token"`
	CreatedAt          uint64                  `cbor:"created_at"`
	Limits             *SubscriptionLimitsData `cbor:"limits,omitempty"`
	// IncludePayload bundles the changed entity into the delivery envelope's
	// `included` map (EXTENSION-SUBSCRIPTION v3.12/v3.14, §2.1). Persisted
	// from the subscribe request; engine reads it at delivery (§4.2). Default
	// false — existing subscribers see the lean hashes-only shape.
	IncludePayload bool `cbor:"include_payload,omitempty"`
}

// ToEntity creates a system/subscription entity.
func (d SubscriptionData) ToEntity() (entity.Entity, error) {
	raw, err := ecf.Encode(d)
	if err != nil {
		return entity.Entity{}, err
	}
	return entity.NewEntity(TypeSubscription, cbor.RawMessage(raw))
}

// SubscriptionDataFromEntity decodes a subscription entity's data.
func SubscriptionDataFromEntity(e entity.Entity) (SubscriptionData, error) {
	var d SubscriptionData
	if err := ecf.Decode(e.Data, &d); err != nil {
		return SubscriptionData{}, err
	}
	return d, nil
}

// SubscriptionRequestData is the data payload for system/subscription/request.
type SubscriptionRequestData struct {
	Events       []string                `cbor:"events,omitempty"`
	DeliverTo    DeliverySpec            `cbor:"deliver_to"`
	DeliverToken hash.Hash               `cbor:"deliver_token"`
	Limits       *SubscriptionLimitsData `cbor:"limits,omitempty"`
	// IncludePayload opts in to entity bundling in the delivery envelope's
	// `included` map (EXTENSION-SUBSCRIPTION v3.12/v3.13/v3.14, §2.3). When
	// true, the subscribe handler MUST verify the caller has tree:get on the
	// resource (else 403 payload_unauthorized — v3.13 security pin) and
	// persists the flag onto the subscription. Default false.
	IncludePayload bool `cbor:"include_payload,omitempty"`
}

// ToEntity creates a system/subscription/request entity.
func (d SubscriptionRequestData) ToEntity() (entity.Entity, error) {
	raw, err := ecf.Encode(d)
	if err != nil {
		return entity.Entity{}, err
	}
	return entity.NewEntity(TypeSubscriptionRequest, cbor.RawMessage(raw))
}

// SubscriptionRequestDataFromEntity decodes a subscription request entity's data.
func SubscriptionRequestDataFromEntity(e entity.Entity) (SubscriptionRequestData, error) {
	var d SubscriptionRequestData
	if err := ecf.Decode(e.Data, &d); err != nil {
		return SubscriptionRequestData{}, err
	}
	return d, nil
}

// SubscriptionLimitsData is the data payload for system/subscription/limits.
type SubscriptionLimitsData struct {
	MaxEvents          *uint64 `cbor:"max_events,omitempty"`
	MaxDurationMs      *uint64 `cbor:"max_duration_ms,omitempty"`
	RateLimit          *uint64 `cbor:"rate_limit,omitempty"`
	NotificationBudget *uint64 `cbor:"notification_budget,omitempty"`
}

// SubscriptionCancelData is the data payload for system/subscription/cancel.
type SubscriptionCancelData struct {
	SubscriptionID string `cbor:"subscription_id"`
}

// ToEntity creates a system/subscription/cancel entity.
func (d SubscriptionCancelData) ToEntity() (entity.Entity, error) {
	raw, err := ecf.Encode(d)
	if err != nil {
		return entity.Entity{}, err
	}
	return entity.NewEntity(TypeSubscriptionCancel, cbor.RawMessage(raw))
}

// SubscriptionCancelDataFromEntity decodes a subscription cancel entity's data.
func SubscriptionCancelDataFromEntity(e entity.Entity) (SubscriptionCancelData, error) {
	var d SubscriptionCancelData
	if err := ecf.Decode(e.Data, &d); err != nil {
		return SubscriptionCancelData{}, err
	}
	return d, nil
}

// SubscriptionRedirectData is the data payload for system/subscription/redirect.
// Returned with status 303 when a peer is at subscription capacity for a prefix.
type SubscriptionRedirectData struct {
	Reason       string      `cbor:"reason"`                 // "at_capacity"
	Prefix       string      `cbor:"prefix"`                 // The prefix at capacity
	Alternatives []hash.Hash `cbor:"alternatives,omitempty"` // Identity hashes of current subscribers
	Capacity     *uint64     `cbor:"capacity,omitempty"`     // Configured limit
}

// ToEntity creates a system/subscription/redirect entity.
func (d SubscriptionRedirectData) ToEntity() (entity.Entity, error) {
	raw, err := ecf.Encode(d)
	if err != nil {
		return entity.Entity{}, err
	}
	return entity.NewEntity(TypeSubscriptionRedirect, cbor.RawMessage(raw))
}

// SubscriptionRedirectDataFromEntity decodes a subscription redirect entity's data.
func SubscriptionRedirectDataFromEntity(e entity.Entity) (SubscriptionRedirectData, error) {
	var d SubscriptionRedirectData
	if err := ecf.Decode(e.Data, &d); err != nil {
		return SubscriptionRedirectData{}, err
	}
	return d, nil
}
