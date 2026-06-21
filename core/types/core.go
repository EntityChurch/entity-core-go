package types

import (
	"reflect"

	"go.entitychurch.org/entity-core-go/core/entity"
	"go.entitychurch.org/entity-core-go/core/hash"
)

// RegisterCoreTypes registers all non-handler-specific types
// into the given registry. Handler-specific types (hello, authenticate, tree/*)
// are registered by their respective handlers via TypeProvider.
func RegisterCoreTypes(r *TypeRegistry) {
	// Phase 0: 8 primitives.
	for _, name := range []string{
		"primitive/string",
		"primitive/bytes",
		"primitive/uint",
		"primitive/int",
		"primitive/float",
		"primitive/bool",
		"primitive/null",
		"primitive/any",
	} {
		r.RegisterPrimitive(name)
	}

	// Phase 1: Sentinel Go type mapping (no definition generated).
	// hash.Hash is recognized during reflection of other structs.
	r.RegisterGoType(reflect.TypeOf(hash.Hash{}), "system/hash")
	// DeliverySpec is recognized during reflection of ExecuteData and SubscriptionRequestData.
	r.RegisterGoType(reflect.TypeOf(DeliverySpec{}), "system/delivery-spec")
	// ContinuationTransformOpData is recognized during reflection of ContinuationTransformData.
	r.RegisterGoType(reflect.TypeOf(ContinuationTransformOpData{}), "system/continuation/transform-op")
	// ContinuationTransformData is recognized during reflection of ContinuationData.
	r.RegisterGoType(reflect.TypeOf(ContinuationTransformData{}), "system/continuation/transform")
	// QueryFieldPredicateData is recognized during reflection of QueryExpressionData.
	r.RegisterGoType(reflect.TypeOf(QueryFieldPredicateData{}), TypeQueryFieldPredicate)
	// Granter is a polymorphic sum (system/hash | system/capability/multi-granter)
	// per PROPOSAL-MULTISIG-CORE-PRIMITIVE M1. Register as a sentinel so
	// reflection over CapabilityTokenData succeeds; the granter field's true
	// spec (a union_of) is set via OverrideField in Phase 6.
	r.RegisterGoType(reflect.TypeOf(Granter{}), "system/hash")
	// entity.Entity is recognized during reflection of FieldSpec.Constraints
	// (EXTENSION-TYPE v1.1 §3.3 — array_of core/entity).
	r.RegisterGoType(reflect.TypeOf(entity.Entity{}), TypeCoreEntity)

	// Phase 2: Manual types (not derivable from Go structs).
	r.RegisterManual(TypeDefinition{
		Name:    "system/hash",
		Extends: "primitive/bytes",
		Fields: map[string]FieldSpec{
			"format_code": {TypeRef: "primitive/uint", ByteSize: uintPtr(1)},
			"digest":      {TypeRef: "primitive/bytes"},
		},
		Layout: []string{"format_code", "digest"},
	})

	// Bootstrap type: entity — the abstract structural root from which every
	// entity type specializes. content_hash is derived from {type, data} per
	// ENTITY-CBOR-ENCODING §4.2, not declared as a field. The bare name
	// reflects entity's primordial position outside the four-namespace
	// structure (TYPE-SYSTEM §2.7.1).
	r.RegisterManual(TypeDefinition{
		Name: "entity",
		Fields: map[string]FieldSpec{
			"type": {TypeRef: "primitive/string"},
			"data": {TypeRef: "primitive/any"},
		},
	})

	// core/entity — the materialized form an entity takes once a content
	// hash has been resolved into a slot. Used as a type_ref marker in field
	// specs to require "this slot holds a real, identity-bearing entity, not
	// raw CBOR." Lives in core/* alongside core/envelope (TYPE-SYSTEM §8.1,
	// §2.7.1; PROPOSAL-TYPE-NAMESPACE-CONVENTIONS).
	r.RegisterManual(TypeDefinition{
		Name: TypeCoreEntity,
		Fields: map[string]FieldSpec{
			"type":         {TypeRef: "primitive/string"},
			"data":         {TypeRef: "primitive/any"},
			"content_hash": {TypeRef: "system/hash"},
		},
	})

	r.RegisterManual(TypeDefinition{
		Name: "core/envelope",
		Fields: map[string]FieldSpec{
			"root":     {TypeRef: TypeCoreEntity},
			"included": {MapOf: &FieldSpec{TypeRef: TypeCoreEntity}, KeyType: "system/hash", Optional: true},
		},
	})

	r.RegisterManual(TypeDefinition{
		Name:    "system/envelope",
		Extends: "core/envelope",
	})

	r.RegisterManual(TypeDefinition{
		Name:    "system/protocol/envelope",
		Extends: "core/envelope",
	})

	r.RegisterManual(TypeDefinition{
		Name: "system/delivery-spec",
		Fields: map[string]FieldSpec{
			"uri":       {TypeRef: "primitive/string"},
			"operation": {TypeRef: "primitive/string"},
		},
	})

	r.RegisterManual(TypeDefinition{
		Name: "system/resource-limits",
		Fields: map[string]FieldSpec{
			"max_budget":         {TypeRef: "primitive/uint", Optional: true},
			"max_ttl":            {TypeRef: "primitive/uint", Optional: true},
			"max_visited_length": {TypeRef: "primitive/uint", Optional: true},
		},
	})

	r.RegisterManual(TypeDefinition{
		Name: "system/tree/listing-entry",
		Fields: map[string]FieldSpec{
			"hash":         {TypeRef: "system/hash", Optional: true},
			"has_children": {TypeRef: "primitive/bool"},
		},
	})

	r.RegisterManual(TypeDefinition{Name: "system/tree/path", Extends: "primitive/string"})
	r.RegisterManual(TypeDefinition{Name: "system/type/name", Extends: "primitive/string"})
	r.RegisterManual(TypeDefinition{Name: "system/peer-id", Extends: "primitive/string"})

	// system/deletion-marker — canonical marker entity for intentional deletion.
	// Empty-field schema; ECF-encoded data is the CBOR empty map (0xa0). Same
	// content hash on every peer (see CanonicalDeletionMarkerHash in
	// deletion_marker.go). Per PROPOSAL-DELETION-MARKERS.md A.8 Amendment 1.
	r.RegisterManual(TypeDefinition{
		Name:   TypeDeletionMarker,
		Fields: map[string]FieldSpec{},
	})

	// Phase 3: Meta-types (order matters for self-reference).
	// FieldSpec contains *FieldSpec → self-referential.
	r.ReflectType("system/type/field-spec", reflect.TypeOf(FieldSpec{}))
	r.ReflectType("system/type", reflect.TypeOf(TypeDefinition{}))

	// Phase 4: Leaf structs (no nested struct dependencies beyond hash.Hash).
	// Durability types first — referenced as pointer fields by ExecuteData
	// (durability_request) and ExecuteResponseData (durability), so their Go
	// type ↔ spec-name mapping must exist before those reflect
	// (EXTENSION-DURABILITY §2 / §5 — exploratory extension).
	r.ReflectType(TypeDurabilityRequest, reflect.TypeOf(DurabilityRequestData{}))
	r.ReflectType(TypeDurabilityResult, reflect.TypeOf(DurabilityResultData{}))
	// durability-result.handle is a tree path (see DurabilityResultData.Handle
	// docstring + EXTENSION-DURABILITY §3). Bind to system/tree/path so the
	// type-def matches Python's reflection (Python ae8228f).
	r.OverrideField(TypeDurabilityResult, "handle", FieldSpec{TypeRef: "system/tree/path", Optional: true})
	r.ReflectType(TypeDurabilityAdvertisement, reflect.TypeOf(DurabilityAdvertisementData{}))
	r.ReflectType("system/peer", reflect.TypeOf(PeerData{}))
	r.ReflectType(TypePeerSession, reflect.TypeOf(SessionData{}))
	r.ReflectType("system/signature", reflect.TypeOf(SignatureData{}))
	// PROPOSAL-PEER-MANIFEST-STATIC-HANDSHAKE §4 — standalone signed-root
	// pointer (NORMATIVE-LOCKED). Layer above system/peer; signature
	// carriage via invariant-pointer at system/signature/{published_root_hash_hex}.
	r.ReflectType(TypePeerPublishedRoot, reflect.TypeOf(PublishedRootData{}))
	// published-root.peer_id is the Base58 peer-id per V7 §1.5 (the
	// same Ruling-1 pattern as REGISTRY/DISCOVERY/NETWORK surfaces).
	// Cross-impl alignment: Rust + Python already bind this field to
	// system/peer-id; Go was the outlier reflecting it as primitive/string.
	r.OverrideField(TypePeerPublishedRoot, "peer_id", FieldSpec{TypeRef: "system/peer-id"})

	// EXTENSION-REGISTRY v1.0 — entity types + handler request/result types.
	// Inner shape types (ResolverChainEntry / PinnedEntry / DispatchEntry +
	// LocalNameListEntry) reflect-register first so the outer types referencing
	// them resolve cleanly during reflection.
	r.ReflectType(TypeRegistryResolverChainEntry, reflect.TypeOf(ResolverChainEntry{}))
	r.ReflectType(TypeRegistryPinnedEntry, reflect.TypeOf(PinnedEntry{}))
	r.ReflectType(TypeRegistryDispatchEntry, reflect.TypeOf(DispatchEntry{}))
	r.ReflectType(TypeRegistryLocalNameListEntry, reflect.TypeOf(LocalNameListEntry{}))
	r.ReflectType(TypeRegistryBinding, reflect.TypeOf(BindingData{}))
	r.ReflectType(TypeRegistryRevocation, reflect.TypeOf(RevocationData{}))
	r.ReflectType(TypeRegistryResolverConfig, reflect.TypeOf(ResolverConfigData{}))
	r.ReflectType(TypeRegistryLocalNameConfig, reflect.TypeOf(LocalNameConfigData{}))
	r.ReflectType(TypeRegistryResolutionLog, reflect.TypeOf(ResolutionLogData{}))
	r.ReflectType(TypeRegistryResolveRequest, reflect.TypeOf(ResolveRequestData{}))
	r.ReflectType(TypeRegistryResolveResult, reflect.TypeOf(ResolveResultData{}))
	r.ReflectType(TypeRegistryInvalidateCacheRequest, reflect.TypeOf(InvalidateCacheRequestData{}))
	r.ReflectType(TypeRegistryLocalNameBindRequest, reflect.TypeOf(LocalNameBindRequestData{}))
	r.ReflectType(TypeRegistryLocalNameBindResult, reflect.TypeOf(LocalNameBindResultData{}))
	r.ReflectType(TypeRegistryLocalNameUnbindRequest, reflect.TypeOf(LocalNameUnbindRequestData{}))
	r.ReflectType(TypeRegistryLocalNameListRequest, reflect.TypeOf(LocalNameListRequestData{}))
	r.ReflectType(TypeRegistryLocalNameListResult, reflect.TypeOf(LocalNameListResultData{}))
	r.ReflectType(TypeRegistryLocalNameUpdateTransports, reflect.TypeOf(LocalNameUpdateTransportsRequestData{}))

	// EXTENSION-REGISTRY §6a.9 — peer-issued live-registration surface.
	r.ReflectType(TypeRegistryRegisterRequest, reflect.TypeOf(RegistryRegisterRequestData{}))
	r.ReflectType(TypeRegistryIssuerPolicy, reflect.TypeOf(IssuerPolicyData{}))
	r.ReflectType(TypeRegistryRevokeRequest, reflect.TypeOf(RegistryRevokeRequestData{}))
	r.ReflectType(TypeRegistryRenewRequest, reflect.TypeOf(RegistryRenewRequestData{}))

	// `binding.target_peer_id` is the Base58 peer-id per V7 §1.5 — the
	// semantic system/peer-id type, NOT the bare primitive/string the
	// reflected struct field renders to. Pin all surfaces that carry it.
	r.OverrideField(TypeRegistryBinding, "target_peer_id", FieldSpec{TypeRef: "system/peer-id"})
	r.OverrideField(TypeRegistryPinnedEntry, "target_peer_id", FieldSpec{TypeRef: "system/peer-id"})
	r.OverrideField(TypeRegistryResolveResult, "peer_id", FieldSpec{TypeRef: "system/peer-id", Optional: true})
	r.OverrideField(TypeRegistryLocalNameBindRequest, "target_peer_id", FieldSpec{TypeRef: "system/peer-id"})
	r.OverrideField(TypeRegistryLocalNameListEntry, "target_peer_id", FieldSpec{TypeRef: "system/peer-id"})
	r.OverrideField(TypeRegistryRegisterRequest, "target_peer_id", FieldSpec{TypeRef: "system/peer-id"})
	// §6a.9.1 issuer-policy `allowlist` is a list of target_peer_ids per the
	// spec data block, not bare strings. Matches Rust + Python.
	r.OverrideField(TypeRegistryIssuerPolicy, "allowlist",
		FieldSpec{ArrayOf: &FieldSpec{TypeRef: "system/peer-id"}, Optional: true})
	// §6a.9.1 v1.2 ruling: renew carries nonce + issued_at for replay
	// defense, enforced by the handler. Mark them schema-optional to match
	// Rust + Python's permissive-schema-strict-handler convention so the
	// type_system §12.3 cross-impl shape gate converges.
	r.OverrideField(TypeRegistryRenewRequest, "nonce",
		FieldSpec{TypeRef: "primitive/bytes", Optional: true})
	r.OverrideField(TypeRegistryRenewRequest, "issued_at",
		FieldSpec{TypeRef: "primitive/uint", Optional: true})

	// EXTENSION-DISCOVERY v1.0 — entity types per §2.1, §2.2.1, §3 ScanResult.
	// Base58 peer_id surfaces (candidate.peer_id is nullable; identity-claim.
	// peer_id is always present) get the system/peer-id override since the
	// reflected `PeerID string` field renders to primitive/string. Same
	// Ruling-1 pattern as REGISTRY (target_peer_id) + NETWORK transport
	// profiles (peer_id).
	r.ReflectType(TypeDiscoveryCandidate, reflect.TypeOf(CandidateData{}))
	r.ReflectType(TypeDiscoveryDecision, reflect.TypeOf(DecisionData{}))
	r.ReflectType(TypeDiscoveryIdentityClaim, reflect.TypeOf(IdentityClaimData{}))
	r.ReflectType(TypeDiscoveryScanResult, reflect.TypeOf(ScanResultData{}))
	r.ReflectType(TypeDiscoveryScanRequest, reflect.TypeOf(ScanRequestData{}))
	r.ReflectType(TypeDiscoveryAnnounceRequest, reflect.TypeOf(AnnounceRequestData{}))
	r.ReflectType(TypeDiscoveryAnnounceStopRequest, reflect.TypeOf(AnnounceStopRequestData{}))
	r.OverrideField(TypeDiscoveryCandidate, "peer_id", FieldSpec{TypeRef: "system/peer-id", Optional: true})
	r.OverrideField(TypeDiscoveryIdentityClaim, "peer_id", FieldSpec{TypeRef: "system/peer-id"})

	// EXTENSION-RELAY v1.0 — entity types per §3.1, §3.2, §4.1, §4.2 (post-
	// Go-review at arch 54e5373 + 15b30d0). Base58 peer_id surfaces
	// (destination/next_hop/put_by) get the system/peer-id override since
	// reflection of `string` renders to primitive/string. Same Ruling-1
	// pattern as REGISTRY (target_peer_id) + DISCOVERY (peer_id).
	r.ReflectType(TypeRelayForwardRequest, reflect.TypeOf(ForwardRequestData{}))
	r.ReflectType(TypeRelayStoreEntry, reflect.TypeOf(StoreEntryData{}))
	// AdvertiseLimits MUST register before AdvertiseData — the latter
	// references it via reflection (same pattern as path-scope/id-scope under
	// capability/grant).
	r.ReflectType(TypeRelayAdvertiseLimits, reflect.TypeOf(AdvertiseLimits{}))
	r.ReflectType(TypeRelayAdvertise, reflect.TypeOf(AdvertiseData{}))
	r.ReflectType(TypeRelayForwardResult, reflect.TypeOf(ForwardResultData{}))
	r.ReflectType(TypeRelayPutResult, reflect.TypeOf(PutResultData{}))
	r.ReflectType(TypeRelayPollRequest, reflect.TypeOf(PollRequestData{}))
	r.ReflectType(TypeRelayPollResult, reflect.TypeOf(PollResultData{}))
	r.OverrideField(TypeRelayForwardRequest, "destination", FieldSpec{TypeRef: "system/peer-id"})
	r.OverrideField(TypeRelayForwardRequest, "next_hop", FieldSpec{TypeRef: "system/peer-id", Optional: true})
	r.OverrideField(TypeRelayStoreEntry, "put_by", FieldSpec{TypeRef: "system/peer-id"})
	r.OverrideField(TypeRelayForwardResult, "next_hop", FieldSpec{TypeRef: "system/peer-id", Optional: true})

	// EXTENSION-ROUTE v1 — storage plane for the routing table
	// (PROPOSAL-EXTENSION-ROUTE.md). Match is a peer-id-or-`*` sum, so it
	// stays primitive/string; Via is a peer-id when present.
	r.ReflectType(TypeRoute, reflect.TypeOf(RouteData{}))
	r.OverrideField(TypeRoute, "via", FieldSpec{TypeRef: "system/peer-id", Optional: true})

	// §3.5 system/peer/inbox-relay — MX-equivalent declaration (cohort
	// R6/R7 fold at arch faf3fa9). InboxRelayEntry MUST register before
	// InboxRelayData (latter references it via reflection).
	r.ReflectType(TypeInboxRelayEntry, reflect.TypeOf(InboxRelayEntry{}))
	r.ReflectType(TypePeerInboxRelay, reflect.TypeOf(InboxRelayData{}))
	r.OverrideField(TypeInboxRelayEntry, "relay", FieldSpec{TypeRef: "system/peer-id"})

	r.ReflectType("system/protocol/error", reflect.TypeOf(ErrorData{}))
	r.ReflectType("system/protocol/execute/response", reflect.TypeOf(ExecuteResponseData{}))
	r.ReflectType("system/capability/grant", reflect.TypeOf(CapabilityGrantData{}))
	r.ReflectType("system/handler/operation-spec", reflect.TypeOf(HandlerOperationSpec{}))
	r.ReflectType("system/capability/path-scope", reflect.TypeOf(CapabilityScope{}))
	r.ReflectType("system/capability/id-scope", reflect.TypeOf(CapabilityScope{}))
	r.ReflectType("system/capability/grant-entry", reflect.TypeOf(GrantEntry{}))
	r.ReflectType("system/capability/delegation-caveats", reflect.TypeOf(DelegationCaveats{}))
	r.ReflectType("system/capability/revocation", reflect.TypeOf(CapabilityRevocationData{}))
	r.ReflectType(TypeCapRevokeRequest, reflect.TypeOf(CapabilityRevokeRequestData{}))
	r.ReflectType(TypeCapDelegateRequest, reflect.TypeOf(CapabilityDelegateRequestData{}))
	r.ReflectType(TypeCapPolicyEntry, reflect.TypeOf(CapabilityPolicyEntryData{}))
	r.ReflectType("system/bounds", reflect.TypeOf(BoundsData{}))
	r.ReflectType("system/type/validate-request", reflect.TypeOf(ValidateRequestData{}))
	// Violation must register before validate-result because
	// validate-result.violations is array_of system/type/violation.
	r.ReflectType(TypeTypeViolation, reflect.TypeOf(Violation{}))
	r.ReflectType("system/type/validate-result", reflect.TypeOf(ValidateResultData{}))

	// EXTENSION-TYPE v1.1 §4 standard constraint types.
	r.ReflectType(TypeConstraintMin, reflect.TypeOf(ConstraintMinData{}))
	r.ReflectType(TypeConstraintMax, reflect.TypeOf(ConstraintMaxData{}))
	r.ReflectType(TypeConstraintMinLength, reflect.TypeOf(ConstraintMinLengthData{}))
	r.ReflectType(TypeConstraintMaxLength, reflect.TypeOf(ConstraintMaxLengthData{}))
	r.ReflectType(TypeConstraintMinCount, reflect.TypeOf(ConstraintMinCountData{}))
	r.ReflectType(TypeConstraintMaxCount, reflect.TypeOf(ConstraintMaxCountData{}))
	r.ReflectType(TypeConstraintPattern, reflect.TypeOf(ConstraintPatternData{}))
	r.ReflectType(TypeConstraintOneOf, reflect.TypeOf(ConstraintOneOfData{}))
	r.ReflectType(TypeConstraintNotOneOf, reflect.TypeOf(ConstraintNotOneOfData{}))
	r.ReflectType(TypeConstraintFormat, reflect.TypeOf(ConstraintFormatData{}))
	r.ReflectType(TypeConstraintTypePattern, reflect.TypeOf(ConstraintTypePatternData{}))

	// EXTENSION-TYPE v1.1 §5.2 / §5.3 — standard constraint handler envelope.
	r.ReflectType(TypeConstraintValidateReq, reflect.TypeOf(ConstraintValidateRequestData{}))
	r.ReflectType(TypeConstraintValidateResult, reflect.TypeOf(ConstraintValidateResultData{}))

	// EXTENSION-TYPE v1.1 §7 / §8 — type-handler analysis-op types.
	r.ReflectType(TypeTypeFieldComparison, reflect.TypeOf(FieldComparisonData{}))
	r.ReflectType(TypeTypeFieldIncompatibility, reflect.TypeOf(FieldIncompatibilityData{}))
	r.ReflectType(TypeTypeCompareRequest, reflect.TypeOf(CompareRequestData{}))
	r.ReflectType(TypeTypeCompareResult, reflect.TypeOf(CompareResultData{}))
	r.ReflectType(TypeTypeCompatibleRequest, reflect.TypeOf(CompatibleRequestData{}))
	r.ReflectType(TypeTypeCompatibilityReport, reflect.TypeOf(CompatibilityReportData{}))
	r.ReflectType(TypeTypeConvergeRequest, reflect.TypeOf(ConvergeRequestData{}))
	r.ReflectType(TypeTypeAdoptRequest, reflect.TypeOf(AdoptRequestData{}))
	r.ReflectType(TypeTypeReconcileRequest, reflect.TypeOf(ReconcileRequestData{}))
	r.ReflectType(TypeTypeReconcileResult, reflect.TypeOf(ReconcileResultData{}))

	// EXTENSION-TYPE v1.1 §7.3/§7.4/§7.6/§8.5: spec-defined built-in types
	// carry inline field constraints. Reflection produces the structural
	// shape but not the constraints; restore them here so Go's
	// advertisement is faithful to the spec (arch ruling Q4 / v7.78
	// erratum candidate — spec-defined built-ins SHOULD reflect with their
	// spec constraints; user-defined types remain divergence-tolerant per
	// §1.5 Invariant 5).
	r.OverrideField(TypeTypeCompatibleRequest, "direction", FieldSpec{
		TypeRef: "primitive/string",
		Constraints: []entity.Entity{
			mustOneOfStringsConstraint(DirectionForward, DirectionBackward, DirectionBidirectional),
		},
	})
	r.OverrideField(TypeTypeCompatibilityReport, "level", FieldSpec{
		TypeRef: "primitive/string",
		Constraints: []entity.Entity{
			mustOneOfStringsConstraint(
				CompatibilityFullyCompatible,
				CompatibilityForwardOnly,
				CompatibilityBackwardOnly,
				CompatibilityPartiallyCompatible,
				CompatibilityIncompatible,
			),
		},
	})
	r.OverrideField(TypeTypeConvergeRequest, "type_paths", FieldSpec{
		ArrayOf:     &FieldSpec{TypeRef: "system/tree/path"},
		Constraints: []entity.Entity{mustMinCountConstraint(2)},
	})
	r.OverrideField(TypeTypeReconcileRequest, "type_paths", FieldSpec{
		ArrayOf:     &FieldSpec{TypeRef: "system/tree/path"},
		Constraints: []entity.Entity{mustMinCountConstraint(2)},
	})
	r.OverrideField(TypeTypeReconcileRequest, "strategy", FieldSpec{
		TypeRef: "primitive/string",
		Constraints: []entity.Entity{
			mustOneOfStringsConstraint(ReconcileIntersect, ReconcileUnion, ReconcilePrefer),
		},
	})
	r.OverrideField(TypeTypeViolation, "kind", FieldSpec{
		TypeRef: "primitive/string",
		Constraints: []entity.Entity{
			mustOneOfStringsConstraint(ViolationKindStructural, ViolationKindConstraint, ViolationKindUnknownConstraint),
		},
	})

	// Phase 5: Structs with nested struct refs (depend on Phase 4 registrations).
	r.ReflectType("system/capability/token", reflect.TypeOf(CapabilityTokenData{}))
	r.ReflectType("system/capability/request", reflect.TypeOf(CapabilityRequestData{}))
	r.ReflectType("system/handler", reflect.TypeOf(HandlerData{}))
	r.ReflectType("system/handler/manifest", reflect.TypeOf(HandlerManifestData{}))
	r.ReflectType("system/protocol/resource-target", reflect.TypeOf(ResourceTarget{}))
	r.ReflectType("system/protocol/execute", reflect.TypeOf(ExecuteData{}))
	r.ReflectType("system/handler/register-request", reflect.TypeOf(RegisterRequestData{}))
	r.ReflectType("system/handler/register-result", reflect.TypeOf(RegisterResultData{}))

	// Phase 5b: Inbox and subscription types.
	// SubscriptionLimitsData must be reflected before types that embed it.
	r.ReflectType(TypeInboxDelivery, reflect.TypeOf(InboxDeliveryData{}))
	r.ReflectType(TypeInboxNotification, reflect.TypeOf(InboxNotificationData{}))
	r.ReflectType(TypeSubscriptionLimits, reflect.TypeOf(SubscriptionLimitsData{}))
	r.ReflectType(TypeSubscription, reflect.TypeOf(SubscriptionData{}))
	r.ReflectType(TypeSubscriptionRequest, reflect.TypeOf(SubscriptionRequestData{}))
	r.ReflectType(TypeSubscriptionCancel, reflect.TypeOf(SubscriptionCancelData{}))
	r.ReflectType(TypeSubscriptionRedirect, reflect.TypeOf(SubscriptionRedirectData{}))

	// Phase 5c: Continuation types.
	// transform-op first (referenced by ContinuationTransformData), then
	// transform (referenced by ContinuationData), then the continuations.
	r.ReflectType(TypeContinuationTransformOp, reflect.TypeOf(ContinuationTransformOpData{}))
	r.ReflectType(TypeContinuationTransform, reflect.TypeOf(ContinuationTransformData{}))
	r.ReflectType(TypeContinuation, reflect.TypeOf(ContinuationData{}))
	r.ReflectType(TypeContinuationJoin, reflect.TypeOf(ContinuationJoinData{}))
	r.ReflectType(TypeContinuationSuspended, reflect.TypeOf(ContinuationSuspendedData{}))
	r.ReflectType(TypeContinuationResumeRequest, reflect.TypeOf(ContinuationResumeRequestData{}))
	r.ReflectType(TypeContinuationAbandonRequest, reflect.TypeOf(ContinuationAbandonRequestData{}))
	r.ReflectType(TypeContinuationAdvanceRequest, reflect.TypeOf(ContinuationAdvanceRequestData{}))
	r.ReflectType(TypeContinuationInstallResult, reflect.TypeOf(ContinuationInstallResultData{}))

	// Phase 5d: Clock types.
	// Leaf clock types first (referenced by ClockStateData and ClockTickData).
	r.ReflectType(TypeClockTimestamp, reflect.TypeOf(ClockTimestampData{}))
	r.ReflectType(TypeClockLogical, reflect.TypeOf(ClockLogicalData{}))
	r.ReflectType(TypeClockVector, reflect.TypeOf(ClockVectorData{}))
	r.ReflectType(TypeClockHLC, reflect.TypeOf(ClockHLCData{}))
	r.ReflectType(TypeClockConfig, reflect.TypeOf(ClockConfigData{}))
	r.ReflectType(TypeClockCompareResult, reflect.TypeOf(ClockCompareResultData{}))
	// ClockStateData depends on leaf clock types above.
	r.ReflectType(TypeClockState, reflect.TypeOf(ClockStateData{}))
	// ClockTickData depends on ClockStateData.
	r.ReflectType(TypeClockTick, reflect.TypeOf(ClockTickData{}))
	// ClockCompareParams uses primitive/any fields — register manually.
	r.RegisterManual(TypeDefinition{
		Name: TypeClockCompareParams,
		Fields: map[string]FieldSpec{
			"a": {TypeRef: "primitive/any"},
			"b": {TypeRef: "primitive/any"},
		},
	})

	// Phase 5e: Compute extension types.
	r.ReflectType(TypeComputeLiteral, reflect.TypeOf(ComputeLiteralData{}))
	r.ReflectType(TypeComputeLookupScope, reflect.TypeOf(ComputeLookupScopeData{}))
	r.ReflectType(TypeComputeLookupTree, reflect.TypeOf(ComputeLookupTreeData{}))
	r.ReflectType(TypeComputeLookupHash, reflect.TypeOf(ComputeLookupHashData{}))
	r.ReflectType(TypeComputeApply, reflect.TypeOf(ComputeApplyData{}))
	r.ReflectType(TypeComputeIf, reflect.TypeOf(ComputeIfData{}))
	r.RegisterManual(TypeDefinition{
		Name: TypeComputeLet,
		Fields: map[string]FieldSpec{
			"bindings": {ArrayOf: &FieldSpec{TypeRef: "primitive/any"}},
			"body":     {TypeRef: "system/hash"},
		},
	})
	r.ReflectType(TypeComputeLambda, reflect.TypeOf(ComputeLambdaData{}))
	r.ReflectType(TypeComputeArithmetic, reflect.TypeOf(ComputeArithmeticData{}))
	r.ReflectType(TypeComputeCompare, reflect.TypeOf(ComputeCompareData{}))
	r.ReflectType(TypeComputeLogic, reflect.TypeOf(ComputeLogicData{}))
	r.ReflectType(TypeComputeField, reflect.TypeOf(ComputeFieldData{}))
	r.ReflectType(TypeComputeConstruct, reflect.TypeOf(ComputeConstructData{}))
	r.ReflectType(TypeComputeIndex, reflect.TypeOf(ComputeIndexData{}))
	r.ReflectType(TypeComputeLength, reflect.TypeOf(ComputeLengthData{}))
	r.ReflectType(TypeComputeNumericCast, reflect.TypeOf(ComputeNumericCastData{}))
	r.ReflectType(TypeComputeClosure, reflect.TypeOf(ComputeClosureData{}))
	// v3.19b: ComputeScopeBinding must register BEFORE ComputeScopeData
	// because ComputeScopeData.Bindings is map[string]ComputeScopeBinding —
	// the inner struct must be in knownTypes when ScopeData reflects, or
	// ReflectType returns "unregistered struct type" and compute/scope
	// silently fails to land at system/type/compute/scope.
	r.ReflectType(TypeComputeScopeBinding, reflect.TypeOf(ComputeScopeBinding{}))
	r.ReflectType(TypeComputeScope, reflect.TypeOf(ComputeScopeData{}))
	r.ReflectType(TypeComputeResult, reflect.TypeOf(ComputeResultData{}))
	r.ReflectType(TypeComputeError, reflect.TypeOf(ComputeErrorData{}))
	r.ReflectType(TypeComputeSubgraph, reflect.TypeOf(ComputeSubgraphData{}))
	r.ReflectType(TypeComputeInstallRequest, reflect.TypeOf(ComputeInstallRequestData{}))
	r.ReflectType(TypeComputeInstallResult, reflect.TypeOf(ComputeInstallResultData{}))
	r.ReflectType(TypeComputeStoreArgs, reflect.TypeOf(ComputeStoreArgsData{}))
	r.ReflectType(TypeComputeMapArgs, reflect.TypeOf(ComputeMapArgsData{}))
	r.ReflectType(TypeComputeFilterArgs, reflect.TypeOf(ComputeFilterArgsData{}))
	r.ReflectType(TypeComputeFoldArgs, reflect.TypeOf(ComputeFoldArgsData{}))

	// Phase 5f: EXTENSION-CONTENT v3.6 §2 entity types. Reflected from Go
	// structs; []hash.Hash → array_of {type_ref: "system/hash"} per the
	// §2.8 wire-shape pin (flat hash records, not envelope wrappers).
	r.ReflectType(TypeContentBlob, reflect.TypeOf(ContentBlobData{}))
	r.ReflectType(TypeContentChunk, reflect.TypeOf(ContentChunkData{}))
	r.ReflectType(TypeContentDescriptor, reflect.TypeOf(ContentDescriptorData{}))

	// Storage-substitute substrate types (NETWORK §6.5.3 / STORAGE-SUBSTITUTE-HTTP
	// §3-RES.2 / STORAGE-SUBSTITUTE-SOURCES §2.1). All four are reachable
	// over the wire today (publisher may write them; consumer may read them);
	// the dispatch glue that turns them into operational fetches lives in
	// ext/storagesubstitutesources/ + ext/storagesubstitutehttp/. Registering
	// them now means cross-impl type-shape probes (`probe-peer`,
	// `compare-types`) see them as first-class.
	//
	// TransportEndpoint MUST register first — both HTTPPollProfileData and
	// SubstituteSnapshotManifestData embed it as a nested struct, and the
	// reflection pass requires the inner type's spec name to be known.
	// Wire string is system/substitute/endpoint per Ruling 1.
	r.ReflectType(TypeSubstituteEndpoint, reflect.TypeOf(TransportEndpoint{}))
	r.ReflectType(TypePeerTransportHTTPPoll, reflect.TypeOf(HTTPPollProfileData{}))
	r.ReflectType(TypePeerTransportTCP, reflect.TypeOf(TCPProfileData{}))
	r.ReflectType(TypePeerTransportHTTP, reflect.TypeOf(HTTPProfileData{}))
	r.ReflectType(TypePeerTransportWebSocket, reflect.TypeOf(WebSocketProfileData{}))
	r.ReflectType(TypeSubstituteSnapshotManifest, reflect.TypeOf(SubstituteSnapshotManifestData{}))
	r.ReflectType(TypeSubstituteSource, reflect.TypeOf(SubstituteSourceData{}))
	// try-request entity carries an inlined entity.Entity in `entry`.
	// The reflection registers it; the inner system/substitute/source it
	// carries gets validated when the convention handler decodes it.
	r.ReflectType(TypeSubstituteTryRequest, reflect.TypeOf(SubstituteTryRequestData{}))
	// F2 (RULINGS-STORAGE-SUBSTITUTE-CROSS-IMPL Ruling 2): entry carries the
	// FULL system/substitute/source entity, so pin its type precisely rather
	// than the looser core/entity the Go struct field (entity.Entity) reflects
	// to. Lets the type checker validate the entry's own fields.
	r.OverrideField(TypeSubstituteTryRequest, "entry", FieldSpec{TypeRef: TypeSubstituteSource})

	// system/capability/multi-granter — multi-sig granter shape per
	// PROPOSAL-MULTISIG-CORE-PRIMITIVE M2. Registered before the override on
	// `system/capability/token.granter` so the union variant resolves.
	r.ReflectType(TypeMultiGranter, reflect.TypeOf(MultiGranter{}))

	// Phase 6: Post-reflection overrides for fields missing from Go structs.
	// system/capability/token: add resource_limits field.
	r.AddField("system/capability/token", "resource_limits",
		FieldSpec{TypeRef: "system/resource-limits", Optional: true})

	// system/capability/token: granter is polymorphic (M1) — system/hash for
	// single-sig OR system/capability/multi-granter for multi-sig.
	r.OverrideField("system/capability/token", "granter", FieldSpec{
		UnionOf: []FieldSpec{
			{TypeRef: "system/hash"},
			{TypeRef: TypeMultiGranter},
		},
	})

	// Handler interface type — public-facing subset (pattern, name, operations).
	r.RegisterManual(TypeDefinition{
		Name: "system/handler/interface",
		Fields: map[string]FieldSpec{
			"pattern":    {TypeRef: "system/tree/path"},
			"name":       {TypeRef: "primitive/string"},
			"operations": {MapOf: &FieldSpec{TypeRef: "system/handler/operation-spec"}},
		},
	})

	// system/handler/manifest extends system/handler/interface (adds scope fields).
	r.SetExtends("system/handler/manifest", "system/handler/interface")

	// Phase 6: Post-reflection field type_ref overrides for semantic types.
	// These update type metadata only — Go structs use string for all of these.

	// delivery-spec: uri field
	r.OverrideField("system/delivery-spec", "uri", FieldSpec{TypeRef: "system/tree/path"})

	// Type definition fields
	r.OverrideField("system/type", "name", FieldSpec{TypeRef: "system/type/name"})
	r.OverrideField("system/type", "extends", FieldSpec{TypeRef: "system/type/name", Optional: true})
	r.OverrideField("system/type", "type_args",
		FieldSpec{MapOf: &FieldSpec{TypeRef: "system/type/name"}, Optional: true})

	// field-spec fields
	r.OverrideField("system/type/field-spec", "type_ref", FieldSpec{TypeRef: "system/type/name", Optional: true})
	r.OverrideField("system/type/field-spec", "key_type", FieldSpec{TypeRef: "system/type/name", Optional: true})
	r.OverrideField("system/type/field-spec", "type_args",
		FieldSpec{MapOf: &FieldSpec{TypeRef: "system/type/name"}, Optional: true})

	// operation-spec fields
	r.OverrideField("system/handler/operation-spec", "input_type", FieldSpec{TypeRef: "system/type/name", Optional: true})
	r.OverrideField("system/handler/operation-spec", "output_type", FieldSpec{TypeRef: "system/type/name", Optional: true})

	// validate-request: type_path field (EXTENSION-TYPE v1.1 §8.3 — optional).
	r.OverrideField("system/type/validate-request", "type_path",
		FieldSpec{TypeRef: "system/type/name", Optional: true})

	// validate-result: violations array element, violation.kind one_of, etc.
	r.OverrideField(TypeTypeViolation, "constraint", FieldSpec{TypeRef: "system/type/name", Optional: true})

	// EXTENSION-TYPE v1.1 §7 — type analysis op fields.
	r.OverrideField(TypeTypeCompareRequest, "type_a", FieldSpec{TypeRef: TypeTreePath})
	r.OverrideField(TypeTypeCompareRequest, "type_b", FieldSpec{TypeRef: TypeTreePath})
	r.OverrideField(TypeTypeCompareResult, "type_a_path", FieldSpec{TypeRef: TypeTreePath})
	r.OverrideField(TypeTypeCompareResult, "type_b_path", FieldSpec{TypeRef: TypeTreePath})
	r.OverrideField(TypeTypeCompatibleRequest, "type_a", FieldSpec{TypeRef: TypeTreePath})
	r.OverrideField(TypeTypeCompatibleRequest, "type_b", FieldSpec{TypeRef: TypeTreePath})
	r.OverrideField(TypeTypeCompatibilityReport, "type_a_path", FieldSpec{TypeRef: TypeTreePath})
	r.OverrideField(TypeTypeCompatibilityReport, "type_b_path", FieldSpec{TypeRef: TypeTreePath})
	r.OverrideField(TypeTypeConvergeRequest, "type_paths",
		FieldSpec{ArrayOf: &FieldSpec{TypeRef: TypeTreePath}})
	r.OverrideField(TypeTypeAdoptRequest, "source_path", FieldSpec{TypeRef: TypeTreePath})
	r.OverrideField(TypeTypeAdoptRequest, "local_name",
		FieldSpec{TypeRef: TypeTypeName, Optional: true})
	r.OverrideField(TypeTypeReconcileRequest, "type_paths",
		FieldSpec{ArrayOf: &FieldSpec{TypeRef: TypeTreePath}})
	r.OverrideField(TypeTypeReconcileResult, "reconciled_type", FieldSpec{TypeRef: TypeCoreEntity})
	r.OverrideField(TypeTypeReconcileResult, "sources",
		FieldSpec{ArrayOf: &FieldSpec{TypeRef: TypeTreePath}})
	r.OverrideField(TypeTypeFieldIncompatibility, "a_type", FieldSpec{TypeRef: TypeTypeName})
	r.OverrideField(TypeTypeFieldIncompatibility, "b_type", FieldSpec{TypeRef: TypeTypeName})

	// EXTENSION-TYPE v1.1 §5.2 — constraint dispatch envelope: constraint_type
	// is a type-name path.
	r.OverrideField(TypeConstraintValidateReq, "constraint_type", FieldSpec{TypeRef: TypeTypeName})

	// peer/hello/authenticate: peer_id field
	r.OverrideField("system/peer", "peer_id", FieldSpec{TypeRef: "system/peer-id"})

	// F1 (NETWORK errata bdfb545 — §6.5.1 profile peer_id Hash→system/peer-id):
	// transport-profile peer_id is the Base58 id-string (the {peer_id} path
	// segment), the semantic system/peer-id type — NOT the bare primitive/string
	// the `PeerID string` struct field reflects to, and NOT system/hash. Pin all
	// three live/poll profiles. (source_peer_id stays system/hash — it's an
	// entity-internal trust anchor per V7 §1.4, correctly reflected already.)
	r.OverrideField(TypePeerTransportHTTPPoll, "peer_id", FieldSpec{TypeRef: "system/peer-id"})
	r.OverrideField(TypePeerTransportTCP, "peer_id", FieldSpec{TypeRef: "system/peer-id"})
	r.OverrideField(TypePeerTransportHTTP, "peer_id", FieldSpec{TypeRef: "system/peer-id"})
	r.OverrideField(TypePeerTransportWebSocket, "peer_id", FieldSpec{TypeRef: "system/peer-id"})

	// Path-typed fields → system/tree/path
	r.OverrideField("system/protocol/execute", "uri", FieldSpec{TypeRef: "system/tree/path"})
	r.OverrideField("system/handler", "interface", FieldSpec{TypeRef: "system/tree/path"})
	r.OverrideField("system/handler", "expression_path", FieldSpec{TypeRef: "system/tree/path", Optional: true})
	r.OverrideField("system/handler/manifest", "pattern", FieldSpec{TypeRef: "system/tree/path"})
	r.OverrideField("system/handler/manifest", "expression_path", FieldSpec{TypeRef: "system/tree/path", Optional: true})
	r.OverrideField("system/handler/interface", "pattern", FieldSpec{TypeRef: "system/tree/path"})
	r.OverrideField("system/handler/register-result", "pattern", FieldSpec{TypeRef: "system/tree/path"})

	// Compute-extension path-typed fields → system/tree/path (per
	// EXTENSION-COMPUTE field specs and PROPOSAL-PATH-TYPE T1-T2).
	r.OverrideField(TypeComputeApply, "path", FieldSpec{TypeRef: "system/tree/path", Optional: true})
	r.OverrideField(TypeComputeLookupTree, "path", FieldSpec{TypeRef: "system/tree/path"})
	r.OverrideField(TypeComputeLookupHash, "path", FieldSpec{TypeRef: "system/tree/path", Optional: true})
	r.OverrideField(TypeComputeConstruct, "entity_type", FieldSpec{TypeRef: "system/type/name"})
	r.OverrideField(TypeComputeSubgraph, "root_expression_path", FieldSpec{TypeRef: "system/tree/path"})
	r.OverrideField(TypeComputeSubgraph, "result_path", FieldSpec{TypeRef: "system/tree/path"})
	r.OverrideField(TypeComputeInstallRequest, "result_path", FieldSpec{TypeRef: "system/tree/path", Optional: true})
	r.OverrideField(TypeComputeInstallResult, "subgraph_path", FieldSpec{TypeRef: "system/tree/path"})
	r.OverrideField(TypeComputeInstallResult, "result_path", FieldSpec{TypeRef: "system/tree/path"})
	r.OverrideField(TypeComputeStoreArgs, "path", FieldSpec{TypeRef: "system/tree/path"})
	r.OverrideField(TypeComputeNumericCast, "to_type", FieldSpec{TypeRef: "system/type/name"})

	// Path-typed array fields → array_of system/tree/path
	r.OverrideField("system/bounds", "visited",
		FieldSpec{ArrayOf: &FieldSpec{TypeRef: "system/tree/path"}, Optional: true})
	r.OverrideField("system/capability/path-scope", "include",
		FieldSpec{ArrayOf: &FieldSpec{TypeRef: "system/tree/path"}})
	r.OverrideField("system/capability/path-scope", "exclude",
		FieldSpec{ArrayOf: &FieldSpec{TypeRef: "system/tree/path"}, Optional: true})
	r.OverrideField("system/protocol/resource-target", "targets",
		FieldSpec{ArrayOf: &FieldSpec{TypeRef: "system/tree/path"}})
	r.OverrideField("system/protocol/resource-target", "exclude",
		FieldSpec{ArrayOf: &FieldSpec{TypeRef: "system/tree/path"}, Optional: true})

	// Entity-typed fields → entity (PROPOSAL-ENTITY-FIELD-ANNOTATION).
	// These fields carry materialized entities {type, data, content_hash},
	// not raw CBOR values. Narrowed from primitive/any to entity.
	// Note: core/envelope root and included already use TypeCoreEntity in their definition.
	r.OverrideField("system/protocol/execute", "params", FieldSpec{TypeRef: TypeCoreEntity})
	r.OverrideField("system/protocol/execute/response", "result", FieldSpec{TypeRef: TypeCoreEntity})
	r.OverrideField(TypeInboxDelivery, "result", FieldSpec{TypeRef: TypeCoreEntity})
	r.OverrideField(TypeTreePutRequest, "entity", FieldSpec{TypeRef: TypeCoreEntity, Optional: true})
	r.OverrideField("system/type/validate-request", "entity", FieldSpec{TypeRef: TypeCoreEntity})

	// Scope type refs on grant-entry
	r.OverrideField("system/capability/grant-entry", "handlers", FieldSpec{TypeRef: "system/capability/path-scope"})
	r.OverrideField("system/capability/grant-entry", "resources", FieldSpec{TypeRef: "system/capability/path-scope"})
	r.OverrideField("system/capability/grant-entry", "operations", FieldSpec{TypeRef: "system/capability/id-scope"})
	r.OverrideField("system/capability/grant-entry", "peers", FieldSpec{TypeRef: "system/capability/id-scope", Optional: true})
	r.OverrideField("system/capability/grant-entry", "constraints",
		FieldSpec{MapOf: &FieldSpec{TypeRef: "primitive/any"}, Optional: true})
	r.OverrideField("system/capability/grant-entry", "allowances",
		FieldSpec{MapOf: &FieldSpec{TypeRef: "primitive/any"}, Optional: true})

	// Inbox/subscription semantic type overrides.
	r.OverrideField(TypeInboxNotification, "uri", FieldSpec{TypeRef: TypeTreePath})
	r.OverrideField(TypeSubscription, "pattern", FieldSpec{TypeRef: TypeTreePath})
	r.OverrideField(TypeSubscription, "deliver_uri", FieldSpec{TypeRef: TypeTreePath})
	r.OverrideField(TypeSubscription, "events",
		FieldSpec{ArrayOf: &FieldSpec{TypeRef: "primitive/string"}})
	r.OverrideField(TypeSubscriptionRequest, "events",
		FieldSpec{ArrayOf: &FieldSpec{TypeRef: "primitive/string"}, Optional: true})
	r.OverrideField(TypeSubscriptionRequest, "deliver_to", FieldSpec{TypeRef: TypeDeliverySpec})
	r.OverrideField(TypeSubscriptionRedirect, "prefix", FieldSpec{TypeRef: TypeTreePath})
	r.OverrideField(TypeSubscriptionRedirect, "alternatives",
		FieldSpec{ArrayOf: &FieldSpec{TypeRef: "system/hash"}, Optional: true})

	// Continuation semantic type overrides.
	r.OverrideField(TypeContinuation, "target", FieldSpec{TypeRef: TypeTreePath})
	r.OverrideField(TypeContinuation, "on_error", FieldSpec{TypeRef: TypeDeliverySpec, Optional: true})
	r.OverrideField(TypeContinuation, "deliver_to", FieldSpec{TypeRef: TypeDeliverySpec, Optional: true})
	r.OverrideField(TypeContinuationJoin, "target", FieldSpec{TypeRef: TypeTreePath})
	r.OverrideField(TypeContinuationJoin, "on_error", FieldSpec{TypeRef: TypeDeliverySpec, Optional: true})
	r.OverrideField(TypeContinuationJoin, "deliver_to", FieldSpec{TypeRef: TypeDeliverySpec, Optional: true})
	r.OverrideField(TypeContinuationJoin, "expected",
		FieldSpec{ArrayOf: &FieldSpec{TypeRef: "primitive/string"}})
	r.OverrideField(TypeContinuationSuspended, "target", FieldSpec{TypeRef: TypeTreePath})
	r.OverrideField(TypeContinuationResumeRequest, "deliver_to", FieldSpec{TypeRef: TypeDeliverySpec, Optional: true})
	r.OverrideField(TypeContinuationInstallResult, "path", FieldSpec{TypeRef: TypeTreePath})

	// Phase 5e: Query types (EXTENSION-QUERY v1.0).
	// QueryFieldPredicateData registered as sentinel in Phase 1.
	r.ReflectType(TypeQueryFieldPredicate, reflect.TypeOf(QueryFieldPredicateData{}))
	r.ReflectType(TypeQueryMatch, reflect.TypeOf(QueryMatchData{}))
	r.ReflectType(TypeQueryExpression, reflect.TypeOf(QueryExpressionData{}))
	r.ReflectType(TypeQueryResult, reflect.TypeOf(QueryResultData{}))
	r.ReflectType(TypeQueryConstraints, reflect.TypeOf(QueryConstraintsData{}))
	r.ReflectType(TypeQueryAllowances, reflect.TypeOf(QueryAllowancesData{}))
	r.ReflectType(TypeQueryIndexConfig, reflect.TypeOf(QueryIndexConfigData{}))

	// Query semantic type overrides.
	r.OverrideField(TypeQueryExpression, "path_filter", FieldSpec{TypeRef: TypeTreePath, Optional: true})
	r.OverrideField(TypeQueryExpression, "path_prefix", FieldSpec{TypeRef: TypeTreePath, Optional: true})
	r.OverrideField(TypeQueryMatch, "path", FieldSpec{TypeRef: TypeTreePath, Optional: true})
	r.OverrideField(TypeQueryMatch, "type", FieldSpec{TypeRef: TypeTypeName})
	r.OverrideField(TypeQueryConstraints, "type_scope", FieldSpec{TypeRef: "system/capability/id-scope", Optional: true})
	r.OverrideField(TypeQueryIndexConfig, "type_name", FieldSpec{TypeRef: TypeTypeName})

	// Phase 5f: Encryption types (EXTENSION-ENCRYPTION v1.0). No handler
	// ops are dispatched over the wire — encryption is a client-side
	// primitive — but the entity types MUST be registered so tree:put of a
	// system/encrypted / system/encryption-pubkey / handoff / revocation /
	// key-backup entity is accepted by every conformant peer. Sub-shape
	// types (kdf-params, wrapped-key) are registered first so reflection
	// of the outer wrapper resolves them via the known-types map.
	r.ReflectType(TypeEncryptionKDFParams, reflect.TypeOf(KDFParams{}))
	r.ReflectType(TypeEncryptionWrappedKey, reflect.TypeOf(WrappedKey{}))
	r.ReflectType(TypeEncryptionPubkey, reflect.TypeOf(EncryptionPubkeyData{}))
	r.ReflectType(TypeEncrypted, reflect.TypeOf(EncryptedData{}))
	r.ReflectType(TypeEncryptionHandoff, reflect.TypeOf(EncryptionHandoffData{}))
	r.ReflectType(TypeEncryptionRevocation, reflect.TypeOf(EncryptionRevocationData{}))
	r.ReflectType(TypeEncryptionKeyBackup, reflect.TypeOf(EncryptionKeyBackupData{}))

	// system/note — the §16 ENC-KAT-INNER carrier type per R3 (the
	// encryption-cohort V2.5 arch ruling). The KAT plaintext is the ECF bytes of a
	// system/note entity, not a bare UTF-8 string; this exercises the
	// decrypt → typed entity → re-inject path (§13.3) and pins the true
	// ciphertext length. Registered as a manual type because no Go struct
	// is needed — the inner data is built inline in ext/encryption.
	r.RegisterManual(TypeDefinition{
		Name: "system/note",
		Fields: map[string]FieldSpec{
			"body":    {TypeRef: "primitive/string"},
			"created": {TypeRef: "primitive/uint"},
		},
	})

	// Handler-specific types (hello, authenticate, tree/*) are registered by
	// their respective handlers via TypeProvider.RegisterTypes().
}
