package validate

import "sort"

// AllCategories returns every validation category the suite can run, sorted by
// name. This is the single list the CLI's -list-categories output, the
// -category usage text, and the RunCategory "unknown category" error all derive
// from — so those never drift independently.
//
// Each entry references its cat* constant (defined alongside the category's
// runner), so a renamed constant is a compile error here, not silent rot. When
// you add a new category, add its case to Run + RunCategory in suite.go AND its
// constant here. TestAllCategoriesSortedUnique guards the shape of this list.
func AllCategories() []string {
	cats := []string{
		catAttestation,
		catAuthz,
		catAutoVersion,
		catBehavioralRole,
		catBehavioralV33,
		catCapability,
		catClock,
		catCompute,
		catConcurrency,
		catConformance,
		catConformancePassthrough,
		catConnectivity,
		catContent,
		catContinuations,
		catConvergence,
		catConvergentMirror,
		catCrossPeerHTTPSub,
		catCrossPeerTCPSub,
		catCryptoAgility,
		catDiscovery,
		catDurability,
		catEncoding,
		catEncryption,
		catEntityNative,
		catFormatAgility,
		catHandlers,
		catHistory,
		catIdentity,
		catLocalFiles,
		catMultiSig,
		catNegotiation,
		catOrigination,
		catPeerCanonicalization,
		catPeerIDForm,
		catPeerIssued,
		catPolicyDualForm,
		catPublishedRoot,
		catPublishFetchHTTPPoll,
		catQuery,
		catQuorum,
		catRegistry,
		catRelay,
		catRelayMultiPeer,
		catRelayMultiPrincipal,
		catRelayOfflineDelivery,
		catRelayOfflineDeliveryRegistry,
		catRelaySourceRoute,
		catResourceBounds,
		catRevision,
		catRole,
		catRoute,
		catSecurity,
		catServingMode,
		catSession,
		catSubscriptions,
		catTransportFamily,
		catTreeOps,
		catType,
		catTypeSystem,
		catUniversalAddressSpace,
	}
	sort.Strings(cats)
	return cats
}
