package validate

import (
	"context"
	"fmt"
	"strings"
)

// This file holds the shared self-skip helper for OPTIONAL extension
// categories (S1 in AUDIT-VALIDATE-PEER-COMPREHENSIVE). Several
// extension categories (attestation, quorum, identity, role, …) ran
// unconditionally and hard-FAILed when the handler was absent — encoding "the
// Go reference peer ships this handler" as the conformance contract. A
// conformant peer with a different extension subset got spurious FAILs. The
// durability category is the model: absence of an optional extension is
// conformant, so it SKIPs (which the suite counts distinctly), and dependent
// checks skip via CheckRunner.Require.

// isHandlerAbsent reports whether a TreeGet error means the handler manifest is
// simply not bound (the peer does not implement this optional extension) rather
// than a genuine failure. TreeGet surfaces an absent binding as
// "tree get status 404".
func isHandlerAbsent(err error) bool {
	return err != nil && strings.Contains(err.Error(), "status 404")
}

// optionalManifestPresent fetches an optional extension's handler manifest at
// handlerPath. Absence (404) → SkipCheck (conformant); any other error →
// FailCheck. On success it stores the manifest entity under "manifest_entity"
// for the category's decode check and returns PassCheck. Wire the category's
// dependent checks to Require("handler_manifest_present") so they skip too when
// the handler is absent.
func optionalManifestPresent(ctx context.Context, client *PeerClient, r *CheckRunner, handlerPath, name string) CheckOutcome {
	ent, _, err := client.TreeGet(ctx, handlerPath)
	if err != nil {
		if isHandlerAbsent(err) {
			return SkipCheck(fmt.Sprintf("%s handler not present at %s — absence of an optional extension is conformant (S1)", name, handlerPath))
		}
		return FailCheck(fmt.Sprintf("failed to fetch %s handler manifest: %v", name, err))
	}
	r.Store("manifest_entity", ent)
	return PassCheck(fmt.Sprintf("%s handler manifest present (type: %s)", name, ent.Type))
}
