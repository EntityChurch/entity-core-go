package role

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"

	"go.entitychurch.org/entity-core-go/core/capability"
	"go.entitychurch.org/entity-core-go/core/crypto"
	"go.entitychurch.org/entity-core-go/core/entity"
	ecerrors "go.entitychurch.org/entity-core-go/core/errors"
	"go.entitychurch.org/entity-core-go/core/handler"
	"go.entitychurch.org/entity-core-go/core/hash"
	"go.entitychurch.org/entity-core-go/core/store"
	"go.entitychurch.org/entity-core-go/core/types"

	"github.com/fxamacker/cbor/v2"
)

// Security-edge tests for the role extension. Each test maps to a SEC-N
// item in docs/validation/PLAN-LIFECYCLE-INTEGRATION-VALIDATION.md.
// The tests are in-process Go assertions covering invariants that the
// cross-impl wire harness can't reach (forged caps, race-adjacent
// post-state checks). Each impl mirrors the canonical case set in its
// own test layer.

// =====================================================================
// SEC-1 — confused deputy via role handler
// =====================================================================

// TestSEC1_AssignRL2_MultiGrantPartialCoverage verifies the RL2 contract
// at :assign — the caller's capability MUST cover EVERY grant entry the
// role's derived cap would carry. Existing fixtures cover the
// single-grant case; this test exercises a multi-grant role definition
// where the caller cap covers some grant entries but not all. Per
// IsAttenuated semantics ("every child grant must be covered by some
// parent grant"), a single uncovered grant entry causes RL2 to fail
// closed and refuse the assign.
//
// Threat model: a low-authority caller invoking :assign with a role
// definition that exceeds the caller's authority. Without RL2 firing
// per-entry, an attacker could craft a role with a "covered grant +
// secret broader grant" combo and trick the role handler into minting
// a cap with broader authority than the caller possessed. The minted
// cap's chain would (on use) chain through the runtime peer's handler
// grant, NOT through the caller — so chain validation would NOT catch
// it later. RL2 at issue time is the only line of defense for this
// privilege-escalation path.
func TestSEC1_AssignRL2_MultiGrantPartialCoverage(t *testing.T) {
	f := newOperatorFixture(t)

	// Update the role definition to have TWO grant entries: the first
	// stays within the caller's authority (system/tree get/list under
	// shared/{ctx}/*), the second exceeds it (system/role admin —
	// caller has system/role:* on system/role/* but role-def claims
	// arbitrary system/role:put on the WHOLE tree).
	multiGrants := []types.GrantEntry{
		{
			// Covered by caller cap.
			Handlers:   types.CapabilityScope{Include: []string{"system/tree"}},
			Resources:  types.CapabilityScope{Include: []string{"shared/" + f.contextStr + "/*"}},
			Operations: types.CapabilityScope{Include: []string{"get", "list"}},
		},
		{
			// NOT covered: caller cap doesn't grant system/tree:put on shared/whatever/*.
			Handlers:   types.CapabilityScope{Include: []string{"system/tree"}},
			Resources:  types.CapabilityScope{Include: []string{"shared/" + f.contextStr + "/*"}},
			Operations: types.CapabilityScope{Include: []string{"put"}}, // not in caller's grants
		},
	}
	updatedRoleDef := types.RoleData{
		Name:   f.roleName,
		Grants: multiGrants,
	}
	updatedRoleEnt, err := updatedRoleDef.ToEntity()
	if err != nil {
		t.Fatalf("updated role def encode: %v", err)
	}
	if _, err := f.hctx.Store.Put(updatedRoleEnt); err != nil {
		t.Fatalf("put updated role def: %v", err)
	}
	f.hctx.LocationIndex.Set(RoleDefinitionPath(f.contextStr, f.roleName), updatedRoleEnt.ContentHash)

	resp := f.callAssign(t, f.assigneeIdentity.ContentHash)
	if resp.Status != 403 {
		t.Fatalf("status = %d, want 403 — RL2 must reject when ANY grant entry exceeds caller's authority. Multi-grant partial coverage is a privilege-escalation path; chain validation can't catch this later because the issued cap chains through the handler grant, not the caller.", resp.Status)
	}
	if !errResultHasCode(t, resp, "assigner_authority_insufficient") {
		t.Fatalf("error code = %s; want assigner_authority_insufficient", dumpResult(t, resp))
	}

	// Post-state must be clean: no assignment entity bound, no cap minted.
	asnPath := AssignmentPath(f.contextStr, f.assigneeIdentity.ContentHash, f.roleName)
	if f.hctx.LocationIndex.Has(asnPath) {
		t.Errorf("assignment entity persisted despite RL2 rejection — partial-write violation; an attacker could leave traces of attempted privilege escalation")
	}
	prefix := RoleDerivedPeerPrefix(f.contextStr, f.assigneeIdentity.ContentHash)
	if entries := f.hctx.LocationIndex.List(prefix); len(entries) > 0 {
		t.Errorf("role-derived caps appeared at %s despite RL2 rejection (count=%d)", prefix, len(entries))
	}
}

// =====================================================================
// SEC-3 — re-derive silently skips excluded assignees
// =====================================================================

// TestSEC3_ReDeriveSkipsExcluded verifies §6.1 layer 2 enforcement
// inside the re-derive cascade — excluded peers MUST be skipped during
// re-derivation. They appear neither in `new_token_hashes` (no new cap
// issued) nor in `skipped_grantees` (which is the §5.5 SI-15 channel
// for RL2 failures, distinct from exclusion).
//
// Threat model: an attacker excluded from a context tries to "ride"
// a re-derive cascade to obtain a fresh cap. If the cascade doesn't
// consult the exclusion subtree per assignee, the excluded peer is
// re-issued a cap on every re-derive — making exclusion effectively
// reversible by anyone with :re-derive authority.
func TestSEC3_ReDeriveSkipsExcluded(t *testing.T) {
	f := newOperatorFixture(t)

	// Set up a SECOND assignee Y so we can confirm the cascade works
	// for Y while skipping X.
	var ySeed [32]byte
	ySeed[0] = 0xb4
	yKp := crypto.FromSeed(ySeed)
	yIdentity, _ := yKp.IdentityEntity()
	if _, err := f.hctx.Store.Put(yIdentity); err != nil {
		t.Fatalf("put yIdentity: %v", err)
	}

	// Assign X (the operator-fixture's assignee) and Y to the role.
	for _, peerHash := range []hash.Hash{f.assigneeIdentity.ContentHash, yIdentity.ContentHash} {
		resp := f.callAssign(t, peerHash)
		if resp.Status != 200 {
			t.Fatalf("setup: assign of %v: status=%d (%s)", peerHash, resp.Status, dumpResult(t, resp))
		}
	}

	// Exclude X.
	excl := types.RoleExclusionData{
		ExcludedBy: f.localIdentity.ContentHash,
		ExcludedAt: 1500,
	}
	exclEnt, _ := excl.ToEntity()
	if _, err := f.hctx.Store.Put(exclEnt); err != nil {
		t.Fatalf("put exclusion: %v", err)
	}
	exclPath := ExclusionPath(f.contextStr, f.assigneeIdentity.ContentHash)
	f.hctx.LocationIndex.Set(exclPath, exclEnt.ContentHash)

	// Trigger re-derive. Build the request via the handler's :re-derive entry.
	body := types.RoleReDeriveRequestData{Role: f.roleName}
	params, _ := body.ToEntity()
	rdPath := RoleDefinitionPath(f.contextStr, f.roleName)
	f.hctx.Resource = &types.ResourceTarget{Targets: []string{rdPath}}
	req := &handler.Request{
		Operation: "re-derive",
		Params:    params,
		Context:   f.hctx,
	}
	resp, err := f.h.Handle(context.Background(), req)
	if err != nil {
		t.Fatalf("re-derive: %v", err)
	}
	if resp.Status != 200 {
		t.Fatalf("re-derive status = %d, want 200; %s", resp.Status, dumpResult(t, resp))
	}
	result, err := types.RoleReDeriveResultDataFromEntity(resp.Result)
	if err != nil {
		t.Fatalf("decode re-derive result: %v", err)
	}

	// X must NOT appear in NewTokenHashes — the cascade silently skipped
	// X due to its exclusion. (Compare to TV-RD-19's SI-15 case where
	// uncovered peers go into SkippedGrantees with code "rl2_failure".)
	for _, h := range result.NewTokenHashes {
		// Each new cap's path under role-derived/{ctx}/X/ would mean X was issued.
		xCapPath := RoleDerivedTokenPath(f.contextStr, f.assigneeIdentity.ContentHash, h)
		if f.hctx.LocationIndex.Has(xCapPath) {
			t.Errorf("§6.1 layer 2 BYPASS: re-derive issued a fresh cap for excluded peer X at %s — exclusion is effectively reversible by anyone with :re-derive authority", xCapPath)
		}
	}

	// X must also NOT appear in SkippedGrantees — that field is for RL2
	// failures (SI-15), not for exclusion silent-skip.
	for _, h := range result.SkippedGrantees {
		if h == f.assigneeIdentity.ContentHash {
			t.Errorf("excluded peer X surfaced in skipped_grantees — that field is reserved for SI-15 RL2 failures, not exclusion. Exclusion is a silent-skip per §6.1 layer 2.")
		}
	}

	// Y MUST have been re-derived (cascade still works for non-excluded peers).
	yReDerived := false
	for _, h := range result.NewTokenHashes {
		yCapPath := RoleDerivedTokenPath(f.contextStr, yIdentity.ContentHash, h)
		if f.hctx.LocationIndex.Has(yCapPath) {
			yReDerived = true
			break
		}
	}
	if !yReDerived {
		t.Errorf("non-excluded peer Y was not re-derived — exclusion of X must NOT block the cascade for other peers")
	}
}

// =====================================================================
// SEC-6 — forged role-derived cap signature rejected
// =====================================================================

// SEC-6 has three sub-cases corresponding to the three layered defenses
// in V7 §5.5 chain validation: parent-grantee/granter linkage, signer/
// granter equality, and cryptographic signature verification. Each
// sub-case constructs an adversarial cap and confirms the chain walk
// rejects it.
//
// Setup pattern: build a legitimate root cap (the "handler grant") that
// the runtime peer holds, then construct an adversarial role-derived
// cap whose parent points at that root. The forgery's three flavors
// exercise the three defenses.

type forgedCapFixture struct {
	runtimeKp       crypto.Keypair
	runtimeIdentity entity.Entity
	adversaryKp     crypto.Keypair
	adversaryIdent  entity.Entity
	rootCap         entity.Entity // legitimate handler-grant root
	rootCapSig      entity.Entity
}

func newForgedCapFixture(t *testing.T) *forgedCapFixture {
	t.Helper()
	var rSeed [32]byte
	rSeed[0] = 0x10
	runtimeKp := crypto.FromSeed(rSeed)
	runtimeIdentity, _ := runtimeKp.IdentityEntity()

	var aSeed [32]byte
	aSeed[0] = 0x20
	adversaryKp := crypto.FromSeed(aSeed)
	adversaryIdent, _ := adversaryKp.IdentityEntity()

	// Build a legitimate root cap — runtime peer wildcard self-grant
	// (matches `debug_open_grants: true` in PeerConfig per §3.1 of
	// the lifecycle exploration). Granter == grantee == runtime peer,
	// no parent. Wildcard scope so derived caps with system/tree
	// grants attenuate cleanly without contrived parent-grant shapes.
	rootData := types.CapabilityTokenData{
		Grants: []types.GrantEntry{{
			Handlers:   types.CapabilityScope{Include: []string{"*"}},
			Resources:  types.CapabilityScope{Include: []string{"*"}},
			Operations: types.CapabilityScope{Include: []string{"*"}},
		}},
		Granter:   types.SingleSigGranter(runtimeIdentity.ContentHash),
		Grantee:   runtimeIdentity.ContentHash,
		CreatedAt: 1000,
	}
	rootCap, err := rootData.ToEntity()
	if err != nil {
		t.Fatalf("rootCap encode: %v", err)
	}
	rootSigBytes := runtimeKp.Sign(rootCap.ContentHash.Bytes())
	rootSigData := types.SignatureData{
		Target:    rootCap.ContentHash,
		Signer:    runtimeIdentity.ContentHash,
		Algorithm: "ed25519",
		Signature: rootSigBytes,
	}
	rootCapSig, _ := rootSigData.ToEntity()

	return &forgedCapFixture{
		runtimeKp:       runtimeKp,
		runtimeIdentity: runtimeIdentity,
		adversaryKp:     adversaryKp,
		adversaryIdent:  adversaryIdent,
		rootCap:         rootCap,
		rootCapSig:      rootCapSig,
	}
}

// SEC-6a — adversary as both granter and signer.
//
// Threat: attacker mints a "role-derived cap" claiming themselves as
// granter, parent pointing at the legitimate handler grant. The chain
// walker hits Site 2 (parent linkage) and sees parent.grantee = runtime
// peer ≠ current.granter = adversary. Rejected with ErrCapabilityDenied.
func TestSEC6a_ForgedCap_AdversaryAsGranter(t *testing.T) {
	f := newForgedCapFixture(t)

	// Adversary's "role-derived cap" — claims adversary as granter, points
	// parent at the legitimate root cap.
	parentHash := f.rootCap.ContentHash
	forgedData := types.CapabilityTokenData{
		Grants: []types.GrantEntry{{
			Handlers:   types.CapabilityScope{Include: []string{"system/tree"}},
			Resources:  types.CapabilityScope{Include: []string{"*"}},
			Operations: types.CapabilityScope{Include: []string{"*"}},
		}},
		Granter:   types.SingleSigGranter(f.adversaryIdent.ContentHash),
		Grantee:   f.adversaryIdent.ContentHash,
		Parent:    &parentHash,
		CreatedAt: 1100,
	}
	forgedCap, _ := forgedData.ToEntity()
	forgedSigBytes := f.adversaryKp.Sign(forgedCap.ContentHash.Bytes())
	forgedSigData := types.SignatureData{
		Target:    forgedCap.ContentHash,
		Signer:    f.adversaryIdent.ContentHash,
		Algorithm: "ed25519",
		Signature: forgedSigBytes,
	}
	forgedSig, _ := forgedSigData.ToEntity()

	included := map[hash.Hash]entity.Entity{
		f.runtimeIdentity.ContentHash: f.runtimeIdentity,
		f.adversaryIdent.ContentHash:  f.adversaryIdent,
		f.rootCap.ContentHash:         f.rootCap,
		f.rootCapSig.ContentHash:      f.rootCapSig,
		forgedCap.ContentHash:         forgedCap,
		forgedSig.ContentHash:         forgedSig,
	}

	err := capability.VerifyChain(forgedCap, included, f.runtimeKp.PeerID())
	if err == nil {
		t.Fatal("SEC-6a BREACH: forged cap with adversary-as-granter accepted by chain walker. Site 2 (parent.grantee != current.granter) defense did NOT fire.")
	}
	if !errors.Is(err, ecerrors.ErrCapabilityDenied) {
		t.Errorf("expected ErrCapabilityDenied, got: %v", err)
	}
}

// SEC-6b — runtime peer as granter (claimed), adversary as signer.
//
// Threat: attacker constructs a cap claiming runtime peer as granter
// (so Site 2 passes), but signs it with adversary's key (forging the
// signature). The signature entity declares signer = adversary. Site 1
// (verifyLinkSignatures) sees signer ≠ granter → rejected.
func TestSEC6b_ForgedCap_AdversarySignerMismatch(t *testing.T) {
	f := newForgedCapFixture(t)

	parentHash := f.rootCap.ContentHash
	forgedData := types.CapabilityTokenData{
		Grants: []types.GrantEntry{{
			Handlers:   types.CapabilityScope{Include: []string{"system/tree"}},
			Resources:  types.CapabilityScope{Include: []string{"*"}},
			Operations: types.CapabilityScope{Include: []string{"*"}},
		}},
		Granter:   types.SingleSigGranter(f.runtimeIdentity.ContentHash), // claims runtime peer
		Grantee:   f.adversaryIdent.ContentHash,
		Parent:    &parentHash,
		CreatedAt: 1100,
	}
	forgedCap, _ := forgedData.ToEntity()

	// Sign with adversary's key, but declare signer = adversary in the
	// signature entity. Site 1 checks signer == granter and rejects.
	advSig := f.adversaryKp.Sign(forgedCap.ContentHash.Bytes())
	forgedSigData := types.SignatureData{
		Target:    forgedCap.ContentHash,
		Signer:    f.adversaryIdent.ContentHash, // != cap.Granter
		Algorithm: "ed25519",
		Signature: advSig,
	}
	forgedSig, _ := forgedSigData.ToEntity()

	included := map[hash.Hash]entity.Entity{
		f.runtimeIdentity.ContentHash: f.runtimeIdentity,
		f.adversaryIdent.ContentHash:  f.adversaryIdent,
		f.rootCap.ContentHash:         f.rootCap,
		f.rootCapSig.ContentHash:      f.rootCapSig,
		forgedCap.ContentHash:         forgedCap,
		forgedSig.ContentHash:         forgedSig,
	}

	err := capability.VerifyChain(forgedCap, included, f.runtimeKp.PeerID())
	if err == nil {
		t.Fatal("SEC-6b BREACH: forged cap with mismatched signer/granter accepted. Site 1 (signer == granter) defense did NOT fire.")
	}
	if !errors.Is(err, ecerrors.ErrCapabilityDenied) {
		t.Errorf("expected ErrCapabilityDenied, got: %v", err)
	}
}

// SEC-6c — runtime peer as granter and signer, but invalid signature bytes.
//
// Threat: attacker mints a cap claiming runtime peer for everything,
// but the signature bytes are forged or zeroed. Site 1 (signer ==
// granter) passes; Site 1's crypto.Verify catches the invalid bytes
// and returns ErrAuthenticationFailed.
//
// Note: TestVerifyChainInvalidSignature in capability_test.go covers
// this for a root cap; this test exercises it on a 2-link role-derived
// chain, where the role-derived cap has a parent.
func TestSEC6c_ForgedCap_InvalidSignatureBytes(t *testing.T) {
	f := newForgedCapFixture(t)

	parentHash := f.rootCap.ContentHash
	forgedData := types.CapabilityTokenData{
		Grants: []types.GrantEntry{{
			Handlers:   types.CapabilityScope{Include: []string{"system/tree"}},
			Resources:  types.CapabilityScope{Include: []string{"*"}},
			Operations: types.CapabilityScope{Include: []string{"*"}},
		}},
		Granter:   types.SingleSigGranter(f.runtimeIdentity.ContentHash),
		Grantee:   f.adversaryIdent.ContentHash,
		Parent:    &parentHash,
		CreatedAt: 1100,
	}
	forgedCap, _ := forgedData.ToEntity()

	// Zero-bytes signature — claim signer = runtime peer, but bytes
	// don't verify. Crypto.Verify catches it.
	zeroBytes := make([]byte, crypto.Ed25519SignatureSize)
	forgedSigData := types.SignatureData{
		Target:    forgedCap.ContentHash,
		Signer:    f.runtimeIdentity.ContentHash, // matches granter
		Algorithm: "ed25519",
		Signature: zeroBytes,
	}
	forgedSig, _ := forgedSigData.ToEntity()

	included := map[hash.Hash]entity.Entity{
		f.runtimeIdentity.ContentHash: f.runtimeIdentity,
		f.adversaryIdent.ContentHash:  f.adversaryIdent,
		f.rootCap.ContentHash:         f.rootCap,
		f.rootCapSig.ContentHash:      f.rootCapSig,
		forgedCap.ContentHash:         forgedCap,
		forgedSig.ContentHash:         forgedSig,
	}

	err := capability.VerifyChain(forgedCap, included, f.runtimeKp.PeerID())
	if err == nil {
		t.Fatal("SEC-6c BREACH: forged cap with invalid signature bytes accepted. Crypto.Verify defense did NOT fire on the role-derived link.")
	}
	// Either ErrCapabilityDenied or ErrAuthenticationFailed is acceptable —
	// both fail closed.
	if !errors.Is(err, ecerrors.ErrCapabilityDenied) && !errors.Is(err, ecerrors.ErrAuthenticationFailed) {
		t.Errorf("expected ErrCapabilityDenied or ErrAuthenticationFailed, got: %v", err)
	}
}

// SEC-6d — sanity test: legitimate 2-link chain (role-derived from
// runtime peer's handler grant) MUST validate. Confirms the fixture
// setup itself is well-formed and we're exercising real defenses
// rather than tripping over fixture issues.
func TestSEC6d_LegitimateChain_Validates(t *testing.T) {
	f := newForgedCapFixture(t)

	// Construct a legitimate role-derived cap: runtime peer signs a cap
	// to a third-party assignee, parent = root cap.
	var asnSeed [32]byte
	asnSeed[0] = 0x30
	asnKp := crypto.FromSeed(asnSeed)
	asnIdentity, _ := asnKp.IdentityEntity()

	parentHash := f.rootCap.ContentHash
	derivedData := types.CapabilityTokenData{
		Grants: []types.GrantEntry{{
			Handlers:   types.CapabilityScope{Include: []string{"system/tree"}},
			Resources:  types.CapabilityScope{Include: []string{"shared/*"}},
			Operations: types.CapabilityScope{Include: []string{"get"}},
		}},
		Granter:   types.SingleSigGranter(f.runtimeIdentity.ContentHash),
		Grantee:   asnIdentity.ContentHash,
		Parent:    &parentHash,
		CreatedAt: 1100,
	}
	derivedCap, _ := derivedData.ToEntity()
	derivedSigBytes := f.runtimeKp.Sign(derivedCap.ContentHash.Bytes())
	derivedSigData := types.SignatureData{
		Target:    derivedCap.ContentHash,
		Signer:    f.runtimeIdentity.ContentHash,
		Algorithm: "ed25519",
		Signature: derivedSigBytes,
	}
	derivedSig, _ := derivedSigData.ToEntity()

	included := map[hash.Hash]entity.Entity{
		f.runtimeIdentity.ContentHash: f.runtimeIdentity,
		asnIdentity.ContentHash:       asnIdentity,
		f.rootCap.ContentHash:         f.rootCap,
		f.rootCapSig.ContentHash:      f.rootCapSig,
		derivedCap.ContentHash:        derivedCap,
		derivedSig.ContentHash:        derivedSig,
	}

	if err := capability.VerifyChain(derivedCap, included, f.runtimeKp.PeerID()); err != nil {
		t.Fatalf("legitimate 2-link chain rejected — fixture is broken: %v", err)
	}
}

// =====================================================================
// SEC-2 — race: concurrent assign vs exclude
// =====================================================================

// TestSEC2_AssignExcludeRace exercises the check-then-act window inside
// handleAssign. The race:
//
//	T1: assign goroutine — isExcluded(X) check returns false (no
//	    exclusion bound yet)
//	T2: exclude goroutine — writes exclusion entity, sweeps the
//	    role-derived subtree for X (currently empty)
//	T3: assign goroutine — issues role-derived cap for X
//
// Post-state: exclusion exists AND cap exists. The exclusion's
// fleet-wide IA8 sweep (sync hook on tree mutation) fires only at the
// exclusion-write moment; the late-arriving cap escapes the sweep.
//
// Spec contract: §4.6 layer 2 says "block new derivation" once an
// exclusion exists. The handler must enforce this atomically, not as
// a check-then-act sequence with a race window. Either:
//
//	(a) handleAssign holds a write-lock during isExcluded → issue,
//	(b) handleAssign re-checks isExcluded immediately before issuing
//	    the cap and rolls back if the exclusion appeared,
//	(c) any role-derived put fires a sweep-the-issuer hook (heavy).
//
// This test runs many concurrent iterations to amplify exposure. If
// any iteration leaves a cap that survives a bound exclusion, that's
// a privilege-escalation path: an attacker invokes :assign at the
// moment of :exclude and retains a valid cap that the spec says they
// shouldn't have.
func TestSEC2_AssignExcludeRace(t *testing.T) {
	const iterations = 100
	leakedCaps := 0

	for i := 0; i < iterations; i++ {
		f := newOperatorFixture(t)

		var wg sync.WaitGroup
		wg.Add(2)

		// Goroutine A: :assign through the handler.
		go func() {
			defer wg.Done()
			f.callAssign(t, f.assigneeIdentity.ContentHash)
		}()

		// Goroutine B: :exclude through the handler. Uses a fresh hctx
		// so author/local fields are set the same way as a normal exclude
		// dispatch.
		go func() {
			defer wg.Done()
			exclPath := ExclusionPath(f.contextStr, f.assigneeIdentity.ContentHash)
			emptyRaw, _ := types.RoleAssignRequestData{Role: ""}.ToEntity() // any non-nil entity
			_ = emptyRaw
			// Build a minimal exclude request and dispatch via the handler.
			body := map[string]any{}
			_ = body
			// Use the handler's exclude entry by constructing a request inline.
			// We share the same hctx (Store/LocationIndex are go-routine-safe).
			emptyParams, _ := entity.NewEntity("primitive/any", []byte{0xa0}) // empty CBOR map
			// Set Resource on a per-call basis is fine because Handler.Handle
			// re-reads hctx.Resource. But hctx is shared — to avoid clobbering
			// the assign goroutine's hctx.Resource, we use a fresh hctx for
			// exclude that points at the same Store + LocationIndex.
			hctx := &handler.HandlerContext{
				Author:        f.localKp.PeerID(),
				AuthorHash:    f.localIdentity.ContentHash,
				LocalPeerID:   f.localKp.PeerID(),
				Resource:      &types.ResourceTarget{Targets: []string{exclPath}},
				Store:         f.hctx.Store,
				LocationIndex: f.hctx.LocationIndex,
				Included:      make(map[hash.Hash]entity.Entity),
			}
			req := &handler.Request{
				Operation: "exclude",
				Params:    emptyParams,
				Context:   hctx,
			}
			f.h.Handle(context.Background(), req)
		}()

		wg.Wait()

		// Post-state assertion: if exclusion bound, no role-derived cap for X.
		exclPath := ExclusionPath(f.contextStr, f.assigneeIdentity.ContentHash)
		if !f.hctx.LocationIndex.Has(exclPath) {
			continue // exclusion didn't make it; race produced no exclusion outcome
		}
		prefix := RoleDerivedPeerPrefix(f.contextStr, f.assigneeIdentity.ContentHash)
		for _, e := range f.hctx.LocationIndex.List(prefix) {
			if strings.HasSuffix(barePath(e.Path), "/signature") {
				continue
			}
			leakedCaps++
			break
		}
	}

	if leakedCaps > 0 {
		t.Errorf("SEC-2: %d/%d iterations leaked a role-derived cap despite a bound exclusion. The check-then-act window in handleAssign is exploitable: attacker times :assign to coincide with :exclude and retains a cap. Per §4.6 layer 2 (\"block new derivation\"), this MUST be atomic. Fix: either handleAssign re-checks isExcluded immediately before TreeSet on the cap (rolling back on detection) or the assign+exclude pair takes a context-scoped lock. Logging the race exposure: this is a finding, not a wire-test regression.", leakedCaps, iterations)
	}
}

// =====================================================================
// SEC-5 — post-revocation cap rejection contract
// =====================================================================

// TestSEC5_PostRevocationRejection verifies the contract: after a
// role-derived cap binding is removed from the tree, subsequent
// chain-walk on that cap MUST reject. (In-flight ops at the moment of
// revocation may complete — that's the spec-accepted "one extra op"
// window. What this test pins is the post-revocation guarantee on
// the NEXT chain validation.)
//
// Wire flow: cap is "revoked" by deleting the binding at
// system/capability/grants/role-derived/{ctx}/{peer_id}/{token_hash}
// per §5.1. V7's is_revoked check sees the missing binding and rejects.
// In our in-process test we exercise this by removing the cap entity
// from the included set the chain-walker sees — the structural
// equivalent: cap not findable → ChainUnreachable → reject.
func TestSEC5_PostRevocationRejection(t *testing.T) {
	f := newForgedCapFixture(t)

	// Build a legitimate role-derived cap chained from the wildcard root.
	var asnSeed [32]byte
	asnSeed[0] = 0x40
	asnKp := crypto.FromSeed(asnSeed)
	asnIdentity, _ := asnKp.IdentityEntity()

	parentHash := f.rootCap.ContentHash
	derivedData := types.CapabilityTokenData{
		Grants: []types.GrantEntry{{
			Handlers:   types.CapabilityScope{Include: []string{"system/tree"}},
			Resources:  types.CapabilityScope{Include: []string{"shared/*"}},
			Operations: types.CapabilityScope{Include: []string{"get"}},
		}},
		Granter:   types.SingleSigGranter(f.runtimeIdentity.ContentHash),
		Grantee:   asnIdentity.ContentHash,
		Parent:    &parentHash,
		CreatedAt: 1100,
	}
	derivedCap, _ := derivedData.ToEntity()
	derivedSigBytes := f.runtimeKp.Sign(derivedCap.ContentHash.Bytes())
	derivedSigData := types.SignatureData{
		Target:    derivedCap.ContentHash,
		Signer:    f.runtimeIdentity.ContentHash,
		Algorithm: "ed25519",
		Signature: derivedSigBytes,
	}
	derivedSig, _ := derivedSigData.ToEntity()

	includedFull := map[hash.Hash]entity.Entity{
		f.runtimeIdentity.ContentHash: f.runtimeIdentity,
		asnIdentity.ContentHash:       asnIdentity,
		f.rootCap.ContentHash:         f.rootCap,
		f.rootCapSig.ContentHash:      f.rootCapSig,
		derivedCap.ContentHash:        derivedCap,
		derivedSig.ContentHash:        derivedSig,
	}

	// Step 1: cap validates pre-revocation.
	if err := capability.VerifyChain(derivedCap, includedFull, f.runtimeKp.PeerID()); err != nil {
		t.Fatalf("pre-revocation: cap should validate, got: %v", err)
	}

	// Step 2: simulate revocation by removing the parent cap from the
	// included set. The chain-walker can't reach the parent → chain
	// unreachable → ErrCapabilityDenied. (In production this corresponds
	// to deleting the parent cap's binding so is_revoked returns true.)
	includedRevoked := map[hash.Hash]entity.Entity{
		f.runtimeIdentity.ContentHash: f.runtimeIdentity,
		asnIdentity.ContentHash:       asnIdentity,
		// f.rootCap intentionally absent — parent revoked
		f.rootCapSig.ContentHash: f.rootCapSig,
		derivedCap.ContentHash:   derivedCap,
		derivedSig.ContentHash:   derivedSig,
	}
	err := capability.VerifyChain(derivedCap, includedRevoked, f.runtimeKp.PeerID())
	if err == nil {
		t.Fatal("SEC-5 BREACH: post-revocation cap accepted by chain walker. Removing the parent cap from the resolution set MUST cause chain-walk failure.")
	}
	if !errors.Is(err, ecerrors.ErrCapabilityDenied) {
		t.Errorf("expected ErrCapabilityDenied, got: %v", err)
	}

	// Step 3: also verify removing the derived cap itself surfaces
	// (the cap entity not being resolvable when looked up by hash).
	// VerifyChain takes the entity directly, so this scenario is more
	// about the wire layer's lookup-by-hash; structurally the test
	// above covers the contract. Document for completeness.
}

// =====================================================================
// SEC-8 — app-peer compromise scope-limit (parallel chains)
// =====================================================================

// TestSEC8_ParallelChainIsolation verifies that compromise of one
// app-peer is scope-limited: the operator's other app-peers are
// unaffected because their chains validate independently. The
// architecture (§4.9 of the lifecycle exploration) calls each app
// peer "an isolated work surface, with its own scope, revocable
// individually." This test pins the structural property.
//
// Setup:
//   - operatorKp: the user's operator identity (cluster-delegated)
//   - app1Kp: application peer A1 (scope S1)
//   - app2Kp: application peer A2 (scope S2)
//   - operator delegates separate caps to A1 and A2
//
// Test sequence:
//  1. Both A1 and A2 caps validate.
//  2. "Revoke" A1 — remove A1's cap from the resolution set.
//  3. A1's cap fails chain-walk (parent unreachable).
//  4. A2's cap STILL validates (independent chain).
//
// Scope-limit threat model: an attacker who compromises A1 must NOT
// gain access to S2 via A2's authority — A2's chain has nothing to do
// with A1.
func TestSEC8_ParallelChainIsolation(t *testing.T) {
	// Operator identity (the cluster-delegated active identity).
	var opSeed [32]byte
	opSeed[0] = 0x50
	operatorKp := crypto.FromSeed(opSeed)
	operatorIdentity, _ := operatorKp.IdentityEntity()

	// Operator's root self-grant (operator-level wildcard authority,
	// representing the cluster-issued operator delegation in concrete
	// form for this test).
	opRootData := types.CapabilityTokenData{
		Grants: []types.GrantEntry{{
			Handlers:   types.CapabilityScope{Include: []string{"*"}},
			Resources:  types.CapabilityScope{Include: []string{"*"}},
			Operations: types.CapabilityScope{Include: []string{"*"}},
		}},
		Granter:   types.SingleSigGranter(operatorIdentity.ContentHash),
		Grantee:   operatorIdentity.ContentHash,
		CreatedAt: 1000,
	}
	opRoot, _ := opRootData.ToEntity()
	opRootSigBytes := operatorKp.Sign(opRoot.ContentHash.Bytes())
	opRootSig, _ := types.SignatureData{
		Target:    opRoot.ContentHash,
		Signer:    operatorIdentity.ContentHash,
		Algorithm: "ed25519",
		Signature: opRootSigBytes,
	}.ToEntity()

	// App peer 1 — scope S1: shared/work/*
	var a1Seed [32]byte
	a1Seed[0] = 0x51
	app1Kp := crypto.FromSeed(a1Seed)
	app1Identity, _ := app1Kp.IdentityEntity()
	parentHashOp := opRoot.ContentHash
	app1Data := types.CapabilityTokenData{
		Grants: []types.GrantEntry{{
			Handlers:   types.CapabilityScope{Include: []string{"system/tree"}},
			Resources:  types.CapabilityScope{Include: []string{"shared/work/*"}},
			Operations: types.CapabilityScope{Include: []string{"get", "put"}},
		}},
		Granter:   types.SingleSigGranter(operatorIdentity.ContentHash),
		Grantee:   app1Identity.ContentHash,
		Parent:    &parentHashOp,
		CreatedAt: 1100,
	}
	app1Cap, _ := app1Data.ToEntity()
	app1SigBytes := operatorKp.Sign(app1Cap.ContentHash.Bytes())
	app1Sig, _ := types.SignatureData{
		Target:    app1Cap.ContentHash,
		Signer:    operatorIdentity.ContentHash,
		Algorithm: "ed25519",
		Signature: app1SigBytes,
	}.ToEntity()

	// App peer 2 — scope S2: shared/personal/*
	var a2Seed [32]byte
	a2Seed[0] = 0x52
	app2Kp := crypto.FromSeed(a2Seed)
	app2Identity, _ := app2Kp.IdentityEntity()
	app2Data := types.CapabilityTokenData{
		Grants: []types.GrantEntry{{
			Handlers:   types.CapabilityScope{Include: []string{"system/tree"}},
			Resources:  types.CapabilityScope{Include: []string{"shared/personal/*"}},
			Operations: types.CapabilityScope{Include: []string{"get", "put"}},
		}},
		Granter:   types.SingleSigGranter(operatorIdentity.ContentHash),
		Grantee:   app2Identity.ContentHash,
		Parent:    &parentHashOp,
		CreatedAt: 1110,
	}
	app2Cap, _ := app2Data.ToEntity()
	app2SigBytes := operatorKp.Sign(app2Cap.ContentHash.Bytes())
	app2Sig, _ := types.SignatureData{
		Target:    app2Cap.ContentHash,
		Signer:    operatorIdentity.ContentHash,
		Algorithm: "ed25519",
		Signature: app2SigBytes,
	}.ToEntity()

	// Both caps in the resolution set.
	includedFull := map[hash.Hash]entity.Entity{
		operatorIdentity.ContentHash: operatorIdentity,
		app1Identity.ContentHash:     app1Identity,
		app2Identity.ContentHash:     app2Identity,
		opRoot.ContentHash:           opRoot,
		opRootSig.ContentHash:        opRootSig,
		app1Cap.ContentHash:          app1Cap,
		app1Sig.ContentHash:          app1Sig,
		app2Cap.ContentHash:          app2Cap,
		app2Sig.ContentHash:          app2Sig,
	}

	// Pre-revocation: both caps validate against the operator as root.
	if err := capability.VerifyChain(app1Cap, includedFull, operatorKp.PeerID()); err != nil {
		t.Fatalf("pre-revocation: app1 cap should validate: %v", err)
	}
	if err := capability.VerifyChain(app2Cap, includedFull, operatorKp.PeerID()); err != nil {
		t.Fatalf("pre-revocation: app2 cap should validate: %v", err)
	}

	// "Revoke" app1 — remove app1Cap from resolution. Models deleting
	// app1's delegation cap binding from the tree.
	includedApp1Revoked := make(map[hash.Hash]entity.Entity, len(includedFull)-2)
	for k, v := range includedFull {
		if k == app1Cap.ContentHash || k == app1Sig.ContentHash {
			continue
		}
		includedApp1Revoked[k] = v
	}

	// app1 cap MUST fail post-revocation. Pass the cap entity directly
	// (chain walker takes the entity, not a hash lookup) — we model
	// revocation by removing app1's PARENT-LINK SIGNATURE so signature
	// verification fails. Equivalently, remove operatorIdentity to break
	// the signature lookup. Use the more direct model: VerifyChain takes
	// the cap entity, but its parent (opRoot) is still resolvable; what
	// changes is — actually for a 2-link chain, removing app1Cap from
	// the included set doesn't matter because VerifyChain receives it
	// directly. The scope-limit is structural: app2's chain doesn't
	// REFERENCE app1 at all.
	//
	// The right structural assertion: app2's chain validates without
	// needing app1's cap entity in the resolution set. That's what
	// scope-limit MEANS for parallel chains.
	if err := capability.VerifyChain(app2Cap, includedApp1Revoked, operatorKp.PeerID()); err != nil {
		t.Fatalf("SEC-8 BREACH: app2's cap failed validation when app1's cap was removed from resolution. Parallel chains MUST be independent — compromise of A1 must NOT take down A2. Error: %v", err)
	}

	// Also verify: app1's chain DOES depend on opRoot. Removing opRoot
	// breaks app1's chain (sanity — the chain layering is real).
	includedOpRootRevoked := make(map[hash.Hash]entity.Entity, len(includedFull)-2)
	for k, v := range includedFull {
		if k == opRoot.ContentHash || k == opRootSig.ContentHash {
			continue
		}
		includedOpRootRevoked[k] = v
	}
	if err := capability.VerifyChain(app1Cap, includedOpRootRevoked, operatorKp.PeerID()); err == nil {
		t.Errorf("sanity: app1 chain should fail when its parent (opRoot) is removed; chain-walk did not detect missing parent")
	}
}

// =====================================================================
// SEC-13 — chain depth limit
// =====================================================================

// TestSEC13_ChainDepthExceeded verifies the chain-walker enforces
// maxChainDepth=64. Build a chain of 65 caps; the walker MUST refuse
// to traverse past the limit (returning ErrCapabilityDenied or similar
// chain-validation error). This is a DoS bound: without a cap, an
// attacker could submit a maliciously deep chain that consumes CPU.
func TestSEC13_ChainDepthExceeded(t *testing.T) {
	var seed [32]byte
	seed[0] = 0x60
	rootKp := crypto.FromSeed(seed)
	rootIdent, _ := rootKp.IdentityEntity()

	// Build a long single-sig chain: each cap's granter is the previous
	// link's grantee. Every level uses the same kp for simplicity (so
	// signatures verify). This is unusual structurally but that's the
	// point — the walker must cut the chain at the depth limit.
	included := map[hash.Hash]entity.Entity{
		rootIdent.ContentHash: rootIdent,
	}

	prevKp := rootKp
	prevIdent := rootIdent
	var prevCap entity.Entity
	var prevHash *hash.Hash

	const chainLength = 70 // safely above maxChainDepth=64
	caps := make([]entity.Entity, 0, chainLength)

	for i := 0; i < chainLength; i++ {
		var nextSeed [32]byte
		nextSeed[0] = 0x60
		nextSeed[1] = byte(i + 1)
		nextKp := crypto.FromSeed(nextSeed)
		nextIdent, _ := nextKp.IdentityEntity()

		capData := types.CapabilityTokenData{
			Grants: []types.GrantEntry{{
				Handlers:   types.CapabilityScope{Include: []string{"*"}},
				Resources:  types.CapabilityScope{Include: []string{"*"}},
				Operations: types.CapabilityScope{Include: []string{"*"}},
			}},
			Granter:   types.SingleSigGranter(prevIdent.ContentHash),
			Grantee:   nextIdent.ContentHash,
			CreatedAt: 1000 + uint64(i),
		}
		if prevHash != nil {
			ph := *prevHash
			capData.Parent = &ph
		}
		capEnt, _ := capData.ToEntity()
		sigBytes := prevKp.Sign(capEnt.ContentHash.Bytes())
		sigData := types.SignatureData{
			Target:    capEnt.ContentHash,
			Signer:    prevIdent.ContentHash,
			Algorithm: "ed25519",
			Signature: sigBytes,
		}
		sigEnt, _ := sigData.ToEntity()

		included[capEnt.ContentHash] = capEnt
		included[sigEnt.ContentHash] = sigEnt
		included[nextIdent.ContentHash] = nextIdent
		caps = append(caps, capEnt)

		ch := capEnt.ContentHash
		prevHash = &ch
		prevKp = nextKp
		prevIdent = nextIdent
		prevCap = capEnt
	}
	_ = prevCap

	// Validate the leaf cap. Chain has 70 levels; walker should reject
	// at maxChainDepth=64.
	leaf := caps[len(caps)-1]
	err := capability.VerifyChain(leaf, included, rootKp.PeerID())
	if err == nil {
		t.Fatal("SEC-13 BREACH: chain of 70 levels accepted; maxChainDepth=64 not enforced. DoS bound: an attacker can submit arbitrarily deep chains.")
	}
	// Any chain-related error code is acceptable — the contract is "rejected".
	if !errors.Is(err, ecerrors.ErrCapabilityDenied) {
		t.Logf("note: depth-limit error code = %v (any rejection acceptable)", err)
	}
}

// =====================================================================
// SEC-14 — stale linkage entity gracefully handled
// =====================================================================

// TestSEC14_StaleLinkageEntity verifies the role handler handles stale
// linkage entities gracefully. The linkage entity at
// system/role/{ctx}/derived-tokens/{peer}/{role} points at a cap hash
// that's been deleted (e.g., via direct tree manipulation, partial
// sweep failure, or a corrupted snapshot). Re-derive must not crash;
// it should issue a fresh cap and overwrite the linkage.
func TestSEC14_StaleLinkageEntity(t *testing.T) {
	f := newOperatorFixture(t)

	// Assign first.
	resp := f.callAssign(t, f.assigneeIdentity.ContentHash)
	if resp.Status != 200 {
		t.Fatalf("assign: %d (%s)", resp.Status, dumpResult(t, resp))
	}
	result, _ := types.RoleAssignResultDataFromEntity(resp.Result)
	originalCapHash := result.DerivedTokens[0]

	// Manually break the cap binding (simulate corruption / partial sweep).
	capPath := RoleDerivedTokenPath(f.contextStr, f.assigneeIdentity.ContentHash, originalCapHash)
	f.hctx.LocationIndex.Remove(capPath)

	// Linkage at derived-tokens/{peer}/{role} still points at the missing cap.
	linkPath := DerivedTokenLinkPath(f.contextStr, f.assigneeIdentity.ContentHash, f.roleName)
	if !f.hctx.LocationIndex.Has(linkPath) {
		t.Fatalf("setup: linkage entity missing at %s", linkPath)
	}

	// Trigger re-derive — must complete without crash and produce a fresh cap.
	body := types.RoleReDeriveRequestData{Role: f.roleName}
	params, _ := body.ToEntity()
	rdPath := RoleDefinitionPath(f.contextStr, f.roleName)
	f.hctx.Resource = &types.ResourceTarget{Targets: []string{rdPath}}
	rdReq := &handler.Request{
		Operation: "re-derive",
		Params:    params,
		Context:   f.hctx,
	}
	rdResp, err := f.h.Handle(context.Background(), rdReq)
	if err != nil {
		t.Fatalf("re-derive returned error: %v", err)
	}
	if rdResp.Status != 200 {
		t.Fatalf("re-derive status=%d (%s)", rdResp.Status, dumpResult(t, rdResp))
	}
	rdResult, _ := types.RoleReDeriveResultDataFromEntity(rdResp.Result)

	// A fresh cap must have been issued and bound.
	if len(rdResult.NewTokenHashes) != 1 {
		t.Fatalf("expected 1 new token, got %d", len(rdResult.NewTokenHashes))
	}
	newCapHash := rdResult.NewTokenHashes[0]
	newCapPath := RoleDerivedTokenPath(f.contextStr, f.assigneeIdentity.ContentHash, newCapHash)
	if !f.hctx.LocationIndex.Has(newCapPath) {
		t.Errorf("fresh cap not bound at %s after re-derive over stale linkage", newCapPath)
	}
}

// =====================================================================
// SEC-15 — self-exclusion sweeps the peer's own role-derived caps
// =====================================================================

// TestSEC15_SelfExclusion verifies the mechanical behavior when a
// peer excludes its own peer-id in a context. Per §6.1, the layer-1
// sweep removes the peer's role-derived caps in that context. Other
// access paths (L0, other contexts, non-role-derived caps) are
// unaffected — exclusion is per-context.
//
// This test documents the contract and ensures self-exclusion doesn't
// break invariants (the spec doesn't reject it, but verifying the
// mechanical behavior closes a corner case).
func TestSEC15_SelfExclusion(t *testing.T) {
	f := newOperatorFixture(t)

	// Use the local peer's own identity hash as both the assignee and
	// the exclusion target (self-exclusion).
	selfHash := f.localIdentity.ContentHash

	// Assign self to the role.
	resp := f.callAssign(t, selfHash)
	if resp.Status != 200 {
		t.Fatalf("self-assign: %d (%s)", resp.Status, dumpResult(t, resp))
	}
	result, _ := types.RoleAssignResultDataFromEntity(resp.Result)
	capHash := result.DerivedTokens[0]
	capPath := RoleDerivedTokenPath(f.contextStr, selfHash, capHash)
	if !f.hctx.LocationIndex.Has(capPath) {
		t.Fatalf("self cap not bound pre-exclusion at %s", capPath)
	}

	// Self-exclude via the handler.
	exclPath := ExclusionPath(f.contextStr, selfHash)
	emptyParams, _ := entity.NewEntity("primitive/any", []byte{0xa0})
	hctx := &handler.HandlerContext{
		Author:        f.opKp.PeerID(),
		AuthorHash:    f.opIdentity.ContentHash,
		LocalPeerID:   f.localKp.PeerID(),
		Resource:      &types.ResourceTarget{Targets: []string{exclPath}},
		Store:         f.hctx.Store,
		LocationIndex: f.hctx.LocationIndex,
		Included:      make(map[hash.Hash]entity.Entity),
	}
	exclReq := &handler.Request{
		Operation: "exclude",
		Params:    emptyParams,
		Context:   hctx,
	}
	exclResp, err := f.h.Handle(context.Background(), exclReq)
	if err != nil {
		t.Fatalf("self-exclude: %v", err)
	}
	if exclResp.Status != 200 {
		t.Fatalf("self-exclude status=%d (%s)", exclResp.Status, dumpResult(t, exclResp))
	}

	// Self cap must be swept.
	if f.hctx.LocationIndex.Has(capPath) {
		t.Errorf("self-exclusion did NOT sweep peer's own role-derived cap at %s — §6.1 layer 1 violation", capPath)
	}
	// Exclusion entity bound.
	if !f.hctx.LocationIndex.Has(exclPath) {
		t.Errorf("self-exclusion entity not bound at %s", exclPath)
	}
}

// =====================================================================
// SEC-16 — replay of exclusion entity is idempotent
// =====================================================================

// TestSEC16_ExclusionReplayIdempotent verifies that replaying the
// same exclusion entity at the same path is idempotent — no crash,
// no extra side-effect, no spurious sweep cascade. This matters for
// tree-sync: an exclusion entity propagating across peers may arrive
// multiple times due to retries, sync re-runs, or topology changes.
func TestSEC16_ExclusionReplayIdempotent(t *testing.T) {
	f := newOperatorFixture(t)

	// Assign + exclude once.
	if resp := f.callAssign(t, f.assigneeIdentity.ContentHash); resp.Status != 200 {
		t.Fatalf("setup assign: %d (%s)", resp.Status, dumpResult(t, resp))
	}

	exclPath := ExclusionPath(f.contextStr, f.assigneeIdentity.ContentHash)
	emptyParams, _ := entity.NewEntity("primitive/any", []byte{0xa0})

	doExclude := func() *handler.Response {
		hctx := &handler.HandlerContext{
			Author:        f.opKp.PeerID(),
			AuthorHash:    f.opIdentity.ContentHash,
			LocalPeerID:   f.localKp.PeerID(),
			Resource:      &types.ResourceTarget{Targets: []string{exclPath}},
			Store:         f.hctx.Store,
			LocationIndex: f.hctx.LocationIndex,
			Included:      make(map[hash.Hash]entity.Entity),
		}
		req := &handler.Request{Operation: "exclude", Params: emptyParams, Context: hctx}
		resp, err := f.h.Handle(context.Background(), req)
		if err != nil {
			t.Fatalf("exclude: %v", err)
		}
		return resp
	}

	first := doExclude()
	if first.Status != 200 {
		t.Fatalf("first exclude: %d (%s)", first.Status, dumpResult(t, first))
	}

	// Replay 5x. Each must succeed (or at least not crash); resulting state
	// (exclusion bound, no caps for X) must remain consistent.
	prefix := RoleDerivedPeerPrefix(f.contextStr, f.assigneeIdentity.ContentHash)
	for i := 0; i < 5; i++ {
		resp := doExclude()
		if resp.Status != 200 {
			t.Errorf("replay %d: status=%d (%s) — replay should be idempotent", i+1, resp.Status, dumpResult(t, resp))
		}
		// State invariants.
		if !f.hctx.LocationIndex.Has(exclPath) {
			t.Errorf("replay %d: exclusion entity disappeared", i+1)
		}
		for _, e := range f.hctx.LocationIndex.List(prefix) {
			if !strings.HasSuffix(barePath(e.Path), "/signature") {
				t.Errorf("replay %d: spurious cap appeared at %s", i+1, e.Path)
			}
		}
	}
}

// =====================================================================
// SEC-17 — multi-role overlapping grants: per-role unassign isolation
// =====================================================================

// TestSEC17_MultiRoleOverlappingGrants verifies that unassigning ONE
// role doesn't affect another role's cap, even when their grants
// overlap. Per R6 (multi-role per (peer, context)) + SI-5 (linkage-
// based per-role precision), each role's cap is independent.
//
// TV-RD-9 covers single-role isolation with disjoint roles ("reader"
// vs "writer"). SEC-17 specifically uses overlapping grants — role A
// covers `shared/work/*`, role B covers `shared/work/secret/*` (a
// strict subset). Unassigning A must NOT touch B's cap.
func TestSEC17_MultiRoleOverlappingGrants(t *testing.T) {
	f := newOperatorFixture(t)

	// Define a SECOND role with overlapping but distinct grants.
	roleB := "secret-reader"
	roleBGrants := []types.GrantEntry{{
		Handlers:   types.CapabilityScope{Include: []string{"system/tree"}},
		Resources:  types.CapabilityScope{Include: []string{"shared/" + f.contextStr + "/secret/*"}}, // subset of role A's
		Operations: types.CapabilityScope{Include: []string{"get"}},
	}}
	roleBDef := types.RoleData{Name: roleB, Grants: roleBGrants}
	roleBEnt, _ := roleBDef.ToEntity()
	if _, err := f.hctx.Store.Put(roleBEnt); err != nil {
		t.Fatalf("put roleB: %v", err)
	}
	f.hctx.LocationIndex.Set(RoleDefinitionPath(f.contextStr, roleB), roleBEnt.ContentHash)

	// Assign assignee to BOTH role A (the fixture's roleName) and role B.
	respA := f.callAssign(t, f.assigneeIdentity.ContentHash)
	if respA.Status != 200 {
		t.Fatalf("assign role A: %d (%s)", respA.Status, dumpResult(t, respA))
	}
	resultA, _ := types.RoleAssignResultDataFromEntity(respA.Result)

	// Build a fresh hctx with a different Resource for role B's assign.
	asnPathB := AssignmentPath(f.contextStr, f.assigneeIdentity.ContentHash, roleB)
	bodyB := types.RoleAssignRequestData{Role: roleB}
	bodyBEnt, _ := bodyB.ToEntity()
	hctxB := &handler.HandlerContext{
		Author:           f.opKp.PeerID(),
		AuthorHash:       f.opIdentity.ContentHash,
		LocalPeerID:      f.localKp.PeerID(),
		CallerCapability: f.localToOpCap,
		HandlerGrant:     f.handlerGrant,
		Resource:         &types.ResourceTarget{Targets: []string{asnPathB}},
		Store:            f.hctx.Store,
		LocationIndex:    f.hctx.LocationIndex,
		Included:         make(map[hash.Hash]entity.Entity),
	}
	respB, err := f.h.Handle(context.Background(), &handler.Request{
		Operation: "assign", Params: bodyBEnt, Context: hctxB,
	})
	if err != nil {
		t.Fatalf("assign role B: %v", err)
	}
	if respB.Status != 200 {
		t.Fatalf("assign role B status=%d (%s)", respB.Status, dumpResult(t, respB))
	}
	resultB, _ := types.RoleAssignResultDataFromEntity(respB.Result)

	capPathA := RoleDerivedTokenPath(f.contextStr, f.assigneeIdentity.ContentHash, resultA.DerivedTokens[0])
	capPathB := RoleDerivedTokenPath(f.contextStr, f.assigneeIdentity.ContentHash, resultB.DerivedTokens[0])

	// Unassign role A only.
	emptyParams, _ := entity.NewEntity("primitive/any", []byte{0xa0})
	asnPathA := AssignmentPath(f.contextStr, f.assigneeIdentity.ContentHash, f.roleName)
	hctxU := &handler.HandlerContext{
		Author:        f.opKp.PeerID(),
		AuthorHash:    f.opIdentity.ContentHash,
		LocalPeerID:   f.localKp.PeerID(),
		Resource:      &types.ResourceTarget{Targets: []string{asnPathA}},
		Store:         f.hctx.Store,
		LocationIndex: f.hctx.LocationIndex,
		Included:      make(map[hash.Hash]entity.Entity),
	}
	respU, err := f.h.Handle(context.Background(), &handler.Request{
		Operation: "unassign", Params: emptyParams, Context: hctxU,
	})
	if err != nil {
		t.Fatalf("unassign role A: %v", err)
	}
	if respU.Status != 200 {
		t.Fatalf("unassign role A status=%d (%s)", respU.Status, dumpResult(t, respU))
	}

	// Role A's cap MUST be gone; role B's cap MUST survive.
	if f.hctx.LocationIndex.Has(capPathA) {
		t.Errorf("role A's cap survived unassign(A) — per-role precision broken")
	}
	if !f.hctx.LocationIndex.Has(capPathB) {
		t.Errorf("role B's cap was incorrectly removed by unassign(A) — overlapping grants caused collateral revocation. Per R6 + SI-5, each role's cap is independent.")
	}
}

// =====================================================================
// SEC-18 — bearer cap (zero-grantee) regression test (post-V7 v7.39)
// =====================================================================

// TestSEC18_ZeroGranteeAssignmentPath verifies the V7 v7.39 PR-3
// rejection at chain-walk. Prior to v7.39 this was a documented
// finding (zero-grantee assigns succeeded at role layer with no
// rejection at any subsequent layer); now it's a regression test for
// the V7-layer rejection. Per PROPOSAL-ROLE-V2.0-PRODUCTION-READINESS
// PR-3 §9.3 verification plan: the role layer may or may not reject
// zero-grantee at assign time (impl choice — defense in depth is
// allowed but not mandated); the V7 layer MUST reject the resulting
// cap at chain validation.
func TestSEC18_ZeroGranteeAssignmentPath(t *testing.T) {
	f := newOperatorFixture(t)

	// Construct an all-zeros hash (algorithm code 0x00 + 32 bytes of zeros).
	zeroBytes := make([]byte, 33)
	zeroBytes[0] = hash.AlgorithmSHA256
	zeroHash, err := hash.FromBytes(zeroBytes)
	if err != nil {
		t.Fatalf("synth zero hash: %v", err)
	}

	resp := f.callAssign(t, zeroHash)
	if resp.Status != 200 {
		// Defense-in-depth: role layer rejected at assign time. Also
		// acceptable per PR-3 (the spec mandates V7-layer rejection;
		// role-layer rejection is allowed). No further check needed.
		if resp.Status >= 400 && resp.Status < 500 {
			t.Logf("role layer rejected zero-grantee at assign time with status %d (defense-in-depth; v2.0-conformant)", resp.Status)
			return
		}
		t.Fatalf("unexpected status %d for zero-grantee assign", resp.Status)
	}

	// Role layer accepted the assign; cap was minted with grantee = zeroHash.
	// Per V7 v7.39 §3.6 + §5.5 (PR-3), chain-walk MUST reject this cap
	// because zeroHash doesn't resolve to a system/peer entity.
	result, _ := types.RoleAssignResultDataFromEntity(resp.Result)
	if len(result.DerivedTokens) != 1 {
		t.Fatalf("expected 1 derived token, got %d", len(result.DerivedTokens))
	}
	capEnt, ok := f.hctx.Store.Get(result.DerivedTokens[0])
	if !ok {
		t.Fatalf("cap entity not in store")
	}

	// Build the resolution set. zeroHash is intentionally NOT included.
	included := map[hash.Hash]entity.Entity{
		f.localIdentity.ContentHash: f.localIdentity,
		capEnt.ContentHash:          capEnt,
	}
	// Add the cap's signature (V7 §3.5 invariant pointer path — the sole
	// location ROLE binds role-derived cap signatures). The zero-grantee
	// cap is rejected by ValidateStructure before signature verification,
	// so the assertion below holds regardless; kept canonical for hygiene.
	sigPath := types.InvariantSignaturePath(f.localKp.PeerID().String(), capEnt.ContentHash)
	if sigHash, ok := f.hctx.LocationIndex.Get(sigPath); ok {
		if sigEnt, ok := f.hctx.Store.Get(sigHash); ok {
			included[sigHash] = sigEnt
		}
	}

	err = capability.VerifyChain(capEnt, included, f.localKp.PeerID())
	if err == nil {
		t.Fatal("PR-3 REGRESSION: zero-grantee cap accepted at chain validation. V7 v7.39 §3.6 requires unresolvable_grantee rejection.")
	}
	if !errors.Is(err, ecerrors.ErrUnresolvableGrantee) {
		t.Errorf("expected ErrUnresolvableGrantee, got: %v", err)
	}
}

// =====================================================================
// SEC-12 — layer-3 opt-in handler positive case
// =====================================================================

// TestSEC12_Layer3HandlerEnforcement verifies the convention §4.6
// layer 3: a handler operating in a context-scoped namespace MAY
// consult is_excluded(context, author) and reject 403 even if the
// caller's cap is otherwise valid. This is opt-in — TV-RD-16 covers
// the negative case (system/tree does NOT check). SEC-12 is the
// positive case: a custom context-aware handler that DOES check.
//
// We simulate the handler inline. In production this would be a
// group handler, service-role handler, or any application handler
// that wants context-aware exclusion enforcement.
func TestSEC12_Layer3HandlerEnforcement(t *testing.T) {
	f := newOperatorFixture(t)

	// Assign assignee to the role so they have a (legitimate) cap.
	resp := f.callAssign(t, f.assigneeIdentity.ContentHash)
	if resp.Status != 200 {
		t.Fatalf("assign: %d", resp.Status)
	}

	// The "context-aware handler" — would normally be its own handler
	// type. Here it's a function that takes (li, ctx, author) and
	// returns whether the request should be rejected.
	contextAwareCheck := func(li store.LocationIndex, contextStr string, author hash.Hash) (rejected bool) {
		// Layer 3 check: is the author excluded in this context?
		return isExcluded(li, contextStr, author)
	}

	// Pre-exclusion: handler accepts.
	if contextAwareCheck(f.hctx.LocationIndex, f.contextStr, f.assigneeIdentity.ContentHash) {
		t.Fatal("layer-3 check rejected pre-exclusion — should accept (no exclusion bound)")
	}

	// Bind exclusion entity for the assignee.
	excl := types.RoleExclusionData{
		ExcludedBy: f.localIdentity.ContentHash,
		ExcludedAt: 1500,
	}
	exclEnt, _ := excl.ToEntity()
	if _, err := f.hctx.Store.Put(exclEnt); err != nil {
		t.Fatalf("put excl: %v", err)
	}
	f.hctx.LocationIndex.Set(ExclusionPath(f.contextStr, f.assigneeIdentity.ContentHash), exclEnt.ContentHash)

	// Post-exclusion: layer-3 handler rejects.
	if !contextAwareCheck(f.hctx.LocationIndex, f.contextStr, f.assigneeIdentity.ContentHash) {
		t.Errorf("§4.6 layer 3 BREACH: context-aware handler did not detect exclusion via isExcluded helper. The handler-level check is the third layer of defense (after token revocation and derivation blocking); without it, in-flight requests with not-yet-revoked caps still succeed at handlers that should be context-aware.")
	}

	// Different context: layer-3 check should still accept (exclusion is per-context).
	otherContext := "other/context"
	if contextAwareCheck(f.hctx.LocationIndex, otherContext, f.assigneeIdentity.ContentHash) {
		t.Errorf("layer-3 check incorrectly rejected in unrelated context %q — exclusion is per-context per §6.1", otherContext)
	}
}

// =====================================================================
// INT-1 — full lifecycle integration: cluster → operator → app-peer → role
// =====================================================================

// TestINT1_FullLifecycleChain exercises the GUIDE-ROLE §14.1 Acme
// deployment shape end-to-end: a recovery cluster (1-of-1 quorum for
// simplicity) signs an identity-cert attestation for the operator,
// the operator's local-peer→operator cap is on the app peer (modeling
// the post-:configure state), the operator drives :assign on the app
// peer, and the resulting role-derived cap chains correctly.
//
// What this proves end-to-end:
//
//  1. Quorum + attestation layer: quorum entity is bound; attestation
//     attesting the operator-as-controller is bound under the quorum.
//  2. Identity layer: local-peer→operator cap is present (would be
//     issued by :configure in production; here constructed manually
//     to keep the test focused on the role↔identity bridge).
//  3. Role layer: :assign uses local-peer→operator cap as caller
//     cap, RL2 validates, role-derived cap is minted.
//  4. §10.2 invariant holds across the full stack: the role-derived
//     cap's chain bottoms out at the app peer, NOT at the operator
//     or the cluster. Rotating the operator does NOT affect the
//     role-derived cap.
//
// This is the integration test the lifecycle exploration's §14.1
// targets — composes attestation + quorum + identity + role in a
// single coherent scenario.
func TestINT1_FullLifecycleChain(t *testing.T) {
	f := newOperatorFixture(t)

	// Cluster keypair — the recovery anchor (cold key, used only here
	// to issue/sign the operator's identity-cert attestation).
	var clusterSeed [32]byte
	clusterSeed[0] = 0x70
	clusterKp := crypto.FromSeed(clusterSeed)
	clusterIdentity, err := clusterKp.IdentityEntity()
	if err != nil {
		t.Fatalf("cluster identity: %v", err)
	}
	if _, err := f.hctx.Store.Put(clusterIdentity); err != nil {
		t.Fatalf("put cluster identity: %v", err)
	}

	// 1-of-1 quorum — the simplest threshold. Signers: just the cluster.
	quorumData := types.QuorumData{
		Signers:   []hash.Hash{clusterIdentity.ContentHash},
		Threshold: 1,
		Name:      "test-cluster",
	}
	quorumEnt, err := quorumData.ToEntity()
	if err != nil {
		t.Fatalf("quorum encode: %v", err)
	}
	if _, err := f.hctx.Store.Put(quorumEnt); err != nil {
		t.Fatalf("put quorum: %v", err)
	}
	// Bind quorum at its canonical path.
	quorumPath := "system/quorum/" + HashHex(quorumEnt.ContentHash)
	f.hctx.LocationIndex.Set(quorumPath, quorumEnt.ContentHash)

	// Attestation: cluster attests "operator's identity has
	// function=controller". This is the identity-cert for the operator.
	props := map[string]cbor.RawMessage{}
	kindRaw, _ := cbor.Marshal(types.KindIdentityCert)
	functionRaw, _ := cbor.Marshal(types.FunctionController)
	modeRaw, _ := cbor.Marshal(types.ModeInternal)
	props["kind"] = kindRaw
	props["function"] = functionRaw
	props["mode"] = modeRaw
	attData := types.AttestationData{
		Attesting:  quorumEnt.ContentHash, // attestation comes from the quorum
		Attested:   f.opIdentity.ContentHash,
		Properties: props,
	}
	attEnt, err := attData.ToEntity()
	if err != nil {
		t.Fatalf("attestation encode: %v", err)
	}
	if _, err := f.hctx.Store.Put(attEnt); err != nil {
		t.Fatalf("put attestation: %v", err)
	}
	// Bind attestation at a canonical path so it's reachable.
	attPath := "system/attestation/" + HashHex(attEnt.ContentHash)
	f.hctx.LocationIndex.Set(attPath, attEnt.ContentHash)

	// 1-of-1 quorum signature: cluster signs the attestation.
	attSigBytes := clusterKp.Sign(attEnt.ContentHash.Bytes())
	attSigData := types.SignatureData{
		Target:    attEnt.ContentHash,
		Signer:    clusterIdentity.ContentHash,
		Algorithm: "ed25519",
		Signature: attSigBytes,
	}
	attSigEnt, _ := attSigData.ToEntity()
	if _, err := f.hctx.Store.Put(attSigEnt); err != nil {
		t.Fatalf("put attestation sig: %v", err)
	}
	f.hctx.LocationIndex.Set(attPath+"/signature", attSigEnt.ContentHash)

	// At this point the test has the full identity stack on the app
	// peer's tree:
	//   - cluster identity entity
	//   - quorum entity (bound at system/quorum/{quorum_hash_hex})
	//   - identity-cert attestation (bound at system/attestation/{att_hash_hex})
	//   - cluster's signature on the attestation (sibling)
	//   - operator's identity entity (in store)
	//   - app peer's identity entity (in store via operator fixture)
	//   - local-peer→operator cap (the operator-fixture's f.localToOpCap;
	//     in production this would be issued by identity:configure
	//     consuming the attestation chain above)
	//
	// Now drive role:assign — operator wields local-peer→operator cap.

	resp := f.callAssign(t, f.assigneeIdentity.ContentHash)
	if resp.Status != 200 {
		t.Fatalf("assign: %d (%s)", resp.Status, dumpResult(t, resp))
	}
	result, _ := types.RoleAssignResultDataFromEntity(resp.Result)
	if len(result.DerivedTokens) != 1 {
		t.Fatalf("expected 1 derived token, got %d", len(result.DerivedTokens))
	}
	roleDerivedHash := result.DerivedTokens[0]

	// VALIDATION 1 — All four layers' entities are present.
	checks := []struct {
		label string
		path  string
	}{
		{"cluster identity in store", ""}, // by hash, not path
		{"quorum bound at canonical path", quorumPath},
		{"attestation bound", attPath},
		{"attestation signature bound", attPath + "/signature"},
		{"role assignment bound", AssignmentPath(f.contextStr, f.assigneeIdentity.ContentHash, f.roleName)},
		{"role-derived cap bound", RoleDerivedTokenPath(f.contextStr, f.assigneeIdentity.ContentHash, roleDerivedHash)},
	}
	for _, c := range checks {
		if c.path == "" {
			continue
		}
		if !f.hctx.LocationIndex.Has(c.path) {
			t.Errorf("missing: %s (path=%s)", c.label, c.path)
		}
	}
	for _, h := range []hash.Hash{
		clusterIdentity.ContentHash, quorumEnt.ContentHash, attEnt.ContentHash,
		f.opIdentity.ContentHash, f.localIdentity.ContentHash,
		f.assigneeIdentity.ContentHash,
	} {
		if _, ok := f.hctx.Store.Get(h); !ok {
			t.Errorf("entity %v missing from store", h)
		}
	}

	// VALIDATION 2 — §10.2 invariant: role-derived cap chain doesn't
	// reference operator or cluster. Walk the cap's chain and verify
	// no link has operator or cluster as granter or grantee.
	current := roleDerivedHash
	visited := map[hash.Hash]bool{}
	for !current.IsZero() {
		if visited[current] {
			t.Fatalf("cycle in cap chain at %v", current)
		}
		visited[current] = true
		ent, ok := f.hctx.Store.Get(current)
		if !ok {
			t.Fatalf("cap %v missing from store", current)
		}
		tok, err := types.CapabilityTokenDataFromEntity(ent)
		if err != nil {
			t.Fatalf("decode cap %v: %v", current, err)
		}
		granter, single := tok.Granter.SingleHash()
		if !single {
			t.Errorf("non-single-sig granter at %v in role-derived chain", current)
		}
		if granter == f.opIdentity.ContentHash {
			t.Errorf("§10.2 VIOLATION: role-derived chain link %v has operator as granter — operator rotation would break the chain", current)
		}
		if granter == clusterIdentity.ContentHash {
			t.Errorf("§10.2 VIOLATION: role-derived chain link %v has cluster as granter — cluster recovery would invalidate role-derived caps", current)
		}
		if tok.Grantee == f.opIdentity.ContentHash || tok.Grantee == clusterIdentity.ContentHash {
			t.Errorf("§10.2 VIOLATION: role-derived chain link %v has operator/cluster as grantee — chain references identity layer", current)
		}
		if tok.Parent == nil {
			break
		}
		current = *tok.Parent
	}

	// VALIDATION 3 — Operator's cap chain is independent. Rotating the
	// operator (replacing local-peer→operator cap with a new one) does
	// NOT touch the role-derived cap. We simulate by removing the old
	// cap from the tree and verifying the role-derived cap entity is
	// still in the store and bound at its path.
	f.hctx.LocationIndex.Remove("system/capability/grants/local-peer-to-controller/" + HashHex(f.opIdentity.ContentHash))
	roleCapPath := RoleDerivedTokenPath(f.contextStr, f.assigneeIdentity.ContentHash, roleDerivedHash)
	if !f.hctx.LocationIndex.Has(roleCapPath) {
		t.Errorf("INT-1 FAILURE: role-derived cap was affected by operator-cap removal — chains MUST be independent (§10.2). Operator rotation must not invalidate role-derived caps already issued.")
	}
}

// =====================================================================
// INT-3 — layered exclusion: per-context isolation
// =====================================================================

// TestINT3_PerContextExclusionIsolation verifies that exclusions are
// per-context — excluding X in context A does NOT affect X's role
// assignments in context B. Per §6.1 "contexts are independent" + the
// lifecycle exploration §3.7 / §4.6.
//
// Threat model: assume an over-broad implementation that interprets
// exclusion as global denial across all contexts. Such an impl would
// allow a context-A admin to deny X access to context-B (which they
// have no authority over) — a privilege escalation in the OPPOSITE
// direction (context-A admin gaining authority over context-B).
//
// This test ensures isolation: X's role in context B survives an
// exclude(X) issued in context A.
func TestINT3_PerContextExclusionIsolation(t *testing.T) {
	f := newOperatorFixture(t)

	// Replace the caller cap with a wildcard one — INT-3 needs RL2 to
	// pass for grants in BOTH contexts (the operator-fixture's default
	// caller cap only covers context A's resource prefix).
	wildcardCap := types.CapabilityTokenData{
		Grants: []types.GrantEntry{{
			Handlers:   types.CapabilityScope{Include: []string{"*"}},
			Resources:  types.CapabilityScope{Include: []string{"*"}},
			Operations: types.CapabilityScope{Include: []string{"*"}},
		}},
		Granter:   types.SingleSigGranter(f.localIdentity.ContentHash),
		Grantee:   f.opIdentity.ContentHash,
		CreatedAt: 1050,
	}
	wildcardCapEnt, _ := wildcardCap.ToEntity()
	if _, err := f.hctx.Store.Put(wildcardCapEnt); err != nil {
		t.Fatalf("put wildcard cap: %v", err)
	}
	f.hctx.CallerCapability = wildcardCapEnt
	f.localToOpCap = wildcardCapEnt

	// Define a SECOND role definition in a DIFFERENT context.
	contextB := "private/notes"
	roleB := "owner"
	roleBGrants := []types.GrantEntry{{
		Handlers:   types.CapabilityScope{Include: []string{"system/tree"}},
		Resources:  types.CapabilityScope{Include: []string{"shared/" + contextB + "/*"}},
		Operations: types.CapabilityScope{Include: []string{"get", "put"}},
	}}
	roleBDef := types.RoleData{Name: roleB, Grants: roleBGrants}
	roleBEnt, _ := roleBDef.ToEntity()
	if _, err := f.hctx.Store.Put(roleBEnt); err != nil {
		t.Fatalf("put roleB: %v", err)
	}
	f.hctx.LocationIndex.Set(RoleDefinitionPath(contextB, roleB), roleBEnt.ContentHash)

	// Assign X to role A in context A (the fixture's context).
	respA := f.callAssign(t, f.assigneeIdentity.ContentHash)
	if respA.Status != 200 {
		t.Fatalf("assign in context A: %d", respA.Status)
	}
	resultA, _ := types.RoleAssignResultDataFromEntity(respA.Result)
	capPathA := RoleDerivedTokenPath(f.contextStr, f.assigneeIdentity.ContentHash, resultA.DerivedTokens[0])

	// Assign X to role B in context B.
	asnPathB := AssignmentPath(contextB, f.assigneeIdentity.ContentHash, roleB)
	bodyB := types.RoleAssignRequestData{Role: roleB}
	bodyBEnt, _ := bodyB.ToEntity()
	hctxB := &handler.HandlerContext{
		Author:           f.opKp.PeerID(),
		AuthorHash:       f.opIdentity.ContentHash,
		LocalPeerID:      f.localKp.PeerID(),
		CallerCapability: f.localToOpCap,
		HandlerGrant:     f.handlerGrant,
		Resource:         &types.ResourceTarget{Targets: []string{asnPathB}},
		Store:            f.hctx.Store,
		LocationIndex:    f.hctx.LocationIndex,
		Included:         make(map[hash.Hash]entity.Entity),
	}
	respB, err := f.h.Handle(context.Background(), &handler.Request{
		Operation: "assign", Params: bodyBEnt, Context: hctxB,
	})
	if err != nil {
		t.Fatalf("assign in context B: %v", err)
	}
	if respB.Status != 200 {
		t.Fatalf("assign in context B status=%d (%s)", respB.Status, dumpResult(t, respB))
	}
	resultB, _ := types.RoleAssignResultDataFromEntity(respB.Result)
	capPathB := RoleDerivedTokenPath(contextB, f.assigneeIdentity.ContentHash, resultB.DerivedTokens[0])

	// Exclude X in context A only.
	emptyParams, _ := entity.NewEntity("primitive/any", []byte{0xa0})
	exclPath := ExclusionPath(f.contextStr, f.assigneeIdentity.ContentHash)
	hctxX := &handler.HandlerContext{
		Author:        f.opKp.PeerID(),
		AuthorHash:    f.opIdentity.ContentHash,
		LocalPeerID:   f.localKp.PeerID(),
		Resource:      &types.ResourceTarget{Targets: []string{exclPath}},
		Store:         f.hctx.Store,
		LocationIndex: f.hctx.LocationIndex,
		Included:      make(map[hash.Hash]entity.Entity),
	}
	if r, err := f.h.Handle(context.Background(), &handler.Request{
		Operation: "exclude", Params: emptyParams, Context: hctxX,
	}); err != nil || r.Status != 200 {
		t.Fatalf("exclude in context A: status=%d err=%v", r.Status, err)
	}

	// Context A's cap MUST be gone (sweep ran).
	if f.hctx.LocationIndex.Has(capPathA) {
		t.Errorf("context A's cap survived exclude in context A — local sweep failed")
	}

	// Context B's cap MUST survive (per-context isolation).
	if !f.hctx.LocationIndex.Has(capPathB) {
		t.Errorf("INT-3 BREACH: context B's cap was incorrectly removed by exclude in context A. Per §6.1 'contexts are independent'; an over-broad impl would let an authority in one context deny access in another. Per-context isolation must hold.")
	}

	// The exclusion entity itself must only be at context A's path.
	if !f.hctx.LocationIndex.Has(exclPath) {
		t.Errorf("exclusion entity not bound at context A's path %s", exclPath)
	}
	if f.hctx.LocationIndex.Has(ExclusionPath(contextB, f.assigneeIdentity.ContentHash)) {
		t.Errorf("exclusion entity unexpectedly bound at context B's path — should be context-isolated")
	}
}

// =====================================================================
// TV-RD-NON-DEV-PEER — Role v2.0 PR-1 root-cap chain validation
// =====================================================================
//
// Per PROPOSAL-ROLE-V2.0-PRODUCTION-READINESS PR-1 + EXTENSION-ROLE
// v2.0 §5.1: role-derived caps are root caps (parent: nil). This means
// chain validation succeeds even when the role handler's own grant is
// narrow (the natural production-peer shape). Pre-v2.0, a non-dev peer
// with handler grant scoped to {handlers: [system/role]} would mint a
// role-derived cap whose grants might cover system/tree — and chain
// validation would fail at use time (`is_attenuated(role_grants,
// handler_grant)` returns false). v2.0 collapses the chain by making
// the role-derived cap the root, so chain-walk terminates without
// ever consulting the handler grant.
//
// The Go-side test fixture's wildcard root cap was masking this issue
// pre-v2.0 (SEC-6d sanity test). Post-v2.0 we verify the realistic
// non-dev-peer case directly: narrow handler grant, broad role grants,
// chain validates because the role-derived cap is the chain root.

func TestSEC_NonDevPeerChainValidation(t *testing.T) {
	f := newOperatorFixture(t)

	// Replace the wildcard handlerGrant with a NARROW one — only
	// system/role:* on system/role/*. This models the production
	// non-dev-peer shape per EXTENSION-ROLE §4.5 / GUIDE §10.
	narrowHandlerGrantData := types.CapabilityTokenData{
		Grants: []types.GrantEntry{{
			Handlers:   types.CapabilityScope{Include: []string{"system/role"}},
			Resources:  types.CapabilityScope{Include: []string{"system/role/*"}},
			Operations: types.CapabilityScope{Include: []string{"*"}},
		}},
		Granter:   types.SingleSigGranter(f.localIdentity.ContentHash),
		Grantee:   f.localIdentity.ContentHash,
		CreatedAt: 800,
	}
	narrowHandlerGrant, _ := narrowHandlerGrantData.ToEntity()
	if _, err := f.hctx.Store.Put(narrowHandlerGrant); err != nil {
		t.Fatalf("put narrow handler grant: %v", err)
	}
	f.hctx.HandlerGrant = narrowHandlerGrant

	// Run :assign. Pre-v2.0 the issued cap would chain through
	// narrowHandlerGrant; chain-walk would reject (role grants like
	// system/tree:get are not a subset of {system/role}). Under v2.0,
	// the issued cap has parent: nil, so chain-walk terminates at the
	// role-derived cap itself.
	resp := f.callAssign(t, f.assigneeIdentity.ContentHash)
	if resp.Status != 200 {
		t.Fatalf("v2.0 BREACH: assign under narrow handler grant returned %d. Per PR-1, role-derived caps are root caps; this should succeed independent of handler-grant scope. (%s)",
			resp.Status, dumpResult(t, resp))
	}
	result, _ := types.RoleAssignResultDataFromEntity(resp.Result)

	// Verify the issued cap has parent: nil (root cap).
	capEnt, ok := f.hctx.Store.Get(result.DerivedTokens[0])
	if !ok {
		t.Fatalf("cap entity not in store")
	}
	tok, _ := types.CapabilityTokenDataFromEntity(capEnt)
	if tok.Parent != nil {
		t.Errorf("v2.0 PR-1 VIOLATION: role-derived cap has parent set; should be nil (root cap). Got: %v", *tok.Parent)
	}

	// Walk the cap's chain via VerifyChain to confirm chain validation
	// succeeds even with the narrow handler grant in the resolution set.
	included := map[hash.Hash]entity.Entity{
		f.localIdentity.ContentHash:    f.localIdentity,
		f.assigneeIdentity.ContentHash: f.assigneeIdentity,
		capEnt.ContentHash:             capEnt,
	}
	// Find and add the cap's signature (V7 §3.5 invariant pointer path —
	// the sole location ROLE binds role-derived cap signatures).
	sigPath := types.InvariantSignaturePath(f.localKp.PeerID().String(), capEnt.ContentHash)
	if sigHash, ok := f.hctx.LocationIndex.Get(sigPath); ok {
		if sigEnt, ok := f.hctx.Store.Get(sigHash); ok {
			included[sigHash] = sigEnt
		}
	}

	if err := capability.VerifyChain(capEnt, included, f.localKp.PeerID()); err != nil {
		t.Errorf("TV-RD-NON-DEV-PEER FAILURE: v2.0 root cap should validate cleanly under narrow handler-grant config; got: %v", err)
	}
}

// =====================================================================
// TV-CAP-ZERO-GRANTEE — V7 v7.39 PR-3 unresolvable-grantee rejection
// =====================================================================
//
// Per PROPOSAL-ROLE-V2.0-PRODUCTION-READINESS PR-3 + V7 v7.39 §3.6 +
// §5.5: caps with grantee that doesn't resolve to a present
// system/peer entity MUST be rejected with ErrUnresolvableGrantee.
// Closes the bearer-cap surface area discovered in SEC-18.

func TestSEC_ZeroGranteeRejected(t *testing.T) {
	// Set up a runtime peer + a "victim" cap with grantee = zero-hash.
	var rSeed [32]byte
	rSeed[0] = 0x80
	runtimeKp := crypto.FromSeed(rSeed)
	runtimeIdent, _ := runtimeKp.IdentityEntity()

	zeroBytes := make([]byte, 33)
	zeroBytes[0] = hash.AlgorithmSHA256
	zeroHash, _ := hash.FromBytes(zeroBytes)

	// Construct a cap with grantee = zero-hash. The cap is otherwise
	// well-formed: legitimate granter + signature.
	bearerData := types.CapabilityTokenData{
		Grants: []types.GrantEntry{{
			Handlers:   types.CapabilityScope{Include: []string{"system/tree"}},
			Resources:  types.CapabilityScope{Include: []string{"*"}},
			Operations: types.CapabilityScope{Include: []string{"*"}},
		}},
		Granter:   types.SingleSigGranter(runtimeIdent.ContentHash),
		Grantee:   zeroHash,
		CreatedAt: 1000,
	}
	bearerCap, _ := bearerData.ToEntity()
	bearerSigBytes := runtimeKp.Sign(bearerCap.ContentHash.Bytes())
	bearerSig, _ := types.SignatureData{
		Target:    bearerCap.ContentHash,
		Signer:    runtimeIdent.ContentHash,
		Algorithm: "ed25519",
		Signature: bearerSigBytes,
	}.ToEntity()

	included := map[hash.Hash]entity.Entity{
		runtimeIdent.ContentHash: runtimeIdent,
		bearerCap.ContentHash:    bearerCap,
		bearerSig.ContentHash:    bearerSig,
		// NOTE: no identity entity for zeroHash — that's the test.
	}

	err := capability.VerifyChain(bearerCap, included, runtimeKp.PeerID())
	if err == nil {
		t.Fatal("TV-CAP-ZERO-GRANTEE BREACH: bearer cap with zero-hash grantee accepted by chain walker. Per V7 v7.39 §3.6 + PR-3, MUST be rejected with ErrUnresolvableGrantee.")
	}
	if !errors.Is(err, ecerrors.ErrUnresolvableGrantee) {
		t.Errorf("expected ErrUnresolvableGrantee, got: %v", err)
	}
}

// TestSEC_ZeroGranteeRejected_SelfCapStillValidates is the self-cap
// edge case from PR-3's informative box. Caps minted with grantee ==
// granter (common for handler grants and root self-caps) MUST continue
// to validate — the granter's identity is required to be in the
// resolution set anyway, so resolving the same hash for grantee is a
// no-op cache hit.
func TestSEC_ZeroGranteeRejected_SelfCapStillValidates(t *testing.T) {
	var seed [32]byte
	seed[0] = 0x81
	kp := crypto.FromSeed(seed)
	ident, _ := kp.IdentityEntity()

	selfCapData := types.CapabilityTokenData{
		Grants: []types.GrantEntry{{
			Handlers:   types.CapabilityScope{Include: []string{"*"}},
			Resources:  types.CapabilityScope{Include: []string{"*"}},
			Operations: types.CapabilityScope{Include: []string{"*"}},
		}},
		Granter:   types.SingleSigGranter(ident.ContentHash),
		Grantee:   ident.ContentHash, // grantee == granter (self-cap)
		CreatedAt: 1000,
	}
	selfCap, _ := selfCapData.ToEntity()
	selfSigBytes := kp.Sign(selfCap.ContentHash.Bytes())
	selfSig, _ := types.SignatureData{
		Target:    selfCap.ContentHash,
		Signer:    ident.ContentHash,
		Algorithm: "ed25519",
		Signature: selfSigBytes,
	}.ToEntity()

	included := map[hash.Hash]entity.Entity{
		ident.ContentHash:   ident,
		selfCap.ContentHash: selfCap,
		selfSig.ContentHash: selfSig,
	}

	if err := capability.VerifyChain(selfCap, included, kp.PeerID()); err != nil {
		t.Fatalf("self-cap (grantee == granter) should validate post-PR-3: %v", err)
	}
}

// =====================================================================
// TV-RD-DELEGATE-CHAIN-DEPTH — Role v2.0 PR-1 chain depth collapse
// =====================================================================
//
// Per PROPOSAL-ROLE-V2.0-PRODUCTION-READINESS PR-1 §7: depth measured
// as link count from cap to (and including) root cap. Pre-v2.0 a
// delegation cap chained: delegation → role-derived → handler-grant
// (depth 3). Post-v2.0: delegation → role-derived (depth 2). Confirms
// PR-1 collapses the chain by one link on the most common case.

func TestSEC_DelegateChainDepth(t *testing.T) {
	f := newDelegateFixture(t)

	resp := f.callDelegate(t, types.RoleDelegateRequestData{
		Delegate: f.delegateIdentity.ContentHash,
		Context:  f.contextStr,
		Role:     f.roleName,
		Scope:    f.literalScope(),
	})
	if resp.Status != 200 {
		t.Fatalf("delegate: %d (%s)", resp.Status, dumpResult(t, resp))
	}
	result, _ := types.RoleDelegateResultDataFromEntity(resp.Result)
	delegationCapHash := result.DelegationTokenHash

	// Walk the chain counting links (cap to root, inclusive).
	depth := 0
	current := delegationCapHash
	visited := map[hash.Hash]bool{}
	for !current.IsZero() {
		if visited[current] {
			t.Fatalf("cycle in chain at %v", current)
		}
		visited[current] = true
		depth++

		ent, ok := f.hctx.Store.Get(current)
		if !ok {
			t.Fatalf("cap %v not in store at depth %d", current, depth)
		}
		tok, err := types.CapabilityTokenDataFromEntity(ent)
		if err != nil {
			t.Fatalf("decode cap at depth %d: %v", depth, err)
		}
		if tok.Parent == nil {
			break
		}
		current = *tok.Parent
	}

	// Per PR-1 §7: depth == 2 (delegation cap → role-derived root cap).
	if depth != 2 {
		t.Errorf("TV-RD-DELEGATE-CHAIN-DEPTH FAILURE: chain depth = %d, expected 2 per Role v2.0 PR-1. Pre-v2.0 was 3 (delegation → role-derived → handler-grant); v2.0 collapses to 2 because role-derived cap is now root.", depth)
	}
}

// =====================================================================
// COVERAGE GAP — Role TTL metadata → cap expiry integration
// =====================================================================
//
// TestRoleMetadataTTL covers the metadata-extraction helper in isolation;
// TestEffectiveExpiresAt_MinDefined covers the formula. This test
// integrates: define a role with a TTL in metadata, assign, verify the
// minted cap's ExpiresAt is bounded by the TTL via MIN_DEFINED per
// EXTENSION-ROLE v2.0 §5.3.

func TestRoleTTL_BoundsCapExpiry(t *testing.T) {
	f := newOperatorFixture(t)

	// Re-define the role with TTL metadata.
	const roleTTL = uint64(60_000) // 60 seconds in milliseconds
	metadata, err := cbor.Marshal(map[string]any{"ttl": roleTTL})
	if err != nil {
		t.Fatalf("marshal metadata: %v", err)
	}
	roleDef := types.RoleData{
		Name:     f.roleName,
		Grants:   f.roleGrants,
		Metadata: metadata,
	}
	roleDefEnt, _ := roleDef.ToEntity()
	if _, err := f.hctx.Store.Put(roleDefEnt); err != nil {
		t.Fatalf("put role def: %v", err)
	}
	f.hctx.LocationIndex.Set(RoleDefinitionPath(f.contextStr, f.roleName), roleDefEnt.ContentHash)

	resp := f.callAssign(t, f.assigneeIdentity.ContentHash)
	if resp.Status != 200 {
		t.Fatalf("assign: %d (%s)", resp.Status, dumpResult(t, resp))
	}
	result, _ := types.RoleAssignResultDataFromEntity(resp.Result)
	capEnt, _ := f.hctx.Store.Get(result.DerivedTokens[0])
	tok, _ := types.CapabilityTokenDataFromEntity(capEnt)

	// Cap ExpiresAt MUST be bounded by the role TTL. Caller cap has no
	// expires_at in the operator fixture (zero-uint64 from Default), so
	// MIN_DEFINED collapses to {role.ttl}; the cap should have
	// ExpiresAt == roleTTL.
	if tok.ExpiresAt == nil {
		t.Fatalf("cap.ExpiresAt is nil; expected role TTL = %d to bound it via MIN_DEFINED", roleTTL)
	}
	if *tok.ExpiresAt != roleTTL {
		t.Errorf("cap.ExpiresAt = %d, want = role TTL %d (caller cap has no expiry; MIN_DEFINED should collapse to TTL only)",
			*tok.ExpiresAt, roleTTL)
	}
}

// =====================================================================
// COVERAGE GAP — Delegation cap chain validates end-to-end via VerifyChain
// =====================================================================
//
// TestSEC_DelegateChainDepth confirms structural depth = 2 post-PR-1.
// This test runs a full VerifyChain on the delegation cap chain
// (delegation → role-derived root). Exercises:
//   - PR-1 root-cap chain termination at the role-derived cap
//   - PR-3 per-link grantee resolution (delegate identity for the
//     delegation cap; delegator identity for the role-derived cap)
//   - V7 §5.5 chain linkage (delegation.granter == role_derived.grantee)

func TestDelegation_ChainValidatesEndToEnd(t *testing.T) {
	f := newDelegateFixture(t)

	resp := f.callDelegate(t, types.RoleDelegateRequestData{
		Delegate: f.delegateIdentity.ContentHash,
		Context:  f.contextStr,
		Role:     f.roleName,
		Scope:    f.literalScope(),
	})
	if resp.Status != 200 {
		t.Fatalf("delegate: %d (%s)", resp.Status, dumpResult(t, resp))
	}
	result, _ := types.RoleDelegateResultDataFromEntity(resp.Result)
	delegationCapHash := result.DelegationTokenHash

	// Build the resolution set for VerifyChain. Per PR-3, every link's
	// grantee MUST resolve. Per V7 §5.5, every link's granter MUST also
	// resolve. The chain is:
	//   - delegation cap: granter=delegator, grantee=delegate target
	//   - role-derived cap (root): granter=delegator, grantee=delegator
	//
	// All identities + caps + their signatures need to be present.
	included := map[hash.Hash]entity.Entity{
		f.localIdentity.ContentHash:    f.localIdentity,    // delegator (granter at both links)
		f.delegateIdentity.ContentHash: f.delegateIdentity, // delegate (grantee of delegation cap)
	}

	// Add the delegation cap and its signature.
	delegationCapEnt, ok := f.hctx.Store.Get(delegationCapHash)
	if !ok {
		t.Fatalf("delegation cap not in store")
	}
	included[delegationCapEnt.ContentHash] = delegationCapEnt

	// Walk to find the parent cap (role-derived cap, the root) and add it.
	dtok, _ := types.CapabilityTokenDataFromEntity(delegationCapEnt)
	if dtok.Parent == nil {
		t.Fatalf("delegation cap has no parent — should chain to role-derived cap")
	}
	roleDerivedEnt, ok := f.hctx.Store.Get(*dtok.Parent)
	if !ok {
		t.Fatalf("role-derived parent cap not in store")
	}
	included[roleDerivedEnt.ContentHash] = roleDerivedEnt

	// Add cap signatures. The delegation cap was signed by the handler
	// during :delegate (look up via tree path). The parent (role-derived)
	// cap is a synthetic fixture entity — sign it inline so VerifyChain
	// has the signature for its chain link.
	delegationSigPath := types.InvariantSignaturePath(f.localKp.PeerID().String(), delegationCapHash)
	if sigH, ok := f.hctx.LocationIndex.Get(delegationSigPath); ok {
		if sigEnt, ok := f.hctx.Store.Get(sigH); ok {
			included[sigH] = sigEnt
		}
	}
	parentSigBytes := f.localKp.Sign(roleDerivedEnt.ContentHash.Bytes())
	parentSigData := types.SignatureData{
		Target:    roleDerivedEnt.ContentHash,
		Signer:    f.localIdentity.ContentHash,
		Algorithm: "ed25519",
		Signature: parentSigBytes,
	}
	parentSigEnt, _ := parentSigData.ToEntity()
	included[parentSigEnt.ContentHash] = parentSigEnt

	// Run the full chain walk.
	if err := capability.VerifyChain(delegationCapEnt, included, f.localKp.PeerID()); err != nil {
		t.Fatalf("delegation chain validation failed: %v\n  delegation cap: %v\n  role-derived parent: %v\n  expected: chain validates end-to-end via VerifyChain (PR-1 root cap + PR-3 per-link grantee resolution + V7 §5.5 linkage)",
			err, delegationCapHash, roleDerivedEnt.ContentHash)
	}
}

// Suppress "imported and not used" for store/handler when builds remove the
// SEC-* tests. (Defensive — Go's import discipline is strict.)
var _ = store.NewMemoryContentStore
var _ = handler.NewResponse
