package validate

import (
	"context"
	"fmt"
	"time"

	"go.entitychurch.org/entity-core-go/core/crypto"
	"go.entitychurch.org/entity-core-go/core/ecf"
	"go.entitychurch.org/entity-core-go/core/entity"
	"go.entitychurch.org/entity-core-go/core/hash"
	"go.entitychurch.org/entity-core-go/core/protocol"
	"go.entitychurch.org/entity-core-go/core/types"

	"github.com/fxamacker/cbor/v2"
)

const catSecurity = "security"

// runSecurity runs all security enforcement checks against the remote peer.
// These send intentionally broken or unauthorized requests and verify the peer
// returns the spec-correct DENY surface, confirming it actually enforces the
// capability security pipeline.
//
// V7 v7.71 §3.3 + §A4-AUTHZ status discriminator: authentication-class
// failures (missing/invalid/mismatched signature, missing author, signer-author
// mismatch) MUST surface as 401; authorization-class failures (cap chain
// rejection, scope, expiry on a chain-walked cap, forged root) MUST surface
// as 403. The per-check helpers below pin the right side of that line.
func runSecurity(ctx context.Context, client *PeerClient) []CheckResult {
	r := NewCheckRunner(catSecurity)

	// --- Declare all checks ---

	// Phase 1: Authentication enforcement (broken envelopes).
	r.Declare("no_author_rejected", "V7 §5.1")
	r.Declare("no_capability_rejected", "V7 §5.1")
	r.Declare("author_not_in_included", "V7 §5.2")
	r.Declare("capability_not_in_included", "V7 §5.2")
	r.Declare("no_signature_rejected", "V7 §5.2")
	r.Declare("signature_wrong_target", "V7 §5.2")
	r.Declare("signer_author_mismatch", "V7 §3.5")
	r.Declare("tampered_signature", "V7 §5.2")
	r.Declare("grantee_author_mismatch", "V7 §5.2")
	r.Declare("forged_root_capability", "V7 §5.5")

	// Phase 2: Scope enforcement (restricted delegated capabilities).
	r.Declare("operation_scope_denied", "V7 §5.4")
	r.Declare("handler_scope_denied", "V7 §5.4")
	// V7 v7.72 §9.0 carve-out: handler_scope_denied targets
	// system/subscription (extension). Under --profile core a core peer
	// correctly 404s before the handler-scope check can fire (§6.5
	// resolution-first dispatch). handler_scope_denied_core_1 reroutes
	// the property through system/capability (a core handler) so the
	// 403 path is exercised on a core peer.
	r.Declare("handler_scope_denied_core_1", "V7 v7.72 §9.0 carve-out (--profile core variant)")
	r.Declare("resource_scope_denied", "V7 §5.4")
	r.Declare("expired_capability_denied", "V7 §5.2")
	r.Declare("not_before_denied", "V7 §5.2")

	// --- Phase 1: Authentication Enforcement Checks ---

	r.Run("no_author_rejected", func() CheckOutcome {
		return toOutcome(checkNoAuthor(ctx, client))
	})

	r.Run("no_capability_rejected", func() CheckOutcome {
		return toOutcome(checkNoCapability(ctx, client))
	})

	r.Run("author_not_in_included", func() CheckOutcome {
		return toOutcome(checkAuthorNotInIncluded(ctx, client))
	})

	r.Run("capability_not_in_included", func() CheckOutcome {
		return toOutcome(checkCapabilityNotInIncluded(ctx, client))
	})

	r.Run("no_signature_rejected", func() CheckOutcome {
		return toOutcome(checkNoSignature(ctx, client))
	})

	r.Run("signature_wrong_target", func() CheckOutcome {
		return toOutcome(checkSignatureWrongTarget(ctx, client))
	})

	r.Run("signer_author_mismatch", func() CheckOutcome {
		return toOutcome(checkSignerAuthorMismatch(ctx, client))
	})

	r.Run("tampered_signature", func() CheckOutcome {
		return toOutcome(checkTamperedSignature(ctx, client))
	})

	r.Run("grantee_author_mismatch", func() CheckOutcome {
		return toOutcome(checkGranteeAuthorMismatch(ctx, client))
	})

	r.Run("forged_root_capability", func() CheckOutcome {
		return toOutcome(checkForgedRootCapability(ctx, client))
	})

	// --- Phase 2: Scope Enforcement Checks ---

	r.Run("operation_scope_denied", func() CheckOutcome {
		return toOutcome(checkOperationScopeDenied(ctx, client))
	})

	r.Run("handler_scope_denied", func() CheckOutcome {
		if client.Profile() == ProfileCore {
			return SkipCheck("V7 v7.72 §9.0 carve-out: targets system/subscription (extension); core peer 404s before §5.4 fires per §6.5 resolution-first. See handler_scope_denied_core_1.")
		}
		return toOutcome(checkHandlerScopeDenied(ctx, client))
	})

	// V7 v7.72 §9.0 carve-out: the property of handler_scope_denied,
	// rerouted through system/capability (a core handler) so it runs
	// on a core peer. Under --profile full it also runs alongside the
	// extension-targeted variant (matches-if-present sibling test).
	r.Run("handler_scope_denied_core_1", func() CheckOutcome {
		return toOutcome(checkHandlerScopeDeniedCore(ctx, client))
	})

	r.Run("resource_scope_denied", func() CheckOutcome {
		return toOutcome(checkResourceScopeDenied(ctx, client))
	})

	r.Run("expired_capability_denied", func() CheckOutcome {
		return toOutcome(checkExpiredCapabilityDenied(ctx, client))
	})

	r.Run("not_before_denied", func() CheckOutcome {
		return toOutcome(checkNotBeforeDenied(ctx, client))
	})

	results := r.Results()

	// Phase 3: multi-link chain / attenuation probes (F1–F6). The legacy
	// checks above cover only single-link forgery and a single child
	// overshooting scope; the chain/attenuation surface is where the
	// cross-impl §5.5/§5.6/§5.7 divergences live. See security_chain.go.
	results = append(results, runSecurityChain(client)...)

	return results
}

// toOutcome converts a CheckResult to a CheckOutcome for use in CheckRunner.
func toOutcome(cr CheckResult) CheckOutcome {
	return CheckOutcome{severity: cr.Severity, message: cr.Message, details: cr.Details}
}

// --- Helpers ---

// denyClass distinguishes the §3.3 status side a tampered EXECUTE lands on.
// auth-class (401) covers signature/author/identity-resolution failures;
// authz-class (403) covers missing-capability / authorization-domain DENYs.
type denyClass int

const (
	authClassDeny denyClass = iota
	authzClassDeny
)

// sendTamperedExecute builds a valid authenticated EXECUTE, applies a tamper
// function that modifies the envelope, then sends it and checks for the
// spec-correct DENY status. V7 v7.71 §3.3 pins authentication-class failures
// at 401 and authorization-domain failures at 403. The expectedClass argument
// names which side of that discriminator the tamper produces.
func sendTamperedExecute(
	ctx context.Context,
	client *PeerClient,
	checkName, specRef string,
	tamper func(env *entity.Envelope, execEntity *entity.Entity) error,
) CheckResult {
	return sendTamperedExecuteWithClass(ctx, client, checkName, specRef, authClassDeny, tamper)
}

// sendTamperedExecuteAuthz is the authz-class variant. Use for tampers that
// produce a missing-capability / chain-DENY surface (envelope-structural cap
// failures that route through ErrCapabilityDenied → 403, NOT through the
// auth-class signature/identity path).
func sendTamperedExecuteAuthz(
	ctx context.Context,
	client *PeerClient,
	checkName, specRef string,
	tamper func(env *entity.Envelope, execEntity *entity.Entity) error,
) CheckResult {
	return sendTamperedExecuteWithClass(ctx, client, checkName, specRef, authzClassDeny, tamper)
}

func sendTamperedExecuteWithClass(
	ctx context.Context,
	client *PeerClient,
	checkName, specRef string,
	class denyClass,
	tamper func(env *entity.Envelope, execEntity *entity.Entity) error,
) CheckResult {
	kp := client.Keypair()
	identity := client.IdentityEntity()
	cap := client.CapEntity()
	uri := fmt.Sprintf("entity://%s/system/tree", client.RemotePeerID())

	// Build a valid tree get request.
	params, resource, err := buildSimpleGetParams()
	if err != nil {
		return fail(catSecurity, checkName, specRef, "setup error: "+err.Error())
	}

	env, err := protocol.CreateAuthenticatedExecute(
		kp, identity, cap,
		client.NextRequestID(), uri, "get", params, resource,
	)
	if err != nil {
		return fail(catSecurity, checkName, specRef, "create execute error: "+err.Error())
	}

	// Include auth chain entities from connection.
	for h, ent := range client.AuthenticateIncluded() {
		env.Include(entity.Entity{Type: ent.Type, Data: ent.Data, ContentHash: h})
	}

	// Apply the tamper function.
	if err := tamper(&env, &env.Root); err != nil {
		return fail(catSecurity, checkName, specRef, "tamper error: "+err.Error())
	}

	if class == authzClassDeny {
		return sendAndExpectAuthzDeny(client, env, checkName, specRef)
	}
	return sendAndExpectAuthDeny(client, env, checkName, specRef)
}

// sendAndExpectAuthDeny asserts the spec-correct authentication-class DENY
// surface per V7 v7.71 §3.3: status 401 (Authentication failed). Used by the
// security category's Phase-1 tamper checks where the failure is a signature
// / author / envelope-identity-resolution issue, not an authorization-domain
// scope/expiry/chain-root issue.
//
// Source-compat note: pre-v7.71 Go emitted `403 authentication_failed` for
// every chain-walk failure; v7.71 §3.3 reroutes auth-class to 401. A 403
// response is now a real regression on the auth-class path — surface as
// FAIL rather than silently tolerate.
func sendAndExpectAuthDeny(client *PeerClient, env entity.Envelope, checkName, specRef string) CheckResult {
	respEnv, _, err := client.SendRawEnvelope(env)
	if err != nil {
		return fail(catSecurity, checkName, specRef,
			fmt.Sprintf("peer crashed or closed connection: %v", err))
	}
	respData, err := types.ExecuteResponseDataFromEntity(respEnv.Root)
	if err != nil {
		return fail(catSecurity, checkName, specRef,
			"could not decode response: "+err.Error())
	}
	if respData.Status == 401 {
		return pass(catSecurity, checkName, specRef,
			"correctly rejected with 401 (v7.71 §3.3 auth-class DENY)")
	}
	if respData.Status == 403 {
		return fail(catSecurity, checkName, specRef,
			"v7.71 §3.3 maps authentication-class failures to 401, not 403; impl is conflating auth-class with authz-class DENY")
	}
	return fail(catSecurity, checkName, specRef,
		fmt.Sprintf("expected status 401 (v7.71 §3.3 auth-class), got %d", respData.Status))
}

// sendAndExpectAuthzDeny asserts the spec-correct authorization-class DENY
// surface per V7 v7.71 §3.3: status 403 (request-time authorization DENY,
// §5.2 verify_request). Used by Phase-2 scope / expiry / forged-root checks
// where the failure is in the authorization domain.
func sendAndExpectAuthzDeny(client *PeerClient, env entity.Envelope, checkName, specRef string) CheckResult {
	respEnv, _, err := client.SendRawEnvelope(env)
	if err != nil {
		return fail(catSecurity, checkName, specRef,
			fmt.Sprintf("peer crashed or closed connection: %v", err))
	}
	respData, err := types.ExecuteResponseDataFromEntity(respEnv.Root)
	if err != nil {
		return fail(catSecurity, checkName, specRef,
			"could not decode response: "+err.Error())
	}
	if respData.Status == 403 {
		return pass(catSecurity, checkName, specRef,
			"correctly rejected with 403 (v7.71 §3.3 authz-class DENY)")
	}
	if respData.Status == 401 {
		return fail(catSecurity, checkName, specRef,
			"v7.71 §3.3 maps authorization-class failures to 403, not 401; impl is conflating authz-class with auth-class DENY")
	}
	return fail(catSecurity, checkName, specRef,
		fmt.Sprintf("expected status 403 (v7.71 §3.3 authz-class), got %d", respData.Status))
}

// buildSimpleGetParams creates params and resource target for a basic tree get.
func buildSimpleGetParams() (entity.Entity, *types.ResourceTarget, error) {
	type getParams struct {
		Format string `cbor:"format"`
	}
	paramsData := getParams{Format: "entity"}
	raw, err := ecf.Encode(paramsData)
	if err != nil {
		return entity.Entity{}, nil, err
	}
	paramsEntity, err2 := entity.NewEntity("system/tree/get-request", cbor.RawMessage(raw))
	if err2 != nil {
		return entity.Entity{}, nil, err2
	}
	resource := &types.ResourceTarget{Targets: []string{"system/type/system/peer"}}
	return paramsEntity, resource, nil
}

// rebuildExecuteEntity decodes the execute entity, applies changes, and re-encodes.
// Returns the new entity (with updated content hash).
func rebuildExecuteEntity(execEntity entity.Entity, modify func(d *types.ExecuteData)) (entity.Entity, error) {
	var execData types.ExecuteData
	if err := ecf.Decode(execEntity.Data, &execData); err != nil {
		return entity.Entity{}, fmt.Errorf("decode execute data: %w", err)
	}
	modify(&execData)
	return execData.ToEntity()
}

// signEntity creates a signature entity for the given target using the given keypair and identity.
func signEntity(target hash.Hash, kp crypto.Keypair, identity entity.Entity) (entity.Entity, error) {
	sig := kp.Sign(target.Bytes())
	sigData := types.SignatureData{
		Target:    target,
		Signer:    identity.ContentHash,
		Algorithm: "ed25519",
		Signature: sig,
	}
	return sigData.ToEntity()
}

// createCapabilityToken creates a capability token entity and its signature.
func createCapabilityToken(tokenData types.CapabilityTokenData, signerKP crypto.Keypair, signerIdentity entity.Entity) (entity.Entity, entity.Entity, error) {
	tokenEntity, err := tokenData.ToEntity()
	if err != nil {
		return entity.Entity{}, entity.Entity{}, err
	}
	sigEntity, err := signEntity(tokenEntity.ContentHash, signerKP, signerIdentity)
	if err != nil {
		return entity.Entity{}, entity.Entity{}, err
	}
	return tokenEntity, sigEntity, nil
}

// buildDelegatedExecute builds a complete EXECUTE envelope using a delegated
// capability chain: connection cap (from server) → child cap (from us).
// The child cap restricts scope. The EXECUTE uses the child cap as its capability.
func buildDelegatedExecute(
	client *PeerClient,
	childCap, childCapSig entity.Entity,
	uri, operation string,
	params entity.Entity,
	resource *types.ResourceTarget,
) (entity.Envelope, error) {
	kp := client.Keypair()
	identity := client.IdentityEntity()

	// Build ExecuteData pointing to our identity as author and the child cap.
	raw, err := ecf.Encode(params)
	if err != nil {
		return entity.Envelope{}, err
	}

	execData := types.ExecuteData{
		RequestID:  client.NextRequestID(),
		URI:        uri,
		Operation:  operation,
		Params:     cbor.RawMessage(raw),
		Author:     identity.ContentHash,
		Capability: childCap.ContentHash,
		Resource:   resource,
	}

	execEntity, err := execData.ToEntity()
	if err != nil {
		return entity.Envelope{}, err
	}

	// Sign the EXECUTE.
	execSig, err := signEntity(execEntity.ContentHash, kp, identity)
	if err != nil {
		return entity.Envelope{}, err
	}

	included := map[hash.Hash]entity.Entity{
		identity.ContentHash:    identity,
		childCap.ContentHash:    childCap,
		childCapSig.ContentHash: childCapSig,
		execSig.ContentHash:     execSig,
	}

	// Include the parent capability chain (connection cap + its sig + granter identity).
	parentCap := client.CapEntity()
	included[parentCap.ContentHash] = parentCap
	for h, ent := range client.AuthenticateIncluded() {
		included[h] = entity.Entity{Type: ent.Type, Data: ent.Data, ContentHash: h}
	}

	return entity.NewEnvelope(execEntity, included), nil
}

// --- Phase 1: Authentication Enforcement Checks ---

func checkNoAuthor(ctx context.Context, client *PeerClient) CheckResult {
	return sendTamperedExecute(ctx, client, "no_author_rejected", "V7 §5.1",
		func(env *entity.Envelope, execEntity *entity.Entity) error {
			newExec, err := rebuildExecuteEntity(*execEntity, func(d *types.ExecuteData) {
				d.Author = hash.Hash{} // zero author
			})
			if err != nil {
				return err
			}
			// Re-sign with the new execute entity.
			kp := client.Keypair()
			identity := client.IdentityEntity()
			sig, err := signEntity(newExec.ContentHash, kp, identity)
			if err != nil {
				return err
			}
			env.Root = newExec
			env.Included[sig.ContentHash] = sig
			return nil
		})
}

func checkNoCapability(ctx context.Context, client *PeerClient) CheckResult {
	// Zero-capability tamper: auth.go:80 surfaces ErrCapabilityDenied
	// "missing capability" → §3.3 authz-class 403. The cap is absent so
	// there is no auth-class signature/identity claim to verify; the
	// failure lives in the authorization domain.
	return sendTamperedExecuteAuthz(ctx, client, "no_capability_rejected", "V7 §5.1",
		func(env *entity.Envelope, execEntity *entity.Entity) error {
			newExec, err := rebuildExecuteEntity(*execEntity, func(d *types.ExecuteData) {
				d.Capability = hash.Hash{} // zero capability
			})
			if err != nil {
				return err
			}
			kp := client.Keypair()
			identity := client.IdentityEntity()
			sig, err := signEntity(newExec.ContentHash, kp, identity)
			if err != nil {
				return err
			}
			env.Root = newExec
			env.Included[sig.ContentHash] = sig
			return nil
		})
}

func checkAuthorNotInIncluded(ctx context.Context, client *PeerClient) CheckResult {
	return sendTamperedExecute(ctx, client, "author_not_in_included", "V7 §5.2",
		func(env *entity.Envelope, _ *entity.Entity) error {
			// Remove the author identity entity from included.
			identity := client.IdentityEntity()
			delete(env.Included, identity.ContentHash)
			return nil
		})
}

func checkCapabilityNotInIncluded(ctx context.Context, client *PeerClient) CheckResult {
	// Missing-cap-entity tamper: auth.go:84 surfaces ErrCapabilityDenied
	// "capability not in included" → §3.3 authz-class 403. Same reasoning
	// as checkNoCapability — no cap to verify, no auth-class surface.
	return sendTamperedExecuteAuthz(ctx, client, "capability_not_in_included", "V7 §5.2",
		func(env *entity.Envelope, _ *entity.Entity) error {
			// Remove the capability entity from included.
			cap := client.CapEntity()
			delete(env.Included, cap.ContentHash)
			return nil
		})
}

func checkNoSignature(ctx context.Context, client *PeerClient) CheckResult {
	return sendTamperedExecute(ctx, client, "no_signature_rejected", "V7 §5.2",
		func(env *entity.Envelope, execEntity *entity.Entity) error {
			// Remove all signature entities from included.
			for h, ent := range env.Included {
				if ent.Type == types.TypeSignature {
					// Check if this signature targets the execute entity.
					sigData, err := types.SignatureDataFromEntity(ent)
					if err == nil && sigData.Target == execEntity.ContentHash {
						delete(env.Included, h)
					}
				}
			}
			return nil
		})
}

func checkSignatureWrongTarget(ctx context.Context, client *PeerClient) CheckResult {
	return sendTamperedExecute(ctx, client, "signature_wrong_target", "V7 §5.2",
		func(env *entity.Envelope, execEntity *entity.Entity) error {
			// Remove the real signature, add one targeting a different hash.
			kp := client.Keypair()
			identity := client.IdentityEntity()

			for h, ent := range env.Included {
				if ent.Type == types.TypeSignature {
					sigData, err := types.SignatureDataFromEntity(ent)
					if err == nil && sigData.Target == execEntity.ContentHash {
						delete(env.Included, h)
					}
				}
			}

			// Sign a bogus hash (the identity entity hash instead of the execute hash).
			bogusTarget := identity.ContentHash
			sig := kp.Sign(bogusTarget.Bytes())
			sigData := types.SignatureData{
				Target:    bogusTarget,
				Signer:    identity.ContentHash,
				Algorithm: "ed25519",
				Signature: sig,
			}
			sigEntity, err := sigData.ToEntity()
			if err != nil {
				return err
			}
			env.Included[sigEntity.ContentHash] = sigEntity
			return nil
		})
}

func checkSignerAuthorMismatch(ctx context.Context, client *PeerClient) CheckResult {
	return sendTamperedExecute(ctx, client, "signer_author_mismatch", "V7 §3.5",
		func(env *entity.Envelope, execEntity *entity.Entity) error {
			// Create a second keypair and use it to sign the execute.
			// The signer identity won't match the author.
			otherKP, err := crypto.Generate()
			if err != nil {
				return err
			}
			otherIdentity, err := otherKP.IdentityEntity()
			if err != nil {
				return err
			}

			// Remove the original signature.
			for h, ent := range env.Included {
				if ent.Type == types.TypeSignature {
					sigData, sigErr := types.SignatureDataFromEntity(ent)
					if sigErr == nil && sigData.Target == execEntity.ContentHash {
						delete(env.Included, h)
					}
				}
			}

			// Add signature from other keypair (signer != author).
			sig := otherKP.Sign(execEntity.ContentHash.Bytes())
			sigData := types.SignatureData{
				Target:    execEntity.ContentHash,
				Signer:    otherIdentity.ContentHash, // different from author
				Algorithm: "ed25519",
				Signature: sig,
			}
			sigEntity, err := sigData.ToEntity()
			if err != nil {
				return err
			}
			env.Included[sigEntity.ContentHash] = sigEntity
			env.Included[otherIdentity.ContentHash] = otherIdentity
			return nil
		})
}

func checkTamperedSignature(ctx context.Context, client *PeerClient) CheckResult {
	return sendTamperedExecute(ctx, client, "tampered_signature", "V7 §5.2",
		func(env *entity.Envelope, execEntity *entity.Entity) error {
			// Find the execute signature and flip some bytes.
			for h, ent := range env.Included {
				if ent.Type == types.TypeSignature {
					sigData, err := types.SignatureDataFromEntity(ent)
					if err == nil && sigData.Target == execEntity.ContentHash {
						delete(env.Included, h)

						// Flip bytes in the signature.
						tampered := make([]byte, len(sigData.Signature))
						copy(tampered, sigData.Signature)
						for i := 0; i < 4 && i < len(tampered); i++ {
							tampered[i] ^= 0xFF
						}

						sigData.Signature = tampered
						newSigEntity, err := sigData.ToEntity()
						if err != nil {
							return err
						}
						env.Included[newSigEntity.ContentHash] = newSigEntity
						return nil
					}
				}
			}
			return fmt.Errorf("no execute signature found to tamper")
		})
}

func checkGranteeAuthorMismatch(ctx context.Context, client *PeerClient) CheckResult {
	// Create a second keypair. Build an EXECUTE where:
	// - Author = second identity (not the capability grantee)
	// - Capability = connection cap (grantee = our primary identity)
	// The grantee on the cap won't match the author.
	kp := client.Keypair()
	cap := client.CapEntity()
	uri := fmt.Sprintf("entity://%s/system/tree", client.RemotePeerID())

	otherKP, err := crypto.Generate()
	if err != nil {
		return fail(catSecurity, "grantee_author_mismatch", "V7 §5.2", "generate keypair: "+err.Error())
	}
	otherIdentity, err := otherKP.IdentityEntity()
	if err != nil {
		return fail(catSecurity, "grantee_author_mismatch", "V7 §5.2", "create identity: "+err.Error())
	}
	_ = kp // primary keypair not used for signing here

	params, resource, err := buildSimpleGetParams()
	if err != nil {
		return fail(catSecurity, "grantee_author_mismatch", "V7 §5.2", "setup: "+err.Error())
	}

	// Build EXECUTE with other identity as author but using our connection capability.
	raw, err := ecf.Encode(params)
	if err != nil {
		return fail(catSecurity, "grantee_author_mismatch", "V7 §5.2", "encode params: "+err.Error())
	}

	execData := types.ExecuteData{
		RequestID:  client.NextRequestID(),
		URI:        uri,
		Operation:  "get",
		Params:     cbor.RawMessage(raw),
		Author:     otherIdentity.ContentHash,
		Capability: cap.ContentHash,
		Resource:   resource,
	}
	execEntity, err := execData.ToEntity()
	if err != nil {
		return fail(catSecurity, "grantee_author_mismatch", "V7 §5.2", "create execute: "+err.Error())
	}

	// Sign with the other keypair (valid signature, but wrong author for this cap).
	execSig, err := signEntity(execEntity.ContentHash, otherKP, otherIdentity)
	if err != nil {
		return fail(catSecurity, "grantee_author_mismatch", "V7 §5.2", "sign: "+err.Error())
	}

	included := map[hash.Hash]entity.Entity{
		otherIdentity.ContentHash: otherIdentity,
		cap.ContentHash:           cap,
		execSig.ContentHash:       execSig,
	}
	for h, ent := range client.AuthenticateIncluded() {
		included[h] = entity.Entity{Type: ent.Type, Data: ent.Data, ContentHash: h}
	}

	env := entity.NewEnvelope(execEntity, included)
	// V7 v7.71 §3.3 / §A4-AUTHZ — `grantee != author` is a self-attribution
	// invariant (§5.2), distinct from grantee resolution. Both are authz-class
	// in v7.71's discriminator, so 403 is the spec-correct status. Include
	// the original cap's grantee identity (the validator's primary identity)
	// in `included` so the pre-chain grantee resolution check passes and the
	// `grantee != author` mismatch fires as the cause of the DENY.
	if validatorIdentity := client.IdentityEntity(); !validatorIdentity.ContentHash.IsZero() {
		env.Included[validatorIdentity.ContentHash] = validatorIdentity
	}
	return sendAndExpectAuthzDeny(client, env, "grantee_author_mismatch", "V7 §5.2")
}

func checkForgedRootCapability(ctx context.Context, client *PeerClient) CheckResult {
	// Create a capability where granter is NOT the server. Self-signed, valid
	// structure, but the server should reject it because granter != local peer.
	kp := client.Keypair()
	identity := client.IdentityEntity()
	uri := fmt.Sprintf("entity://%s/system/tree", client.RemotePeerID())

	now := uint64(time.Now().UnixMilli())
	fiveMin := now + 5*60*1000
	tokenData := types.CapabilityTokenData{
		Grants: []types.GrantEntry{{
			Handlers:   types.CapabilityScope{Include: []string{"*"}},
			Resources:  types.CapabilityScope{Include: []string{"*"}},
			Operations: types.CapabilityScope{Include: []string{"*"}},
		}},
		Granter:   types.SingleSigGranter(identity.ContentHash), // us, not the server
		Grantee:   identity.ContentHash,
		CreatedAt: now,
		ExpiresAt: &fiveMin,
	}

	capEntity, capSig, err := createCapabilityToken(tokenData, kp, identity)
	if err != nil {
		return fail(catSecurity, "forged_root_capability", "V7 §5.5", "create cap: "+err.Error())
	}

	params, resource, err := buildSimpleGetParams()
	if err != nil {
		return fail(catSecurity, "forged_root_capability", "V7 §5.5", "setup: "+err.Error())
	}

	raw, err := ecf.Encode(params)
	if err != nil {
		return fail(catSecurity, "forged_root_capability", "V7 §5.5", "encode: "+err.Error())
	}

	execData := types.ExecuteData{
		RequestID:  client.NextRequestID(),
		URI:        uri,
		Operation:  "get",
		Params:     cbor.RawMessage(raw),
		Author:     identity.ContentHash,
		Capability: capEntity.ContentHash,
		Resource:   resource,
	}
	execEntity, err := execData.ToEntity()
	if err != nil {
		return fail(catSecurity, "forged_root_capability", "V7 §5.5", "create execute: "+err.Error())
	}

	execSig, err := signEntity(execEntity.ContentHash, kp, identity)
	if err != nil {
		return fail(catSecurity, "forged_root_capability", "V7 §5.5", "sign: "+err.Error())
	}

	included := map[hash.Hash]entity.Entity{
		identity.ContentHash:  identity,
		capEntity.ContentHash: capEntity,
		capSig.ContentHash:    capSig,
		execSig.ContentHash:   execSig,
	}

	env := entity.NewEnvelope(execEntity, included)
	return sendAndExpectAuthzDeny(client, env, "forged_root_capability", "V7 §5.5")
}

// --- Phase 2: Scope Enforcement Checks ---

func checkOperationScopeDenied(ctx context.Context, client *PeerClient) CheckResult {
	// Delegate a child cap that only allows "get", then send "put".
	return sendScopeTest(ctx, client, "operation_scope_denied", "V7 §5.4",
		types.GrantEntry{
			Handlers:   types.CapabilityScope{Include: []string{"system/tree"}},
			Resources:  types.CapabilityScope{Include: []string{"*"}},
			Operations: types.CapabilityScope{Include: []string{"get"}}, // only get
		},
		"system/tree", "put", // exceeds: put not allowed
		"system/validate/security-test",
	)
}

func checkHandlerScopeDenied(ctx context.Context, client *PeerClient) CheckResult {
	// Delegate a child cap that only allows system/tree, then target system/subscription.
	return sendScopeTest(ctx, client, "handler_scope_denied", "V7 §5.4",
		types.GrantEntry{
			Handlers:   types.CapabilityScope{Include: []string{"system/tree"}}, // only tree
			Resources:  types.CapabilityScope{Include: []string{"*"}},
			Operations: types.CapabilityScope{Include: []string{"*"}},
		},
		"system/subscription", "subscribe", // exceeds: wrong handler
		"system/validate/security-test",
	)
}

// checkHandlerScopeDeniedCore is the V7 v7.72 §9.0 core-profile variant
// of checkHandlerScopeDenied. The property is identical (a child cap
// scoped to handler X cannot reach handler Y); the target handler is
// system/capability (core MUST per §6.2) so the test runs on a core
// peer without depending on EXTENSION-SUBSCRIPTION being installed.
func checkHandlerScopeDeniedCore(ctx context.Context, client *PeerClient) CheckResult {
	return sendScopeTest(ctx, client, "handler_scope_denied_core_1", "V7 §5.4 (v7.72 §9.0 core variant)",
		types.GrantEntry{
			Handlers:   types.CapabilityScope{Include: []string{"system/tree"}}, // only tree
			Resources:  types.CapabilityScope{Include: []string{"*"}},
			Operations: types.CapabilityScope{Include: []string{"*"}},
		},
		"system/capability", "request", // exceeds: wrong handler (capability is core)
		"system/validate/security-test",
	)
}

func checkResourceScopeDenied(ctx context.Context, client *PeerClient) CheckResult {
	// Delegate a child cap that only allows system/type/*, then access system/handler/*.
	return sendScopeTest(ctx, client, "resource_scope_denied", "V7 §5.4",
		types.GrantEntry{
			Handlers:   types.CapabilityScope{Include: []string{"system/tree"}},
			Resources:  types.CapabilityScope{Include: []string{"system/type/*"}}, // only types
			Operations: types.CapabilityScope{Include: []string{"*"}},
		},
		"system/tree", "get", // handler+op ok
		"system/handler/system/tree", // exceeds: resource not in scope
	)
}

func checkExpiredCapabilityDenied(ctx context.Context, client *PeerClient) CheckResult {
	// Delegate a child cap that expired 1 second ago.
	kp := client.Keypair()
	identity := client.IdentityEntity()
	parentCap := client.CapEntity()
	uri := fmt.Sprintf("entity://%s/system/tree", client.RemotePeerID())

	now := uint64(time.Now().UnixMilli())
	expired := now - 1000 // 1 second ago
	tokenData := types.CapabilityTokenData{
		Grants: []types.GrantEntry{{
			Handlers:   types.CapabilityScope{Include: []string{"*"}},
			Resources:  types.CapabilityScope{Include: []string{"*"}},
			Operations: types.CapabilityScope{Include: []string{"*"}},
		}},
		Granter:   types.SingleSigGranter(identity.ContentHash),
		Grantee:   identity.ContentHash,
		Parent:    &parentCap.ContentHash,
		CreatedAt: now - 2000,
		ExpiresAt: &expired,
	}

	childCap, childCapSig, err := createCapabilityToken(tokenData, kp, identity)
	if err != nil {
		return fail(catSecurity, "expired_capability_denied", "V7 §5.2", "create cap: "+err.Error())
	}

	params, resource, err := buildSimpleGetParams()
	if err != nil {
		return fail(catSecurity, "expired_capability_denied", "V7 §5.2", "setup: "+err.Error())
	}

	env, err := buildDelegatedExecute(client, childCap, childCapSig, uri, "get", params, resource)
	if err != nil {
		return fail(catSecurity, "expired_capability_denied", "V7 §5.2", "build: "+err.Error())
	}

	return sendAndExpectAuthzDeny(client, env, "expired_capability_denied", "V7 §5.2")
}

func checkNotBeforeDenied(ctx context.Context, client *PeerClient) CheckResult {
	// Delegate a child cap with not_before far in the future.
	kp := client.Keypair()
	identity := client.IdentityEntity()
	parentCap := client.CapEntity()
	uri := fmt.Sprintf("entity://%s/system/tree", client.RemotePeerID())

	now := uint64(time.Now().UnixMilli())
	future := now + 365*24*60*60*1000 // 1 year in the future
	tokenData := types.CapabilityTokenData{
		Grants: []types.GrantEntry{{
			Handlers:   types.CapabilityScope{Include: []string{"*"}},
			Resources:  types.CapabilityScope{Include: []string{"*"}},
			Operations: types.CapabilityScope{Include: []string{"*"}},
		}},
		Granter:   types.SingleSigGranter(identity.ContentHash),
		Grantee:   identity.ContentHash,
		Parent:    &parentCap.ContentHash,
		CreatedAt: now,
		NotBefore: &future,
	}

	childCap, childCapSig, err := createCapabilityToken(tokenData, kp, identity)
	if err != nil {
		return fail(catSecurity, "not_before_denied", "V7 §5.2", "create cap: "+err.Error())
	}

	params, resource, err := buildSimpleGetParams()
	if err != nil {
		return fail(catSecurity, "not_before_denied", "V7 §5.2", "setup: "+err.Error())
	}

	env, err := buildDelegatedExecute(client, childCap, childCapSig, uri, "get", params, resource)
	if err != nil {
		return fail(catSecurity, "not_before_denied", "V7 §5.2", "build: "+err.Error())
	}

	return sendAndExpectAuthzDeny(client, env, "not_before_denied", "V7 §5.2")
}

// sendScopeTest is a helper for Phase 2 scope checks. It creates a delegated
// capability with the given restricted grants, then sends a request that exceeds
// the scope and expects 403.
func sendScopeTest(
	ctx context.Context,
	client *PeerClient,
	checkName, specRef string,
	restrictedGrant types.GrantEntry,
	handler, operation string,
	resourcePath string,
) CheckResult {
	kp := client.Keypair()
	identity := client.IdentityEntity()
	parentCap := client.CapEntity()
	uri := fmt.Sprintf("entity://%s/%s", client.RemotePeerID(), handler)

	now := uint64(time.Now().UnixMilli())
	fiveMin := now + 5*60*1000
	tokenData := types.CapabilityTokenData{
		Grants:    []types.GrantEntry{restrictedGrant},
		Granter:   types.SingleSigGranter(identity.ContentHash),
		Grantee:   identity.ContentHash,
		Parent:    &parentCap.ContentHash,
		CreatedAt: now,
		ExpiresAt: &fiveMin,
	}

	childCap, childCapSig, err := createCapabilityToken(tokenData, kp, identity)
	if err != nil {
		return fail(catSecurity, checkName, specRef, "create child cap: "+err.Error())
	}

	params, _, err := buildSimpleGetParams()
	if err != nil {
		return fail(catSecurity, checkName, specRef, "setup: "+err.Error())
	}

	resource := &types.ResourceTarget{Targets: []string{resourcePath}}

	env, err := buildDelegatedExecute(client, childCap, childCapSig, uri, operation, params, resource)
	if err != nil {
		return fail(catSecurity, checkName, specRef, "build: "+err.Error())
	}

	// Scope checks (operation / handler / resource) are authz-class — the
	// child cap's grant restrictions exclude the request, surfacing as the
	// §5.2 authorization-domain DENY (v7.71 §3.3 403).
	return sendAndExpectAuthzDeny(client, env, checkName, specRef)
}
