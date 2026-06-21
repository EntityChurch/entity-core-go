// registry-request-binding is the publisher-side CLI for the peer-issued
// REGISTRY backend (EXTENSION-REGISTRY §6a.9 — live registration). Run by
// a publisher who holds the keypair for `target_peer_id` and wants a
// registry to sign+publish a binding for some name.
//
// This is "Part B.live" — the self-service counterpart to the operator's
// registry-issue-binding (Part B.curated). The registry MUST be running
// with --issuer-policy-mode={open,allowlist,manual} for the request to be
// accepted; in `manual` mode the registry queues the request as
// pending_review and an operator approves out-of-band.
//
// Wire flow per §6a.9:
//   1. Build a system/registry/register-request entity.
//   2. Sign request.content_hash with the publisher's keypair — this is
//      Layer 1 ownership-proof (V7 §5.2 target-matching signature).
//   3. tree:put the signature at system/signature/{hex(request.content_hash)}.
//   4. EXECUTE register-request on system/registry/peer-issued. Registry
//      verifies layer-1, runs issuer-policy admission, signs+publishes the
//      binding on approve.
//
// Usage:
//
//	registry-request-binding -addr host:port -identity publisher-name \
//	    -name billslab.com [-requested-ttl 24h] [-transport <hex-hash>]...
//
// `-identity` IS the target_peer_id — the registry pins the name to the
// peer-id derived from this keypair. The publisher does not need a grant
// to write the signature entity (it is at the invariant-pointer path the
// handler looks up); the registry's --issuer-policy-mode flag SHOULD
// provide the system/capability/registry-request-binding grant per §6a.9.
package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"flag"
	"fmt"
	"os"
	"time"

	"go.entitychurch.org/entity-core-go/cmd/internal/validate"
	"go.entitychurch.org/entity-core-go/core/crypto"
	"go.entitychurch.org/entity-core-go/core/ecf"
	"go.entitychurch.org/entity-core-go/core/entity"
	"go.entitychurch.org/entity-core-go/core/types"
	"go.entitychurch.org/entity-core-go/ext/registry/peerissued"
)

func main() {
	addr := flag.String("addr", "", "registry peer address (host:port)")
	identity := flag.String("identity", "", "publisher identity name (loaded from ~/.entity/identities/) — IS target_peer_id")
	name := flag.String("name", "", "name to register")
	requestedTTL := flag.Duration("requested-ttl", 0, "publisher-suggested TTL; policy MAY clamp to default_ttl. Zero = registry chooses")
	flag.Parse()

	requireFlag("addr", *addr)
	requireFlag("identity", *identity)
	requireFlag("name", *name)

	kp, err := crypto.LoadIdentity(*identity)
	if err != nil {
		fail("load identity %q: %v", *identity, err)
	}
	signerEnt, err := kp.IdentityEntity()
	if err != nil {
		fail("identity entity: %v", err)
	}

	nonce := make([]byte, 16)
	if _, err := rand.Read(nonce); err != nil {
		fail("generate nonce: %v", err)
	}

	body := types.RegistryRegisterRequestData{
		Name:         *name,
		TargetPeerID: string(kp.PeerID()),
		Nonce:        nonce,
		IssuedAt:     uint64(time.Now().UnixMilli()),
	}
	if *requestedTTL > 0 {
		v := uint64(requestedTTL.Milliseconds())
		body.RequestedTTL = &v
	}

	reqEnt, err := body.ToEntity()
	if err != nil {
		fail("encode register-request: %v", err)
	}

	// Layer-1 ownership proof — signature by target_peer_id (the publisher)
	// over request.content_hash, at the §5.2 invariant-pointer path the
	// handler reads (LocalSignaturePath).
	sigBytes := kp.Sign(reqEnt.ContentHash.Bytes())
	sigData := types.SignatureData{
		Target:    reqEnt.ContentHash,
		Signer:    signerEnt.ContentHash,
		Algorithm: signerEnt.Type,
		Signature: sigBytes,
	}
	sigEnt, err := sigData.ToEntity()
	if err != nil {
		fail("encode signature: %v", err)
	}

	client, err := validate.NewPeerClientWithKeypair(*addr, kp)
	if err != nil {
		fail("connect: %v", err)
	}
	defer client.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if err := client.Connect(ctx); err != nil {
		fail("dial: %v", err)
	}
	// PerformHandshake drives V7 §4 hello+authenticate so the client's cap
	// is populated before SendExecute. Skipping this leaves c.capEntity at
	// zero — and CreateAuthenticatedExecute unconditionally includes
	// capEntity by ContentHash, which would ship a zero-hash empty-Entity
	// slot the responder rejects as "type is empty".
	for _, chk := range client.PerformHandshake(ctx) {
		if chk.Severity == validate.Fail {
			fail("handshake: %s — %s", chk.Name, chk.Message)
		}
	}

	// Publish signature at the invariant-pointer path. The handler reads
	// this via hctx.LocationIndex.Get(LocalSignaturePath(req.content_hash)).
	sigPath := types.LocalSignaturePath(reqEnt.ContentHash)
	if _, err := client.TreePut(ctx, sigPath, sigEnt); err != nil {
		fail("tree:put signature @ %s: %v", sigPath, err)
	}

	// EXECUTE register-request on the peer-issued handler.
	uri := fmt.Sprintf("entity://%s/%s", client.RemotePeerID(), peerissued.IssuerHandlerPattern)
	respEnv, _, err := client.SendExecute(ctx, uri, peerissued.OpRegisterRequest, reqEnt, nil)
	if err != nil {
		fail("execute register-request: %v", err)
	}
	resp, err := types.ExecuteResponseDataFromEntity(respEnv.Root)
	if err != nil {
		fail("decode execute-response: %v", err)
	}

	switch {
	case resp.Status >= 200 && resp.Status < 300:
		var bindResult types.LocalNameBindResultData
		if len(resp.Result) > 0 {
			var resultEnt entity.Entity
			if err := ecf.Decode(resp.Result, &resultEnt); err != nil {
				fail("decode result envelope: %v", err)
			}
			if bindResult, err = types.LocalNameBindResultDataFromEntity(resultEnt); err != nil {
				fail("decode bind-result: %v", err)
			}
		}
		fmt.Printf("registered name %q at %s\n", *name, *addr)
		fmt.Printf("  binding_hash    %s\n", bindResult.BindingHash)
		fmt.Printf("  target_peer_id  %s\n", body.TargetPeerID)
		fmt.Printf("  nonce           %s\n", hex.EncodeToString(nonce))
		fmt.Printf("  issued_at       %d\n", body.IssuedAt)
		if body.RequestedTTL != nil {
			fmt.Printf("  requested_ttl   %dms\n", *body.RequestedTTL)
		}
	default:
		// V7 §3.3 error payload is wrapped in resp.Result as an entity
		// whose Data decodes to {code, message}.
		errStr := decodeErrorPayload(resp)
		if errStr == "" {
			errStr = fmt.Sprintf("status=%d (no error payload)", resp.Status)
		}
		fmt.Fprintf(os.Stderr, "registry rejected request: status=%d %s\n", resp.Status, errStr)
		os.Exit(1)
	}
}

func decodeErrorPayload(resp types.ExecuteResponseData) string {
	if len(resp.Result) == 0 {
		return ""
	}
	var resultEnt entity.Entity
	if err := ecf.Decode(resp.Result, &resultEnt); err != nil {
		return ""
	}
	var errBody struct {
		Code    string `cbor:"code"`
		Message string `cbor:"message"`
	}
	if err := ecf.Decode(resultEnt.Data, &errBody); err != nil {
		return ""
	}
	if errBody.Code == "" {
		return ""
	}
	return fmt.Sprintf("code=%s message=%s", errBody.Code, errBody.Message)
}

func requireFlag(name, value string) {
	if value == "" {
		fmt.Fprintf(os.Stderr, "missing required -%s\n", name)
		flag.Usage()
		os.Exit(2)
	}
}

func fail(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "registry-request-binding: "+format+"\n", args...)
	os.Exit(1)
}
