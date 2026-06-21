// registry-issue-binding is the operator signing tool for the peer-issued
// REGISTRY backend (PROPOSAL-PEER-ISSUED-REGISTRY-BACKEND §3.2 — curated
// registration). Run by the registry's operator, holding the registry's
// signing key (which IS the running registry peer's identity); the tool
// connects to the registry peer over its live socket, signs a binding,
// and publishes the three artifacts (body + signature + by-name pointer)
// the peer-issued backend reads.
//
// This is "Part B.curated" — the v1 release path for the Entity Church
// Registry. Part B.live (publisher self-registration via register-request
// + issuer-policy) is an explicit follow-on cycle (proposal §3.3); the
// demo runs through this tool.
//
// Usage:
//
//	registry-issue-binding -addr host:port -identity registry-name \
//	    -name billslab.com -target-peer <base58> \
//	    [-transport <hex-hash>]... [-ttl 24h] [-notes "the BLλ ground"]
//
// The `-identity` MUST match the registry peer's running identity — the
// tool authenticates as the registry to itself, which gives it full caps
// to write under the registry's namespace.
package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"time"

	"go.entitychurch.org/entity-core-go/cmd/internal/validate"
	"go.entitychurch.org/entity-core-go/core/crypto"
	"go.entitychurch.org/entity-core-go/core/entity"
	"go.entitychurch.org/entity-core-go/core/types"
)

func main() {
	addr := flag.String("addr", "", "registry peer address (host:port)")
	identity := flag.String("identity", "", "registry identity name (loaded from ~/.entity/identities/)")
	name := flag.String("name", "", "name to bind (NFC-normalized, no '/' or control chars)")
	targetPeer := flag.String("target-peer", "", "target peer-id (base58, V7 §1.5) the name resolves to")
	ttl := flag.Duration("ttl", 0, "binding TTL (e.g. 24h); zero = no expiry")
	flag.Parse()

	requireFlag("addr", *addr)
	requireFlag("identity", *identity)
	requireFlag("name", *name)
	requireFlag("target-peer", *targetPeer)

	kp, err := crypto.LoadIdentity(*identity)
	if err != nil {
		fail("load identity %q: %v", *identity, err)
	}
	signerEnt, err := kp.IdentityEntity()
	if err != nil {
		fail("identity entity: %v", err)
	}

	body := types.BindingData{
		Name:         *name,
		Kind:         types.BindingKindPeerIssued,
		TargetPeerID: *targetPeer,
		IssuedAt:     uint64(time.Now().UnixMilli()),
	}
	if *ttl > 0 {
		v := uint64(ttl.Milliseconds())
		body.TTL = &v
	}

	bindingEnt, err := body.ToEntity()
	if err != nil {
		fail("encode binding: %v", err)
	}

	// V7 §5.2 signature over the binding's content_hash, signer = the
	// registry's identity. The peer-issued backend's verify (§2.1 step 3)
	// checks target / signer / crypto against this signature.
	sigBytes := kp.Sign(bindingEnt.ContentHash.Bytes())
	sigData := types.SignatureData{
		Target:    bindingEnt.ContentHash,
		Signer:    signerEnt.ContentHash,
		Algorithm: signerEnt.Type, // surface only; backend verifies via PeerData.key_type
		Signature: sigBytes,
	}
	sigEnt, err := sigData.ToEntity()
	if err != nil {
		fail("encode signature: %v", err)
	}

	// Connect to the registry over the live transport. Tool authenticates
	// AS the registry, so handshake gives it full caps.
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
	// is populated. Without it, c.capEntity stays zero and the unconditional
	// CreateAuthenticatedExecute include of capEntity by ContentHash ships a
	// zero-hash empty-Entity slot the responder rejects.
	for _, chk := range client.PerformHandshake(ctx) {
		if chk.Severity == validate.Fail {
			fail("handshake: %s — %s", chk.Name, chk.Message)
		}
	}

	// Three writes — body, signature, by-name pointer. All three bind to
	// `bindingEnt.ContentHash`; the by-name path lets the peer-issued
	// backend's TreeGet locate the binding by name in one round-trip.
	publish := func(label, path string, ent entity.Entity) {
		if _, err := client.TreePut(ctx, path, ent); err != nil {
			fail("%s tree:put @ %s: %v", label, path, err)
		}
	}
	publish("binding-body", types.BindingStoragePath(bindingEnt.ContentHash), bindingEnt)
	publish("signature", types.LocalSignaturePath(bindingEnt.ContentHash), sigEnt)
	publish("by-name-pointer", types.PeerIssuedByNamePath(*name), bindingEnt)

	fmt.Printf("issued peer-issued binding %s\n", bindingEnt.ContentHash)
	fmt.Printf("  name           %s\n", *name)
	fmt.Printf("  target_peer_id %s\n", *targetPeer)
	fmt.Printf("  registry       %s\n", kp.PeerID())
	if body.TTL != nil {
		fmt.Printf("  ttl            %dms\n", *body.TTL)
	}
}

func requireFlag(name, value string) {
	if value == "" {
		fmt.Fprintf(os.Stderr, "missing required -%s\n", name)
		flag.Usage()
		os.Exit(2)
	}
}

func fail(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "registry-issue-binding: "+format+"\n", args...)
	os.Exit(1)
}
