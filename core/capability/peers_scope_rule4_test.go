package capability

import (
	"crypto/sha256"
	"testing"

	"github.com/mr-tron/base58"

	"go.entitychurch.org/entity-core-go/core/crypto"
	"go.entitychurch.org/entity-core-go/core/types"
)

// sha256FormOf builds the NON-canonical SHA-256-form (hash_type=0x01) peer-id for
// an Ed25519 keypair, whose canonical form is identity-form (hash_type=0x00). The
// two are the SAME identity in different wire forms; the SHA-256 form cannot be
// canonicalized without the public key (the digest is a one-way hash of it), so a
// verifier that has not contacted the peer sees it as unresolvable.
//
// Wire format (§1.5 / v7.66 §2.2): Base58(varint(key_type) || varint(hash_type)
// || digest). key_type 0x01 and hash_type 0x01 are both single-byte varints.
func sha256FormOf(t *testing.T, kp crypto.Keypair) string {
	t.Helper()
	sum := sha256.Sum256(kp.PublicKey)
	buf := append([]byte{crypto.KeyTypeEd25519, crypto.HashTypeSHA256}, sum[:]...)
	s := base58.Encode(buf)
	// Guard the construction: it must be a well-formed peer-id that is NOT already
	// canonical (else the test would not exercise the unresolvable arm).
	if _, ok := crypto.CanonicalizePeerID(crypto.PeerID(s)); ok {
		t.Fatalf("constructed SHA-256-form peer-id unexpectedly canonicalizes: %s", s)
	}
	return s
}

// TestPeersScope_Rule4_NonCanonicalExcludeFailsClosed pins ENTITY-CORE-PROTOCOL
// §3.6 rule 4 / §5.2 resolve_peer_scope (0.8.2.29): a received `peers.exclude`
// entry that cannot be canonicalized MUST match — the peer is excluded (fail
// closed) — rather than silently failing to match under a literal comparison,
// which left the named peer NOT excluded (authority granted by a canonicalization
// gap). Same scope-position asymmetry as the path-scope sentinel at 0.8.2.21,
// on the id-scope surface.
//
// Mutation witness: repoint MatchesPeerScope back to matchesIDScope (the bare
// literal matcher) and the fail-closed case below flips to "included" — the
// exclude no longer matches the SHA-256-form entry, so the peer is not excluded.
func TestPeersScope_Rule4_NonCanonicalExcludeFailsClosed(t *testing.T) {
	kp, err := crypto.Generate()
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	target := string(kp.PeerID()) // canonical identity-form (0x00) — the peer under test
	sha256Form := sha256FormOf(t, kp)

	other, err := crypto.Generate()
	if err != nil {
		t.Fatalf("generate other: %v", err)
	}
	otherCanonical := string(other.PeerID())

	pid := kp.PeerID()

	// THE FIX — a non-canonical (SHA-256-form) exclude naming the target's identity
	// MUST exclude it. Under the old literal matcher it did not (fail open).
	failClosed := types.CapabilityScope{Include: []string{"*"}, Exclude: []string{sha256Form}}
	if MatchesPeerScope(target, failClosed, pid) {
		t.Fatal("non-canonical peers.exclude naming the target MUST exclude it (§3.6 rule 4 fail-closed); " +
			"the peer was admitted — the exclude fail-open is live")
	}

	// POSITIVE CONTROL — a CANONICAL exclude of a DIFFERENT peer MUST NOT exclude
	// the target. This distinguishes "fail closed on an UNRESOLVABLE exclude" from
	// "exclude everything on any exclude": a resolvable, non-matching exclude is
	// correctly ignored, so the fix does not over-deny.
	otherExcluded := types.CapabilityScope{Include: []string{"*"}, Exclude: []string{otherCanonical}}
	if !MatchesPeerScope(target, otherExcluded, pid) {
		t.Fatal("a canonical exclude of a DIFFERENT peer must not exclude the target (over-denial)")
	}

	// REGRESSION GUARDS — the common cases are byte-for-byte unchanged.
	if !MatchesPeerScope(target, types.CapabilityScope{Include: []string{"*"}}, pid) {
		t.Fatal("wildcard include must admit")
	}
	if !MatchesPeerScope(target, types.CapabilityScope{Include: []string{target}}, pid) {
		t.Fatal("exact-literal include must admit")
	}
	if MatchesPeerScope(target, types.CapabilityScope{Include: []string{target}, Exclude: []string{target}}, pid) {
		t.Fatal("exact-literal exclude must deny")
	}
	if MatchesPeerScope(target, types.CapabilityScope{Include: []string{otherCanonical}}, pid) {
		t.Fatal("include of a different peer must not admit the target")
	}

	// INCLUDE fail-safe — an unresolvable include entry MUST NOT match (grant
	// withheld). (Same result as the old literal matcher, so not a mutation
	// discriminator, but it pins the include direction of rule 4.)
	if MatchesPeerScope(target, types.CapabilityScope{Include: []string{sha256Form}}, pid) {
		t.Fatal("unresolvable include entry must be withheld (§3.6 rule 4 include direction)")
	}
}
