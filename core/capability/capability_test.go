package capability

import (
	"testing"

	"go.entitychurch.org/entity-core-go/core/crypto"
	"go.entitychurch.org/entity-core-go/core/entity"
	"go.entitychurch.org/entity-core-go/core/hash"
	"go.entitychurch.org/entity-core-go/core/types"
)

// Test peer IDs — proper 46-char Base58 format matching real PeerID generation.
const testPeerID = crypto.PeerID("2KZFtestpeerAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")
const testPeerB = crypto.PeerID("3MbGtargetPeerBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB")
const testPeerC = crypto.PeerID("4NcHremotePeerCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC")

func TestMatchesPatternExact(t *testing.T) {
	tests := []struct {
		uri     string
		pattern string
		want    bool
	}{
		{"system/tree/", "system/tree/", true},
		{"system/tree/", "system/type/", false},
		{"system/tree", "system/tree", true},
	}
	for _, tt := range tests {
		got := MatchesPattern(tt.uri, tt.pattern)
		if got != tt.want {
			t.Errorf("MatchesPattern(%q, %q) = %v, want %v", tt.uri, tt.pattern, got, tt.want)
		}
	}
}

func TestMatchesPatternUniversal(t *testing.T) {
	if !MatchesPattern("anything", "*") {
		t.Fatal("* should match anything")
	}
}

func TestMatchesPatternSubtree(t *testing.T) {
	tests := []struct {
		uri     string
		pattern string
		want    bool
	}{
		{"system/tree/foo/bar", "system/tree/*", true},
		{"system/tree/", "system/tree/*", true},
		{"system/tree", "system/tree/*", true},
		{"system/type/foo", "system/tree/*", false},
	}
	for _, tt := range tests {
		got := MatchesPattern(tt.uri, tt.pattern)
		if got != tt.want {
			t.Errorf("MatchesPattern(%q, %q) = %v, want %v", tt.uri, tt.pattern, got, tt.want)
		}
	}
}

func TestMatchesPatternPeerWildcard(t *testing.T) {
	tests := []struct {
		uri     string
		pattern string
		want    bool
	}{
		{"/" + string(testPeerID) + "/system/tree", "/*/system/tree", true},
		{"/" + string(testPeerB) + "/system/tree", "/*/system/tree", true},
		{"system/tree", "/*/system/tree", false}, // no leading / — not absolute
		{"/" + string(testPeerID) + "/system/tree/foo", "/*/system/tree/*", true},
		{"/" + string(testPeerID) + "/anything", "/*/*", true},        // all peers, all paths
		{"/" + string(testPeerB) + "/deep/nested/path", "/*/*", true}, // /*/*  remainder is * → match all
	}
	for _, tt := range tests {
		got := MatchesPattern(tt.uri, tt.pattern)
		if got != tt.want {
			t.Errorf("MatchesPattern(%q, %q) = %v, want %v", tt.uri, tt.pattern, got, tt.want)
		}
	}
}

func TestCanonicalize(t *testing.T) {
	pid := testPeerID

	tests := []struct {
		path string
		want string
	}{
		{"system/tree/", "/" + string(testPeerID) + "/system/tree/"},
		{"local/files", "/" + string(testPeerID) + "/local/files"},
		{"*", "/" + string(testPeerID) + "/*"},                                                       // bare * → local peer all paths
		{"/already/absolute", "/already/absolute"},                                                   // pass through
		{"entity://" + string(testPeerB) + "/system/tree", "/" + string(testPeerB) + "/system/tree"}, // URI → absolute
	}
	for _, tt := range tests {
		got := Canonicalize(tt.path, pid)
		if got != tt.want {
			t.Errorf("Canonicalize(%q) = %q, want %q", tt.path, got, tt.want)
		}
	}
}

// TestCapResourceCanonicalization_PR8 pins V7 §5.5 / PROPOSAL §PR-8: bare
// "*" in a cap RESOURCE pattern is peer-local (canonicalizes to
// "/{peer}/*"), NOT a universal cross-peer wildcard. Cross-peer authority
// requires explicit "/*/*" or named-peer absolute form.
func TestCapResourceCanonicalization_PR8(t *testing.T) {
	pid := testPeerID
	otherPath := "/" + string(testPeerB) + "/some/resource"
	localPath := "/" + string(testPeerID) + "/some/resource"

	// Bare "*" cap resource: covers local-peer paths only.
	if !IsCoveredBy(localPath, []string{"*"}, pid, pid) {
		t.Fatal("bare * should cover local-peer paths")
	}
	if IsCoveredBy(otherPath, []string{"*"}, pid, pid) {
		t.Fatal("bare * MUST NOT cover cross-peer paths (peer-local rule)")
	}

	// Universal cross-peer requires "/*/*" explicit form.
	if !IsCoveredBy(otherPath, []string{"/*/*"}, pid, pid) {
		t.Fatal("/*/* should cover cross-peer paths")
	}
	if !IsCoveredBy(localPath, []string{"/*/*"}, pid, pid) {
		t.Fatal("/*/* should also cover local-peer paths")
	}
}

func TestCheckPermission(t *testing.T) {
	cap := types.CapabilityTokenData{
		Grants: []types.GrantEntry{
			{
				Handlers:   types.CapabilityScope{Include: []string{"system/tree"}},
				Resources:  types.CapabilityScope{Include: []string{"system/tree/*"}},
				Operations: types.CapabilityScope{Include: []string{"get", "put"}},
			},
		},
	}
	exec := types.ExecuteData{
		Operation: "get",
	}

	pid := testPeerID
	if !CheckPermission(exec, cap, "system/tree", pid, pid) {
		t.Fatal("should allow get on system/tree")
	}

	exec.Operation = "delete"
	if CheckPermission(exec, cap, "system/tree", pid, pid) {
		t.Fatal("should deny delete on system/tree")
	}
}

func TestCheckPermissionWildcardOperations(t *testing.T) {
	cap := types.CapabilityTokenData{
		Grants: []types.GrantEntry{
			{
				Handlers:   types.CapabilityScope{Include: []string{"system/tree"}},
				Resources:  types.CapabilityScope{Include: []string{"*"}},
				Operations: types.CapabilityScope{Include: []string{"*"}},
			},
		},
	}
	pid := testPeerID

	for _, op := range []string{"get", "put", "delete", "subscribe", "anything"} {
		exec := types.ExecuteData{Operation: op}
		if !CheckPermission(exec, cap, "system/tree", pid, pid) {
			t.Fatalf("wildcard operations should allow %q", op)
		}
	}
}

func TestCheckPermissionHandlerIsolation(t *testing.T) {
	// A capability scoped to system/tree must NOT authorize system/capability.
	cap := types.CapabilityTokenData{
		Grants: []types.GrantEntry{
			{
				Handlers:   types.CapabilityScope{Include: []string{"system/tree"}},
				Resources:  types.CapabilityScope{Include: []string{"system/type/*", "system/handler/*"}},
				Operations: types.CapabilityScope{Include: []string{"get"}},
			},
		},
	}
	exec := types.ExecuteData{Operation: "get"}
	pid := testPeerID

	// Correct handler: allowed.
	if !CheckPermission(exec, cap, "system/tree", pid, pid) {
		t.Fatal("should allow get on system/tree handler")
	}

	// Wrong handler: denied.
	if CheckPermission(exec, cap, "system/capability", pid, pid) {
		t.Fatal("should deny get on system/capability handler — wrong handler scope")
	}

	// Wildcard handler: allowed for any handler.
	wildcardCap := types.CapabilityTokenData{
		Grants: []types.GrantEntry{
			{
				Handlers:   types.CapabilityScope{Include: []string{"*"}},
				Resources:  types.CapabilityScope{Include: []string{"*"}},
				Operations: types.CapabilityScope{Include: []string{"get"}},
			},
		},
	}
	if !CheckPermission(exec, wildcardCap, "system/capability", pid, pid) {
		t.Fatal("wildcard handlers should allow any handler")
	}

	// Subtree handler pattern: system/* covers system/tree but not custom/handler.
	subtreeCap := types.CapabilityTokenData{
		Grants: []types.GrantEntry{
			{
				Handlers:   types.CapabilityScope{Include: []string{"system/*"}},
				Resources:  types.CapabilityScope{Include: []string{"*"}},
				Operations: types.CapabilityScope{Include: []string{"get"}},
			},
		},
	}
	if !CheckPermission(exec, subtreeCap, "system/tree", pid, pid) {
		t.Fatal("system/* should cover system/tree")
	}
	if CheckPermission(exec, subtreeCap, "custom/handler", pid, pid) {
		t.Fatal("system/* should NOT cover custom/handler")
	}

	// Empty handlers: nothing matches.
	emptyCap := types.CapabilityTokenData{
		Grants: []types.GrantEntry{
			{
				Handlers:   types.CapabilityScope{Include: []string{}},
				Resources:  types.CapabilityScope{Include: []string{"*"}},
				Operations: types.CapabilityScope{Include: []string{"get"}},
			},
		},
	}
	if CheckPermission(exec, emptyCap, "system/tree", pid, pid) {
		t.Fatal("empty handlers should deny everything")
	}
}

func TestCheckPathPermissionHandlerIsolation(t *testing.T) {
	// Level 2 also filters by handler — a grant for system/tree should not
	// authorize path access when the handler is system/capability.
	cap := types.CapabilityTokenData{
		Grants: []types.GrantEntry{
			{
				Handlers:   types.CapabilityScope{Include: []string{"system/tree"}},
				Resources:  types.CapabilityScope{Include: []string{"*"}},
				Operations: types.CapabilityScope{Include: []string{"get"}},
			},
		},
	}
	pid := testPeerID

	// Correct handler: path check passes.
	if !CheckPathPermission("get", "system/type/foo", cap, "system/tree", pid, pid) {
		t.Fatal("should allow path access with matching handler")
	}

	// Wrong handler: path check denied even though resources match.
	if CheckPathPermission("get", "system/type/foo", cap, "system/capability", pid, pid) {
		t.Fatal("should deny path access with wrong handler")
	}
}

func TestCheckPathPermissionWithExclude(t *testing.T) {
	cap := types.CapabilityTokenData{
		Grants: []types.GrantEntry{
			{
				Handlers:   types.CapabilityScope{Include: []string{"system/tree"}},
				Resources:  types.CapabilityScope{Include: []string{"*"}, Exclude: []string{"system/capability/*"}},
				Operations: types.CapabilityScope{Include: []string{"get"}},
			},
		},
	}

	pid := testPeerID
	if !CheckPathPermission("get", "system/tree/foo", cap, "system/tree", pid, pid) {
		t.Fatal("should allow get on system/tree/foo")
	}

	if CheckPathPermission("get", "system/capability/tokens", cap, "system/tree", pid, pid) {
		t.Fatal("should deny get on excluded system/capability/tokens")
	}
}

func TestCheckPathPermission(t *testing.T) {
	cap := types.CapabilityTokenData{
		Grants: []types.GrantEntry{
			{
				Handlers:   types.CapabilityScope{Include: []string{"system/tree"}},
				Resources:  types.CapabilityScope{Include: []string{"system/tree/*"}},
				Operations: types.CapabilityScope{Include: []string{"get"}},
			},
		},
	}

	pid := testPeerID

	if !CheckPathPermission("get", "system/tree/foo/bar", cap, "system/tree", pid, pid) {
		t.Fatal("should allow get on subtree path")
	}

	if CheckPathPermission("put", "system/tree/foo", cap, "system/tree", pid, pid) {
		t.Fatal("should deny put")
	}
}

func TestIsAttenuated(t *testing.T) {
	pid := testPeerID

	parent := types.CapabilityTokenData{
		Grants: []types.GrantEntry{
			{
				Handlers:   types.CapabilityScope{Include: []string{"system/tree"}},
				Resources:  types.CapabilityScope{Include: []string{"system/tree/*"}},
				Operations: types.CapabilityScope{Include: []string{"get", "put"}},
			},
		},
	}

	// Valid attenuation: subset of operations.
	child := types.CapabilityTokenData{
		Grants: []types.GrantEntry{
			{
				Handlers:   types.CapabilityScope{Include: []string{"system/tree"}},
				Resources:  types.CapabilityScope{Include: []string{"system/tree/*"}},
				Operations: types.CapabilityScope{Include: []string{"get"}},
			},
		},
	}
	if !IsAttenuated(child, parent, pid, pid) {
		t.Fatal("should be properly attenuated")
	}

	// Invalid attenuation: expanded operations.
	bad := types.CapabilityTokenData{
		Grants: []types.GrantEntry{
			{
				Handlers:   types.CapabilityScope{Include: []string{"system/tree"}},
				Resources:  types.CapabilityScope{Include: []string{"system/tree/*"}},
				Operations: types.CapabilityScope{Include: []string{"get", "put", "delete"}},
			},
		},
	}
	if IsAttenuated(bad, parent, pid, pid) {
		t.Fatal("should not be attenuated: expanded operations")
	}
}

func TestIsAttenuatedExpiration(t *testing.T) {
	pid := testPeerID

	parentExpiry := uint64(1000)
	parent := types.CapabilityTokenData{
		Grants: []types.GrantEntry{
			{Handlers: types.CapabilityScope{Include: []string{"*"}}, Resources: types.CapabilityScope{Include: []string{"*"}}, Operations: types.CapabilityScope{Include: []string{"get"}}},
		},
		ExpiresAt: &parentExpiry,
	}

	// Child expires before parent: OK.
	childExpiry := uint64(500)
	child := types.CapabilityTokenData{
		Grants: []types.GrantEntry{
			{Handlers: types.CapabilityScope{Include: []string{"*"}}, Resources: types.CapabilityScope{Include: []string{"*"}}, Operations: types.CapabilityScope{Include: []string{"get"}}},
		},
		ExpiresAt: &childExpiry,
	}
	if !IsAttenuated(child, parent, pid, pid) {
		t.Fatal("child expiring before parent should be OK")
	}

	// Child expires after parent: bad.
	laterExpiry := uint64(2000)
	bad := types.CapabilityTokenData{
		Grants: []types.GrantEntry{
			{Handlers: types.CapabilityScope{Include: []string{"*"}}, Resources: types.CapabilityScope{Include: []string{"*"}}, Operations: types.CapabilityScope{Include: []string{"get"}}},
		},
		ExpiresAt: &laterExpiry,
	}
	if IsAttenuated(bad, parent, pid, pid) {
		t.Fatal("child should not expire after parent")
	}

	// Child has no expiration when parent does: bad.
	noExpiry := types.CapabilityTokenData{
		Grants: []types.GrantEntry{
			{Handlers: types.CapabilityScope{Include: []string{"*"}}, Resources: types.CapabilityScope{Include: []string{"*"}}, Operations: types.CapabilityScope{Include: []string{"get"}}},
		},
	}
	if IsAttenuated(noExpiry, parent, pid, pid) {
		t.Fatal("child without expiry when parent has one should fail")
	}
}

func TestVerifyChainRootCapability(t *testing.T) {
	// Create a root capability: granter is local peer, no parent.
	localKP, _ := crypto.Generate()
	granteeKP, _ := crypto.Generate()

	localIdentity, _ := localKP.IdentityEntity()
	granteeIdentity, _ := granteeKP.IdentityEntity()

	capData := types.CapabilityTokenData{
		Grants: []types.GrantEntry{
			{Handlers: types.CapabilityScope{Include: []string{"system/tree"}}, Resources: types.CapabilityScope{Include: []string{"system/tree/*"}}, Operations: types.CapabilityScope{Include: []string{"get"}}},
		},
		Granter:   types.SingleSigGranter(localIdentity.ContentHash),
		Grantee:   granteeIdentity.ContentHash,
		CreatedAt: 1000,
	}
	capEntity, err := capData.ToEntity()
	if err != nil {
		t.Fatal(err)
	}

	// Sign the capability with local keypair.
	sig := localKP.Sign(capEntity.ContentHash.Bytes())
	sigData := types.SignatureData{
		Target:    capEntity.ContentHash,
		Signer:    localIdentity.ContentHash,
		Algorithm: "ed25519",
		Signature: sig,
	}
	sigEntity, err := sigData.ToEntity()
	if err != nil {
		t.Fatal(err)
	}

	included := map[hash.Hash]entity.Entity{
		localIdentity.ContentHash:   localIdentity,
		granteeIdentity.ContentHash: granteeIdentity,
		sigEntity.ContentHash:       sigEntity,
	}

	err = VerifyChain(capEntity, included, localKP.PeerID())
	if err != nil {
		t.Fatalf("expected valid chain, got: %v", err)
	}
}

func TestVerifyChainInvalidSignature(t *testing.T) {
	localKP, _ := crypto.Generate()
	granteeKP, _ := crypto.Generate()

	localIdentity, _ := localKP.IdentityEntity()
	granteeIdentity, _ := granteeKP.IdentityEntity()

	capData := types.CapabilityTokenData{
		Grants: []types.GrantEntry{
			{Handlers: types.CapabilityScope{Include: []string{"*"}}, Resources: types.CapabilityScope{Include: []string{"*"}}, Operations: types.CapabilityScope{Include: []string{"get"}}},
		},
		Granter:   types.SingleSigGranter(localIdentity.ContentHash),
		Grantee:   granteeIdentity.ContentHash,
		CreatedAt: 1000,
	}
	capEntity, _ := capData.ToEntity()

	// Bad signature.
	badSig := make([]byte, 64)
	sigData := types.SignatureData{
		Target:    capEntity.ContentHash,
		Signer:    localIdentity.ContentHash,
		Algorithm: "ed25519",
		Signature: badSig,
	}
	sigEntity, _ := sigData.ToEntity()

	included := map[hash.Hash]entity.Entity{
		localIdentity.ContentHash:   localIdentity,
		granteeIdentity.ContentHash: granteeIdentity,
		sigEntity.ContentHash:       sigEntity,
	}

	err := VerifyChain(capEntity, included, localKP.PeerID())
	if err == nil {
		t.Fatal("expected error for invalid signature")
	}
}

func TestCheckResourceScope(t *testing.T) {
	pid := testPeerID

	// Resource covered by wildcard grant.
	resource := &types.ResourceTarget{Targets: []string{"system/tree/foo"}}
	scope := types.CapabilityScope{Include: []string{"*"}}
	if !CheckResourceScope(resource, scope, pid, pid) {
		t.Fatal("wildcard should cover any resource")
	}

	// Resource covered by subtree grant.
	scope = types.CapabilityScope{Include: []string{"system/tree/*"}}
	if !CheckResourceScope(resource, scope, pid, pid) {
		t.Fatal("subtree pattern should cover system/tree/foo")
	}

	// Resource NOT covered.
	scope = types.CapabilityScope{Include: []string{"local/files/*"}}
	if CheckResourceScope(resource, scope, pid, pid) {
		t.Fatal("local/files/* should not cover system/tree/foo")
	}

	// Multiple targets, all covered.
	resource = &types.ResourceTarget{Targets: []string{"system/tree/a", "system/tree/b"}}
	scope = types.CapabilityScope{Include: []string{"system/tree/*"}}
	if !CheckResourceScope(resource, scope, pid, pid) {
		t.Fatal("subtree should cover both targets")
	}

	// Multiple targets, one NOT covered.
	resource = &types.ResourceTarget{Targets: []string{"system/tree/a", "local/files/b"}}
	if CheckResourceScope(resource, scope, pid, pid) {
		t.Fatal("system/tree/* should not cover local/files/b")
	}

	// Excluded resource.
	resource = &types.ResourceTarget{Targets: []string{"system/tree/secret"}}
	scope = types.CapabilityScope{
		Include: []string{"system/tree/*"},
		Exclude: []string{"system/tree/secret"},
	}
	if CheckResourceScope(resource, scope, pid, pid) {
		t.Fatal("excluded resource should be denied")
	}
}

func TestCheckPermissionWithResource(t *testing.T) {
	cap := types.CapabilityTokenData{
		Grants: []types.GrantEntry{
			{
				Handlers:   types.CapabilityScope{Include: []string{"system/tree"}},
				Resources:  types.CapabilityScope{Include: []string{"system/tree/*"}},
				Operations: types.CapabilityScope{Include: []string{"get"}},
			},
		},
	}
	pid := testPeerID

	// With matching resource: allowed.
	exec := types.ExecuteData{
		Operation: "get",
		Resource:  &types.ResourceTarget{Targets: []string{"system/tree/foo"}},
	}
	if !CheckPermission(exec, cap, "system/tree", pid, pid) {
		t.Fatal("should allow get with covered resource")
	}

	// With non-matching resource: denied.
	exec.Resource = &types.ResourceTarget{Targets: []string{"local/files/secret"}}
	if CheckPermission(exec, cap, "system/tree", pid, pid) {
		t.Fatal("should deny get with uncovered resource")
	}

	// Without resource: still allowed (backward compatible).
	exec.Resource = nil
	if !CheckPermission(exec, cap, "system/tree", pid, pid) {
		t.Fatal("should allow get without resource (backward compatible)")
	}
}

func TestCheckPermissionWithPeers(t *testing.T) {
	pid := testPeerID
	otherPID := testPeerB

	// Grant restricted to specific peer.
	cap := types.CapabilityTokenData{
		Grants: []types.GrantEntry{
			{
				Handlers:   types.CapabilityScope{Include: []string{"*"}},
				Resources:  types.CapabilityScope{Include: []string{"*"}},
				Operations: types.CapabilityScope{Include: []string{"get"}},
				Peers:      &types.CapabilityScope{Include: []string{string(testPeerID)}},
			},
		},
	}
	exec := types.ExecuteData{Operation: "get"}

	// Matching peer: allowed.
	if !CheckPermission(exec, cap, "system/tree", pid, pid) {
		t.Fatal("should allow on matching peer")
	}

	// Different peer: denied.
	if CheckPermission(exec, cap, "system/tree", otherPID, otherPID) {
		t.Fatal("should deny on different peer")
	}

	// Wildcard peers: allowed for any.
	cap.Grants[0].Peers = &types.CapabilityScope{Include: []string{"*"}}
	if !CheckPermission(exec, cap, "system/tree", otherPID, otherPID) {
		t.Fatal("wildcard peers should allow any peer")
	}

	// Explicit peer ID in peers scope.
	cap.Grants[0].Peers = &types.CapabilityScope{Include: []string{string(testPeerID)}}
	if !CheckPermission(exec, cap, "system/tree", pid, pid) {
		t.Fatal("explicit peer ID should match localPeerID")
	}
}

// TestCheckPermissionPeersFromURI exercises the §5.2 peers dimension as the
// spec defines it: the peer under test is extract_peer(execute.uri), NOT the
// local peer, and an absent `peers` field DEFAULTS to {include:[local]} and is
// still checked — it does not skip the dimension. Before the fix, Go tested
// localPeerID and skipped absent-peers, so P-2 and P-3 below (a local-scoped
// grant / an absent field authorizing a FOREIGN namespace) both wrongly
// ALLOWed — a privilege escalation invisible to the old test, which only ever
// set target == local via an empty URI. Peer IDs here are valid 46-char Base58
// so extract_peer recognizes them (the older 45-char test constants do not).
func TestCheckPermissionPeersFromURI(t *testing.T) {
	const local = crypto.PeerID("2KZFlocalPeerLAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")  // 46
	const remote = crypto.PeerID("3MbGremotePeerRBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB") // 46
	if len(local) != 46 || len(remote) != 46 {
		t.Fatalf("test peer ids must be 46 chars: local=%d remote=%d", len(local), len(remote))
	}

	mkCap := func(peers *types.CapabilityScope) types.CapabilityTokenData {
		return types.CapabilityTokenData{
			Grants: []types.GrantEntry{{
				Handlers:   types.CapabilityScope{Include: []string{"*"}},
				Resources:  types.CapabilityScope{Include: []string{"*"}},
				Operations: types.CapabilityScope{Include: []string{"get"}},
				Peers:      peers,
			}},
		}
	}
	exec := func(uri string) types.ExecuteData {
		return types.ExecuteData{Operation: "get", URI: uri}
	}
	localURI := "/" + string(local) + "/system/tree"
	remoteURI := "/" + string(remote) + "/system/tree"

	tests := []struct {
		name  string
		peers *types.CapabilityScope
		uri   string
		want  bool
	}{
		// P-1: foreign-scoped grant, foreign target — allowed (the harmless direction).
		{"P1_grant_R_uri_R", &types.CapabilityScope{Include: []string{string(remote)}}, remoteURI, true},
		// P-2: local-scoped grant, foreign target — DENY (escalation via wrong operand).
		{"P2_grant_L_uri_R", &types.CapabilityScope{Include: []string{string(local)}}, remoteURI, false},
		// P-3: absent peers, foreign target — DENY (absent defaults to {include:[local]}).
		{"P3_absent_uri_R", nil, remoteURI, false},
		// Sanity: absent peers, local target — allowed (the common single-peer cap).
		{"absent_uri_L", nil, localURI, true},
		// Sanity: foreign-scoped grant, local target — DENY.
		{"grant_R_uri_L", &types.CapabilityScope{Include: []string{string(remote)}}, localURI, false},
		// Wildcard peers authorizes any target.
		{"wildcard_uri_R", &types.CapabilityScope{Include: []string{"*"}}, remoteURI, true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := CheckPermission(exec(tc.uri), mkCap(tc.peers), "system/tree", local, local)
			if got != tc.want {
				t.Fatalf("CheckPermission(uri=%s, peers=%v) = %v, want %v", tc.uri, tc.peers, got, tc.want)
			}
		})
	}
}

// TestExtractPeer pins the §5.2 extract_peer contract: first segment when a
// syntactic peer_id (≥46 Base58 chars), else local. Short-form handler paths
// and sub-46 segments resolve to local.
func TestExtractPeer(t *testing.T) {
	const local = crypto.PeerID("2KZFlocalPeerLAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")  // 46
	const remote = crypto.PeerID("3MbGremotePeerRBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB") // 46
	cases := []struct {
		in   string
		want crypto.PeerID
	}{
		{"/" + string(remote) + "/system/tree", remote},
		{"entity://" + string(remote) + "/system/tree", remote},
		{"/" + string(remote), remote},
		{"system/tree", local},        // short-form → local
		{"", local},                   // empty → local
		{"/short/system/tree", local}, // sub-46 first segment → local
		{"/" + string(local) + "/x", local},
	}
	for _, c := range cases {
		if got := extractPeer(c.in, local); got != c.want {
			t.Errorf("extractPeer(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

func TestMatchesPeerScope(t *testing.T) {
	pid := testPeerID

	// Wildcard includes everything.
	scope := types.CapabilityScope{Include: []string{"*"}}
	if !MatchesPeerScope(string(testPeerID), scope, pid) {
		t.Fatal("wildcard should include any peer")
	}

	// Exact match.
	scope = types.CapabilityScope{Include: []string{string(testPeerID)}}
	if !MatchesPeerScope(string(testPeerID), scope, pid) {
		t.Fatal("exact match should include")
	}

	// No match.
	scope = types.CapabilityScope{Include: []string{string(testPeerB)}}
	if MatchesPeerScope(string(testPeerID), scope, pid) {
		t.Fatal("should not include unmatched peer")
	}

	// Excluded.
	scope = types.CapabilityScope{Include: []string{"*"}, Exclude: []string{string(testPeerID)}}
	if MatchesPeerScope(string(testPeerID), scope, pid) {
		t.Fatal("excluded peer should be denied")
	}
}

func TestCanonicalizeSpecialValues(t *testing.T) {
	pid := testPeerID

	tests := []struct {
		path string
		want string
	}{
		{"*", "/" + string(testPeerID) + "/*"}, // peer-relative wildcard
		{"*/system/tree", "*/system/tree"},     // ambiguous — passed through (rejected by callers)
		{"./path", "./path"},                   // reserved — passed through
		{"../path", "../path"},                 // reserved — passed through
		{"/*/system/tree", "/*/system/tree"},   // absolute peer wildcard — pass through
		{"/*/*", "/*/*"},                       // all peers all paths — pass through
		{"system/tree/", "/" + string(testPeerID) + "/system/tree/"},
		{"local/files", "/" + string(testPeerID) + "/local/files"},
	}
	for _, tt := range tests {
		got := Canonicalize(tt.path, pid)
		if got != tt.want {
			t.Errorf("Canonicalize(%q) = %q, want %q", tt.path, got, tt.want)
		}
	}
}

func TestIsPattern(t *testing.T) {
	if !IsPattern("system/tree/*") {
		t.Fatal("system/tree/* should be a pattern")
	}
	if !IsPattern("*") {
		t.Fatal("* should be a pattern")
	}
	if IsPattern("system/tree") {
		t.Fatal("system/tree should not be a pattern")
	}
}

func TestPatternsOverlap(t *testing.T) {
	tests := []struct {
		a, b string
		want bool
	}{
		{"*", "anything", true},
		{"system/tree", "system/tree", true},
		{"system/tree", "system/type", false},
		{"system/tree/*", "system/tree/foo", true},
		{"system/tree/foo", "system/tree/*", true},
		{"system/*", "system/tree/*", true},
		{"system/tree/*", "local/files/*", false},
	}
	for _, tt := range tests {
		got := PatternsOverlap(tt.a, tt.b)
		if got != tt.want {
			t.Errorf("PatternsOverlap(%q, %q) = %v, want %v", tt.a, tt.b, got, tt.want)
		}
	}
}

func TestIsCoveredBy(t *testing.T) {
	pid := testPeerID

	if !IsCoveredBy("system/tree/foo", []string{"system/tree/*"}, pid, pid) {
		t.Fatal("system/tree/foo should be covered by system/tree/*")
	}
	if !IsCoveredBy("system/tree/foo", []string{"*"}, pid, pid) {
		t.Fatal("anything should be covered by *")
	}
	if IsCoveredBy("local/files/x", []string{"system/tree/*"}, pid, pid) {
		t.Fatal("local/files/x should not be covered by system/tree/*")
	}
}
