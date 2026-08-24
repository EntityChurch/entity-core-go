// The peer-issued fixture registry: loads a `-wire` bundle emitted by
// cmd/peerissued-fixtures and serves it as a static coral-reef registry
// over the Amendment 5 http-poll routes.
//
// This is the other half of the peer_issued wire vectors. The target peer
// is started with `--peer-issued-registry <pid>@http://<addr>` pinning THIS
// server as a peer-issued backend; the vectors then drive `system/registry:
// resolve` against the target and assert the observable outcome.
//
// Two properties make the wiring work, both load-bearing:
//
//   - **The registry peer-id is a deterministic constant.** It falls out of
//     the fixed seed in the bundle generator, so the target can be started
//     with the registry PINNED before this server exists — no chicken-and-egg,
//     no handshake, no port discovery on the peer's side.
//   - **The request log is the evidence.** Over the wire, four of the six
//     vectors collapse to the same observable status (`chain_exhausted`):
//     the meta-resolver's §2.2 advance-on-error drops the backend's reason
//     on the floor. Asserting status alone would pass just as well against a
//     peer that never consulted the backend at all. So this server records
//     every request path, and the vectors assert the FETCH PATTERN — which
//     is what actually distinguishes "rejected the binding for the right
//     reason" from "never looked."
//
// Scope is WholeStoreScope: every entity in the bundle is meant to be
// publicly fetchable — this is a fixture origin, not a peer with a private
// tree. The one deliberate absence is OFFLINE-NOTFOUND-1's name, which MUST
// 404 for the vector to mean anything.

package validate

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"go.entitychurch.org/entity-core-go/core/crypto"
	"go.entitychurch.org/entity-core-go/core/entity"
	"go.entitychurch.org/entity-core-go/core/hash"
	"go.entitychurch.org/entity-core-go/core/store"
	"go.entitychurch.org/entity-core-go/core/types"
	"go.entitychurch.org/entity-core-go/ext/httplive"

	"github.com/fxamacker/cbor/v2"
)

// peerIssuedExpected mirrors the `expected_result` object in MANIFEST.json.
// Deliberately a local struct rather than an import of the generator's type:
// the bundle is a wire contract consumed by three impls, so the validator
// reads it as data, not as Go internals.
type peerIssuedExpected struct {
	Status      string  `json:"status"`
	Binding     string  `json:"binding,omitempty"`
	PeerID      string  `json:"peer_id,omitempty"`
	TrustAnchor string  `json:"trust_anchor,omitempty"`
	NegTTLMs    *uint64 `json:"neg_ttl_ms,omitempty"`
	BackendID   string  `json:"backend_id,omitempty"`
	Error       string  `json:"error,omitempty"`
}

// peerIssuedVector is one MANIFEST.json vector entry.
type peerIssuedVector struct {
	ID                string             `json:"id"`
	Mode              string             `json:"mode"`
	Description       string             `json:"description"`
	ClockMs           uint64             `json:"clock_ms"`
	Name              string             `json:"name"`
	BindingHash       string             `json:"binding_hash,omitempty"`
	SignatureHash     string             `json:"signature_hash,omitempty"`
	RevocationHash    string             `json:"revocation_hash,omitempty"`
	RevocationSigHash string             `json:"revocation_signature_hash,omitempty"`
	Expected          peerIssuedExpected `json:"expected_result"`
	Files             []string           `json:"files"`

	// dir is the on-disk vector directory (filled in at load).
	dir string
}

// peerIssuedManifest is the bundle's top-level MANIFEST.json.
type peerIssuedManifest struct {
	BundleVersion        string             `json:"bundle_version"`
	Proposal             string             `json:"proposal"`
	RegistryPeerID       string             `json:"registry_peer_id"`
	RegistryIdentityHash string             `json:"registry_identity_hash"`
	NegativeTTLMs        uint64             `json:"negative_ttl_ms"`
	Vectors              []peerIssuedVector `json:"vectors"`
}

// vectorByShortID looks a vector up by its ID suffix ("RESOLVE-1"), which
// is also its directory name. Returns nil when the bundle predates the
// vector — the caller turns that into a FAIL naming the missing vector
// rather than silently testing five of six.
func (m *peerIssuedManifest) vectorByShortID(short string) *peerIssuedVector {
	for i := range m.Vectors {
		if strings.TrimPrefix(m.Vectors[i].ID, "REG-PEERISSUED-") == short {
			return &m.Vectors[i]
		}
	}
	return nil
}

// peerIssuedFixture is the loaded bundle plus the live HTTP origin serving it.
type peerIssuedFixture struct {
	manifest *peerIssuedManifest
	url      string // http://host:port — what the target peer was pinned to
	listener net.Listener
	srv      *http.Server

	mu   sync.Mutex
	reqs []string
}

// requests returns a snapshot of every path this origin has been asked for,
// in order.
func (f *peerIssuedFixture) requests() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := make([]string, len(f.reqs))
	copy(out, f.reqs)
	return out
}

// requestsSince returns the paths recorded after index `mark`, and the new
// mark. The vectors use this to scope the fetch-pattern assertion to their
// own resolve — six vectors share one long-lived origin.
func (f *peerIssuedFixture) requestsSince(mark int) ([]string, int) {
	all := f.requests()
	if mark > len(all) {
		mark = len(all)
	}
	return all[mark:], len(all)
}

func (f *peerIssuedFixture) mark() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.reqs)
}

func (f *peerIssuedFixture) close() {
	if f.srv != nil {
		_ = f.srv.Close()
	}
}

// decodeHashableEntity reconstructs an Entity from the bundle's `.cbor`
// bytes, which are `ecf.EncodeHashable(type, data)` — the same 2-key
// {data, type} body a CONTENT_GET returns on the wire. Rebuilding through
// entity.NewEntity recomputes the content hash, so a corrupted fixture is
// caught here rather than surfacing as a mysterious resolve failure.
func decodeHashableEntity(b []byte) (entity.Entity, error) {
	var raw struct {
		Type string          `cbor:"type"`
		Data cbor.RawMessage `cbor:"data"`
	}
	if err := cbor.Unmarshal(b, &raw); err != nil {
		return entity.Entity{}, fmt.Errorf("decode hashable wire: %w", err)
	}
	if raw.Type == "" {
		return entity.Entity{}, fmt.Errorf("decoded entity has empty type")
	}
	return entity.NewEntity(raw.Type, raw.Data)
}

// parseHash33 parses the bundle's 66-char hex hashes — the invariant-pointer
// form WITH the format byte. The 64-char digest-only form is rejected
// outright: accepting it here would let a bundle that used the wrong form
// still load, and that is exactly the class of bug the 66-char convention
// exists to make loud.
func parseHash33(s string) (hash.Hash, error) {
	s = strings.TrimSpace(s)
	if len(s) != 66 {
		return hash.Hash{}, fmt.Errorf("hash %q is %d hex chars, want 66 (33-byte algorithm||digest form)", s, len(s))
	}
	b, err := hex.DecodeString(s)
	if err != nil {
		return hash.Hash{}, fmt.Errorf("hash %q: %w", s, err)
	}
	return hash.FromBytes(b)
}

// loadPeerIssuedFixture reads the bundle at `dir`, loads every vector's
// entities into an in-memory store + location index under the registry's
// peer-id, and starts an http-poll origin on `addr`.
//
// The layout it publishes is the registry's read-side contract from
// PROPOSAL-PEER-ISSUED-REGISTRY-BACKEND §2.2:
//
//	system/registry/binding/by-name/{nfc(name)}          → binding hash
//	system/signature/{hex33(binding_hash)}               → signature hash
//	system/registry/revocation/by-target/{hex33(bh)}     → revocation hash
//	system/signature/{hex33(revocation_hash)}            → revocation sig hash
//
// plus the universal §3 binding storage path, and the registry identity
// itself (which the backend fetches to derive the pinned key).
func loadPeerIssuedFixture(dir, addr string) (*peerIssuedFixture, error) {
	manifestBytes, err := os.ReadFile(filepath.Join(dir, "MANIFEST.json"))
	if err != nil {
		return nil, fmt.Errorf("read MANIFEST.json: %w", err)
	}
	var m peerIssuedManifest
	if err := json.Unmarshal(manifestBytes, &m); err != nil {
		return nil, fmt.Errorf("parse MANIFEST.json: %w", err)
	}
	if m.RegistryPeerID == "" {
		return nil, fmt.Errorf("MANIFEST.json has no registry_peer_id")
	}

	// The bundle MUST be the -wire variant. The cohort bundle puts all six
	// vectors on one name, which against a single long-lived peer means
	// RESOLVE-1 warms the by-name cache and REVOKED-1 / EXPIRED-1 then
	// resolve out of that cache instead of the wire — each vector silently
	// measuring the previous one's leftovers. Detect it and refuse, rather
	// than emitting six green checks that measured nothing.
	names := map[string]string{}
	for _, v := range m.Vectors {
		if v.Name == "" {
			continue
		}
		if prev, dup := names[v.Name]; dup {
			return nil, fmt.Errorf(
				"bundle at %s is the COHORT bundle, not the wire bundle: %s and %s both resolve %q. "+
					"All six vectors sharing one name is correct for the byte-equality pin and wrong for "+
					"driving a live peer (cacheOnResolve makes each vector measure the previous one's "+
					"leftovers). Regenerate with: go run ./cmd/peerissued-fixtures -wire -out %s",
				dir, prev, v.ID, v.Name, dir)
		}
		names[v.Name] = v.ID
	}

	cs := store.NewMemoryContentStore()
	li := store.NewMemoryLocationIndex()
	nli := store.NewNamespacedIndex(li, m.RegistryPeerID)

	put := func(path string, b []byte) (hash.Hash, error) {
		ent, err := decodeHashableEntity(b)
		if err != nil {
			return hash.Hash{}, fmt.Errorf("%s: %w", path, err)
		}
		if _, err := cs.Put(ent); err != nil {
			return hash.Hash{}, fmt.Errorf("%s: store put: %w", path, err)
		}
		return ent.ContentHash, nil
	}

	// The registry identity — the backend fetches this to derive the pinned
	// verification key, so it must be servable by content hash.
	idPath := filepath.Join(dir, "registry", "identity.cbor")
	idBytes, err := os.ReadFile(idPath)
	if err != nil {
		return nil, fmt.Errorf("read registry identity: %w", err)
	}
	idHash, err := put(idPath, idBytes)
	if err != nil {
		return nil, err
	}
	if declared := strings.TrimSpace(m.RegistryIdentityHash); declared != "" {
		want, err := parseHash33(declared)
		if err != nil {
			return nil, fmt.Errorf("manifest registry_identity_hash: %w", err)
		}
		if want != idHash {
			return nil, fmt.Errorf(
				"registry identity hash drift: identity.cbor hashes to %s, MANIFEST.json declares %s — the bundle is inconsistent",
				idHash.String(), want.String())
		}
	}

	// Per-vector entities + the index entries that make them reachable.
	for i := range m.Vectors {
		v := &m.Vectors[i]
		v.dir = filepath.Join(dir, "vectors", strings.TrimPrefix(v.ID, "REG-PEERISSUED-"))

		if len(v.Files) == 0 {
			// OFFLINE-NOTFOUND-1 — nothing to serve. Its whole point is the
			// 404, so publishing anything here would break it.
			continue
		}

		hashes := map[string]hash.Hash{}
		for _, f := range v.Files {
			p := filepath.Join(v.dir, f)
			b, err := os.ReadFile(p)
			if err != nil {
				return nil, fmt.Errorf("%s: read %s: %w", v.ID, f, err)
			}
			h, err := put(p, b)
			if err != nil {
				return nil, err
			}
			hashes[strings.TrimSuffix(f, ".cbor")] = h
		}

		bindingHash, ok := hashes["binding"]
		if !ok {
			return nil, fmt.Errorf("%s: no binding.cbor among files %v", v.ID, v.Files)
		}
		// Cross-check the recomputed hash against the manifest's declaration.
		// A mismatch means the .cbor and MANIFEST.json disagree — load-time
		// failure beats a resolve that fails for an unexplained reason.
		if declared := v.BindingHash; declared != "" {
			want, err := parseHash33(declared)
			if err != nil {
				return nil, fmt.Errorf("%s binding_hash: %w", v.ID, err)
			}
			if want != bindingHash {
				return nil, fmt.Errorf("%s: binding.cbor hashes to %s, manifest declares %s",
					v.ID, bindingHash.String(), want.String())
			}
		}

		// §2.2 by-name pointer — the entry point for every live resolve.
		if err := nli.Set(types.PeerIssuedByNamePath(v.Name), bindingHash); err != nil {
			return nil, fmt.Errorf("%s: index by-name: %w", v.ID, err)
		}
		// §3 universal binding storage path.
		if err := nli.Set(types.BindingStoragePath(bindingHash), bindingHash); err != nil {
			return nil, fmt.Errorf("%s: index binding storage: %w", v.ID, err)
		}
		// V7 §5.2 invariant-pointer signature path — 66-char hex WITH the
		// format byte, via LocalSignaturePath (which uses h.Bytes()).
		if sigHash, ok := hashes["signature"]; ok {
			if err := nli.Set(types.LocalSignaturePath(bindingHash), sigHash); err != nil {
				return nil, fmt.Errorf("%s: index signature: %w", v.ID, err)
			}
		}
		// Revocation: the by-target index plus the revocation's own signature.
		if revHash, ok := hashes["revocation"]; ok {
			if err := nli.Set(types.PeerIssuedRevocationByTargetPath(bindingHash), revHash); err != nil {
				return nil, fmt.Errorf("%s: index revocation by-target: %w", v.ID, err)
			}
			if revSigHash, ok := hashes["revocation_signature"]; ok {
				if err := nli.Set(types.LocalSignaturePath(revHash), revSigHash); err != nil {
					return nil, fmt.Errorf("%s: index revocation signature: %w", v.ID, err)
				}
			}
		}
	}

	f := &peerIssuedFixture{manifest: &m}

	pollH := httplive.NewPollHandler("", cs, li, httplive.WholeStoreScope{}, crypto.PeerID(m.RegistryPeerID))
	logged := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		f.reqs = append(f.reqs, r.URL.Path)
		f.mu.Unlock()
		pollH.ServeHTTP(w, r)
	})

	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("listen on %s: %w", addr, err)
	}
	f.listener = ln
	f.url = "http://" + ln.Addr().String()
	f.srv = &http.Server{Handler: logged}
	go func() { _ = f.srv.Serve(ln) }()

	return f, nil
}

// --- fetch-pattern helpers -------------------------------------------------
//
// The vectors assert against the recorded request paths. These build the
// same URL shapes the PollHandler serves, so an assertion can't drift from
// the routes without the helper drifting too.

// treeLeafPath is the Amendment 5 TREE_GET leaf URL for a peer-relative
// path in the registry's tree: /{peer_id}/{path}.bin
func (f *peerIssuedFixture) treeLeafPath(peerRelative string) string {
	return "/" + f.manifest.RegistryPeerID + "/" + peerRelative + httplive.DefaultLeafSuffix
}

// contentPath is the Amendment 5 CONTENT_GET URL for a hash: /content/{hex33}
func contentPath(h hash.Hash) string {
	return "/content/" + hex.EncodeToString(h.Bytes())
}

// sawPath reports whether `want` appears in `paths`.
func sawPath(paths []string, want string) bool {
	for _, p := range paths {
		if p == want {
			return true
		}
	}
	return false
}

// anyPathContains reports whether any recorded path contains `sub`.
func anyPathContains(paths []string, sub string) bool {
	for _, p := range paths {
		if strings.Contains(p, sub) {
			return true
		}
	}
	return false
}
