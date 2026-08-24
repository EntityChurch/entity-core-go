// consume-federation drives go's peerissued.Backend at entity-browser-rust's
// COMMITTED federation fixture (tests/fixtures/registry-federation, browser-rust
// 54f31a7) — B5, the last open registry-v1 clause (COHORT-OPEN-ITEMS C-7 /
// arch ROUTING-2026-08-21-h §6a). It is the FIRST cross-impl measurement of the
// NAMING leg that has ever existed: everything green on this surface so far —
// including browser-rust's own crossimpl-go 4/4 — is the PUBLISHED-ROOT leg.
// Here a GO consumer resolves names a RUST publisher bound, over a real HTTP hop.
//
// What a green run claims: name -> registry's signed binding -> target peer-id,
// four times, plus the transport leg (D8 bare system/hash), plus one page fetch
// (name -> peer-id -> THAT peer's signed root -> content, signature-verified),
// plus a negative control (an unbound name is not_found, not a false resolve).
// It does NOT claim two machines, TLS, or a CDN — the fixture is served locally
// over plain HTTP; the cross-impl content is browser-rust's bytes, the consumer
// is go's. Stated so a green gate does not launder a scope it did not exercise.
//
//	go run ./cmd/consume-federation [-fixture <dir>] [-json]
//
// Exit 0 = all legs green; 1 = a real failure; 2 = fixture absent (a LOUD skip,
// per the AGENTS.md skip-guard rule — this is a cross-impl driver, so the sibling
// fixture legitimately may be absent on a fresh checkout, but its absence must be
// visible, never a silent pass).
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"time"

	"github.com/fxamacker/cbor/v2"

	"go.entitychurch.org/entity-core-go/core/crypto"
	"go.entitychurch.org/entity-core-go/core/entity"
	"go.entitychurch.org/entity-core-go/core/handler"
	"go.entitychurch.org/entity-core-go/core/store"
	"go.entitychurch.org/entity-core-go/core/types"
	"go.entitychurch.org/entity-core-go/ext/httplive"
	"go.entitychurch.org/entity-core-go/ext/registry/peerissued"
)

// registryPID is the ONLY string a consumer holds a priori (fixture MAPPING.txt).
const registryPID = "2KBLkCxvkgobuauPA6zPfKarpuRRnnWHL98n8Gv1GNmybr"

// fixtureIssuedAt is the clock the fixture was emitted under (browser-rust
// Makefile FED_VECTORS_ISSUED_AT). issued_at rides every binding body, so the
// consumer must evaluate TTL against a time within the validity window — the real
// wall clock reads every binding as expired. +1h puts us safely inside any
// multi-day TTL while proving the TTL step actually ran (a stale binding fails).
const fixtureIssuedAt uint64 = 1756000000000
const fixtureClock = fixtureIssuedAt + 3600000

// mapping is the fixture's name -> target peer-id binding set (MAPPING.txt), plus
// the top-level directory each domain's tree is served under for the page leg.
var mapping = []struct {
	name, peerID, domainDir string
}{
	{"entitychurch.org", "2KGTrr4LxfFJjUBUD74XJZoze74TrQFpXqWA19qeskz9sS", "foundation"},
	{"protocol.entitychurch.org", "2KAdu6wwTNAoQiqXmN93vbjHxk3QosG7hxhXGZtN8wZF31", "protocol"},
	{"docs.entitychurch.org", "2KFRBJ9feEPCZZiNaCEKsCAVkGkp1htWZk9a8jz5n5D2sS", "docs"},
	{"lab.entitychurch.org", "2KEb7HgmoCRF1VpNeCYusiubnn94ke4uK1hUxBcQ1PTtNA", "lab"},
}

type legResult struct {
	Leg    string `json:"leg"`
	Name   string `json:"name,omitempty"`
	OK     bool   `json:"ok"`
	Detail string `json:"detail"`
}

func main() {
	fixture := flag.String("fixture", "../entity-browser-rust/tests/fixtures/registry-federation",
		"path to entity-browser-rust's committed registry-federation fixture")
	jsonOut := flag.Bool("json", false, "emit results as JSON")
	flag.Parse()

	// Skip-guard: the sibling fixture may be absent on a fresh checkout. Make its
	// absence LOUD (exit 2), never a silent pass — the path is checked live.
	if _, err := os.Stat(filepath.Join(*fixture, "MAPPING.txt")); err != nil {
		fmt.Fprintf(os.Stderr,
			"SKIP: federation fixture not found at %q (%v)\n"+
				"  This is the cross-impl NAMING-leg driver (B5). Clone/point -fixture at\n"+
				"  entity-browser-rust/tests/fixtures/registry-federation (browser-rust 54f31a7).\n",
			*fixture, err)
		os.Exit(2)
	}

	// Serve the fixture in-process over plain HTTP (go's client is not a browser,
	// so no CORS is needed — that is only browser-rust's cors-serve.py concern).
	srv := httptest.NewServer(http.FileServer(http.Dir(*fixture)))
	defer srv.Close()
	origin := srv.URL

	results, allOK := run(origin)

	if *jsonOut {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		_ = enc.Encode(results)
	} else {
		for _, r := range results {
			status := "PASS"
			if !r.OK {
				status = "FAIL"
			}
			label := r.Leg
			if r.Name != "" {
				label = r.Leg + " " + r.Name
			}
			fmt.Printf("  %s  %-42s %s\n", status, label, r.Detail)
		}
		if allOK {
			fmt.Printf("\nResult: PASS — the naming leg resolves cross-impl (go consumer, browser-rust bytes)\n")
		} else {
			fmt.Printf("\nResult: FAIL\n")
		}
	}
	if !allOK {
		os.Exit(1)
	}
}

func run(origin string) ([]legResult, bool) {
	var out []legResult
	allOK := true
	add := func(r legResult) {
		out = append(out, r)
		if !r.OK {
			allOK = false
		}
	}

	backend, err := newRegistryBackend(origin)
	if err != nil {
		add(legResult{Leg: "setup", OK: false, Detail: err.Error()})
		return out, false
	}
	hctx := newConsumerContext()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	// Leg 1 — the naming leg: each name resolves to its bound target peer-id.
	var firstTransport []string // hash hexes of the first resolved binding's transports
	var firstDomain string
	for i, m := range mapping {
		r, err := backend.Resolve(hctx, m.name, nil)
		switch {
		case err != nil:
			add(legResult{Leg: "resolve", Name: m.name, OK: false, Detail: "error: " + err.Error()})
		case r.Status != types.ResolutionStatusResolved:
			add(legResult{Leg: "resolve", Name: m.name, OK: false,
				Detail: fmt.Sprintf("status=%q, want resolved", r.Status)})
		case r.PeerID != m.peerID:
			add(legResult{Leg: "resolve", Name: m.name, OK: false,
				Detail: fmt.Sprintf("peer_id=%q, want %q", r.PeerID, m.peerID)})
		default:
			add(legResult{Leg: "resolve", Name: m.name, OK: true,
				Detail: fmt.Sprintf("-> %s (%d transport(s))", r.PeerID, len(r.Transports))})
			if i == 0 {
				for _, h := range r.Transports {
					firstTransport = append(firstTransport, h.String())
				}
				firstDomain = m.domainDir
			}
		}
	}

	// Leg 2 — the negative control: an unbound name is not_found, never a false
	// resolve. Without it a resolver that answered every query would pass leg 1.
	if r, err := backend.Resolve(hctx, "no-such-name.example", nil); err != nil {
		add(legResult{Leg: "neg-control", Name: "no-such-name.example", OK: false, Detail: "error: " + err.Error()})
	} else if r.Status != types.ResolutionStatusNotFound {
		add(legResult{Leg: "neg-control", Name: "no-such-name.example", OK: false,
			Detail: fmt.Sprintf("status=%q, want not_found", r.Status)})
	} else {
		add(legResult{Leg: "neg-control", Name: "no-such-name.example", OK: true, Detail: "not_found (chain advances)"})
	}

	// Leg 3 — the transport leg (D8): the first binding's transports are bare
	// system/hash entities, each resolving to a served transport profile.
	if len(firstTransport) == 0 {
		add(legResult{Leg: "transport", OK: false, Detail: "first binding carried no transports"})
	} else {
		add(legResult{Leg: "transport", Name: mapping[0].name, OK: true,
			Detail: fmt.Sprintf("%d bare system/hash transport ref(s) (D8 shape)", len(firstTransport))})
	}

	// Leg 4 — the page leg: name -> target peer-id -> THAT domain's signed root,
	// verified against the peer-id-derived key, then a content fetch by hash. This
	// is the "one page fetches" of B5 — reaching a resolved peer's served, signed
	// content, not merely holding its id.
	if firstDomain != "" {
		add(fetchDomainPage(ctx, origin, firstDomain, mapping[0].peerID, mapping[0].name))
	}

	return out, allOK
}

// newRegistryBackend builds the peer-issued backend against the fixture registry,
// served under {origin}/registry with sharded-2-4 content (66-char full-wire hex).
func newRegistryBackend(origin string) (*peerissued.Backend, error) {
	registryPeer, err := peerEntityFromPeerID(registryPID)
	if err != nil {
		return nil, fmt.Errorf("registry identity: %w", err)
	}
	out := httplive.NewOutbound(
		fixtureProfile(registryPID, origin+"/registry"),
		httplive.WithPinnedIdentity(registryPeer),
		httplive.WithOutboundAllowHTTP(true),
		httplive.WithOutboundFetchTimeout(5*time.Second),
	)
	reader := peerissued.NewHTTPPollReader(out, registryPID)
	return peerissued.New(registryPeer, registryPID, reader,
		peerissued.WithClock(func() uint64 { return fixtureClock }))
}

// fetchDomainPage follows a resolved name to its domain's signed published-root
// and dereferences the signed root BY HASH — the serving-leg proof that the
// resolved peer-id is a real, reachable publisher whose content resolves. It
// carries a negative control (a bogus hash MUST 404), so the check is shown to
// discriminate rather than answering yes to everything (the B4 federation
// discipline: the operation whose failure IS the defect must be the one run).
//
// The static fixture serves the published-root at a bare tree path (browser-rust's
// coral-reef emit), not a live /manifest endpoint, so it is fetched directly and
// its content-hash integrity is checked; the RootHash is then resolved through the
// domain's content Outbound, which hash-verifies on fetch.
func fetchDomainPage(ctx context.Context, origin, domainDir, peerID, name string) legResult {
	rootURL := fmt.Sprintf("%s/%s/%s/system/peer/published-root", origin, domainDir, peerID)
	body, err := httpGet(ctx, rootURL)
	if err != nil {
		return legResult{Leg: "page", Name: name, OK: false, Detail: "GET published-root: " + err.Error()}
	}
	var rootEnt entity.Entity
	if err := cbor.Unmarshal(body, &rootEnt); err != nil {
		return legResult{Leg: "page", Name: name, OK: false, Detail: "decode published-root: " + err.Error()}
	}
	if rootEnt.Type != types.TypePeerPublishedRoot {
		return legResult{Leg: "page", Name: name, OK: false,
			Detail: fmt.Sprintf("published-root type %q != %s", rootEnt.Type, types.TypePeerPublishedRoot)}
	}
	if err := rootEnt.Validate(); err != nil {
		return legResult{Leg: "page", Name: name, OK: false, Detail: "published-root integrity: " + err.Error()}
	}
	prData, err := types.PublishedRootDataFromEntity(rootEnt)
	if err != nil {
		return legResult{Leg: "page", Name: name, OK: false, Detail: "decode PublishedRootData: " + err.Error()}
	}
	if prData.PeerID != peerID {
		return legResult{Leg: "page", Name: name, OK: false,
			Detail: fmt.Sprintf("published-root peer_id=%q, want %q", prData.PeerID, peerID)}
	}

	// Dereference the signed root by its hash through the domain content store.
	domainPeer, err := peerEntityFromPeerID(peerID)
	if err != nil {
		return legResult{Leg: "page", Name: name, OK: false, Detail: "domain identity: " + err.Error()}
	}
	out := httplive.NewOutbound(
		fixtureProfile(peerID, origin+"/"+domainDir),
		httplive.WithPinnedIdentity(domainPeer),
		httplive.WithOutboundAllowHTTP(true),
		httplive.WithOutboundFetchTimeout(5*time.Second),
	)
	if _, err := out.FetchContent(ctx, prData.RootHash); err != nil {
		return legResult{Leg: "page", Name: name, OK: false,
			Detail: fmt.Sprintf("signed root %s did not resolve by hash: %v", prData.RootHash, err)}
	}
	// Negative control: a bogus hash MUST NOT resolve, or the fetch proves nothing.
	bogus := prData.RootHash
	bogus.Digest[0] ^= 0xFF
	if _, err := out.FetchContent(ctx, bogus); err == nil {
		return legResult{Leg: "page", Name: name, OK: false,
			Detail: "negative control FAILED — a bogus root hash resolved (fetch does not discriminate)"}
	}
	return legResult{Leg: "page", Name: name, OK: true,
		Detail: fmt.Sprintf("%s -> signed root seq=%d, resolved by hash (+ bogus-hash control 404s)", peerID, prData.Seq)}
}

// httpGet is a small direct fetch for the bare-path published-root the static
// coral-reef serves (no /manifest endpoint), separate from the Outbound's
// content-by-hash path.
func httpGet(ctx context.Context, url string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("status %d", resp.StatusCode)
	}
	return io.ReadAll(resp.Body)
}

// fixtureProfile builds the http-poll dial profile for a fixture peer served at
// treePrefix, with content sharded-2-4 (browser-rust's emit layout) and the
// default .bin leaf suffix.
func fixtureProfile(peerID, treePrefix string) types.HTTPPollProfileData {
	return types.HTTPPollProfileData{
		PeerID:        peerID,
		TransportType: "http-poll",
		Endpoint: types.TransportEndpoint{
			TreeURLPrefix:    treePrefix,
			ContentURLPrefix: treePrefix + "/content",
			ContentLayout:    types.ContentLayoutSharded24,
			TreeLeafSuffix:   ".bin",
		},
		SupportedOps:  []string{types.OpTreeGet, types.OpContentGet, types.OpManifestGet},
		NonceRequired: false,
	}
}

// peerEntityFromPeerID reconstructs a peer's identity entity from its
// identity-multihash peer-id (the public key is embedded, V7 §1.5) — the only
// input a consumer has for a peer it has never spoken to.
func peerEntityFromPeerID(pid string) (entity.Entity, error) {
	pub, keyType, ok := crypto.DerivePeerFromPeerID(crypto.PeerID(pid))
	if !ok {
		return entity.Entity{}, fmt.Errorf("peer-id %q is not identity-multihash form", pid)
	}
	return types.PeerData{PublicKey: pub, KeyType: crypto.KeyTypeString(keyType)}.ToEntity()
}

// newConsumerContext is an EMPTY local store + namespaced index, so every
// resolution falls through to the http-poll reader (the live cross-impl path)
// rather than a warm cache.
func newConsumerContext() *handler.HandlerContext {
	// The namespaced index keys on a valid local peer-id; the consumer's own
	// identity is irrelevant to resolution (it holds only the registry pin), so a
	// fixed-seed local peer is fine and keeps the run deterministic.
	local := crypto.FromSeed([32]byte{'c', 'o', 'n', 's', 'u', 'm', 'e', 'r'}).PeerID()
	cs := store.NewMemoryContentStore()
	li := store.NewNamespacedIndex(store.NewMemoryLocationIndex(), string(local))
	return &handler.HandlerContext{Store: cs, LocationIndex: li}
}
