// mdns — DNS-SD-based DISCOVERY backend per EXTENSION-DISCOVERY §3.
//
// Wire surface pinned in wire.go (§3.2 service-type + MUST TXT keys).
// This file is the Go-side library glue using github.com/grandcat/zeroconf
// (a mature DNS-SD implementation built on miekg/dns). The cohort
// discipline (#1 in the handoff): different mDNS libs may emit TXT keys
// in different orders. The §3.2 pin makes the keys themselves normative;
// runtime ordering is library-determined and not part of the wire pin.
// If a sibling impl's lib re-sorts the keys, that is conformant — the
// receiving side parses TXT records as a key→value map, not an ordered
// list, per RFC 6763 §6.
package mdns

import (
	"context"
	"fmt"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"

	"go.entitychurch.org/entity-core-go/core/hash"
	"go.entitychurch.org/entity-core-go/core/types"
	"go.entitychurch.org/entity-core-go/ext/discovery"

	"github.com/fxamacker/cbor/v2"
	"github.com/grandcat/zeroconf"
)

// announceInterfaces returns the set of interfaces grandcat/zeroconf should
// announce + browse on. By default we include:
//
//   - every interface flagged MULTICAST + UP (grandcat's own default), AND
//   - the loopback interface(s) when up, EVEN THOUGH Linux's `lo` does NOT
//     carry the MULTICAST flag.
//
// Without the loopback inclusion, cross-impl peers on the same host (Go +
// Python in particular — same-host cohort dev) cannot see each other's
// announcements, because `python-zeroconf` + `avahi-daemon` explicitly
// subscribe to 224.0.0.251 on `lo` and our grandcat-backed peer would
// otherwise emit only on the routable interfaces. Same-host LAN
// convergence (the D8 cohort gate) requires `lo`.
//
// Returns nil on error (grandcat falls back to its own default — the
// previous behavior — so we never block startup if interface enumeration
// fails). The list is the *full* set; grandcat won't add anything else.
func announceInterfaces() []net.Interface {
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil
	}
	var out []net.Interface
	for _, ifi := range ifaces {
		if ifi.Flags&net.FlagUp == 0 {
			continue
		}
		// Include multicast-capable interfaces (grandcat's own filter), AND
		// loopback (which Linux marks UP+LOOPBACK without MULTICAST despite
		// supporting the 224.0.0.251 group at the kernel level — see
		// `ip maddr show lo`).
		if ifi.Flags&net.FlagMulticast != 0 || ifi.Flags&net.FlagLoopback != 0 {
			out = append(out, ifi)
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// ProfileResolver looks up a transport profile by its `profile_ref`
// segment, returning the port the profile listens on and the advertised
// transport protocol names (e.g. "tcp", "http-poll"). Returns an error if
// the profile is not found / not advertisable.
//
// This decouples the mDNS backend from EXTENSION-NETWORK directly:
// entity-peer/main.go wires a resolver that reads the peer's
// `system/peer/transport/{peer}/{profile-id}` bindings. Tests pass a
// minimal in-memory resolver.
type ProfileResolver func(profileRef string) (port int, protos []string, err error)

// Backend implements discovery.Backend for mDNS.
type Backend struct {
	mu sync.Mutex

	localPeerID string
	resolver    ProfileResolver

	// Announce sessions — profileRef → zeroconf server.
	announced map[string]*zeroconf.Server

	// Display-name hint (optional TXT key per §3.2). Operator-set.
	displayName string

	// Default scan timeout for the immediate-snapshot return path
	// (§3.0). Backends can block this long on a one-shot Browse.
	scanTimeout time.Duration

	// Observed candidates — populated by Browse during Scan AND streamed
	// from the persistent watcher (started on first observe-callback
	// wiring). Map key = candidate.content_hash.
	observed map[hash.Hash]types.CandidateData

	// Observe / reap callbacks wired by the substrate.
	observeCb func(types.CandidateData)
	reapCb    func(hash.Hash)
}

// Option configures a Backend at construction.
type Option func(*Backend)

// WithDisplayName sets the §3.2 OPTIONAL display_name TXT key.
func WithDisplayName(name string) Option {
	return func(b *Backend) { b.displayName = name }
}

// WithScanTimeout overrides the immediate-snapshot scan timeout (default 1s).
func WithScanTimeout(d time.Duration) Option {
	return func(b *Backend) { b.scanTimeout = d }
}

// New constructs an mDNS backend bound to a peer-id + profile resolver.
func New(localPeerID string, resolver ProfileResolver, opts ...Option) *Backend {
	b := &Backend{
		localPeerID: localPeerID,
		resolver:    resolver,
		announced:   make(map[string]*zeroconf.Server),
		observed:    make(map[hash.Hash]types.CandidateData),
		scanTimeout: 1 * time.Second,
	}
	for _, opt := range opts {
		opt(b)
	}
	return b
}

// Kind implements discovery.Backend.
func (b *Backend) Kind() string { return BackendKind }

// SetObserveCallback implements discovery.Backend. Called once at
// backend registration by the substrate; subsequent Scan calls + the
// persistent watcher push through these.
func (b *Backend) SetObserveCallback(observe func(types.CandidateData), reap func(hash.Hash)) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.observeCb = observe
	b.reapCb = reap
}

// Announce implements discovery.Backend. Registers the local peer at
// `_entity-core._udp.local.` with the MUST-present TXT keys per §3.2.
//
// The instance name is `{peer_id}:{profile_ref}` so multiple profiles on
// the same peer don't collide on the DNS-SD instance namespace.
func (b *Backend) Announce(ctx context.Context, profileRef string) error {
	b.mu.Lock()
	defer b.mu.Unlock()

	if _, ok := b.announced[profileRef]; ok {
		// Already announcing — idempotent. (Symmetric with AnnounceStop.)
		return nil
	}
	if b.resolver == nil {
		return fmt.Errorf("mdns: ProfileResolver not wired — cannot resolve port for profile_ref=%q", profileRef)
	}
	port, protos, err := b.resolver(profileRef)
	if err != nil {
		return fmt.Errorf("mdns: resolve profile %q: %w", profileRef, err)
	}
	if port <= 0 {
		return fmt.Errorf("mdns: profile %q resolved to invalid port %d", profileRef, port)
	}

	txt := []string{
		TXTKeyVersion + "=" + CurrentVersion,
		TXTKeyPeerIDHint + "=" + b.localPeerID,
		TXTKeyProfileRef + "=" + profileRef,
	}
	if len(protos) > 0 {
		txt = append(txt, TXTKeyProto+"="+strings.Join(protos, ","))
	}
	if b.displayName != "" {
		txt = append(txt, TXTKeyDisplayName+"="+b.displayName)
	}

	instance := mdnsInstanceName(b.localPeerID, profileRef)
	// announceInterfaces explicitly includes loopback so same-host
	// cross-impl peers (Go + Py + avahi) can see each other; nil → grandcat
	// default (multicast-flagged interfaces only — excludes Linux `lo`).
	//
	// grandcat takes service + domain as separate args and concatenates;
	// passing the full ServiceType plus a "local." domain would emit
	// `_entity-core._udp.local.local.` on the wire (caught against avahi
	// + Py wireshark trace). Use ServiceTypeLabel + ServiceDomain.
	srv, err := zeroconf.Register(instance, ServiceTypeLabel, ServiceDomain, port, txt, announceInterfaces())
	if err != nil {
		return fmt.Errorf("mdns: zeroconf.Register failed: %w", err)
	}
	b.announced[profileRef] = srv
	return nil
}

// AnnounceStop implements discovery.Backend. Idempotent.
func (b *Backend) AnnounceStop(ctx context.Context, profileRef string) error {
	b.mu.Lock()
	srv, ok := b.announced[profileRef]
	delete(b.announced, profileRef)
	b.mu.Unlock()
	if !ok {
		return nil // idempotent
	}
	srv.Shutdown()
	return nil
}

// Scan implements discovery.Backend. Runs a bounded Browse against the
// pinned §3.2 service-type and returns the observed candidates as
// CandidateData. The `filter` argument is currently ignored (v1 backend
// MAY ignore per §3.3); a future iteration can layer TXT-key predicate
// filtering once the cohort agrees on a shape.
//
// Per §3.0, the substrate calls this for the immediate snapshot return;
// the substrate's observe-callback pipes async arrivals into the
// watchable prefix without each consumer needing to re-invoke `:scan`.
func (b *Backend) Scan(ctx context.Context, filter map[string]cbor.RawMessage) ([]types.CandidateData, error) {
	b.mu.Lock()
	timeout := b.scanTimeout
	observeCb := b.observeCb
	b.mu.Unlock()

	// Same interface-list trick as Announce — include loopback so we
	// observe same-host cross-impl announcements.
	var resolverOpts []zeroconf.ClientOption
	if ifs := announceInterfaces(); ifs != nil {
		resolverOpts = append(resolverOpts, zeroconf.SelectIfaces(ifs))
	}
	resolver, err := zeroconf.NewResolver(resolverOpts...)
	if err != nil {
		return nil, fmt.Errorf("mdns: NewResolver: %w", err)
	}
	entriesCh := make(chan *zeroconf.ServiceEntry, 32)

	browseCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	// Same split as Announce — service + domain separate args (full
	// ServiceType would double-suffix to `…local.local.`).
	if err := resolver.Browse(browseCtx, ServiceTypeLabel, ServiceDomain, entriesCh); err != nil {
		return nil, fmt.Errorf("mdns: Browse: %w", err)
	}

	// Collect until context fires.
	var collected []types.CandidateData
	for {
		select {
		case e, ok := <-entriesCh:
			if !ok {
				return collected, nil
			}
			if e == nil {
				continue
			}
			cd := candidateFromServiceEntry(e)
			collected = append(collected, cd)
			// Also pipe through the observe callback so the watchable
			// prefix surface reflects this arrival immediately. The
			// substrate's binder is idempotent on equal content_hash.
			if observeCb != nil {
				observeCb(cd)
			}
		case <-browseCtx.Done():
			return collected, nil
		}
	}
}

// candidateFromServiceEntry materializes a CandidateData from a
// zeroconf.ServiceEntry. Per §2.1, peer_id is null pre-IDENTIFY — the
// peer_id_hint TXT key advertises a *claimed* peer-id but the substrate
// only populates CandidateData.PeerID after IDENTIFY (via the substrate's
// PromoteSuccessor pathway). So pre-IDENTIFY the candidate carries:
//
//   - peer_id     = ""  (omitempty → absent on wire)
//   - backend     = "mdns"
//   - observed_at = now
//   - endpoint_hint = CBOR-encoded {host, port, ipv4, ipv6, txt} blob
//   - identity_hint = nil (TOFU on the mDNS backend; backends MAY surface
//     a non-nil hint via the TXT-key channel in a future amendment)
//   - supersedes = nil (chain head)
//
// The TXT-key peer_id_hint is preserved in the endpoint_hint blob so
// the IDENTIFY-completion path can compare against it.
func candidateFromServiceEntry(e *zeroconf.ServiceEntry) types.CandidateData {
	hint := endpointHintFromEntry(e)
	return types.CandidateData{
		Backend:      BackendKind,
		ObservedAt:   uint64(time.Now().UnixMilli()),
		EndpointHint: hint,
	}
}

// endpointHintFromEntry CBOR-encodes the opaque per-§2.1 endpoint_hint
// for the mDNS backend.
func endpointHintFromEntry(e *zeroconf.ServiceEntry) cbor.RawMessage {
	hint := mdnsEndpointHint{
		HostName: e.HostName,
		Port:     e.Port,
		Text:     append([]string(nil), e.Text...),
	}
	for _, ip := range e.AddrIPv4 {
		hint.IPv4 = append(hint.IPv4, ip.String())
	}
	for _, ip := range e.AddrIPv6 {
		hint.IPv6 = append(hint.IPv6, ip.String())
	}
	raw, err := cbor.Marshal(hint)
	if err != nil {
		return nil
	}
	return cbor.RawMessage(raw)
}

// mdnsEndpointHint is the backend-specific opaque shape carried in
// CandidateData.EndpointHint. The substrate doesn't interpret these
// fields (§2.1 endpoint_hint is opaque); only the mDNS backend (and the
// IDENTIFY-completion path that needs port + peer_id_hint) decodes them.
type mdnsEndpointHint struct {
	HostName string   `cbor:"host_name"`
	Port     int      `cbor:"port"`
	IPv4     []string `cbor:"ipv4,omitempty"`
	IPv6     []string `cbor:"ipv6,omitempty"`
	Text     []string `cbor:"text,omitempty"`
}

// DecodeEndpointHint exposes the mDNS endpoint_hint decode to callers
// (e.g. the IDENTIFY-completion path that needs to dial the candidate or
// read its peer_id_hint TXT key). Returns (host, port, txt-map, err).
//
// The TXT key map preserves only the §3.2 MUST + OPTIONAL keys; unknown
// keys are dropped per §3.2 forward-compat.
func DecodeEndpointHint(raw cbor.RawMessage) (host string, port int, txt map[string]string, err error) {
	var h mdnsEndpointHint
	if err = cbor.Unmarshal(raw, &h); err != nil {
		return "", 0, nil, fmt.Errorf("decode mdns endpoint_hint: %w", err)
	}
	return h.HostName, h.Port, parseTXTKeys(h.Text), nil
}

// parseTXTKeys parses zeroconf-style "key=value" TXT entries into a map.
// Per RFC 6763 §6 and §3.2 forward-compat: unknown keys MUST be ignored
// (we silently drop them rather than including them).
func parseTXTKeys(txt []string) map[string]string {
	out := make(map[string]string, len(txt))
	for _, t := range txt {
		idx := strings.IndexByte(t, '=')
		if idx < 0 {
			continue
		}
		k := t[:idx]
		v := t[idx+1:]
		switch k {
		case TXTKeyVersion, TXTKeyPeerIDHint, TXTKeyProfileRef, TXTKeyProto, TXTKeyDisplayName:
			out[k] = v
		}
	}
	return out
}

// mdnsInstanceName returns the DNS-SD instance name for an announcement.
// `{peer_id}:{profile_ref}` keeps multi-profile announcements distinct
// within a single peer's DNS-SD instance namespace.
func mdnsInstanceName(peerID, profileRef string) string {
	return peerID + ":" + profileRef
}

// staticResolver is a test-only ProfileResolver convenience that maps a
// fixed table of profileRef→(port, protos). Exposed for tests + simple
// configurations; production wiring uses the entity-peer adapter that
// reads system/peer/transport/{peer}/{profile-id}.
type staticResolver map[string]struct {
	Port   int
	Protos []string
}

// StaticResolver builds a ProfileResolver from a fixed table.
func StaticResolver(table map[string]struct {
	Port   int
	Protos []string
}) ProfileResolver {
	return func(profileRef string) (int, []string, error) {
		entry, ok := table[profileRef]
		if !ok {
			return 0, nil, fmt.Errorf("static resolver: unknown profile_ref %q", profileRef)
		}
		return entry.Port, entry.Protos, nil
	}
}

// Compile-time check that *Backend satisfies discovery.Backend.
var _ discovery.Backend = (*Backend)(nil)

// Silence unused imports we hold for the strconv API surface (kept for
// future port-parsing fixups when zeroconf's net.IP handling needs
// explicit textual rendering).
var _ = strconv.Itoa
var _ = (*net.IPNet)(nil)
