// Package publishedroot owns the publishing half of
// `system/peer/published-root` per PROPOSAL-PEER-MANIFEST-STATIC-HANDSHAKE §4
// (NORMATIVE-LOCKED). It is the §1.1 tree anchor: the publisher
// signs the current tree-root hash so a consumer reaching the manifest by an
// untrusted path (e.g., a CDN intermediary) can verify the root claim against
// the publisher's identity key, walk TREE_GET from that signed root, and
// reject every off-chain binding the host might fabricate.
//
// The Publisher watches a configured prefix's RootTracker output via a sync
// hook (position 6/7 — after rootTracker writes the new root, before async
// emit). On every observed change it mints a new system/peer/published-root
// entity with a monotonic Seq, binds it at the canonical storage path, and
// binds its signature at the V7 §5.2/§975 invariant-pointer
// `system/signature/{published_root_hash_hex}`. The most-recently-bound
// entity is exposed via `Current()` so the http-poll publisher
// (ext/httplive PollHandler.Manifest) can serve it as MANIFEST_GET's body.
//
// Authority (keypair + identity) is wired post-construction via
// SetupAuthority — same lifecycle as historyRecorder / identityH / etc. so
// the hook registration order in entity-peer/main.go does not change.
package publishedroot

import (
	"fmt"
	"log"
	"strings"
	"sync"
	"time"

	"go.entitychurch.org/entity-core-go/core/crypto"
	"go.entitychurch.org/entity-core-go/core/entity"
	"go.entitychurch.org/entity-core-go/core/hash"
	"go.entitychurch.org/entity-core-go/core/store"
	"go.entitychurch.org/entity-core-go/core/tree"
	"go.entitychurch.org/entity-core-go/core/types"
)

// PrefixForLocalPeer is the conventional root-tracker prefix the publisher
// follows when the operator wants "publish whatever lives under
// `system/`." RootTracker rejects the empty prefix (its reloadConfigsLocked
// drops `prefix == ""`), so we pick a meaningful umbrella that covers the
// peer's authored content. Operators wanting a narrower or wider domain
// pass their own prefix via NewPublisher.
//
// `system/` covers the peer's complete authored state: handlers, identity
// certs, role assignments, content bindings under `system/content/...`,
// signatures, and everything else this peer signs into its own tree.
// `local/files/...` (operator file mounts) is intentionally excluded —
// those bindings live outside `system/` and are local-shape state, not
// part of the published self-description.
const PrefixForLocalPeer = "system/"

// publishedPrefix renders a tracker prefix in the form EXTENSION-TREE §3.3a
// requires on the wire: a non-empty prefix MUST end with "/", and "/" is the
// universal tree.
//
// The tracker stores prefixes without a guaranteed trailing slash (its config
// path derivation trims one), so normalize here rather than at every call site
// — a prefix that reaches the wire without its slash is not a cosmetic defect:
// `absolute_prefix + relative_key` would concatenate straight into a wrong
// path, and §3.3's trim would not be its inverse.
func publishedPrefix(prefix string) string {
	if prefix == "" {
		return "/"
	}
	if strings.HasSuffix(prefix, "/") {
		return prefix
	}
	return prefix + "/"
}

// PublisherHandlerPattern is the MutationContext.HandlerPattern tag the
// publisher stamps on its own LI writes (published-root binding + signature
// invariant pointer). Sync-hook consumers — notably tree.RootTracker — check
// for this tag and skip the resulting events to break the publisher feedback
// loop (publisher writes land inside the tracked prefix → would otherwise
// advance the trie root → would fire the publisher again).
const PublisherHandlerPattern = "publishedroot/publisher"

// Publisher mints and binds successive system/peer/published-root entities
// in response to RootTracker writes. It is safe for concurrent use; the
// internal mutex serializes Publish so seq monotonicity holds even when
// two cascades race the same root path.
type Publisher struct {
	cs       store.ContentStore
	tracker  *tree.RootTracker
	prefix   string
	debugLog *log.Logger

	mu          sync.Mutex
	li          store.LocationIndex
	kp          *crypto.Keypair
	identity    *entity.Entity
	peerIDHash  hash.Hash    // content_hash of the publisher's system/peer entity (for signature.signer)
	peerID      string       // Base58 peer-id per V7 §1.5 (for published-root.peer_id, Ruling-1)
	lastSeq     uint64
	lastHash    *hash.Hash // content_hash of the most-recently-bound published-root
	lastEntity  *entity.Entity
	rootPath    string // the LI path RootTracker writes the tracked root to
	authorityOK bool
	publishing  bool // re-entry guard for Publish-cascade-Publish recursion
	// pending is the trailing edge of the coalescing window: a root that
	// arrived while a publish was in flight and so could not be published
	// then. The in-flight publish drains it on completion. Without this
	// the guard DROPS that root, and if the write burst has stopped there
	// is no next cascade to pick it up — the published root stays behind
	// the tracked root forever, which is a §6.5.6 convergence failure and
	// not merely a slow one. Measured: reproducible at 5000 sequential
	// writes before this existed.
	pending *hash.Hash

	// Debounce coalescing (§6.5.6: "coalescing / debouncing is explicitly
	// permitted — a signature per tree:put is write-amplifying and is not
	// the intent; a cascade SHOULD produce one republish, not one per
	// binding"). dirty holds the newest tracked root observed since the
	// last publish; the timer collapses a burst into one signature.
	debounce   time.Duration
	dirty      *hash.Hash
	timerArmed bool
}

// DefaultDebounce is the trailing-edge coalescing window.
//
// Chosen against the two numbers that bound it. §6.5.6 permits up to a
// 30 s maximum convergence delay, and measured publish cost is ~21 µs
// with post-burst convergence ~1 ms — so a window of tens of ms collapses
// a burst into a single signature while leaving convergence three-plus
// orders of magnitude inside the ceiling. 25 ms is also far below every
// consumer-visible wait in the suite (serving_mode polls for 10 s), so it
// is invisible to conformance timing while removing most of the
// amplification.
//
// It is a trailing-edge debounce, not a rate limit: the timer measures
// quiet, and the LAST root observed is the one published. A burst of any
// length therefore costs one signature, and the value published is always
// the newest — never a stale midpoint.
const DefaultDebounce = 25 * time.Millisecond

// PublisherOption configures a Publisher at construction.
type PublisherOption func(*Publisher)

// WithDebounce sets the coalescing window. Zero or negative disables
// debouncing entirely — every tracked-root advance publishes immediately,
// which is the maximum-freshness / maximum-amplification end of the trade
// §6.5.6 describes.
func WithDebounce(d time.Duration) PublisherOption {
	return func(p *Publisher) { p.debounce = d }
}

// NewPublisher builds a publisher that watches the rootTracker for prefix
// and is ready to publish once SetupAuthority is called. cs / tracker are
// captured at construction so the hook closure can be registered with the
// peer.WithNamedSyncHook builder option before peer.New runs; the
// location-index (which only exists in its namespaced form after peer
// construction) is supplied later via SetupAuthority.
//
// debugLog may be nil. The publisher silently no-ops (with debug log if
// set) until SetupAuthority lands the LI + keypair + identity entity.
func NewPublisher(cs store.ContentStore, tracker *tree.RootTracker, prefix string, debugLog *log.Logger, opts ...PublisherOption) *Publisher {
	p := &Publisher{
		cs:       cs,
		tracker:  tracker,
		prefix:   prefix,
		debugLog: debugLog,
		debounce: DefaultDebounce,
		// RootTracker writes its tracked root to
		// `store.CleanPath("system/tree/root/" + prefix)` — CleanPath strips
		// trailing slashes. We mirror the same canonicalization so the
		// HasSuffix match against the NamespacedIndex-qualified event path
		// (`/{peerID}/system/tree/root/<cleaned-prefix>`) actually fires.
		rootPath: strings.TrimRight("system/tree/root/"+prefix, "/"),
	}
	for _, opt := range opts {
		opt(p)
	}
	return p
}

// SetupAuthority wires the publisher's location index + signing identity.
// Must be called after peer construction (li comes from p.LocationIndex(),
// which is the NamespacedIndex; kp + identity from peer.New). Performs an
// initial Publish against the tracker's current root if any is present.
//
// EnableTracking, when true, writes a system/tree/tracking-config that
// enables incremental trie-root maintenance for the publisher's prefix.
// This is what makes MANIFEST_GET serve a non-empty manifest on a fresh
// peer that hasn't yet had a TrackingConfig declared; without it, the
// RootTracker has no root and Publish has nothing to sign.
func (p *Publisher) SetupAuthority(li store.LocationIndex, kp crypto.Keypair, identity entity.Entity, enableTracking bool) error {
	p.mu.Lock()
	p.li = li
	p.kp = &kp
	p.identity = &identity
	// V7 §1.5 / v7.65 Amendment 1: peer identity hash is the content_hash of
	// the canonical system/peer entity (the same hash IdentityEntity() emits).
	// Kept for the signature entity's signer field (V7 §5.2 — signer is a hash).
	p.peerIDHash = identity.ContentHash
	// Ruling-1 (cross-impl-run absorption): published-root.peer_id is
	// the Base58 peer-id per V7 §1.5, not a hash. Derived once at authority-
	// setup time and reused for every Publish.
	p.peerID = string(crypto.PeerIDFromKeypair(kp))
	p.authorityOK = true
	p.mu.Unlock()

	if enableTracking {
		if err := p.enableTrackingConfig(); err != nil {
			return fmt.Errorf("enable tracking-config: %w", err)
		}
	}

	// Initial publish if the tracker already has a root for our prefix
	// (peer constructed with seed-data already, or restart from sqlite).
	// When enableTracking just fired a cascade that's already spawned an
	// async publish, this call races against that spawned goroutine and
	// the re-entry guard fires errPublishInProgress — that's the right
	// state; the spawned publish covers this root.
	if root, ok := p.tracker.Root(p.prefix); ok && !root.IsZero() {
		if _, err := p.Publish(root); err != nil && err != errPublishInProgress {
			return fmt.Errorf("initial publish: %w", err)
		}
	}
	return nil
}

// enableTrackingConfig writes a system/tree/tracking-config entity for
// p.prefix at the conventional naming path system/tree/tracking-config/
// publishedroot. Per EXTENSION-TREE v3.8 §3.4.1a the RootTracker scans
// these on every binding-cascade and enables / disables tracking; writing
// one now means the next root-bearing tree change emits at
// system/tree/root/{prefix}, which our OnTreeChange picks up.
func (p *Publisher) enableTrackingConfig() error {
	cfg := types.TrackingConfigData{
		Prefix:  p.prefix,
		Enabled: true,
	}
	ent, err := cfg.ToEntity()
	if err != nil {
		return err
	}
	h, err := p.cs.Put(ent)
	if err != nil {
		return err
	}
	// The conventional path; "publishedroot" labels who installed it so it
	// can be removed cleanly by name. Multiple TrackingConfigs CAN coexist
	// per RootTracker; ours doesn't displace operator-installed ones.
	cfgPath := "system/tree/tracking-config/publishedroot"
	if err := p.li.Set(cfgPath, h); err != nil {
		return err
	}
	return nil
}

// Current returns the most recently bound published-root entity (and true)
// or nil/false if no publish has happened yet. http-poll's MANIFEST_GET
// route reads this and serves the ECF-encoded entity body.
func (p *Publisher) Current() (*entity.Entity, bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.lastEntity == nil {
		return nil, false
	}
	cp := *p.lastEntity
	return &cp, true
}

// Publish mints a new system/peer/published-root binding rootHash, signs it
// with the publisher's keypair, and binds both at their canonical storage
// paths. Seq monotonicity is enforced internally: every call uses lastSeq+1.
// Returns the bound published-root entity.
//
// The lock is released before LI writes so the sync-hook cascade the writes
// trigger (rootTracker → re-rebuild → publisher.OnTreeChange → Publish) can
// re-enter without deadlocking. Re-entry is short-circuited by the `publishing`
// guard: when set, OnTreeChange skips its Publish call (the next cascade will
// pick up the new root once we're done).
func (p *Publisher) Publish(rootHash hash.Hash) (entity.Entity, error) {
	p.mu.Lock()
	if !p.authorityOK {
		p.mu.Unlock()
		return entity.Entity{}, fmt.Errorf("publishedroot.Publish: authority not configured")
	}
	if p.publishing {
		// Another Publish is in flight (we're being re-entered via the
		// LI-write cascade). Record this root as the trailing edge rather
		// than discarding it: the in-flight call republishes it before it
		// returns. Dropping it is only safe while writes keep arriving —
		// and the case that matters is the burst that just stopped.
		r := rootHash
		p.pending = &r
		p.mu.Unlock()
		return entity.Entity{}, errPublishInProgress
	}
	p.publishing = true
	p.mu.Unlock()

	var last entity.Entity
	current := rootHash
	// Bounded so a pathological feedback loop degrades into a stall we can
	// see rather than a goroutine that never returns. The RootTracker skips
	// PublisherHandlerPattern writes, so our own bindings do not advance the
	// tracked root and this normally runs once, twice at a burst tail.
	for round := 0; round < maxTrailingRepublishes; round++ {
		ent, err := p.publishOnce(current)
		if err != nil {
			p.clearPublishing()
			return entity.Entity{}, err
		}
		last = ent
		// Draining `pending` and releasing the `publishing` flag MUST happen
		// under one lock hold. Split across two, there is a window between
		// "pending is empty" and "publishing = false" in which a new root
		// arrives, sees publishing still set, parks itself in pending, and
		// is then dropped by a loop that has already decided to exit — the
		// exact lost wakeup this drain exists to prevent, reintroduced one
		// level down. Caught by TestRepublishConvergenceAfterBurst under
		// parallel-package load, not by review.
		p.mu.Lock()
		next := p.pending
		p.pending = nil
		if next == nil || *next == current {
			p.publishing = false
			p.mu.Unlock()
			return last, nil
		}
		p.mu.Unlock()
		current = *next
	}
	p.clearPublishing()
	if p.debugLog != nil {
		p.debugLog.Printf("[publishedroot] trailing republish bound (%d) hit; tracked root may still be ahead",
			maxTrailingRepublishes)
	}
	return last, nil
}

// maxTrailingRepublishes bounds the drain loop in Publish.
const maxTrailingRepublishes = 64

func (p *Publisher) clearPublishing() {
	p.mu.Lock()
	p.publishing = false
	p.mu.Unlock()
}

// publishOnce mints, signs and binds exactly one published-root for
// rootHash. It assumes the caller holds the `publishing` flag.
func (p *Publisher) publishOnce(rootHash hash.Hash) (entity.Entity, error) {
	p.mu.Lock()
	p.lastSeq++
	pr := types.PublishedRootData{
		PeerID:   p.peerID,
		RootHash: rootHash,
		// EXTENSION-TREE §3.3a: REQUIRED, and MUST end with "/". We publish the
		// prefix we actually track, so a consumer reconstructs paths as
		// `absolute_prefix + relative_key` against the same operand we trimmed
		// with — never a default and never an inference.
		Prefix:      publishedPrefix(p.prefix),
		Seq:         p.lastSeq,
		PublishedAt: uint64(time.Now().UnixMilli()),
		Predecessor: p.lastHash,
	}
	li := p.li
	kp := *p.kp
	cs := p.cs
	peerIDHash := p.peerIDHash
	peerID := p.peerID
	p.mu.Unlock()

	prEntity, err := pr.ToEntity()
	if err != nil {
		return entity.Entity{}, fmt.Errorf("encode published-root: %w", err)
	}

	sigBytes := kp.Sign(prEntity.ContentHash.Bytes())
	sigData := types.SignatureData{
		Target:    prEntity.ContentHash,
		Signer:    peerIDHash,
		Algorithm: crypto.KeyTypeString(kp.KeyType),
		Signature: sigBytes,
	}
	sigEntity, err := sigData.ToEntity()
	if err != nil {
		return entity.Entity{}, fmt.Errorf("encode published-root signature: %w", err)
	}

	if _, err := cs.Put(prEntity); err != nil {
		return entity.Entity{}, fmt.Errorf("store published-root: %w", err)
	}
	if _, err := cs.Put(sigEntity); err != nil {
		return entity.Entity{}, fmt.Errorf("store published-root signature: %w", err)
	}

	// Self-tagging so the rootTracker can break the publish-feedback loop.
	// Without this, the publisher's own writes (published-root entity at
	// system/peer/published-root/{peer_id}, signature at system/signature/{hex})
	// land inside the tracked prefix system/, the rootTracker rebuilds the trie
	// to include the new entity hash, the trie-root path advances, that fires
	// publisher.OnTreeChange, which Publishes again — ad infinitum. Seq counter
	// runs away (observed at ~55/s with no external traffic), and ClosureScope's
	// memoized closure for the previous head is invalidated before any consumer
	// CONTENT_GET can complete, producing the 404 storm that caused
	// published_root.v4/v5/v7 to SKIP under the orchestrator.
	publisherCtx := &store.MutationContext{
		AuthorHash:     peerIDHash,
		HandlerPattern: PublisherHandlerPattern,
		Operation:      "publish",
	}
	// ORDER IS LOAD-BEARING: bind the SIGNATURE first, the published-root
	// second.
	//
	// The published-root binding is what makes a new head VISIBLE, and
	// ClosureScope memoizes its member set per head. Binding the head first
	// opens a window in which a consumer can observe head H, build and cache
	// a snapshot for H, and miss the signature that had not yet been bound —
	// and because the snapshot is keyed by head, it stays wrong until the
	// head advances again. The manifest is then served but unverifiable.
	//
	// Rapid republishing hid this: the head advanced within milliseconds and
	// the next snapshot picked the signature up. Adding a debounce made the
	// head sit still, and v5_outbound_dial began failing 2/2 with a 404 on
	// the signature pointer. The debounce exposed the flaw; it did not
	// create it.
	//
	// Signature-before-pointer is the same discipline SUBSTITUTE §7.3 states
	// for publishing (upload content first, the manifest that references it
	// last): bind what is referenced before the reference that makes it
	// reachable.
	sigPath := types.LocalSignaturePath(prEntity.ContentHash)
	if cw, ok := li.(store.ContextualWriter); ok {
		if _, err := cw.SetWithContext(sigPath, sigEntity.ContentHash, publisherCtx); err != nil {
			return entity.Entity{}, fmt.Errorf("bind published-root sig at %s: %w", sigPath, err)
		}
	} else {
		if err := li.Set(sigPath, sigEntity.ContentHash); err != nil {
			return entity.Entity{}, fmt.Errorf("bind published-root sig at %s: %w", sigPath, err)
		}
	}
	storagePath := types.PublishedRootStoragePath(peerID)
	if cw, ok := li.(store.ContextualWriter); ok {
		if _, err := cw.SetWithContext(storagePath, prEntity.ContentHash, publisherCtx); err != nil {
			return entity.Entity{}, fmt.Errorf("bind published-root at %s: %w", storagePath, err)
		}
	} else {
		if err := li.Set(storagePath, prEntity.ContentHash); err != nil {
			return entity.Entity{}, fmt.Errorf("bind published-root at %s: %w", storagePath, err)
		}
	}

	hashCopy := prEntity.ContentHash
	p.mu.Lock()
	p.lastHash = &hashCopy
	p.lastEntity = &prEntity
	p.mu.Unlock()
	if p.debugLog != nil {
		p.debugLog.Printf("[publishedroot] seq=%d root=%s entity=%s",
			pr.Seq, rootHash, prEntity.ContentHash)
	}
	return prEntity, nil
}

// errPublishInProgress is the sentinel returned by Publish when a recursive
// re-entry is detected. Callers (notably OnTreeChange) ignore it — the
// outer Publish in flight already covers the new root.
var errPublishInProgress = fmt.Errorf("publishedroot: publish already in progress")

// OnTreeChange is the sync-hook entry point. Registered via
// peer.WithNamedSyncHook("publishedroot/publisher", pub.OnTreeChange).
// Fires for every LI binding; the hook fast-paths events that are not the
// tracked-root path before any locking work happens.
func (p *Publisher) OnTreeChange(evt store.TreeChangeEvent) *store.ConsumerResult {
	// Filter to the tracker's tracked-root path ONLY. The qualified path
	// comes back as "/{peerID}/system/tree/root/{prefix}" because the
	// namespaced location index prepends the local peer's id. Splitting
	// the namespace off and exact-matching the bare path is the precise
	// shape; HasSuffix matching is unsafe because history records head
	// pointers at "system/history/head/{peerID}/system/tree/root/{prefix}",
	// which has the same suffix but a completely different hash. With the
	// loose match the publisher would re-publish history's transition hash
	// AS the trie root, breaking v7 CONTENT_GET(root_hash) — the entity
	// resolves to a system/history/transition instead of a snapshot-node.
	_, bare := store.SplitNamespace(evt.Path)
	if bare != p.rootPath {
		return nil
	}
	// Skip our own re-bindings (when Publish writes back the published-root
	// path, that fires another event). Filter by ChangeType: deletes from the
	// tracked-root path mean prefix-disable, not a new root.
	if evt.ChangeType == store.ChangeDeleted {
		return nil
	}
	// Self-write guard: if the event was emitted by Publish itself (the
	// signature/published-root paths), it won't match rootPath above, so we
	// don't double-fire. The rootPath suffix can only be written by RootTracker.

	p.mu.Lock()
	ready := p.authorityOK
	p.mu.Unlock()
	if !ready {
		// Authority will publish initial root once SetupAuthority lands.
		if p.debugLog != nil {
			p.debugLog.Printf("[publishedroot] tree change observed before authority ready (path=%s)", evt.Path)
		}
		return nil
	}

	if evt.Hash.IsZero() {
		return nil
	}

	// Publish OUT-OF-BAND on a goroutine. Calling Publish synchronously
	// here would deadlock against rootTracker's per-prefix mutex: this
	// hook fires INSIDE rootTracker's applyEventWithDepth (which holds
	// prefixMu for our prefix), and Publish's own li.Set re-triggers
	// applyEventWithDepth which would try to re-acquire the same prefix
	// mutex. Spawning lets the outer rootTracker call return and release
	// the lock before the publish runs. The Publish-internal re-entry
	// guard then compresses bursts (each Publish triggers cascade writes
	// that re-fire this hook; the spawned Publish sees publishing=true
	// and returns errPublishInProgress without doing duplicate work).
	p.mu.Lock()
	debounce := p.debounce
	if debounce > 0 {
		// Trailing-edge coalescing. Record the newest root and arm one
		// timer; every further advance inside the window just overwrites
		// `dirty`, so a burst of any length costs ONE signature and the
		// value published is the newest — never a stale midpoint.
		root := evt.Hash
		p.dirty = &root
		if p.timerArmed {
			p.mu.Unlock()
			return nil
		}
		p.timerArmed = true
		p.mu.Unlock()
		time.AfterFunc(debounce, p.flushDirty)
		return nil
	}
	p.mu.Unlock()

	go func(root hash.Hash) {
		if _, err := p.Publish(root); err != nil {
			if err == errPublishInProgress {
				return
			}
			if p.debugLog != nil {
				p.debugLog.Printf("[publishedroot] async publish error: %v", err)
			}
		}
	}(evt.Hash)
	return nil
}

// flushDirty publishes the newest root observed during the debounce
// window. It is the trailing edge: the timer measures QUIET, so this runs
// once the writes stop rather than on a fixed cadence.
//
// Convergence (§6.5.6) rests on this being unconditional — if it ever
// returned without either publishing `dirty` or handing it to an in-flight
// publish, the burst tail would be lost and the published root would sit
// behind the tracked root forever. errPublishInProgress is precisely that
// hand-off: Publish parked the root in `pending` and its drain loop will
// carry it.
func (p *Publisher) flushDirty() {
	p.mu.Lock()
	p.timerArmed = false
	d := p.dirty
	p.dirty = nil
	p.mu.Unlock()
	if d == nil {
		return
	}
	if _, err := p.Publish(*d); err != nil && err != errPublishInProgress {
		if p.debugLog != nil {
			p.debugLog.Printf("[publishedroot] debounced publish error: %v", err)
		}
	}
}

// Flush publishes any root still sitting in the debounce window, without
// waiting for the timer. Call it before shutting a publisher down so a
// burst that ended inside the window is not left unpublished.
//
// Not calling it is recoverable rather than fatal: SetupAuthority
// publishes the tracker's current root on startup, so a peer that dies
// with a pending debounce re-converges on its next boot. Flush turns that
// from "fixed on restart" into "never wrong".
func (p *Publisher) Flush() {
	p.flushDirty()
}
