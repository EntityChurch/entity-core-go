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
func NewPublisher(cs store.ContentStore, tracker *tree.RootTracker, prefix string, debugLog *log.Logger) *Publisher {
	return &Publisher{
		cs:       cs,
		tracker:  tracker,
		prefix:   prefix,
		debugLog: debugLog,
		// RootTracker writes its tracked root to
		// `store.CleanPath("system/tree/root/" + prefix)` — CleanPath strips
		// trailing slashes. We mirror the same canonicalization so the
		// HasSuffix match against the NamespacedIndex-qualified event path
		// (`/{peerID}/system/tree/root/<cleaned-prefix>`) actually fires.
		rootPath: strings.TrimRight("system/tree/root/"+prefix, "/"),
	}
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
		// Another Publish is already in flight on this publisher (we're
		// being re-entered via the LI-write cascade). The outer call's
		// effects subsume this one; return the in-flight last entity if
		// available so callers don't see a spurious error.
		p.mu.Unlock()
		return entity.Entity{}, errPublishInProgress
	}
	p.publishing = true
	p.lastSeq++
	pr := types.PublishedRootData{
		PeerID:      p.peerID,
		RootHash:    rootHash,
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

	defer func() {
		p.mu.Lock()
		p.publishing = false
		p.mu.Unlock()
	}()

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
