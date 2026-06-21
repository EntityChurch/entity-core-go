package revision

import (
	"strings"
	"testing"

	"go.entitychurch.org/entity-core-go/core/hash"
	"go.entitychurch.org/entity-core-go/core/store"
	"go.entitychurch.org/entity-core-go/core/tree"
	"go.entitychurch.org/entity-core-go/core/types"
)

// fakeVersionWithRoot creates a RevisionEntryData stub and stores it,
// returning its content hash. Lets tests construct realistic version hashes
// for use as localVer/remoteVer in deletion-resolution tests.
func fakeVersionWithRoot(t *testing.T, cs store.ContentStore, root hash.Hash, parents []hash.Hash) hash.Hash {
	t.Helper()
	v := types.RevisionEntryData{Root: root, Parents: tree.SortedParents(parents)}
	ent, err := v.ToEntity()
	if err != nil {
		t.Fatalf("build version entity: %v", err)
	}
	h, err := cs.Put(ent)
	if err != nil {
		t.Fatalf("put version: %v", err)
	}
	return h
}

func mustPutMarker(t *testing.T, cs store.ContentStore) {
	t.Helper()
	if _, err := cs.Put(types.CanonicalDeletionMarker()); err != nil {
		t.Fatalf("put canonical marker: %v", err)
	}
}

// TestResolveDeletionVsEntity_DeletionWins — explicit deletion-wins override.
// A canonical marker on one side and an entity on the other resolves to the
// marker regardless of timing or hash ordering. Per Amendment 4 this is no
// longer the default; it must be configured explicitly.
func TestResolveDeletionVsEntity_DeletionWins(t *testing.T) {
	cs := store.NewMemoryContentStore()
	mustPutMarker(t, cs)
	markerHash := types.CanonicalDeletionMarkerHash()
	entityHash := storeTestEntity(t, cs, "app/doc", map[string]string{"v": "edited"})
	localVer := fakeVersionWithRoot(t, cs, markerHash, nil)
	remoteVer := fakeVersionWithRoot(t, cs, entityHash, nil)

	// Marker on local, entity on remote.
	result := resolveDeletionVsEntity(cs, deletionStrategyDeletionWins, "foo", markerHash, entityHash, localVer, remoteVer)
	if !result.HasConflict {
		t.Fatal("expected HasConflict=true")
	}
	if result.ResolvedHash != markerHash {
		t.Fatalf("expected marker to win, got %s", result.ResolvedHash)
	}
	if len(result.SidecarBindings) != 0 {
		t.Fatalf("deletion-wins should produce no sidecars, got %d", len(result.SidecarBindings))
	}

	// Symmetric: entity on local, marker on remote.
	result = resolveDeletionVsEntity(cs, deletionStrategyDeletionWins, "foo", entityHash, markerHash, localVer, remoteVer)
	if result.ResolvedHash != markerHash {
		t.Fatalf("symmetric: expected marker to win, got %s", result.ResolvedHash)
	}
}

// TestResolveDeletionVsEntity_PreserveOnConflict — the new ratified default.
// Entity supersedes marker; the delete signal is silently dropped. Recommended
// for collaborative-edit workflows where edit preservation is the priority.
func TestResolveDeletionVsEntity_PreserveOnConflict(t *testing.T) {
	cs := store.NewMemoryContentStore()
	mustPutMarker(t, cs)
	markerHash := types.CanonicalDeletionMarkerHash()
	entityHash := storeTestEntity(t, cs, "app/doc", map[string]string{"v": "edited"})
	localVer := fakeVersionWithRoot(t, cs, markerHash, nil)
	remoteVer := fakeVersionWithRoot(t, cs, entityHash, nil)

	// Marker on local, entity on remote → entity wins.
	result := resolveDeletionVsEntity(cs, deletionStrategyPreserveOnConflict, "foo", markerHash, entityHash, localVer, remoteVer)
	if !result.HasConflict {
		t.Fatal("expected HasConflict=true")
	}
	if result.ResolvedHash != entityHash {
		t.Fatalf("expected entity to win under preserve-on-conflict, got %s", result.ResolvedHash)
	}
	if len(result.SidecarBindings) != 0 {
		t.Fatalf("preserve-on-conflict should produce no sidecars, got %d", len(result.SidecarBindings))
	}

	// Symmetric: entity on local, marker on remote → entity still wins.
	result = resolveDeletionVsEntity(cs, deletionStrategyPreserveOnConflict, "foo", entityHash, markerHash, localVer, remoteVer)
	if result.ResolvedHash != entityHash {
		t.Fatalf("symmetric: expected entity to win, got %s", result.ResolvedHash)
	}
}

// TestResolveDeletionVsEntity_ThreeWayFallthrough — activates the §193 dormant
// code path. Returns HasConflict=false so the caller falls through to
// applyMergeStrategy(three-way), which classifies marker-vs-entity as
// unresolvable and writes a conflict entity. The resolver itself only needs
// to signal the fall-through; the conflict-entity write happens in the caller.
func TestResolveDeletionVsEntity_ThreeWayFallthrough(t *testing.T) {
	cs := store.NewMemoryContentStore()
	mustPutMarker(t, cs)
	markerHash := types.CanonicalDeletionMarkerHash()
	entityHash := storeTestEntity(t, cs, "app/doc", map[string]string{"v": "edited"})
	localVer := fakeVersionWithRoot(t, cs, markerHash, nil)
	remoteVer := fakeVersionWithRoot(t, cs, entityHash, nil)

	result := resolveDeletionVsEntity(cs, deletionStrategyThreeWayFallthrough, "foo", markerHash, entityHash, localVer, remoteVer)
	if result.HasConflict {
		t.Fatalf("three-way-fallthrough must return HasConflict=false to activate §193 dormant path, got resolved=%s", result.ResolvedHash)
	}
	if len(result.SidecarBindings) != 0 {
		t.Fatalf("three-way-fallthrough should produce no sidecars, got %d", len(result.SidecarBindings))
	}

	// Symmetric.
	result = resolveDeletionVsEntity(cs, deletionStrategyThreeWayFallthrough, "foo", entityHash, markerHash, localVer, remoteVer)
	if result.HasConflict {
		t.Fatalf("symmetric three-way-fallthrough must return HasConflict=false, got resolved=%s", result.ResolvedHash)
	}
}

// TestResolveDeletionVsEntity_Deterministic — byte-order hash comparison.
// Lower hash wins. Stable but arbitrary; tests verify both directions.
func TestResolveDeletionVsEntity_Deterministic(t *testing.T) {
	cs := store.NewMemoryContentStore()
	mustPutMarker(t, cs)
	markerHash := types.CanonicalDeletionMarkerHash()
	markerBytes := markerHash.Bytes()

	// Build entities whose hashes sort BELOW and ABOVE the marker hash.
	// To get reliable below/above, generate several and pick by sort order.
	var below, above hash.Hash
	for i := 0; i < 100; i++ {
		h := storeTestEntity(t, cs, "app/doc", map[string]int{"i": i})
		hb := h.Bytes()
		if compareBytes(hb, markerBytes) < 0 && below.IsZero() {
			below = h
		}
		if compareBytes(hb, markerBytes) > 0 && above.IsZero() {
			above = h
		}
		if !below.IsZero() && !above.IsZero() {
			break
		}
	}
	if below.IsZero() || above.IsZero() {
		t.Fatalf("setup: couldn't find below/above hashes in 100 tries (very unlucky)")
	}

	localVer := fakeVersionWithRoot(t, cs, markerHash, nil)
	remoteVer := fakeVersionWithRoot(t, cs, below, nil)

	// Entity hash SORTS BELOW marker → entity wins.
	result := resolveDeletionVsEntity(cs, deletionStrategyDeterministic, "foo", markerHash, below, localVer, remoteVer)
	if result.ResolvedHash != below {
		t.Fatalf("deterministic: lower-sorting entity should win, got %s (marker=%s, entity=%s)",
			result.ResolvedHash, markerHash, below)
	}

	// Entity hash SORTS ABOVE marker → marker wins.
	result = resolveDeletionVsEntity(cs, deletionStrategyDeterministic, "foo", markerHash, above, localVer, remoteVer)
	if result.ResolvedHash != markerHash {
		t.Fatalf("deterministic: marker should win against higher-sorting entity, got %s (marker=%s, entity=%s)",
			result.ResolvedHash, markerHash, above)
	}
}

// compareBytes is a local lexicographic byte compare (test helper).
func compareBytes(a, b []byte) int {
	for i := 0; i < len(a) && i < len(b); i++ {
		if a[i] < b[i] {
			return -1
		}
		if a[i] > b[i] {
			return 1
		}
	}
	if len(a) < len(b) {
		return -1
	}
	if len(a) > len(b) {
		return 1
	}
	return 0
}

// TestResolveDeletionVsEntity_NotADeletionConflict — when neither side is a
// marker, the resolver reports no conflict; caller falls through to the
// standard entity-vs-entity merge strategy.
func TestResolveDeletionVsEntity_NotADeletionConflict(t *testing.T) {
	cs := store.NewMemoryContentStore()
	h1 := storeTestEntity(t, cs, "app/doc", map[string]string{"v": "a"})
	h2 := storeTestEntity(t, cs, "app/doc", map[string]string{"v": "b"})
	result := resolveDeletionVsEntity(cs, deletionStrategyDeletionWins, "foo", h1, h2, hash.Hash{}, hash.Hash{})
	if result.HasConflict {
		t.Fatalf("expected HasConflict=false for entity-vs-entity, got resolved=%s", result.ResolvedHash)
	}
}

// TestResolveDeletionVsEntity_BothMarkersIsIdentity — canonical markers
// are byte-identical; if both sides are markers the caller's same-hash
// check normally fires first, but if it doesn't (defensive), this returns
// the marker without erroring.
func TestResolveDeletionVsEntity_BothMarkersIsIdentity(t *testing.T) {
	cs := store.NewMemoryContentStore()
	mustPutMarker(t, cs)
	markerHash := types.CanonicalDeletionMarkerHash()
	result := resolveDeletionVsEntity(cs, deletionStrategyDeletionWins, "foo", markerHash, markerHash, hash.Hash{}, hash.Hash{})
	if !result.HasConflict {
		t.Fatal("expected HasConflict=true (defensive)")
	}
	if result.ResolvedHash != markerHash {
		t.Fatalf("both-markers should resolve to marker, got %s", result.ResolvedHash)
	}
}

// TestResolveDeletionVsEntity_EmptyStrategyIsDefault — empty strategy string
// defers to the ratified default (preserve-on-conflict per Amendment 4).
// Entity wins; delete signal silently dropped.
func TestResolveDeletionVsEntity_EmptyStrategyIsDefault(t *testing.T) {
	cs := store.NewMemoryContentStore()
	mustPutMarker(t, cs)
	markerHash := types.CanonicalDeletionMarkerHash()
	entityHash := storeTestEntity(t, cs, "app/doc", map[string]string{"v": "edited"})
	result := resolveDeletionVsEntity(cs, "", "foo", markerHash, entityHash, hash.Hash{}, hash.Hash{})
	if result.ResolvedHash != entityHash {
		t.Fatalf("empty strategy should default to preserve-on-conflict (entity wins), got %s", result.ResolvedHash)
	}
}

// TestValidateDeletionResolution — Amendment 4 config-write validator.
// Valid: empty + the four ratified named strategies.
// Invalid (with `invalid_strategy` prefix): `lww`, `keep-both`, unknown strings.
func TestValidateDeletionResolution(t *testing.T) {
	valid := []string{
		"",
		string(deletionStrategyPreserveOnConflict),
		string(deletionStrategyDeletionWins),
		string(deletionStrategyThreeWayFallthrough),
		string(deletionStrategyDeterministic),
	}
	for _, s := range valid {
		if err := ValidateDeletionResolution(s); err != nil {
			t.Errorf("ValidateDeletionResolution(%q) returned error %v, want nil", s, err)
		}
	}

	invalid := []string{"lww", "keep-both", "bogus", "DELETION-WINS" /* case-sensitive */}
	for _, s := range invalid {
		err := ValidateDeletionResolution(s)
		if err == nil {
			t.Errorf("ValidateDeletionResolution(%q) returned nil, want invalid_strategy error", s)
			continue
		}
		if !strings.HasPrefix(err.Error(), "invalid_strategy:") {
			t.Errorf("ValidateDeletionResolution(%q) error = %v, want prefix 'invalid_strategy:'", s, err)
		}
	}
}

// TestResolveDeletionStrategy_PerPrefixConfig — verifies per-prefix
// merge-config lookup. Writes a config with a non-default valid strategy
// at a specific pattern; verifies lookup returns the configured value for
// matching paths and the default for non-matching ones.
func TestResolveDeletionStrategy_PerPrefixConfig(t *testing.T) {
	hctx := newTestContext()

	// Persist a merge-config setting `deletion-wins` for pattern "docs/*".
	cfg := types.RevisionMergeConfigData{
		Pattern:            "docs/*",
		Strategy:           "three-way",
		DeletionResolution: string(deletionStrategyDeletionWins),
	}
	storeEntity(t, hctx, "system/revision/config/merge/path/docs", "system/revision/merge-config", cfg)

	// Path matching the pattern → deletion-wins.
	if got := resolveDeletionStrategy(hctx, "data/", "docs/foo"); got != deletionStrategyDeletionWins {
		t.Fatalf("expected deletion-wins for docs/foo, got %q", got)
	}
	// Path NOT matching → spec default.
	if got := resolveDeletionStrategy(hctx, "data/", "other/foo"); got != defaultDeletionStrategy {
		t.Fatalf("expected default for other/foo, got %q", got)
	}
}

// TestResolveDeletionStrategy_NoConfig — no config registered → spec default.
func TestResolveDeletionStrategy_NoConfig(t *testing.T) {
	hctx := newTestContext()
	if got := resolveDeletionStrategy(hctx, "data/", "any/path"); got != defaultDeletionStrategy {
		t.Fatalf("expected default with no config, got %q", got)
	}
}

// TestResolveDeletionStrategy_EmptyDeletionResolutionField — merge-config
// entry exists but DeletionResolution field is empty → skip; fall through
// to spec default. Prevents a half-configured entry from clobbering the
// default.
func TestResolveDeletionStrategy_EmptyDeletionResolutionField(t *testing.T) {
	hctx := newTestContext()
	cfg := types.RevisionMergeConfigData{
		Pattern:  "*",
		Strategy: "three-way",
		// DeletionResolution intentionally empty.
	}
	storeEntity(t, hctx, "system/revision/config/merge/path/wildcard", "system/revision/merge-config", cfg)

	if got := resolveDeletionStrategy(hctx, "data/", "anything"); got != defaultDeletionStrategy {
		t.Fatalf("empty DeletionResolution should not override default, got %q", got)
	}
}

// TestResolveDeletionStrategy_InvalidStrategyIsSkipped — defensive read-time
// skip. If an invalid strategy value (`lww`, `keep-both`, unknown) escaped
// config-write validation and ended up persisted, the resolver MUST skip it
// and fall through to the spec default rather than honoring the invalid
// value. Mirrors Amendment 4's "rejection-at-write-time AND skip-at-read-time"
// defense in depth.
func TestResolveDeletionStrategy_InvalidStrategyIsSkipped(t *testing.T) {
	for _, invalid := range []string{"lww", "keep-both", "bogus"} {
		t.Run(invalid, func(t *testing.T) {
			hctx := newTestContext()
			cfg := types.RevisionMergeConfigData{
				Pattern:            "*",
				Strategy:           "three-way",
				DeletionResolution: invalid,
			}
			storeEntity(t, hctx, "system/revision/config/merge/path/wildcard", "system/revision/merge-config", cfg)

			if got := resolveDeletionStrategy(hctx, "data/", "anything"); got != defaultDeletionStrategy {
				t.Fatalf("invalid DeletionResolution %q should be skipped → default, got %q", invalid, got)
			}
		})
	}
}
