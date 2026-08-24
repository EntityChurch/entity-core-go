package encvectors

import (
	"bytes"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"go.entitychurch.org/entity-core-go/core/hash"
	"go.entitychurch.org/entity-core-go/core/types"
	"go.entitychurch.org/entity-core-go/ext/encryption"
)

// §16.6 requirement 3 makes negative controls a MUST, and the reason is that a
// vector harness which only verifies its own emission proves a round trip and
// nothing else. Each test below either mutates the FILE (does the verifier
// notice a wrong expectation?) or injects a deliberately-wrong RESOLVER (do the
// shipped rows notice a wrong implementation?). The second kind is what says
// whether the vector is worth emitting at all.

// --- wrong resolvers -------------------------------------------------------
//
// Each is a plausible implementation of §4.4 that gets exactly one thing wrong,
// written as a full resolver rather than a wrapper so that it fails the way a
// sibling implementation would: silently, with a well-formed answer.

// faults enumerates the ways resolveWith can be told to be wrong. Sharing one
// skeleton keeps the controls honest — a stub that diverged from the real walk
// in some incidental way could "catch" a row for the wrong reason.
type faults struct {
	TieBreakDescending  bool // pick the LARGER content_hash on a tie
	HashIsPrimaryKey    bool // sort by content_hash first, created second
	TieBreakOnCarrier   bool // Q1 wrong reading: order by the carrier hash
	GlobalRecency       bool // ignore the tier ladder entirely
	StopAtFirstNonEmpty bool // a non-empty tier terminates the walk
	FirstEnumerated     bool // no ordering rule at all
	CarrierRevKillsKey  bool // treat a carrier revocation as killing the key
	IgnoreExpires       bool // never apply the §4.1 expiry filter
	AnyExpiryDrops      bool // drop any key that CARRIES an expiry
	IgnoreRetrieval     bool // select a key whose entity cannot be read
	UnreadableIsFatal   bool // treat an unreadable candidate as an error, not a drop
	IgnoreCarrierLive   bool // ignore liveness filter 1
	TieBreakBareDigest  bool // Q2's rejected reading: compare digests, not the full form
	FormatIsPrecedence  bool // read content_hash_format as a preference, not a sort input
}

func resolverFor(f faults) ResolverFn {
	return func(p encryption.RecipientPublications) (encryption.Resolution, error) {
		return resolveWith(p, f)
	}
}

// resolveWith is a second implementation of the §4.4 walk, parameterised by the
// fault to inject. It is intentionally independent of ext/encryption's resolver
// so that a bug shared with the real one cannot hide.
func resolveWith(p encryption.RecipientPublications, f faults) (encryption.Resolution, error) {
	type cand struct {
		pubkey  hash.Hash
		carrier hash.Hash
		created uint64
	}

	rungs := []struct {
		tier encryption.Tier
		cs   []encryption.Carrier
	}{
		{encryption.TierC, p.TierC}, {encryption.TierB, p.TierB}, {encryption.TierA, p.TierA},
	}
	if f.GlobalRecency {
		all := append(append(append([]encryption.Carrier{}, p.TierC...), p.TierB...), p.TierA...)
		tierOf := map[hash.Hash]encryption.Tier{}
		for _, c := range p.TierC {
			tierOf[c.Pubkey] = encryption.TierC
		}
		for _, c := range p.TierB {
			tierOf[c.Pubkey] = encryption.TierB
		}
		for _, c := range p.TierA {
			tierOf[c.Pubkey] = encryption.TierA
		}
		sub := f
		sub.GlobalRecency = false
		res, err := resolveWith(encryption.RecipientPublications{
			TierC: all, Pubkeys: p.Pubkeys, RevokedPubkeys: p.RevokedPubkeys,
			RevokedCarriers: p.RevokedCarriers, Now: p.Now,
		}, sub)
		if err != nil {
			return res, err
		}
		res.Tier = tierOf[res.Pubkey]
		return res, nil
	}

	dropped := false
	for _, rung := range rungs {
		if len(rung.cs) == 0 {
			continue
		}
		var live []cand
		seen := map[hash.Hash]bool{}
		for _, c := range rung.cs {
			if !c.Live && !f.IgnoreCarrierLive {
				dropped = true
				continue
			}
			if p.RevokedCarriers[c.Hash] {
				dropped = true
				if f.CarrierRevKillsKey {
					seen[c.Pubkey] = true // poison the key, not just this carrier
				}
				continue
			}
			if seen[c.Pubkey] {
				continue
			}
			seen[c.Pubkey] = true
			if p.RevokedPubkeys[c.Pubkey] {
				dropped = true
				continue
			}
			ent, ok := p.Pubkeys[c.Pubkey]
			if !ok && f.UnreadableIsFatal {
				return encryption.Resolution{}, encryption.ErrEncryptionRecipientUnknown
			}
			if !ok && !f.IgnoreRetrieval {
				dropped = true
				continue
			}
			if ent.Expires != 0 {
				expired := p.Now != 0 && p.Now >= ent.Expires
				if f.AnyExpiryDrops || (expired && !f.IgnoreExpires) {
					dropped = true
					continue
				}
			}
			live = append(live, cand{pubkey: c.Pubkey, carrier: c.Hash, created: ent.Created})
		}
		if len(live) == 0 {
			if f.StopAtFirstNonEmpty {
				break
			}
			continue
		}
		best := live[0]
		for _, c := range live[1:] {
			if f.FirstEnumerated {
				break
			}
			switch {
			case f.HashIsPrimaryKey:
				if c.pubkey != best.pubkey && bytesLess(c.pubkey, best.pubkey) {
					best = c
				}
			case f.FormatIsPrecedence && c.pubkey.Algorithm != best.pubkey.Algorithm:
				// Reads the format byte as "which content_hash_format do I
				// prefer" rather than as the first byte of a sort key —
				// grouping candidates by format before ordering them. It gets
				// the mixed tie rows RIGHT for the wrong reason, which is what
				// makes it worth injecting separately.
				if c.pubkey.Algorithm < best.pubkey.Algorithm {
					best = c
				}
			case c.created != best.created:
				if c.created > best.created {
					best = c
				}
			case f.TieBreakOnCarrier:
				if bytesLess(c.carrier, best.carrier) {
					best = c
				}
			case f.TieBreakDescending:
				if bytesLess(best.pubkey, c.pubkey) {
					best = c
				}
			case f.TieBreakBareDigest:
				// EffectiveDigest() strips the format byte — the natural
				// reading, and the one arch's Q2 ruling rejected. Identical to
				// the correct rule under a single algorithm.
				if bytes.Compare(c.pubkey.EffectiveDigest(), best.pubkey.EffectiveDigest()) < 0 {
					best = c
				}
			default:
				if bytesLess(c.pubkey, best.pubkey) {
					best = c
				}
			}
		}
		return encryption.Resolution{Pubkey: best.pubkey, Tier: rung.tier}, nil
	}
	_ = dropped
	return encryption.Resolution{}, encryption.ErrEncryptionRecipientUnknown
}

func bytesLess(a, b hash.Hash) bool {
	x, y := a.Bytes(), b.Bytes()
	for i := 0; i < len(x) && i < len(y); i++ {
		if x[i] != y[i] {
			return x[i] < y[i]
		}
	}
	return len(x) < len(y)
}

// --- the controls that matter: do the shipped rows catch a wrong impl? ------

func TestShippedRowsCatchWrongResolvers(t *testing.T) {
	rows := Rows()

	// Each entry names the row that MUST be the one to fail. Asserting only
	// "something failed" would let a row fail for an unrelated reason and still
	// look like coverage — the point is that the guard is where we think it is.
	for _, tt := range []struct {
		name    string
		fault   faults
		wantRow string
		blindTo string
	}{
		{
			name:    "tie-break descending (the defect core-go shipped)",
			fault:   faults{TieBreakDescending: true},
			wantRow: "tiebreak/ascending-lower-hash-wins",
			blindTo: "every row that only asserts order-independence",
		},
		{
			name:    "content_hash sorted as the primary key",
			fault:   faults{HashIsPrimaryKey: true},
			wantRow: "recency/newest-wins",
			blindTo: "both tie rows, which it answers correctly",
		},
		{
			name:    "tie-break taken on the carrier hash (Q1's wrong reading)",
			fault:   faults{TieBreakOnCarrier: true},
			wantRow: "projection/tie-breaks-on-pubkey-not-carrier",
			blindTo: "every Tier-A row, where carrier and pubkey are the same value",
		},
		{
			name:    "global recency sort, tier ladder ignored",
			fault:   faults{GlobalRecency: true},
			wantRow: "ladder/c-outranks-newer-a",
			blindTo: "every single-tier row",
		},
		{
			name:    "walk stops at the first non-empty tier",
			fault:   faults{StopAtFirstNonEmpty: true},
			wantRow: "dead-tier/falls-through-to-a-live-lower-tier",
			blindTo: "every row where the top tier has a live candidate",
		},
		{
			name:    "carrier revocation treated as killing the key",
			fault:   faults{CarrierRevKillsKey: true},
			wantRow: "revocation/carrier-targeted-leaves-sibling-standing",
			blindTo: "the single-carrier revocation row, which it answers correctly",
		},
		{
			name:    "expiry never applied",
			fault:   faults{IgnoreExpires: true},
			wantRow: "expires/expired-key-dropped",
			blindTo: "every row with no expiring key",
		},
		{
			name:    "any key carrying an expiry is dropped",
			fault:   faults{AnyExpiryDrops: true},
			wantRow: "expires/unexpired-key-still-selected",
			blindTo: "the expired-key row, which it answers correctly",
		},
		{
			// Caught by the all-unreadable row, NOT by the mixed one — and the
			// reason is worth recording. An unreadable key has no readable
			// `created`, so a resolver that skips the retrievability filter has
			// nothing to order it BY and cannot outrank a readable sibling. The
			// rule is only observable when retrievability decides between
			// binding something and reporting recipient_unknown.
			name:    "retrievability ignored",
			fault:   faults{IgnoreRetrieval: true},
			wantRow: "unknown/all-unreadable",
			blindTo: "any row with at least one readable key, which it still answers correctly",
		},
		{
			// The other half of the same rule, and a genuinely distinct wrong
			// implementation: §4.4 says an unreadable candidate is "dropped and
			// the walk continues", explicitly NOT a distinct error.
			name:    "unreadable candidate treated as fatal instead of dropped",
			fault:   faults{UnreadableIsFatal: true},
			wantRow: "retrievability/unreadable-key-dropped",
			blindTo: "every row whose keys are all readable",
		},
		{
			name:    "carrier validity ignored",
			fault:   faults{IgnoreCarrierLive: true},
			wantRow: "carrier-validity/dead-carrier-dropped",
			blindTo: "every row whose carriers are all live",
		},
		{
			// Q2's rejected reading, and the control that makes the ruling
			// falsifiable. Until the mixed-format rows landed, this fault was
			// UNDETECTABLE by every row in the file — not because the rows were
			// weak but because the two readings are the same function under one
			// algorithm. A ruling nothing can fail is not gated.
			name:    "tie-break on the bare digest (Q2's rejected reading)",
			fault:   faults{TieBreakBareDigest: true},
			wantRow: "tiebreak/mixed-format-prefixed-not-bare-digest",
			blindTo: "every single-algorithm row, where stripping a shared prefix changes nothing",
		},
		{
			name:    "content_hash_format read as precedence rather than as sort input",
			fault:   faults{FormatIsPrecedence: true},
			wantRow: "tiebreak/mixed-format-created-still-outranks",
			blindTo: "both mixed TIE rows, which it answers correctly — for the wrong reason",
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			rep := VerifyRows(rows, resolverFor(tt.fault))
			if rep.Fail == 0 {
				t.Fatalf("a resolver that gets %q wrong PASSED all %d rows — the vector is blind to it "+
					"(this resolver is blind to %s)", tt.name, rep.Pass, tt.blindTo)
			}
			if !reportNames(rep, tt.wantRow) {
				t.Errorf("expected row %q to be the one that fails; got:\n%s", tt.wantRow, reportText(rep))
			}
		})
	}
}

// TestPermutationPassCatchesOrderDependence is the control for the structural
// reversal check specifically. §16.6 calls this out by name: a guard that
// cannot be made to fire needs its own injected-fault control, or it is
// coverage-shaped and measures nothing. Against a correct resolver the reversal
// pass can never fail.
func TestPermutationPassCatchesOrderDependence(t *testing.T) {
	rep := VerifyRows(Rows(), resolverFor(faults{FirstEnumerated: true}))
	if rep.Fail == 0 {
		t.Fatalf("a resolver with no ordering rule at all PASSED all %d rows", rep.Pass)
	}
	// Assert on the [reversed] marker specifically, not merely that some
	// ordering row failed. `tiebreak/ascending-lower-hash-wins` lists the
	// expected winner FIRST, so a first-enumerated resolver answers it
	// correctly on the forward pass and can only be caught on the flip.
	if !reportNames(rep, "[reversed]") {
		t.Errorf("no row failed on the reversed pass, so the permutation guard did not fire; got:\n%s",
			reportText(rep))
	}
}

// TestCorrectResolverPassesEveryRow is the baseline. On its own it proves only
// that core-go agrees with core-go — it is meaningful only alongside the
// controls above.
func TestCorrectResolverPassesEveryRow(t *testing.T) {
	rep := VerifyRows(Rows(), encryption.ResolveRecipientKey)
	if rep.Fail != 0 {
		t.Fatalf("core-go's own resolver fails its own vector:\n%s", reportText(rep))
	}
	if rep.Pass != len(Rows()) {
		t.Errorf("verified %d rows, emitted %d", rep.Pass, len(Rows()))
	}
}

// TestEveryRuleHasANegativeControl is the meta-guard. §16.6's coverage list is
// normative, and a row can be added for a rule without anyone adding the
// wrong-resolver that proves the row bites. This asserts the mapping is total
// in the direction that matters: every fault we can name is caught somewhere.
//
// The fault set is ENUMERATED FROM THE STRUCT, not written out beside it. It
// was a hand-maintained list, which is the shape that quietly stops covering
// things: adding a field to `faults` and a case to resolveWith left this test
// passing while the new fault went unchecked, and it would have read as
// coverage. Reflection makes the list unable to fall behind the type — a new
// bool field fails here until some row catches it.
func TestEveryRuleHasANegativeControl(t *testing.T) {
	ft := reflect.TypeOf(faults{})
	for i := 0; i < ft.NumField(); i++ {
		field := ft.Field(i)
		if field.Type.Kind() != reflect.Bool {
			t.Fatalf("faults.%s is %s; this test assumes every fault is a bool switch",
				field.Name, field.Type)
		}
		var f faults
		reflect.ValueOf(&f).Elem().Field(i).SetBool(true)
		if rep := VerifyRows(Rows(), resolverFor(f)); rep.Fail == 0 {
			t.Errorf("fault %q is not caught by any row — a wrong resolver with exactly this "+
				"defect passes the whole vector", field.Name)
		}
	}
}

// --- controls on the verifier: does a mutated FILE get caught? --------------

func TestVerifierCatchesMutatedExpectations(t *testing.T) {
	for _, tt := range []struct {
		name   string
		mutate func(v *ResolveVector)
	}{
		{
			name: "expected selection changed to another live key",
			mutate: func(v *ResolveVector) {
				if v.Name == "recency/newest-wins" {
					v.Expect.Selected = pkOld
				}
			},
		},
		{
			name: "right key, wrong tier",
			mutate: func(v *ResolveVector) {
				if v.Name == "ladder/same-pubkey-at-c-and-a" {
					v.Expect.Tier = "A"
				}
			},
		},
		{
			name: "an error row relabelled as a selection",
			mutate: func(v *ResolveVector) {
				if v.Name == "unknown/no-publications" {
					v.Expect = selected(pkTierA, "A")
				}
			},
		},
		{
			name: "a selection row relabelled as an error",
			mutate: func(v *ResolveVector) {
				if v.Name == "ladder/a-alone" {
					v.Expect = unknownRecipient()
				}
			},
		},
		{
			name: "an error row claiming a code that is not a §4.4 outcome",
			mutate: func(v *ResolveVector) {
				if v.Name == "unknown/all-revoked" {
					v.Expect.Error = "encryption_key_revoked"
				}
			},
		},
		{
			name: "outcome field emptied — a row that states no expectation",
			mutate: func(v *ResolveVector) {
				if v.Name == "ladder/a-alone" {
					v.Expect.Outcome = ""
				}
			},
		},
		{
			name: "outcome field set to something the verifier does not know",
			mutate: func(v *ResolveVector) {
				if v.Name == "ladder/a-alone" {
					v.Expect.Outcome = "probably"
				}
			},
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			rows := Rows()
			for i := range rows {
				tt.mutate(&rows[i])
			}
			rep := VerifyRows(rows, encryption.ResolveRecipientKey)
			if rep.Fail == 0 {
				t.Fatalf("verifier accepted a file with %s — all %d rows passed", tt.name, rep.Pass)
			}
		})
	}
}

// TestVerifierRefusesEmptyAndForeignFiles guards the two ways a file can be
// green while crossing nothing: no rows at all, and a schema this build does
// not speak. Both must be hard errors, never a zero-check pass.
//
// The schema case is load-bearing now rather than theoretical: /1 rows carry a
// flat candidate list that conflates carrier and pubkey, so reinterpreting one
// under /2 would silently test the wrong thing.
func TestVerifierRefusesEmptyAndForeignFiles(t *testing.T) {
	dir := t.TempDir()

	empty := filepath.Join(dir, "empty.cbor")
	writeFile(t, empty, VectorFile{Schema: Schema, Emitter: "test", Rows: nil})
	if _, err := Verify(empty, io.Discard); err == nil {
		t.Error("a file with no rows verified successfully — 0 checks / 0 failures must not read as a pass")
	}

	old := filepath.Join(dir, "v1.cbor")
	writeFile(t, old, VectorFile{Schema: "encryption-resolve-order/1", Emitter: "test", Rows: Rows()})
	if _, err := Verify(old, io.Discard); err == nil {
		t.Error("a /1 file was accepted under /2 — the candidate model changed and cannot be reinterpreted")
	}
}

// --- determinism ------------------------------------------------------------

// TestEmissionIsDeterministic is what makes the emitter_commit pin mean
// anything: a file nobody can re-derive is an assertion, not evidence.
func TestEmissionIsDeterministic(t *testing.T) {
	dir := t.TempDir()
	a, b := filepath.Join(dir, "a.cbor"), filepath.Join(dir, "b.cbor")
	if err := Emit(a, "test-pin", io.Discard); err != nil {
		t.Fatalf("emit a: %v", err)
	}
	if err := Emit(b, "test-pin", io.Discard); err != nil {
		t.Fatalf("emit b: %v", err)
	}
	if string(readFile(t, a)) != string(readFile(t, b)) {
		t.Error("two emissions differ — something here reads a clock or a random source")
	}
}

func TestEmittedFileVerifies(t *testing.T) {
	path := filepath.Join(t.TempDir(), "v.cbor")
	if err := Emit(path, "test-pin", io.Discard); err != nil {
		t.Fatalf("emit: %v", err)
	}
	ok, err := Verify(path, io.Discard)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if !ok {
		t.Error("core-go's own emission does not verify against core-go")
	}
}

// TestRowsStayNeutralOnDeclaredExclusions enforces what the `excludes` field
// promises (§16.6 requirement 4). Without it a row added later could quietly
// widen scope past what the file claims, and it would look exactly like
// coverage.
func TestRowsStayNeutralOnDeclaredExclusions(t *testing.T) {
	for _, v := range Rows() {
		all := append(append(append([]Carrier{}, v.TierC...), v.TierB...), v.TierA...)
		// The declared-unreachable clause: no row may contain a pair where
		// one hash is a proper prefix of the other. `excludes` states this
		// is impossible with the allocated formats rather than untested, so
		// a row that somehow produced one would make the file lie about
		// itself — and would be exercising a clause nobody can author.
		for i, a := range all {
			for _, b := range all[i+1:] {
				if isProperPrefix(a.Pubkey.Bytes(), b.Pubkey.Bytes()) ||
					isProperPrefix(b.Pubkey.Bytes(), a.Pubkey.Bytes()) {
					t.Errorf("%s: one pubkey hash is a proper prefix of another — `excludes` "+
						"declares this unreachable with the formats V7 §4 allocates", v.Name)
				}
			}
		}
		for _, k := range v.Pubkeys {
			if k.Expires != 0 && v.Now == 0 {
				t.Errorf("%s: a key carries `expires` but the row authors no `now` — the expiry "+
					"filter would silently not run, making the row look like coverage", v.Name)
			}
		}
	}
}

func isProperPrefix(short, long []byte) bool {
	return len(short) < len(long) && bytes.Equal(short, long[:len(short)])
}

// TestMixedFormatRowsDiscriminateTheTwoReadings is the test that makes the Q2
// rows evidence instead of decoration.
//
// A row only gates a ruling if the REJECTED reading fails it. Arch pinned the
// tie-break to the full multihash-prefixed content_hash over the bare digest;
// the two agree on every single-algorithm row in this file, so those rows pass
// under either reading and prove nothing about the ruling. This asserts the
// opposition directly: on the mixed row, ascending-by-prefixed-bytes and
// ascending-by-bare-digest pick DIFFERENT keys, and the row expects the former.
//
// Written as an independent comparison rather than by calling a second resolver
// on purpose — a check that re-derives its expectation from the code under test
// proves only that the code agrees with itself.
func TestMixedFormatRowsDiscriminateTheTwoReadings(t *testing.T) {
	const row = "tiebreak/mixed-format-prefixed-not-bare-digest"
	var v *ResolveVector
	for i := range Rows() {
		if Rows()[i].Name == row {
			v = &Rows()[i]
		}
	}
	if v == nil {
		t.Fatalf("row %q is gone — Q2 is unobservable again", row)
	}
	if len(v.Pubkeys) != 2 {
		t.Fatalf("row %q has %d candidates; the opposition needs exactly 2", row, len(v.Pubkeys))
	}
	a, b := v.Pubkeys[0].Pubkey, v.Pubkeys[1].Pubkey
	if v.Pubkeys[0].Created != v.Pubkeys[1].Created {
		t.Fatalf("row %q candidates differ on `created` — the tie-break never runs", row)
	}
	if a.Algorithm == b.Algorithm {
		t.Fatalf("row %q candidates share content_hash_format 0x%02x — the two readings "+
			"cannot diverge within one algorithm, which is the whole reason this row exists",
			row, a.Algorithm)
	}

	lower := func(x, y hash.Hash, digestOnly bool) hash.Hash {
		bx, by := x.Bytes(), y.Bytes()
		if digestOnly {
			bx, by = x.EffectiveDigest(), y.EffectiveDigest()
		}
		if bytes.Compare(bx, by) <= 0 {
			return x
		}
		return y
	}

	prefixedWinner := lower(a, b, false)
	bareWinner := lower(a, b, true)
	if prefixedWinner == bareWinner {
		t.Fatalf("row %q: both readings select %x — the row does not discriminate and Q2 "+
			"remains unobservable", row, prefixedWinner.Bytes())
	}
	if v.Expect.Selected != prefixedWinner {
		t.Errorf("row %q expects %x but the PINNED reading (full multihash-prefixed, ascending) "+
			"selects %x", row, v.Expect.Selected.Bytes(), prefixedWinner.Bytes())
	}
	if v.Expect.Selected == bareWinner {
		t.Errorf("row %q expects the BARE-DIGEST winner — the row asserts the rejected reading", row)
	}
}

// TestEveryRowIsNamedAndExplained keeps the file diagnosable from itself: a row
// that fails on a sibling's verifier is read by someone without this tree.
func TestEveryRowIsNamedAndExplained(t *testing.T) {
	seen := map[string]bool{}
	for i, v := range Rows() {
		if v.Name == "" {
			t.Errorf("row %d has no name", i)
		}
		if v.Why == "" {
			t.Errorf("row %q does not say what it guards", v.Name)
		}
		if seen[v.Name] {
			t.Errorf("duplicate row name %q", v.Name)
		}
		seen[v.Name] = true
	}
}

// TestEveryReferencedPubkeyIsAuthoredOrDeliberatelyAbsent catches the fixture
// mistake that would be indistinguishable from the retrievability rule: a row
// that forgets to author a key looks exactly like a row testing an unreadable
// one. Only the rows that OPT IN by name may leave a referenced key absent.
func TestEveryReferencedPubkeyIsAuthoredOrDeliberatelyAbsent(t *testing.T) {
	intentional := map[string]bool{
		"retrievability/unreadable-key-dropped": true,
		"unknown/all-unreadable":                true,
	}
	for _, v := range Rows() {
		if intentional[v.Name] {
			continue
		}
		authored := map[hash.Hash]bool{}
		for _, k := range v.Pubkeys {
			authored[k.Pubkey] = true
		}
		all := append(append(append([]Carrier{}, v.TierC...), v.TierB...), v.TierA...)
		for _, c := range all {
			if !authored[c.Pubkey] {
				t.Errorf("%s: carrier %s names pubkey %s with no authored entity — if that is "+
					"deliberate the row belongs in the intentional set, otherwise it is a fixture bug "+
					"masquerading as the retrievability rule", v.Name, c.Hash, c.Pubkey)
			}
		}
	}
}

// --- helpers ----------------------------------------------------------------

func reportNames(r *Report, want string) bool {
	for _, l := range r.Lines {
		if contains(l, "FAIL") && contains(l, want) {
			return true
		}
	}
	return false
}

func reportText(r *Report) string {
	out := ""
	for _, l := range r.Lines {
		out += l + "\n"
	}
	return out
}

func contains(haystack, needle string) bool {
	for i := 0; i+len(needle) <= len(haystack); i++ {
		if haystack[i:i+len(needle)] == needle {
			return true
		}
	}
	return false
}

func writeFile(t *testing.T, path string, f VectorFile) {
	t.Helper()
	raw, err := Encode(f)
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	if err := os.WriteFile(path, raw, 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}
}

func readFile(t *testing.T, path string) []byte {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	return b
}

var _ = types.EncryptionErrRecipientUnknown
