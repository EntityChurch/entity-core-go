# The Ratchet And Divergence Rule

How the methodology's ratchet and the cross-impl divergence rule actually play out in this repo — worked examples behind the terse statements in AGENTS.md.

_Moved verbatim from `AGENTS.md` during the 2026-09 memory split; content unchanged. Find an entry by its symptom._

---

## The divergence rule and the close-out ratchet, in practice

  > **The smell rides a ROUTED recommendation too, not just a fix — a lone seat matching a spec
  > MUST outranks a cohort emitting a convenience (earned 2026-09-04, B2; arch ruled against go).**
  > go correctly flagged B2 (`unsupported_mode`@501) as a genuine spec-vs-spec ruling and did not
  > converge it — but the *recommendation* attached to the route weighted the 2-1 cohort ("go's
  > §9.1 reading, matching rust"). arch ruled py's way: the corpus MUST (`EXTENSION-REGISTRY`
  > §6a.9.2 deliberately pins `unsupported_mode`) governs; a census of what peers emit cannot tell
  > you what the corpus mandates (arch AP-22). **Enforcement: before recommending a reading on a
  > routed spec-vs-spec, grep the corpus for the spelling the spec MANDATES (`[MUST]`, "pinned",
  > "MUST NOT fall back") — and if a lone seat holds that spelling against the majority, its
  > position is the default recommendation, not the cohort's.** No new discipline (the divergence
  > rule reaches the recommendation, not only the fix); recorded because the routing was right and
  > the recommendation was still wrong, which the "do not vote" framing did not obviously cover.
  > Sibling win the same cycle, worth the pair: arch's *prose* worklist ("go's 4 local-files
  > `storage_error` sites → `io_error`") contradicted arch's own just-landed line 836 (a tree bind
  > is `storage_error` anywhere); the 4 sites are `hctx.TreeSet` binds, so go verified against the
  > spec TEXT, kept `storage_error`, and routed the discrepancy rather than implementing the prose.
  > **When a routing packet's prose and the landed spec text diverge, implement the text and route
  > the prose** — the same "a newly-landed clause contradicting a prior ruling is a spec-issue to
  > route" discipline, now covering an arch *claim about our tree* that the spec text refutes.

**The close-out ratchet does not owe a NEW rule every time — reaching for one is itself the
anti-pattern** (earned 2026-08-16 by an audit of this session's own ratchets). The E-1 close-out
minted a "path helper must reference the owner's exported path function" invariant from
`encTierCCertPath` restating a literal. Traced (A1): the literal was byte-identical to
`identity.PublicCertPath`, it never diverged, no peer corrected it, and it only re-stated §8.4.2 /
D12 one layer down — **no bite, so below even the anti-pattern floor** ("bit us once"). It was sought
out to satisfy the ritual that a feature ends with a ratchet, and it diluted the load-bearing
protocol-invariants list; removed. The rule this earns: **a close-out whose feature only re-applied
existing disciplines closes out by recording that ("no new discipline earned"), not by minting a
novel one.** Enforcement: every ratchet addition names its bite — the incident, the peer correction,
or the `(file, commit)` where it manifested; an addition that can only cite "noticed while
implementing" is a candidate at most, and usually already covered. Audit ratchet additions against
the promotion ladder, not against the calendar.

