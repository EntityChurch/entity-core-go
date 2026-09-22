# Published Surface Citations

How to cite on files that ship publicly: a pointer SHA resolves nowhere for a public reader (published history is re-authored), a receipt SHA records what a claim was verified against. Read before a release cut.

_Moved verbatim from `AGENTS.md` during the 2026-09 memory split; content unchanged. Find an entry by its symptom._

---

## Citations on the published surface: name the finding, not the hash (pointer vs receipt)

**Earned 2026-08-23, browser-rust caught it downstream.** `core/peer/peer.go` and
`core/peer/handler_grant_ceiling_test.go` both cited `entity-core-rust`'s fix as
`c484fa6` — a commit that exists **on no branch, in no repo**. The rust seat had
committed, reset `dev` locally, and re-committed, twice; `c484fa6` survives only in
that machine's reflog. Nothing was lost (the trees are byte-identical to the surviving
commits and the remote only ever moved forward) but the hash a reader looks up resolves
nowhere. Both files are `.go`, so both **ship**.

The rule is [RUNBOOK-RELEASE-CURATION] + [ADR-0012] Amendment 1 and it is stronger than
the orphan case: `--series` **re-authors every commit** on the release branch, so an
internal SHA quoted in a file that publishes can never resolve for a public reader *even
when it is perfectly alive here*. A sibling's SHA is worse — the reader has no such repo.
**In anything that ships, cite the SYMBOL and the finding** (`their
default_handler_self_grant`, `core/capability/src/lib.rs`) — that is what
AGENTS-STANDARD's *"pin citations to `(symbol, path, commit)`"* reduces to when the
commit half cannot travel. A released version or a tag survives a re-author; a dev SHA
does not.

**Two kinds of SHA live on our published surface and they are NOT the same** — the
distinction is what to check before touching one:

- **A POINTER** — "fixed at `abc1234`", "landed at rust `3e9c9fc`" — invites the reader
  to go look. On the published surface it is broken by construction. Rewrite it to name
  the symbol/behavior; keep a hash only if it is a *tag* or a released version.
- **A RECEIPT** — `cmd/peer-manager/start.go`'s `siblingPinRust` / `siblingPinPython`,
  the corpus artifact hashes, `docs/STATUS.md`'s `@ <commit>` measurement pins. These
  do not ask to be resolved; they record *the state a claim was verified against*, and
  ADR-0012 **requires** them ("a number is only true of the commit it was taken at").
  Leave them. Stripping a receipt would delete the only thing that dates the claim.

**Enforcement, before you write one:** ask whether a reader of the published mirror is
expected to *resolve* it. If yes, it is a pointer and the hash is the wrong citation. If
it is a receipt, say so at the site (`[historical]`, `read live <date>`, `measured @`) so
the next sweep does not "fix" it. The measured scope on the published tree today is ~161
distinct hashes across ~115 files, overwhelmingly receipts; the two above were the only
pointers to a commit that resolves nowhere at all.

