# Engineering memory — entity-core-go

Durable, hard-won lessons that would otherwise be rediscovered the hard way. This is not a
status log and not a changelog: **no dates as structure, no session narration, superseded rather
than appended** (git holds the history). Each file is one part of the system; find an entry **by
the symptom you arrived with**.

These files were split out of `AGENTS.md` in the 2026-09 doc-standard cleanup — the content moved
verbatim, so an entry's provenance (dates, `earned/ratified/candidate`, cross-impl attribution) is
preserved as written. Read one **by trigger**, never all at once; `AGENTS.md` carries the terse
rule and points here for the worked example.

> **The rule that bounds this directory:** an entry that could become a test, a lint rule, a build
> assertion or a gate **SHOULD become one — and then it is deleted from here.** Memory is where a
> finding waits *while it is still only prose.*

| file | you are here because… |
|---|---|
| **`CONFORMANCE-GATE-AND-ORACLE-AUTHORING.md`** | a `validate-complete.sh` run surprised you (a green exit that wasn't, a port collision, a posture FAIL), or you are about to write a new wire/oracle check and need it to discriminate. |
| **`PROTOCOL-WIRE-INVARIANTS.md`** | you are touching the receive boundary, ECF/CBOR, hashing, paths, or the dispatch context — where a mistake is a silent hash mismatch or a blind gate, not a failing test. |
| **`CAPABILITY-AUTHORIZATION.md`** | a `403` is wrong, a grant is silently widened or narrowed, or you are changing a scope matcher, exclude semantics, or the PD-2 outbound-authorization gate. |
| **`COMPUTE-ERROR-SEMANTICS.md`** | you are touching the compute evaluator or any of its error paths (`compute/error` has two in-language forms). |
| **`SPEC-READING-AND-CROSS-IMPL-ROUTING.md`** | you are about to claim something about a sibling implementation or the spec, route a finding, or converge an error code — the class of bug that is a plausible sentence nobody opened the tree to check. |
| **`PUBLISHED-SURFACE-CITATIONS.md`** | you are citing a commit in a file that ships publicly, or preparing a release cut (pointer vs receipt). |
| **`THE-RATCHET-AND-DIVERGENCE-RULE.md`** | you want the worked examples behind the methodology's ratchet and the cross-impl divergence rule as they play out here. |
