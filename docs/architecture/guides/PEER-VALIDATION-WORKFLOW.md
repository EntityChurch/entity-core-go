# Peer Validation Workflow

How the Entity Core project reaches convergence across Go, Python, and Rust implementations.

## Two Workflows

There are two distinct workflows depending on the phase of work:

1. **Spec Adoption** — each team independently implements a spec. Differences reveal spec ambiguities, design improvements, and bugs. The goal is the right design, not just matching code.

2. **Convergence** — the spec has stabilized for a feature. Go runs validation against the other peers, finds gaps, fixes them. The goal is all peers passing the same tests.

Most work alternates between these. A convergence run might reveal that the spec needs an amendment, which kicks off a mini adoption cycle.

---

## Spec Adoption Workflow

When a new spec or spec revision is published, each team implements independently from the spec text. This is intentional — independent implementations expose problems that a single implementation never would.

### What divergence tells you

When implementations differ, classify the divergence:

| Category | Signal | Action | Example |
|----------|--------|--------|---------|
| **Spec ambiguity** | Two teams read the spec differently, both interpretations are reasonable | Spec amendment to clarify | "Does extract prefix come from params or resource.targets?" — spec showed both, didn't say which takes precedence |
| **Spec wrong** | An implementation finds a better design that the spec didn't consider | Spec amendment to improve | Snapshot carrying prefix made hashes location-dependent — proposal I3 removed it |
| **Implementation bug** | One team missed a MUST requirement | Fix the implementation | Python extract not including trie nodes (TREE §6.2 says MUST) |
| **Implementation gap** | Feature not implemented yet | Implement it | Python merge missing source_envelope parameter |
| **Spec writer blind spot** | The team that wrote the spec didn't implement their own requirement | Fix implementation, possibly revisit spec | Handler scope `system/inbox/*` created by Go validator didn't match `system/inbox` — scope semantics were clear, usage was wrong |

### The feedback loop

```
  Spec published
       │
       ▼
  Teams implement independently
       │
       ▼
  Run convergence → find differences
       │
       ├─► Spec ambiguity     → Draft proposal, update spec, re-implement
       ├─► Better design found → Draft proposal, update spec, re-implement
       ├─► Implementation bug  → Fix the peer, add validation check
       └─► Spec correct, impl wrong → Fix the peer
```

### Proposals

When a divergence reveals a spec issue, document it as a proposal in:
```
../entity-core-architecture/docs/architecture/v7.0-core-revision/proposals/
```

A proposal includes: what the spec currently says, what the problem is, what the amendment should be. Example: `PROPOSAL-CROSS-PEER-INTEROP-CLARIFICATIONS.md` addressed inbox result format, snapshot prefix removal, subscription resource targets, and merge source_envelope — all found during Go/Rust convergence.

After a proposal is adopted, the spec is updated and all three implementations align to the new text.

### What NOT to assume

- **Don't assume Go is always right.** Go hosts the validation suite and is the most-complete implementation, which makes it a convenient reference — but the reference is the **spec**, not Go. When a validator check fails, read the spec section referenced by the check BEFORE looking at Go's implementation. Several findings (trie-root wrapper, tracked-root path, continuation resource-field handling, notification→advance) were disambiguated by reading the spec and filing ambiguity/violation docs — in some cases Go's behavior was also wrong and had to change.
- **Rotate the reference periodically.** `validate-peers.sh` defaults to Go-as-reference, which means Go bugs are invisible in origination checks (anything the Go reference accepts passes). Run Rust-as-reference and Python-as-reference on a cadence (weekly, pre-release) via `REFERENCE_ADDR=...` — any check that passes in one orientation but fails in another points at a bug in the reference that passed it.
- **Run full combinatorial pairings before releases.** `validate-peers.sh` with `-reference-peer` covers one reference at a time. Cross-pair bugs (e.g., Rust↔Python divergence that Go happens to bridge) only surface with all 6 orderings exercised via `test-cross-peer.sh`. See the `test-convergence` skill for the procedure.
- Don't assume the spec is final. The spec converges to correctness through implementation feedback.
- Don't just make one peer match another. Understand WHY they differ. The difference might be telling you something about the spec.

---

## Convergence Workflow

Once the spec is stable for a feature area, the goal is getting all peers to pass the same validation. Go drives this because it hosts the validation suite and peer-manager.

### The Cycle

```
   ┌─────────────────────────────────────────────┐
   │  1. Develop feature + validation in Go      │
   │     (spec → implementation → test checks)   │
   └──────────────────┬──────────────────────────┘
                      ▼
   ┌─────────────────────────────────────────────┐
   │  2. Run validate-peers.sh                   │
   │     (responder + A-role origination vs.     │
   │      Go reference — canonical pre-merge)    │
   └──────────────────┬──────────────────────────┘
                      ▼
   ┌─────────────────────────────────────────────┐
   │  3. Run multi-peer convergence              │
   │     (P1-P4 determinism, M1-M3 merge, 3-way) │
   └──────────────────┬──────────────────────────┘
                      ▼
   ┌─────────────────────────────────────────────┐
   │  4. Failures → read logs → trace root cause │
   │     (spec ref, Go impl, target peer code)   │
   └──────────────────┬──────────────────────────┘
                      ▼
   ┌─────────────────────────────────────────────┐
   │  5. Fix the target peer's code              │
   │     (Python: ../entity-core-py/)            │
   │     (Rust:   ../entity-core-rust/)          │
   └──────────────────┬──────────────────────────┘
                      ▼
   ┌─────────────────────────────────────────────┐
   │  6. Restart peer → re-validate → iterate    │
   │     (peer-manager rebuilds automatically)   │
   └──────────────────┬──────────────────────────┘
                      ▼
              Clean pass → done
```

## Step by Step

### 1. Develop the feature and validation in Go

Go is the reference implementation. New features follow this path:

- Read the spec (in `../entity-core-architecture/docs/architecture/v7.0-core-revision/specs/`)
- Implement in Go (`core/`, `ext/`)
- Add validation checks to the suite (`cmd/internal/validate/`)
- Verify Go passes its own tests

The validation suite is the spec-as-code. Each check references a spec section. When you add a new feature, add the check that would catch a peer missing it.

**Key insight from this session:** Single-peer checks should include roundtrip tests, not just individual operations. For example, the extract→merge roundtrip caught three bugs (missing trie nodes, missing source_envelope, wrong prefix source) that individual extract and merge tests missed.

### 2. Responder + origination validation (canonical)

Run `scripts/validate-peers.sh` — auto-starts a Go reference peer, tests the target as both responder (answers incoming requests) and A-role originator (dispatches outbound EXECUTEs against the reference). This is the standard pre-merge check.

```bash
# Default — validate rust + python with full responder + origination coverage.
./scripts/validate-peers.sh

# Target one peer.
./scripts/validate-peers.sh python

# Save JSON reports.
SAVE=1 ./scripts/validate-peers.sh

# Focus on one category.
CATEGORY=tree_operations ./scripts/validate-peers.sh rust
CATEGORY=origination ./scripts/validate-peers.sh python

# Use an externally-managed reference (rotation — see skill doc for reference rotation guidance).
REFERENCE_ADDR=127.0.0.1:9000 ./scripts/validate-peers.sh python
```

Single-peer-only validation (`NO_REFERENCE=1` or direct `validate-peer -addr` without `-reference-peer`) catches responder-side issues: type mismatches, missing handlers, encoding issues, wrong params format. It does **NOT** catch origination-side issues — outbound params not entity-wrapped, continuation using wrong field, notification handler not advancing continuations. The origination category covers those via a reference peer.

See `.claude/skills/validate-peers/SKILL.md` for category list, output format, and reference rotation procedure.

### 3. Multi-peer convergence

Start a Go peer alongside the target and run cross-peer tests:

```bash
# Start a managed Go peer
go run ./cmd/peer-manager start --name test-go --type go --debug

# Option A: start a managed Python peer too
go run ./cmd/peer-manager start --name test-py --type python --debug

# Option B: use an already-running peer
# (peer at 127.0.0.1:9001 started externally)

# Get addresses
ADDRS=$(go run ./cmd/peer-manager addrs "test-go,test-py")
# or: ADDRS="127.0.0.1:9001,$(go run ./cmd/peer-manager addr test-go)"

# Run convergence
go run ./cmd/validate-peer -peers "$ADDRS" -identity framework-admin -timeout 120s
```

Or use the script for fully managed runs:
```bash
TYPES=go,python ./scripts/test-cross-peer.sh
```

### 4. Trace failures

When a convergence test fails, the process is:

**a) Identify which peer failed.** The test labels peers A and B. Check which peer returned the error:
```
FAIL xsub_subscribe    SUBSCRIPTION §3
  subscribe failed: subscribe status 403
```
→ 403 came from Peer B (the one we subscribed on).

**b) Check the failing peer's logs.**
```bash
tail -50 $(go run ./cmd/peer-manager logs test-py)
# or grep for the specific error:
grep "403\|subscribe\|error" ~/.entity/logs/test-py.log
```

**c) Find the specific error.** Common patterns:
- `status=403 error=none` after a handler runs → handler returned 403, not dispatch layer
- `status=403 code=forbidden` → dispatch layer denied (grant/scope issue)
- `status=400 code=invalid_params` → params structure wrong (missing type field, missing resource targets)
- `TypeError: unexpected keyword argument` → Python function signature mismatch

**d) Read the spec section.** The failing check always has a spec ref (e.g., `SUBSCRIPTION §3`). Read the spec to understand what's required.

**e) Compare with Go.** Go passes the same test, so its implementation is correct. Read the corresponding Go handler/dispatch code to understand the expected behavior.

**f) Read the target peer's code.** Understand what it does differently.

### 5. Fix the target peer's code

Make the fix directly in the target peer's codebase:

```
Python handlers:  ../entity-core-py/packages/entity-handlers/src/entity_handlers/
Python core:      ../entity-core-py/packages/entity-core/src/entity_core/
Rust tree:        ../entity-core-rust/core/tree/src/
Rust inbox:       ../entity-core-rust/extensions/inbox/src/
Rust peer:        ../entity-core-rust/core/peer/src/
```

Common fix categories:
- **Missing feature**: implement what Go has (e.g., merge source_envelope support)
- **Wrong field source**: read from resource_targets instead of params (V7 pattern)
- **Missing normalization**: use spec §5.4 pattern matching instead of exact string comparison
- **Entity wrapping**: params and results must be entities per V4 §3.4 ({type, data, content_hash})
- **Missing envelope contents**: extract must include trie nodes per TREE §6.2

### 6. Restart and re-validate

**Python peers (via uv run) pick up changes immediately on restart:**
```bash
go run ./cmd/peer-manager stop test-py
go run ./cmd/peer-manager start --name test-py --type python --debug
```

**Go peers need to be rebuilt:**
```bash
go run ./cmd/peer-manager stop test-go
go run ./cmd/peer-manager start --name test-go --type go --debug
```

**For fast iteration, use KEEP=1 and re-run just the validator:**
```bash
# First run (starts peers)
KEEP=1 TYPES=go,python ./scripts/test-cross-peer.sh

# Fix code, then re-test without restarting:
ADDRS=$(go run ./cmd/peer-manager addrs "cross-go,cross-python")
go run ./cmd/validate-peer -peers "$ADDRS" -identity framework-admin -timeout 60s

# If you need to restart one peer to pick up changes:
go run ./cmd/peer-manager stop cross-python
go run ./cmd/peer-manager start --name cross-python --type python --debug
```

## Case Study: Go + Python Convergence

Starting from Python passing 92.5% of single-peer tests, convergence testing found 8 issues. Classifying each:

| Issue | Category | Root cause | Action taken |
|-------|----------|-----------|-------------|
| Subscribe 403 with entity:// URIs | **Impl bug** (Python) | Token validation did ad-hoc string compare instead of spec §5.4 matching | Fixed Python to use `matches_scope()` |
| Async delivery 403 | **Impl bug** (Go) | Go validator created token with `system/inbox/*` (resource wildcard) for handler scope | Fixed to `system/inbox` (handler name) |
| Remote execute 400 | **Impl bug** (Python) | Params not entity-wrapped per V4 §3.4 | Fixed Python `deliver_async` |
| Remote execute missing resource | **Impl gap** (Python) | `_remote_execute` didn't forward resource_targets on wire | Added parameter forwarding |
| Notification delivery TypeError | **Impl gap** (Python) | Extension execute callback missing resource_targets param | Added parameter to callback |
| Extract wrong prefix | **Spec ambiguity** | Spec showed prefix in both params and resource.targets, didn't state precedence | Aligned all impls: resource.targets first, params fallback. Tracked in proposal I3 |
| Extract missing trie nodes | **Impl bug** (Python) | TREE §6.2 MUST requirement missed | Fixed Python extract to include trie nodes |
| Merge source_envelope missing | **Impl gap** (Python) | Feature defined in spec but not implemented | Implemented in Python merge handler |

**Result: 77/82 pass, 0 failures** on Go+Python convergence.

**Feedback to spec:** The extract prefix ambiguity was already captured in `PROPOSAL-CROSS-PEER-INTEROP-CLARIFICATIONS.md` (I3). No new spec issues discovered — the existing proposal covered all the ambiguities we found. The remaining issues were implementation bugs/gaps against a clear spec.

**Validation improvements:** Three issues were retroactively catchable by single-peer tests. Added: extract→merge roundtrip (catches trie nodes + source_envelope + resource_targets) and entity:// URI delivery token test. Future implementations will hit these in single-peer validation before reaching convergence.

## Adding Validation for New Features

When implementing a new spec feature:

1. **Add single-peer checks first.** Include roundtrip tests that exercise the full operation pipeline, not just individual operations in isolation.

2. **Test with entity:// URIs.** If the feature involves URIs in tokens or grants, test with both bare paths and full `entity://peerID/path` forms.

3. **Test with resource_targets.** If the feature reads a path, test that it works from `resource.targets[0]` (V7 pattern), not just from params.

4. **Test envelope completeness.** If the feature produces envelopes, verify all referenced entities are included (trie nodes, intermediate nodes, not just leaf entities).

5. **Run convergence after single-peer passes.** The convergence test catches wire-level issues (serialization, URI normalization, resource forwarding) that local tests miss.
