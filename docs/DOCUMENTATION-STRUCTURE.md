# Documentation Structure Standard

**Version:** 1.1
**Scope:** All entity-systems implementation projects

This document defines the standard documentation structure for entity-systems projects. It enforces clear tier boundaries so that canonical specs, research, status tracking, and validation artifacts never mix.

## Directory Layout

```
{project}/docs/
├── DOCUMENTATION-STRUCTURE.md       # This document
│
├── architecture/                    # Canonical: stable design decisions
│   ├── specs/                       # Project-owned specifications (living)
│   ├── proposals/                   # Change proposals to project-level specs
│   │   ├── active/                  # Under review
│   │   └── implemented/             # Adopted (retained as audit trail)
│   └── guides/                      # How-to, patterns, principles (living)
│
├── agents/                          # Agent context
│   └── memory/                      # Canonical: durable engineering memory (INDEX.md + one file per topic)
│
├── status/                          # Current state: dated tracking, health, planning; TRACKER-* (living, internal)
│
├── outbox/                          # Internal: routing packets this repo has SENT (addressee block + tip)
│
├── validation/                      # Conformance: does what we built match?
│   ├── reports/                     # Dated conformance snapshots and JSON artifacts
│   └── spec-issues/                 # Spec ambiguities discovered during validation
│
└── reviews/                         # Dated audits and reviews (internal)
```

> The authoritative cross-repo doc, memory and routing standard is
> **`AGENTS-STANDARD.md`** (injected fleet-wide) plus the repo's own
> `CANONICAL-DOCS.toml`, which declares what each directory *is*. This document
> is the repo-local elaboration; where they differ, the standard wins.

### Tier rules

Each tier has a clear purpose. Files must not mix across tiers.

**`architecture/`** — canonical, living design documents. Specs define stable contracts the project commits to. Guides teach how to use those contracts. Proposals track the change lifecycle. Everything here is maintained and kept current.

**`agents/memory/`** — canonical, durable engineering memory: the hard-won lessons a competent newcomer would otherwise rediscover the hard way. One file per part of the system, entered through `INDEX.md`, findable by symptom. Superseded in place, never appended with dates. An entry that could become a test or a gate should become one — and then leaves memory.

**`status/`** — current project state, as **dated** snapshots (`HANDOFF-`, `CHECKPOINT-`, `STATUS-`) that answer "where are we now?" and age out. `TRACKER-*.md` (per-counterpart) is the exception: durable, edited in place, internal (never published).

**`outbox/`** — routing packets this repo has **sent**, each opening with a `To:`/`From:`/`Tip:` addressee block. Internal; never published. (Acknowledged packets move to `archive/outbox/`.)

**`validation/`** — conformance testing artifacts. `reports/` are dated snapshots; `spec-issues/` feed back to the architecture repo as proposals.

**`reviews/`** — dated audits and process reviews. Internal.

### What does NOT belong in `architecture/`

- Durable engineering lessons → `agents/memory/`
- Status trackers and health reports → `status/`
- Point-in-time reviews and audits → `reviews/`
- Sent routing packets → `outbox/`
- Validation artifacts → `validation/`

`architecture/` is a canonical tier — only living specs, guides, and active proposals belong there.

## Relationship to Canonical Architecture

The protocol specifications live upstream, in two sibling spec repos — this repo
**references** them and never duplicates them:

```
../entity-core-protocol/specs/            # ENTITY-CORE-PROTOCOL, ENTITY-CBOR-ENCODING, ENTITY-NATIVE-TYPE-SYSTEM
../entity-system-architecture/            # specs/extensions/EXTENSION-*, docs/proposals/PROPOSAL-*
```

(The pre-split `entity-core-architecture` repo is **stale** — do not read specs from it.)

Implementation projects **reference** these specs — they do not duplicate them. Each implementation project **owns** its own:
- Project-level specs (tool interfaces, extension architecture, platform decisions)
- Research artifacts (explorations, design reviews)
- Validation artifacts (conformance reports, spec issues)
- Status tracking (health checks, adoption progress)

Protocol-level proposals flow through the architecture repo. Project-level proposals live in the project's `architecture/proposals/`.

## Document Lifecycle

```
EXPLORATION → REVIEW → PROPOSAL → SPEC AMENDMENT → IMPLEMENTATION → VALIDATION
   research/   research/  architecture/  architecture/     (code)      validation/
                          proposals/     specs/
```

1. **Exploration** — research a design space → `research/`
2. **Review** — evaluate findings → `research/`
3. **Proposal** — formal change request → `architecture/proposals/active/`
4. **Adoption** — accepted → `architecture/proposals/implemented/`, spec version bumped
5. **Implementation** — code changes
6. **Validation** — conformance verified → `validation/reports/`
7. **Status** — track progress → `status/`

## Naming Conventions

### Prefixes

| Prefix | Meaning | Location |
|--------|---------|----------|
| `EXPLORATION-*` | Research, discovery, comparative analysis | `research/` |
| `REVIEW-*` | Evaluation of design or implementation | `research/` or `status/` |
| `PROPOSAL-*` | Formal change request | `architecture/proposals/` |
| `GUIDE-*` | How-to, patterns, workflows | `architecture/guides/` |
| `SPEC-ISSUE-*` | Ambiguity or gap in canonical specs | `validation/spec-issues/` |
| `NOTE-*` | Lightweight clarification | Wherever relevant |

### Dates in filenames

Use dates for **point-in-time artifacts** (reports, violation snapshots, health checks).
Do **not** use dates for **living documents** (specs, guides, proposals).

## Canonical vs. Driftable

| Document type | Canonical? | Tier | Maintenance |
|---------------|-----------|------|-------------|
| Specs (architecture repo) | Yes | external | Updated on every proposal adoption |
| Specs (project-level) | Yes | `architecture/specs/` | Updated when project design changes |
| Guides | Yes | `architecture/guides/` | Updated when patterns change |
| Proposals | Frozen | `architecture/proposals/` | Never modified after adoption/deferral |
| Research/Explorations | No | `research/` | Historical — allowed to drift |
| Status/Health reports | No | `status/` | Point-in-time snapshots |
| Validation reports | No | `validation/` | Point-in-time snapshots |

## Adapting Per Project

Not every project needs every directory. Start with what you have:

- **Protocol implementation** (entity-core-go): Heavy on `validation/`. Light on `architecture/specs/` (protocol specs live in the architecture repo). Project specs cover tools and extension architecture.
- **SDK/UI implementation** (egui-entity-core-rust): Heavy on `architecture/specs/` (owns SDK API, window arch). Light on `validation/` until conformance testing matures.
- **Canonical architecture** (entity-core-architecture): No `validation/` or `status/`. All content is design-time.

Empty directories should not be created — add them when content arrives.
