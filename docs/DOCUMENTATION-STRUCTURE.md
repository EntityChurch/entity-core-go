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
├── research/                        # Non-canonical: explorations, evaluations, design reviews
│   └── {topic}/                     # Subdirectories by domain when >10 docs
│
├── status/                          # Current state: tracking, health, planning
│
├── validation/                      # Conformance: does what we built match?
│   ├── reports/                     # Dated conformance snapshots and JSON artifacts
│   ├── spec-issues/                 # Spec ambiguities discovered during validation
│   └── peer-tracking/               # Per-implementation violation tracking
│
└── legacy/                          # Archived: previous versions, superseded work
```

### Tier rules

Each tier has a clear purpose. Files must not mix across tiers.

**`architecture/`** — canonical, living design documents. Specs define stable contracts the project commits to. Guides teach how to use those contracts. Proposals track the change lifecycle. Everything here is maintained and kept current. If a document drifts, it belongs in `research/` or `legacy/`, not here.

**`research/`** — non-canonical explorations, evaluations, and design reviews. Point-in-time analysis that informed decisions but is not itself a decision. Allowed to drift. Organized by topic when the volume warrants it.

**`status/`** — current project state. Implementation tracking, code health reports, proposal adoption status, planning documents. Point-in-time snapshots that answer "where are we now?"

**`validation/`** — conformance testing artifacts. Reports are dated snapshots. Spec issues feed back to the architecture repo as proposals. Peer tracking monitors each implementation's conformance over time.

**`legacy/`** — archived material from previous versions or superseded work. Not maintained. Kept for historical reference.

### What does NOT belong in `architecture/`

- Explorations and evaluations → `research/`
- Status trackers and health reports → `status/`
- Point-in-time reviews → `research/`
- Backlogs and bug reports → `status/` or issue tracker
- Validation artifacts → `validation/`

This is the rule that v1.0 failed to enforce. `architecture/` is the canonical tier — only living specs, guides, and active proposals belong there.

## Relationship to Canonical Architecture

The `entity-core-architecture` repo owns the canonical protocol specifications:

```
entity-core-architecture/docs/architecture/v7.0-core-revision/
├── core-protocol-domain/specs/      # V7 protocol, extensions, types, encoding
├── sdk-domain/specs/                # SDK operations, extension operations
├── proposals/{implemented,deferred} # Protocol-level change proposals
└── reviews/{core,network,sync,...}  # Protocol-level research
```

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
