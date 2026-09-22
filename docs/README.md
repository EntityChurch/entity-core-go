# `docs/` — documentation map

Navigation for this repo's documentation. The tier standard these directories
follow is [`DOCUMENTATION-STRUCTURE.md`](DOCUMENTATION-STRUCTURE.md).

## Start here (living docs — kept current)

| Doc | What it covers |
|-----|----------------|
| [`/AGENTS.md`](../AGENTS.md) | Architecture orientation: the strict core package DAG, module layout, import paths, Go design decisions, interop pitfalls, the validate-peer reference. The single best entry point. |
| [`/README.md`](../README.md) | Build & test (`make` + `podman`), module paths, repo layout. |
| [`/cmd/README.md`](../cmd/README.md) | Inventory of every CLI (peer, validator, peer-manager, probes, fixtures). |
| [`architecture/`](architecture/) | Canonical project-level specs and guides (see below). |
| [`agents/memory/`](agents/memory/INDEX.md) | Durable engineering memory — the hard-won lessons that used to swell `AGENTS.md`, split out and findable by symptom. Published. |
| [`STATUS.md`](STATUS.md) | The rolling status log — where the project is, the current conformance numbers, backlog and blockers. Re-measured, not carried forward. |

> The canonical *protocol* spec is not here — it lives in the sibling spec
> repos `../entity-core-protocol/` (the core floor) and
> `../entity-system-architecture/` (the extensions and the proposals). This
> repo references them, never duplicates them. (The old `entity-core-architecture`
> repo is pre-split and stale — do not read specs from it.)

## The tiers

The canonical surface published here is `architecture/specs/`,
`architecture/guides/`, `agents/memory/`, and the rolling `STATUS.md`. The repo
maintains additional working tiers locally (`status/`, `outbox/`, `validation/`,
`reviews/`) that are point-in-time or internal and are not part of the published
canonical surface. Each directory declares what it *is* in `CANONICAL-DOCS.toml`.

| Directory | Tier | Maintained? | Holds |
|-----------|------|-------------|-------|
| `architecture/specs/` | canonical | yes | Project-level specs (extension architecture, query storage, execution-context propagation). |
| `architecture/guides/` | canonical | yes | How-to / patterns: peer-validation workflow, using-diagnostics, validate-peer grants, entity-sync, convergent-mirror recipe. |
| `agents/memory/` | canonical | yes | Durable engineering memory, entered through `INDEX.md`. Found by symptom, superseded not appended. Published. |
| `STATUS.md` | canonical | yes | The single rolling status log. One file, re-measured rather than appended to. |
| `status/` | working | — | Dated, immutable snapshots (`HANDOFF-`, `CHECKPOINT-`, `STATUS-`, `TRACKER-`). Internal; publishes nothing. |
| `outbox/` | working | — | Routing packets this repo has *sent* (each an addressee block + a tip). Internal; publishes nothing. |

## Canonical vs. archive

The intent is a clean **canonical** surface (what is carried to a public
release) with everything historical preserved locally as **archive**:

- **Canonical / living:** the root `AGENTS.md` / `README.md`, `cmd/README.md`,
  `STATUS.md`, `agents/memory/` (durable engineering memory), and `architecture/`
  (specs, guides). `architecture/` is kept to canonical content only — no dated
  point-in-time files.
- **Archive / internal (local only):** `status/`, `outbox/`, `validation/`, and
  `reviews/` hold dated, internal, or historical artifacts — preserved in the
  working repo, but not part of the published canonical surface.

The two kinds of status document separate by **path**, not by filename: the
rolling log is `STATUS.md` at this level, and everything under `status/` is a
dated snapshot. That is the whole rule, and it is visible in the tree rather
than something a contributor has to remember.
