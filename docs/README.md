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

> The canonical *protocol* spec is not here — it lives in the
> `entity-core-architecture` sibling repo. This repo references it, never
> duplicates it.

## The tiers

The canonical surface published here is `architecture/specs/` and
`architecture/guides/`. The repo maintains additional working tiers locally
(`status/`, `validation/`, `reviews/`, `legacy/`) that are point-in-time or
historical and are not part of the published canonical surface.

| Directory | Tier | Maintained? | Holds |
|-----------|------|-------------|-------|
| `architecture/specs/` | canonical | yes | Project-level specs (extension architecture, query storage, execution-context propagation). |
| `architecture/guides/` | canonical | yes | How-to / patterns: peer-validation workflow, using-diagnostics, validate-peer grants, entity-sync, convergent-mirror recipe. |

## Canonical vs. archive

The intent is a clean **canonical** surface (what is carried to a public
release) with everything historical preserved locally as **archive**:

- **Canonical / living:** the root `AGENTS.md` / `README.md`, `cmd/README.md`,
  and `architecture/` (specs, guides). `architecture/` is kept to canonical
  content only — no dated point-in-time files.
- **Archive (local only):** `status/`, `validation/`, `reviews/`, and
  `legacy/` hold point-in-time and historical artifacts — preserved in the
  working repo, but not part of the published canonical surface.
