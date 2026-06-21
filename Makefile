# Entity Core Go — make + podman build convention.
#
# Host needs ONLY `make` + `podman` (no host Go). `make build` compiles every
# cmd/ binary in-container via the self-contained multistage Dockerfile.
# `make test`/`vet`/`race` run the Go toolchain over the go.work modules inside
# the stock golang image. The repo is self-contained (the go.work + intra-repo
# replace directives tie core/ext/cmd together), so only the repo itself is
# bind-mounted — no parent/sibling layout is assumed, which keeps the
# clone-fresh test (a clone in /tmp under any directory name) working. A
# persistent host module cache speeds repeat runs.
IMAGE     := entity-core-go
TOOLCHAIN := golang:1.25-bookworm
GOMOD     := $(HOME)/.cache/go-mod-entity-core-go
MODULES   := core ext cmd

# ============================================================================
# Podman resource caps — per-container ceilings so a build/run can't take the
# host down. Tune the COMMITTED defaults for THIS project; override per-machine
# WITHOUT editing this file via env vars or an untracked caps.local.mk.
#   Precedence (highest first):  env var  >  caps.local.mk  >  defaults below
#   CAP_SWAP == CAP_MEM  =>  zero swap: OOM-killed cleanly at the cap instead of
#   thrashing the host into a freeze.
# See RESOURCE-CAPS.md for the standard, per-machine overrides, and the
# host-wide dev-heavy.slice (build-time fork-bomb protection).
# ============================================================================
-include caps.local.mk          # untracked per-machine overrides (gitignored)

CAP_MEM           ?= 4g         # hard memory ceiling per container (heaviest target `make race` peaks ~2.5 GiB)
CAP_SWAP          ?= $(CAP_MEM) # keep == CAP_MEM (no swap); raise only deliberately
CAP_PIDS          ?= 2048       # max procs/threads (RUN only) — stops fork bombs
CAP_CPUS          ?= 8          # CPU cores at runtime (RUN only; fractional ok)
CAP_CGROUP_PARENT ?=            # optional host slice to nest under, e.g. dev-heavy.slice

_cap_cgp := $(if $(strip $(CAP_CGROUP_PARENT)),--cgroup-parent=$(CAP_CGROUP_PARENT),)

# podman BUILD accepts --memory/--memory-swap/--cgroup-parent (NOT --cpus/--pids-limit)
PODMAN_BUILD_CAPS := --memory=$(CAP_MEM) --memory-swap=$(CAP_SWAP) $(_cap_cgp)
# podman RUN accepts the full set
PODMAN_RUN_CAPS   := --memory=$(CAP_MEM) --memory-swap=$(CAP_SWAP) \
                     --pids-limit=$(CAP_PIDS) --cpus=$(CAP_CPUS) $(_cap_cgp)

.PHONY: help build image test vet lint fmt check race tidy clean \
        validate validate-rust validate-python validate-save

.DEFAULT_GOAL := help

# ADR-0019 Tier-1 verbs: help build test lint fmt check clean — implemented on
# top of this repo's existing vet/race/tidy/validate* recipes. Every recipe
# already runs inside the pinned golang image, so there is no separate -native
# split here (the host needs only make + podman).
help:
	@echo "entity-core-go — make + podman (host needs only make + podman)"
	@echo
	@echo "  build    compile every cmd/ binary in-container (alias: image)"
	@echo "  test     go test ./... across all workspace modules"
	@echo "  lint     go vet ./... — read-only static checks (alias: vet)"
	@echo "  fmt      gofmt -w across all modules (writes)"
	@echo "  check    lint + test (the green gate)"
	@echo "  race     go test -race ./..."
	@echo "  tidy     go mod tidy across modules"
	@echo "  clean    remove the build image"
	@echo "  validate[-rust|-python|-save]   live peer-orchestration harnesses"

# Compile all binaries in-container (CGO-free static builds → alpine runtime).
# `image` is kept as an alias so `build` is the conventional Tier-1 entry point.
build:
	podman build $(PODMAN_BUILD_CAPS) -t $(IMAGE) .

image: build

# Run an arbitrary go command across every workspace module inside the toolchain
# image. The go.work at the repo root ties core/ext/cmd together.
define GO
	mkdir -p $(GOMOD)
	podman run --rm $(PODMAN_RUN_CAPS) \
		-v $(CURDIR):/src:Z \
		-v $(GOMOD):/go/pkg/mod:Z \
		-w /src \
		$(TOOLCHAIN) \
		sh -c 'set -e; for m in $(MODULES); do echo "== $$m =="; (cd $$m && $(1)); done'
endef

test:
	$(call GO,go test ./...)

vet:
	$(call GO,go vet ./...)

# Tier-1 lint = read-only static checks; alias of the existing vet target.
lint: vet

# Tier-1 fmt = autoformat (writes) across every workspace module.
fmt:
	$(call GO,gofmt -w .)

# Tier-1 check = the green gate (lint + test), what CI runs.
check: lint test

race:
	$(call GO,go test -race ./...)

tidy:
	$(call GO,go mod tidy)

# Tier-1 clean = remove the build image (the only build artifact; the compiled
# binaries live inside it, never on the host tree).
clean:
	-podman rmi $(IMAGE)

# Peer-orchestration validation harnesses — these drive live peers and are not
# bare-box build steps; left as host scripts.
validate:
	./scripts/validate-peers.sh

validate-rust:
	./scripts/validate-peers.sh rust

validate-python:
	./scripts/validate-peers.sh python

validate-save:
	SAVE=1 ./scripts/validate-peers.sh
