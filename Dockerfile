# syntax=docker/dockerfile:1.7

# ---- builder ----------------------------------------------------------------
FROM golang:1.25-alpine AS builder

RUN apk add --no-cache git ca-certificates

WORKDIR /src

# Module manifests first so dependency download caches when only sources change.
COPY go.work ./
COPY core/go.mod core/go.sum ./core/
COPY ext/go.mod  ext/go.sum  ./ext/
COPY cmd/go.mod  cmd/go.sum  ./cmd/

RUN --mount=type=cache,target=/go/pkg/mod \
    go mod download -x

# Sources.
COPY core/ ./core/
COPY ext/  ./ext/
COPY cmd/  ./cmd/

# Build every main package under cmd/ into /out.
# CGO disabled so the binaries run on a scratch/alpine runtime without glibc.
RUN --mount=type=cache,target=/go/pkg/mod \
    --mount=type=cache,target=/root/.cache/go-build \
    cd cmd && \
    CGO_ENABLED=0 GOOS=linux \
    go build -trimpath -ldflags="-s -w" -o /out/ ./...

# ---- runtime ----------------------------------------------------------------
FROM alpine:3.20

RUN apk add --no-cache ca-certificates tzdata && \
    addgroup -S entity && adduser -S -G entity -h /home/entity entity && \
    mkdir -p /home/entity/.entity && chown -R entity:entity /home/entity

COPY --from=builder /out/ /usr/local/bin/

USER entity
WORKDIR /home/entity
ENV HOME=/home/entity

# entity-peer default; override with any other CLI shipped in /usr/local/bin
# (validate-peer, peer-manager, entity-sync, probe-peer, compare-types, ...).
EXPOSE 9000
CMD ["entity-peer", "-addr", "0.0.0.0:9000"]
