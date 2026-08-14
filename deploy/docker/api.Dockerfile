# Tunnex control-plane API — multi-stage Go build.
# Build context is the repo root (see docker-compose.yml).

FROM golang:1.25.13-alpine AS build
WORKDIR /src

# Download deps first for layer caching. go.sum is created on first build.
COPY apps/api/go.mod apps/api/go.sum* ./
ENV GOFLAGS=-mod=readonly
RUN go mod download

COPY apps/api/ ./
# Edition selector (open-core). Empty (default) = OPEN build — the enterprise policy
# engine is //go:build enterprise-tagged and is NOT linked, so the default image can
# never contain it (the CI edition-isolation guard asserts this on the open build).
# Set TUNNEX_BUILD_TAGS=enterprise to build the ENTERPRISE image reproducibly from
# committed config (Zero Trust policy/enforcement/device-approval) — used for local +
# self-hosted enterprise testing. This replaces the old temporary `sed` hack; the same
# tag `make build-editions`/`test-editions` already compile-check now plumbs into the image.
ARG TUNNEX_BUILD_TAGS=""
RUN CGO_ENABLED=0 GOOS=linux go build -tags "$TUNNEX_BUILD_TAGS" -trimpath -ldflags="-s -w" -o /out/tunnex-api ./cmd/server
# The operator tools ship IN THIS IMAGE deliberately (S11 walk finding WF-S11-1): docs/upgrade.md and
# docs/backup-restore.md instruct an operator to run `preflight` and `backupctl` against a live deployment,
# and the only place they reliably have DATABASE_URL and TUNNEX_MASTER_KEY already in the environment is a
# control-plane container. Shipping the runbook's commands somewhere other than where the runbook runs is how
# a documented procedure becomes an undocumented one.
RUN CGO_ENABLED=0 GOOS=linux go build -tags "$TUNNEX_BUILD_TAGS" -trimpath -ldflags="-s -w" -o /out/preflight ./cmd/preflight \
    && CGO_ENABLED=0 GOOS=linux go build -tags "$TUNNEX_BUILD_TAGS" -trimpath -ldflags="-s -w" -o /out/backupctl ./cmd/backupctl \
    && CGO_ENABLED=0 GOOS=linux go build -tags "$TUNNEX_BUILD_TAGS" -trimpath -ldflags="-s -w" -o /out/releaseverify ./cmd/releaseverify

FROM alpine:3.20
RUN apk add --no-cache ca-certificates wget && adduser -D -u 10001 tunnex
# Pre-own the secrets mountpoint as uid 10001 so the named volume inherits uid-10001 on first
# init and the non-root process can write 0600 files.
RUN mkdir -p /var/lib/tunnex/secrets \
    && chown -R 10001:10001 /var/lib/tunnex \
    && chmod 700 /var/lib/tunnex/secrets
USER tunnex
COPY --from=build /out/tunnex-api /usr/local/bin/tunnex-api
COPY --from=build /out/preflight /usr/local/bin/preflight
COPY --from=build /out/backupctl /usr/local/bin/backupctl
COPY --from=build /out/releaseverify /usr/local/bin/releaseverify
EXPOSE 8080
HEALTHCHECK --interval=10s --timeout=3s --start-period=5s --retries=5 \
  CMD wget -qO- http://127.0.0.1:8080/healthz || exit 1
ENTRYPOINT ["/usr/local/bin/tunnex-api"]
