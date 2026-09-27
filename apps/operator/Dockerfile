# syntax=docker/dockerfile:1
# Tunnex GitOps operator (S10.2). Build context = apps/operator ONLY (THE HARD RULE: this module imports no
# Tunnex DB package, so it needs nothing from apps/api). VERSION is the git sha, stamped into main.version and
# logged at startup for the walk's build-provenance census.
FROM golang:1.26.8-alpine@sha256:8ac98ca534ac3f51e1f420a1dd2c15e74c75cfa0f23f3ad27eb5d7236c349a0c AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
ARG VERSION=dev
ENV GOFLAGS=-mod=readonly CGO_ENABLED=0
RUN go build -trimpath -ldflags "-s -w -X main.version=${VERSION}" -o /out/operator ./cmd/operator

FROM gcr.io/distroless/static:nonroot@sha256:e2e927ec666bae08560abb3c55d0659eceabb657f56b6782ab500a9fc7f555e3
COPY --from=build /out/operator /operator
USER 65532:65532
ENTRYPOINT ["/operator"]
