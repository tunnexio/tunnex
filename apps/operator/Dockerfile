# syntax=docker/dockerfile:1
# Tunnex GitOps operator (S10.2). Build context = apps/operator ONLY (THE HARD RULE: this module imports no
# Tunnex DB package, so it needs nothing from apps/api). VERSION is the git sha, stamped into main.version and
# logged at startup for the walk's build-provenance census.
FROM golang:1.25.12-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
ARG VERSION=dev
ENV GOFLAGS=-mod=readonly CGO_ENABLED=0
RUN go build -trimpath -ldflags "-s -w -X main.version=${VERSION}" -o /out/operator ./cmd/operator

FROM gcr.io/distroless/static:nonroot
COPY --from=build /out/operator /operator
USER 65532:65532
ENTRYPOINT ["/operator"]
