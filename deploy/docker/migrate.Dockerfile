# Tunnex migrate tool — applies embedded migrations. Build context is the repo root.

FROM golang:1.26.8-alpine@sha256:8ac98ca534ac3f51e1f420a1dd2c15e74c75cfa0f23f3ad27eb5d7236c349a0c AS build
WORKDIR /src
COPY apps/api/go.mod apps/api/go.sum* ./
ENV GOFLAGS=-mod=readonly
RUN go mod download
COPY apps/api/ ./
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags="-s -w" -o /out/tunnex-migrate ./cmd/migrate

FROM alpine:3.20@sha256:d9e853e87e55526f6b2917df91a2115c36dd7c696a35be12163d44e6e2a4b6bc
RUN apk add --no-cache ca-certificates
COPY --from=build /out/tunnex-migrate /usr/local/bin/tunnex-migrate
ENTRYPOINT ["/usr/local/bin/tunnex-migrate"]
