# Tunnex migrate tool — applies embedded migrations. Build context is the repo root.

FROM golang:1.26.11-alpine@sha256:ecb67f987aa1a57794c91d19ade7ae0209f2f0f5496aaef9e6ae85ddf92d02ab AS build
WORKDIR /src/apps/api
COPY apps/api/go.mod apps/api/go.sum* ./
COPY packages/apptransport/ /src/packages/apptransport/
ENV GOFLAGS=-mod=readonly
RUN go mod download
COPY apps/api/ ./
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags="-s -w" -o /out/tunnex-migrate ./cmd/migrate

FROM alpine:3.24.2@sha256:294b683cb724975bec92580e1e685676bd4b50bda910ddb8c51d4cabeaec77e6
RUN apk add --no-cache ca-certificates
COPY --from=build /out/tunnex-migrate /usr/local/bin/tunnex-migrate
ENTRYPOINT ["/usr/local/bin/tunnex-migrate"]
