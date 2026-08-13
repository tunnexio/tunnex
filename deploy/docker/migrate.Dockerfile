# Tunnex migrate tool — applies embedded migrations. Build context is the repo root.

FROM golang:1.25.12-alpine AS build
WORKDIR /src
COPY apps/api/go.mod apps/api/go.sum* ./
ENV GOFLAGS=-mod=readonly
RUN go mod download
COPY apps/api/ ./
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags="-s -w" -o /out/tunnex-migrate ./cmd/migrate

FROM alpine:3.20
RUN apk add --no-cache ca-certificates
COPY --from=build /out/tunnex-migrate /usr/local/bin/tunnex-migrate
ENTRYPOINT ["/usr/local/bin/tunnex-migrate"]
