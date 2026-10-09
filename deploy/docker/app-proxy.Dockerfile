# Build separately; AA-7 supplies explicit TLS, credentials and deployment wiring.
FROM golang:1.26.9-alpine@sha256:cdfd4fe2da6b225d8b40c6b7a105736e548e83ff56d5d8f9394446eeb5eb84e0 AS build
WORKDIR /src/apps/app-proxy
COPY packages/apptransport/ /src/packages/apptransport/
COPY apps/app-proxy/ ./
ENV GOFLAGS=-mod=readonly
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags="-s -w" -o /out/tunnex-app-proxy ./cmd/app-proxy

FROM alpine:3.24.2@sha256:294b683cb724975bec92580e1e685676bd4b50bda910ddb8c51d4cabeaec77e6
RUN apk add --no-cache ca-certificates && adduser -D -u 10001 tunnex && mkdir -p /var/lib/tunnex/app-restore && chown 10001:10001 /var/lib/tunnex/app-restore && chmod 0700 /var/lib/tunnex/app-restore
USER tunnex
COPY --from=build /out/tunnex-app-proxy /usr/local/bin/tunnex-app-proxy
ENTRYPOINT ["/usr/local/bin/tunnex-app-proxy"]
