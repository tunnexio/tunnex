# Optional Beam process; never enabled by the default server stack.
FROM golang:1.26.8-alpine@sha256:8ac98ca534ac3f51e1f420a1dd2c15e74c75cfa0f23f3ad27eb5d7236c349a0c AS build
WORKDIR /src/apps/app-proxy
COPY packages/apptransport/ /src/packages/apptransport/
COPY apps/app-proxy/ ./
ENV GOFLAGS=-mod=readonly
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags="-s -w" -o /out/tunnex-beam-proxy ./cmd/beam-proxy

FROM alpine:3.24.2@sha256:294b683cb724975bec92580e1e685676bd4b50bda910ddb8c51d4cabeaec77e6
RUN apk add --no-cache ca-certificates && adduser -D -u 10001 tunnex \
    && mkdir -p /var/lib/tunnex/app-restore \
    && chown 10001:10001 /var/lib/tunnex/app-restore \
    && chmod 0700 /var/lib/tunnex/app-restore
USER tunnex
COPY --from=build /out/tunnex-beam-proxy /usr/local/bin/tunnex-beam-proxy
ENTRYPOINT ["/usr/local/bin/tunnex-beam-proxy"]
