# The managed runtime is a separate release artifact from tunnex-node.
FROM golang:1.26.10-alpine@sha256:9ce231b28998b32e116927c61aa5c406183061d4f3f2d61b292c88e7f6bdf7ca AS build
ARG TUNNEX_VERSION=dev
WORKDIR /src
COPY apps/cli/go.mod apps/cli/go.sum ./apps/cli/
COPY apps/cli ./apps/cli
COPY packages/apptransport ./packages/apptransport
WORKDIR /src/apps/cli
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags="-s -w -X main.version=${TUNNEX_VERSION}" -o /out/tunnex-agent-runtime ./cmd/tunnex-agent-runtime

FROM alpine:3.24.2@sha256:294b683cb724975bec92580e1e685676bd4b50bda910ddb8c51d4cabeaec77e6
RUN apk add --no-cache wireguard-tools openresolv \
    && mkdir -p /etc/tunnex-agent /var/lib/tunnex-agent \
    && chmod 700 /etc/tunnex-agent /var/lib/tunnex-agent
COPY --from=build /out/tunnex-agent-runtime /usr/local/bin/tunnex-agent-runtime
# Runtime launch contract: --cap-add=NET_ADMIN --device=/dev/net/tun
USER root
ENTRYPOINT ["/usr/local/bin/tunnex-agent-runtime"]
