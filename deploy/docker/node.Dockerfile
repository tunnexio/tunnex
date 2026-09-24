# tunnex-node data-plane agent — multi-stage Go build.
# Runs with NET_ADMIN in compose so it can manage WireGuard interfaces (S3.x).

FROM golang:1.25.13-alpine AS build
WORKDIR /src
COPY apps/node/go.mod apps/node/go.sum* ./
ENV GOFLAGS=-mod=readonly
RUN go mod download
COPY apps/node/ ./
ARG VERSION=dev
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath \
    -ldflags="-s -w -X main.buildVersion=${VERSION}" \
    -o /out/tunnex-node ./cmd/agent

# One verified multi-platform index for the C builder AND its runtime ABI.
FROM alpine:3.22@sha256:14358309a308569c32bdc37e2e0e9694be33a9d99e68afb0f5ff33cc1f695dce AS ipsec-build
RUN apk add --no-cache build-base openssl-dev linux-headers python3 gnupg pax-utils ca-certificates
COPY deploy/ipsec/build.sh deploy/ipsec/verify_source.py deploy/ipsec/PROVENANCE.json deploy/ipsec/NOTICE deploy/ipsec/STRONGSWAN-RELEASE-PGP-KEY deploy/ipsec/strongswan-6.1.0.tar.gz.sig /build/ipsec/
COPY deploy/docker/node.Dockerfile /build/ipsec/node.Dockerfile
RUN sh /build/ipsec/build.sh

FROM alpine:3.22@sha256:14358309a308569c32bdc37e2e0e9694be33a9d99e68afb0f5ff33cc1f695dce
# WireGuard data plane (S3.2): wg/wg-quick + ip (iproute2) drive the kernel
# WireGuard module (present in most modern kernels incl. Docker's LinuxKit VM).
# ca-certificates for the control channel. If a host lacks the module the agent
# fails readiness with a diagnosable error rather than pretending success.
# openvpn (S9.1 D-S9.5-OPTIN b): the OpenVPN server binary ships UNCONDITIONALLY — its
# presence is NEVER gated on the feature flag (the conntrack-tools packaging trap: a feature
# guarded by an unstated runtime dep breaks silently on a base-image change). The FEATURE is
# what the org opts into; the binary is always here. Absent-at-runtime → ovpn_binary_absent
# (refuse-loudly on the health surface), never a crash.
# AWS compat-rule inspection uses the explicit iptables-nft-save binary only;
# the alternative-selected iptables wrapper is never part of the authority proof.
RUN apk add --no-cache ca-certificates wireguard-tools iproute2 nftables iptables openvpn libcrypto3 libssl3 \
    && iptables-nft-save -V
COPY --from=ipsec-build /stage/opt/tunnex-ipsec /opt/tunnex-ipsec
COPY --from=ipsec-build /stage/usr/share/tunnex-ipsec /usr/share/tunnex-ipsec
COPY --from=build /out/tunnex-node /usr/local/bin/tunnex-node
COPY deploy/ipsec/verify_runtime.sh /usr/share/tunnex-ipsec/verify_runtime.sh
RUN apk info -v > /usr/share/tunnex-ipsec/source/runtime-apk-manifest.txt \
    && sh /usr/share/tunnex-ipsec/verify_runtime.sh
EXPOSE 9091
HEALTHCHECK --interval=10s --timeout=3s --start-period=5s --retries=5 \
  CMD wget -qO- http://127.0.0.1:9091/healthz >/dev/null 2>&1 || exit 1
ENTRYPOINT ["/usr/local/bin/tunnex-node"]
