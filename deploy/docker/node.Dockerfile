# tunnex-node data-plane agent — multi-stage Go build.
# Runs with NET_ADMIN in compose so it can manage WireGuard interfaces (S3.x).

FROM golang:1.26.11-alpine@sha256:ecb67f987aa1a57794c91d19ade7ae0209f2f0f5496aaef9e6ae85ddf92d02ab AS build
WORKDIR /src/apps/node
COPY packages/apptransport/ /src/packages/apptransport/
COPY apps/node/go.mod apps/node/go.sum* ./
ENV GOFLAGS=-mod=readonly
RUN go mod download
COPY apps/node/ ./
ARG VERSION=dev
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath \
    -ldflags="-s -w -X main.buildVersion=${VERSION}" \
    -o /out/tunnex-node ./cmd/agent
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags="-s -w" \
    -o /out/tunnex-ai-vpn-relay ./cmd/ai-vpn-relay

# One verified multi-platform index for the C builder AND its runtime ABI.
FROM alpine:3.24.2@sha256:294b683cb724975bec92580e1e685676bd4b50bda910ddb8c51d4cabeaec77e6 AS ipsec-build
RUN apk add --no-cache build-base openssl-dev linux-headers python3 gnupg pax-utils ca-certificates
COPY deploy/ipsec/build.sh deploy/ipsec/verify_source.py deploy/ipsec/PROVENANCE.json deploy/ipsec/NOTICE deploy/ipsec/STRONGSWAN-RELEASE-PGP-KEY deploy/ipsec/strongswan-6.1.0.tar.gz.sig /build/ipsec/
COPY deploy/docker/node.Dockerfile /build/ipsec/node.Dockerfile
RUN sh /build/ipsec/build.sh

FROM alpine:3.24.2@sha256:294b683cb724975bec92580e1e685676bd4b50bda910ddb8c51d4cabeaec77e6 AS bgp-observer-build
COPY deploy/bgp/build_observer.sh /build_observer.sh
COPY deploy/bgp/zebra-no-sys-admin.patch /build/zebra-no-sys-admin.patch
RUN sh /build_observer.sh

# K8N-2: bpftool built from the pinned upstream release (libbpf/bpftool v7.8.1, the
# "-sources" archive that carries its libbpf submodule), checked against its sha256 before
# it is unpacked. It is built WITHOUT a JIT disassembler: SKIP_LLVM=1 and SKIP_LIBBFD=1, and
# neither llvm-dev nor binutils-dev is installed, so feature detection cannot find them
# either. SKIP_CRYPTO=1 leaves out program signing (and libcrypto); no clang, so no BPF
# skeletons (`prog profile` and the pids column). libbpf is linked statically; the binary
# needs only libelf, zlib, zstd and libcap at runtime. The build fails unless bpftool itself
# reports llvm and libbfd off and ldd shows no LLVM.
FROM alpine:3.24.2@sha256:294b683cb724975bec92580e1e685676bd4b50bda910ddb8c51d4cabeaec77e6 AS bpftool
RUN apk add --no-cache build-base elfutils-dev zlib-dev zstd-dev libcap-dev linux-headers \
    && wget -q -O /tmp/bpftool.tar.gz \
        https://github.com/libbpf/bpftool/releases/download/v7.8.1/bpftool-libbpf-v7.8.1-sources.tar.gz \
    && printf '%s  /tmp/bpftool.tar.gz\n' fed76b7acb54d810cc3982eb6394726010114977542fd146695887a7d904b60c | sha256sum -c - \
    && mkdir /tmp/bpftool && tar -xzf /tmp/bpftool.tar.gz -C /tmp/bpftool --strip-components=1 \
    && make -C /tmp/bpftool/src -j"$(nproc)" SKIP_LLVM=1 SKIP_LIBBFD=1 SKIP_CRYPTO=1 \
    && strip /tmp/bpftool/src/bpftool \
    && mkdir -p /stage/usr/sbin /stage/usr/share/tunnex-bpftool \
    && install -m 0755 /tmp/bpftool/src/bpftool /stage/usr/sbin/bpftool \
    && cp /tmp/bpftool/LICENSE /tmp/bpftool/LICENSE.BSD-2-Clause /tmp/bpftool/LICENSE.GPL-2.0 /stage/usr/share/tunnex-bpftool/ \
    && cp /tmp/bpftool/libbpf/LICENSE.LGPL-2.1-only /stage/usr/share/tunnex-bpftool/libbpf-LICENSE.LGPL-2.1-only \
    && cp /tmp/bpftool/libbpf/LICENSE /stage/usr/share/tunnex-bpftool/libbpf-LICENSE \
    && /stage/usr/sbin/bpftool version \
    && /stage/usr/sbin/bpftool --json version | grep -q '"version":"7.8.1"' \
    && /stage/usr/sbin/bpftool --json version | grep -q '"llvm":false' \
    && /stage/usr/sbin/bpftool --json version | grep -q '"libbfd":false' \
    && ! ldd /stage/usr/sbin/bpftool | grep -qi llvm

FROM alpine:3.24.2@sha256:294b683cb724975bec92580e1e685676bd4b50bda910ddb8c51d4cabeaec77e6
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
# The observed CNI proof reads kernel set members with `ipset save NAME` (K8N-1); nft
# cannot list those sets. It is only ever used to read. `ipset version` asks the kernel
# and fails in an unprivileged build, so the build runs `ipset help`, which loads the
# binary and its library without a netlink socket.
# On a Cilium node the host-posture manager reads Cilium's pinned ip-masq-agent map with
# `bpftool --json map dump pinned PATH` (K8N-2), the command an operator can run to see what
# Tunnex saw. It is only ever used to read, and only in that privileged container.
# bpftool is built from upstream source in the bpftool stage above, without LLVM (Alpine's
# package depends on perf and python3 and links libLLVM, about 168 MB). Only its binary and
# license files are copied; the libraries it is linked against are installed by name.
# `bpftool version` loads the binary and every library without a bpf() call, so it runs in
# the build and fails it if the closure is not complete.
RUN apk add --no-cache ca-certificates wireguard-tools iproute2 nftables iptables ipset openvpn libcrypto3 libssl3 \
        libelf libcap2 zlib zstd-libs \
    && iptables-nft-save -V \
    && ipset help >/dev/null
COPY --from=bpftool /stage/ /
RUN bpftool version
COPY deploy/bgp/install.sh deploy/bgp/PROVENANCE.json deploy/bgp/NOTICE /usr/share/tunnex-bgp/
RUN sh /usr/share/tunnex-bgp/install.sh
COPY --from=bgp-observer-build /stage/opt/tunnex-bgp /opt/tunnex-bgp
COPY --from=ipsec-build /stage/opt/tunnex-ipsec /opt/tunnex-ipsec
COPY --from=ipsec-build /stage/usr/share/tunnex-ipsec /usr/share/tunnex-ipsec
COPY --from=build /out/tunnex-node /usr/local/bin/tunnex-node
COPY --from=build /out/tunnex-ai-vpn-relay /usr/local/bin/tunnex-ai-vpn-relay
COPY deploy/ipsec/verify_runtime.sh /usr/share/tunnex-ipsec/verify_runtime.sh
RUN test -x /usr/local/bin/tunnex-node \
    && test -x /usr/local/bin/tunnex-ai-vpn-relay \
    && apk info -v > /usr/share/tunnex-ipsec/source/runtime-apk-manifest.txt \
    && sh /usr/share/tunnex-ipsec/verify_runtime.sh
EXPOSE 9091
HEALTHCHECK --interval=10s --timeout=3s --start-period=5s --retries=5 \
  CMD wget -qO- http://127.0.0.1:9091/healthz >/dev/null 2>&1 || exit 1
ENTRYPOINT ["/usr/local/bin/tunnex-node"]
