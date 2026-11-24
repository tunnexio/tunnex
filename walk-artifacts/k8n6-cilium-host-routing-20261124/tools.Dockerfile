FROM alpine:3.24.4
RUN apk add --no-cache nftables iptables ipset bpftool wireguard-tools tcpdump conntrack-tools curl socat iproute2 jq
