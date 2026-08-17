#!/bin/sh
set -eu

ROOT=$(CDPATH= cd -- "$(dirname "$0")/.." && pwd)
DOCKERFILE="$ROOT/deploy/docker/agent-runtime.Dockerfile"
UNIT="$ROOT/deploy/systemd/tunnex-agent-runtime.service"

grep -Fq 'apk add --no-cache wireguard-tools openresolv' "$DOCKERFILE"
grep -Fq -- '--cap-add=NET_ADMIN --device=/dev/net/tun' "$DOCKERFILE"
grep -Fq 'USER root' "$DOCKERFILE"
grep -Fq 'DeviceAllow=/dev/net/tun rw' "$UNIT"
grep -Fq 'CapabilityBoundingSet=CAP_NET_ADMIN' "$UNIT"
grep -Fq 'AmbientCapabilities=CAP_NET_ADMIN' "$UNIT"
grep -Fq 'User=root' "$UNIT"
grep -Fq 'Group=root' "$UNIT"
grep -Fq 'ReadWritePaths=/etc/wireguard /etc/tunnex-agent /var/lib/tunnex-agent' "$UNIT"
grep -Fq 'ProtectSystem=strict' "$UNIT"
grep -Fq 'NoNewPrivileges=false' "$UNIT"
! grep -Fq 'NoNewPrivileges=true' "$UNIT"
grep -Fq 'RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6 AF_NETLINK' "$UNIT"
! grep -Fxq 'RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6' "$UNIT"
grep -Fq 'PrivateTmp=true' "$UNIT"
grep -Fq 'ProtectHome=true' "$UNIT"
grep -Fq 'ProtectKernelTunables=true' "$UNIT"
grep -Fq 'ProtectKernelModules=true' "$UNIT"
grep -Fq 'ProtectControlGroups=true' "$UNIT"
grep -Fq 'RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6' "$UNIT"
grep -Fq 'Restart=on-failure' "$UNIT"

# Restart-rate limits are unit-level settings. Keep them out of [Service],
# where systemd ignores them on supported Ubuntu systemd releases.
unit_section=$(awk '
  /^\[Unit\]/{section="Unit"; next}
  /^\[Service\]/{section="Service"; next}
  /^\[Install\]/{section="Install"; next}
  section == "Unit" && /^(StartLimitIntervalSec|StartLimitBurst)=/{print}
' "$UNIT")
service_limits=$(awk '
  /^\[Unit\]/{section="Unit"; next}
  /^\[Service\]/{section="Service"; next}
  /^\[Install\]/{section="Install"; next}
  section == "Service" && /^(StartLimitIntervalSec|StartLimitBurst)=/{print}
' "$UNIT")
[ "$unit_section" = "StartLimitIntervalSec=60s
StartLimitBurst=6" ]
[ -z "$service_limits" ]
if command -v systemd-analyze >/dev/null 2>&1; then
  systemd-analyze verify "$UNIT"
fi

echo 'managed-agent runtime container/service contract: PASS'
