#!/bin/sh
set -eu
umask 077
mkdir -p /ssh-state
if [ ! -f /ssh-state/host ]; then ssh-keygen -q -t ed25519 -N '' -f /ssh-state/host; fi
cat > /ssh-state/sshd.conf <<'CONF'
Port 2222
ListenAddress 0.0.0.0
HostKey /ssh-state/host
PidFile /ssh-state/sshd.pid
TrustedUserCAKeys /ssh-fixture/ca.pub
AuthorizedPrincipalsFile /ssh-fixture/principals/%u
AuthorizedKeysFile none
PasswordAuthentication no
KbdInteractiveAuthentication no
PermitRootLogin no
AllowUsers fixture
AllowTcpForwarding no
AllowAgentForwarding no
X11Forwarding no
LogLevel VERBOSE
# Dedicated negative-auth fixture: avoid source penalty masking later assertions.
PerSourcePenalties no
CONF
exec /usr/sbin/sshd -D -e -f /ssh-state/sshd.conf
