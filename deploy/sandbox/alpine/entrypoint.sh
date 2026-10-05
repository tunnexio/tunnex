#!/bin/bash
# Fixed unprivileged SSH process. No installation or service manager.
set -eu
unavailable() { echo 'sandbox terminal unavailable' >&2; exit 1; }
[ "$#" = 0 ] && [ "$(id -u)" = 1001 ] && [ "$(id -g)" = 1001 ] || unavailable
[ -d /run ] && [ ! -L /run ] && [ "$(stat -c %u /run)" = 1001 ] || unavailable
if [ ! -e /run/sshd ] && [ ! -L /run/sshd ]; then
    mkdir -m 755 /run/sshd || unavailable
fi
[ -d /run/sshd ] && [ ! -L /run/sshd ] && [ "$(stat -c %u /run/sshd)" = 1001 ] || unavailable
mode=$(stat -c %a /run/sshd)
(( (8#$mode & 8#022) == 0 )) || unavailable
exec /usr/sbin/sshd -D -e -f /run/tunnex-ssh/sshd_config
