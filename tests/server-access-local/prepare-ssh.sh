#!/bin/sh
set -eu
cd "$(dirname "$0")"
umask 077
mkdir -p .runtime/ssh .runtime/ssh-client .runtime/ssh-public/principals
for name in ca client; do
 if [ ! -f ".runtime/ssh/$name" ]; then ssh-keygen -q -t ed25519 -N '' -f ".runtime/ssh/$name"; fi
done
ssh-keygen -q -s .runtime/ssh/ca -I org-sa0/actor-fixture/session-fixture -z 1 -n tunnex:org-sa0:server-linux:account-fixture -V '-1m:+5m' -O clear -O permit-pty .runtime/ssh/client.pub
cp .runtime/ssh/ca.pub .runtime/ssh-public/ca.pub
printf 'tunnex:org-sa0:server-linux:account-fixture\n' > .runtime/ssh-public/principals/fixture
chmod 755 .runtime/ssh-public .runtime/ssh-public/principals
chmod 644 .runtime/ssh-public/ca.pub .runtime/ssh-public/principals/fixture

cp .runtime/ssh/client .runtime/ssh/client.pub .runtime/ssh/client-cert.pub .runtime/ssh-client/
