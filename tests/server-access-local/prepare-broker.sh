#!/bin/sh
set -eu
cd "$(dirname "$0")"
umask 077
mkdir -p .runtime/broker
./run.sh exec -T gateway cat /state/ca.pem > .runtime/broker/gateway-ca.pem
./run.sh exec -T gateway cat /state/cert.pem > .runtime/broker/gateway-cert.pem
if [ ! -f .runtime/broker/server.key ]; then
 openssl req -x509 -newkey ed25519 -nodes -keyout .runtime/broker/server.key -out .runtime/broker/server.pem -days 1 -subj /CN=sa0-outbound-broker -addext subjectAltName=DNS:outbound-broker > .runtime/broker/keygen.log 2>&1
fi
cp .runtime/broker/server.pem .runtime/ssh-client/broker-ca.pem
