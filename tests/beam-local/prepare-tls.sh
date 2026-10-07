#!/bin/sh
# Disposable local TLS only. This does not install a system trust root.
set -eu
cd "$(dirname "$0")"
umask 077
mkdir -p .runtime/tls
if [ -f .runtime/tls/ca.pem ] && [ -f .runtime/tls/server-cert.pem ] && \
   openssl x509 -in .runtime/tls/ca.pem -noout -text | grep -q 'Certificate Sign'; then
  exit 0
fi
[ -f .runtime/tls/ca-key.pem ] || openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out .runtime/tls/ca-key.pem 2>/dev/null
[ -f .runtime/tls/server-key.pem ] || openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out .runtime/tls/server-key.pem 2>/dev/null
openssl req -new -x509 -key .runtime/tls/ca-key.pem -out .runtime/tls/ca.pem -days 2 \
  -subj '/CN=Beam local development CA' \
  -addext 'basicConstraints=critical,CA:TRUE' \
  -addext 'keyUsage=critical,keyCertSign,cRLSign' \
  -addext 'subjectKeyIdentifier=hash'
tmp=$(mktemp -d .runtime/tls/issue-XXXXXX)
trap 'rm -rf "$tmp"' EXIT INT TERM
openssl req -new -key .runtime/tls/server-key.pem -out "$tmp/server.csr" -subj '/CN=localhost'
cat > "$tmp/server.ext" <<'EOF'
basicConstraints=critical,CA:FALSE
keyUsage=critical,digitalSignature,keyEncipherment
extendedKeyUsage=serverAuth
subjectAltName=DNS:localhost,IP:127.0.0.1,DNS:*.beam.127.0.0.1.sslip.io
subjectKeyIdentifier=hash
authorityKeyIdentifier=keyid,issuer
EOF
openssl x509 -req -in "$tmp/server.csr" -CA .runtime/tls/ca.pem -CAkey .runtime/tls/ca-key.pem \
  -set_serial "0x$(openssl rand -hex 16)" -out .runtime/tls/server-cert.pem -days 2 -extfile "$tmp/server.ext" 2>/dev/null
chmod 600 .runtime/tls/*pem
openssl verify -CAfile .runtime/tls/ca.pem .runtime/tls/server-cert.pem >/dev/null
