#!/bin/sh
# Read-only image-content checks; no daemon start or network changes.
set -eu
for binary in wg wg-quick ip nft iptables-nft-save openvpn; do
    command -v "$binary" >/dev/null
done
test -s /etc/ssl/certs/ca-certificates.crt
test -x /usr/local/bin/tunnex-node
test -x /opt/tunnex-ipsec/libexec/ipsec/charon
wg --version
ip -Version
# nft initializes NETLINK_NETFILTER even for --version on Alpine. QEMU
# user-mode image builds cannot provide that socket. Check installed package
# metadata and the executable dependency closure here; native qualification
# separately exercises actual nftables operations.
apk info -v nftables
iptables-nft-save -V
openvpn --version
# Includes both common libraries and each plugin's dynamic closure.
for binary in "$(command -v nft)" /opt/tunnex-ipsec/libexec/ipsec/charon \
 /opt/tunnex-ipsec/sbin/swanctl \
 /opt/tunnex-ipsec/lib/ipsec/*.so.*; do
    test -f "$binary"
    dependencies=$(ldd "$binary" 2>&1) || { printf 'IPsec runtime dependency verification failed: %s\n%s\n' "$binary" "$dependencies" >&2; exit 1; }
    case "$dependencies" in *'not found'*|*'Error loading'*) exit 1;; esac
done
for plugin in vici kernel-netlink socket-default openssl nonce random kdf; do
    test -f "/opt/tunnex-ipsec/lib/ipsec/plugins/libstrongswan-$plugin.so"
done
# Plugins intentionally resolve symbols from the parent daemon's core libraries.
# Preload those exact owned libraries for dependency checking; unresolved symbols
# or missing external libraries still fail. Actual daemon loading is a later gate.
for library in /opt/tunnex-ipsec/lib/ipsec/plugins/*.so; do
    dependencies=$(LD_PRELOAD="/opt/tunnex-ipsec/lib/ipsec/libstrongswan.so.0 /opt/tunnex-ipsec/lib/ipsec/libcharon.so.0" ldd "$library" 2>&1) || {
        printf 'IPsec plugin dependency verification failed: %s\n%s\n' "$library" "$dependencies" >&2
        exit 1
    }
    case "$dependencies" in *'not found'*|*'Error loading'*) exit 1;; esac
    case "${library##*/}" in
      libstrongswan-vici.so|libstrongswan-kernel-netlink.so|libstrongswan-socket-default.so|libstrongswan-openssl.so|libstrongswan-nonce.so|libstrongswan-random.so|libstrongswan-kdf.so) ;;
      *) echo 'Unexpected IPsec plugin' >&2; exit 1;;
    esac
done
for binary in gcc cc make python3 gpg; do
    if command -v "$binary" >/dev/null 2>&1; then
        echo 'Unexpected build tool in runtime image' >&2
        exit 1
    fi
done
test ! -e /etc/tunnex-ipsec/strongswan.conf
# Bundled authentic corresponding source, not an unfulfilled source offer.
cd /usr/share/tunnex-ipsec/source
printf '%s  %s\n' d9484eea319481bda86f992fa69cbdbdd9c0d6f8b9a4bd793a7df45c0760d963 strongswan-6.1.0.tar.gz | sha256sum -c -
test -s ../notices/strongSwan-COPYING
