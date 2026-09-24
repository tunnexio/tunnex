#!/bin/sh
# Build-time only. Never launch a daemon or change networking.
set -eu
umask 022
python3 /build/ipsec/verify_source.py /build/source
cd /build/source/strongswan-6.1.0
./configure \
  --prefix=/opt/tunnex-ipsec \
  --sysconfdir=/etc/tunnex-ipsec \
  --with-piddir=/run/tunnex-ipsec \
  --disable-defaults \
  --enable-charon --enable-ikev2 --enable-vici \
  --enable-kernel-netlink --enable-socket-default \
  --enable-openssl --enable-nonce --enable-random --enable-kdf \
  --enable-swanctl
make -j2
make DESTDIR=/stage install
# Only runtime dynamic artifacts; sources and reproducible build inputs follow.
find /stage/opt/tunnex-ipsec -type f \( -name '*.a' -o -name '*.la' \) -delete
rm -rf /stage/opt/tunnex-ipsec/include
# Upstream configure forces counters=true with VICI. The qualified node daemon
# uses the explicit seven-plugin list; package no extra auto-built plugin.
rm -f /stage/opt/tunnex-ipsec/lib/ipsec/plugins/libstrongswan-counters.so
mkdir -p /stage/usr/share/tunnex-ipsec/source /stage/usr/share/tunnex-ipsec/notices
cp /build/source/strongswan-6.1.0.tar.gz /build/source/strongswan-6.1.0.tar.gz.sig \
   /build/source/STRONGSWAN-RELEASE-PGP-KEY /stage/usr/share/tunnex-ipsec/source/
cp /build/ipsec/build.sh /build/ipsec/verify_source.py /build/ipsec/PROVENANCE.json \
   /build/ipsec/node.Dockerfile /stage/usr/share/tunnex-ipsec/source/
cp COPYING /stage/usr/share/tunnex-ipsec/notices/strongSwan-COPYING
cp /build/ipsec/NOTICE /stage/usr/share/tunnex-ipsec/notices/NOTICE
apk info -v > /stage/usr/share/tunnex-ipsec/source/build-apk-manifest.txt
scanelf --recursive --needed /stage/opt/tunnex-ipsec > /stage/usr/share/tunnex-ipsec/source/elf-needed.txt
# Configuration is deliberately not copied from make install. The future node
# supervisor owns an explicit private config/socket; no starter or boot service.
