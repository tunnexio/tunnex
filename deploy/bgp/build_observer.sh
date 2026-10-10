#!/bin/sh
set -eu
apk add --no-cache build-base autoconf automake bison flex libtool c-ares-dev elfutils-dev json-c-dev libcap-dev libyang-dev linux-headers python3-dev readline-dev bsd-compat-headers patch
wget -q https://github.com/FRRouting/frr/archive/frr-10.6.1.tar.gz -O /tmp/frr.tar.gz
printf '%s  /tmp/frr.tar.gz\n' c591055fc29c237f16f337835268515685872876e6f6abf82f91226543a22068c4e169904780a7ad08e383a31509b93a14fbfce26170186e64b9af3799e8f271 | sha512sum -c -
tar -xzf /tmp/frr.tar.gz -C /tmp
cd /tmp/frr-frr-10.6.1
printf '%s  /build/zebra-no-sys-admin.patch\n' 4861c1425d878028bd36ea19bc5b1c6fa9b94d5da7e007ff356e34b359a87496 | sha256sum -c -
patch --fuzz=0 -p1 < /build/zebra-no-sys-admin.patch

./bootstrap.sh
LDFLAGS="-Wl,-rpath,/opt/tunnex-bgp/lib" ./configure --prefix=/opt/tunnex-bgp --sbindir=/opt/tunnex-bgp --libdir=/opt/tunnex-bgp/lib --sysconfdir=/run/tunnex-bgp --localstatedir=/run/tunnex-bgp --disable-bfdd --disable-bgpd --disable-staticd --disable-watchfrr --disable-doc --disable-snmp --disable-rpki --disable-protobuf --disable-zeromq --enable-user=root --enable-group=root --enable-vty-group=root --disable-dependency-tracking
make -j2 zebra/zebra
mkdir -p /stage/opt/tunnex-bgp/lib
cp zebra/.libs/zebra /stage/opt/tunnex-bgp/zebra
cp lib/.libs/libfrr.so.0.0.0 /stage/opt/tunnex-bgp/lib/
ln -s libfrr.so.0.0.0 /stage/opt/tunnex-bgp/lib/libfrr.so.0
chmod 0755 /stage/opt/tunnex-bgp/zebra /stage/opt/tunnex-bgp/lib/libfrr.so.0.0.0
