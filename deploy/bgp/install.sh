#!/bin/sh
set -eu
version=10.6.1-r0
case "$(apk --print-arch)" in
 aarch64) digest=70d3cf2ed8620a4e20830d160f0af2b93db40ffbc70f1cddf8e9e60ebaae5179 ;;
 x86_64) digest=804ee8cef7ab3b7e2f539121a9d1b78172c5dc8eca0cf92eeceb678ca162533a ;;
 *) echo 'Unsupported BGP package architecture' >&2; exit 1 ;;
esac
package=/tmp/tunnex-frr.apk
wget -q "https://dl-cdn.alpinelinux.org/alpine/v3.24/community/$(apk --print-arch)/frr-${version}.apk" -O "$package"
printf '%s  %s\n' "$digest" "$package" | sha256sum -c -
# apk verifies the package signature using the base image's trusted Alpine keys.
apk add --no-cache "$package"
rm "$package"
# Managed daemons keep root ownership; FRR requires membership in its VTY group.
addgroup root frrvty
mkdir -p /var/tmp/frr /lib/frr
mkdir -p /opt/tunnex-bgp /usr/share/tunnex-bgp
cp /usr/lib/frr/bgpd /usr/lib/frr/zebra /usr/bin/vtysh /opt/tunnex-bgp/
chmod 0755 /opt/tunnex-bgp/bgpd /opt/tunnex-bgp/zebra /opt/tunnex-bgp/vtysh
apk info -v frr > /usr/share/tunnex-bgp/package-version.txt
# Package installation never starts bgpd, zebra, watchfrr or OpenRC.
/opt/tunnex-bgp/bgpd --version | head -n 1 | grep -F 'bgpd version 10.6.1'
/opt/tunnex-bgp/bgpd --help | grep -F -- '--no_kernel'
/opt/tunnex-bgp/zebra --version | head -n 1 | grep -F 'zebra version 10.6.1'
/opt/tunnex-bgp/vtysh --help >/dev/null
