#!/bin/sh
# Contract test for the installer public URL input. It extracts only the pure
# validation/host helpers, so no network, Docker, or installation is performed.
set -eu

extract_helpers() {
	awk '/^public_base_url_ok\(\)/,/^}/; /^public_base_url_host\(\)/,/^}/' "$1"
}

for script in deploy/install.sh deploy/get.sh; do
	eval "$(extract_helpers "$script")"
	public_base_url_ok https://vpn.acme.com
	public_base_url_ok http://203.0.113.10:8443
	[ "$(public_base_url_host https://vpn.acme.com)" = vpn.acme.com ]
	[ "$(public_base_url_host http://203.0.113.10:8443)" = 203.0.113.10 ]
	if public_base_url_ok vpn.acme.com || public_base_url_ok http://vpn.acme.com/path || public_base_url_ok https://user@vpn.acme.com || public_base_url_ok ftp://vpn.acme.com; then
		echo "$script accepted an invalid public URL" >&2
		exit 1
	fi
done
echo "public URL contract: ok"
