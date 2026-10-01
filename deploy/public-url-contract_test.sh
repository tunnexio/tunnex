#!/bin/sh
# Contract test for the installer public URL input. It extracts only the pure
# validation/host helpers, so no network, Docker, or installation is performed.
set -eu

extract_helpers() {
	awk '/^public_base_url_ok\(\)/,/^}/; /^public_base_url_host\(\)/,/^}/; /^public_base_url_scheme\(\)/,/^}/; /^public_base_url_is_ip\(\)/,/^}/; /^public_ipv4_ok\(\)/,/^}/; /^public_base_url_port\(\)/,/^}/; /^tls_mode_ok\(\)/,/^}/; /^public_base_url_tls_mode_ok\(\)/,/^}/; /^select_tls_mode\(\)/,/^}/' "$1"
}

for script in deploy/install.sh; do
	eval "$(extract_helpers "$script")"
	public_base_url_ok https://vpn.acme.com
	public_base_url_ok http://203.0.113.10:8443
	[ "$(public_base_url_host https://vpn.acme.com)" = vpn.acme.com ]
	[ "$(public_base_url_host http://203.0.113.10:8443)" = 203.0.113.10 ]
	public_base_url_tls_mode_ok direct https://vpn.acme.com
	public_base_url_tls_mode_ok direct https://51.20.98.153
	public_base_url_tls_mode_ok direct https://51.20.98.153:443
	public_base_url_tls_mode_ok terminated https://192.168.1.1:8443
	public_base_url_tls_mode_ok terminated 'https://[2001:db8::1]:8443'
	for host in 51.20.98.153 1.1.1.1 100.63.255.255 100.128.0.1 172.15.255.255 172.32.0.1 198.17.255.255 198.20.0.1 223.255.255.254; do
		public_base_url_tls_mode_ok direct "https://$host" || { echo "$script refused public IPv4 $host" >&2; exit 1; }
	done
	for host in 0.1.2.3 10.0.0.1 100.64.0.1 100.127.255.255 127.0.0.1 169.254.169.254 172.16.0.1 172.31.255.255 192.0.0.1 192.0.2.1 192.88.99.1 192.168.1.1 198.18.0.1 198.19.255.255 198.51.100.1 203.0.113.1 224.0.0.1 255.255.255.255 256.1.1.1 51.020.98.153 1.2.3 1.2.3.4.5 '51.20.98.153.' '[2001:db8::1]' '[::1]'; do
		if public_base_url_tls_mode_ok direct "https://$host"; then
			echo "$script accepted a non-public or ambiguous direct IP: $host" >&2
			exit 1
		fi
	done
	for url in https://51.20.98.153: https://51.20.98.153::443 https://51.20.98.153:443:443 https://51.20.98.153:0443; do
		if public_base_url_tls_mode_ok direct "$url"; then
			echo "$script accepted a malformed IP certificate authority: $url" >&2
			exit 1
		fi
	done
	public_base_url_tls_mode_ok http http://203.0.113.10
	public_base_url_tls_mode_ok terminated https://vpn.acme.com:8443
	if public_base_url_tls_mode_ok direct https://51.20.98.153:8443 || public_base_url_tls_mode_ok direct https://vpn.acme.com:8443 || public_base_url_tls_mode_ok http http://203.0.113.10:8080; then
		echo "$script accepted an unsupported direct edge topology" >&2
		exit 1
	fi
	# Derivation ignores stale/operator-injected IP values and follows only the
	# validated origin and TLS mode, including non-default terminated ports.
	have_tty() { return 1; }
	die() { echo "$*" >&2; exit 1; }
	for topology in 'direct https://51.20.98.153 51.20.98.153' 'direct https://51.20.98.153:443 51.20.98.153' 'direct https://vpn.acme.com empty' 'terminated https://51.20.98.153:8443 empty' 'http http://51.20.98.153 empty'; do
		set -- $topology
		TUNNEX_TLS_MODE=$1 BASE_URL=$2 expected=$3
		EDGE_PUBLIC_IP=stale TUNNEX_EDGE_PUBLIC_IP=untrusted
		select_tls_mode
		[ "${EDGE_PUBLIC_IP:-empty}" = "$expected" ] || { echo "$script derived an incorrect IP certificate address" >&2; exit 1; }
	done
	if public_base_url_ok vpn.acme.com || public_base_url_ok http://vpn.acme.com/path || public_base_url_ok https://user@vpn.acme.com || public_base_url_ok ftp://vpn.acme.com; then
		echo "$script accepted an invalid public URL" >&2
		exit 1
	fi
done
echo "public URL contract: ok"
