#!/bin/sh
# Tunnex bootstrap installer — served at https://get.tunnex.io
#
#   curl -fsSL https://get.tunnex.io | sh
#
# This file deliberately stays a tiny launcher. The customer-facing site is
# published asynchronously from a separate repository; keeping a second full
# installer here previously allowed it to lag behind deploy/tunnex.yml. The
# canonical installer below is the only implementation of prompts, TLS modes,
# release selection, and compose configuration.
set -eu

CANONICAL_INSTALLER_URL='https://raw.githubusercontent.com/tunnexio/tunnex/main/deploy/install.sh'

die() {
	printf '\n  \033[31m✗\033[0m %s\n\n' "$*" >&2
	exit 1
}

umask 077
installer="$(mktemp "${TMPDIR:-/tmp}/tunnex-install.XXXXXX")" ||
	die "could not create a secure temporary installer file"
cleanup() { rm -f "$installer"; }
trap cleanup 0 HUP INT TERM

# Do not resolve a version here. install.sh resolves the latest published
# semantic release and verifies its signed descriptor, so all installation
# paths use one release-selection and TLS/configuration implementation.
curl -fsSL "$CANONICAL_INSTALLER_URL" -o "$installer" ||
	die "could not download the canonical Tunnex installer"

sh "$installer" "$@"
