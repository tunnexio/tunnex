#!/bin/sh
set -eu

ROOT=$(CDPATH= cd -- "$(dirname "$0")/.." && pwd)
KEY='b48ff99923c43052ade580cdca63952690f07f08372c35814baa44cb84d674a0'
for file in "$ROOT/.env.example" "$ROOT/deploy/get.sh" "$ROOT/deploy/install.sh"; do
	grep -F "$KEY" "$file" >/dev/null || {
		echo "trusted release public key missing from $file" >&2
		exit 1
	}
done
grep -F 'TUNNEX_RELEASE_KEY_ID=release-2026-08-01' "$ROOT/.env.example" "$ROOT/deploy/get.sh" "$ROOT/deploy/install.sh" >/dev/null || {
	echo "release key id missing from installer config" >&2
	exit 1
}
echo "release public-key contract: PASS"
