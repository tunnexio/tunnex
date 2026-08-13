#!/bin/sh
set -eu

ROOT=$(CDPATH= cd -- "$(dirname "$0")/.." && pwd)
KEY='4086a27d45e1609b41b9d29f397323edc2009414a649aa704b39c34634f75cfb'
for file in "$ROOT/.env.example" "$ROOT/deploy/get.sh" "$ROOT/deploy/install.sh"; do
	grep -F "$KEY" "$file" >/dev/null || {
		echo "trusted release public key missing from $file" >&2
		exit 1
	}
done
grep -F 'TUNNEX_RELEASE_KEY_ID=release-2026' "$ROOT/.env.example" "$ROOT/deploy/get.sh" "$ROOT/deploy/install.sh" >/dev/null || {
	echo "release key id missing from installer config" >&2
	exit 1
}
echo "release public-key contract: PASS"
