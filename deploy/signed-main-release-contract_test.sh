#!/bin/sh
# Regression contract for the exact defect where green sha installs had no
# signed release descriptor, so the Upgrade Center correctly but invisibly hid.
set -eu

ROOT=$(CDPATH= cd -- "$(dirname "$0")/.." && pwd)
CI="$ROOT/.github/workflows/ci.yml"

grep -Fq 'release-descriptor:' "$CI"
grep -Fq 'needs: [publish]' "$CI"
grep -Fq 'TUNNEX_RELEASE_SIGNING_PRIVATE_KEY' "$CI"
grep -Fq 'TUNNEX_RELEASE_KEY_ID' "$CI"
grep -Fq 'tunnex-build-${SOURCE_SHA}' "$CI"
grep -Fq 'gh release upload tunnex-updates release.json release.json.sha256 --clobber' "$CI"
grep -Fq 'needs: [publish, release-descriptor]' "$CI"

for installer in "$ROOT/deploy/get.sh" "$ROOT/deploy/install.sh"; do
  grep -Fq 'RELEASE_DESCRIPTOR_TAG="tunnex-build-${SOURCE_REF}"' "$installer"
  grep -Fq -- '-expected-source-sha "$SOURCE_REF"' "$installer"
  grep -Fq -- '-print-env' "$installer"
  grep -Fq 'images pinned by digest' "$installer"
  grep -Fq 'chmod 0644 release.json' "$installer"
done

for variable in TUNNEX_RELEASE_MANIFEST_PATH TUNNEX_RELEASE_PUBLIC_KEY TUNNEX_RELEASE_SEQUENCE TUNNEX_RELEASE_VERSION TUNNEX_RELEASE_SOURCE_SHA TUNNEX_RELEASE_CATALOG_URL TUNNEX_RELEASE_UPDATE_CHECK; do
  grep -Fq "${variable}: \${${variable}" "$ROOT/deploy/tunnex.yml"
done
grep -Fq './release.json:/var/lib/tunnex/release.json:ro' "$ROOT/deploy/tunnex.yml"
grep -Fq 'TUNNEX_RELEASE_CATALOG_URL' "$ROOT/deploy/upgrade.sh"
grep -Fq 'releaseverify -manifest /tmp/tunnex-release.json -public-key "$1" -print-env' "$ROOT/deploy/upgrade.sh"
grep -Fq 'chmod 0644 "$DIR/release.json"' "$ROOT/deploy/upgrade.sh"

echo 'signed successful-main release contract: PASS'
