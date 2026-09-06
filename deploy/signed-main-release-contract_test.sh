#!/bin/sh
# Regression contract for the exact defect where green sha installs had no
# signed release descriptor, so the Upgrade Center correctly but invisibly hid.
set -eu

ROOT=$(CDPATH= cd -- "$(dirname "$0")/.." && pwd)
CI="$ROOT/.github/workflows/ci.yml"

grep -Fq 'release-assets:' "$CI"
grep -Fq 'needs: [publish, cli-release]' "$CI"
grep -Fq 'TUNNEX_RELEASE_SIGNING_PRIVATE_KEY' "$CI"
grep -Fq 'TUNNEX_RELEASE_KEY_ID' "$CI"
grep -Fq 'tunnex-build-${SOURCE_SHA}' "$CI"
grep -Fq 'run: sh deploy/signed-main-release-contract_test.sh' "$CI"
grep -Fq 'gh release create tunnex-updates release.json release.json.sha256' "$CI"
grep -Fq 'gh release upload tunnex-updates release.json release.json.sha256 --clobber' "$CI"

# Desktop installers have their own source and release pipeline in
# tunnexio/tunnex-client. The server release must not silently republish a stale
# copy from this monorepo. Desktop build gates run in the standalone repository.
release_assets=$(sed -n '/^  release-assets:/,$p' "$CI")
for forbidden in 'desktop-artifacts' 'tunnex-*-installer' 'Tunnex-desktop-SHA256SUMS'; do
  if printf '%s\n' "$release_assets" | grep -Fq "$forbidden"; then
    echo "signed successful-main release contract: FAIL: server release publishes desktop artifact marker: $forbidden" >&2
    exit 1
  fi
done

grep -Fq "CANONICAL_INSTALLER_URL='https://raw.githubusercontent.com/tunnexio/tunnex/main/deploy/install.sh'" "$ROOT/deploy/get.sh"

installer="$ROOT/deploy/install.sh"
grep -Fq 'RELEASE_DESCRIPTOR_TAG="tunnex-build-${SOURCE_REF}"' "$installer"
grep -Fq -- '-expected-source-sha "$SOURCE_REF"' "$installer"
grep -Fq -- '-print-env' "$installer"
grep -Fq 'images pinned by digest' "$installer"
grep -Fq 'chmod 0644 release.json' "$installer"
grep -Fq 'deploy/upgrade.sh" -o "$STAGE_DIR/upgrade.sh"' "$installer"
grep -Fq 'Verify the staged descriptor before publishing' "$installer"
grep -Fq 'chmod 0755 upgrade.sh' "$installer"
grep -Fq 'deploy/upgrade-runner.sh" -o "$STAGE_DIR/upgrade-runner.sh"' "$installer"
grep -Fq 'ROOT_UPGRADE_DIR=/usr/local/lib/tunnex' "$installer"
grep -Fq 'ExecStart=${ROOT_UPGRADE_DIR}/upgrade-runner.sh' "$installer"
grep -Fq 'TUNNEX_COMPOSE_SHA256=$(file_sha256 tunnex.yml)' "$installer"

for variable in TUNNEX_RELEASE_MANIFEST_PATH TUNNEX_RELEASE_PUBLIC_KEY TUNNEX_RELEASE_SEQUENCE TUNNEX_RELEASE_VERSION TUNNEX_RELEASE_SOURCE_SHA TUNNEX_RELEASE_CATALOG_URL TUNNEX_RELEASE_UPDATE_CHECK; do
  grep -Fq "${variable}: \${${variable}" "$ROOT/deploy/tunnex.yml"
done
grep -Fq './release.json:/var/lib/tunnex/release.json:ro' "$ROOT/deploy/tunnex.yml"
grep -Fq 'TUNNEX_RELEASE_CATALOG_URL' "$ROOT/deploy/upgrade.sh"
grep -Fq 'releaseverify -manifest /tmp/tunnex-release.json -public-key "$1" -print-env' "$ROOT/deploy/upgrade.sh"
grep -Fq 'chmod 0644 "$DIR/release.json"' "$ROOT/deploy/upgrade.sh"

echo 'signed successful-main release contract: PASS'
