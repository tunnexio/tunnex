#!/bin/sh
# Regression contract for the exact defect where green sha installs had no
# signed release descriptor, so the Upgrade Center correctly but invisibly hid.
set -eu

ROOT=$(CDPATH= cd -- "$(dirname "$0")/.." && pwd)
CI="$ROOT/.github/workflows/ci.yml"

grep -Fq 'release-assets:' "$CI"
grep -Fq 'needs: [publish, publish-pullable, cli-release]' "$CI"
grep -Fq 'TUNNEX_RELEASE_SIGNING_PRIVATE_KEY' "$CI"
grep -Fq 'TUNNEX_RELEASE_KEY_ID' "$CI"
grep -Fq 'tunnex-build-${SOURCE_SHA}' "$CI"
grep -Fq 'artifact-metadata: write' "$CI"
grep -Fq 'name: operator, dockerfile: apps/operator/Dockerfile' "$CI"
grep -Fq 'flavor: latest=false' "$CI"
grep -Fq 'release-version-guard:' "$CI"
grep -Fq 'needs: [gates, e2e, e2e-enterprise]' "$CI"
grep -Fq 'needs: [release-version-guard, gates, e2e, e2e-enterprise]' "$CI"
grep -Fq 'name: Refuse published tag reuse before any artifact publication' "$CI"
grep -Fq 'GH_REPO: ${{ github.repository }}' "$CI"
grep -Fq 'release tags must use exact stable vMAJOR.MINOR.PATCH syntax' "$CI"
grep -Fq 'refusing source reuse before any image or chart publication' "$CI"
grep -Fq 'MARKER_NAME="Tunnex-release-source.json"' "$CI"
grep -Fq "'{schema_version:1,tag:\$tag,source_sha:\$source_sha}'" "$CI"
grep -Fq 'assert_artifact_refs_absent' "$CI"
grep -Fq '${GITHUB_REPOSITORY}-operator' "$CI"
grep -Fq '${GITHUB_REPOSITORY_OWNER}/charts/tunnex-operator-crds' "$CI"
grep -Fq '${GITHUB_REPOSITORY_OWNER}/charts/tunnex-host-posture' "$CI"
grep -Fq 'registry_ref_exists "$repo" "$IMAGE_TAG"' "$CI"
grep -Fq 'local chart_version="${GITHUB_REF_NAME#v}"' "$CI"
grep -Fq 'registry_ref_exists "$repo" "$chart_version"' "$CI"
grep -Fq 'the version is burned and must not be overwritten' "$CI"
grep -Fq 'the immutable ref is burned and must not be overwritten' "$CI"
grep -Fq 'RELEASE_TAG="tunnex-build-${GITHUB_SHA}"' "$CI"
grep -Fq 'IMAGE_TAG="sha-${GITHUB_SHA::7}"' "$CI"
grep -Fq 'RELEASE_STATUS="$(curl -sS -o "$RELEASE_RESPONSE" -w' "$CI"
grep -Fq 'RELEASE_REF_STATUS="$(curl -sS -o "$RELEASE_REF_RESPONSE" -w' "$CI"
grep -Fq 'git/ref/tags/${ENCODED_RELEASE_TAG}' "$CI"
grep -Fq 'refusing draft creation or adoption' "$CI"
grep -Fq 'GitHub release source-ref lookup for ${RELEASE_TAG} returned HTTP ${RELEASE_REF_STATUS}' "$CI"
grep -Fq 'GitHub release lookup for ${RELEASE_TAG} returned HTTP ${RELEASE_STATUS}' "$CI"
grep -Fq 'release ${RELEASE_TAG} is already published and immutable' "$CI"
grep -Fq 'draft release ${RELEASE_TAG} belongs to a different source' "$CI"
grep -Fq -- '--title "$RELEASE_TAG" --generate-notes --draft --verify-tag' "$CI"
grep -Fq -- '--target "$GITHUB_SHA" --title "$RELEASE_TAG" --generate-notes' "$CI"
grep -Fq 'name: Revalidate release source ledger immediately before image publication' "$CI"
grep -Fq 'name: Refuse published tag reuse before chart publication' "$CI"
grep -Fq 'refusing tag reuse before any OCI chart publication' "$CI"
grep -Fq 'refusing to overwrite existing OCI chart ${chart}:${CHART_VERSION} with different bytes' "$CI"
grep -Fq 'Reusing exact matching OCI chart ${chart}:${CHART_VERSION}' "$CI"
grep -Fq 'bash deploy/helm-package-reproducible.sh deploy/helm/tunnex-host-posture' "$CI"
grep -Fq 'publish_or_verify_chart tunnex-host-posture' "$CI"
grep -Fq 'for chart in tunnex-host-posture tunnex-gateway tunnex-operator tunnex-operator-crds' "$CI"
grep -Fq 'chart-artifacts/tunnex-host-posture-*.tgz' "$CI"
published_tag_guard_line=$(grep -n -m1 'name: Refuse published tag reuse before any artifact publication' "$CI" | cut -d: -f1)
first_image_push_line=$(grep -n -m1 'name: Build + push' "$CI" | cut -d: -f1)
first_chart_push_line=$(grep -n -m1 'helm push "$package"' "$CI" | cut -d: -f1)
test "$published_tag_guard_line" -lt "$first_image_push_line"
test "$published_tag_guard_line" -lt "$first_chart_push_line"
grep -Fq 'refs/tags/*) TAGS="${GITHUB_REF#refs/tags/}" ;;' "$CI"
grep -Fq '*)           TAGS="latest sha-${GITHUB_SHA::7}" ;;' "$CI"
grep -Fq 'is absent or no longer the source-ledger draft; refusing asset publication' "$CI"
grep -Fq 'name: Publish only the completed source-ledger release' "$CI"
grep -Fq 'gh release edit "$RELEASE_TAG" --draft=false --latest' "$CI"
test "$(grep -Fc 'commits/${RELEASE_TAG}' "$CI")" -ge 5
test "$(grep -Fc 'CURRENT_RELEASE_SHA=' "$CI")" -ge 5
grep -Fq 'release source ref ${RELEASE_TAG} moved from workflow source ${GITHUB_SHA}' "$CI"
test "$(grep -Fc 'Tunnex-release-source.json --output -' "$CI")" -ge 4
if awk '/^  release-assets:/{inside=1} /^  publish-update-catalog:/{inside=0} inside' "$CI" | grep -Fq 'gh release create'; then
  echo 'release-assets must not recreate a missing source-ledger draft' >&2
  exit 1
fi
grep -Fq 'run: sh deploy/signed-main-release-contract_test.sh' "$CI"
grep -Fq 'publish-update-catalog:' "$CI"
grep -Fq 'needs: [release-assets]' "$CI"
grep -Fq 'gh release download "$GITHUB_REF_NAME"' "$CI"
grep -Fq '(cd catalog-artifacts && sha256sum -c release.json.sha256)' "$CI"
grep -Fq 'catalog-artifacts/release.json catalog-artifacts/release.json.sha256 --clobber' "$CI"
grep -Fq 'catalog-artifacts/release.json catalog-artifacts/release.json.sha256' "$CI"
completed_release_line=$(grep -n -m1 'name: Publish only the completed source-ledger release' "$CI" | cut -d: -f1)
catalog_job_line=$(grep -n -m1 'publish-update-catalog:' "$CI" | cut -d: -f1)
test "$completed_release_line" -lt "$catalog_job_line"

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
