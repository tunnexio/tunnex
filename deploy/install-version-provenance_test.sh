#!/bin/sh
# Behavioural contract for the two public installer paths. No network, Docker, or root required.
set -eu

ROOT="$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT HUP INT TERM

fail() {
	printf 'installer provenance test: %s\n' "$*" >&2
	exit 1
}

extract_resolver() {
	sed -n '/^# BEGIN INSTALL VERSION RESOLVER/,/^# END INSTALL VERSION RESOLVER/p' "$1"
}

extract_resolver "$ROOT/deploy/install.sh" >"$TMP/install.resolver"
extract_resolver "$ROOT/deploy/get.sh" >"$TMP/get.resolver"
[ -s "$TMP/install.resolver" ] || fail "install.sh resolver block is missing"
cmp -s "$TMP/install.resolver" "$TMP/get.resolver" ||
	fail "install.sh and get.sh version resolvers drifted"

# ⛔ THE DISPLAY RESOLVER IS DUPLICATED FOR THE SAME REASON THE VERSION RESOLVER IS — each installer must
# be a single self-contained file an operator can read before running it — so it needs the same guard. An
# unguarded copy is the one that drifts, and a drifted VERSION LABEL is worse than no label: two operators
# comparing notes would be told different things about the same build.
extract_display() {
	sed -n '/^# BEGIN DISPLAY VERSION RESOLVER/,/^# END DISPLAY VERSION RESOLVER/p' "$1"
}

extract_display "$ROOT/deploy/install.sh" >"$TMP/install.display"
extract_display "$ROOT/deploy/get.sh" >"$TMP/get.display"
[ -s "$TMP/install.display" ] || fail "install.sh display-version block is missing"
[ -s "$TMP/get.display" ] || fail "get.sh display-version block is missing"
cmp -s "$TMP/install.display" "$TMP/get.display" ||
	fail "install.sh and get.sh display-version resolvers drifted"

# ⚠ DISPLAY MUST NOT DECIDE WHAT GETS PULLED. The label is cosmetic; the
# release resolver is the sole authority for image tag and source commit.
grep -qE '^[[:space:]]*(VERSION|SOURCE_REF|SOURCE_COMMIT)=' "$TMP/get.display" &&
	fail "the display-version block assigns VERSION/SOURCE_REF/SOURCE_COMMIT — it must be display-only"

# And both installers must actually SHOW the human label rather than the raw image tag.
for installer in "$ROOT/deploy/install.sh" "$ROOT/deploy/get.sh"; do
	grep -Fq 'resolve_display_version' "$installer" ||
		fail "$(basename "$installer") never calls resolve_display_version"
	grep -Fq 'DISPLAY_VERSION' "$installer" ||
		fail "$(basename "$installer") never displays DISPLAY_VERSION"
done

die() {
	printf '%s\n' "$*" >&2
	exit 1
}

curl() {
	[ "${MOCK_CURL_MUST_NOT_RUN:-0}" = "0" ] || fail "resolver called the API for an explicit override"
	case "$2" in
	*/releases/latest) printf '%s' "${MOCK_LATEST_RELEASE:-}" ;;
	*/commits/*) printf '%s' "${MOCK_TAG_COMMIT:-}" ;;
	*) fail "unexpected resolver API URL '$2'" ;;
	esac
}

API="https://api.example.invalid/repos/tunnexio/tunnex"
# shellcheck disable=SC1090
. "$TMP/install.resolver"

resolve_result() {
	resolve_install_version
	printf '%s|%s|%s' "$VERSION" "$SOURCE_REF" "$VERSION_PROVENANCE"
}

SHA="b3c7bcd4895f31c63fe4b882a8cd622415b80ae4"
MOCK_LATEST_RELEASE='{"tag_name":"v1.2.3"}'
MOCK_TAG_COMMIT="{\"sha\":\"${SHA}\"}"
export MOCK_LATEST_RELEASE MOCK_TAG_COMMIT

actual="$(unset TUNNEX_VERSION TUNNEX_SOURCE_REF; resolve_result)"
expected="v1.2.3|${SHA}|latest published release v1.2.3 (${SHA})"
[ "$actual" = "$expected" ] || fail "latest-release resolution mismatch: got '$actual'"

actual="$(TUNNEX_VERSION=v1.2.3 resolve_result)"
[ "$actual" = "v1.2.3|${SHA}|operator override v1.2.3 (source ${SHA})" ] ||
	fail "release override mismatch: got '$actual'"

actual="$(TUNNEX_VERSION=v1.2.3 TUNNEX_SOURCE_REF="$SHA" MOCK_CURL_MUST_NOT_RUN=1 resolve_result)"
[ "$actual" = "v1.2.3|${SHA}|operator override v1.2.3 (source ${SHA})" ] ||
	fail "explicit release source override mismatch: got '$actual'"

actual="$(TUNNEX_VERSION=latest resolve_result)"
[ "$actual" = "$expected" ] ||
	fail "latest override must resolve the published release: got '$actual'"

actual="$(TUNNEX_VERSION=sha-b3c7bcd MOCK_CURL_MUST_NOT_RUN=1 resolve_result)"
[ "$actual" = "sha-b3c7bcd|b3c7bcd|operator override sha-b3c7bcd (manifest ref b3c7bcd)" ] ||
	fail "SHA override must remove the image-tag prefix for the Git ref: got '$actual'"

if output="$(MOCK_LATEST_RELEASE='{}' resolve_result 2>&1)"; then
	fail "an absent latest release silently selected a version"
fi
printf '%s' "$output" | grep -q 'Refusing to install an untagged build' ||
	fail "missing-release refusal did not name the forbidden untagged fallback"

for installer in "$ROOT/deploy/install.sh" "$ROOT/deploy/get.sh"; do
	grep -Fq '/releases/latest' "$installer" ||
		fail "$(basename "$installer") is not selecting GitHub's latest published release"
	grep -Fq '/commits/${VERSION}' "$installer" ||
		fail "$(basename "$installer") does not resolve the release tag to an exact source commit"
	grep -Fq '${RAW}/${SOURCE_REF}/deploy/tunnex.yml' "$installer" ||
		fail "$(basename "$installer") does not bind the compose manifest to the resolved source commit"
	grep -Fq 'RELEASE_DESCRIPTOR_TAG="$VERSION"' "$installer" ||
		fail "$(basename "$installer") does not bind descriptors to the semantic release tag"
	grep -Fq 'expected-source-sha "$SOURCE_REF"' "$installer" ||
		fail "$(basename "$installer") does not verify descriptor source SHA against SOURCE_REF"
	grep -Fq 'images pinned by digest' "$installer" ||
		fail "$(basename "$installer") does not surface digest pinning"
	grep -q '^TUNNEX_SOURCE_REF=${SOURCE_REF}$' "$installer" ||
		fail "$(basename "$installer") does not persist manifest provenance"
	grep -Fq 'compose -f tunnex.yml logs api' "$installer" ||
		fail "$(basename "$installer") does not surface the detached first-run API banner"
	grep -Fq 'TUNNEX - FIRST RUN' "$installer" ||
		fail "$(basename "$installer") does not extract the first-run banner"
	grep -Fq "grep -q 'password'" "$installer" ||
		fail "$(basename "$installer") does not detect the detached credential banner"
	grep -Fq 'BEGIN MASKED SECRET READER' "$installer" || fail "$(basename "$installer") lacks the masked secret reader"
	grep -Fq 'stty raw -echo' "$installer" || fail "$(basename "$installer") does not disable terminal echo safely"
	grep -Fq 'printf '\''*'\''' "$installer" || fail "$(basename "$installer") does not mask typed secret bytes"
	grep -Fq "printf '\\b \\b'" "$installer" || fail "$(basename "$installer") does not erase a mask on backspace"
	grep -Fq "printf '\\003'" "$installer" || fail "$(basename "$installer") does not handle Ctrl-C"
	grep -Fq "printf '\\177'" "$installer" || fail "$(basename "$installer") does not handle Delete"
	if ! grep -Fq 'secret input ended before Enter' "$installer" && ! grep -Fq 'no_tty_help' "$installer"; then
		fail "$(basename "$installer") lacks EOF handling"
	fi
	if grep -Fq 'SMTP_PASSWORD="$(ask ' "$installer"; then
		fail "$(basename "$installer") still reads SMTP passwords with visible line input"
	fi
done

grep -Fq 'DOCKER_METADATA_SHORT_SHA_LENGTH: "7"' "$ROOT/.github/workflows/ci.yml" ||
	fail "CI no longer pins the SHA abbreviation length consumed by installers"
grep -Fq 'gh release create "$RELEASE_TAG" --title "$RELEASE_TAG" --generate-notes --prerelease' "$ROOT/.github/workflows/ci.yml" ||
	fail "CI main-build releases can replace the public latest release"
grep -Fq 'gh release edit "$GITHUB_REF_NAME" --latest' "$ROOT/.github/workflows/ci.yml" ||
	fail "CI does not explicitly mark a completed versioned release as latest"
grep -Fq 'type=sha,format=short,prefix=sha-,enable={{is_default_branch}}' "$ROOT/.github/workflows/ci.yml" ||
	fail "CI image tag naming drifted from installer resolution"

# Organization migration contract: every active installation and enrollment surface must pull
# from the organization-owned GHCR namespace. Historical walk records are intentionally excluded.
for image_surface in \
	"$ROOT/deploy/get.sh" \
	"$ROOT/deploy/install.sh" \
	"$ROOT/deploy/tunnex.yml" \
	"$ROOT/deploy/helm/tunnex-cp/values.yaml" \
	"$ROOT/deploy/helm/tunnex-gateway/values.yaml" \
	"$ROOT/apps/api/cmd/releaseverify/main.go" \
	"$ROOT/apps/api/internal/config/config.go" \
	"$ROOT/apps/web/src/components/Gateways.tsx"; do
	if grep -Fq 'ghcr.io/iotunnex' "$image_surface"; then
		fail "$(basename "$image_surface") still points at the retired personal GHCR namespace"
	fi
	grep -Fq 'ghcr.io/tunnexio' "$image_surface" ||
		fail "$(basename "$image_surface") does not point at the organization GHCR namespace"
done

# Bootstrap inputs are written by both installers and must reach the API container. Keep this as a
# contract test at the distribution boundary: a value present in .env but absent from compose silently
# reverts first boot to admin@tunnex.local or disables SMTP, which is only discovered after the container
# has already created its one-time credential.
for variable in TUNNEX_ADMIN_EMAIL SMTP_HOST SMTP_PORT SMTP_FROM SMTP_USERNAME SMTP_PASSWORD TUNNEX_RELEASE_MANIFEST_PATH TUNNEX_RELEASE_PUBLIC_KEY TUNNEX_RELEASE_SEQUENCE TUNNEX_RELEASE_VERSION TUNNEX_RELEASE_SOURCE_SHA TUNNEX_RELEASE_CATALOG_URL TUNNEX_RELEASE_UPDATE_CHECK; do
	grep -Fq "      ${variable}: \${${variable}" "$ROOT/deploy/tunnex.yml" ||
		fail "deploy/tunnex.yml does not forward ${variable} to the API container"
done

for service in API WEB NGINX NODE_AGENT; do
	grep -Fq "\${TUNNEX_${service}_IMAGE:-" "$ROOT/deploy/tunnex.yml" ||
		fail "deploy/tunnex.yml does not support a verified ${service} digest pin"
done
grep -Fq './release.json:/var/lib/tunnex/release.json:ro' "$ROOT/deploy/tunnex.yml" ||
	fail "deploy/tunnex.yml does not mount the signed descriptor read-only"

printf 'installer provenance contract: PASS\n'
