#!/bin/sh
# Behavioural contract for the public bootstrap and canonical installer. No
# network, Docker, or root required.
set -eu

ROOT="$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT HUP INT TERM

fail() {
	printf 'installer provenance test: %s\n' "$*" >&2
	exit 1
}

# get.tunnex.io is intentionally a launcher, not a second full installer.
# The site is synced asynchronously, so it must delegate to the canonical
# implementation that owns TLS and compose environment variables.
grep -Fq "CANONICAL_INSTALLER_URL='https://raw.githubusercontent.com/tunnexio/tunnex/main/deploy/install.sh'" "$ROOT/deploy/get.sh" ||
	fail "get.sh does not use the canonical installer"
grep -Fq 'sh "$installer" "$@"' "$ROOT/deploy/get.sh" ||
	fail "get.sh does not preserve caller arguments when it delegates"
if grep -Fq 'compose -f' "$ROOT/deploy/get.sh" || grep -Fq 'TUNNEX_EDGE_LISTEN=' "$ROOT/deploy/get.sh"; then
	fail "get.sh regained installer/compose implementation that can drift"
fi

mkdir -p "$TMP/bin" "$TMP/scratch"
cat >"$TMP/bin/curl" <<'EOF'
#!/bin/sh
set -eu
out=''
while [ "$#" -gt 0 ]; do
	case "$1" in
	-o) out=$2; shift 2 ;;
	https://raw.githubusercontent.com/tunnexio/tunnex/main/deploy/install.sh)
		printf '%s\n' "$1" >"$MOCK_CURL_RECORD"
		shift
		;;
	*) shift ;;
	esac
done
[ -n "$out" ]
cat >"$out" <<'SCRIPT'
#!/bin/sh
printf '%s|%s\n' "${TUNNEX_PUBLIC_BASE_URL:-}" "${1:-}" >"$MOCK_CHILD_RECORD"
SCRIPT
EOF
chmod 755 "$TMP/bin/curl"
MOCK_CURL_RECORD="$TMP/curl-url" MOCK_CHILD_RECORD="$TMP/child" \
	TUNNEX_PUBLIC_BASE_URL='https://vpn.acme.com' TMPDIR="$TMP/scratch" PATH="$TMP/bin:$PATH" \
	"$ROOT/deploy/get.sh" --yes
[ "$(cat "$TMP/curl-url")" = 'https://raw.githubusercontent.com/tunnexio/tunnex/main/deploy/install.sh' ] ||
	fail "bootstrap fetched an unexpected installer URL"
[ "$(cat "$TMP/child")" = 'https://vpn.acme.com|--yes' ] ||
	fail "bootstrap lost environment or arguments"
[ -z "$(find "$TMP/scratch" -type f -print -quit)" ] ||
	fail "bootstrap left its downloaded installer on disk"

extract_resolver() {
	sed -n '/^# BEGIN INSTALL VERSION RESOLVER/,/^# END INSTALL VERSION RESOLVER/p' "$1"
}
extract_resolver "$ROOT/deploy/install.sh" >"$TMP/install.resolver"
[ -s "$TMP/install.resolver" ] || fail "install.sh resolver block is missing"

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

actual="$(TUNNEX_VERSION=v1.2.3 TUNNEX_SOURCE_REF="$SHA" MOCK_CURL_MUST_NOT_RUN=1 resolve_result)"
[ "$actual" = "v1.2.3|${SHA}|operator override v1.2.3 (source ${SHA})" ] ||
	fail "explicit release source override mismatch: got '$actual'"

for required in \
	'/releases/latest' \
	'/commits/${VERSION}' \
	'${RAW}/${SOURCE_REF}/deploy/tunnex.yml' \
	'${RAW}/${SOURCE_REF}/deploy/upgrade.sh' \
	'${RAW}/${SOURCE_REF}/deploy/upgrade-runner.sh' \
	'sh -n upgrade.sh.next' \
	'sh -n upgrade-runner.sh.next' \
	'chmod 0755 upgrade.sh' \
	'chmod 0755 upgrade-runner.sh' \
	'systemctl enable --now tunnex-upgrade-runner.path' \
	'TUNNEX_COMPOSE_SHA256=$(file_sha256 tunnex.yml)' \
	'RELEASE_DESCRIPTOR_TAG="$VERSION"' \
	'expected-source-sha "$SOURCE_REF"' \
	'images pinned by digest' \
	'TUNNEX_EDGE_LISTEN=${EDGE_LISTEN}' \
	'TUNNEX_TLS_MODE=${TLS_MODE}' \
	'BEGIN MASKED SECRET READER'; do
	grep -Fq "$required" "$ROOT/deploy/install.sh" ||
		fail "canonical installer lacks required contract: $required"
done

grep -Fq 'DOCKER_METADATA_SHORT_SHA_LENGTH: "7"' "$ROOT/.github/workflows/ci.yml" ||
	fail "CI no longer pins the SHA abbreviation length consumed by installers"
grep -Fq 'gh release edit "$GITHUB_REF_NAME" --latest' "$ROOT/.github/workflows/ci.yml" ||
	fail "CI does not explicitly mark a completed versioned release as latest"

for variable in TUNNEX_ADMIN_EMAIL SMTP_HOST SMTP_PORT SMTP_FROM SMTP_USERNAME SMTP_PASSWORD TUNNEX_EDGE_LISTEN TUNNEX_COOKIE_SECURE; do
	grep -Fq "\${${variable}" "$ROOT/deploy/tunnex.yml" ||
		fail "deploy/tunnex.yml does not consume ${variable}"
done
grep -Fq './upgrade-state/requests:/var/lib/tunnex/upgrade/requests' "$ROOT/deploy/tunnex.yml" ||
	fail "compose does not mount the bounded upgrade request directory"
grep -Fq './upgrade-state/status:/var/lib/tunnex/upgrade/status:ro' "$ROOT/deploy/tunnex.yml" ||
	fail "compose does not mount upgrade status read-only"

printf 'installer provenance contract: PASS\n'
