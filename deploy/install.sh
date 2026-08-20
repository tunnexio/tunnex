#!/bin/sh
# Tunnex.io — zero-build installer (S6.6). ONE script, safe to pipe blind into a root shell.
#
#   Convenience (one-liner):
#     curl -fsSL https://raw.githubusercontent.com/tunnexio/tunnex/main/deploy/install.sh | sh
#
#   Security-conscious (download, verify, inspect, then run — the recommended default):
#     curl -fsSL <url>/install.sh -o install.sh
#     curl -fsSL <url>/install.sh.sha256 -o install.sh.sha256 && sha256sum -c install.sh.sha256
#     less install.sh
#     sudo sh install.sh
#
# Brings up a working Tunnex deployment from PREBUILT images — no source build, no file edits.
# Prerequisite: any host with Docker Engine + the Compose v2 plugin AND a public address (a DNS name
# or public IP users + gateways can reach). It installs the SOFTWARE; it does not conjure the server.
#
# Non-interactive / piped-with-no-terminal: set the inputs as env vars so the pipe still works:
#     curl -fsSL <url> | TUNNEX_PUBLIC_BASE_URL=https://vpn.acme.com TUNNEX_ADMIN_EMAIL=owner@example.com TUNNEX_SMTP=skip sh
# For SMTP=configure non-interactively, also export SMTP_HOST/SMTP_PORT/SMTP_USERNAME/SMTP_PASSWORD/SMTP_FROM.
#
# Idempotent: re-running against an existing ./tunnex REUSES the generated DB password (a fresh one
# would not match the existing postgres volume) and never leaves a half-written .env (write-then-move).
set -eu

REPO="tunnexio/tunnex"
RAW="https://raw.githubusercontent.com/${REPO}"
API="https://api.github.com/repos/${REPO}"
DIR="${TUNNEX_DIR:-tunnex}"
# Trusted release verification key. The matching private signing key remains in CI only.
TRUSTED_RELEASE_PUBLIC_KEY=b48ff99923c43052ade580cdca63952690f07f08372c35814baa44cb84d674a0

say() { printf '%s\n' "$*"; }
die() { printf 'error: %s\n' "$*" >&2; exit 1; }

# BEGIN INSTALL VERSION RESOLVER — kept byte-identical in install.sh and get.sh; the regression test
# extracts this block from both files and refuses drift.
resolve_install_version() {
	VERSION="${TUNNEX_VERSION:-}"
	SOURCE_REF="${TUNNEX_SOURCE_REF:-}"
	SOURCE_COMMIT=""
	VERSION_PROVENANCE=""

	# Customers install releases, never an arbitrary successful main build. The
	# GitHub release is the mutable discovery pointer; its tag plus the resolved
	# commit are then checked against the signed descriptor before anything runs.
	if [ -z "$VERSION" ] || [ "$VERSION" = "latest" ]; then
		_release="$(curl -fsSL "${API}/releases/latest" 2>/dev/null || true)"
		VERSION="$(printf '%s' "$_release" |
			sed -n 's/.*"tag_name"[[:space:]]*:[[:space:]]*"\(v[0-9][^"]*\)".*/\1/p' |
			head -1)"
		[ -n "$VERSION" ] || die "could not resolve the latest published Tunnex release. Refusing to install an untagged build."
		SOURCE_REF=""
		VERSION_PROVENANCE="latest published release ${VERSION}"
	fi

	case "$VERSION" in
	v*)
		# `releases/latest` identifies the customer-facing tag, while the commit
		# endpoint resolves annotated and lightweight tags to the exact immutable
		# source SHA that releaseverify expects.
		if [ -z "$SOURCE_REF" ]; then
			_commit="$(curl -fsSL "${API}/commits/${VERSION}" 2>/dev/null || true)"
			SOURCE_REF="$(printf '%s' "$_commit" |
				sed -n 's/.*"sha"[[:space:]]*:[[:space:]]*"\([0-9a-f]\{40\}\)".*/\1/p' |
				head -1)"
			[ -n "$SOURCE_REF" ] || die "could not resolve the exact source commit for release ${VERSION}."
		fi
		SOURCE_COMMIT="$SOURCE_REF"
		case "$VERSION_PROVENANCE" in
		"latest published release "*) VERSION_PROVENANCE="${VERSION_PROVENANCE} (${SOURCE_REF})" ;;
		*) VERSION_PROVENANCE="operator override ${VERSION} (source ${SOURCE_REF})" ;;
		esac
		;;
	*)
		case "$VERSION" in
		sha-*)
			# Docker's sha-* image tag is not a Git ref; raw.githubusercontent.com accepts the abbreviated
			# commit after the prefix is removed. TUNNEX_SOURCE_REF remains available for an explicit full SHA.
			SOURCE_REF="${SOURCE_REF:-${VERSION#sha-}}"
			;;
		*)
			SOURCE_REF="${SOURCE_REF:-$VERSION}"
			;;
		esac
		VERSION_PROVENANCE="operator override ${VERSION} (manifest ref ${SOURCE_REF})"
		;;
	esac

	case "$VERSION" in '' | *[!A-Za-z0-9._-]*) die "resolved image tag '${VERSION}' contains unsupported characters" ;; esac
	case "$SOURCE_REF" in '' | *[!A-Za-z0-9._/-]*) die "resolved manifest ref '${SOURCE_REF}' contains unsupported characters" ;; esac
}
# END INSTALL VERSION RESOLVER

# BEGIN DISPLAY VERSION RESOLVER — kept byte-identical in install.sh and get.sh; the regression test
# asserts they have not drifted, the same guard the version resolver above carries.
# The install resolver already selects a semantic release tag. Keep this tiny
# display seam so both installer entry points remain structurally identical.
resolve_display_version() {
	DISPLAY_VERSION="$VERSION"
}
# END DISPLAY VERSION RESOLVER

# have_tty: can we read from the controlling terminal? True under `curl | sh` on a real terminal
# (stdin is the pipe, but /dev/tty is the keyboard); false in CI / fully-detached pipes.
have_tty() { [ -e /dev/tty ] && { true </dev/tty; } 2>/dev/null; }
# ask reads from the TERMINAL even under `curl | sh`.
ask() {
	printf '%s' "$1" >/dev/tty
	IFS= read -r reply </dev/tty || die "no input on the terminal"
	printf '%s' "$reply"
}
# BEGIN MASKED SECRET READER — kept behaviorally identical with get.sh; the contract test checks both.
# ask_secret PROMPT — masked raw terminal input. Sets ANSWER while never echoing the secret itself.
# Non-interactive callers must provide SMTP_PASSWORD through the environment; there is no stdin fallback.
ask_secret() {
	_prompt="$1"
	if ! have_tty; then ANSWER=""; return 0; fi
	_saved="$(stty -g </dev/tty 2>/dev/null || true)"
	[ -n "$_saved" ] || die "could not configure the terminal for secret input"
	trap "stty '$_saved' </dev/tty 2>/dev/null || stty echo </dev/tty 2>/dev/null; exit 130" INT TERM
	stty raw -echo </dev/tty 2>/dev/null || { stty "$_saved" </dev/tty 2>/dev/null || true; die "could not disable terminal echo for secret input"; }
	printf '%s ' "$_prompt" >/dev/tty
	_secret=''
	while :; do
		_byte="$(dd if=/dev/tty bs=1 count=1 2>/dev/null || true)"
		[ -n "$_byte" ] || { stty "$_saved" </dev/tty 2>/dev/null || true; trap - INT TERM; die "secret input ended before Enter"; }
		case "$_byte" in
		"$(printf '\r')" | "$(printf '\n')") break ;;
		"$(printf '\003')") stty "$_saved" </dev/tty 2>/dev/null || true; trap - INT TERM; exit 130 ;;
		"$(printf '\177')" | "$(printf '\010')")
			if [ -n "$_secret" ]; then _secret="${_secret%?}"; printf '\b \b' >/dev/tty; fi
			;;
		*) _secret="${_secret}${_byte}"; printf '*' >/dev/tty ;;
		esac
	done
	stty "$_saved" </dev/tty 2>/dev/null || stty echo </dev/tty 2>/dev/null || true
	trap - INT TERM
	printf '\n' >/dev/tty
	ANSWER="$_secret"
}
# END MASKED SECRET READER
# A public base URL is the authoritative origin for email links and SSO callbacks. Keep the
# scheme the operator supplied; silently prepending http breaks HTTPS-only identity providers.
public_base_url_ok() {
	case "$1" in http://* | https://*) ;; *) return 1 ;; esac
	_authority=${1#*://}
	case "$_authority" in '' | */* | *\?* | *\#* | *@* | *[[:space:]]*) return 1 ;; esac
	case "$_authority" in *[![:alnum:].:\[\]-]*) return 1 ;; esac
	case "$_authority" in localhost | localhost:* | 127.* | 127.*:* | ::1 | \[::1\] | 0.0.0.0 | 0.0.0.0:*) return 1 ;; esac
	return 0
}
public_base_url_host() {
	_authority=${1#*://}
	case "$_authority" in
	\[*\]*) _host=${_authority%%]*}; printf '%s]\n' "$_host" ;;
	*) printf '%s\n' "${_authority%%:*}" ;;
	esac
}
public_base_url_scheme() {
	case "$1" in https://*) printf '%s\n' https ;; http://*) printf '%s\n' http ;; *) return 1 ;; esac
}
public_base_url_is_ip() {
	_host="$(public_base_url_host "$1")"
	case "$_host" in
	\[*:*\]) return 0 ;;
	*.*.*.*) case "$_host" in *[!0-9.]* | .* | *.) return 1 ;; esac; return 0 ;;
	esac
	return 1
}
public_base_url_port() {
	_authority=${1#*://}
	case "$_authority" in
	\[*\]:*) printf '%s\n' "${_authority##*:}" ;;
	\[*\]) printf '%s\n' "" ;;
	*:* ) printf '%s\n' "${_authority##*:}" ;;
	*) printf '%s\n' "" ;;
	esac
}
tls_mode_ok() {
	case "$1" in direct | terminated | http) return 0 ;; *) return 1 ;; esac
}
public_base_url_tls_mode_ok() {
	_mode=$1
	_url=$2
	_scheme="$(public_base_url_scheme "$_url")" || return 1
	_port="$(public_base_url_port "$_url")"
	case "$_mode" in
	direct)
		[ "$_scheme" = https ] && public_base_url_is_ip "$_url" && return 1
		case "$_scheme:$_port" in https:|https:443|http:|http:80) return 0 ;; esac
		;;
	terminated) [ "$_scheme" = https ] && return 0 ;;
	http) case "$_scheme:$_port" in http:|http:80) return 0 ;; esac ;;
	esac
	return 1
}
select_tls_mode() {
	TLS_MODE="${TUNNEX_TLS_MODE:-}"
	SCHEME="$(public_base_url_scheme "$BASE_URL")"
	if [ -z "$TLS_MODE" ]; then
		if [ "$SCHEME" = https ]; then
			if have_tty; then
				TLS_MODE="$(ask 'TLS mode [direct (this VM) / terminated (external load balancer)] [direct]: ')"
				[ -n "$TLS_MODE" ] || TLS_MODE=direct
			else
				TLS_MODE=direct
			fi
		else
			TLS_MODE=http
		fi
	fi
	tls_mode_ok "$TLS_MODE" || die "TUNNEX_TLS_MODE must be direct, terminated, or http."
	public_base_url_tls_mode_ok "$TLS_MODE" "$BASE_URL" ||
		die "${BASE_URL} is incompatible with TLS mode ${TLS_MODE}. Direct HTTPS needs a DNS hostname on port 443; use http://<public-IP> for plain HTTP or TUNNEX_TLS_MODE=terminated behind an external TLS endpoint."
	case "$TLS_MODE" in direct) EDGE_LISTEN="$BASE_URL" ;; *) EDGE_LISTEN="http://:80" ;; esac
	[ "$SCHEME" = https ] && COOKIE_SECURE=true || COOKIE_SECURE=false
}

# ── 0. prerequisites — fail LOUD + actionable ────────────────────────────────────────────────────
command -v docker >/dev/null 2>&1 || die "Docker is required. Install Docker Engine + the Compose plugin (https://docs.docker.com/engine/install/), then re-run."
docker compose version >/dev/null 2>&1 || die "The Docker Compose v2 plugin is required (\`docker compose version\` must work)."
command -v curl >/dev/null 2>&1 || die "curl is required."
command -v openssl >/dev/null 2>&1 || die "openssl is required (secret generation)."

# ── 1. resolve the newest published semantic release ────────────────────────────────────────────
resolve_install_version
resolve_display_version
say ">> Installing Tunnex ${DISPLAY_VERSION} (image tag ${VERSION})"
say ">> Provenance: ${VERSION_PROVENANCE}"

# ── 2. public address — env override OR prompt; loopback refused at the SOURCE (both paths) ───────
BASE_URL="${TUNNEX_PUBLIC_BASE_URL:-${TUNNEX_PUBLIC_ADDR:-}}"
if [ -n "$BASE_URL" ]; then
	public_base_url_ok "$BASE_URL" || die "TUNNEX_PUBLIC_BASE_URL='${BASE_URL}' is not a usable public URL. Set an http:// or https:// URL with no path, credentials, or query (for example, https://vpn.acme.com)."
elif have_tty; then
	while :; do
		BASE_URL="$(ask 'Public base URL your users + gateways reach (including http:// or https://, e.g. https://vpn.acme.com): ')"
		if public_base_url_ok "$BASE_URL"; then break; fi
		say "!! '${BASE_URL}' is not a usable public URL. Include http:// or https://, with no path, credentials, or query."
	done
else
	die "no terminal to prompt on. Re-run non-interactively with the URL set, e.g.:
    curl -fsSL ${RAW}/main/deploy/install.sh | TUNNEX_PUBLIC_BASE_URL=https://vpn.acme.com TUNNEX_SMTP=skip sh"
fi
ADDR="$(public_base_url_host "$BASE_URL")"
select_tls_mode

ADMIN_EMAIL="${TUNNEX_ADMIN_EMAIL:-admin@${ADDR}}"
if have_tty && [ -z "${TUNNEX_ADMIN_EMAIL:-}" ]; then
	ADMIN_EMAIL="$(ask "Administrator email [${ADMIN_EMAIL}]: ")"
	[ -n "$ADMIN_EMAIL" ] || ADMIN_EMAIL="admin@${ADDR}"
fi
case "$ADMIN_EMAIL" in
	'' | *[!A-Za-z0-9@._%+-]* | *@*@*) die "TUNNEX_ADMIN_EMAIL must be a valid single email address (got '${ADMIN_EMAIL}')" ;;
	*@*) : ;;
	*) die "TUNNEX_ADMIN_EMAIL must be an email address (got '${ADMIN_EMAIL}')" ;;
esac

# ── 3. SMTP — env override (skip|configure) OR prompt; default when non-interactive = skip ───────
SMTP_HOST="${SMTP_HOST:-}"
SMTP_PORT="${SMTP_PORT:-}"
SMTP_FROM="${SMTP_FROM:-}"
SMTP_USERNAME="${SMTP_USERNAME:-}"
SMTP_PASSWORD="${SMTP_PASSWORD:-}"
SMTP_MODE="${TUNNEX_SMTP:-}"
if [ -z "$SMTP_MODE" ]; then
	if have_tty; then
		case "$(ask 'Configure SMTP now for email (verify / reset / invite)? [y/N]: ')" in
		y | Y | yes | YES) SMTP_MODE=configure ;;
		*) SMTP_MODE=skip ;;
		esac
	else
		SMTP_MODE=skip # non-interactive default: email disabled (local sign-in still works)
	fi
fi
case "$SMTP_MODE" in
configure)
	if have_tty; then
		[ -n "$SMTP_HOST" ] || SMTP_HOST="$(ask '  SMTP host: ')"
		[ -n "$SMTP_PORT" ] || SMTP_PORT="$(ask '  SMTP port [587]: ')"
		[ -n "$SMTP_USERNAME" ] || SMTP_USERNAME="$(ask '  SMTP username: ')"
		[ -n "$SMTP_PASSWORD" ] || { ask_secret '  SMTP password:'; SMTP_PASSWORD="$ANSWER"; }
		[ -n "$SMTP_FROM" ] || SMTP_FROM="$(ask "  From address [no-reply@${ADDR}]: ")"
	fi
	SMTP_PORT="${SMTP_PORT:-587}"
	SMTP_FROM="${SMTP_FROM:-no-reply@${ADDR}}"
	[ -n "$SMTP_HOST" ] || die "TUNNEX_SMTP=configure but SMTP_HOST is not set (export SMTP_HOST/SMTP_USERNAME/SMTP_PASSWORD for a non-interactive run)."
	;;
skip)
	say ">> ⛔ SMTP SKIPPED — NOBODY CAN BE INVITED TO THIS DEPLOYMENT."
	say "   Invitations are the only way people join, and they are delivered by email. Password resets"
	say "   and address verification need it too. You can still sign in as the administrator, and the"
	say "   dashboard shows a copyable invitation link you can send by hand."
	say "   Enable it later: set SMTP_HOST/SMTP_PORT/SMTP_FROM (and SMTP_USERNAME/SMTP_PASSWORD if your"
	say "   provider needs auth) in .env, then \`docker compose -f tunnex.yml up -d api\`."
	;;
*)
	die "TUNNEX_SMTP must be 'skip' or 'configure' (got '${SMTP_MODE}')."
	;;
esac

# ── 4. workspace + the VERSIONED compose (matches the pinned images) ─────────────────────────────
mkdir -p "$DIR"
cd "$DIR"
trap 'rm -f .env.new tunnex.yml.next upgrade.sh.next release.json.next 2>/dev/null' EXIT # never leave a half-written managed file behind on failure

# Fetch the complete host payload before replacing any managed file. The UI's
# upgrade command is not usable when upgrade.sh is absent, so a partial download
# must fail the install rather than leave a control plane that only looks ready.
curl -fsSL "${RAW}/${SOURCE_REF}/deploy/tunnex.yml" -o tunnex.yml.next || die "could not download deploy/tunnex.yml at ${SOURCE_REF}"
curl -fsSL "${RAW}/${SOURCE_REF}/deploy/upgrade.sh" -o upgrade.sh.next || die "could not download deploy/upgrade.sh at ${SOURCE_REF}"
sh -n upgrade.sh.next || die "downloaded deploy/upgrade.sh is not valid shell"

# Published releases carry a signed descriptor. Bind its semantic release tag
# to the exact resolved source commit before starting any image.
case "$VERSION" in
	v*) RELEASE_DESCRIPTOR_TAG="$VERSION" ;;
	sha-*) RELEASE_DESCRIPTOR_TAG="tunnex-build-${SOURCE_REF}" ;;
	*) die "a signed release descriptor is required for version ${VERSION}" ;;
esac
RELEASE_MANIFEST_URL="${TUNNEX_RELEASE_MANIFEST_URL:-https://github.com/tunnexio/tunnex/releases/download/${RELEASE_DESCRIPTOR_TAG}/release.json}"
curl -fsSL "$RELEASE_MANIFEST_URL" -o release.json.next || die "could not download the signed release manifest for ${SOURCE_REF}; refusing an unverifiable install"
mv tunnex.yml.next tunnex.yml
mv upgrade.sh.next upgrade.sh
chmod 0755 upgrade.sh
mv release.json.next release.json
# Signed release metadata is mounted into the unprivileged API container. It is not
# secret, so keep it world-readable while the bind mount itself stays read-only.
chmod 0644 release.json
RELEASE_MANIFEST_PATH="/var/lib/tunnex/release.json"
TUNNEX_RELEASE_PUBLIC_KEY="${TUNNEX_RELEASE_PUBLIC_KEY:-$TRUSTED_RELEASE_PUBLIC_KEY}"

# ── 5. secrets — REUSE the existing DB password on a re-run (a new one won't match the volume) ────
PG_PASS=""
if [ -f .env ]; then
	PG_PASS="$(sed -n 's/^POSTGRES_PASSWORD=//p' .env | head -1)"
	[ -n "$PG_PASS" ] && say ">> Reusing the existing database password (idempotent re-run)."
fi
[ -n "$PG_PASS" ] || PG_PASS="$(openssl rand -hex 24)"

# ── 6. write a CLEAN .env (write the WHOLE file — NEVER append; duplicate keys make compose ──────
#      silently use the FIRST value — the trap that bit the POC). Back up any existing one. ────────
if [ -f .env ]; then
	cp .env ".env.bak.$(date +%Y%m%d%H%M%S)"
	say ">> Backed up your existing .env"
fi
umask 077
cat >.env.new <<EOF
# Tunnex deployment config — generated by install.sh. Safe to edit these values; do NOT hand-edit
# tunnex.yml. Upgrade: bump TUNNEX_VERSION to a newer release tag, then \`docker compose -f tunnex.yml pull && up -d\`.
TUNNEX_VERSION=${VERSION}
# Exact Git ref the installer used for tunnex.yml; image tag + manifest provenance stay inspectable.
TUNNEX_SOURCE_REF=${SOURCE_REF}
TUNNEX_RELEASE_MANIFEST_PATH=${RELEASE_MANIFEST_PATH}
TUNNEX_RELEASE_PUBLIC_KEY=${TUNNEX_RELEASE_PUBLIC_KEY:-$TRUSTED_RELEASE_PUBLIC_KEY}
TUNNEX_RELEASE_KEY_ID=release-2026-08-01
TUNNEX_RELEASE_CATALOG_URL=${TUNNEX_RELEASE_CATALOG_URL:-https://github.com/tunnexio/tunnex/releases/download/tunnex-updates/release.json}
TUNNEX_RELEASE_UPDATE_CHECK=${TUNNEX_RELEASE_UPDATE_CHECK:-true}
TUNNEX_LOG_LEVEL=info
APP_BASE_URL=${BASE_URL}
TUNNEX_TLS_MODE=${TLS_MODE}
TUNNEX_EDGE_LISTEN=${EDGE_LISTEN}
TUNNEX_COOKIE_SECURE=${COOKIE_SECURE}
TUNNEX_NODE_ENDPOINT=${ADDR}:51820
POSTGRES_USER=tunnex
POSTGRES_PASSWORD=${PG_PASS}
POSTGRES_DB=tunnex
DATABASE_URL=postgres://tunnex:${PG_PASS}@postgres:5432/tunnex?sslmode=disable
REDIS_URL=redis://redis:6379/0
SMTP_HOST=${SMTP_HOST}
SMTP_PORT=${SMTP_PORT}
SMTP_FROM=${SMTP_FROM}
SMTP_USERNAME=${SMTP_USERNAME}
SMTP_PASSWORD=${SMTP_PASSWORD}
TUNNEX_ADMIN_EMAIL=${ADMIN_EMAIL}
EOF
mv .env.new .env # atomic swap — the .env is never observed half-written

# ── 7. pull + start ─────────────────────────────────────────────────────────────────────────────
say ">> Pulling images and verifying the signed release…"
docker compose -f tunnex.yml pull
case "$(docker version --format '{{.Server.Arch}}' 2>/dev/null || true)" in
	amd64|x86_64) RELEASE_ARCH=amd64 ;;
	arm64|aarch64) RELEASE_ARCH=arm64 ;;
	*) die "could not determine a supported Docker server architecture for release verification" ;;
esac
if ! RELEASE_ENV="$(docker run --rm --entrypoint releaseverify \
	-v "$PWD/release.json:/tmp/release.json:ro" \
	"ghcr.io/tunnexio/tunnex-api:${VERSION}" \
	-manifest /tmp/release.json -public-key "$TUNNEX_RELEASE_PUBLIC_KEY" \
	-expected-source-sha "$SOURCE_REF" -platform "$RELEASE_ARCH" -print-env)"; then
	die "signed release verification failed; refusing to start images from an unverifiable release"
fi
for RELEASE_KEY in TUNNEX_API_IMAGE TUNNEX_WEB_IMAGE TUNNEX_NGINX_IMAGE TUNNEX_NODE_AGENT_IMAGE TUNNEX_MIGRATE_IMAGE TUNNEX_RELEASE_SEQUENCE TUNNEX_RELEASE_VERSION TUNNEX_RELEASE_SOURCE_SHA; do
	RELEASE_VALUE="$(printf '%s\n' "$RELEASE_ENV" | sed -n "s/^${RELEASE_KEY}=//p" | head -1)"
	[ -n "$RELEASE_VALUE" ] || die "signed release verifier omitted ${RELEASE_KEY}"
	printf '%s=%s\n' "$RELEASE_KEY" "$RELEASE_VALUE" >>.env
done
docker compose -f tunnex.yml pull
say ">> Signed release verified; images pinned by digest. Starting the stack…"
docker compose -f tunnex.yml up -d --wait

# The API prints the one-time credential to stdout. Surface that banner here because `up -d` is detached;
# operators should not need to search container logs, and the API will also email it when SMTP is configured.
CREDS="$(docker compose -f tunnex.yml logs api 2>/dev/null | sed -n '/TUNNEX - FIRST RUN/,/^.*=\{20,\}$/p' | tail -n +2 || true)"
if printf '%s' "$CREDS" | grep -q 'password'; then
	say ''
	say 'Your administrator credential (shown once):'
	say "$CREDS"
fi

# ── 8. NEXT STEPS (the customer's first experience — a real hand-off, not an echo) ───────────────
say ''
say '════════════════════════════════════════════════════════════════════════════'
say " Tunnex ${VERSION} is running."
say ''
say "   1. Open the dashboard:   ${BASE_URL}/"
say "   2. Sign in as ${ADMIN_EMAIL}; set the one-time password to your own password."
say '   3. Create your first organization.'
say '   4. Enroll a gateway:     Dashboard → Gateways → “Generate join token”.'
say '      Copy the ONE command it shows and run it in this folder to bring the'
say '      gateway online (it re-creates the node-agent with your join token).'
say ''
say "   Config:   $(pwd)/.env       (edit values here; never hand-edit tunnex.yml)"
say '   Upgrade:  set TUNNEX_VERSION to a newer tag in .env, then:'
say '             docker compose -f tunnex.yml pull && docker compose -f tunnex.yml up -d'
say '════════════════════════════════════════════════════════════════════════════'
