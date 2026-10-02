#!/bin/sh
# Focused contract for the fresh-host one-command installer. The full installer
# runs against command stubs, so this proves presentation, mutation ordering,
# Docker bootstrap, release verification, and Compose hand-off without changing
# the developer machine.
set -eu

ROOT=$(CDPATH= cd -- "$(dirname "$0")/.." && pwd)
INSTALLER="$ROOT/deploy/install.sh"
PYTHON3=$(command -v python3 || true)
[ -n "$PYTHON3" ] || { printf 'install host bootstrap contract: FAIL: python3 is required for the pseudo-terminal walkthrough\n' >&2; exit 1; }
TMP=$(mktemp -d "${TMPDIR:-/tmp}/tunnex-install-host-test.XXXXXX")
trap 'rm -rf "$TMP"' EXIT INT TERM
BIN="$TMP/bin"
mkdir -p "$BIN"

fail() {
	printf 'install host bootstrap contract: FAIL: %s\n' "$*" >&2
	exit 1
}

cat >"$TMP/os-release" <<'EOF'
ID=ubuntu
VERSION_CODENAME=noble
EOF

cat >"$BIN/uname" <<'EOF'
#!/bin/sh
printf 'Linux\n'
EOF
cat >"$BIN/id" <<'EOF'
#!/bin/sh
case "${1:-}" in
-u) printf '0\n' ;;
-un) printf 'root\n' ;;
-nG) printf 'root\n' ;;
*) printf 'uid=0(root) gid=0(root) groups=0(root)\n' ;;
esac
EOF
cat >"$BIN/dpkg" <<'EOF'
#!/bin/sh
printf 'amd64\n'
EOF
# GitHub runners already include Docker under /usr/bin. Give installer
# subprocesses a small, explicit system-tool path instead, so this fixture can
# truthfully model a host with no Docker CLI until apt installs the test double.
SYSTEM_BIN="$TMP/system-bin"
mkdir -p "$SYSTEM_BIN"
for tool in awk basename cat chmod cp cut date dd dirname env grep head mkdir mktemp mv openssl rm sed sh shasum sleep sort stty tail tr; do
	tool_path=$(command -v "$tool" || true)
	[ -n "$tool_path" ] && ln -s "$tool_path" "$SYSTEM_BIN/$tool"
done
TEST_PATH="$BIN:$SYSTEM_BIN"
cat >"$BIN/install" <<'EOF'
#!/bin/sh
# Package-repository writes are intentionally absorbed by this disposable stub.
exit 0
EOF
cat >"$BIN/curl" <<'EOF'
#!/bin/sh
out=''
url=''
while [ "$#" -gt 0 ]; do
	case "$1" in
	-o) out=$2; shift 2 ;;
	-*) shift ;;
	*) url=$1; shift ;;
	esac
done
[ -n "$out" ] || exit 2
case "$url" in
*download.docker.com/*/gpg) printf 'test docker key\n' >"$out" ;;
*/deploy/tunnex.yml)
	cat >"$out" <<'YAML'
services:
  api:
    image: ${TUNNEX_API_IMAGE}
    environment:
      TUNNEX_DATABASE_URL: ${TUNNEX_DATABASE_URL:-}
      TUNNEX_BOOTSTRAP_ORG_NAME: ${TUNNEX_BOOTSTRAP_ORG_NAME:-}
      TUNNEX_BOOTSTRAP_GATEWAY_TOKEN_SHA256: ${TUNNEX_BOOTSTRAP_GATEWAY_TOKEN_SHA256:-}
# bundled-db
YAML
	if [ "${TUNNEX_TEST_IP_TLS:-1}" = 1 ]; then
		printf '%s\n' '# TUNNEX_EDGE_PUBLIC_IP' >>"$out"
	fi
	if [ "${TUNNEX_TEST_EDGE_TRUST:-}" = 1 ]; then
		printf '%s\n' '# TUNNEX_EDGE_TRUSTED_PROXIES' >>"$out"
	fi
	if [ "${TUNNEX_TEST_AI:-}" = 1 ]; then
		printf '%s\n' '  bifrost:' '    image: ${TUNNEX_AI_ENGINE_IMAGE:?set by signed release verification}' >>"$out"
	fi
	;;
*/deploy/ai-bootstrap.sh) cp "$TUNNEX_TEST_SOURCE_ROOT/deploy/ai-bootstrap.sh" "$out" ;;
*/deploy/ai-gateway/config-managed.json) cp "$TUNNEX_TEST_SOURCE_ROOT/deploy/ai-gateway/config-managed.json" "$out" ;;
*/deploy/upgrade.sh)
	printf '#!/bin/sh\nexit 0\n' >"$out"
	;;
*/deploy/upgrade-runner.sh)
	exit 22
	;;
*/release.json)
	printf '{}\n' >"$out"
	;;
*) exit 22 ;;
esac
EOF
cat >"$BIN/apt-get" <<'EOF'
#!/bin/sh
printf '%s\n' "$*" >>"$TUNNEX_TEST_APT_LOG"
case " $* " in
*' docker-ce '*)
	cat >"$TUNNEX_TEST_BIN/docker" <<'DOCKER'
#!/bin/sh
case "${1:-}" in
info) exit 0 ;;
version) printf 'amd64\n' ;;
pull) exit 0 ;;
run)
	cat <<'ENV'
TUNNEX_API_IMAGE=ghcr.io/tunnexio/tunnex-api@sha256:test
TUNNEX_WEB_IMAGE=ghcr.io/tunnexio/tunnex-web@sha256:test
TUNNEX_NGINX_IMAGE=ghcr.io/tunnexio/tunnex-nginx@sha256:test
TUNNEX_NODE_AGENT_IMAGE=ghcr.io/tunnexio/tunnex-node@sha256:test
TUNNEX_MIGRATE_IMAGE=ghcr.io/tunnexio/tunnex-api@sha256:test
TUNNEX_RELEASE_SEQUENCE=99
TUNNEX_RELEASE_VERSION=v9.9.9
TUNNEX_RELEASE_SOURCE_SHA=0123456789abcdef0123456789abcdef01234567
ENV
	if [ "${TUNNEX_TEST_AI:-}" = 1 ] && [ "${TUNNEX_TEST_AI_PIN_MISSING:-}" != 1 ]; then
		printf '%s\n' 'TUNNEX_AI_ENGINE_IMAGE=ghcr.io/tunnexio/tunnex-ai-engine@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'
	fi
	;;
volume)
	if [ "${TUNNEX_TEST_AI_EXISTING_VOLUME:-}" = 1 ]; then printf '%s\n' retained-ai-engine-config; fi
	;;
compose)
	case "${2:-}" in
	version) printf 'Docker Compose version v2.test\n' ;;
	*) printf '%s\n' "$*" >>"${TUNNEX_TEST_DOCKER_LOG:-/dev/null}" ;;
	esac
	;;
*) exit 0 ;;
esac
DOCKER
	chmod +x "$TUNNEX_TEST_BIN/docker"
	;;
esac
EOF
chmod +x "$BIN"/*

APT_LOG="$TMP/apt.log"
: >"$APT_LOG"
OUTPUT="$TMP/install-output.txt"
SOURCE_SHA=0123456789abcdef0123456789abcdef01234567
PATH="$TEST_PATH" \
TUNNEX_TEST_BIN="$BIN" \
TUNNEX_TEST_APT_LOG="$APT_LOG" \
TUNNEX_OS_RELEASE_FILE="$TMP/os-release" \
TUNNEX_VERSION=v9.9.9 \
TUNNEX_SOURCE_REF="$SOURCE_SHA" \
TUNNEX_PUBLIC_BASE_URL=https://preview.tunnex.test \
TUNNEX_TLS_MODE=terminated \
TUNNEX_ADMIN_EMAIL=owner@preview.tunnex.test \
TUNNEX_SMTP=skip \
TUNNEX_DIR="$TMP/control-plane" \
	sh "$INSTALLER" --yes >"$OUTPUT"

for expected in \
	'▀█▀ █ █ █▄ █ █▄ █ █▀▀ ▀▄▀' \
	'Connect Everything. Trust Nothing.' \
	'TUNNEX / GUIDED SETUP' \
	'TUNNEX SETUP' \
	'Security boundary' \
	'A separate Linux gateway is recommended.' \
	'[1/5] Checking this host' \
	'Detected: ubuntu' \
	'Install or complete Docker Engine, Compose v2, and required utilities for ubuntu' \
	'[2/5] Selecting a verified Tunnex release' \
	'[3/5] Configuring your Tunnex Server' \
	'[4/5] Reviewing the installation plan' \
	'╭─ QuickStart plan' \
	'Mode               Tunnex Server setup' \
	'Public URL         https://preview.tunnex.test' \
	'TLS mode           terminated' \
	'[5/5] Installing and verifying Tunnex' \
	'Docker Engine and Compose v2 are ready.' \
	'Tunnex v9.9.9 is running.'; do
	grep -Fq "$expected" "$OUTPUT" || fail "local preview omitted: $expected"
done

grep -Fq 'docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin' "$APT_LOG" ||
	fail 'fresh Ubuntu preview did not install the complete Docker Engine + Compose set'
grep -Fq 'TUNNEX_TLS_MODE=terminated' "$TMP/control-plane/.env" ||
	fail 'generated environment lost the selected TLS mode'
grep -qx 'TUNNEX_EDGE_PUBLIC_IP=' "$TMP/control-plane/.env" ||
	fail 'externally terminated TLS incorrectly requested an IP certificate'
grep -Fq 'TUNNEX_PORTABLE_CONTROL_PLANE=true' "$TMP/control-plane/.env" ||
	fail 'Linux CP-only install did not retain scale-zero compatibility with older upgrade helpers'
grep -Fq 'TUNNEX_RELEASE_SOURCE_SHA=0123456789abcdef0123456789abcdef01234567' "$TMP/control-plane/.env" ||
	fail 'generated environment lost verified release provenance'
grep -Fq 'COMPOSE_PROJECT_NAME=control-plane' "$TMP/control-plane/.env" ||
	fail 'installer did not persist an installation-specific Compose project name'
grep -Fq 'TUNNEX_GATEWAY_PLACEMENT=separate' "$TMP/control-plane/.env" ||
	fail 'fresh Linux installation did not default to a separate gateway'

# The opt-in local path must pass the first organization and name-bound token
# through Compose, check readiness, and remove the consumed token from .env.
PATH="$TEST_PATH" TUNNEX_TEST_BIN="$BIN" TUNNEX_TEST_APT_LOG="$APT_LOG" \
TUNNEX_TEST_DOCKER_LOG="$TMP/local-gateway-compose.log" \
TUNNEX_OS_RELEASE_FILE="$TMP/os-release" TUNNEX_VERSION=v9.9.9 TUNNEX_SOURCE_REF="$SOURCE_SHA" \
TUNNEX_PUBLIC_BASE_URL=https://preview.tunnex.test TUNNEX_TLS_MODE=terminated \
TUNNEX_ADMIN_EMAIL=owner@preview.tunnex.test TUNNEX_SMTP=skip \
TUNNEX_BOOTSTRAP_ORG_NAME='First office' TUNNEX_GATEWAY_PLACEMENT=same-host \
TUNNEX_COLOCATED_GATEWAY_CONFIRM=yes TUNNEX_GATEWAY_ADDRESS=203.0.113.24 \
TUNNEX_DIR="$TMP/local-gateway" sh "$INSTALLER" --yes >"$TMP/local-gateway-output.txt"
grep -Fq 'TUNNEX_BOOTSTRAP_ORG_NAME="First office"' "$TMP/local-gateway/.env" || fail 'first organization was not saved'
grep -Fq 'TUNNEX_NODE_NAME=quickstart-gateway' "$TMP/local-gateway/.env" || fail 'local gateway name pin was not saved'
grep -Fq 'TUNNEX_PORTABLE_CONTROL_PLANE=false' "$TMP/local-gateway/.env" || fail 'same-host install was incorrectly marked CP-only'
grep -Fq 'TUNNEX_NODE_ENDPOINT=203.0.113.24:51820' "$TMP/local-gateway/.env" || fail 'local gateway address was not saved'
grep -Fxq 'TUNNEX_JOIN_TOKEN=' "$TMP/local-gateway/.env" || fail 'consumed join token was retained in dotenv'
grep -Fxq 'TUNNEX_BOOTSTRAP_GATEWAY_TOKEN_SHA256=' "$TMP/local-gateway/.env" || fail 'consumed join hash was retained in dotenv'
grep -Fq '/readyz' "$TMP/local-gateway-compose.log" || fail 'local gateway success did not check readiness'
grep -Fq 'Local gateway enrolled and ready in your first organization.' "$TMP/local-gateway-output.txt" || fail 'local enrollment success missing'

# OpenClaw-style local preview must show the complete, host-specific plan while
# stopping before Docker/bootstrap, download, or product mutations.
: >"$APT_LOG"
PREVIEW_DIR="$TMP/onboarding-preview"
PATH="$TEST_PATH" \
TUNNEX_TEST_BIN="$BIN" \
TUNNEX_TEST_APT_LOG="$APT_LOG" \
TUNNEX_OS_RELEASE_FILE="$TMP/os-release" \
TUNNEX_VERSION=v9.9.9 \
TUNNEX_SOURCE_REF="$SOURCE_SHA" \
TUNNEX_PUBLIC_BASE_URL=https://preview.tunnex.test \
TUNNEX_TLS_MODE=terminated \
TUNNEX_ADMIN_EMAIL=owner@preview.tunnex.test \
TUNNEX_SMTP=skip \
TUNNEX_DIR="$PREVIEW_DIR" \
	sh "$INSTALLER" --dry-run >"$TMP/onboarding-preview-output.txt"
grep -Fq 'Changes            Preview only (no host or product changes)' "$TMP/onboarding-preview-output.txt" ||
	fail 'dry-run did not disclose the no-mutation boundary'
grep -Fq 'Onboarding preview complete. Re-run without --dry-run when you are ready.' "$TMP/onboarding-preview-output.txt" ||
	fail 'dry-run did not provide a safe rerun instruction'
[ ! -s "$APT_LOG" ] || fail 'dry-run invoked host package installation'
[ ! -e "$PREVIEW_DIR" ] || fail 'dry-run created an installation directory'

# Cancellation is exercised independently of a real TTY. If the confirmation
# says no, control must never reach the marker representing host mutation.
awk '/^# BEGIN INSTALL CONFIRMATION/{copy=1; next} /^# END INSTALL CONFIRMATION/{copy=0} copy' "$INSTALLER" >"$TMP/confirmation-function.sh"
cat >"$TMP/cancel-test.sh" <<EOF
#!/bin/sh
set -eu
AUTO_CONFIRM=false
say() { printf '%s\n' "\$*"; }
have_tty() { return 0; }
ask() { printf 'n\n'; }
. "$TMP/confirmation-function.sh"
confirm_installation
touch "$TMP/mutation-reached"
EOF
sh "$TMP/cancel-test.sh" >"$TMP/cancel-output.txt"
[ ! -e "$TMP/mutation-reached" ] || fail 'cancellation reached host mutation'
grep -Fq 'Cancelled before changing the host.' "$TMP/cancel-output.txt" ||
	fail 'cancellation did not explain that the host remained unchanged'

# A second clean target reuses the now-working Docker CLI and must not invoke
# apt at all. This protects customer reruns and hosts with Docker preinstalled.
: >"$APT_LOG"
PATH="$TEST_PATH" \
TUNNEX_TEST_BIN="$BIN" \
TUNNEX_TEST_APT_LOG="$APT_LOG" \
TUNNEX_OS_RELEASE_FILE="$TMP/os-release" \
TUNNEX_VERSION=v9.9.9 \
TUNNEX_SOURCE_REF="$SOURCE_SHA" \
TUNNEX_PUBLIC_BASE_URL=http://198.51.100.10 \
TUNNEX_TLS_MODE=http \
TUNNEX_ADMIN_EMAIL=owner@preview.tunnex.test \
TUNNEX_SMTP=skip \
TUNNEX_DIR="$TMP/existing-docker" \
	sh "$INSTALLER" --yes >"$TMP/reuse-output.txt"
[ ! -s "$APT_LOG" ] || fail 'an already usable Docker installation was modified'
grep -Fq 'Use the existing Docker Engine and Compose installation' "$TMP/reuse-output.txt" ||
	fail 'existing-Docker reuse was not made visible in the review'

# Docker Desktop hosts run the portable control plane, not a fake co-located
# WireGuard gateway. The choice is visible, persisted, and preserved on upgrade.
PORTABLE_DOCKER_LOG="$TMP/portable-compose.log"
: >"$PORTABLE_DOCKER_LOG"
PATH="$TEST_PATH" \
TUNNEX_HOST_KERNEL=Darwin \
TUNNEX_TEST_DOCKER_LOG="$PORTABLE_DOCKER_LOG" \
TUNNEX_VERSION=v9.9.9 \
TUNNEX_SOURCE_REF="$SOURCE_SHA" \
TUNNEX_PUBLIC_BASE_URL=http://198.51.100.11 \
TUNNEX_TLS_MODE=http \
TUNNEX_ADMIN_EMAIL=owner@preview.tunnex.test \
TUNNEX_SMTP=skip \
TUNNEX_DIR="$TMP/macos-portable" \
	sh "$INSTALLER" --yes >"$TMP/portable-output.txt"
grep -Fq 'Portable Tunnex Server; enroll the gateway on a separate Linux host' "$TMP/portable-output.txt" ||
	fail 'portable deployment shape was not visible in the onboarding review'
grep -Fq 'TUNNEX_PORTABLE_CONTROL_PLANE=true' "$TMP/macos-portable/.env" ||
	fail 'portable deployment shape was not persisted'
grep -Fq 'compose --project-name macos-portable --env-file .env -f tunnex.yml up -d --wait --scale node-agent=0' "$PORTABLE_DOCKER_LOG" ||
	fail 'portable control plane attempted to start the privileged node-agent'
grep -Fq 'TUNNEX_PORTABLE_CONTROL_PLANE' "$ROOT/deploy/upgrade.sh" &&
	grep -Fq -- '--scale node-agent=0' "$ROOT/deploy/upgrade.sh" ||
	fail 'upgrade path does not preserve the portable control-plane boundary'

# Windows enters the shared product installer through Git Bash. Its MINGW
# kernel must take the same portable-control-plane branch as Docker Desktop on
# macOS: no privileged local node-agent, and the persisted shape must survive
# the first install for the upgrade helper to read.
WINDOWS_DOCKER_LOG="$TMP/windows-compose.log"
: >"$WINDOWS_DOCKER_LOG"
PATH="$TEST_PATH" \
	TUNNEX_HOST_KERNEL=MINGW64_NT \
	TUNNEX_TEST_DOCKER_LOG="$WINDOWS_DOCKER_LOG" \
	TUNNEX_VERSION=v9.9.9 \
	TUNNEX_SOURCE_REF="$SOURCE_SHA" \
	TUNNEX_PUBLIC_BASE_URL=http://198.51.100.12 \
	TUNNEX_TLS_MODE=http \
	TUNNEX_ADMIN_EMAIL=owner@preview.tunnex.test \
	TUNNEX_SMTP=skip \
	TUNNEX_DIR="$TMP/windows-portable" \
	sh "$INSTALLER" --yes >"$TMP/windows-portable-output.txt"
grep -Fq 'Portable Tunnex Server; enroll the gateway on a separate Linux host' "$TMP/windows-portable-output.txt" ||
	fail 'Windows/Git Bash onboarding did not disclose the portable control-plane boundary'
grep -Fq 'TUNNEX_PORTABLE_CONTROL_PLANE=true' "$TMP/windows-portable/.env" ||
	fail 'Windows/Git Bash install did not persist the portable control-plane boundary'
grep -Fq 'compose --project-name windows-portable --env-file .env -f tunnex.yml up -d --wait --scale node-agent=0' "$WINDOWS_DOCKER_LOG" ||
	fail 'Windows/Git Bash install attempted to start the privileged node-agent'

# Execute the complete installer with external inputs and mocked release/host
# commands. Runtime connectivity itself is covered by the private-container walk.
printf '%s\n' 'postgres://fixture:byodb-file-secret@db.internal/cp?sslmode=verify-full' >"$TMP/db-url"
BYODB_LOG="$TMP/byodb-compose.log"
PATH="$TEST_PATH" TUNNEX_TEST_DOCKER_LOG="$BYODB_LOG" \
  TUNNEX_VERSION=v9.9.9 TUNNEX_SOURCE_REF="$SOURCE_SHA" \
  TUNNEX_PUBLIC_BASE_URL=https://preview.tunnex.test TUNNEX_TLS_MODE=terminated \
  TUNNEX_ADMIN_EMAIL=owner@preview.tunnex.test TUNNEX_SMTP=skip \
  TUNNEX_DATABASE_MODE=external TUNNEX_DATABASE_URL_FILE="$TMP/db-url" \
  TUNNEX_DIR="$TMP/byodb-control-plane" \
  sh "$INSTALLER" --yes >"$TMP/byodb-output.txt"
grep -Fq 'COMPOSE_PROFILES=external-db' "$TMP/byodb-control-plane/.env" || fail 'external profile not persisted'
grep -Fq 'TUNNEX_DATABASE_MODE=external' "$TMP/byodb-control-plane/.env" || fail 'external mode not persisted'
grep -Fq "TUNNEX_DATABASE_URL='postgres://fixture:byodb-file-secret@db.internal/cp?sslmode=verify-full'" "$TMP/byodb-control-plane/.env" || fail 'external URL not persisted literally'
! grep -Fq byodb-file-secret "$TMP/byodb-output.txt" || fail 'external credential leaked to installer output'
check_line=$(grep -n -- '--entrypoint preflight api --database-only' "$BYODB_LOG" | cut -d: -f1)
start_line=$(grep -n -- 'up -d --wait' "$BYODB_LOG" | cut -d: -f1)
[ -n "$check_line" ] && [ "$check_line" -lt "$start_line" ] || fail 'database preflight did not precede CP startup'

# Drive the actual customer path through a pseudo-terminal. Unlike the
# environment-only fixture above, this exercises each visible question, masked
# secret entry, review, confirmation, fresh-host Docker plan, and final handoff.
cat >"$TMP/pty-walkthrough.py" <<'PYTHON'
import errno
import os
import pty
import select
import sys
import time

installer, transcript_path = sys.argv[1:]
dialogue = [
    (b"Public base URL your users + gateways reach", b"https://preview.tunnex.test\r"),
    (b"TLS mode [direct (this VM) / terminated (external load balancer)] [direct]:", b"terminated\r"),
    (b"Administrator email [admin@preview.tunnex.test]:", b"owner@preview.tunnex.test\r"),
    (b"Configure SMTP now for email (verify / reset / invite)? [y/N]:", b"y\r"),
    (b"SMTP host:", b"mail.preview.tunnex.test\r"),
    (b"SMTP port [587]:", b"587\r"),
    (b"SMTP username:", b"support@preview.tunnex.test\r"),
    (b"SMTP password:", b"preview-smtp-secret\r"),
    (b"From address [no-reply@preview.tunnex.test]:", b"support@preview.tunnex.test\r"),
    (b"Server database: bundled or external PostgreSQL? [bundled]:", b"bundled\r"),
    (b"Your first organization [My organization]:", b"Preview organization\r"),
    (b"Gateway location [separate / same-host] [separate]:", b"separate\r"),
    (b"Proceed with this installation? [Y/n]:", b"y\r"),
]

pid, fd = pty.fork()
if pid == 0:
    os.execve("/bin/sh", ["sh", installer], os.environ.copy())

transcript = bytearray()
unmatched = bytearray()

def abort(message):
    with open(transcript_path, "wb") as output:
        output.write(transcript)
    tail = bytes(transcript[-2000:]).decode(errors="replace")
    raise SystemExit(message + "\n--- installer transcript tail ---\n" + tail)

def read_chunk():
    # os.read alone blocks forever on an unexpected new prompt, defeating the
    # deadline in the caller. Bound the read as well as the dialogue loop.
    if not select.select([fd], [], [], 30)[0]:
        os.kill(pid, 9)
        abort("installer produced no output for 30 seconds")
    try:
        return os.read(fd, 4096)
    except OSError as exc:
        if exc.errno == errno.EIO:
            return b""
        raise

for prompt, answer in dialogue:
    deadline = time.monotonic() + 30
    while prompt not in unmatched:
        if time.monotonic() >= deadline:
            os.kill(pid, 9)
            raise SystemExit("timed out waiting for installer prompt: " + prompt.decode())
        chunk = read_chunk()
        if not chunk:
            abort("installer exited before prompt: " + prompt.decode())
        transcript.extend(chunk)
        unmatched.extend(chunk)
    os.write(fd, answer)
    unmatched.clear()

while True:
    chunk = read_chunk()
    if not chunk:
        break
    transcript.extend(chunk)

_, status = os.waitpid(pid, 0)
with open(transcript_path, "wb") as output:
    output.write(transcript)
if os.waitstatus_to_exitcode(status) != 0:
    raise SystemExit("interactive installer walkthrough failed")
PYTHON

rm -f "$BIN/docker"
: >"$APT_LOG"
INTERACTIVE_OUTPUT="$TMP/interactive-output.txt"
PATH="$TEST_PATH" \
TUNNEX_TEST_BIN="$BIN" \
TUNNEX_TEST_APT_LOG="$APT_LOG" \
TUNNEX_OS_RELEASE_FILE="$TMP/os-release" \
TUNNEX_VERSION=v9.9.9 \
TUNNEX_SOURCE_REF="$SOURCE_SHA" \
TUNNEX_PUBLIC_BASE_URL='' \
TUNNEX_TLS_MODE='' \
TUNNEX_ADMIN_EMAIL='' \
TUNNEX_SMTP='' \
SMTP_HOST='' SMTP_PORT='' SMTP_USERNAME='' SMTP_PASSWORD='' SMTP_FROM='' \
TERM=xterm-256color TUNNEX_COLOR=always \
TUNNEX_TEST_TTY_DEVICE=- \
TUNNEX_DIR="$TMP/interactive-control-plane" \
	env -u NO_COLOR "$PYTHON3" "$TMP/pty-walkthrough.py" "$INSTALLER" "$INTERACTIVE_OUTPUT"
grep -Fq "$(printf '\033[1;97m')" "$INTERACTIVE_OUTPUT" ||
	fail 'interactive walkthrough did not render the white TUNN wordmark segment'
grep -Fq "$(printf '\033[1;31m')" "$INTERACTIVE_OUTPUT" ||
	fail 'interactive walkthrough did not render the red EX wordmark segment'
awk '/^setup_palette\(\)/,/^# BEGIN INSTALL CONFIRMATION/' "$INSTALLER" >"$TMP/palette-functions.sh"
cat >"$TMP/no-color-wordmark-test.sh" <<EOF
#!/bin/sh
set -eu
say() { printf '%s\\n' "\$*"; }
die() { exit 1; }
. "$TMP/palette-functions.sh"
setup_palette
print_wordmark
EOF
NO_COLOR=1 TUNNEX_COLOR=always sh "$TMP/no-color-wordmark-test.sh" >"$TMP/no-color-wordmark.txt"
if grep -Fq "$(printf '\033')" "$TMP/no-color-wordmark.txt"; then
	fail 'NO_COLOR did not suppress wordmark colour sequences'
fi
grep -Fq '▀█▀ █ █ █▄ █ █▄ █ █▀▀ ▀▄▀' "$TMP/no-color-wordmark.txt" ||
	fail 'NO_COLOR wordmark lost its terminal-safe glyphs'
"$PYTHON3" - "$INTERACTIVE_OUTPUT" >"$TMP/interactive-output-normalized.txt" <<'PYTHON'
import re
import sys

transcript = open(sys.argv[1], "rb").read().replace(b"\r", b"")
# The PTY preview deliberately forces colour. Remove terminal control sequences
# before asserting copy so the wordmark is checked equally with and without
# callers exporting NO_COLOR.
transcript = re.sub(rb"\x1b\[[0-?]*[ -/]*[@-~]", b"", transcript)
sys.stdout.buffer.write(transcript)
PYTHON

for expected in \
	'▀█▀ █ █ █▄ █ █▄ █ █▀▀ ▀▄▀' \
	'Public base URL your users + gateways reach' \
	'TLS mode [direct (this VM) / terminated (external load balancer)] [direct]:' \
	'Administrator email [admin@preview.tunnex.test]:' \
	'Configure SMTP now for email (verify / reset / invite)? [y/N]:' \
	'SMTP host:' \
	'SMTP port [587]:' \
	'SMTP username:' \
	'SMTP password:' \
	'From address [no-reply@preview.tunnex.test]:' \
	'Server database: bundled or external PostgreSQL? [bundled]:' \
	'Proceed with this installation? [Y/n]:' \
	'Downloading the signed release verifier' \
	'Pulling verified Tunnex images' \
	'Starting the Tunnex Server (initial migrations' \
	'Email              mail.preview.tunnex.test:587 as support@preview.tunnex.test' \
	'Tunnex v9.9.9 is running.'; do
	grep -Fq "$expected" "$TMP/interactive-output-normalized.txt" ||
		fail "interactive walkthrough omitted: $expected"
done
grep -Fq '▀█▀ █ █ █▄ █ █▄ █ █▀▀ ▀▄▀' "$TMP/interactive-output-normalized.txt" || fail 'interactive walkthrough omitted the wordmark'
if grep -Fq 'preview-smtp-secret' "$INTERACTIVE_OUTPUT"; then
	fail 'interactive walkthrough echoed the SMTP password'
fi
grep -Fq 'SMTP_PASSWORD=preview-smtp-secret' "$TMP/interactive-control-plane/.env" ||
	fail 'interactive walkthrough did not persist the masked SMTP answer'
grep -Fq 'docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin' "$APT_LOG" ||
	fail 'interactive fresh-host walkthrough did not execute the confirmed Docker plan'

if [ "${TUNNEX_TEST_SHOW_OUTPUT:-0}" = 1 ]; then
	printf '%s\n' '--- local onboarding preview ---'
	cat "$INTERACTIVE_OUTPUT"
	printf '%s\n' '--- end local onboarding preview ---'
fi

# Readiness is stronger than command presence: when the socket is root-only,
# the installer keeps this run moving through sudo instead of telling the user
# to log out and rerun the one-liner.
ROOT_BIN="$TMP/root-bin"
mkdir -p "$ROOT_BIN"
cat >"$ROOT_BIN/id" <<'EOF'
#!/bin/sh
case "${1:-}" in
-u) printf '1000\n' ;;
-un) printf 'ubuntu\n' ;;
-nG) printf 'ubuntu\n' ;;
*) exit 0 ;;
esac
EOF
cat >"$ROOT_BIN/sudo" <<'EOF'
#!/bin/sh
TUNNEX_TEST_ROOT=1 exec "$@"
EOF
cat >"$ROOT_BIN/docker" <<'EOF'
#!/bin/sh
case "${1:-}:${2:-}" in
compose:version) exit 0 ;;
info:*) [ "${TUNNEX_TEST_ROOT:-}" = 1 ] ;;
*) exit 0 ;;
esac
EOF
cat >"$ROOT_BIN/getent" <<'EOF'
#!/bin/sh
exit 1
EOF
chmod +x "$ROOT_BIN"/*

awk '/^# BEGIN HOST BOOTSTRAP/{copy=1; next} /^# END HOST BOOTSTRAP/{copy=0} copy' "$INSTALLER" >"$TMP/bootstrap-functions.sh"

# os-release is declarative host metadata, not a shell fragment the installer
# may execute. This fixture would create a marker if load_host_os sourced it.
MALICIOUS_OS_RELEASE="$TMP/malicious-os-release"
MALICIOUS_MARKER="$TMP/os-release-was-sourced"
cat >"$MALICIOUS_OS_RELEASE" <<EOF
ID=ubuntu
VERSION_CODENAME=noble
UNRELATED_COMMAND=\$(touch "$MALICIOUS_MARKER")
EOF
cat >"$TMP/malicious-os-release-test.sh" <<EOF
#!/bin/sh
set -eu
say() { :; }
die() { exit 1; }
as_root() { "\$@"; }
. "$TMP/bootstrap-functions.sh"
TUNNEX_HOST_KERNEL=Linux TUNNEX_OS_RELEASE_FILE="$MALICIOUS_OS_RELEASE" load_host_os
[ "\$HOST_OS_ID" = ubuntu ]
[ "\$HOST_OS_CODENAME" = noble ]
EOF
PATH="$TEST_PATH" sh "$TMP/malicious-os-release-test.sh" ||
	fail 'os-release metadata could not be parsed safely'
[ ! -e "$MALICIOUS_MARKER" ] || fail 'os-release fixture was executed instead of parsed'

# yum-utils supplies `yum-config-manager` as a separate executable. A fresh
# yum-family host must not try the dnf-only `yum config-manager` spelling.
RPM_BIN="$TMP/rpm-bin"
RPM_SYSTEM_BIN="$TMP/rpm-system-bin"
RPM_LOG="$TMP/rpm.log"
mkdir -p "$RPM_BIN" "$RPM_SYSTEM_BIN"
: >"$RPM_LOG"
cat >"$RPM_BIN/yum" <<'EOF'
#!/bin/sh
printf 'yum %s\n' "$*" >>"$TUNNEX_TEST_RPM_LOG"
EOF
cat >"$RPM_BIN/yum-config-manager" <<'EOF'
#!/bin/sh
printf 'yum-config-manager %s\n' "$*" >>"$TUNNEX_TEST_RPM_LOG"
EOF
chmod +x "$RPM_BIN"/*
ln -s "$(command -v sh)" "$RPM_SYSTEM_BIN/sh"
cat >"$TMP/yum-bootstrap-test.sh" <<EOF
#!/bin/sh
set -eu
say() { :; }
die() { exit 1; }
as_root() { "\$@"; }
HOST_OS_ID=rocky
. "$TMP/bootstrap-functions.sh"
HOST_OS_ID=rocky
install_rpm_prerequisites
EOF
PATH="$RPM_BIN:$RPM_SYSTEM_BIN" TUNNEX_TEST_RPM_LOG="$RPM_LOG" sh "$TMP/yum-bootstrap-test.sh" ||
	fail 'fresh yum-family Docker bootstrap failed'
grep -Fq 'yum-config-manager --add-repo https://download.docker.com/linux/centos/docker-ce.repo' "$RPM_LOG" ||
	fail 'yum-family bootstrap did not invoke yum-config-manager for Docker repository setup'
if grep -Fq 'yum config-manager' "$RPM_LOG"; then
	fail 'yum-family bootstrap used the dnf-only yum config-manager spelling'
fi

# A fresh macOS host follows the same contract: reuse Docker Desktop when it is
# present, otherwise prepare a CLI-compatible runtime and wait for the daemon.
# All commands below are disposable stubs; this test never touches the real Mac.
MAC_BIN="$TMP/mac-bin"
MAC_APPS="$TMP/mac-applications"
MAC_LOG="$TMP/mac-brew.log"
mkdir -p "$MAC_BIN" "$MAC_APPS"
: >"$MAC_LOG"
cat >"$MAC_BIN/uname" <<'EOF'
#!/bin/sh
printf 'Darwin\n'
EOF
cat >"$MAC_BIN/id" <<'EOF'
#!/bin/sh
case "${1:-}" in
-u) printf '0\n' ;;
*) printf 'uid=0(root) gid=0(root) groups=0(root)\n' ;;
esac
EOF
cat >"$MAC_BIN/brew" <<'EOF'
#!/bin/sh
printf '%s\n' "$*" >>"$TUNNEX_TEST_MAC_BREW_LOG"
case " $* " in
*' install '*)
	cat >"$TUNNEX_TEST_MAC_BIN/docker" <<'DOCKER'
#!/bin/sh
case "${1:-}:${2:-}" in
info:*) [ -z "${TUNNEX_TEST_MAC_DOCKER_READY_FILE:-}" ] || [ -f "$TUNNEX_TEST_MAC_DOCKER_READY_FILE" ] ;;
compose:version) printf 'Docker Compose version v2.test\n' ;;
*) exit 0 ;;
esac
DOCKER
	cat >"$TUNNEX_TEST_MAC_BIN/colima" <<'COLIMA'
#!/bin/sh
[ "${1:-}" = start ]
COLIMA
	chmod +x "$TUNNEX_TEST_MAC_BIN/docker" "$TUNNEX_TEST_MAC_BIN/colima"
	;;
esac
EOF
cat >"$MAC_BIN/open" <<'EOF'
#!/bin/sh
printf '%s\n' "$*" >>"$TUNNEX_TEST_MAC_OPEN_LOG"
: >"$TUNNEX_TEST_MAC_DOCKER_READY_FILE"
EOF
chmod +x "$MAC_BIN"/*
cat >"$TMP/mac-bootstrap-test.sh" <<EOF
#!/bin/sh
set -eu
say() { printf '%s\\n' "\$*"; }
die() { printf 'error: %s\\n' "\$*" >&2; exit 1; }
as_root() { "\$@"; }
. "$TMP/bootstrap-functions.sh"
ensure_docker_ready
[ "\$HOST_OS_ID" = macos ]
[ "\$DOCKER_AS_ROOT" = false ]
EOF
PATH="$MAC_BIN:$SYSTEM_BIN" \
TUNNEX_TEST_MAC_BIN="$MAC_BIN" \
TUNNEX_TEST_MAC_BREW_LOG="$MAC_LOG" \
TUNNEX_MAC_APPLICATIONS_DIR="$MAC_APPS" \
	sh "$TMP/mac-bootstrap-test.sh" >"$TMP/mac-bootstrap-output.txt" ||
	fail 'fresh macOS runtime bootstrap did not become ready'
grep -Fq 'install docker docker-compose colima openssl' "$MAC_LOG" ||
	fail 'fresh macOS bootstrap omitted Docker CLI, Compose, Colima, or OpenSSL'
grep -Fq 'Starting the Colima container runtime' "$TMP/mac-bootstrap-output.txt" ||
	fail 'fresh macOS bootstrap did not make runtime startup visible'

# A Docker CLI and Compose plugin on PATH do not prove Docker Desktop is
# running. The installer must start an installed Desktop application before
# treating its daemon as unusable.
MAC_OPEN_LOG="$TMP/mac-open.log"
MAC_READY_FILE="$TMP/mac-desktop-ready"
: >"$MAC_OPEN_LOG"
mkdir -p "$MAC_APPS/Docker.app"
cat >"$TMP/mac-stopped-desktop-test.sh" <<EOF
#!/bin/sh
set -eu
say() { printf '%s\\n' "\$*"; }
die() { printf 'error: %s\\n' "\$*" >&2; exit 1; }
as_root() { "\$@"; }
. "$TMP/bootstrap-functions.sh"
ensure_docker_ready
[ "\$DOCKER_AS_ROOT" = false ]
EOF
PATH="$MAC_BIN:$SYSTEM_BIN" \
TUNNEX_TEST_MAC_BIN="$MAC_BIN" \
TUNNEX_TEST_MAC_BREW_LOG="$MAC_LOG" \
TUNNEX_TEST_MAC_OPEN_LOG="$MAC_OPEN_LOG" \
TUNNEX_TEST_MAC_DOCKER_READY_FILE="$MAC_READY_FILE" \
TUNNEX_MAC_APPLICATIONS_DIR="$MAC_APPS" \
	sh "$TMP/mac-stopped-desktop-test.sh" >"$TMP/mac-stopped-desktop-output.txt" ||
	fail 'stopped macOS Docker Desktop was not started before readiness verification'
[ -f "$MAC_READY_FILE" ] || fail 'macOS Docker Desktop startup did not make the daemon ready'
grep -Fq -- '-a Docker' "$MAC_OPEN_LOG" ||
	fail 'stopped macOS Docker Desktop did not receive the Desktop startup command'
grep -Fq 'Starting Docker Desktop' "$TMP/mac-stopped-desktop-output.txt" ||
	fail 'stopped macOS Docker Desktop startup was not visible'

cat >"$TMP/root-socket-test.sh" <<EOF
#!/bin/sh
set -eu
say() { printf '%s\\n' "\$*"; }
die() { printf 'error: %s\\n' "\$*" >&2; exit 1; }
as_root() {
	if [ "\$(id -u)" -eq 0 ]; then "\$@"; else sudo "\$@"; fi
}
. "$TMP/bootstrap-functions.sh"
TUNNEX_HOST_KERNEL=Linux
start_linux_docker() { touch "$TMP/root-socket-tried-to-start-docker"; }
ensure_docker_ready
[ "\$DOCKER_AS_ROOT" = true ]
docker_cli info
EOF
PATH="$ROOT_BIN:$SYSTEM_BIN" sh "$TMP/root-socket-test.sh" ||
	fail 'root-only Docker socket was not handled for the current install'
[ ! -e "$TMP/root-socket-tried-to-start-docker" ] ||
	fail 'usable root-only Docker socket was mistaken for a stopped daemon'

# Execute the actual installer against a release declaring the bundled engine.
# The fixture's verifier emits the signed pin; no key or inference is provided.
run_ai_install() {
	PATH="$TEST_PATH" TUNNEX_TEST_BIN="$BIN" TUNNEX_TEST_APT_LOG="$APT_LOG" \
	TUNNEX_TEST_AI=1 TUNNEX_TEST_SOURCE_ROOT="$ROOT" TUNNEX_OS_RELEASE_FILE="$TMP/os-release" \
	TUNNEX_VERSION=v9.9.9 TUNNEX_SOURCE_REF="$SOURCE_SHA" \
	TUNNEX_PUBLIC_BASE_URL="$2" TUNNEX_ADMIN_EMAIL=owner@preview.tunnex.test \
	TUNNEX_SMTP=skip TUNNEX_DIR="$1" sh "$INSTALLER" --yes
}
# New terminated releases require trust before publishing any managed payload.
if (TUNNEX_TEST_EDGE_TRUST=1 TUNNEX_TLS_MODE=terminated run_ai_install "$TMP/no-proxy-peers" https://preview.tunnex.test) >"$TMP/no-proxy-peers-output" 2>&1; then
  fail 'new terminated TLS deployment accepted missing proxy peers'
fi
grep -Fq 'Externally terminated HTTPS requires TUNNEX_EDGE_TRUSTED_PROXIES' "$TMP/no-proxy-peers-output" || fail 'missing proxy peers failed outside preflight'
[ ! -e "$TMP/no-proxy-peers/.env" ] && [ ! -e "$TMP/no-proxy-peers/tunnex.yml" ] || fail 'missing proxy peers published deployment files'
(TUNNEX_TEST_EDGE_TRUST=1 TUNNEX_TLS_MODE=terminated TUNNEX_EDGE_TRUSTED_PROXIES='10.20.0.12/32 2001:db8::12/128' run_ai_install "$TMP/proxy-peers" https://preview.tunnex.test) >"$TMP/proxy-peers-output"
grep -Fxq 'TUNNEX_EDGE_TRUSTED_PROXIES=10.20.0.12/32 2001:db8::12/128' "$TMP/proxy-peers/.env" || fail 'explicit proxy peers were not persisted'
cp "$TMP/proxy-peers/.env" "$TMP/proxy-peers-before.env"
(TUNNEX_TEST_EDGE_TRUST=1 run_ai_install "$TMP/proxy-peers" http://51.20.98.153) >"$TMP/proxy-peers-rerun-output"
cmp -s "$TMP/proxy-peers-before.env" "$TMP/proxy-peers/.env" || fail 'rerun did not preserve the installed terminated transport'
# A retained terminated origin still needs peers even with a new input URL.
sed '/^TUNNEX_EDGE_TRUSTED_PROXIES=/d' "$TMP/proxy-peers/.env" >"$TMP/proxy-peers/.env.next"
mv "$TMP/proxy-peers/.env.next" "$TMP/proxy-peers/.env"
cp "$TMP/proxy-peers/.env" "$TMP/proxy-peers-missing-before.env"
cp "$TMP/proxy-peers/tunnex.yml" "$TMP/proxy-peers-before.yml"
if (TUNNEX_TEST_EDGE_TRUST=1 run_ai_install "$TMP/proxy-peers" http://51.20.98.153) >"$TMP/proxy-peers-missing-output" 2>&1; then
  fail 'a conflicting rerun URL bypassed required proxy trust'
fi
cmp -s "$TMP/proxy-peers-missing-before.env" "$TMP/proxy-peers/.env" || fail 'missing retained peers changed installed settings'
cmp -s "$TMP/proxy-peers-before.yml" "$TMP/proxy-peers/tunnex.yml" || fail 'missing retained peers replaced Compose'
for invalid_peers in '0.0.0.0/0' '::/0' '10.20.0.12/33' '1::2::3' '10.0.0.1; echo injected'; do
  if (TUNNEX_TEST_EDGE_TRUST=1 TUNNEX_TLS_MODE=terminated TUNNEX_EDGE_TRUSTED_PROXIES="$invalid_peers" run_ai_install "$TMP/bad-proxy-peers" https://preview.tunnex.test) >"$TMP/bad-proxy-peers-output" 2>&1; then
    fail 'invalid proxy peers passed installer preflight'
  fi
  [ ! -e "$TMP/bad-proxy-peers/.env" ] && [ ! -e "$TMP/bad-proxy-peers/tunnex.yml" ] || fail 'invalid proxy peers published deployment files'
done
# Public-IP HTTPS must provision trusted edge mode and usable AI together.
# Every network and Docker command remains stubbed: no real certificate request.
run_ai_install "$TMP/ai-public-ip" https://51.20.98.153:443 >"$TMP/ai-public-ip-output"
for value in APP_BASE_URL=https://51.20.98.153:443 TUNNEX_TLS_MODE=direct TUNNEX_EDGE_LISTEN=https://51.20.98.153:443 TUNNEX_EDGE_PUBLIC_IP=51.20.98.153 TUNNEX_COOKIE_SECURE=true TUNNEX_AI_GATEWAY_URL=http://bifrost:8080; do
	grep -qx "$value" "$TMP/ai-public-ip/.env" || fail "public-IP HTTPS configuration missing: $value"
done
"$PYTHON3" -c 'import json,sys; assert "51.20.98.153" in json.load(open(sys.argv[1]))["protected_hosts"]' \
	"$TMP/ai-public-ip/ai-egress-policy.json" || fail 'public-IP HTTPS left its control-plane IP unprotected'
grep -Fq 'allow public TCP 443 for HTTPS and certificate renewal' "$TMP/ai-public-ip-output" || fail 'IP HTTPS omitted its renewal network requirement'
cp "$TMP/ai-public-ip/.env" "$TMP/ai-public-ip-before.env"
cp "$TMP/ai-public-ip/tunnex.yml" "$TMP/ai-public-ip-before.yml"
run_ai_install "$TMP/ai-public-ip" https://51.20.98.153:443 >"$TMP/ai-public-ip-rerun-output"
cmp -s "$TMP/ai-public-ip-before.env" "$TMP/ai-public-ip/.env" || fail 'IP HTTPS rerun changed durable configuration or keys'
if (TUNNEX_TEST_IP_TLS=0 run_ai_install "$TMP/ai-public-ip" https://51.20.98.153:443) >"$TMP/ai-public-ip-unsupported-output" 2>&1; then
	fail 'IP HTTPS accepted an older signed deployment without IP certificate support'
fi
grep -Fq 'selected signed release does not support public IPv4 HTTPS' "$TMP/ai-public-ip-unsupported-output" || fail 'old IP HTTPS release failed outside the capability guard'
cmp -s "$TMP/ai-public-ip-before.env" "$TMP/ai-public-ip/.env" || fail 'old IP HTTPS release changed protected configuration'
cmp -s "$TMP/ai-public-ip-before.yml" "$TMP/ai-public-ip/tunnex.yml" || fail 'old IP HTTPS release replaced the deployment'
# The input URL does not replace .env on a rerun. Changing that input must
# not bypass the capability requirement of the retained direct-IP deployment.
for requested_url in https://preview.tunnex.test http://51.20.98.153; do
	if (TUNNEX_TEST_IP_TLS=0 run_ai_install "$TMP/ai-public-ip" "$requested_url") >"$TMP/ai-public-ip-conflict-output" 2>&1; then
		fail 'different rerun URL bypassed the installed IP HTTPS capability guard'
	fi
	grep -Fq 'selected signed release does not support public IPv4 HTTPS' "$TMP/ai-public-ip-conflict-output" || fail 'retained IP HTTPS failed outside the capability guard'
	cmp -s "$TMP/ai-public-ip-before.env" "$TMP/ai-public-ip/.env" || fail 'conflicting rerun URL changed protected settings'
	cmp -s "$TMP/ai-public-ip-before.yml" "$TMP/ai-public-ip/tunnex.yml" || fail 'conflicting rerun URL replaced the IP HTTPS deployment'
done
# A missing derived hint cannot hide an installed explicit direct-IP origin.
sed '/^TUNNEX_EDGE_PUBLIC_IP=/d' "$TMP/ai-public-ip-before.env" >"$TMP/ai-public-ip/.env"
cp "$TMP/ai-public-ip/.env" "$TMP/ai-public-ip-no-hint.env"
if (TUNNEX_TEST_IP_TLS=0 run_ai_install "$TMP/ai-public-ip" https://preview.tunnex.test) >"$TMP/ai-public-ip-no-hint-output" 2>&1; then
	fail 'missing derived IP hint bypassed the installed direct-IP capability guard'
fi
grep -Fq 'selected signed release does not support public IPv4 HTTPS' "$TMP/ai-public-ip-no-hint-output" || fail 'direct-IP origin failed outside the capability guard'
cmp -s "$TMP/ai-public-ip-no-hint.env" "$TMP/ai-public-ip/.env" || fail 'direct-IP origin guard changed protected settings'
cmp -s "$TMP/ai-public-ip-before.yml" "$TMP/ai-public-ip/tunnex.yml" || fail 'direct-IP origin guard replaced the deployment'
cp "$TMP/ai-public-ip-before.env" "$TMP/ai-public-ip/.env"
if run_ai_install "$TMP/ai-private-direct" https://172.31.20.253 >"$TMP/ai-private-direct-output" 2>&1; then
	fail 'direct TLS accepted a private IPv4 certificate'
fi
[ ! -e "$TMP/ai-private-direct/.env" ] || fail 'invalid direct TLS wrote deployment configuration'
(TUNNEX_TLS_MODE=terminated run_ai_install "$TMP/ai-public-ip-terminated" https://51.20.98.153:8443) >"$TMP/ai-public-ip-terminated-output"
grep -qx 'TUNNEX_EDGE_PUBLIC_IP=' "$TMP/ai-public-ip-terminated/.env" || fail 'external IP TLS requested direct certificate management'
(TUNNEX_EDGE_PUBLIC_IP=51.20.98.153 run_ai_install "$TMP/ai-stale-ip" https://preview.tunnex.test) >"$TMP/ai-stale-ip-output"
grep -qx 'TUNNEX_EDGE_PUBLIC_IP=' "$TMP/ai-stale-ip/.env" || fail 'DNS TLS retained an injected IP certificate address'
(TUNNEX_COMPOSE_PROJECT=custom-ai-project run_ai_install "$TMP/ai-https" https://preview.tunnex.test) >"$TMP/ai-https-output"
grep -qx 'TUNNEX_AI_GATEWAY_URL=http://bifrost:8080' "$TMP/ai-https/.env" || fail 'HTTPS bootstrap did not integrate its private backend'
grep -qx 'TUNNEX_AI_BOOTSTRAP_VERSION=1' "$TMP/ai-https/.env" || fail 'AI bootstrap provenance was not recorded'
grep -qx 'TUNNEX_AI_VPN_AUTO=true' "$TMP/ai-https/.env" || fail 'VPN AI was not enabled by fresh bootstrap'
grep -qx 'TUNNEX_AI_ENGINE_IMAGE=ghcr.io/tunnexio/tunnex-ai-engine@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa' "$TMP/ai-https/.env" || fail 'AI image did not use the verified pin'
[ -f "$TMP/ai-https/ai-engine.json" ] && [ -f "$TMP/ai-https/ai-bootstrap.sh" ] || fail 'AI configuration was not installed'
"$PYTHON3" -c 'import os, stat, sys; assert stat.S_IMODE(os.stat(sys.argv[1]).st_mode) == 0o600' "$TMP/ai-https/.env" || fail 'AI credentials were not owner-only'
! grep -Eq '"providers"[[:space:]]*:' "$TMP/ai-https/ai-engine.json" || fail 'bootstrap seeded provider credentials'
for key in TUNNEX_AI_GATEWAY_ADMIN_USER TUNNEX_AI_GATEWAY_ADMIN_PASSWORD TUNNEX_AI_ENGINE_ENCRYPTION_KEY TUNNEX_AI_CUSTOM_PROXY_USERNAME TUNNEX_AI_CUSTOM_PROXY_PASSWORD; do
	[ "$(grep -c "^$key=" "$TMP/ai-https/.env")" -eq 1 ] || fail 'AI credentials were duplicated'
	value=$(sed -n "s/^$key=//p" "$TMP/ai-https/.env")
	[ -n "$value" ] || fail 'AI credential generation was empty'
	! grep -Fq "$value" "$TMP/ai-https-output" || fail 'AI bootstrap printed a private credential'
done
"$PYTHON3" - "$TMP/ai-https" <<'PYTHON'
import json
from pathlib import Path
import stat
import sys

installation = Path(sys.argv[1]).resolve()
env = dict(line.split("=", 1) for line in (installation / ".env").read_text().splitlines() if "=" in line)
assert env["TUNNEX_AI_CUSTOM_PROXY_URL"] == "http://{}:{}@ai-egress:8190".format(
    env["TUNNEX_AI_CUSTOM_PROXY_USERNAME"], env["TUNNEX_AI_CUSTOM_PROXY_PASSWORD"])
policy_path = Path(env["TUNNEX_AI_CUSTOM_ENDPOINTS_FILE"]).resolve()
assert policy_path == installation / "ai-egress-policy.json"
assert stat.S_IMODE(policy_path.stat().st_mode) == 0o644
policy = json.loads(policy_path.read_text())
assert policy == {"public_https": True, "endpoints": [], "denied_cidrs": [],
                  "protected_hosts": ["api", "bifrost", "redis", "web", "nginx", "caddy", "ai-egress", "preview.tunnex.test", "postgres"]}
PYTHON
# An operator's explicit opt-out survives reinstall/upgrade verbatim.
sed 's/^TUNNEX_AI_VPN_AUTO=true$/TUNNEX_AI_VPN_AUTO=false/' "$TMP/ai-https/.env" >"$TMP/ai-opt-out.env"
cp "$TMP/ai-opt-out.env" "$TMP/ai-https/.env"
cp "$TMP/ai-https/.env" "$TMP/ai-before.env"
printf '\n' >>"$TMP/ai-https/ai-engine.json"
cp "$TMP/ai-https/ai-engine.json" "$TMP/ai-before.json"
# An operator's valid endpoint rules and formatting remain authoritative.
cat >"$TMP/ai-https/ai-egress-policy.json" <<'JSON'
{
  "public_https": false,
  "endpoints": [{"name":"Private model","url":"https://models.internal","allowed_cidrs":["10.20.0.0/16"]}],
  "protected_hosts": ["api", "bifrost"],
  "denied_cidrs": ["10.20.1.0/24"]
}
JSON
cp "$TMP/ai-https/ai-egress-policy.json" "$TMP/ai-before-policy.json"
run_ai_install "$TMP/ai-https" https://preview.tunnex.test >"$TMP/ai-rerun-output"
cmp -s "$TMP/ai-before.env" "$TMP/ai-https/.env" || fail 'rerun rotated durable AI credentials'
cmp -s "$TMP/ai-before.json" "$TMP/ai-https/ai-engine.json" || fail 'rerun overwrote managed engine configuration'
cmp -s "$TMP/ai-before-policy.json" "$TMP/ai-https/ai-egress-policy.json" || fail 'rerun overwrote the operator egress policy'
grep -qx 'COMPOSE_PROJECT_NAME=custom-ai-project' "$TMP/ai-https/.env" || fail 'rerun changed the installation project and encrypted storage'
if (TUNNEX_COMPOSE_PROJECT=other-project run_ai_install "$TMP/ai-https" https://preview.tunnex.test) >"$TMP/ai-project-output" 2>&1; then
	fail 'rerun allowed selecting unrelated project storage'
fi

# A pre-AI installation needs the new installer/helper before it can apply
# the new mandatory Compose settings. Reinstalling preserves its database
# credential and project while provisioning the absent private AI backend.
grep '^POSTGRES_PASSWORD=' "$TMP/control-plane/.env" >"$TMP/pre-ai-postgres-before"
! grep -q '^TUNNEX_AI_ENGINE_ENCRYPTION_KEY=' "$TMP/control-plane/.env" || fail 'pre-AI migration fixture already had an engine key'
sed -e 's|^TUNNEX_VERSION=.*|TUNNEX_VERSION=v0.1.34|' \
  -e 's|^TUNNEX_SOURCE_REF=.*|TUNNEX_SOURCE_REF=0e882f0af7c232d870645a80675f0b5bf7a39032|' \
  -e 's|^\(TUNNEX_[A-Z_]*_IMAGE\)=.*|\1=old@sha256:bbbb|' \
  "$TMP/control-plane/.env" >"$TMP/pre-ai-migration.env"
cp "$TMP/pre-ai-migration.env" "$TMP/control-plane/.env"
(TUNNEX_COMPOSE_PROJECT=control-plane run_ai_install "$TMP/control-plane" https://preview.tunnex.test) >"$TMP/pre-ai-migration-output"
grep '^POSTGRES_PASSWORD=' "$TMP/control-plane/.env" >"$TMP/pre-ai-postgres-after"
cmp -s "$TMP/pre-ai-postgres-before" "$TMP/pre-ai-postgres-after" || fail 'pre-AI migration rotated the existing database password'
grep -qx 'COMPOSE_PROJECT_NAME=control-plane' "$TMP/control-plane/.env" || fail 'pre-AI migration changed durable storage project'
grep -q '^TUNNEX_AI_ENGINE_ENCRYPTION_KEY=.' "$TMP/control-plane/.env" || fail 'pre-AI migration omitted the durable engine key'
grep -q '^TUNNEX_AI_CUSTOM_PROXY_PASSWORD=.' "$TMP/control-plane/.env" || fail 'pre-AI migration omitted the private proxy credential'
[ -f "$TMP/control-plane/ai-egress-policy.json" ] || fail 'pre-AI migration omitted the outbound policy'
grep -Fq 'Preserving existing .env configuration' "$TMP/pre-ai-migration-output" || fail 'pre-AI migration did not reuse installed settings'
grep -qx 'TUNNEX_VERSION=v9.9.9' "$TMP/control-plane/.env" || fail 'pre-AI migration retained stale version metadata'
grep -qx "TUNNEX_SOURCE_REF=$SOURCE_SHA" "$TMP/control-plane/.env" || fail 'pre-AI migration retained stale source metadata'
for image in API WEB NGINX NODE_AGENT MIGRATE; do
  grep -q "^TUNNEX_${image}_IMAGE=ghcr.io/tunnexio/tunnex-.*@sha256:test$" \
    "$TMP/control-plane/.env" || fail 'pre-AI migration did not update a verified image pin'
done
grep -qx 'TUNNEX_AI_ENGINE_IMAGE=ghcr.io/tunnexio/tunnex-ai-engine@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa' \
  "$TMP/control-plane/.env" || fail 'pre-AI migration omitted the signed engine pin'
cmp -s "$ROOT/deploy/ai-bootstrap.sh" "$TMP/control-plane/ai-bootstrap.sh" || fail 'pre-AI migration did not install the new signed-source helper'
cmp -s "$ROOT/deploy/ai-gateway/config-managed.json" "$TMP/control-plane/ai-engine.json" || fail 'pre-AI migration changed the managed bootstrap config'
"$PYTHON3" -c 'import json,sys; c=json.load(open(sys.argv[1])); assert "providers" not in c; assert c["governance"]["virtual_keys"] == []' \
  "$TMP/control-plane/ai-engine.json" || fail 'pre-AI migration seeded provider state or model grants'

# An installation with the original three AI secrets can add proxy setup
# without replacing its matching encryption key or retained engine volumes.
mkdir "$TMP/ai-legacy"
sed '/^TUNNEX_AI_CUSTOM_/d' \
  "$TMP/ai-before.env" >"$TMP/ai-legacy/.env"
cp "$TMP/ai-before.json" "$TMP/ai-legacy/ai-engine.json"
(TUNNEX_COMPOSE_PROJECT=custom-ai-project TUNNEX_TEST_AI_EXISTING_VOLUME=1 \
  run_ai_install "$TMP/ai-legacy" https://preview.tunnex.test) >"$TMP/ai-legacy-output"
for key in TUNNEX_AI_GATEWAY_ADMIN_USER TUNNEX_AI_GATEWAY_ADMIN_PASSWORD TUNNEX_AI_ENGINE_ENCRYPTION_KEY; do
	grep "^$key=" "$TMP/ai-before.env" >"$TMP/ai-secret-before"
	grep "^$key=" "$TMP/ai-legacy/.env" >"$TMP/ai-secret-after"
	cmp -s "$TMP/ai-secret-before" "$TMP/ai-secret-after" || fail 'proxy bootstrap rotated an existing engine secret'
done
[ -f "$TMP/ai-legacy/ai-egress-policy.json" ] || fail 'legacy AI installation omitted automatic egress policy'

(TUNNEX_DATABASE_MODE=external TUNNEX_DATABASE_URL_FILE="$TMP/db-url" \
  run_ai_install "$TMP/ai-byodb" https://preview.tunnex.test) >"$TMP/ai-byodb-output"
"$PYTHON3" -c 'import json,sys; p=json.load(open(sys.argv[1])); assert "postgres" not in p["protected_hosts"]; assert "caddy" in p["protected_hosts"]' \
  "$TMP/ai-byodb/ai-egress-policy.json" || fail 'external DB policy protected an absent bundled database'
! grep -Fq byodb-file-secret "$TMP/ai-byodb-output" || fail 'AI bootstrap printed the external database credential'

# IPv6 origin brackets and ports must not enter DNS protected-host lookups.
(TUNNEX_TLS_MODE=terminated run_ai_install "$TMP/ai-ipv6" 'https://[2001:db8::12]:8443') >"$TMP/ai-ipv6-output"
"$PYTHON3" -c 'import json,sys; p=json.load(open(sys.argv[1])); assert "2001:db8::12" in p["protected_hosts"]; assert not any("[" in host for host in p["protected_hosts"])' \
  "$TMP/ai-ipv6/ai-egress-policy.json" || fail 'IPv6 policy retained URL brackets or port'
(TUNNEX_HOST_KERNEL=MINGW64_NT run_ai_install "$TMP/ai-windows" https://preview.tunnex.test) >"$TMP/ai-windows-output"
grep -qx 'TUNNEX_PORTABLE_CONTROL_PLANE=true' "$TMP/ai-windows/.env" || fail 'Windows AI bootstrap lost its portable mode'
[ -f "$TMP/ai-windows/ai-egress-policy.json" ] || fail 'Windows canonical installer omitted the AI egress policy'

# Native Windows Compose reads bind sources directly from dotenv. Simulate
# cygpath without changing hosts to prove native-path persistence and POSIX
# file checks on the next run; relative paths must still be refused.
cat >"$BIN/cygpath" <<'EOF'
#!/bin/sh
[ "$2" = -- ] || exit 1
case "$1" in
  -m) case "$3" in /*) printf 'C:%s\n' "$3" ;; *) exit 1 ;; esac ;;
  -u) case "$3" in C:/*) printf '%s\n' "${3#C:}" ;; *) exit 1 ;; esac ;;
  *) exit 1 ;;
esac
EOF
chmod +x "$BIN/cygpath"
(TUNNEX_HOST_KERNEL=MINGW64_NT run_ai_install "$TMP/ai-windows-native" https://preview.tunnex.test) >"$TMP/ai-windows-native-output"
"$PYTHON3" - "$TMP/ai-windows-native" <<'PYTHON'
from pathlib import Path
import sys
installation = Path(sys.argv[1]).resolve()
env = dict(line.split("=", 1) for line in (installation / ".env").read_text().splitlines() if "=" in line)
policy_path = env["TUNNEX_AI_CUSTOM_ENDPOINTS_FILE"]
assert policy_path.startswith("C:/")
assert Path(policy_path[2:]).resolve() == installation / "ai-egress-policy.json"
PYTHON
[ -f "$TMP/ai-windows-native/ai-egress-policy.json" ] || fail 'Windows shell did not create the POSIX policy source'
cp "$TMP/ai-windows-native/.env" "$TMP/ai-windows-native-before.env"
cp "$TMP/ai-windows-native/ai-egress-policy.json" "$TMP/ai-windows-native-before.json"
(TUNNEX_HOST_KERNEL=MINGW64_NT run_ai_install "$TMP/ai-windows-native" https://preview.tunnex.test) >"$TMP/ai-windows-native-rerun-output"
cmp -s "$TMP/ai-windows-native-before.env" "$TMP/ai-windows-native/.env" || fail 'Windows native-path rerun changed durable settings'
cmp -s "$TMP/ai-windows-native-before.json" "$TMP/ai-windows-native/ai-egress-policy.json" || fail 'Windows native-path rerun changed policy rules'
sed 's|^TUNNEX_AI_CUSTOM_ENDPOINTS_FILE=.*|TUNNEX_AI_CUSTOM_ENDPOINTS_FILE=relative-policy.json|' \
  "$TMP/ai-windows-native/.env" >"$TMP/ai-windows-relative.env"
cp "$TMP/ai-windows-relative.env" "$TMP/ai-windows-native/.env"
if (TUNNEX_HOST_KERNEL=MINGW64_NT run_ai_install "$TMP/ai-windows-native" https://preview.tunnex.test) >"$TMP/ai-windows-relative-output" 2>&1; then
  fail 'Windows path conversion accepted a relative policy source'
fi
cmp -s "$TMP/ai-windows-relative.env" "$TMP/ai-windows-native/.env" || fail 'Windows path refusal changed protected settings'
grep -Fq 'policy path must be absolute' "$TMP/ai-windows-relative-output" || fail 'Windows relative path failed outside the policy guard'
rm "$BIN/cygpath"

run_ai_install "$TMP/ai-http" http://192.0.2.10 >"$TMP/ai-http-output"
grep -qx 'TUNNEX_AI_GATEWAY_URL=http://bifrost:8080' "$TMP/ai-http/.env" || fail 'HTTP bootstrap omitted the internal backend needed for UI opt-in'
[ -f "$TMP/ai-http/ai-engine.json" ] || fail 'HTTP evaluation omitted its backend'
grep -Fq 'Settings > AI Gateway transport' "$TMP/ai-http-output" || fail 'HTTP bootstrap did not explain the admin setting'
grep -qx 'TUNNEX_AI_ALLOW_PRIVATE_HTTP=false' "$TMP/ai-http/.env" || fail 'private HTTP AI was not disabled by default'
(TUNNEX_AI_ALLOW_PRIVATE_HTTP=true run_ai_install "$TMP/ai-http-private" http://192.0.2.10) >"$TMP/ai-private-http-output"
grep -qx 'TUNNEX_AI_GATEWAY_URL=http://bifrost:8080' "$TMP/ai-http-private/.env" || fail 'explicit private HTTP policy did not enable integration'
grep -qx 'TUNNEX_AI_ALLOW_PRIVATE_HTTP=true' "$TMP/ai-http-private/.env" || fail 'explicit private HTTP policy was not persisted'
grep -Fq 'separate instance-admin opt-in' "$TMP/ai-private-http-output" || fail 'legacy environment policy was presented as the UI opt-in'
cp "$TMP/ai-http-private/.env" "$TMP/ai-private-before.env"
run_ai_install "$TMP/ai-http-private" http://192.0.2.10 >"$TMP/ai-private-rerun-output"
cmp -s "$TMP/ai-private-before.env" "$TMP/ai-http-private/.env" || fail 'rerun changed the explicit private HTTP policy or durable keys'
if (TUNNEX_AI_ALLOW_PRIVATE_HTTP=automatic run_ai_install "$TMP/ai-http-invalid" http://192.0.2.10) >"$TMP/ai-invalid-output" 2>&1; then
	fail 'invalid private HTTP policy was accepted'
fi

if (TUNNEX_TEST_AI_PIN_MISSING=1 run_ai_install "$TMP/ai-unverified" https://preview.tunnex.test) >"$TMP/ai-pin-output" 2>&1; then
	fail 'engine without a signed image pin was accepted'
fi
[ ! -f "$TMP/ai-unverified/tunnex.yml" ] || fail 'missing AI pin published a deployment'
if (TUNNEX_TEST_AI_EXISTING_VOLUME=1 run_ai_install "$TMP/ai-lost-key" https://preview.tunnex.test) >"$TMP/ai-lost-output" 2>&1; then
	fail 'retained encrypted storage received a replacement key'
fi
[ ! -f "$TMP/ai-lost-key/.env" ] || fail 'missing durable key was silently regenerated'

# Every proxy refusal happens before publishing a deployment or mutating
# protected settings, and prints no proxy password or authenticated URL.
for fault in partial duplicate missing-policy operator-proxy; do
	mkdir "$TMP/ai-$fault"
	cp "$TMP/ai-before.env" "$TMP/ai-$fault/.env"
	cp "$TMP/ai-before.json" "$TMP/ai-$fault/ai-engine.json"
	printf '%s\n' '# original deployment' >"$TMP/ai-$fault/tunnex.yml"
	case "$fault" in
	partial)
		expected='AI egress credentials are incomplete'
		sed '/^TUNNEX_AI_CUSTOM_PROXY_PASSWORD=/d' "$TMP/ai-$fault/.env" >"$TMP/ai-fault.env" ;;
	duplicate)
		expected='AI egress configuration contains duplicate entries'
		cp "$TMP/ai-$fault/.env" "$TMP/ai-fault.env"
		grep '^TUNNEX_AI_CUSTOM_PROXY_USERNAME=' "$TMP/ai-$fault/.env" >>"$TMP/ai-fault.env" ;;
	missing-policy)
		expected='configured AI egress policy is missing or unreadable'
		sed "s|^TUNNEX_AI_CUSTOM_ENDPOINTS_FILE=.*|TUNNEX_AI_CUSTOM_ENDPOINTS_FILE=$TMP/no-such-policy.json|" \
		  "$TMP/ai-$fault/.env" >"$TMP/ai-fault.env" ;;
	operator-proxy)
		expected='operator-managed AI egress proxy'
		sed 's|^TUNNEX_AI_CUSTOM_PROXY_URL=.*|TUNNEX_AI_CUSTOM_PROXY_URL=http://operator:do-not-print@elsewhere:8190|' \
		  "$TMP/ai-$fault/.env" >"$TMP/ai-fault.env" ;;
	esac
	cp "$TMP/ai-fault.env" "$TMP/ai-$fault/.env"
	if (TUNNEX_COMPOSE_PROJECT=custom-ai-project run_ai_install "$TMP/ai-$fault" https://preview.tunnex.test) >"$TMP/ai-$fault-output" 2>&1; then
		fail "AI egress accepted $fault configuration"
	fi
	grep -Fq "$expected" "$TMP/ai-$fault-output" || fail 'egress refusal did not exercise its expected guard'
	cmp -s "$TMP/ai-fault.env" "$TMP/ai-$fault/.env" || fail 'egress refusal changed protected configuration'
	grep -qx '# original deployment' "$TMP/ai-$fault/tunnex.yml" || fail 'egress refusal published a new deployment'
	! grep -Fq do-not-print "$TMP/ai-$fault-output" || fail 'egress refusal printed an operator secret'
	proxy_password=$(sed -n 's/^TUNNEX_AI_CUSTOM_PROXY_PASSWORD=//p' "$TMP/ai-before.env")
	! grep -Fq "$proxy_password" "$TMP/ai-$fault-output" || fail 'egress refusal printed a proxy secret'
done

# Missing one credential refuses before publishing or changing installed files.
sed '/^TUNNEX_AI_ENGINE_ENCRYPTION_KEY=/d' "$TMP/ai-https/.env" >"$TMP/ai-partial.env"
cp "$TMP/ai-partial.env" "$TMP/ai-https/.env"
cp "$TMP/ai-https/tunnex.yml" "$TMP/ai-before.yml"
if run_ai_install "$TMP/ai-https" https://preview.tunnex.test >"$TMP/ai-partial-output" 2>&1; then
	fail 'partial AI credentials were regenerated'
fi
cmp -s "$TMP/ai-partial.env" "$TMP/ai-https/.env" || fail 'partial credential refusal changed existing secrets'
cmp -s "$TMP/ai-before.yml" "$TMP/ai-https/tunnex.yml" || fail 'partial credential refusal changed the deployment'

printf 'install host bootstrap contract: PASS\n'
