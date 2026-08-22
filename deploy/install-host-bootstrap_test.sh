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
YAML
	;;
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
	'[1/5] Checking this host' \
	'Install or complete Docker Engine, Compose v2, and required utilities for ubuntu' \
	'[2/5] Selecting a verified Tunnex release' \
	'[3/5] Configuring your control plane' \
	'[4/5] Reviewing the installation plan' \
	'Public URL       https://preview.tunnex.test' \
	'TLS mode         terminated' \
	'[5/5] Installing and verifying Tunnex' \
	'Docker Engine and Compose v2 are ready.' \
	'Tunnex v9.9.9 is running.'; do
	grep -Fq "$expected" "$OUTPUT" || fail "local preview omitted: $expected"
done

grep -Fq 'docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin' "$APT_LOG" ||
	fail 'fresh Ubuntu preview did not install the complete Docker Engine + Compose set'
grep -Fq 'TUNNEX_TLS_MODE=terminated' "$TMP/control-plane/.env" ||
	fail 'generated environment lost the selected TLS mode'
grep -Fq 'TUNNEX_PORTABLE_CONTROL_PLANE=false' "$TMP/control-plane/.env" ||
	fail 'Linux install was not recorded as the co-located gateway shape'
grep -Fq 'TUNNEX_RELEASE_SOURCE_SHA=0123456789abcdef0123456789abcdef01234567' "$TMP/control-plane/.env" ||
	fail 'generated environment lost verified release provenance'
grep -Fq 'COMPOSE_PROJECT_NAME=control-plane' "$TMP/control-plane/.env" ||
	fail 'installer did not persist an installation-specific Compose project name'

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
grep -Fq 'Portable control plane; enroll the gateway on a separate Linux host' "$TMP/portable-output.txt" ||
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
grep -Fq 'Portable control plane; enroll the gateway on a separate Linux host' "$TMP/windows-portable-output.txt" ||
	fail 'Windows/Git Bash onboarding did not disclose the portable control-plane boundary'
grep -Fq 'TUNNEX_PORTABLE_CONTROL_PLANE=true' "$TMP/windows-portable/.env" ||
	fail 'Windows/Git Bash install did not persist the portable control-plane boundary'
grep -Fq 'compose --project-name windows-portable --env-file .env -f tunnex.yml up -d --wait --scale node-agent=0' "$WINDOWS_DOCKER_LOG" ||
	fail 'Windows/Git Bash install attempted to start the privileged node-agent'

# Drive the actual customer path through a pseudo-terminal. Unlike the
# environment-only fixture above, this exercises each visible question, masked
# secret entry, review, confirmation, fresh-host Docker plan, and final handoff.
cat >"$TMP/pty-walkthrough.py" <<'PYTHON'
import errno
import os
import pty
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
TUNNEX_COLOR=always \
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
	'Proceed with this installation? [Y/n]:' \
	'Email            mail.preview.tunnex.test:587 as support@preview.tunnex.test' \
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
RPM_LOG="$TMP/rpm.log"
mkdir -p "$RPM_BIN"
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
PATH="$RPM_BIN:/usr/bin:/bin" TUNNEX_TEST_RPM_LOG="$RPM_LOG" sh "$TMP/yum-bootstrap-test.sh" ||
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
PATH="$MAC_BIN:/usr/bin:/bin" \
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
PATH="$MAC_BIN:/usr/bin:/bin" \
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
PATH="$ROOT_BIN:/usr/bin:/bin" sh "$TMP/root-socket-test.sh" ||
	fail 'root-only Docker socket was not handled for the current install'
[ ! -e "$TMP/root-socket-tried-to-start-docker" ] ||
	fail 'usable root-only Docker socket was mistaken for a stopped daemon'

printf 'install host bootstrap contract: PASS\n'
