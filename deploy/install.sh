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
# Prerequisite: a Linux or macOS host AND a public address (a DNS name or public IP users + gateways
# can reach). Windows enters through install.ps1, which prepares the native host before handing off to
# this shared product flow. Docker Engine/desktop + Compose v2 are prepared when absent; the installer
# does not conjure the server, DNS, or firewall rules.
#
# Non-interactive / piped-with-no-terminal: set the inputs as env vars so the pipe still works:
#     curl -fsSL <url> | TUNNEX_PUBLIC_BASE_URL=https://vpn.acme.com TUNNEX_ADMIN_EMAIL=owner@example.com TUNNEX_SMTP=skip sh
# For SMTP=configure non-interactively, also export SMTP_HOST/SMTP_PORT/SMTP_USERNAME/SMTP_PASSWORD/SMTP_FROM.
#
# Idempotent: re-running against an existing ./tunnex REUSES the generated DB password (a fresh one
# would not match the existing postgres volume) and never leaves a half-written .env (write-then-move).
set -eu
umask 077

REPO="tunnexio/tunnex"
RAW="https://raw.githubusercontent.com/${REPO}"
API="https://api.github.com/repos/${REPO}"
DIR="${TUNNEX_DIR:-tunnex}"
# Trusted release verification key. The matching private signing key remains in CI only.
TRUSTED_RELEASE_PUBLIC_KEY=b48ff99923c43052ade580cdca63952690f07f08372c35814baa44cb84d674a0

say() { printf '%s\n' "$*"; }
die() { printf '%s✗%s %s\n' "${TUNNEX_ERROR:-}" "${TUNNEX_RESET:-}" "$*" >&2; exit 1; }
as_root() {
	if [ "$(id -u)" -eq 0 ]; then "$@"; return; fi
	command -v sudo >/dev/null 2>&1 || die "sudo is required to prepare this Tunnex Server host"
	sudo "$@"
}
file_sha256() {
	if command -v sha256sum >/dev/null 2>&1; then
		sha256sum "$1" | awk '{print $1}'
	else
		shasum -a 256 "$1" | awk '{print $1}'
	fi
}

setup_palette() {
	TUNNEX_WHITE=''
	TUNNEX_RED=''
	TUNNEX_CYAN=''
	TUNNEX_AMBER=''
	TUNNEX_ERROR=''
	TUNNEX_DIM=''
	TUNNEX_RESET=''
	[ -z "${NO_COLOR+x}" ] || return 0
	[ "${TERM:-}" != dumb ] || return 0
	case "${TUNNEX_COLOR:-auto}" in
	always) : ;;
	auto) [ -t 1 ] || return 0 ;;
	never) return 0 ;;
	*) die "TUNNEX_COLOR must be auto, always, or never" ;;
	esac
	TUNNEX_WHITE="$(printf '\033[1;97m')"
	TUNNEX_RED="$(printf '\033[1;31m')"
	TUNNEX_CYAN="$(printf '\033[1;36m')"
	TUNNEX_AMBER="$(printf '\033[1;33m')"
	TUNNEX_ERROR="$(printf '\033[1;31m')"
	TUNNEX_DIM="$(printf '\033[2m')"
	TUNNEX_RESET="$(printf '\033[0m')"
}
# Original installer wordmark, retained at the user-requested compact size.
# Connected E and symmetric X, approved for terminal legibility.
ui_motion() {
	[ -t 1 ] && [ "${TERM:-}" != dumb ] && [ -z "${NO_COLOR+x}" ] &&
		[ "${TUNNEX_LOADER:-auto}" != never ]
}
# Original compact glyphs and spacing, with one red for every EX row.
wordmark_row() {
	printf '  %s%s%s%s%s%s\n' "$TUNNEX_WHITE" "$1" "$TUNNEX_RESET" "$TUNNEX_RED" "$2" "$TUNNEX_RESET"
	if ui_motion; then sleep 0.12; fi
}
# A short decorative sweep; never presented as installation progress.
brand_sweep() {
	ui_motion || return 0
	_sweep_step=0
	while [ "$_sweep_step" -lt 12 ]; do
		printf '\r    '
		_sweep_cell=0
		while [ "$_sweep_cell" -lt 12 ]; do
			if [ "$_sweep_cell" -eq "$_sweep_step" ]; then
				printf '%s━━%s' "$TUNNEX_CYAN" "$TUNNEX_RESET"
			else
				printf '%s──%s' "$TUNNEX_DIM" "$TUNNEX_RESET"
			fi
			_sweep_cell=$((_sweep_cell + 1))
		done
		sleep 0.07
		_sweep_step=$((_sweep_step + 1))
	done
	printf '\r\033[2K'
}
print_wordmark() {
	say ''
	printf '  %sTUNNEX / GUIDED SETUP%s\n\n' "$TUNNEX_DIM" "$TUNNEX_RESET"
	wordmark_row '▀█▀ █ █ █▄ █ █▄ █ ' '█▀▀ ▀▄▀'
	wordmark_row ' █  █ █ █ ▀█ █ ▀█ ' '█▀▀ ▄▀▄'
	wordmark_row ' ▀  ▀▀▀ ▀  ▀ ▀  ▀ ' '▀▀▀ ▀ ▀'

	brand_sweep
	printf '  %sConnect Everything. Trust Nothing.%s\n' "$TUNNEX_WHITE" "$TUNNEX_RESET"
	printf '\n  %s────────────────────────────────────────────%s\n' "$TUNNEX_DIM" "$TUNNEX_RESET"
}
stage() {
	printf '\n  '
	_stage_index=1
	while [ "$_stage_index" -le 5 ]; do
		if [ "$_stage_index" -lt "$1" ]; then
			printf '%s━%s' "$TUNNEX_CYAN" "$TUNNEX_RESET"
		elif [ "$_stage_index" -eq "$1" ]; then
			printf '%s●%s' "$TUNNEX_RED" "$TUNNEX_RESET"
		else
			printf '%s─%s' "$TUNNEX_DIM" "$TUNNEX_RESET"
		fi
		if ui_motion; then sleep 0.035; fi
		_stage_index=$((_stage_index + 1))
	done
	printf '  %s[%s/5] %s%s\n\n' "$TUNNEX_WHITE" "$1" "$2" "$TUNNEX_RESET"
}
info() {
	printf '    %s·%s %s\n' "$TUNNEX_DIM" "$TUNNEX_RESET" "$1"
}
success() {
	printf '    %s✓%s %s\n' "$TUNNEX_CYAN" "$TUNNEX_RESET" "$1"
}
warn() {
	printf '    %s!%s %s\n' "$TUNNEX_AMBER" "$TUNNEX_RESET" "$1"
}
plan_start() {
	printf '\n    %s╭─%s %sQuickStart plan%s\n' "$TUNNEX_DIM" "$TUNNEX_RESET" "$TUNNEX_WHITE" "$TUNNEX_RESET"
}
plan_item() {
	printf '    %s│%s  %s%-18s%s %s\n' "$TUNNEX_DIM" "$TUNNEX_RESET" "$TUNNEX_DIM" "$1" "$TUNNEX_RESET" "$2"
}
plan_end() {
	printf '    %s╰─────────────────────────────────────────%s\n' "$TUNNEX_DIM" "$TUNNEX_RESET"
}
preview_complete() {
	printf '\n  %s╭─ %sPREVIEW COMPLETE%s\n' "$TUNNEX_CYAN" "$TUNNEX_WHITE" "$TUNNEX_RESET"
	printf '  %s│%s  This was a simulation. Nothing was installed.\n' "$TUNNEX_CYAN" "$TUNNEX_RESET"
	printf '  %s│%s  %sNext%s  Dashboard → Sign in → Enroll gateway\n' "$TUNNEX_CYAN" "$TUNNEX_RESET" "$TUNNEX_WHITE" "$TUNNEX_RESET"
	printf '  %s╰───────────────────────────────────────────%s\n\n' "$TUNNEX_CYAN" "$TUNNEX_RESET"
}
show_setup_boundary() {
	printf '\n%sTUNNEX SETUP%s\n' "$TUNNEX_RED" "$TUNNEX_RESET"
	printf '%s╭─%s %sSecurity boundary%s\n' "$TUNNEX_RED" "$TUNNEX_RESET" "$TUNNEX_WHITE" "$TUNNEX_RESET"
	printf '  %s│%s Tunnex Server manages your users, Linux gateways and access settings.\n' "$TUNNEX_RED" "$TUNNEX_RESET"
	printf '  %s│%s Your public URL is used for sign-in, email links, and gateway enrollment.\n' "$TUNNEX_RED" "$TUNNEX_RESET"
	printf '  %s│%s Keep the host patched and expose only the ports required by your TLS mode.\n' "$TUNNEX_RED" "$TUNNEX_RESET"
	printf '  %s│%s macOS and Windows run Tunnex Server; their gateway stays on Linux.\n' "$TUNNEX_RED" "$TUNNEX_RESET"
	printf '%s╰────────────────────────────────────────────────────────────%s\n' "$TUNNEX_RED" "$TUNNEX_RESET"
	info 'A separate Linux gateway is recommended. Review every change before installation.'
}
# Run a command while keeping an interactive terminal informed. Unlike the
# OpenClaw installer, this needs no downloaded UI binary: the loader is native
# POSIX shell, is disabled for non-interactive automation, and prints the
# captured command output only when that command fails.
run_with_loader() {
	_loader_title=$1
	shift
	if ! have_tty || [ ! -t 1 ] || [ "${TERM:-}" = dumb ] || [ -n "${NO_COLOR+x}" ] || [ "${TUNNEX_LOADER:-auto}" = never ]; then
		info "${_loader_title}"
		"$@"
		return
	fi
	_loader_log=$(mktemp "${TMPDIR:-/tmp}/tunnex-loader.XXXXXX") || {
		info "${_loader_title}"
		"$@"
		return
	}
	(
		while :; do
			for _loader_frame in '⠋' '⠙' '⠹' '⠸' '⠼' '⠴' '⠦' '⠧' '⠇' '⠏'; do
				if [ "$TUNNEX_TTY_DEVICE" = - ]; then
					printf '\r    %s%s%s %s' "$TUNNEX_CYAN" "$_loader_frame" "$TUNNEX_RESET" "$_loader_title" >&2
				else
					printf '\r    %s%s%s %s' "$TUNNEX_CYAN" "$_loader_frame" "$TUNNEX_RESET" "$_loader_title" >"$TUNNEX_TTY_DEVICE"
				fi
				sleep 0.1
			done
		done
	) &
	_loader_pid=$!
	if "$@" >"$_loader_log" 2>&1; then _loader_status=0; else _loader_status=$?; fi
	kill "$_loader_pid" 2>/dev/null || true
	wait "$_loader_pid" 2>/dev/null || true
	if [ "$TUNNEX_TTY_DEVICE" = - ]; then
		printf '\r\033[2K' >&2
	else
		printf '\r\033[2K' >"$TUNNEX_TTY_DEVICE"
	fi
	if [ "$_loader_status" -ne 0 ]; then
		warn "${_loader_title} failed"
		tail -n 80 "$_loader_log" >&2 || true
	else
		success "${_loader_title}"
	fi
	rm -f "$_loader_log"
	return "$_loader_status"
}

# BEGIN INSTALL CONFIRMATION — extracted by deploy/install-host-bootstrap_test.sh.
confirm_installation() {
	if [ "$AUTO_CONFIRM" = false ] && have_tty; then
		case "$(ask 'Proceed with this installation? [Y/n]: ')" in
		n|N|no|NO) say ">> Cancelled before changing the host."; exit 0 ;;
		esac
	fi
}
# END INSTALL CONFIRMATION

# BEGIN HOST BOOTSTRAP — extracted by deploy/install-host-bootstrap_test.sh.
DOCKER_AS_ROOT=false
docker_cli() {
	if [ "$DOCKER_AS_ROOT" = true ]; then
		as_root docker "$@"
	else
		docker "$@"
	fi
}
load_host_os() {
	HOST_KERNEL=${TUNNEX_HOST_KERNEL:-$(uname -s)}
	HOST_OS_ID=''
	HOST_OS_CODENAME=''
	HOST_PACKAGE_MANAGER=''
	case "$HOST_KERNEL" in
	Linux)
		_os_release=${TUNNEX_OS_RELEASE_FILE:-/etc/os-release}
		if [ -r "$_os_release" ]; then
			# os-release is shell-compatible, but it is host input, not installer code.
			# Read only the descriptive keys required for package selection; never source it.
			while IFS= read -r _os_release_line || [ -n "$_os_release_line" ]; do
				case "$_os_release_line" in
				ID=*) _os_release_key=ID ;;
				VERSION_CODENAME=*) _os_release_key=VERSION_CODENAME ;;
				UBUNTU_CODENAME=*) _os_release_key=UBUNTU_CODENAME ;;
				*) continue ;;
				esac
				_os_release_value=${_os_release_line#*=}
				case "$_os_release_value" in
				\"*\") _os_release_value=${_os_release_value#\"}; _os_release_value=${_os_release_value%\"} ;;
				\'*\') _os_release_value=${_os_release_value#\'}; _os_release_value=${_os_release_value%\'} ;;
				esac
				case "$_os_release_value" in
				''|*[!A-Za-z0-9._-]*) continue ;;
				esac
				case "$_os_release_key" in
				ID) HOST_OS_ID=$_os_release_value ;;
				VERSION_CODENAME) HOST_OS_CODENAME=$_os_release_value ;;
				UBUNTU_CODENAME) [ -n "$HOST_OS_CODENAME" ] || HOST_OS_CODENAME=$_os_release_value ;;
				esac
			done <"$_os_release"
			[ -n "$HOST_OS_ID" ] || HOST_OS_ID=linux
		else
			HOST_OS_ID=linux
		fi
		for _pm in apt-get dnf yum zypper pacman apk; do
			if command -v "$_pm" >/dev/null 2>&1; then HOST_PACKAGE_MANAGER=$_pm; break; fi
		done
		[ -n "$HOST_PACKAGE_MANAGER" ] ||
			die "no supported package manager was found. Install Docker Engine + Compose v2, then re-run the same command."
		;;
	Darwin)
		HOST_OS_ID=macos
		HOST_PACKAGE_MANAGER=brew
		;;
	MINGW*|MSYS*|CYGWIN*)
		HOST_OS_ID=windows
		HOST_PACKAGE_MANAGER=windows
		;;
	*) die "automatic runtime preparation is not available for ${HOST_KERNEL}. Install Docker + Compose v2, then re-run." ;;
	esac
}
install_apt_prerequisites() {
	as_root apt-get update
	as_root env DEBIAN_FRONTEND=noninteractive apt-get install -y ca-certificates curl gnupg openssl
	if ! command -v docker >/dev/null 2>&1; then
		case "$HOST_OS_ID" in
		ubuntu|debian)
			[ -n "$HOST_OS_CODENAME" ] || die "cannot determine the ${HOST_OS_ID} release codename for Docker packages"
			_key_tmp=$(mktemp "${TMPDIR:-/tmp}/tunnex-docker-key.XXXXXX")
			_repo_tmp=$(mktemp "${TMPDIR:-/tmp}/tunnex-docker-repo.XXXXXX")
			trap 'rm -f "$_key_tmp" "$_repo_tmp"' EXIT INT TERM
			curl -fsSL "https://download.docker.com/linux/${HOST_OS_ID}/gpg" -o "$_key_tmp" ||
				die "could not download Docker's repository signing key"
			as_root install -d -m 0755 /etc/apt/keyrings
			as_root install -m 0644 "$_key_tmp" /etc/apt/keyrings/docker.asc
			_arch=$(dpkg --print-architecture)
			printf 'deb [arch=%s signed-by=/etc/apt/keyrings/docker.asc] https://download.docker.com/linux/%s %s stable\n' \
				"$_arch" "$HOST_OS_ID" "$HOST_OS_CODENAME" >"$_repo_tmp"
			as_root install -m 0644 "$_repo_tmp" /etc/apt/sources.list.d/docker.list
			as_root apt-get update
			as_root env DEBIAN_FRONTEND=noninteractive apt-get install -y \
				docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin
			rm -f "$_key_tmp" "$_repo_tmp"
			trap - EXIT INT TERM
			;;
		*)
			# An apt-compatible derivative need not have an official Docker CE repository.
			# Prefer its maintained native packages rather than guessing a repository URL.
			as_root env DEBIAN_FRONTEND=noninteractive apt-get install -y docker.io
			if ! as_root env DEBIAN_FRONTEND=noninteractive apt-get install -y docker-compose-v2; then
				as_root env DEBIAN_FRONTEND=noninteractive apt-get install -y docker-compose-plugin
			fi
			;;
		esac
	elif ! docker compose version >/dev/null 2>&1; then
		if as_root env DEBIAN_FRONTEND=noninteractive apt-get install -y docker-compose-v2; then
			:
		elif as_root env DEBIAN_FRONTEND=noninteractive apt-get install -y docker-compose-plugin; then
			:
		else
			die "Docker exists but Compose v2 could not be added without replacing it. Install a Compose v2 plugin compatible with this Docker distribution, then re-run."
		fi
	fi
}
install_rpm_prerequisites() {
	if command -v dnf >/dev/null 2>&1; then
		_rpm=dnf
		_rpm_config_manager='dnf config-manager'
	else
		_rpm=yum
		_rpm_config_manager=yum-config-manager
	fi
	command -v "$_rpm" >/dev/null 2>&1 || die "${HOST_OS_ID} has neither dnf nor yum"
	as_root "$_rpm" -y install ca-certificates curl openssl
	if ! command -v docker >/dev/null 2>&1; then
		case "$HOST_OS_ID" in fedora) _repo_os=fedora ;; *) _repo_os=centos ;; esac
		if [ "$_rpm" = dnf ]; then
			as_root "$_rpm" -y install dnf-plugins-core
		else
			as_root "$_rpm" -y install yum-utils
		fi
		# dnf exposes `dnf config-manager`; yum-utils exposes the separate
		# `yum-config-manager` executable. Calling the former through yum aborts
		# a fresh RHEL-family bootstrap before Docker can be installed.
		as_root $_rpm_config_manager --add-repo "https://download.docker.com/linux/${_repo_os}/docker-ce.repo"
		as_root "$_rpm" -y install docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin
	elif ! docker compose version >/dev/null 2>&1; then
		as_root "$_rpm" -y install docker-compose-plugin ||
			die "Docker exists but Compose v2 could not be added without replacing it. Install a compatible Compose v2 plugin, then re-run."
	fi
}
install_zypper_prerequisites() {
	as_root zypper --non-interactive refresh
	as_root zypper --non-interactive install ca-certificates curl openssl docker docker-compose
}
install_pacman_prerequisites() {
	as_root pacman -Sy --noconfirm ca-certificates curl openssl docker docker-compose
}
install_apk_prerequisites() {
	as_root apk add ca-certificates curl openssl docker docker-cli-compose
}
wait_for_docker() {
	_waited=0
	while [ "$_waited" -lt "${TUNNEX_DOCKER_WAIT_SECONDS:-120}" ]; do
		if docker info >/dev/null 2>&1 && docker compose version >/dev/null 2>&1; then return 0; fi
		sleep 2
		_waited=$((_waited + 2))
	done
	return 1
}
install_macos_prerequisites() {
	_mac_applications_dir=${TUNNEX_MAC_APPLICATIONS_DIR:-/Applications}
	if [ -d "${_mac_applications_dir}/Docker.app" ]; then
		say ">> Starting Docker Desktop…"
		open -a Docker || die "Docker Desktop is installed but could not be started"
		wait_for_docker || die "Docker Desktop did not become ready. Finish its first-run setup, then re-run the same command."
		return 0
	fi
	if ! command -v brew >/dev/null 2>&1; then
		command -v bash >/dev/null 2>&1 || die "bash is required to install Homebrew on macOS"
		say ">> Installing Homebrew so the container runtime can be prepared…"
		NONINTERACTIVE=1 /bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"
		if [ -x /opt/homebrew/bin/brew ]; then
			PATH="/opt/homebrew/bin:$PATH"
		elif [ -x /usr/local/bin/brew ]; then
			PATH="/usr/local/bin:$PATH"
		else
			die "Homebrew installation finished but brew is not available on PATH"
		fi
		export PATH
	fi
	brew install docker docker-compose colima openssl
	say ">> Starting the Colima container runtime…"
	colima start
	wait_for_docker || die "Colima started but Docker Engine and Compose v2 did not become ready"
}
install_host_prerequisites() {
	load_host_os
	case "$HOST_PACKAGE_MANAGER" in
	apt-get) install_apt_prerequisites ;;
	dnf|yum) install_rpm_prerequisites ;;
	zypper) install_zypper_prerequisites ;;
	pacman) install_pacman_prerequisites ;;
	apk) install_apk_prerequisites ;;
	brew) install_macos_prerequisites ;;
	windows) die "fresh Windows setup uses the PowerShell one-liner so Docker Desktop and Git Bash can be prepared safely" ;;
	esac
}
start_linux_docker() {
	if [ -d /run/systemd/system ] && command -v systemctl >/dev/null 2>&1; then
		as_root systemctl enable --now docker >/dev/null 2>&1 ||
			die "Docker was installed but its system service could not be started"
	elif command -v rc-service >/dev/null 2>&1; then
		as_root rc-service docker start >/dev/null 2>&1 || die "Docker's OpenRC service could not be started"
		command -v rc-update >/dev/null 2>&1 && as_root rc-update add docker default >/dev/null 2>&1 || true
	elif command -v service >/dev/null 2>&1; then
		as_root service docker start >/dev/null 2>&1 || die "Docker's service could not be started"
	fi
}
ensure_docker_ready() {
	if ! command -v openssl >/dev/null 2>&1 ||
	   ! command -v docker >/dev/null 2>&1 ||
	   ! docker compose version >/dev/null 2>&1; then
		install_host_prerequisites
	fi
	[ -n "${HOST_KERNEL:-}" ] || HOST_KERNEL=${TUNNEX_HOST_KERNEL:-$(uname -s)}
	case "$HOST_KERNEL" in
	Linux)
		# Do not rewrite service enablement on a usable installation. A root-only
		# Docker socket is still a usable daemon for this run, so it must not be
		# mistaken for a stopped service either.
		if ! docker info >/dev/null 2>&1 && ! as_root docker info >/dev/null 2>&1; then
			start_linux_docker
		fi
		;;
	Darwin)
		# `docker compose version` only proves the client is installed. If Docker
		# Desktop was stopped, use the same visible startup/resume path as a
		# fresh macOS host before declaring the daemon unusable.
		if ! docker info >/dev/null 2>&1; then install_macos_prerequisites; fi
		;;
	esac
	if docker info >/dev/null 2>&1 && docker compose version >/dev/null 2>&1; then
		DOCKER_AS_ROOT=false
	elif as_root docker info >/dev/null 2>&1 && as_root docker compose version >/dev/null 2>&1; then
		DOCKER_AS_ROOT=true
	else
		die "Docker Engine is installed but the daemon or Compose v2 is not usable"
	fi
	command -v openssl >/dev/null 2>&1 || die "openssl is required for secret generation"
	if [ "$DOCKER_AS_ROOT" = true ] && [ "$(id -u)" -ne 0 ] && command -v getent >/dev/null 2>&1 && getent group docker >/dev/null 2>&1; then
		_user=$(id -un)
		case " $(id -nG) " in
		*" docker "*) : ;;
		*) as_root usermod -aG docker "$_user" || true
		   say ">> Docker access was enabled for ${_user}; it takes effect at the next login. This install will safely use sudo." ;;
		esac
	fi
}
# END HOST BOOTSTRAP

host_is_portable_control_plane() {
	[ -n "${HOST_KERNEL:-}" ] || HOST_KERNEL=${TUNNEX_HOST_KERNEL:-$(uname -s)}
	case "$HOST_KERNEL" in
	Darwin|MINGW*|MSYS*|CYGWIN*) return 0 ;;
	*) return 1 ;;
	esac
}

# BEGIN INSTALL VERSION RESOLVER — the canonical installer owns release selection;
# deploy/install-version-provenance_test.sh extracts and exercises this block directly.
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

# BEGIN DISPLAY VERSION RESOLVER — the selected release tag is already the
# customer-facing version, so no source-build label needs to be synthesized.
resolve_display_version() {
	DISPLAY_VERSION="$VERSION"
}
# END DISPLAY VERSION RESOLVER

# have_tty: can we read from the controlling terminal? True under `curl | sh` on a real terminal
# (stdin is the pipe, but /dev/tty is the keyboard); false in CI / fully-detached pipes.
# The override lets the focused PTY contract use its allocated slave directly
# on hosts whose sandbox forbids reopening /dev/tty; customer installs keep the
# controlling-terminal default.
TUNNEX_TTY_DEVICE=${TUNNEX_TEST_TTY_DEVICE:-/dev/tty}
have_tty() {
	if [ "$TUNNEX_TTY_DEVICE" = - ]; then [ -t 0 ]; else [ -e "$TUNNEX_TTY_DEVICE" ] && { true <"$TUNNEX_TTY_DEVICE"; } 2>/dev/null; fi
}
tty_write() {
	if [ "$TUNNEX_TTY_DEVICE" = - ]; then printf '%s' "$1" >&2; else printf '%s' "$1" >"$TUNNEX_TTY_DEVICE"; fi
}
tty_newline() {
	if [ "$TUNNEX_TTY_DEVICE" = - ]; then printf '\n' >&2; else printf '\n' >"$TUNNEX_TTY_DEVICE"; fi
}
tty_read_line() {
	if [ "$TUNNEX_TTY_DEVICE" = - ]; then IFS= read -r reply; else IFS= read -r reply <"$TUNNEX_TTY_DEVICE"; fi
	printf '%s' "$reply"
}
tty_stty() {
	if [ "$TUNNEX_TTY_DEVICE" = - ]; then stty "$@"; else stty "$@" <"$TUNNEX_TTY_DEVICE"; fi
}
tty_read_byte() {
	if [ "$TUNNEX_TTY_DEVICE" = - ]; then dd bs=1 count=1 2>/dev/null; else dd if="$TUNNEX_TTY_DEVICE" bs=1 count=1 2>/dev/null; fi
}
# ask reads from the TERMINAL even under `curl | sh`.
ask() {
	tty_write "$1"
	tty_read_line || die "no input on the terminal"
}
# BEGIN MASKED SECRET READER — kept behaviorally identical with get.sh; the contract test checks both.
# ask_secret PROMPT — masked raw terminal input. Sets ANSWER while never echoing the secret itself.
# Non-interactive callers must provide SMTP_PASSWORD through the environment; there is no stdin fallback.
ask_secret() {
	_prompt="$1"
	if ! have_tty; then ANSWER=""; return 0; fi
	_saved="$(tty_stty -g 2>/dev/null || true)"
	[ -n "$_saved" ] || die "could not configure the terminal for secret input"
	trap "tty_stty '$_saved' 2>/dev/null || tty_stty echo 2>/dev/null; exit 130" INT TERM
	tty_stty raw -echo 2>/dev/null || { tty_stty "$_saved" 2>/dev/null || true; die "could not disable terminal echo for secret input"; }
	tty_write "$_prompt "
	_secret=''
	while :; do
		_byte="$(tty_read_byte || true)"
		[ -n "$_byte" ] || { tty_stty "$_saved" 2>/dev/null || true; trap - INT TERM; die "secret input ended before Enter"; }
		case "$_byte" in
		"$(printf '\r')" | "$(printf '\n')") break ;;
		"$(printf '\003')") tty_stty "$_saved" 2>/dev/null || true; trap - INT TERM; exit 130 ;;
		"$(printf '\177')" | "$(printf '\010')")
			if [ -n "$_secret" ]; then _secret="${_secret%?}"; tty_write "$(printf '\b \b')"; fi
			;;
		*) _secret="${_secret}${_byte}"; tty_write '*' ;;
		esac
	done
	tty_stty "$_saved" 2>/dev/null || tty_stty echo 2>/dev/null || true
	trap - INT TERM
	tty_newline
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
	*[!0-9.]* | '') return 1 ;;
	*) return 0 ;;
	esac
}
# Certificate issuance needs an unambiguous, publicly routable IPv4 address.
# Reserved, private, documentation and multicast ranges cannot use this mode.
public_ipv4_ok() {
	printf '%s\n' "$1" | awk -F. '
		NF != 4 { exit 1 }
		{
			for (i = 1; i <= 4; i++) {
				if ($i !~ /^[0-9]+$/ || length($i) > 3 || $i ~ /^0[0-9]/ || $i + 0 > 255) exit 1
			}
			a = $1 + 0; b = $2 + 0; c = $3 + 0
			if (a == 0 || a == 10 || a == 127 || a >= 224 ||
			    (a == 100 && b >= 64 && b <= 127) ||
			    (a == 169 && b == 254) || (a == 172 && b >= 16 && b <= 31) ||
			    (a == 192 && (b == 168 || (b == 0 && (c == 0 || c == 2)) || (b == 88 && c == 99))) ||
			    (a == 198 && (b == 18 || b == 19 || (b == 51 && c == 100))) ||
			    (a == 203 && b == 0 && c == 113)) exit 1
		}'
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
		if [ "$_scheme" = https ] && public_base_url_is_ip "$_url"; then
			_ip=$(public_base_url_host "$_url")
			public_ipv4_ok "$_ip" || return 1
			case "${_url#*://}" in "$_ip" | "$_ip:443") ;; *) return 1 ;; esac
		fi
		case "$_scheme:$_port" in https:|https:443|http:|http:80) return 0 ;; esac
		;;
	terminated) [ "$_scheme" = https ] && return 0 ;;
	http) case "$_scheme:$_port" in http:|http:80) return 0 ;; esac ;;
	esac
	return 1
}
# BEGIN EXPLICIT EDGE PROXY VALIDATION
edge_trusted_proxies_ok() {
  printf '%s\n' "$1" | LC_ALL=C awk '
    function ipv4(ip, a,n,i) {
      n=split(ip,a,"."); if(n!=4) return 0
      for(i=1;i<=n;i++) if(a[i]!~/^[0-9]+$/ || length(a[i])>3 || a[i]~/^0[0-9]/ || a[i]+0>255) return 0
      return 1
    }
    function groups(ip, a,n,i) {
      if(ip=="") return 0
      n=split(ip,a,":")
      for(i=1;i<=n;i++) if(a[i]!~/^[0-9a-fA-F]+$/ || length(a[i])>4) return -1
      return n
    }
    function ipv6(ip, a,n,l,r) {
      if(ip!~/^[0-9a-fA-F:]+$/) return 0
      n=split(ip,a,"::")
      if(n==1) return groups(ip)==8
      if(n!=2) return 0
      l=groups(a[1]); r=groups(a[2])
      return l>=0 && r>=0 && l+r<8
    }
    NR!=1 || length($0)>4096 || /[^0-9a-fA-F.:\/ ]/ || NF<1 || NF>64 { exit 1 }
    {
      for(j=1;j<=NF;j++) {
        n=split($j,part,"/"); if(n>2) exit 1
        if(ipv4(part[1])) bits=32
        else if(ipv6(part[1])) bits=128
        else exit 1
        if(n==2 && (part[2]!~/^[1-9][0-9]*$/ || part[2]+0>bits)) exit 1
      }
    }'
}
# END EXPLICIT EDGE PROXY VALIDATION

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
		die "${BASE_URL} is incompatible with TLS mode ${TLS_MODE}. Direct HTTPS needs a DNS hostname or public IPv4 address on port 443; use TUNNEX_TLS_MODE=terminated behind an external TLS endpoint."
	case "$TLS_MODE" in direct) EDGE_LISTEN="$BASE_URL" ;; *) EDGE_LISTEN="http://:80" ;; esac
	EDGE_PUBLIC_IP=
	if [ "$TLS_MODE" = direct ] && [ "$SCHEME" = https ] && public_base_url_is_ip "$BASE_URL"; then
		EDGE_PUBLIC_IP=$(public_base_url_host "$BASE_URL")
	fi
	[ "$SCHEME" = https ] && COOKIE_SECURE=true || COOKIE_SECURE=false
}

# Offline presentation demo: intentionally exits before host/release operations.
ui_preview() {
	print_wordmark
	printf '\n    %sDESIGN PREVIEW%s  ·  Sample data / no installation\n' "$TUNNEX_CYAN" "$TUNNEX_RESET"
	stage 1 'Checking this host'
	run_with_loader 'Checking host requirements' sleep 1
	info 'macOS / Windows · Portable Tunnex Server'
	stage 2 'Selecting a verified Tunnex release'
	run_with_loader 'Verifying release signature' sleep 1
	info 'Signed release · Images pinned by digest (sample)'
	stage 3 'Configuring your Tunnex Server'
	plan_start
	plan_item 'Dashboard' 'https://vpn.example.com'
	plan_item 'Administrator' 'owner@example.com'
	plan_item 'First organization' 'Example organization'
	plan_end
	stage 4 'Reviewing the installation plan'
	plan_start
	plan_item 'Mode' 'Tunnex Server setup'
	plan_item 'Gateway' 'Separate Linux host (recommended)'
	plan_item 'Alternative' 'Same Linux host: quick start, not recommended for production; requires yes'
	plan_item 'VPN traffic' 'Split tunnel — configured private networks only'
	plan_item 'Changes' 'UI preview only; no host changes'
	plan_end
	printf '\n    %s›%s Proceed with this installation? %sY / n%s\n' "$TUNNEX_RED" "$TUNNEX_RESET" "$TUNNEX_DIM" "$TUNNEX_RESET"
	stage 5 'Installing and verifying Tunnex'
	run_with_loader 'Pulling verified images' sleep 1
	run_with_loader 'Waiting for Tunnex Server health' sleep 1
	preview_complete
}

AUTO_CONFIRM=false
DRY_RUN=false
UI_PREVIEW=false
for _arg in "$@"; do
	case "$_arg" in
	--ui-preview) UI_PREVIEW=true ;;
	--yes|-y) AUTO_CONFIRM=true ;;
	--dry-run|--preview) DRY_RUN=true ;;
	*) die "unknown installer option: $_arg" ;;
	esac
done

setup_palette
if [ "$UI_PREVIEW" = true ]; then ui_preview; exit 0; fi
print_wordmark
show_setup_boundary
stage 1 "Checking this host"
command -v curl >/dev/null 2>&1 || die "curl is required to download Tunnex and its verified host prerequisites."
if command -v docker >/dev/null 2>&1 &&
   docker compose version >/dev/null 2>&1 &&
   command -v openssl >/dev/null 2>&1; then
	HOST_PLAN="Use the existing Docker Engine and Compose installation"
else
	load_host_os
	HOST_PLAN="Install or complete Docker Engine, Compose v2, and required utilities for ${HOST_OS_ID}"
fi
case "${HOST_KERNEL:-${TUNNEX_HOST_KERNEL:-$(uname -s)}}" in
Darwin) HOST_DISPLAY_NAME='macOS' ;;
MINGW*|MSYS*|CYGWIN*) HOST_DISPLAY_NAME='Windows' ;;
Linux) HOST_DISPLAY_NAME="${HOST_OS_ID:-Linux}" ;;
*) HOST_DISPLAY_NAME='this host' ;;
esac
if host_is_portable_control_plane; then
	PORTABLE_CONTROL_PLANE=true
	DEPLOYMENT_SHAPE="Portable Tunnex Server; enroll the gateway on a separate Linux host"
else
	PORTABLE_CONTROL_PLANE=false
	DEPLOYMENT_SHAPE="Tunnex Server; separate Linux gateway recommended"
fi
success "Detected: ${HOST_DISPLAY_NAME}"
info "${HOST_PLAN}"
info "${DEPLOYMENT_SHAPE}"

# ── 1. resolve the newest published semantic release ────────────────────────────────────────────
stage 2 "Selecting a verified Tunnex release"
resolve_install_version
resolve_display_version
info "Installing Tunnex ${DISPLAY_VERSION} (image tag ${VERSION})"
info "Provenance: ${VERSION_PROVENANCE}"

# ── 2. public address — env override OR prompt; loopback refused at the SOURCE (both paths) ───────
stage 3 "Configuring your Tunnex Server"
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

# HTTPS remains the AI default. This policy is an explicit operator decision;
# an address alone does not prove that public access is blocked.
AI_ALLOW_PRIVATE_HTTP=${TUNNEX_AI_ALLOW_PRIVATE_HTTP:-}
if [ -z "$AI_ALLOW_PRIVATE_HTTP" ] && [ -f "$DIR/.env" ]; then
	AI_ALLOW_PRIVATE_HTTP=$(sed -n 's/^TUNNEX_AI_ALLOW_PRIVATE_HTTP=//p' "$DIR/.env" | head -1)
fi
AI_ALLOW_PRIVATE_HTTP=${AI_ALLOW_PRIVATE_HTTP:-false}
case "$AI_ALLOW_PRIVATE_HTTP" in true|false) ;; *) die 'TUNNEX_AI_ALLOW_PRIVATE_HTTP must be true or false.' ;; esac
if [ "$AI_ALLOW_PRIVATE_HTTP" = true ]; then
	warn 'Legacy private HTTP policy retained. Releases with AI transport settings require a separate instance-admin opt-in in the console.'
fi

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
warn 'SMTP skipped — invitations, password resets, and verification emails are unavailable.'
	say "   Invitations are the only way people join, and they are delivered by email. Password resets"
	say "   and address verification need it too. You can still sign in as the administrator, and the"
	say "   dashboard shows a copyable invitation link you can send by hand."
	say "   Enable it later in Dashboard -> Settings -> Email delivery (server administrator)."
	;;
*)
	die "TUNNEX_SMTP must be 'skip' or 'configure' (got '${SMTP_MODE}')."
	;;
esac

# BEGIN BYODB INPUT — tested independently without host mutation.
configure_database() {
	DB_MODE=${TUNNEX_DATABASE_MODE:-}
	DB_URL=${TUNNEX_DATABASE_URL:-}
	DB_TLS_SOURCE=${TUNNEX_DATABASE_TLS_SOURCE:-tunnex_database_tls}
	if [ -f "$DIR/.env" ]; then
		_saved_mode=$(sed -n 's/^TUNNEX_DATABASE_MODE=//p' "$DIR/.env" | head -1)
		_saved_mode=${_saved_mode:-bundled}
		[ -z "$DB_MODE" ] || [ "$DB_MODE" = "$_saved_mode" ] || die 'Database mode cannot change on reinstall; use a planned data migration.'
		if [ -n "${TUNNEX_DATABASE_URL_FILE:-}" ]; then
			[ -z "$DB_URL" ] || die 'Choose either TUNNEX_DATABASE_URL or TUNNEX_DATABASE_URL_FILE.'
			[ -f "$TUNNEX_DATABASE_URL_FILE" ] && [ -r "$TUNNEX_DATABASE_URL_FILE" ] || die 'Database URL file is not readable.'
			DB_URL=$(cat "$TUNNEX_DATABASE_URL_FILE")
		fi
		if [ -n "$DB_URL" ]; then
			_saved_url=$(sed -n 's/^TUNNEX_DATABASE_URL=//p' "$DIR/.env" | head -1)
			# Our generated dotenv uses literal single quotes, never shell evaluation.
			_saved_url=${_saved_url#\'}
			_saved_url=${_saved_url%\'}
			[ "$DB_URL" = "$_saved_url" ] || die 'Existing database configuration is preserved; rotate its credential in the installed configuration, not by reinstalling.'
		fi
		DB_MODE=$_saved_mode
		return
	fi
	if [ -z "$DB_MODE" ]; then
		if [ -n "$DB_URL" ] || [ -n "${TUNNEX_DATABASE_URL_FILE:-}" ]; then
			DB_MODE=external
		elif have_tty; then
			DB_MODE=$(ask 'Server database: bundled or external PostgreSQL? [bundled]: ')
		fi
	fi
	DB_MODE=${DB_MODE:-bundled}
	case "$DB_MODE" in
	bundled)
		[ -z "$DB_URL" ] && [ -z "${TUNNEX_DATABASE_URL_FILE:-}" ] || die 'External database inputs conflict with bundled mode.'
		;;
	external)
		_db_file=${TUNNEX_DATABASE_URL_FILE:-}
		if [ -z "$DB_URL" ] && [ -z "$_db_file" ] && have_tty; then
			_db_file=$(ask 'Path to a protected file containing the PostgreSQL connection URL: ')
		fi
		if [ -n "$_db_file" ]; then
			[ -z "$DB_URL" ] || die 'Choose either TUNNEX_DATABASE_URL or TUNNEX_DATABASE_URL_FILE.'
			[ -f "$_db_file" ] && [ -r "$_db_file" ] || die 'Database URL file is not readable.'
			DB_URL=$(cat "$_db_file")
		fi
		case "$DB_URL" in postgres://*|postgresql://*) ;; *) die 'External mode requires a PostgreSQL connection URL.' ;; esac
		# Single-quoted dotenv preserves dollar signs; quote/newline characters must
		# be percent-encoded in a URI, never interpreted as dotenv syntax.
		case "$DB_URL" in *"'"*|*'\'*|*"
"*|*"$(printf '\r')"*) die 'URL contains unsafe literal characters; percent-encode credentials.' ;; esac
		case "$DB_TLS_SOURCE" in
		tunnex_database_tls) ;;
		/*) [ -d "$DB_TLS_SOURCE" ] || die 'Database TLS source must be an existing directory.' ;;
		*) die 'Database TLS source must be an absolute directory path.' ;;
		esac
		case "$DB_TLS_SOURCE" in *[!a-zA-Z0-9_./-]*) die 'Database TLS path must contain only letters, numbers, slash, dot, underscore and hyphen.' ;; esac
		;;
	*) die 'TUNNEX_DATABASE_MODE must be bundled or external.' ;;
	esac
}
# END BYODB INPUT
configure_database

# BEGIN FIRST ORGANIZATION AND GATEWAY — safe to exercise without host mutation.
configure_first_organization_and_gateway() {
	FIRST_ORG_NAME=${TUNNEX_BOOTSTRAP_ORG_NAME:-}
	GATEWAY_PLACEMENT=${TUNNEX_GATEWAY_PLACEMENT:-}
	EXISTING_INSTALL=false
	if [ -f "$DIR/.env" ]; then
		EXISTING_INSTALL=true
		_saved_gateway=$(sed -n 's/^TUNNEX_GATEWAY_PLACEMENT=//p' "$DIR/.env" | head -1)
		if [ -z "$_saved_gateway" ]; then
			_saved_cp_only=$(sed -n 's/^TUNNEX_PORTABLE_CONTROL_PLANE=//p' "$DIR/.env" | head -1)
			if [ "$_saved_cp_only" = true ] || [ "$PORTABLE_CONTROL_PLANE" = true ]; then _saved_gateway=separate; else _saved_gateway=same-host; fi
		fi
		[ -z "$GATEWAY_PLACEMENT" ] || [ "$GATEWAY_PLACEMENT" = "$_saved_gateway" ] || die 'Gateway placement is preserved on reinstall; move gateways through a planned migration.'
		[ -z "$FIRST_ORG_NAME" ] || info 'Existing installation: first-organization input is not applied on rerun; existing organizations are preserved.'
		GATEWAY_PLACEMENT=$_saved_gateway
		FIRST_ORG_NAME='Existing organization settings preserved'
	else
		if [ "${FIRST_ORG_SUPPORTED:-true}" != true ]; then
			[ -z "$FIRST_ORG_NAME" ] || die 'The selected release does not support automatic first-organization setup. Select a newer release or use its existing dashboard setup.'
			FIRST_ORG_NAME='Create in dashboard (selected release)'
			GATEWAY_PLACEMENT=${GATEWAY_PLACEMENT:-separate}
			[ "$GATEWAY_PLACEMENT" = separate ] || die 'Automatic same-host enrollment requires a release with first-organization support.'
			DEPLOYMENT_SHAPE='Separate Linux gateway (recommended)'
			return
		fi
		if [ -z "$FIRST_ORG_NAME" ] && have_tty; then
			FIRST_ORG_NAME=$(ask 'Your first organization [My organization]: ')
		fi
		FIRST_ORG_NAME=${FIRST_ORG_NAME:-My organization}
		case "$FIRST_ORG_NAME" in *'
'*) die 'Organization name must be a single line.' ;; esac
		# Prevent multiline dotenv injection and terminal control sequences.
		[ "${#FIRST_ORG_NAME}" -le 120 ] && ! printf '%s' "$FIRST_ORG_NAME" | LC_ALL=C grep -q '[[:cntrl:]]' || die 'Organization name must be at most 120 characters without control characters.'
		[ -n "$(printf '%s' "$FIRST_ORG_NAME" | tr -d '[:space:]')" ] || die 'Organization name cannot be blank.'
		if [ -z "$GATEWAY_PLACEMENT" ] && [ "$PORTABLE_CONTROL_PLANE" != true ] && have_tty; then
			info 'Separate Linux gateway (recommended): isolates VPN traffic from the Tunnex Server.'
			warn 'Same host (quick start): not recommended for production; shares resources and failure impact.'
			GATEWAY_PLACEMENT=$(ask 'Gateway location [separate / same-host] [separate]: ')
		fi
		GATEWAY_PLACEMENT=${GATEWAY_PLACEMENT:-separate}
	fi
	case "$GATEWAY_PLACEMENT" in
	separate) DEPLOYMENT_SHAPE='Separate Linux gateway (recommended)' ;;
	same-host)
		[ "$PORTABLE_CONTROL_PLANE" != true ] || die 'Same-host gateways require Linux. Use a separate Linux gateway for macOS or Windows.'
		DEPLOYMENT_SHAPE='Same Linux host — quick start; not recommended for production'
		if [ "$EXISTING_INSTALL" != true ]; then
			_local_consent=${TUNNEX_COLOCATED_GATEWAY_CONFIRM:-}
			if [ -z "$_local_consent" ] && have_tty; then
				_local_consent=$(ask 'Automatically enroll a gateway on this Tunnex Server machine? Not recommended for production. [y/N]: ')
			fi
			case "$_local_consent" in y|Y|yes|YES) ;; *) die 'Same-host enrollment needs explicit yes consent (TUNNEX_COLOCATED_GATEWAY_CONFIRM=yes for unattended setup).' ;; esac
			GATEWAY_ADDRESS=${TUNNEX_GATEWAY_ADDRESS:-}
			if [ -z "$GATEWAY_ADDRESS" ] && have_tty; then
				GATEWAY_ADDRESS=$(ask "Gateway IP or hostname clients reach directly (not an HTTP proxy) [${ADDR}]: ")
			fi
			GATEWAY_ADDRESS=${GATEWAY_ADDRESS:-$ADDR}
			public_base_url_ok "http://${GATEWAY_ADDRESS}" || die 'Gateway address must be a reachable IP or hostname (bracket IPv6 addresses).'
			[ "$(public_base_url_host "http://${GATEWAY_ADDRESS}")" = "$GATEWAY_ADDRESS" ] || die 'Gateway address must not contain a port; this installer uses UDP 51820.'
		fi
		;;
	*) die 'TUNNEX_GATEWAY_PLACEMENT must be separate or same-host.' ;;
	esac
}
gateway_network_guidance() {
	case "$TLS_MODE" in
	direct)
		if [ -n "$EDGE_PUBLIC_IP" ]; then
			info 'Server firewall: allow public TCP 443 for HTTPS and certificate renewal; TCP 80 redirects to HTTPS.'
		else
			info 'Server firewall: allow inbound TCP 80 and 443 for HTTPS and certificate issuance.'
		fi
		;;
	terminated) info 'Server firewall: allow TCP 80 only from your TLS proxy/load balancer; expose HTTPS on that proxy.' ;;
	http) info 'Server firewall: allow inbound TCP 80 from intended users; HTTP is unencrypted.' ;;
	esac
	if [ "$GATEWAY_PLACEMENT" = separate ]; then
		info 'Server firewall: allow TCP 8443 from gateway hosts for the authenticated control channel.'
	fi
	info 'Gateway firewall: allow inbound UDP 51820 from VPN clients and required peer gateways; configure NAT port forwarding if needed.'
	info 'Gateway needs Linux, /dev/net/tun, WireGuard support and NET_ADMIN. Compose enables IPv4 forwarding in the local gateway container.'
	info 'Allow outbound DNS and HTTPS for installation; gateways also need access to the server control channel.'
	info 'Apply these rules to host firewalls AND cloud security groups. The installer does not open them.'
	info 'Private access uses split tunnel. Configure private routes and access permissions in the dashboard; full tunnel is a later admin choice.'
}
wait_for_local_gateway() {
	_gateway_attempt=0
	while ! tunnex_compose exec -T node-agent wget -qO- http://127.0.0.1:9091/readyz >/dev/null 2>&1; do
		_gateway_attempt=$((_gateway_attempt + 1))
		[ "$_gateway_attempt" -lt 60 ] || return 1
		sleep 2
	done
}
# END FIRST ORGANIZATION AND GATEWAY
# The launcher on main can precede the signed release. Preserve the established
# manual setup for older payloads, but never silently ignore an explicit new input.
FIRST_ORG_SUPPORTED=true
if [ ! -f "$DIR/.env" ]; then
	_contract_file=$(mktemp "${TMPDIR:-/tmp}/tunnex-bootstrap-contract.XXXXXX")
	if ! curl -fsSL "${RAW}/${SOURCE_REF}/deploy/tunnex.yml" -o "$_contract_file"; then
		rm -f "$_contract_file"
		die 'Could not verify setup capabilities in the selected release.'
	fi
	if ! grep -Fq 'TUNNEX_BOOTSTRAP_ORG_NAME:' "$_contract_file" || ! grep -Fq 'TUNNEX_BOOTSTRAP_GATEWAY_TOKEN_SHA256:' "$_contract_file"; then
		FIRST_ORG_SUPPORTED=false
		info 'This release uses manual organization setup and gateway enrollment in the dashboard. Automatic setup will be available in a newer release.'
	fi
	rm -f "$_contract_file"
fi
configure_first_organization_and_gateway
# Older upgrade helpers understand only this existing scale-zero flag. Keep it
# true for every CP-only install, including Linux with a separate gateway.
CP_ONLY=false
[ "$GATEWAY_PLACEMENT" != separate ] || CP_ONLY=true

# ── 4. review once, then prepare the host and versioned compose ──────────────────────────────────
stage 4 "Reviewing the installation plan"
plan_start
plan_item 'Mode' 'Tunnex Server setup'
plan_item 'First organization' "$FIRST_ORG_NAME"
plan_item 'Server database' "$DB_MODE PostgreSQL (credentials hidden)"
plan_item 'Version' "${DISPLAY_VERSION}"
plan_item 'Public URL' "${BASE_URL}"
plan_item 'TLS mode' "${TLS_MODE}"
plan_item 'Legacy HTTP flag' "${AI_ALLOW_PRIVATE_HTTP} (older releases only; current releases use Settings → AI Gateway transport)"
plan_item 'Administrator' "${ADMIN_EMAIL}"
case "$SMTP_MODE" in
configure) plan_item 'Email' "${SMTP_HOST}:${SMTP_PORT} as ${SMTP_FROM}" ;;
skip) plan_item 'Email' 'skipped' ;;
esac
plan_item 'Host readiness' "${HOST_PLAN}"
plan_item 'Deployment' "${DEPLOYMENT_SHAPE}"
plan_item 'VPN traffic' 'Split tunnel — configured private networks only'
if [ "$GATEWAY_PLACEMENT" = same-host ] && [ "$EXISTING_INSTALL" != true ]; then
	plan_item 'Gateway endpoint' "${GATEWAY_ADDRESS}:51820/UDP"
fi
case "$DIR" in
/*) INSTALL_PLAN_DIR=$DIR ;;
*) INSTALL_PLAN_DIR="$(pwd)/${DIR}" ;;
esac
INSTALL_PROJECT_SOURCE=${INSTALL_PLAN_DIR%/}
INSTALL_COMPOSE_PROJECT=${TUNNEX_COMPOSE_PROJECT:-${INSTALL_PROJECT_SOURCE##*/}}
if [ -f "$DIR/.env" ]; then
	_saved_project=$(sed -n 's/^COMPOSE_PROJECT_NAME=//p' "$DIR/.env" | head -1)
	if [ -n "$_saved_project" ]; then
		[ -z "${TUNNEX_COMPOSE_PROJECT:-}" ] || [ "$TUNNEX_COMPOSE_PROJECT" = "$_saved_project" ] ||
			die 'The installation Compose project cannot change on reinstall; it selects existing encrypted storage.'
		INSTALL_COMPOSE_PROJECT=$_saved_project
	fi
fi
INSTALL_COMPOSE_PROJECT=$(printf '%s' "$INSTALL_COMPOSE_PROJECT" | tr '[:upper:]' '[:lower:]')
case "$INSTALL_COMPOSE_PROJECT" in
[a-z0-9]*) ;;
*) die "installation directory must end in a letter or number, or set TUNNEX_COMPOSE_PROJECT to a valid Compose project name" ;;
esac
case "$INSTALL_COMPOSE_PROJECT" in
*[!a-z0-9_-]*) die "TUNNEX_COMPOSE_PROJECT may contain only lowercase letters, numbers, hyphens, and underscores" ;;
esac
plan_item 'Directory' "${INSTALL_PLAN_DIR}"
plan_item 'Compose project' "${INSTALL_COMPOSE_PROJECT}"
if [ "$DRY_RUN" = true ]; then
	plan_item 'Changes' 'Preview only (no host or product changes)'
	plan_end
	gateway_network_guidance
	stage 5 "Preview complete"
	success "Onboarding preview complete. Re-run without --dry-run when you are ready."
	exit 0
fi
plan_end
gateway_network_guidance
confirm_installation

stage 5 "Installing and verifying Tunnex"
info 'Preparing Docker Engine and Compose v2'
ensure_docker_ready
success 'Docker Engine and Compose v2 are ready.'

mkdir -p "$DIR"
cd "$DIR"
STAGE_DIR=$(mktemp -d "$PWD/.tunnex-install.XXXXXX")
trap 'rm -rf "$STAGE_DIR" .env.new tunnex-upgrade-runner.service.next tunnex-upgrade-runner.path.next 2>/dev/null' EXIT # never leave a half-written managed file behind on failure

# Fetch the complete host payload before replacing any managed file. The UI's
# upgrade command is not usable when upgrade.sh is absent, so a partial download
# must fail the install rather than leave a control plane that only looks ready.
curl -fsSL "${RAW}/${SOURCE_REF}/deploy/tunnex.yml" -o "$STAGE_DIR/tunnex.yml" || die "could not download deploy/tunnex.yml at ${SOURCE_REF}"
# Reinstallation preserves .env rather than applying the newly supplied URL.
# Protect the installed transport as well as the requested fresh-install mode.
IP_TLS_REQUIRED=false
[ -z "$EDGE_PUBLIC_IP" ] || IP_TLS_REQUIRED=true
if [ -f .env ]; then
	_saved_base=$(sed -n 's/^APP_BASE_URL=//p' .env | head -1)
	_saved_mode=$(sed -n 's/^TUNNEX_TLS_MODE=//p' .env | head -1)
	_saved_ip=$(sed -n 's/^TUNNEX_EDGE_PUBLIC_IP=//p' .env | head -1)
	if [ -n "$_saved_ip" ]; then
		IP_TLS_REQUIRED=true
	elif [ "$_saved_mode" = direct ]; then
		case "$_saved_base" in
		https://*) if public_base_url_is_ip "$_saved_base"; then IP_TLS_REQUIRED=true; fi ;;
		esac
	fi
fi
if [ "$IP_TLS_REQUIRED" = true ] && ! grep -Fq 'TUNNEX_EDGE_PUBLIC_IP' "$STAGE_DIR/tunnex.yml"; then
	die 'The selected signed release does not support public IPv4 HTTPS. Select a release with that capability.'
fi
# New releases verify the complete externally terminated TLS chain. Old signed
# targets retain their existing behavior. Reruns preserve the installed origin.
EDGE_TRUST_REQUIRED=false
EDGE_TRUSTED_PROXIES=${TUNNEX_EDGE_TRUSTED_PROXIES:-}
_effective_base=$BASE_URL
_effective_mode=$TLS_MODE
if [ -f .env ]; then
  _effective_base=$(sed -n 's/^APP_BASE_URL=//p' .env | head -1)
  _effective_mode=$(sed -n 's/^TUNNEX_TLS_MODE=//p' .env | head -1)
  [ -n "$EDGE_TRUSTED_PROXIES" ] || EDGE_TRUSTED_PROXIES=$(sed -n 's/^TUNNEX_EDGE_TRUSTED_PROXIES=//p' .env | head -1)
  if [ -z "$_effective_mode" ]; then
    case "$_effective_base" in
      https://*) if public_base_url_is_ip "$_effective_base"; then _effective_mode=terminated; else _effective_mode=direct; fi ;;
      http://*) _effective_mode=http ;;
    esac
  fi
fi
if [ -n "$EDGE_TRUSTED_PROXIES" ]; then
  edge_trusted_proxies_ok "$EDGE_TRUSTED_PROXIES" || die 'TUNNEX_EDGE_TRUSTED_PROXIES must contain explicit IPs/CIDRs, separated by spaces; no /0 or other syntax is allowed.'
fi
if grep -Fq 'TUNNEX_EDGE_TRUSTED_PROXIES' "$STAGE_DIR/tunnex.yml" && [ "$_effective_mode" = terminated ]; then
  EDGE_TRUST_REQUIRED=true
  if [ -z "$EDGE_TRUSTED_PROXIES" ] && have_tty; then
    EDGE_TRUSTED_PROXIES=$(ask 'Trusted TLS proxy IPs/CIDRs (space-separated, as seen by this VM): ')
  fi
  edge_trusted_proxies_ok "$EDGE_TRUSTED_PROXIES" ||
    die 'Externally terminated HTTPS requires TUNNEX_EDGE_TRUSTED_PROXIES with explicit load-balancer IPs/CIDRs (space-separated, no /0). Configure them before installing or upgrading.'
fi
curl -fsSL "${RAW}/${SOURCE_REF}/deploy/upgrade.sh" -o "$STAGE_DIR/upgrade.sh" || die "could not download deploy/upgrade.sh at ${SOURCE_REF}"
sh -n "$STAGE_DIR/upgrade.sh" || die "downloaded deploy/upgrade.sh is not valid shell"

# Published releases carry a signed descriptor. Bind its semantic release tag
# to the exact resolved source commit before starting any image.
case "$VERSION" in
	v*) RELEASE_DESCRIPTOR_TAG="$VERSION" ;;
	sha-*) RELEASE_DESCRIPTOR_TAG="tunnex-build-${SOURCE_REF}" ;;
	*) die "a signed release descriptor is required for version ${VERSION}" ;;
esac
RELEASE_MANIFEST_URL="${TUNNEX_RELEASE_MANIFEST_URL:-https://github.com/tunnexio/tunnex/releases/download/${RELEASE_DESCRIPTOR_TAG}/release.json}"
curl -fsSL "$RELEASE_MANIFEST_URL" -o "$STAGE_DIR/release.json" || die "could not download the signed release manifest for ${SOURCE_REF}; refusing an unverifiable install"
# The API image runs releaseverify as an unprivileged user. The descriptor is
# public metadata, so make the staged bind mount readable before verification;
# a restrictive caller umask must not turn a valid release into a false reject.
chmod 0644 "$STAGE_DIR/release.json"

# `get.tunnex.io` deliberately serves install.sh from main while the resolver
# selects the newest published tag. Old release source has no UI updater; do
# not make that harmless main-before-tag interval break fresh installation.
RUNNER_REQUIRED=false
grep -Fq 'TUNNEX_HOST_UPGRADE_REQUEST_PATH' "$STAGE_DIR/tunnex.yml" && RUNNER_REQUIRED=true
RUNNER_PAYLOAD_AVAILABLE=false
if curl -fsSL "${RAW}/${SOURCE_REF}/deploy/upgrade-runner.sh" -o "$STAGE_DIR/upgrade-runner.sh"; then
	sh -n "$STAGE_DIR/upgrade-runner.sh" || die "downloaded deploy/upgrade-runner.sh is not valid shell"
	RUNNER_PAYLOAD_AVAILABLE=true
elif [ "$RUNNER_REQUIRED" = true ]; then
	die "could not download required deploy/upgrade-runner.sh at ${SOURCE_REF}"
fi
RUNNER_AVAILABLE=false
HOST_KERNEL=${HOST_KERNEL:-${TUNNEX_HOST_KERNEL:-$(uname -s)}}
if [ "$RUNNER_PAYLOAD_AVAILABLE" = true ] && [ "$HOST_KERNEL" = Linux ] &&
   [ -d /run/systemd/system ] && command -v systemctl >/dev/null 2>&1; then
	RUNNER_AVAILABLE=true
fi

# Verify the staged descriptor before publishing any compose or privileged code.
run_with_loader 'Downloading the signed release verifier' docker_cli pull "ghcr.io/tunnexio/tunnex-api:${VERSION}" ||
	die 'could not download the signed release verifier image'
case "$(docker_cli version --format '{{.Server.Arch}}' 2>/dev/null || true)" in
	amd64|x86_64) RELEASE_ARCH=amd64 ;;
	arm64|aarch64) RELEASE_ARCH=arm64 ;;
	*) die "could not determine a supported Docker server architecture for release verification" ;;
esac
if ! RELEASE_ENV="$(docker_cli run --rm --entrypoint releaseverify \
	-v "$STAGE_DIR/release.json:/tmp/release.json:ro" \
	"ghcr.io/tunnexio/tunnex-api:${VERSION}" \
	-manifest /tmp/release.json -public-key "$TRUSTED_RELEASE_PUBLIC_KEY" \
	-expected-source-sha "$SOURCE_REF" -platform "$RELEASE_ARCH" -print-env)"; then
	die "signed release verification failed; refusing to publish deployment files or privileged updater code"
fi
if [ "$DB_MODE" = external ]; then
	grep -Fq 'TUNNEX_DATABASE_URL:' "$STAGE_DIR/tunnex.yml" && grep -Fq 'bundled-db' "$STAGE_DIR/tunnex.yml" ||
		die 'The selected signed release does not support BYODB. Select a BYODB-capable release before installing.'
fi

# Old releases do not declare the bundled engine. Fetch its complete setup only
# when the selected signed source supports it; main-before-tag stays compatible.
AI_BUNDLED=false
if grep -Fq 'TUNNEX_AI_ENGINE_IMAGE:' "$STAGE_DIR/tunnex.yml" || grep -Fq '${TUNNEX_AI_ENGINE_IMAGE:' "$STAGE_DIR/tunnex.yml"; then
	AI_BUNDLED=true
	AI_IMAGE_PIN=$(printf '%s\n' "$RELEASE_ENV" | sed -n 's/^TUNNEX_AI_ENGINE_IMAGE=//p' | head -1)
	[ -n "$AI_IMAGE_PIN" ] || die 'The selected release declares an AI backend but its signed image pin is missing.'
	curl -fsSL "${RAW}/${SOURCE_REF}/deploy/ai-bootstrap.sh" -o "$STAGE_DIR/ai-bootstrap.sh" || die 'Could not download the signed-source AI bootstrap helper.'
	sh -n "$STAGE_DIR/ai-bootstrap.sh" || die 'Downloaded AI bootstrap helper is not valid shell.'
	curl -fsSL "${RAW}/${SOURCE_REF}/deploy/ai-gateway/config-managed.json" -o "$STAGE_DIR/ai-engine.json" || die 'Could not download the signed-source managed AI configuration.'
	AI_ENV_FILE="$PWD/.env"
	AI_COMPOSE_PROJECT=$INSTALL_COMPOSE_PROJECT
	ai_fail() { die "$*"; }
	ai_docker() { docker_cli "$@"; }
	. "$STAGE_DIR/ai-bootstrap.sh"
	ai_validate_existing
	if [ -f ai-engine.json ] && grep -Eq '"providers"[[:space:]]*:' ai-engine.json; then
		die 'Existing file-managed AI configuration requires a reviewed migration; it was preserved.'
	fi
fi

mv "$STAGE_DIR/tunnex.yml" tunnex.yml
mv "$STAGE_DIR/upgrade.sh" upgrade.sh
chmod 0755 upgrade.sh
mv "$STAGE_DIR/release.json" release.json
# Signed release metadata is mounted into the unprivileged API container. It is not
# secret, so keep it world-readable while the bind mount itself stays read-only.
chmod 0644 release.json
if [ "$AI_BUNDLED" = true ]; then
	mv "$STAGE_DIR/ai-bootstrap.sh" ai-bootstrap.sh
	# Existing managed configuration and encrypted volumes remain authoritative.
	[ -f ai-engine.json ] || mv "$STAGE_DIR/ai-engine.json" ai-engine.json
	chmod 0644 ai-engine.json ai-bootstrap.sh
fi
RELEASE_MANIFEST_PATH="/var/lib/tunnex/release.json"
TUNNEX_RELEASE_PUBLIC_KEY="${TUNNEX_RELEASE_PUBLIC_KEY:-$TRUSTED_RELEASE_PUBLIC_KEY}"

# The API can write only a bounded request file; the root host runner owns the
# read-only status side and is the sole process with Docker authority.
INSTALL_DIR=$(pwd)
case "$INSTALL_DIR" in *'%'*|*'
'*) die "installation path contains characters unsupported by the upgrade service" ;; esac
if [ "$RUNNER_AVAILABLE" = true ]; then
	ROOT_UPGRADE_DIR=/usr/local/lib/tunnex
	as_root install -d -o root -g root -m 0755 "$ROOT_UPGRADE_DIR"
	as_root install -m 0755 -o root -g root upgrade.sh "$ROOT_UPGRADE_DIR/upgrade.sh.next"
	as_root install -m 0755 -o root -g root "$STAGE_DIR/upgrade-runner.sh" "$ROOT_UPGRADE_DIR/upgrade-runner.sh.next"
	as_root mv "$ROOT_UPGRADE_DIR/upgrade.sh.next" "$ROOT_UPGRADE_DIR/upgrade.sh"
	as_root mv "$ROOT_UPGRADE_DIR/upgrade-runner.sh.next" "$ROOT_UPGRADE_DIR/upgrade-runner.sh"
	as_root install -d -o root -g root -m 0755 "$INSTALL_DIR/upgrade-state"
	as_root install -d -m 0700 "$INSTALL_DIR/upgrade-state/requests"
	as_root chown 10001:10001 "$INSTALL_DIR/upgrade-state/requests"
	as_root install -d -o root -g root -m 0755 "$INSTALL_DIR/upgrade-state/status"
	as_root install -d -o root -g root -m 0700 "$INSTALL_DIR/upgrade-state/work"
	cat >tunnex-upgrade-runner.service.next <<EOF
[Unit]
Description=Tunnex fixed-purpose control-plane upgrade runner
After=docker.service
Requires=docker.service

[Service]
Type=oneshot
WorkingDirectory=${INSTALL_DIR}
Environment="TUNNEX_DIR=${INSTALL_DIR}"
Environment=TUNNEX_UPGRADE_HELPER=${ROOT_UPGRADE_DIR}/upgrade.sh
ExecStart=${ROOT_UPGRADE_DIR}/upgrade-runner.sh
PrivateTmp=true
NoNewPrivileges=true
EOF
	cat >tunnex-upgrade-runner.path.next <<EOF
[Unit]
Description=Watch for an approved Tunnex control-plane upgrade

[Path]
PathExists=${INSTALL_DIR}/upgrade-state/requests/request
Unit=tunnex-upgrade-runner.service

[Install]
WantedBy=multi-user.target
EOF
	as_root install -o root -g root -m 0644 tunnex-upgrade-runner.service.next /etc/systemd/system/tunnex-upgrade-runner.service
	as_root install -o root -g root -m 0644 tunnex-upgrade-runner.path.next /etc/systemd/system/tunnex-upgrade-runner.path
	rm -f tunnex-upgrade-runner.service.next tunnex-upgrade-runner.path.next
	as_root systemctl daemon-reload
	as_root systemctl enable --now tunnex-upgrade-runner.path
else
	say ">> Dashboard host upgrades are unavailable on this runtime; verified upgrades remain available through ./upgrade.sh."
fi

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
	say ">> Preserving existing .env configuration (backup retained)."
else
	umask 077
	FIRST_ORG_DOTENV=$(printf '%s' "$FIRST_ORG_NAME" | sed -e 's/\\/\\\\/g' -e 's/"/\\"/g' -e 's/\$/$$/g')
	[ "$FIRST_ORG_SUPPORTED" = true ] || FIRST_ORG_DOTENV=''
	BOOTSTRAP_GATEWAY_TOKEN=''
	BOOTSTRAP_GATEWAY_HASH=''
	BOOTSTRAP_GATEWAY_NAME=''
	if [ "$GATEWAY_PLACEMENT" = same-host ]; then
		BOOTSTRAP_GATEWAY_TOKEN=$(openssl rand -hex 32)
		BOOTSTRAP_GATEWAY_HASH=$(printf '%s' "$BOOTSTRAP_GATEWAY_TOKEN" | openssl dgst -sha256 | awk '{print $NF}')
		BOOTSTRAP_GATEWAY_NAME=quickstart-gateway
	fi
	cat >.env.new <<EOF
# Tunnex deployment config — generated by install.sh. Safe to edit these values; do NOT hand-edit
# tunnex.yml. Upgrade through the dashboard or run ./upgrade.sh on this host.
TUNNEX_VERSION=${VERSION}
# Exact Git ref the installer used for tunnex.yml; image tag + manifest provenance stay inspectable.
TUNNEX_SOURCE_REF=${SOURCE_REF}
TUNNEX_RELEASE_MANIFEST_PATH=${RELEASE_MANIFEST_PATH}
TUNNEX_RELEASE_PUBLIC_KEY=${TUNNEX_RELEASE_PUBLIC_KEY:-$TRUSTED_RELEASE_PUBLIC_KEY}
TUNNEX_RELEASE_KEY_ID=release-2026-08-01
TUNNEX_RELEASE_CATALOG_URL=${TUNNEX_RELEASE_CATALOG_URL:-https://github.com/tunnexio/tunnex/releases/download/tunnex-updates/release.json}
TUNNEX_RELEASE_UPDATE_CHECK=${TUNNEX_RELEASE_UPDATE_CHECK:-true}
TUNNEX_COMPOSE_SHA256=$(file_sha256 tunnex.yml)
COMPOSE_PROJECT_NAME=${INSTALL_COMPOSE_PROJECT}
TUNNEX_LOG_LEVEL=info
APP_BASE_URL=${BASE_URL}
TUNNEX_TLS_MODE=${TLS_MODE}
TUNNEX_EDGE_LISTEN=${EDGE_LISTEN}
TUNNEX_EDGE_PUBLIC_IP=${EDGE_PUBLIC_IP}
TUNNEX_EDGE_TRUSTED_PROXIES=${EDGE_TRUSTED_PROXIES}
TUNNEX_COOKIE_SECURE=${COOKIE_SECURE}
TUNNEX_AI_ALLOW_PRIVATE_HTTP=${AI_ALLOW_PRIVATE_HTTP}
TUNNEX_NODE_ENDPOINT=${GATEWAY_ADDRESS:-$ADDR}:51820
TUNNEX_PORTABLE_CONTROL_PLANE=${CP_ONLY}
TUNNEX_GATEWAY_PLACEMENT=${GATEWAY_PLACEMENT}
TUNNEX_BOOTSTRAP_ORG_NAME="${FIRST_ORG_DOTENV}"
TUNNEX_BOOTSTRAP_GATEWAY_TOKEN_SHA256=${BOOTSTRAP_GATEWAY_HASH}
TUNNEX_BOOTSTRAP_GATEWAY_NAME=${BOOTSTRAP_GATEWAY_NAME}
TUNNEX_NODE_NAME=${BOOTSTRAP_GATEWAY_NAME}
TUNNEX_JOIN_TOKEN=${BOOTSTRAP_GATEWAY_TOKEN}
TUNNEX_HOST_UPGRADE_REQUEST_SOURCE=${TUNNEX_HOST_UPGRADE_REQUEST_SOURCE:-./upgrade-state/requests}
TUNNEX_HOST_UPGRADE_STATUS_SOURCE=${TUNNEX_HOST_UPGRADE_STATUS_SOURCE:-./upgrade-state/status}
POSTGRES_USER=tunnex
POSTGRES_PASSWORD=${PG_PASS}
POSTGRES_DB=tunnex
TUNNEX_DATABASE_MODE=${DB_MODE}
TUNNEX_DATABASE_URL='${DB_URL}'
TUNNEX_DATABASE_TLS_SOURCE=${DB_TLS_SOURCE}
DATABASE_URL=postgres://tunnex:${PG_PASS}@postgres:5432/tunnex?sslmode=disable
REDIS_URL=redis://redis:6379/0
SMTP_HOST=${SMTP_HOST}
SMTP_PORT=${SMTP_PORT}
SMTP_FROM=${SMTP_FROM}
SMTP_USERNAME=${SMTP_USERNAME}
SMTP_PASSWORD=${SMTP_PASSWORD}
TUNNEX_ADMIN_EMAIL=${ADMIN_EMAIL}
EOF
	if [ "$RUNNER_AVAILABLE" != true ]; then
		sed -e 's|^TUNNEX_HOST_UPGRADE_REQUEST_SOURCE=.*$|TUNNEX_HOST_UPGRADE_REQUEST_SOURCE=tunnex_host_upgrade_requests|' \
		    -e 's|^TUNNEX_HOST_UPGRADE_STATUS_SOURCE=.*$|TUNNEX_HOST_UPGRADE_STATUS_SOURCE=tunnex_host_upgrade_status|' \
		    .env.new >.env.portable
		mv .env.portable .env.new
	fi
	mv .env.new .env # atomic swap — the .env is never observed half-written
fi
set_dotenv() {
	_key=$1 _value=$2 _tmp=.env.next
	umask 077
	case "$_value" in *'
'*|*'
'*) die "invalid release environment value" ;; esac
	awk -F= -v key="$_key" -v value="$_value" '
		$1 == key { print key "=" value; seen=1; next }
		{ print }
		END { if (!seen) print key "=" value }
	' .env >"$_tmp"
	mv "$_tmp" .env
}

# ── 7. pull + start ─────────────────────────────────────────────────────────────────────────────
say ">> Signed release verified; pinning images…"
for RELEASE_KEY in TUNNEX_API_IMAGE TUNNEX_WEB_IMAGE TUNNEX_NGINX_IMAGE TUNNEX_NODE_AGENT_IMAGE TUNNEX_MIGRATE_IMAGE TUNNEX_RELEASE_SEQUENCE TUNNEX_RELEASE_VERSION TUNNEX_RELEASE_SOURCE_SHA; do
	RELEASE_VALUE="$(printf '%s\n' "$RELEASE_ENV" | sed -n "s/^${RELEASE_KEY}=//p" | head -1)"
	[ -n "$RELEASE_VALUE" ] || die "signed release verifier omitted ${RELEASE_KEY}"
	set_dotenv "$RELEASE_KEY" "$RELEASE_VALUE"
done
set_dotenv TUNNEX_VERSION "$VERSION"
set_dotenv TUNNEX_SOURCE_REF "$SOURCE_REF"
set_dotenv TUNNEX_COMPOSE_SHA256 "$(file_sha256 tunnex.yml)"
set_dotenv TUNNEX_PORTABLE_CONTROL_PLANE "$CP_ONLY"
if [ "$EDGE_TRUST_REQUIRED" = true ]; then
	set_dotenv TUNNEX_EDGE_TRUSTED_PROXIES "$EDGE_TRUSTED_PROXIES"
	set_dotenv TUNNEX_TLS_MODE terminated
	set_dotenv TUNNEX_EDGE_LISTEN http://:80
	set_dotenv TUNNEX_EDGE_PUBLIC_IP ''
	set_dotenv TUNNEX_COOKIE_SECURE true
fi
if [ "$AI_BUNDLED" = true ]; then
	ai_set_env() { set_dotenv "$@"; }
	set_dotenv TUNNEX_AI_ALLOW_PRIVATE_HTTP "$AI_ALLOW_PRIVATE_HTTP"
	ai_prepare_config
	if [ "${AI_HTTP_UI_POLICY:-false}" = true ]; then
		info 'The private AI backend is included. HTTPS is the default. An instance administrator can allow HTTP in Settings > AI Gateway transport; HTTP does not encrypt credentials or requests.'
	elif [ -z "$(ai_env_value TUNNEX_AI_GATEWAY_URL)" ]; then
		warn 'The private AI backend is installed. AI configuration and access require a real HTTPS public URL; HTTP evaluation keeps AI access off.'
	else
		[ "$AI_ALLOW_PRIVATE_HTTP" != true ] || warn 'HTTP AI access is allowed by explicit operator policy. Keep this control-plane endpoint private/VPN-only and its network restrictions verified.'
		info 'The private AI backend is included. Organization access, provider keys and model grants remain explicit setup steps.'
	fi
fi
case "$DB_MODE" in
bundled) set_dotenv COMPOSE_PROFILES bundled-db ;;
external) set_dotenv COMPOSE_PROFILES external-db ;;
esac
tunnex_compose() {
	case "$DB_MODE" in external) _db_profile=external-db ;; *) _db_profile=bundled-db ;; esac
	COMPOSE_PROFILES=$_db_profile docker_cli compose --project-name "$INSTALL_COMPOSE_PROJECT" --env-file .env -f tunnex.yml "$@"
}
run_with_loader 'Pulling verified Tunnex images' tunnex_compose pull || die 'could not pull the verified Tunnex images'
success 'Signed release verified; images pinned by digest.'
if [ "$DB_MODE" = external ]; then
	run_with_loader 'Checking private PostgreSQL from the Tunnex Server network' tunnex_compose run --rm --no-deps --entrypoint preflight api --database-only ||
		die 'External database preflight failed; Tunnex Server was not started. Fix the installed database configuration and rerun.'
fi
if [ "$GATEWAY_PLACEMENT" = separate ]; then
	run_with_loader 'Starting the Tunnex Server (initial migrations may take up to 15 minutes)' tunnex_compose up -d --wait --scale node-agent=0 --wait-timeout 900 ||
		die 'Tunnex Server did not become healthy'
else
	run_with_loader 'Starting the Tunnex Server and Linux gateway (initial migrations may take up to 15 minutes)' tunnex_compose up -d --wait --wait-timeout 900 ||
		die 'Tunnex Server and Linux gateway did not become healthy'
fi

# The API prints the one-time credential to stdout. Surface that banner here because `up -d` is detached;
# operators should not need to search container logs, and the API will also email it when SMTP is configured.
CREDS="$(tunnex_compose logs api 2>/dev/null | sed -n '/TUNNEX - FIRST RUN/,/^.*=\{20,\}$/p' | tail -n +2 || true)"
if printf '%s' "$CREDS" | grep -q 'password'; then
	say ''
	say 'Your administrator credential (shown once):'
	say "$CREDS"
fi

# Container health is process liveness. Enrollment success needs a functioning
# control session and WireGuard backend, as reported by the existing readiness probe.
if [ "$GATEWAY_PLACEMENT" = same-host ] && [ "$EXISTING_INSTALL" != true ]; then
	info 'Waiting for the local gateway to enroll and become ready'
	wait_for_local_gateway || die 'Tunnex Server started, but the local gateway is not ready. Check gateway logs and Linux/TUN requirements. If its one-hour join token expired, issue a new token from the dashboard; rerunning setup never mints another.'
	# Remove the consumed token from the installed configuration. Agent identity
	# lives in its existing state volume, so recreation no longer needs the token.
	set_dotenv TUNNEX_JOIN_TOKEN ''
	set_dotenv TUNNEX_BOOTSTRAP_GATEWAY_TOKEN_SHA256 ''
	unset BOOTSTRAP_GATEWAY_TOKEN BOOTSTRAP_GATEWAY_HASH
	success 'Local gateway enrolled and ready in your first organization.'
fi

# ── 8. NEXT STEPS (the customer's first experience — a real hand-off, not an echo) ───────────────
say ''
printf '  %s────────────────────────────────────────%s\n' "$TUNNEX_DIM" "$TUNNEX_RESET"
success "Tunnex ${VERSION} is running."
say ''
say "   1. Open the dashboard:   ${BASE_URL}/"
if [ "$FIRST_ORG_SUPPORTED" = true ]; then
	say "      Continue setup:      ${BASE_URL}/setup"
fi
say "   2. Sign in as ${ADMIN_EMAIL}; set the one-time password to your own password."
if [ "$EXISTING_INSTALL" = true ]; then
	say '   3. Your existing organization and gateway configuration are preserved.'
elif [ "$FIRST_ORG_SUPPORTED" != true ]; then
	say '   3. Create your first organization in the dashboard (this release uses manual setup).'
else
	say "   3. Fresh databases are ready with ${FIRST_ORG_NAME}; you are its owner."
	say '      When reusing a database, its existing accounts and organizations are preserved.'
fi
if [ "$GATEWAY_PLACEMENT" = separate ]; then
	say '   4. Enroll a gateway:     Dashboard → Gateways → “Generate join token”.'
	say '      Run its ONE command on a Linux gateway host with /dev/net/tun and NET_ADMIN.'
	say '      This host runs the Tunnex Server only.'
else
	if [ "$EXISTING_INSTALL" = true ]; then
		say '   4. Check your existing gateway status in Dashboard → Gateways.'
	else
		say '   4. Your same-host gateway is enrolled. View its address in Dashboard → Gateways.'
	fi
fi
say '   5. Configure private routes and access permissions, then invite users to connect.'
say '      Split tunnel keeps normal internet traffic local. Full tunnel can be enabled later.'
say ''
say "   Config:   $(pwd)/.env       (edit values here; never hand-edit tunnex.yml)"
say '   Upgrade:  use the dashboard when an update appears, or run ./upgrade.sh for a dry run.'
printf '  %s────────────────────────────────────────%s\n' "$TUNNEX_DIM" "$TUNNEX_RESET"
