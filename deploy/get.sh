#!/bin/sh
# Tunnex installer — served at https://get.tunnex.io
#
#   curl -fsSL https://get.tunnex.io | sh
#
# Verify first if you would rather (and you should):
#
#   curl -fsSL https://get.tunnex.io -o get.sh
#   curl -fsSL https://get.tunnex.io/SHA256SUMS -o SHA256SUMS
#   sha256sum -c SHA256SUMS --ignore-missing
#   less get.sh && sh get.sh
#
# Non-interactive (every default taken, nothing asked):
#
#   curl -fsSL https://get.tunnex.io | TUNNEX_PUBLIC_BASE_URL=https://vpn.acme.com sh -s -- --yes
#
# ⛔ IT ASKS EVERYTHING FIRST, SHOWS WHAT IT WILL DO, AND ONLY THEN TOUCHES THE MACHINE.
#
# The first version interleaved questions with work: resolve a release, ask, download, ask again. That shape
# leaves a half-configured directory when someone changes their mind at question four, and it never gives
# the operator a moment where the whole decision is visible before it is acted on. Every answer is collected
# up front, echoed back as a summary, confirmed once, and then the install runs with nothing left to ask.
#
# Idempotent: re-running against an existing ./tunnex REUSES the generated database password. A fresh one
# would not match the volume, and the stack would come up refusing its own credentials.
set -eu

# Trusted release verification key. The matching private signing key remains in CI only.
TRUSTED_RELEASE_PUBLIC_KEY=b48ff99923c43052ade580cdca63952690f07f08372c35814baa44cb84d674a0

# ── plumbing ────────────────────────────────────────────────────────────────────────────────────
die() { printf '\n  \033[31m✗\033[0m %s\n\n' "$*" >&2; exit 1; }

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

# step/ok — a progress line OVERWRITTEN by its own result, so the transcript reads as a checklist rather
# than a log. \033[K clears the rest of the line: without it the tail of a longer previous message survives
# underneath a shorter one.
step() { printf '  \033[2m…\033[0m %s\033[K\r' "$1"; }
ok() { printf '  \033[32m✓\033[0m %s\033[K\n' "$1"; }

# ── the wordmark ────────────────────────────────────────────────────────────────────────────────
#
# ⭐ TUNN IN WHITE, EX IN RED — the same split the product's own logo uses, so the terminal and the
# dashboard are recognisably one thing. Each line is printed in two segments because the colour changes
# mid-glyph-row.
#
# ⚠ AND THERE IS AN ASCII FALLBACK, because box-drawing characters render as mojibake on a terminal that is
# not UTF-8 — which is the default on a bare VPS with LANG=C, i.e. exactly the machine this runs on. A
# banner that comes out as garbage is worse than one that is plain.
wordmark() {
	_r='\033[38;5;203m' # brand red
	_w='\033[97m'       # wordmark white
	_z='\033[0m'
	case "${LC_ALL:-${LC_CTYPE:-${LANG:-}}}" in
	*[Uu][Tt][Ff]*)
		printf "\n  ${_w}%s${_z}${_r}%s${_z}\n" '▀█▀ █ █ █▄ █ █▄ █ ' '█▀▀ ▀▄▀'
		printf "  ${_w}%s${_z}${_r}%s${_z}\n" ' █  █ █ █ ▀█ █ ▀█ ' '█▀▀ ▄▀▄'
		printf "  ${_w}%s${_z}${_r}%s${_z}\n" ' ▀  ▀▀▀ ▀  ▀ ▀  ▀ ' '▀▀▀ ▀ ▀'
		;;
	*)
		printf "\n  ${_w}%s${_z}${_r}%s${_z}\n" ' _____ _   _ _   _ ' ' _____ __  __'
		printf "  ${_w}%s${_z}${_r}%s${_z}\n" '|_   _| | | | \ | |' '| ____|\ \/ /'
		printf "  ${_w}%s${_z}${_r}%s${_z}\n" '  | | | | | |  \| |' '|  _|   \  / '
		printf "  ${_w}%s${_z}${_r}%s${_z}\n" '  | | | |_| | |\  |' '| |___  /  \ '
		printf "  ${_w}%s${_z}${_r}%s${_z}\n" '  |_|  \___/|_| \_|' '|_____|/_/\_\'
		;;
	esac
}

# ⛔ THE TERMINAL IS OPENED ONCE, ON FD 3, AND FAILING TO OPEN IT IS THE ONLY TTY TEST THAT MEANS ANYTHING.
#
# This used to test `[ -r /dev/tty ] && [ -t 1 ]` and then read from /dev/tty per question. On a real
# machine under `curl … | sh` that combination reported a usable terminal and then every read returned EOF,
# so the address loop printed its error four times in a second without a human ever being asked:
#
#     !! Not usable. Enter the bare DNS name or public IP — no http://, not localhost.
#     !! Not usable. Enter the bare DNS name or public IP — no http://, not localhost.
#
# Opening the descriptor IS the test, because it is the same operation the reads perform. If it fails there
# is no terminal, and the script says so and stops rather than pretending to ask.
HAVE_TTY=0
# ⚠ BRACES + REDIRECT ON THE GROUP: the shell reports a failed `exec` redirection ITSELF, so
# `exec 3</dev/tty 2>/dev/null` still leaked `/dev/tty: Device not configured` onto a clean run.
# ⛔ READ-WRITE (`3<>`), NOT READ-ONLY (`3<`). Prompts are WRITTEN to this descriptor and answers are READ
# from it, and a read-only fd fails EBADF on the first `printf … >&3` — which under `set -e` killed the
# script silently, exit 1, no message, immediately after printing the first prompt. The prompt appeared
# because it was the last thing that worked, which is what made it look like the read had failed.
if { exec 3<>/dev/tty; } 2>/dev/null; then HAVE_TTY=1; fi

BANNER_SHOWN=0
ASSUME_YES=0
for arg in "$@"; do
	case "$arg" in
	--yes | -y) ASSUME_YES=1 ;;
	--help | -h)
		printf 'usage: sh get.sh [--yes]\n  --yes   accept every default, ask nothing (for automation)\n'
		exit 0
		;;
	*) die "unknown argument: $arg" ;;
	esac
done

no_tty_help() {
	die "no readable terminal, so the questions cannot be asked.

  Re-run non-interactively — every prompt has a default and --yes takes all of them:

      curl -fsSL https://get.tunnex.io | TUNNEX_PUBLIC_BASE_URL=https://vpn.acme.com sh -s -- --yes

  Override any default with an environment variable:
      TUNNEX_PUBLIC_BASE_URL (required) http:// or https:// URL users and gateways reach
      TUNNEX_ADMIN_EMAIL               administrator email
      TUNNEX_POOL_CIDR                 WireGuard pool, default 10.99.0.0/16
      TUNNEX_IPV6_POOL_CIDR             IPv6 ULA pool, default fd7a:1b2c:3d4e::/48
      SMTP_HOST SMTP_PORT SMTP_FROM SMTP_USERNAME SMTP_PASSWORD"
}

# read_tty — one line from fd 3 into REPLY_RAW.
#
# ⛔ EOF RETURNS NON-ZERO AND IS NOT AN EMPTY ANSWER. Conflating the two is what turned an unanswerable
# prompt into an infinite loop: "" failed validation, the loop asked again, and nothing ever changed.
read_tty() {
	[ "$HAVE_TTY" = "1" ] || return 1
	IFS= read -r REPLY_RAW <&3 || return 1
	return 0
}

# ask PROMPT DEFAULT — free text; Enter accepts the default. Sets ANSWER.
ask() {
	_prompt="$1"
	_default="${2:-}"
	if [ "$ASSUME_YES" = "1" ] || [ "$HAVE_TTY" = "0" ]; then
		ANSWER="$_default"
		return 0
	fi
	# ⚠ %b, NOT %s. A prompt may carry its own dim hint, and %s prints the escape LITERALLY — which is
	# exactly what shipped: `SMTP port \033[2m(587 = STARTTLS…)\033[0m (587)`.
	if [ -n "$_default" ]; then
		printf '  %b \033[2m(%s)\033[0m ' "$_prompt" "$_default" >&3
	else
		printf '  %b ' "$_prompt" >&3
	fi
	read_tty || no_tty_help
	[ -n "$REPLY_RAW" ] || REPLY_RAW="$_default"
	ANSWER="$REPLY_RAW"
}

# BEGIN MASKED SECRET READER — kept behaviorally identical with install.sh; the contract test checks both.
# ask_secret PROMPT — masked raw terminal input. Sets ANSWER.
#
# ⛔ A PASSWORD MUST NOT BE ECHOED. The reader below shows one `*` per byte, so the operator can see that
# input is arriving without exposing the secret or putting it in scrollback.
#
# ⚠ THE RESTORE IS UNCONDITIONAL, via a trap: if the read is interrupted (Ctrl-C mid-prompt) without it,
# the operator is left with a shell that does not echo anything they type and no obvious way back.
ask_secret() {
	_prompt="$1"
	if [ "$ASSUME_YES" = "1" ] || [ "$HAVE_TTY" = "0" ]; then
		ANSWER=""
		return 0
	fi
	_saved="$(stty -g <&3 2>/dev/null || true)"
	[ -n "$_saved" ] || no_tty_help
	# shellcheck disable=SC2064
	trap "stty '$_saved' <&3 2>/dev/null || stty echo <&3 2>/dev/null; exit 130" INT TERM
	stty raw -echo <&3 2>/dev/null || { stty "$_saved" <&3 2>/dev/null || true; no_tty_help; }
	printf '  %b ' "$_prompt" >&3
	_secret=''
	while :; do
		_byte="$(dd if=/dev/fd/3 bs=1 count=1 2>/dev/null || true)"
		[ -n "$_byte" ] || { stty "$_saved" <&3 2>/dev/null || true; trap - INT TERM; no_tty_help; }
		case "$_byte" in
		"$(printf '\r')" | "$(printf '\n')") break ;;
		"$(printf '\003')") stty "$_saved" <&3 2>/dev/null || true; trap - INT TERM; exit 130 ;;
		"$(printf '\177')" | "$(printf '\010')")
			if [ -n "$_secret" ]; then _secret="${_secret%?}"; printf '\b \b' >&3; fi
			;;
		*) _secret="${_secret}${_byte}"; printf '*' >&3 ;;
		esac
	done
	stty "$_saved" <&3 2>/dev/null || stty echo <&3 2>/dev/null || true
	trap - INT TERM
	printf '\n' >&3
	ANSWER="$_secret"
}
# END MASKED SECRET READER

# choose PROMPT DEFAULT_INDEX LABEL... — a numbered menu. Sets CHOICE to the 1-based index.
#
# ⚠ NUMBERED, NOT ARROW KEYS. An arrow-key menu needs raw terminal mode, and raw mode under `curl … | sh`
# is exactly the kind of thing that works on the author's machine and hangs on a customer's. A digit works
# on every terminal, every shell, and over ssh.
choose() {
	_prompt="$1"
	_default="$2"
	shift 2
	if [ "$ASSUME_YES" = "1" ] || [ "$HAVE_TTY" = "0" ]; then
		CHOICE="$_default"
		return 0
	fi
	printf '  %s\n' "$_prompt" >&3
	_i=1
	for _opt in "$@"; do
		if [ "$_i" = "$_default" ]; then
			printf '    \033[1m%s)\033[0m %s \033[2m(default)\033[0m\n' "$_i" "$_opt" >&3
		else
			printf '    \033[1m%s)\033[0m %s\n' "$_i" "$_opt" >&3
		fi
		_i=$((_i + 1))
	done
	_max=$#
	_n=0
	while :; do
		printf '  › ' >&3
		read_tty || no_tty_help
		[ -n "$REPLY_RAW" ] || REPLY_RAW="$_default"
		case "$REPLY_RAW" in
		'' | *[!0-9]*) ;;
		*)
			if [ "$REPLY_RAW" -ge 1 ] && [ "$REPLY_RAW" -le "$_max" ]; then
				CHOICE="$REPLY_RAW"
				return 0
			fi
			;;
		esac
		_n=$((_n + 1))
		if [ "$_n" -ge 3 ]; then die "no valid choice after 3 attempts."; fi
		printf '    \033[33mEnter a number between 1 and %s.\033[0m\n' "$_max" >&3
	done
}

# ⛔ LOOPBACK IS REFUSED AT THE SOURCE. Email links, SSO callbacks and the WireGuard endpoint derive from
# this value. Preserve the operator's explicit scheme; silently prepending http breaks HTTPS-only IdPs.
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
hostname_ok() {
	case "$1" in '' | *://* | */* | *[[:space:]]*) return 1 ;; esac
	return 0
}
cidr_ok() {
	case "$1" in *.*.*.*/*) return 0 ;; esac
	return 1
}
ipv6_cidr_ok() {
	case "$1" in *:*/*) return 0 ;; esac
	return 1
}
email_ok() {
	case "$1" in *@*.*) return 0 ;; esac
	return 1
}

# ask_validated PROMPT DEFAULT VALIDATOR HINT — bounded, and every exit is an exit.
#
# ⛔ `if …; then` AND NOT `cmd && action`, THROUGHOUT THIS SCRIPT. Under `set -e` a bare `A && B` statement
# whose A FAILS makes the whole list fail, and the shell exits. That is fine when A failing is fatal and
# catastrophic when it is the normal case: `grep -qi mailpit && die` aborted the installer on every compose
# file that CORRECTLY had no Mailpit in it, and this validator exited the script on a operator's first typo
# instead of re-asking. The `&&` form is only safe where failure means stop.
ask_validated() {
	_p="$1" _d="$2" _v="$3" _hint="$4"
	_c=0
	while :; do
		ask "$_p" "$_d"
		if "$_v" "$ANSWER"; then return 0; fi
		_c=$((_c + 1))
		if [ "$_c" -ge 3 ] || [ "$HAVE_TTY" = "0" ] || [ "$ASSUME_YES" = "1" ]; then die "$_hint"; fi
		printf '    \033[33m%s\033[0m\n' "$_hint" >&3
	done
}

# ── 0. preflight ────────────────────────────────────────────────────────────────────────────────
#
# ⛔ THE BRAND COMES FIRST, BEFORE ANYTHING CAN PROMPT OR FAIL. An operator who is asked for their root
# password before they have seen what they are installing is being asked by an anonymous script.
wordmark
# ⭐ THE TAGLINE, WORD FOR WORD FROM THE BRAND. The same two sentences the dashboard and the site use, so a
# customer meeting the product in a terminal meets the same product.
printf '  \033[2mConnect Everything. Trust Nothing.\033[0m\n'
printf '  \033[2mSelf-hosted Zero Trust VPN\033[0m\n\n'
BANNER_SHOWN=1

command -v curl >/dev/null 2>&1 || die "curl is required."

# SUDO is empty when already root. Every privileged command goes through it, so a root container and a
# sudo-capable user take the same path and neither needs a special case.
SUDO=""
if [ "$(id -u)" -ne 0 ]; then
	command -v sudo >/dev/null 2>&1 ||
		die "not running as root and sudo is not available. Re-run as root."
	SUDO="sudo"
	# ⛔ THE PASSWORD IS ASKED ONCE, AT THE START, AND NOT IN THE MIDDLE OF THE WORK.
	#
	# Docker installation, firewall rules and every compose command need root. Left to happen naturally, the
	# prompt appears somewhere inside a progress line — after the operator has walked away from a script
	# they were told would take a minute — and a sudo prompt that times out fails the step it was in.
	#
	# ⚠ `sudo -v` VALIDATES AND CACHES, it does not run anything. If the cache is already warm it prints
	# nothing at all, so a passwordless or recently-authenticated session sees no prompt.
	if ! sudo -n true 2>/dev/null; then
		# ⚠ NO TERMINAL MEANS NO PASSWORD PROMPT, and sudo's own error about askpass helpers is not a
		# sentence an operator should have to decode. Say what to do instead.
		if [ "$HAVE_TTY" = "0" ]; then
			die "administrator access is required and there is no terminal to ask for a password on.
  Re-run as root, or give this user passwordless sudo:
      curl -fsSL https://get.tunnex.io -o get.sh && sudo sh get.sh"
		fi
		printf '\n  \033[1mAdministrator access\033[0m\n'
		printf '  \033[2mDocker, firewall rules and the container stack all need root.\033[0m\n'
		printf '  \033[2mAsked once, now, so nothing stops halfway.\033[0m\n\n'
		sudo -v || die "administrator access is required to install Tunnex."
	fi
fi

# DOCKER is how this script invokes docker. A user added to the `docker` group during THIS run does not
# have the group in THIS shell — the membership applies at next login — so the group change alone would
# leave every later command failing with a permission error on a machine that is correctly configured.
DOCKER="docker"

# os_family reports the family we know how to install on, or "unknown". /etc/os-release is the standard
# every modern distribution ships; ID_LIKE catches derivatives (Pop!_OS, Rocky, Amazon Linux) without
# naming each one.
os_family() {
	[ -r /etc/os-release ] || { printf 'unknown'; return; }
	# shellcheck disable=SC1091
	. /etc/os-release
	case " ${ID:-} ${ID_LIKE:-} " in
	*" debian "* | *" ubuntu "*) printf 'debian' ;;
	*" rhel "* | *" fedora "* | *" centos "* | *" amzn "*) printf 'rhel' ;;
	*) printf 'unknown' ;;
	esac
}

os_pretty() {
	if [ -r /etc/os-release ]; then
		# shellcheck disable=SC1091
		. /etc/os-release
		printf '%s' "${PRETTY_NAME:-${NAME:-unknown}}"
	else
		printf 'unknown'
	fi
}

# ⛔ READINESS MEANS THE DAEMON ANSWERS THIS USER — NOT THAT THE CLI EXISTS.
#
# This checked `docker compose version`, which SUCCEEDS with no daemon access whatsoever: it is a
# client-side plugin query. So on a machine where Docker was installed by hand and the user was never added
# to the `docker` group, the check passed, the sudo fallback below was never reached, and the install ran
# all the way to `docker pull` before failing with:
#
#     permission denied while trying to connect to the docker API at unix:///var/run/docker.sock
#
# `docker info` is the question that means something: it round-trips to the daemon over the socket, so it
# fails for a stopped daemon AND for a user who may not talk to it.
docker_ready() {
	command -v docker >/dev/null 2>&1 || return 1
	$DOCKER compose version >/dev/null 2>&1 || return 1
	$DOCKER info >/dev/null 2>&1 || return 1
	return 0
}

# resolve_docker finds a working way to invoke docker, in increasing order of privilege, and sets DOCKER.
# Returns non-zero only when Docker is genuinely absent or unusable by any route.
resolve_docker() {
	DOCKER="docker"
	if docker_ready; then return 0; fi
	command -v docker >/dev/null 2>&1 || return 1

	# ⚠ THE DAEMON MAY SIMPLY NOT BE RUNNING — a different problem from a permission one, with a different
	# fix, and cheap to rule out before asking anyone for anything.
	if command -v systemctl >/dev/null 2>&1; then
		$SUDO systemctl start docker >/dev/null 2>&1 || true
		DOCKER="docker"
		if docker_ready; then return 0; fi
	fi

	# ⭐ AND THE COMMON CASE ON A MACHINE WHERE SOMEONE INSTALLED DOCKER BY HAND: the daemon is fine and this
	# user is not in the `docker` group. sudo works now; the group is fixed for next time.
	if [ -n "$SUDO" ]; then
		DOCKER="sudo docker"
		if docker_ready; then
			GROUP_FIX=1
			return 0
		fi
	fi
	DOCKER="docker"
	return 1
}

# ⛔ DOCKER IS INSTALLED FOR THE OPERATOR, WITH CONSENT, RATHER THAN DEMANDED FROM THEM.
#
# This used to stop at `Docker is required. Install Docker Engine, then re-run.` — true, useless, and the
# first thing a customer meets on a fresh VPS. A one-command installer that ends by asking someone to go and
# run a different command is not a one-command installer.
#
# ⚠ CONSENT IS ASKED, NOT ASSUMED. Installing a system package manager's worth of software is not something
# to do silently inside a script someone piped into a shell, and the prompt names exactly what will happen.
ensure_docker() {
	if resolve_docker; then
		fix_docker_group
		return 0
	fi

	_fam="$(os_family)"
	printf "\n  \033[1mDocker\033[0m\n"
	printf "  \033[2mTunnex runs as containers. Docker Engine and the Compose v2 plugin are required.\033[0m\n"
	printf "  \033[2mDetected: %s\033[0m\n" "$(os_pretty)"

	if [ "$_fam" = "unknown" ]; then
		die "Docker is not installed and this system is not one I can install it on automatically.
  Install Docker Engine and the Compose v2 plugin, then re-run:
      https://docs.docker.com/engine/install/"
	fi

	choose "Install Docker now?" 1 \
		"Yes — install Docker Engine + Compose plugin (uses Docker's official installer)" \
		"No — stop here and I will install it myself"
	if [ "$CHOICE" != "1" ]; then
		die "Docker is required. Install it and re-run:
      https://docs.docker.com/engine/install/"
	fi

	# ⚠ DOCKER'S OWN CONVENIENCE SCRIPT, FROM DOCKER'S OWN DOMAIN. It is the method Docker publishes and
	# maintains for every distribution here, and it adds their signed repository rather than dropping
	# binaries — so upgrades keep working through the system package manager afterwards.
	step "installing Docker (a few minutes)"
	if ! curl -fsSL https://get.docker.com -o /tmp/get-docker.sh 2>/dev/null; then
		die "could not download Docker's installer from https://get.docker.com"
	fi
	if ! $SUDO sh /tmp/get-docker.sh >/tmp/docker-install.log 2>&1; then
		printf '\n'
		tail -12 /tmp/docker-install.log >&2
		die "Docker installation failed — the error is above, full log at /tmp/docker-install.log
  Install it manually and re-run: https://docs.docker.com/engine/install/"
	fi
	rm -f /tmp/get-docker.sh
	ok "Docker installed"

	if command -v systemctl >/dev/null 2>&1; then
		$SUDO systemctl enable --now docker >/dev/null 2>&1 || true
	fi

	resolve_docker || die "Docker was installed but the daemon is not reachable.
  Check it with: $SUDO systemctl status docker
  Install log: /tmp/docker-install.log"
	fix_docker_group
}

# fix_docker_group leaves the machine so the NEXT session does not need sudo.
#
# ⚠ AND IT DOES NOT CHANGE HOW THIS RUN INVOKES DOCKER. A group added now does not exist in the current
# shell — it applies at next login — so relying on it here would break every command that follows, on a
# machine that had just been configured correctly. DOCKER keeps whatever resolve_docker proved works.
fix_docker_group() {
	[ "${GROUP_FIX:-0}" = "1" ] || return 0
	[ -n "$SUDO" ] || return 0
	if $SUDO usermod -aG docker "$(id -un)" >/dev/null 2>&1; then
		GROUP_NOTE=1
	fi
}

GROUP_NOTE=0
GROUP_FIX=0
CRED_SHOWN=0

# ── ports ───────────────────────────────────────────────────────────────────────────────────────
#
# ⛔ THE PORTS ARE THE THING THAT MAKES AN INSTALL LOOK BROKEN WHEN IT WORKED PERFECTLY.
#
# Every service comes up healthy, the script prints a dashboard URL, and the browser times out — because a
# cloud security group closed everything except SSH. The operator has no way to tell that apart from a
# failed install, and the first thing they do is run it again.
#
# ⚠ THIS ADVISES; IT DOES NOT REACH OUT AND OPEN THINGS IT CANNOT SEE. A local firewall it can offer to
# open, with consent. A cloud security group lives in an API this script has no credentials for and should
# not have — so it is NAMED, with the exact ports, at the moment the operator can still go and fix it.
#
#   80/tcp     the dashboard
#   8443/tcp   the agent control channel — gateways dial this directly, so it is NOT optional
#   51820/udp  WireGuard
#
# ⚠ 8443 IS THE ONE PEOPLE MISS. It looks like an internal port and it is not: a gateway enrols and
# reconciles over it from wherever it runs, so a deployment with 80 open and 8443 closed has a dashboard
# that works and gateways that never come online.
detect_cloud() {
	# IMDS, one second, no retries. A non-cloud machine must not pay for this check.
	if curl -fsS -m 1 -H 'Metadata-Flavor: Google' \
		http://169.254.169.254/computeMetadata/v1/instance/id >/dev/null 2>&1; then
		printf 'gcp'
		return
	fi
	if curl -fsS -m 1 -H 'Metadata: true' \
		"http://169.254.169.254/metadata/instance?api-version=2021-02-01" >/dev/null 2>&1; then
		printf 'azure'
		return
	fi
	# AWS IMDSv2 first (a token is required on modern instances), then v1 for older ones.
	_t="$(curl -fsS -m 1 -X PUT http://169.254.169.254/latest/api/token \
		-H 'X-aws-ec2-metadata-token-ttl-seconds: 60' 2>/dev/null || true)"
	if [ -n "$_t" ] && curl -fsS -m 1 -H "X-aws-ec2-metadata-token: $_t" \
		http://169.254.169.254/latest/meta-data/instance-id >/dev/null 2>&1; then
		printf 'aws'
		return
	fi
	if curl -fsS -m 1 http://169.254.169.254/latest/meta-data/instance-id >/dev/null 2>&1; then
		printf 'aws'
		return
	fi
	printf 'none'
}

report_ports() {
	printf '\n  \033[1mNetwork\033[0m\n'
	printf '  \033[2mThese must be reachable from your users and gateways:\033[0m\n'
	printf '      \033[1m80/tcp\033[0m     dashboard\n'
	printf '      \033[1m8443/tcp\033[0m   agent control channel \033[2m(gateways dial this — often missed)\033[0m\n'
	printf '      \033[1m51820/udp\033[0m  WireGuard\n'

	# A local firewall this script CAN see, and can offer to open.
	_fw=""
	if command -v ufw >/dev/null 2>&1 && $SUDO ufw status 2>/dev/null | grep -qi '^Status: active'; then
		_fw="ufw"
	elif command -v firewall-cmd >/dev/null 2>&1 && $SUDO firewall-cmd --state >/dev/null 2>&1; then
		_fw="firewalld"
	fi

	if [ -n "$_fw" ]; then
		printf '\n  \033[33m%s is active on this machine and will block them.\033[0m\n' "$_fw"
		choose "Open these ports in $_fw now?" 1 "Yes — open 80/tcp, 8443/tcp, 51820/udp" "No — I will do it myself"
		if [ "$CHOICE" = "1" ]; then
			step "opening ports in $_fw"
			if [ "$_fw" = "ufw" ]; then
				$SUDO ufw allow 80/tcp >/dev/null 2>&1 || true
				$SUDO ufw allow 8443/tcp >/dev/null 2>&1 || true
				$SUDO ufw allow 51820/udp >/dev/null 2>&1 || true
			else
				$SUDO firewall-cmd --permanent --add-port=80/tcp >/dev/null 2>&1 || true
				$SUDO firewall-cmd --permanent --add-port=8443/tcp >/dev/null 2>&1 || true
				$SUDO firewall-cmd --permanent --add-port=51820/udp >/dev/null 2>&1 || true
				$SUDO firewall-cmd --reload >/dev/null 2>&1 || true
			fi
			ok "ports opened in $_fw"
		fi
	fi

	# ⛔ AND THE CLOUD FIREWALL, WHICH IS A DIFFERENT FIREWALL AND THE ONE THAT ACTUALLY BLOCKS PEOPLE. It
	# is outside the machine, so opening ufw says nothing about it — an operator who just answered "yes"
	# above would otherwise reasonably believe the networking was handled.
	case "$(detect_cloud)" in
	aws)
		printf '\n  \033[33m⚠ This looks like an EC2 instance.\033[0m Its \033[1msecurity group\033[0m is separate from\n'
		printf '  anything on this machine and will block those ports until you add inbound rules:\n'
		printf '      EC2 → Instances → this instance → Security → Security groups → Edit inbound rules\n'
		;;
	gcp)
		printf '\n  \033[33m⚠ This looks like a Compute Engine instance.\033[0m VPC \033[1mfirewall rules\033[0m are separate\n'
		printf '  from anything on this machine and will block those ports until you allow them:\n'
		printf '      gcloud compute firewall-rules create tunnex \\\n'
		printf '        --allow=tcp:80,tcp:8443,udp:51820 --target-tags=tunnex\n'
		;;
	azure)
		printf '\n  \033[33m⚠ This looks like an Azure VM.\033[0m Its \033[1mnetwork security group\033[0m is separate from\n'
		printf '  anything on this machine and will block those ports until you add inbound rules:\n'
		printf '      Virtual machine → Networking → Add inbound port rule\n'
		;;
	*)
		printf '\n  \033[2mIf this machine sits behind a cloud firewall, router or NAT, allow those ports there too.\033[0m\n'
		;;
	esac
	printf '\n'
}

# ── 1. resolve the newest published semantic release ────────────────────────────────────────────
API="https://api.github.com/repos/tunnexio/tunnex"
RAW="https://raw.githubusercontent.com/tunnexio/tunnex"
resolve_install_version
resolve_display_version


printf '  \033[2mInstalling %s\033[0m\n' "$DISPLAY_VERSION"
printf '  \033[2mProvenance: %s\033[0m\n' "$VERSION_PROVENANCE"

[ "$HAVE_TTY" = "1" ] || [ "$ASSUME_YES" = "1" ] || no_tty_help

ensure_docker
report_ports

# ── 2. EVERY QUESTION, BEFORE ANY WORK ──────────────────────────────────────────────────────────
printf '  \033[1mDeployment\033[0m\n'

# ⚠ NO DEFAULT FOR THE ADDRESS, ON PURPOSE. Every other prompt can be guessed; this one cannot, and a wrong
# guess is invisible until a device fails to connect.
BASE_URL="${TUNNEX_PUBLIC_BASE_URL:-${TUNNEX_PUBLIC_ADDR:-}}"
if [ -n "$BASE_URL" ]; then
	public_base_url_ok "$BASE_URL" || die "TUNNEX_PUBLIC_BASE_URL='${BASE_URL}' is not a usable public URL — include http:// or https:// and omit paths, credentials and queries."
else
	ask_validated "Public base URL users and gateways reach (including http:// or https://)" "" public_base_url_ok \
		"Enter an http:// or https:// URL with no path, credentials or query — not localhost."
	BASE_URL="$ANSWER"
fi
ADDR="$(public_base_url_host "$BASE_URL")"

# ⛔ THE POOL IS ASKED, NOT ASSUMED. It is the space every device gets a /32 from, and it must not collide
# with any LAN you intend to route — a collision surfaces later, as traffic that silently goes elsewhere.
ask_validated "WireGuard address pool" "${TUNNEX_POOL_CIDR:-10.99.0.0/16}" cidr_ok \
	"Enter a CIDR block, e.g. 10.99.0.0/16 — it must not overlap any LAN you will route."
POOL_CIDR="$ANSWER"
ask_validated "IPv6 ULA pool" "${TUNNEX_IPV6_POOL_CIDR:-fd7a:1b2c:3d4e::/48}" ipv6_cidr_ok \
	"Enter an IPv6 ULA pool, normally a /48, e.g. fd7a:1b2c:3d4e::/48."
IPV6_POOL_CIDR="$ANSWER"

printf '\n  \033[1mAdministrator\033[0m\n'
ask_validated "Email for the first administrator" "${TUNNEX_ADMIN_EMAIL:-admin@${ADDR}}" email_ok \
	"Enter a valid email address."
ADMIN_EMAIL="$ANSWER"

printf '\n  \033[1mEmail delivery\033[0m\n'
printf '  \033[2mInvitations, password resets and email verification all need SMTP.\033[0m\n'

SMTP_HOST="${SMTP_HOST:-}"
SMTP_PORT="${SMTP_PORT:-587}"
SMTP_FROM="${SMTP_FROM:-}"
SMTP_USERNAME="${SMTP_USERNAME:-}"
SMTP_PASSWORD="${SMTP_PASSWORD:-}"

if [ -z "$SMTP_HOST" ]; then
	choose "Configure SMTP?" 2 \
		"Yes — set it up now" \
		"Skip — invitations will not be delivered (add it later in .env)"
	if [ "$CHOICE" = "1" ]; then
		ask_validated "SMTP host" "" hostname_ok "Enter the server hostname, e.g. smtp.example.net."
		SMTP_HOST="$ANSWER"
		# ⚠ 587, NOT 465. Go's net/smtp dials plaintext and upgrades via STARTTLS; it has no implicit-TLS
		# path, so an SMTPS port hangs or errors. A standard-library property, not a setting.
		ask "SMTP port \033[2m(587 = STARTTLS; 465 is not supported)\033[0m" "587"
		SMTP_PORT="$ANSWER"
		ask_validated "Send mail as" "no-reply@${ADDR}" email_ok "Enter a valid email address."
		SMTP_FROM="$ANSWER"
		ask "SMTP username \033[2m(blank if none)\033[0m" ""
		SMTP_USERNAME="$ANSWER"
		if [ -n "$SMTP_USERNAME" ]; then
			ask_secret "SMTP password"
			SMTP_PASSWORD="$ANSWER"
		fi
	fi
fi

# ── 3. THE SUMMARY — the one moment the whole decision is visible before anything happens ───────
printf '\n  \033[1mReady to install\033[0m\n'
printf '    Version          %s\n' "$DISPLAY_VERSION"
printf '    Image tag        %s\n' "$VERSION"
printf '    Source commit    %s\n' "$SOURCE_REF"
	printf '    Public URL       %s\n' "$BASE_URL"
	printf '    Dashboard        %s/\n' "$BASE_URL"
printf '    Administrator    %s\n' "$ADMIN_EMAIL"
printf '    Address pool     %s\n' "$POOL_CIDR"
printf '    IPv6 ULA pool    %s\n' "$IPV6_POOL_CIDR"
if [ -n "$SMTP_HOST" ]; then
	printf '    Email            %s:%s as %s\n' "$SMTP_HOST" "$SMTP_PORT" "$SMTP_FROM"
else
	printf '    Email            \033[33mnot configured — invitations will not be delivered\033[0m\n'
fi
printf '    Directory        %s/tunnex\n\n' "$(pwd)"

if [ "$ASSUME_YES" = "0" ] && [ "$HAVE_TTY" = "1" ]; then
	choose "Proceed?" 1 "Install now" "Cancel"
	[ "$CHOICE" = "1" ] || die "Cancelled. Nothing was written."
fi

# ── 4. install ──────────────────────────────────────────────────────────────────────────────────

printf '\n'
mkdir -p tunnex
cd tunnex

step "installing the verified host updater"
curl -fsSL "${RAW}/${SOURCE_REF}/deploy/upgrade.sh" -o upgrade.sh 2>/dev/null ||
	die "could not download deploy/upgrade.sh at ${SOURCE_REF}"
chmod 755 upgrade.sh
ok "host updater installed"

step "fetching the release manifest"
curl -fsSL "${RAW}/${SOURCE_REF}/deploy/tunnex.yml" -o tunnex.yml 2>/dev/null ||
	die "could not download deploy/tunnex.yml at ${SOURCE_REF}"

# A published release has an immutable signed descriptor. The release tag is
# resolved once, then SOURCE_REF is its exact commit, so images, compose and
# release metadata describe one verified release rather than a moving branch.
case "$VERSION" in
	v*) RELEASE_DESCRIPTOR_TAG="$VERSION" ;;
	sha-*) RELEASE_DESCRIPTOR_TAG="tunnex-build-${SOURCE_REF}" ;;
	*) die "a signed release descriptor is required for version ${VERSION}" ;;
esac
RELEASE_MANIFEST_URL="${TUNNEX_RELEASE_MANIFEST_URL:-https://github.com/tunnexio/tunnex/releases/download/${RELEASE_DESCRIPTOR_TAG}/release.json}"
curl -fsSL "$RELEASE_MANIFEST_URL" -o release.json 2>/dev/null ||
	die "could not download the signed release manifest for ${SOURCE_REF}; refusing an unverifiable install"
# Signed release metadata is mounted into the unprivileged API container. It is not
# secret, so keep it world-readable while the bind mount itself stays read-only.
chmod 0644 release.json
RELEASE_MANIFEST_PATH="/var/lib/tunnex/release.json"
# Resolve the trusted key once for both .env generation and the verifier command.
# Under `set -u`, relying only on the heredoc default leaves the shell variable unset.
TUNNEX_RELEASE_PUBLIC_KEY="${TUNNEX_RELEASE_PUBLIC_KEY:-$TRUSTED_RELEASE_PUBLIC_KEY}"

# ⛔ CONFIRM WHAT WE FETCHED IS A PRODUCTION COMPOSE FILE rather than trusting the tag. A dev compose file
# reaching a customer is a Mailpit that swallows every invitation and a non-production environment flag —
# both of which look fine and behave wrongly.
if grep -qi 'mailpit' tunnex.yml; then
	die "the fetched tunnex.yml references Mailpit — that is a development compose file. Refusing to install."
fi
grep -q 'TUNNEX_ENV: production' tunnex.yml ||
	die "the fetched tunnex.yml does not set TUNNEX_ENV: production. Refusing to install."
ok "deployment manifest fetched"

if command -v sha256sum >/dev/null 2>&1; then
	TUNNEX_COMPOSE_SHA256="$(sha256sum tunnex.yml | awk '{print $1}')"
else
	TUNNEX_COMPOSE_SHA256="$(shasum -a 256 tunnex.yml | awk '{print $1}')"
fi

step "writing configuration"
PG_PASS=""
if [ -f .env ]; then
	PG_PASS="$(grep -E '^POSTGRES_PASSWORD=' .env | head -1 | cut -d= -f2- || true)"
fi
REUSED=""
if [ -n "$PG_PASS" ]; then REUSED=" (reused the existing database password)"; fi
[ -n "$PG_PASS" ] || PG_PASS="$(head -c 32 /dev/urandom | od -An -tx1 | tr -d ' \n')"

umask 077
cat >.env <<EOF
# Written by the Tunnex installer. Edit values here; never hand-edit tunnex.yml.
#
# ⛔ EVERY VARIABLE tunnex.yml MARKS REQUIRED MUST BE HERE. Compose fails at interpolation — before it pulls
# a single layer — with "required variable X is missing a value", and the four with \${VAR:?} are
# APP_BASE_URL, DATABASE_URL, POSTGRES_PASSWORD and TUNNEX_NODE_ENDPOINT.
TUNNEX_VERSION=${VERSION}
# Exact Git ref the installer used for tunnex.yml; image tag + manifest provenance stay inspectable.
TUNNEX_SOURCE_REF=${SOURCE_REF}
TUNNEX_LOG_LEVEL=info
APP_BASE_URL=${BASE_URL}
# Release upgrades verify this value locally; it is not a telemetry or call-home credential.
# The installer keeps it in the deployment config so the UI command never exposes it.
TUNNEX_RELEASE_PUBLIC_KEY=${TUNNEX_RELEASE_PUBLIC_KEY:-$TRUSTED_RELEASE_PUBLIC_KEY}
TUNNEX_RELEASE_KEY_ID=release-2026-08-01
TUNNEX_RELEASE_MANIFEST_PATH=${RELEASE_MANIFEST_PATH}
TUNNEX_RELEASE_CATALOG_URL=${TUNNEX_RELEASE_CATALOG_URL:-https://github.com/tunnexio/tunnex/releases/download/tunnex-updates/release.json}
TUNNEX_RELEASE_UPDATE_CHECK=${TUNNEX_RELEASE_UPDATE_CHECK:-true}
# Baseline hash lets the updater detect edits to the installed deployment file.
TUNNEX_COMPOSE_SHA256=${TUNNEX_COMPOSE_SHA256}
# The WireGuard endpoint peers dial. Host:port, not a URL — it goes into every device config.
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
# Recorded for the operator; the pool itself is per-organization and set in the dashboard.
TUNNEX_ADMIN_EMAIL=${ADMIN_EMAIL}
TUNNEX_POOL_CIDR=${POOL_CIDR}
TUNNEX_IPV6_POOL_CIDR=${IPV6_POOL_CIDR}
# ⛔ NEVER SET THIS ON A DEPLOYMENT — it tees message bodies to the log, and those bodies are working links.
MAIL_DEV_LOG=false
EOF
ok "configuration written${REUSED}"

# ⛔ VALIDATE THE COMPOSE FILE AGAINST THE .env WE JUST WROTE, BEFORE PULLING ANYTHING.
#
# A missing required variable fails at INTERPOLATION — so it surfaced as "could not pull images", which is
# the wrong sentence about the wrong step and sent the operator looking at their registry and their docker
# group. `config -q` asks the one question that matters — is this file complete and usable — and asks it
# where the answer is cheap.
#
# ⚠ AND IT IS A GUARD AGAINST DRIFT, NOT JUST AGAINST TODAY'S BUG: tunnex.yml is fetched from the release,
# this .env is written here, and a future release that requires a new variable would otherwise fail on a
# customer's machine with a message about images.
step "validating configuration"
if ! $DOCKER compose -f tunnex.yml config -q >/tmp/tunnex-config.log 2>&1; then
	printf '\n'
	tail -12 /tmp/tunnex-config.log >&2
	die "the configuration is not usable — the error is above.
  This means tunnex.yml wants a variable the installer did not write. Full log: /tmp/tunnex-config.log"
fi
ok "configuration validated"

# ⛔ THE ERROR IS SHOWN, NOT SWALLOWED. This read `>/dev/null 2>&1 || die "could not pull images."` — so an
# operator whose user is not in the `docker` group, or whose registry is unreachable, got four words and no
# way to tell those apart. The same swallowed-error shape this product has a law about, in the installer.
step "pulling images — this takes a minute"
if ! $DOCKER compose -f tunnex.yml pull >/tmp/tunnex-pull.log 2>&1; then
	printf '\n'
	tail -12 /tmp/tunnex-pull.log >&2
	die "could not pull images — the error is above, and the full log is /tmp/tunnex-pull.log
  If it says permission denied, this user is not in the \`docker\` group yet:
      log out and back in, or re-run with: sudo sh get.sh"
fi
ok "images pulled"

step "verifying signed release descriptor and pinning images"
case "$($DOCKER version --format '{{.Server.Arch}}' 2>/dev/null || true)" in
	amd64|x86_64) RELEASE_ARCH=amd64 ;;
	arm64|aarch64) RELEASE_ARCH=arm64 ;;
	*) die "could not determine a supported Docker server architecture for release verification" ;;
esac
if ! RELEASE_ENV="$($DOCKER run --rm --entrypoint releaseverify \
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
if ! $DOCKER compose -f tunnex.yml pull >/tmp/tunnex-pinned-pull.log 2>&1; then
	tail -12 /tmp/tunnex-pinned-pull.log >&2
	die "could not pull the signed, digest-pinned images"
fi
ok "signed release verified; images pinned by digest"

step "starting the stack"
if ! $DOCKER compose -f tunnex.yml up -d --wait >/tmp/tunnex-up.log 2>&1; then
	printf '\n'
	tail -20 /tmp/tunnex-up.log >&2
	die "the stack did not come up healthy — the error is above, full log at /tmp/tunnex-up.log
  Inspect with: cd $(pwd) && $DOCKER compose -f tunnex.yml ps"
fi
ok "stack running"

# ── 5. THE FIRST-RUN CREDENTIAL, READ BACK AND SHOWN WHERE THE OPERATOR IS LOOKING ──────────────
#
# ⛔ THE STEP THAT WAS MISSING AND IT COST THE WHOLE INSTALL. The administrator credential is printed ONCE,
# to the API container's stdout — and `up -d` is detached, so it scrolled into a log the operator was never
# told to read. It exists as an argon2id hash and nowhere else, so this is the only moment it can be shown.
CREDS="$($DOCKER compose -f tunnex.yml logs api 2>/dev/null |
	sed -n '/TUNNEX - FIRST RUN/,/^.*=\{20,\}$/p' | tail -n +2 || true)"

printf '\n'
if printf '%s' "$CREDS" | grep -q 'password'; then
	printf '  \033[1mYour administrator credential — shown once, copy it now\033[0m\n\n'
	printf '%s\n' "$CREDS"
	CRED_SHOWN=1
else
	# ⛔ ABSENT IS NOT THE SAME AS LOST, AND SAYING SO WRONGLY IS ALARMING FOR NO REASON.
	#
	# bootstrap.EnsureAdmin mints the administrator ONLY when the deployment has never had a user, and
	# prints nothing on every other start. So a re-run against an existing database — which is exactly what
	# an idempotent installer produces, and what "reused the existing database password" announces two steps
	# earlier — has no banner to find, because the account already exists and its credential was printed
	# during the FIRST run.
	#
	# ⚠ THE PREVIOUS MESSAGE READ AS DATA LOSS. It said the credential could not be read and offered
	# `down -v` — destroying the deployment — to an operator whose account was fine and whose password they
	# may simply have kept. Distinguishing the two cases is the difference between a note and a scare.
	if [ -n "$REUSED" ]; then
		printf '  \033[2mNo new administrator was created — this deployment already had one, so its\033[0m\n'
		printf '  \033[2mcredential was printed during the first install. Sign in with that.\033[0m\n\n'
		printf '  Lost it? There is no recovery and no second admin. Start over with a clean\n'
		printf '  database (this destroys all Tunnex data on this machine):\n'
		printf '      cd %s && %s compose -f tunnex.yml down -v && curl -fsSL https://get.tunnex.io | sh\n' "$(pwd)" "$DOCKER"
	else
		printf '  \033[33m⚠ Could not read the first-run credential from the API log.\033[0m\n\n'
		printf '  Retrieve it with:\n'
		printf '      cd %s && %s compose -f tunnex.yml logs api | grep -A8 "FIRST RUN"\n\n' "$(pwd)" "$DOCKER"
		printf '  If it is genuinely gone there is no recovery and no second admin —\n'
		printf '      cd %s && %s compose -f tunnex.yml down -v\n' "$(pwd)" "$DOCKER"
	fi
fi

# ── 6. hand-off ─────────────────────────────────────────────────────────────────────────────────
printf '\n  \033[1mNext\033[0m\n'
printf '    1. Open  %s/\n' "$BASE_URL"
if [ "$CRED_SHOWN" = "1" ]; then
	printf '    2. Sign in with the credential above — you must set your own password immediately.\n'
else
	printf '    2. Sign in as the administrator created on the first install.\n'
fi
printf '    3. Create your first organization.\n'
printf '    4. Gateways → Generate join token, then run the command it shows on your gateway host.\n'
if [ -z "$SMTP_HOST" ]; then
	printf '\n  \033[33mEmail is not configured.\033[0m Invitations are still created and the dashboard shows a\n'
	printf '  copyable link you can send yourself. Set SMTP_* in .env, then:\n'
	printf '      docker compose -f tunnex.yml up -d api\n'
	printf '\n  Need to retrieve the one-time administrator credential? Inspect the API log explicitly:\n'
	printf '      cd %s && %s compose -f tunnex.yml logs api | grep -A8 "FIRST RUN"\n' "$(pwd)" "$DOCKER"
	printf '  The log contains the one-time password; do not paste it into tickets or shared logs.\n'
fi
# ⭐ SIGNUP IS ALREADY SHUT, and saying so is the difference between an operator who thinks they must hurry
# and one who knows the deployment is already theirs.
if [ "$GROUP_NOTE" = "1" ]; then
	printf '\n  \033[2mYou were added to the `docker` group. Log out and back in to run docker without sudo.\033[0m\n'
fi
printf '\n  \033[2mPublic signup is closed on this deployment — the administrator above is the only way in,\n'
printf '  and everyone else arrives by invitation or SSO.\033[0m\n\n'
