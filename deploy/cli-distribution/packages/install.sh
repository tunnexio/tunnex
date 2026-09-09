#!/bin/sh
# Tunnex CLI only. Source: https://github.com/tunnexio/packages
set -eu

main() {
    fail() { printf 'Tunnex: %s\n' "$*" >&2; exit 1; }
    root() {
        if [ "$(id -u)" = 0 ]; then "$@"; else sudo "$@"; fi
    }
    sha() {
        if command -v sha256sum >/dev/null 2>&1; then
            sha256sum "$1" | awk '{print $1}'
        else
            shasum -a 256 "$1" | awk '{print $1}'
        fi
    }
    # Never overwrite another repository definition or key.
    put() {
        if [ -e "$2" ] || [ -L "$2" ]; then
            [ "$(sha "$1")" = "$(sha "$2")" ] || fail "Existing $2 differs; inspect it before retrying."
        else
            root install -m 644 "$1" "$2"
        fi
    }
    case "${1:-}" in
        --help|-h)
            printf '%s\n' 'Install tunnex-cli using the native package manager.' \
                'Linux: APT, DNF/YUM, zypper, APK, pacman (amd64/arm64).' \
                'macOS: existing Homebrew. No enrollment or tunnel activation.' \
                'Arch uses a full system upgrade; other OS/architectures are refused.'
            return ;;
        '') ;;
        *) fail 'Unknown argument. Use --help.' ;;
    esac
    [ "$#" -le 1 ] || fail 'Too many arguments.'
    case "$(uname -s)" in
        Darwin)
            command -v brew >/dev/null 2>&1 || fail 'Install Homebrew from https://brew.sh, then rerun as a regular user.'
            [ "$(id -u)" != 0 ] || fail 'Run this installer as a regular user for Homebrew.'
            brew install tunnexio/tap/tunnex-cli wireguard-tools
            for tool in tunnex wg wg-quick wireguard-go; do
                command -v "$tool" >/dev/null 2>&1 || fail "Required tool $tool is missing from PATH after installation."
            done
            tunnex version
            printf '%s\n' 'Installed CLI and WireGuard tools. Next: tunnex login --server https://YOUR_CONTROL_PLANE'
            return ;;
        Linux) ;;
        *) fail 'Unsupported OS. See https://github.com/tunnexio/packages#installation' ;;
    esac
    case "$(uname -m)" in
        x86_64|aarch64|arm64) ;;
        *) fail 'Supported Linux architectures: x86_64 and aarch64.' ;;
    esac
    [ -r /etc/os-release ] || fail 'Missing /etc/os-release; use the documented archive installation.'
    # shellcheck disable=SC1091
    . /etc/os-release
    case "${ID:-}" in
        nixos) fail 'Use: nix profile install github:tunnexio/packages#tunnex-cli' ;;
    esac
    [ ! -e /run/ostree-booted ] || fail 'Use the documented distribution-specific installation on immutable systems.'
    manager=''
    for candidate in apt-get dnf yum zypper apk pacman; do
        if command -v "$candidate" >/dev/null 2>&1; then manager=$candidate; break; fi
    done
    [ -n "$manager" ] || fail 'No supported package manager; see https://github.com/tunnexio/packages#other-linux-systems'
    if [ "$(id -u)" != 0 ]; then
        command -v sudo >/dev/null 2>&1 || fail 'Run as root or install sudo.'
        sudo -v
    fi
    command -v curl >/dev/null 2>&1 || fail 'Install curl and ca-certificates first.'
    base=https://tunnexio.github.io/packages
    key_id=9A565661A108388E34E4D9C6A0C5B3B1D39A8181
    temp=$(mktemp -d)
    trap 'rm -rf "$temp"' EXIT
    trap 'exit 1' HUP INT TERM
    umask 022
    if [ "$manager" = apk ]; then
        key=tunnex.rsa.pub
        expected=4c869a95f1b40559f6fd301dee9b62d77508ae5a9a32b7de79df6533ebf08253
    else
        key=tunnex.asc
        expected=b65bce5272ce7df63df537c46db34be162434460f39403e230de543ef9ad1748
    fi
    curl --proto '=https' --tlsv1.2 -fsSL --retry 3 "$base/$key" -o "$temp/$key"
    [ "$(sha "$temp/$key")" = "$expected" ] || fail 'Repository key checksum mismatch; no repository configured.'
    printf 'Installing Tunnex CLI using %s.\n' "$manager"
    case "$manager" in
        apt-get)
            printf 'deb [signed-by=/usr/share/keyrings/tunnex.asc] %s/apt stable main\n' "$base" > "$temp/repo"
            # Check both destinations before the first write.
            for pair in /usr/share/keyrings/tunnex.asc /etc/apt/sources.list.d/tunnex.list; do
                if [ "$pair" = /usr/share/keyrings/tunnex.asc ]; then src="$temp/$key"; else src="$temp/repo"; fi
                if [ -e "$pair" ] || [ -L "$pair" ]; then [ "$(sha "$src")" = "$(sha "$pair")" ] || fail "Existing $pair differs; inspect it before retrying."; fi
            done
            put "$temp/$key" /usr/share/keyrings/tunnex.asc
            put "$temp/repo" /etc/apt/sources.list.d/tunnex.list
            root apt-get update
            root apt-get install -y tunnex-cli
            ;;
        dnf|yum|zypper)
            # Use a local pinned key, so accepting keys cannot fetch different bytes.
            printf '[tunnex]\nname=Tunnex CLI\nbaseurl=%s/rpm\nenabled=1\ngpgcheck=1\nrepo_gpgcheck=1\ngpgkey=file:///etc/pki/rpm-gpg/tunnex.asc\n' "$base" > "$temp/repo"
            if [ "$manager" = zypper ]; then repos=/etc/zypp/repos.d; else repos=/etc/yum.repos.d; fi
            for pair in /etc/pki/rpm-gpg/tunnex.asc "$repos/tunnex.repo"; do
                if [ "$pair" = /etc/pki/rpm-gpg/tunnex.asc ]; then src="$temp/$key"; else src="$temp/repo"; fi
                if [ -e "$pair" ] || [ -L "$pair" ]; then [ "$(sha "$src")" = "$(sha "$pair")" ] || fail "Existing $pair differs; inspect it before retrying."; fi
            done
            root mkdir -p /etc/pki/rpm-gpg
            put "$temp/$key" /etc/pki/rpm-gpg/tunnex.asc
            put "$temp/repo" "$repos/tunnex.repo"
            root rpm --import /etc/pki/rpm-gpg/tunnex.asc
            if [ "$manager" = zypper ]; then
                root zypper --non-interactive --gpg-auto-import-keys refresh tunnex
                root zypper --non-interactive install --from tunnex tunnex-cli
            else
                root "$manager" install -y tunnex-cli
            fi
            ;;
        apk)
            put "$temp/$key" /etc/apk/keys/tunnex.rsa.pub
            if ! grep -Fxq "$base/alpine" /etc/apk/repositories; then
                printf '\n%s/alpine\n' "$base" | root tee -a /etc/apk/repositories >/dev/null
            fi
            root apk update
            root apk add tunnex-cli
            ;;
        pacman)
            # pacman expands $arch when reading the repository configuration.
            # shellcheck disable=SC2016
            printf '[tunnex]\nSigLevel = Required DatabaseRequired\nServer = %s/arch/$arch\n' "$base" > "$temp/repo"
            include='Include = /etc/pacman.d/tunnex.conf'
            # Refuse an existing manually defined section instead of duplicating it.
            if grep -Eq '^[[:space:]]*\[tunnex\]' /etc/pacman.conf; then
                fail 'Existing [tunnex] in /etc/pacman.conf; keep using pacman -Syu tunnex-cli.'
            fi
            if [ -e /etc/pacman.d/tunnex.conf ]; then [ "$(sha "$temp/repo")" = "$(sha /etc/pacman.d/tunnex.conf)" ] || fail 'Conflicting /etc/pacman.d/tunnex.conf'; fi
            root pacman-key --init
            root pacman-key --add "$temp/$key"
            root pacman-key --lsign-key "$key_id"
            put "$temp/repo" /etc/pacman.d/tunnex.conf
            if ! grep -Fxq "$include" /etc/pacman.conf; then
                printf '\n%s\n' "$include" | root tee -a /etc/pacman.conf >/dev/null
            fi
            printf '%s\n' 'Arch requires a full system upgrade along with CLI installation.'
            root pacman -Syu --noconfirm tunnex-cli
            ;;
    esac
    /usr/bin/tunnex version
    printf '%s\n' 'Installed. Next: tunnex login --server https://YOUR_CONTROL_PLANE'
}

# Parse the complete script before executing when piped to sh.
main "$@"
