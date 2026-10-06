#!/bin/sh
# Local editor client bootstrap. No sudo, target enrollment or stored password.
set -eu
fail() { printf '%s\n' "Tunnex: $*" >&2; exit 1; }
[ "$#" -ge 8 ] || fail "Use the complete command copied from Tunnex."
[ "$1" = --server ] || fail "Missing control-plane URL."
server=$2
case "$server" in https://*) ;; *) fail "HTTPS is required." ;; esac
command -v curl >/dev/null || fail "Install curl first."
command -v ssh >/dev/null || fail "Install OpenSSH client first."
os=$(uname -s)
case "$os" in Darwin) os=darwin ;; Linux) os=linux ;; *) fail "Supported clients: macOS and Linux." ;; esac
case "$(uname -m)" in x86_64|amd64) arch=amd64 ;; arm64|aarch64) arch=arm64 ;; *) fail "Unsupported CPU architecture." ;; esac
code_bin=$(command -v code || true)
if [ -z "$code_bin" ] && [ "$os" = darwin ] && [ -x '/Applications/Visual Studio Code.app/Contents/Resources/app/bin/code' ]; then
  code_bin='/Applications/Visual Studio Code.app/Contents/Resources/app/bin/code'
  PATH="/Applications/Visual Studio Code.app/Contents/Resources/app/bin:$PATH"; export PATH
fi
[ -n "$code_bin" ] || fail "Install Visual Studio Code and enable its code command, then run this command again."
umask 077
[ -n "${HOME:-}" ] || fail "HOME is required."
dir="$HOME/.local/share/tunnex/editor-client"
[ ! -L "$HOME/.local" ] && [ ! -L "$HOME/.local/share" ] && [ ! -L "$HOME/.local/share/tunnex" ] && [ ! -L "$dir" ] || fail "Refusing a symlinked install directory."
mkdir -p "$dir"
chmod 700 "$dir"
work=$(mktemp -d "$dir/.prepare.XXXXXXXX")
trap 'rm -rf "$work"' EXIT HUP INT TERM
asset="tunnex-$os-$arch"
# Curl retains certificate validation; custom test CAs can use CURL_CA_BUNDLE.
fetch() { curl --fail --silent --show-error --proto '=https' --tlsv1.2 --connect-timeout 15 --max-time 180 "$1" -o "$2"; }
fetch "$server/editor-client/$asset.sha256" "$work/hash"
expected=$(tr -d '\r\n' < "$work/hash")
[ "${#expected}" -eq 64 ] || fail "Invalid client checksum."
case "$expected" in *[!0-9a-f]*) fail "Invalid client checksum." ;; esac
hash() { if command -v sha256sum >/dev/null; then sha256sum "$1" | cut -d ' ' -f 1; else shasum -a 256 "$1" | cut -d ' ' -f 1; fi; }
client="$dir/$expected/tunnex"
[ ! -L "$dir/$expected" ] && [ ! -L "$client" ] || fail "Refusing a symlinked client."
if [ ! -x "$client" ] || [ "$(hash "$client")" != "$expected" ]; then
  printf '%s\n' 'Preparing compatible Tunnex CLI…'
  fetch "$server/editor-client/$asset" "$work/tunnex"
  [ "$(hash "$work/tunnex")" = "$expected" ] || fail "Client checksum mismatch; nothing installed."
  chmod 700 "$work/tunnex"
  "$work/tunnex" help > "$work/help" 2>&1
  grep -q 'tunnex editor' "$work/help" || fail "This client does not support editor access."
  mkdir -p "$dir/$expected"
  chmod 700 "$dir/$expected"
  mv "$work/tunnex" "$client"
else
  printf '%s\n' 'Tunnex CLI is ready.'
fi
"$code_bin" --list-extensions > "$work/extensions"
if ! grep -qi '^ms-vscode-remote.remote-ssh$' "$work/extensions"; then
  printf '%s\n' 'Installing VS Code Remote - SSH…'
  "$code_bin" --install-extension ms-vscode-remote.remote-ssh
fi
# Editor validates the URL, tenant, server and account before browser approval.
if [ -n "${CURL_CA_BUNDLE:-}" ]; then
  "$client" editor "$@" --ca "$CURL_CA_BUNDLE"
else
  "$client" editor "$@"
fi
