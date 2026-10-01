#!/bin/sh
# A tagged release must not become latest while the public launcher still runs
# an older installer against its new deployment files. Compare public bytes;
# accepting a repository dispatch alone does not prove website deployment.
set -eu

ROOT=$(CDPATH= cd -- "$(dirname "$0")/.." && pwd)
SOURCE_SHA=${1:-${GITHUB_SHA:-}}
case "$SOURCE_SHA" in
  ''|*[!0-9a-f]*) echo 'error: installer site verification requires a full lowercase source SHA' >&2; exit 1 ;;
esac
[ "${#SOURCE_SHA}" -eq 40 ] || {
  echo 'error: installer site verification requires a full lowercase source SHA' >&2
  exit 1
}

STAGE=$(mktemp -d "${TMPDIR:-/tmp}/tunnex-installer-site.XXXXXX")
trap 'rm -rf "$STAGE"' 0 HUP INT TERM

# No tokens or cookies: these are the same public responses customers fetch.
# Fail immediately so an incomplete release remains a reviewable draft. Its
# main build prerelease can already drive a reviewed website sync beforehand.
curl --fail --location --silent --show-error --proto '=https' --proto-redir '=https' \
  --connect-timeout 10 --max-time 30 --header 'Accept: text/plain' \
  https://get.tunnex.io -o "$STAGE/get.sh" || {
  echo 'error: public POSIX installer is unavailable; refusing tagged release promotion' >&2
  exit 1
}
curl --fail --location --silent --show-error --proto '=https' --proto-redir '=https' \
  --connect-timeout 10 --max-time 30 --header 'Accept: text/plain' \
  https://get.tunnex.io/install.ps1 -o "$STAGE/install.ps1" || {
  echo 'error: public Windows installer is unavailable; refusing tagged release promotion' >&2
  exit 1
}

python3 - "$ROOT" "$STAGE" "$SOURCE_SHA" <<'PY'
import sys
from pathlib import Path

root, stage = map(Path, sys.argv[1:3])
source_sha = sys.argv[3]
canonical = b"https://raw.githubusercontent.com/tunnexio/tunnex/main/deploy/install.sh"
launcher = (root / "deploy/get.sh").read_bytes()
if canonical not in launcher:
    sys.exit("error: canonical launcher URL is missing; refusing tagged release promotion")
# Match the website handler's first replacement exactly. All other bytes,
# including newlines and the PowerShell BOM, must remain unchanged.
expected = launcher.replace(canonical, canonical.replace(b"/main/", f"/{source_sha}/".encode()), 1)
if (stage / "get.sh").read_bytes() != expected:
    sys.exit("error: public POSIX launcher does not match this release source; deploy its installer sync before promoting the tagged release")
if (stage / "install.ps1").read_bytes() != (root / "deploy/install.ps1").read_bytes():
    sys.exit("error: public Windows installer bytes do not match this release source; deploy its installer sync before promoting the tagged release")
print(f"Verified public platform installers for source {source_sha}")
PY
