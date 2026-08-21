#!/bin/sh
# Contract test for the customer-facing host updater command.
set -eu

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
grep -Fq 'const repairCommand = "curl -fsSL https://get.tunnex.io | sh"' "$ROOT/apps/web/src/components/UpgradeCenter.tsx"
grep -Fq 'Installed version' "$ROOT/apps/web/src/components/UpgradeCenter.tsx"
grep -Fq 'Target version' "$ROOT/apps/web/src/components/UpgradeCenter.tsx"
grep -Fq 'Upgrade control plane' "$ROOT/apps/web/src/components/UpgradeCenter.tsx"
grep -Fq 'api.POST("/api/v1/admin/upgrade")' "$ROOT/apps/web/src/components/UpgradeCenter.tsx"
grep -Fq 'health check failed' "$ROOT/deploy/upgrade.sh"
grep -Fq 'restore the verified pre-upgrade backup' "$ROOT/deploy/upgrade.sh"
if grep -F 'const hostCommand' "$ROOT/apps/web/src/components/UpgradeCenter.tsx" | grep -Eq -- '--public-key|release\.json'; then
  echo 'UI host command must not expose key flags or placeholder manifest paths' >&2
  exit 1
fi
TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT INT TERM

mkdir -p "$TMP/tunnex"
cp "$ROOT/deploy/upgrade.sh" "$TMP/tunnex/upgrade.sh"
chmod 755 "$TMP/tunnex/upgrade.sh"
: >"$TMP/tunnex/tunnex.yml"
cat >"$TMP/tunnex/.env" <<'EOF'
TUNNEX_RELEASE_PUBLIC_KEY=from-installed-config
TUNNEX_RELEASE_CATALOG_URL=https://updates.example.test/release.json
EOF
: >"$TMP/tunnex/release.json"
: >"$TMP/catalog.json"
cat >"$TMP/curl" <<'EOF'
#!/bin/sh
[ "$1" = "-fsSL" ]
[ "$2" = "https://updates.example.test/release.json" ]
[ "$3" = "-o" ]
cp "$MOCK_CATALOG" "$4"
EOF
chmod 755 "$TMP/curl"
cat >"$TMP/releaseverify" <<'EOF'
#!/bin/sh
[ "$1" = "-manifest" ]
[ "$3" = "-public-key" ]
[ "$4" = "from-installed-config" ]
if [ "${5:-}" = "-print-env" ]; then
  cat <<'ENV'
TUNNEX_RELEASE_SOURCE_SHA=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
TUNNEX_RELEASE_VERSION=v9.9.9
TUNNEX_RELEASE_SEQUENCE=99
ENV
fi
EOF
chmod 755 "$TMP/releaseverify"

output=$(cd "$TMP/tunnex" && PATH="$TMP:$PATH" MOCK_CATALOG="$TMP/catalog.json" TUNNEX_RELEASEVERIFY="$TMP/releaseverify" ./upgrade.sh)
printf '%s\n' "$output" | grep -Fq 'dry run: re-run with --apply'
printf '%s\n' "$output" | grep -Fq 'release verified'

if (cd "$TMP/tunnex" && PATH="$TMP:$PATH" MOCK_CATALOG="$TMP/catalog.json" TUNNEX_RELEASEVERIFY="$TMP/releaseverify" ./upgrade.sh --expected-source-sha bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb) 2>"$TMP/pin-error"; then
  echo 'expected an approved-release mismatch to fail' >&2
  exit 1
fi
grep -Fq 'no longer matches the release approved in the UI' "$TMP/pin-error"

if (cd "$TMP/tunnex" && PATH="$TMP:$PATH" MOCK_CATALOG="$TMP/catalog.json" TUNNEX_RELEASEVERIFY="$TMP/releaseverify" ./upgrade.sh --public-key '') 2>"$TMP/error"; then
  echo 'expected empty explicit key to fail' >&2
  exit 1
fi
grep -Fq 'trusted release public key is not configured' "$TMP/error"

cat >"$TMP/tunnex/.env" <<'EOF'
TUNNEX_RELEASE_PUBLIC_KEY=from-installed-config
TUNNEX_RELEASE_CATALOG_URL=https://updates.example.test/release.json
TUNNEX_COMPOSE_SHA256=not-the-current-file
EOF
if (cd "$TMP/tunnex" && PATH="$TMP:$PATH" MOCK_CATALOG="$TMP/catalog.json" TUNNEX_RELEASEVERIFY="$TMP/releaseverify" ./upgrade.sh) 2>"$TMP/baseline-error"; then
  echo 'expected compose baseline mismatch to fail' >&2
  exit 1
fi
grep -Fq 'installed deployment files changed after provisioning' "$TMP/baseline-error"

echo 'upgrade helper contract passed'
