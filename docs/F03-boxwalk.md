# F03 managed-agent bootstrap boxwalk

Status: **INCONCLUSIVE — current-source rerun required**. The approval-on
same-process behavior passed on the authorized AWS development control plane
and disposable Ubuntu 26.04 VM, but the shared source moved after the deployed
API was built. The redacted rerun evidence and exact provenance gap are under
`walk-artifacts/F03/20260815T081148Z/`. No run is currently counted as live-wire
satisfaction for the final shared source.

## Preconditions and secret hygiene

Use a disposable control-plane environment with the current shared migration
chain through 0093, an
active organization gateway, and an authorized operator session. Use a real
Linux host with `curl`, `jq`, `wireguard-tools`, `sudo`, and a reachable API.
Do not put tokens, runtime credentials, private keys, or full bootstrap
responses in committed artifacts.

```bash
run_id="$(date -u +%Y%m%dT%H%M%SZ)"
artifact="walk-artifacts/F03/$run_id"
mkdir -p "$artifact"
printf '%s\n' "$artifact" > "$artifact/location.txt"
umask 077
```

The committed walk paths are relative to the repository root:
`walk-artifacts/F03/<run-id>/location.txt`, `migration-version.txt`,
`bootstrap-issue-redacted.txt`, `bootstrap-redeem-redacted.txt`,
`replay-refused.txt`, `restart-persistence.txt`, `revoke-offboarding.txt`,
`secret-file-modes.txt`, `service-runtime.txt`, and `cleanup.txt`. Redact bearer values; scratch
private material belongs only in an ignored temporary directory.

## Live-wire steps

1. **Migration and fixture.** Record the migration version and active gateway
   identity, with organization/user IDs redacted or pseudonymized, in
   `migration-version.txt`. Confirm the issue caller is authenticated and
   authorized; separately record an unauthenticated and unauthorized refusal.

2. **Issue.** From the released Agents page, choose the active gateway and
   issue a managed agent command. Record only status, response shape, and the
   fact that no roster row appeared at issuance in
   `bootstrap-issue-redacted.txt`. Do not save the command or token in a
   committed file.

3. **Redeem on Linux.** Run the displayed command on the real host. Before
   running, confirm `runtime` is absent and none of
   `/usr/local/bin/tunnex-agent-runtime`,
   `/etc/systemd/system/tunnex-agent-runtime.service`,
   `/etc/wireguard/runtime.conf`,
   `/etc/tunnex-agent/runtime-credential`, or
   `/var/lib/tunnex-agent/runtime-state.json` exists. Capture redacted
   HTTP/status and `wg show runtime` evidence in
   `bootstrap-redeem-redacted.txt`. Verify the private key was generated on
   the host, the API request contained only the public key, the service is
   enabled and active, `runtime` is the only installer-owned interface, and
   the installed secret/state files are mode 0600. Record the enabled/active,
   desired/applied revision, and interface facts in `service-runtime.txt`.
   When device approval is enabled, first prove the pending agent receives no
   config and the interface remains absent; approve through the supported
   owner action and prove the same still-running service then applies revision
   1 without a manual restart.
   On Ubuntu 26.04, also record that the installed signed unit has
   `NoNewPrivileges=false` while retaining `ProtectSystem=strict`, the
   `CAP_NET_ADMIN` bounding/ambient sets, explicit `ReadWritePaths`, and
   `DeviceAllow=/dev/net/tun rw`. Verify `RestrictAddressFamilies` contains
   exactly `AF_UNIX AF_INET AF_INET6 AF_NETLINK`; the journal must contain no
   `Address family not supported by protocol` netlink refusal and no AppArmor
   `no new privs` transition denial for `wg-quick`, `ip`, or `wg`.

4. **One-time replay.** Re-run the exact command or a request using the same
   bootstrap token and a fresh client-generated public key. It must receive the
   same generic invalid-token refusal as an expired/wrong token, create no
   second device, and leave the original interface/config untouched. Record
   redacted output in `replay-refused.txt`.

5. **Restart persistence.** Restart the API process/container without changing
   PostgreSQL. Re-run the replay refusal and query the roster through the
   authorized UI/API. The consumed state and exactly one device must persist
   across restart. Record only statuses/counts in `restart-persistence.txt`.

6. **Credential and file boundary.** On the Linux host, record:

   ```bash
   stat -c '%a %n' /etc/wireguard/runtime.conf \
     /etc/tunnex-agent/runtime-credential \
     /var/lib/tunnex-agent/runtime-state.json
   sudo wg show runtime
   ```

   All three files must be 600. Inspect the API access log and browser network
   capture for absence of a private key and absence of a second runtime
   credential delivery. Never commit file contents. Record modes and redacted
   observations in `secret-file-modes.txt`.

7. **Revoke/offboarding.** In the Agents page choose Remove, confirm the copy
   says revoke first, then remove. Record the revoke response, subsequent
   roster response, and `wg show` proving the peer is gone in
   `revoke-offboarding.txt`. If deletion is intentionally made to fail, verify
   the UI says the agent was revoked but could not be removed. Confirm the old
   runtime credential and WireGuard config do not restore access. Prove the
   service is inactive (the unit may remain enabled for a clean boot-time
   authorization recheck) and `wg show runtime` reports absence. It must not be
   failed/restarting. Explicit cleanup in step 8 disables and removes the unit.

8. **Cleanup.** Disable/stop the runtime service, remove only its five managed
   paths named in step 3, destroy only the disposable control-plane resources, and
   record the resource identifiers and successful cleanup in `cleanup.txt`.
   Do not delete shared or production data.

## Current substitute evidence

### Partial AWS development walks (2026-08-15)

The earlier released command was issued by the Enterprise/Scale development control
plane at schema 93 and executed unchanged on the disposable Ubuntu VM. A real
current-head node agent owned the uniquely enrolled disposable gateway and sent
both `/agent/report` and `/agent/status`; no database status was fabricated.
The released Agents payload then reported `gateway_reporting=true`,
`online=true`, and a non-null fresh handshake while the runtime panel reported
`connected`, `stale=false`, and desired/attempted/applied `1/1/1`.

The two WireGuard peers completed a real handshake, survived service restarts,
and re-established the handshake after one keepalive interval. Replaying the
consumed bootstrap token with a newly generated public key returned HTTP 401,
created no second row, and left the device/runtime state unchanged. After the
operator observed the connected row, canonical revoke returned HTTP 204; the
next runtime poll removed `runtime` and exited status 0 with the unit inactive,
still enabled for the ruled boot-time authorization recheck, `NRestarts=0`, and
systemd result `success`. The revoked credential then received HTTP 401.

Cleanup removed only the two disposable F03 agents and gateways, the managed
runtime, reporter service, test namespace/interfaces, and scratch secrets.
`/dev/net/tun`, `releaseverify`, the control-plane stack, and unrelated gateway
and agent resources were preserved. See the redacted files in
`walk-artifacts/F03/20260815T074024Z/`. That run required a manual service start
after approval, so it is not the canonical approval-gate satisfaction.

The follow-up run in `walk-artifacts/F03/20260815T081148Z/` closed that behavior
gap: with approval enabled, the pending agent kept the same running MainPID,
zero restarts, revision 0, and no interface; owner approval returned 204; that
same process applied revision 1 and the real reporter/runtime peers handshaked.
The control plane reported desired/attempted/applied `1/1/1`, connected,
`gateway_reporting=true`, `online=true`, and a fresh handshake. Revoke then
clean-exited status 0, inactive/enabled with zero restarts and no interface,
and the credential returned 401. However, the shared F04 API/status source moved
after the deployed API build and the live status response omitted the newly
required `health` field. Because the deployed runtime hash also differs from
the preceding connected run, evidence composition is not used for completion.
A fresh signed build from a frozen shared source must repeat this bounded leg.

### Historical disposable companion run (2026-08-15)

This is **SUBSTITUTE** evidence, not **SATISFIES**: the run used the leased
Enterprise/Scale control plane and a privileged Linux runtime container, not a
real Linux host with systemd and committed walk artifacts.

- The historical pre-collision control plane reported `edition=enterprise`;
  migration schema 84 was clean and organization runtime opt-in was enabled
  only for that walk. The collision-safe schema-93 walk remains required.
- One bootstrap redemption created the managed device. Replaying the consumed
  token returned HTTP 401 and did not create another device.
- The runtime process polled, attempted revision 1, and reported the bounded
  `apply_failed` result. The container lacked the disposable WireGuard/nft
  capabilities needed for a successful apply; no raw runtime error or secret
  was recorded.
- Restarting the runtime process preserved the same server-reported revision
  facts. Runtime config, credential, and state files were `0600 root:root`.
- Canonical device revoke returned HTTP 204; disabling organization runtime
  synchronization returned HTTP 200. The runtime status endpoint then returned
  HTTP 403 `f04_runtime_opt_in_required`, and the runtime process exited
  fail-closed. The three file hashes remained unchanged after revoke/disable.
- Bootstrap/redeem scratch secrets were deleted after the walk. No raw token,
  runtime credential, private key, cookie, or full response was committed.

The run did **not** prove a real systemd unit start/restart, successful
WireGuard interface apply, committed `walk-artifacts/F03/<run-id>/` evidence,
tamper/wrong-architecture fixture refusal, or the full real-host overwrite
preservation walk. Those remain named gates for F03 completion.

- `go test ./db -run TestAgentBootstrap -count=1` — PASS, migration contract
  substitute.
- PostgreSQL 16 enterprise `TestManagedAgentBootstrap...` tests — PASS,
  non-skipped service/integration substitute; not a real Linux-host walk.
- `go test ./internal/http -run TestSessionlessRequestsAre401 -count=1` — PASS,
  authwalk substitute.
- `pnpm --filter @tunnex/web test -- test/agentview.test.ts` — 35/35 PASS,
  command-generation substitute.
- `pnpm --filter @tunnex/web typecheck` — PASS.

Later redacted live-wire artifacts are committed under `walk-artifacts/F03/`;
the final exact-source run must create a new run directory rather than alter
the historical evidence above.

## Executable disposable Linux/systemd harness — preparation only

This is the ready-to-run F03/F04 walk sheet. The disposable companion run
exercised the non-systemd runtime leg after the signed unit and service
identity contracts were stabilized, but the real Linux/systemd leg remains
required.

### 0. Preconditions and hard stop

The target is a disposable Linux VM (or a container with a real systemd,
`/dev/net/tun`, `CAP_NET_ADMIN`, and `wg-quick`). The control plane is a
uniquely named Docker Compose project with its own PostgreSQL 16, Redis,
volumes, organization, gateway, and enterprise license. The current repository
uses one API binary: enterprise is proven by the installed disposable license
and `/api/v1/meta`, not by `make up-enterprise`.

Preparation requires `docker compose`, `curl`, `jq`, `sha256sum`, `openssl`,
`go`, `systemctl`, `sudo`, `wg`, `wg-quick`, and `resolvconf` or `openresolv`.
Run from the repository root:

```bash
set -eu
command -v docker curl jq sha256sum openssl go systemctl sudo wg wg-quick lsof >/dev/null
command -v resolvconf >/dev/null || command -v openresolv >/dev/null
pnpm --filter @tunnex/web exec vitest run test/agentview.test.ts
sh deploy/runtime-release-contract_test.sh
```

Both acceptance reds must be absent before continuing. Until then, do not
start `tunnex-agent-runtime.service`, redeem a token, create a WireGuard
interface, publish a fixture, or mutate a non-disposable resource.

### 1. Allocate isolated names and redacted artifacts

```bash
set -eu
run_id="$(date -u +%Y%m%dT%H%M%SZ)"
project="f03-boxwalk-${run_id}"
artifact="walk-artifacts/F03/${run_id}"
scratch="$(mktemp -d "${TMPDIR:-/tmp}/tunnex-f03-${run_id}.XXXXXX")"
chmod 700 "$scratch"
mkdir -p "$artifact"
printf '%s\n' "$artifact" > "$artifact/location.txt"
printf '%s\n' "$project" > "$artifact/project-name.txt"
umask 077
```

Only redacted status, counts, modes, public fixture names, and public-file
hashes may be committed under `artifact`. Tokens, runtime credentials,
private keys, full bootstrap responses, cookies, config bodies, and raw logs
remain in `$scratch` and are deleted during cleanup.

### 2. Start the isolated enterprise control plane

Use a disposable `.env` or exported values; never reuse the repository's
normal project or volumes. The license-install step is an authenticated
operator action and is a prerequisite, not an inferred fixture fact.

The license must be supplied through `TUNNEX_LICENSE_FILE`. This is the only
accepted channel for the walk. It must be an absolute, regular, non-symlink
file outside the repository, owned by the current user, with mode `0600`:

```bash
set -eu
repo_root="$(pwd -P)"
license_file="${TUNNEX_LICENSE_FILE:?set TUNNEX_LICENSE_FILE to the disposable license file}"
case "$license_file" in
  /*) ;;
  *) echo 'TUNNEX_LICENSE_FILE must be absolute' >&2; exit 1 ;;
esac
case "$license_file" in
  "$repo_root"|"$repo_root"/*)
    echo 'TUNNEX_LICENSE_FILE must be outside the repository' >&2; exit 1 ;;
esac
[ -f "$license_file" ] && [ ! -L "$license_file" ] || {
  echo 'TUNNEX_LICENSE_FILE must be a regular non-symlink file' >&2; exit 1;
}
[ "$(stat -c '%u' "$license_file")" = "$(id -u)" ] || {
  echo 'TUNNEX_LICENSE_FILE must be owned by the current user' >&2; exit 1;
}
[ "$(stat -c '%a' "$license_file")" = 600 ] || {
  echo 'TUNNEX_LICENSE_FILE must have mode 0600' >&2; exit 1;
}
```

The launcher below must run in a child process with tracing disabled before
the file is opened. The license is never an argument, Compose YAML value, or
env-file value. It is read only into that process, used for the authenticated
install request, and unset before the process exits:

```bash
set -eu
set +x
export COMPOSE_PROJECT_NAME="$project"
export POSTGRES_DB="tunnex_${run_id}"
export POSTGRES_USER="tunnex_${run_id}"
export POSTGRES_PASSWORD="$(openssl rand -hex 24)"
export DATABASE_URL="postgres://${POSTGRES_USER}:${POSTGRES_PASSWORD}@postgres:5432/${POSTGRES_DB}?sslmode=disable"
export REDIS_URL="redis://redis:6379/0"
for port in "${HOST_HTTP_PORT:-}" "${HOST_API_MTLS_PORT:-}" "${HOST_WG_PORT:-}"; do
  [ -n "$port" ] || continue
  ! lsof -nP -iTCP:"$port" -sTCP:LISTEN >/dev/null 2>&1 || {
    echo "selected disposable host port is already listening: $port" >&2
    exit 1
  }
  ! lsof -nP -iUDP:"$port" >/dev/null 2>&1 || {
    echo "selected disposable host UDP port is already allocated: $port" >&2
    exit 1
  }
done
: "${HOST_HTTP_PORT:?set a unique disposable HOST_HTTP_PORT}"
: "${HOST_API_MTLS_PORT:?set a unique disposable HOST_API_MTLS_PORT}"
: "${HOST_WG_PORT:?set a unique disposable HOST_WG_PORT}"
[ "$HOST_WG_PORT" != 51820 ] || {
  echo 'HOST_WG_PORT must not be the normal 51820 port' >&2
  exit 1
}
docker compose -f docker-compose.yml -f docker-compose.dev.yml up -d --build --wait postgres redis api web nginx
docker compose -f docker-compose.yml -f docker-compose.dev.yml run --rm migrate up
cookie_file="$scratch/cookies.txt"
: > "$cookie_file"
chmod 600 "$cookie_file"
# Keep login, forced-password rotation, and license POST in one process so the
# cookie jar is not lost between steps. Secrets are body data only.
bootstrap_password="$(docker compose logs api 2>&1 | awk '$1 == "password" {print $2; exit}')"
[ "${#bootstrap_password}" -ge 16 ] || { echo 'bootstrap password was not found' >&2; exit 1; }
new_password="$(openssl rand -hex 24)"
printf '%s' "{\"email\":\"admin@tunnex.local\",\"password\":\"$bootstrap_password\"}" |
  curl -fsS -c "$cookie_file" -H 'content-type: application/json' --data-binary @- \
    "http://127.0.0.1:${HOST_HTTP_PORT}/api/v1/auth/login" >/dev/null
printf '%s' "{\"current_password\":\"$bootstrap_password\",\"new_password\":\"$new_password\"}" |
  curl -fsS -b "$cookie_file" -c "$cookie_file" -H 'X-Tunnex-CSRF: disposable' \
    -H 'content-type: application/json' --data-binary @- \
    "http://127.0.0.1:${HOST_HTTP_PORT}/api/v1/auth/password" >/dev/null
printf '%s' "{\"email\":\"admin@tunnex.local\",\"password\":\"$new_password\"}" |
  curl -fsS -c "$cookie_file" -H 'content-type: application/json' --data-binary @- \
    "http://127.0.0.1:${HOST_HTTP_PORT}/api/v1/auth/login" >/dev/null
chmod 600 "$cookie_file"
unset bootstrap_password new_password
curl -fsS -b "$cookie_file" "http://127.0.0.1:${HOST_HTTP_PORT}/api/v1/auth/me" >/dev/null
IFS= read -r TUNNEX_LICENSE < "$license_file" || true
# POST the license from a body assembled in memory. Do not put the license in
# curl arguments or output.
printf '%s' "{\"key\":\"$TUNNEX_LICENSE\"}" |
  curl -fsS -b "$scratch/cookies.txt" -H 'content-type: application/json' --data-binary @- \
    "http://127.0.0.1:${HOST_HTTP_PORT}/api/v1/license" > "$scratch/license-response.json"
unset TUNNEX_LICENSE
unset TUNNEX_LICENSE_FILE
curl -fsS "http://127.0.0.1:${HOST_HTTP_PORT}/api/v1/meta" > "$scratch/meta.json"
jq -e '.edition == "enterprise"' "$scratch/meta.json" >/dev/null
docker compose -f docker-compose.yml -f docker-compose.dev.yml run --rm migrate version > "$artifact/migration-version.txt"
```

Create one disposable organization, one active gateway, and one authorized
operator. Record only `kid`, license id, domain, band, expiry, pseudonyms, and
the migration version in the artifact. Never copy the license response, cookie,
or raw license into an artifact.

Cleanup is two-phase. First complete and verify Compose/VM cleanup and confirm
no process, log, artifact, or repository path contains the sentinel or license.
Only when that cleanup succeeds may the operator delete a user-designated
temporary license file:

```bash
cleanup_ok=0
cleanup() {
  rc=$?
  docker compose -p "$project" -f docker-compose.yml -f docker-compose.dev.yml \
    down -v --remove-orphans
  rm -rf "$scratch"
  if [ "$rc" -eq 0 ] \
    && ! docker ps -a --filter "name=$project" --format '{{.Names}}' | grep -q . \
    && ! docker network ls --filter "name=$project" --format '{{.Name}}' | grep -q . \
    && ! docker volume ls --filter "name=$project" --format '{{.Name}}' | grep -q .; then
    if [ "${TUNNEX_LICENSE_FILE_DELETE_AFTER_CLEANUP:-}" = yes ]; then
      rm -f -- "$license_file"
    fi
    cleanup_ok=1
  fi
  if [ "$cleanup_ok" -ne 1 ]; then
    exit 1
  fi
  exit "$rc"
}
trap cleanup EXIT
```

The ready-to-run enterprise invocation is:

```bash
TUNNEX_LICENSE_FILE=/private/tmp/tunnex-enterprise.lic \
TUNNEX_LICENSE_FILE_DELETE_AFTER_CLEANUP=yes \
HOST_HTTP_PORT="${F3_HTTP_PORT:?set a unique F3_HTTP_PORT}" \
HOST_API_MTLS_PORT="${F3_API_MTLS_PORT:?set a unique F3_API_MTLS_PORT}" \
HOST_WG_PORT="${F3_WG_PORT:?set a unique F3_WG_PORT}" \
  bash /path/to/the-copied-boxwalk-launcher.sh

The command above is an invocation template: copy the executable shell blocks
below into a disposable launcher before running them; this Markdown file is the
runbook, not itself an executable script.
```

The final line is a parameter reminder, not a literal shell command; the
operator must run the launcher copied from this section so the license remains
stdin/file-read-only and never enters shell history.

### 2a. Fake-sentinel channel proof

Before using a real license, create a disposable sentinel file outside the
repository and run the launcher with a fake Compose/API stub. The proof must
fail if the sentinel appears in process arguments, Compose config, logs, the
artifact directory, or tracked repository files:

```bash
set -eu
sentinel_file="$(mktemp /private/tmp/tunnex-sentinel.XXXXXX)"
chmod 600 "$sentinel_file"
sentinel="F03_SENTINEL_$(date +%s)_$$"
export sentinel
printf '%s\n' "$sentinel" > "$sentinel_file"
TUNNEX_LICENSE_FILE="$sentinel_file" TUNNEX_LICENSE_FILE_DELETE_AFTER_CLEANUP=yes \
  env -u TUNNEX_LICENSE bash -c '
    set +x
    license_file="$TUNNEX_LICENSE_FILE"
    IFS= read -r TUNNEX_LICENSE < "$license_file"
    export TUNNEX_LICENSE
    unset TUNNEX_LICENSE_FILE
    test "$TUNNEX_LICENSE" = "$sentinel"
    unset TUNNEX_LICENSE
  '
! pgrep -af "$sentinel" >/dev/null
! docker compose -p "$project" config 2>/dev/null | grep -F "$sentinel"
! docker compose -p "$project" logs 2>/dev/null | grep -F "$sentinel"
! grep -R -F "$sentinel" "$artifact" "$repo_root" 2>/dev/null
rm -f -- "$sentinel_file"
```

The sentinel proof is a SUBSTITUTE for the secret channel only; it does not
make the enterprise wire walk SATISFIES. A failed assertion is a hard stop.

### 3. Create and verify a local signed tag/SHA release fixture

The fixture must match production: a full 40-character `source_sha`, release
version, both OCI architecture digests, both runtime binary assets, and the
F02 signed unit asset with exact name, SHA-256, and source-SHA. The runtime
assets are built locally; the native one is used by the VM.

```bash
set -eu
fixture_tag="tunnex-build-f03-${run_id}"
fixture_sha="$(git rev-parse HEAD)"
fixture_version="sha-$(printf '%s' "$fixture_sha" | cut -c1-7)"
mkdir -p "$scratch/release/$fixture_tag"
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -buildvcs=false \
  -ldflags="-s -w -X main.version=${fixture_version}" \
  -o "$scratch/release/$fixture_tag/tunnex-agent-runtime-linux-amd64" \
  ./apps/cli/cmd/tunnex-agent-runtime
CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -trimpath -buildvcs=false \
  -ldflags="-s -w -X main.version=${fixture_version}" \
  -o "$scratch/release/$fixture_tag/tunnex-agent-runtime-linux-arm64" \
  ./apps/cli/cmd/tunnex-agent-runtime
cp deploy/systemd/tunnex-agent-runtime.service "$scratch/release/$fixture_tag/tunnex-agent-runtime.service"
sha256sum "$scratch/release/$fixture_tag"/* > "$scratch/asset-sha256sums"
```

Generate an ephemeral Ed25519 keypair and construct the signed descriptor with
the exact `managed_agent_runtime` schema. The `unit` object below is the
pending F02 contract and is deliberately part of the stop gate:

```bash
cat > "$scratch/keygen.go" <<'EOF'
package main
import("crypto/ed25519";"crypto/rand";"encoding/hex";"fmt")
func main(){pub,priv,err:=ed25519.GenerateKey(rand.Reader);if err!=nil{panic(err)};fmt.Printf("private=%s\npublic=%s\n",hex.EncodeToString(priv),hex.EncodeToString(pub))}
EOF
go run "$scratch/keygen.go" > "$scratch/key.txt"
signing_key="$(sed -n 's/^private=//p' "$scratch/key.txt")"
fixture_public_key="$(sed -n 's/^public=//p' "$scratch/key.txt")"
runtime_amd64_sha="$(sha256sum "$scratch/release/$fixture_tag/tunnex-agent-runtime-linux-amd64" | awk '{print $1}')"
runtime_arm64_sha="$(sha256sum "$scratch/release/$fixture_tag/tunnex-agent-runtime-linux-arm64" | awk '{print $1}')"
unit_sha="$(sha256sum "$scratch/release/$fixture_tag/tunnex-agent-runtime.service" | awk '{print $1}')"
jq -n --arg source_sha "$fixture_sha" --arg version "$fixture_version" \
  --arg amd64 "$runtime_amd64_sha" --arg arm64 "$runtime_arm64_sha" --arg unit "$unit_sha" \
  '{schema_version:1,sequence:1,version:$version,source_sha:$source_sha,
    published_at:"2026-01-01T00:00:00Z",min_protocol:1,compatibility:"open+enterprise",
    downtime:"brief",release_notes_url:"https://example.invalid/f03",
    images:{api:{linux_amd64_digest:("sha256:" + ("a"*64)),linux_arm64_digest:("sha256:" + ("b"*64))},
      web:{linux_amd64_digest:("sha256:" + ("a"*64)),linux_arm64_digest:("sha256:" + ("b"*64))},
      nginx:{linux_amd64_digest:("sha256:" + ("a"*64)),linux_arm64_digest:("sha256:" + ("b"*64))},
      "node-agent":{linux_amd64_digest:("sha256:" + ("a"*64)),linux_arm64_digest:("sha256:" + ("b"*64))},
      migrate:{linux_amd64_digest:("sha256:" + ("a"*64)),linux_arm64_digest:("sha256:" + ("b"*64))}},
    managed_agent_runtime:{binary:"tunnex-agent-runtime",version:$version,
      linux_amd64:{name:"tunnex-agent-runtime-linux-amd64",sha256:$amd64,source_sha:$source_sha},
      linux_arm64:{name:"tunnex-agent-runtime-linux-arm64",sha256:$arm64,source_sha:$source_sha},
      unit:{name:"tunnex-agent-runtime.service",sha256:$unit,source_sha:$source_sha}}}' \
  > "$scratch/release/$fixture_tag/release-unsigned.json"
(cd apps/api && GOFLAGS=-mod=readonly go run ./cmd/releasesign \
  -manifest "$scratch/release/$fixture_tag/release-unsigned.json" \
  -private-key "$signing_key" -kid "f03-boxwalk" \
  -output "$scratch/release/$fixture_tag/release.json")
```

Verify the signed descriptor for both platforms:

```bash
(cd apps/api && GOFLAGS=-mod=readonly go run ./cmd/releaseverify \
  -manifest "$scratch/release/$fixture_tag/release.json" \
  -public-key "$fixture_public_key" -expected-source-sha "$fixture_sha" \
  -platform amd64 -print-env) > "$scratch/amd64.env"
(cd apps/api && GOFLAGS=-mod=readonly go run ./cmd/releaseverify \
  -manifest "$scratch/release/$fixture_tag/release.json" \
  -public-key "$fixture_public_key" -expected-source-sha "$fixture_sha" \
  -platform arm64 -print-env) > "$scratch/arm64.env"
grep -Fq 'TUNNEX_AGENT_RUNTIME_BINARY=tunnex-agent-runtime' "$scratch/amd64.env"
grep -Fq 'TUNNEX_AGENT_RUNTIME_AMD64_NAME=tunnex-agent-runtime-linux-amd64' "$scratch/amd64.env"
grep -Fq 'TUNNEX_AGENT_RUNTIME_ARM64_NAME=tunnex-agent-runtime-linux-arm64' "$scratch/arm64.env"
grep -Fq 'TUNNEX_AGENT_RUNTIME_UNIT_NAME=tunnex-agent-runtime.service' "$scratch/amd64.env"
```

The current installer hardcodes GitHub release URLs. For a local-only fixture,
use a scratch `curl` shim that maps only the exact immutable
`/releases/download/$fixture_tag/<asset>` paths to `$scratch/release`; delegate
the CP URL to the real disposable CP. This shim is transport test plumbing,
not release provenance. Do not publish the fixture or alter DNS during
preparation.

### 4. Issue and redeem once

From the released Agents route, issue a managed command for the disposable
gateway. Before running it, assert that all managed targets and `runtime` are
absent:

```bash
set -eu
for p in /usr/local/bin/tunnex-agent-runtime /etc/systemd/system/tunnex-agent-runtime.service \
  /etc/wireguard/runtime.conf /etc/tunnex-agent/runtime-credential \
  /var/lib/tunnex-agent/runtime-state.json; do test ! -e "$p"; done
! sudo wg show runtime >/dev/null 2>&1
```

After the two-red gate is green, run the displayed command. Verify the request
contains only the client-generated public key, and inspect only redacted
status/shape. Verify ownership and modes without reading contents:

```bash
stat -c '%U:%G %a %n' /etc/wireguard/runtime.conf \
  /etc/tunnex-agent/runtime-credential \
  /var/lib/tunnex-agent/runtime-state.json
systemctl cat tunnex-agent-runtime.service | grep -F 'NoNewPrivileges=false'
systemctl show tunnex-agent-runtime.service \
  -p ProtectSystem -p CapabilityBoundingSet -p AmbientCapabilities \
  -p ReadWritePaths -p DeviceAllow -p RestrictAddressFamilies
```

The runtime state JSON must contain no credential, token, `PrivateKey`, or
private-key material. Record in `bootstrap-redeem-redacted.txt` and
`secret-file-modes.txt` only statuses, modes, owner/group, and public hashes.

### 5. Start/restart and prove poll/apply/report persistence

```bash
set -eu
systemctl start tunnex-agent-runtime.service
systemctl is-active --quiet tunnex-agent-runtime.service
sleep 2
systemctl restart tunnex-agent-runtime.service
systemctl is-active --quiet tunnex-agent-runtime.service
```

Verify one authenticated poll, one applied revision, and one bounded report in
the disposable CP logs/metrics. Query the authorized roster and record exactly
one device. Restart only the disposable API container, without changing
PostgreSQL, then repeat service-active, applied-revision, poll, and roster
count checks. Record redacted results in `restart-persistence.txt`.

### 6. Replay, tamper, and overwrite refusal

Redeem the consumed token again with a fresh client-generated public key. It
must receive the same generic invalid-token response as wrong/expired input,
create no second device, and leave the original files/interface unchanged.
Record only the status/error class in `replay-refused.txt`.

In `$scratch`, run separate fail-closed cases for: modified signed manifest,
bad signature, missing unit, wrong unit name, wrong unit digest, wrong unit
source-SHA, unsupported architecture, and modified runtime bytes. Each must
fail before token redemption, key generation, file write, service mutation, or
interface change. Record pre/post public hashes and service state only in
`tamper-refused.txt`.

For overwrite refusal, create sentinel files and a known service state in the
disposable VM, run bootstrap, and compare `sha256sum`, `stat`, and systemd
state before/after. It must report an explicit existing-installation refusal
before download, redemption, key generation, cleanup, or mutation. Record only
the redacted comparison in `overwrite-refused.txt`.

### 7. Revoke and fail-closed offboarding

Revoke through the authorized Agents route. The next runtime poll must be
unauthorized, the service must disable the interface and exit cleanly inactive,
and the old credential must not poll again. The unit may remain enabled so a
boot rechecks authorization; explicit cleanup disables it. A real `wg-quick`
permission/command failure must remain nonzero; only a proven absent interface
is idempotent. Verify the peer is gone and record redacted status/interface
facts in `revoke-offboarding.txt`.

### 8. Cleanup and mandatory stop conditions

Cleanup is scoped only to the disposable VM and compose project:

```bash
set -eu
systemctl disable --now tunnex-agent-runtime.service || true
sudo systemctl disable --now tunnex-agent-runtime.service || true
sudo rm -f /usr/local/bin/tunnex-agent-runtime /etc/systemd/system/tunnex-agent-runtime.service \
  /etc/wireguard/runtime.conf /etc/tunnex-agent/runtime-credential \
  /var/lib/tunnex-agent/runtime-state.json
docker compose -p "$project" -f docker-compose.yml -f docker-compose.dev.yml down -v --remove-orphans
rm -rf "$scratch"
printf 'disposable project stopped; VM files removed\n' > "$artifact/cleanup.txt"
```

Stop and preserve evidence if enterprise edition or the current migration 0093 cannot be
verified; either acceptance red remains; any target already exists; a
signature/digest/tamper case succeeds; replay creates a second device;
restart loses consumption or revision; any secret appears in a request, log,
state file, DOM, or artifact; revoke leaves a usable peer; or cleanup would
touch anything outside the disposable VM/project. Real systemd artifacts are
committed under `walk-artifacts/F03/`; final satisfaction still requires the
new exact-source run identified in this document's status header.
