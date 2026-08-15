# F01 boxwalk draft

Status: Evidence captured; root review and current-head full-gate disposition pending. Unit and static tests below are **SUBSTITUTES**, never SATISFIES. Do not mark F01 complete from this file.

## Preconditions

1. Use a disposable PostgreSQL database with migrations through 0088 applied and an enterprise build where the agent endpoints are available.
2. Set `TUNNEX_TEST_DATABASE_URL` only in the shell running the tests. Do not commit the value or any session credentials.
3. Create a test organization with an owner/admin, an unrelated plain member, and an agent owner. Record IDs in `walk-artifacts/F01/<run-id>/identifiers.txt`; redact emails/tokens in committed evidence.
4. Keep scratch credentials/configs in the ignored walk-artifacts path. Never commit private keys or bootstrap secrets.

## Exact live-wire steps and evidence paths

```bash
run_id="$(date -u +%Y%m%dT%H%M%SZ)"
artifact="walk-artifacts/F01/$run_id"
mkdir -p "$artifact"
printf '%s\n' "$artifact" > "$artifact/location.txt"
```

1. **Migration/backfill:** apply 0088 to a fixture containing existing active, pending, revoked agent devices, a human device, and telemetry rows. Capture SQL results showing one profile per non-deleted agent, unchanged `devices.user_id/status`, and unchanged `device_status` in `"$artifact/migration-backfill.txt"`.
2. **DB boundary:** attempt `UPDATE devices SET status='suspended'` on a human device; record the rejected statement and unchanged row in `"$artifact/human-suspended-rejected.txt"`.
3. **Permission-before-data:** as the unrelated member, call profile GET and PATCH. Capture HTTP status/body in `"$artifact/member-forbidden.txt"`; confirm no owner email, telemetry, labels, or environment appears.
4. **Owner metadata:** as the agent owner, PATCH environment/runtime/labels without status. Capture request/response and a follow-up GET in `"$artifact/owner-metadata-refetch.txt"`. Confirm status and telemetry are unchanged.
5. **Lifecycle authority:** as owner, attempt suspend and resume; capture 403s in `"$artifact/owner-lifecycle-forbidden.txt"`. As admin/member-manager, suspend then resume and capture both responses plus GETs in `"$artifact/admin-suspend-resume.txt"`.
6. **Approval/terminal:** set up pending and revoked agents through their canonical flows. Attempt profile activation and suspended transitions; capture refusal and unchanged metadata in `"$artifact/pending-revoked-terminal.txt"`.
7. **Atomicity:** send metadata plus an illegal lifecycle intent in one PATCH. Capture the refusal and a fresh GET proving metadata did not change in `"$artifact/atomic-no-partial-mutation.txt"`.
8. **Data plane:** after suspend, query/inspect the effective peer/config compilation and capture absence in `"$artifact/suspended-absent-peer.txt"`; resume and capture restoration in `"$artifact/resumed-peer.txt"`.
9. **Rollback:** on a disposable clone, prove down succeeds for only default profiles and no suspended rows; separately prove it refuses suspended rows and non-default metadata without deleting rows. Capture both outcomes in `"$artifact/rollback-guards.txt"`.
10. **Released web route and list privacy:** authenticate as a plain member and load `/agents`. Capture the actual `GET /api/v1/organizations/{orgId}/agents` response in `"$artifact/member-agents-list.json"` and the rendered DOM in `"$artifact/member-agents-dom.html"`; verify the basic organization roster status/liveness/traffic remains visible, while `owner_email`, `Authorised by`, owner email, privileged profile/runtime telemetry, profile metadata, and lifecycle controls are absent. Repeat as the agent owner and as an admin/member-manager, capturing `"$artifact/owner-agents-list.json"` and `"$artifact/admin-agents-list.json"`; verify owner email is present only for those authorized views. This was executed on the isolated authenticated route; the redacted evidence artifact is listed below. Unit/route tests remain SUBSTITUTES, never SATISFIES.
11. **Profile permission and org switch:** as the unrelated member, expand an agent row and capture the profile GET response plus DOM in `"$artifact/member-profile-403.txt"` and `"$artifact/member-profile-dom.html"`; verify no owner, privileged profile/runtime telemetry, metadata, or lifecycle facts render. Switch from org A to org B while the requests are in flight, capture both list responses and DOM snapshots in `"$artifact/org-switch-before.html"` and `"$artifact/org-switch-after.html"`, and verify no org A roster, profile, or runtime fact remains after org B is selected. The current route clears gateways, selected gateway, edition state, rows, profiles, runtime status, and role immediately on org change; this was confirmed in the isolated authenticated route walk.

## Current substitute evidence

The following disposable PostgreSQL 16 results are **SUBSTITUTES** for the production boxwalk, while satisfying the requested database-wire test proof:

```bash
docker run -d --rm --name tunnex-f01-proof-47905 \
  -e POSTGRES_USER=f01 -e POSTGRES_PASSWORD=f01 -e POSTGRES_DB=f01 \
  -p 127.0.0.1::5432 postgres:16-alpine

# Inside a temporary Go 1.25 container sharing only the PostgreSQL network namespace:
DATABASE_URL=postgres://f01:f01@127.0.0.1:5432/f01?sslmode=disable go run ./cmd/migrate up
TUNNEX_TEST_DATABASE_URL=postgres://f01:f01@127.0.0.1:5432/f01?sslmode=disable \
  go test -v ./db -run 'TestAgentProfileMigrationContract|TestAgentProfile' -count=1
TUNNEX_TEST_DATABASE_URL=postgres://f01:f01@127.0.0.1:5432/f01?sslmode=disable \
  go test -v ./internal/devices -run 'TestAgentLifecycleTransition|TestSuspendedAgentIsAbsentFromPeersAndAtomicProfileFailure' -count=1
TUNNEX_TEST_DATABASE_URL=postgres://f01:f01@127.0.0.1:5432/f01?sslmode=disable \
  go test -v ./internal/http -run 'TestAgentProfile' -count=1
```

Observed in the PostgreSQL/unit substitute: migration 82 clean; default and enterprise focused suites PASS without skips; backfill preserved owner/status/telemetry; active→suspended removed the effective peer and resume restored it; metadata and suspended rollback refusals preserved rows and values. Current 0088 live rollback evidence is recorded at `walk-artifacts/F01/20260815T081827Z/rollback-0088-current.txt`; the connected-agent data-plane live proof is recorded at `walk-artifacts/F01/20260815T-final/runtime-live-final.md`.

- `go test ./db -run TestAgentProfileMigrationContract -count=1` — PASS (static migration contract substitute).
- `TUNNEX_TEST_DATABASE_URL="$F02_PRIVACY_DSN" go test -v ./internal/devices -run 'TestAgentLifecycleTransition|TestSuspendedAgentIsAbsentFromPeersAndAtomicProfileFailure' -count=1` — PASS, non-skipped in F02's isolated PostgreSQL database.
- `TUNNEX_TEST_DATABASE_URL="$F02_PRIVACY_DSN" go test -v ./internal/http -run '^TestAgentProfileHandlersAuthorizationAndAtomicity$' -count=1` — PASS, non-skipped; proves ListAgents owner-email absence/presence, profile authorization, metadata persistence, lifecycle authorization, terminal semantics, and no partial mutation.
- `TUNNEX_TEST_DATABASE_URL="$F02_PRIVACY_DSN" go test -tags enterprise -v ./internal/http -run '^TestAgentProfileHandlersAuthorizationAndAtomicity$' -count=1` — PASS, non-skipped.
- `pnpm --filter @tunnex/web exec vitest run test/agentprofileeditor.test.tsx` — PASS (isolated editor substitute; the released route now mounts this component, but this test does not exercise the authenticated route).
- `pnpm --filter @tunnex/web exec vitest run test/agentprofileabsence.test.tsx` — PASS (released-route DOM absence substitute; it proves the current route does not mount profile metadata/lifecycle controls).
- `pnpm --filter @tunnex/web typecheck` — PASS.
- `pnpm --filter @tunnex/web exec vitest run test/agentsruntimewiring.test.tsx` — PASS, 21 tests; SUBSTITUTE for authenticated browser evidence. It pins organization-viewable roster status/liveness/traffic alongside member absence of owner attribution and privileged profile/runtime/lifecycle facts, plus metadata/lifecycle refetch and runtime org-switch clearing, but does not SATISFY the live-wire walk.

Live affected-path evidence is captured in `walk-artifacts/F01/20260814T172001Z/browser-walk-privacy-org-switch.md`: owner and manager list payloads contain redacted `owner_email` fields, the plain-member payload omits the key entirely, member DOM controls are absent, and the live org-switch snapshot has no old gateway option while target requests are in flight. This is the current route evidence; the earlier `20260814T164824Z/browser-walk.md` is superseded.

## Remaining live gate: connected-agent data-plane harness

This is the exact disposable harness for the approved F04 managed runtime. It is preparation, not evidence that the walk has run. It uses only the isolated `f01-browser` project and a runtime container attached to that project's private network. Do not use the existing stack or an internal/live control plane.

### Preconditions and hard stops

- Docker/Colima is running; `docker version` works and `/dev/net/tun` exists on the host. If either is false, record `BLOCKED` in `"$artifact/data-plane-blocked.txt"` and stop; do not substitute component tests.
- Use `TUNNEX_WG_BACKEND=wgctrl`, not `mem`, for this walk. The gateway container must expose `wg show`; a memory backend cannot satisfy peer/config absence.
- Use a verified owner session to issue the one-time bootstrap token. Keep the cookie, token, private key, runtime credential, config, and state only under ignored `"$artifact/scratch/"`; never commit them.
- Build the runtime from `deploy/docker/agent-runtime.Dockerfile`; do not hand-write a replacement runtime or bypass its poll/report loop.

### Setup and redacted artifact layout

```bash
set -euo pipefail
umask 077
run_id="$(date -u +%Y%m%dT%H%M%SZ)"
artifact="walk-artifacts/F01/$run_id"
mkdir -p "$artifact/scratch/runtime" "$artifact/scratch/state"
printf 'scratch/\n' > "$artifact/.gitignore"
printf '%s\n' "$artifact" > "$artifact/location.txt"
test -e /dev/net/tun
docker version >/dev/null

export COMPOSE_PROJECT_NAME=f01-browser
export POSTGRES_USER=f01 POSTGRES_PASSWORD=f01_browser_pw POSTGRES_DB=f01
export DATABASE_URL='postgres://f01:f01_browser_pw@postgres:5432/f01?sslmode=disable'
export REDIS_URL='redis://redis:6379/0'
export HOST_HTTP_PORT=18081 HOST_API_MTLS_PORT=18444 HOST_WG_PORT=51881
export TUNNEX_WG_BACKEND=wgctrl
docker compose -f docker-compose.yml -f docker-compose.dev.yml up -d --build --wait
docker compose ps > "$artifact/compose-status.txt"
gateway_container="$(docker compose ps -q node-agent)"
test -n "$gateway_container"
docker exec "$gateway_container" wg show > "$artifact/peer-before.txt"
docker build -f deploy/docker/agent-runtime.Dockerfile -t f01-browser-agent-runtime:walk . > "$artifact/runtime-build.txt"
```

### Issue, redeem, and start one connected runtime

```bash
owner_cookie="$artifact/scratch/owner.cookie"
curl -fsS -c "$owner_cookie" -H 'Content-Type: application/json' \
  -d '{"email":"owner@demo.tunnex.local","password":"tunnex-demo-password"}' \
  http://127.0.0.1:18081/api/v1/auth/login > "$artifact/scratch/owner-login.json"
org_id=01900000-0000-7000-8000-000000000001
gateway_id="$(curl -fsS -b "$owner_cookie" \
  "http://127.0.0.1:18081/api/v1/organizations/$org_id/nodes" |
  jq -r 'map(select(.status == "active" and (.endpoint // "") != ""))[0].id')"
test "$gateway_id" != null

bootstrap_json="$artifact/scratch/bootstrap.json"
curl -fsS -b "$owner_cookie" -H 'Content-Type: application/json' \
  -d "{\"name\":\"f01-connected-agent\",\"gateway_id\":\"$gateway_id\"}" \
  "http://127.0.0.1:18081/api/v1/organizations/$org_id/agents/bootstrap-token" > "$bootstrap_json"
bootstrap_token="$(jq -er .bootstrap_token "$bootstrap_json")"

agent_private="$(docker run --rm --entrypoint sh f01-browser-agent-runtime:walk -c 'wg genkey')"
agent_public="$(printf '%s\n' "$agent_private" | docker run --rm -i --entrypoint sh f01-browser-agent-runtime:walk -c 'wg pubkey')"
curl -fsS -H 'Content-Type: application/json' \
  -d "{\"bootstrap_token\":\"$bootstrap_token\",\"public_key\":\"$agent_public\"}" \
  http://127.0.0.1:18081/api/v1/agent/bootstrap > "$artifact/scratch/bootstrap-response.json"
runtime_credential="$(jq -er .runtime_credential "$artifact/scratch/bootstrap-response.json")"
jq -er .config "$artifact/scratch/bootstrap-response.json" |
  sed "s/__TUNNEX_PRIVATE_KEY__/$agent_private/" > "$artifact/scratch/runtime/runtime.conf"
jq -n --arg server 'http://api:8080' --arg credential "$runtime_credential" \
  '{server:$server,credential:$credential,applied_revision:0,client_version:"f01-walk"}' \
  > "$artifact/scratch/state/runtime-state.json"

docker run -d --name f01-browser-agent-runtime --network f01-browser_default \
  --cap-add NET_ADMIN --device /dev/net/tun \
  --user "$(id -u):$(id -g)" \
  -v "$PWD/$artifact/scratch/runtime:/etc/tunnex-agent" \
  -v "$PWD/$artifact/scratch/state:/var/lib/tunnex-agent" \
  f01-browser-agent-runtime:walk
```

The runtime is connected only when all of these are true: its logs show a successful poll/apply/report cycle; `docker exec "$gateway_container" wg show` contains the redacted public-key fingerprint; and the API runtime-status response shows the applied revision. Record only counts, revisions, status codes, and a hash/fingerprint—not the token, private key, config, or full response—in `"$artifact/runtime-connected.txt"`.

### Suspend → peer/config absence → resume restoration

Use the existing administrative/member-management session for lifecycle changes. The owner session above must not be used for suspend/resume. Capture redacted HTTP status and fresh GET/runtime-status bodies:

```bash
manager_cookie="$artifact/scratch/manager.cookie"
# Supply a verified member-management fixture account approved by the current seed workflow.
# If no verified manager exists, stop and record BLOCKED; do not use an unverified admin as proof.
curl -fsS -c "$manager_cookie" -H 'Content-Type: application/json' \
  -d '{"email":"<verified-member-manager>","password":"tunnex-demo-password"}' \
  http://127.0.0.1:18081/api/v1/auth/login > "$artifact/scratch/manager-login.json"

device_id="$(jq -er '.device.id' "$artifact/scratch/bootstrap-response.json")"
curl -fsS -b "$manager_cookie" -X PATCH -H 'Content-Type: application/json' \
  -d '{"status":"suspended"}' \
  "http://127.0.0.1:18081/api/v1/organizations/$org_id/agents/$device_id" > "$artifact/scratch/suspend.json"
docker exec "$gateway_container" wg show > "$artifact/peer-suspended.txt"
curl -fsS -b "$owner_cookie" \
  "http://127.0.0.1:18081/api/v1/organizations/$org_id/agents/$device_id/runtime-status" \
  > "$artifact/suspended-runtime-status.json"

# Required assertions, written as redacted facts in suspended-absent-peer.txt:
# 1. device status is suspended;
# 2. the agent public-key fingerprint is absent from wg show / effective peer compilation;
# 3. runtime poll is refused uniformly and no new config is returned;
# 4. the suspended row is not deleted and its profile metadata is unchanged.

curl -fsS -b "$manager_cookie" -X PATCH -H 'Content-Type: application/json' \
  -d '{"status":"active"}' \
  "http://127.0.0.1:18081/api/v1/organizations/$org_id/agents/$device_id" > "$artifact/scratch/resume.json"
sleep 2
docker exec "$gateway_container" wg show > "$artifact/peer-resumed.txt"
curl -fsS -b "$owner_cookie" \
  "http://127.0.0.1:18081/api/v1/organizations/$org_id/agents/$device_id/runtime-status" \
  > "$artifact/resumed-runtime-status.json"
# Required assertions in resumed-peer.txt: status active, the same public-key
# fingerprint is present again, and the applied revision/config is restored.
```

If the API returns a lifecycle refusal, the runtime stays connected, or the peer/config state cannot be observed from the real gateway backend, record the exact redacted status/log boundary and mark the live gate `BLOCKED`; do not reinterpret a unit/PG result as satisfaction.

### Disposable rollback walk

Use a separate project and volume names. Never roll back the retained `f01-browser` database or any existing stack:

```bash
export COMPOSE_PROJECT_NAME=f01-rollback
export POSTGRES_USER=f01rb POSTGRES_PASSWORD=f01rb_pw POSTGRES_DB=f01rb
export DATABASE_URL='postgres://f01rb:f01rb_pw@postgres:5432/f01rb?sslmode=disable'
docker compose -f docker-compose.yml -f docker-compose.dev.yml up -d --wait postgres
docker compose run --rm --build migrate up > "$artifact/rollback-up.txt"

# Default/empty profile case: seed one agent, ensure its profile is default/empty,
# ensure there are no suspended rows, then run down repeatedly through 0088.
for step in 1 2 3 4; do docker compose run --rm --build migrate down >> "$artifact/rollback-default.txt"; done
# Required result: 0088 down exits 0, agent_profiles is removed, device row/value remains.

# Refusal cases use a fresh f01-rollback-nondefault project/database each time.
# Apply migrations, insert non-default profile metadata, then run the same four
# down commands. Capture exit 1 and SQL snapshots before/after in rollback-nondefault.txt.
# Repeat with one active agent changed to suspended; capture exit 1 and unchanged
# profile/device rows in rollback-suspended.txt.

docker compose down
docker volume ls --filter name=f01-rollback
```

The rollback walk is satisfied only when the default case reaches the pre-0088 schema and both refusal cases preserve every row/value. Current collision-safe 0088 evidence is `walk-artifacts/F01/20260815T081827Z/rollback-0088-current.txt`; the earlier 0079 artifact is historical only. Cleanup commands for the connected run are `docker rm -f f01-browser-agent-runtime` followed by `COMPOSE_PROJECT_NAME=f01-browser docker compose -f docker-compose.yml -f docker-compose.dev.yml down` (retain the named `f01-browser` volumes). Cleanup must remove only the disposable rollback project/volumes after the artifacts are redacted; retain no cookie, token, private key, runtime credential, or raw config.

## Current gate status

Authenticated UI/list wire evidence is live-satisfied by the named browser artifacts, and current 0088 rollback is live-satisfied by `walk-artifacts/F01/20260815T081827Z/rollback-0088-current.txt`. PostgreSQL/unit lifecycle and data-plane tests remain **SUBSTITUTES**. The connected-agent suspend→peer/config absence→resume restoration is now **LIVE-SATISFIED**; redacted evidence is `walk-artifacts/F01/20260815T-final/runtime-live-final.md`. F01 is a candidate for root story review; this document does not change plan status.

## Current audit note (held)

The current route clears `gateways`, selected gateway, `notEntitled`, `rows`, `profiles`, `runtimeStatus`, and role immediately on organization change (`apps/web/src/pages/Agents.tsx`). The affected-path walk confirmed no stale old-org gateway/options/facts during the in-flight request. Earlier `walk-artifacts/F01/20260814T164824Z/browser-walk.md` is superseded. F01 remains In Progress pending independent review; no named live gate remains open in this ledger.

### 2026-08-15 runtime harness diagnosis

The first F01 connected-agent reruns used `/private/tmp/...` bind mounts. On the
Colima Docker VM those mounts appeared as empty directories inside the container,
so the runtime exited at startup with the bounded stderr:
`open /var/lib/tunnex-agent/runtime-state.json: no such file or directory`.
This was a harness/platform-path defect, not a runtime image or API defect.

Measured image evidence: `tunnex-f04-runtime-current:latest`, image ID and repo
digest `sha256:df0289e3d31d7c75ef4b48520f61579b3b2019faa4f136e81e025bb332771023`;
`wg`, `wg-quick`, and `resolvconf` were present; `/dev/net/tun` was present when
explicitly attached. The host-side config, credential, and state files were all
mode 0600. Repeating with a `/Users/...`-backed disposable mount kept the same
image running, created interface `runtime`, advanced local state to revision 1,
and returned runtime status `desired_revision=1`, `applied_revision=1`,
`connectivity=connected`, `stale=false`.

This corrects the harness and satisfies the runtime local-interface leg. The
final F01-owned rerun also satisfied the gateway peer/handshake leg and the
suspend/resume absence/restoration sequence; redacted evidence is recorded in
`walk-artifacts/F01/20260815T-final/runtime-live-final.md`. No product code
change was warranted. F01 remains subject to root review and plan disposition.

### Current-head gate evidence — 2026-08-15

Focused default/enterprise F01 HTTP tests, focused migration/contract tests,
node tests, helper tests, helper cross-compiles, web typecheck/full web test
(75 files/1,044 tests), web build, and `git diff --check` passed. The current
collision-safe 1–93 sequence passed at `93|dirty=false` in five isolated
PostgreSQL 16.15 databases; current 0088 down/up/refusal evidence is recorded
under `walk-artifacts/F01/20260815T081827Z/`.

The required full gates are not all green on this shared head:

- `make generate-check` failed because the coordinated uncommitted generated
  F01/F02/F03 set differs from `HEAD`, despite stable regeneration.
- `make test-editions` failed on shared CA/fixture/database state (CA decrypt
  authentication failures, duplicate runtime seed key, invalid seeded email,
  and forced F04 audit-failure test).
- `make build-editions` first failed in the Docker compiler with
  `internal/release/bootstrap.go:5: could not import net/url (open : no such
  file or directory)` while the equivalent host Go build passed; an independent
  second Docker run passed, so this is classified as transient builder state.

The repeated edition-suite failures are shared CA/fixture/database state, with
file/line evidence recorded in `docs/F01-decisions.md`; they are not silently
converted to SUBSTITUTES or claimed as F01 product failures. F01 remains In
Progress and is not marked Done by this task.

### AWS dev-control-plane acceptance — 2026-08-15

The production-shaped F01 path was repeated on the authorized AWS development
control plane after the collision-safe schema reached `93|clean`. A separate
agent on `aws-gw-1` passed create/approve, metadata PATCH and fresh-refetch
persistence, suspend with no new handshake under forced traffic, and resume of
the same peer with a newly advancing handshake. A real plain-member session saw
the agent row and its organization-viewable basic liveness/traffic, but received
no owner email, privileged profile/runtime telemetry, profile read/write access,
lifecycle, remove, quota, runtime, or enrollment controls in the released `/agents` DOM.
The owner refetch proved the refused member mutation changed nothing.

Redacted evidence is
`walk-artifacts/F01/20260815T052728Z/F01-live-summary.txt` with SHA-256
`53e5571ded779d84b0aaad836a74ffc2dcadf0e4f795152e01ea5d0a458ff054`.
No F03 or F04 disposable identity was touched by this walk.
