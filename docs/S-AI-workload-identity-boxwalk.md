# Workload identity local box-walk — 2026-09-09

**Partial implementation proof. Story acceptance remains INCOMPLETE.**

Source: `story/S-AI-workload-identity`, paper base `4e0ffd66`, plus the local
implementation snapshot listed in `walk-artifacts/workload0909/source-sha256.txt`.
The manifest names source bytes rather than misrepresenting an uncommitted tree
as a released commit. This session neither published nor installed the new path
into the existing port-5180 preview.

## Actual HTTP proof

The production CLI binary called a real local HTTP API listener backed by the
workload service, a disposable PostgreSQL instance and a synthetic engine/provider.
It did not call Azure or use saved provider credentials.

Recorded command (from repository root):

```sh
TUNNEX_WORKLOAD_CLI=/private/tmp/tunnex-workload-tools/tunnex \
  bash scripts/test-workload-isolated.sh -p 1 ./internal/http \
  -run 'TestWorkloadCLIHTTPWire|TestWorkloadManagementRoleBoundary' -count=1 -v
```

[Sanitized output](../walk-artifacts/workload0909/http-wire.log) records PASS:

- Twenty independent CLI enrollments under one stable workload/accounting key.
- Registered signing-key rotation.
- Child SDK-environment model listing, JSON chat, streaming SSE and Anthropic
  requests through the wrapper and gateway.
- Unselected model refusal before the fixture engine is called.
- Enrollment-key-only revocation preserves registered instance access.
- Instance retirement, management endpoint isolation and workload disable.

The current retirement behavior has a separately held restart defect (W3).
Passing the retirement test does not prove supervisor restart works.

Isolation verified before database-capable commands:

| Setting | Value |
| --- | --- |
| Docker context | `colima-tunnex-sso-review` |
| Compose project | `tunnexworkload0909` |
| Container | `tunnexworkload0909-postgres-1` |
| Network | `tunnexworkload0909_default` |
| Port | `127.0.0.1:15489` |
| Data | Disposable tmpfs; no existing database volume |
| Schema | Migration 153, clean |

## Supporting checks

| Check | Result and limit |
| --- | --- |
| Open-edition API `go test -p 2 ./... -count=1` | PASS against the isolated fixture. |
| Enterprise API `go test -p 2 -tags enterprise ./... -count=1` | All non-DB packages passed. The DB package was interrupted by a fixture memory-pressure restart; not counted as a pass from that run. |
| Enterprise DB rerun `go test -p 1 -tags enterprise ./db -count=1` | PASS after recreating only the disposable fixture with bounded buffers/WAL. Logs confirmed the earlier checkpointer was killed by signal 9; fixture inspect recorded OOMKilled. |
| Both API edition builds | PASS, `GOFLAGS=-mod=readonly`. |
| Generated Go/TS/RBAC/SQLC/design tokens | PASS, regenerated with pinned tools; source hashes unchanged byte-for-byte. |
| Workload lifecycle/compatibility DB tests | PASS: use/replay races, revocation, policy, provider references, inactivity maintenance, aggregate thresholds and replacement video ownership. These are integration substitutes for missing deployment walks. |
| Focused CLI race tests | PASS after enabling local test listeners; sandbox listener refusal was not counted as a product failure. |
| CLI Linux/Windows compile | PASS; Windows runtime deliberately unavailable, so this is not a Windows execution proof. |
| Web full suite | 1,484 passed, two role assertions initially failed because they omitted new workload permissions. The corrected five-test role suite then passed. |
| Web focused workload/usage tests | 18 passed. |
| Web typecheck and production build | PASS. Existing bundle-size warning remains. |
| Website docs | Draft based on fetched `tunnex-web` main `c785aa095c0c975b9a2eb393ae18e9fc7fe55438`; formatting and Astro build pass. No publication. |

## Rendered UI

The separate `http://127.0.0.1:5188/workload-preview.html` uses the real Workloads
component with in-memory sample data. Desktop inspection covered the model-policy
dialog, autoscaling enrollment form, key/instance tables and AI-viewer action
removal. Its fixture banner identifies that changes affect sample data only.

[Captured workload screen](../walk-artifacts/workload0909/workloads-preview.png)
contains synthetic names/identifiers and no secrets. It proves rendering at the
inspected viewport, not a saved API policy, live upstream call or mobile approval.

## Explicitly still pending

The six held findings in [the review](S-AI-workload-identity-review.md), shared MCP
review disposition, central MCP execution, explicit legacy migration preview,
shared admission protection, full auth metadata and production lifecycle work
remain. Multiple API replicas, full twenty-replica replacement/restart, issuer
outage/failover and platform execution need real deployment walks at the
**production qualification** gate. Unit/integration results do not satisfy that gate.

No CI result, merge, release, production HA result or user visual approval is
claimed. Original API, provider credentials, human login and parent dirty work
were preserved.
