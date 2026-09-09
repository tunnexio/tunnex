# Workload identity local box-walk — 2026-09-09

**Integrated local control-plane rollout verified. Production/story acceptance remains INCOMPLETE.**

The subsequent [real Azure workload walk](S-AI-workload-azure-live-boxwalk.md)
verified two actual GPT-5 calls, restart, automatic token renewal, scoped
revocation and cleanup. It also recorded missing Azure cost data; dollar-threshold
qualification remains open. The fixture-only statements below describe the earlier
rollout walk.

Source: `story/S-AI-workload-identity`, paper base `4e0ffd66`, plus the local
implementation snapshot listed in `walk-artifacts/workload-cp0909/source-sha256.txt`
(and the earlier isolated snapshot under `workload0909`).
The manifest names source bytes rather than misrepresenting an uncommitted tree
as a released commit. The initial isolated run did not install the new path. The subsequent user-requested
local rollout below supersedes that limitation; no release or remote publication occurred.

## Integrated local CP rollout

The user requested deployment into the existing control plane and a redesign
using the application’s existing components. On 2026-09-09 the matching API and
web implementation replaced the local processes serving **http://127.0.0.1:5180**.
The installed macOS CLI at `/opt/homebrew/bin/tunnex` was updated to the tested
build. Previous API/CLI binaries and a PostgreSQL dump are preserved in a private
rollback directory; no secrets or database dump are included in this evidence.

| Deployment boundary | Verified value |
| --- | --- |
| Docker context | `colima-tunnex-sso-review` |
| Compose project | `tunnexaiwalk0907repro4` |
| API / PostgreSQL | `tunnexaiwalk0907repro4-cp-api` / `tunnexaiwalk0907repro4-cp-postgres` |
| Network | `tunnexaiwalk0907repro4_engine` |
| Schema | 153, clean; existing state was 151 and reserved MCP migration 152 was not included |
| API health | `/healthz` HTTP 200 |
| Existing provider configuration | Before/after SHA-256 identical: `aad2b8da9ed6b806b176c22b0934010d2c1f04786037e5907f60feadf9ea8c37` |
| Application UI | Real signed-in router/sidebar/API on port 5180; no in-memory preview API |

The real UI created **Engineering app (local test)** with the existing private
fixture model, then issued a bounded reusable enrollment key. Actual CLI calls
through the deployed CP proved:

- Model listing **200** and fixture chat **200** with nonempty content; ungranted
  model **403**. The child received only a local session credential.
- Ordinary restart reused the same instance with the enrollment-key file absent.
- A second replica obtained a separate identity under the same workload policy.
- Revoking the first instance caused **401**, without automatic re-enrollment;
  the sibling continued to call the fixture model successfully.
- Key-only revocation stopped further joins while the existing sibling retained
  access. The revoked key’s **Revoke instances** action remains reachable.
- The real **Usage & cost → Spend by workload** table reported the fixture calls
  under one workload. Fixture calls have missing price data and are correctly
  marked uncosted; this is not a live dollar-threshold proof.

The test workload remains available for inspection, with one revoked and one
active instance. Its introduction key is revoked. Azure GPT and Claude models
and their saved credentials were preserved; no paid provider was called.

The UI uses shared DataTable, Card, Button, one-time-secret modal and right-side
form drawer components. The default list is searchable. Workload details separate
Overview, Enrollment keys and Instances without duplicating the gateway navigation.
Screenshots: [overview](../walk-artifacts/workload-cp0909/workload-overview.png),
[instances](../walk-artifacts/workload-cp0909/workload-instances.png),
[edit drawer](../walk-artifacts/workload-cp0909/workload-edit.png),
[usage](../walk-artifacts/workload-cp0909/workload-usage.png).

Post-fix verification: 30 focused web tests, web typecheck/build, both API edition
builds, both-edition storage-failure/lifecycle regressions, CLI workload/race tests,
and the updated real HTTP CLI fixture walk passed. W1–W6 and the related stale
model-mode selection defect are corrected. W7 (confirmation after a committed
retirement response is lost) remains a separately documented qualification limit.
See [review dispositions](S-AI-workload-identity-review.md).

[Sanitized proof](../walk-artifacts/workload-cp0909/verification.log) and
[source manifest](../walk-artifacts/workload-cp0909/source-sha256.txt) and
[binary hashes](../walk-artifacts/workload-cp0909/binary-sha256.txt)
identify this uncommitted implementation snapshot without presenting a paper
commit as the deployed product commit.

## Earlier isolated HTTP proof

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

The initial run exposed W3. The updated run preserves instance state after ordinary
child exit, verifies restart reuse, and exercises explicit retirement separately.

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

## Earlier standalone rendering (superseded)

The separate `http://127.0.0.1:5188/workload-preview.html` uses the real Workloads
component with in-memory sample data. Desktop inspection covered the model-policy
dialog, autoscaling enrollment form, key/instance tables and AI-viewer action
removal. Its fixture banner identifies that changes affect sample data only.

[Captured workload screen](../walk-artifacts/workload0909/workloads-preview.png)
contains synthetic names/identifiers and no secrets. It proves rendering at the
inspected viewport, not a saved API policy, live upstream call or mobile approval.

## Explicitly still pending

W1–W6 are now corrected. W7, shared MCP review disposition, central MCP execution,
explicit legacy migration preview,
shared admission protection, full auth metadata and production lifecycle work
remain. Multiple API replicas, full twenty-replica replacement/restart, issuer
outage/failover and platform execution need real deployment walks at the
**production qualification** gate. Unit/integration results do not satisfy that gate.

No CI result, merge, release, production HA result or user visual approval is
claimed. Provider credentials, human login and parent dirty work were preserved. The local
API/frontend processes were replaced under the user’s rollout instruction.
