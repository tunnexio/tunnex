# F02 — Multiple agents per gateway and organization quotas

## Paper status

This is the F02 decision paper. The independently safe foundation and live two-agent/quota walk are measured and reviewable. H1-H3 are locked below; the plan status remains **In Progress** until root applies the independent story-close review.

## Story acceptance

F02 must allow more than one live agent device on one gateway while preserving device identity, organization-scoped address uniqueness, public-key uniqueness, safe revocation, and a reversible migration. It must not infer or invent an organization quota from an existing gateway or human-device cap.

## Evidence baseline (0089 and PostgreSQL)

| Evidence | Result |
| --- | --- |
| `apps/api/db/migrations/0089_multi_agent_per_gateway.up.sql:1-10` | Removes only `devices_agent_node_key`; it does not alter device IDs, organization IP allocation, or public-key uniqueness. |
| `apps/api/db/agent_gateway_migration_integration_test.go:TestMultiAgentPerGatewayConcurrentIdentity` | On real PostgreSQL, concurrent same-node inserts commit with distinct device IDs, public keys, and organization IPs; duplicate key/IP attempts are rejected. The released-route proof is recorded below. |
| `apps/api/db/agent_gateway_migration_integration_test.go:TestMultiAgentPerGatewayRollback` | **PASS**, non-skipped in an isolated Docker PostgreSQL 16 + Go runner network. One live same-node agent permits 0089 down and preserves its row; two live same-node agents refuse down, preserve both rows, leave the one-agent index absent, and record the expected dirty version metadata. |
| `walk-artifacts/F02/20260815T045504Z/migration-collision-proof.md` | **PASS** on `tunnex-cp` using only disposable databases. The schema-87 backup clone applied 0088–0093, rolled back cleanly to 0087, and reapplied to 0093; the renumbered F02 rollback/refusal and cluster-scope up/down/up PostgreSQL tests passed without changing the live database. |
| `apps/api/internal/devices/service.go:438-535` and `apps/api/db/queries/devices.sql:242-265` | Device creation serializes organization allocation with an advisory lock, reads active allocations, and relies on database uniqueness for the final identity/address boundary. The existing human-device cap is not an agent quota. |
| `apps/api/db/queries/devices.sql:196-233` | Deliberate device revocation is terminal and retains the assigned IP for history; gateway revocation separately cascades to all live/pending devices homed on that node. |

## Locked decisions

### D1 — Safe multi-agent foundation (locked)

Migration 0089 is the only F02 schema change in scope (`apps/api/db/migrations/0089_multi_agent_per_gateway.up.sql:6-10`; down: `apps/api/db/migrations/0089_multi_agent_per_gateway.down.sql:1-19`): remove the obsolete one-agent-per-node constraint, and restore it only when rollback can prove that no node has more than one live agent. Rollback must refuse before changing data when the precondition is false.

### D2 — Identity and allocation invariants (locked)

Same-gateway agents remain distinct device rows with distinct device IDs, public keys, and organization-scoped assigned IPs. The org allocation lock and database uniqueness constraints remain authoritative. No gateway/device cap is repurposed as an organization agent quota.

### D3 — No implicit enforcement (locked)

Migration 0089 alone imposes no quota. The separately reversible 0092 quota slice is the explicitly selected organization setting; existing human-device limits continue to apply only where their existing predicate says they apply.

### D4 — Revocation safety (locked)

An agent removal uses the existing revoke-then-remove contract. Revoke must disable that device while leaving another same-gateway agent intact; hard deletion is only allowed after revocation. The gateway-wide cascade is a distinct destructive operation and is not substituted for per-agent revocation.

## Locked quota decisions

### H1 — Quota source (locked)

The quota is an explicit nullable organization-level setting, exposed through a dedicated agent-quota settings API. `NULL`/unset means unlimited. It is not sourced from a signed licence claim and is not inferred from gateway or human-device caps.

### H2 — Lifecycle counting (locked)

The limit counts agent device identities in `pending`, `active`, and `suspended` states. `revoked` and soft-deleted devices do not count. Pending identities reserve capacity before key generation/insert completes, so concurrent enrollment cannot overshoot the limit.

### H3 — Scope and unit (locked)

The unit is organization-wide agent device identities, aggregated across gateways. It is not a per-gateway limit and does not count IP allocations, public keys, or human devices.

### H1-H3 enforcement and surface (locked)

The check runs inside the existing transaction-scoped organization advisory lock used by device creation and allocation (`apps/api/internal/devices/service.go:438-535`). A refusal is HTTP 409 with stable code `agent_quota_exceeded`; no client-side remaining count is returned or inferred. Administrators set/read the nullable value through the dedicated organization agent-quota endpoint, permission-gated by `org:update` and edition-gated consistently with the existing Agents surface. The UI adopts the successful scoped mutation response as server truth (without re-fetching or replacing the shared organization selection); the live walk separately re-read the API to prove persistence, and the UI renders no optimistic remaining capacity.

Rollback drops only the quota column; existing device rows, identities, allocations, and audit history are preserved. `NULL` remains the compatibility/unlimited value.

## Rejected alternatives for H1-H3

The signed licence/plan claim source, per-gateway scope, live-allocation unit, and exclusion of pending or suspended identities were rejected for this slice. They remain findable here because they would change enforcement, API, and operator semantics; reopening them requires a new product disposition.

## Absence audit — current multi-agent surfaces

This is an audit of the current tree, not a proposal to add missing surfaces.

| Capability / mutation | API evidence | Real UI call site and operator feedback | F02 implication |
| --- | --- | --- | --- |
| Issue one-time agent bootstrap token | `apps/api/internal/http/agent_handlers.go:16-29` | `apps/web/src/pages/Agents.tsx:120-137` POSTs org + name + gateway; failure says “Could not enrol the agent.” | This is the creation mutation. Quota refusal is server-owned; no remaining count is inferred. |
| Redeem token and create agent device | `apps/api/internal/http/agent_handlers.go:31-43`; service allocation/identity path at `apps/api/internal/devices/service.go:438-535` | The command produced at `apps/web/src/pages/Agents.tsx:400-410` runs on the agent host; no browser-side device identity or private key is created. | Concurrent enrollment is real behavior to prove, not a UI-only claim. |
| List agents | `apps/api/internal/http/agent_handlers.go:45-119` | Agents page `apps/web/src/pages/Agents.tsx:91-107`; Dashboard `apps/web/src/pages/Dashboard.tsx:183-190`; Access policy source `apps/web/src/pages/Access.tsx:1547-1563`. | Agents are absent on 403 edition refusal; ordinary load errors are not rendered as zero on the Agents page. |
| Revoke one agent | `apps/api/internal/http/device_handlers.go:220-239`; SQL `apps/api/db/queries/devices.sql:196-212` | `apps/web/src/pages/Agents.tsx:141-154` POSTs revoke and reports “Could not revoke the agent.” on failure. | The walk must prove the other same-gateway agent remains usable. |
| Remove a revoked agent from roster | `apps/api/internal/http/device_handlers.go:188-218` | `apps/web/src/pages/Agents.tsx:156-168,383-394` DELETEs only after revoke; it tells the operator if revocation succeeded but cleanup failed. | Deletion is not the revocation mechanism; the audit trail and CRL safety contract remain. |
| Revoke a gateway | Node-level cascade is `apps/api/db/queries/devices.sql:214-233`; recovery semantics are documented in `apps/api/internal/devices/restore.go:55-80`. | Gateway impact/refusal messaging is in `apps/web/src/lib/gatewaysview.ts:224-255` and `apps/web/src/pages/Gateways.tsx:121-162`. | This is intentionally distinct from revoke-one-agent and must not be used to satisfy F02’s per-agent proof. |

The quota mutation and display now have explicit surfaces: `PUT /api/v1/organizations/{orgId}/agent-quota` and the managed-agent quota card in `apps/web/src/pages/Agents.tsx`. No remaining count or client-side capacity warning is displayed; the server conflict is authoritative.

## Live Enterprise acceptance evidence

The disposable production-shaped stack was reached through `http://127.0.0.1:18086` after `/api/v1/meta` reported `edition=enterprise`. The walk used one organization, one real gateway/node, the released Agents route/API, and canonical owner, admin, member, and unauthenticated sessions. No license, bootstrap token, runtime credential, private key, or cookie value is recorded here.

| Leg | Redacted result |
| --- | --- |
| Quota persistence | Owner set `max_agent_identities=2` through the released quota route; organization refetch returned `2`. Cleanup set it to `NULL`; refetch returned `NULL`. |
| Concurrent enrollment | Three real bootstrap requests targeted the same gateway concurrently: **2 HTTP 200 commits**, each with a distinct device ID, public key, and organization IP; **1 HTTP 409** with stable code `agent_quota_exceeded`. |
| Lifecycle counting | Pending, active, and suspended identities each consumed capacity and caused the next enrollment to return `409 agent_quota_exceeded`; revoked/deleted identity removal freed capacity. |
| Unlimited and revoke isolation | With quota `NULL`, enrollment returned `200`. Revoking/removing one agent left the other same-gateway agent active with its identity intact. Device approval was restored to `off`. |
| Permission and absence behavior | Owner mutation returned `200`; verified member returned `403 forbidden`; unverified admin returned `403 email_not_verified`; unauthenticated mutation returned `401 unauthenticated`. Open-edition and Community checks returned no agent/quota facts or actions. Focused released-route UI absence/wiring tests passed **19/19**. |

### Rollback command and redacted evidence

The rollback proof ran without host-port forwarding, using container-local TCP on an isolated Docker network:

```text
docker run -d --name f02-rollback-pg --network f02-rollback-net \
  -e POSTGRES_USER=<redacted> -e POSTGRES_PASSWORD=<redacted> \
  -e POSTGRES_DB=<redacted> postgres:16
docker run --rm --name f02-rollback-go --network f02-rollback-net \
  -v /Users/pawangupta/tunnex:/src -w /src/apps/api \
  -e TUNNEX_TEST_DATABASE_URL=postgres://<redacted>@f02-rollback-pg:5432/<redacted>?sslmode=disable \
  golang:1.25.13-alpine go test -v ./db \
  -run '^TestMultiAgentPerGatewayRollback$' -count=1
```

Redacted output:

```text
=== RUN   TestMultiAgentPerGatewayRollback
--- PASS: TestMultiAgentPerGatewayRollback (1.07s)
PASS
ok   github.com/tunnexio/tunnex/apps/api/db  1.074s
```

The test covers both rollback branches: safe one-agent down restores `devices_agent_node_key` without changing the agent row; two-agent down refuses before data loss, preserves both rows/identities, leaves the constraint absent, and records the failed down at migration version 79 as dirty. Disposable containers and network were removed after the run.

## Boxwalk record

The live procedure and results are recorded in [`docs/F02-boxwalk.md`](/Users/pawangupta/tunnex/docs/F02-boxwalk.md), including concurrent enrollment, quota boundary, lifecycle counting, revoke-one preservation, permission/absence behavior, cleanup, and both rollback branches.

## Self-review — findings held for disposition

1. **P2 — Quota setting is intentionally not a remaining-count surface.** The UI shows only the configured nullable maximum and server response truth; it does not predict availability.
2. **P2 — Gateway-wide revoke is a separate blast radius.** The existing cascade remains distinct from the proven per-agent revoke preservation leg.

No P0/P1 F02 findings remain from this close review. The two P2 observations remain **HELD** as operational follow-up; no product, OpenAPI, generated, or plan-status change follows from this paper.
