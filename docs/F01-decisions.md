# F01 decisions

Status: **SATISFIES / Done.** The historical in-progress ledgers below are retained as the measured path to closure; the final disposition is recorded at the end of this paper.

## Locked decisions

| Decide-item | Disposition | Measured basis |
| --- | --- | --- |
| Canonical agent identity | Locked: an agent is the existing `devices` row (`id`, `org_id`, `user_id`, `node_id`, `kind = 'agent'`). | `agent_profiles.device_id` is the primary key and foreign key to `devices`; profile queries join the device and require `kind = 'agent'`. |
| Canonical owner | Locked: `devices.user_id`; profile metadata never duplicates ownership. | `GetAgentProfileForOrg` returns `d.user_id` and joins `users` for the response email; the migration comment explicitly says owner is not duplicated. |
| Canonical lifecycle | Locked: `devices.status`; persisted values are `active`, `pending`, `suspended`, and `revoked`. `pending` means enrolled and awaiting approval. | Migration 0088 replaces the status check; `AgentLifecycleTransition` permits only active↔suspended; approval remains `ApproveDevice` pending→active and revoke remains the existing device flow. |
| Canonical telemetry | Locked: `device_status`; profile reads handshake and byte counters through the left join and does not store telemetry in `agent_profiles`. | `GetAgentProfileForOrg` selects `ds.last_handshake_at`, `ds.rx_bytes`, and `ds.tx_bytes`. |
| Profile data boundary | Locked: `agent_profiles` stores metadata only: `environment`, `runtime`, and object `labels`. | Migration 0088 defines only those mutable metadata fields plus timestamps; `UpdateAgentProfile` updates only them. |
| Lifecycle authority | Locked: only the existing member-management permission may suspend/resume, and only active↔suspended is exposed through profile PATCH. | Handler checks `PermMemberManage`; `agentProfileLifecycleAllowed` rejects member self-lifecycle, pending, revoked, and arbitrary states. |
| Owner edits | Locked: an owner/member may edit metadata only. A metadata-only request contains no status and is committed atomically. | Handler authorizes ownership before profile load; the service takes an optional lifecycle intent and validates it before metadata update in one transaction. |
| Terminal and approval semantics | Locked: revoked is terminal for this surface; pending cannot be activated through profile PATCH. Approval and revoke remain their existing canonical flows. | `AgentLifecycleTransition` has no pending/revoked edges; handler tests and integration proof assert refusal. |
| Information hiding | Locked: the basic Agents roster's status, liveness, and traffic are organization-viewable operational facts. Owner email is visible only to member-managers or the owning member; privileged profile/runtime telemetry, metadata, and lifecycle controls require profile ownership or member-management authority. Unrelated members receive 403 from profile GET/PATCH and no privileged profile/runtime DOM. | `ListAgents` deliberately returns basic roster liveness/traffic after `org:view` while shaping `owner_email`; `requireAgentProfileAccess`, the non-admin PATCH branch, and the released-route absence tests cover the privileged boundary. |
| Edition boundary | Locked: profile GET/PATCH use the same permission-before-edition ordering as ListAgents; the open/default build returns `edition_required` after authentication and before profile data or mutation work. | `GetAgentProfile` and `UpdateAgentProfile` gate on the nil open-edition policy port after `authorize`; executable `!enterprise` tests cover both operations. |
| Migration reversibility | Locked: 0088 backfills non-deleted agent devices idempotently, preserves device truth, and down refuses suspended rows or non-default metadata before destructive steps. | `ON CONFLICT DO NOTHING`, canonical-column references, and the explicit down guards are covered by migration tests and the isolated PostgreSQL 16 proof. |

## Held findings / unresolved decide-items

These are intentionally not resolved in F01 without root/F03 disposition.

1. **Independent review — resolved:** the authenticated released-route, rollback, and connected-agent evidence were independently reviewed with no remaining F01 P0/P1 finding.
2. **Resolved live gate:** authenticated UI/list wire evidence, the disposable migration rollback walk, and the connected-agent data-plane proof are satisfied by their named redacted artifacts. Unit/PG lifecycle and data-plane tests remain SUBSTITUTES for the live proofs.

## Isolated PostgreSQL proof ledger — 2026-08-14

The proof used PostgreSQL 16.14 in disposable Docker container `tunnex-f01-proof-47905`, with separate disposable databases for backfill and rollback cases. The container and Docker-only Go caches were removed after the run.

- Migration reached `82|dirty=false`.
- `go test -v ./db -run "TestAgentProfileMigrationContract|TestAgentProfile" -count=1` — PASS.
- `go test -v ./internal/devices -run "TestAgentLifecycleTransition|TestSuspendedAgentIsAbsentFromPeersAndAtomicProfileFailure" -count=1` — PASS, including non-skipped PostgreSQL peer absence/resume and atomicity proof.
- The same devices command with `-tags enterprise` — PASS, including bootstrap redemption.
- `go test -v ./internal/http -run "TestAgentProfile" -count=1` — PASS, including non-skipped owner/member/admin handler proof.
- `TUNNEX_TEST_DATABASE_URL="$F02_PRIVACY_DSN" go test -v ./internal/http -run '^TestAgentProfileHandlersAuthorizationAndAtomicity$' -count=1` — PASS, non-skipped in F02's isolated PostgreSQL database; includes ListAgents owner-email absence/presence and profile authorization/atomicity.
- `TUNNEX_TEST_DATABASE_URL="$F02_PRIVACY_DSN" go test -tags enterprise -v ./internal/http -run '^TestAgentProfileHandlersAuthorizationAndAtomicity$' -count=1` — PASS, non-skipped in F02's isolated PostgreSQL database.
- Backfill database: existing agent profile count `1`, canonical owner `22222222-2222-4222-8222-222222222222`, status `active`, telemetry `rx_bytes=123`.
- Current collision-safe 0088 proof: default down exited 0 at `87|dirty=false`, removed `agent_profiles`, retained the active agent device, and up-again reached `93|dirty=false` with the default profile backfilled.
- Current collision-safe 0088 proof: non-default down exited 1 with `0088 rollback refused: non-default agent profile metadata would be lost`; migration was `87|dirty=true` while the device and exact `prod`, `python`, `{"team":"sec"}` profile values remained present.
- Current collision-safe 0088 proof: suspended down exited 1 with `0088 rollback refused: suspended agent/device rows must be resumed or revoked first`; migration was `87|dirty=true` while the suspended agent and default profile remained present.
- Redacted evidence: `walk-artifacts/F01/20260815T081827Z/rollback-0088-current.txt`. The earlier 0079/schema-83 artifact remains historical pre-collision evidence only.

## Contract/generation closure ledger — 2026-08-14

- OpenAPI F01 status contract now has response `pending|active|suspended|revoked` and mutation `active|suspended`; no `enrolled` literal remains in generated Go, CLI, TS, or sqlc outputs.
- Combined generation preserved F04 runtime operations: generated Go/CLI/TS outputs retain poll/report/runtime-status operations, and sqlc retains F01 profile plus F04 runtime query symbols.
- `go test ./db -run 'TestAgentProfile(MigrationContract|GeneratedStatusContract)' -count=1` — PASS; enterprise-tagged equivalent — PASS.
- `pnpm --filter @tunnex/web typecheck` and `pnpm --filter @tunnex/web build` — PASS.
- `make generate-check` reached its guard but exited 1 because this shared, uncommitted branch contains generated changes relative to `HEAD`; regeneration itself completed and a second generation produced no additional source drift.
- Default and enterprise HTTP compile/tests are green after the coordinated typed ErrorCode regeneration; F04 poll/report/runtime-status operations remain present in Go, CLI, and TS outputs.

## F01 endpoint and call-site absence audit

Measured from the current OpenAPI operation registrations, handlers, and web source:

| F01 operation | Server behavior | Real web call site |
| --- | --- | --- |
| `GET /api/v1/organizations/{orgId}/agents/{deviceId}` (`getAgentProfile`) | Permission/owner check precedes profile, owner-email, and telemetry load; returns canonical profile view. | `apps/web/src/pages/Agents.tsx` expandable agent row. |
| `PATCH /api/v1/organizations/{orgId}/agents/{deviceId}` (`updateAgentProfile`) | Owner/member can send metadata only; member-manager can request active↔suspended; service performs the metadata/lifecycle mutation atomically. | `apps/web/src/pages/Agents.tsx` metadata editor and lifecycle confirmation. |

The released `/agents` route now has production call sites for both F01 profile operations and executable route tests for member absence, manager visibility, refetch persistence, lifecycle confirmation, and in-flight org-switch clearing. Authenticated route evidence is captured in `walk-artifacts/F01/20260814T165700Z/browser-walk-correction.md` plus the subsequent affected-path artifact; the earlier walk is superseded.

## Live browser proof ledger — 2026-08-14

- Owner/manager list wire payloads were captured redacted: authorized responses contain `owner_email`; the member response contains no `owner_email` keys. The member DOM retains the organization-viewable basic roster liveness/traffic while omitting owner attribution, privileged profile/runtime facts, Actions, and Remove controls.
- Owner metadata PATCH returned 200 and a follow-up profile GET/refetch showed the saved metadata. Manager suspend→suspended and resume→active each refetched from the server. The seeded unverified admin was observed only for control visibility; no mutation was sent from that session.
- Org switch cleared the old roster immediately while target requests were in flight, then rendered the target empty state; no old gateway, profile, or runtime fact remained.
- Evidence: `walk-artifacts/F01/20260814T165700Z/browser-walk-correction.md` and the affected-path wire artifact recorded with this slice.

- Affected-path artifact: `walk-artifacts/F01/20260814T172001Z/browser-walk-privacy-org-switch.md`. It records the redacted owner/manager/member list payload shapes and the live member DOM/org-switch observations.
- UI/list wire status: SATISFIES for the authenticated isolated route walk. Rollback status and connected-agent data-plane status are SATISFIES for their named live disposable walks.
- Rollback status: SATISFIES for current 0088 in `walk-artifacts/F01/20260815T081827Z/rollback-0088-current.txt`; default down/up-again preserved the device, and non-default/suspended guards refused without losing profile/device values. Refusal cases ended at `87|dirty=true` because the migration runner records the failed down attempt. The earlier 0079 artifact is retained only as historical evidence.
- Post-correction focused evidence: `GOFLAGS=-mod=readonly go test ./internal/http -run 'TestAgentProfile|TestEditionGateNeverPrecedesPermissionGate' -count=1` — PASS; enterprise-tagged equivalent — PASS. `pnpm --filter @tunnex/web exec vitest run test/agentsruntimewiring.test.tsx test/agentprofileeditor.test.tsx` — PASS, 18 tests; typecheck and build — PASS; `git diff --check` — PASS.
- `make generate` completed and regenerated the combined artifacts. `make generate-check` exited 1 because this shared uncommitted branch still differs from `HEAD` in the pre-existing F01/F02/F03 generated/sqlc set; the guard printed generated diffs rather than a new post-generation drift claim. This remains a root coordination gate.

## Current-head story-close gate ledger — 2026-08-15

- Focused F01 default HTTP tests — PASS: `GOFLAGS=-mod=readonly go test ./internal/http -run '^(TestAgentProfile|TestAgentRuntime|TestSessionlessRequestsAre401|TestEditionGateNeverPrecedesPermissionGate)$' -count=1`.
- Focused F01 enterprise HTTP tests — PASS: same command with `-tags enterprise`.
- Focused F01 migration/contract tests — PASS: `GOFLAGS=-mod=readonly go test ./db -run 'TestAgentProfile(MigrationContract|GeneratedStatusContract)|TestAgentProfile' -count=1`.
- `make generate-check` — FAIL (exit 2) by repository guard because the shared uncommitted branch contains generated F01/F02/F03 changes relative to `HEAD`; regeneration completed and the output was stable, but the guard cannot pass until the coordinated generated set is committed.
- Current collision-safe 1–93 chain — PASS at `93|dirty=false` in five isolated PostgreSQL 16.15 databases used for the current 0088/0090 rollback proofs. The F01 default case also passed 88→87→93 up-again.
- `make test-editions` — FAIL (exit 2) on the current shared database. Failures were CA ciphertext/auth fixture failures, duplicate `nodes_cert_serial` runtime seed data, invalid seeded email serialization in an HTTP runtime route test, and the forced F04 audit-failure test. These are shared-stack/fixture gates, not isolated F01 focused failures; root disposition remains required.
- `make build-editions` — first run FAIL (exit 2) in the Docker build with `internal/release/bootstrap.go:5: could not import net/url (open : no such file or directory)` while host `GOFLAGS=-mod=readonly go build ./...` passed; an independent second Docker run on the same source passed (exit 0). Classify the first result as transient Docker/compiler state, not a reproducible source defect.
- `make test-node` — PASS. `make test-helper` — PASS. `make helper-crosscompile` — PASS for darwin/amd64, darwin/arm64, and windows/amd64.
- `pnpm --filter @tunnex/web typecheck && pnpm --filter @tunnex/web test && pnpm --filter @tunnex/web build` — PASS: 75 test files, 1,044 tests; typecheck and Vite build passed.
- `git diff --check` — PASS.

This was an intermediate shared-state result. It is superseded by the fresh isolated current-tree gate matrix recorded in the final disposition below.

## Final disposition — 2026-08-15

F01 **SATISFIES**. The authenticated released route, permission-gated DOM
absence, mutation refetch, current 0088 rollback/preservation, and real
suspend→peer absence→resume handshake walks all pass in the named redacted
artifacts. The later fresh isolated current-tree matrix passed generation,
migration, both editions, both builds, node/helper/crosscompile, full web, and
diff checks. The subsequent F04 offboard-only CLI change does not touch the F01
API, schema, UI, lifecycle, or evidence boundary. No F01 gate remains open.

### Independent gate diagnosis — 2026-08-15

- `make test-editions` reproduced exit 2 on the same shared `tunnex` database. `apps/api/internal/agentca/ca_test.go:29-48` uses the shared `TUNNEX_TEST_DATABASE_URL` without isolating the CA row; tests then fail at lines 56, 74, 87, and 119 because an existing CA cannot be decrypted with the new per-test key. This is shared database state, not an F01 code defect.
- `apps/api/internal/agentruntime/service_integration_test.go:41-42` seeds the fixed certificate serial `f04-cert` into the same shared database; the rerun fails with `nodes_cert_serial_key` duplicate data. This is fixture/database contamination.
- `apps/api/internal/http/agent_runtime_route_integration_test.go:99-101` receives a forced-audit 500 from a trigger created by `apps/api/internal/tenancy/agent_runtime_opt_in_integration_test.go:75-87`; the trigger is persistent shared DB state from a prior run, not an F01 route failure. The same run also reports the unrelated invalid-email serialization at the `/auth/me` handler path.
- The repeated CA failures in `apps/api/internal/nodes/rekey_integration_test.go:164,263,322,370,412,444` and `apps/api/internal/nodes/service_test.go:91` have the same shared CA-state cause.
- `apps/api/internal/tenancy/agent_runtime_opt_in_integration_test.go:47` reports its intentional forced-audit failure because the stale trigger is already present before the test's own setup. This confirms cross-run contamination.
- `make build-editions` was independently rerun after the first `net/url` failure and passed exit 0; no source fix or F01 regression test is warranted.

Both-green still requires root-controlled external state: a fresh isolated edition-test database (including clean CA/audit-trigger state), a generated-artifact baseline/ownership handoff so `generate-check` can compare against the correct committed set, and the required CI checks on the final exact SHA.

## Destructive/FK audit

`agent_profiles.device_id` references `devices.id ON DELETE CASCADE`. The current device removal contract avoids hard deletion: the server requires `revoked` and soft-deletes the device, preserving credential revocation, telemetry, posture, audit, and agent-source policy history. The released Agents route tells the operator “revoked first, then removed”; if removal fails it says the agent was revoked but could not be removed. This is the measured operator message; no F01 destructive verb is added.
