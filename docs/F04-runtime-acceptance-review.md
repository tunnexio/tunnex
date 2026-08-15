# F04 managed-runtime acceptance review

## Review scope

Read-only review of the current F04 diff against `docs/F04-decisions.md` and
the story acceptance. Root runtime changes and companion work were preserved;
this review added no product, generated, OpenAPI, UI, or plan changes.

## Current-head evidence

The released runtime path now exists and is wired through the generated API
adapter, the separate `tunnex-agent-runtime` entrypoint, and the managed
runtime service. Root's live evidence reports applied revision `1`, interface
`runtime`, gateway peer/handshake, control-plane connected, restart persistence,
and revoke-triggered interface removal.

| Acceptance area | Verified evidence |
| --- | --- |
| Hash-only/device binding and no-oracle machine auth | `apps/api/internal/agentruntime/service.go:69-82` hashes the bearer, requires the credential's exact org/device, agent kind, live status, non-deleted device, and non-revoked credential. `TestRuntimeAuthMiddlewareUniformlyRefusesNonRuntimeCredentials` passes. |
| Opt-in and edition conjunction | `OrganizationOptIn` requires both paid-edition unlock and the persisted org flag at `apps/api/internal/agentruntime/service.go:43-56`; server wiring is at `apps/api/cmd/server/main.go:412-417`. 0093 defaults false and rollback/audit integration tests pass. |
| Permission order and mutation audit | `SetOrganizationAgentRuntimeEnabled` checks `agent_runtime:manage` before edition at `apps/api/internal/http/agent_handlers.go:53-75`; tenancy persists the flag and audit event in one transaction at `apps/api/internal/tenancy/service.go:382-406`. |
| Poll/report/status | `apps/api/internal/http/agent_runtime_handlers.go` exposes the generated operations. The non-skipped PostgreSQL route contract proves 200/204 poll behavior, monotonic report refusal, secret absence, opt-in disable/re-enable, status projection, and no-oracle refusals. |
| CLI cold start, last-good, revocation | Focused default and enterprise CLI suites pass. Revoked credentials call `Disable`; apply/report failures retain last-good state. Alpine absent-interface stderr is idempotent and permission failures remain fatal. |
| UI and generated contract | `AgentRuntimeSettingCard` calls the scoped toggle route and returns no DOM for unauthorized roles. Generated Go/CLI/TS operation/model symbols and `agent_runtime:manage` RBAC output are present. Released-route wiring/absence tests pass 21/21. |

## Commands and exact results

```text
GOFLAGS=-mod=readonly go test ./db ./internal/agentruntime ./internal/http \
  -run '^(TestAgentRuntime|TestRuntimeAuthMiddleware|TestAgentRuntimeStatus|TestAgentRuntimeSync|TestF04RuntimeChannelAcceptanceSpec)' -count=1
PASS (db and http; agentruntime had no matching tests)

GOFLAGS=-mod=readonly go test -tags enterprise ./db ./internal/agentruntime ./internal/http \
  -run '^(TestAgentRuntime|TestRuntimeAuthMiddleware|TestAgentRuntimeStatus|TestAgentRuntimeSync|TestF04RuntimeChannelAcceptanceSpec)' -count=1
PASS (db and http; agentruntime had no matching tests)

GOFLAGS=-mod=readonly go test ./internal/cli \
  -run '^(TestAgentRuntime|TestManagedAgentRuntime|TestManagedRuntime|TestRunWireGuardQuickDown)' -count=1
PASS

GOFLAGS=-mod=readonly go test -tags enterprise ./internal/cli \
  -run '^(TestAgentRuntime|TestManagedAgentRuntime|TestManagedRuntime|TestRunWireGuardQuickDown)' -count=1
PASS

pnpm --filter @tunnex/web test -- --run \
  test/agentsruntimewiring.test.tsx test/agentprofileabsence.test.tsx
21/21 PASS

pnpm --filter @tunnex/web typecheck
PASS

git diff --check
PASS
```

The first CLI attempt without elevated loopback access was unavailable because
the sandbox rejected `httptest` listener creation; the same default and
enterprise commands were rerun with loopback access and passed.

## F2-owned live negative matrix

The following ran against the F2-owned disposable Scale edge
`http://127.0.0.1:18086` after `/api/v1/meta` reported `enterprise`. No shared
opt-in, root agent, root container, or real license was changed or read.

For `GET /api/v1/agent/runtime/poll?applied_revision=0&client_version=f2-negative`,
the absent bearer, malformed bearer, human/session-like bearer, human-device
bearer, cross-org runtime-like bearer, and revoked runtime-like bearer each
returned HTTP 401. After removing the request-id field, every response had the
same SHA-256 body hash:

```text
2da3d80d884a937fe84aa97acdbee715e84f49e7ea33cde43870279c987ce64e
```

The normalized wire bodies contained no `runtime_credential`, `bootstrap_token`,
`private_key`, `token_hash`, or `authorization` fields. A separately redeemed
F2-owned disposable agent returned 200 before canonical revoke; its same
credential returned 401 after revoke with the identical normalized body hash.
The disposable identity was then removed through the canonical device-delete
route. The credential itself was never written to an artifact or log.

## Route-red diagnosis: stale expectation, not a product defect

The PostgreSQL route test's cross-org quota assertion at
`apps/api/internal/http/agent_runtime_route_integration_test.go:146` expects
403, but the current route correctly returns 404. `authorize()` at
`apps/api/internal/http/handlers.go:63-91` returns `org_not_found` whenever the
principal is not a member of the requested organization, before the handler's
permission and edition checks. `SetOrganizationAgentQuota` calls that boundary
first at `apps/api/internal/http/agent_handlers.go:36-50`.

This is the established information-hiding rule, not an F04 regression:
`apps/api/internal/http/org_membership_boundary_test.go:46-53` explicitly says
non-members must receive 404 because 403 would confirm that the organization
exists. The same rule is pinned by `TestAuthorizeFailClosedAndProgression` in
`apps/api/internal/http/authz_test.go:35-46`. The F02 paper's quota permission
and edition wording (`docs/F02-decisions.md:55`) therefore composes with the
global org boundary: known-but-foreign and unknown organizations are both 404;
members without `org:update` remain 403; permission still precedes edition for
members. The focused test expectation is stale and needs disposition as a test
correction; changing the product to 403 would be a no-oracle defect.

## F2-owned bounded wire evidence

Using a newly redeemed F2-owned disposable identity on the same Scale edge,
the captured wire results were:

```text
GET runtime/poll (valid bearer): 200
POST runtime/report (required body, error_code=""): 204
GET runtime/poll (Bearer malformed): 401
canonical revoke: 204; canonical delete: 204
```

The retained evidence was projected before storage: poll contained revision,
device/org identity, address, gateway endpoint/public key, allowed IPs, DNS,
and keepalive only; refusal contained `unauthenticated` and its generic
message. Both projected bodies reported `secret_fields_present=0`. Captured
success/refusal headers contained none of `authorization`, `credential`,
`private`, `token`, or `hash`. No bearer, bootstrap token, private key, or raw
response was retained.

## F2-owned shipped-runtime walk

The shipped image was built from `deploy/docker/agent-runtime.Dockerfile` as
`f2-f04-agent-runtime:20260815` (CGO-free Linux binary, image manifest
`f1bfafed0e5c0275e66b6a9178e33817cb67b39f1a1baa98dff02fbc58dd944a`). A separate
F2-owned container ran `/usr/local/bin/tunnex-agent-runtime` on the stable F2
Docker network, with its own redeemed identity and container-local copies of
the root-scoped 0600 config, credential, and durable state files.

The host has no `/dev/net/tun`, so the walk used a narrowly scoped
container-local `wg-quick` shim only to record the rendered config; it did not
touch the attached F01 runtime, the gateway, or the shared opt-in. The config's
private key was never printed or fingerprinted. Redacted fingerprints were:

```text
initial revision=1
runtime.conf sha256=fadfdc69a396fba81011fafb7dc2058f537915b626cd3a266db945d62ab4362d
active.conf  sha256=fadfdc69a396fba81011fafb7dc2058f537915b626cd3a266db945d62ab4362d
interface-section-without-private-key sha256=7448d5edb5501c30b655fd9d9511542e858bfecf84e47ebca9e141528bce5ec59f7a729b
peer-section sha256=36da38d3aaa716ffc77e23d0848d50ebc231c34cd484cd205b5ca114a6e09767
durable state applied_revision=1
```

The F2-only reverse proxy was stopped for 7 seconds. During the bounded
exponential retry window, config, active config, both section fingerprints,
and durable `applied_revision=1` remained unchanged. After proxy recovery the
runtime issued `GET poll?applied_revision=1` → 204 and `POST report` → 204.
Restarting only the shipped runtime container then produced the same 204/204
pair, retained revision 1, and preserved all four fingerprints. Two overlapping
wire reports with applied/attempted revision 1 both returned 204; the secret-free
admin status remained `desired=1, applied=1, last_attempted=1,
connectivity=connected, stale=false`.

This is shipped-binary/container and real-control-channel evidence, but the
kernel peer/interface portion is a SUBSTITUTE because the host lacks
`/dev/net/tun`; it does not SATISFY a hardware-backed WireGuard peer walk.

## Independent review of bounded retry patch

Root's `managed_runtime.go` patch injects `Jitter`, defaults it to
`boundedRuntimeJitter`, validates every delay as positive and no greater than
the current backoff, then doubles/clamps the backoff. The jitter function stays
in the upper half of the window. `TestManagedAgentRuntimeLongPollTickerAndBoundedBackoff`
passed count=10 and under `-race` count=3. No zero or beyond-backoff delay was
observed; no regression was found.

## F2-owned isolated PostgreSQL fallback evidence

The following historical pre-collision proof ran on an isolated Docker network
with a disposable PostgreSQL 16 container through then-current migration 84
(`migrate_up_complete version=84 dirty=false`). The collision-safe 79–93
sequence requires a fresh rerun:

```text
docker run ... postgres:16
docker run --rm ... golang:1.25.13-alpine sh -ec \
  'go run ./cmd/migrate up && \
   go test -v ./internal/agentruntime -run "^TestRuntimeServicePostgresContract$" -count=1 && \
   go test -v ./internal/http -run "^TestAgentRuntimeRoutesPostgresContract$" -count=1'
```

`TestRuntimeServicePostgresContract` PASS (0.03s), including auth refusal
classes, poll 200/204, monotonic backwards/ahead refusal, overlapping reports,
and final server state applied=3/attempted=3. The former route-test mismatch is
closed: the current non-skipped PostgreSQL route contract asserts the existing
404 no-oracle boundary for both known cross-org and unknown organizations.

## Ranked close findings

No P0 or P1 semantic defect was found in the reviewed fold represented by this
historical checkpoint. The remaining ranked items are repository and
exact-source live completion gates; this note does not replace refold review.

The following story-level gates remain before F04 can be called complete:

1. **P1 — Required current-head repository gates remain a completion gate.**
   Focused default/enterprise API/CLI tests, web tests/typecheck, isolated
   PostgreSQL contracts, live wire walks, and `git diff --check` are evidenced.
   The full AGENTS gate bundle (`make generate-check`, migrations, both-edition
   test/build, node/helper/crosscompile, and web build) has not been rerun
   cleanly against this intentionally shared dirty worktree; `generate-check`
   was previously blocked by shared generated drift. F04 is not Done-eligible
   until root records the current-head gate result.
2. **P1 — Exact-source live parity remains required.** The prior AWS dev walk
   proved the behavior, but later source folds changed runtime status,
   authorization, long-poll deadlines, and offboard handling. Rebuild and
   repeat the bounded live leg from the actual implementation commit before
   calling the story complete.

F04 remains open pending the repository gate, current refold review, and
exact-source live parity. The plan status was not changed by this review.

## AWS dev-control-plane live wire — 2026-08-15

The current source and collision-safe schema were deployed to the authorized
AWS development control plane, where schema `93|clean`, Enterprise edition,
signed runtime provenance, runtime opt-in, issue/redeem/approve, real TUN plus
WireGuard apply and handshake, secret-free status, last-good preservation,
process restart, and revoke-triggered disable all passed. The final old-bearer
poll returned the uniform HTTP 401 refusal, the runtime process exited, and the
interface was absent. Redacted evidence is
`walk-artifacts/F04/20260815T051740Z/live-dev-cp.md`.

## Final exact-source closure walk — 2026-08-15

**SATISFIES.** The final walk used the reviewed `bb7a406` API/web deployment
and the source-bound signed runtime from `09d9848`, whose only product delta is
the terminal-offboard revision reset discovered by this walk. The final
runtime asset and unchanged service unit verified against the immutable signed
descriptor before installation.

The fresh disposable agent proved owner approval, real WireGuard apply and
handshake, two 30-second unchanged polls returning 204/zero bytes, and a
scoped desired-revision bump waking the held poll with revision 2. Owner status
returned 2/2/2, connected/ready/fresh. A plain member received 403 and no
runtime-status fields; the released owner route rendered the same ready facts.
Forced report aging rendered disconnected, last-good and stale in both the API
and released UI, then returned to ready/fresh after recovery. A 35-second
agent-VM-only control-plane outage preserved the last-good configuration,
applied revision, running service and real peer.

The first exact opt-out/re-enable attempt correctly exposed a real defect and
was not accepted: offboard removed the interface but left applied revision 2,
so restart did not reapply it. Commit `09d9848` records applied revision zero
only after a successful terminal offboard. The source-bound signed fixed
runtime then proved the complete ceremony: released-UI opt-out persisted and
audited, the machine channel returned uniform 401, the service exited cleanly,
the interface disappeared and durable applied revision became zero; released-
UI re-enable persisted and audited, restart reapplied revision 2, recreated
the interface, handshaked, and returned owner status to connected/ready/fresh.

Both disposable agents were canonically revoked and removed. The dedicated
VM service, interface and five managed-runtime paths were removed; `/dev/net/tun`
and the base release verifier were preserved. The organization's original ON
opt-in was restored. Redacted evidence is in
`walk-artifacts/F04/20260815T103303Z/`.

The exact local gate matrix recorded for this story remains green. The final
fold changed only the runtime offboard state plus focused regressions and was
re-proved on the live wire. F04 has no remaining P0/P1 finding or substituted
live gate and is review-pass eligible.
